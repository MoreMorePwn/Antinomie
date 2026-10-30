// SPDX-License-Identifier: GPL-3.0-only
//! Capabilities from an installed capa, run with the bundled capa-rules.
use super::tools;
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

const MANAGED: &str = "/opt/antinomie-tools/capa/capa";
const RULES: &[u8] = include_bytes!("../../assets/rules/capa-rules-v9.4.0.tar.gz");
pub(super) const RULES_RELEASE: &str = "capa-rules v9.4.0";
/// capa's own time limit, in seconds.
pub(super) const TIMEOUT_SECONDS: u64 = 240;
/// Where the sandbox mounts capa's compiled-rule cache.
pub(super) const CACHE_MOUNT: &str = "/cache/capa";
/// The cache is emptied when it grows past this many octets.
const CACHE_MAX_SIZE: u64 = 256 * 1024 * 1024;

/// The host folder that keeps capa's compiled rules for this rules release,
/// beside the installed tools. capa names each cache file by the rules'
/// content and its own version, so a new release starts an empty folder and an
/// old one is never read as the new.
pub(super) fn cache_dir(tools: Option<&Path>) -> Option<PathBuf> {
    let folder = tools?
        .parent()?
        .join("cache")
        .join("capa")
        .join(RULES_RELEASE.replace(' ', "-"));
    crate::storage::private_dir(&folder).ok()?;
    Some(folder)
}

/// Mount the cache folder into the worker's sandbox, writable, where capa
/// keeps its compiled rules from one run to the next.
pub(super) fn mount_cache(cmd: &mut std::process::Command, tools: Option<&Path>) {
    if let Some(cache) = cache_dir(tools) {
        cmd.arg("--bind").arg(cache).arg(CACHE_MOUNT);
    }
}

/// Empty the cache folder if it has grown past [`CACHE_MAX_SIZE`]: capa
/// writes into it while it reads an untrusted file, so its size is bounded
/// and a damaged entry is rebuilt on the next run.
pub(super) fn trim_cache(tools: Option<&Path>) {
    let Some(folder) = cache_dir(tools) else {
        return;
    };
    if super::jobs::directory_len(&folder).is_ok_and(|len| len > CACHE_MAX_SIZE) {
        let _ = fs::remove_dir_all(&folder);
    }
}

/// "Tactic::Technique [ID]" from a capa ATT&CK or MBC object.
fn mapping(value: &serde_json::Value) -> Option<String> {
    let parts = value.get("parts").and_then(|p| p.as_array()).map(|parts| {
        parts
            .iter()
            .filter_map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join("::")
    });
    let id = value.get("id").and_then(|i| i.as_str()).unwrap_or("");
    match parts {
        Some(parts) if !parts.is_empty() => Some(if id.is_empty() {
            parts
        } else {
            format!("{parts} [{id}]")
        }),
        _ => value.as_str().map(str::to_owned),
    }
}

pub(super) fn capabilities(section: &mut AnalysisSection) {
    let Some(capa) = tools::find_tool(crate::analysis_tools::CAPA_SYSTEM, MANAGED) else {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = format!(
            "capa is not installed; install it from Tools > Analysis tools (or on the system) and Antinomie runs it with the bundled {RULES_RELEASE}"
        );
        return;
    };
    let unpacked = fs::write("/tmp/capa-rules.tar.gz", RULES)
        .map_err(|e| e.to_string())
        .and_then(|()| {
            tools::run(
                "/usr/bin/tar",
                &["-xzf", "/tmp/capa-rules.tar.gz", "-C", "/tmp"],
                &[],
                Duration::from_secs(60),
                4096,
            )
            .and_then(|run| {
                if run.success {
                    Ok(())
                } else {
                    Err("rules archive did not unpack".into())
                }
            })
        });
    if let Err(error) = unpacked {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = format!("capa rules unavailable: {error}");
        return;
    }
    let timeout = Duration::from_secs(super::limits::seconds(TIMEOUT_SECONDS));
    // A cache folder mounted by the host keeps the compiled rules from one
    // run to the next; without it capa compiles them every time.
    let cache = Path::new(CACHE_MOUNT).is_dir();
    let mut environment = vec![("HOME", "/tmp")];
    if cache {
        environment.push(("XDG_CACHE_HOME", CACHE_MOUNT));
    }
    let run = match tools::run_with(
        capa,
        &["--json", "-r", "/tmp/capa-rules", "/input/specimen"],
        &environment,
        timeout,
        32 * 1024 * 1024,
        true,
    ) {
        Ok(run) => run,
        Err(error) => {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = format!("capa failed to start: {error}");
            return;
        }
    };
    section.tools = vec![tools::version(capa, &["--version"]), RULES_RELEASE.into()];
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&run.stdout) else {
        eprintln!(
            "capa output did not parse ({} octets, success {}): {}",
            run.stdout.len(),
            run.success,
            run.stdout.chars().take(300).collect::<String>()
        );
        if run.timed_out {
            super::limits::time_out(
                section,
                "capa",
                timeout.as_secs(),
                "capa found nothing before it was stopped. Statically linked programs take capa much longer because it also analyses the bundled C library.",
            );
        } else if run.truncated {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = "capa printed more than 32 MiB, so its result was not read".into();
            super::limits::add(
                section,
                AnalysisLimitKind::Size,
                "capa's output was bigger than the 32 MiB the analysis reads.",
                None,
            );
        } else {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = run.failure_text("capa", timeout).unwrap_or_else(|| {
                let lines = tools::error_lines(&[&run.stderr, &run.stdout], 4);
                if lines.is_empty() {
                    "capa finished but printed no result that can be read; the file format may be one capa does not support".into()
                } else {
                    format!(
                        "capa finished but printed no result that can be read: {}",
                        lines.join("; ")
                    )
                }
            });
        }
        return;
    };
    let rules = json
        .get("rules")
        .and_then(|r| r.as_object())
        .cloned()
        .unwrap_or_default();
    let mut count = 0usize;
    for (name, rule) in &rules {
        let meta = rule.get("meta").cloned().unwrap_or_default();
        if meta.get("lib").and_then(|l| l.as_bool()).unwrap_or(false) {
            continue;
        }
        let list = |key: &str| -> Vec<String> {
            meta.get(key)
                .and_then(|v| v.as_array())
                .map(|items| items.iter().filter_map(mapping).collect())
                .unwrap_or_default()
        };
        let namespace = meta
            .get("namespace")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_owned();
        let locations = rule
            .get("matches")
            .map(|m| {
                m.as_array()
                    .map_or_else(|| m.as_object().map_or(0, |o| o.len()), |a| a.len())
            })
            .unwrap_or(0);
        let attack = list("attack");
        let mbc = list("mbc");
        let mut value = format!(
            "{locations} {}",
            if locations == 1 {
                "location"
            } else {
                "locations"
            }
        );
        if !attack.is_empty() {
            value.push_str(&format!("; ATT&CK {}", attack.join(", ")));
        }
        super::worker::structured_entry(
            section,
            name.clone(),
            value,
            None,
            AnalysisData::Capability {
                name: name.clone(),
                namespace,
                attack,
                mbc,
            },
        );
        count += 1;
    }
    section.summary = format!("{count} capabilities from capa with {RULES_RELEASE}");
    if run.timed_out {
        super::limits::time_out(
            section,
            "capa",
            timeout.as_secs(),
            format!(
                "{count} capabilities from capa with {RULES_RELEASE} were found before it was stopped."
            ),
        );
    } else if run.truncated {
        section.state = AnalysisSectionState::Partial;
        super::limits::add(
            section,
            AnalysisLimitKind::Size,
            "capa's output was bigger than the 32 MiB the analysis reads; the rest was ignored.",
            None,
        );
    } else {
        section.state = AnalysisSectionState::Complete;
    }
}

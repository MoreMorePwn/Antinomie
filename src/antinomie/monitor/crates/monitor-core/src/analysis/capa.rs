// SPDX-License-Identifier: MIT
//! Capabilities from an installed capa, run with the bundled capa-rules.
use super::tools;
use super::*;
use std::{fs, time::Duration};

const MANAGED: &str = "/opt/antinomie-tools/capa/capa";
const RULES: &[u8] = include_bytes!("../../assets/rules/capa-rules-v9.4.0.tar.gz");
pub(super) const RULES_RELEASE: &str = "capa-rules v9.4.0";

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
    let run = match tools::run_with(
        capa,
        &["--json", "-r", "/tmp/capa-rules", "/input/specimen"],
        &[("HOME", "/tmp")],
        Duration::from_secs(240),
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
        section.state = AnalysisSectionState::Unavailable;
        section.summary = if run.timed_out {
            "capa ran out of time (4 minutes) and was stopped; statically linked programs take capa much longer because it also analyses the bundled C library".into()
        } else {
            "capa reported no readable result; the format may be unsupported by capa".into()
        };
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
    section.state = if run.truncated || run.timed_out {
        AnalysisSectionState::Partial
    } else {
        AnalysisSectionState::Complete
    };
    section.summary = format!("{count} capabilities from capa with {RULES_RELEASE}");
}

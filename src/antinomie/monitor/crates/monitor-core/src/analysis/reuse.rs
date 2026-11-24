// SPDX-License-Identifier: GPL-3.0-only
//! Reusing a complete static result, and recording a check that was not run
//! (ANT-T0618, audit AN-09 and AN-02b).
//!
//! An Auto job analyses the library copy of its sample, one analysis folder
//! per group of checks (`<data>/analyses/<id>`). A second job for the same
//! file used to run every tool again. The service now asks [`find`] for a
//! folder made with the same key, and [`adopt`] gives the job a folder of its
//! own that links the old one's files, so retention of either job never
//! removes what the other reads.
//!
//! **The key** ([`key`]) is the SHA-256 of the sample, the checks, the app
//! version, the tools the checks run (the version Antinomie installed, and the
//! size and time of each system program), the rule profile for the Rules
//! check, and the size and count limits. A time limit is not part of it: a
//! result that is complete is complete under any limit.
//!
//! **A hit** is a folder whose `reuse.json` has that key, whose report has no
//! layer, and whose every asked section is `Complete` with no bound that cut
//! it short. A timed-out, refused, partial or unavailable result is never a
//! hit, and neither is a folder from before the key was kept.
//!
//! **Visible.** The adopted report's summaries start with "reused from run
//! ... (analysis ...)", so the report, the window and the CLI show it; the
//! sidecar `reuse.json` of the copy names the source.
//!
//! A check that was skipped before it ran ([`skipped_report`]) is a report of
//! its own with the check `Unavailable` and the reason as its summary, so it
//! shows where a result would.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// The file in an analysis folder that holds its key.
pub const SIDECAR: &str = "reuse.json";

#[derive(Debug, Serialize, Deserialize)]
struct Sidecar {
    key: String,
    /// Set on a folder made by [`adopt`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<Reused>,
}

/// Where a reused result came from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reused {
    /// The analysis it was copied from.
    pub report: String,
    /// The Auto run that analysis was made for, when it says so.
    pub run: Option<String>,
}

/// A folder [`find`] found.
#[derive(Clone, Debug)]
pub struct Found {
    pub folder: PathBuf,
    pub report: AnalysisReport,
    pub reused: Reused,
}

/// The tools a check runs: the optional packages (by id) and the system
/// programs outside them.
fn tools_of(kind: AnalysisKind) -> (&'static [&'static str], &'static [&'static str]) {
    match kind {
        AnalysisKind::Capabilities => (&["capa"], &[]),
        AnalysisKind::Floss => (&["floss"], &[]),
        AnalysisKind::Identification => (&["die", "magika"], &["/usr/bin/file"]),
        AnalysisKind::Embedded => (&[], crate::dependencies::BINWALK),
        AnalysisKind::Unpacking => (&["upx"], &[]),
        AnalysisKind::Disassembly | AnalysisKind::Decompilation => {
            (&["ghidra"], crate::analysis_tools::RADARE2_SYSTEM)
        }
        _ => (&[], &[]),
    }
}

/// A program's size and modification time, or "absent".
fn stamp(path: &str) -> String {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).map_or_else(
        |_| format!("{path} absent"),
        |meta| {
            format!(
                "{path} {} {}.{}",
                meta.len(),
                meta.mtime(),
                meta.mtime_nsec()
            )
        },
    )
}

/// What a result of `checks` for the sample `sha256` depends on, as one
/// string; equal strings mean the same tools run on the same bytes.
pub fn key(
    data_dir: &Path,
    sha256: &str,
    checks: &[AnalysisKind],
    limits: Option<AnalysisLimits>,
) -> String {
    let mut kinds = checks.to_vec();
    kinds.sort_by_key(|kind| format!("{kind:?}"));
    kinds.dedup();
    let mut material = format!(
        "sha256 {}\napp {}\nlimits {}\nrules {}\n",
        sha256.to_ascii_lowercase(),
        crate::api::APP_VERSION,
        serde_json::to_string(&limits).unwrap_or_default(),
        super::capa::RULES_RELEASE,
    );
    let statuses = crate::analysis_tools::statuses(data_dir);
    for kind in kinds {
        material.push_str(&format!("check {kind:?}\n"));
        let (packages, programs) = tools_of(kind);
        for id in packages {
            if let Some(status) = statuses.iter().find(|status| status.id == *id) {
                material.push_str(&format!("package {id} {:?}\n", status.installed));
                for path in crate::analysis_tools::system_candidates(id) {
                    material.push_str(&stamp(path));
                    material.push('\n');
                }
            }
        }
        for path in programs {
            material.push_str(&stamp(path));
            material.push('\n');
        }
        if kind == AnalysisKind::Rules {
            // The profile the Rules check would read now.
            let profile = crate::ruleset::load_registry(data_dir)
                .ok()
                .map(|registry| {
                    let facts = crate::ruleset::tool_facts_for("yara", &Default::default());
                    crate::ruleset::selection_digest_of(data_dir, &registry, "yara", &facts)
                });
            material.push_str(&format!("profile {profile:?}\n"));
        }
    }
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

/// Keep `key` in the analysis folder `folder`, so a later job can find it.
pub fn remember(folder: &Path, key: &str) {
    let sidecar = Sidecar {
        key: key.to_owned(),
        from: None,
    };
    if let Ok(bytes) = serde_json::to_vec(&sidecar) {
        let _ = crate::storage::atomic_bytes(&folder.join(SIDECAR), &bytes);
    }
}

fn sidecar_of(folder: &Path) -> Option<Sidecar> {
    use std::io::Read;
    let mut bytes = Vec::new();
    fs::File::open(folder.join(SIDECAR))
        .ok()?
        .take(4096)
        .read_to_end(&mut bytes)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Whether every asked check of `report` finished whole.
fn whole(report: &AnalysisReport, checks: &[AnalysisKind]) -> bool {
    report.layer.is_none()
        && matches!(
            report.state,
            AnalysisState::Complete | AnalysisState::Partial
        )
        && checks.iter().all(|kind| {
            report.sections.iter().any(|section| {
                section.kind == *kind
                    && section.state == AnalysisSectionState::Complete
                    && section.limits.is_empty()
            })
        })
}

/// The newest folder under `roots` (the data folder's `analyses` folders)
/// made with `key` whose `checks` are whole. `run_of` names the Auto run a
/// folder was made for.
pub fn find(
    roots: &[PathBuf],
    key: &str,
    checks: &[AnalysisKind],
    run_of: impl Fn(&Path) -> Option<String>,
) -> Option<Found> {
    let mut best: Option<(std::time::SystemTime, Found)> = None;
    for root in roots {
        for entry in fs::read_dir(root).ok()?.flatten() {
            let folder = entry.path();
            let Some(sidecar) = sidecar_of(&folder) else {
                continue;
            };
            if sidecar.key != key {
                continue;
            }
            let Ok(report) = super::jobs::open_report(&folder) else {
                continue;
            };
            if !whole(&report, checks) {
                continue;
            }
            let made = fs::metadata(folder.join("report.json"))
                .and_then(|meta| meta.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            if best.as_ref().is_some_and(|(newest, _)| *newest >= made) {
                continue;
            }
            // A copy names its own source's run and report.
            let reused = sidecar.from.unwrap_or_else(|| Reused {
                report: report.id.clone(),
                run: run_of(&folder),
            });
            best = Some((
                made,
                Found {
                    folder,
                    report,
                    reused,
                },
            ));
        }
    }
    best.map(|(_, found)| found)
}

/// Make the analysis of a job out of `found`: a folder of its own under
/// `root` whose files are links to the old one's, and a report that says it
/// was reused. Returns the new report.
pub fn adopt(root: &Path, key: &str, found: &Found) -> Result<AnalysisReport, String> {
    let mut report = found.report.clone();
    report.id = crate::storage::unique_id();
    let folder = root.join(&report.id);
    link_tree(&found.folder, &folder)?;
    let note = match &found.reused.run {
        Some(run) => format!("reused from run {run}, analysis {}", found.reused.report),
        None => format!("reused from analysis {}", found.reused.report),
    };
    for section in &mut report.sections {
        section.summary = format!("{} ({note}; the check was not run again)", section.summary);
    }
    let encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    // The copy has a report of its own: the link to the old one is cut first.
    let _ = fs::remove_file(folder.join("report.json"));
    crate::storage::atomic_bytes(&folder.join("report.json"), &encoded)?;
    let sidecar = Sidecar {
        key: key.to_owned(),
        from: Some(found.reused.clone()),
    };
    let bytes = serde_json::to_vec(&sidecar).map_err(|e| e.to_string())?;
    let _ = fs::remove_file(folder.join(SIDECAR));
    crate::storage::atomic_bytes(&folder.join(SIDECAR), &bytes)?;
    Ok(report)
}

/// Link (or copy, across filesystems) the regular files of `from` into `to`.
fn link_tree(from: &Path, to: &Path) -> Result<(), String> {
    crate::storage::private_dir(to).map_err(|e| format!("{}: {e}", to.display()))?;
    for entry in fs::read_dir(from).map_err(|e| format!("{}: {e}", from.display()))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink() {
            return Err(format!("{} is a link", entry.path().display()));
        }
        let target = to.join(entry.file_name());
        if meta.is_dir() {
            // The worker's scratch output is not part of a result.
            if entry.file_name() != "output" {
                link_tree(&entry.path(), &target)?;
            }
        } else if meta.is_file() {
            fs::hard_link(entry.path(), &target)
                .or_else(|_| fs::copy(entry.path(), &target).map(|_| ()))
                .map_err(|e| format!("{}: {e}", target.display()))?;
        }
    }
    Ok(())
}

/// A report for a check that was not run, with `text` as why: the check is
/// `Unavailable` and says so where a result would be read. Returns its id.
pub fn skipped_report(
    root: &Path,
    sha256: &str,
    kind: AnalysisKind,
    text: &str,
) -> Result<AnalysisReport, String> {
    let selection = AnalysisSelection {
        enabled: true,
        checks: vec![kind],
        time_limit_minutes: 0,
        limits: AnalysisLimits::DEFAULT,
    };
    let mut report = super::jobs::new_report(
        &format!("sample:{}", sha256.to_ascii_lowercase()),
        &selection,
    );
    report.state = AnalysisState::Partial;
    report.specimen_sha256 = Some(sha256.to_ascii_lowercase());
    for section in &mut report.sections {
        section.state = AnalysisSectionState::Unavailable;
        section.summary = text.chars().take(1000).collect();
    }
    let folder = root.join(&report.id);
    crate::storage::private_dir(&folder).map_err(|e| format!("{}: {e}", folder.display()))?;
    let encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    crate::storage::atomic_bytes(&folder.join("report.json"), &encoded)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ant-reuse-{name}-{}", crate::storage::unique_id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A finished analysis folder of `checks` with `state` for each.
    fn made(
        root: &Path,
        key: &str,
        checks: &[AnalysisKind],
        state: AnalysisSectionState,
    ) -> String {
        let selection = AnalysisSelection {
            enabled: true,
            checks: checks.to_vec(),
            time_limit_minutes: 0,
            limits: AnalysisLimits::DEFAULT,
        };
        let mut report = super::super::jobs::new_report("sample:ab", &selection);
        report.state = AnalysisState::Complete;
        for section in &mut report.sections {
            section.state = state;
            section.summary = "7 rows".into();
        }
        let folder = root.join(&report.id);
        fs::create_dir_all(folder.join("listings")).unwrap();
        fs::write(folder.join("listings/strings.jsonl"), b"{}\n").unwrap();
        fs::write(folder.join("specimen"), b"bytes").unwrap();
        fs::write(
            folder.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        remember(&folder, key);
        report.id
    }

    #[test]
    fn the_key_follows_the_sample_the_checks_the_limits_and_the_tools() {
        let data = temp("key");
        let base = key(&data, "AB", &[AnalysisKind::Strings], None);
        assert_eq!(base, key(&data, "ab", &[AnalysisKind::Strings], None));
        assert_ne!(base, key(&data, "cd", &[AnalysisKind::Strings], None));
        assert_ne!(base, key(&data, "ab", &[AnalysisKind::Entropy], None));
        let mut limits = AnalysisLimits::DEFAULT;
        limits.rows += 1;
        assert_ne!(
            base,
            key(&data, "ab", &[AnalysisKind::Strings], Some(limits))
        );
        // The order of the checks does not matter.
        assert_eq!(
            key(
                &data,
                "ab",
                &[AnalysisKind::Strings, AnalysisKind::Entropy],
                None
            ),
            key(
                &data,
                "ab",
                &[AnalysisKind::Entropy, AnalysisKind::Strings],
                None
            )
        );
        // An installed tool's version is part of its check's key, not of another's.
        let before = key(&data, "ab", &[AnalysisKind::Capabilities], None);
        let tool = data.join("tools/capa");
        fs::create_dir_all(&tool).unwrap();
        fs::write(tool.join("tool.json"), r#"{"id":"capa","version":"1.0.0"}"#).unwrap();
        let entry = crate::analysis_tools::package("capa").unwrap().entry;
        fs::write(tool.join(entry), b"x").unwrap();
        assert_ne!(
            before,
            key(&data, "ab", &[AnalysisKind::Capabilities], None)
        );
        assert_eq!(base, key(&data, "ab", &[AnalysisKind::Strings], None));
        let _ = fs::remove_dir_all(data);
    }

    #[test]
    fn only_a_whole_result_with_the_same_key_is_found() {
        let root = temp("find");
        let wanted = [AnalysisKind::Strings, AnalysisKind::Entropy];
        let timed_out = made(&root, "k", &wanted, AnalysisSectionState::Timeout);
        let partial = made(&root, "k", &wanted, AnalysisSectionState::Partial);
        let other_key = made(&root, "other", &wanted, AnalysisSectionState::Complete);
        let fewer = made(
            &root,
            "k",
            &[AnalysisKind::Strings],
            AnalysisSectionState::Complete,
        );
        let find = |key: &str| {
            find(std::slice::from_ref(&root), key, &wanted, |_| {
                Some("r_old".into())
            })
        };
        assert!(
            find("k").is_none(),
            "{timed_out} {partial} {other_key} {fewer}"
        );
        let good = made(&root, "k", &wanted, AnalysisSectionState::Complete);
        let found = find("k").expect("a hit");
        assert_eq!(found.report.id, good);
        assert_eq!(
            found.reused,
            Reused {
                report: good.clone(),
                run: Some("r_old".into())
            }
        );
        // A section cut short by a bound is not whole either.
        let mut report = found.report.clone();
        report.sections[0].limits.push(AnalysisLimit {
            kind: AnalysisLimitKind::Size,
            text: "cut".into(),
            seconds: None,
            setting: None,
        });
        assert!(!whole(&report, &wanted));
        // A folder from before keys were kept has no sidecar.
        fs::remove_file(root.join(&good).join(SIDECAR)).unwrap();
        assert!(find("k").is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_adopted_result_is_a_folder_of_its_own_that_says_where_it_came_from() {
        let root = temp("adopt");
        let wanted = [AnalysisKind::Strings];
        let old = made(&root, "k", &wanted, AnalysisSectionState::Complete);
        let found = find(std::slice::from_ref(&root), "k", &wanted, |_| {
            Some("r_first".into())
        })
        .unwrap();
        let report = adopt(&root, "k", &found).unwrap();
        assert_ne!(report.id, old);
        assert!(
            report.sections[0]
                .summary
                .contains("reused from run r_first, analysis")
        );
        assert!(report.sections[0].summary.contains(&old));
        let copy = root.join(&report.id);
        assert!(copy.join("listings/strings.jsonl").is_file());
        // Deleting the source leaves the copy whole, and the copy's report is its own.
        fs::remove_dir_all(root.join(&old)).unwrap();
        assert_eq!(
            fs::read(copy.join("listings/strings.jsonl")).unwrap(),
            b"{}\n"
        );
        let reread = super::super::jobs::open_report(&copy).unwrap();
        assert_eq!(reread.id, report.id);
        // The copy is itself reusable and still names the first run.
        let again = find(std::slice::from_ref(&root), "k", &wanted, |_| None).unwrap();
        assert_eq!(again.reused.run.as_deref(), Some("r_first"));
        assert_eq!(again.reused.report, old);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_skipped_check_is_a_report_that_says_why() {
        let root = temp("skip");
        let report = skipped_report(
            &root,
            &"AB".repeat(32),
            AnalysisKind::Capabilities,
            "skipped: predicted 900 s over the 480 s limit",
        )
        .unwrap();
        let read = super::super::jobs::open_report(&root.join(&report.id)).unwrap();
        assert_eq!(read.sections[0].state, AnalysisSectionState::Unavailable);
        assert!(
            read.sections[0]
                .summary
                .starts_with("skipped: predicted 900 s")
        );
        assert_eq!(read.specimen_sha256, Some("ab".repeat(32)));
        let _ = fs::remove_dir_all(root);
    }

    /// By hand (ANT-T0618 measurement): `ANT_REUSE_FOLDER=<a finished analysis
    /// folder, copied>` with its checks in `ANT_REUSE_CHECKS=a,b`.
    #[test]
    #[ignore = "needs ANT_REUSE_FOLDER"]
    fn time_a_reuse_of_a_real_analysis() {
        let Some(folder) = std::env::var_os("ANT_REUSE_FOLDER") else {
            return;
        };
        let folder = PathBuf::from(folder);
        let report = super::super::jobs::open_report(&folder).unwrap();
        let checks: Vec<AnalysisKind> = report.sections.iter().map(|s| s.kind).collect();
        let data = temp("data");
        let sha = report.specimen_sha256.clone().unwrap();
        let t = std::time::Instant::now();
        let key = key(&data, &sha, &checks, report.limits);
        eprintln!("TIMING key: {:.4} s", t.elapsed().as_secs_f64());
        remember(&folder, &key);
        let root = folder.parent().unwrap().to_owned();
        let t = std::time::Instant::now();
        let found = find(std::slice::from_ref(&root), &key, &checks, |_| None);
        eprintln!(
            "TIMING find (whole: {}): {:.4} s",
            found.is_some(),
            t.elapsed().as_secs_f64()
        );
        let Some(found) = found else {
            return;
        };
        let t = std::time::Instant::now();
        let adopted = adopt(&root, &key, &found).unwrap();
        eprintln!(
            "TIMING adopt into {}: {:.4} s",
            adopted.id,
            t.elapsed().as_secs_f64()
        );
    }
}

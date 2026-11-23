// SPDX-License-Identifier: GPL-3.0-only
//! The static analysis of an Auto run, put where the window reads it.
//!
//! Auto analyses the library copy of the sample, one report per tool, each in
//! `<data>/analyses/<id>`. The window, the run API and the evidence bundle
//! read one report in the recording's own `analysis/` folder (and the same
//! report embedded in `run.json`). [`attach_static_reports`] joins the reports
//! into that one: the sections are the newest finished one of each check, the
//! listings are linked or copied next to it, and the specimen archive comes
//! from the first report. The `analyses/` folders stay as they were. The
//! run's `run.json` and `manifest.json` are not written (Triage's caches are
//! keyed to them): the loader reads the sidecar for a run that has none
//! embedded.
use super::*;

/// The folder an Auto run's report ends in, inside the run's folder.
const TARGET: &str = "analysis";

/// Link `from` to `to`, or copy it when they are on different filesystems.
fn link_or_copy(from: &Path, to: &Path) -> Result<(), String> {
    if to.exists() {
        return Ok(());
    }
    fs::hard_link(from, to)
        .or_else(|_| fs::copy(from, to).map(|_| ()))
        .map_err(|e| format!("{}: {e}", to.display()))
}

/// Whether a check has its final result in `section`.
fn settled(section: &AnalysisSection) -> bool {
    !matches!(
        section.state,
        AnalysisSectionState::Pending | AnalysisSectionState::Running
    )
}

/// What the loader reads of a sidecar.
const SIDECAR_MAX: usize = 128 * 1024;

/// Cut the previews of the biggest sections until the report fits the bound a
/// run's own report has. The complete rows are in the listings.
fn shorten_to_fit(report: &mut AnalysisReport) {
    loop {
        let size = serde_json::to_vec(report).map_or(0, |bytes| bytes.len());
        if size <= SIDECAR_MAX {
            return;
        }
        let Some(section) = report
            .sections
            .iter_mut()
            .filter(|section| !section.entries.is_empty())
            .max_by_key(|section| section.entries.len())
        else {
            return;
        };
        let keep = section.entries.len() / 2;
        section.entries.truncate(keep);
        if !section.summary.contains("preview shortened") {
            section.summary = format!(
                "{}; preview shortened, the whole result is in the listing",
                section.summary
            );
        }
    }
}

/// Join the static reports in `parts` (oldest first; a later report's check
/// replaces an earlier one's) into `<run_directory>/analysis` and into the
/// run's folder only. Nothing is done when the run has a report of its own
/// already (the window's) or when no part can be read. Returns the joined
/// report.
pub fn attach_static_reports(
    parts: &[PathBuf],
    run_directory: &Path,
) -> Result<Option<AnalysisReport>, String> {
    let target = run_directory.join(TARGET);
    if target.join("report.json").exists() {
        return Ok(None);
    }
    let mut opened: Vec<(&PathBuf, AnalysisReport)> = parts
        .iter()
        .filter_map(|part| Some((part, open_report(part).ok()?)))
        .filter(|(_, report)| report.layer.is_none())
        .collect();
    if opened.is_empty() {
        return Ok(None);
    }
    // The report that names the specimen: the first one that has it.
    let first = opened
        .iter()
        .position(|(_, r)| r.specimen_sha256.is_some())
        .unwrap_or(0);
    let (primary_dir, mut joined) = {
        let (dir, report) = opened.remove(first);
        (dir.clone(), report)
    };
    let mut sources: Vec<PathBuf> = vec![primary_dir.clone()];
    // Each check's section, with the report it came from: the newest report
    // that finished it.
    let mut chosen: Vec<(AnalysisSection, usize)> = std::mem::take(&mut joined.sections)
        .into_iter()
        .map(|section| (section, 0))
        .collect();
    for (dir, report) in &opened {
        sources.push((*dir).clone());
        let index = sources.len() - 1;
        for section in &report.sections {
            match chosen.iter().position(|(s, _)| s.kind == section.kind) {
                Some(at) if settled(section) || !settled(&chosen[at].0) => {
                    chosen[at] = (section.clone(), index);
                }
                Some(_) => {}
                None => chosen.push((section.clone(), index)),
            }
        }
    }
    chosen.sort_by_key(|(section, _)| {
        AnalysisKind::TRIAGE
            .iter()
            .chain(AnalysisKind::DEEP)
            .position(|kind| *kind == section.kind)
            .unwrap_or(usize::MAX)
    });
    let owner: Vec<(AnalysisKind, usize)> = chosen.iter().map(|(s, i)| (s.kind, *i)).collect();
    joined.sections = chosen.into_iter().map(|(section, _)| section).collect();
    joined.state = if joined.sections_settled()
        || joined
            .sections
            .iter()
            .all(|s| matches!(s.state, AnalysisSectionState::Unavailable))
    {
        AnalysisState::Complete
    } else {
        AnalysisState::Partial
    };
    joined.reason = None;
    storage::private_dir(&target).map_err(|e| e.to_string())?;
    let listings = target.join("listings");
    storage::private_dir(&listings).map_err(|e| e.to_string())?;
    for section in &joined.sections {
        let Some((_, index)) = owner.iter().find(|(kind, _)| *kind == section.kind) else {
            continue;
        };
        let mut names = Vec::new();
        if section.listing.is_some() {
            names.push(super::super::listing::file_name(section.kind));
        }
        if section.disassembly.is_some() {
            names.push(super::super::listing::GHIDRA_DISASSEMBLY_FILE);
        }
        for name in names {
            let from = sources[*index].join("listings").join(name);
            if from.is_file() {
                link_or_copy(&from, &listings.join(name))?;
            }
        }
    }
    for name in [sealed::SEALED, sealed::PLAIN] {
        let from = primary_dir.join(name);
        if from.is_file() {
            link_or_copy(&from, &target.join(name))?;
            break;
        }
    }
    shorten_to_fit(&mut joined);
    persist_report(&target, &joined)?;
    Ok(Some(joined))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn part(root: &Path, name: &str, kinds: &[AnalysisKind]) -> PathBuf {
        let dir = root.join("analyses").join(name);
        storage::private_dir(&dir.join("listings")).unwrap();
        let selection = AnalysisSelection {
            enabled: true,
            checks: kinds.to_vec(),
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut report = new_report("/tmp/sample", &selection);
        report.id = name.into();
        report.state = AnalysisState::Complete;
        report.specimen_sha256 = Some("ab".repeat(32));
        report.specimen_len = Some(3);
        for section in &mut report.sections {
            section.state = AnalysisSectionState::Complete;
            section.summary = format!("{:?} of {name}", section.kind);
            section.listing = Some(AnalysisListing {
                rows: 0,
                bytes: 2,
                truncated: false,
            });
            fs::write(
                dir.join("listings")
                    .join(super::super::super::listing::file_name(section.kind)),
                b"{}",
            )
            .unwrap();
        }
        fs::write(dir.join("specimen.zip"), format!("zip of {name}")).unwrap();
        persist_report(&dir, &report).unwrap();
        dir
    }

    #[test]
    fn the_reports_of_an_auto_run_become_the_runs_one_report() {
        let root = std::env::temp_dir().join(format!("ant-attach-{}", storage::unique_id()));
        let run = root.join("run");
        storage::private_dir(&run).unwrap();
        let record = serde_json::json!({"id": "run1", "state": "Finished", "analysis": null});
        fs::write(run.join("run.json"), record.to_string()).unwrap();
        fs::write(
            run.join("manifest.json"),
            serde_json::json!({"run": record}).to_string(),
        )
        .unwrap();
        let a = part(
            &root,
            "aaa",
            &[AnalysisKind::Metadata, AnalysisKind::Strings],
        );
        let b = part(&root, "bbb", &[AnalysisKind::Entropy]);
        let joined = attach_static_reports(&[a.clone(), b], &run)
            .unwrap()
            .unwrap();
        assert_eq!(joined.id, "aaa");
        assert_eq!(joined.state, AnalysisState::Complete);
        let kinds: Vec<_> = joined.sections.iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            [
                AnalysisKind::Metadata,
                AnalysisKind::Strings,
                AnalysisKind::Entropy
            ]
        );
        let entropy = joined
            .sections
            .iter()
            .find(|s| s.kind == AnalysisKind::Entropy)
            .unwrap();
        assert_eq!(entropy.summary, "Entropy of bbb");
        let reread = open_report(&run.join("analysis")).unwrap();
        assert_eq!(reread, joined);
        for kind in kinds {
            assert!(
                run.join("analysis/listings")
                    .join(super::super::super::listing::file_name(kind))
                    .is_file()
            );
        }
        assert_eq!(
            fs::read(run.join("analysis/specimen.zip")).unwrap(),
            b"zip of aaa"
        );
        // The run's own records are left as they were.
        assert_eq!(
            fs::read(run.join("run.json")).unwrap(),
            record.to_string().into_bytes()
        );
        // The reports under `analyses/` are left as they were.
        assert!(a.join("report.json").is_file());
        // A run with a report of its own is left alone.
        assert!(attach_static_reports(&[a], &run).unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }
}

// SPDX-License-Identifier: MIT
//! Per-section progress of a running worker: the worker publishes the report
//! after every section and the host adopts what is validated, so a deadline or
//! a crash keeps the sections that finished.
use super::*;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

/// Name of the worker's progress report in its output directory.
pub(super) const FILE: &str = "progress.json";
/// How often the host looks at a running worker's progress.
const POLL: Duration = Duration::from_secs(2);

/// Worker side: publish `report` with section `running` marked as running
/// (`None` once every section is done). Best effort and atomic.
pub(super) fn publish(directory: &Path, report: &AnalysisReport, running: Option<usize>) {
    let mut snapshot = report.clone();
    snapshot.state = AnalysisState::Running;
    if let Some(section) = running.and_then(|index| snapshot.sections.get_mut(index)) {
        section.state = AnalysisSectionState::Pending;
        section.summary = "running in the analysis worker".into();
    }
    let Ok(encoded) = super::worker::bounded_report(&mut snapshot) else {
        return;
    };
    let target = directory.join(FILE);
    let temporary = directory.join(".progress.tmp");
    if fs::write(&temporary, encoded).is_ok() && fs::rename(&temporary, &target).is_err() {
        let _ = fs::remove_file(&temporary);
    }
}

/// Host side: what the host last saw of a worker's progress file.
#[derive(Default)]
pub(super) struct Watch {
    seen: Option<(SystemTime, u64)>,
    last_poll: Option<std::time::Instant>,
}

impl Watch {
    /// The validated progress report when the worker published a new one since
    /// the last call (at most every couple of seconds).
    pub(super) fn changed(
        &mut self,
        directory: &Path,
        expected: &AnalysisReport,
    ) -> Option<AnalysisReport> {
        if self.last_poll.is_some_and(|at| at.elapsed() < POLL) {
            return None;
        }
        self.last_poll = Some(std::time::Instant::now());
        let path: PathBuf = directory.join("output").join(FILE);
        let metadata = fs::symlink_metadata(&path).ok()?;
        let stamp = (metadata.modified().ok()?, metadata.len());
        if self.seen == Some(stamp) {
            return None;
        }
        self.seen = Some(stamp);
        super::jobs::read_report(&path, expected, false).ok()
    }
}

/// Take the finished sections of `progress` into `report`. `keep_listings`
/// false drops listing references (the files are not validated yet).
pub(super) fn merge(report: &mut AnalysisReport, progress: AnalysisReport, keep_listings: bool) {
    for (section, new) in report.sections.iter_mut().zip(progress.sections) {
        let finished = new.state != AnalysisSectionState::Pending;
        if finished || section.state == AnalysisSectionState::Pending {
            *section = new;
        }
        if !keep_listings {
            section.listing = None;
        }
    }
}

/// Host side, after a deadline or a crash: keep the sections the worker
/// finished. Returns whether any were adopted; listings are validated by the
/// caller's `adopt_listings`.
pub(super) fn salvage(directory: &Path, report: &mut AnalysisReport) -> bool {
    let path = directory.join("output").join(FILE);
    let Ok(progress) = super::jobs::read_report(&path, report, false) else {
        return false;
    };
    let finished = progress
        .sections
        .iter()
        .any(|section| section.state != AnalysisSectionState::Pending);
    merge(report, progress, true);
    finished
}

impl super::jobs::Job {
    /// A deadline stops the worker, not the sections it already finished:
    /// adopt them (and their validated listings) before the rest is marked
    /// unfinished.
    pub(super) fn keep_finished_sections(&mut self) {
        if progress::salvage(&self.directory, &mut self.report) {
            super::jobs::adopt_listings(&self.directory, &mut self.report);
        }
    }
}

pub(crate) fn worker_deadline(report: &AnalysisReport) -> Duration {
    // The sum of the sections' own budgets, so one slow tool (capa at 4
    // minutes) cannot use up the time of a later one (decompilation); this is
    // the hard backstop behind each tool's own timeout.
    let seconds: u64 = report
        .sections
        .iter()
        .map(|section| match section.kind {
            AnalysisKind::Decompilation => super::worker::DECOMPILER_SECONDS + 120,
            AnalysisKind::Capabilities => 300,
            AnalysisKind::Embedded => 200,
            AnalysisKind::Identification => 160,
            AnalysisKind::Disassembly | AnalysisKind::Rules => 90,
            _ => 20,
        })
        .sum();
    Duration::from_secs(seconds.max(60))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> AnalysisReport {
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![
                AnalysisKind::Metadata,
                AnalysisKind::Strings,
                AnalysisKind::Capabilities,
            ],
        };
        let mut report = super::super::jobs::new_report("/bin/x", &selection);
        report.specimen_len = Some(10);
        report.specimen_sha256 = Some("ab".repeat(32));
        report
    }

    #[test]
    fn a_deadline_keeps_finished_sections_and_marks_only_the_rest() {
        let directory = std::env::temp_dir().join(format!("ant-progress-{}", std::process::id()));
        let output = directory.join("output");
        fs::create_dir_all(&output).unwrap();
        let expected = report();
        let mut worker = expected.clone();
        worker.sections[0].state = AnalysisSectionState::Complete;
        worker.sections[0].summary = "done".into();
        publish(&output, &worker, Some(1));
        // The host reads the live snapshot without listings.
        let mut live = expected.clone();
        let snapshot = Watch::default().changed(&directory, &live).unwrap();
        merge(&mut live, snapshot, false);
        assert_eq!(live.sections[0].state, AnalysisSectionState::Complete);
        assert_eq!(live.sections[1].summary, "running in the analysis worker");
        // The worker is stopped: finished sections stay, the rest is marked.
        let mut stopped = expected.clone();
        assert!(salvage(&directory, &mut stopped));
        super::super::jobs::fail(&mut stopped, AnalysisState::Partial, "deadline");
        assert_eq!(stopped.sections[0].state, AnalysisSectionState::Complete);
        assert_eq!(stopped.sections[0].summary, "done");
        for section in &stopped.sections[1..] {
            assert_eq!(section.state, AnalysisSectionState::Unavailable);
            assert_eq!(section.summary, "deadline");
        }
        // A snapshot for another report is refused.
        let mut other = expected.clone();
        other.id = "other".into();
        assert!(!salvage(&directory, &mut other));
        let _ = fs::remove_dir_all(&directory);
    }
}

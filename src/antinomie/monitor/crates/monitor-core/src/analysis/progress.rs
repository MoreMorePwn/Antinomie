// SPDX-License-Identifier: GPL-3.0-only
//! Per-section progress of a running worker: the worker publishes the report
//! after every section and the host adopts what is validated, so a deadline or
//! a crash keeps the sections that finished.
mod activity;
use super::*;
pub(super) use activity::{Stage, tool_started};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

/// Name of the worker's progress report in its output directory.
pub(super) const FILE: &str = "progress/progress.json";
/// How often the host looks at a running worker's progress.
const POLL: Duration = Duration::from_secs(2);

/// Worker side: publish `report` with section `running` marked as running
/// (`None` once every section is done). Best effort and atomic.
pub(super) fn publish(directory: &Path, report: &AnalysisReport, running: Option<usize>) {
    let mut snapshot = report.clone();
    snapshot.state = AnalysisState::Running;
    if let Some(section) = running.and_then(|index| snapshot.sections.get_mut(index)) {
        section.state = AnalysisSectionState::Running;
        section.summary = "running in the analysis worker".into();
    }
    let Ok(encoded) = super::worker::bounded_report(&mut snapshot) else {
        return;
    };
    let target = directory.join(FILE);
    let temporary = directory.join("progress/.progress.tmp");
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
        if self.seen == Some(stamp)
            && !expected
                .sections
                .iter()
                .any(|s| s.state == AnalysisSectionState::Running)
        {
            return None;
        }
        let mut report = super::jobs::read_report(&path, expected, false).ok()?;
        activity::annotate(&directory.join("output/progress"), &mut report);
        self.seen = Some(stamp);
        Some(report)
    }
}

/// Take the finished sections of `progress` into `report`. `keep_listings`
/// false drops listing references (the files are not validated yet).
pub(super) fn merge(report: &mut AnalysisReport, progress: AnalysisReport, keep_listings: bool) {
    for (section, new) in report.sections.iter_mut().zip(progress.sections) {
        // What the host already holds finished is not the worker's to change;
        // checks added to a finished analysis carry those sections along.
        if !matches!(
            section.state,
            AnalysisSectionState::Pending | AnalysisSectionState::Running
        ) {
            continue;
        }
        let finished = !matches!(
            new.state,
            AnalysisSectionState::Pending | AnalysisSectionState::Running
        );
        if finished
            || matches!(
                section.state,
                AnalysisSectionState::Pending | AnalysisSectionState::Running
            )
        {
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
    let finished = progress.sections.iter().any(|section| {
        !matches!(
            section.state,
            AnalysisSectionState::Pending | AnalysisSectionState::Running
        )
    });
    merge(report, progress, true);
    finished
}

impl super::jobs::Job {
    /// A deadline stops the worker, not the sections it already finished:
    /// adopt them (and their validated listings) before the rest is marked
    /// unfinished.
    pub(super) fn keep_finished_sections(&mut self) {
        if progress::salvage(&self.directory, &mut self.report) {
            super::jobs::adopt_listings(
                &self.directory,
                &mut self.report,
                super::jobs::carried(&self.supplement),
            );
        }
    }
}

/// Preserve report/tab order, but finish inexpensive checks before the two
/// heavyweight whole-program analyzers. Within each tier retain user order.
pub(super) fn execution_order(report: &AnalysisReport) -> Vec<usize> {
    let mut indices: Vec<_> = (0..report.sections.len()).collect();
    indices.sort_by_key(|&i| match report.sections[i].kind {
        AnalysisKind::Metadata
        | AnalysisKind::Structures
        | AnalysisKind::Strings
        | AnalysisKind::Regex
        | AnalysisKind::Entropy
        | AnalysisKind::Hardening => 0,
        AnalysisKind::Rules | AnalysisKind::Identification | AnalysisKind::Unpacking => 1,
        AnalysisKind::Embedded | AnalysisKind::Disassembly => 2,
        AnalysisKind::Capabilities | AnalysisKind::Floss => 3,
        AnalysisKind::Decompilation => 4,
    });
    indices
}

/// [`execution_order`] of the checks still to run: a report that already has
/// finished sections (checks added later) keeps them as they are.
pub(super) fn pending_order(report: &AnalysisReport) -> Vec<usize> {
    let mut order = execution_order(report);
    order.retain(|&index| report.sections[index].state == AnalysisSectionState::Pending);
    order
}

pub(crate) fn worker_deadline(report: &AnalysisReport) -> Duration {
    // The sum of the sections' own budgets, so one slow tool (capa at 4
    // minutes) cannot use up the time of a later one (decompilation); this is
    // the hard backstop behind each tool's own timeout. A time limit the run
    // asked for replaces each tool's own.
    let own = |default: u64| super::limits::seconds_in(report, default);
    let seconds: u64 = report
        .sections
        .iter()
        // Checks a finished analysis already has are not run again.
        .filter(|section| section.state == AnalysisSectionState::Pending)
        .map(|section| match section.kind {
            AnalysisKind::Decompilation => own(super::worker::DECOMPILER_SECONDS) + 120,
            AnalysisKind::Capabilities => own(super::capa::TIMEOUT_SECONDS) + 60,
            AnalysisKind::Floss => own(super::floss::TIMEOUT_SECONDS) + 60,
            AnalysisKind::Unpacking => own(super::unpack::BUDGET_SECONDS) + 30,
            AnalysisKind::Embedded => own(super::binwalk::TIMEOUT_SECONDS) + 20,
            AnalysisKind::Identification => own(60) * 2 + 40,
            AnalysisKind::Disassembly | AnalysisKind::Rules => own(60) + 30,
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
            time_limit_minutes: 0,
        };
        let mut report = super::super::jobs::new_report("/bin/x", &selection);
        report.specimen_len = Some(10);
        report.specimen_sha256 = Some("ab".repeat(32));
        report
    }

    #[test]
    fn light_checks_finish_before_whole_program_tools_without_reordering_the_report() {
        let mut report = report();
        let kinds = [
            AnalysisKind::Decompilation,
            AnalysisKind::Capabilities,
            AnalysisKind::Disassembly,
            AnalysisKind::Rules,
            AnalysisKind::Metadata,
            AnalysisKind::Identification,
            AnalysisKind::Embedded,
            AnalysisKind::Floss,
        ];
        report.sections = kinds.iter().copied().map(AnalysisSection::new).collect();
        let order = execution_order(&report);
        // Capa and FLOSS keep their relative order; Ghidra comes last.
        assert_eq!(order, [4, 3, 5, 2, 6, 1, 7, 0]);
        assert_eq!(
            report.sections.iter().map(|s| s.kind).collect::<Vec<_>>(),
            kinds
        );
    }

    #[test]
    fn checks_added_to_a_finished_analysis_run_alone_and_leave_the_rest_as_it_is() {
        let mut report = report();
        report.sections = [
            AnalysisKind::Decompilation,
            AnalysisKind::Strings,
            AnalysisKind::Capabilities,
        ]
        .map(AnalysisSection::new)
        .to_vec();
        report.sections[0].state = AnalysisSectionState::Complete;
        report.sections[0].listing = Some(AnalysisListing {
            rows: 3,
            bytes: 30,
            truncated: false,
        });
        // Only the pending checks run, and only they count toward the deadline.
        assert_eq!(pending_order(&report), [1, 2]);
        assert_eq!(worker_deadline(&report), Duration::from_secs(20 + 300));
        // A time limit of the run replaces the tool's own, capa's 4 minutes.
        report.time_limit_seconds = Some(600);
        assert_eq!(worker_deadline(&report), Duration::from_secs(20 + 660));
        report.time_limit_seconds = None;
        // A live snapshot does not take the finished section's listing away.
        let mut snapshot = report.clone();
        snapshot.state = AnalysisState::Running;
        snapshot.sections[1].state = AnalysisSectionState::Complete;
        merge(&mut report, snapshot, false);
        assert!(report.sections[0].listing.is_some());
        assert_eq!(report.sections[1].state, AnalysisSectionState::Complete);
    }

    #[test]
    fn a_deadline_keeps_finished_sections_and_marks_only_the_rest() {
        let directory = std::env::temp_dir().join(format!("ant-progress-{}", std::process::id()));
        let output = directory.join("output");
        fs::create_dir_all(output.join("progress")).unwrap();
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
        assert_eq!(live.sections[1].state, AnalysisSectionState::Running);
        assert_eq!(live.sections[1].summary, "running in the analysis worker");
        assert_eq!(live.sections[2].state, AnalysisSectionState::Pending);
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

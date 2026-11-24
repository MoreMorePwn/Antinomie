// SPDX-License-Identifier: GPL-3.0-only
//! A worker that is gone, or that gives no sign of life for far longer than
//! its check may take, ends its job instead of leaving the analysis
//! "running" with a frozen elapsed time (item 36, 2026-11-14).
//!
//! The job normally learns that its worker ended from
//! [`SandboxProcess::poll_status`], which waits until the sandbox's namespace
//! is proved gone. When the launcher has ended but that proof does not come
//! (the namespace init was never pinned, for one), the job waited for ever.
//! Now a launcher seen ended for [`GONE_GRACE`] closes the check that was
//! running as failed, with how the worker ended, and the job finishes; the
//! cleanup that follows still owns what is left of the sandbox.
//!
//! The worker publishes its progress after each check and names each tool it
//! starts. A worker whose progress files have not changed for twice its
//! running check's budget and two minutes more is taken as hung: it is
//! stopped the way a deadline stops it, and the check is closed the same way.
use super::*;
use std::time::SystemTime;

/// How long the launcher may be seen ended before the job stops waiting for
/// the proof that its namespace is gone.
pub(super) const GONE_GRACE: Duration = Duration::from_secs(3);
/// How often the progress files are looked at.
const LOOK_EVERY: Duration = Duration::from_secs(1);

/// What a running job has seen of its worker.
#[derive(Default)]
pub(super) struct Liveness {
    /// When the launcher was first seen ended.
    gone: Option<Instant>,
    /// The progress files' modification times when last looked at.
    stamps: Option<[Option<SystemTime>; 2]>,
    /// When they last changed (or when the job started watching).
    changed_at: Option<Instant>,
    looked_at: Option<Instant>,
    /// Why the worker is being stopped as hung.
    pub(super) stalled: Option<String>,
}

/// What [`Liveness::check`] found.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Verdict {
    Alive,
    /// The worker ended: its exit code or signal.
    Gone(Option<i32>, Option<i32>),
    /// The worker gives no sign of life; why.
    Stalled(String),
}

/// "signal 9" or "exit 1" for a launcher's end. bubblewrap ends with 128 + N
/// when its program was killed by signal N.
pub(super) fn ended_text(exit: Option<i32>, signal: Option<i32>) -> String {
    match (signal, exit) {
        (Some(signal), _) => format!("signal {signal}"),
        (None, Some(code)) if (129..160).contains(&code) => format!("signal {}", code - 128),
        (None, Some(code)) => format!("exit {code}"),
        (None, None) => "no exit status".into(),
    }
}

/// The reason a check and its analysis carry when the worker ended under it.
pub(super) fn stopped_text(how: &str) -> String {
    format!("the analysis worker stopped unexpectedly ({how})")
}

impl Liveness {
    /// Look at the worker of a job still running `report` in `directory`:
    /// `ended` is how its launcher ended, when it has.
    pub(super) fn check(
        &mut self,
        ended: Option<(Option<i32>, Option<i32>)>,
        directory: &Path,
        report: &AnalysisReport,
        now: Instant,
    ) -> Verdict {
        if let Some((exit, signal)) = ended {
            let since = *self.gone.get_or_insert(now);
            if now.duration_since(since) >= GONE_GRACE {
                return Verdict::Gone(exit, signal);
            }
            return Verdict::Alive;
        }
        if self
            .looked_at
            .is_some_and(|at| now.duration_since(at) < LOOK_EVERY)
        {
            return Verdict::Alive;
        }
        self.looked_at = Some(now);
        let progress = directory.join("output/progress");
        let stamp = |name: &str| {
            fs::symlink_metadata(progress.join(name))
                .and_then(|metadata| metadata.modified())
                .ok()
        };
        let stamps = [stamp("progress.json"), stamp("current.json")];
        if self.stamps != Some(stamps) || self.changed_at.is_none() {
            self.stamps = Some(stamps);
            self.changed_at = Some(now);
            return Verdict::Alive;
        }
        let Some(section) = report
            .sections
            .iter()
            .find(|section| section.state == AnalysisSectionState::Running)
        else {
            return Verdict::Alive;
        };
        let quiet = now.duration_since(self.changed_at.unwrap_or(now));
        let limit = stall_limit(super::super::progress::check_budget(report, section.kind));
        if quiet < limit {
            return Verdict::Alive;
        }
        Verdict::Stalled(format!(
            "the analysis worker stopped responding during {} (no progress for {} s)",
            section.kind.label(),
            quiet.as_secs()
        ))
    }
}

/// How long a worker may go without any progress while one check runs:
/// twice the check's budget and two minutes more. The worker stops each tool
/// at its own time limit, so a worker this quiet is hung.
fn stall_limit(budget_seconds: u64) -> Duration {
    Duration::from_secs(budget_seconds.saturating_mul(2).saturating_add(120))
}

impl Job {
    /// The worker ended with `exit` or `signal`: a clean exit hands over its
    /// report; any other end closes the check it was running as failed.
    pub(super) fn worker_ended(&mut self, exit: Option<i32>, signal: Option<i32>) {
        if exit != Some(0) || signal.is_some() {
            self.close_stopped_worker(&stopped_text(&ended_text(exit, signal)));
            return;
        }
        match read_report(
            &self.directory.join("output/report.json"),
            &self.report,
            true,
        ) {
            Ok(report) => {
                self.report = report;
                adopt_listings(
                    &self.directory,
                    &mut self.report,
                    supplement::carried(&self.supplement),
                );
            }
            Err(error) => fail(&mut self.report, AnalysisState::Unavailable, error),
        }
    }

    /// The worker ended (or was stopped as hung) with checks still to do:
    /// what it finished is kept, the check it was running fails with
    /// `reason`, and the checks it never started are marked not run, to be
    /// run again from their tabs.
    pub(super) fn close_stopped_worker(&mut self, reason: &str) {
        self.keep_finished_sections();
        let not_run = format!("not run: {reason}; run this check again from its tab");
        for section in &mut self.report.sections {
            match section.state {
                AnalysisSectionState::Running => {
                    section.state = AnalysisSectionState::Unavailable;
                    section.summary = reason.to_owned();
                }
                AnalysisSectionState::Pending => {
                    section.state = AnalysisSectionState::Unavailable;
                    section.summary = not_run.clone();
                }
                _ => {}
            }
        }
        let kept = self
            .report
            .sections
            .iter()
            .any(|section| section.state.has_result());
        fail(
            &mut self.report,
            if kept {
                AnalysisState::Partial
            } else {
                AnalysisState::Unavailable
            },
            format!("{reason}; see worker.log"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job_for(report: AnalysisReport, directory: &Path) -> Job {
        Job {
            run_id: None,
            report,
            directory: directory.to_path_buf(),
            handle: None,
            total_len: 0,
            received_len: 0,
            file: None,
            deadline: Instant::now() + Duration::from_secs(600),
            child: None,
            cleanup_reason: None,
            reserved_len: 0,
            digest: Sha256::new(),
            disk_len: 0,
            worker_len: 0,
            report_len: 0,
            specimen_publication: None,
            progress: Default::default(),
            liveness: Default::default(),
            host_copy: None,
            supplement: None,
            rules_use: None,
        }
    }

    #[test]
    fn the_way_a_worker_ended_reads_as_a_signal_or_an_exit_code() {
        assert_eq!(ended_text(None, Some(9)), "signal 9");
        // bubblewrap passes on a signal as 128 + N.
        assert_eq!(ended_text(Some(137), None), "signal 9");
        assert_eq!(ended_text(Some(1), None), "exit 1");
        assert_eq!(
            stopped_text("signal 9"),
            "the analysis worker stopped unexpectedly (signal 9)"
        );
    }

    fn running_report() -> AnalysisReport {
        let mut report = new_report(
            "/bin/x",
            &AnalysisSelection {
                enabled: true,
                checks: vec![AnalysisKind::Metadata, AnalysisKind::Rules],
                time_limit_minutes: 0,
                limits: Default::default(),
            },
        );
        report.state = AnalysisState::Running;
        report.sections[1].state = AnalysisSectionState::Running;
        report
    }

    /// A launcher that ended is not waited on for ever: after the grace the
    /// verdict is Gone, with how it ended.
    #[test]
    fn a_launcher_seen_ended_for_the_grace_means_the_worker_is_gone() {
        let directory = std::env::temp_dir().join(format!("ant-live-{}", storage::unique_id()));
        let report = running_report();
        let mut liveness = Liveness::default();
        let start = Instant::now();
        assert_eq!(
            liveness.check(None, &directory, &report, start),
            Verdict::Alive
        );
        let ended = Some((Some(137), None));
        assert_eq!(
            liveness.check(ended, &directory, &report, start + Duration::from_secs(1)),
            Verdict::Alive
        );
        assert_eq!(
            liveness.check(ended, &directory, &report, start + Duration::from_secs(5)),
            Verdict::Gone(Some(137), None)
        );
    }

    /// No progress for far longer than the running check may take is a hung
    /// worker; a change of the progress files starts the count again.
    #[test]
    fn a_worker_without_progress_for_twice_its_check_budget_is_stalled() {
        let directory = std::env::temp_dir().join(format!("ant-stall-{}", storage::unique_id()));
        let progress = directory.join("output/progress");
        fs::create_dir_all(&progress).unwrap();
        let report = running_report();
        let budget = super::super::super::progress::check_budget(&report, AnalysisKind::Rules);
        let limit = stall_limit(budget);
        let mut liveness = Liveness::default();
        let start = Instant::now();
        assert_eq!(
            liveness.check(None, &directory, &report, start),
            Verdict::Alive
        );
        let late = start + limit - Duration::from_secs(1);
        assert_eq!(
            liveness.check(None, &directory, &report, late),
            Verdict::Alive
        );
        fs::write(progress.join("current.json"), "{}").unwrap();
        let after = start + limit + Duration::from_secs(1);
        assert_eq!(
            liveness.check(None, &directory, &report, after),
            Verdict::Alive,
            "a new progress file is a sign of life"
        );
        let Verdict::Stalled(why) = liveness.check(
            None,
            &directory,
            &report,
            after + limit + Duration::from_secs(1),
        ) else {
            panic!("not stalled");
        };
        assert!(
            why.contains("stopped responding during Rule matches"),
            "{why}"
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// The finished checks stay, the running one fails with the reason, the
    /// rest are marked not run.
    #[test]
    fn a_stopped_worker_closes_its_running_check_as_failed() {
        let directory = std::env::temp_dir().join(format!("ant-close-{}", storage::unique_id()));
        fs::create_dir_all(&directory).unwrap();
        let mut report = running_report();
        report
            .sections
            .push(AnalysisSection::new(AnalysisKind::Strings));
        report.sections[0].state = AnalysisSectionState::Complete;
        let mut job = job_for(report, &directory);
        let reason = stopped_text("signal 9");
        job.close_stopped_worker(&reason);
        assert_eq!(job.report.state, AnalysisState::Partial);
        assert_eq!(job.report.sections[0].state, AnalysisSectionState::Complete);
        assert_eq!(
            job.report.sections[1].state,
            AnalysisSectionState::Unavailable
        );
        assert_eq!(job.report.sections[1].summary, reason);
        assert!(
            job.report.sections[2]
                .summary
                .starts_with("not run: the analysis worker stopped unexpectedly (signal 9)")
        );
        assert!(
            job.report
                .reason
                .as_deref()
                .is_some_and(|r| r.starts_with(&reason))
        );
        let _ = fs::remove_dir_all(&directory);
    }

    /// The frozen analysis of 2026-11-14, reproduced: a fake worker that
    /// publishes its progress (one check done, the next running) and is
    /// killed mid-check. The job closes the running check as failed with how
    /// the worker ended, keeps the finished one, and ends; it never stays
    /// "running".
    #[test]
    #[ignore = "requires installed bubblewrap and usable user namespaces"]
    fn a_worker_killed_mid_check_ends_its_analysis_with_the_reason() {
        let directory = std::env::temp_dir().join(format!("ant-killed-{}", storage::unique_id()));
        storage::private_dir(&directory).unwrap();
        let specimen = fs::read("/usr/bin/true").unwrap();
        fs::write(directory.join("specimen"), &specimen).unwrap();
        let mut report = running_report();
        report.state = AnalysisState::Running;
        report.sections[1].state = AnalysisSectionState::Pending;
        report.specimen_len = Some(specimen.len() as u64);
        report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
        // What the worker publishes: Metadata done, Rules running.
        let mut done = report.clone();
        done.sections[0].state = AnalysisSectionState::Complete;
        done.sections[0].summary = "done".into();
        let staging = directory.join("staging");
        fs::create_dir_all(staging.join("progress")).unwrap();
        super::super::super::progress::publish(&staging, &done, Some(1));
        let published = fs::read_to_string(staging.join("progress/progress.json")).unwrap();
        let worker = directory.join("worker-fixture");
        fs::write(
            &worker,
            format!(
                "#!/bin/sh\ncat > /output/progress/progress.json <<'JSON'\n{published}\nJSON\nsleep 1\nkill -KILL $$\n"
            ),
        )
        .unwrap();
        crate::test_exec::make_executable(&worker, 0o700);
        let mut job = job_for(report, &directory);
        job.total_len = specimen.len() as u64;
        job.received_len = specimen.len() as u64;
        job.child = Some(spawn_worker_binary(&job, &worker, None).unwrap());
        let mut jobs = Jobs::default();
        jobs.active = Some(job);
        let started = Instant::now();
        while jobs.active.is_some() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "the analysis stayed running"
            );
            jobs.worker_tick();
            std::thread::sleep(Duration::from_millis(20));
        }
        let report = jobs.updates().pop().unwrap().1;
        let reason = report.reason.clone().unwrap_or_default();
        assert_eq!(report.state, AnalysisState::Partial, "{reason}");
        assert!(
            reason.contains("the analysis worker stopped unexpectedly (signal 9)"),
            "{reason}"
        );
        assert_eq!(report.sections[0].state, AnalysisSectionState::Complete);
        assert_eq!(report.sections[1].state, AnalysisSectionState::Unavailable);
        assert_eq!(
            report.sections[1].summary,
            "the analysis worker stopped unexpectedly (signal 9)"
        );
        let _ = fs::remove_dir_all(&directory);
    }
}

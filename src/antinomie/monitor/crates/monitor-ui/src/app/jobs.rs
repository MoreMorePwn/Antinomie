// SPDX-License-Identifier: GPL-3.0-only
//! The Jobs window's side of the app: what is running now, read from the jobs
//! the app already keeps (the backend snapshot, the export worker, the rules
//! window, Triage, the Memory tab, the Samples page), the way a job is
//! stopped or opened, and the list the quit confirmation shows.
use super::*;
use crate::{
    jobs::{Job, Outcome, Request, Stop},
    run_state_line::now_ms,
    toasts::{Action, Then},
};
use antinomie_monitor_core::{
    analysis::{AnalysisSectionState, AnalysisState},
    disks::{DiskJobPurpose, DiskJobStage},
    RunArtifactState,
};

fn file_name(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
}

impl MonitorApp {
    pub(crate) fn jobs_title(&self) -> egui::WidgetText {
        self.jobs.title(self.settings.font_size)
    }

    pub(super) fn jobs_panel(&mut self, ui: &mut egui::Ui) {
        if let Some(request) = self.jobs.show(ui) {
            match request {
                Request::Open(action) => self.follow_toast_action(action),
                Request::Stop(key) => self.stop_job(&key),
            }
        }
    }

    fn vm_name(&self, vm_id: &str) -> String {
        self.snapshot
            .vms
            .iter()
            .find(|vm| vm.id == vm_id)
            .map_or_else(|| vm_id.chars().take(8).collect(), |vm| vm.name.clone())
    }

    /// Read this frame's jobs and move the ones that ended to Finished.
    pub(super) fn jobs_tick(&mut self, ctx: &egui::Context) {
        let now = now_ms();
        let jobs = self.collect_jobs();
        let mut board = std::mem::take(&mut self.jobs);
        board.update(now, jobs, |job, stopped| self.job_outcome(job, stopped));
        self.jobs = board;
        // The elapsed time ticks while the window is on screen.
        if self.jobs.take_drawn() {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }

    fn collect_jobs(&self) -> Vec<Job> {
        let snapshot = &self.snapshot;
        let mut jobs = Vec::new();

        // Programs running in the guest, and runs still recording after the
        // root exited.
        for run in &snapshot.runs {
            let live = matches!(
                run.state,
                RunState::Running | RunState::StopRequested | RunState::TerminalClosed
            ) || (run.state == RunState::Unknown && run.root_task_cookie == 0);
            if !live {
                continue;
            }
            let alive = run
                .execution
                .as_ref()
                .map(|execution| execution.live_task_count);
            let rooted = run
                .execution
                .as_ref()
                .is_some_and(|execution| execution.root_exit.is_some());
            let mut state = match (run.state.clone(), rooted) {
                (RunState::StopRequested, _) => "Stop requested".to_owned(),
                (RunState::Unknown, _) => "Starting".to_owned(),
                (_, true) => "Root exited, still recording".to_owned(),
                (RunState::TerminalClosed, false) => "Terminal closed, still recording".to_owned(),
                _ => "Running".to_owned(),
            };
            if let Some(alive) = alive.filter(|count| *count > 0) {
                state.push_str(&format!(
                    ", {alive} process{} alive",
                    if alive == 1 { "" } else { "es" }
                ));
            }
            let mut job = Job::new(
                format!("run:{}", run.id),
                "Run",
                format!(
                    "{} on {}",
                    file_name(&run.request.path),
                    self.vm_name(&run.vm_id)
                ),
            )
            .started(run.started_ms)
            .state(state)
            .open_action(Action {
                label: "Open Triage".into(),
                panel: Panel::Triage,
                then: Some(Then::Run {
                    vm_id: run.vm_id.clone(),
                    run_id: run.id.clone(),
                }),
            });
            if actionable_run(run, snapshot) {
                job = job.stop(Stop::Run(run.id.clone()));
            }
            jobs.push(job);
        }

        // The VM starting or stopping.
        let active_name = snapshot
            .active_vm
            .as_deref()
            .map(|id| self.vm_name(id))
            .unwrap_or_default();
        match snapshot.state {
            VmState::Starting => {
                let slow = snapshot
                    .accelerator
                    .as_ref()
                    .is_some_and(|used| used.record.starts_with("tcg"));
                let state = match (&snapshot.start_note, slow) {
                    (Some(note), _) => note.clone(),
                    (None, true) => "Starting (TCG boot, no KVM: waiting for the guest)".into(),
                    (None, false) => "Starting".into(),
                };
                jobs.push(
                    Job::new("vm-start", "VM start", active_name.clone())
                        .state(state)
                        .stop(Stop::Vm),
                );
            }
            VmState::Stopping => jobs.push(
                Job::new("vm-stop", "VM stop", active_name.clone())
                    .state("Waiting for the guest to shut down"),
            ),
            _ => {}
        }
        if let Some(progress) = &snapshot.vm_snapshot_progress {
            jobs.push(
                Job::new("vm-snapshot", "VM snapshot", self.vm_name(&progress.vm_id))
                    .state(progress.stage.clone()),
            );
        }
        if let Some(layout) = &snapshot.base_layout {
            jobs.push(
                Job::new("base-layout", "Base disk layout", layout.base.clone())
                    .state(layout.stage.clone())
                    .open(Panel::Library(LibraryPage::BaseImages)),
            );
        }
        if let Some(flush) = &snapshot.recording_flush {
            jobs.push(
                Job::new("recording-flush", "Saving recordings", "the stopped boot")
                    .state(flush.label())
                    .progress(flush.done_count as u64, flush.total_count as u64)
                    .open(Panel::RunHistory),
            );
        }

        // Memory dump and process cores.
        if let Some(dump) = &snapshot.memory_dump {
            jobs.push(
                Job::new("memory-dump", "Memory dump", dump.dump.vm_name.clone())
                    .started(Some(dump.dump.started_ms))
                    .state(dump.status_text())
                    .progress(dump.completed, dump.total)
                    .open(Panel::Memory),
            );
        }
        for core in &snapshot.process_cores {
            let armed = matches!(
                core.state,
                RunArtifactState::WaitingForTreeExit | RunArtifactState::WaitingForRootExit
            );
            let going = armed
                || matches!(
                    core.state,
                    RunArtifactState::Recording
                        | RunArtifactState::Queued
                        | RunArtifactState::InProgress
                );
            if !going {
                continue;
            }
            let program = core
                .source_run_id
                .as_ref()
                .and_then(|id| snapshot.runs.iter().find(|run| &run.id == id))
                .map(|run| file_name(&run.request.path).to_owned())
                .unwrap_or_default();
            let target = format!("PID {} {program}", core.target.tgid);
            let state = if armed {
                "Armed: dumps when the process exits".to_owned()
            } else {
                format!("{:?}", core.phase)
            };
            jobs.push(
                Job::new(format!("core:{}", core.id), "Process core", target.trim())
                    .state(state)
                    .progress(core.stored_size, u64::from(core.max_size))
                    .stop(Stop::Command(Command::CancelCoreCapture {
                        capture_id: core.id.clone(),
                    }))
                    .open(Panel::CoreDump),
            );
        }

        // Static analysis checks of every report still being made.
        let mut seen = BTreeSet::new();
        for report in snapshot
            .runs
            .iter()
            .filter_map(|run| run.analysis.as_ref())
            .chain(&snapshot.analysis_reports)
        {
            if !matches!(
                report.state,
                AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
            ) || !seen.insert(report.id.clone())
            {
                continue;
            }
            let total = report.sections.len();
            let done = report
                .sections
                .iter()
                .filter(|section| {
                    !matches!(
                        section.state,
                        AnalysisSectionState::Pending | AnalysisSectionState::Running
                    )
                })
                .count();
            let running: Vec<&str> = report
                .sections
                .iter()
                .filter(|section| section.state == AnalysisSectionState::Running)
                .map(|section| section.kind.label())
                .collect();
            let state = match report.state {
                AnalysisState::Acquiring => "Getting the file".to_owned(),
                AnalysisState::Queued => "Queued".to_owned(),
                _ if running.is_empty() => format!("{done} of {total} checks done"),
                _ => format!("{} ({done} of {total} done)", running.join(", ")),
            };
            jobs.push(
                Job::new(
                    format!("analysis:{}", report.id),
                    "Static analysis",
                    file_name(&report.source_path),
                )
                .state(state)
                .progress(done as u64, total as u64)
                .stop(Stop::Command(Command::CancelAnalysis {
                    analysis_id: report.id.clone(),
                }))
                .open(Panel::StaticAnalysis),
            );
        }

        // Downloads, installs, builds.
        if let Some(download) = snapshot.download.as_ref().filter(|d| !d.finished) {
            let state = if download.installing {
                "Installing".to_owned()
            } else if !download.note.is_empty() {
                download.note.clone()
            } else {
                "Downloading".to_owned()
            };
            let mut job = Job::new("download", "Base download", download.label.clone())
                .state(state)
                .progress(download.received, download.total)
                .open(Panel::Library(LibraryPage::BaseImages));
            if !download.installing {
                job = job.stop(Stop::Command(Command::CancelDownload));
            }
            jobs.push(job);
        }
        if snapshot.remote_refreshing {
            jobs.push(
                Job::new("catalog-refresh", "Catalog refresh", "remote base catalog")
                    .state("Downloading")
                    .stop(Stop::Command(Command::CancelRefresh))
                    .open(Panel::Library(LibraryPage::BaseImages)),
            );
        }
        if let Some(build) = snapshot.build.as_ref().filter(|b| !b.finished) {
            jobs.push(
                Job::new("build", "Base build", build.label.clone())
                    .state(format!("Stage: {}", build.stage))
                    .stop(Stop::Command(Command::CancelBuild))
                    .open(Panel::Library(LibraryPage::BaseImages)),
            );
        }
        if let Some(install) = snapshot.tool_install.as_ref().filter(|i| !i.finished) {
            let state = if install.note.is_empty() {
                install.stage.clone()
            } else {
                install.note.clone()
            };
            jobs.push(
                Job::new("tool-install", "Tool install", install.name.clone())
                    .state(state)
                    .progress(install.received, install.total)
                    .stop(Stop::Command(Command::CancelToolInstall))
                    .open(Panel::Library(LibraryPage::Tools)),
            );
        }
        if let Some(disk) = &snapshot.disk_job {
            let purpose = match disk.purpose {
                DiskJobPurpose::Measure => "Measuring the disk",
                DiskJobPurpose::View => "Opening the disk view",
                DiskJobPurpose::Dump => "Making a disk dump",
                DiskJobPurpose::Keep => "Keeping the view as a dump",
                DiskJobPurpose::Reference => "Opening the comparison disk",
                DiskJobPurpose::Carve => "Saving a partition",
                DiskJobPurpose::Import => "Importing a disk",
            };
            let mut job = Job::new("disk-job", "Disk job", self.vm_name(&disk.vm_id))
                .started(Some(disk.started_ms))
                .stop(Stop::Command(Command::CancelDiskJob {
                    vm_id: disk.vm_id.clone(),
                }))
                .open(Panel::Disks);
            job = match &disk.stage {
                DiskJobStage::Measuring => job.state(purpose),
                DiskJobStage::Converting { percent } => job
                    .state(format!("{purpose}: converting"))
                    .fraction(percent / 100.0),
                DiskJobStage::Hashing { done, total } => job
                    .state(format!("{purpose}: hashing"))
                    .progress(*done, *total),
                DiskJobStage::Finalizing => job.state(format!("{purpose}: finishing")),
            };
            jobs.push(job);
        }

        // Work the windows own.
        if let Some((kind, label)) = self.evidence_jobs.running() {
            jobs.push(
                Job::new("evidence", kind, label)
                    .state("Working")
                    .open(Panel::StaticAnalysis),
            );
        }
        if let Some((text, cancel)) = self.rules_ui.running_job() {
            jobs.push(
                Job::new("rules", "Rules and datasets", text)
                    .state("Downloading or installing")
                    .flag(Some(cancel))
                    .open(Panel::Library(LibraryPage::Rules)),
            );
        }
        jobs.extend(self.triage.running_jobs());
        jobs.extend(self.memory_view.running_jobs());
        jobs.extend(self.core_view.running_jobs());
        jobs.extend(self.samples.running_jobs());
        if let Some(cancel) = self.updates.running_check() {
            jobs.push(
                Job::new("update-check", "Update check", "Antinomie releases")
                    .state("Asking")
                    .flag(Some(cancel)),
            );
        }
        jobs
    }

    /// How a job that is gone ended.
    fn job_outcome(&self, job: &Job, stopped: bool) -> (Outcome, String) {
        let snapshot = &self.snapshot;
        let failed = |error: &Option<String>| match error {
            Some(error) => (Outcome::Failed, error.clone()),
            None if stopped => (Outcome::Cancelled, "Stopped by you".into()),
            None => (Outcome::Finished, String::new()),
        };
        let key = job.key.as_str();
        if let Some(id) = key.strip_prefix("run:") {
            let run = snapshot
                .runs
                .iter()
                .chain(&self.history)
                .find(|run| run.id == id);
            return match run {
                Some(run) => {
                    let detail = run_state_text::run_status(run).to_owned();
                    match run.state {
                        RunState::FailedToStart
                        | RunState::LaunchUnconfirmed
                        | RunState::Interrupted => (
                            Outcome::Failed,
                            run.recording_error.clone().unwrap_or(detail),
                        ),
                        RunState::Stopped if stopped => {
                            (Outcome::Cancelled, "Stopped by you".into())
                        }
                        _ => (Outcome::Finished, detail),
                    }
                }
                None => (Outcome::Finished, "The run ended".into()),
            };
        }
        if let Some(id) = key.strip_prefix("analysis:") {
            return match self.analysis_report(id) {
                Some(report) => match report.state {
                    AnalysisState::Unavailable => (
                        Outcome::Failed,
                        report
                            .reason
                            .clone()
                            .unwrap_or_else(|| "Unavailable".into()),
                    ),
                    AnalysisState::Cancelled => (Outcome::Cancelled, "Cancelled".into()),
                    AnalysisState::Partial => {
                        (Outcome::Finished, "Some checks did not finish".into())
                    }
                    _ => (Outcome::Finished, "All checks done".into()),
                },
                None => (Outcome::Finished, String::new()),
            };
        }
        if let Some(id) = key.strip_prefix("core:") {
            return match snapshot.process_cores.iter().find(|core| core.id == id) {
                Some(core) => match core.state {
                    RunArtifactState::Failed | RunArtifactState::Interrupted => (
                        Outcome::Failed,
                        core.issue
                            .clone()
                            .unwrap_or_else(|| format!("{:?}", core.state)),
                    ),
                    RunArtifactState::Partial => (Outcome::Finished, "Partial core".into()),
                    _ if stopped => (Outcome::Cancelled, "Stopped by you".into()),
                    _ => (Outcome::Finished, "Core saved".into()),
                },
                None => (Outcome::Finished, String::new()),
            };
        }
        if let Some(id) = key.strip_prefix("plugin:") {
            if let Some((outcome, detail)) = self.memory_view.plugin_outcome(id) {
                return (outcome, detail);
            }
        }
        match key {
            "download" => failed(&snapshot.download.as_ref().and_then(|d| d.error.clone())),
            "build" => failed(&snapshot.build.as_ref().and_then(|b| b.error.clone())),
            "tool-install" => failed(&snapshot.tool_install.as_ref().and_then(|i| i.error.clone())),
            "vm-start" => match snapshot.state {
                VmState::Failed => (
                    Outcome::Failed,
                    snapshot
                        .last_error
                        .clone()
                        .unwrap_or_else(|| "Failed".into()),
                ),
                _ if stopped => (Outcome::Cancelled, "Stopped by you".into()),
                _ => (Outcome::Finished, "The VM is up".into()),
            },
            _ if stopped => (Outcome::Cancelled, "Stopped by you".into()),
            _ => (Outcome::Finished, String::new()),
        }
    }

    /// The Stop button of a running job.
    fn stop_job(&mut self, key: &str) {
        let Some(stop) = self.jobs.job(key).and_then(|job| job.stop.clone()) else {
            return;
        };
        match stop {
            Stop::Flag(flag) => {
                crate::jobs::raise(&flag);
                self.jobs.mark_stopping(key);
            }
            Stop::Command(command) => {
                self.send(command);
                self.jobs.mark_stopping(key);
            }
            Stop::Run(id) => self.request_kill(Some(&id)),
            Stop::Vm => {
                self.send(Command::Stop);
                self.jobs.mark_stopping(key);
            }
            Stop::Call(call) => {
                call();
                self.jobs.mark_stopping(key);
            }
        }
    }

    /// The running jobs, one line each, for the quit confirmation.
    pub(super) fn quit_lines(&self) -> Vec<String> {
        self.jobs.lines(now_ms())
    }
}

fn actionable_run(run: &RunSummary, snapshot: &Snapshot) -> bool {
    snapshot.state == VmState::Running
        && snapshot.active_vm.as_ref() == Some(&run.vm_id)
        && snapshot.boot_id.as_ref() == Some(&run.boot_id)
        && run.root_task_cookie != 0
        && matches!(run.state, RunState::Running | RunState::TerminalClosed)
}

// SPDX-License-Identifier: GPL-3.0-only
//! One program on one VM, from the library to a settled recording (design
//! 4.1 stages `provision` to `collect`, 5.6 engine states; audit G5, G6): the
//! part of a job that touches the engine, written once for `run exec` and,
//! later, for the lane.
//!
//! The stages, with the deadlines of 4.1:
//!
//! | Stage | Does | Ends when | Deadline |
//! |---|---|---|---|
//! | `provision` | boots the VM if allowed and needed | `Running` and the guest kernel answered | `boot_limit` |
//! | `upload` | `UploadSample` from the library | the result; "read-only file system" is retried | 60 s |
//! | `launch` | `Execute` with the sample linked | a new run in the snapshot | 30 s |
//!
//! The upload, launch and guest-answer waits are KVM times: under TCG they
//! are stretched by the engine's own factor ([`Waiter::guest_wait`]), and the
//! silence limit of a guest command does not count the engine's boot wait.
//! | `run` | reads the terminal, sends `StopRun` at the limit | run ended and no live task | `run_limit` + 120 s |
//! | `collect` | waits for the evidence, then `Stop`, the flush and the disk layer | recording final | 300 s evidence, 1800 s layer |
//!
//! A refused command, a missing result, a run that never started or was lost,
//! and evidence that does not complete are failures with the codes of 5.4.5.
//! A signal or a dead engine is not: it ends the wait with an error and the
//! caller shuts the engine down.
use super::{Engine, WaitError, Waiter, settled_after_stop};
use crate::api::{
    event::{EventBody, StageStatus},
    failure::{Failure, FailureCode},
    job::{Outcome, Stage},
    spec::Route,
};
use antinomie_monitor_core::{
    Command, ExecRequest, RunArtifactState, RunArtifacts, RunState, RunSummary, VmState,
    analysis::AnalysisState, route::RouteKind, samples::SampleRef,
};
use std::{path::Path, time::Duration};

/// `upload_s` (design 4.1): how long an upload may be retried while the guest
/// finishes mounting its disk.
pub const UPLOAD_WAIT: Duration = Duration::from_secs(60);
/// `launch_s`: from the `Execute` result to the run appearing in the snapshot.
pub const LAUNCH_WAIT: Duration = Duration::from_secs(30);
/// `collect_s`: the precedent of `guest-run.rs`, 300 s.
pub const EVIDENCE_WAIT: Duration = Duration::from_secs(300);
/// How long a run may take to end after `StopRun` was sent.
pub const STOP_RUN_GRACE: Duration = Duration::from_secs(120);
/// `boot_s`.
pub const BOOT_WAIT: Duration = Duration::from_secs(180);
/// At most one "not ready for files" progress line in this long: the retries
/// themselves go on every second.
pub const NOT_READY_NOTE_EVERY: Duration = Duration::from_secs(5);
/// Pause between two uploads the guest was not ready for.
const UPLOAD_RETRY: Duration = Duration::from_secs(1);

/// What to run and where.
#[derive(Clone, Debug)]
pub struct RunPlan {
    pub vm_id: String,
    /// The library sample; the file is decrypted in memory into the guest.
    pub sample: SampleRef,
    /// Where it lands in the guest (`SampleRecord::guest_path`).
    pub guest_path: String,
    /// The launch; `path` and `sample` are set from the two fields above.
    pub request: ExecRequest,
    /// The sample is a library: run this program with `LD_PRELOAD` set to the
    /// library's guest path instead of running the sample itself.
    pub load_into: Option<String>,
    /// Boot the VM when it is stopped; otherwise a stopped VM is `no_vm`.
    pub start_vm: bool,
    /// `StopRun` is sent when the run has lasted this long.
    pub run_limit: Duration,
    pub boot_limit: Duration,
}

/// Why the run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// The program's process tree ended by itself.
    Exited,
    /// `StopRun` was sent at the run limit.
    RunLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    pub code: String,
    pub text: String,
}

/// Milliseconds per stage; a stage that did not run has none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Timings {
    pub provision_ms: Option<u64>,
    pub upload_ms: Option<u64>,
    pub launch_ms: Option<u64>,
    pub run_ms: Option<u64>,
    pub collect_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct RunReport {
    pub outcome: Outcome,
    pub failure: Option<Failure>,
    pub warnings: Vec<Warning>,
    /// The run as the engine last described it.
    pub run: Option<RunSummary>,
    pub artifacts: Option<RunArtifacts>,
    pub end_reason: Option<EndReason>,
    pub timings: Timings,
    /// The VM was stopped and its recording is final.
    pub settled: bool,
}

/// How a run is classified once it is over (design 5.6, "Engine states").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Still going, or its end is not proven yet.
    Live,
    /// `Finished`, `Stopped`, `TerminalClosed` or `Finalized`, and no live task.
    Ended,
    /// `FailedToStart` or `LaunchUnconfirmed`.
    LaunchFailed,
    /// `Interrupted`: the recording ended while the program was going.
    Lost,
}

/// The phase of a run. A run whose guest reports no execution state (an old
/// guest) is over when its state says so.
pub fn phase(run: &RunSummary) -> Phase {
    match run.state {
        RunState::FailedToStart | RunState::LaunchUnconfirmed => Phase::LaunchFailed,
        RunState::Interrupted => Phase::Lost,
        RunState::Finished | RunState::Stopped | RunState::TerminalClosed | RunState::Finalized => {
            if run
                .execution
                .as_ref()
                .is_none_or(|execution| execution.live_task_count == 0)
            {
                Phase::Ended
            } else {
                Phase::Live
            }
        }
        RunState::Unknown | RunState::Running | RunState::StopRequested => Phase::Live,
    }
}

/// Which parts of the run's evidence are still being written: the rule of
/// `guest-run.rs`. No `artifacts.json` yet counts as pending.
pub fn pending_parts(run: &RunSummary, artifacts: Option<&RunArtifacts>) -> Vec<&'static str> {
    let mut parts = Vec::new();
    match artifacts {
        None => parts.push("artifacts"),
        Some(artifacts) => {
            for (name, state) in [
                ("network", artifacts.network_state),
                ("memory", artifacts.memory_state),
                ("core", artifacts.core_state),
            ] {
                if state.in_progress() {
                    parts.push(name);
                }
            }
        }
    }
    if run.request.analysis.enabled
        && run.analysis.as_ref().is_none_or(|report| {
            matches!(
                report.state,
                AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
            )
        })
    {
        parts.push("analysis");
    }
    parts
}

/// The pieces of evidence that finished incomplete: `partial`, not `failed`
/// (design 5.6).
pub fn incomplete_parts(run: &RunSummary, artifacts: Option<&RunArtifacts>) -> Vec<Warning> {
    let mut warnings = Vec::new();
    if let Some(artifacts) = artifacts {
        for (name, state) in [
            ("network", artifacts.network_state),
            ("memory", artifacts.memory_state),
            ("core", artifacts.core_state),
        ] {
            if matches!(
                state,
                RunArtifactState::Partial
                    | RunArtifactState::Interrupted
                    | RunArtifactState::Failed
            ) {
                warnings.push(Warning {
                    code: format!("{name}_{state:?}").to_ascii_lowercase(),
                    text: format!("the {name} evidence is {state:?}").to_ascii_lowercase(),
                });
            }
        }
    }
    if let Some(error) = &run.recording_error {
        warnings.push(Warning {
            code: "recording_error".into(),
            text: error.clone(),
        });
    }
    if let Some(report) = &run.analysis
        && matches!(
            report.state,
            AnalysisState::Partial | AnalysisState::Unavailable | AnalysisState::Cancelled
        )
    {
        let state = format!("{:?}", report.state).to_ascii_lowercase();
        warnings.push(Warning {
            code: format!("analysis_{state}"),
            text: format!("the guest-side static analysis is {state}"),
        });
    }
    warnings
}

/// The error text of an upload that only means the guest is not ready yet:
/// the first upload after boot fails for about a second (spike T0345).
fn guest_not_ready(message: &str) -> bool {
    message
        .to_ascii_lowercase()
        .contains("read-only file system")
}

/// The progress line of an upload the guest was not ready for, `tries` times
/// so far.
fn not_ready_text(tries: u32) -> String {
    let text = "the guest is not ready for files yet; trying again";
    if tries > 1 {
        format!("{text} ({tries} tries so far)")
    } else {
        text.into()
    }
}

/// What a job says about a launch it gave up that started after all.
pub(crate) fn late_launch_warning(run_id: &str) -> Warning {
    Warning {
        code: "late_launch".into(),
        text: format!(
            "the engine answered the launch after the job had given up on it: the program ran \
             as run {run_id} until the VM was stopped; that recording is kept"
        ),
    }
}

/// Why a stage ended the run early.
pub(crate) enum Stop {
    Failed(Failure),
    /// A signal or a dead engine: not a result.
    Abort(WaitError),
}

impl From<WaitError> for Stop {
    fn from(error: WaitError) -> Self {
        Self::Abort(error)
    }
}

fn fail(code: FailureCode, stage: Stage, message: &str, detail: Option<&str>) -> Stop {
    Stop::Failed(Failure::new(code, stage, message, detail))
}

/// Reads a run's `artifacts.json`.
pub type Evidence<'a> = &'a dyn Fn(&Path) -> Result<Option<RunArtifacts>, String>;

/// The real reader. A progress file replaced between stat and open is read
/// again a few times; any other error is final.
pub fn load_artifacts(directory: &Path) -> Result<Option<RunArtifacts>, String> {
    for attempt in 0..4 {
        match RunArtifacts::load(directory) {
            Err(error)
                if attempt < 3 && error == "run artifacts: archive member changed during open" =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => return result,
        }
    }
    Err("artifact read retry exhausted".into())
}

impl<E: Engine> Waiter<E> {
    /// Forget results nobody waits for (a refused `TerminalRead` answers).
    pub fn discard_results(&mut self) {
        self.results.clear();
    }

    pub(crate) fn run_of(&self, run_id: &str) -> Option<RunSummary> {
        self.snapshot
            .runs
            .iter()
            .find(|run| run.id == run_id)
            .cloned()
    }

    /// Run one program to a settled recording. `sink` receives the progress as
    /// `EventBody`s. Errors are signals and a dead engine; every other way to
    /// fail is in the report.
    pub fn exec(
        &mut self,
        plan: &RunPlan,
        evidence: Evidence<'_>,
        sink: &mut dyn FnMut(EventBody),
    ) -> Result<RunReport, WaitError> {
        let mut report = RunReport {
            outcome: Outcome::Succeeded,
            failure: None,
            warnings: Vec::new(),
            run: None,
            artifacts: None,
            end_reason: None,
            timings: Timings::default(),
            settled: false,
        };
        let outcome = self.exec_stages(plan, evidence, sink, &mut report);
        match outcome {
            Ok(()) => {}
            Err(Stop::Abort(error)) => return Err(error),
            Err(Stop::Failed(failure)) => {
                report.outcome = Outcome::Failed;
                report.failure = Some(failure);
                // Leave the VM stopped whatever went wrong.
                self.cleanup_stop(plan, &mut report, sink)?;
            }
        }
        if report.outcome == Outcome::Succeeded && !report.warnings.is_empty() {
            report.outcome = Outcome::Partial;
        }
        for warning in &report.warnings {
            sink(EventBody::JobWarning {
                code: warning.code.clone(),
                text: warning.text.clone(),
            });
        }
        sink(EventBody::JobFinished {
            outcome: report.outcome,
            failure: report.failure.clone(),
        });
        Ok(report)
    }

    /// Stop the VM after a failure, if it runs. A stop that does not settle is
    /// a warning on a report that already failed.
    fn cleanup_stop(
        &mut self,
        plan: &RunPlan,
        report: &mut RunReport,
        sink: &mut dyn FnMut(EventBody),
    ) -> Result<(), WaitError> {
        self.drain()?;
        // Only this VM is ever stopped: another one running is not ours.
        if self.snapshot.active_vm.as_deref() != Some(plan.vm_id.as_str()) {
            report.settled = settled_after_stop(&self.snapshot, &plan.vm_id);
            self.report_late_launch(plan, report, sink);
            return Ok(());
        }
        sink(EventBody::JobProgress {
            stage: Stage::Collect,
            text: "stopping the VM".into(),
            fraction: None,
        });
        match self.stop_vm(&plan.vm_id, None) {
            Ok(_) => report.settled = true,
            Err(error @ (WaitError::Interrupted | WaitError::Disconnected(_))) => {
                return Err(error);
            }
            Err(error) => report.warnings.push(Warning {
                code: "stop_failed".into(),
                text: error.to_string(),
            }),
        }
        self.report_late_launch(plan, report, sink);
        Ok(())
    }

    /// A launch given up as silent that started the program after all: the
    /// stop above ended it with the VM (the engine handles the stop after the
    /// launch), and the job names its run instead of leaving it unreported.
    fn report_late_launch(
        &mut self,
        plan: &RunPlan,
        report: &mut RunReport,
        sink: &mut dyn FnMut(EventBody),
    ) {
        let Some(run) = self.late_launch() else {
            return;
        };
        sink(EventBody::JobRun {
            run_id: run.id.clone(),
            pid: Some(run.pid).filter(|pid| *pid != 0),
            route: route_of(&plan.request, &run),
        });
        report.warnings.push(late_launch_warning(&run.id));
        report.run = Some(run);
    }

    fn stage(
        &mut self,
        stage: Stage,
        status: StageStatus,
        began_ms: u64,
        sink: &mut dyn FnMut(EventBody),
    ) -> u64 {
        let took = self.now_ms().saturating_sub(began_ms);
        sink(EventBody::JobStage {
            stage,
            status,
            duration_ms: (status != StageStatus::Started).then_some(took),
        });
        took
    }

    fn exec_stages(
        &mut self,
        plan: &RunPlan,
        evidence: Evidence<'_>,
        sink: &mut dyn FnMut(EventBody),
        report: &mut RunReport,
    ) -> Result<(), Stop> {
        let progress = |sink: &mut dyn FnMut(EventBody), stage, text: &str| {
            sink(EventBody::JobProgress {
                stage,
                text: text.to_owned(),
                fraction: None,
            });
        };

        // provision
        let began = self.now_ms();
        self.stage(Stage::Provision, StageStatus::Started, began, sink);
        let provisioned = self.provision(plan, sink);
        report.timings.provision_ms = Some(self.stage(
            Stage::Provision,
            if provisioned.is_ok() {
                StageStatus::Finished
            } else {
                StageStatus::Failed
            },
            began,
            sink,
        ));
        provisioned?;

        // upload
        let began = self.now_ms();
        self.stage(Stage::Upload, StageStatus::Started, began, sink);
        let uploaded = self.upload(plan, sink);
        report.timings.upload_ms = Some(self.stage(
            Stage::Upload,
            if uploaded.is_ok() {
                StageStatus::Finished
            } else {
                StageStatus::Failed
            },
            began,
            sink,
        ));
        uploaded?;

        // launch
        let began = self.now_ms();
        self.stage(Stage::Launch, StageStatus::Started, began, sink);
        let launched = self.launch(plan);
        report.timings.launch_ms = Some(self.stage(
            Stage::Launch,
            if launched.is_ok() {
                StageStatus::Finished
            } else {
                StageStatus::Failed
            },
            began,
            sink,
        ));
        let run = launched?;
        sink(EventBody::JobRun {
            run_id: run.id.clone(),
            pid: Some(run.pid).filter(|pid| *pid != 0),
            route: route_of(&plan.request, &run),
        });
        report.run = Some(run.clone());

        // run
        let began = self.now_ms();
        self.stage(Stage::Run, StageStatus::Started, began, sink);
        let ran = self.run(plan, &run.id, sink, report);
        report.timings.run_ms = Some(self.stage(
            Stage::Run,
            if ran.is_ok() {
                StageStatus::Finished
            } else {
                StageStatus::Failed
            },
            began,
            sink,
        ));
        ran?;

        // collect
        let began = self.now_ms();
        self.stage(Stage::Collect, StageStatus::Started, began, sink);
        progress(sink, Stage::Collect, "waiting for the evidence to complete");
        let collected = self.collect(plan, &run.id, evidence, sink, report);
        report.timings.collect_ms = Some(self.stage(
            Stage::Collect,
            if collected.is_ok() {
                StageStatus::Finished
            } else {
                StageStatus::Failed
            },
            began,
            sink,
        ));
        collected
    }

    fn provision(&mut self, plan: &RunPlan, sink: &mut dyn FnMut(EventBody)) -> Result<(), Stop> {
        let vm = plan.vm_id.clone();
        self.drain()?;
        let running = |snapshot: &antinomie_monitor_core::Snapshot| {
            snapshot.active_vm.as_deref() == Some(vm.as_str()) && snapshot.state == VmState::Running
        };
        if !running(&self.snapshot) {
            if !plan.start_vm {
                return Err(fail(
                    FailureCode::NoVm,
                    Stage::Provision,
                    "the VM is not running; pass --start to boot it",
                    None,
                ));
            }
            // The previous boot's recording must be final before this boot
            // begins (the layer wait of 4.1).
            let vm_id = plan.vm_id.clone();
            self.wait_until(
                "the previous recording's disk layer",
                Some(super::SETTLE_WAIT),
                |snapshot| !snapshot.disk_layers.iter().any(|l| l.vm_id == vm_id),
            )
            .map_err(|error| match error {
                WaitError::TimedOut { what } => Stop::Failed(Failure::new(
                    FailureCode::VmStartFailed,
                    Stage::Provision,
                    "the previous boot's disk layer did not settle",
                    Some(&what),
                )),
                other => Stop::Abort(other),
            })?;
            sink(EventBody::JobProgress {
                stage: Stage::Provision,
                text: "starting the VM".into(),
                fraction: None,
            });
            self.command(
                Command::Start {
                    vm_id: plan.vm_id.clone(),
                },
                Some(plan.boot_limit),
            )
            .map_err(|error| match error {
                WaitError::Failed(message) => Stop::Failed(Failure::new(
                    FailureCode::VmStartFailed,
                    Stage::Provision,
                    "the VM did not start",
                    Some(&message),
                )),
                WaitError::TimedOut { .. } => Stop::Failed(Failure::new(
                    FailureCode::VmStartFailed,
                    Stage::Provision,
                    "the VM did not start in time",
                    None,
                )),
                other => Stop::Abort(other),
            })?;
        }
        let vm = plan.vm_id.clone();
        // The VM runs now, so its accelerator is known.
        let boot_limit = self.guest_wait(plan.boot_limit);
        self.wait_until("the guest to answer", Some(boot_limit), move |snapshot| {
            snapshot.active_vm.as_deref() == Some(vm.as_str())
                && snapshot.state == VmState::Running
                && snapshot.guest_kernel.is_some()
        })
        .map_err(|error| match error {
            WaitError::TimedOut { .. } => Stop::Failed(Failure::new(
                FailureCode::GuestUnreachable,
                Stage::Provision,
                "the guest did not answer in time",
                None,
            )),
            other => Stop::Abort(other),
        })
    }

    fn upload(&mut self, plan: &RunPlan, sink: &mut dyn FnMut(EventBody)) -> Result<(), Stop> {
        self.upload_sample(&plan.sample.sha256, &plan.guest_path, UPLOAD_WAIT, sink)
            .map(|_| ())
    }

    /// Send a library sample into the guest. The first upload after boot fails
    /// for about a second while the disk mounts; that is retried until `wait`
    /// has passed. The engine's own words about the transfer are returned.
    pub(crate) fn upload_sample(
        &mut self,
        sha256: &str,
        destination: &str,
        wait: Duration,
        sink: &mut dyn FnMut(EventBody),
    ) -> Result<String, Stop> {
        let deadline = self.now_ms() + super::millis(self.guest_wait(wait));
        let mut tries = 0u32;
        let mut noted_ms: Option<u64> = None;
        loop {
            let result = self.lane_command(Command::UploadSample {
                sha256: sha256.to_owned(),
                destination: destination.to_owned(),
                executable: true,
            });
            match result {
                Ok(message) => return Ok(message),
                Err(WaitError::Failed(message))
                    if guest_not_ready(&message) && self.now_ms() < deadline =>
                {
                    tries += 1;
                    let now = self.now_ms();
                    if noted_ms.is_none_or(|at| {
                        now.saturating_sub(at) >= super::millis(NOT_READY_NOTE_EVERY)
                    }) {
                        noted_ms = Some(now);
                        sink(EventBody::JobProgress {
                            stage: Stage::Upload,
                            text: not_ready_text(tries),
                            fraction: None,
                        });
                    }
                    self.pause(UPLOAD_RETRY)?;
                }
                Err(WaitError::Failed(message)) => {
                    return Err(fail(
                        FailureCode::UploadFailed,
                        Stage::Upload,
                        "the sample could not be sent into the guest",
                        Some(&message),
                    ));
                }
                Err(silent @ WaitError::Silent { .. }) => {
                    return Err(fail(
                        FailureCode::Internal,
                        Stage::Upload,
                        "the engine did not answer the upload",
                        Some(&silent.to_string()),
                    ));
                }
                Err(other) => return Err(Stop::Abort(other)),
            }
        }
    }

    fn launch(&mut self, plan: &RunPlan) -> Result<RunSummary, Stop> {
        let mut request = plan.request.clone();
        match &plan.load_into {
            Some(program) => {
                // The library is named by the hash it was uploaded with: the
                // engine links the run to the sample from the push record.
                request.path = program.clone();
                request.env.retain(|item| !item.starts_with("LD_PRELOAD="));
                request.env.push(format!("LD_PRELOAD={}", plan.guest_path));
            }
            None => {
                request.path = plan.guest_path.clone();
                request.sample = Some(plan.sample.clone());
            }
        }
        self.launch_request(request)
    }

    /// `Execute` the request and wait for the new run to appear in the
    /// snapshot (`launch_s`).
    pub(crate) fn launch_request(&mut self, request: ExecRequest) -> Result<RunSummary, Stop> {
        let known: Vec<String> = self
            .snapshot
            .runs
            .iter()
            .map(|run| run.id.clone())
            .collect();
        let id = self.send(Command::Execute(request))?;
        self.lane_wait(id, "Execute".into())
            .map_err(|error| match error {
                WaitError::Failed(message) => Stop::Failed(Failure::new(
                    FailureCode::LaunchFailed,
                    Stage::Launch,
                    "the guest refused to start the program",
                    Some(&message),
                )),
                silent @ WaitError::Silent { .. } => {
                    // The engine may still start it: the cleanup links it.
                    self.unanswered_launch = Some(super::UnansweredLaunch {
                        id,
                        known: known.clone(),
                    });
                    Stop::Failed(Failure::new(
                        FailureCode::Internal,
                        Stage::Launch,
                        "the engine did not answer the launch",
                        Some(&silent.to_string()),
                    ))
                }
                other => Stop::Abort(other),
            })?;
        let launch_wait = self.guest_wait(LAUNCH_WAIT);
        self.wait_until("the run to appear", Some(launch_wait), |snapshot| {
            snapshot.runs.iter().any(|run| !known.contains(&run.id))
        })
        .map_err(|error| match error {
            WaitError::TimedOut { .. } => Stop::Failed(Failure::new(
                FailureCode::LaunchFailed,
                Stage::Launch,
                "no run appeared after the launch",
                None,
            )),
            other => Stop::Abort(other),
        })?;
        Ok(self
            .snapshot
            .runs
            .iter()
            .find(|run| !known.contains(&run.id))
            .cloned()
            .expect("the wait saw a new run"))
    }

    fn run(
        &mut self,
        plan: &RunPlan,
        run_id: &str,
        sink: &mut dyn FnMut(EventBody),
        report: &mut RunReport,
    ) -> Result<(), Stop> {
        let begun = self.now_ms();
        let limit_ms = super::millis(plan.run_limit);
        let grace_ms = super::millis(STOP_RUN_GRACE);
        let mut stop_sent = false;
        loop {
            self.drain()?;
            let Some(run) = self.run_of(run_id) else {
                return Err(fail(
                    FailureCode::GuestLost,
                    Stage::Run,
                    "the run disappeared from the engine",
                    None,
                ));
            };
            match phase(&run) {
                Phase::Ended => {
                    report.run = Some(run);
                    break;
                }
                Phase::LaunchFailed => {
                    return Err(fail(
                        FailureCode::LaunchFailed,
                        Stage::Launch,
                        "the program never started",
                        run.recording_error.as_deref(),
                    ));
                }
                Phase::Lost => {
                    return Err(fail(
                        FailureCode::GuestLost,
                        Stage::Run,
                        "the recording ended while the program was going",
                        run.recording_error.as_deref(),
                    ));
                }
                Phase::Live => {}
            }
            let elapsed = self.now_ms().saturating_sub(begun);
            if !stop_sent && elapsed >= limit_ms {
                stop_sent = true;
                sink(EventBody::JobProgress {
                    stage: Stage::Run,
                    text: "the run limit is reached; stopping the run".into(),
                    fraction: None,
                });
                self.send(Command::StopRun {
                    run_id: run_id.to_owned(),
                })?;
            }
            if stop_sent && elapsed >= limit_ms + grace_ms {
                return Err(fail(
                    FailureCode::GuestLost,
                    Stage::Run,
                    "the run did not end after it was told to stop",
                    None,
                ));
            }
            // The terminal is dropped when nobody reads it (audit E17).
            self.send(Command::TerminalRead {
                run_id: run_id.to_owned(),
            })?;
            self.pump(Duration::from_millis(200))?;
            self.discard_results();
        }
        // One last read so the tail holds the program's final lines.
        self.send(Command::TerminalRead {
            run_id: run_id.to_owned(),
        })?;
        self.pump(Duration::from_millis(200))?;
        self.drain()?;
        self.discard_results();
        report.end_reason = Some(if stop_sent {
            EndReason::RunLimit
        } else {
            EndReason::Exited
        });
        Ok(())
    }

    fn collect(
        &mut self,
        plan: &RunPlan,
        run_id: &str,
        evidence: Evidence<'_>,
        sink: &mut dyn FnMut(EventBody),
        report: &mut RunReport,
    ) -> Result<(), Stop> {
        let deadline = self.now_ms() + super::millis(EVIDENCE_WAIT);
        loop {
            self.drain()?;
            let Some(run) = self.run_of(run_id) else {
                return Err(fail(
                    FailureCode::GuestLost,
                    Stage::Collect,
                    "the run disappeared from the engine",
                    None,
                ));
            };
            let artifacts = evidence(&run.directory).map_err(|error| {
                fail(
                    FailureCode::RecordingFailed,
                    Stage::Collect,
                    "the run's evidence could not be read",
                    Some(&error),
                )
            })?;
            let pending = pending_parts(&run, artifacts.as_ref());
            if pending.is_empty() {
                report
                    .warnings
                    .extend(incomplete_parts(&run, artifacts.as_ref()));
                report.run = Some(run);
                report.artifacts = artifacts;
                break;
            }
            if self.now_ms() >= deadline {
                return Err(fail(
                    FailureCode::RecordingFailed,
                    Stage::Collect,
                    "the evidence did not complete in time",
                    Some(&format!("still pending: {}", pending.join(", "))),
                ));
            }
            self.pump(Duration::from_millis(100))?;
        }
        sink(EventBody::JobProgress {
            stage: Stage::Collect,
            text: "stopping the VM and saving the recording".into(),
            fraction: None,
        });
        self.stop_vm(&plan.vm_id, None)
            .map_err(|error| match error {
                WaitError::Failed(message) => Stop::Failed(Failure::new(
                    FailureCode::RecordingFailed,
                    Stage::Collect,
                    "the VM did not stop cleanly",
                    Some(&message),
                )),
                WaitError::TimedOut { what } => Stop::Failed(Failure::new(
                    FailureCode::RecordingFailed,
                    Stage::Collect,
                    "the recording did not settle in time",
                    Some(&what),
                )),
                other => Stop::Abort(other),
            })?;
        report.settled = true;
        Ok(())
    }
}

/// The route the run used, for the `job.run` event: the one asked for, else
/// the one the engine recorded, else the default (nothing leaves the VM).
pub(crate) fn route_of(request: &ExecRequest, run: &RunSummary) -> Route {
    let kind = request
        .route
        .or_else(|| run.route.as_ref().map(|record| record.kind))
        .unwrap_or(RouteKind::Drop);
    match kind {
        RouteKind::Drop => Route::Drop,
        RouteKind::Internet => Route::Internet,
        RouteKind::InetSim => Route::InetSim,
        RouteKind::Tor => Route::Tor,
        RouteKind::Vpn => Route::Vpn,
        RouteKind::Socks5 => Route::Socks5,
    }
}

#[cfg(test)]
mod tests;

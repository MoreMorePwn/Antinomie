// SPDX-License-Identifier: GPL-3.0-only
//! The run waiter against a scripted engine and a manual clock: no VM, no
//! sleeping. The sequences are the ones the spike (ANT-T0345) recorded.
use super::*;
use crate::{
    clock::{Clock, ManualClock},
    waiter::tests::{Fake, make, result},
};
use antinomie_monitor_core::{GuestKernel, Notification, RunExecution, Snapshot, VmState};
use serde_json::json;
use std::sync::{Arc, Mutex};

const VM: &str = "vm1";

fn run_summary(id: &str, state: &str, live_tasks: u64) -> RunSummary {
    let mut run: RunSummary = serde_json::from_value(json!({
        "id": id, "vm_id": VM, "boot_id": "b1", "session_id": 1,
        "root_task_cookie": 7, "pid": 750,
        "request": ExecRequest::default(),
        "directory": "/runs/r1", "terminal_eof": false,
        "state": state, "recording_error": null,
    }))
    .expect("a run summary");
    run.execution = Some(RunExecution {
        generation: 1,
        live_task_count: live_tasks,
        pending_async_count: 0,
        flags: 0,
        root_wait_status: None,
        root_exit: None,
        async_loss_count: 0,
        total_task_count: 1,
    });
    run
}

fn running_vm(runs: Vec<RunSummary>) -> Snapshot {
    Snapshot {
        active_vm: Some(VM.into()),
        state: VmState::Running,
        guest_kernel: Some(GuestKernel::default()),
        runs,
        ..Snapshot::default()
    }
}

fn stopped_vm(runs: Vec<RunSummary>) -> Snapshot {
    Snapshot {
        runs,
        ..Snapshot::default()
    }
}

fn plan() -> RunPlan {
    RunPlan {
        vm_id: VM.into(),
        sample: SampleRef {
            sha256: "ab".repeat(32),
            name: "job.sh".into(),
        },
        guest_path: "/tmp/abababab-job.sh".into(),
        request: ExecRequest::default(),
        start_vm: false,
        run_limit: Duration::from_secs(20),
        boot_limit: Duration::from_secs(180),
    }
}

fn complete() -> RunArtifacts {
    RunArtifacts {
        network_state: RunArtifactState::Complete,
        memory_state: RunArtifactState::Disabled,
        core_state: RunArtifactState::Disabled,
        ..RunArtifacts::default()
    }
}

type Log = Arc<Mutex<Vec<EventBody>>>;

fn exec(
    waiter: &mut Waiter<Fake>,
    plan: &RunPlan,
    evidence: impl Fn(&Path) -> Result<Option<RunArtifacts>, String>,
) -> (Result<RunReport, WaitError>, Vec<EventBody>) {
    let log: Log = Log::default();
    let sink_log = log.clone();
    let report = waiter.exec(plan, &evidence, &mut move |event| {
        sink_log.lock().unwrap().push(event)
    });
    let events = log.lock().unwrap().clone();
    (report, events)
}

fn stages(events: &[EventBody]) -> Vec<(Stage, StageStatus)> {
    events
        .iter()
        .filter_map(|event| match event {
            EventBody::JobStage { stage, status, .. } => Some((*stage, *status)),
            _ => None,
        })
        .collect()
}

/// The engine of the happy path: it answers every command, starts a run on
/// `Execute`, finishes it `after_ms` later, and settles the stop at once.
fn happy(clock: &Arc<ManualClock>, finish_after_ms: u64) -> Fake {
    let mut fake = Fake::new(clock.clone());
    fake.queue
        .push_back(Notification::Snapshot(running_vm(vec![])));
    fake.react = Some(Box::new(move |command, id, queue| match command {
        Command::UploadSample { .. } | Command::TerminalRead { .. } | Command::StopRun { .. } => {
            if !matches!(command, Command::TerminalRead { .. }) {
                queue.push_back(result(id, true, "ok"));
            }
        }
        Command::Execute(_) => {
            queue.push_back(result(id, true, "launched pid 750"));
            queue.push_back(Notification::Snapshot(running_vm(vec![run_summary(
                "r1", "Running", 1,
            )])));
        }
        Command::Stop => {
            queue.push_back(Notification::Snapshot(stopped_vm(vec![run_summary(
                "r1", "Finished", 0,
            )])));
            queue.push_back(result(id, true, "VM stopped"));
        }
        _ => queue.push_back(result(id, true, "ok")),
    }));
    // The run ends on its own `finish_after_ms` after the launch.
    fake.timed.push((
        finish_after_ms + 1_000,
        Notification::Snapshot(running_vm(vec![run_summary("r1", "Finished", 0)])),
    ));
    fake
}

#[test]
fn a_program_that_ends_by_itself_is_uploaded_run_collected_and_settled() {
    let clock = Arc::new(ManualClock::new(0));
    let (mut waiter, _) = make(happy(&clock, 2_000));
    let sent = waiter.engine_mut().sent.clone();
    let (report, events) = exec(&mut waiter, &plan(), |_| Ok(Some(complete())));
    let report = report.unwrap();
    assert_eq!(report.outcome, Outcome::Succeeded, "{:?}", report.failure);
    assert_eq!(report.end_reason, Some(EndReason::Exited));
    assert!(report.settled && report.warnings.is_empty());
    assert_eq!(report.run.as_ref().unwrap().id, "r1");
    let sent = sent.lock().unwrap().clone();
    let position = |name: &str| sent.iter().position(|sent| sent == name).unwrap();
    assert!(position("UploadSample") < position("Execute"));
    assert!(position("Execute") < position("TerminalRead"));
    assert!(position("TerminalRead") < position("Stop"));
    assert!(!sent.contains(&"Start".to_owned()), "{sent:?}");
    assert!(!sent.contains(&"StopRun".to_owned()), "{sent:?}");
    assert_eq!(
        stages(&events),
        [
            (Stage::Provision, StageStatus::Started),
            (Stage::Provision, StageStatus::Finished),
            (Stage::Upload, StageStatus::Started),
            (Stage::Upload, StageStatus::Finished),
            (Stage::Launch, StageStatus::Started),
            (Stage::Launch, StageStatus::Finished),
            (Stage::Run, StageStatus::Started),
            (Stage::Run, StageStatus::Finished),
            (Stage::Collect, StageStatus::Started),
            (Stage::Collect, StageStatus::Finished),
        ]
    );
    assert!(matches!(
        events.iter().find(|e| matches!(e, EventBody::JobRun { .. })),
        Some(EventBody::JobRun { run_id, route: Route::Drop, .. }) if run_id == "r1"
    ));
    assert!(matches!(
        events.last(),
        Some(EventBody::JobFinished {
            outcome: Outcome::Succeeded,
            failure: None
        })
    ));
}

#[test]
fn the_run_limit_sends_stop_run_once_and_the_run_still_settles() {
    let clock = Arc::new(ManualClock::new(0));
    // The program never ends by itself; it ends 3 s after StopRun.
    let mut fake = happy(&clock, 1_000_000);
    fake.timed.clear();
    let mut react = fake.react.take().unwrap();
    let stopped = Arc::new(Mutex::new(0u32));
    let count = stopped.clone();
    fake.react = Some(Box::new(move |command, id, queue| {
        if matches!(command, Command::StopRun { .. }) {
            *count.lock().unwrap() += 1;
            queue.push_back(result(id, true, "stop requested"));
        } else {
            react(command, id, queue);
        }
    }));
    let (mut waiter, _) = make(fake);
    // Stopped 3 s after the limit (limit 20 s, launch at about 0).
    waiter.engine_mut().timed.push((
        23_000,
        Notification::Snapshot(running_vm(vec![run_summary("r1", "Stopped", 0)])),
    ));
    let (report, events) = exec(&mut waiter, &plan(), |_| Ok(Some(complete())));
    let report = report.unwrap();
    assert_eq!(report.outcome, Outcome::Succeeded, "{:?}", report.failure);
    assert_eq!(report.end_reason, Some(EndReason::RunLimit));
    assert_eq!(*stopped.lock().unwrap(), 1);
    let run_ms = report.timings.run_ms.unwrap();
    assert!((20_000..24_000).contains(&run_ms), "{run_ms}");
    assert!(events.iter().any(|e| matches!(
        e,
        EventBody::JobProgress { text, .. } if text.contains("run limit")
    )));
}

#[test]
fn a_run_that_ignores_stop_run_is_lost_after_the_grace() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000_000);
    fake.timed.clear();
    let (mut waiter, _) = make(fake);
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(Some(complete())));
    let report = report.unwrap();
    assert_eq!(report.outcome, Outcome::Failed);
    let failure = report.failure.unwrap();
    assert_eq!(failure.code, FailureCode::GuestLost);
    assert_eq!(failure.stage, Stage::Run);
    assert!(report.settled, "the VM is stopped after a failure too");
}

#[test]
fn a_stopped_vm_is_no_vm_unless_it_may_be_started() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = Fake::new(clock.clone());
    fake.queue
        .push_back(Notification::Snapshot(stopped_vm(vec![])));
    let (mut waiter, _) = make(fake);
    let sent = waiter.engine_mut().sent.clone();
    let (report, events) = exec(&mut waiter, &plan(), |_| Ok(None));
    let report = report.unwrap();
    assert_eq!(report.failure.as_ref().unwrap().code, FailureCode::NoVm);
    assert!(report.failure.unwrap().message.contains("--start"));
    assert!(sent.lock().unwrap().is_empty(), "nothing was sent");
    assert!(matches!(
        events.last(),
        Some(EventBody::JobFinished {
            outcome: Outcome::Failed,
            ..
        })
    ));

    // With permission it boots: Start, then the guest answers.
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000);
    fake.queue.clear();
    fake.queue
        .push_back(Notification::Snapshot(stopped_vm(vec![])));
    let mut react = fake.react.take().unwrap();
    fake.react = Some(Box::new(move |command, id, queue| {
        if matches!(command, Command::Start { .. }) {
            queue.push_back(result(id, true, "started"));
            queue.push_back(Notification::Snapshot(running_vm(vec![])));
        } else {
            react(command, id, queue);
        }
    }));
    let (mut waiter, _) = make(fake);
    let sent = waiter.engine_mut().sent.clone();
    let mut plan = plan();
    plan.start_vm = true;
    let (report, _) = exec(&mut waiter, &plan, |_| Ok(Some(complete())));
    assert_eq!(report.unwrap().outcome, Outcome::Succeeded);
    assert_eq!(
        sent.lock().unwrap().first().map(String::as_str),
        Some("Start")
    );
}

#[test]
fn a_vm_that_does_not_start_is_vm_start_failed() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = Fake::new(clock);
    fake.queue
        .push_back(Notification::Snapshot(stopped_vm(vec![])));
    fake.react = Some(Box::new(|command, id, queue| {
        if matches!(command, Command::Start { .. }) {
            queue.push_back(result(id, false, "only one VM may run at a time"));
        }
    }));
    let (mut waiter, _) = make(fake);
    let mut plan = plan();
    plan.start_vm = true;
    let (report, _) = exec(&mut waiter, &plan, |_| Ok(None));
    let failure = report.unwrap().failure.unwrap();
    assert_eq!(failure.code, FailureCode::VmStartFailed);
    assert_eq!(
        failure.detail.as_deref(),
        Some("only one VM may run at a time")
    );
}

#[test]
fn the_first_upload_after_boot_is_retried_while_the_disk_is_read_only() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 10_000);
    let mut react = fake.react.take().unwrap();
    let attempts = Arc::new(Mutex::new(0u32));
    let seen = attempts.clone();
    fake.react = Some(Box::new(move |command, id, queue| {
        if matches!(command, Command::UploadSample { .. }) {
            let mut n = seen.lock().unwrap();
            *n += 1;
            if *n < 3 {
                queue.push_back(result(
                    id,
                    false,
                    "guest command 0x1001: Read-only file system (os error 30)",
                ));
                return;
            }
        }
        react(command, id, queue);
    }));
    let (mut waiter, _) = make(fake);
    let (report, events) = exec(&mut waiter, &plan(), |_| Ok(Some(complete())));
    assert_eq!(report.unwrap().outcome, Outcome::Succeeded);
    assert_eq!(*attempts.lock().unwrap(), 3);
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e,
                EventBody::JobProgress {
                    stage: Stage::Upload,
                    ..
                }
            ))
            .count(),
        2
    );
}

#[test]
fn any_other_upload_error_is_upload_failed_at_once() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000);
    let mut react = fake.react.take().unwrap();
    fake.react = Some(Box::new(move |command, id, queue| {
        if matches!(command, Command::UploadSample { .. }) {
            queue.push_back(result(id, false, "the sample is not in the library"));
        } else {
            react(command, id, queue);
        }
    }));
    let (mut waiter, clock) = make(fake);
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(None));
    let failure = report.unwrap().failure.unwrap();
    assert_eq!(failure.code, FailureCode::UploadFailed);
    assert!(clock.now_ms() < 5_000, "no retry for a real error");
}

#[test]
fn a_launch_the_guest_refuses_or_never_confirms_is_launch_failed() {
    for (state, expected) in [
        ("FailedToStart", "never started"),
        ("LaunchUnconfirmed", "never started"),
    ] {
        let clock = Arc::new(ManualClock::new(0));
        let mut fake = happy(&clock, 1_000);
        fake.timed.clear();
        let mut react = fake.react.take().unwrap();
        let state = state.to_owned();
        fake.react = Some(Box::new(move |command, id, queue| {
            react(command, id, queue);
            if matches!(command, Command::Execute(_)) {
                queue.push_back(Notification::Snapshot(running_vm(vec![run_summary(
                    "r1", &state, 0,
                )])));
            }
        }));
        let (mut waiter, _) = make(fake);
        let (report, _) = exec(&mut waiter, &plan(), |_| Ok(None));
        let failure = report.unwrap().failure.unwrap();
        assert_eq!(failure.code, FailureCode::LaunchFailed);
        assert!(failure.message.contains(expected), "{}", failure.message);
    }

    // The guest answers the Execute with a refusal.
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000);
    let mut react = fake.react.take().unwrap();
    fake.react = Some(Box::new(move |command, id, queue| {
        if matches!(command, Command::Execute(_)) {
            queue.push_back(result(
                id,
                false,
                "Guest desktop needs a VM with a graphical base",
            ));
        } else {
            react(command, id, queue);
        }
    }));
    let (mut waiter, _) = make(fake);
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(None));
    let failure = report.unwrap().failure.unwrap();
    assert_eq!(failure.code, FailureCode::LaunchFailed);
    assert!(failure.detail.unwrap().contains("graphical"));
}

#[test]
fn a_missing_result_after_sixty_seconds_is_internal() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000);
    let mut react = fake.react.take().unwrap();
    fake.react = Some(Box::new(move |command, id, queue| {
        if !matches!(command, Command::Execute(_)) {
            react(command, id, queue);
        }
    }));
    let (mut waiter, clock) = make(fake);
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(None));
    let failure = report.unwrap().failure.unwrap();
    assert_eq!(failure.code, FailureCode::Internal);
    assert_eq!(failure.stage, Stage::Launch);
    assert!(
        (60_000..65_000).contains(&clock.now_ms()),
        "{}",
        clock.now_ms()
    );
}

#[test]
fn an_interrupted_run_is_guest_lost() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000);
    fake.timed.clear();
    fake.timed.push((
        2_000,
        Notification::Snapshot(running_vm(vec![run_summary("r1", "Interrupted", 0)])),
    ));
    let (mut waiter, _) = make(fake);
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(None));
    let report = report.unwrap();
    assert_eq!(report.failure.unwrap().code, FailureCode::GuestLost);
    assert_eq!(report.outcome, Outcome::Failed);
}

#[test]
fn a_run_with_live_tasks_is_not_over_even_when_its_state_says_finished() {
    assert_eq!(phase(&run_summary("r", "Finished", 2)), Phase::Live);
    assert_eq!(phase(&run_summary("r", "Finished", 0)), Phase::Ended);
    for state in ["Finished", "Stopped", "TerminalClosed", "Finalized"] {
        assert_eq!(phase(&run_summary("r", state, 0)), Phase::Ended, "{state}");
    }
    for state in ["Unknown", "Running", "StopRequested"] {
        assert_eq!(phase(&run_summary("r", state, 0)), Phase::Live, "{state}");
    }
    assert_eq!(
        phase(&run_summary("r", "FailedToStart", 0)),
        Phase::LaunchFailed
    );
    assert_eq!(
        phase(&run_summary("r", "LaunchUnconfirmed", 0)),
        Phase::LaunchFailed
    );
    assert_eq!(phase(&run_summary("r", "Interrupted", 0)), Phase::Lost);
    let mut no_execution = run_summary("r", "Finished", 0);
    no_execution.execution = None;
    assert_eq!(phase(&no_execution), Phase::Ended);
}

#[test]
fn evidence_still_being_written_is_waited_for_up_to_three_hundred_seconds() {
    let clock = Arc::new(ManualClock::new(0));
    let (mut waiter, clock) = make(happy(&clock, 1_000));
    let ticks = Arc::new(Mutex::new(0u32));
    let seen = ticks.clone();
    let (report, _) = exec(&mut waiter, &plan(), move |_| {
        let mut n = seen.lock().unwrap();
        *n += 1;
        Ok(Some(RunArtifacts {
            network_state: if *n < 20 {
                RunArtifactState::InProgress
            } else {
                RunArtifactState::Complete
            },
            ..complete()
        }))
    });
    let report = report.unwrap();
    assert_eq!(report.outcome, Outcome::Succeeded);
    assert!(clock.now_ms() < 60_000);

    // Never finishing is `recording_failed` at 300 s.
    let c = Arc::new(ManualClock::new(0));
    let (mut waiter, clock) = make(happy(&c, 1_000));
    let (report, _) = exec(&mut waiter, &plan(), |_| {
        Ok(Some(RunArtifacts {
            memory_state: RunArtifactState::Recording,
            ..complete()
        }))
    });
    let report = report.unwrap();
    let failure = report.failure.unwrap();
    assert_eq!(failure.code, FailureCode::RecordingFailed);
    assert!(failure.detail.unwrap().contains("memory"));
    assert!(
        (300_000..320_000).contains(&clock.now_ms()),
        "{}",
        clock.now_ms()
    );
    assert!(report.settled);
}

#[test]
fn a_missing_artifacts_file_counts_as_pending_like_guest_run() {
    let run = run_summary("r", "Finished", 0);
    assert_eq!(pending_parts(&run, None), ["artifacts"]);
    let done = complete();
    assert!(pending_parts(&run, Some(&done)).is_empty());
    let mut with_analysis = run.clone();
    with_analysis.request.analysis.enabled = true;
    assert_eq!(pending_parts(&with_analysis, Some(&done)), ["analysis"]);
}

#[test]
fn partial_evidence_makes_the_outcome_partial_not_failed() {
    let clock = Arc::new(ManualClock::new(0));
    let (mut waiter, _) = make(happy(&clock, 1_000));
    let (report, events) = exec(&mut waiter, &plan(), |_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::Partial,
            core_state: RunArtifactState::Failed,
            ..complete()
        }))
    });
    let report = report.unwrap();
    assert_eq!(report.outcome, Outcome::Partial);
    assert!(report.failure.is_none());
    let codes: Vec<&str> = report.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(codes, ["network_partial", "core_failed"]);
    assert!(
        events
            .iter()
            .any(|e| matches!(e, EventBody::JobWarning { code, .. } if code == "core_failed"))
    );
    assert!(matches!(
        events.last(),
        Some(EventBody::JobFinished {
            outcome: Outcome::Partial,
            ..
        })
    ));
}

#[test]
fn a_signal_aborts_the_run_without_a_report() {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000_000);
    fake.timed.clear();
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let raise = flag.clone();
    let mut react = fake.react.take().unwrap();
    fake.react = Some(Box::new(move |command, id, queue| {
        react(command, id, queue);
        if matches!(command, Command::Execute(_)) {
            raise.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }));
    let (mut waiter, _) = make(fake);
    let seen = flag.clone();
    waiter.interrupt_when(move || seen.load(std::sync::atomic::Ordering::SeqCst));
    let sent = waiter.engine_mut().sent.clone();
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(None));
    assert_eq!(report.unwrap_err(), WaitError::Interrupted);
    assert!(
        !sent.lock().unwrap().contains(&"Stop".to_owned()),
        "the caller shuts the engine down; no Stop is sent after a signal"
    );
}

#[test]
fn the_stop_waits_for_the_disk_layer_before_the_report_says_settled() {
    use antinomie_monitor_core::disk_layers::{DiskLayer, LayerPhase};
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = happy(&clock, 1_000);
    let mut react = fake.react.take().unwrap();
    fake.react = Some(Box::new(move |command, id, queue| {
        if matches!(command, Command::Stop) {
            let mut stopped = stopped_vm(vec![run_summary("r1", "Finished", 0)]);
            stopped.disk_layers = vec![DiskLayer {
                vm_id: VM.into(),
                boot_id: "b1".into(),
                phase: LayerPhase::Saving,
                started_ms: 0,
                phase_ms: 0,
            }];
            queue.push_back(Notification::Snapshot(stopped));
            queue.push_back(result(id, true, "VM stopped"));
        } else {
            react(command, id, queue);
        }
    }));
    let (mut waiter, clock) = make(fake);
    // The layer clears 40 s after the stop.
    waiter.engine_mut().timed.push((
        45_000,
        Notification::Snapshot(stopped_vm(vec![run_summary("r1", "Finished", 0)])),
    ));
    let (report, _) = exec(&mut waiter, &plan(), |_| Ok(Some(complete())));
    let report = report.unwrap();
    assert!(report.settled);
    assert!(clock.now_ms() >= 45_000, "{}", clock.now_ms());
    assert_eq!(report.outcome, Outcome::Succeeded);
}

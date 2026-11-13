// SPDX-License-Identifier: GPL-3.0-only
//! The waiter during a guest transition (ANT-T0479): the engine refuses guest
//! commands while it reconnects to a guest or restores a snapshot. The
//! refusal is [`WaitError::GuestTransition`], never an engine failure; the
//! upload and the launch ask again until their own limits, and `run exec`'s
//! run loop goes on through it.
use super::{RunPlan, WaitError, Waiter};
use crate::{
    api::{failure::FailureCode, job::Outcome, job::Stage},
    clock::ManualClock,
    engine::{
        FakeEngine,
        fake::{TRANSITION_CANCEL, TRANSITION_REFUSAL},
    },
};
use antinomie_monitor_core::{
    Command, ExecRequest, GuestKernel, RunArtifactState, RunArtifacts, RunExecution, RunState,
    RunSummary, VmState, samples::SampleRef,
};
use serde_json::json;
use std::{sync::Arc, time::Duration};

const SECOND: Duration = Duration::from_secs(1);
const VM: &str = "vm1";

fn live_run() -> RunSummary {
    let mut run: RunSummary = serde_json::from_value(json!({
        "id": "r1", "vm_id": VM, "boot_id": "b1", "session_id": 1,
        "root_task_cookie": 7, "pid": 750,
        "request": ExecRequest::default(),
        "directory": "/runs/r1", "terminal_eof": false,
        "state": "Running", "recording_error": null,
    }))
    .expect("a run summary");
    run.execution = Some(RunExecution {
        generation: 1,
        live_task_count: 1,
        pending_async_count: 0,
        flags: 0,
        root_wait_status: None,
        root_exit: None,
        async_loss_count: 0,
        total_task_count: 1,
    });
    run
}

/// A waiter on a running VM whose engine `script` describes.
fn waiter(script: impl FnOnce(&mut FakeEngine)) -> Waiter<FakeEngine> {
    let clock = Arc::new(ManualClock::new(0));
    let mut fake = FakeEngine::new(clock.clone());
    fake.start_with(|s| {
        s.active_vm = Some(VM.into());
        s.state = VmState::Running;
        s.guest_kernel = Some(GuestKernel::default());
    });
    script(&mut fake);
    let mut waiter = Waiter::new(fake, clock);
    waiter.first_snapshot(SECOND).unwrap();
    waiter
}

fn upload(waiter: &mut Waiter<FakeEngine>) -> Result<String, super::Stop> {
    waiter.upload_sample(
        &"ab".repeat(32),
        "/tmp/x",
        Duration::from_secs(60),
        &mut |_| {},
    )
}

fn failure(stop: super::Stop) -> crate::api::failure::Failure {
    match stop {
        super::Stop::Failed(failure) => failure,
        super::Stop::Abort(error) => panic!("an abort, not a failure: {error:?}"),
    }
}

#[test]
fn the_engines_refusal_during_a_transition_is_a_guest_transition_not_a_failure() {
    let mut w = waiter(|fake| {
        fake.guest_transition(Duration::ZERO, 10 * SECOND);
        fake.on("Stop").ok("VM stopped");
    });
    let refused = w.send(Command::TerminalRead {
        run_id: "r1".into(),
    });
    assert_eq!(
        refused,
        Err(WaitError::GuestTransition(TRANSITION_REFUSAL.into()))
    );
    // A host command is not refused.
    assert!(w.send(Command::Stop).is_ok());
}

#[test]
fn an_upload_waits_for_the_transition_and_is_sent_once_the_guest_is_back() {
    let mut w = waiter(|fake| {
        fake.guest_transition(Duration::ZERO, 12 * SECOND);
        fake.on("UploadSample").ok("uploaded 4096 bytes to /tmp/x");
    });
    assert_eq!(
        upload(&mut w).ok().as_deref(),
        Some("uploaded 4096 bytes to /tmp/x")
    );
    let sent = w.engine_mut().sent();
    assert_eq!(sent.len(), 1);
    assert!(sent[0].at_ms >= 12_000, "{sent:?}");
}

#[test]
fn an_upload_through_a_transition_that_never_ends_is_guest_unreachable() {
    let mut w = waiter(|fake| {
        fake.guest_transition(Duration::ZERO, 3600 * SECOND);
    });
    let failure = failure(upload(&mut w).unwrap_err());
    assert_eq!(failure.code, FailureCode::GuestUnreachable, "{failure:?}");
    assert_eq!(failure.stage, Stage::Upload);
    assert!(failure.detail.unwrap().contains("not back within"));
}

#[test]
fn a_launch_refused_while_the_engine_loses_the_guest_is_guest_unreachable() {
    // Before: the refused send was an abort, and the lane made it `internal`.
    let mut w = waiter(|fake| {
        fake.guest_transition(Duration::ZERO, 3600 * SECOND);
        fake.after(5 * SECOND, |s| {
            s.state = VmState::Failed;
            s.last_error = Some("the guest stopped answering".into());
        });
    });
    let failure = failure(w.launch_request(ExecRequest::default()).unwrap_err());
    assert_eq!(failure.code, FailureCode::GuestUnreachable, "{failure:?}");
    assert_eq!(failure.stage, Stage::Launch);
    assert!(w.engine_mut().sent().is_empty(), "nothing was launched");
}

#[test]
fn a_launch_cancelled_at_the_boundary_is_sent_again_once_the_guest_is_back() {
    let mut w = waiter(|fake| {
        fake.on("Execute").after(SECOND).fail(TRANSITION_CANCEL);
        fake.on("Execute")
            .after(SECOND)
            .then(SECOND, |s| s.runs.push(live_run()))
            .ok("launched pid 750");
    });
    let run = w
        .launch_request(ExecRequest::default())
        .ok()
        .expect("a run");
    assert_eq!(run.id, "r1");
    assert_eq!(w.engine_mut().sent_names(), ["Execute", "Execute"]);
}

#[test]
fn run_exec_goes_on_through_a_transition_and_stops_the_run_after_it() {
    // `run exec`: terminal reads and the StopRun at the limit are refused
    // while the engine reconnects; the run is stopped once the guest is back.
    // Before: the refused terminal read ended the command with an error.
    let mut w = waiter(|fake| {
        fake.on("UploadSample").ok("uploaded 4096 bytes to /tmp/x");
        fake.on("Execute")
            .after(SECOND)
            .then(SECOND, |s| s.runs.push(live_run()))
            .ok("launched pid 750");
        fake.on("StopRun").ok("stop requested");
        fake.on("Stop")
            .then(SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
            })
            .ok("VM stopped");
        // Terminal reads get no answer: an answer at the same clock time
        // would end every 200 ms pump at once, and the manual clock would
        // never move (the loop would send reads for good).
        fake.on("TerminalRead").forever().silent();
        // The run limit (20 s from about 2 s) falls inside this.
        fake.guest_transition(10 * SECOND, 30 * SECOND);
        fake.after(31 * SECOND, |s| {
            if let Some(run) = s.runs.first_mut() {
                run.state = RunState::Stopped;
                run.execution.as_mut().unwrap().live_task_count = 0;
            }
        });
    });
    let plan = RunPlan {
        vm_id: VM.into(),
        sample: SampleRef {
            sha256: "ab".repeat(32),
            name: "job.sh".into(),
        },
        guest_path: "/tmp/x".into(),
        request: ExecRequest::default(),
        load_into: None,
        start_vm: false,
        run_limit: Duration::from_secs(20),
        boot_limit: Duration::from_secs(180),
    };
    let evidence = |_: &std::path::Path| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::Complete,
            memory_state: RunArtifactState::Disabled,
            core_state: RunArtifactState::Disabled,
            ..RunArtifacts::default()
        }))
    };
    let report = w.exec(&plan, &evidence, &mut |_| {}).expect("a report");
    assert_ne!(report.outcome, Outcome::Failed, "{:?}", report.failure);
    let fake = w.engine_mut();
    assert!(
        fake.refused()
            .iter()
            .any(|(name, _)| name == "TerminalRead")
    );
    let stops: Vec<_> = fake
        .sent()
        .into_iter()
        .filter(|s| s.name == "StopRun")
        .collect();
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert!(stops[0].at_ms >= 30_000, "{stops:?}");
}

// SPDX-License-Identifier: GPL-3.0-only
//! The stages `run` and `collect` against a [`FakeEngine`] and a manual clock
//! (card P3-4c): every way a run ends, the run limit, the watchdog's silence
//! and stall rules, the hard path of a hung stop, cancellation. No VM, no
//! sleeping.
use super::{
    CollectEnd, Launched, Prepared, RunEnd, StageStop, Stopped,
    tests::{MS, SECOND, W, cycle, restore_ok, run_summary, upload_ok},
};
use crate::{
    api::{
        failure::FailureCode,
        job::{EndReason, Job, Outcome, RecordingPhase, Stage},
    },
    engine::FakeEngine,
    lane::process::ProcessInfo,
    waiter::Waiter,
};
use antinomie_monitor_core::{
    RunArtifactState, RunArtifacts, RunExecution, RunState, RunSummary, Snapshot, VmState,
    WaitStatus, disk_layers::LayerPhase,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

pub(super) fn execution(live: u64, root: Option<WaitStatus>) -> RunExecution {
    RunExecution {
        generation: 1,
        live_task_count: live,
        pending_async_count: 0,
        flags: 0,
        root_wait_status: None,
        root_exit: root,
        async_loss_count: 0,
        total_task_count: 1,
    }
}

pub(super) fn live_run() -> RunSummary {
    let mut run = run_summary("Running");
    run.execution = Some(execution(1, None));
    run
}

/// The run ends by itself with this status.
pub(super) fn ended(root: Option<WaitStatus>) -> impl Fn(&mut Snapshot) + Send + Sync + 'static {
    move |s| {
        s.runs[0].state = RunState::Finished;
        s.runs[0].execution = Some(execution(0, root.clone()));
    }
}

/// `Execute` starts a run; when `ends` is given the run ends that long after
/// the command (the command itself answers after a second).
pub(super) fn execute_run(fake: &mut FakeEngine, ends: Option<(Duration, Option<WaitStatus>)>) {
    let mut step = fake
        .on("Execute")
        .after(SECOND)
        .then(500 * MS, |s| s.runs.push(live_run()));
    if let Some((after, status)) = ends {
        step = step.then(after, ended(status));
    }
    step.ok("launched pid 750, terminal session 1");
}

/// `Stop` answers after a second and the VM is stopped two seconds later.
pub(super) fn stop_ok(fake: &mut FakeEngine) {
    fake.on("Stop")
        .after(SECOND)
        .then(2 * SECOND, |s| {
            s.state = VmState::Stopped;
            s.active_vm = None;
        })
        .ok("VM stopped");
}

/// `StopRun` is accepted and the run is `Stopped` two seconds later.
pub(super) fn stop_run_ok(fake: &mut FakeEngine) {
    fake.on("StopRun")
        .after(100 * MS)
        .then(2 * SECOND, |s| {
            s.runs[0].state = RunState::Stopped;
            s.runs[0].execution = Some(execution(0, None));
        })
        .ok("stop requested");
}

/// The engine says something every `every` until `until` (snapshots arrive
/// all the time on a live engine).
pub(super) fn chatter(fake: &mut FakeEngine, every: Duration, until: Duration) {
    let mut at = every;
    while at < until {
        fake.after(at, |_| {});
        at += every;
    }
}

/// A process table entry the provision records as the lane's QEMU.
pub(super) fn qemu(w: &W, pid: u32, ticks: u64) {
    w.procs.procs.borrow_mut().insert(
        pid,
        ProcessInfo {
            argv: vec![
                "qemu-system-x86_64".into(),
                "file=/d/vms/auto-1/disk".into(),
            ],
            start_ticks: Some(ticks),
        },
    );
}

/// Run `prechecks` to `launch`.
pub(super) fn launched(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> (Prepared, Launched) {
    w.stages(waiter).launch_cycle(job).expect("the launch")
}

fn run_stage(
    w: &W,
    waiter: &mut Waiter<FakeEngine>,
    job: &Job,
    ready: &(Prepared, Launched),
) -> Result<RunEnd, StageStop> {
    w.stages(waiter).run(job, &ready.0, &ready.1)
}

fn collect_stage(
    w: &W,
    waiter: &mut Waiter<FakeEngine>,
    job: &Job,
    ready: &(Prepared, Launched),
) -> Result<CollectEnd, StageStop> {
    w.stages(waiter).collect(job, &ready.1)
}

fn code(stop: &StageStop) -> FailureCode {
    stop.failure().unwrap_or_else(|| panic!("{stop:?}")).code
}

fn seconds(w: &W, since: u64) -> u64 {
    use crate::clock::Clock;
    (w.fx.clock.now_ms() - since) / 1000
}

fn now(w: &W) -> u64 {
    use crate::clock::Clock;
    w.fx.clock.now_ms()
}

// ---- run ----------------------------------------------------------------

#[test]
fn a_program_that_exits_ends_the_run_with_its_exit_code() {
    let w = W::new("run-exit");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(
            fake,
            Some((8 * SECOND, Some(WaitStatus::Exited { code: 3 }))),
        );
    });
    let ready = launched(&w, &mut waiter, &job);
    let end = run_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(
        (end.reason, end.exit, end.signal),
        (EndReason::Exited, Some(3), None)
    );
    let stored = w.job(&job.id);
    let run = stored.run.unwrap();
    assert_eq!(run.end_reason, Some(EndReason::Exited));
    assert_eq!(run.exit, Some(3));
    assert!(run.ended_ms.is_some());
    assert_eq!(stored.recording.unwrap().phase, RecordingPhase::Finalizing);
    assert!(
        !waiter
            .engine_mut()
            .sent_names()
            .contains(&"StopRun".to_owned()),
        "a run that ends by itself is not stopped"
    );
}

#[test]
fn a_program_killed_by_a_signal_is_signaled_with_its_core_flag() {
    let w = W::new("run-signal");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(
            fake,
            Some((
                5 * SECOND,
                Some(WaitStatus::Signaled {
                    signal: 11,
                    core_dumped: true,
                }),
            )),
        );
    });
    let ready = launched(&w, &mut waiter, &job);
    let end = run_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(
        (end.reason, end.exit, end.signal, end.core_dumped),
        (EndReason::Signaled, None, Some(11), true)
    );
    assert!(w.job(&job.id).run.unwrap().core_dumped);
}

#[test]
fn the_run_limit_stops_the_run_once_and_is_not_a_failure() {
    let w = W::with("run-limit", |p| p.program.run_time_s = 20);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        stop_run_ok(fake);
    });
    let ready = launched(&w, &mut waiter, &job);
    let began = now(&w);
    let end = run_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(end.reason, EndReason::TimeLimit);
    let took = seconds(&w, began);
    assert!((20..=24).contains(&took), "the limit is 20 s: {took}");
    let stops = waiter
        .engine_mut()
        .sent_names()
        .iter()
        .filter(|n| *n == "StopRun")
        .count();
    assert_eq!(stops, 1);
    assert_eq!(
        w.job(&job.id).run.unwrap().end_reason,
        Some(EndReason::TimeLimit)
    );
}

#[test]
fn a_run_that_ignores_stop_run_is_guest_lost_after_the_grace() {
    let w = W::with("run-ignores", |p| p.program.run_time_s = 20);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("StopRun").after(100 * MS).ok("stop requested");
    });
    let ready = launched(&w, &mut waiter, &job);
    let began = now(&w);
    let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::GuestLost);
    let took = seconds(&w, began);
    assert!(
        (140..=145).contains(&took),
        "20 s limit plus 120 s grace: {took}"
    );
    assert_eq!(
        w.job(&job.id).run.unwrap().end_reason,
        Some(EndReason::GuestLost)
    );
}

#[test]
fn a_run_the_engine_reports_as_never_started_is_launch_failed() {
    let w = W::new("run-failed-to-start");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .then(3 * SECOND, |s| s.runs[0].state = RunState::FailedToStart)
            .ok("launched");
    });
    let ready = launched(&w, &mut waiter, &job);
    let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::LaunchFailed);
}

#[test]
fn an_interrupted_run_a_vanished_run_and_a_dead_vm_are_guest_lost() {
    type Edit = fn(&mut Snapshot);
    let cases: [(&str, Edit); 3] = [
        ("run-interrupted", |s| {
            s.runs[0].state = RunState::Interrupted;
        }),
        ("run-vanished", |s| s.runs.clear()),
        ("run-vm-failed", |s| {
            s.state = VmState::Failed;
            s.last_error = Some("qemu exited with status 1".into());
        }),
    ];
    for (name, edit) in cases {
        let w = W::new(name);
        let job = w.fx.running(1);
        let mut waiter = w.engine(|fake| {
            restore_ok(fake);
            upload_ok(fake);
            fake.on("Execute")
                .after(SECOND)
                .then(500 * MS, |s| s.runs.push(live_run()))
                .then(4 * SECOND, edit)
                .ok("launched");
        });
        let ready = launched(&w, &mut waiter, &job);
        let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
        assert_eq!(code(&stop), FailureCode::GuestLost, "{name}");
    }
}

#[test]
fn a_vm_that_stops_under_the_program_is_guest_lost() {
    let w = W::new("run-vm-stopped");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .then(4 * SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
            })
            .ok("launched");
    });
    let ready = launched(&w, &mut waiter, &job);
    let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::GuestLost);
}

/// What the engine shows when the lane's QEMU is killed in the run stage
/// (T7 qemu-kill, ANT-T0473): the VM is gone and the run `Finalized` by the
/// engine, with no end of the program from the guest.
pub(super) fn qemu_killed(execution_left: Option<RunExecution>) -> impl Fn(&mut Snapshot) {
    move |s| {
        s.state = VmState::Stopped;
        s.active_vm = None;
        s.last_error = Some("QEMU exited: signal 9".into());
        s.runs[0].state = RunState::Finalized;
        s.runs[0].execution = execution_left.clone();
    }
}

#[test]
fn a_qemu_killed_under_the_program_is_guest_lost_though_the_engine_finalized_the_run() {
    // The PC saw both: no execution state left, and one with no live task
    // and no exit status.
    for (name, left) in [
        ("run-qemu-killed", None),
        ("run-qemu-killed-exec", Some(execution(0, None))),
    ] {
        let w = W::new(name);
        let job = w.fx.running(1);
        let mut waiter = w.engine(|fake| {
            restore_ok(fake);
            upload_ok(fake);
            fake.on("Execute")
                .after(SECOND)
                .then(500 * MS, |s| s.runs.push(live_run()))
                .then(5 * SECOND, qemu_killed(left.clone()))
                .ok("launched");
        });
        let ready = launched(&w, &mut waiter, &job);
        let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
        assert_eq!(code(&stop), FailureCode::GuestLost, "{name}");
        let failure = stop.failure().unwrap();
        assert_eq!(failure.stage, Stage::Run, "{name}");
        assert!(
            failure.message.contains("VM stopped"),
            "{name}: {}",
            failure.message
        );
        let stored = w.job(&job.id);
        assert_eq!(
            stored.run.unwrap().end_reason,
            Some(EndReason::GuestLost),
            "{name}"
        );
        assert_eq!(
            stored.recording.unwrap().phase,
            RecordingPhase::Interrupted,
            "{name}"
        );
    }
}

#[test]
fn a_run_that_ended_before_the_vm_stopped_is_still_its_own_end() {
    // The guest reported the exit and no task left, then the VM ended: the
    // program's own end, not a lost guest.
    let w = W::new("run-ended-then-vm");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .then(
                5 * SECOND,
                qemu_killed(Some(execution(0, Some(WaitStatus::Exited { code: 0 })))),
            )
            .ok("launched");
    });
    let ready = launched(&w, &mut waiter, &job);
    let end = run_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!((end.reason, end.exit), (EndReason::Exited, Some(0)));
}

#[test]
fn sixty_seconds_without_the_engine_is_the_watchdogs_silence() {
    let w = W::new("run-silent");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("TerminalRead").forever().silent();
    });
    let ready = launched(&w, &mut waiter, &job);
    let began = now(&w);
    let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::Internal);
    let took = seconds(&w, began);
    assert!((59..=63).contains(&took), "{took}");
    assert!(
        stop.failure().unwrap().message.contains("went silent"),
        "{stop:?}"
    );
}

#[test]
fn an_engine_that_keeps_answering_is_never_silent() {
    let w = W::with("run-chatty", |p| p.program.run_time_s = 150);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(
            fake,
            Some((130 * SECOND, Some(WaitStatus::Exited { code: 0 }))),
        );
        // The terminal reads are answered (unscripted: a refusal is still an
        // answer), so 130 quiet seconds are not silence.
    });
    let ready = launched(&w, &mut waiter, &job);
    let end = run_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(end.reason, EndReason::Exited);
}

#[test]
fn a_cancel_stops_the_run_and_ends_the_stage_cancelled() {
    let w = W::new("run-cancel");
    let job = w.fx.running(1);
    let flag = Arc::new(AtomicBool::new(false));
    let raised = flag.clone();
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .call(6 * SECOND, move || raised.store(true, Ordering::SeqCst))
            .ok("launched");
        stop_run_ok(fake);
    });
    let ready = launched(&w, &mut waiter, &job);
    let polled = flag.clone();
    waiter.cancel_when(true, move || polled.load(Ordering::SeqCst));
    let began = now(&w);
    let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert!(matches!(stop, StageStop::Cancelled), "{stop:?}");
    assert!(seconds(&w, began) < 15, "it did not wait for the run limit");
    assert!(
        waiter
            .engine_mut()
            .sent_names()
            .contains(&"StopRun".to_owned())
    );
    assert_eq!(
        w.job(&job.id).run.unwrap().end_reason,
        Some(EndReason::Stopped)
    );
}

#[test]
fn a_cancelled_run_that_will_not_stop_is_given_up_after_the_grace() {
    let w = W::new("run-cancel-stuck");
    let job = w.fx.running(1);
    let flag = Arc::new(AtomicBool::new(false));
    let raised = flag.clone();
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .call(6 * SECOND, move || raised.store(true, Ordering::SeqCst))
            .ok("launched");
        fake.on("StopRun").ok("stop requested");
    });
    let ready = launched(&w, &mut waiter, &job);
    let polled = flag.clone();
    waiter.cancel_when(false, move || polled.load(Ordering::SeqCst));
    let began = now(&w);
    let stop = run_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert!(matches!(stop, StageStop::Cancelled), "{stop:?}");
    assert!((125..=135).contains(&seconds(&w, began)));
}

// ---- collect ------------------------------------------------------------

fn complete() -> RunArtifacts {
    RunArtifacts {
        network_state: RunArtifactState::Complete,
        memory_state: RunArtifactState::Disabled,
        core_state: RunArtifactState::Disabled,
        ..RunArtifacts::default()
    }
}

/// A launched and finished run, ready to be collected.
fn finished_run(
    w: &W,
    extra: impl FnOnce(&mut FakeEngine),
) -> (Job, Waiter<FakeEngine>, (Prepared, Launched)) {
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(
            fake,
            Some((3 * SECOND, Some(WaitStatus::Exited { code: 0 }))),
        );
        extra(fake);
    });
    let ready = launched(w, &mut waiter, &job);
    run_stage(w, &mut waiter, &job, &ready).expect("the run");
    (job, waiter, ready)
}

#[test]
fn collect_stops_the_vm_and_waits_for_the_recording() {
    let w = W::new("collect-ok");
    let (job, mut waiter, ready) = finished_run(&w, stop_ok);
    let end = collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(end.outcome, Outcome::Succeeded);
    assert!(end.warnings.is_empty() && !end.cancelled);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    assert_eq!(
        w.job(&job.id).recording.unwrap().phase,
        RecordingPhase::Complete
    );
    assert_eq!(
        waiter.engine_mut().sent_names().last().map(String::as_str),
        Some("Stop")
    );
}

#[test]
fn incomplete_evidence_makes_the_job_partial_not_failed() {
    let mut w = W::new("collect-partial");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::Partial,
            memory_state: RunArtifactState::Failed,
            core_state: RunArtifactState::Disabled,
            ..RunArtifacts::default()
        }))
    });
    let (job, mut waiter, ready) = finished_run(&w, stop_ok);
    let end = collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(end.outcome, Outcome::Partial);
    let codes: Vec<_> = end.warnings.iter().map(|w| w.code.as_str()).collect();
    assert_eq!(codes, ["network_partial", "memory_failed"]);
    let stored: Vec<_> = w
        .job(&job.id)
        .warnings
        .iter()
        .map(|w| w.code.clone())
        .filter(|code| code != "qemu_pid_unknown")
        .collect();
    assert_eq!(stored, ["network_partial", "memory_failed"]);
}

#[test]
fn collect_waits_for_evidence_that_is_still_being_written() {
    let mut w = W::new("collect-pending");
    let reads = Arc::new(AtomicUsize::new(0));
    let counter = reads.clone();
    w.evidence = Box::new(move |_| {
        let n = counter.fetch_add(1, Ordering::SeqCst);
        let mut artifacts = complete();
        if n < 30 {
            artifacts.network_state = RunArtifactState::InProgress;
        }
        Ok(Some(artifacts))
    });
    let (job, mut waiter, ready) = finished_run(&w, stop_ok);
    let began = now(&w);
    let end = collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(end.outcome, Outcome::Succeeded);
    assert!(reads.load(Ordering::SeqCst) > 30);
    assert!(seconds(&w, began) >= 3);
}

#[test]
fn evidence_that_never_completes_is_recording_failed_at_300_seconds() {
    let mut w = W::new("collect-never");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            memory_state: RunArtifactState::InProgress,
            ..complete()
        }))
    });
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        // The engine keeps talking, so only the stage deadline applies.
        chatter(fake, 30 * SECOND, 700 * SECOND);
    });
    let began = now(&w);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
    let took = seconds(&w, began);
    assert!((300..=302).contains(&took), "{took}");
    assert!(
        stop.failure()
            .unwrap()
            .detail
            .as_deref()
            .unwrap()
            .contains("memory")
    );
}

/// A finished run that asked for static analysis, which never reports.
fn finished_analysis_run(w: &W) -> (Job, Waiter<FakeEngine>, (Prepared, Launched)) {
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .then(3 * SECOND, |s| {
                ended(Some(WaitStatus::Exited { code: 0 }))(s);
                s.runs[0].request.analysis.enabled = true;
            })
            .ok("launched pid 750, terminal session 1");
        stop_ok(fake);
        // The engine keeps talking, so only the stage deadline applies.
        chatter(fake, 30 * SECOND, 700 * SECOND);
    });
    let ready = launched(w, &mut waiter, &job);
    run_stage(w, &mut waiter, &job, &ready).expect("the run");
    (job, waiter, ready)
}

#[test]
fn a_slow_static_analysis_does_not_fail_a_complete_recording() {
    let w = W::new("collect-analysis-late");
    let (job, mut waiter, ready) = finished_analysis_run(&w);
    let began = now(&w);
    let end = collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert!((300..=310).contains(&seconds(&w, began)));
    assert_eq!(end.outcome, Outcome::Succeeded, "{:?}", end.warnings);
    assert!(end.warnings.is_empty());
    assert_eq!(end.pending, ["analysis"]);
    let stored = w.job(&job.id);
    assert_eq!(stored.run.unwrap().pending, ["analysis"]);
    assert_eq!(stored.recording.unwrap().phase, RecordingPhase::Complete);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
}

#[test]
fn network_evidence_pending_beside_the_analysis_still_fails_the_wait() {
    let mut w = W::new("collect-analysis-and-network");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::InProgress,
            ..complete()
        }))
    });
    let (job, mut waiter, ready) = finished_analysis_run(&w);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
    let detail = stop.failure().unwrap().detail.clone().unwrap();
    assert!(
        detail.contains("network") && detail.contains("analysis"),
        "{detail}"
    );
}

#[test]
fn a_quiet_engine_warns_at_120_seconds_and_ends_the_wait_at_240() {
    let mut w = W::new("collect-stall");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::InProgress,
            ..complete()
        }))
    });
    let (job, mut waiter, ready) = finished_run(&w, |_| {});
    let began = now(&w);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
    let took = seconds(&w, began);
    assert!((238..=242).contains(&took), "twice stall_s: {took}");
    assert!(stop.failure().unwrap().message.contains("went quiet"));
    let warnings = w.job(&job.id).warnings;
    assert_eq!(
        warnings
            .iter()
            .filter(|w| w.code == "collect_stalled")
            .count(),
        1
    );
}

#[test]
fn a_vm_that_fails_while_the_evidence_is_written_is_guest_lost() {
    let mut w = W::new("collect-vm-failed");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::InProgress,
            ..complete()
        }))
    });
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.after(20 * SECOND, |s| s.state = VmState::Failed);
        chatter(fake, 5 * SECOND, 60 * SECOND);
    });
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::GuestLost);
}

#[test]
fn an_unreadable_evidence_file_is_recording_failed() {
    let mut w = W::new("collect-unreadable");
    w.evidence = Box::new(|_| Err("run artifacts: damaged".into()));
    let (job, mut waiter, ready) = finished_run(&w, stop_ok);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
}

#[test]
fn a_stop_nobody_answers_ends_the_recorded_qemu_by_force() {
    let w = W::new("collect-hung-stop");
    qemu(&w, 900, 5);
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.on("Stop")
            .then(125 * SECOND, |s| s.state = VmState::Failed)
            .silent();
    });
    let began = now(&w);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
    assert_eq!(w.procs.killed.borrow().as_slice(), [900]);
    let took = seconds(&w, began);
    assert!(
        (120..=135).contains(&took),
        "stop_s then the hard path: {took}"
    );
    let warnings = w.job(&job.id).warnings;
    assert!(
        warnings
            .iter()
            .any(|w| w.code == "vm_hard_stop" && w.text.contains("900"))
    );
}

#[test]
fn the_hard_path_leaves_a_process_alone_when_it_is_not_the_recorded_one() {
    let w = W::new("collect-hung-other");
    qemu(&w, 900, 5);
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.on("Stop").silent();
    });
    // The pid was reused by another process after the start was recorded.
    w.procs
        .procs
        .borrow_mut()
        .get_mut(&900)
        .unwrap()
        .start_ticks = Some(6);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
    assert!(w.procs.killed.borrow().is_empty());
    assert!(
        w.job(&job.id)
            .warnings
            .iter()
            .any(|w| w.text.contains("left alone"))
    );
}

#[test]
fn a_disk_layer_that_never_settles_is_recording_failed_after_layer_s() {
    let w = W::new("collect-layer");
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.on("Stop")
            .after(SECOND)
            .then(2 * SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
                s.disk_layers = vec![crate::lane::tests::layer(LayerPhase::Finalizing)];
            })
            .ok("VM stopped");
    });
    let began = now(&w);
    let stop = collect_stage(&w, &mut waiter, &job, &ready).unwrap_err();
    assert_eq!(code(&stop), FailureCode::RecordingFailed);
    let took = seconds(&w, began);
    assert!((1800..=1810).contains(&took), "layer_s: {took}");
}

#[test]
fn collect_waits_for_the_layer_before_it_lets_the_lane_go() {
    let w = W::new("collect-layer-ok");
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.on("Stop")
            .after(SECOND)
            .then(2 * SECOND, |s| {
                s.state = VmState::Stopped;
                s.active_vm = None;
                s.disk_layers = vec![crate::lane::tests::layer(LayerPhase::Finalizing)];
            })
            .then(600 * SECOND, |s| s.disk_layers.clear())
            .ok("VM stopped");
    });
    let began = now(&w);
    let end = collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert_eq!(end.outcome, Outcome::Succeeded);
    assert!(seconds(&w, began) >= 600);
    assert!(waiter.snapshot().disk_layers.is_empty());
}

#[test]
fn a_cancel_during_the_evidence_wait_still_stops_the_vm_and_keeps_the_recording() {
    let mut w = W::new("collect-cancel");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::InProgress,
            ..complete()
        }))
    });
    let flag = Arc::new(AtomicBool::new(false));
    let raised = flag.clone();
    let (job, mut waiter, ready) = finished_run(&w, |fake| {
        fake.after(30 * SECOND, move |_| raised.store(true, Ordering::SeqCst));
        chatter(fake, 5 * SECOND, 100 * SECOND);
        stop_ok(fake);
    });
    let polled = flag.clone();
    waiter.cancel_when(true, move || polled.load(Ordering::SeqCst));
    let end = collect_stage(&w, &mut waiter, &job, &ready).unwrap();
    assert!(end.cancelled);
    assert_eq!(
        waiter.snapshot().state,
        VmState::Stopped,
        "the VM was stopped"
    );
    assert_eq!(
        w.job(&job.id).recording.unwrap().phase,
        RecordingPhase::Complete
    );
}

#[test]
fn the_stop_helper_reports_how_the_vm_was_left() {
    let w = W::new("stopped-helper");
    let job = w.fx.running(1);
    // Already stopped and settled: no command at all.
    let mut waiter = w.engine(|_| {});
    let stopped = w
        .stages(&mut waiter)
        .stop_lane_vm(&job, crate::lane::tests::VM, Duration::from_secs(120))
        .unwrap();
    assert_eq!(stopped, Stopped::Settled);
    assert!(waiter.engine_mut().sent().is_empty());
    // Another VM is not ours.
    let mut other = w.engine(|fake| {
        fake.start_with(|s| {
            crate::lane::tests::healthy(s);
            s.state = VmState::Running;
            s.active_vm = Some("someone-elses".into());
        });
    });
    let stopped = w
        .stages(&mut other)
        .stop_lane_vm(&job, crate::lane::tests::VM, Duration::from_secs(120))
        .unwrap();
    assert!(matches!(stopped, Stopped::Unsettled(_)));
    assert!(other.engine_mut().sent().is_empty());
    let _ = (Stage::Collect, cycle);
}

// SPDX-License-Identifier: GPL-3.0-only
//! A guest transition during a lane job (ANT-T0479, the PC's finding P6).
//! While the engine reconnects to a guest that stopped answering, or restores
//! a snapshot, it refuses guest commands ("guest transition in progress").
//! That is never `internal`: the stages wait within their own limits, and a
//! guest that does not come back is `guest_lost` once the program runs,
//! `guest_unreachable` before it. A run the disk floor stopped ends `stopped`
//! and the job `partial`, however the guest takes the stop. FakeEngine and a
//! manual clock.
use super::{
    Driven, HostChecks, HostProblem,
    run_tests::{chatter, execute_run, launched, stop_ok, stop_run_ok},
    tests::{MS, SECOND, W, restore_ok, upload_ok},
};
use crate::{
    api::{
        failure::FailureCode,
        run::{EndReason, Outcome, Run, Stage},
    },
    config::Preset,
    engine::{
        FakeEngine,
        fake::{TRANSITION_CANCEL, TRANSITION_REFUSAL},
    },
    waiter::{WaitError, guest_transition, transition_failure},
};
use antinomie_monitor_core::{RunArtifactState, RunArtifacts, VmState};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// A host whose disk falls below the floor when the flag is set.
struct Floor(Arc<AtomicBool>);

impl HostChecks for Floor {
    fn check(&self, _: &Run, _: &Preset) -> Result<(), HostProblem> {
        Ok(())
    }
    fn low_disk(&self) -> Option<String> {
        self.0
            .load(Ordering::SeqCst)
            .then(|| "/data has 3 GiB free, 20 GiB are needed".to_owned())
    }
}

fn failure_of(driven: &Driven) -> crate::api::failure::Failure {
    match driven {
        Driven::Retried { failure, .. } | Driven::Failed(failure) => failure.clone(),
        other => panic!("{other:?}"),
    }
}

fn now(w: &W) -> u64 {
    use crate::clock::Clock;
    w.fx.clock.now_ms()
}

fn stop_runs_sent(fake: &mut FakeEngine) -> Vec<u64> {
    fake.sent()
        .into_iter()
        .filter(|s| s.name == "StopRun")
        .map(|s| s.at_ms)
        .collect()
}

#[test]
fn the_engines_transition_words_are_known_and_others_are_not() {
    assert!(guest_transition(TRANSITION_REFUSAL));
    assert!(guest_transition(TRANSITION_CANCEL));
    assert!(!guest_transition("unknown run"));
    assert!(!guest_transition(
        "guest command 0x1001: Read-only file system (os error 30)"
    ));
    // Once the program runs the guest is lost; before, the sample did not
    // run, so it cannot have crashed the guest.
    for (stage, code) in [
        (Stage::Upload, FailureCode::GuestUnreachable),
        (Stage::Launch, FailureCode::GuestUnreachable),
        (Stage::Run, FailureCode::GuestLost),
        (Stage::Collect, FailureCode::GuestLost),
    ] {
        assert_eq!(transition_failure(stage, "words").code, code, "{stage:?}");
    }
}

#[test]
fn a_guest_that_hangs_under_the_program_is_guest_lost_and_retried_not_internal() {
    // The PC's T7 guest-panic on Debian: the guest hangs with QEMU alive, the
    // engine's reconnect attempts refuse the lane's terminal reads and its
    // StopRun, then it gives up and fails the VM. Before: `internal`, "the
    // engine failed the lane", not retried.
    let w = W::with("transition-hang", |p| p.program.run_time_s = 60);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        // Five reconnect attempts of 10 s, 2 to 16 s apart, from 20 s on; the
        // run limit (about 68 s) falls inside the fourth.
        for (from, until) in [(20, 30), (32, 42), (46, 56), (64, 74), (90, 100)] {
            fake.guest_transition(SECOND * from, SECOND * until);
        }
        fake.after(100 * SECOND, |s| {
            s.state = VmState::Failed;
            s.last_error = Some(
                "the guest stopped answering and 5 reconnections failed: transport timed out"
                    .into(),
            );
        });
        chatter(fake, 5 * SECOND, 400 * SECOND);
        stop_ok(fake);
    });
    let driven = w.stages(&mut waiter).drive(&job);
    assert!(matches!(driven, Driven::Retried { .. }), "{driven:?}");
    let failure = failure_of(&driven);
    assert_eq!(failure.code, FailureCode::GuestLost, "{failure:?}");
    assert_eq!(failure.stage, Stage::Run);
    let fake = waiter.engine_mut();
    assert!(
        fake.refused()
            .iter()
            .any(|(name, _)| name == "TerminalRead"),
        "the engine did refuse guest commands"
    );
    // The StopRun refused at the limit was asked again after the attempt.
    let stops = stop_runs_sent(fake);
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert!(stops[0] >= 74_000, "{stops:?}");
    let stored = w.job(&job.id);
    assert_eq!(stored.program.unwrap().end_reason, Some(EndReason::GuestLost));
    let file = w.lane_file();
    assert!(file.quarantine.is_none() && file.current.is_none());
}

#[test]
fn a_hung_guest_that_refuses_the_stop_is_guest_lost_after_the_limit_and_the_grace() {
    // QEMU alive, the guest silent, the VM never failed: the run limit, then
    // 120 s after StopRun, and `guest_lost`, whatever the engine refused
    // meanwhile.
    let w = W::with("transition-stop-refused", |p| p.program.run_time_s = 20);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("StopRun").after(100 * MS).ok("stop requested");
    });
    let ready = launched(&w, &mut waiter, &job);
    let began = now(&w);
    waiter
        .engine_mut()
        .guest_transition(15 * SECOND, 40 * SECOND);
    chatter(waiter.engine_mut(), 5 * SECOND, 300 * SECOND);
    let stop = w
        .stages(&mut waiter)
        .run(&job, &ready.0, &ready.1)
        .unwrap_err();
    let failure = stop.failure().unwrap_or_else(|| panic!("{stop:?}"));
    assert_eq!(failure.code, FailureCode::GuestLost, "{failure:?}");
    assert_eq!(
        failure.message,
        "the run did not end after it was told to stop"
    );
    let took = (now(&w) - began) / 1000;
    assert!(
        (140..=145).contains(&took),
        "20 s limit plus 120 s grace: {took}"
    );
    let stops = stop_runs_sent(waiter.engine_mut());
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert!(stops[0] >= began + 40_000, "sent once the guest was back");
}

#[test]
fn a_stop_run_the_engine_cancelled_at_a_guest_transition_is_sent_again() {
    // The engine had taken StopRun when a reconnect began and cancelled it at
    // the boundary: the run must still be stopped, not given up as lost.
    let w = W::with("transition-stop-cancelled", |p| p.program.run_time_s = 20);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("StopRun").after(100 * MS).fail(TRANSITION_CANCEL);
        stop_run_ok(fake);
    });
    let ready = launched(&w, &mut waiter, &job);
    let end = w
        .stages(&mut waiter)
        .run(&job, &ready.0, &ready.1)
        .expect("the run ends at its limit");
    assert_eq!(end.reason, EndReason::TimeLimit);
    assert_eq!(stop_runs_sent(waiter.engine_mut()).len(), 2);
}

#[test]
fn a_floor_stop_refused_during_a_guest_transition_still_ends_the_run_stopped_and_the_job_partial() {
    // The PC's T7 disk-full (b) on BusyBox: the floor check's StopRun was
    // refused and the job ended `failed internal`. Design 4.6.3: the run
    // ends `stopped`, the job `partial` with `low_disk`.
    let mut w = W::new("transition-floor");
    let job = w.fx.running(1);
    let low = Arc::new(AtomicBool::new(false));
    w.host = Box::new(Floor(low.clone()));
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        stop_run_ok(fake);
        stop_ok(fake);
        fake.call_after(100 * SECOND, move || low.store(true, Ordering::SeqCst));
        // The floor is seen at the minute mark near 128 s, inside this.
        fake.guest_transition(110 * SECOND, 140 * SECOND);
        chatter(fake, 5 * SECOND, 400 * SECOND);
    });
    let driven = w.stages(&mut waiter).drive(&job);
    let Driven::Collected(end) = driven else {
        panic!("{driven:?}");
    };
    assert_eq!(end.outcome, Outcome::Partial);
    let stored = w.job(&job.id);
    assert_eq!(stored.program.unwrap().end_reason, Some(EndReason::Stopped));
    assert!(stored.warnings.iter().any(|x| x.code == "low_disk"));
    let fake = waiter.engine_mut();
    assert!(fake.refused().iter().any(|(name, _)| name == "StopRun"));
    let stops = stop_runs_sent(fake);
    assert_eq!(stops.len(), 1, "{stops:?}");
    assert!(stops[0] >= 140_000, "{stops:?}");
}

#[test]
fn a_floor_stopped_run_the_guest_never_ends_is_stopped_and_partial_not_guest_lost() {
    // On a full disk the guest may be held on a write and never confirm the
    // stop, and the VM may fail after it. The run was stopped for the floor
    // all the same: `stopped`, `partial`, the missing evidence a warning.
    let mut w = W::new("transition-floor-hung");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::InProgress,
            memory_state: RunArtifactState::Disabled,
            core_state: RunArtifactState::Disabled,
            ..RunArtifacts::default()
        }))
    });
    let low = Arc::new(AtomicBool::new(false));
    w.host = Box::new(Floor(low.clone()));
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("StopRun").after(100 * MS).ok("stop requested");
        fake.call_after(100 * SECOND, move || low.store(true, Ordering::SeqCst));
        fake.after(300 * SECOND, |s| {
            s.state = VmState::Failed;
            s.last_error = Some("the guest stopped answering and 5 reconnections failed".into());
        });
        chatter(fake, 5 * SECOND, 900 * SECOND);
        stop_ok(fake);
    });
    let driven = w.stages(&mut waiter).drive(&job);
    let Driven::Collected(end) = driven else {
        panic!("{driven:?}");
    };
    assert_eq!(end.outcome, Outcome::Partial);
    let stored = w.job(&job.id);
    assert_eq!(stored.program.unwrap().end_reason, Some(EndReason::Stopped));
    let codes: Vec<_> = stored.warnings.iter().map(|x| x.code.as_str()).collect();
    assert!(
        codes.contains(&"low_disk") && codes.contains(&"evidence_incomplete"),
        "{codes:?}"
    );
}

#[test]
fn an_upload_refused_during_a_guest_transition_is_sent_again_once_the_guest_is_back() {
    // Before: the refusal was `upload_failed` and cost an attempt.
    let w = W::new("transition-upload");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        fake.on("UploadSample")
            .after(60 * MS)
            .ok("uploaded 4096 bytes to /tmp/01010101-sample-1");
        execute_run(fake, Some((3 * SECOND, None)));
        stop_ok(fake);
        // The restore is not a guest command; the upload (about 4.4 s) is.
        fake.guest_transition(std::time::Duration::ZERO, 20 * SECOND);
    });
    let driven = w.stages(&mut waiter).drive(&job);
    assert!(matches!(driven, Driven::Collected(_)), "{driven:?}");
    let fake = waiter.engine_mut();
    assert!(
        fake.refused()
            .iter()
            .any(|(name, _)| name == "UploadSample")
    );
    let uploads: Vec<_> = fake
        .sent()
        .into_iter()
        .filter(|s| s.name == "UploadSample")
        .collect();
    assert_eq!(uploads.len(), 1);
    assert!(uploads[0].at_ms >= 20_000, "{uploads:?}");
}

#[test]
fn a_launch_the_engine_cancelled_while_it_lost_the_guest_is_guest_unreachable_not_launch_failed() {
    // The engine took `Execute`, began a reconnect and cancelled it at the
    // boundary, then failed the VM: nothing was started. Before: the
    // permanent `launch_failed` "the guest refused to start the program".
    let w = W::new("transition-launch");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(SECOND + 500 * MS, |s| {
                s.state = VmState::Failed;
                s.last_error = Some("the guest stopped answering".into());
            })
            .fail(TRANSITION_CANCEL);
        chatter(fake, 5 * SECOND, 60 * SECOND);
        stop_ok(fake);
    });
    let driven = w.stages(&mut waiter).drive(&job);
    assert!(matches!(driven, Driven::Retried { .. }), "{driven:?}");
    let failure = failure_of(&driven);
    assert_eq!(failure.code, FailureCode::GuestUnreachable, "{failure:?}");
    assert_eq!(failure.stage, Stage::Launch);
    assert!(
        failure
            .detail
            .as_deref()
            .is_some_and(|d| d.contains("snapshot/reconnect boundary")),
        "{failure:?}"
    );
}

#[test]
fn a_transition_error_that_reaches_the_end_of_the_job_is_never_internal() {
    // Any path that lets the engine's refusal through: the job's ending maps
    // it by the stage, never to `internal`.
    let w = W::new("transition-settle");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        stop_ok(fake);
    });
    let _ = launched(&w, &mut waiter, &job);
    w.fx.store.begin_stage(&job.id, Stage::Run).unwrap();
    let driven = w.stages(&mut waiter).settle_for_test(
        &job,
        super::StageStop::Abort(WaitError::GuestTransition(TRANSITION_REFUSAL.into())),
    );
    let failure = failure_of(&driven);
    assert_eq!(failure.code, FailureCode::GuestLost, "{failure:?}");
}

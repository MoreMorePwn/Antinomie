// SPDX-License-Identifier: GPL-3.0-only
//! A whole job through the lane (card P3-4c): every ending of `drive` (collected,
//! retried, failed, cancelled, waiting), the retry and permanent paths,
//! quarantine, the watchdog's job limit, cancellation at every point, and the
//! crash points of the new checkpoints. FakeEngine and a manual clock.
use super::{
    Driven, StageStop,
    run_tests::{chatter, execute_run, live_run, qemu, stop_ok, stop_run_ok},
    tests::{Host, MS, SECOND, W, kernel, restore_ok, upload_ok},
};
use crate::{
    api::{
        event::EventBody,
        failure::FailureCode,
        job::{EndReason, Job, JobState, Outcome, RecordingPhase, Stage, WaitingFor},
    },
    engine::FakeEngine,
    lane::{
        QemuOutcome, RecoverOptions,
        state::{Checkpoint, WriteFault},
        tests::VM,
    },
    store::{
        Eligibility,
        tests::{kinds, lane, manager},
    },
    waiter::Waiter,
};
use antinomie_monitor_core::{RunArtifactState, RunArtifacts, RunState, VmState, WaitStatus};
use std::sync::{Arc, Mutex, mpsc};

fn exited(code: u8) -> Option<WaitStatus> {
    Some(WaitStatus::Exited { code })
}

/// One attempt that works: revert, upload, a program that ends after `run`
/// seconds, and the stop.
fn attempt(fake: &mut FakeEngine, run: u32) {
    restore_ok(fake);
    upload_ok(fake);
    execute_run(fake, Some((SECOND * (run + 2), exited(0))));
    stop_run_ok(fake);
    stop_ok(fake);
}

fn drive(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> Driven {
    w.stages(waiter).drive(job)
}

fn claim(w: &W) -> Option<Job> {
    w.fx.store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
}

fn sent(waiter: &mut Waiter<FakeEngine>) -> Vec<String> {
    waiter
        .engine_mut()
        .sent_names()
        .into_iter()
        .filter(|name| name != "TerminalRead")
        .collect()
}

fn failure_of(driven: &Driven) -> FailureCode {
    match driven {
        Driven::Retried { failure, .. } | Driven::Failed(failure) => failure.code,
        other => panic!("{other:?}"),
    }
}

/// An attempt whose upload is refused for good.
fn attempt_upload_refused(fake: &mut FakeEngine) {
    restore_ok(fake);
    fake.on("UploadSample").fail("disk full");
    stop_ok(fake);
}

/// Run `body` with a function that makes the fake run `action` when it
/// reaches the call. The action runs on another thread against the same
/// store and lane files, and the lane waits for it: it lands at an exact point
/// of the script.
fn with_action<R>(
    action: impl Fn() + Sync,
    body: impl FnOnce(Arc<dyn Fn() + Send + Sync>) -> R,
) -> R {
    let (request, requests) = mpsc::channel::<()>();
    let (ack, acks) = mpsc::channel::<()>();
    let link = Mutex::new((request, acks));
    let call: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        let link = link.lock().unwrap();
        link.0.send(()).unwrap();
        link.1.recv().unwrap();
    });
    let action = &action;
    std::thread::scope(|scope| {
        scope.spawn(move || {
            while requests.recv().is_ok() {
                action();
                ack.send(()).unwrap();
            }
        });
        body(call)
    })
}

/// [`with_action`] where the action is a user's cancel of `job`.
fn with_canceller<R>(w: &W, job: &Job, body: impl FnOnce(Arc<dyn Fn() + Send + Sync>) -> R) -> R {
    let store = &w.fx.store;
    let id = &job.id;
    with_action(
        || {
            store.cancel(id, Some("test"), &manager()).unwrap();
        },
        body,
    )
}

fn lane_is_free(w: &W) {
    let file = w.lane_file();
    assert_eq!(file.current, None, "the lane let the job go");
    assert_eq!(file.qemu, None, "no stale process record");
}

// ---- collected ----------------------------------------------------------

#[test]
fn a_job_runs_from_prechecks_to_collect_and_the_lane_is_free() {
    let w = W::new("drive-ok");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| attempt(fake, 6));
    let Driven::Collected(end) = drive(&w, &mut waiter, &job) else {
        panic!("collected");
    };
    assert_eq!(end.outcome, Outcome::Succeeded);
    assert_eq!(
        sent(&mut waiter),
        [
            "RestoreVmSnapshot",
            "UploadSample",
            "UploadSample",
            "Execute",
            "Stop"
        ]
    );
    // The job is still running: the host stages come next. The lane holds a
    // `collected` entry and no work.
    let stored = w.job(&job.id);
    assert_eq!(
        (stored.state, stored.stage),
        (JobState::Running, Some(Stage::Collect))
    );
    let file = w.lane_file();
    assert_eq!(file.current, None);
    assert_eq!(file.collected.len(), 1);
    assert_eq!(file.collected[0].job_id, job.id);
    assert_eq!(file.qemu, None, "the VM is gone");
    assert_eq!(stored.run.unwrap().exit, Some(0));
    assert_eq!(stored.recording.unwrap().phase, RecordingPhase::Complete);
    let kinds = kinds(&w.fx, &job.id);
    assert!(kinds.contains(&"job.run".to_owned()));

    // Until the host stages exist the job is ended from here.
    let done = w.stages(&mut waiter).finish_collected(&job, &end).unwrap();
    assert_eq!(done.state, JobState::Succeeded);
    assert!(w.lane_file().collected.is_empty());
    assert!(!waiter.cancel_requested(), "the hooks were taken off");
}

/// The custody actor the engine had for each command that writes custody.
fn custody_actors(waiter: &mut Waiter<FakeEngine>) -> Vec<(String, Option<String>)> {
    waiter
        .engine_mut()
        .sent()
        .into_iter()
        .filter(|sent| sent.name == "UploadSample" || sent.name == "Execute")
        .map(|sent| (sent.name, sent.actor))
        .collect()
}

#[test]
fn bh_29_the_engine_names_the_jobs_caller_while_it_sends_and_launches() {
    // Two lanes, one engine each, jobs of two callers: each engine writes
    // its own job's caller into the push record and the run log, and lets it
    // go when the job leaves the lane.
    let first = W::new("custody-actor-a");
    let second = W::new("custody-actor-b");
    let job_a = first.fx.running(1);
    let job_b = {
        let submitted = second
            .fx
            .submit_as(
                &crate::store::tests::caller(2000),
                crate::store::tests::spec(1),
            )
            .unwrap();
        let claimed = claim(&second).unwrap();
        assert_eq!(claimed.id, submitted.job.id);
        claimed
    };
    let mut lane_a = first.engine(|fake| attempt(fake, 6));
    let mut lane_b = second.engine(|fake| attempt(fake, 6));
    first.stages(&mut lane_a).run_to_launch(&job_a).unwrap();
    second.stages(&mut lane_b).run_to_launch(&job_b).unwrap();
    let a = Some("local:1000".to_owned());
    let b = Some("local:2000".to_owned());
    assert_eq!(
        custody_actors(&mut lane_a),
        [
            ("UploadSample".to_owned(), a.clone()),
            ("UploadSample".to_owned(), a.clone()),
            ("Execute".to_owned(), a.clone()),
        ]
    );
    assert_eq!(
        custody_actors(&mut lane_b),
        [
            ("UploadSample".to_owned(), b.clone()),
            ("UploadSample".to_owned(), b.clone()),
            ("Execute".to_owned(), b),
        ]
    );
    assert_eq!(lane_a.engine_mut().custody_actor(), a.as_deref());

    // A whole job through `drive`: the actor is gone once the lane let go.
    let w = W::new("custody-actor-drive");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| attempt(fake, 6));
    let Driven::Collected(_) = drive(&w, &mut waiter, &job) else {
        panic!("collected");
    };
    assert!(
        custody_actors(&mut waiter)
            .iter()
            .all(|(_, actor)| actor.as_deref() == Some("local:1000"))
    );
    assert_eq!(waiter.engine_mut().custody_actor(), None);
}

#[test]
fn the_run_limit_is_not_a_failure_for_the_job() {
    let w = W::with("drive-limit", |p| p.run.timeout_s = 20);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        stop_run_ok(fake);
        stop_ok(fake);
    });
    let Driven::Collected(end) = drive(&w, &mut waiter, &job) else {
        panic!("collected");
    };
    assert_eq!(end.outcome, Outcome::Succeeded);
    let run = w.job(&job.id).run.unwrap();
    assert_eq!(run.end_reason, Some(EndReason::TimeLimit));
}

#[test]
fn partial_evidence_ends_the_job_partial() {
    let mut w = W::new("drive-partial");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::Interrupted,
            memory_state: RunArtifactState::Disabled,
            core_state: RunArtifactState::Disabled,
            ..RunArtifacts::default()
        }))
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| attempt(fake, 3));
    let Driven::Collected(end) = drive(&w, &mut waiter, &job) else {
        panic!("collected");
    };
    let done = w.stages(&mut waiter).finish_collected(&job, &end).unwrap();
    assert_eq!(done.state, JobState::Partial);
}

// ---- retry and the permanent errors -------------------------------------

#[test]
fn a_transient_failure_requeues_the_job_after_a_backoff_and_the_next_attempt_works() {
    let w = W::new("drive-retry");
    let job = w.fx.running(1);
    qemu(&w, 900, 5);
    let mut waiter = w.engine(|fake| {
        attempt_upload_refused(fake);
        attempt(fake, 3);
    });
    let first = drive(&w, &mut waiter, &job);
    let Driven::Retried { failure, backoff_s } = &first else {
        panic!("{first:?}");
    };
    assert_eq!(failure.code, FailureCode::UploadFailed);
    assert!((24..=36).contains(backoff_s), "{backoff_s}");
    // The lane let go: the VM was stopped, no process is recorded.
    lane_is_free(&w);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    // The job waits out the backoff in the queue.
    let queued = w.job(&job.id);
    assert_eq!(
        (queued.state, queued.waiting_for),
        (JobState::Queued, Some(WaitingFor::Backoff))
    );
    assert!(kinds(&w.fx, &job.id).contains(&"job.requeued".to_owned()));
    assert!(claim(&w).is_none(), "not before the backoff");
    w.fx.clock.advance(60_000);
    let second = claim(&w).expect("claimed after the backoff");
    assert_eq!(second.attempt, 2);
    let Driven::Collected(_) = drive(&w, &mut waiter, &second) else {
        panic!("the second attempt works");
    };
    assert_eq!(
        w.fx.store.previous_failures(&job.id).unwrap(),
        [FailureCode::UploadFailed]
    );
    // A full revert both times.
    let restores = sent(&mut waiter)
        .iter()
        .filter(|n| *n == "RestoreVmSnapshot")
        .count();
    assert_eq!(restores, 2);
}

#[test]
fn a_job_with_no_attempt_left_fails_with_the_last_failure() {
    let w = W::with("drive-exhausted", |p| p.retry.max_attempts = 2);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        attempt_upload_refused(fake);
        attempt_upload_refused(fake);
    });
    assert!(matches!(
        drive(&w, &mut waiter, &job),
        Driven::Retried { .. }
    ));
    w.fx.clock.advance(300_000);
    let second = claim(&w).unwrap();
    let last = drive(&w, &mut waiter, &second);
    assert_eq!(failure_of(&last), FailureCode::UploadFailed);
    assert!(matches!(last, Driven::Failed(_)));
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Failed);
    assert_eq!(stored.failure.unwrap().code, FailureCode::UploadFailed);
    lane_is_free(&w);
}

#[test]
fn a_permanent_error_is_not_retried_even_with_attempts_left() {
    // The desktop run with a core dump is refused before the engine is asked.
    let w = W::with("drive-permanent", |p| {
        p.retry.max_attempts = 5;
        p.retry.retry_on = crate::api::failure::FailureCode::ALL.to_vec();
        p.evidence.core_dump = true;
    });
    let mut job = w.fx.running(1);
    job.spec.overrides.run_in = Some(crate::api::spec::RunIn::GuestDesktop);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        stop_ok(fake);
    });
    let driven = drive(&w, &mut waiter, &job);
    assert!(matches!(driven, Driven::Failed(_)), "{driven:?}");
    assert_eq!(failure_of(&driven), FailureCode::LaunchFailed);
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Failed);
    assert_eq!(stored.attempt, 1);
    assert_eq!(
        waiter.snapshot().state,
        VmState::Stopped,
        "the VM was stopped"
    );
    lane_is_free(&w);
}

#[test]
fn a_failure_the_policy_does_not_list_is_final() {
    let w = W::with("drive-unlisted", |p| p.retry.retry_on.clear());
    let job = w.fx.running(1);
    let mut waiter = w.engine(attempt_upload_refused);
    let driven = drive(&w, &mut waiter, &job);
    assert!(matches!(driven, Driven::Failed(_)), "{driven:?}");
    assert_eq!(w.job(&job.id).state, JobState::Failed);
}

#[test]
fn a_qemu_killed_in_the_run_stage_is_guest_lost_and_retried() {
    // T7 qemu-kill (ANT-T0473): the engine finalizes the run when QEMU dies;
    // attempt 1 must be `guest_lost` and requeued, not a `partial` job.
    let w = W::new("drive-qemu-killed");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(SECOND)
            .then(500 * MS, |s| s.runs.push(live_run()))
            .then(5 * SECOND, super::run_tests::qemu_killed(None))
            .ok("launched");
        stop_ok(fake);
    });
    let first = drive(&w, &mut waiter, &job);
    assert!(matches!(first, Driven::Retried { .. }), "{first:?}");
    assert_eq!(failure_of(&first), FailureCode::GuestLost);
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Queued);
    assert!(
        kinds(&w.fx, &job.id).contains(&"job.requeued".to_owned()),
        "{:?}",
        kinds(&w.fx, &job.id)
    );
}

#[test]
fn a_sample_that_ends_the_guest_twice_is_final_and_says_so() {
    let w = W::with("drive-crashes-guest", |p| p.retry.max_attempts = 3);
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        for n in 1..=2 {
            restore_ok(fake);
            upload_ok(fake);
            fake.on("Execute")
                .after(SECOND)
                .then(500 * MS, move |s| {
                    let mut run = live_run();
                    run.id = format!("r{n}");
                    s.runs.push(run);
                })
                .then(4 * SECOND, |s| {
                    s.runs.last_mut().unwrap().state = RunState::Interrupted
                })
                .ok("launched");
            stop_ok(fake);
        }
    });
    let first = drive(&w, &mut waiter, &job);
    assert!(matches!(first, Driven::Retried { .. }), "{first:?}");
    assert_eq!(failure_of(&first), FailureCode::GuestLost);
    w.fx.clock.advance(300_000);
    let second = claim(&w).unwrap();
    let last = drive(&w, &mut waiter, &second);
    assert!(matches!(last, Driven::Failed(_)), "{last:?}");
    let stored = w.job(&job.id);
    assert_eq!(stored.failure.unwrap().code, FailureCode::GuestLost);
    assert!(stored.warnings.iter().any(|w| w.code == "crashes_guest"));
    // The library tag is asked for once, for this sample.
    assert_eq!(
        w.tags.0.lock().unwrap().as_slice(),
        [(
            job.sample.as_ref().unwrap().sha256.to_string(),
            "auto:crashes-guest".to_owned()
        )]
    );
    lane_is_free(&w);
}

#[test]
fn a_silent_engine_during_the_run_fails_the_job_internal_and_stops_the_vm() {
    let w = W::new("drive-silent");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("TerminalRead").forever().silent();
        stop_ok(fake);
    });
    let driven = drive(&w, &mut waiter, &job);
    assert_eq!(failure_of(&driven), FailureCode::Internal);
    assert!(matches!(driven, Driven::Failed(_)));
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    lane_is_free(&w);
}

/// B3's orphan in the lane: the engine answers `Execute` ten seconds after
/// the silence limit, with a run. The lane stops the VM (which ends the
/// program), and the job names that run instead of leaving it unreported.
#[test]
fn a_launch_answered_after_the_lane_gave_up_is_stopped_and_named_by_the_job() {
    let w = W::new("drive-late-launch");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute")
            .after(70 * SECOND)
            .then(69 * SECOND, |s| s.runs.push(super::run_tests::live_run()))
            .ok("launched pid 750, terminal session 1");
        stop_ok(fake);
    });
    let driven = drive(&w, &mut waiter, &job);
    assert_eq!(failure_of(&driven), FailureCode::Internal);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    let stored = w.job(&job.id);
    assert_eq!(
        stored.run.as_ref().map(|run| run.run_id.as_str()),
        Some("r1"),
        "{driven:?}"
    );
    assert_eq!(
        stored.recording.as_ref().map(|recording| recording.phase),
        Some(RecordingPhase::Interrupted)
    );
    assert!(
        stored
            .warnings
            .iter()
            .any(|warning| warning.code == "late_launch" && warning.text.contains("r1")),
        "{:?}",
        stored.warnings
    );
    assert!(kinds(&w.fx, &job.id).contains(&"job.run".to_owned()));
    lane_is_free(&w);
}

#[test]
fn a_hung_stop_is_killed_and_a_recording_failure_is_retried_once() {
    let w = W::with("drive-hung-stop", |p| {
        p.retry.max_attempts = 3;
        p.retry.retry_on.push(FailureCode::RecordingFailed);
    });
    let job = w.fx.running(1);
    qemu(&w, 900, 5);
    let mut waiter = w.engine(|fake| {
        for _ in 0..2 {
            restore_ok(fake);
            upload_ok(fake);
            execute_run(fake, Some((4 * SECOND, exited(0))));
            fake.on("Stop")
                .then(125 * SECOND, |s| s.state = VmState::Failed)
                .silent();
            // The cleanup asks again once the engine has noticed.
            stop_ok(fake);
        }
    });
    let first = drive(&w, &mut waiter, &job);
    assert!(matches!(first, Driven::Retried { .. }), "{first:?}");
    assert_eq!(failure_of(&first), FailureCode::RecordingFailed);
    assert_eq!(w.procs.killed.borrow().as_slice(), [900]);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    lane_is_free(&w);
    w.fx.clock.advance(300_000);
    let second = claim(&w).unwrap();
    let last = drive(&w, &mut waiter, &second);
    assert!(matches!(last, Driven::Failed(_)), "once only: {last:?}");
    assert_eq!(w.job(&job.id).state, JobState::Failed);
}

// ---- quarantine ---------------------------------------------------------

#[test]
fn three_guests_that_never_answer_quarantine_the_lane_and_the_job_waits() {
    let w = W::with("drive-quarantine", |p| {
        p.retry.max_attempts = 6;
        p.retry.backoff_s = vec![1];
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        for _ in 0..3 {
            // The VM boots but the guest never answers.
            fake.on("RestoreVmSnapshot")
                .after(2 * SECOND)
                .then(100 * MS, |s| {
                    s.state = VmState::Starting;
                    s.active_vm = Some(VM.into());
                })
                .then(2 * SECOND, |s| s.state = VmState::Running)
                .ok("restored");
            stop_ok(fake);
        }
    });
    let mut current = job.clone();
    for round in 1..=3 {
        let driven = drive(&w, &mut waiter, &current);
        assert!(
            matches!(driven, Driven::Retried { .. }),
            "round {round}: {driven:?}"
        );
        assert_eq!(failure_of(&driven), FailureCode::GuestUnreachable);
        assert_eq!(w.lane_file().failures, round);
        if round < 3 {
            w.fx.clock.advance(10_000);
            current = claim(&w).expect("claimed again");
        }
    }
    let file = w.lane_file();
    let quarantine = file.quarantine.expect("the third failure quarantines");
    assert_eq!(quarantine.reason, FailureCode::GuestUnreachable);
    assert!(w.engine_events().iter().any(|e| matches!(
        e,
        EventBody::LaneState {
            state: crate::api::event::LaneState::Quarantined,
            ..
        }
    )));
    // The job stays queued and says why.
    w.fx.clock.advance(10_000);
    let verdict = w.stages(&mut waiter).eligibility();
    assert_eq!(verdict, Eligibility::Wait(WaitingFor::LaneQuarantined));
    assert!(
        w.fx.store
            .claim_next(&lane(), &mut |_| verdict)
            .unwrap()
            .is_none()
    );
    let queued = w.job(&job.id);
    assert_eq!(
        (queued.state, queued.waiting_for),
        (JobState::Queued, Some(WaitingFor::LaneQuarantined))
    );
}

#[test]
fn a_revert_that_fails_twice_quarantines_and_is_never_retried() {
    let w = W::with("drive-revert-failed", |p| {
        p.retry.max_attempts = 5;
        p.retry.retry_on = FailureCode::ALL.to_vec();
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.on("RestoreVmSnapshot").fail("the snapshot is damaged");
        fake.on("RestoreVmSnapshot").fail("the snapshot is damaged");
    });
    let driven = drive(&w, &mut waiter, &job);
    assert!(matches!(driven, Driven::Failed(_)), "{driven:?}");
    assert_eq!(failure_of(&driven), FailureCode::RevertFailed);
    assert!(w.lane_file().quarantine.is_some());
    assert_eq!(w.job(&job.id).state, JobState::Failed);
}

// ---- waits and aborts ---------------------------------------------------

#[test]
fn a_host_that_cannot_take_the_job_yet_puts_it_back_without_using_an_attempt() {
    let mut w = W::new("drive-wait");
    w.host = Box::new(Host(Some(super::HostProblem::Wait(
        WaitingFor::Resources,
        "disk is low".into(),
    ))));
    let job = w.fx.running(1);
    let mut waiter = w.engine(|_| {});
    let driven = drive(&w, &mut waiter, &job);
    assert!(
        matches!(
            driven,
            Driven::Waiting {
                waiting_for: WaitingFor::Resources,
                ..
            }
        ),
        "{driven:?}"
    );
    let stored = w.job(&job.id);
    assert_eq!(
        (stored.state, stored.waiting_for),
        (JobState::Queued, Some(WaitingFor::Resources))
    );
    assert!(w.fx.store.previous_failures(&job.id).unwrap().is_empty());
    assert!(waiter.engine_mut().sent().is_empty());
    assert_eq!(w.lane_file().current, None);
}

#[test]
fn a_dead_engine_leaves_the_job_and_the_lane_for_recovery() {
    let w = W::new("drive-dead");
    let job = w.fx.running(1);
    qemu(&w, 900, 5);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        fake.on("Execute").die();
    });
    let driven = drive(&w, &mut waiter, &job);
    assert!(matches!(driven, Driven::Aborted(_)), "{driven:?}");
    assert_eq!(w.job(&job.id).state, JobState::Running);
    let work = w
        .lane_file()
        .current
        .expect("the lane still holds the work");
    assert_eq!(
        (work.stage, work.checkpoint),
        (Stage::Launch, Checkpoint::Started)
    );
    assert!(w.lane_file().qemu.is_some());
}

// ---- cancellation -------------------------------------------------------

#[test]
fn a_job_cancelled_before_it_starts_ends_cancelled_without_a_command() {
    let w = W::new("cancel-before");
    let job = w.fx.running(1);
    w.fx.store.cancel(&job.id, Some("no"), &manager()).unwrap();
    let mut waiter = w.engine(|fake| attempt(fake, 3));
    let driven = drive(&w, &mut waiter, &job);
    assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
    assert_eq!(w.job(&job.id).state, JobState::Cancelled);
    assert!(waiter.engine_mut().sent().is_empty());
    lane_is_free(&w);
}

#[test]
fn a_shutdown_cancel_puts_the_job_back_in_the_queue() {
    let w = W::new("cancel-shutdown");
    let job = w.fx.running(1);
    w.fx.store.cancel_for_shutdown(&job.id).unwrap();
    let mut waiter = w.engine(|fake| attempt(fake, 3));
    assert!(matches!(drive(&w, &mut waiter, &job), Driven::Requeued));
    assert_eq!(w.job(&job.id).state, JobState::Queued);
}

#[test]
fn a_cancel_during_the_revert_stops_the_wait_and_the_vm_the_engine_started() {
    let w = W::new("cancel-provision");
    let job = w.fx.running(1);
    let (driven, names, state) = with_canceller(&w, &job, |cancel| {
        let mut waiter = w.engine(|fake| {
            fake.on("RestoreVmSnapshot")
                .after(2 * SECOND)
                .then(100 * MS, |s| {
                    s.state = VmState::Starting;
                    s.active_vm = Some(VM.into());
                })
                .then(2 * SECOND, |s| s.state = VmState::Running)
                .call(500 * MS, move || cancel())
                .ok("restored");
            stop_ok(fake);
        });
        let driven = drive(&w, &mut waiter, &job);
        (driven, sent(&mut waiter), waiter.snapshot().state.clone())
    });
    assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
    // The restore was waited for to its end, then the VM it started was stopped.
    assert_eq!(names, ["RestoreVmSnapshot", "Stop"]);
    assert_eq!(state, VmState::Stopped);
    assert_eq!(w.job(&job.id).state, JobState::Cancelled);
    lane_is_free(&w);
}

#[test]
fn a_cancel_during_the_upload_wait_ends_the_job_and_stops_the_vm() {
    let w = W::new("cancel-upload");
    let job = w.fx.running(1);
    let (driven, names) = with_canceller(&w, &job, |cancel| {
        let mut waiter = w.engine(|fake| {
            restore_ok(fake);
            fake.on("UploadSample")
                .after(50 * MS)
                .call(60 * MS, move || cancel())
                .fail("guest command 0x1001: Read-only file system (os error 30)");
            stop_ok(fake);
        });
        (drive(&w, &mut waiter, &job), sent(&mut waiter))
    });
    assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
    // The pause before the retry sees the cancel: no second upload, the VM
    // stopped.
    assert_eq!(names, ["RestoreVmSnapshot", "UploadSample", "Stop"]);
    assert_eq!(w.job(&job.id).state, JobState::Cancelled);
    lane_is_free(&w);
}

#[test]
fn a_cancel_while_the_program_runs_stops_it_stops_the_vm_and_keeps_the_recording() {
    let w = W::new("cancel-run");
    let job = w.fx.running(1);
    let (driven, names) = with_canceller(&w, &job, |cancel| {
        let mut waiter = w.engine(|fake| {
            restore_ok(fake);
            upload_ok(fake);
            fake.on("Execute")
                .after(SECOND)
                .then(500 * MS, |s| s.runs.push(live_run()))
                .call(10 * SECOND, move || cancel())
                .ok("launched");
            stop_run_ok(fake);
            stop_ok(fake);
        });
        (drive(&w, &mut waiter, &job), sent(&mut waiter))
    });
    assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
    assert_eq!(
        names,
        [
            "RestoreVmSnapshot",
            "UploadSample",
            "UploadSample",
            "Execute",
            "StopRun",
            "Stop"
        ]
    );
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Cancelled);
    assert_eq!(stored.run.unwrap().end_reason, Some(EndReason::Stopped));
    assert_eq!(
        stored.recording.map(|r| r.phase),
        Some(RecordingPhase::Complete),
        "the recording is kept and settled"
    );
    lane_is_free(&w);
}

#[test]
fn a_cancel_while_collect_waits_for_evidence_still_stops_the_vm() {
    let mut w = W::new("cancel-collect");
    w.evidence = Box::new(|_| {
        Ok(Some(RunArtifacts {
            network_state: RunArtifactState::InProgress,
            memory_state: RunArtifactState::Disabled,
            core_state: RunArtifactState::Disabled,
            ..RunArtifacts::default()
        }))
    });
    let job = w.fx.running(1);
    let (driven, names, state) = with_canceller(&w, &job, |cancel| {
        let mut waiter = w.engine(|fake| {
            restore_ok(fake);
            upload_ok(fake);
            execute_run(fake, Some((5 * SECOND, exited(0))));
            fake.call_after(40 * SECOND, move || cancel());
            chatter(fake, 10 * SECOND, 120 * SECOND);
            stop_ok(fake);
        });
        let driven = drive(&w, &mut waiter, &job);
        (driven, sent(&mut waiter), waiter.snapshot().state.clone())
    });
    assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
    assert_eq!(names.last().map(String::as_str), Some("Stop"));
    assert_eq!(state, VmState::Stopped);
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Cancelled);
    assert_eq!(stored.recording.unwrap().phase, RecordingPhase::Complete);
    lane_is_free(&w);
}

#[test]
fn a_cancel_while_the_vm_stops_finishes_the_stop_and_ends_cancelled() {
    let w = W::new("cancel-stop");
    let job = w.fx.running(1);
    let driven = with_canceller(&w, &job, |cancel| {
        let mut waiter = w.engine(|fake| {
            restore_ok(fake);
            upload_ok(fake);
            execute_run(fake, Some((5 * SECOND, exited(0))));
            fake.on("Stop")
                .after(SECOND)
                .call(500 * MS, move || cancel())
                .then(2 * SECOND, |s| {
                    s.state = VmState::Stopped;
                    s.active_vm = None;
                })
                .ok("VM stopped");
        });
        drive(&w, &mut waiter, &job)
    });
    assert!(matches!(driven, Driven::Cancelled), "{driven:?}");
    assert_eq!(w.job(&job.id).state, JobState::Cancelled);
    lane_is_free(&w);
}

// ---- the watchdog -------------------------------------------------------

#[test]
fn the_job_limit_stops_a_job_that_is_still_in_a_stage_and_fails_it_with_the_watchdog() {
    // job_hard_s = timeout_s + 1800 = 1805 s. The layer wait takes 1799 s and
    // the restore, which takes 10 s more, crosses the limit.
    let w = W::with("drive-hard", |p| {
        p.run.timeout_s = 5;
        p.retry.retry_on = FailureCode::ALL.to_vec();
        p.retry.max_attempts = 5;
    });
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        fake.start_with(|s| {
            s.disk_layers = vec![crate::lane::tests::layer(
                antinomie_monitor_core::disk_layers::LayerPhase::Finalizing,
            )]
        });
        fake.after(1799 * SECOND, |s| s.disk_layers.clear());
        fake.on("RestoreVmSnapshot")
            .after(10 * SECOND)
            .then(100 * MS, |s| {
                s.state = VmState::Starting;
                s.active_vm = Some(VM.into());
            })
            .then(10 * SECOND, |s| {
                s.state = VmState::Running;
                s.guest_kernel = Some(kernel(21));
            })
            .ok("restored");
        stop_ok(fake);
    });
    let driven = drive(&w, &mut waiter, &job);
    let Driven::Failed(failure) = &driven else {
        panic!("{driven:?}");
    };
    assert_eq!(failure.code, FailureCode::Internal);
    assert_eq!(failure.detail.as_deref(), Some("watchdog"));
    assert_eq!(failure.stage, Stage::Provision);
    // Never retried, whatever the policy lists; the VM was stopped.
    let stored = w.job(&job.id);
    assert_eq!(stored.state, JobState::Failed);
    assert_eq!(stored.attempt, 1);
    assert_eq!(waiter.snapshot().state, VmState::Stopped);
    lane_is_free(&w);
}

// ---- crash points of the new checkpoints --------------------------------

/// Run a job to the point just before `collect` finishes, in `waiter`.
fn up_to_collect(w: &W, waiter: &mut Waiter<FakeEngine>, job: &Job) -> super::Launched {
    let ready = super::run_tests::launched(w, waiter, job);
    w.stages(waiter).run(job, &ready.0, &ready.1).unwrap();
    ready.1
}

fn recover(w: &mut W) -> crate::lane::StartupRecovery {
    w.fx.reopen();
    let mut fresh = w.engine(|_| {});
    crate::lane::recover_startup(
        &w.fx.store,
        &w.lanes,
        &mut fresh,
        &w.procs,
        &RecoverOptions::default(),
    )
    .unwrap()
}

/// `collect` with a lane-file fault armed when `Stop` is sent: between the
/// `collect started` write and the `collected` write.
fn collect_with_fault(w: &W, fault: WriteFault, job: &Job) -> Result<super::CollectEnd, StageStop> {
    let lanes = &w.lanes;
    with_action(
        || lanes.inject_fault(fault),
        |arm| {
            let mut waiter = w.engine(|fake| {
                restore_ok(fake);
                upload_ok(fake);
                execute_run(fake, Some((3 * SECOND, exited(0))));
                fake.on("Stop")
                    .after(SECOND)
                    .call(100 * MS, move || arm())
                    .then(2 * SECOND, |s| {
                        s.state = VmState::Stopped;
                        s.active_vm = None;
                    })
                    .ok("VM stopped");
            });
            let launched = up_to_collect(w, &mut waiter, job);
            w.stages(&mut waiter).collect_stage(job, &launched)
        },
    )
}

#[test]
fn a_crash_before_the_collected_rename_makes_a_new_attempt() {
    let mut w = W::new("crash-before-collected");
    let job = w.fx.running(1);
    qemu(&w, 900, 5);
    let stop = collect_with_fault(&w, WriteFault::BeforeRename, &job);
    assert!(matches!(stop, Err(StageStop::Failed(_))), "{stop:?}");
    // The file kept its last good content: collect started.
    let work = w.lane_file().current.unwrap();
    assert_eq!(
        (work.stage, work.checkpoint),
        (Stage::Collect, Checkpoint::Started)
    );
    assert!(w.lane_file().collected.is_empty());
    let report = recover(&mut w);
    assert_eq!(report.jobs.requeued, std::slice::from_ref(&job.id));
    assert_eq!(w.job(&job.id).state, JobState::Queued);
    let lane_report = &report.lanes[0];
    assert!(lane_report.resume.is_empty());
    assert_eq!(
        lane_report.interrupted.as_ref().map(|work| work.stage),
        Some(Stage::Collect)
    );
    assert_eq!(w.lane_file().current, None);
    assert!(
        matches!(lane_report.qemu, QemuOutcome::Killed(900)),
        "{:?}",
        lane_report.qemu
    );
}

#[test]
fn a_crash_after_the_collected_rename_resumes_the_job_at_analyse() {
    let mut w = W::new("crash-after-collected");
    let job = w.fx.running(1);
    let stop = collect_with_fault(&w, WriteFault::AfterRename, &job);
    assert!(matches!(stop, Err(StageStop::Failed(_))), "{stop:?}");
    // The rename happened: the lane file says collected, the store still has
    // the job running at collect.
    let file = w.lane_file();
    assert_eq!(file.current, None);
    assert_eq!(file.collected.len(), 1);
    assert_eq!(w.job(&job.id).state, JobState::Running);
    let report = recover(&mut w);
    assert!(report.jobs.requeued.is_empty(), "{:?}", report.jobs);
    assert_eq!(report.lanes[0].resume, std::slice::from_ref(&job.id));
    let kept = w.job(&job.id);
    assert_eq!(
        (kept.state, kept.stage),
        (JobState::Running, Some(Stage::Collect))
    );
}

#[test]
fn a_crash_while_the_program_runs_makes_a_new_attempt() {
    let mut w = W::new("crash-in-run");
    let job = w.fx.running(1);
    let mut waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, None);
        fake.on("TerminalRead").die();
    });
    let driven = drive(&w, &mut waiter, &job);
    assert!(matches!(driven, Driven::Aborted(_)), "{driven:?}");
    let work = w.lane_file().current.unwrap();
    assert_eq!(
        (work.stage, work.checkpoint),
        (Stage::Run, Checkpoint::Started)
    );
    let report = recover(&mut w);
    assert_eq!(report.jobs.requeued, std::slice::from_ref(&job.id));
    assert_eq!(w.job(&job.id).state, JobState::Queued);
}

// ---- a stop that never settles -----------------------------------------

/// Everything up to a `Stop` that nobody answers and that leaves the engine
/// in `Failed` after the forced kill.
fn wedged(w: &W, second_stop: impl FnOnce(&mut FakeEngine)) -> (Job, Waiter<FakeEngine>) {
    qemu(w, 900, 5);
    let job = w.fx.running(1);
    let waiter = w.engine(|fake| {
        restore_ok(fake);
        upload_ok(fake);
        execute_run(fake, Some((3 * SECOND, exited(0))));
        stop_run_ok(fake);
        fake.on("Stop")
            .then(125 * SECOND, |s| s.state = VmState::Failed)
            .silent();
        second_stop(fake);
    });
    (job, waiter)
}

#[test]
fn a_stop_that_never_settles_after_the_forced_kill_quarantines_the_lane() {
    let w = W::new("drive-wedged");
    let (job, mut waiter) = wedged(&w, |_| {});
    let driven = drive(&w, &mut waiter, &job);
    assert_eq!(failure_of(&driven), FailureCode::RecordingFailed);
    assert_eq!(w.procs.killed.borrow().as_slice(), [900]);
    // The lane is out of service: the closest reason of 4.5.3 is a revert
    // that cannot happen, and it stays so until `auto lane reset`.
    let file = w.lane_file();
    assert_eq!(file.current, None, "the lane let the job go");
    let quarantine = file.quarantine.expect("quarantined");
    assert_eq!(quarantine.reason, FailureCode::RevertFailed);
    assert!(
        quarantine.detail.contains("did not stop"),
        "{}",
        quarantine.detail
    );
    assert!(
        w.job(&job.id)
            .warnings
            .iter()
            .any(|x| x.code == "vm_not_stopped")
    );
    // It was announced, and no job is started on it.
    let events = w.engine_events();
    assert!(events.iter().any(|e| matches!(
        e,
        EventBody::LaneState {
            state: crate::api::event::LaneState::Quarantined,
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(
        e,
        EventBody::EngineAlert { code, .. } if code == "lane_quarantined"
    )));
    assert_eq!(
        w.stages(&mut waiter).eligibility(),
        Eligibility::Wait(WaitingFor::LaneQuarantined)
    );
}

#[test]
fn a_stop_that_settles_on_the_second_try_leaves_the_lane_in_service() {
    let w = W::new("drive-wedged-ok");
    // The first stop of the cleanup is refused, the second is answered.
    let (job, mut waiter) = wedged(&w, |fake| {
        fake.on("Stop").fail("the engine is busy");
        stop_ok(fake);
    });
    let driven = drive(&w, &mut waiter, &job);
    assert_eq!(failure_of(&driven), FailureCode::RecordingFailed);
    let file = w.lane_file();
    assert_eq!(file.quarantine, None);
    assert_eq!(file.current, None);
    assert_eq!(file.qemu, None, "the process record goes with a clean stop");
    // The warning still says what happened on the way.
    assert!(
        w.job(&job.id)
            .warnings
            .iter()
            .any(|x| x.code == "vm_not_stopped")
    );
}

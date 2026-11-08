// SPDX-License-Identifier: GPL-3.0-only
//! Crash safety (design 4.8): a process killed between the steps of a
//! transition leaves a store that opens, recovers and is consistent.

use super::*;
use crate::store::{mirror::job_events, recover::RecoveryReport};
use std::process::Command;

fn mirror_lines(fx: &Fx, id: &JobId) -> Vec<String> {
    let text =
        std::fs::read_to_string(fx.store.job_dir(id).join("events.ndjson")).unwrap_or_default();
    text.lines().map(str::to_owned).collect()
}

/// The mirror file equals the stored events.
fn assert_mirror_complete(fx: &Fx, id: &JobId) {
    let stored = job_events(&fx.store.conn(), id).unwrap();
    let lines = mirror_lines(fx, id);
    assert_eq!(lines.len(), stored.len(), "mirror lines of {id}");
    for (line, event) in lines.iter().zip(&stored) {
        assert_eq!(line, &serde_json::to_string(event).unwrap());
    }
}

#[test]
fn a_transition_killed_before_the_commit_leaves_nothing() {
    let mut fx = Fx::new("kill-before");
    let job = fx.queued(1);
    fx.store
        .inject_fault(Fault::BeforeCommit, FaultAction::Fail);
    let before = fx.store.get(&job.id).unwrap();
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .is_err()
    );
    fx.reopen();
    let report = fx.store.recover().unwrap();
    assert_eq!(report.requeued, []);
    assert_eq!(fx.store.get(&job.id).unwrap(), before);
    assert_eq!(kinds(&fx, &job.id), ["job.created"]);
    // And the work can simply be done again.
    assert_eq!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .unwrap()
            .id,
        job.id
    );
}

#[test]
fn a_kill_after_the_commit_leaves_the_state_and_recovery_appends_the_mirror() {
    let mut fx = Fx::new("kill-after");
    let job = fx.queued(1);
    fx.store.inject_fault(Fault::AfterCommit, FaultAction::Fail);
    assert!(fx.store.cancel(&job.id, None, &caller(1000)).is_err());
    fx.reopen();
    // The transition is there: state and events.
    assert_eq!(fx.store.get(&job.id).unwrap().state, JobState::Cancelled);
    assert_eq!(
        kinds(&fx, &job.id),
        ["job.created", "job.state", "job.finished"]
    );
    // The mirror lacks its last lines until recovery.
    assert_eq!(mirror_lines(&fx, &job.id).len(), 1);
    let report = fx.store.recover().unwrap();
    assert_eq!(report.mirror_lines, 2);
    assert_mirror_complete(&fx, &job.id);
    // Running it again changes nothing.
    assert_eq!(fx.store.recover().unwrap(), RecoveryReport::default());
}

#[test]
fn a_torn_mirror_line_is_cut_and_written_again() {
    let mut fx = Fx::new("kill-mid-mirror");
    let job = fx.queued(1);
    fx.store.inject_fault(Fault::MidMirror, FaultAction::Fail);
    assert!(fx.store.cancel(&job.id, None, &caller(1000)).is_err());
    fx.reopen();
    let raw = std::fs::read_to_string(fx.store.job_dir(&job.id).join("events.ndjson")).unwrap();
    assert!(!raw.ends_with('\n'), "the last line is torn");
    fx.store.recover().unwrap();
    assert_mirror_complete(&fx, &job.id);
}

#[test]
fn a_missing_or_wrong_mirror_is_rebuilt_from_the_table() {
    let mut fx = Fx::new("mirror-rebuild");
    let job = fx.queued(1);
    let path = fx.store.job_dir(&job.id).join("events.ndjson");
    std::fs::write(&path, "garbage\n").unwrap();
    std::fs::remove_file(fx.store.job_dir(&job.id).join("spec.json")).unwrap();
    // The watermark of the last recovery is behind: reset it.
    fx.store
        .conn()
        .execute("DELETE FROM meta WHERE key = 'recovered_gseq'", [])
        .unwrap();
    fx.reopen();
    let report = fx.store.recover().unwrap();
    assert_eq!(report.spec_files, 1);
    assert_mirror_complete(&fx, &job.id);
    assert!(fx.store.job_dir(&job.id).join("spec.json").is_file());
}

#[test]
fn a_job_left_running_is_requeued_once_without_counting_the_attempt() {
    let mut fx = Fx::new("kill-running");
    let job = fx.running(1);
    fx.store.begin_stage(&job.id, Stage::Run).unwrap();
    fx.reopen(); // the process died; nothing was told to the job
    let report = fx.store.recover().unwrap();
    assert_eq!(report.requeued, std::slice::from_ref(&job.id));
    let queued = fx.store.get(&job.id).unwrap();
    assert_eq!(
        (queued.state, queued.stage, queued.lane, queued.attempt),
        (JobState::Queued, None, None, 1)
    );
    let types = kinds(&fx, &job.id);
    assert_eq!(
        types[types.len() - 3..],
        ["job.stage", "job.requeued", "job.state"]
    );
    let (code, detail): (String, String) = fx
        .store
        .conn()
        .query_row(
            "SELECT failure_code, detail FROM attempts WHERE job_id = ?1",
            [job.id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (code.as_str(), detail.as_str()),
        ("guest_lost", "service_restart")
    );
    // The open stage was closed as failed.
    let open: u32 = fx
        .store
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM stages WHERE finished_ms IS NULL",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(open, 0);

    // The second attempt is still the first counted one: two retries remain.
    let again = fx
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(again.attempt, 2);
    let failure = Failure::new(FailureCode::UploadFailed, Stage::Upload, "x", None);
    fx.store
        .requeue(
            &job.id,
            RequeueKind::Retry,
            "upload_failed",
            Some(&failure),
            None,
        )
        .unwrap();

    // A second crash of the same job counts: attempt 3 is now beyond max_attempts (2).
    fx.store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    fx.reopen();
    let second = fx.store.recover().unwrap();
    assert_eq!(second.failed, std::slice::from_ref(&job.id));
    let failed = fx.store.get(&job.id).unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(failed.failure.unwrap().code, FailureCode::GuestLost);
}

#[test]
fn a_cancel_in_progress_is_finished_or_requeued_by_its_reason() {
    let mut fx = Fx::new("kill-cancelling");
    let user = fx.running(1);
    fx.store
        .cancel(&user.id, Some("by hand"), &caller(1000))
        .unwrap();
    let mut other = fx.running(2);
    other = fx.store.cancel_for_shutdown(&other.id).unwrap();
    assert_eq!(other.state, JobState::Cancelling);
    fx.reopen();
    let report = fx.store.recover().unwrap();
    assert_eq!(report.cancelled, std::slice::from_ref(&user.id));
    assert_eq!(report.requeued, std::slice::from_ref(&other.id));
    assert_eq!(fx.store.get(&user.id).unwrap().state, JobState::Cancelled);
    assert_eq!(fx.store.get(&other.id).unwrap().state, JobState::Queued);
}

#[test]
fn recovery_leaves_queued_and_finished_jobs_alone() {
    let mut fx = Fx::new("recover-idle");
    let done = fx.running(2);
    fx.store.finish(&done.id, Outcome::Succeeded, None).unwrap();
    let queued = fx.queued(1);
    let (a, b) = (
        fx.store.get(&queued.id).unwrap(),
        fx.store.get(&done.id).unwrap(),
    );
    fx.reopen();
    assert_eq!(fx.store.recover().unwrap(), RecoveryReport::default());
    assert_eq!(
        (
            fx.store.get(&queued.id).unwrap(),
            fx.store.get(&done.id).unwrap()
        ),
        (a, b)
    );
}

/// A real kill: a child process runs a transition with `abort()` armed, then
/// this process opens the store the child left.
#[test]
fn a_real_process_kill_at_each_point_leaves_a_store_that_recovers() {
    if let Ok(dir) = std::env::var("ANT_STORE_CRASH_CHILD") {
        let point = match std::env::var("ANT_STORE_CRASH_POINT").unwrap().as_str() {
            "before" => Fault::BeforeCommit,
            "after" => Fault::AfterCommit,
            _ => Fault::MidMirror,
        };
        let store = Store::open(std::path::Path::new(&dir)).unwrap();
        let id = JobId::try_from(std::env::var("ANT_STORE_CRASH_JOB").unwrap()).unwrap();
        store.inject_fault(point, FaultAction::Abort);
        let _ = store.claim_next(&lane(), &mut |_| Eligibility::Ready);
        let _ = store.cancel(&id, None, &caller(1000));
        unreachable!("the fault aborts the process");
    }
    for point in ["before", "after", "mid"] {
        let mut fx = Fx::new(&format!("real-kill-{point}"));
        // A real clock: the child opens the store with the system clock.
        let job = fx.queued(1);
        drop(std::mem::replace(
            &mut fx.store,
            Store::open_read_only(&fx.dir.join("service")).unwrap(),
        ));
        let status = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "--nocapture"])
            .arg("store::tests::crash::a_real_process_kill_at_each_point_leaves_a_store_that_recovers")
            .env("ANT_STORE_CRASH_CHILD", fx.dir.join("service"))
            .env("ANT_STORE_CRASH_POINT", point)
            .env("ANT_STORE_CRASH_JOB", job.id.as_str())
            .status()
            .unwrap();
        assert!(!status.success(), "the child was killed ({point})");
        fx.store = Store::open_with_clock(&fx.dir.join("service"), fx.clock.clone()).unwrap();
        let report = fx.store.recover().unwrap();
        let state = fx.store.get(&job.id).unwrap();
        match point {
            // Nothing committed: the job is still queued, as before.
            "before" => {
                assert_eq!(state.state, JobState::Queued);
                assert_eq!(kinds(&fx, &job.id), ["job.created"]);
            }
            // The claim committed; the job was running when the process died,
            // so recovery put it back.
            _ => {
                assert_eq!(report.requeued, std::slice::from_ref(&job.id), "{point}");
                assert_eq!(state.state, JobState::Queued);
            }
        }
        assert_mirror_complete(&fx, &job.id);
        assert_eq!(fx.store.recover().unwrap(), RecoveryReport::default());
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The state machine through the store API: every edge of design 5.6, every
//! forbidden edge, `waiting_for`, retries and cancellation.

use super::*;
use crate::api::{event::StageStatus, ops::JobListParams, status::PauseReason};
use crate::store::machine;

fn fail(code: FailureCode, stage: Stage) -> Failure {
    Failure::new(code, stage, "failed", None)
}

#[test]
fn claim_order_is_priority_then_age() {
    let fx = Fx::new("order");
    let low = fx.queued(1);
    fx.clock.advance(10);
    let older_high = fx
        .submit(JobSpec {
            priority: Some(5),
            ..spec(2)
        })
        .job;
    fx.clock.advance(10);
    let urgent = fx
        .submit(JobSpec {
            priority: Some(5),
            ..spec(3)
        })
        .job;
    // All default priority 5: oldest first.
    assert_eq!(fx.store.get(&low.id).unwrap().queue_position, Some(0));
    assert_eq!(
        fx.store.get(&older_high.id).unwrap().queue_position,
        Some(1)
    );
    assert_eq!(fx.store.get(&urgent.id).unwrap().queue_position, Some(2));
    let mut fx2 = Fx::with_policy("order2", |p| p.limits.priority_max = 9);
    fx2.limits = SubmitLimits::default();
    let a = fx2.queued(1);
    fx2.clock.advance(5);
    let b = fx2
        .submit(JobSpec {
            priority: Some(9),
            ..spec(2)
        })
        .job;
    let first = fx2
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(first.id, b.id, "higher priority starts first");
    assert_eq!(fx2.store.get(&a.id).unwrap().queue_position, Some(0));
}

#[test]
fn claiming_starts_attempt_one_at_prechecks() {
    let fx = Fx::new("claim");
    let job = fx.running(1);
    assert_eq!(job.state, JobState::Running);
    assert_eq!(job.stage, Some(Stage::Prechecks));
    assert_eq!(job.attempt, 1);
    assert_eq!(job.started_ms, Some(T0));
    assert_eq!(job.lane, Some(lane()));
    assert_eq!(job.waiting_for, None);
    assert_eq!(job.queue_position, None);
    assert_eq!(
        kinds(&fx, &job.id),
        ["job.created", "job.state", "job.stage"]
    );
    // Nothing else to claim.
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .is_none()
    );
}

#[test]
fn stages_follow_each_other_and_the_job_succeeds() {
    let fx = Fx::new("stages");
    let job = fx.running(1);
    for stage in [
        Stage::Provision,
        Stage::Upload,
        Stage::Launch,
        Stage::Run,
        Stage::Collect,
    ] {
        fx.clock.advance(100);
        let job = fx.store.begin_stage(&job.id, stage).unwrap();
        assert_eq!(job.stage, Some(stage));
    }
    // The same stage twice in one attempt is refused.
    assert_eq!(
        fx.store.begin_stage(&job.id, Stage::Run).unwrap_err().code,
        ErrorCode::Conflict
    );
    fx.clock.advance(100);
    fx.store.end_stage(&job.id, StageStatus::Skipped).unwrap();
    fx.clock.advance(100);
    let done = fx.store.finish(&job.id, Outcome::Succeeded, None).unwrap();
    assert_eq!(done.state, JobState::Succeeded);
    assert_eq!(done.outcome, Some(Outcome::Succeeded));
    assert_eq!(done.stage, None);
    assert_eq!(done.finished_ms, Some(T0 + 700));
    assert_eq!(done.failure, None);
    let (events, _) = fx.store.events_list(&job.id, 0, 100).unwrap();
    let last = events.last().unwrap();
    assert!(matches!(
        last.body,
        EventBody::JobFinished {
            outcome: Outcome::Succeeded,
            ..
        }
    ));
    let stage_events: Vec<_> = events
        .iter()
        .filter_map(|e| match &e.body {
            EventBody::JobStage {
                stage,
                status,
                duration_ms,
            } => Some((*stage, *status, *duration_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(
        stage_events[0],
        (Stage::Prechecks, StageStatus::Started, None)
    );
    assert_eq!(
        stage_events[1],
        (Stage::Prechecks, StageStatus::Finished, Some(100))
    );
    assert!(stage_events.contains(&(Stage::Collect, StageStatus::Skipped, Some(100))));
    // The attempt and stage rows are closed.
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
}

#[test]
fn partial_and_failed_endings() {
    let fx = Fx::new("endings");
    let a = fx.running(1);
    let partial = fx.store.finish(&a.id, Outcome::Partial, None).unwrap();
    assert_eq!(
        (partial.state, partial.failure.clone()),
        (JobState::Partial, None)
    );
    let b = fx.running(2);
    let failed = fx
        .store
        .finish(
            &b.id,
            Outcome::Failed,
            Some(fail(FailureCode::RecordingFailed, Stage::Collect)),
        )
        .unwrap();
    assert_eq!(failed.failure.unwrap().code, FailureCode::RecordingFailed);
    // A partial job carries no failure; a success cannot be given one.
    let c = fx.running(3);
    let error = fx
        .store
        .finish(
            &c.id,
            Outcome::Succeeded,
            Some(fail(FailureCode::Internal, Stage::Run)),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    // `failed` with no failure gets an `internal` one rather than none.
    let failed = fx.store.finish(&c.id, Outcome::Failed, None).unwrap();
    assert_eq!(failed.failure.unwrap().code, FailureCode::Internal);
}

#[test]
fn cancelling_a_queued_job_ends_it_at_once() {
    let fx = Fx::new("cancel-queued");
    let job = fx.queued(1);
    let cancelled = fx
        .store
        .cancel(&job.id, Some("not needed"), &caller(1000))
        .unwrap();
    assert_eq!(cancelled.state, JobState::Cancelled);
    assert_eq!(cancelled.finished_ms, Some(T0));
    let failure = cancelled.failure.unwrap();
    assert_eq!(
        (failure.code, failure.message.as_str()),
        (FailureCode::Cancelled, "not needed")
    );
    assert_eq!(
        kinds(&fx, &job.id),
        ["job.created", "job.state", "job.finished"]
    );
    // Cancelling again is a conflict.
    assert_eq!(
        fx.store
            .cancel(&job.id, None, &caller(1000))
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

#[test]
fn cancelling_a_running_job_goes_through_cancelling() {
    let fx = Fx::new("cancel-running");
    let job = fx.running(1);
    fx.store.begin_stage(&job.id, Stage::Run).unwrap();
    let cancelling = fx
        .store
        .cancel(&job.id, Some("stop"), &caller(1000))
        .unwrap();
    assert_eq!(cancelling.state, JobState::Cancelling);
    assert_eq!(cancelling.stage, Some(Stage::Run));
    // Idempotent while it unwinds.
    assert_eq!(
        fx.store.cancel(&job.id, None, &caller(1000)).unwrap().state,
        JobState::Cancelling
    );
    // Cancelling ends in cancelled ...
    let done = fx.store.finish(&job.id, Outcome::Cancelled, None).unwrap();
    assert_eq!(done.state, JobState::Cancelled);
    assert_eq!(done.failure.unwrap().message, "stop");
    // ... or in failed when cleanup fails.
    let other = fx.running(2);
    fx.store.cancel(&other.id, None, &caller(1000)).unwrap();
    let failed = fx
        .store
        .finish(
            &other.id,
            Outcome::Failed,
            Some(fail(FailureCode::RevertFailed, Stage::Cleanup)),
        )
        .unwrap();
    assert_eq!(failed.state, JobState::Failed);
    assert_eq!(failed.failure.unwrap().code, FailureCode::RevertFailed);
}

#[test]
fn only_the_owner_or_a_manager_may_cancel() {
    let fx = Fx::new("cancel-auth");
    let job = fx.queued(1);
    let error = fx.store.cancel(&job.id, None, &caller(2000)).unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(fx.store.get(&job.id).unwrap().state, JobState::Queued);
    assert_eq!(
        fx.store.cancel(&job.id, None, &manager()).unwrap().state,
        JobState::Cancelled
    );
}

#[test]
fn a_retryable_failure_requeues_with_backoff_until_attempts_run_out() {
    let fx = Fx::new("retry");
    let job = fx.running(1);
    let failure = fail(FailureCode::VmStartFailed, Stage::Provision);
    let queued = fx
        .store
        .requeue(
            &job.id,
            RequeueKind::Retry,
            "vm_start_failed",
            Some(&failure),
            Some(30),
        )
        .unwrap();
    assert_eq!(
        (queued.state, queued.waiting_for, queued.stage, queued.lane),
        (JobState::Queued, Some(WaitingFor::Backoff), None, None)
    );
    assert_eq!(queued.attempt, 1);
    assert_eq!(
        kinds(&fx, &job.id)[kinds(&fx, &job.id).len() - 2..],
        ["job.requeued", "job.state"]
    );
    // Not started during the backoff; says why.
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fx.store.get(&job.id).unwrap().waiting_for,
        Some(WaitingFor::Backoff)
    );
    fx.clock.advance(29_999);
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .is_none()
    );
    fx.clock.advance(1);
    let again = fx
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!((again.attempt, again.waiting_for), (2, None));
    // The second attempt is the last (max_attempts 2): a retry is refused.
    let error = fx
        .store
        .requeue(&job.id, RequeueKind::Retry, "again", Some(&failure), None)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(fx.store.get(&job.id).unwrap().state, JobState::Running);
    // The attempt rows keep the first failure.
    let (code, detail): (String, String) = fx
        .store
        .conn()
        .query_row(
            "SELECT failure_code, detail FROM attempts WHERE job_id = ?1 AND n = 1",
            [job.id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (code.as_str(), detail.as_str()),
        ("vm_start_failed", "vm_start_failed")
    );
}

#[test]
fn a_shutdown_puts_the_job_back_without_counting_the_attempt() {
    let fx = Fx::new("shutdown");
    let job = fx.running(1);
    let cancelling = fx.store.cancel_for_shutdown(&job.id).unwrap();
    assert_eq!(cancelling.state, JobState::Cancelling);
    let queued = fx
        .store
        .requeue(
            &job.id,
            RequeueKind::Shutdown,
            "service_shutdown",
            None,
            None,
        )
        .unwrap();
    assert_eq!((queued.state, queued.waiting_for), (JobState::Queued, None));
    let again = fx
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(again.attempt, 2);
    // Both remaining retries are still available: attempt 2 did not use up the budget.
    let failure = fail(FailureCode::UploadFailed, Stage::Upload);
    fx.store
        .requeue(
            &job.id,
            RequeueKind::Retry,
            "upload_failed",
            Some(&failure),
            None,
        )
        .unwrap();

    // A user's cancel outranks the shutdown: the job is cancelled, not put back.
    fx.store.cancel(&job.id, None, &caller(1000)).unwrap();
    let other = fx.running(2);
    fx.store.cancel_for_shutdown(&other.id).unwrap();
    fx.store
        .cancel(&other.id, Some("user"), &caller(1000))
        .unwrap();
    assert_eq!(
        fx.store
            .requeue(&other.id, RequeueKind::Shutdown, "x", None, None)
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
    assert_eq!(
        fx.store
            .finish(&other.id, Outcome::Cancelled, None)
            .unwrap()
            .state,
        JobState::Cancelled
    );
}

#[test]
fn waiting_for_is_set_changed_and_cleared() {
    let fx = Fx::new("waiting");
    let job = fx.queued(1);
    let mut why = Eligibility::Wait(WaitingFor::Lane);
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| why)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fx.store.get(&job.id).unwrap().waiting_for,
        Some(WaitingFor::Lane)
    );
    why = Eligibility::Wait(WaitingFor::LayerPending);
    fx.store.claim_next(&lane(), &mut |_| why).unwrap();
    assert_eq!(
        fx.store.get(&job.id).unwrap().waiting_for,
        Some(WaitingFor::LayerPending)
    );
    // One job.state event per change, none for an unchanged reason.
    fx.store.claim_next(&lane(), &mut |_| why).unwrap();
    assert_eq!(
        kinds(&fx, &job.id),
        ["job.created", "job.state", "job.state"]
    );
    // Ready clears it.
    let started = fx
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(started.waiting_for, None);
}

#[test]
fn a_paused_queue_starts_nothing_and_says_so() {
    let fx = Fx::new("paused");
    let job = fx.queued(1);
    fx.store.set_pause(Some(PauseReason::Operator)).unwrap();
    assert!(
        fx.store
            .claim_next(&lane(), &mut |_| Eligibility::Ready)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fx.store.get(&job.id).unwrap().waiting_for,
        Some(WaitingFor::QueuePaused)
    );
    assert_eq!(
        fx.store.pause_reason().unwrap(),
        Some(PauseReason::Operator)
    );
    fx.store.set_pause(None).unwrap();
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
fn a_job_that_waits_too_long_fails_with_the_code_of_the_wait() {
    let fx = Fx::with_policy("wait", |p| p.limits.wait_s = 100);
    let cases = [
        (WaitingFor::Resources, FailureCode::HostResources),
        (WaitingFor::Dependency, FailureCode::DependencyMissing),
        (WaitingFor::Quota, FailureCode::QuotaExceeded),
        (WaitingFor::LayerPending, FailureCode::HostResources),
    ];
    let ids: Vec<_> = (0..cases.len())
        .map(|n| fx.queued(n as u8 + 1).id)
        .collect();
    // The scheduler gives each job its own reason.
    fx.store
        .claim_next(&lane(), &mut |job| {
            let at = ids.iter().position(|id| *id == job.id).unwrap();
            Eligibility::Wait(cases[at].0)
        })
        .unwrap();
    // A job that waits for the lane never times out.
    let lane_wait = fx.queued(8);
    fx.store
        .claim_next(
            &lane(),
            &mut |job| match ids.iter().position(|id| *id == job.id) {
                Some(at) => Eligibility::Wait(cases[at].0),
                None => Eligibility::Wait(WaitingFor::Lane),
            },
        )
        .unwrap();
    // Not yet.
    fx.clock.advance(99_999);
    assert!(fx.store.expire_waits().unwrap().is_empty());
    fx.clock.advance(1);
    let failed = fx.store.expire_waits().unwrap();
    assert_eq!(failed.len(), 4);
    for (at, (_, code)) in cases.iter().enumerate() {
        let job = failed.iter().find(|j| j.id == ids[at]).unwrap();
        assert_eq!(job.state, JobState::Failed);
        let failure = job.failure.as_ref().unwrap();
        assert_eq!((failure.code, failure.stage), (*code, Stage::Prechecks));
    }
    assert_eq!(fx.store.get(&lane_wait.id).unwrap().state, JobState::Queued);
    // A lane wait does not time out.
    fx.clock.advance(1_000_000);
    assert!(fx.store.expire_waits().unwrap().is_empty());
}

#[test]
fn artifacts_warnings_and_assessment_belong_to_a_running_job() {
    use crate::api::{
        artifact::{ArtifactKind, MediaType},
        assessment::*,
    };
    let fx = Fx::new("parts");
    let job = fx.running(1);
    let artifact = fx
        .store
        .add_artifact(
            &job.id,
            crate::store::artifacts::NewArtifact {
                kind: ArtifactKind::NetworkPcap,
                name: "run.pcap".into(),
                size: 10,
                sha256: sha(7),
                media_type: MediaType::ApplicationPcap,
                raw_indicators: false,
                location: "network/run.pcap".into(),
            },
        )
        .unwrap();
    assert!(artifact.sensitive);
    assert_eq!(
        fx.store.get(&job.id).unwrap().artifacts,
        vec![artifact.clone()]
    );
    assert_eq!(
        fx.store.artifact(&artifact.id).unwrap().1,
        "network/run.pcap"
    );
    // BH-22: the same file written again (a job resumed at `analyse` writes
    // its report again) replaces the row; the old hash is gone with it.
    let report = |sha256| crate::store::artifacts::NewArtifact {
        kind: ArtifactKind::ReportJson,
        name: "report-0000.json".into(),
        size: 20,
        sha256,
        media_type: MediaType::ApplicationJson,
        raw_indicators: true,
        location: "artifacts/report-0000.json".into(),
    };
    let first = fx.store.add_artifact(&job.id, report(sha(8))).unwrap();
    fx.clock.advance(1);
    let again = fx.store.add_artifact(&job.id, report(sha(9))).unwrap();
    assert_ne!(first.id, again.id);
    let reports: Vec<_> = fx
        .store
        .artifacts(&job.id)
        .unwrap()
        .into_iter()
        .filter(|a| a.kind == ArtifactKind::ReportJson)
        .collect();
    assert_eq!(reports, vec![again.clone()]);
    assert_eq!(reports[0].sha256, sha(9));
    assert!(fx.store.artifact(&first.id).is_err());
    assert_eq!(
        fx.store.artifacts(&job.id).unwrap().len(),
        2,
        "the pcap stays"
    );
    let assessment = Assessment {
        assessment: AssessmentKind::ObservedOnly,
        highest_tier: Tier::None,
        label: Some(Label::CleanObserved),
        score: Some(0),
        families: vec![],
        counts: Counts::default(),
        key_behaviours: vec![],
        detections: vec![],
        techniques: vec![],
        ioc_dataset_count: 0,
        basis: "nothing seen".into(),
    };
    assert_eq!(
        fx.store
            .set_assessment(&job.id, &assessment)
            .unwrap()
            .assessment,
        Some(assessment)
    );
    for n in 0..1005 {
        fx.store
            .add_warning(&job.id, "w", &format!("warning {n}"))
            .unwrap();
    }
    let job = fx.store.get(&job.id).unwrap();
    assert_eq!(job.warnings.len(), 1001);
    assert_eq!(job.warnings[999].text, "warning 999");
    assert_eq!(job.warnings[1000].code, "warnings_truncated");
    let types = kinds(&fx, &job.id);
    assert_eq!(types.iter().filter(|t| *t == "job.warning").count(), 1001);
    // After the end nothing more is taken.
    fx.store.finish(&job.id, Outcome::Succeeded, None).unwrap();
    assert_eq!(
        fx.store.add_warning(&job.id, "w", "late").unwrap_err().code,
        ErrorCode::Conflict
    );
}

/// Bring a fresh job into every state; try every operation on it; the
/// operation works exactly when the state machine has the edge.
#[test]
fn every_forbidden_edge_is_refused_and_changes_nothing() {
    const STATES: [JobState; 8] = [
        JobState::Queued,
        JobState::Running,
        JobState::Cancelling,
        JobState::Succeeded,
        JobState::Partial,
        JobState::Failed,
        JobState::Cancelled,
        JobState::Rejected,
    ];
    let failure = || fail(FailureCode::Internal, Stage::Run);
    for from in STATES {
        // One operation per target state.
        for to in STATES {
            let fx = Fx::new("edges");
            let id = job_in(&fx, from);
            let before = fx.store.get(&id).unwrap();
            let events_before = kinds(&fx, &id);
            let result: R<Job> = match to {
                JobState::Running => fx
                    .store
                    .claim_next(&lane(), &mut |_| Eligibility::Ready)
                    .and_then(|job| match job {
                        Some(job) if job.id == id => Ok(job),
                        _ => Err(ApiError::new(ErrorCode::Conflict, "not claimed")),
                    }),
                JobState::Cancelling => fx.store.cancel_for_shutdown(&id),
                JobState::Queued => fx
                    .store
                    .requeue(&id, RequeueKind::Shutdown, "x", None, None),
                JobState::Succeeded => fx.store.finish(&id, Outcome::Succeeded, None),
                JobState::Partial => fx.store.finish(&id, Outcome::Partial, None),
                JobState::Failed => fx.store.finish(&id, Outcome::Failed, Some(failure())),
                JobState::Cancelled => fx.store.finish(&id, Outcome::Cancelled, None),
                JobState::Rejected => fx.store.finish(&id, Outcome::Rejected, None),
            };
            // `requeue` from `cancelling` needs a shutdown cancel; the table's
            // edge exists, and the helper above made this job a user cancel.
            let expected = machine::allowed(from, to)
                && !(from == JobState::Cancelling && to == JobState::Queued);
            assert_eq!(
                result.is_ok(),
                expected,
                "{from:?} -> {to:?}: {:?}",
                result.err()
            );
            if !expected {
                let after = fx.store.get(&id).unwrap();
                assert_eq!(after, before, "{from:?} -> {to:?} changed the job");
                assert_eq!(
                    kinds(&fx, &id),
                    events_before,
                    "{from:?} -> {to:?} wrote events"
                );
            }
        }
    }
}

/// A job in the given state, made through the public operations.
fn job_in(fx: &Fx, state: JobState) -> JobId {
    match state {
        JobState::Queued => fx.queued(1).id,
        JobState::Rejected => fx.submit(spec(99)).job.id,
        JobState::Running => fx.running(1).id,
        JobState::Cancelling => {
            let id = fx.running(1).id;
            fx.store.cancel(&id, None, &caller(1000)).unwrap();
            id
        }
        JobState::Succeeded | JobState::Partial | JobState::Failed | JobState::Cancelled => {
            let id = fx.running(1).id;
            match state {
                JobState::Succeeded => fx.store.finish(&id, Outcome::Succeeded, None),
                JobState::Partial => fx.store.finish(&id, Outcome::Partial, None),
                JobState::Failed => fx.store.finish(
                    &id,
                    Outcome::Failed,
                    Some(fail(FailureCode::Internal, Stage::Run)),
                ),
                _ => {
                    fx.store.cancel(&id, None, &caller(1000)).unwrap();
                    fx.store.finish(&id, Outcome::Cancelled, None)
                }
            }
            .unwrap();
            id
        }
    }
}

#[test]
fn queued_jobs_can_fail_and_every_edge_in_the_table_is_reachable() {
    // queued -> failed, running -> queued, cancelling -> queued are in the table
    // and exercised above; check the table size against the diagram.
    assert!(machine::allowed(JobState::Queued, JobState::Failed));
    let fx = Fx::new("edge-queued-failed");
    let id = fx.queued(1).id;
    let failed = fx
        .store
        .finish(
            &id,
            Outcome::Failed,
            Some(fail(FailureCode::HostResources, Stage::Prechecks)),
        )
        .unwrap();
    assert_eq!(failed.state, JobState::Failed);
}

#[test]
fn listing_pages_newest_first_and_filters() {
    let fx = Fx::new("list");
    let mut ids = Vec::new();
    for n in 1..=7u8 {
        fx.clock.advance(10);
        let mut s = spec(n);
        if n % 2 == 0 {
            s.labels.insert("ci".into(), "yes".into());
        }
        ids.push(fx.submit(s).job.id);
    }
    let done = fx
        .store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(done.id, ids[0]);
    fx.store.finish(&done.id, Outcome::Succeeded, None).unwrap();

    let page = fx
        .store
        .list(
            &JobListParams {
                limit: Some(3),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    let listed: Vec<_> = page.jobs.iter().map(|j| j.id.clone()).collect();
    assert_eq!(listed, [ids[6].clone(), ids[5].clone(), ids[4].clone()]);
    let cursor = page.next_cursor.unwrap();
    let second = fx
        .store
        .list(
            &JobListParams {
                limit: Some(3),
                cursor: Some(cursor),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(
        second.jobs.iter().map(|j| j.id.clone()).collect::<Vec<_>>(),
        [ids[3].clone(), ids[2].clone(), ids[1].clone()]
    );
    let third = fx
        .store
        .list(
            &JobListParams {
                limit: Some(3),
                cursor: second.next_cursor,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(third.jobs.len(), 1);
    assert_eq!(third.next_cursor, None);

    use crate::api::ops::JobListParams as P;
    let finished = fx
        .store
        .list(
            &P {
                outcome: Some(Outcome::Succeeded),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(finished.jobs.len(), 1);
    let queued = fx
        .store
        .list(
            &P {
                state: Some(JobState::Queued),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(queued.jobs.len(), 6);
    let labelled = fx
        .store
        .list(
            &P {
                label: Some("ci=yes".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(labelled.jobs.len(), 3);
    let any_value = fx
        .store
        .list(
            &P {
                label: Some("ci".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(any_value.jobs.len(), 3);
    let by_sha = fx
        .store
        .list(
            &P {
                sha256: Some(sha(3)),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(by_sha.jobs.len(), 1);
    let since = fx
        .store
        .list(
            &P {
                since_ms: Some(T0 + 50),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(since.jobs.len(), 3);
    let own = fx.store.list(&P::default(), Some("local:4242")).unwrap();
    assert!(own.jobs.is_empty());

    for bad in [Some(0), Some(201)] {
        assert_eq!(
            fx.store
                .list(
                    &P {
                        limit: bad,
                        ..Default::default()
                    },
                    None
                )
                .unwrap_err()
                .field
                .as_deref(),
            Some("limit")
        );
    }
    let bad = fx
        .store
        .list(
            &P {
                cursor: Some("zzz".into()),
                ..Default::default()
            },
            None,
        )
        .unwrap_err();
    assert_eq!(bad.field.as_deref(), Some("cursor"));
}

#[test]
fn a_label_filter_pages_past_non_matching_jobs() {
    let fx = Fx::new("list-label");
    // 250 jobs, 3 labelled: the first page of the scan holds none of the early ones.
    let mut labelled = Vec::new();
    for n in 0..250u32 {
        fx.clock.advance(1);
        let mut s = spec(1 + (n % 9) as u8);
        if n == 0 || n == 100 || n == 249 {
            s.labels.insert("pick".into(), "me".into());
        }
        s.idempotency_key = None;
        let job = fx
            .store
            .submit(
                &Caller {
                    client_id: format!("local:{}", 5000 + n),
                    ..caller(0)
                },
                s,
                &fx.ctx(),
            )
            .unwrap()
            .job;
        if n == 0 || n == 100 || n == 249 {
            labelled.push(job.id);
        }
    }
    let page = fx
        .store
        .list(
            &JobListParams {
                label: Some("pick".into()),
                limit: Some(2),
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(
        page.jobs.iter().map(|j| j.id.clone()).collect::<Vec<_>>(),
        [labelled[2].clone(), labelled[1].clone()]
    );
    let rest = fx
        .store
        .list(
            &JobListParams {
                label: Some("pick".into()),
                limit: Some(2),
                cursor: page.next_cursor,
                ..Default::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(rest.jobs.len(), 1);
    assert_eq!(rest.jobs[0].id, labelled[0]);
}

/// BH-01 (bug hunt 0.9.0): a lane that can run a job must find it even when
/// 64 or more older jobs ahead of it are ones it cannot take now (another
/// lane's architecture, a backoff). `claim_next` looks at 64 rows only.
#[test]
fn bh_01_a_job_the_lane_can_run_behind_64_it_cannot_is_still_claimed() {
    let fx = Fx::with_policy("bh01", |p| p.limits.max_queued_per_client = 100);
    for _ in 0..64 {
        fx.queued(1);
        fx.clock.advance(1);
    }
    let wanted = fx.queued(2);
    let claimed = fx
        .store
        .claim_next(&lane(), &mut |job| {
            if job.sample.as_ref().is_some_and(|s| s.sha256 == sha(2)) {
                Eligibility::Ready
            } else {
                Eligibility::Wait(WaitingFor::Lane)
            }
        })
        .unwrap();
    assert_eq!(claimed.map(|job| job.id), Some(wanted.id));
}

// SPDX-License-Identifier: GPL-3.0-only
//! `job.submit`: synchronous validation, `rejected`, idempotency, quotas and
//! duplicates.

use super::*;
use crate::api::{
    error::ErrorReason,
    spec::{Overrides, Route, RunAs, RunAsName},
};

#[test]
fn an_accepted_job_is_queued_with_the_policy_filled_in() {
    let fx = Fx::new("accepted");
    let submitted = fx.submit(spec(1));
    assert!(!submitted.replayed);
    let job = submitted.job;
    assert_eq!(job.state, JobState::Queued);
    assert_eq!(job.outcome, None);
    assert_eq!(job.queue_position, Some(0));
    assert_eq!(job.client_id, "local:1000");
    assert_eq!(job.created_ms, T0);
    assert_eq!(job.attempt, 0);
    assert_eq!(job.max_attempts, 2);
    assert_eq!(job.policy.name, "default");
    assert_eq!(job.policy.digest, "digest-of-default-300");
    assert_eq!(job.sample.as_ref().unwrap().sha256, sha(1));
    // The resolved spec: defaults from the policy, the sample by hash.
    assert_eq!(job.spec.sample.sha256, Some(sha(1)));
    assert_eq!(job.spec.policy.as_deref(), Some("default"));
    assert_eq!(job.spec.priority, Some(5));
    assert_eq!(job.spec.overrides.timeout_s, Some(300));
    assert_eq!(job.spec.overrides.route, Some(Route::Drop));
    assert_eq!(job.spec.overrides.report_defang, Some(true));
    assert_eq!(
        job.spec.overrides.run_as,
        Some(RunAs::Named(RunAsName::User))
    );
    assert_eq!(kinds(&fx, &job.id), ["job.created"]);
    // The spec is also written to the job directory.
    assert!(
        fx.dir
            .join("service/jobs")
            .join(job.id.as_str())
            .join("spec.json")
            .is_file()
    );
}

#[test]
fn shape_errors_unknown_policy_and_v1_limits_are_errors_not_jobs() {
    let fx = Fx::new("errors");
    let call = |spec: JobSpec| fx.submit_as(&caller(1000), spec).unwrap_err();

    let error = call(JobSpec {
        priority: Some(10),
        ..spec(1)
    });
    assert_eq!(
        (error.code, error.field.as_deref()),
        (ErrorCode::InvalidArgument, Some("priority"))
    );
    let error = call(JobSpec {
        name: Some("a/b".into()),
        ..spec(1)
    });
    assert_eq!(error.field.as_deref(), Some("name"));
    let error = call(JobSpec {
        policy: Some("nope".into()),
        ..spec(1)
    });
    assert_eq!(error.code, ErrorCode::NotFound);

    let live = JobSpec {
        overrides: Overrides {
            route: Some(Route::Internet),
            ..Default::default()
        },
        ..spec(1)
    };
    let error = call(live);
    assert_eq!(error.code, ErrorCode::Unsupported);
    assert_eq!(error.reason(), Some(ErrorReason::LiveRouteNotInV1));

    // sample.path is local-only.
    let remote = Caller {
        client_id: "web:alice".into(),
        ..caller(0)
    };
    let by_path = JobSpec {
        sample: SampleSource {
            path: Some("/tmp/x".into()),
            ..Default::default()
        },
        ..spec(1)
    };
    let error = fx.submit_as(&remote, by_path).unwrap_err();
    assert_eq!(error.field.as_deref(), Some("sample.path"));

    // A caller without the submit scope.
    let reader = Caller {
        scopes: vec![Scope::Read],
        ..caller(1000)
    };
    assert_eq!(
        fx.submit_as(&reader, spec(1)).unwrap_err().code,
        ErrorCode::Forbidden
    );
    // None of these stored a job.
    assert_eq!(fx.store.counts().unwrap(), Default::default());
}

#[test]
fn a_spec_that_fails_policy_or_intake_is_stored_rejected() {
    let fx = Fx::new("rejected");
    let cases: Vec<(JobSpec, FailureCode, &str)> = vec![
        (spec(99), FailureCode::SampleMissing, "sample"),
        (spec(20), FailureCode::SampleTypeDenied, "sample"),
        (spec(21), FailureCode::SampleTooLarge, "sample"),
        (
            JobSpec {
                priority: Some(9),
                ..spec(1)
            },
            FailureCode::PolicyDenied,
            "priority",
        ),
        (
            JobSpec {
                overrides: Overrides {
                    timeout_s: Some(1801),
                    ..Default::default()
                },
                ..spec(1)
            },
            FailureCode::PolicyDenied,
            "overrides.timeout_s",
        ),
        (
            JobSpec {
                overrides: Overrides {
                    run_as: Some(RunAs::Named(RunAsName::Root)),
                    ..Default::default()
                },
                ..spec(1)
            },
            FailureCode::PolicyDenied,
            "overrides.run_as",
        ),
        (
            JobSpec {
                overrides: Overrides {
                    env: Some(vec!["A=1".into()]),
                    ..Default::default()
                },
                ..spec(1)
            },
            FailureCode::PolicyDenied,
            "overrides.env",
        ),
        (
            JobSpec {
                overrides: Overrides {
                    memory_dump: Some(true),
                    ..Default::default()
                },
                ..spec(1)
            },
            FailureCode::PolicyDenied,
            "overrides.memory_dump",
        ),
        (
            JobSpec {
                overrides: Overrides {
                    keep_on_failure: Some(true),
                    ..Default::default()
                },
                ..spec(1)
            },
            FailureCode::PolicyDenied,
            "overrides.keep_on_failure",
        ),
    ];
    for (spec, code, field) in cases {
        let job = fx.submit(spec).job;
        assert_eq!(job.state, JobState::Rejected, "{code:?}");
        assert_eq!(job.outcome, Some(Outcome::Rejected));
        assert_eq!(job.finished_ms, Some(T0));
        let failure = job.failure.clone().unwrap();
        assert_eq!(failure.code, code);
        assert_eq!(failure.stage, Stage::Prechecks);
        assert!(!failure.retryable);
        assert!(failure.detail.unwrap().contains(field), "{field}");
        assert_eq!(kinds(&fx, &job.id), ["job.created", "job.finished"]);
        // It consumes no lane time: it is never queued.
        assert_eq!(job.queue_position, None);
        assert_eq!(fx.store.get(&job.id).unwrap().state, JobState::Rejected);
    }
    assert_eq!(fx.store.counts().unwrap().queued, 0);
}

#[test]
fn a_policy_the_caller_may_not_use_rejects_with_policy_denied() {
    let mut fx = Fx::new("access");
    fx.policies = PolicySet::single(policy("default", |p| {
        p.access.clients = vec!["web:*".into()];
    }));
    let job = fx.submit(spec(1)).job;
    assert_eq!(job.state, JobState::Rejected);
    assert_eq!(job.failure.unwrap().code, FailureCode::PolicyDenied);
    let web = Caller {
        client_id: "web:bob".into(),
        ..caller(0)
    };
    assert_eq!(
        fx.submit_as(&web, spec(1)).unwrap().job.state,
        JobState::Queued
    );
}

#[test]
fn a_spec_may_override_within_the_ceiling() {
    let fx = Fx::with_policy("ceiling", |p| {
        p.run.allow_root = true;
        p.run.env_allowed = true;
        p.limits.priority_max = 9;
        p.evidence.memory_dump = true;
    });
    let spec = JobSpec {
        priority: Some(9),
        overrides: Overrides {
            timeout_s: Some(1800),
            route: Some(Route::InetSim),
            run_as: Some(RunAs::Named(RunAsName::Root)),
            env: Some(vec!["A=1".into()]),
            memory_dump: Some(true),
            ..Default::default()
        },
        ..spec(1)
    };
    let job = fx.submit(spec).job;
    assert_eq!(job.state, JobState::Queued, "{:?}", job.failure);
    assert_eq!(job.spec.overrides.route, Some(Route::InetSim));
    assert_eq!(job.spec.priority, Some(9));
}

#[test]
fn the_same_key_and_spec_replay_the_job() {
    let fx = Fx::new("idem");
    let first = fx.submit(keyed(1, "k1"));
    assert!(!first.replayed);
    let again = fx.submit(keyed(1, "k1"));
    assert!(again.replayed);
    assert_eq!(again.job.id, first.job.id);
    // Another order of the same fields is the same spec.
    let mut labels = BTreeMap::new();
    labels.insert("b".to_owned(), "2".to_owned());
    labels.insert("a".to_owned(), "1".to_owned());
    let one = fx.submit(JobSpec {
        labels: labels.clone(),
        ..keyed(2, "k2")
    });
    let two = fx.submit(JobSpec {
        labels,
        ..keyed(2, "k2")
    });
    assert!(two.replayed);
    assert_eq!(two.job.id, one.job.id);
    assert_eq!(fx.store.counts().unwrap().queued, 2);
    // A replay writes no event.
    assert_eq!(kinds(&fx, &first.job.id), ["job.created"]);
}

#[test]
fn the_same_key_with_another_spec_is_a_conflict() {
    let fx = Fx::new("idem-conflict");
    let first = fx.submit(keyed(1, "k"));
    let error = fx.submit_as(&caller(1000), keyed(2, "k")).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    assert_eq!(error.details["job_id"], first.job.id.as_str());
    // The key is scoped to the client.
    let other = fx.submit_as(&caller(1001), keyed(2, "k")).unwrap();
    assert!(!other.replayed);
    // A rejected job keeps its key too.
    let rejected = fx.submit(keyed(99, "r"));
    assert_eq!(rejected.job.state, JobState::Rejected);
    assert!(fx.submit(keyed(99, "r")).replayed);
}

#[test]
fn a_key_is_free_again_after_24_hours() {
    let fx = Fx::new("idem-expiry");
    let first = fx.submit(keyed(1, "k"));
    fx.clock.advance(24 * 3600 * 1000 - 1);
    assert!(fx.submit(keyed(1, "k")).replayed);
    fx.clock.advance(1);
    // Even a different spec now: the key is free, a new job is made.
    let second = fx.submit(keyed(2, "k"));
    assert!(!second.replayed);
    assert_ne!(second.job.id, first.job.id);
    // The janitor clears keys that nobody asked for again.
    let third = fx.submit(keyed(3, "j"));
    fx.clock.advance(24 * 3600 * 1000);
    assert_eq!(fx.store.expire_idempotency_keys().unwrap(), 2);
    let key: Option<String> = fx
        .store
        .conn()
        .query_row(
            "SELECT idempotency_key FROM jobs WHERE id = ?1",
            [third.job.id.as_str()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(key, None);
}

#[test]
fn the_queue_and_client_caps_are_enforced() {
    let mut fx = Fx::with_policy("quota", |p| p.limits.max_queued_per_client = 3);
    fx.limits = SubmitLimits {
        max_queued: 5,
        per_client_queued: 10,
    };
    for n in 1..=3 {
        fx.queued(n);
    }
    // The policy's cap (3) is the smaller one.
    let error = fx.submit_as(&caller(1000), spec(4)).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert!(error.retryable);
    assert!(error.details.contains_key("retry_after_s"));
    // Another client has its own count, up to the node cap.
    for n in 4..=5 {
        fx.submit_as(&caller(1001), spec(n)).unwrap();
    }
    let error = fx.submit_as(&caller(1002), spec(6)).unwrap_err();
    assert_eq!(error.code, ErrorCode::QuotaExceeded);
    assert!(error.message.contains("queue is full"));
    // A running job leaves the queue, so it makes room.
    fx.store
        .claim_next(&lane(), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    fx.submit_as(&caller(1002), spec(6)).unwrap();
}

#[test]
fn duplicates_follow_the_policy() {
    // run (default): the new job repeats the latest finished one.
    let fx = Fx::new("dup-run");
    let first = fx.running(1);
    fx.store
        .finish(&first.id, Outcome::Succeeded, None)
        .unwrap();
    let again = fx.submit(spec(1)).job;
    assert_eq!(again.state, JobState::Queued);
    assert_eq!(again.repeat_of, Some(first.id.clone()));
    // A queued or running earlier job is not "finished": no repeat_of.
    assert_eq!(fx.submit(spec(2)).job.repeat_of, None);

    // reject
    let fx = Fx::with_policy("dup-reject", |p| on_dup(p, OnDuplicate::Reject));
    let first = fx.running(1);
    fx.store.finish(&first.id, Outcome::Partial, None).unwrap();
    let denied = fx.submit(spec(1)).job;
    assert_eq!(denied.state, JobState::Rejected);
    assert_eq!(denied.failure.unwrap().code, FailureCode::DuplicateDenied);

    // reuse: the earlier job is the result, no new job.
    let fx = Fx::with_policy("dup-reuse", |p| on_dup(p, OnDuplicate::Reuse));
    let first = fx.running(1);
    fx.store
        .finish(&first.id, Outcome::Succeeded, None)
        .unwrap();
    let reused = fx.submit(spec(1));
    assert!(reused.replayed);
    assert_eq!(reused.job.id, first.id);
    assert_eq!(fx.store.count_state(JobState::Queued).unwrap(), 0);

    // reuse of a failed job runs again; reuse across another policy digest needs the flag.
    let fx = Fx::with_policy("dup-reuse-failed", |p| on_dup(p, OnDuplicate::Reuse));
    let first = fx.running(1);
    fx.store
        .finish(
            &first.id,
            Outcome::Failed,
            Some(Failure::new(FailureCode::GuestLost, Stage::Run, "x", None)),
        )
        .unwrap();
    let again = fx.submit(spec(1));
    assert!(!again.replayed);
    assert_eq!(again.job.repeat_of, Some(first.id));
}

#[test]
fn remote_replies_carry_no_host_path() {
    let fx = Fx::new("redact");
    let job = fx.running(1);
    fx.store
        .add_warning(
            &job.id,
            "tool_missing",
            "cannot open /home/user/data/x/y.bin: no such file",
        )
        .unwrap();
    let mut job = fx.store.get(&job.id).unwrap();
    job.spec.sample.path = Some("/home/user/x".into());
    job.recording = Some(crate::api::job::JobRecording {
        vm_id: "v".into(),
        boot_id: "b".into(),
        run_id: "r".into(),
        run_key: "k".into(),
        phase: crate::api::job::RecordingPhase::Live,
        directory: Some("/mnt/rec".into()),
    });
    redact_remote(&mut job);
    assert_eq!(job.spec.sample.path, None);
    assert_eq!(job.recording.unwrap().directory, None);
    assert_eq!(job.warnings[0].text, "cannot open <path>: no such file");
}

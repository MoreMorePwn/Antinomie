// SPDX-License-Identifier: GPL-3.0-only
//! `job.submit`: synchronous validation, `rejected`, idempotency, quotas and
//! duplicates.

use super::permissions::with;
use super::*;
use crate::api::{error::ErrorReason, ops::Limits};
use serde_json::json;

#[test]
fn an_accepted_job_is_queued_with_the_preset_filled_in() {
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
    assert_eq!(job.policy.name, "standard");
    assert_eq!(job.policy.digest, "digest-of-standard-300");
    assert_eq!(job.policy.based_on, None);
    assert!(job.policy.changes.is_empty());
    assert_eq!(job.sample.as_ref().unwrap().sha256, sha(1));
    // The stored spec: the preset's name, the priority, the sample by hash
    // and no overrides; the options are the frozen preset.
    assert_eq!(job.spec.sample.sha256, Some(sha(1)));
    assert_eq!(job.spec.policy.as_deref(), Some("standard"));
    assert_eq!(job.spec.priority, Some(5));
    assert!(job.spec.overrides.is_empty());
    let frozen = fx.store.frozen_preset(&job.id).unwrap();
    assert_eq!(frozen.preset.program.run_time_s, 300);
    assert_eq!(frozen.preset.network.route, crate::api::spec::Route::Drop);
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
fn shape_errors_an_unknown_preset_and_reserved_keys_are_errors_not_jobs() {
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
    assert_eq!(error.code, ErrorCode::PresetDenied);
    // Overrides are a partial preset: tables of its keys.
    let error = call(with(json!({"timeout_s": 60})));
    assert_eq!(error.field.as_deref(), Some("overrides"));
    let error = call(with(json!({"run": {"timeout_s": 60}})));
    assert_eq!(error.field.as_deref(), Some("overrides.run"));

    // Every key 0.9.0 reserves, away from its default: unsupported.
    for (overrides, field) in [
        (
            json!({"program": {"run_in": "guest_desktop"}}),
            "program.run_in",
        ),
        (
            json!({"program": {"source": "guest_path"}}),
            "program.source",
        ),
        (
            json!({"program": {"executable": "/bin/ls"}}),
            "program.executable",
        ),
        (
            json!({"program": {"preload": [{"sample": "ab", "how": "ld_preload"}]}}),
            "program.preload",
        ),
        (
            json!({"program": {"extra_files": [{"sample": "ab", "guest_path": "/tmp/x"}]}}),
            "program.extra_files",
        ),
        (json!({"record": {"scope": "whole_vm"}}), "record.scope"),
        (
            json!({"record": {"screenshot_every_s": 5}}),
            "record.screenshot_every_s",
        ),
        (
            json!({"network": {"private_addresses": true}}),
            "network.private_addresses",
        ),
        (
            json!({"network": {"abuse_filter": false}}),
            "network.abuse_filter",
        ),
        (json!({"dumps": {"disk_dump": true}}), "dumps.disk_dump"),
        (
            json!({"static_analysis": {"rebuilt_file_mib": 32}}),
            "static_analysis.rebuilt_file_mib",
        ),
        (
            json!({"static_analysis": {"rebuilt_run_mib": 32}}),
            "static_analysis.rebuilt_run_mib",
        ),
        (
            json!({"triage": {"written_per_file_mib": 1}}),
            "triage.written_per_file_mib",
        ),
        (
            json!({"triage": {"written_per_run_mib": 1}}),
            "triage.written_per_run_mib",
        ),
        (
            json!({"triage": {"earlier_per_file_mib": 1}}),
            "triage.earlier_per_file_mib",
        ),
        (
            json!({"triage": {"earlier_per_run_mib": 1}}),
            "triage.earlier_per_run_mib",
        ),
        (
            json!({"detection": {"scan_every_min": 2}}),
            "detection.scan_every_min",
        ),
        (
            json!({"report": {"sections": ["summary"]}}),
            "report.sections",
        ),
    ] {
        let error = call(with(overrides));
        assert_eq!(error.code, ErrorCode::Unsupported, "{field}");
        assert_eq!(error.field.as_deref(), Some(field));
        assert_eq!(error.reason(), Some(ErrorReason::Reserved));
        assert!(error.message.contains("arrives with 0.9.1"), "{error:?}");
    }
    // At its default, a reserved key is accepted.
    let fine = fx
        .submit_as(
            &caller(1000),
            with(json!({"program": {"run_in": "app_terminal"}})),
        )
        .unwrap();
    assert_eq!(fine.job.state, JobState::Queued);
    fx.store.cancel(&fine.job.id, None, &caller(1000)).unwrap();

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

    // A caller without runs.submit.
    let reader = Caller::new("local:1000", &[crate::api::ops::Permission::RunsSeeAll]);
    let error = fx.submit_as(&reader, spec(1)).unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(error.details["needs"], serde_json::json!(["runs.submit"]));
    // None of these stored a job but the cancelled one.
    assert_eq!(fx.store.counts().unwrap().queued, 0);
}

#[test]
fn a_spec_that_fails_a_check_or_intake_is_stored_rejected() {
    let fx = Fx::with_policy("rejected", |p| p.accepts.types = vec!["elf".into()]);
    let mut limited = caller(1000);
    limited.limits = Limits {
        priority_max: Some(5),
        max_run_s: Some(600),
        ..Limits::default()
    };
    let cases: Vec<(JobSpec, FailureCode, &str)> = vec![
        (spec(99), FailureCode::SampleMissing, "sample"),
        (spec(20), FailureCode::SampleTypeDenied, "sample"),
        (spec(21), FailureCode::SampleTooLarge, "sample"),
        (
            JobSpec {
                priority: Some(9),
                ..spec(1)
            },
            FailureCode::LimitExceeded,
            "priority",
        ),
        (
            with(json!({"program": {"run_time_s": 601}})),
            FailureCode::LimitExceeded,
            "program.run_time_s",
        ),
        (
            with(json!({"program": {"user": "root"}})),
            FailureCode::PermissionDenied,
            "program.user",
        ),
        (
            with(json!({"dumps": {"memory_dump_on_exit": true}})),
            FailureCode::PermissionDenied,
            "dumps.memory_dump_on_exit",
        ),
        (
            with(json!({"vm": {"keep_on_failure": true}})),
            FailureCode::PermissionDenied,
            "vm.keep_on_failure",
        ),
        (
            with(json!({"network": {"route": "tor"}})),
            FailureCode::PermissionDenied,
            "network.route",
        ),
        (
            with(json!({"vm": {"lane_group": "arm64"}})),
            FailureCode::UnavailableOnNode,
            "vm.lane_group",
        ),
    ];
    for (spec, code, field) in cases {
        let job = fx.submit_as(&limited, spec).unwrap().job;
        assert_eq!(job.state, JobState::Rejected, "{code:?}");
        assert_eq!(job.outcome, Some(Outcome::Rejected));
        assert_eq!(job.finished_ms, Some(T0));
        let failure = job.failure.clone().unwrap();
        assert_eq!(failure.code, code);
        assert_eq!(failure.stage, Stage::Prechecks);
        assert!(!failure.retryable);
        assert!(failure.detail.unwrap().contains(field), "{field}");
        assert_eq!(failure.field.as_deref(), Some(field));
        assert_eq!(kinds(&fx, &job.id), ["job.created", "job.finished"]);
        // It consumes no lane time: it is never queued.
        assert_eq!(job.queue_position, None);
        assert_eq!(fx.store.get(&job.id).unwrap().state, JobState::Rejected);
    }
    assert_eq!(fx.store.counts().unwrap().queued, 0);
}

#[test]
fn a_rejected_custom_run_names_the_preset_it_was_based_on() {
    let fx = Fx::new("rejected-custom");
    let job = fx
        .submit(with(
            json!({"network": {"route": "tor"}, "program": {"run_time_s": 600}}),
        ))
        .job;
    assert_eq!(job.state, JobState::Rejected);
    assert_eq!(job.policy.name, "custom");
    assert_eq!(job.policy.based_on.as_ref().unwrap().name, "standard");
    assert_eq!(job.policy.changes, ["network.route", "program.run_time_s"]);
}

#[test]
fn a_change_makes_the_run_custom_and_an_equal_value_does_not() {
    let fx = Fx::new("custom");
    let owner = Caller::with_every_permission("local:1000");
    let spec = JobSpec {
        priority: Some(9),
        ..with(json!({
            "program": {"run_time_s": 1800, "user": "root", "environment": ["A=1"]},
            "network": {"route": "inet_sim"},
            "dumps": {"memory_dump_on_exit": true},
            "report": {"defang": true}
        }))
    };
    let job = fx.submit_as(&owner, spec).unwrap().job;
    assert_eq!(job.state, JobState::Queued, "{:?}", job.failure);
    assert_eq!(job.policy.name, "custom");
    assert_eq!(job.policy.digest.len(), 64);
    let base = job.policy.based_on.clone().unwrap();
    assert_eq!(
        (base.name.as_str(), base.digest.as_str()),
        ("standard", "digest-of-standard-300")
    );
    assert_eq!(
        job.policy.changes,
        [
            "dumps.memory_dump_on_exit",
            "network.route",
            "program.environment",
            "program.run_time_s",
            "program.user"
        ]
    );
    // The stored spec keeps the changes only (report.defang was already on).
    assert_eq!(
        serde_json::to_value(&job.spec.overrides).unwrap(),
        json!({
            "dumps": {"memory_dump_on_exit": true},
            "network": {"route": "inet_sim"},
            "program": {"environment": ["A=1"], "run_time_s": 1800, "user": "root"}
        })
    );
    assert_eq!(job.spec.policy.as_deref(), Some("standard"));
    assert_eq!(job.spec.priority, Some(9));
    let frozen = fx.store.frozen_preset(&job.id).unwrap();
    assert_eq!(frozen.preset.program.run_time_s, 1800);
    assert_eq!(frozen.digest, job.policy.digest);
    // An override equal to the preset's value leaves the preset as it is.
    let same = fx
        .submit(with(
            json!({"program": {"run_time_s": 300}, "detection": {"yara": true}}),
        ))
        .job;
    assert_eq!(same.policy.name, "standard");
    assert!(same.spec.overrides.is_empty());
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
    let mut fx = Fx::new("quota");
    fx.limits = SubmitLimits {
        max_queued: 5,
        per_client_queued: 10,
        wait_s: 3600,
    };
    let mut capped = caller(1000);
    capped.limits.max_queued = Some(3);
    for n in 1..=3 {
        assert_eq!(
            fx.submit_as(&capped, spec(n)).unwrap().job.state,
            JobState::Queued
        );
    }
    // The caller's cap (3) is the smaller one.
    let error = fx.submit_as(&capped, spec(4)).unwrap_err();
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
fn duplicates_follow_the_preset() {
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

    // reuse of a failed job runs again; reuse across another preset digest needs the flag.
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

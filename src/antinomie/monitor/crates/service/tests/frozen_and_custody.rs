// SPDX-License-Identifier: GPL-3.0-only
//! The policy a job froze at submit survives a reload (card P3-3), and a job's
//! custody entries name its caller (card P3-7).

// `ApiError` is the contract's error type (large by design, see the crate root).
#![allow(clippy::result_large_err)]

use antinomie_monitor_core::samples::{CustodyEvent, Library, NewSample};
use antinomie_service::{
    api::{
        failure::FailureCode,
        ids::Sha256Hex,
        job::{JobSample, JobState},
        ops::{Caller, Scope},
        spec::{JobSpec, Overrides, Route, SampleSource},
    },
    clock::ManualClock,
    config::{DEFAULT_POLICY, NoVms, SharedPolicies},
    custody::{actor_of, record_automation},
    store::{IntakeError, SampleAdmission, Store, SubmitContext, SubmitLimits},
};
use std::{fs, path::PathBuf, sync::Arc};

struct Fixed(JobSample);

impl SampleAdmission for Fixed {
    fn admit(
        &self,
        _: &SampleSource,
        _: Option<&str>,
        _: &antinomie_service::config::LoadedPolicy,
        _: &str,
    ) -> Result<JobSample, IntakeError> {
        Ok(self.0.clone())
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-frozen-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("policies")).unwrap();
    dir
}

fn spec(sha: &Sha256Hex) -> JobSpec {
    JobSpec {
        sample: SampleSource {
            sha256: Some(sha.clone()),
            ..Default::default()
        },
        name: None,
        policy: None,
        priority: None,
        labels: Default::default(),
        idempotency_key: None,
        overrides: Overrides::default(),
    }
}

fn caller(id: &str) -> Caller {
    Caller {
        client_id: id.into(),
        scopes: vec![Scope::Submit],
        policies: vec![],
    }
}

#[test]
fn a_reload_changes_new_jobs_and_never_a_stored_one() {
    let dir = scratch("reload");
    let file = dir.join("policies/default.toml");
    fs::write(&file, DEFAULT_POLICY).unwrap();
    let policies = SharedPolicies::new(Default::default());
    policies.reload(&dir, &NoVms).unwrap();

    let sha = Sha256Hex::try_from("ab".repeat(32)).unwrap();
    let intake = Fixed(JobSample {
        sha256: sha.clone(),
        size: 10,
        kind: "elf".into(),
        architecture: Some("x86_64".into()),
        name: "x".into(),
    });
    let store = Store::open_with_clock(
        &dir.join("service"),
        Arc::new(ManualClock::new(1_794_000_000_000)),
    )
    .unwrap();
    let ctx = SubmitContext {
        policies: &policies,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let first = store
        .submit(&caller("local:1000"), spec(&sha), &ctx)
        .unwrap()
        .job;
    let first_digest = first.policy.digest.clone();
    assert_eq!(
        store.frozen_policy(&first.id).unwrap().policy.run.timeout_s,
        300
    );

    // The administrator tightens the policy and sends SIGHUP.
    fs::write(
        &file,
        DEFAULT_POLICY
            .replace("timeout_s    = 300", "timeout_s    = 60")
            .replace("priority_max          = 5", "priority_max          = 9"),
    )
    .unwrap();
    policies.reload(&dir, &NoVms).unwrap();
    let second = store
        .submit(&caller("local:1000"), spec(&sha), &ctx)
        .unwrap()
        .job;
    assert_ne!(second.policy.digest, first_digest);
    assert_eq!(second.spec.overrides.timeout_s, Some(60));
    // The first job keeps the policy it froze: digest, content and resolved spec.
    let again = store.get(&first.id).unwrap();
    assert_eq!(again.policy.digest, first_digest);
    assert_eq!(again.spec.overrides.timeout_s, Some(300));
    assert_eq!(store.frozen_policy(&first.id).unwrap().digest, first_digest);
    assert_eq!(
        store
            .frozen_policy(&first.id)
            .unwrap()
            .policy
            .limits
            .priority_max,
        5
    );

    // Even if the file is deleted, the job still has its terms.
    fs::remove_file(&file).unwrap();
    assert!(
        policies.reload(&dir, &NoVms).is_ok(),
        "no policies is valid, if empty"
    );
    assert_eq!(
        store
            .frozen_policy(&second.id)
            .unwrap()
            .policy
            .run
            .timeout_s,
        60
    );
    // A new submit against the deleted policy is not_found.
    let error = store
        .submit(&caller("local:1000"), spec(&sha), &ctx)
        .unwrap_err();
    assert_eq!(
        error.code,
        antinomie_service::api::error::ErrorCode::NotFound
    );
    let _ = FailureCode::PolicyDenied;
}

#[test]
fn a_job_writes_one_automation_entry_under_its_caller() {
    let dir = scratch("custody");
    let data = dir.join("data");
    fs::create_dir_all(&data).unwrap();
    let mut library = Library::open(&data).unwrap();
    let bytes = b"#!/bin/sh\necho job\n";
    let sha = library
        .add_bytes_as(
            bytes,
            NewSample {
                name: "job.sh".into(),
                ..Default::default()
            },
            "auto:policy-default",
        )
        .unwrap()
        .sha256;
    let sha = Sha256Hex::try_from(sha).unwrap();
    fs::write(dir.join("policies/default.toml"), DEFAULT_POLICY).unwrap();
    let policies = SharedPolicies::new(Default::default());
    policies.reload(&dir, &NoVms).unwrap();
    let intake = Fixed(JobSample {
        sha256: sha.clone(),
        size: 19,
        kind: "sh".into(),
        architecture: None,
        name: "job.sh".into(),
    });
    let store = Store::open(&dir.join("service")).unwrap();
    let ctx = SubmitContext {
        policies: &policies,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let mut s = spec(&sha);
    s.overrides.route = Some(Route::InetSim);
    let job = store.submit(&caller("web:alice"), s, &ctx).unwrap().job;
    assert_eq!(job.state, JobState::Queued);
    assert_eq!(actor_of(&job), "web:alice");

    record_automation(&data, &job).unwrap();
    let library = Library::open(&data).unwrap();
    let rows = library.events(sha.as_str()).unwrap();
    let last = rows.last().unwrap();
    assert_eq!(last.by, "web:alice");
    match &last.event {
        CustodyEvent::Automation {
            job: id,
            policy,
            policy_digest,
            route,
            submitted_by,
        } => {
            assert_eq!(id, &job.id.to_string());
            assert_eq!(
                (policy.as_str(), route.as_str(), submitted_by.as_str()),
                ("default", "inet_sim", "web:alice")
            );
            assert_eq!(policy_digest, &job.policy.digest);
        }
        other => panic!("{other:?}"),
    }
    assert!(library.custody_check(sha.as_str()).unwrap().ok());

    // A job whose client_id is not a name the log accepts is written as `app`.
    let mut odd = job.clone();
    odd.client_id = "who knows".into();
    assert_eq!(actor_of(&odd), "app");
    // No sample yet: nothing is written.
    let mut bare = job;
    bare.sample = None;
    assert!(record_automation(&data, &bare).is_err());
}

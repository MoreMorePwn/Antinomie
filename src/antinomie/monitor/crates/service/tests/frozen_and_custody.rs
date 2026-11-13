// SPDX-License-Identifier: GPL-3.0-only
//! The preset a job froze at submit survives a reload (card P3-3, presets of
//! ANT-T0490), and a job's custody entries name its caller (card P3-7).

// `ApiError` is the contract's error type (large by design, see the crate root).
#![allow(clippy::result_large_err)]

use antinomie_monitor_core::samples::{CustodyEvent, Library, NewSample};
use antinomie_service::{
    api::{
        failure::FailureCode,
        ids::Sha256Hex,
        ops::{Caller, Permission},
        run::{RunSample, RunState},
        spec::{Overrides, Route, RunRequest, SampleSource},
    },
    clock::ManualClock,
    config::{NoVms, SharedPresets, builtin::STANDARD},
    custody::{actor_of, record_automation},
    store::{IntakeError, SampleAdmission, Store, SubmitContext, SubmitLimits},
};
use std::{fs, path::PathBuf, sync::Arc};

struct Fixed(RunSample);

impl SampleAdmission for Fixed {
    fn admit(
        &self,
        _: &SampleSource,
        _: Option<&str>,
        _: &antinomie_service::config::LoadedPreset,
        _: &str,
    ) -> Result<RunSample, IntakeError> {
        Ok(self.0.clone())
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-frozen-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("presets")).unwrap();
    dir
}

fn spec(sha: &Sha256Hex) -> RunRequest {
    RunRequest {
        sample: SampleSource {
            sha256: Some(sha.clone()),
            ..Default::default()
        },
        name: None,
        preset: Some("mine".into()),
        priority: None,
        labels: Default::default(),
        idempotency_key: None,
        overrides: Overrides::default(),
    }
}

fn caller(id: &str) -> Caller {
    Caller::new(id, &[Permission::SamplesAdd, Permission::RunsSubmit])
}

#[test]
fn a_reload_changes_new_jobs_and_never_a_stored_one() {
    let dir = scratch("reload");
    let file = dir.join("presets/mine.toml");
    fs::write(&file, STANDARD).unwrap();
    let presets = SharedPresets::new(Default::default());
    presets.reload(&dir, &NoVms).unwrap();

    let sha = Sha256Hex::try_from("ab".repeat(32)).unwrap();
    let intake = Fixed(RunSample {
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
    let set = presets.snapshot();
    let ctx = SubmitContext {
        presets: &set,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let first = store
        .submit(&caller("local:1000"), spec(&sha), &ctx)
        .unwrap()
        .run;
    let first_digest = first.preset.digest.clone();
    assert_eq!(
        store
            .frozen_preset(&first.id)
            .unwrap()
            .preset
            .program
            .run_time_s,
        300
    );

    // The administrator shortens the preset and sends SIGHUP.
    fs::write(
        &file,
        STANDARD
            .replace("run_time_s = 300", "run_time_s = 60")
            .replace("on_duplicate = \"run\"", "on_duplicate = \"reject\""),
    )
    .unwrap();
    presets.reload(&dir, &NoVms).unwrap();
    let set = presets.snapshot();
    let ctx = SubmitContext {
        presets: &set,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let second = store
        .submit(&caller("local:1000"), spec(&sha), &ctx)
        .unwrap()
        .run;
    assert_ne!(second.preset.digest, first_digest);
    assert_eq!(
        store
            .frozen_preset(&second.id)
            .unwrap()
            .preset
            .program
            .run_time_s,
        60
    );
    // The first job keeps the preset it froze: digest and content.
    let again = store.get(&first.id).unwrap();
    assert_eq!(again.preset.digest, first_digest);
    let frozen = store.frozen_preset(&first.id).unwrap();
    assert_eq!(frozen.digest, first_digest);
    assert_eq!(frozen.preset.program.run_time_s, 300);
    assert_eq!(
        frozen.preset.duplicates.on_duplicate,
        antinomie_service::config::service::OnDuplicate::Run
    );

    // Even if the file is deleted, the job still has its options.
    fs::remove_file(&file).unwrap();
    assert!(
        presets.reload(&dir, &NoVms).is_ok(),
        "the built-in presets alone are valid"
    );
    assert_eq!(
        store
            .frozen_preset(&second.id)
            .unwrap()
            .preset
            .program
            .run_time_s,
        60
    );
    // A new submit naming the deleted preset is preset_denied.
    let set = presets.snapshot();
    let ctx = SubmitContext {
        presets: &set,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let error = store
        .submit(&caller("local:1000"), spec(&sha), &ctx)
        .unwrap_err();
    assert_eq!(
        error.code,
        antinomie_service::api::error::ErrorCode::PresetDenied
    );
    let _ = FailureCode::PresetDenied;
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
            "auto:preset-default",
        )
        .unwrap()
        .sha256;
    let sha = Sha256Hex::try_from(sha).unwrap();
    fs::write(dir.join("presets/mine.toml"), STANDARD).unwrap();
    let presets = SharedPresets::new(Default::default());
    presets.reload(&dir, &NoVms).unwrap();
    let set = presets.snapshot();
    let intake = Fixed(RunSample {
        sha256: sha.clone(),
        size: 19,
        kind: "sh".into(),
        architecture: None,
        name: "job.sh".into(),
    });
    let store = Store::open(&dir.join("service")).unwrap();
    let ctx = SubmitContext {
        presets: &set,
        intake: &intake,
        limits: SubmitLimits::default(),
        on_duplicate: None,
    };
    let mut s = spec(&sha);
    s.overrides = Overrides(
        serde_json::json!({"network": {"route": "inet_sim"}})
            .as_object()
            .cloned()
            .unwrap(),
    );
    let job = store.submit(&caller("web:alice"), s, &ctx).unwrap().run;
    assert_eq!(job.state, RunState::Queued, "{:?}", job.failure);
    assert_eq!(actor_of(&job), "web:alice");
    // A Custom run: the automation actor is the preset it was based on.
    assert_eq!(job.preset.name, "custom");
    assert_eq!(
        antinomie_service::custody::automation_actor(&job),
        "auto:preset-mine"
    );

    let route = store.frozen_preset(&job.id).unwrap().preset.network.route;
    assert_eq!(route, Route::InetSim);
    record_automation(&data, &job, &route).unwrap();
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
                ("custom", "inet_sim", "web:alice")
            );
            assert_eq!(policy_digest, &job.preset.digest);
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
    assert!(record_automation(&data, &bare, &route).is_err());
}

// SPDX-License-Identifier: GPL-3.0-only
//! The run API of 0.9.0 (ANT-T0492) through the daemon: `preset.get`,
//! `preset.list`, the run object's `preset`, `settings` and
//! `permissions_used`, `run.rerun` with another preset, and the names the
//! rename retired.

use super::tests::{call, submit_upload, svc};
use crate::{
    api::{
        error::ErrorCode,
        ops::{Caller, Permission},
    },
    server::{CallContext, Handler, Transport},
    store::tests::lane,
};
use serde_json::json;

fn as_caller(permissions: &[Permission]) -> CallContext {
    CallContext {
        caller: Caller::new("local:4242", permissions),
        cancel: Default::default(),
        transport: Transport::Socket,
    }
}

#[test]
fn preset_get_answers_every_option_and_an_unknown_name_is_not_found() {
    let svc = svc("preset-get", |preset| preset.dumps.core_dump_on_exit = true);
    let got = call(&svc, "preset.get", json!({"name": "standard"})).unwrap();
    assert_eq!(got["name"], "standard");
    assert_eq!(got["digest"], "digest");
    assert_eq!(got["built_in"], false);
    // The same tables and keys as the file.
    assert_eq!(got["dumps"]["core_dump_on_exit"], true);
    assert_eq!(got["program"]["run_time_s"], 300);
    assert_eq!(got["network"]["route"], "drop");
    assert!(got["offered_to"].is_array());
    let error = call(&svc, "preset.get", json!({"name": "gone"})).unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert_eq!(error.field.as_deref(), Some("name"));
    let error = call(&svc, "preset.get", json!({})).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

#[test]
fn the_preset_reads_need_runs_submit_and_say_whether_the_caller_can_use_it() {
    let svc = svc("preset-list", |preset| {
        preset.dumps.core_dump_on_exit = true
    });
    let listed = call(&svc, "preset.list", json!({})).unwrap();
    let standard = &listed["presets"][0];
    assert_eq!(standard["needs"], json!(["evidence.core_dump"]));
    assert_eq!(standard["usable"], true);
    let submitter = as_caller(&[Permission::RunsSubmit]);
    let listed = svc
        .service
        .call("preset.list", json!({}), &submitter)
        .unwrap();
    assert_eq!(
        listed["presets"][0]["missing"],
        json!(["evidence.core_dump"])
    );
    assert_eq!(listed["presets"][0]["usable"], false);
    // A reader without runs.submit sees no preset.
    let reader = as_caller(&[Permission::RunsSeeAll]);
    for op in ["preset.list", "preset.get"] {
        let error = svc
            .service
            .call(op, json!({"name": "standard"}), &reader)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{op}");
        assert_eq!(error.details["needs"], json!(["runs.submit"]));
    }
}

#[test]
fn a_run_shows_its_preset_its_settings_and_the_permissions_it_uses() {
    let svc = svc("run-object", |preset| preset.dumps.core_dump_on_exit = true);
    let run = submit_upload(&svc);
    assert!(run.id.as_str().starts_with("r_"));
    let got = call(&svc, "run.get", json!({"run_id": run.id})).unwrap();
    assert_eq!(
        got["preset"],
        json!({"name": "standard", "digest": "digest"})
    );
    assert_eq!(got["request"]["preset"], "standard");
    assert_eq!(got["settings"]["dumps"]["core_dump_on_exit"], true);
    assert_eq!(got["settings"]["program"]["run_time_s"], 300);
    assert_eq!(
        got["permissions_used"],
        json!([{"permission": "evidence.core_dump",
                "field": "dumps.core_dump_on_exit", "source": "caller"}])
    );
    let listed = call(&svc, "run.list", json!({})).unwrap();
    assert_eq!(listed["runs"][0]["id"], json!(run.id));
    assert_eq!(
        listed["runs"][0]["permissions_used"],
        got["permissions_used"]
    );
    // A Custom run: its settings are the resolved options.
    let custom = call(
        &svc,
        "run.submit",
        json!({"sample": {"sha256": run.sample.as_ref().unwrap().sha256},
               "overrides": {"program": {"run_time_s": 60}}}),
    )
    .unwrap();
    assert_eq!(custom["preset"]["name"], "custom");
    assert_eq!(custom["preset"]["based_on"]["name"], "standard");
    assert_eq!(custom["preset"]["changes"], json!(["program.run_time_s"]));
    assert_eq!(custom["settings"]["program"]["run_time_s"], 60);
}

#[test]
fn rerun_with_another_preset_takes_that_preset_as_it_is_now() {
    let svc = svc("rerun-preset", |_| {});
    let run = submit_upload(&svc);
    let store = &svc.service.store;
    let running = store
        .claim_next(&lane(), &mut |_| crate::store::Eligibility::Ready)
        .unwrap()
        .unwrap();
    store
        .finish(&running.id, crate::api::run::Outcome::Succeeded, None)
        .unwrap();
    // The only preset of this service is `standard`: another name is refused
    // the way a submit refuses it.
    let error = call(
        &svc,
        "run.rerun",
        json!({"run_id": run.id, "preset": "deep"}),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PresetDenied);
    let again = call(
        &svc,
        "run.rerun",
        json!({"run_id": run.id, "preset": "standard",
               "overrides": {"program": {"run_time_s": 45}}}),
    )
    .unwrap();
    assert_eq!(again["repeat_of"], json!(run.id));
    assert_eq!(again["request"]["preset"], "standard");
    assert_eq!(again["settings"]["program"]["run_time_s"], 45);
}

#[test]
fn the_names_before_the_rename_are_unknown_and_the_later_run_ops_reserved() {
    let svc = svc("old-names", |_| {});
    for old in [
        "job.submit",
        "job.get",
        "job.list",
        "job.retry",
        "policy.list",
        "recording.run.list",
    ] {
        let error = call(&svc, old, json!({})).unwrap_err();
        assert!(
            matches!(
                error.code,
                ErrorCode::InvalidArgument | ErrorCode::Unsupported
            ),
            "{old}: {error:?}"
        );
        assert_ne!(error.code, ErrorCode::NotFound, "{old}");
    }
    for later in [
        "run.end",
        "run.annotate",
        "run.share",
        "preset.put",
        "preset.retire",
    ] {
        assert_eq!(
            call(&svc, later, json!({})).unwrap_err().code,
            ErrorCode::Unsupported,
            "{later}"
        );
    }
    // The old member names are refused, never ignored.
    let error = call(&svc, "run.get", json!({"job_id": "r_x"})).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

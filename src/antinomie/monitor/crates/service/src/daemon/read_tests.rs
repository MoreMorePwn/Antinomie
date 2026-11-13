// SPDX-License-Identifier: GPL-3.0-only
//! The reads the daemon serves over the socket (card T0417): the recording
//! reads (class C and class T), the library, the custody chains, the VMs and
//! the bases. Operations are called as a socket client's request would reach
//! them, and some over a real Unix socket against the same data directory.

use super::tests::{Svc, call, me, socket_ctx, submit_upload, svc, svc_logged, upload};
use crate::{
    api::{
        error::ErrorCode,
        ops::{Caller, Scope},
    },
    query::{
        ReadContext,
        request::RecordingRead,
        service::QueryApi,
        testing::{Data, Run, VM, add_run, standard},
    },
    server::{CallContext, Handler, Server, Transport, client::Client, limits::Limits},
};
use antinomie_monitor_core::{
    BaseSummary, GuestArch, RunArtifactState, RunArtifacts, VmConfig,
    samples::{Library, NewSample},
};
use antinomie_triage::tests::{http_pcap, write_rwx_calls};
use serde_json::{Value, json};
use std::{
    mem::ManuallyDrop,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// The fixture helpers over the daemon test's own data directory. The
/// directory belongs to the `Svc`, so the helper value never removes it.
fn fixtures(svc: &Svc) -> ManuallyDrop<Data> {
    let root = svc.dir.join("data");
    std::fs::create_dir_all(root.join(VM).join("runs")).unwrap();
    ManuallyDrop::new(Data {
        root,
        vm: VM.into(),
    })
}

/// A finished run with RWX calls under cookie 55 and an HTTP capture its
/// artifact list names: the recording the Triage reads are tested on.
fn rwx_run(data: &Data) -> Run {
    let run = add_run(data, "boot-9", "run-9", 1_700_000_100_000, "Finalized");
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(run.dir.join("telemetry.raw"), raw).unwrap();
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(run.dir.join("run.json")).unwrap()).unwrap();
    record["root_task_cookie"] = json!(55);
    std::fs::write(
        run.dir.join("run.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let pcap = run.dir.join("network.pcap");
    std::fs::write(&pcap, http_pcap()).unwrap();
    let artifacts = RunArtifacts {
        run_id: run.id.clone(),
        vm_id: VM.into(),
        boot_id: run.boot.clone(),
        network_captures: vec![std::fs::canonicalize(&pcap).unwrap()],
        network_state: RunArtifactState::Complete,
        ..Default::default()
    };
    std::fs::write(
        run.dir.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    run
}

fn reader() -> CallContext {
    CallContext {
        caller: Caller::from_scopes("local:1", &[Scope::Read]),
        cancel: Default::default(),
        transport: Transport::Socket,
    }
}

/// The reply of `op`, asking again while a Triage scan is being built.
fn settled(
    svc: &Svc,
    op: &str,
    params: Value,
    ctx: &CallContext,
) -> Result<Value, crate::api::error::ApiError> {
    let started = Instant::now();
    loop {
        let value = svc.service.call(op, params.clone(), ctx)?;
        if value.get("building").is_none_or(Value::is_null) {
            return Ok(value);
        }
        assert!(started.elapsed() < Duration::from_secs(120), "no scan");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn every_recording_read_is_served_and_equals_the_direct_read_of_the_same_run() {
    let svc = svc("recordings", |_| {});
    let data = fixtures(&svc);
    let standard_run = standard(&data);
    let rwx = rwx_run(&data);
    let direct = &svc.service.query;
    let ctx = ReadContext::local_owner("local:1");
    let before = data.snapshot();

    // Class C: the list, one run, a trace page, the custody list.
    for (op, params) in [
        ("recording.run.list", json!({})),
        ("recording.run.get", json!({"run_key": standard_run.key()})),
        (
            "recording.trace.page",
            json!({"run_key": standard_run.key()}),
        ),
        (
            "recording.process.tree",
            json!({"run_key": standard_run.key()}),
        ),
        (
            "recording.artifact.list",
            json!({"run_key": standard_run.key()}),
        ),
        (
            "recording.analysis.list",
            json!({"run_key": standard_run.key()}),
        ),
    ] {
        let over_socket = call(&svc, op, params.clone()).unwrap();
        let in_process = serde_json::to_value(
            direct
                .read(RecordingRead::parse(op, params).unwrap(), &ctx)
                .unwrap(),
        )
        .unwrap();
        assert_eq!(over_socket, in_process, "{op}");
        assert!(!over_socket.to_string().is_empty());
    }

    // Class T: the Triage reads answer after the scan is built, with the
    // same objects as the in-process service gives.
    let key = rwx.key();
    for (op, params) in [
        ("recording.summary", json!({"run_key": key})),
        ("recording.findings.list", json!({"run_key": key})),
        ("recording.indicators.list", json!({"run_key": key})),
        (
            "recording.files.list",
            json!({"run_key": key, "tab": "opened"}),
        ),
        ("recording.network.summary", json!({"run_key": key})),
        (
            "recording.network.list",
            json!({"run_key": key, "tab": "endpoints"}),
        ),
        ("recording.timeline", json!({"run_key": key})),
    ] {
        let over_socket = settled(&svc, op, params.clone(), &socket_ctx()).unwrap();
        let started = Instant::now();
        let in_process = loop {
            let value = serde_json::to_value(
                direct
                    .read(RecordingRead::parse(op, params.clone()).unwrap(), &ctx)
                    .unwrap(),
            )
            .unwrap();
            if value.get("building").is_none_or(Value::is_null) {
                break value;
            }
            assert!(started.elapsed() < Duration::from_secs(120));
            std::thread::sleep(Duration::from_millis(100));
        };
        assert_eq!(over_socket, in_process, "{op}");
    }
    let summary = settled(
        &svc,
        "recording.summary",
        json!({"run_key": key}),
        &socket_ctx(),
    )
    .unwrap();
    assert!(summary["value"]["counts"]["processes"].as_u64().unwrap() >= 1);
    assert_eq!(
        data.snapshot().len(),
        before.len(),
        "a read leaves the data directory's files as they were (the Triage index aside)"
    );
}

#[test]
fn bytes_the_sample_produced_need_the_sensitive_scope_over_the_socket() {
    let svc = svc("sensitive", |_| {});
    let data = fixtures(&svc);
    let run = standard(&data);
    let key = run.key();
    let reader = reader();
    // A reader sees the rows and the artifact list ...
    assert!(
        svc.service
            .call("recording.artifact.list", json!({"run_key": key}), &reader)
            .is_ok()
    );
    // ... and none of the bytes the sample produced.
    for (op, params) in [
        (
            "recording.captured.read",
            json!({"run_key": key, "field": "x", "offset": "0", "len": 4}),
        ),
        (
            "recording.files.content",
            json!({"run_key": key, "version_id": "v1", "range": {"offset": 0, "len": 4}}),
        ),
        (
            "recording.network.packet",
            json!({"run_key": key, "capture_id": "c1", "n": 1}),
        ),
    ] {
        let error = svc.service.call(op, params, &reader).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::PermissionDenied,
            "{op}: {}",
            error.message
        );
    }
    // The artifact bytes of a capture or a core are refused the same way,
    // before any file is touched.
    let listed = call(&svc, "recording.artifact.list", json!({"run_key": key})).unwrap();
    let sensitive: Vec<&Value> = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["sensitive"] == json!(true))
        .collect();
    assert!(
        !sensitive.is_empty(),
        "the fixture has a capture and a core"
    );
    for artifact in sensitive {
        let params = json!({
            "run_key": key, "artifact_id": artifact["id"],
            "range": {"offset": 0, "len": 8},
        });
        let error = svc
            .service
            .call("recording.artifact.get", params.clone(), &reader)
            .unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::PermissionDenied,
            "{}",
            artifact["id"]
        );
        // The owner of the socket (all scopes) is served.
        assert!(call(&svc, "recording.artifact.get", params).is_ok());
    }
}

#[test]
fn a_reader_without_read_is_refused_every_recording_read() {
    let svc = svc("noread", |_| {});
    let nobody = CallContext {
        caller: Caller::from_scopes("local:2", &[Scope::Submit]),
        cancel: Default::default(),
        transport: Transport::Socket,
    };
    for op in [
        "recording.run.list",
        "recording.summary",
        "sample.list",
        "vm.list",
        "base.list",
    ] {
        let error = svc.service.call(op, json!({}), &nobody).unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{op}");
    }
}

#[test]
fn run_keys_that_name_nothing_or_something_outside_are_not_found() {
    let svc = svc("badkeys", |_| {});
    let data = fixtures(&svc);
    standard(&data);
    for key in [
        "vm-1:boot-1:no-such-run",
        "../../etc:boot-1:run-1",
        "no-vm:boot-1:run-1",
    ] {
        let error = call(&svc, "recording.run.get", json!({"run_key": key})).unwrap_err();
        assert!(
            matches!(error.code, ErrorCode::NotFound | ErrorCode::InvalidArgument),
            "{key}: {:?}",
            error.code
        );
    }
}

/// A library with two samples (a script and an ELF header) in `svc`'s data
/// directory; returns their SHA-256s.
fn library_with_samples(svc: &Svc) -> (String, String) {
    let data = svc.dir.join("data");
    let mut library = Library::open(&data).unwrap();
    let script = library
        .add_bytes(
            b"#!/bin/sh\necho benign\n",
            NewSample {
                name: "one.sh".into(),
                ..Default::default()
            },
        )
        .unwrap();
    let mut elf = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
    elf.resize(64, 7);
    let binary = library
        .add_bytes(
            &elf,
            NewSample {
                name: "two.bin".into(),
                ..Default::default()
            },
        )
        .unwrap();
    (script.sha256, binary.sha256)
}

#[test]
fn the_library_is_listed_paged_filtered_and_shown_over_the_socket() {
    let svc = svc("library", |_| {});
    // No library yet: empty, and nothing is created by the read.
    let none = call(&svc, "sample.list", json!({})).unwrap();
    assert_eq!(none["samples"], json!([]));
    assert!(!svc.dir.join("data").join("samples").exists());
    let error = call(&svc, "sample.get", json!({"sha256": "ab".repeat(32)})).unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);

    let (script, binary) = library_with_samples(&svc);
    let all = call(&svc, "sample.list", json!({})).unwrap();
    assert_eq!(all["samples"].as_array().unwrap().len(), 2);
    for key in [
        "sha256",
        "size",
        "type",
        "architecture",
        "name",
        "tags",
        "first_seen_ms",
        "run_count",
        "last_job",
        "custody_ok",
    ] {
        assert!(all["samples"][0].get(key).is_some(), "missing {key}");
    }
    // The reply is the contract's own `SampleList`.
    let typed: crate::api::ops::SampleList = serde_json::from_value(all.clone()).unwrap();
    assert_eq!(typed.samples.len(), 2);

    let page = call(&svc, "sample.list", json!({"limit": 1})).unwrap();
    assert_eq!(page["samples"].as_array().unwrap().len(), 1);
    let cursor = page["next_cursor"].as_str().unwrap().to_owned();
    let rest = call(&svc, "sample.list", json!({"limit": 1, "cursor": cursor})).unwrap();
    assert_eq!(rest["samples"].as_array().unwrap().len(), 1);
    assert!(rest["next_cursor"].is_null());
    assert_ne!(page["samples"][0]["sha256"], rest["samples"][0]["sha256"]);
    let bad = call(&svc, "sample.list", json!({"cursor": "junk"})).unwrap_err();
    assert_eq!(bad.code, ErrorCode::InvalidArgument);
    for limit in [0, 1001] {
        assert!(call(&svc, "sample.list", json!({"limit": limit})).is_err());
    }
    let by_q = call(&svc, "sample.list", json!({"q": "TWO"})).unwrap();
    assert_eq!(by_q["samples"][0]["sha256"], json!(binary));
    let checked = call(&svc, "sample.list", json!({"custody": true})).unwrap();
    assert!(
        checked["samples"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["custody_ok"] == json!(true))
    );

    let shown = call(
        &svc,
        "sample.get",
        json!({"sha256": script, "origins": true, "events": true, "runs": true}),
    )
    .unwrap();
    assert_eq!(shown["name"], "one.sh");
    assert_eq!(shown["custody_ok"], true);
    assert_eq!(shown["sha1"].as_str().unwrap().len(), 40);
    assert!(!shown["events"].as_array().unwrap().is_empty());
    assert_eq!(shown["runs"], json!([]));
    // An unknown member is named, a bad hash is refused.
    let error = call(&svc, "sample.get", json!({"sha256": script, "evil": 1})).unwrap_err();
    assert_eq!(error.field.as_deref(), Some("evil"));
    assert!(call(&svc, "sample.get", json!({"sha256": "../../etc/passwd"})).is_err());
}

#[test]
fn run_counts_cover_runs_no_window_indexed_and_a_read_writes_nothing() {
    let svc = svc("library-runs", |_| {});
    let data = fixtures(&svc);
    let (script, binary) = library_with_samples(&svc);
    let run = add_run(&data, "boot-1", "run-1", 1_700_000_000_000, "Finalized");
    // A command-line run: the sample it executed and a library it preloaded.
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(run.dir.join("run.json")).unwrap()).unwrap();
    record["request"]["sample"] = json!({"sha256": script, "name": "one.sh"});
    record["request"]["preloaded"] = json!([{
        "sha256": binary, "name": "two.bin", "path": "/tmp/two.bin",
        "via": "LD_PRELOAD", "note": ""
    }]);
    std::fs::write(
        run.dir.join("run.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();

    let listed = call(&svc, "sample.list", json!({})).unwrap();
    for sample in listed["samples"].as_array().unwrap() {
        assert_eq!(sample["run_count"], 1, "{sample}");
    }
    let shown = call(&svc, "sample.get", json!({"sha256": binary, "runs": true})).unwrap();
    assert_eq!(shown["run_count"], 1);
    assert_eq!(shown["runs"][0]["run_id"], "run-1");
    assert_eq!(shown["runs"][0]["exit"], "Exit 0");
    // The reads wrote nothing into the seen-run index.
    let library = Library::open(&svc.dir.join("data")).unwrap();
    assert!(library.runs_of(&script).unwrap().is_empty());
    // The write path indexes the same runs, and the count does not double.
    let mut library = library;
    let options = svc.service.options.clone();
    assert_eq!(library.index_all_runs(&options).unwrap(), 2);
    let listed = call(&svc, "sample.list", json!({})).unwrap();
    for sample in listed["samples"].as_array().unwrap() {
        assert_eq!(sample["run_count"], 1, "{sample}");
    }
}

#[test]
fn tags_are_set_by_a_manager_and_named_in_the_custody_log() {
    let svc = svc("tags", |_| {});
    let (script, _) = library_with_samples(&svc);
    let tagged = call(
        &svc,
        "sample.tag",
        json!({"sha256": script, "tags": [
            {"kind": "verdict", "value": "suspicious"}, {"kind": "custom", "value": "lab"}
        ]}),
    )
    .unwrap();
    assert_eq!(tagged["tags"].as_array().unwrap().len(), 2);
    let shown = call(
        &svc,
        "sample.get",
        json!({"sha256": script, "events": true}),
    )
    .unwrap();
    let by_me = shown["events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["by"] == json!(me().client_id));
    assert!(by_me, "the tag entry names the socket caller: {shown}");
    // Setting replaces: one tag left.
    let replaced = call(
        &svc,
        "sample.tag",
        json!({"sha256": script, "tags": [{"kind": "custom", "value": "lab"}]}),
    )
    .unwrap();
    assert_eq!(replaced["tags"].as_array().unwrap().len(), 1);
    for bad in [
        json!({"sha256": script, "tags": [{"kind": "verdict", "value": "great"}]}),
        json!({"sha256": script, "tags": [{"kind": "shade", "value": "red"}]}),
        json!({"sha256": "0".repeat(64), "tags": []}),
    ] {
        assert!(call(&svc, "sample.tag", bad).is_err());
    }
    // Only `manage` sets tags and verifies chains.
    let reader = reader();
    for op in ["sample.tag", "custody.verify"] {
        let error = svc
            .service
            .call(op, json!({"sha256": script, "tags": []}), &reader)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{op}");
    }
}

#[test]
fn custody_verify_checks_one_chain_or_the_whole_library() {
    let svc = svc("custody", |_| {});
    let (script, _) = library_with_samples(&svc);
    let one = call(&svc, "custody.verify", json!({"sha256": script})).unwrap();
    assert_eq!(one["ok"], true);
    assert_eq!(one["problems"], json!([]));
    assert_eq!(one["head"].as_str().unwrap().len(), 64);
    let all = call(&svc, "custody.verify", json!({})).unwrap();
    assert_eq!(all["ok"], true);
    assert_eq!(all["samples"].as_array().unwrap().len(), 2);
    assert_eq!(all["broken"], json!([]));
    let typed: crate::api::status::CustodyVerification = serde_json::from_value(all).unwrap();
    assert!(typed.ok && typed.problems.is_empty());
    let error = call(&svc, "custody.verify", json!({"sha256": "ab".repeat(32)})).unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn the_archive_is_served_by_range_to_the_sensitive_scope_and_logged() {
    let svc = svc("download", |_| {});
    let (script, _) = library_with_samples(&svc);
    // `read` alone is refused: the archive holds the sample.
    let reader = reader();
    let error = svc
        .service
        .call("sample.download", json!({"sha256": script}), &reader)
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    let archive = std::fs::read(
        Library::open(&svc.dir.join("data"))
            .unwrap()
            .archive_path(&script)
            .unwrap(),
    )
    .unwrap();
    let first = call(&svc, "sample.download", json!({"sha256": script})).unwrap();
    assert_eq!(first["password"], "infected");
    assert_eq!(first["size"], archive.len());
    let bytes =
        crate::server::b64::decode(first["range"]["data"].as_str().unwrap().as_bytes(), 1 << 21)
            .unwrap();
    assert_eq!(bytes, archive, "the archive, never the plaintext");
    assert!(!String::from_utf8_lossy(&bytes).contains("echo benign"));
    // A later range, one past the end, and above the limit.
    let tail = call(
        &svc,
        "sample.download",
        json!({"sha256": script, "range": {"offset": 4, "len": 8}}),
    )
    .unwrap();
    assert_eq!(tail["range"]["len"], 8);
    assert!(
        call(
            &svc,
            "sample.download",
            json!({"sha256": script, "range": {"offset": archive.len() + 1, "len": 1}})
        )
        .is_err()
    );
    let error = call(
        &svc,
        "sample.download",
        json!({"sha256": script, "range": {"offset": 0, "len": (1 << 20) + 1}}),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    // The first range wrote one `exported` custody entry; the second none.
    let shown = call(
        &svc,
        "sample.get",
        json!({"sha256": script, "events": true}),
    )
    .unwrap();
    let exported = shown["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "exported")
        .count();
    assert_eq!(exported, 1, "{shown}");
    assert_eq!(
        call(&svc, "custody.verify", json!({"sha256": script})).unwrap()["ok"],
        true
    );
    assert!(call(&svc, "sample.download", json!({"sha256": "ab".repeat(32)})).is_err());
}

#[test]
fn an_upload_is_added_to_the_library_and_a_client_path_never_is() {
    let svc = svc("sampleadd", |_| {});
    let id = upload(&svc, b"#!/bin/sh\necho added\n");
    let added = call(
        &svc,
        "sample.add",
        json!({"sample": {"upload_id": id}, "name": "added.sh",
               "tags": [{"kind": "custom", "value": "lab"}]}),
    )
    .unwrap();
    assert_eq!(added["name"], "added.sh");
    assert_eq!(added["new"], true);
    assert_eq!(added["tags"][0]["value"], "lab");
    let sha = added["sha256"].as_str().unwrap().to_owned();
    let shown = call(&svc, "sample.get", json!({"sha256": sha, "events": true})).unwrap();
    assert!(
        shown["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["by"] == json!(me().client_id)),
        "{shown}"
    );
    // The staged copy is gone; the upload cannot be added twice.
    assert!(call(&svc, "sample.add", json!({"sample": {"upload_id": id}})).is_err());
    // A path, a hash or nothing: refused with the field.
    let outside = svc.dir.join("outside.sh");
    std::fs::write(&outside, b"x").unwrap();
    let error = call(
        &svc,
        "sample.add",
        json!({"sample": {"path": outside.display().to_string()}}),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("sample.path"));
    for sample in [json!({"sha256": sha}), json!({})] {
        assert!(call(&svc, "sample.add", json!({"sample": sample})).is_err());
    }
    // Only a submitter adds.
    let error = svc
        .service
        .call(
            "sample.add",
            json!({"sample": {"upload_id": id}}),
            &reader(),
        )
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

#[test]
fn vms_and_bases_come_from_the_engines_latest_snapshot() {
    let svc = svc("vmbase", |_| {});
    // The engine has not listed its bases yet.
    {
        let mut view = svc.service.slots[0].view.lock().unwrap();
        view.lanes.bases_checking = true;
    }
    let error = call(&svc, "base.list", json!({})).unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert!(error.retryable);
    {
        let mut view = svc.service.slots[0].view.lock().unwrap();
        view.lanes.bases_checking = false;
        view.lanes.vms = vec![
            VmConfig {
                id: "vm-a".into(),
                name: "Analysis".into(),
                base_identity: Some("sha-base".into()),
                ..VmConfig::default()
            },
            VmConfig {
                id: "vm-b".into(),
                name: "Spare".into(),
                ..VmConfig::default()
            },
        ];
        view.lanes.bases = vec![BaseSummary {
            id: "sha-base".into(),
            label: "BusyBox".into(),
            directory: "/never/shown".into(),
            guest: None,
            min_ram_mib: 128,
            min_disk_gib: 1,
            fixed_display: false,
            arch: GuestArch::default(),
            size_bytes: 1,
            revision: Some(21),
            min_app_version: None,
            built_with: None,
            stealth_support: Vec::new(),
        }];
    }
    let vms = call(&svc, "vm.list", json!({})).unwrap();
    assert_eq!(vms["vms"].as_array().unwrap().len(), 2);
    assert_eq!(vms["vms"][0]["base_identity"], "sha-base");
    assert!(vms["vms"][1]["base_identity"].is_null());
    let bases = call(&svc, "base.list", json!({})).unwrap();
    assert_eq!(bases["bases"][0]["identity"], "sha-base");
    assert_eq!(bases["bases"][0]["name"], "BusyBox");
    assert!(
        !bases.to_string().contains("/never/shown"),
        "no host path in a base summary"
    );
    // A reader may list them; extra members are named.
    assert!(svc.service.call("vm.list", json!({}), &reader()).is_ok());
    let typed: crate::api::ops::VmList = serde_json::from_value(vms).unwrap();
    assert_eq!(typed.vms.len(), 2);
}

#[test]
fn the_reads_work_over_a_real_socket_with_the_same_answers() {
    let svc = svc("realsocket", |_| {});
    let data = fixtures(&svc);
    let run = standard(&data);
    let (script, _) = library_with_samples(&svc);
    let path = svc.dir.join("run").join("antinomie.sock");
    let handler: Arc<dyn Handler> = Arc::clone(&svc.service) as Arc<dyn Handler>;
    let server = Server::bind(&path, handler, Limits::default()).unwrap();
    let stop = server.stop_handle();
    let thread = std::thread::spawn(move || server.serve());
    let mut client = Client::connect(&path, Duration::from_secs(5)).unwrap();
    for (op, params) in [
        ("recording.run.list", json!({})),
        ("recording.run.get", json!({"run_key": run.key()})),
        (
            "recording.trace.page",
            json!({"run_key": run.key(), "limit": 5}),
        ),
        ("sample.list", json!({})),
        ("sample.get", json!({"sha256": script})),
        ("custody.verify", json!({})),
        ("vm.list", json!({})),
        ("base.list", json!({})),
    ] {
        let over_socket = client.call(op, params.clone()).unwrap();
        let in_process = call(&svc, op, params).unwrap();
        assert_eq!(over_socket, in_process, "{op}");
    }
    // The identity is the socket's, never a member of the request.
    let error = client
        .call("recording.run.list", json!({"client_id": "web:mallory"}))
        .unwrap_err();
    assert!(error.to_string().contains("client_id"), "{error}");
    drop(client);
    stop.stop();
    thread.join().unwrap();
}

/// A service whose log lines are collected.
fn logged(name: &str) -> (Svc, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let svc = svc_logged(
        name,
        |_| {},
        Arc::new(move |line: &str| sink.lock().unwrap().push(line.to_owned())),
    );
    (svc, lines)
}

#[test]
fn the_service_log_records_sensitive_reads_with_caller_run_and_size_never_the_bytes() {
    let (svc, lines) = logged("audit");
    let data = fixtures(&svc);
    let run = standard(&data);
    let key = run.key();
    let owner = me().client_id;
    let (vm, boot, id) = key.parts();
    let triple = format!("{vm}:{boot}:{id}");

    // Reads of the rows and refused reads write nothing.
    call(&svc, "recording.run.list", json!({})).unwrap();
    call(&svc, "recording.artifact.list", json!({"run_key": key})).unwrap();
    let denied = svc
        .service
        .call(
            "recording.captured.read",
            json!({"run_key": key, "field": "x", "offset": "0", "len": 4}),
            &reader(),
        )
        .unwrap_err();
    assert_eq!(denied.code, ErrorCode::PermissionDenied);
    assert!(lines.lock().unwrap().is_empty(), "{:?}", lines.lock());

    // The bytes of a capture or a core.
    let listed = call(&svc, "recording.artifact.list", json!({"run_key": key})).unwrap();
    let mut served = Vec::new();
    for artifact in listed["items"].as_array().unwrap() {
        if artifact["sensitive"] != json!(true) {
            continue;
        }
        let reply = call(
            &svc,
            "recording.artifact.get",
            json!({"run_key": key, "artifact_id": artifact["id"], "range": {"offset": 0, "len": 8}}),
        )
        .unwrap();
        served.push((
            reply["value"]["len"].as_u64().unwrap(),
            reply["value"]["data_b64"].clone(),
        ));
    }
    assert!(!served.is_empty());
    // A non-sensitive artifact is read without a line.
    let before = lines.lock().unwrap().len();
    assert_eq!(before, served.len());

    // The archive of a sample.
    let (script, _) = library_with_samples(&svc);
    let download = call(&svc, "sample.download", json!({"sha256": script})).unwrap();
    let sent = download["range"]["len"].as_u64().unwrap();

    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), served.len() + 1, "{lines:?}");
    for (line, (len, _)) in lines.iter().zip(&served) {
        assert_eq!(
            line,
            &format!(
                "sensitive read: caller={owner} op=recording.artifact.get run={triple} size={len}"
            )
        );
    }
    assert_eq!(
        lines.last().unwrap(),
        &format!("sensitive read: caller={owner} op=sample.download sample={script} size={sent}")
    );
    // Never the bytes, in either encoding.
    let archive = download["range"]["data"].as_str().unwrap();
    for line in &lines {
        assert!(!line.contains(archive));
        for (_, b64) in &served {
            assert!(!line.contains(b64.as_str().unwrap()));
        }
    }
}

#[test]
fn run_list_shows_the_job_that_made_a_run_the_same_through_the_daemon_and_in_process() {
    use crate::{
        api::{
            ids::LaneId,
            job::{JobRecording, RecordingPhase},
        },
        store::{Eligibility, JobPatch, job_index::StoreJobIndex},
    };
    let svc = svc("jobindex", |_| {});
    let data = fixtures(&svc);
    let made = add_run(&data, "boot-1", "run-made", 1_700_000_100_000, "Finalized");
    let other = add_run(&data, "boot-1", "run-other", 1_700_000_000_000, "Finalized");
    // A job that is running and records the run, as the lane's stages do.
    let job = submit_upload(&svc);
    let store = &svc.service.store;
    let claimed = store
        .claim_next(&LaneId::new(1), &mut |_| Eligibility::Ready)
        .unwrap()
        .unwrap();
    assert_eq!(claimed.id, job.id);
    store
        .patch(
            &job.id,
            JobPatch {
                recording: Some(JobRecording {
                    vm_id: VM.into(),
                    boot_id: made.boot.clone(),
                    run_id: made.id.clone(),
                    run_key: made.key().to_string(),
                    phase: RecordingPhase::Complete,
                    directory: None,
                }),
                ..JobPatch::default()
            },
        )
        .unwrap();

    // The daemon's reads.
    let list = call(&svc, "recording.run.list", json!({})).unwrap();
    let job_of = |list: &Value, run: &str| {
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["run_id"] == run)
            .map(|item| item["job_id"].clone())
            .unwrap()
    };
    assert_eq!(job_of(&list, "run-made"), json!(job.id.as_str()));
    assert_eq!(job_of(&list, "run-other"), Value::Null);
    let found = call(&svc, "recording.run.list", json!({"job_id": job.id})).unwrap();
    assert_eq!(found["items"].as_array().unwrap().len(), 1);
    assert_eq!(found["items"][0]["run_id"], "run-made");

    // The CLI's direct mode: its own service over the same data directory,
    // with the job store opened for reading (nothing created, nothing written).
    let options = svc.service.options.clone();
    let index = StoreJobIndex::open_read_only(&options.data_dir).expect("the store is there");
    let direct = crate::query::QueryService::new(options).with_jobs(Arc::new(index));
    let ctx = ReadContext::local_owner("local:1");
    for params in [json!({}), json!({"job_id": job.id})] {
        let in_process = serde_json::to_value(
            direct
                .read(
                    RecordingRead::parse("recording.run.list", params.clone()).unwrap(),
                    &ctx,
                )
                .unwrap(),
        )
        .unwrap();
        let over_socket = call(&svc, "recording.run.list", params).unwrap();
        assert_eq!(in_process, over_socket, "the same list both ways");
    }
    // Without a job store, direct mode lists runs without jobs and creates none.
    let bare = Data::new("jobindex-bare");
    assert!(StoreJobIndex::open_read_only(&bare.root).is_none());
    assert!(!bare.root.join("service").exists());
    let _ = other;
}

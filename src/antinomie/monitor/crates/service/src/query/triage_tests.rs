// SPDX-License-Identifier: GPL-3.0-only
//! The Triage-based reads (card Q-4) over a fixture recording: RWX mapping
//! calls under root cookie 55 and an HTTP capture, the recording the Triage
//! crate's own tests and the CLI's use. Counts are compared with the report
//! builder the window's export and `antinomie-cli report` use.

use super::{
    ReadContext,
    phase::FixedLayers,
    request::{RecordingRead, RecordingReply},
    service::{QueryApi, QueryService},
    testing::*,
};
use crate::api::{
    error::{ApiError, ErrorCode, ErrorReason},
    job::RecordingPhase,
};
use antinomie_monitor_core::{
    RunArtifactState, RunArtifacts,
    disk_layers::{DiskLayer, LayerPhase},
    recording::{find_run_read_only, read_only_locations},
    report::{Choices, Part},
};
use antinomie_triage::{
    SavedRun, report_export,
    tests::{http_pcap, write_rwx_calls},
};
use serde_json::{Value, json};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

fn call(
    service: &QueryService,
    op: &str,
    params: Value,
    ctx: &ReadContext,
) -> Result<RecordingReply, ApiError> {
    service.read(RecordingRead::parse(op, params)?, ctx)
}

/// The reply as JSON, asking again while the scan is being built.
fn settle(service: &QueryService, op: &str, params: Value) -> Value {
    let started = Instant::now();
    loop {
        let reply = call(service, op, params.clone(), &ctx()).unwrap();
        let value = serde_json::to_value(&reply).unwrap();
        if value.get("building").is_none() {
            return value;
        }
        assert!(
            started.elapsed() < Duration::from_secs(120),
            "the scan never finished"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn have_tshark() -> bool {
    report_export::fixtures::have_tshark()
}

/// A finished run with RWX calls under cookie 55 and, with `capture`, an HTTP
/// capture its artifact list names.
fn rwx_run(data: &Data, capture: bool) -> Run {
    let run = add_run(data, "boot-1", "run-1", 1_700_000_000_000, "Finalized");
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
    if capture {
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
    }
    run
}

/// The summary counts of the report builder over the same recording: the
/// window's export path (`SavedRun`, the scan, `build_report`).
fn report_counts(data: &Data, run: &Run) -> Value {
    let options = data.options();
    let location = read_only_locations(&options)
        .unwrap()
        .into_iter()
        .find(|l| l.vm_id == VM)
        .unwrap();
    let summary = find_run_read_only(&location, &run.boot, &run.id)
        .unwrap()
        .unwrap();
    let saved = SavedRun::open(summary, &options).unwrap();
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scan = saved.scan(&cancel).unwrap();
    let choices = Choices {
        parts: vec![Part::Summary],
        ..Choices::default()
    };
    let job = report_export::Job::for_saved(&saved, choices, 0);
    let (_, built) = report_export::build_report(&job, &scan).unwrap();
    let counts = built.report.summary.unwrap().counts;
    json!({
        "processes": counts.processes, "findings": counts.findings,
        "indicators": counts.indicators, "indicators_matched": counts.indicators_matched,
        "techniques": counts.techniques, "files_changed": counts.files_changed,
        "files_opened": counts.files_opened, "endpoints": counts.endpoints,
        "domains": counts.domains,
    })
}

#[test]
fn the_summary_is_building_then_the_report_builders_and_nothing_is_written() {
    let data = Data::new("t-summary");
    let run = rwx_run(&data, true);
    let service = data.service();
    let key = run.key();
    let before = data.snapshot();
    // The first ask starts the scan and says so.
    let first = serde_json::to_value(
        call(
            &service,
            "recording.summary",
            json!({"run_key": key}),
            &ctx(),
        )
        .unwrap(),
    )
    .unwrap();
    assert!(
        first["building"]["retry_after_ms"].as_u64().unwrap() > 0,
        "{first}"
    );
    assert!(first.get("value").is_none());
    let summary = settle(&service, "recording.summary", json!({"run_key": key}));
    assert_eq!(summary["phase"], "complete");
    let value = &summary["value"];
    assert!(value["assessment"].is_string(), "{summary}");
    assert!(value["counts"]["processes"].as_u64().unwrap() >= 1);
    assert!(value["counts"]["findings"].as_u64().unwrap() >= 1);
    let counts = value["counts"].clone();
    // Every other Triage read, then the directory is as it was.
    for (op, extra) in [
        ("recording.findings.list", json!({})),
        ("recording.indicators.list", json!({})),
        ("recording.files.list", json!({"tab": "changed"})),
        ("recording.files.list", json!({"tab": "opened"})),
        ("recording.network.summary", json!({})),
        ("recording.network.list", json!({"tab": "endpoints"})),
        ("recording.timeline", json!({})),
    ] {
        let mut params = json!({"run_key": key});
        params
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        settle(&service, op, params);
    }
    assert_eq!(
        before,
        data.snapshot(),
        "a Triage read writes nothing into the data directory (no journal, no digest)"
    );
    assert!(!run.dir.join("triage-digest.json").exists());
    assert!(!run.dir.join("triage-findings-v2.jsonl").exists());
    assert!(service.scans_in_memory() <= 2);
    // Parity with the report builder the export and `antinomie-cli report` use.
    // Last, and with the process-wide kept index dropped (other tests running
    // alongside push it out, it keeps two entries outside triage's own tests):
    // that builder is the window's scan, which writes its journals into the run.
    antinomie_triage::scan_cache::forget();
    assert_eq!(counts, report_counts(&data, &run));
}

#[test]
fn findings_filter_sort_and_page_over_the_whole_row_set() {
    let data = Data::new("t-findings");
    let run = rwx_run(&data, false);
    let service = data.service();
    let key = run.key();
    let all = settle(&service, "recording.findings.list", json!({"run_key": key}));
    let items = all["items"].as_array().unwrap().clone();
    assert!(!items.is_empty(), "{all}");
    assert_eq!(all["total"].as_u64().unwrap(), items.len() as u64);
    let rule = items[0]["rule"].as_str().unwrap().to_owned();
    let row = &items[0];
    assert!(row["finding_id"].as_str().unwrap().starts_with("fnd_"));
    assert!(row["ref"]["call"].is_string(), "ids are decimal strings");
    // The filter language is the window's: a field of the table.
    let only = settle(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "q": format!("finding.rule == \"{rule}\"")}),
    );
    assert!(
        only["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["rule"] == rule)
    );
    let none = settle(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "q": "finding.rule == \"no.such.rule\""}),
    );
    assert!(none["items"].as_array().unwrap().is_empty());
    // The request filters.
    let by_tier = settle(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "tier": items[0]["tier"]}),
    );
    assert!(
        by_tier["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["tier"] == items[0]["tier"])
    );
    // A bad filter is invalid_argument naming q, with the column.
    let error = call(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "q": "finding.rule == "}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(
        (error.code, error.field.as_deref()),
        (ErrorCode::InvalidArgument, Some("q"))
    );
    assert!(error.details.get("position").is_some(), "{error:?}");
    let error = call(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "q": "bogus.field == 1"}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("q"));
    // Sort: any field of the table, over the whole set; an unknown field is
    // refused.
    let asc = settle(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "sort": {"field": "finding.count", "dir": "asc"}}),
    );
    let desc = settle(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "sort": {"field": "finding.count", "dir": "desc"}}),
    );
    let counts = |page: &Value| -> Vec<u64> {
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["count"].as_u64().unwrap())
            .collect()
    };
    let (up, down) = (counts(&asc), counts(&desc));
    assert!(up.windows(2).all(|w| w[0] <= w[1]), "{up:?}");
    assert!(down.windows(2).all(|w| w[0] >= w[1]), "{down:?}");
    assert_eq!(up.len(), items.len());
    let error = call(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "sort": {"field": "nope", "dir": "asc"}}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("sort"));
    // Paging: one row at a time covers the set once, in the same order; the
    // cursor belongs to its filter.
    let mut seen = Vec::new();
    let mut cursor = Value::Null;
    loop {
        let mut params = json!({"run_key": key, "limit": 1});
        if !cursor.is_null() {
            params["cursor"] = cursor.clone();
        }
        let page = settle(&service, "recording.findings.list", params);
        seen.extend(
            page["items"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["finding_id"].clone()),
        );
        cursor = page["next_cursor"].clone();
        if cursor.is_null() {
            break;
        }
        let error = call(
            &service,
            "recording.findings.list",
            json!({"run_key": key, "limit": 1, "cursor": cursor, "q": "finding.count > 0"}),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
    }
    let listed: Vec<Value> = items.iter().map(|f| f["finding_id"].clone()).collect();
    assert_eq!(seen, listed);
    let error = call(
        &service,
        "recording.findings.list",
        json!({"run_key": key, "limit": 501}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("limit"));
}

#[test]
fn a_finding_is_read_by_its_id() {
    let data = Data::new("t-finding");
    let run = rwx_run(&data, false);
    let service = data.service();
    let key = run.key();
    let list = settle(&service, "recording.findings.list", json!({"run_key": key}));
    let first = &list["items"][0];
    let got = settle(
        &service,
        "recording.findings.get",
        json!({"run_key": key, "finding_id": first["finding_id"]}),
    );
    assert_eq!(got["value"]["rule"], first["rule"]);
    assert_eq!(got["value"]["ref"], first["ref"]);
    assert!(
        got["value"]["rule_text"]
            .as_str()
            .is_some_and(|t| !t.is_empty())
    );
    assert_eq!(got["value"]["evidence_refs"][0], first["ref"]);
    let error = call(
        &service,
        "recording.findings.get",
        json!({"run_key": key, "finding_id": "fnd_000000000000000000"}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn the_network_reads_come_from_the_capture() {
    if !have_tshark() {
        eprintln!("skipped: tshark is needed");
        return;
    }
    let data = Data::new("t-network");
    let run = rwx_run(&data, true);
    let service = data.service();
    let key = run.key();
    let summary = settle(
        &service,
        "recording.network.summary",
        json!({"run_key": key}),
    );
    let value = &summary["value"];
    assert!(value["endpoints"].as_u64().unwrap() >= 1, "{summary}");
    assert!(value["frames"].as_u64().unwrap() >= 1);
    let counts = report_counts(&data, &run);
    assert_eq!(value["endpoints"], counts["endpoints"]);
    assert_eq!(value["domains"], counts["domains"]);
    let endpoints = settle(
        &service,
        "recording.network.list",
        json!({"run_key": key, "tab": "endpoints", "q": "network.protocol == \"tcp\""}),
    );
    let rows = endpoints["items"].as_array().unwrap();
    assert!(!rows.is_empty(), "{endpoints}");
    // The capture is a capture_id of recording.network.captures, never a path.
    let captures = settle(
        &service,
        "recording.network.captures",
        json!({"run_key": key}),
    );
    let capture_id = captures["items"][0]["capture_id"].clone();
    assert_eq!(rows[0]["capture"], capture_id);
    assert!(
        !endpoints
            .to_string()
            .contains(&data.root.display().to_string())
    );
    for tab in ["domains", "urls", "tls", "dns", "http"] {
        let page = settle(
            &service,
            "recording.network.list",
            json!({"run_key": key, "tab": tab, "sort": null}),
        );
        assert!(page["items"].is_array(), "{tab}: {page}");
    }
    let http = settle(
        &service,
        "recording.network.list",
        json!({"run_key": key, "tab": "http"}),
    );
    assert_eq!(http["items"][0]["host"], "example.com");
    let urls = settle(
        &service,
        "recording.network.list",
        json!({"run_key": key, "tab": "urls"}),
    );
    assert_eq!(urls["items"][0]["url"], "http://example.com/");
    // The indicators of the same capture.
    let indicators = settle(
        &service,
        "recording.indicators.list",
        json!({"run_key": key}),
    );
    assert_eq!(indicators["total"], counts["indicators"]);
    let defanged = settle(
        &service,
        "recording.indicators.list",
        json!({"run_key": key, "defang": true, "kind": "domain"}),
    );
    if let Some(row) = defanged["items"].get(0) {
        assert_eq!(row["raw_indicators"], false);
        assert_eq!(row["value"], row["defanged"]);
    }
    let raw = settle(
        &service,
        "recording.indicators.list",
        json!({"run_key": key}),
    );
    assert!(
        raw["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["raw_indicators"] == true)
    );
}

#[test]
fn the_timeline_merges_processes_findings_and_files_in_time_order() {
    let data = Data::new("t-timeline");
    let run = rwx_run(&data, false);
    let service = data.service();
    let key = run.key();
    let page = settle(&service, "recording.timeline", json!({"run_key": key}));
    let items = page["items"].as_array().unwrap();
    assert!(!items.is_empty(), "{page}");
    let times: Vec<u64> = items.iter().map(|e| e["ts_ms"].as_u64().unwrap()).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "{times:?}");
    let kinds: Vec<&str> = items.iter().map(|e| e["kind"].as_str().unwrap()).collect();
    assert!(
        kinds.contains(&"process_start") && kinds.contains(&"finding"),
        "{kinds:?}"
    );
    assert!(
        items
            .iter()
            .all(|e| e["title"].as_str().unwrap().chars().count() <= 200)
    );
    let findings = settle(
        &service,
        "recording.timeline",
        json!({"run_key": key, "kinds": ["finding"]}),
    );
    assert!(
        findings["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["kind"] == "finding")
    );
    let late = settle(
        &service,
        "recording.timeline",
        json!({"run_key": key, "from_ms": times.last().unwrap() + 1}),
    );
    assert!(late["items"].as_array().unwrap().is_empty());
}

#[test]
fn a_recording_that_is_still_written_refuses_the_triage_reads() {
    let data = Data::new("t-live");
    let run = rwx_run(&data, false);
    let live = DiskLayer {
        vm_id: VM.into(),
        boot_id: run.boot.clone(),
        phase: LayerPhase::Live,
        started_ms: 1,
        phase_ms: 2,
    };
    let service = data
        .service()
        .with_layers(Arc::new(FixedLayers(vec![live])));
    for (op, extra) in [
        ("recording.summary", json!({})),
        ("recording.findings.list", json!({})),
        ("recording.files.list", json!({"tab": "opened"})),
        ("recording.network.list", json!({"tab": "domains"})),
        ("recording.timeline", json!({})),
    ] {
        let mut params = json!({"run_key": run.key()});
        params
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let error = call(&service, op, params, &ctx()).unwrap_err();
        assert_eq!(error.code, ErrorCode::PreconditionFailed, "{op}");
        assert_eq!(error.reason(), Some(ErrorReason::RecordingOpen), "{op}");
    }
    assert_eq!(service.scans_in_memory(), 0, "no scan was started");
    // The run list still says live.
    let list = settle(&service, "recording.run.list", json!({}));
    assert_eq!(
        list["phase"],
        serde_json::to_value(RecordingPhase::Live).unwrap()
    );
}

#[test]
fn a_run_that_never_started_cannot_be_triaged() {
    let data = Data::new("t-noroot");
    let run = add_run(&data, "boot-1", "run-1", 1_700_000_000_000, "FailedToStart");
    let mut record: Value =
        serde_json::from_slice(&std::fs::read(run.dir.join("run.json")).unwrap()).unwrap();
    record["root_task_cookie"] = json!(0);
    std::fs::write(
        run.dir.join("run.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let error = call(
        &data.service(),
        "recording.summary",
        json!({"run_key": run.key()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PreconditionFailed);
}

#[test]
fn the_sensitive_file_content_needs_its_scope_and_other_runs_are_not_found() {
    let data = Data::new("t-scope");
    let run = rwx_run(&data, false);
    let service = data.service();
    let key = run.key();
    let error = call(
        &service,
        "recording.files.content",
        json!({"run_key": key, "version_id": "ver_0"}),
        &plain_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    let error = call(
        &service,
        "recording.files.content",
        json!({"run_key": key, "version_id": "ver_0", "range": {"offset": 0, "len": 2_000_000}}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    let error = call(
        &service,
        "recording.summary",
        json!({"run_key": super::key::RunKey::new(VM, "boot-9", "nope").unwrap()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn the_file_tables_list_what_the_run_opened_and_a_changed_file_has_versions() {
    let data = Data::new("t-files");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    // The synthetic trace opens no file the scan can name: the tables are
    // empty and still answer in their shape, for the filter and the sort too.
    let opened = settle(
        &service,
        "recording.files.list",
        json!({"run_key": key, "tab": "opened", "q": "file.path contains \"passwd\"",
               "sort": {"field": "file.path", "dir": "desc"}}),
    );
    assert_eq!(opened["total"], 0, "{opened}");
    let error = call(
        &service,
        "recording.files.list",
        json!({"run_key": key, "tab": "opened", "q": "path contains \"x\""}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(
        error.field.as_deref(),
        Some("q"),
        "the Triage field is file.path"
    );
    // No file was changed, so the changed table is empty and no id names one.
    let changed = settle(
        &service,
        "recording.files.list",
        json!({"run_key": key, "tab": "changed"}),
    );
    assert!(changed["items"].as_array().unwrap().is_empty());
    for tab in [
        "created",
        "read",
        "written",
        "deleted",
        "renamed",
        "executed",
        "attributes",
        "probed",
        "other",
    ] {
        let page = settle(
            &service,
            "recording.files.list",
            json!({"run_key": key, "tab": tab}),
        );
        assert!(page["items"].is_array(), "{tab}");
    }
    let error = call(
        &service,
        "recording.files.versions",
        json!({"run_key": key, "file_id": "fil_00000000000000000000"}),
        &ctx(),
    );
    // A scan that is still being made answers `building`; a finished one, not_found.
    let error = match error {
        Ok(_) => settle_error(
            &service,
            "recording.files.versions",
            json!({"run_key": key, "file_id": "fil_00000000000000000000"}),
        ),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::NotFound);
    // The catalogue publishes the Triage crate's own field names.
    let catalogue = super::ops::catalogue(Default::default());
    let files = catalogue
        .ops
        .iter()
        .find(|o| o.op == "recording.files.list")
        .unwrap();
    let names: Vec<_> = files.tables.as_ref().unwrap()["opened"]
        .fields
        .iter()
        .map(|f| f.name.as_str())
        .collect();
    assert!(names.contains(&"file.path") && names.contains(&"file.operation"));
    assert!(files.sortable.iter().any(|s| s.field == "file.path"));
}

/// The error an operation settles on, asking again while it is building.
fn settle_error(service: &QueryService, op: &str, params: Value) -> ApiError {
    let started = Instant::now();
    loop {
        match call(service, op, params.clone(), &ctx()) {
            Err(error) => return error,
            Ok(_) => {
                assert!(started.elapsed() < Duration::from_secs(120));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

#[test]
fn an_operation_row_maps_the_triage_values() {
    use antinomie_triage::query::RowValue as R;
    let data = Data::new("t-oprow");
    let run = standard(&data);
    let service = data.service();
    let opened = service.open_run(&run.key()).unwrap();
    let values: Vec<(&'static str, R)> = vec![
        ("file.path", R::Text("/tmp/x".into())),
        ("file.operation", R::Text("openat".into())),
        ("file.via", R::Text("io_uring".into())),
        ("file.success", R::Bool(true)),
        ("file.access", R::Text("O_RDWR".into())),
        ("file.fd", R::Number(5)),
        ("file.written_size", R::Number(12)),
        ("file.content", R::Text("é".repeat(300))),
        ("process.pid", R::Number(100)),
        ("process.cookie", R::Number(18_446_744_073_709_551_615)),
        ("stream.id", R::Number(9)),
        ("event.id", R::Number(3)),
        ("event.time_ns", R::Number(1_500_000_000)),
    ];
    let row = super::files::operation_row(&opened, &values);
    let value = serde_json::to_value(&row).unwrap();
    assert_eq!(value["path"], "/tmp/x");
    assert_eq!(value["via"], "io_uring");
    assert_eq!(value["success"], true);
    assert_eq!(value["fd"], 5);
    assert_eq!(value["written_size"], 12);
    assert_eq!(value["read_size"], Value::Null);
    assert_eq!(
        value["process"]["cookie"], "18446744073709551615",
        "u64 ids are strings"
    );
    assert_eq!(
        value["ref"],
        json!({"stream": "9", "task": "18446744073709551615", "call": "3"})
    );
    assert_eq!(value["content"].as_str().unwrap().chars().count(), 256);
    assert_eq!(value["guest_ns"], 1_500_000_000u64);
    assert_eq!(
        value["ts_ms"], 1_700_000_000_500u64,
        "mapped through the run's clock anchor"
    );
    assert!(value["file_id"].as_str().unwrap().starts_with("fop_"));
}

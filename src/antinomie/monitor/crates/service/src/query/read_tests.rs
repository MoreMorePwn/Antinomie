// SPDX-License-Identifier: GPL-3.0-only
//! The core-only reads over a small synthetic recording (cards Q-2 and Q-3):
//! golden pages for every operation, every limit, host paths absent, and the
//! rule that a read writes nothing.

use super::{
    ReadContext,
    context::ReadContext as Ctx,
    phase::FixedLayers,
    request::{RecordingRead, RecordingReply},
    service::{JobIndex, QueryApi, QueryService},
    testing::*,
};
use crate::api::{
    error::{ApiError, ErrorCode, ErrorReason},
    ids::JobId,
    job::RecordingPhase,
};
use antinomie_monitor_core::disk_layers::{DiskLayer, LayerPhase};
use serde_json::{Value, json};
use std::{path::PathBuf, sync::Arc};

fn call(
    service: &QueryService,
    op: &str,
    params: Value,
    ctx: &ReadContext,
) -> Result<RecordingReply, ApiError> {
    service.read(RecordingRead::parse(op, params)?, ctx)
}

macro_rules! reply {
    ($result:expr, $variant:ident) => {
        match $result.unwrap() {
            RecordingReply::$variant(value) => value,
            other => panic!("unexpected reply {other:?}"),
        }
    };
}

fn json_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn run_list_is_newest_first_and_carries_the_run_info() {
    let data = Data::new("runs");
    let older = add_run(&data, "boot-1", "run-old", 1_700_000_000_000, "Finalized");
    let newer = add_run(&data, "boot-2", "run-new", 1_700_000_100_000, "Stopped");
    let service = data.service();
    let page = reply!(
        call(&service, "recording.run.list", json!({}), &ctx()),
        Runs
    );
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.items[0].run_key, newer.key());
    assert_eq!(page.items[1].run_key, older.key());
    assert_eq!(page.total, Some(2));
    assert_eq!(page.total_exact, Some(true));
    assert_eq!(page.phase, RecordingPhase::Complete);
    let info = json_of(&page.items[1]);
    assert_eq!(info["vm_id"], VM);
    assert_eq!(info["boot_id"], "boot-1");
    assert_eq!(info["run_id"], "run-old");
    assert_eq!(info["state"], "finalized");
    assert_eq!(info["phase"], "complete");
    assert_eq!(info["started_ms"], 1_700_000_000_000u64);
    assert_eq!(
        info["ended_ms"], 1_700_000_005_000u64,
        "from the run's manifest"
    );
    assert_eq!(info["sample_sha256"], sample_sha());
    assert_eq!(info["program"], "/tmp/sample.sh");
    assert_eq!(info["route"], "drop");
    assert_eq!(info["exit"], json!({"kind": "exited", "code": 0}));
    assert_eq!(info["job_id"], Value::Null);
    assert_eq!(json_of(&page.items[0])["state"], "stopped");
}

#[test]
fn run_list_filters_and_pages_with_a_cursor() {
    let data = Data::new("runfilter");
    for (index, state) in ["Finalized", "Stopped", "Finalized"].iter().enumerate() {
        add_run(
            &data,
            "boot-1",
            &format!("run-{index}"),
            1_700_000_000_000 + index as u64 * 1000,
            state,
        );
    }
    let service = data.service();
    let first = reply!(
        call(&service, "recording.run.list", json!({"limit": 2}), &ctx()),
        Runs
    );
    assert_eq!(first.items.len(), 2);
    let cursor = first.next_cursor.clone().expect("a second page");
    let second = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"limit": 2, "cursor": cursor}),
            &ctx()
        ),
        Runs
    );
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    assert_eq!(json_of(&second.items[0])["run_id"], "run-0");
    // Filters.
    let stopped = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"state": "stopped"}),
            &ctx()
        ),
        Runs
    );
    assert_eq!(stopped.items.len(), 1);
    let since = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"since_ms": 1_700_000_001_000u64}),
            &ctx()
        ),
        Runs
    );
    assert_eq!(since.items.len(), 2);
    let sha = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"sample_sha256": sample_sha()}),
            &ctx()
        ),
        Runs
    );
    assert_eq!(sha.items.len(), 3);
    let other = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"sample_sha256": "0".repeat(64)}),
            &ctx()
        ),
        Runs
    );
    assert!(other.items.is_empty());
    let none = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"vm_id": "other-vm"}),
            &ctx()
        ),
        Runs
    );
    assert!(none.items.is_empty());
    // A filter that needs the job store finds no job without one.
    let job = JobId::from_parts(1, [1; 10]);
    let by_job = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"job_id": job}),
            &ctx()
        ),
        Runs
    );
    assert!(by_job.items.is_empty());
    // A cursor for another filter is stale; a limit out of range is refused.
    let cursor = first.next_cursor.clone().unwrap();
    let error = call(
        &service,
        "recording.run.list",
        json!({"state": "stopped", "cursor": cursor}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
    let error = call(
        &service,
        "recording.run.list",
        json!({"limit": 501}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    // A new run in front shifts every offset: the old cursor is stale.
    add_run(&data, "boot-1", "run-new", 1_700_000_900_000, "Finalized");
    let error = call(
        &service,
        "recording.run.list",
        json!({"limit": 2, "cursor": cursor}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
}

struct Jobs {
    run: String,
    job: JobId,
    analysis: PathBuf,
}

impl JobIndex for Jobs {
    fn job_of_run(&self, _: &str, _: &str, run: &str) -> Option<JobId> {
        (run == self.run).then(|| self.job.clone())
    }
    fn analysis_directory(&self, job: &JobId) -> Option<PathBuf> {
        (*job == self.job).then(|| self.analysis.clone())
    }
}

#[test]
fn run_list_knows_the_job_that_made_a_run_when_the_store_does() {
    let data = Data::new("jobs");
    add_run(&data, "boot-1", "run-1", 1_700_000_000_000, "Finalized");
    add_run(&data, "boot-1", "run-2", 1_700_000_001_000, "Finalized");
    let job = JobId::from_parts(5, [3; 10]);
    let jobs = Jobs {
        run: "run-1".into(),
        job: job.clone(),
        analysis: data.root.join("unused"),
    };
    let service = data.service().with_jobs(Arc::new(jobs));
    let page = reply!(
        call(
            &service,
            "recording.run.list",
            json!({"job_id": job}),
            &ctx()
        ),
        Runs
    );
    assert_eq!(page.items.len(), 1);
    assert_eq!(json_of(&page.items[0])["job_id"], json!(job));
    let all = reply!(
        call(&service, "recording.run.list", json!({}), &ctx()),
        Runs
    );
    assert_eq!(
        all.items
            .iter()
            .filter(|i| json_of(i)["job_id"] != Value::Null)
            .count(),
        1
    );
}

#[test]
fn run_get_is_the_detail_and_sends_no_host_path() {
    let data = Data::new("rundetail");
    let run = standard(&data);
    let service = data.service();
    let single = reply!(
        call(
            &service,
            "recording.run.get",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Run
    );
    let detail = json_of(&single.value.unwrap());
    assert_eq!(detail["run_id"], "run-1");
    assert_eq!(detail["execution"]["total_task_count"], 3);
    assert_eq!(
        detail["execution"]["root_exit"],
        json!({"kind": "exited", "code": 0})
    );
    assert_eq!(
        detail["owner_state"], "gone",
        "no writer for a complete recording"
    );
    assert_eq!(detail["layer"], "none");
    assert_eq!(
        detail["artifacts"]["network"],
        json!({"state": "complete", "present": true})
    );
    assert_eq!(
        detail["artifacts"]["core"],
        json!({"state": "partial", "present": true})
    );
    assert_eq!(
        detail["artifacts"]["memory"],
        json!({"state": "disabled", "present": false})
    );
    assert!(
        detail.get("directory").is_none(),
        "the folder is local only"
    );
    assert_eq!(detail["notes"][0], "kept under <data>/x");
    let text = detail.to_string();
    assert!(!text.contains(&data.root.display().to_string()), "{text}");
    assert_eq!(single.phase, RecordingPhase::Complete);
    assert_eq!(single.untrusted, Some(true));
    // Unknown and foreign runs are not found.
    let ghost = super::key::RunKey::new(VM, "boot-1", "nope").unwrap();
    let error = call(
        &service,
        "recording.run.get",
        json!({"run_key": ghost}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    let foreign = super::key::RunKey::new("other-vm", "boot-1", "run-1").unwrap();
    assert_eq!(
        call(
            &service,
            "recording.run.get",
            json!({"run_key": foreign}),
            &ctx()
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    // The boot is part of the address: a run id alone is not unique.
    let wrong_boot = super::key::RunKey::new(VM, "boot-9", "run-1").unwrap();
    assert_eq!(
        call(
            &service,
            "recording.run.get",
            json!({"run_key": wrong_boot}),
            &ctx()
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn the_trace_pages_in_event_order_with_totals_and_cursors() {
    let data = Data::new("trace");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let all = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key}),
            &ctx()
        ),
        Trace
    );
    let names: Vec<_> = all.items.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(names, ["execve", "openat", "read", "write", "openat"]);
    assert_eq!(all.total, Some(5));
    assert_eq!(all.total_exact, Some(true));
    assert!(all.next_cursor.is_none());
    let row = json_of(&all.items[1]);
    assert_eq!(row["ref"]["call"], "2");
    assert_eq!(row["pid"], 100);
    assert_eq!(row["nr"], 257);
    assert_eq!(row["ret"], "3");
    assert_eq!(row["group"], "file");
    assert_eq!(row["args"][0], "0x3");
    assert_eq!(row["args"].as_array().unwrap().len(), 6);
    assert_eq!(row["args_preview"][0]["key"], "path");
    assert_eq!(row["args_preview"][0]["text"], "/etc/passwd");
    // The host time is the run's start plus the guest time since its anchor.
    assert_eq!(row["ts_ms"], 1_700_000_000_000u64 + 2);
    assert_eq!(all.untrusted, Some(true));
    // Two at a time, following the cursor to the end.
    let mut seen = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut params = json!({"run_key": key, "limit": 2});
        if let Some(cursor) = &cursor {
            params["cursor"] = json!(cursor);
        }
        let page = reply!(
            call(&service, "recording.trace.page", params, &ctx()),
            Trace
        );
        assert!(page.items.len() <= 2);
        seen.extend(page.items.iter().map(|row| row.call.call.0));
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(seen, [1, 2, 3, 4, 5]);
}

#[test]
fn the_trace_filters_by_process_and_hidden_groups() {
    let data = Data::new("tracefilter");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let child = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "pid": 101}),
            &ctx()
        ),
        Trace
    );
    assert_eq!(child.items.len(), 2);
    assert_eq!(child.total, Some(2));
    let hidden = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "hide_groups": ["file"]}),
            &ctx()
        ),
        Trace
    );
    let names: Vec<_> = hidden.items.iter().map(|row| row.name.as_str()).collect();
    assert_eq!(names, ["execve"], "openat, read and write are file calls");
    assert_eq!(hidden.total, Some(1));
    // `q` is the Triage crate's syscall filter language (card Q-4).
    let named = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "q": "syscall.name == \"openat\""}),
            &ctx()
        ),
        Trace
    );
    let names: Vec<_> = named.items.iter().map(|row| row.name.as_str()).collect();
    assert!(!names.is_empty() && names.iter().all(|name| *name == "openat"));
    assert_eq!(named.total, Some(names.len() as u64));
    assert!(names.len() < 5, "the other calls are filtered out");
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": key, "q": "syscall.nope == 1"}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert_eq!(error.field.as_deref(), Some("q"));
    // The same walk with another filter is another walk.
    let first = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "q": "pid >= 0", "limit": 1}),
            &ctx()
        ),
        Trace
    );
    let cursor = first.next_cursor.expect("more rows");
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": key, "q": "pid >= 1", "limit": 1, "cursor": cursor}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": key, "limit": 0}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("limit"));
    // A cursor from another filter is stale.
    let first = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "limit": 1}),
            &ctx()
        ),
        Trace
    );
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": key, "limit": 1, "pid": 100, "cursor": first.next_cursor.unwrap()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
}

#[test]
fn a_call_is_read_in_full_by_its_ref_and_its_captured_bytes_by_field() {
    let data = Data::new("call");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let single = reply!(
        call(
            &service,
            "recording.trace.get",
            json!({"run_key": key, "ref": {"stream": "9", "task": "10", "call": "2"}}),
            &ctx()
        ),
        Invocation
    );
    let invocation = json_of(&single.value.unwrap());
    assert_eq!(invocation["entry"]["syscall_name"], "openat");
    assert_eq!(invocation["exit"]["result"], "3");
    assert_eq!(invocation["entry"]["fields"][0]["key"], "path");
    assert_eq!(invocation["entry"]["fields"][0]["captured_len"], 11);
    assert_eq!(invocation["async_omitted"], 0);
    assert!(!invocation.to_string().contains("raw_path"));
    assert!(
        !invocation
            .to_string()
            .contains(&data.root.display().to_string())
    );
    let field = invocation["entry"]["fields"][0]["field"]
        .as_str()
        .unwrap()
        .to_owned();
    let bytes = reply!(
        call(
            &service,
            "recording.captured.read",
            json!({"run_key": key, "field": field, "offset": "0", "len": 11}),
            &ctx()
        ),
        Bytes
    );
    let reply = bytes.value.unwrap();
    assert_eq!(reply.len, 11);
    assert_eq!(super::convert::base64(b"/etc/passwd"), reply.data_b64);
    let tail = reply!(
        call(
            &service,
            "recording.captured.read",
            json!({"run_key": key, "field": field, "offset": "5", "len": 6}),
            &ctx()
        ),
        Bytes
    );
    assert_eq!(
        super::convert::base64(b"passwd"),
        tail.value.unwrap().data_b64
    );
    // Sensitive: the normal scope is refused; the range is bounded.
    let error = call(
        &service,
        "recording.captured.read",
        json!({"run_key": key, "field": field, "offset": "0", "len": 4}),
        &plain_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Forbidden);
    let error = call(
        &service,
        "recording.captured.read",
        json!({"run_key": key, "field": field, "offset": "0", "len": 65_537}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    let error = call(
        &service,
        "recording.captured.read",
        json!({"run_key": key, "field": field, "offset": "8", "len": 16}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(
        error.field.as_deref(),
        Some("offset"),
        "bytes the recording did not capture"
    );
    let error = call(
        &service,
        "recording.captured.read",
        json!({"run_key": key, "field": "junk", "offset": "0", "len": 1}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("field"));
    // An unknown call.
    let error = call(
        &service,
        "recording.trace.get",
        json!({"run_key": key, "ref": {"stream": "9", "task": "10", "call": "77"}}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn the_process_tree_is_flat_rows_by_pid_with_the_engines_issues_on_the_first_page() {
    let data = Data::new("tree");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let page = reply!(
        call(
            &service,
            "recording.process.tree",
            json!({"run_key": key}),
            &ctx()
        ),
        Processes
    );
    let pids: Vec<_> = page.items.iter().map(|n| n.pid).collect();
    assert_eq!(pids, [100, 101]);
    assert_eq!(page.items[0].calls, 3);
    assert_eq!(page.items[1].calls, 2);
    assert_eq!(page.total, Some(2));
    assert!(page.notes.is_some(), "the first page carries the notes");
    let value = json_of(&page);
    assert_eq!(value["notes"]["truncated"], false);
    // A second read of the same generation comes from the cache.
    assert_eq!(service.trees.lock().unwrap().len(), 1);
    let again = reply!(
        call(
            &service,
            "recording.process.tree",
            json!({"run_key": key, "limit": 1}),
            &ctx()
        ),
        Processes
    );
    assert_eq!(again.items.len(), 1);
    let rest = reply!(
        call(
            &service,
            "recording.process.tree",
            json!({"run_key": key, "limit": 1, "cursor": again.next_cursor.unwrap()}),
            &ctx()
        ),
        Processes
    );
    assert_eq!(rest.items[0].pid, 101);
    assert!(rest.notes.is_none(), "only the first page");
    // A subtree.
    let sub = reply!(
        call(
            &service,
            "recording.process.tree",
            json!({"run_key": key, "root_pid": 101}),
            &ctx()
        ),
        Processes
    );
    assert_eq!(sub.items.iter().map(|n| n.pid).collect::<Vec<_>>(), [101]);
}

#[test]
fn captures_and_cores_are_metadata_with_opaque_ids() {
    let data = Data::new("evidence");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let captures = reply!(
        call(
            &service,
            "recording.network.captures",
            json!({"run_key": key}),
            &ctx()
        ),
        Captures
    );
    assert_eq!(captures.items.len(), 1);
    let capture = json_of(&captures.items[0]);
    assert!(capture["capture_id"].as_str().unwrap().starts_with("ra_"));
    assert_eq!(capture["segment"], 0);
    assert_eq!(capture["state"], "complete");
    assert_eq!(capture["size"], pcap().len());
    assert!(capture.get("path").is_none(), "the host path is local only");
    assert!(
        !json_of(&captures)
            .to_string()
            .contains(&data.root.display().to_string())
    );
    let cores = reply!(
        call(
            &service,
            "recording.cores.list",
            json!({"run_key": key}),
            &ctx()
        ),
        Cores
    );
    assert_eq!(cores.items.len(), 1);
    let core = json_of(&cores.items[0]);
    assert_eq!(core["core_id"], "exit");
    assert_eq!(core["state"], "partial");
    assert_eq!(core["requested_size"], 1 << 20);
    assert_eq!(core["saved_size"], 256);
    assert!(
        core["warnings"].as_array().is_some_and(|w| !w.is_empty()),
        "the file is not an ELF core: {core}"
    );
    // A run that kept none: not recorded.
    let bare = add_run(&data, "boot-1", "run-bare", 1_700_000_200_000, "Finalized");
    for op in ["recording.network.captures", "recording.cores.list"] {
        let error = call(&service, op, json!({"run_key": bare.key()}), &ctx()).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound, "{op}");
        assert_eq!(error.reason(), Some(ErrorReason::NotRecorded), "{op}");
    }
}

#[test]
fn the_terminal_transcript_pages_by_journal_offset() {
    let data = Data::new("terminal");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let page = reply!(
        call(
            &service,
            "recording.terminal.replay",
            json!({"run_key": key}),
            &ctx()
        ),
        Terminal
    );
    let kinds: Vec<_> = page
        .items
        .iter()
        .map(|r| json_of(r)["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(kinds, ["output", "resize", "output", "eof"]);
    assert_eq!(
        json_of(&page.items[0])["data_b64"],
        super::convert::base64(b"$ ./sample.sh\r\n")
    );
    assert_eq!(
        json_of(&page.items[1]),
        json!({"kind": "resize", "rows": 24, "cols": 80})
    );
    assert!(page.next_cursor.is_none());
    let first = reply!(
        call(
            &service,
            "recording.terminal.replay",
            json!({"run_key": key, "limit": 2}),
            &ctx()
        ),
        Terminal
    );
    assert_eq!(first.items.len(), 2);
    let second = reply!(
        call(
            &service,
            "recording.terminal.replay",
            json!({"run_key": key, "limit": 2, "cursor": first.next_cursor.unwrap()}),
            &ctx()
        ),
        Terminal
    );
    assert_eq!(json_of(&second.items[1])["kind"], "eof");
    let error = call(
        &service,
        "recording.terminal.replay",
        json!({"run_key": key, "limit": 257}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    let bare = add_run(&data, "boot-1", "run-bare", 1_700_000_200_000, "Finalized");
    let error = call(
        &service,
        "recording.terminal.replay",
        json!({"run_key": bare.key()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::NotRecorded));
}

#[test]
fn artifacts_list_what_the_run_kept_and_serve_ranges() {
    let data = Data::new("artifacts");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let page = reply!(
        call(
            &service,
            "recording.artifact.list",
            json!({"run_key": key}),
            &ctx()
        ),
        Artifacts
    );
    let listed: Vec<_> = page
        .items
        .iter()
        .map(|a| {
            (
                json_of(a)["kind"].as_str().unwrap().to_owned(),
                a.name.clone(),
                a.sensitive,
            )
        })
        .collect();
    for expected in [
        ("terminal_journal", "terminal.journal", false),
        ("run_record", "run.json", false),
        ("artifacts_record", "artifacts.json", false),
        ("analysis_report", "analysis/report.json", false),
        ("network_capture", "boots/boot-1/network/seg-1.pcap", true),
        ("core_dump", "cores/exit.core", true),
    ] {
        assert!(
            listed
                .iter()
                .any(|(k, n, s)| (k.as_str(), n.as_str(), *s) == expected),
            "{expected:?} in {listed:?}"
        );
    }
    for hidden in ["telemetry.raw", "manifest.json", "events.json"] {
        assert!(
            !listed.iter().any(|(_, n, _)| n == hidden),
            "{hidden} is internal"
        );
    }
    assert!(
        !json_of(&page)
            .to_string()
            .contains(&data.root.display().to_string())
    );
    // The ids are stable across reads.
    let again = reply!(
        call(
            &service,
            "recording.artifact.list",
            json!({"run_key": key}),
            &ctx()
        ),
        Artifacts
    );
    assert_eq!(json_of(&page.items), json_of(&again.items));
    let id_of = |name: &str| {
        page.items
            .iter()
            .find(|a| a.name == name)
            .unwrap()
            .id
            .clone()
    };
    // A normal file, whole and by range.
    let journal = reply!(
        call(
            &service,
            "recording.artifact.get",
            json!({"run_key": key, "artifact_id": id_of("terminal.journal"), "range": {"offset": 0, "len": 5}}),
            &plain_ctx()
        ),
        Bytes
    );
    let value = journal.value.unwrap();
    assert_eq!((value.offset.0, value.len), (0, 5));
    let on_disk = std::fs::read(run.dir.join("terminal.journal")).unwrap();
    assert_eq!(value.data_b64, super::convert::base64(&on_disk[..5]));
    let whole = reply!(
        call(
            &service,
            "recording.artifact.get",
            json!({"run_key": key, "artifact_id": id_of("run.json")}),
            &plain_ctx()
        ),
        Bytes
    );
    assert_eq!(
        whole.value.unwrap().len,
        std::fs::metadata(run.dir.join("run.json")).unwrap().len()
    );
    // A capture is sensitive.
    let capture = id_of("boots/boot-1/network/seg-1.pcap");
    let error = call(
        &service,
        "recording.artifact.get",
        json!({"run_key": key, "artifact_id": capture}),
        &plain_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Forbidden);
    let pcap_bytes = reply!(
        call(
            &service,
            "recording.artifact.get",
            json!({"run_key": key, "artifact_id": capture}),
            &ctx()
        ),
        Bytes
    );
    assert_eq!(pcap_bytes.value.unwrap().len as usize, pcap().len());
    // Bounds: more than 1 MiB, past the end, an id of another run.
    let error = call(&service, "recording.artifact.get", json!({"run_key": key, "artifact_id": capture, "range": {"offset": 0, "len": (1u64 << 20) + 1}}), &ctx()).unwrap_err();
    assert_eq!(error.code, ErrorCode::PayloadTooLarge);
    let error = call(
        &service,
        "recording.artifact.get",
        json!({"run_key": key, "artifact_id": capture, "range": {"offset": 99_999, "len": 4}}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    let other = JobId::from_parts(1, [0; 10])
        .to_string()
        .replacen("j_", "ra_", 1);
    let error = call(
        &service,
        "recording.artifact.get",
        json!({"run_key": key, "artifact_id": other}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn an_artifact_that_is_a_symlink_is_not_listed_or_served() {
    let data = Data::new("symlink");
    let run = standard(&data);
    let secret = data.root.join("outside.txt");
    std::fs::write(&secret, "secret").unwrap();
    std::fs::remove_file(run.dir.join("terminal.journal")).unwrap();
    std::os::unix::fs::symlink(&secret, run.dir.join("terminal.journal")).unwrap();
    let service = data.service();
    let page = reply!(
        call(
            &service,
            "recording.artifact.list",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Artifacts
    );
    assert!(!page.items.iter().any(|a| a.name == "terminal.journal"));
    // The terminal read refuses it as well.
    assert!(
        call(
            &service,
            "recording.terminal.replay",
            json!({"run_key": run.key()}),
            &ctx()
        )
        .is_err()
    );
}

#[test]
fn the_analysis_is_read_by_section_with_paging_filter_and_sort() {
    let data = Data::new("analysis");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let list = reply!(
        call(
            &service,
            "recording.analysis.list",
            json!({"run_key": key}),
            &ctx()
        ),
        AnalysisSections
    );
    assert_eq!(list.items.len(), 2);
    let strings = json_of(&list.items[1]);
    assert_eq!(strings["kind"], "strings");
    assert_eq!(strings["state"], "complete");
    assert_eq!(strings["rows"], 3);
    assert_eq!(strings["truncated"], false);
    let metadata = reply!(
        call(
            &service,
            "recording.analysis.section",
            json!({"run_key": key, "kind": "metadata"}),
            &ctx()
        ),
        AnalysisRows
    );
    assert_eq!(metadata.items.len(), 2, "rows kept in the report itself");
    assert_eq!(metadata.items[0].entry.label, "type");
    let page = reply!(
        call(
            &service,
            "recording.analysis.section",
            json!({"run_key": key, "kind": "strings", "limit": 2}),
            &ctx()
        ),
        AnalysisRows
    );
    assert_eq!(
        page.items
            .iter()
            .map(|r| r.entry.value.as_str())
            .collect::<Vec<_>>(),
        ["alpha", "bravo"]
    );
    assert_eq!(page.total, Some(3));
    let record = json_of(&page.items[0].entry);
    assert_eq!(record["offset"], "16");
    assert_eq!(record["record"]["data"]["type"], "string");
    assert_eq!(record["record"]["location"]["kind"], "file_offset");
    assert_eq!(record["record"]["location"]["value"], "0x10");
    let rest = reply!(
        call(
            &service,
            "recording.analysis.section",
            json!({"run_key": key, "kind": "strings", "limit": 2, "cursor": page.next_cursor.unwrap()}),
            &ctx()
        ),
        AnalysisRows
    );
    assert_eq!(rest.items.len(), 1);
    assert_eq!(rest.items[0].index, 2);
    let found = reply!(
        call(
            &service,
            "recording.analysis.section",
            json!({"run_key": key, "kind": "strings", "q": "RAV"}),
            &ctx()
        ),
        AnalysisRows
    );
    assert_eq!(found.items.len(), 1);
    assert_eq!(found.items[0].entry.value, "bravo");
    let sorted = reply!(
        call(
            &service,
            "recording.analysis.section",
            json!({"run_key": key, "kind": "strings", "sort": {"field": "text", "dir": "desc"}}),
            &ctx()
        ),
        AnalysisRows
    );
    assert_eq!(
        sorted
            .items
            .iter()
            .map(|r| r.entry.value.as_str())
            .collect::<Vec<_>>(),
        ["charlie", "bravo", "alpha"]
    );
    assert!(matches!(&sorted.notes, Some(super::page::PageExtra::Analysis(notes)) if notes.sorted));
    let error = call(
        &service,
        "recording.analysis.section",
        json!({"run_key": key, "kind": "strings", "sort": {"field": "nope", "dir": "asc"}}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.field.as_deref(), Some("sort"));
    // A section the report does not have; no subject; two subjects.
    let error = call(
        &service,
        "recording.analysis.section",
        json!({"run_key": key, "kind": "floss"}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    let error = call(&service, "recording.analysis.list", json!({}), &ctx()).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    let job = JobId::from_parts(1, [1; 10]);
    let error = call(
        &service,
        "recording.analysis.list",
        json!({"run_key": key, "job_id": job}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    // No Ghidra listing in this report.
    let error = call(
        &service,
        "recording.analysis.ghidra",
        json!({"run_key": key}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::NotRecorded));
    // A run without an analysis.
    let bare = add_run(&data, "boot-1", "run-bare", 1_700_000_200_000, "Finalized");
    let error = call(
        &service,
        "recording.analysis.list",
        json!({"run_key": bare.key()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::NotRecorded));
}

#[test]
fn the_host_side_analysis_of_a_job_is_read_through_the_job_store() {
    let data = Data::new("jobanalysis");
    standard(&data);
    let analysis = data.root.join("analyses").join("analysis-job");
    write_analysis(&analysis, "analysis-job");
    let job = JobId::from_parts(9, [9; 10]);
    let jobs = Jobs {
        run: "none".into(),
        job: job.clone(),
        analysis,
    };
    let service = data.service().with_jobs(Arc::new(jobs));
    let list = reply!(
        call(
            &service,
            "recording.analysis.list",
            json!({"job_id": job}),
            &ctx()
        ),
        AnalysisSections
    );
    assert_eq!(list.items.len(), 2);
    assert_eq!(list.phase, RecordingPhase::Complete);
    let rows = reply!(
        call(
            &service,
            "recording.analysis.section",
            json!({"job_id": job, "kind": "strings"}),
            &ctx()
        ),
        AnalysisRows
    );
    assert_eq!(rows.items.len(), 3);
    let other = JobId::from_parts(9, [8; 10]);
    let error = call(
        &service,
        "recording.analysis.list",
        json!({"job_id": other}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    // A service without a store finds no job analysis.
    let bare = data.service();
    assert_eq!(
        call(
            &bare,
            "recording.analysis.list",
            json!({"job_id": job}),
            &ctx()
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
}

#[test]
fn custody_lists_the_chain_of_the_runs_sample_and_hides_host_paths_from_remote_callers() {
    use antinomie_monitor_core::samples::{Library, NewOrigin, NewSample, OriginKind};
    let data = Data::new("custody");
    let run = standard(&data);
    {
        let mut library = Library::open(&data.root).unwrap();
        library
            .add_bytes(
                SAMPLE_BYTES,
                NewSample {
                    name: "sample.sh".into(),
                    description: String::new(),
                    tags: Vec::new(),
                    origin: NewOrigin {
                        kind: OriginKind::Added,
                        source: "test".into(),
                        path: "/home/analyst/Downloads/sample.sh".into(),
                        name: "sample.sh".into(),
                        ..NewOrigin::default()
                    },
                    info: None,
                },
            )
            .unwrap();
    }
    {
        // The same bytes by another route: a second entry in the chain.
        let mut library = Library::open(&data.root).unwrap();
        let added = library
            .add_bytes(
                SAMPLE_BYTES,
                NewSample {
                    name: "again.sh".into(),
                    description: String::new(),
                    tags: Vec::new(),
                    origin: NewOrigin {
                        kind: OriginKind::Added,
                        source: "mirror".into(),
                        path: "/srv/mirror/again.sh".into(),
                        name: "again.sh".into(),
                        ..NewOrigin::default()
                    },
                    info: None,
                },
            )
            .unwrap();
        assert!(!added.new);
    }
    let service = data.service();
    let by_run = reply!(
        call(
            &service,
            "recording.custody.list",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Custody
    );
    let by_sha = reply!(
        call(
            &service,
            "recording.custody.list",
            json!({"sha256": sample_sha()}),
            &ctx()
        ),
        Custody
    );
    assert_eq!(json_of(&by_run.items), json_of(&by_sha.items));
    assert!(by_run.items.len() >= 2);
    assert_eq!(by_run.items[0].seq, 1);
    assert_eq!(by_run.items[0].kind, "added");
    assert_eq!(by_run.items[1].prev, by_run.items[0].hash);
    assert_eq!(by_run.total_exact, Some(true));
    let origin = by_run.items[0].data["origin"].as_str().unwrap().to_owned();
    assert!(origin.starts_with("Added from this computer"), "{origin}");
    let remote = reply!(
        call(
            &service,
            "recording.custody.list",
            json!({"sha256": sample_sha()}),
            &plain_ctx()
        ),
        Custody
    );
    assert_eq!(
        json_of(&remote.items),
        json_of(&by_run.items),
        "no host path in these events"
    );
    // Paging by the chain.
    let first = reply!(
        call(
            &service,
            "recording.custody.list",
            json!({"sha256": sample_sha(), "limit": 1}),
            &ctx()
        ),
        Custody
    );
    assert_eq!(first.items.len(), 1);
    let next = reply!(
        call(
            &service,
            "recording.custody.list",
            json!({"sha256": sample_sha(), "limit": 1, "cursor": first.next_cursor.unwrap()}),
            &ctx()
        ),
        Custody
    );
    assert_eq!(next.items[0].seq, 2);
    // Exactly one subject; an unknown sample; a run without one.
    for params in [
        json!({}),
        json!({"run_key": run.key(), "sha256": sample_sha()}),
    ] {
        assert_eq!(
            call(&service, "recording.custody.list", params, &ctx())
                .unwrap_err()
                .code,
            ErrorCode::InvalidArgument
        );
    }
    let error = call(
        &service,
        "recording.custody.list",
        json!({"sha256": "1".repeat(64)}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn custody_does_not_create_a_library() {
    let data = Data::new("nolibrary");
    standard(&data);
    let service = data.service();
    let error = call(
        &service,
        "recording.custody.list",
        json!({"sha256": sample_sha()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
    assert!(!data.root.join("samples").exists());
}

#[test]
fn every_read_leaves_the_data_directory_exactly_as_it_was() {
    let data = Data::new("nowrites");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let before = data.snapshot();
    let artifacts = reply!(
        call(
            &service,
            "recording.artifact.list",
            json!({"run_key": key}),
            &ctx()
        ),
        Artifacts
    );
    let ids: Vec<_> = artifacts.items.iter().map(|a| a.id.to_string()).collect();
    let capture = artifacts
        .items
        .iter()
        .find(|a| a.name.ends_with(".pcap"))
        .unwrap()
        .id
        .to_string();
    let operations = [
        ("recording.run.list", json!({})),
        ("recording.run.get", json!({"run_key": key})),
        ("recording.trace.page", json!({"run_key": key})),
        (
            "recording.trace.get",
            json!({"run_key": key, "ref": {"stream": "9", "task": "10", "call": "1"}}),
        ),
        ("recording.process.tree", json!({"run_key": key})),
        ("recording.network.captures", json!({"run_key": key})),
        ("recording.cores.list", json!({"run_key": key})),
        ("recording.analysis.list", json!({"run_key": key})),
        (
            "recording.analysis.section",
            json!({"run_key": key, "kind": "strings"}),
        ),
        ("recording.terminal.replay", json!({"run_key": key})),
        ("recording.artifact.list", json!({"run_key": key})),
        (
            "recording.artifact.get",
            json!({"run_key": key, "artifact_id": capture}),
        ),
    ];
    for (op, params) in operations {
        call(&service, op, params, &ctx()).unwrap_or_else(|e| panic!("{op}: {e:?}"));
    }
    for id in ids.iter().take(3) {
        let _ = call(
            &service,
            "recording.artifact.get",
            json!({"run_key": key, "artifact_id": id}),
            &ctx(),
        );
    }
    assert_eq!(
        data.snapshot(),
        before,
        "a read writes nothing under the data directory"
    );
}

#[test]
fn a_stale_analysis_is_not_sealed_or_changed_by_listing_runs() {
    // The engine's own listing repairs a report that no queue owns and seals
    // retained specimens; a read must leave the run folder alone.
    let data = Data::new("stale");
    let run = add_run(&data, "boot-1", "run-1", 1_700_000_000_000, "Finalized");
    write_analysis(&run.dir.join("analysis"), "analysis-1");
    let mut value: Value =
        serde_json::from_slice(&std::fs::read(run.dir.join("analysis/report.json")).unwrap())
            .unwrap();
    value["state"] = json!("running");
    value["sections"][0]["state"] = json!("running");
    std::fs::write(
        run.dir.join("analysis/report.json"),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let before = data.snapshot();
    let service = data.service();
    call(&service, "recording.run.list", json!({}), &ctx()).unwrap();
    call(
        &service,
        "recording.run.get",
        json!({"run_key": run.key()}),
        &ctx(),
    )
    .unwrap();
    assert_eq!(data.snapshot(), before);
}

#[test]
fn a_live_recording_reports_its_phase_grows_and_a_cursor_goes_stale_as_it_does() {
    let data = Data::new("live");
    let run = standard(&data);
    let layers = Arc::new(FixedLayers(vec![DiskLayer {
        vm_id: VM.into(),
        boot_id: "boot-1".into(),
        phase: LayerPhase::Live,
        started_ms: 1,
        phase_ms: 2,
    }]));
    let service = data.service().with_layers(layers);
    let key = run.key();
    let page = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "limit": 2}),
            &ctx()
        ),
        Trace
    );
    assert_eq!(page.phase, RecordingPhase::Live);
    assert_eq!(
        page.total_exact,
        Some(false),
        "a live recording still grows"
    );
    assert!(page.partial.is_none());
    let cursor = page.next_cursor.unwrap();
    // The writer appends: the generation moves and the old cursor is stale.
    let mut more = std::fs::OpenOptions::new()
        .append(true)
        .open(run.dir.join("telemetry.raw"))
        .unwrap();
    std::io::Write::write_all(&mut more, b"").unwrap();
    drop(more);
    write_trace(&run, &{
        let mut calls = standard_calls();
        calls.push(Call {
            id: 6,
            pid: 100,
            nr: 1,
            result: 1,
            path: None,
        });
        calls
    });
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": key, "limit": 2, "cursor": cursor}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::CursorStale));
    // Restarting from the first page sees the new call under a new generation.
    let fresh = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key}),
            &ctx()
        ),
        Trace
    );
    assert_eq!(fresh.items.len(), 6);
    assert_ne!(fresh.generation, page.generation);
    // The run's state is not the `interrupted` a saved `running` settles to.
    let detail = reply!(
        call(
            &service,
            "recording.run.get",
            json!({"run_key": key}),
            &ctx()
        ),
        Run
    );
    assert_eq!(json_of(&detail.value.unwrap())["phase"], "live");
}

#[test]
fn a_run_still_running_in_a_live_boot_is_running_not_interrupted() {
    let data = Data::new("running");
    let run = add_run(&data, "boot-1", "run-1", 1_700_000_000_000, "Running");
    let live = DiskLayer {
        vm_id: VM.into(),
        boot_id: "boot-1".into(),
        phase: LayerPhase::Saving,
        started_ms: 1,
        phase_ms: 2,
    };
    let with_layer = data
        .service()
        .with_layers(Arc::new(FixedLayers(vec![live])));
    let detail = reply!(
        call(
            &with_layer,
            "recording.run.get",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Run
    );
    let value = json_of(&detail.value.unwrap());
    assert_eq!(
        (value["phase"].as_str(), value["state"].as_str()),
        (Some("live"), Some("running"))
    );
    assert_eq!(value["owner_state"], "alive");
    assert_eq!(value["layer"], "pending");
    // With no layer the saved `running` is a recording the writer left: interrupted.
    let without = data
        .service()
        .with_layers(Arc::new(FixedLayers(Vec::new())));
    let detail = reply!(
        call(
            &without,
            "recording.run.get",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Run
    );
    let value = json_of(&detail.value.unwrap());
    assert_eq!(
        (value["phase"].as_str(), value["state"].as_str()),
        (Some("interrupted"), Some("interrupted"))
    );
    assert_eq!(detail.partial, Some(true));
}

#[test]
fn a_finalizing_recording_answers_with_its_phase_and_stays_readable() {
    let data = Data::new("finalizing");
    let run = standard(&data);
    let layers = Arc::new(FixedLayers(vec![DiskLayer {
        vm_id: VM.into(),
        boot_id: "boot-1".into(),
        phase: LayerPhase::Finalizing,
        started_ms: 1,
        phase_ms: 2,
    }]));
    let service = data.service().with_layers(layers);
    let page = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Trace
    );
    assert_eq!(page.phase, RecordingPhase::Finalizing);
    assert_eq!(
        page.total_exact,
        Some(true),
        "the recording is saved and final"
    );
    assert_eq!(page.items.len(), 5);
    let detail = reply!(
        call(
            &service,
            "recording.run.get",
            json!({"run_key": run.key()}),
            &ctx()
        ),
        Run
    );
    assert_eq!(json_of(&detail.value.unwrap())["layer"], "pending");
}

#[test]
fn an_open_read_holds_a_lease_that_retention_can_see() {
    let data = Data::new("lease");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    assert!(!service.run_is_open(&key));
    let opened = service.open_run(&key).unwrap();
    assert!(service.run_is_open(&key));
    drop(opened);
    assert!(!service.run_is_open(&key));
    call(
        &service,
        "recording.run.get",
        json!({"run_key": key}),
        &ctx(),
    )
    .unwrap();
    assert!(!service.run_is_open(&key), "the lease ends with the read");
}

#[test]
fn a_cancelled_read_answers_unavailable_and_a_past_deadline_read_timeout() {
    let data = Data::new("cancel");
    let run = standard(&data);
    let service = data.service();
    let context = Ctx::local_owner("local:1000");
    context
        .cancel
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": run.key()}),
        &context,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Unavailable);
    assert_eq!(
        error.reason(),
        Some(crate::api::error::ErrorReason::Cancelled)
    );
    let late = Ctx::local_owner("local:1000").with_timeout(std::time::Duration::ZERO);
    let error = call(
        &service,
        "recording.trace.page",
        json!({"run_key": run.key()}),
        &late,
    )
    .unwrap_err();
    assert_eq!(error.reason(), Some(ErrorReason::ReadTimeout));
    assert_eq!(service.reads_in_flight(), (0, 0));
}

#[test]
fn reads_stay_consistent_while_a_writer_appends_to_the_trace() {
    let data = Data::new("growing");
    let run = standard(&data);
    let layers = Arc::new(FixedLayers(vec![DiskLayer {
        vm_id: VM.into(),
        boot_id: "boot-1".into(),
        phase: LayerPhase::Live,
        started_ms: 1,
        phase_ms: 2,
    }]));
    let service = data.service().with_layers(layers);
    let key = run.key();
    let writer_run = Run {
        vm: run.vm.clone(),
        boot: run.boot.clone(),
        id: run.id.clone(),
        dir: run.dir.clone(),
    };
    let done = std::sync::atomic::AtomicBool::new(false);
    let mut stale = 0;
    let mut complete_walks = 0;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for call in 6..=25u64 {
                append_calls(
                    &writer_run,
                    1000 + call * 10,
                    &[Call {
                        id: call,
                        pid: 100,
                        nr: 1,
                        result: 1,
                        path: None,
                    }],
                );
                std::thread::sleep(std::time::Duration::from_millis(15));
            }
            done.store(true, std::sync::atomic::Ordering::Release);
        });
        while !done.load(std::sync::atomic::Ordering::Acquire) {
            // Walk the whole trace two rows at a time; a walk that meets a
            // grown recording restarts from the first page.
            let mut cursor: Option<String> = None;
            loop {
                let mut params = json!({"run_key": key, "limit": 2});
                if let Some(cursor) = &cursor {
                    params["cursor"] = json!(cursor);
                }
                match call(&service, "recording.trace.page", params, &ctx()) {
                    Ok(RecordingReply::Trace(page)) => {
                        assert_eq!(page.phase, RecordingPhase::Live);
                        assert_eq!(page.total_exact, Some(false));
                        cursor = page.next_cursor;
                        if cursor.is_none() {
                            complete_walks += 1;
                            break;
                        }
                    }
                    Err(error) => {
                        assert_eq!(error.reason(), Some(ErrorReason::CursorStale), "{error:?}");
                        stale += 1;
                        break;
                    }
                    Ok(other) => panic!("{other:?}"),
                }
            }
        }
    });
    // Once the writer is done the whole trace reads, in order, with no gap.
    let all = reply!(
        call(
            &service,
            "recording.trace.page",
            json!({"run_key": key, "limit": 100}),
            &ctx()
        ),
        Trace
    );
    let ids: Vec<u64> = all.items.iter().map(|row| row.call.call.0).collect();
    assert_eq!(ids, (1..=25).collect::<Vec<_>>());
    assert_eq!(all.total, Some(25));
    eprintln!("growing fixture: {stale} stale walks, {complete_walks} complete walks");
}

#[test]
fn sensitive_reads_are_logged_by_the_service_with_caller_run_and_size_never_the_bytes() {
    let data = Data::new("audit");
    let run = standard(&data);
    let key = run.key();
    let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let service = data.service().with_audit(Arc::new(move |line: &str| {
        sink.lock().unwrap().push(line.to_owned())
    }));
    let single = reply!(
        call(
            &service,
            "recording.trace.get",
            json!({"run_key": key, "ref": {"stream": "9", "task": "10", "call": "2"}}),
            &ctx()
        ),
        Invocation
    );
    let field = json_of(&single.value.unwrap())["entry"]["fields"][0]["field"]
        .as_str()
        .unwrap()
        .to_owned();
    // The rows, a refused read and a read of nothing leave no line.
    call(
        &service,
        "recording.captured.read",
        json!({"run_key": key, "field": field, "offset": "0", "len": 4}),
        &plain_ctx(),
    )
    .unwrap_err();
    assert!(lines.lock().unwrap().is_empty());
    reply!(
        call(
            &service,
            "recording.captured.read",
            json!({"run_key": key, "field": field, "offset": "0", "len": 11}),
            &ctx()
        ),
        Bytes
    );
    let (vm, boot, id) = key.parts();
    let seen = lines.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].starts_with("sensitive read: caller="),
        "{}",
        seen[0]
    );
    assert!(
        seen[0].ends_with(&format!(
            " op=recording.captured.read run={vm}:{boot}:{id} size=11"
        )),
        "{}",
        seen[0]
    );
    // The bytes (/etc/passwd) are not in the line, plain or encoded.
    assert!(!seen[0].contains("passwd") && !seen[0].contains("L2V0Yy9wYXNzd2Q"));
}

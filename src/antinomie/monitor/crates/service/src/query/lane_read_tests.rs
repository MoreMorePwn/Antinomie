// SPDX-License-Identifier: GPL-3.0-only
//! Reads across lanes (ANT-T0455 card D): the query service over lane 1's
//! data folder finds the runs of every lane folder (`<data>/lanes/N/`) where
//! the lane recorded them, a key never names a run of another lane, and the
//! T9 rules of the reads hold for a run of another lane: the sensitive scope,
//! the audit line, host paths kept out, nothing written, and no lane folder
//! read through a link or a record that does not match its place.

use super::{
    ReadContext,
    request::{RecordingRead, RecordingReply},
    service::{JobIndex, QueryApi, QueryService},
    testing::*,
};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::{LaneId, RunId},
    },
    daemon::lanes::read_lanes,
};
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

fn listed(service: &QueryService, params: Value) -> Vec<Value> {
    match call(service, "recording.list", params, &ctx()).unwrap() {
        RecordingReply::Runs(page) => page
            .items
            .iter()
            .map(|item| serde_json::to_value(item).unwrap())
            .collect(),
        other => panic!("unexpected reply {other:?}"),
    }
}

fn detail(service: &QueryService, run: &Run) -> Result<Value, ApiError> {
    match call(
        service,
        "recording.get",
        json!({"recording_key": run.key()}),
        &ctx(),
    )? {
        RecordingReply::Run(single) => Ok(serde_json::to_value(single.value).unwrap()),
        other => panic!("unexpected reply {other:?}"),
    }
}

/// The job store's answer for the runs the test names.
struct Jobs(Vec<(String, RunId)>);

impl JobIndex for Jobs {
    fn job_of_run(&self, vm_id: &str, _boot: &str, run_id: &str) -> Option<RunId> {
        let wanted = format!("{vm_id}/{run_id}");
        self.0
            .iter()
            .find(|(run, _)| *run == wanted)
            .map(|(_, job)| job.clone())
    }
    fn analysis_directory(&self, _job: &RunId) -> Option<PathBuf> {
        None
    }
}

fn job(n: u8) -> RunId {
    RunId::from_parts(1_700_000_000_000 + u64::from(n), [n; 10])
}

/// Lane 1 and `lanes` more lanes, each with one VM (`vm-N`) and a run of the
/// same id `run-1` started at `N` seconds, plus a run of its own.
fn lanes(tag: &str, lanes: u32) -> (Data, Vec<Data>, Vec<Run>) {
    let first = Data::new(tag);
    let mut folders = Vec::new();
    let mut runs = vec![add_run(&first, "boot-1", "run-1", 1_000, "Finalized")];
    for n in 2..=lanes {
        let lane = first.lane(n, &format!("vm-{n}"));
        runs.push(add_run(
            &lane,
            "boot-1",
            "run-1",
            u64::from(n) * 1_000,
            "Finalized",
        ));
        runs.push(add_run(
            &lane,
            "boot-1",
            &format!("lane-{n}-own"),
            u64::from(n) * 1_000 + 1,
            "Stopped",
        ));
        folders.push(lane);
    }
    (first, folders, runs)
}

fn every_lane_is_read(count: u32) {
    let (first, _lanes, runs) = lanes(&format!("lanes{count}"), count);
    let jobs = Jobs(
        runs.iter()
            .enumerate()
            .map(|(i, run)| (format!("{}/{}", run.vm, run.id), job(i as u8 + 1)))
            .collect(),
    );
    let service = first.service().with_jobs(Arc::new(jobs));
    // One list from lane 1 holds the runs of every lane, newest first.
    let items = listed(&service, json!({}));
    assert_eq!(items.len(), runs.len());
    assert_eq!(items[0]["vm_id"], format!("vm-{count}"));
    assert_eq!(items.last().unwrap()["vm_id"], "vm-1");
    // The same run id in every lane is one run per lane, each with its job.
    let same: Vec<&Value> = items.iter().filter(|i| i["run_id"] == "run-1").collect();
    assert_eq!(same.len(), count as usize);
    for (index, run) in runs.iter().enumerate() {
        let found = detail(&service, run).unwrap();
        assert_eq!(found["vm_id"], run.vm.as_str(), "{}", run.id);
        assert_eq!(found["run_id"], run.id.as_str());
        assert_eq!(found["from_run"], json!(job(index as u8 + 1)));
        // The run stays in its own lane's folder: lane 1's in the data
        // folder, lane N's under lanes/N, named as such without host paths.
        let lane = run.vm.trim_start_matches("vm-");
        let expected = if lane == "1" {
            first.root.join("vm-1")
        } else {
            first.root.join("lanes").join(lane).join(&run.vm)
        };
        assert!(run.dir.starts_with(&expected), "{}", run.dir.display());
        let note = if lane == "1" {
            "kept under <data>/x".to_owned()
        } else {
            format!("kept under <data>/lanes/{lane}/x")
        };
        assert_eq!(found["notes"][0], note);
        assert!(
            !found
                .to_string()
                .contains(&first.root.display().to_string())
        );
    }
    // The job filter and the VM filter find a lane's run.
    let last = runs.len() as u8;
    let by_job = listed(&service, json!({"from_run": job(last)}));
    assert_eq!(by_job.len(), 1);
    assert_eq!(by_job[0]["run_id"], runs.last().unwrap().id.as_str());
    let by_vm = listed(&service, json!({"vm_id": "vm-2"}));
    assert_eq!(by_vm.len(), 2);
    assert!(by_vm.iter().all(|i| i["vm_id"] == "vm-2"));
}

#[test]
fn reads_from_lane_1_find_the_runs_of_two_lanes_in_their_own_folders() {
    every_lane_is_read(2);
}

#[test]
fn reads_from_lane_1_find_the_runs_of_three_lanes_in_their_own_folders() {
    every_lane_is_read(3);
}

#[test]
fn the_lanes_read_are_lane_1_and_every_lane_folder_in_order() {
    let (first, lane_folders, _) = lanes("order", 3);
    let found: Vec<(LaneId, PathBuf)> = read_lanes(&first.options())
        .into_iter()
        .map(|(lane, options)| (lane, options.data_dir))
        .collect();
    let expected: Vec<(LaneId, PathBuf)> = std::iter::once((LaneId::new(1), first.root.clone()))
        .chain(
            lane_folders
                .iter()
                .enumerate()
                .map(|(i, l)| (LaneId::new(i as u32 + 2), l.root.clone())),
        )
        .collect();
    assert_eq!(found, expected);
    // A command pointed at a lane folder reads that lane only.
    let lane_options = lane_folders[0].options();
    let only: Vec<LaneId> = read_lanes(&lane_options)
        .into_iter()
        .map(|(lane, _)| lane)
        .collect();
    assert_eq!(only, [LaneId::new(2)]);
    let items = listed(&lane_folders[0].service(), json!({}));
    assert_eq!(items.len(), 2);
    assert!(items.iter().all(|i| i["vm_id"] == "vm-2"));
}

#[test]
fn a_run_key_found_in_two_lanes_is_refused_and_never_guessed() {
    // A VM folder copied by hand into a lane: the same VM id, boot and run.
    let first = Data::new("twice");
    let lane = first.lane(2, VM);
    let one = add_run(&first, "boot-1", "run-1", 1_000, "Finalized");
    add_run(&lane, "boot-1", "run-1", 2_000, "Finalized");
    let service = first.service();
    let error = detail(&service, &one).unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict, "{}", error.message);
    assert!(
        error.message.contains("2 data folders"),
        "{}",
        error.message
    );
    // Runs of the same VM id with their own ids are found, each in its lane.
    let a = add_run(&first, "boot-1", "run-a", 3_000, "Finalized");
    let b = add_run(&lane, "boot-1", "run-b", 4_000, "Stopped");
    assert_eq!(detail(&service, &a).unwrap()["started_ms"], 3_000);
    assert_eq!(detail(&service, &b).unwrap()["started_ms"], 4_000);
    assert_eq!(detail(&service, &b).unwrap()["state"], "stopped");
}

#[test]
fn one_lane_reads_as_before_beside_folders_that_are_not_lanes() {
    let first = Data::new("onelane");
    let run = add_run(&first, "boot-1", "run-1", 1_000, "Finalized");
    // `lanes/` folders without a lane record are not lanes.
    std::fs::create_dir_all(first.root.join("lanes/2/vm-2/runs/run-2")).unwrap();
    let service = first.service();
    let items = listed(&service, json!({}));
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["recording_key"], json!(run.key()));
    assert_eq!(read_lanes(&first.options()).len(), 1);
}

// ---- T9: the rules of a read hold for a run of another lane ---------------

#[test]
fn t9_the_bytes_of_a_lane_run_need_the_sensitive_scope_and_are_audited() {
    let first = Data::new("t9sens");
    let lane = first.lane(2, "vm-2");
    let run = standard(&lane);
    let key = run.key();
    let lines = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&lines);
    let service = first.service().with_audit(Arc::new(move |line: &str| {
        sink.lock().unwrap().push(line.to_owned())
    }));
    let RecordingReply::Invocation(single) = call(
        &service,
        "recording.trace.get",
        json!({"recording_key": key, "ref": {"stream": "9", "task": "10", "call": "2"}}),
        &ctx(),
    )
    .unwrap() else {
        panic!("not an invocation")
    };
    let field = serde_json::to_value(single.value.unwrap()).unwrap()["entry"]["fields"][0]["field"]
        .as_str()
        .unwrap()
        .to_owned();
    // A reader without the sensitive scope gets none of the bytes.
    for (op, params) in [
        (
            "recording.captured.read",
            json!({"recording_key": key, "field": field, "offset": "0", "len": 4}),
        ),
        (
            "recording.files.content",
            json!({"recording_key": key, "version_id": "v1", "range": {"offset": 0, "len": 4}}),
        ),
        (
            "recording.network.packet",
            json!({"recording_key": key, "capture_id": "c1", "n": 1}),
        ),
    ] {
        let error = call(&service, op, params, &plain_ctx()).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::PermissionDenied,
            "{op}: {}",
            error.message
        );
    }
    assert!(lines.lock().unwrap().is_empty());
    // The owner is served, and the read is logged with the lane run's ids.
    let RecordingReply::Bytes(_) = call(
        &service,
        "recording.captured.read",
        json!({"recording_key": key, "field": field, "offset": "0", "len": 11}),
        &ctx(),
    )
    .unwrap() else {
        panic!("not bytes")
    };
    let seen = lines.lock().unwrap().clone();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(
        seen[0].ends_with(" op=recording.captured.read recording=vm-2:boot-1:run-1 size=11"),
        "{}",
        seen[0]
    );
    assert!(!seen[0].contains("passwd"));
}

#[test]
fn t9_a_read_of_a_lane_run_writes_nothing_in_any_lane() {
    let first = Data::new("t9nowrite");
    add_run(&first, "boot-1", "run-0", 500, "Finalized");
    let lane = first.lane(2, "vm-2");
    let run = standard(&lane);
    let key = run.key();
    let before = first.snapshot();
    let service = first.service();
    for (op, params) in [
        ("recording.list", json!({})),
        ("recording.get", json!({"recording_key": key})),
        ("recording.trace.page", json!({"recording_key": key})),
        ("recording.terminal.replay", json!({"recording_key": key})),
        ("recording.artifact.list", json!({"recording_key": key})),
        ("recording.cores.list", json!({"recording_key": key})),
        ("recording.network.captures", json!({"recording_key": key})),
    ] {
        assert!(call(&service, op, params, &ctx()).is_ok(), "{op}");
    }
    assert_eq!(first.snapshot(), before);
}

#[test]
fn t9_a_lane_folder_reached_through_a_link_or_a_record_that_lies_is_never_read() {
    let first = Data::new("t9links");
    let outside = Data::new("t9outside");
    // lanes/2 is a link to another data folder's lane 2.
    let elsewhere = outside.lane(2, "vm-x");
    let hidden = add_run(&elsewhere, "boot-1", "run-x", 1_000, "Finalized");
    std::fs::create_dir_all(first.root.join("lanes")).unwrap();
    std::os::unix::fs::symlink(&elsewhere.root, first.root.join("lanes/2")).unwrap();
    // lanes/3 says it is lane 4.
    let liar = first.lane(3, "vm-3");
    std::fs::write(
        liar.root.join(antinomie_monitor_core::lanes::MARKER_FILE),
        br#"{"schema":1,"lane":4}"#,
    )
    .unwrap();
    let lied = add_run(&liar, "boot-1", "run-3", 2_000, "Finalized");
    // lanes/5's record is a link to a real record.
    let linked = first.lane(5, "vm-5");
    let marker = linked.root.join(antinomie_monitor_core::lanes::MARKER_FILE);
    std::fs::remove_file(&marker).unwrap();
    std::os::unix::fs::symlink(
        elsewhere
            .root
            .join(antinomie_monitor_core::lanes::MARKER_FILE),
        &marker,
    )
    .unwrap();
    let behind_link = add_run(&linked, "boot-1", "run-5", 3_000, "Finalized");
    // A real lane beside them is read.
    let real = first.lane(6, "vm-6");
    let good = add_run(&real, "boot-1", "run-6", 4_000, "Finalized");

    let service = first.service();
    let items = listed(&service, json!({}));
    let ids: Vec<&str> = items
        .iter()
        .map(|i| i["run_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["run-6"]);
    for run in [&hidden, &lied, &behind_link] {
        let error = detail(&service, run).unwrap_err();
        assert_eq!(error.code, ErrorCode::NotFound, "{}", run.id);
    }
    assert_eq!(detail(&service, &good).unwrap()["vm_id"], "vm-6");
    let lanes: Vec<LaneId> = read_lanes(&first.options())
        .into_iter()
        .map(|(lane, _)| lane)
        .collect();
    assert_eq!(lanes, [LaneId::new(1), LaneId::new(6)]);
}

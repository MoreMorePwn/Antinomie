// SPDX-License-Identifier: GPL-3.0-only
//! The packet reads (card Q-5) over a synthetic capture: TShark runs inside
//! bubblewrap, as for the packet panel. The tests need `tshark` and `bwrap`
//! and say so when they skip.

use super::{
    ReadContext,
    request::{RecordingRead, RecordingReply},
    service::{QueryApi, QueryService},
    testing::*,
};
use crate::api::error::{ApiError, ErrorCode};
use serde_json::{Value, json};

fn call(
    service: &QueryService,
    op: &str,
    params: Value,
    ctx: &ReadContext,
) -> Result<RecordingReply, ApiError> {
    service.read(RecordingRead::parse(op, params)?, ctx)
}

fn tools_present() -> bool {
    let ok = |program: &str| {
        std::process::Command::new(program)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    };
    let ready = ok("tshark") && ok("bwrap");
    if !ready {
        eprintln!("skipped: tshark and bwrap are needed for the packet reads");
    }
    ready
}

fn capture_id(service: &QueryService, key: &super::key::RunKey) -> String {
    match call(
        service,
        "recording.network.captures",
        json!({"run_key": key}),
        &ctx(),
    )
    .unwrap()
    {
        RecordingReply::Captures(page) => page.items[0].capture_id.clone(),
        other => panic!("{other:?}"),
    }
}

macro_rules! packets {
    ($result:expr) => {
        match $result.unwrap() {
            RecordingReply::Packets(page) => page,
            other => panic!("unexpected reply {other:?}"),
        }
    };
}

#[test]
fn packet_rows_have_tsharks_columns_and_no_payload_bytes() {
    if !tools_present() {
        return;
    }
    let data = Data::new("packets");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let capture = capture_id(&service, &key);
    let read = || {
        packets!(call(
            &service,
            "recording.network.packets",
            json!({"run_key": key, "capture_id": capture}),
            &plain_ctx()
        ))
    };
    let mut page = read();
    assert_eq!(page.items.len(), 3);
    assert_eq!(page.total, Some(3));
    // The total is exact once TShark's parse is done; a read before that says so.
    for _ in 0..50 {
        if page.total_exact == Some(true) {
            break;
        }
        assert_eq!(page.total_exact, Some(false));
        std::thread::sleep(std::time::Duration::from_millis(100));
        page = read();
    }
    assert_eq!(page.total_exact, Some(true));
    assert!(page.next_cursor.is_none());
    let first = serde_json::to_value(&page.items[0]).unwrap();
    assert_eq!(first["n"], 1);
    assert_eq!(first["time_us"], 1_700_000_000_000_500u64);
    assert_eq!(first["protocol"], "UDP");
    assert_eq!(first["src_ip"], "10.0.0.2");
    assert_eq!(first["dst_ip"], "10.0.0.1");
    assert_eq!(first["src_port"], 40_000);
    assert_eq!(first["dst_port"], 9999);
    assert_eq!(first["transport"], "udp");
    assert_eq!(first["length"], 14 + 20 + 8 + 5);
    let text = serde_json::to_string(&page).unwrap();
    assert!(
        !text.contains("first") || !text.contains("\"first\""),
        "no payload bytes in rows"
    );
    assert!(!text.contains(&data.root.display().to_string()));
    assert_eq!(page.untrusted, Some(true));
    // The normal scope reads rows; paging follows the cursor.
    let two = packets!(call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "limit": 2}),
        &plain_ctx()
    ));
    assert_eq!(two.items.len(), 2);
    let rest = packets!(call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "limit": 2, "cursor": two.next_cursor.unwrap()}),
        &plain_ctx()
    ));
    assert_eq!(rest.items.iter().map(|p| p.n).collect::<Vec<_>>(), [3]);
}

#[test]
fn a_display_filter_selects_frames_and_a_bad_one_is_invalid_argument() {
    if !tools_present() {
        return;
    }
    let data = Data::new("filter");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let capture = capture_id(&service, &key);
    let page = packets!(call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "filter": "udp.dstport == 8888"}),
        &ctx()
    ));
    assert_eq!(page.items.iter().map(|p| p.n).collect::<Vec<_>>(), [3]);
    assert_eq!(page.total, Some(1));
    // A cursor made for one filter is stale for another.
    let two = packets!(call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "limit": 1}),
        &ctx()
    ));
    let error = call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "limit": 1, "filter": "udp", "cursor": two.next_cursor.unwrap()}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Conflict);
    for bad in ["udp.dstport ==", "no.such.field == 1", "((("] {
        let error = call(
            &service,
            "recording.network.packets",
            json!({"run_key": key, "capture_id": capture, "filter": bad}),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument, "{bad}: {error:?}");
        assert_eq!(error.field.as_deref(), Some("filter"));
        assert!(
            !error.message.contains(&data.root.display().to_string()),
            "{}",
            error.message
        );
    }
    // A good filter still works after a bad one on the same service.
    let again = packets!(call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "filter": "udp"}),
        &ctx()
    ));
    assert_eq!(again.items.len(), 3);
}

#[test]
fn a_decoded_packet_needs_the_sensitive_scope() {
    if !tools_present() {
        return;
    }
    let data = Data::new("packet");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let capture = capture_id(&service, &key);
    let params = json!({"run_key": key, "capture_id": capture, "n": 1});
    let error = call(
        &service,
        "recording.network.packet",
        params.clone(),
        &plain_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    let single = match call(&service, "recording.network.packet", params, &ctx()).unwrap() {
        RecordingReply::Packet(single) => single,
        other => panic!("{other:?}"),
    };
    let detail = single.value.unwrap();
    assert_eq!(detail.n, 1);
    assert_eq!(detail.frame_len, 14 + 20 + 8 + 5);
    let names: Vec<_> = detail.tree.nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(names.contains(&"ip") && names.contains(&"udp"), "{names:?}");
    assert!(!detail.bytes.is_empty());
    assert_eq!(single.untrusted, Some(true));
    // Out-of-range and malformed requests.
    for (n, code) in [
        (0u64, ErrorCode::InvalidArgument),
        (99, ErrorCode::NotFound),
    ] {
        let error = call(
            &service,
            "recording.network.packet",
            json!({"run_key": key, "capture_id": capture, "n": n}),
            &ctx(),
        )
        .unwrap_err();
        assert_eq!(error.code, code, "n = {n}");
    }
    let error = call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": "nope"}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    // The id of a file that is not a capture is not a capture.
    let other = match call(
        &service,
        "recording.artifact.list",
        json!({"run_key": key}),
        &ctx(),
    )
    .unwrap()
    {
        RecordingReply::Artifacts(page) => page
            .items
            .iter()
            .find(|a| a.name == "run.json")
            .unwrap()
            .id
            .to_string(),
        other => panic!("{other:?}"),
    };
    let error = call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": other}),
        &ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::NotFound);
}

#[test]
fn packet_reads_write_nothing_under_the_data_directory() {
    if !tools_present() {
        return;
    }
    let data = Data::new("packetwrites");
    let run = standard(&data);
    let service = data.service();
    let key = run.key();
    let capture = capture_id(&service, &key);
    let before = data.snapshot();
    packets!(call(
        &service,
        "recording.network.packets",
        json!({"run_key": key, "capture_id": capture, "filter": "udp"}),
        &ctx()
    ));
    call(
        &service,
        "recording.network.packet",
        json!({"run_key": key, "capture_id": capture, "n": 2}),
        &ctx(),
    )
    .unwrap();
    assert_eq!(data.snapshot(), before);
}

#[test]
fn a_capture_segment_says_which_run_started_it_and_which_were_live() {
    let data = Data::new("capture-link");
    let run = standard(&data);
    // The segment's own summary: written 1 s into the run, 4 s long.
    let started = 1_700_000_001_000u64;
    std::fs::write(
        data.vm_dir()
            .join("boots")
            .join(&run.boot)
            .join("network")
            .join("seg-1.json"),
        json!({"id": "seg-1", "boot_id": run.boot, "file": "seg-1.pcap",
               "started_ms": started, "stopped_ms": started + 4_000, "packets": 3})
        .to_string(),
    )
    .unwrap();
    // A second run on the VM that was live while the segment was written.
    let other = add_run(&data, &run.boot, "run-2", started + 1_000, "Finalized");
    let service = data.service();
    let key = run.key();
    let page = match call(
        &service,
        "recording.network.captures",
        json!({"run_key": key}),
        &ctx(),
    )
    .unwrap()
    {
        RecordingReply::Captures(page) => page,
        other => panic!("{other:?}"),
    };
    let item = serde_json::to_value(&page.items[0]).unwrap();
    assert_eq!(item["first_ms"], started);
    assert_eq!(item["packets"], 3);
    assert_eq!(item["link"]["certainty"], "exact");
    assert_eq!(item["link"]["run_id"], run.id);
    let _ = other;
    // The run that only overlapped is named, by its id.
    assert_eq!(item["link"]["live_runs"], json!(["run-2"]));
}

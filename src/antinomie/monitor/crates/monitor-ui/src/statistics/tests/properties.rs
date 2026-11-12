// SPDX-License-Identifier: GPL-3.0-only
//! Card C, Properties: every row of design 2.2 and 2.2.1.
use super::*;
use crate::statistics::properties::{blocks, table, Block, Row, Tone};
use crate::statistics::toolbar::chips;
use antinomie_monitor_core::{ExecRequest, RunState, RunSummary};
use antinomie_triage::statistics::aggregate::Capped;
use serde_json::json;

fn run_summary() -> RunSummary {
    let request = ExecRequest {
        path: "/tmp/sample".into(),
        args: vec!["--fast".into(), "x y".into()],
        ..ExecRequest::default()
    };
    let environment = antinomie_monitor_core::run_environment::RunEnvironment {
        vm_name: "Analysis VM".into(),
        cpus: 4,
        ram_mib: 2048,
        network: "Isolated".into(),
        stealth: "Generic PC".into(),
        accelerator: "tcg (KVM unavailable)".into(),
        base_name: "debian-minimal".into(),
        base_revision: Some(22),
        kernel_release: "6.12.94".into(),
        kernel_revision: Some(21),
        ..Default::default()
    };
    serde_json::from_value(json!({
        "id": "4c1e9a72beef", "vm_id": "vm1", "boot_id": "boot1", "session_id": 1,
        "root_task_cookie": 55, "pid": 42,
        "request": serde_json::to_value(request).unwrap(),
        "directory": "/runs/4c1e9a72beef", "terminal_eof": false,
        "state": serde_json::to_value(RunState::Finalized).unwrap(),
        "recording_error": null, "started_ms": 1_800_000_000_000_u64,
        "stopped_by_user": true,
        "execution": {"generation": 1, "live_task_count": 0, "pending_async_count": 0, "flags": 0,
                      "root_wait_status": null, "root_exit": null, "async_loss_count": 2, "total_task_count": 31},
        "notes": ["A note about the run"],
        "environment": serde_json::to_value(environment).unwrap(),
    }))
    .expect("a run summary")
}

fn manifest() -> serde_json::Value {
    json!({
        "started_ms": 1_800_000_000_000_u64, "ended_ms": 1_800_000_065_000_u64,
        "packets": 1000, "bytes": 5_242_880,
        "telemetry_loss": {"received_packets": 1000, "lost_packets": 12, "untracked_packets": 0},
        "health": {
            "dropped": 3, "storage_dropped_packets": 2, "ui_dropped": 9, "guest_note_lost": 1,
            "transport_waits": 4113, "transport_wait_ns": 5_000_000, "ring_size": 1_048_576,
            "send_wait_us": 2000, "writer_held_ns": 1_000_000,
            "read_gaps": {"count": 3, "total_ns": 900_000_000, "longest_ns": 500_000_000,
                          "full_spell_count": 1, "full_spell_total_ns": 40_000_000, "full_spell_longest_ns": 40_000_000}
        },
        "run": {
            "execution": {"async_loss_count": 2},
            "environment": {"accelerator": "tcg (KVM unavailable)"},
            "reduced": {"at_ms": 5, "at_guest_ns": 14_000, "quota_bytes": 100, "dropped_calls": {"openat": 4}},
            "notes": ["A note about the run"]
        }
    })
}

fn find<'a>(blocks: &'a [Block], block: &str, label: &str) -> &'a Row {
    blocks
        .iter()
        .find(|b| b.title == block)
        .unwrap_or_else(|| panic!("no block {block}"))
        .rows
        .iter()
        .find(|r| r.label == label)
        .unwrap_or_else(|| panic!("no row {label} in {block}"))
}

#[test]
fn c1_every_row_of_the_run_guest_recording_transport_and_quality_blocks() {
    let fixture = Fixture::with_manifest(&calls(), manifest());
    let stats = stats_of(&fixture, "");
    let facts = Facts::of_run(&run_summary(), "Recording ended");
    let all = blocks(&facts, &stats, TimeBase::RunTime);
    let titles: Vec<&str> = all.iter().map(|b| b.title).collect();
    assert_eq!(
        titles,
        ["Run", "Guest", "Recording", "Transport policy", "Quality"]
    );
    // Run
    assert_eq!(find(&all, "Run", "Program").value, "/tmp/sample --fast x y");
    assert_eq!(find(&all, "Run", "Run id").value, "4c1e9a72beef");
    assert_eq!(find(&all, "Run", "VM").value, "Analysis VM");
    assert_eq!(find(&all, "Run", "State").value, "Recording ended");
    assert_eq!(find(&all, "Run", "Stopped by you").value, "yes");
    assert_eq!(find(&all, "Run", "Duration").value, "1 min 5 s");
    assert!(!find(&all, "Run", "Started").value.is_empty());
    assert!(!find(&all, "Run", "Ended").value.contains("not recorded"));
    // Guest
    assert_eq!(
        find(&all, "Guest", "Base").value,
        "debian-minimal (revision 22)"
    );
    assert_eq!(find(&all, "Guest", "Kernel").value, "6.12.94 (revision 21)");
    assert_eq!(
        find(&all, "Guest", "Accelerator").value,
        "tcg (KVM unavailable)"
    );
    assert_eq!(find(&all, "Guest", "vCPUs").value, "4");
    assert_eq!(find(&all, "Guest", "RAM").value, "2048 MiB");
    assert_eq!(find(&all, "Guest", "Stealth profile").value, "Generic PC");
    assert_eq!(find(&all, "Guest", "Network").value, "Isolated");
    assert!(!find(&all, "Guest", "Architecture").value.is_empty());
    // Recording
    assert_eq!(find(&all, "Recording", "Calls in the view").value, "15");
    assert_eq!(find(&all, "Recording", "First call").value, "+0:00.000");
    assert_eq!(find(&all, "Recording", "Processes seen").value, "1");
    assert_eq!(find(&all, "Recording", "Threads seen").value, "3");
    assert_eq!(
        find(&all, "Recording", "Tasks the guest counted").value,
        "31"
    );
    assert_eq!(
        find(&all, "Recording", "Packets saved").value,
        "1,000 · 5.0 MiB"
    );
    assert_eq!(
        find(&all, "Recording", "Calls with no result recorded").value,
        "1"
    );
    assert_eq!(
        find(&all, "Recording", "Calls of other programs").value,
        "2"
    );
    assert!(
        find(&all, "Recording", "Peak calls/s")
            .value
            .parse::<f64>()
            .is_ok()
            || find(&all, "Recording", "Peak calls/s").value.contains(' ')
    );
    // Transport policy: boot-wide
    let policy = find(&all, "Transport policy", "Transport policy");
    assert!(
        policy.value.contains("never-drop") && policy.value.contains("2000"),
        "{policy:?}"
    );
    assert!(policy.hint.contains("boot"), "{policy:?}");
    assert_eq!(
        find(&all, "Transport policy", "Ring size per vCPU").value,
        "1.0 MiB"
    );
    // Quality, apart and never summed
    let q = |label: &str| find(&all, "Quality", label);
    assert_eq!(
        q("Telemetry lost").value,
        "at least 12 of 1,012 packets (1.19 %)"
    );
    assert_eq!(q("Telemetry lost").tone, Tone::Bad);
    assert_eq!(q("Dropped by the transport").value, "3");
    assert_eq!(q("Not saved by the recorder").value, "2");
    assert_eq!(q("Screen previews dropped").value, "9");
    assert!(q("Screen previews dropped")
        .hint
        .contains("Not a recording loss"));
    assert_eq!(q("Async observations lost").value, "2");
    assert_eq!(q("Credential and hash notes lost").value, "1");
    assert!(q("Reduced recording").value.contains("4 calls not saved"));
    assert!(
        q("Host read gaps").value.starts_with("3 ·"),
        "{:?}",
        q("Host read gaps")
    );
    assert!(q("Host read gaps").hint.contains("boot"));
    assert!(q("Full-ring spells").value.starts_with("1 ·"));
    assert!(q("Guest send waits").value.starts_with("4,113 times"));
    assert!(q("Guest send waits").hint.contains("boot"));
    assert!(q("Writer held").value.contains("ms"));
    assert_eq!(q("Shedding").value, "none");
    assert_eq!(q("Run notes").value, "A note about the run");
    // Copy and export read the same rows.
    let t = table(&all);
    assert_eq!(t.columns, ["block", "field", "value"]);
    assert!(t
        .to_tsv()
        .contains("Quality\tTelemetry lost\tat least 12 of 1,012 packets (1.19 %)"));
}

#[test]
fn c1_a_recording_without_figures_says_not_recorded_and_capped_counts_say_at_least() {
    let fixture = Fixture::new(&calls());
    let mut stats = stats_of(&fixture, "");
    let all = blocks(&Facts::default(), &stats, TimeBase::RunTime);
    assert_eq!(
        find(&all, "Quality", "Recording quality").value,
        "not recorded"
    );
    assert_eq!(
        find(&all, "Quality", "Dropped by the transport").value,
        "not recorded"
    );
    assert_eq!(find(&all, "Guest", "Environment").value, "not recorded");
    stats.threads = Capped {
        count: 262_144,
        at_least: true,
    };
    let all = blocks(&Facts::default(), &stats, TimeBase::Guest);
    assert_eq!(
        find(&all, "Recording", "Threads seen").value,
        "at least 262,144"
    );
    assert!(find(&all, "Recording", "First call").value.ends_with(" s"));
    stats.pid_not_recorded = true;
    let all = blocks(&Facts::default(), &stats, TimeBase::RunTime);
    assert_eq!(
        find(&all, "Recording", "Processes seen").value,
        "not recorded"
    );
    // Host time without a clock anchor says so instead of guessing.
    let all = blocks(&Facts::default(), &stats, TimeBase::Host);
    assert!(find(&all, "Recording", "First call")
        .value
        .contains("no host clock"));
}

#[test]
fn c1_the_strip_names_loss_reduction_gaps_waits_and_a_live_run() {
    let fixture = Fixture::with_manifest(&calls(), manifest());
    let stats = stats_of(&fixture, "");
    let texts: Vec<String> = chips(&stats, true, false)
        .into_iter()
        .map(|c| c.text)
        .collect();
    assert!(
        texts.contains(&"Incomplete: at least 12 packets lost".to_owned()),
        "{texts:?}"
    );
    assert!(
        texts.contains(&"Guest waited 4,113 times".to_owned()),
        "{texts:?}"
    );
    assert!(
        texts.iter().any(|t| t.starts_with("Reduced from +")),
        "{texts:?}"
    );
    assert!(texts.contains(&"Still recording".to_owned()), "{texts:?}");
    assert!(
        texts.contains(&"2 calls of another program not counted".to_owned()),
        "{texts:?}"
    );
    let plain = Fixture::with_manifest(
        &calls(),
        json!({"telemetry_loss": {"received_packets": 5}, "health": {}}),
    );
    let texts: Vec<String> = chips(&stats_of(&plain, ""), false, true)
        .into_iter()
        .map(|c| c.text)
        .collect();
    assert_eq!(texts[0], "Complete");
    assert!(texts.contains(&"Partial".to_owned()));
}

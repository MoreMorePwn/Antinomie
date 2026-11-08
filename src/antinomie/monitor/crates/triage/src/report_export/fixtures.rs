// SPDX-License-Identifier: GPL-3.0-only
//! Fixtures of the report tests, shared with the GUI crate's dialog tests
//! (feature `test-support`): a recording with findings and an HTTP capture,
//! the job that exports it, and a run record.
use super::*;
use crate::tests::{http_pcap, write_rwx_calls};
use antinomie_monitor_core::report::Format;
use antinomie_monitor_core::RunSummary;

pub fn have_tshark() -> bool {
    std::process::Command::new("tshark")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// A recording with RWX mapping calls (findings, processes) and an HTTP
/// capture (URL, endpoint, domain indicators).
pub fn fixture() -> (PacketSpool, PathBuf) {
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..3);
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    let pcap = temp.directory.join("fixture.pcap");
    std::fs::write(&pcap, http_pcap()).unwrap();
    // One rule that matched, with the credit its licence asks to keep.
    antinomie_monitor_core::run_digest::RunDigest::update(&temp.directory, |digest| {
        digest.detections = Some(vec![antinomie_monitor_core::run_digest::DetectionHit {
            engine: "YARA".into(),
            rule_id: "fixture_rule".into(),
            title: "fixture_rule".into(),
            severity: "high".into(),
            count: 2,
            author: "Jane Rule".into(),
            license: "DRL 1.1".into(),
            source: "Example Pack".into(),
            reference: "https://example.org/rule".into(),
            ..Default::default()
        }]);
    })
    .unwrap();
    (temp, pcap)
}

pub fn job(temp: &PacketSpool, pcap: &Path, choices: Choices) -> Job {
    Job {
        archive: temp.directory.clone(),
        pcap: Some(pcap.to_path_buf()),
        request: ScanRequest {
            root_cookie: 55,
            run_finished: true,
            ..ScanRequest::default()
        },
        choices,
        run: report::RunInfo {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run-fixture-1".into(),
            started_ms: Some(1_792_000_000_000),
            finished: true,
            ..Default::default()
        },
        sample: Some(report::SampleInfo {
            name: "fixture.elf".into(),
            sha256: "ab".repeat(32),
            size: Some(100),
            role: String::new(),
        }),
        clock: None,
        data_dir: None,
        now_ms: 1_792_000_100_000,
        folder: temp.directory.join("report"),
    }
}

pub fn all_formats() -> Choices {
    Choices {
        formats: Format::ALL.to_vec(),
        bundle: true,
        ..Choices::default()
    }
}

pub fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

/// A run for tests: its id and the program it ran.
pub fn test_run(id: &str, path: &str) -> RunSummary {
    use antinomie_monitor_core::{ExecRequest, RunState};
    RunSummary {
        environment: None,
        reduced: None,
        boot_wait: None,
        triggers: None,
        stopped_by_user: false,
        stopped_at_ms: None,
        started_ms: None,
        clock_anchor: None,
        id: id.into(),
        vm_id: "chosen".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 7,
        pid: 42,
        request: ExecRequest {
            path: path.into(),
            ..ExecRequest::default()
        },
        directory: std::path::PathBuf::new(),
        terminal_eof: false,
        state: RunState::Running,
        notes: Vec::new(),
        machine: None,
        route: None,
        recording_error: None,
        execution: None,
        analysis: None,
    }
}

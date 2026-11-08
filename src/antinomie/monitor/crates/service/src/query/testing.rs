// SPDX-License-Identifier: GPL-3.0-only
//! Small synthetic recordings for the query tests: a data directory with one
//! VM, runs with a trace, a terminal journal, captures, an analysis report and
//! the files the recorder keeps. Built from the engine's own types and its
//! `Assembler`; no sample bytes are involved.

use super::{QueryService, ReadContext};
use antinomie_monitor_core::{
    BackendOptions, ExecRequest, RunArtifactState, RunArtifacts, RunExecution, WaitStatus,
    analysis::{
        AnalysisAddressKind, AnalysisData, AnalysisEntry, AnalysisKind, AnalysisListing,
        AnalysisLocation, AnalysisRange, AnalysisRecord, AnalysisReport, AnalysisSection,
        AnalysisSectionState, AnalysisState,
    },
    parser::Assembler,
    route::{RouteRecord, RouteVia},
    samples::SampleRef,
};
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

pub const VM: &str = "vm-1";
/// A benign two-line script: the "sample" of every fixture run.
pub const SAMPLE_BYTES: &[u8] = b"#!/bin/sh\necho benign\n";

/// Its SHA-256.
pub fn sample_sha() -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(SAMPLE_BYTES)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// A data directory that is removed with the value.
pub struct Data {
    pub root: PathBuf,
}

impl Data {
    pub fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "ant-query-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        fs::create_dir_all(root.join(VM).join("runs")).unwrap();
        Self { root }
    }

    pub fn options(&self) -> BackendOptions {
        BackendOptions {
            data_dir: self.root.clone(),
            ..BackendOptions::default()
        }
    }

    pub fn service(&self) -> QueryService {
        QueryService::new(self.options())
    }

    /// The VM folder: the disk folder and the recording folder.
    pub fn vm_dir(&self) -> PathBuf {
        self.root.join(VM)
    }

    /// Every file under the data directory with its size and time: a read
    /// must leave this unchanged (design 5.12.2, "No recording writes").
    pub fn snapshot(&self) -> Vec<(PathBuf, u64, i64, i64)> {
        fn walk(dir: &Path, out: &mut Vec<(PathBuf, u64, i64, i64)>) {
            use std::os::unix::fs::MetadataExt;
            let mut entries: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                let meta = fs::symlink_metadata(entry.path()).unwrap();
                out.push((entry.path(), meta.len(), meta.mtime(), meta.mtime_nsec()));
                if meta.is_dir() {
                    walk(&entry.path(), out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.root, &mut out);
        out
    }
}

impl Drop for Data {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn ctx() -> ReadContext {
    ReadContext::local_owner("local:1000")
}

/// A reader with the normal scope only.
pub fn plain_ctx() -> ReadContext {
    let mut context = ReadContext::local_owner("web:7");
    context.caller.scopes = vec![crate::api::ops::Scope::Read];
    context
}

/// One run folder.
pub struct Run {
    pub boot: String,
    pub id: String,
    pub dir: PathBuf,
}

impl Run {
    pub fn key(&self) -> super::key::RunKey {
        super::key::RunKey::new(VM, &self.boot, &self.id).unwrap()
    }
}

/// A finished run `id` of boot `boot` with its `run.json` and `manifest.json`.
pub fn add_run(data: &Data, boot: &str, id: &str, started_ms: u64, state: &str) -> Run {
    let dir = data.vm_dir().join("runs").join(id);
    fs::create_dir_all(&dir).unwrap();
    let request = ExecRequest {
        path: "/tmp/sample.sh".into(),
        sample: Some(SampleRef {
            sha256: sample_sha(),
            name: "sample.sh".into(),
        }),
        ..ExecRequest::default()
    };
    let execution = RunExecution {
        generation: 1,
        live_task_count: 0,
        pending_async_count: 0,
        flags: 0,
        root_wait_status: Some(0),
        root_exit: Some(WaitStatus::Exited { code: 0 }),
        async_loss_count: 0,
        total_task_count: 3,
    };
    let run = json!({
        "started_ms": started_ms,
        "clock_anchor": {"guest_ns": 1_000_000_000u64, "host_us": started_ms * 1000},
        "id": id, "vm_id": VM, "boot_id": boot,
        "session_id": 1, "root_task_cookie": 10, "pid": 100,
        "request": request,
        "directory": "/ignored/by/the/reader",
        "terminal_eof": true,
        "state": state,
        "recording_error": null,
        "execution": execution,
        "notes": [format!("kept under {}/x", data.root.display())],
        "route": RouteRecord::fixed(RouteVia::Gateway),
    });
    fs::write(dir.join("run.json"), serde_json::to_vec(&run).unwrap()).unwrap();
    let manifest = json!({
        "run": {"id": id, "vm_id": VM, "boot_id": boot,
                "request": {"cwd": "/tmp"}, "environment": {}},
        "started_ms": started_ms, "ended_ms": started_ms + 5000, "bytes": 1,
    });
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
    Run {
        boot: boot.into(),
        id: id.into(),
        dir,
    }
}

const GUEST_BASE_NS: u64 = 1_000_000_000;

/// A raw ANTT packet (header minor 1, 136 bytes).
#[allow(clippy::too_many_arguments)]
fn packet(
    call: u64,
    phase: u8,
    fragment: u8,
    seq: u64,
    ns: u64,
    pid: u32,
    nr: u64,
    object: (u32, u64),
    body: &[u8],
) -> Vec<u8> {
    let mut p = vec![0u8; 136];
    p[..4].copy_from_slice(b"ANTT");
    p[4..6].copy_from_slice(&1u16.to_le_bytes());
    p[6..8].copy_from_slice(&1u16.to_le_bytes());
    p[8..10].copy_from_slice(&136u16.to_le_bytes());
    p[10..12].copy_from_slice(&1u16.to_le_bytes());
    p[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
    p[20..24].copy_from_slice(&1u32.to_le_bytes());
    p[24..32].copy_from_slice(&9u64.to_le_bytes());
    p[32..40].copy_from_slice(&10u64.to_le_bytes());
    p[40..48].copy_from_slice(&call.to_le_bytes());
    p[48..56].copy_from_slice(&(call * 2 + u64::from(phase)).to_le_bytes());
    p[56..64].copy_from_slice(&seq.to_le_bytes());
    p[64..72].copy_from_slice(&ns.to_le_bytes());
    p[72..76].copy_from_slice(&pid.to_le_bytes());
    p[76..80].copy_from_slice(&pid.to_le_bytes());
    p[88..96].copy_from_slice(&nr.to_le_bytes());
    p[96..98].copy_from_slice(&1u16.to_le_bytes());
    p[98] = phase;
    p[99] = fragment;
    p[100..104].copy_from_slice(&object.0.to_le_bytes());
    p[104..112].copy_from_slice(&object.1.to_le_bytes());
    p[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
    p[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
    p[128..136].copy_from_slice(&99u64.to_le_bytes());
    p.extend_from_slice(body);
    p
}

/// One call of the synthetic trace.
pub struct Call {
    pub id: u64,
    pub pid: u32,
    /// An x86-64 call number: 0 read, 1 write, 2 open, 59 execve, 257 openat.
    pub nr: u64,
    pub result: i64,
    /// Bytes of a captured path argument, when the call has one.
    pub path: Option<&'static [u8]>,
}

/// Write `telemetry.raw` for `calls` (entry then exit each) and the objects
/// the engine's assembler stores beside it.
pub fn write_trace(run: &Run, calls: &[Call]) {
    let mut raw = fs::File::create(run.dir.join("telemetry.raw")).unwrap();
    let mut assembler = Assembler::new(run.dir.join("objects"), 1 << 20).unwrap();
    let mut seq = 0u64;
    let mut put = |p: Vec<u8>| {
        assembler.ingest(&p).unwrap();
        raw.write_all(&(p.len() as u32).to_le_bytes()).unwrap();
        raw.write_all(&p).unwrap();
    };
    for call in calls {
        let ns = GUEST_BASE_NS + call.id * 1_000_000;
        for phase in [1u8, 2u8] {
            let mut begin = vec![0u8; 120];
            for (i, arg) in [call.id + 1, 2, 3, 4, 5, 6].iter().enumerate() {
                begin[i * 8..i * 8 + 8].copy_from_slice(&arg.to_le_bytes());
            }
            if phase == 2 {
                begin[49] = 1;
                begin[56..64].copy_from_slice(&call.result.to_le_bytes());
            }
            seq += 1;
            put(packet(
                call.id,
                phase,
                1,
                seq,
                ns + u64::from(phase),
                call.pid,
                call.nr,
                (0, 0),
                &begin,
            ));
            if let (1, Some(bytes)) = (phase, call.path) {
                let key = b"path";
                let layout = b"cstring";
                let mut field = vec![0u8; 40];
                field[0] = 0;
                field[1] = 2;
                field[2..4].copy_from_slice(&2u16.to_le_bytes());
                field[4..6].copy_from_slice(&1u16.to_le_bytes());
                field[32..34].copy_from_slice(&(key.len() as u16).to_le_bytes());
                field[34..36].copy_from_slice(&(layout.len() as u16).to_le_bytes());
                field.extend_from_slice(key);
                field.extend_from_slice(layout);
                seq += 1;
                put(packet(
                    call.id,
                    phase,
                    2,
                    seq,
                    ns,
                    call.pid,
                    call.nr,
                    (5, 0),
                    &field,
                ));
                seq += 1;
                put(packet(
                    call.id,
                    phase,
                    3,
                    seq,
                    ns,
                    call.pid,
                    call.nr,
                    (5, 0),
                    bytes,
                ));
                let mut end = vec![0u8; 32];
                end[..8].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
                end[8..16].copy_from_slice(&(bytes.len() as u64).to_le_bytes());
                seq += 1;
                put(packet(
                    call.id,
                    phase,
                    4,
                    seq,
                    ns,
                    call.pid,
                    call.nr,
                    (5, 0),
                    &end,
                ));
            }
            seq += 1;
            put(packet(
                call.id,
                phase,
                5,
                seq,
                ns + 10,
                call.pid,
                call.nr,
                (0, 0),
                &[0u8; 32],
            ));
        }
    }
    raw.sync_all().unwrap();
    drop(assembler);
    antinomie_monitor_core::writer::barrier();
}

/// Append `calls` (no captured fields) to the raw archive as a recorder
/// does: whole packets at the end of the file. `first_seq` continues the
/// packet sequence of what is there.
pub fn append_calls(run: &Run, first_seq: u64, calls: &[Call]) {
    let mut raw = fs::OpenOptions::new()
        .append(true)
        .open(run.dir.join("telemetry.raw"))
        .unwrap();
    let mut seq = first_seq;
    for call in calls {
        let ns = GUEST_BASE_NS + call.id * 1_000_000;
        for phase in [1u8, 2u8] {
            let mut begin = vec![0u8; 120];
            if phase == 2 {
                begin[49] = 1;
                begin[56..64].copy_from_slice(&call.result.to_le_bytes());
            }
            for (fragment, body) in [(1u8, begin), (5u8, vec![0u8; 32])] {
                seq += 1;
                let p = packet(
                    call.id,
                    phase,
                    fragment,
                    seq,
                    ns,
                    call.pid,
                    call.nr,
                    (0, 0),
                    &body,
                );
                let mut record = (p.len() as u32).to_le_bytes().to_vec();
                record.extend(p);
                // One write per packet: a reader sees whole packets or none.
                raw.write_all(&record).unwrap();
            }
        }
    }
    raw.sync_all().unwrap();
}

/// `terminal.journal`: output, a resize, more output, EOF.
pub fn write_terminal(run: &Run) {
    let mut journal = Vec::new();
    let mut record = |kind: u8, data: &[u8]| {
        journal.push(kind);
        journal.extend_from_slice(&(data.len() as u32).to_le_bytes());
        journal.extend_from_slice(data);
    };
    record(1, b"$ ./sample.sh\r\n");
    let mut size = 24u16.to_le_bytes().to_vec();
    size.extend_from_slice(&80u16.to_le_bytes());
    record(2, &size);
    record(1, b"hello from the guest\r\n");
    record(3, b"");
    fs::write(run.dir.join("terminal.journal"), journal).unwrap();
}

/// A classic pcap of three UDP frames, `10.0.0.2:40000` to `10.0.0.1` ports
/// 9999, 9999 and 8888.
pub fn pcap() -> Vec<u8> {
    let mut file = Vec::new();
    file.extend_from_slice(&0xa1b2_c3d4u32.to_le_bytes());
    file.extend_from_slice(&2u16.to_le_bytes());
    file.extend_from_slice(&4u16.to_le_bytes());
    file.extend_from_slice(&[0u8; 8]);
    file.extend_from_slice(&65_535u32.to_le_bytes());
    file.extend_from_slice(&1u32.to_le_bytes());
    for (index, (port, payload)) in [
        (9999u16, &b"first"[..]),
        (9999, b"second"),
        (8888, b"third!"),
    ]
    .into_iter()
    .enumerate()
    {
        let udp_len = 8 + payload.len();
        let ip_len = 20 + udp_len;
        let mut frame = vec![0u8; 14];
        frame[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&[10, 0, 0, 2]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 1]);
        let mut udp = Vec::new();
        udp.extend_from_slice(&40_000u16.to_be_bytes());
        udp.extend_from_slice(&port.to_be_bytes());
        udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        frame.extend(ip);
        frame.extend(udp);
        frame.extend_from_slice(payload);
        file.extend_from_slice(&(1_700_000_000u32 + index as u32).to_le_bytes());
        file.extend_from_slice(&500u32.to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        file.extend(frame);
    }
    file
}

/// `artifacts.json` linking one capture segment and an exit core, and the two
/// files. Returns the capture's path.
pub fn write_artifacts(data: &Data, run: &Run) -> PathBuf {
    let boot_dir = data.vm_dir().join("boots").join(&run.boot);
    fs::create_dir_all(boot_dir.join("network")).unwrap();
    let capture = boot_dir.join("network").join("seg-1.pcap");
    fs::write(&capture, pcap()).unwrap();
    let core = data.vm_dir().join("cores").join("exit.core");
    fs::create_dir_all(core.parent().unwrap()).unwrap();
    fs::write(&core, vec![0u8; 256]).unwrap();
    let artifacts = RunArtifacts {
        run_id: run.id.clone(),
        vm_id: VM.into(),
        boot_id: run.boot.clone(),
        network_captures: vec![capture.clone()],
        network_state: RunArtifactState::Complete,
        core_dump: Some(core),
        core_state: RunArtifactState::Partial,
        core_requested_size: Some(1 << 20),
        core_saved_size: Some(256),
        ..RunArtifacts::default()
    };
    fs::write(
        run.dir.join("artifacts.json"),
        serde_json::to_vec(&artifacts).unwrap(),
    )
    .unwrap();
    capture
}

/// `analysis/report.json` with a Metadata section kept in the report and a
/// Strings section whose rows are in a listing.
pub fn write_analysis(dir: &Path, id: &str) {
    fs::create_dir_all(dir.join("listings")).unwrap();
    let entries = ["alpha", "bravo", "charlie"];
    let mut listing = Vec::new();
    for (index, text) in entries.iter().enumerate() {
        let offset = 16 + index as u64 * 32;
        let entry = AnalysisEntry {
            label: format!("string {index}"),
            value: (*text).into(),
            offset: Some(offset),
            record: Some(AnalysisRecord {
                revision: 1,
                id: index as u64 + 1,
                location: Some(AnalysisLocation {
                    kind: AnalysisAddressKind::FileOffset,
                    value: offset,
                    file_range: Some(AnalysisRange {
                        offset,
                        len: text.len() as u64,
                    }),
                }),
                data: AnalysisData::String {
                    encoding: "ASCII".into(),
                    byte_len: text.len() as u64,
                    retained_len: text.len() as u64,
                },
            }),
        };
        listing.extend(serde_json::to_vec(&entry).unwrap());
        listing.push(b'\n');
    }
    // The rows end without a trailing newline in the engine's listings.
    listing.pop();
    let listing_bytes = listing.len() as u64;
    fs::write(dir.join("listings").join("strings.jsonl"), &listing).unwrap();
    let section = |kind, entries: Vec<AnalysisEntry>, listing| AnalysisSection {
        kind,
        state: AnalysisSectionState::Complete,
        summary: "done".into(),
        entries,
        tools: vec!["builtin 1".into()],
        listing,
        disassembly: None,
        limits: Vec::new(),
    };
    let metadata: Vec<AnalysisEntry> = ["type", "size"]
        .iter()
        .enumerate()
        .map(|(index, label)| AnalysisEntry {
            label: (*label).into(),
            value: format!("value {index}"),
            offset: None,
            record: Some(AnalysisRecord {
                revision: 1,
                id: index as u64 + 1,
                location: None,
                data: AnalysisData::Field {
                    group: "general".into(),
                },
            }),
        })
        .collect();
    let report = AnalysisReport {
        id: id.into(),
        state: AnalysisState::Complete,
        source_path: "/tmp/sample.sh".into(),
        specimen_sha256: Some(sample_sha()),
        specimen_len: Some(4096),
        reason: None,
        sections: vec![
            section(AnalysisKind::Metadata, metadata, None),
            section(
                AnalysisKind::Strings,
                Vec::new(),
                Some(AnalysisListing {
                    rows: 3,
                    bytes: listing_bytes,
                    truncated: false,
                }),
            ),
        ],
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    };
    fs::write(
        dir.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
}

/// The calls of the standard fixture: a launch, a read and a write of a path
/// in a child process.
pub fn standard_calls() -> Vec<Call> {
    vec![
        Call {
            id: 1,
            pid: 100,
            nr: 59,
            result: 0,
            path: Some(b"/tmp/sample.sh"),
        },
        Call {
            id: 2,
            pid: 100,
            nr: 257,
            result: 3,
            path: Some(b"/etc/passwd"),
        },
        Call {
            id: 3,
            pid: 100,
            nr: 0,
            result: 120,
            path: None,
        },
        Call {
            id: 4,
            pid: 101,
            nr: 1,
            result: 5,
            path: None,
        },
        Call {
            id: 5,
            pid: 101,
            nr: 257,
            result: -2,
            path: Some(b"/etc/shadow"),
        },
    ]
}

/// The standard finished run: trace, terminal, captures, a core, analysis.
pub fn standard(data: &Data) -> Run {
    let run = add_run(data, "boot-1", "run-1", 1_700_000_000_000, "Finalized");
    write_trace(&run, &standard_calls());
    write_terminal(&run);
    write_artifacts(data, &run);
    write_analysis(&run.dir.join("analysis"), "analysis-1");
    run
}

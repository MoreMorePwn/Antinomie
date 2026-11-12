// SPDX-License-Identifier: GPL-3.0-only
//! Synthetic recordings with chosen calls, for the statistics tests of this
//! crate and, through the `test-support` feature, of the window.
//!
//! A [`Fixture`] is a run folder in the temp directory holding a
//! `telemetry.raw` of ANTT packets (the format of `parser::parse_packet`) and a
//! `manifest.json`. Every call has its own number, timestamps, result, process,
//! thread and root, so a test can state exactly what the counts must be.
//! Numbers are x86-64 unless the manifest says another guest.
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// x86-64 call numbers the tests use.
pub mod nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const OPEN: u64 = 2;
    pub const CLOSE: u64 = 3;
    pub const MMAP: u64 = 9;
    pub const GETPID: u64 = 39;
    pub const CONNECT: u64 = 42;
    pub const NANOSLEEP: u64 = 35;
    pub const CLONE: u64 = 56;
    pub const EXECVE: u64 = 59;
    pub const WAIT4: u64 = 61;
    pub const FLOCK: u64 = 73;
    pub const FUTEX: u64 = 202;
    pub const EXIT_GROUP: u64 = 231;
    pub const OPENAT: u64 = 257;
    pub const NEWFSTATAT: u64 = 262;
    pub const IO_URING_ENTER: u64 = 426;
}

/// One call of a fixture.
#[derive(Clone, Debug)]
pub struct Call {
    pub nr: u64,
    pub pid: u32,
    pub tid: u32,
    /// The run's root task cookie the packets carry.
    pub root: u64,
    pub entry_ns: u64,
    /// `None`: the exit never arrived.
    pub exit_ns: Option<u64>,
    /// The exit's result; `None` with an exit means the exit carries none.
    pub result: Option<i64>,
    pub args: [u64; 6],
}

impl Call {
    /// A call of process and thread `tid`, root 55, entry at 1,000 ns, an exit
    /// 100 ns later that returned 0.
    pub fn new(nr: u64, tid: u32) -> Self {
        Self {
            nr,
            pid: tid,
            tid,
            root: ROOT,
            entry_ns: 1_000,
            exit_ns: Some(1_100),
            result: Some(0),
            args: [0; 6],
        }
    }

    /// Move the call to `entry_ns` with the given duration (an unfinished call stays so).
    pub fn at(mut self, entry_ns: u64, duration_ns: u64) -> Self {
        self.entry_ns = entry_ns;
        self.exit_ns = self.exit_ns.map(|_| entry_ns + duration_ns);
        self
    }

    pub fn returns(mut self, result: i64) -> Self {
        self.result = Some(result);
        self
    }

    pub fn fails(self, errno: i64) -> Self {
        self.returns(-errno)
    }

    /// The exit never arrived.
    pub fn unfinished(mut self) -> Self {
        self.exit_ns = None;
        self.result = None;
        self
    }

    pub fn pid(mut self, pid: u32) -> Self {
        self.pid = pid;
        self
    }

    pub fn root(mut self, root: u64) -> Self {
        self.root = root;
        self
    }

    pub fn args(mut self, args: [u64; 6]) -> Self {
        self.args = args;
        self
    }
}

/// The root the fixture calls belong to unless a test says otherwise.
pub const ROOT: u64 = 55;

/// A run folder in the temp directory; removed when dropped.
pub struct Fixture {
    pub directory: PathBuf,
}

static NEXT: AtomicU64 = AtomicU64::new(0);

impl Fixture {
    /// A folder holding `calls` and an empty-object manifest.
    pub fn new(calls: &[Call]) -> Self {
        Self::with_manifest(calls, json!({"format": "ANTT run raw LE32"}))
    }

    pub fn with_manifest(calls: &[Call], manifest: Value) -> Self {
        let fixture = Self::empty();
        let mut raw = std::fs::File::create(fixture.directory.join("telemetry.raw")).unwrap();
        write_calls(&mut raw, calls);
        raw.sync_all().unwrap();
        fixture.write_manifest(&manifest);
        fixture
    }

    /// A folder with no files in it.
    pub fn empty() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "antinomie-stats-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&directory).unwrap();
        Self { directory }
    }

    pub fn write_manifest(&self, manifest: &Value) {
        std::fs::write(
            self.directory.join("manifest.json"),
            serde_json::to_vec(manifest).unwrap(),
        )
        .unwrap();
    }

    pub fn raw_path(&self) -> PathBuf {
        self.directory.join("telemetry.raw")
    }

    pub fn path(&self) -> &Path {
        &self.directory
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// Append the packets of `calls` (entry, then exit) to `raw`. Call ids count
/// from 0 in the order given; the task cookie is the thread id.
pub fn write_calls(raw: &mut dyn Write, calls: &[Call]) {
    let mut packet_seq = 0_u64;
    for (id, call) in calls.iter().enumerate() {
        let phases = [(1_u8, call.entry_ns, false)]
            .into_iter()
            .chain(call.exit_ns.map(|ns| (2_u8, ns, true)));
        for (phase, timestamp, exit) in phases {
            for fragment in [1_u8, 5] {
                packet_seq += 1;
                let mut body = vec![0_u8; if fragment == 1 { 120 } else { 32 }];
                if fragment == 1 {
                    for (i, word) in call.args.iter().enumerate() {
                        body[i * 8..i * 8 + 8].copy_from_slice(&word.to_le_bytes());
                    }
                    if let (true, Some(result)) = (exit, call.result) {
                        body[49] = 1;
                        body[56..64].copy_from_slice(&result.to_le_bytes());
                    }
                }
                let mut packet = vec![0_u8; 136];
                packet[..4].copy_from_slice(b"ANTT");
                packet[4..6].copy_from_slice(&1_u16.to_le_bytes());
                packet[6..8].copy_from_slice(&1_u16.to_le_bytes());
                packet[8..10].copy_from_slice(&136_u16.to_le_bytes());
                packet[10..12].copy_from_slice(&1_u16.to_le_bytes());
                packet[12..16].copy_from_slice(&(136 + body.len() as u32).to_le_bytes());
                packet[20..24].copy_from_slice(&1_u32.to_le_bytes());
                packet[24..32].copy_from_slice(&1_u64.to_le_bytes());
                packet[32..40].copy_from_slice(&u64::from(call.tid).to_le_bytes());
                packet[40..48].copy_from_slice(&(id as u64).to_le_bytes());
                packet[48..56].copy_from_slice(&(id as u64 * 2 + u64::from(phase)).to_le_bytes());
                packet[56..64].copy_from_slice(&packet_seq.to_le_bytes());
                packet[64..72].copy_from_slice(&timestamp.to_le_bytes());
                packet[72..76].copy_from_slice(&call.pid.to_le_bytes());
                packet[76..80].copy_from_slice(&call.tid.to_le_bytes());
                packet[88..96].copy_from_slice(&call.nr.to_le_bytes());
                packet[96..98].copy_from_slice(&1_u16.to_le_bytes());
                packet[98] = phase;
                packet[99] = fragment;
                packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
                packet[128..136].copy_from_slice(&call.root.to_le_bytes());
                packet.extend(body);
                raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
                raw.write_all(&packet).unwrap();
            }
        }
    }
}

/// A call built in memory, without a recording: for the aggregator's own tests.
pub fn summary(
    name: &str,
    nr: u64,
    tid: u32,
    entry_ns: u64,
    duration_ns: Option<u64>,
    result: Option<i64>,
) -> antinomie_monitor_core::InvocationSummary {
    use antinomie_monitor_core::{EventSummary, InvocationSummary};
    let event = |phase: u8, timestamp_ns: u64, result: Option<i64>| EventSummary {
        root_task_cookie: ROOT,
        stream_id: 1,
        task_cookie: u64::from(tid),
        call_id: entry_ns,
        event_seq: u64::from(phase),
        phase,
        syscall_nr: nr,
        syscall_name: name.to_owned(),
        pid: tid,
        tid,
        cpu: 0,
        timestamp_ns,
        args: Some([0; 6]),
        result,
        complete: true,
        issues: Vec::new(),
        fields: Vec::new(),
    };
    InvocationSummary {
        stream_id: 1,
        task_cookie: u64::from(tid),
        call_id: entry_ns,
        entry: Some(event(1, entry_ns, None)),
        exit: duration_ns.map(|d| event(2, entry_ns + d, result)),
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
        kernel_notes: Vec::new(),
    }
}

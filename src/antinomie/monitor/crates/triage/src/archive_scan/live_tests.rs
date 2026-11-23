// SPDX-License-Identifier: GPL-3.0-only
//! A live run refreshed from its snapshot is what a full scan of the same
//! recording makes (ANT-T0602): at a call whose exit arrives later, at a call
//! that gains a record after the snapshot, and across a transport reconnect.
use super::*;
use std::io::Write;

const MMAP: u64 = 9;
const NANOSLEEP: u64 = 35;
const ROOT: u64 = 55;
const MAP_FLAGS: u64 = 0x22;

/// One call of a fixture: who made it, its number, id and time.
#[derive(Clone, Copy)]
struct Call {
    nr: u64,
    tid: u32,
    id: u64,
    ns: u64,
}

impl Call {
    /// An anonymous read-write-execute mapping (a finding row) by `tid`.
    fn rwx(tid: u32, id: u64) -> Self {
        Self {
            nr: MMAP,
            tid,
            id,
            ns: 1_000_000 + id * 1_000,
        }
    }

    fn sleep(tid: u32, id: u64) -> Self {
        Self {
            nr: NANOSLEEP,
            ..Self::rwx(tid, id)
        }
    }
}

/// A growing `telemetry.raw`.
struct Raw {
    file: std::fs::File,
    seq: u64,
}

impl Raw {
    fn open(directory: &Path) -> Self {
        std::fs::create_dir_all(directory).unwrap();
        Self {
            file: std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(directory.join("telemetry.raw"))
                .unwrap(),
            seq: 0,
        }
    }

    /// The two fragments of one record of `call`: phase 1 entry, 2 exit, 3
    /// an async observation numbered `event`.
    fn record(&mut self, call: Call, phase: u8, event: u64) {
        for fragment in [1u8, 5] {
            self.seq += 1;
            let mut body = vec![0u8; if fragment == 1 { 120 } else { 32 }];
            if fragment == 1 && call.nr == MMAP {
                body[8..16].copy_from_slice(&4096u64.to_le_bytes());
                body[16..24].copy_from_slice(&7u64.to_le_bytes());
                body[24..32].copy_from_slice(&MAP_FLAGS.to_le_bytes());
            }
            if fragment == 1 && phase == 2 {
                let result: i64 = if call.nr == MMAP { 0x7f00_0000 } else { 0 };
                body[49] = 1;
                body[56..64].copy_from_slice(&result.to_le_bytes());
            }
            let ns = call.ns + if phase == 1 { 0 } else { 500 + event };
            let mut packet = vec![0u8; 136];
            packet[..4].copy_from_slice(b"ANTT");
            packet[4..6].copy_from_slice(&1u16.to_le_bytes());
            packet[6..8].copy_from_slice(&1u16.to_le_bytes());
            packet[8..10].copy_from_slice(&136u16.to_le_bytes());
            packet[10..12].copy_from_slice(&1u16.to_le_bytes());
            packet[12..16].copy_from_slice(&(136 + body.len() as u32).to_le_bytes());
            packet[20..24].copy_from_slice(&1u32.to_le_bytes());
            packet[24..32].copy_from_slice(&1u64.to_le_bytes());
            packet[32..40].copy_from_slice(&u64::from(call.tid).to_le_bytes());
            packet[40..48].copy_from_slice(&call.id.to_le_bytes());
            let event_seq = if phase == 3 {
                event
            } else {
                call.id * 2 + u64::from(phase)
            };
            packet[48..56].copy_from_slice(&event_seq.to_le_bytes());
            packet[56..64].copy_from_slice(&self.seq.to_le_bytes());
            packet[64..72].copy_from_slice(&ns.to_le_bytes());
            packet[72..76].copy_from_slice(&call.tid.to_le_bytes());
            packet[76..80].copy_from_slice(&call.tid.to_le_bytes());
            packet[88..96].copy_from_slice(&call.nr.to_le_bytes());
            packet[96..98].copy_from_slice(&1u16.to_le_bytes());
            packet[98] = phase;
            packet[99] = fragment;
            packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
            packet[128..136].copy_from_slice(&ROOT.to_le_bytes());
            packet.extend(body);
            self.file
                .write_all(&(packet.len() as u32).to_le_bytes())
                .unwrap();
            self.file.write_all(&packet).unwrap();
        }
        self.file.flush().unwrap();
    }

    fn entry(&mut self, call: Call) {
        self.record(call, 1, 0);
    }

    fn exit(&mut self, call: Call) {
        self.record(call, 2, 0);
    }

    fn whole(&mut self, calls: impl IntoIterator<Item = Call>) {
        for call in calls {
            self.entry(call);
            self.exit(call);
        }
    }
}

fn request(identity: Option<(String, String, String)>) -> ScanRequest {
    ScanRequest {
        root_cookie: ROOT,
        keep_index: true,
        page_rows: 100,
        identity,
        ..ScanRequest::default()
    }
}

fn resumes() -> u64 {
    live::RESUMES.with(std::cell::Cell::get)
}

/// Refresh `directory` as the window does and check the answer against a
/// full scan of the same bytes; whether the refresh resumed a snapshot.
fn refresh_and_compare(directory: &Path, request: &ScanRequest) -> (ArchiveScan, bool) {
    let cancel = Arc::new(AtomicBool::new(false));
    let before = resumes();
    let refreshed = scan_archive_query(directory, None, false, &cancel, request).unwrap();
    let resumed = resumes() > before;
    let mut plain = request.clone();
    plain.keep_index = false;
    let full = scan_archive_uncached(directory, None, false, &cancel, &plain).unwrap();
    let differences = requery::differences(&refreshed, &full);
    assert!(differences.is_empty(), "{differences:?}");
    assert_eq!(refreshed.counts.calls, full.counts.calls);
    assert_eq!(refreshed.process.len(), full.process.len());
    (refreshed, resumed)
}

fn temp(tag: &str) -> PacketSpool {
    let spool = PacketSpool::new().unwrap();
    std::fs::create_dir_all(spool.directory.join(tag)).unwrap();
    spool
}

#[test]
fn a_call_whose_exit_arrives_later_is_read_again_from_the_snapshot() {
    let spool = temp("run");
    let directory = spool.directory.join("run");
    let mut raw = Raw::open(&directory);
    let request = request(None);
    // A task sleeps through the first refresh while another maps memory.
    let sleeper = Call::sleep(2, 1000);
    raw.entry(sleeper);
    raw.whole((0..40).map(|id| Call::rwx(1, id)));
    let (first, resumed) = refresh_and_compare(&directory, &request);
    assert!(!resumed, "the first scan has no snapshot");
    assert!(first.counts.findings > 0);
    // Its exit arrives, more calls, and a third task starts sleeping.
    raw.exit(sleeper);
    raw.whole((40..80).map(|id| Call::rwx(1, id)));
    let second_sleeper = Call::sleep(3, 2000);
    raw.entry(second_sleeper);
    raw.whole((80..90).map(|id| Call::rwx(4, id)));
    let (second, resumed) = refresh_and_compare(&directory, &request);
    assert!(resumed, "the refresh starts at the sleeping call");
    assert_eq!(second.counts.calls, 92);
    raw.exit(second_sleeper);
    raw.whole((90..130).map(|id| Call::rwx(5, id)));
    let (third, resumed) = refresh_and_compare(&directory, &request);
    assert!(resumed);
    assert_eq!(third.counts.calls, 132);
    // A refresh of an unchanged recording is answered from the kept rows.
    let (_, resumed) = refresh_and_compare(&directory, &request);
    assert!(!resumed);
    // The snapshot is still there for the next growth.
    raw.whole((130..140).map(|id| Call::rwx(5, id)));
    let (_, resumed) = refresh_and_compare(&directory, &request);
    assert!(resumed);
}

#[test]
fn a_record_added_to_a_call_before_the_snapshot_makes_a_full_scan() {
    let spool = temp("run");
    let directory = spool.directory.join("run");
    let mut raw = Raw::open(&directory);
    let request = request(None);
    raw.whole((0..30).map(|id| Call::rwx(1, id)));
    let sleeper = Call::sleep(2, 1000);
    raw.entry(sleeper);
    refresh_and_compare(&directory, &request);
    // An async observation of call 5 arrives after the snapshot was taken.
    raw.record(Call::rwx(1, 5), 3, 9_000);
    raw.exit(sleeper);
    raw.whole((30..40).map(|id| Call::rwx(1, id)));
    raw.entry(Call::sleep(3, 2000));
    let recording = antinomie_monitor_core::recording::Recording::raw(&directory);
    let cancel = AtomicBool::new(false);
    assert!(
        recording
            .growth_since(0, &cancel)
            .unwrap()
            .earliest_changed
            .is_none(),
        "nothing began before offset 0"
    );
    let (_, resumed) = refresh_and_compare(&directory, &request);
    assert!(!resumed, "a call before the snapshot changed");
    // The full scan kept a new snapshot, and the next refresh resumes it.
    raw.whole((40..60).map(|id| Call::rwx(1, id)));
    let (_, resumed) = refresh_and_compare(&directory, &request);
    assert!(resumed);
}

#[test]
fn the_growth_of_an_index_names_the_earliest_call_that_changed() {
    let spool = temp("run");
    let directory = spool.directory.join("run");
    let mut raw = Raw::open(&directory);
    raw.whole((0..10).map(|id| Call::rwx(1, id)));
    let open = Call::sleep(2, 100);
    raw.entry(open);
    let recording = antinomie_monitor_core::recording::Recording::raw(&directory);
    let cancel = AtomicBool::new(false);
    let (identity, boundary) = recording.indexed_extent(&cancel).unwrap();
    let unchanged = recording.growth_since(boundary, &cancel).unwrap();
    assert_eq!(unchanged.boundary, boundary);
    assert_eq!(unchanged.earliest_changed, None);
    raw.whole((10..20).map(|id| Call::rwx(1, id)));
    let grown = recording.growth_since(boundary, &cancel).unwrap();
    assert_eq!(grown.identity, identity);
    assert!(grown.boundary > boundary);
    assert_eq!(grown.earliest_changed, None, "only new calls");
    raw.exit(open);
    raw.record(Call::rwx(1, 3), 3, 7_000);
    let changed = recording.growth_since(boundary, &cancel).unwrap();
    let third = recording.call_offset((1, 1, 3), &cancel).unwrap().unwrap();
    assert_eq!(changed.earliest_changed, Some(third));
    let sleeping = recording
        .call_offset((1, 2, 100), &cancel)
        .unwrap()
        .unwrap();
    assert!(third < sleeping);
}

/// A run record of segment `boot` that names the segments before it.
fn write_segment(directory: &Path, boot: &str, segment: u32) {
    std::fs::create_dir_all(directory).unwrap();
    let notes: Vec<String> = (2..=segment)
        .map(|at| {
            format!(
                "Recording continues after a transport reconnect (recording segment {at}); the earlier part is kept in the recording of boot x"
            )
        })
        .collect();
    let summary = serde_json::json!({
        "id": "run", "vm_id": "vm", "boot_id": boot, "session_id": 1,
        "root_task_cookie": ROOT, "pid": 1,
        "request": antinomie_monitor_core::ExecRequest::default(),
        "directory": directory, "terminal_eof": false, "state": "Finished",
        "recording_error": null, "notes": notes,
    });
    std::fs::write(directory.join("run.json"), summary.to_string()).unwrap();
    let manifest = serde_json::json!({"run": {"id": "run", "vm_id": "vm", "boot_id": boot}});
    std::fs::write(directory.join("manifest.json"), manifest.to_string()).unwrap();
}

#[test]
fn a_transport_reconnect_is_read_whole_then_refreshed_from_the_new_segment() {
    let spool = temp("rec");
    let root = spool.directory.join("rec");
    let first = root.join("runs/run");
    write_segment(&first, "boot-a", 1);
    let mut raw = Raw::open(&first);
    let identity = |boot: &str| Some(("vm".to_owned(), boot.to_owned(), "run".to_owned()));
    raw.whole((0..20).map(|id| Call::rwx(1, id)));
    let sleeper = Call::sleep(2, 1000);
    raw.entry(sleeper);
    let (_, resumed) = refresh_and_compare(&first, &request(identity("boot-a")));
    assert!(!resumed);
    raw.whole((20..30).map(|id| Call::rwx(1, id)));
    let (_, resumed) = refresh_and_compare(&first, &request(identity("boot-a")));
    assert!(resumed);
    // The transport reconnects: the first segment's last records arrive and
    // the run goes on in a new boot's segment.
    raw.exit(sleeper);
    let second = root.join("boots/boot-b/runs/run");
    write_segment(&second, "boot-b", 2);
    std::fs::write(
        root.join("boots/boot-b/resume-boundary.json"),
        serde_json::json!({"format":1,"snapshot_id":null,"source_boot_id":"boot-a","boot_id":"boot-b"})
            .to_string(),
    )
    .unwrap();
    let mut next = Raw::open(&second);
    next.whole((100..120).map(|id| Call::rwx(1, id)));
    next.entry(Call::sleep(3, 3000));
    let later = request(identity("boot-b"));
    let (both, resumed) = refresh_and_compare(&second, &later);
    assert!(!resumed, "another segment list is read whole");
    assert_eq!(both.counts.calls, 52);
    next.whole((120..140).map(|id| Call::rwx(1, id)));
    let (_, resumed) = refresh_and_compare(&second, &later);
    assert!(resumed, "the newest segment grew");
    // A sealed segment that still grows voids the snapshot.
    raw.whole((30..35).map(|id| Call::rwx(1, id)));
    let (_, resumed) = refresh_and_compare(&second, &later);
    assert!(!resumed);
}

#[test]
fn a_cloned_state_goes_on_as_the_original_does() {
    // Pass 2's state cloned in the middle of a run, both continued with the
    // same calls, ends the same: the engine's rows, the files and the counts.
    let spool = temp("run");
    let directory = spool.directory.join("run");
    let mut raw = Raw::open(&directory);
    raw.whole((0..20).map(|id| Call::rwx(1, id)));
    let cancel = Arc::new(AtomicBool::new(false));
    let request = request(None);
    let mut scan = stages::open_scan(&directory, None, false, &cancel, &request).unwrap();
    let recording = antinomie_monitor_core::recording::Recording::raw(&directory);
    let page = recording
        .invocation_page_cancellable(0, 256, &cancel)
        .unwrap();
    let mut state = file_pass::FileState::new(
        std::mem::take(&mut scan.files),
        rules::Engine::new(Default::default()),
        scan.counts.clone(),
        &request,
    );
    let (mut journal, mut error) = (None, None);
    let mut sinks = file_pass::Sinks {
        tabs: file_tabs::TabSink::new(&request, &cancel),
        read_page: None,
        read_query: query::compile_table("", FILE_FIELDS),
        event_journal: &mut journal,
        event_error: &mut error,
        pending: Vec::new(),
    };
    let (head, tail) = page.invocations.split_at(10);
    for call in head {
        state
            .walk_call(
                &mut sinks,
                &request,
                &scan.cookies,
                &recording,
                0,
                call,
                &cancel,
            )
            .unwrap();
    }
    let mut copy = state.clone();
    for call in tail {
        state
            .walk_call(
                &mut sinks,
                &request,
                &scan.cookies,
                &recording,
                0,
                call,
                &cancel,
            )
            .unwrap();
        copy.walk_call(
            &mut sinks,
            &request,
            &scan.cookies,
            &recording,
            0,
            call,
            &cancel,
        )
        .unwrap();
    }
    let rows = |state: file_pass::FileState| {
        let files = state.files;
        let output = state.engine.finish(&files);
        (
            output.badge,
            output.tiers,
            output
                .rows
                .iter()
                .map(|row| format!("{:?}|{:?}", row.key, row.values))
                .collect::<Vec<_>>(),
            state.counts.failed_attempts,
            files.process_images.len(),
        )
    };
    assert_eq!(rows(state), rows(copy));
}

#[test]
fn a_scan_whose_time_runs_out_is_a_marked_partial_result() {
    // ANT-T0612: Auto Triage's budget ends the passes and says so.
    let spool = temp("run");
    let directory = spool.directory.join("run");
    let mut raw = Raw::open(&directory);
    raw.whole((0..600).map(|id| Call::rwx(1 + (id % 7) as u32, id)));
    let mut request = request(None);
    request.keep_index = false;
    request.run_finished = true;
    request.stop = Some(Arc::new(scan_progress::ScanStop::triage(
        std::time::Duration::ZERO,
    )));
    let cancel = Arc::new(AtomicBool::new(false));
    let scan = scan_archive_query(&directory, None, false, &cancel, &request).unwrap();
    assert!(scan.budget_reached && scan.partial);
    assert!(
        scan.partial_reasons[0].starts_with("the time budget for Triage"),
        "{:?}",
        scan.partial_reasons
    );
    assert!(scan.counts.calls < 600);
}

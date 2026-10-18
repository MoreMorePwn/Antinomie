use super::*;
use crate::observation::CaptureScope;

struct Fixture {
    root: PathBuf,
    capture: RawCapture,
    assembler: Assembler,
    runs: BTreeMap<u64, ProgramRun>,
    captures: BTreeMap<String, CaptureSession>,
}

const QUOTA: u64 = 1 << 20;

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ant-saving-{}", storage::unique_id()));
        let capture = RawCapture::new(root.join("unassigned"), QUOTA).unwrap();
        let assembler = Assembler::new(capture.directory.join("objects"), QUOTA).unwrap();
        Self {
            root,
            capture,
            assembler,
            runs: BTreeMap::new(),
            captures: BTreeMap::new(),
        }
    }
    fn add_run(&mut self, cookie: u64, state: RunState, terminal_eof: bool) {
        let run = ProgramRun::new(
            RunSummary {
                started_ms: None,
                clock_anchor: None,
                id: cookie.to_string(),
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                session_id: cookie,
                root_task_cookie: cookie,
                pid: cookie as u32,
                request: ExecRequest::default(),
                directory: self.root.join(cookie.to_string()),
                terminal_eof,
                state,
                notes: Vec::new(),
                recording_error: None,
                execution: None,
                analysis: None,
            },
            QUOTA,
        )
        .unwrap();
        self.runs.insert(cookie, run);
    }
    fn add_capture(&mut self, id: &str, state: CaptureState) {
        let capture = CaptureSession::new(
            CaptureSummary {
                started_ms: None,
                id: id.into(),
                vm_id: "vm".into(),
                boot_id: "boot".into(),
                capture_cookie: 17,
                scope: CaptureScope::AllUserspace,
                directory: self.root.join(id),
                state,
                recording_error: None,
                start_ns: None,
                stop_ns: None,
                incomplete_reason: None,
            },
            QUOTA,
        )
        .unwrap();
        self.captures.insert(id.into(), capture);
    }
    fn sinks(&mut self) -> Sinks<'_> {
        Sinks {
            capture: &mut self.capture,
            assembler: &mut self.assembler,
            runs: &mut self.runs,
            captures: &mut self.captures,
        }
    }
    fn finish(mut self) {
        self.runs.clear();
        self.captures.clear();
        drop(self.capture);
        crate::writer::barrier();
        storage::settle_json_under(&self.root);
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn saved_terminal(run: &ProgramRun) -> u64 {
    fs::metadata(run.summary.directory.join("terminal.journal"))
        .unwrap()
        .len()
}

#[test]
fn reaching_the_quota_stops_open_recordings_and_leaves_complete_runs_intact() {
    let mut fixture = Fixture::new();
    fixture.add_run(1, RunState::Finished, true);
    fixture.add_run(2, RunState::Running, false);
    fixture.add_capture("active", CaptureState::Active);
    fixture.add_capture("closed", CaptureState::Finalized);
    fixture
        .runs
        .get_mut(&1)
        .unwrap()
        .output(b"done", 4096)
        .unwrap();
    let finished_journal = saved_terminal(&fixture.runs[&1]);
    let mut state = QuotaState::default();

    fixture.sinks().quota_reached(&mut state, QUOTA, 2);

    let message = crate::quota::message(QUOTA);
    assert_eq!(state.reached.as_deref(), Some(message.as_str()));
    // The finished run is not marked failed, and still finalizes cleanly.
    let finished = fixture.runs.get_mut(&1).unwrap();
    assert!(finished.summary.recording_error.is_none());
    assert!(finished.capture.error.is_none());
    assert!(finished.summary.notes.is_empty());
    finished
        .finalize(4096, "clean", &Health::default())
        .unwrap();
    assert_eq!(saved_terminal(finished), finished_journal);
    let manifest: serde_json::Value = serde_json::from_reader(
        File::open(finished.summary.directory.join("manifest.json")).unwrap(),
    )
    .unwrap();
    assert!(manifest["persistence_error"].is_null());
    // Open recordings stop with the one clear message.
    assert_eq!(
        fixture.runs[&2].summary.recording_error.as_deref(),
        Some(message.as_str())
    );
    assert_eq!(fixture.capture.error.as_deref(), Some(message.as_str()));
    assert_eq!(
        fixture.captures["active"]
            .summary
            .recording_error
            .as_deref(),
        Some(message.as_str())
    );
    // A closed capture archive is left as it is.
    assert!(fixture.captures["closed"].summary.recording_error.is_none());
    assert!(fixture.captures["closed"].capture.error.is_none());
    // The open run keeps what it saved; new terminal output is refused with the cause.
    let error = fixture
        .runs
        .get_mut(&2)
        .unwrap()
        .output(b"more", 4096)
        .unwrap_err();
    assert!(error.contains("recording quota"), "{error}");
    fixture.finish();
}

#[test]
fn a_late_packet_of_a_complete_run_is_noted_once_and_never_fails_it() {
    let mut fixture = Fixture::new();
    fixture.add_run(1, RunState::Stopped, true);
    let mut state = QuotaState::default();
    for _ in 0..3 {
        fixture.sinks().quota_reached(&mut state, QUOTA, 1);
    }
    let run = &fixture.runs[&1];
    assert!(run.summary.recording_error.is_none());
    assert_eq!(run.summary.notes.len(), 1);
    assert!(run.summary.notes[0].contains("recording quota"));
    // The first message stays: reaching the quota again does not rewrite it.
    let first = state.reached.clone();
    fixture.sinks().quota_reached(&mut state, 2 * QUOTA, 0);
    assert_eq!(state.reached, first);
    fixture.finish();
}

#[test]
fn another_failure_of_the_boot_does_not_fail_a_complete_run_either() {
    let mut fixture = Fixture::new();
    fixture.add_run(1, RunState::Finished, true);
    fixture.add_run(2, RunState::TerminalClosed, true);
    fixture.add_run(3, RunState::Running, false);
    fixture.sinks().stop_saving("write failed".into());
    assert!(fixture.runs[&1].summary.recording_error.is_none());
    // A closed terminal alone does not prove the program tree ended.
    assert_eq!(
        fixture.runs[&2].summary.recording_error.as_deref(),
        Some("write failed")
    );
    assert_eq!(
        fixture.runs[&3].summary.recording_error.as_deref(),
        Some("write failed")
    );
    fixture.finish();
}

#[test]
fn quota_refusals_of_the_raw_archive_use_the_shared_message() {
    let fixture = Fixture::new();
    let mut tiny = RawCapture::new(fixture.root.join("tiny"), 8).unwrap();
    assert!(!tiny.append(b"too long for eight bytes"));
    let error = tiny.error.clone().unwrap();
    assert_eq!(error, crate::quota::message(8));
    assert!(crate::quota::is_quota_error(&error));
    drop(tiny);
    fixture.finish();
}

#[test]
fn a_terminal_failure_stops_only_its_own_run() {
    let mut fixture = Fixture::new();
    fixture.add_run(1, RunState::Running, false);
    fixture.add_run(2, RunState::Running, false);
    let failed = fixture.runs.get_mut(&1).unwrap();
    let failure = terminal_failure(failed, "terminal persistence failed: disk".into());
    assert_eq!(
        failure,
        TerminalFailure::RunOnly("terminal persistence failed: disk".into())
    );
    // The neighbour, the boot archive and the captures keep recording.
    let neighbour = fixture.runs.get_mut(&2).unwrap();
    assert!(neighbour.summary.recording_error.is_none());
    neighbour.output(b"still recorded", 4096).unwrap();
    assert!(saved_terminal(neighbour) > 0);
    assert!(fixture.capture.error.is_none());
    assert!(fixture.capture.append(b"packet"));
    fixture.finish();
}

#[test]
fn the_first_cause_of_a_run_is_kept_when_later_writes_report_already_stopped() {
    let mut fixture = Fixture::new();
    fixture.add_run(1, RunState::Running, false);
    let run = fixture.runs.get_mut(&1).unwrap();
    run.storage_error("terminal persistence failed: disk");
    let refusal = run.output(b"x", 4096).unwrap_err();
    assert!(
        refusal.starts_with("run saving already stopped"),
        "{refusal}"
    );
    assert!(refusal.contains("disk"), "{refusal}");
    let failure = terminal_failure(run, refusal);
    assert_eq!(
        failure,
        TerminalFailure::RunOnly("terminal persistence failed: disk".into())
    );
    fixture.finish();
}

#[test]
fn a_quota_failure_of_a_terminal_is_reported_as_the_boot_quota() {
    let mut fixture = Fixture::new();
    fixture.add_run(1, RunState::Running, false);
    let run = fixture.runs.get_mut(&1).unwrap();
    let error = run.output(&[0; 64], 8).unwrap_err();
    assert!(matches!(
        terminal_failure(run, error),
        TerminalFailure::Quota(_)
    ));
    fixture.finish();
}

fn packet(len: usize) -> Vec<u8> {
    vec![7; len]
}

#[test]
fn an_observing_capture_holds_unowned_packets_so_they_are_saved_once() {
    let mut fixture = Fixture::new();
    fixture.add_capture("observer", CaptureState::Active);
    for _ in 0..100 {
        let reserved = fixture.capture.bytes + fixture.captures["observer"].stored_len();
        let held = held_by_capture(false, fixture.captures.get("observer"));
        assert!(held);
        let stored = save_unowned(
            &mut fixture.capture,
            &mut fixture.assembler,
            held,
            &packet(236),
            reserved,
        );
        assert!(!stored, "the unassigned archive does not store it again");
        let observer = fixture.captures.get_mut("observer").unwrap();
        assert!(
            observer
                .capture
                .append_with_reserved(&packet(236), reserved)
        );
    }
    assert_eq!(fixture.capture.bytes, 0);
    assert_eq!(fixture.captures["observer"].capture.bytes, 100 * 240);
    // Without an observer the unassigned archive keeps the packet, as before.
    let held = held_by_capture(false, None);
    assert!(!held);
    assert!(save_unowned(
        &mut fixture.capture,
        &mut fixture.assembler,
        held,
        &packet(236),
        0
    ));
    assert_eq!(fixture.capture.bytes, 240);
    fixture.finish();
}

#[test]
fn a_capture_that_cannot_save_or_a_run_owned_packet_is_not_held() {
    let mut fixture = Fixture::new();
    fixture.add_capture("observer", CaptureState::Active);
    assert!(held_by_capture(false, fixture.captures.get("observer")));
    // A run keeps its own copy of the packets it owns.
    assert!(!held_by_capture(true, fixture.captures.get("observer")));
    fixture
        .captures
        .get_mut("observer")
        .unwrap()
        .storage_error("write failed");
    assert!(!held_by_capture(false, fixture.captures.get("observer")));
    // The boot archive then saves what the capture no longer can.
    let held = held_by_capture(false, fixture.captures.get("observer"));
    assert!(save_unowned(
        &mut fixture.capture,
        &mut fixture.assembler,
        held,
        &packet(236),
        0
    ));
    assert_eq!(fixture.capture.bytes, 240);
    fixture.finish();
}

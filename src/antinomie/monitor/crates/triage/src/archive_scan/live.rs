// SPDX-License-Identifier: GPL-3.0-only
//! The incremental refresh of a run that is still being recorded (ANT-T0602).
//!
//! A live run's recording only grows. A scan of one keeps a snapshot of its
//! two passes over the calls, taken before the first call that may still
//! change (a call whose exit has not arrived), and where that call is. The next
//! refresh of the run, when only the recording grew and no call before the
//! snapshot gained a record, starts both passes from the snapshot and reads the
//! calls from there on; the network pass and the settling run in full, and the
//! tables are made from the kept rows ([`crate::requery`]) as a filter change
//! makes them. The answer is the one a full scan of the same recording makes:
//! the tests and the verify harness (`timing.rs`, `ANT_TIMING_MODE=live`)
//! compare the two after every step.
//!
//! Anything that could make the snapshot differ from a full scan's prefix
//! voids it, and the refresh is a full scan: another request, another file,
//! a call before the snapshot that gained a record (its exit, its task's end,
//! an async observation), new requests of a ring read before it, or a fact of
//! the whole recording that the prefix looked up (a task's settled parent, a
//! pid's task cookie) and that the grown recording answers differently.
use super::*;
use antinomie_monitor_core::recording::Recording;
use file_pass::FileState;
use std::sync::Mutex;

/// The error of a scan whose snapshot did not hold once it was read further:
/// the scan starts again and reads the recording whole.
pub const RESTART: &str = "live refresh: the snapshot does not hold";

/// A call's identity in the index: stream, task cookie and call id.
pub type CallKey = (u64, u64, u64);

/// Where a snapshot stands in the walk over the calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// Before call `key` of segment `.0`: the first call that may still change.
    Before(usize, CallKey),
    /// After call `key` of segment `.0`, the last call the walk read.
    After(usize, CallKey),
}

impl Mark {
    fn segment(self) -> usize {
        match self {
            Self::Before(segment, _) | Self::After(segment, _) => segment,
        }
    }
}

/// Pass 1 (processes, task cookies, the launch) between two calls.
#[derive(Clone, Default)]
pub struct ProcessPass {
    /// The root's segment and stream, and its first credentials, for its launch.
    pub root_stream: Option<(usize, u64)>,
    pub root_creds: Option<antinomie_monitor_core::kernel_notes::Credentials>,
    pub root_call: Option<CallKey>,
    pub cookie_sets: std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>>,
    pub nodes: std::collections::BTreeMap<TaskKey, TaskNode>,
    pub scoped_count: u64,
    /// Calls whose saved async observations the pages only preview, and how many.
    pub async_partial: u64,
    pub async_omitted: u64,
    pub clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    /// Calls read, in or out of scope.
    pub seen: u64,
    pub issues: Vec<String>,
}

impl ProcessPass {
    /// The clock anchor from a page, when the run has none yet: the first page
    /// with a call names the guest time of the run's start.
    pub fn anchor(&mut self, started_ms: Option<u64>, page: &[&InvocationSummary]) {
        if self.clock_anchor.is_some() {
            return;
        }
        self.clock_anchor = started_ms
            .zip(
                page.iter()
                    .filter_map(|call| trace::representative(call))
                    .map(|event| event.timestamp_ns)
                    .min(),
            )
            .and_then(|(host_ms, guest_ns)| {
                Some(antinomie_monitor_core::HostClockAnchor {
                    guest_ns,
                    host_us: host_ms.checked_mul(1000)?,
                })
            });
    }

    /// One call of the run's scope.
    pub fn observe(&mut self, request: &ScanRequest, segment: usize, call: &InvocationSummary) {
        if request.root_cookie != 0 && call.task_cookie == request.root_cookie {
            self.root_stream.get_or_insert((segment, call.stream_id));
            self.root_call.get_or_insert(trace::key(call));
            if self.root_creds.is_none() {
                self.root_creds = call
                    .kernel_notes
                    .iter()
                    .find_map(antinomie_monitor_core::kernel_notes::credentials);
            }
        }
        self.scoped_count += 1;
        if call.async_omitted() > 0 {
            self.async_partial += 1;
            self.async_omitted = self.async_omitted.saturating_add(call.async_omitted());
        }
        let one = std::slice::from_ref(call);
        note_cookie_sets(&mut self.cookie_sets, one);
        observe_processes(&mut self.nodes, one);
    }
}

/// Why a snapshot was not resumed, on standard error with
/// `ANTINOMIE_LIVE_DEBUG` set (the tests and the verify harness).
pub fn why(reason: &str) {
    if std::env::var_os("ANTINOMIE_LIVE_DEBUG").is_some() {
        eprintln!("live refresh: {reason}");
    }
}

/// The clock anchor a full scan sets: from the first page that has a call
/// in scope, oldest segment first.
pub fn first_anchor(
    recordings: &[Recording],
    scoped: &impl Fn(&&InvocationSummary) -> bool,
    started_ms: Option<u64>,
    cancel: &AtomicBool,
    pass: &mut ProcessPass,
) {
    for recording in recordings {
        let mut offset = 0;
        loop {
            let Ok(page) = recording.invocation_page_cancellable(offset, 256, cancel) else {
                return;
            };
            let in_scope: Vec<&InvocationSummary> =
                page.invocations.iter().filter(scoped).collect();
            pass.anchor(started_ms, &in_scope);
            if pass.clock_anchor.is_some() {
                return;
            }
            match page.next_offset {
                Some(next) if next > offset => offset = next,
                _ => break,
            }
        }
    }
}

/// A call that may still gain records: its exit has not arrived and its task
/// has not ended.
pub fn in_flight(call: &InvocationSummary) -> bool {
    call.entry.is_some() && call.exit.is_none() && call.task_exit.is_none()
}

/// One recording segment as a scan found it before it read a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentMark {
    pub directory: std::path::PathBuf,
    pub identity: String,
    /// Bytes of its raw file the index held: every call the scan read was
    /// read with at least these packets.
    pub boundary: u64,
}

/// The extent of each segment's index now.
pub fn segment_marks(recordings: &[Recording], cancel: &AtomicBool) -> Option<Vec<SegmentMark>> {
    recordings
        .iter()
        .map(|recording| {
            let (identity, boundary) = recording.indexed_extent(cancel).ok()?;
            Some(SegmentMark {
                directory: recording.directory.clone(),
                identity,
                boundary,
            })
        })
        .collect()
}

/// What a refresh resumes from.
pub struct Snapshot {
    /// The run and the request facts the state depends on.
    pub key: String,
    /// What pass 1 settled that pass 2 reads besides the maps below.
    pub settled_facts: String,
    pub segments: Vec<SegmentMark>,
    pub mark: Mark,
    pub pass1: ProcessPass,
    pub pass2: FileState,
    /// The whole recording's task cookies and settled parents the prefix
    /// was read with.
    pub cookies: std::collections::BTreeMap<u32, u64>,
    pub settled: std::collections::BTreeMap<TaskKey, TaskKey>,
    pub tap: Arc<row_index::Tap>,
    pub tap_marks: Vec<row_index::LogMark>,
}

/// Snapshots kept: the live run on screen. The tests run in parallel and keep more.
const KEPT_RUNS: usize = if cfg!(test) { 32 } else { 1 };

/// The snapshots of the live runs refreshed last, newest last.
static KEPT: Mutex<Vec<Snapshot>> = Mutex::new(Vec::new());

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Refreshes this thread made from a snapshot, for the tests.
    pub static RESUMES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Drop the kept snapshots (the memory, or a test that starts over).
pub fn forget() {
    if let Ok(mut kept) = KEPT.lock() {
        kept.clear();
    }
}

fn keep(snapshot: Snapshot) {
    if let Ok(mut kept) = KEPT.lock() {
        kept.retain(|old| old.key != snapshot.key);
        kept.push(snapshot);
        let extra = kept.len().saturating_sub(KEPT_RUNS);
        kept.drain(..extra);
    }
}

/// A scan whose snapshot may serve the next refresh: one of a run still
/// being recorded that keeps its rows, reads the whole run and has no budget.
pub fn eligible(request: &ScanRequest) -> bool {
    request.keep_index
        && request.stop.is_none()
        && request.tap.is_none()
        && !request.run_finished
        && request.root_cookie != 0
        && std::env::var_os("ANTINOMIE_TRIAGE_NO_INCREMENTAL").is_none()
}

/// The run and the request facts the passes depend on: the source stamp
/// without the growing recording and capture, and the row index's facts.
pub fn key(
    directory: &Path,
    pcap: Option<&Path>,
    pcap_open: bool,
    request: &ScanRequest,
) -> String {
    let directory = std::fs::canonicalize(directory).unwrap_or_else(|_| directory.to_path_buf());
    let mut stamp = refresh::stamp_without_growth(&directory, pcap, pcap_open, request);
    stamp.push_str(&format!(
        "|dir={}|run={:?}|info={}|{}",
        directory.display(),
        request.identity,
        request.finding_view.show_info,
        row_index::facts(request)
    ));
    stamp
}

/// The plan of one scan: whether it resumes, and the snapshot it takes.
#[derive(Default)]
pub struct Plan {
    /// Take a snapshot for the next refresh.
    pub keep: bool,
    pub key: String,
    /// The snapshot this scan resumes from.
    pub resume: Option<Snapshot>,
    /// Where the walks start: segment and inclusive raw offset.
    pub start: (usize, u64),
    /// Each segment's index before the first call was read.
    pub segments: Vec<SegmentMark>,
    /// Decided by pass 1, taken by both passes.
    pub mark: Option<Mark>,
    pub pass1_at: Option<ProcessPass>,
    pub pass2_at: Option<(FileState, Vec<row_index::LogMark>)>,
    /// Pass 2 started from the snapshot: the tables are made from the rows.
    pub resumed: bool,
}

impl Plan {
    /// The plan of a scan made with `request`: a resume when a snapshot of
    /// the same run and request facts is kept.
    pub fn new(
        directory: &Path,
        pcap: Option<&Path>,
        pcap_open: bool,
        request: &ScanRequest,
    ) -> Self {
        if !eligible(request) {
            return Self::default();
        }
        let key = key(directory, pcap, pcap_open, request);
        let resume = KEPT.lock().ok().and_then(|mut kept| {
            let at = kept.iter().position(|snapshot| snapshot.key == key)?;
            Some(kept.remove(at))
        });
        Self {
            keep: true,
            key,
            resume,
            ..Self::default()
        }
    }

    pub fn resuming(&self) -> bool {
        self.resume.is_some()
    }

    /// The same plan for a scan of the whole recording, after the snapshot
    /// did not hold.
    pub fn restart(&mut self) {
        *self = Self {
            keep: self.keep,
            key: std::mem::take(&mut self.key),
            ..Self::default()
        };
    }

    /// A scan that ended before it used its snapshot (the recording was
    /// unchanged, or the scan was cancelled) leaves it for the next refresh.
    pub fn give_back(&mut self) {
        if let Some(snapshot) = self.resume.take() {
            keep(snapshot);
        }
    }

    /// Check the snapshot against the recording before a call is read: the
    /// same files, nothing changed before its mark. Sets where the walks start;
    /// a snapshot that does not hold is dropped and the scan reads it all.
    pub fn prepare(&mut self, recordings: &[Recording], cancel: &AtomicBool) {
        self.segments = if self.keep {
            segment_marks(recordings, cancel).unwrap_or_default()
        } else {
            Vec::new()
        };
        if self.keep && self.segments.len() != recordings.len() {
            self.keep = false;
        }
        let start = self
            .resume
            .as_ref()
            .and_then(|snapshot| resume_point(snapshot, recordings, cancel));
        match start {
            Some(start) => self.start = start,
            None => {
                self.resume = None;
                self.start = (0, 0);
            }
        }
    }

    /// Pass 1 is about to read `call`: decide the mark at the first call that
    /// may change. (The clock anchor is read from a whole page; a resumed
    /// pass checks the one it kept against the first page, see `open_scan`.)
    pub fn before_pass1(&mut self, pass: &ProcessPass, segment: usize, call: &InvocationSummary) {
        if self.keep && self.mark.is_none() && in_flight(call) {
            self.mark = Some(Mark::Before(segment, trace::key(call)));
            self.pass1_at = Some(pass.clone());
        }
    }

    /// Pass 1 read the whole recording and no call may change: the snapshot
    /// is after its last call.
    pub fn after_pass1(&mut self, pass: &ProcessPass, last: Option<(usize, CallKey)>) {
        if self.keep && self.mark.is_none() {
            if let Some((segment, key)) = last {
                self.mark = Some(Mark::After(segment, key));
                self.pass1_at = Some(pass.clone());
            }
        }
    }

    /// Whether pass 2 takes its snapshot before `call` of `segment`.
    pub fn takes_before(&self, segment: usize, call: &InvocationSummary) -> bool {
        self.pass2_at.is_none() && self.mark == Some(Mark::Before(segment, trace::key(call)))
    }

    /// Whether pass 2 takes its snapshot after `call` of `segment`.
    pub fn takes_after(&self, segment: usize, call: &InvocationSummary) -> bool {
        self.pass2_at.is_none() && self.mark == Some(Mark::After(segment, trace::key(call)))
    }

    /// Keep the snapshot this scan took, for the next refresh of the run.
    pub fn store(
        self,
        settled_facts: String,
        cookies: std::collections::BTreeMap<u32, u64>,
        settled: std::collections::BTreeMap<TaskKey, TaskKey>,
        tap: Option<&Arc<row_index::Tap>>,
    ) {
        if !self.keep {
            return;
        }
        let (Some(mark), Some(pass1), Some((pass2, tap_marks)), Some(tap)) =
            (self.mark, self.pass1_at, self.pass2_at, tap)
        else {
            why("no snapshot was taken (no mark, or a pass did not reach it)");
            return;
        };
        if tap.failed() || self.segments.is_empty() {
            why("no snapshot: the kept rows are void");
            return;
        }
        keep(Snapshot {
            key: self.key,
            settled_facts,
            segments: self.segments,
            mark,
            pass1,
            pass2,
            cookies,
            settled,
            tap: Arc::clone(tap),
            tap_marks,
        });
    }
}

/// Where both walks start from `snapshot` on `recordings`, or `None` when it
/// does not hold: another list of segments or file, a segment before the mark
/// that grew, a call before the mark that gained a record, or new requests of
/// a ring the prefix read.
fn resume_point(
    snapshot: &Snapshot,
    recordings: &[Recording],
    cancel: &AtomicBool,
) -> Option<(usize, u64)> {
    let marked = snapshot.mark.segment();
    if snapshot.segments.len() > recordings.len() || marked >= snapshot.segments.len() {
        why("another list of segments");
        return None;
    }
    let rings = &snapshot.pass2.attributed.read;
    for (at, (old, recording)) in snapshot.segments.iter().zip(recordings).enumerate() {
        if old.directory != recording.directory {
            why("another segment folder");
            return None;
        }
        if at > marked {
            // Read whole from its start.
            continue;
        }
        let Ok(growth) = recording.growth_since(old.boundary, cancel) else {
            why("the index could not say what grew");
            return None;
        };
        if growth.identity != old.identity || growth.boundary < old.boundary {
            why("another raw file, or a shorter one");
            return None;
        }
        if at < marked && growth.boundary != old.boundary {
            why("a segment before the snapshot grew");
            return None;
        }
        if growth.attributed.iter().any(|task| rings.contains(task)) {
            why("a ring the prefix read has new requests");
            return None;
        }
        let (key, after) = match snapshot.mark {
            Mark::Before(_, key) => (key, 0),
            Mark::After(_, key) => (key, 1),
        };
        if at == marked {
            let Some(cursor) = recording.call_offset(key, cancel).ok().flatten() else {
                why("the marked call is not in the index");
                return None;
            };
            let cursor = cursor + after;
            if growth
                .earliest_changed
                .is_some_and(|changed| changed < cursor)
            {
                why("a call before the snapshot gained a record");
                return None;
            }
            return Some((marked, cursor));
        }
    }
    None
}

/// Whether the facts of the whole recording that the prefix looked up are
/// the same in the grown recording: each task cookie and settled parent it
/// asked for, and what pass 1 settled for pass 2.
pub fn lookups_hold(
    snapshot: &Snapshot,
    settled_facts: &str,
    cookies: &std::collections::BTreeMap<u32, u64>,
    settled: &std::collections::BTreeMap<TaskKey, TaskKey>,
) -> bool {
    let files = &snapshot.pass2.files;
    if snapshot.settled_facts != settled_facts {
        why(&format!(
            "pass 1 settled other facts: {} / {settled_facts}",
            snapshot.settled_facts
        ));
        return false;
    }
    let held = snapshot.settled_facts == settled_facts
        && files
            .asked_cookies
            .iter()
            .all(|pid| snapshot.cookies.get(pid) == cookies.get(pid))
        && files
            .asked_parents
            .borrow()
            .iter()
            .all(|task| snapshot.settled.get(task) == settled.get(task));
    if !held {
        why("a cookie or a parent the prefix looked up changed");
    }
    held
}

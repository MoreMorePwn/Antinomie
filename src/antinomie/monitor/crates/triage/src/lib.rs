// SPDX-License-Identifier: GPL-3.0-only
//! Triage of a recorded run, without a window: the scan of a recording, the
//! activity rules, the indicators and the filter language. The GUI draws what
//! this crate computes; nothing here depends on it (design 2.1).
//!
//! The modules keep the layout they had in the GUI crate, where each of them
//! reached the others through `use super::*` on this root.
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use antinomie_monitor_core::{syscalls, EventSummary, InvocationSummary};
use query::{FieldSpec, RowValue};

pub mod bpf;
pub mod copier;
pub mod query;
pub mod reduced_text;
pub mod time_format;
pub mod trace;
pub mod tzone;
pub mod values;

pub mod archive_scan;
#[cfg(test)]
pub mod argument_abi_tests;
pub mod async_files;
pub mod attack;
pub mod auditd_events;
pub mod bpf_attach;
pub mod bpf_notes;
pub mod descriptors;
pub mod detection;
pub mod digest;
pub mod digest_job;
#[cfg(test)]
mod digest_job_tests;
pub mod family;
pub mod file_activity;
pub mod file_category;
#[cfg(test)]
pub mod file_category_tests;
pub mod file_content;
pub mod file_events;
pub mod file_location;
pub mod file_shown;
#[cfg(test)]
pub mod file_shown_tests;
pub mod file_tabs;
pub mod file_type;
pub mod file_visibility;
pub mod files;
pub mod findings;
pub mod geoip_fill;
pub mod graph;
pub mod ioc_scan;
pub mod ioc_view;
pub mod kernel_records;
pub mod lineage_index;
pub mod live_judge;
pub mod net_attr;
pub mod net_attr_read;
#[cfg(test)]
pub mod net_attr_tests;
pub mod net_tabs;
pub mod network;
pub mod network_index;
pub mod network_reach;
pub mod normalized;
pub mod pcap_scan;
pub mod process_cells;
pub mod process_env;
pub mod process_record;
pub mod process_tree;
#[cfg(test)]
pub mod process_tree_tests;
pub mod refresh;
pub mod report_export;
pub mod rules;
pub mod run_end;
pub mod run_state;
pub mod saved_run;
pub mod scan_cache;
pub mod scan_progress;
pub mod segments;
pub mod sigma_events;
#[cfg(test)]
pub mod sigma_events_tests;
pub mod sorting;
pub mod summary;
pub mod table;
#[cfg(any(test, feature = "test-support"))]
pub mod tests;
pub mod tone;
#[cfg(test)]
pub mod tracer_qa;
#[cfg(test)]
pub mod uring_qa;
pub mod written_export;
#[cfg(test)]
use self::archive_scan::*;
use self::{
    bpf_attach::BpfFds, bpf_notes::*, descriptors::*, file_category::FILE_FIELDS, file_events::*,
    findings::*, pcap_scan::*, process_tree::*, refresh::*, table::*,
};
pub use network::AddressLookup;
pub use saved_run::{SavedCapture, SavedRun, TriageSettings};
pub use tone::{Tone, ValueKind};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileTab {
    Opened,
    Created,
    Read,
    Written,
    Deleted,
    Renamed,
    Executed,
    Attributes,
    Probed,
    Other,
    Changed,
}

#[derive(Clone)]
pub struct Cell {
    pub text: String,
    /// The colour role of the text; read the colour through [`Cell::color`].
    pub tone: Tone,
    pub mono: bool,
    pub values: Vec<(&'static str, RowValue)>,
    /// Small pills drawn before the text (a path's location, how many other
    /// names it has, a finding that involves it). They are made when the row
    /// is shown, from its values, and are not stored.
    pub badges: Vec<Badge>,
    /// Said on hover instead of the text: a relative time's absolute one.
    pub note: Option<String>,
}

/// A pill in a table cell.
#[derive(Clone, Debug, PartialEq)]
pub struct Badge {
    pub text: String,
    pub tone: Tone,
    pub hover: String,
}

#[cfg(any(test, feature = "test-support"))]
pub struct LimitedRows {
    pub rows: Vec<Vec<Cell>>,
    /// The loaded page is not truncated. Callers still observe this as false.
    pub stopped_early: bool,
}

#[derive(Clone)]
pub struct Finding {
    pub key: trace::InvocationKey,
    pub cells: Vec<Cell>,
    pub call_id: u64,
    pub values: Vec<(&'static str, RowValue)>,
}

pub const PROCESS_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::number("process.depth", "Observed tree depth"),
    FieldSpec::number("process.ppid", "Observed parent process ID"),
    FieldSpec::number("process.parent_cookie", "Observed stable parent identity"),
    FieldSpec::number("process.pid", "Observed TGID"),
    FieldSpec::number("process.tid", "Observed thread ID"),
    FieldSpec::number("process.cookie", "Stable task cookie"),
    FieldSpec::number(
        "process.suspicious",
        "Suspicious observations in this process",
    ),
    FieldSpec::text("process.exe", "Latest successful captured executable"),
    FieldSpec::tags("process.argv", "Captured exec argument strings"),
    FieldSpec::text(
        "process.state",
        "Recorded task exit, separately from tree completion",
    ),
    FieldSpec::number("process.first_ns", "First observed monotonic ns"),
    FieldSpec::number("process.last_ns", "Last observed monotonic ns"),
];

/// Clone, fork, vfork, clone3. `CLONE_THREAD` stays inside the parent. `clone`
/// reads that bit from its `clone_flags` argument, found by name in the table
/// (`clone_flags`). `clone3`'s first argument is a pointer, so its flags come
/// only from a captured `clone_args` flags field.
pub fn clone_flags(nr: u64, args: &[u64; 6]) -> u64 {
    syscalls::argument_of(nr, "clone", "clone_flags").map_or(0, |index| args[index])
}
pub const CLONE_THREAD: u64 = 0x0001_0000;
pub const CLONE_FS: u64 = 0x0000_0200;
pub const CLONE_FILES: u64 = 0x0000_0400;
pub const AT_FDCWD: u64 = (-100i64) as u64;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaskKey {
    pub pid: u32,
    pub cookie: u64,
}

#[derive(Default)]
pub struct TaskNode {
    pub parent: Option<TaskKey>,
    pub comm: String,
    /// Fork return created this pid before any event identified its cookie.
    pub provisional: bool,
    pub tid: u32,
    pub root: bool,
    pub call_id: Option<trace::InvocationKey>,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    pub argv: Vec<String>,
    pub state: String,
    /// The signal number that ended the task, when its exit record says it was killed.
    pub end_signal: Option<u8>,
    /// Who sent that signal, when the guest recorded it (revision 21).
    pub end_sender: Option<antinomie_monitor_core::fatal_signal::FatalSignal>,
    pub exec_history: Vec<String>,
    pub renames: Vec<String>,
    pub in_call: Option<(String, u64)>,
    /// Descriptors this task holds open on a `comm` file.
    pub comm_fds: Vec<i64>,
    /// Joined argv of the committed exec, only when the whole vector was captured.
    pub command_line: Option<String>,
    /// The same vector kept as arguments, for the auditd `PROCTITLE` record.
    pub proctitle: Option<Vec<String>>,
    /// The image is the parent's: a fork that has not run an exec of its own.
    pub forked: bool,
    /// An exec committed here and no image name was recorded for it.
    pub exec_unnamed: bool,
    pub record: process_record::ProcessRecord,
}

pub enum Spawn {
    /// A new process. The returned pid is the child.
    Process,
    /// A thread, or clone3 whose flags were not captured. No parent/child edge.
    Skip,
}

#[cfg_attr(any(test, feature = "test-support"), derive(Clone))]
pub struct ProcessNode {
    pub parent: Option<TaskKey>,
    pub call_id: Option<trace::InvocationKey>,
    pub depth: usize,
    pub pid: u32,
    pub cookie: u64,
    pub comm: String,
    pub parent_missing: bool,
    pub tid: u32,
    pub argv: Vec<String>,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    pub state: String,
    /// The signal number that ended the task, when its exit record says it was killed.
    pub end_signal: Option<u8>,
    /// Who sent that signal, when the guest recorded it (revision 21).
    pub end_sender: Option<antinomie_monitor_core::fatal_signal::FatalSignal>,
    pub exec_history: Vec<String>,
    /// A thread of the process with this pid, not a process of its own.
    pub thread: bool,
    /// Names the task gave itself after its last exec (`prctl(PR_SET_NAME)`, a write to `comm`).
    pub renames: Vec<String>,
    /// The call the task was in at its last record, with its start: the entry
    /// was recorded and no exit followed (a call still blocking at the stop).
    pub in_call: Option<(String, u64)>,
    /// The image is the parent's: a fork that has not run an exec of its own.
    pub forked: bool,
    /// The environment, execs, credentials and call count of the task.
    pub record: process_record::ProcessRecord,
}

pub const FINDING_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("finding.rule", "Stable activity rule"),
    FieldSpec::text("finding.title", "The rule's short title"),
    FieldSpec::number("finding.version", "Rule version"),
    FieldSpec::text("finding.tier", "high, medium, low or info, after context"),
    FieldSpec::text("finding.severity", "Same as finding.tier"),
    FieldSpec::text("finding.base_tier", "The rule's own tier, before context"),
    FieldSpec::text(
        "finding.category",
        "execution, persistence, privilege, evasion, credential, discovery, injection, c2, rootkit, impact, collection, lateral or exfiltration",
    ),
    FieldSpec::tags("finding.technique", "ATT&CK technique and detection ids"),
    FieldSpec::number("finding.count", "Occurrences folded into the row"),
    FieldSpec::tags(
        "finding.flags",
        "failed, allow-listed, outside-scope, vm-wide, suppressed, async, collapsed, capped, periodic, repeated",
    ),
    FieldSpec::boolean("finding.hidden", "Hidden as housekeeping or outside the run"),
    FieldSpec::text("finding.confidence", "Evidence confidence: high or limited"),
    FieldSpec::text("finding.source", "Rule reference"),
    FieldSpec::text("finding.summary", "Matching facts"),
    FieldSpec::text("finding.object", "What repeats are folded by"),
    FieldSpec::boolean("finding.attempted", "A syscall attempt was recorded"),
    FieldSpec::boolean(
        "finding.success",
        "Observed nonnegative syscall exit; missing without exit",
    ),
    FieldSpec::number("finding.first_ns", "First occurrence, guest monotonic ns"),
    FieldSpec::number("finding.last_ns", "Last occurrence, guest monotonic ns"),
    FieldSpec::number("process.pid", "Observed PID"),
    FieldSpec::text(
        "process.exe",
        "Captured executable active at this observation",
    ),
    FieldSpec::number("process.tid", "Observed TID"),
    FieldSpec::number("process.cookie", "Stable task cookie"),
    FieldSpec::number("event.id", "Original invocation ID"),
    FieldSpec::number("stream.id", "Recorded stream identity"),
    FieldSpec::number("syscall.ret", "Observed signed syscall return"),
    FieldSpec::number("event.time_ns", "Guest monotonic nanoseconds"),
    FieldSpec::tags("entry.tag", "Unavailable without a finding annotation"),
];

pub const HTTP_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Owning capture segment"),
    FieldSpec::number("frame.number", "Original request frame"),
    FieldSpec::number("frame.time_us", "Captured Unix microseconds"),
    FieldSpec::text("network.endpoints", "Recorded source and destination"),
    FieldSpec::text("http.method", "Request method"),
    FieldSpec::text("http.host", "Cleartext Host header"),
    FieldSpec::text("http.uri", "Cleartext request URI"),
    FieldSpec::text("http.version", "Observed HTTP version"),
    FieldSpec::number(
        "http.status",
        "Correlated response code; missing if unavailable",
    ),
    FieldSpec::boolean("entry.complete", "Decoded request completeness"),
    FieldSpec::text(
        "network.attribution",
        "Unknown unless socket identity supports exact attribution",
    ),
];
#[derive(Clone, Default)]
pub struct ScanRequest {
    /// The chips above Suspicious activity.
    pub finding_view: rules::View,
    /// The run's network calls, set by the scan once it has read them: what
    /// the capture's flows are matched against (see [`net_attr`]).
    pub attribution: Option<Arc<net_attr::NetAttribution>>,
    pub event_cache: Option<normalized::Cache>,
    pub sorts: [Option<sorting::Spec>; SLOTS],
    pub file_visibility: file_visibility::FileVisibility,
    pub owned_pcap: bool,
    pub clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub root_cookie: u64,
    /// The packer verdict of the run's program, from its Static analysis.
    pub packed: Option<rules::PackedImage>,
    pub address_lookup: AddressLookup,
    pub run_finished: bool,
    /// The VM boot that recorded the run is still up, so the recording's
    /// totals (and with them whether it is whole) are not saved yet.
    pub recording_open: bool,
    /// Stamp of the index on screen; a recording with the same stamp is not read again.
    pub unchanged_since: Option<String>,
    pub identity: Option<(String, String, String)>,
    pub offsets: [usize; SLOTS],
    pub filters: [String; SLOTS],
    /// The app's data folder: where the base a run's disk came from is
    /// installed, for the guest's user and group names.
    pub data_dir: Option<std::path::PathBuf>,
    /// Names given directly (tests); otherwise they are read from the base.
    pub guest_names: Option<Arc<antinomie_monitor_core::guest_names::GuestNames>>,
    /// The run's earlier recording segments and their boots, oldest first,
    /// for the packet index (set by the scan).
    pub segments: Vec<(std::path::PathBuf, String)>,
    /// The datasets' answer for the last scan, while nothing it depends on changed.
    pub ioc_cache: Option<ioc_scan::Cache>,
    /// The run's static analysis report: the sample's hashes and strings.
    pub report: Option<Arc<antinomie_monitor_core::AnalysisReport>>,
    /// Caps on the file write content kept (Settings).
    pub write_limits: antinomie_monitor_core::file_writes::Limits,
    /// Caps on the bytes the Changed files rebuild keeps (Settings).
    pub retention: files::Retention,
    /// Rows one table keeps per page (Settings); 0 reads as [`STORED_ROWS`].
    pub page_rows: usize,
    /// The kernel revision of the run's base, when the run recorded it: from
    /// revision 18 a read or write with no position record is a stream.
    pub kernel_revision: Option<u32>,
    /// The router of the guest's own NAT network, when the VM's profile set
    /// one: its DHCP ports are the base image's background like 10.0.2.2's.
    pub guest_gateway: Option<std::net::IpAddr>,
    /// The launch the run was asked for: the root's pid, the program path and
    /// its arguments. Names the root when the recording has no launch record
    /// of it (its end record, or the whole event, never arrived).
    pub launch: Option<(u32, String, Vec<String>)>,
    /// Set while the earlier bytes of a finished boot are copied into its
    /// recording: each changed file asked about is added to it.
    pub before_copy:
        Option<Arc<std::sync::Mutex<antinomie_monitor_core::file_before_store::Writer>>>,
    /// Written by the scan as it goes, for a screen that waits for it (the
    /// export dialog); `None` for the index the tables show.
    pub progress: Option<Arc<scan_progress::ScanProgress>>,
    /// An index of exactly this recording that is already made and current:
    /// the scan answers with it instead of reading the recording again.
    pub reuse: Option<ArchiveScan>,
    /// Leave the index in the process ([`scan_cache`]) when it reads the run
    /// whole, for the export or report that follows.
    pub keep_index: bool,
    /// Write nothing into the recording: no finding journal, no Sigma event
    /// journal, no clean-up of stale temporaries. The query API reads this way
    /// (design 5.12.2); the window and the CLI's `triage` keep the journals.
    pub read_only: bool,
    /// A budget the passes over the calls stop at, leaving a partial index
    /// ([`scan_progress::ScanStop`]); `None` reads the whole run.
    pub stop: Option<Arc<scan_progress::ScanStop>>,
}

impl ScanRequest {
    /// A phase begins.
    pub fn phase(&self, phase: scan_progress::Phase, total: u64) {
        if let Some(progress) = &self.progress {
            progress.begin(phase, total);
        }
    }
    /// `units` more of the phase are done.
    pub fn advance(&self, units: usize) {
        if let Some(progress) = &self.progress {
            progress.advance(units as u64);
        }
    }
}

/// The default most rows one Triage table keeps per page.
pub const STORED_ROWS: usize = 2000;
/// The range of the Settings value for it.
pub const PAGE_ROWS_RANGE: std::ops::RangeInclusive<u32> = 100..=100_000;

impl ScanRequest {
    /// Rows one table keeps per page.
    pub fn rows(&self) -> usize {
        if self.page_rows == 0 {
            STORED_ROWS
        } else {
            self.page_rows
        }
    }
}
/// The request has no filter, sort, page or toggle: it reads the run whole,
/// as a report does.
pub fn is_whole_run(request: &ScanRequest) -> bool {
    request.filters.iter().all(String::is_empty)
        && request.offsets == [0; SLOTS]
        && request.sorts.iter().all(Option::is_none)
        && request.file_visibility == Default::default()
        && request.finding_view == Default::default()
}

/// The scan's request as the screen has it, with every filter, sort, page and
/// toggle back to the default: the report is of the whole run, not of what
/// the tables are showing.
pub fn whole_run_request(screen: &ScanRequest) -> ScanRequest {
    let mut request = screen.clone();
    request.filters = Default::default();
    request.offsets = [0; SLOTS];
    request.sorts = Default::default();
    request.file_visibility = Default::default();
    request.finding_view = Default::default();
    request.unchanged_since = None;
    request.before_copy = None;
    request.event_cache = None;
    request.ioc_cache = None;
    request
}

/// Query tables with their own filter, sort and page: findings 0, opened 1,
/// changed 2, http 3, dns 4, read 5, ips 6, hosts 7, the file categories 8 to
/// 15, then the TLS, QUIC and SSH sessions, then the rebuilt Network section's
/// Endpoints, Domains and TLS tables.
pub const SLOTS: usize = 20;
/// Operation tabs with their own slot after the original eight.
pub const FILE_TABS: usize = 8;
pub const SESSION_SLOT: usize = 16;
pub const ENDPOINT_SLOT: usize = 17;
pub const DOMAIN_SLOT: usize = 18;
pub const TLS_SLOT: usize = 19;
/// The Details/selection table id of each filter slot, in slot order.
pub const TABLE_IDS: [&str; SLOTS] = [
    "triage-findings",
    "triage-opened",
    "triage-changed",
    "triage-http",
    "triage-dns",
    "triage-read",
    "triage-ips",
    "triage-hosts",
    "triage-created",
    "triage-written",
    "triage-deleted",
    "triage-renamed",
    "triage-executed",
    "triage-attributes",
    "triage-probed",
    "triage-other",
    "triage-sessions",
    "triage-endpoints",
    "triage-domains",
    "triage-tls",
];

pub struct FindingJournal {
    pub temp: std::path::PathBuf,
    pub destination: std::path::PathBuf,
    pub file: std::fs::File,
    pub size: u64,
}

/// One file tab's rows kept in memory, and the matches left out of them.
#[derive(Default)]
pub struct FileRows {
    pub rows: Vec<Vec<Cell>>,
    pub omitted: u64,
}

/// A finished index. It is shared: the index on screen and a report export
/// that finds it current hold the same one, so the export does not read the
/// recording a second time. It is only changed while it is not shared (a test
/// setting up its fixture).
#[derive(Clone)]
pub struct ArchiveScan(pub Arc<ScanData>);

impl ArchiveScan {
    pub fn new(data: ScanData) -> Self {
        Self(Arc::new(data))
    }
}

impl std::ops::Deref for ArchiveScan {
    type Target = ScanData;
    fn deref(&self) -> &ScanData {
        &self.0
    }
}

impl std::ops::DerefMut for ArchiveScan {
    fn deref_mut(&mut self) -> &mut ScanData {
        Arc::get_mut(&mut self.0).expect("an index is changed only while it is not shared")
    }
}

pub struct ScanData {
    /// [`source_stamp`] of the recording when this index began.
    pub stamp: String,
    /// The index was made with no filter, sort, page or toggle: the whole run
    /// as a report reads it.
    pub whole_run: bool,
    /// When the run's process tree ended, recorded or estimated from its last call (host Unix ms).
    pub ended_ms: Option<u64>,
    pub event_cache: Option<normalized::Cache>,
    pub counts: normalized::Counts,
    pub network_counts: Option<(u64, u64, u64)>,
    pub event_journal: Option<antinomie_monitor_core::analysis::detection::JournalSummary>,
    pub event_error: Option<String>,
    #[cfg(any(test, feature = "test-support"))]
    pub coverage: String,
    pub clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    pub file_changes: Vec<files::Change>,
    /// Every file the run changed, for the run's digest.
    pub written_files: Vec<antinomie_monitor_core::run_digest::WrittenFile>,
    /// Every file the run touched, for the File activity window.
    pub file_activity: Arc<file_activity::Activity>,
    pub bpf: Vec<BpfNote>,
    pub bpf_omitted: u64,
    pub read: Vec<Vec<Cell>>,
    pub read_omitted: u64,
    pub partial: bool,
    /// Why the index is partial, one reason each; empty when it is whole.
    pub partial_reasons: Vec<String>,
    /// The request's budget ([`ScanRequest::stop`]) ended a pass early.
    pub budget_reached: bool,
    pub process: Vec<ProcessNode>,
    /// Suspicious observations per task, before the findings filter and page.
    pub suspicious: Suspicious,
    pub findings: Vec<Finding>,
    pub findings_omitted: u64,
    /// Paths a finding above Info names as its object, whatever the findings
    /// table is filtered to, with what they say: the tag of those files in Files.
    pub flagged_paths: file_shown::Flags,
    /// The same rows as lanes and buckets, and the run's overview.
    pub graph: graph::GraphScan,
    /// Rules the scan could not evaluate, and why.
    pub finding_notes: Vec<String>,
    pub opened: Vec<Vec<Cell>>,
    pub opened_omitted: u64,
    pub changed: Vec<Vec<Cell>>,
    pub changed_omitted: u64,
    /// Operation tabs after Opened, in [`FileTab::slot`] order from slot 8.
    pub file_tabs: [FileRows; FILE_TABS],
    pub http: Vec<Vec<Cell>>,
    pub http_omitted: u64,
    /// The Network tabs.
    pub new_tabs: NewTabs,
    /// The IOC window's list of the run and the datasets' answer.
    pub ioc: Option<Arc<ioc_scan::IocScan>>,
    /// The run's network calls and the capture's DNS names, to say which
    /// process made a packet (the Packets list's Source column).
    pub attribution: Option<Arc<net_attr::NetAttribution>>,
    pub network_warning: Option<String>,
    /// The run's program died of a signal before its first recorded system
    /// call: "the sample crashed before its first system call: SIGSEGV".
    pub root_crash: Option<String>,
    /// The last create, write, delete or exec the kernel refused, as
    /// "openat /var/run/dbus/x.pid ENOENT".
    pub last_failed_step: Option<String>,
    /// The signals the run's calls sent, for saying why tasks were killed.
    pub signals: run_end::SignalNotes,
    /// Calls with a field the guest had no decoder for, most frequent first:
    /// "ioctl request 0x5421 (arg2.ioctl)" and how many calls.
    pub schema_gaps: Vec<(String, u64)>,
}

/// The rows of the rebuilt Network tabs and what their pages left out.
#[derive(Default)]
pub struct NewTabs {
    pub endpoints: Vec<Vec<Cell>>,
    pub endpoints_omitted: u64,
    pub domains: Vec<Vec<Cell>>,
    pub domains_omitted: u64,
    pub tls: Vec<Vec<Cell>>,
    pub tls_omitted: u64,
    /// The URLs tab: the HTTP rows (HTTP/1 and cleartext HTTP/2) with their version and IOC verdict.
    pub urls: Vec<Vec<Cell>>,
}

pub struct PacketSpool {
    pub directory: std::path::PathBuf,
    pub rows: std::fs::File,
    pub offsets: std::fs::File,
    pub size: u64,
}

#[derive(Default)]
pub struct PacketIndex {
    /// The tabs and the capture's indicators.
    pub new_tabs: NewTabs,
    /// The run's network calls with the DNS names the capture showed.
    pub attribution: Option<Arc<net_attr::NetAttribution>>,
    pub ioc: antinomie_monitor_core::ioc::indicator::Collector,
    /// Frame, destination IP and hostname counts before UI queries.
    pub counts: Option<(u64, u64, u64)>,
    pub coverage: String,
    pub http: Vec<Vec<Cell>>,
    pub http_omitted: u64,
    pub network_warning: Option<String>,
}

#[derive(Default)]
pub struct FdState {
    /// Images tracked in observation order, keyed by stable task identity.
    pub process_images: std::collections::BTreeMap<TaskKey, TaskNode>,
    /// Task → its parent process as the whole recording settled it (see
    /// `process_tree::settled_parents`); empty while only a prefix is known.
    pub settled_parents: std::collections::BTreeMap<TaskKey, TaskKey>,
    /// `(owner cookie, owner pid, fd)` → path text captured for that descriptor.
    pub opened: std::collections::BTreeMap<(u64, u32, u64), String>,
    /// Child task → the task whose descriptor table it shares (`CLONE_FILES`).
    pub share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    /// Child task → the task whose working directory it shares (`CLONE_FS`).
    pub fs_share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    pub cwd: std::collections::BTreeMap<(u64, u32), String>,
    pub cwd_unverified: std::collections::BTreeSet<(u64, u32)>,
    pub cloexec: std::collections::BTreeSet<(u64, u32, u64)>,
    /// File identity the guest recorded → the name the file was last opened
    /// or renamed to, for a call that reaches it by no descriptor the run saw
    /// opened (a slot of an io_uring registered table).
    identity_paths:
        std::collections::BTreeMap<antinomie_monitor_core::kernel_notes::FileKey, String>,
    /// What the Sigma journal tracks beyond descriptors: sockets, known paths, DNS answers.
    pub journal: sigma_events::State,
}

pub enum DupKind {
    Return,
    Argument,
}

pub struct BpfNote {
    pub heading: String,
    /// One-line summary of the step, for the Observation column.
    pub summary: String,
    pub outcome: String,
    /// Request phrase for a lifecycle step. Load, socket, and seccomp lines
    /// include `fd {result}` when the exit result is >= 0. Attach does too,
    /// unless an argument matches an earlier successful `BPF_PROG_LOAD` fd.
    pub lifecycle: Option<String>,
    /// Disassembly when the instruction image was identified exactly.
    pub translation: Option<String>,
    /// Classic socket-filter and seccomp bytes. Absent when no image was isolated.
    pub dump: Option<String>,
    /// Raw bytes, hash, and the identity fields that were present.
    pub export: Option<String>,
    /// Captured instruction bytes, when an image was isolated.
    pub bytes: Option<Vec<u8>>,
    pub identity: bpf::BpfIdentity,
    /// For an attach: the call that loaded the program, when this slice saw it.
    pub loaded_by: Option<u64>,
    /// bpf's attr decoded by the call's command, one member per line.
    pub attributes: Vec<String>,
}

#[derive(Clone, Copy)]
pub struct TriageInput<'a> {
    pub analysis: Option<&'a antinomie_monitor_core::AnalysisReport>,
    pub invocations: &'a [InvocationSummary],
    pub vm_id: Option<&'a str>,
    pub boot_id: Option<&'a str>,
    pub run_id: Option<&'a str>,
    /// Saved recording directory. `None` for a live session or a single loaded page.
    pub archive: Option<&'a Path>,
    /// Pcap that belongs to this run. Absent means no packet index, not another capture.
    pub pcap: Option<&'a Path>,
    /// The pcap is still being written. The index reads the bytes present now.
    pub pcap_open: bool,
    pub clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    pub started_ms: Option<u64>,
    pub root_cookie: u64,
    pub run_finished: bool,
    /// The selected recording belongs to the currently running VM boot.
    pub current_boot: bool,
}

impl<'a> TriageInput<'a> {
    pub fn empty() -> Self {
        Self {
            analysis: None,
            invocations: &[],
            vm_id: None,
            boot_id: None,
            run_id: None,
            archive: None,
            pcap: None,
            pcap_open: false,
            clock_anchor: None,
            started_ms: None,
            root_cookie: 0,
            run_finished: false,
            current_boot: false,
        }
    }
    #[cfg(any(test, feature = "test-support"))]
    pub fn page(invocations: &'a [InvocationSummary]) -> Self {
        Self {
            analysis: None,
            invocations,
            vm_id: None,
            boot_id: None,
            run_id: None,
            archive: None,
            pcap: None,
            pcap_open: false,
            clock_anchor: None,
            started_ms: None,
            root_cookie: 0,
            run_finished: false,
            current_boot: false,
        }
    }
}

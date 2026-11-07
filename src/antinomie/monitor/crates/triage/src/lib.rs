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
use std::time::{Duration, Instant};

use antinomie_monitor_core::{syscalls, EventSummary, InvocationSummary};
use query::{FieldSpec, RowValue};

pub mod bpf;
pub mod query;
pub mod time_format;
pub mod trace;
pub mod tzone;
pub mod values;

pub mod archive_scan;
pub mod async_files;
pub mod auditd_events;
pub mod bpf_attach;
pub mod bpf_notes;
pub mod descriptors;
pub mod family;
pub mod file_activity;
pub mod file_category;
pub mod file_content;
pub mod file_events;
pub mod file_location;
pub mod file_shown;
pub mod file_tabs;
pub mod file_type;
pub mod file_visibility;
pub mod files;
pub mod findings;
pub mod geoip_fill;
pub mod graph;
pub mod ioc_scan;
pub mod kernel_records;
pub mod lineage_index;
pub mod net_tabs;
pub mod network;
pub mod network_index;
pub mod normalized;
pub mod pcap_scan;
pub mod process_cells;
pub mod process_env;
pub mod process_record;
pub mod process_tree;
pub mod rules;
pub mod run_end;
pub mod segments;
pub mod sigma_events;
pub mod sorting;
pub mod table;
pub mod tone;
#[cfg(test)]
mod file_category_tests;
#[cfg(test)]
mod file_shown_tests;
#[cfg(test)]
mod process_tree_tests;
#[cfg(test)]
mod sigma_events_tests;
#[cfg(test)]
mod tracer_qa;
#[cfg(test)]
mod uring_qa;
#[cfg(test)]
mod workload_qa;
pub use tone::{Tone, ValueKind};
pub use network::AddressLookup;
use self::{
    archive_scan::*, bpf_attach::BpfFds, bpf_notes::*, descriptors::*, file_category::FILE_FIELDS,
    file_events::*, findings::*, pcap_scan::*, process_tree::*, table::*,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum FileTab {
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
struct Cell {
    text: String,
    /// The colour role of the text; read the colour through [`Cell::color`].
    tone: Tone,
    mono: bool,
    values: Vec<(&'static str, RowValue)>,
    /// Small pills drawn before the text (a path's location, how many other
    /// names it has, a finding that involves it). They are made when the row
    /// is shown, from its values, and are not stored.
    badges: Vec<Badge>,
    /// Said on hover instead of the text: a relative time's absolute one.
    note: Option<String>,
}

/// A pill in a table cell.
#[derive(Clone, Debug, PartialEq)]
struct Badge {
    text: String,
    tone: Tone,
    hover: String,
}

impl Cell {
    /// The text color in the theme that is active now, whichever one the row
    /// was indexed in.
    fn color(&self) -> egui::Color32 {
        theme::tone(self.tone)
    }
}

#[cfg(test)]
struct LimitedRows {
    rows: Vec<Vec<Cell>>,
    /// The loaded page is not truncated. Callers still observe this as false.
    stopped_early: bool,
}

#[derive(Clone)]
struct Finding {
    key: trace::InvocationKey,
    cells: Vec<Cell>,
    call_id: u64,
    values: Vec<(&'static str, RowValue)>,
}

const PROCESS_FIELDS: &[FieldSpec<'static>] = &[
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
fn clone_flags(args: &[u64; 6]) -> u64 {
    syscalls::native()
        .argument("clone", "clone_flags")
        .map_or(0, |index| args[index])
}
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const AT_FDCWD: u64 = (-100i64) as u64;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TaskKey {
    pid: u32,
    cookie: u64,
}

#[derive(Default)]
struct TaskNode {
    parent: Option<TaskKey>,
    comm: String,
    /// Fork return created this pid before any event identified its cookie.
    provisional: bool,
    tid: u32,
    root: bool,
    call_id: Option<trace::InvocationKey>,
    first_ns: Option<u64>,
    last_ns: Option<u64>,
    argv: Vec<String>,
    state: String,
    /// The signal number that ended the task, when its exit record says it was killed.
    end_signal: Option<u8>,
    /// Who sent that signal, when the guest recorded it (revision 21).
    end_sender: Option<antinomie_monitor_core::fatal_signal::FatalSignal>,
    exec_history: Vec<String>,
    renames: Vec<String>,
    in_call: Option<(String, u64)>,
    /// Descriptors this task holds open on a `comm` file.
    comm_fds: Vec<i64>,
    /// Joined argv of the committed exec, only when the whole vector was captured.
    command_line: Option<String>,
    /// The same vector kept as arguments, for the auditd `PROCTITLE` record.
    proctitle: Option<Vec<String>>,
    /// The image is the parent's: a fork that has not run an exec of its own.
    forked: bool,
    /// An exec committed here and no image name was recorded for it.
    exec_unnamed: bool,
    record: process_record::ProcessRecord,
}

enum Spawn {
    /// A new process. The returned pid is the child.
    Process,
    /// A thread, or clone3 whose flags were not captured. No parent/child edge.
    Skip,
}

#[cfg_attr(test, derive(Clone))]
struct ProcessNode {
    parent: Option<TaskKey>,
    call_id: Option<trace::InvocationKey>,
    depth: usize,
    pid: u32,
    cookie: u64,
    comm: String,
    parent_missing: bool,
    tid: u32,
    argv: Vec<String>,
    first_ns: Option<u64>,
    last_ns: Option<u64>,
    state: String,
    /// The signal number that ended the task, when its exit record says it was killed.
    end_signal: Option<u8>,
    /// Who sent that signal, when the guest recorded it (revision 21).
    end_sender: Option<antinomie_monitor_core::fatal_signal::FatalSignal>,
    exec_history: Vec<String>,
    /// A thread of the process with this pid, not a process of its own.
    thread: bool,
    /// Names the task gave itself after its last exec (`prctl(PR_SET_NAME)`, a write to `comm`).
    renames: Vec<String>,
    /// The call the task was in at its last record, with its start: the entry
    /// was recorded and no exit followed (a call still blocking at the stop).
    in_call: Option<(String, u64)>,
    /// The image is the parent's: a fork that has not run an exec of its own.
    forked: bool,
    /// The environment, execs, credentials and call count of the task.
    record: process_record::ProcessRecord,
}

const FINDING_FIELDS: &[FieldSpec<'static>] = &[
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

const HTTP_FIELDS: &[FieldSpec<'static>] = &[
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
struct ScanRequest {
    /// The chips above Suspicious activity.
    finding_view: rules::View,
    event_cache: Option<normalized::Cache>,
    sorts: [Option<sorting::Spec>; SLOTS],
    file_visibility: file_visibility::FileVisibility,
    owned_pcap: bool,
    clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    started_ms: Option<u64>,
    ended_ms: Option<u64>,
    root_cookie: u64,
    /// The packer verdict of the run's program, from its Static analysis.
    packed: Option<rules::PackedImage>,
    address_lookup: AddressLookup,
    run_finished: bool,
    /// The VM boot that recorded the run is still up, so the recording's
    /// totals (and with them whether it is whole) are not saved yet.
    recording_open: bool,
    /// Stamp of the index on screen; a recording with the same stamp is not read again.
    unchanged_since: Option<String>,
    identity: Option<(String, String, String)>,
    offsets: [usize; SLOTS],
    filters: [String; SLOTS],
    /// The app's data folder: where the base a run's disk came from is
    /// installed, for the guest's user and group names.
    data_dir: Option<std::path::PathBuf>,
    /// Names given directly (tests); otherwise they are read from the base.
    guest_names: Option<Arc<antinomie_monitor_core::guest_names::GuestNames>>,
    /// The run's earlier recording segments and their boots, oldest first,
    /// for the packet index (set by the scan).
    segments: Vec<(std::path::PathBuf, String)>,
    /// The datasets' answer for the last scan, while nothing it depends on changed.
    ioc_cache: Option<ioc_scan::Cache>,
    /// The run's static analysis report: the sample's hashes and strings.
    report: Option<Arc<antinomie_monitor_core::AnalysisReport>>,
    /// Caps on the file write content kept (Settings).
    write_limits: antinomie_monitor_core::file_writes::Limits,
    /// Caps on the bytes the Changed files rebuild keeps (Settings).
    retention: files::Retention,
    /// Rows one table keeps per page (Settings); 0 reads as [`STORED_ROWS`].
    page_rows: usize,
    /// The kernel revision of the run's base, when the run recorded it: from
    /// revision 18 a read or write with no position record is a stream.
    kernel_revision: Option<u32>,
    /// The launch the run was asked for: the root's pid, the program path and
    /// its arguments. Names the root when the recording has no launch record
    /// of it (its end record, or the whole event, never arrived).
    launch: Option<(u32, String, Vec<String>)>,
    /// Set while the earlier bytes of a finished boot are copied into its
    /// recording: each changed file asked about is added to it.
    before_copy: Option<Arc<std::sync::Mutex<antinomie_monitor_core::file_before_store::Writer>>>,
}

/// The copy of a finished boot's earlier file bytes into its recording, run
/// by `--copy-earlier-bytes` (see `antinomie_monitor_core::file_before_store`).
pub(crate) fn copy_earlier_bytes(
    job: &antinomie_monitor_core::file_before_store::Job,
) -> Result<(), String> {
    file_activity::copy_boot(job)
}

/// The default most rows one Triage table keeps per page.
pub(crate) const STORED_ROWS: usize = 2000;
/// The range of the Settings value for it.
pub(crate) const PAGE_ROWS_RANGE: std::ops::RangeInclusive<u32> = 100..=100_000;

impl ScanRequest {
    /// Rows one table keeps per page.
    fn rows(&self) -> usize {
        if self.page_rows == 0 {
            STORED_ROWS
        } else {
            self.page_rows
        }
    }
}
/// Query tables with their own filter, sort and page: findings 0, opened 1,
/// changed 2, http 3, dns 4, read 5, ips 6, hosts 7, the file categories 8 to
/// 15, then the TLS, QUIC and SSH sessions, then the rebuilt Network section's
/// Endpoints, Domains and TLS tables.
const SLOTS: usize = 20;
/// Operation tabs with their own slot after the original eight.
const FILE_TABS: usize = 8;
const SESSION_SLOT: usize = 16;
const ENDPOINT_SLOT: usize = 17;
const DOMAIN_SLOT: usize = 18;
const TLS_SLOT: usize = 19;
/// The Details/selection table id of each filter slot, in slot order.
const TABLE_IDS: [&str; SLOTS] = [
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

struct FindingJournal {
    temp: std::path::PathBuf,
    destination: std::path::PathBuf,
    file: std::fs::File,
    size: u64,
}

/// One file tab's rows kept in memory, and the matches left out of them.
#[derive(Default)]
struct FileRows {
    rows: Vec<Vec<Cell>>,
    omitted: u64,
}

struct ArchiveScan {
    /// [`source_stamp`] of the recording when this index began.
    stamp: String,
    /// When the run's process tree ended, recorded or estimated from its last call (host Unix ms).
    ended_ms: Option<u64>,
    event_cache: Option<normalized::Cache>,
    counts: normalized::Counts,
    network_counts: Option<(u64, u64, u64)>,
    event_journal: Option<antinomie_monitor_core::analysis::detection::JournalSummary>,
    event_error: Option<String>,
    #[cfg(test)]
    coverage: String,
    clock_anchor: Option<antinomie_monitor_core::HostClockAnchor>,
    file_changes: Vec<files::Change>,
    /// Every file the run changed, for the run's digest.
    written_files: Vec<antinomie_monitor_core::run_digest::WrittenFile>,
    /// Every file the run touched, for the File activity window.
    file_activity: Arc<file_activity::Activity>,
    bpf: Vec<BpfNote>,
    bpf_omitted: u64,
    read: Vec<Vec<Cell>>,
    read_omitted: u64,
    partial: bool,
    /// Why the index is partial, one reason each; empty when it is whole.
    partial_reasons: Vec<String>,
    process: Vec<ProcessNode>,
    /// Suspicious observations per task, before the findings filter and page.
    suspicious: Suspicious,
    findings: Vec<Finding>,
    findings_omitted: u64,
    /// Paths a finding above Info names as its object, whatever the findings
    /// table is filtered to, with what they say: the tag of those files in Files.
    flagged_paths: file_shown::Flags,
    /// The same rows as lanes and buckets, and the run's overview.
    graph: graph::GraphScan,
    /// Rules the scan could not evaluate, and why.
    finding_notes: Vec<String>,
    opened: Vec<Vec<Cell>>,
    opened_omitted: u64,
    changed: Vec<Vec<Cell>>,
    changed_omitted: u64,
    /// Operation tabs after Opened, in [`FileTab::slot`] order from slot 8.
    file_tabs: [FileRows; FILE_TABS],
    http: Vec<Vec<Cell>>,
    http_omitted: u64,
    /// The Network tabs.
    new_tabs: NewTabs,
    /// The IOC window's list of the run and the datasets' answer.
    ioc: Option<Arc<ioc_scan::IocScan>>,
    network_warning: Option<String>,
    /// The run's program died of a signal before its first recorded system
    /// call: "the sample crashed before its first system call: SIGSEGV".
    root_crash: Option<String>,
    /// The last create, write, delete or exec the kernel refused, as
    /// "openat /var/run/dbus/x.pid ENOENT".
    last_failed_step: Option<String>,
    /// The signals the run's calls sent, for saying why tasks were killed.
    signals: run_end::SignalNotes,
    /// Calls with a field the guest had no decoder for, most frequent first:
    /// "ioctl request 0x5421 (arg2.ioctl)" and how many calls.
    schema_gaps: Vec<(String, u64)>,
}

/// The rows of the rebuilt Network tabs and what their pages left out.
#[derive(Default)]
struct NewTabs {
    endpoints: Vec<Vec<Cell>>,
    endpoints_omitted: u64,
    domains: Vec<Vec<Cell>>,
    domains_omitted: u64,
    tls: Vec<Vec<Cell>>,
    tls_omitted: u64,
    /// The URLs tab: the HTTP rows (HTTP/1 and cleartext HTTP/2) with their version and IOC verdict.
    urls: Vec<Vec<Cell>>,
}

struct PacketSpool {
    directory: std::path::PathBuf,
    rows: std::fs::File,
    offsets: std::fs::File,
    size: u64,
}

#[derive(Default)]
struct PacketIndex {
    /// The tabs and the capture's indicators.
    new_tabs: NewTabs,
    ioc: antinomie_monitor_core::ioc::indicator::Collector,
    /// Frame, destination IP and hostname counts before UI queries.
    counts: Option<(u64, u64, u64)>,
    coverage: String,
    http: Vec<Vec<Cell>>,
    http_omitted: u64,
    network_warning: Option<String>,
}

#[derive(Default)]
struct FdState {
    /// Images tracked in observation order, keyed by stable task identity.
    process_images: std::collections::BTreeMap<TaskKey, TaskNode>,
    /// Task → its parent process as the whole recording settled it (see
    /// `process_tree::settled_parents`); empty while only a prefix is known.
    settled_parents: std::collections::BTreeMap<TaskKey, TaskKey>,
    /// `(owner cookie, owner pid, fd)` → path text captured for that descriptor.
    opened: std::collections::BTreeMap<(u64, u32, u64), String>,
    /// Child task → the task whose descriptor table it shares (`CLONE_FILES`).
    share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    /// Child task → the task whose working directory it shares (`CLONE_FS`).
    fs_share: std::collections::BTreeMap<(u64, u32), (u64, u32)>,
    cwd: std::collections::BTreeMap<(u64, u32), String>,
    cwd_unverified: std::collections::BTreeSet<(u64, u32)>,
    cloexec: std::collections::BTreeSet<(u64, u32, u64)>,
    /// File identity the guest recorded → the name the file was last opened
    /// or renamed to, for a call that reaches it by no descriptor the run saw
    /// opened (a slot of an io_uring registered table).
    identity_paths:
        std::collections::BTreeMap<antinomie_monitor_core::kernel_notes::FileKey, String>,
    /// What the Sigma journal tracks beyond descriptors: sockets, known paths, DNS answers.
    journal: sigma_events::State,
}

enum DupKind {
    Return,
    Argument,
}

struct BpfNote {
    heading: String,
    /// One-line summary of the step, for the Observation column.
    summary: String,
    outcome: String,
    /// Request phrase for a lifecycle step. Load, socket, and seccomp lines
    /// include `fd {result}` when the exit result is >= 0. Attach does too,
    /// unless an argument matches an earlier successful `BPF_PROG_LOAD` fd.
    lifecycle: Option<String>,
    /// Disassembly when the instruction image was identified exactly.
    translation: Option<String>,
    /// Classic socket-filter and seccomp bytes. Absent when no image was isolated.
    dump: Option<String>,
    /// Raw bytes, hash, and the identity fields that were present.
    export: Option<String>,
    /// Captured instruction bytes, when an image was isolated.
    bytes: Option<Vec<u8>>,
    identity: bpf::BpfIdentity,
    /// For an attach: the call that loaded the program, when this slice saw it.
    loaded_by: Option<u64>,
    /// bpf's attr decoded by the call's command, one member per line.
    attributes: Vec<String>,
}


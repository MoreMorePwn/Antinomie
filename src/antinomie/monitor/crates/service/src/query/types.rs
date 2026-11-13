// SPDX-License-Identifier: GPL-3.0-only
//! The result objects of the `recording.*` operations (design 5.12.3), one
//! serde type per object and field list.
//!
//! Identifiers and counters that can exceed 2^53 (task cookies, stream, call
//! and object ids, byte offsets of raw files) are decimal strings and are named
//! `*_id`, `*_cookie` or `*_offset` ([`U64`]); register values and addresses are
//! lower-case hex strings with `0x`. Times: `*_ms` host Unix milliseconds;
//! `guest_ns` the guest monotonic nanoseconds of the recording (never wall time);
//! `*_us` Unix microseconds of the packet capture clock. A `ts_ms` beside a
//! `guest_ns` is the host time mapped through the run's clock anchor and is
//! absent when the run has none.
//!
//! The sensitivity of each field (the **Sens.** column of the design) is in its
//! doc comment: **N** normal, **U** untrusted text from the sample or the guest
//! (5.2), **S** needs `artifacts:sensitive`, **L** local socket and CLI only.

use super::key::RunKey;
use crate::api::{
    assessment::{Counts, DetectionHit, KeyBehaviour, Tier},
    ids::{JobId, RecordingArtifactId, Sha256Hex},
    job::RecordingPhase,
    spec::Route,
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, collections::BTreeMap};

/// An unsigned 64-bit identifier or offset, sent as a decimal string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct U64(pub u64);

impl Serialize for U64 {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for U64 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() > 1 && text.starts_with('0') {
            return Err(serde::de::Error::custom("no leading zeros"));
        }
        text.parse().map(Self).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for U64 {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("U64")
    }
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({"type": "string", "pattern": "^(0|[1-9][0-9]{0,19})$",
            "description": "An unsigned 64-bit number as decimal text: it can exceed 2^53."})
    }
}

/// A register value or address: lower-case hex with `0x`.
pub type Hex = String;

/// A syscall result: a signed decimal as text.
pub type Decimal = String;

/// `RunState` by its serde spelling (`api.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunStateName {
    Unknown,
    Running,
    StopRequested,
    Finished,
    Stopped,
    TerminalClosed,
    Finalized,
    FailedToStart,
    LaunchUnconfirmed,
    Interrupted,
}

/// `RunArtifactState` by its serde spelling.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    Disabled,
    WaitingForTreeExit,
    WaitingForRootExit,
    Recording,
    Queued,
    InProgress,
    Complete,
    Partial,
    Interrupted,
    Failed,
}

// ---------------------------------------------------------------------
// Runs

/// How the root process ended: `exited` with a code, or `signaled`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunExit {
    pub kind: RunExitKind,
    pub code: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunExitKind {
    Exited,
    Signaled,
}

/// `recording.run.list` item (from `RunSummary` and the library).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunInfo {
    pub run_key: RunKey,
    /// The engine's own ids. N
    pub vm_id: String,
    pub boot_id: String,
    pub run_id: String,
    pub state: RunStateName,
    pub phase: RecordingPhase,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    /// The library sample the run executed. N
    pub sample_sha256: Option<Sha256Hex>,
    /// Guest path of the executable. U
    pub program: String,
    /// The job of this service that made the run; absent for runs made by the
    /// GUI or a CLI one-shot. N
    pub job_id: Option<JobId>,
    /// The route kind (`drop`, `inet_sim`, ...). N
    pub route: Option<Route>,
    pub exit: Option<RunExit>,
    /// `RunSummary.recording_error` text, host paths removed. U
    pub end_reason: Option<String>,
    /// Set while the run's tree has ended but the run is held open for a copy
    /// of its program running outside the tree (`run.json` `persisted`):
    /// "Held: persisted copy running (pid 1050, .e)". `state` then still says
    /// how the tree ended. U
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<String>,
}

/// From `RunExecution`. All N.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Execution {
    pub live_task_count: u64,
    pub pending_async_count: u64,
    pub total_task_count: u64,
    pub async_loss_count: u64,
    pub root_wait_status: Option<i32>,
    pub root_exit: Option<RunExit>,
}

/// One kind of evidence a run can keep.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactStatus {
    pub state: ArtifactState,
    pub present: bool,
}

/// `{network, memory, core}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunArtifactStates {
    pub network: ArtifactStatus,
    pub memory: ArtifactStatus,
    pub core: ArtifactStatus,
}

/// Who writes the recording now (5.12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OwnerState {
    Alive,
    Gone,
    Unknown,
}

/// The run layer of the recording's VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LayerState {
    None,
    Pending,
    /// The finalizer is gone; the recording itself is whole and only the
    /// earlier-bytes copy is missing until the next engine start adopts it.
    Orphaned,
}

/// `recording.run.get`: a [`RunInfo`] and more.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RunDetail {
    #[serde(flatten)]
    pub info: RunInfo,
    pub execution: Option<Execution>,
    /// U
    pub notes: Vec<String>,
    /// The engine's `RouteRecord`, host paths removed.
    pub route_record: Option<serde_json::Value>,
    /// The engine's `MachineRecord`.
    pub machine: Option<serde_json::Value>,
    /// The engine's `RunEnvironment`, host paths removed.
    pub environment: Option<serde_json::Value>,
    pub artifacts: RunArtifactStates,
    pub generation: super::cursor::Generation,
    pub owner_state: OwnerState,
    pub layer: LayerState,
    /// U
    pub recording_error: Option<String>,
    /// L: the recording directory. Absent from every remote reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

// ---------------------------------------------------------------------
// Trace

/// A syscall group of the engine's `syscall_groups.rs`, by lower-case name.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SyscallGroupName {
    Process,
    File,
    Network,
    Memory,
    Ipc,
    Signal,
    Polling,
    Security,
    System,
    Time,
    Info,
}

impl SyscallGroupName {
    pub const ALL: [Self; 11] = [
        Self::Process,
        Self::File,
        Self::Network,
        Self::Memory,
        Self::Ipc,
        Self::Signal,
        Self::Polling,
        Self::Security,
        Self::System,
        Self::Time,
        Self::Info,
    ];
}

impl From<antinomie_monitor_core::syscall_groups::SyscallGroup> for SyscallGroupName {
    fn from(group: antinomie_monitor_core::syscall_groups::SyscallGroup) -> Self {
        use antinomie_monitor_core::syscall_groups::SyscallGroup as G;
        match group {
            G::Process => Self::Process,
            G::File => Self::File,
            G::Network => Self::Network,
            G::Memory => Self::Memory,
            G::Ipc => Self::Ipc,
            G::Signal => Self::Signal,
            G::Polling => Self::Polling,
            G::Security => Self::Security,
            G::System => Self::System,
            G::Time => Self::Time,
            G::Info => Self::Info,
        }
    }
}

/// The identity of one call inside a recording; clients pass it back unchanged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct CallRef {
    pub stream: U64,
    pub task: U64,
    pub call: U64,
}

/// One captured argument field of a call, in a row (`args_preview`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArgPreview {
    pub key: String,
    pub arg: Option<u8>,
    pub layout: String,
    pub captured_len: u64,
    pub logical_len: Option<u64>,
    pub complete: bool,
    /// A lossy UTF-8 rendering, at most 256 characters. U
    pub text: String,
}

/// `recording.trace.page` row (from `InvocationSummary` and its `entry` or
/// `exit` event).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TraceRow {
    #[serde(rename = "ref")]
    pub call: CallRef,
    pub guest_ns: u64,
    pub ts_ms: Option<u64>,
    /// 0 in recordings older than 0.3.0.
    pub pid: u32,
    pub tid: u32,
    pub name: String,
    pub nr: u32,
    /// Six hex strings, or null.
    pub args: Option<Vec<Hex>>,
    /// Signed result as decimal text; null while no exit is recorded.
    pub ret: Option<Decimal>,
    pub complete: bool,
    /// A syscall group of `syscall_groups.rs` (a filter value).
    pub group: SyscallGroupName,
    /// U
    pub args_preview: Vec<ArgPreview>,
    pub async_saved: u64,
}

/// A captured field of an event. `raw_path` is L and is never sent; the bytes
/// come only from `recording.captured.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CapturedField {
    /// Opaque `"<object_id>:<key>"`, the value `recording.captured.read` takes.
    pub field: String,
    pub key: String,
    pub arg: Option<u8>,
    pub layout: String,
    pub logical_len: Option<u64>,
    pub captured_len: u64,
    pub status: Option<String>,
    pub capture_error: Option<String>,
    pub complete: bool,
    /// The engine's bounded preview, base64. U
    pub preview: String,
    /// `[offset, len]` pairs of the stored bytes.
    pub ranges: Vec<[U64; 2]>,
    pub recapture: Option<String>,
}

/// One phase of a call (from `EventSummary`). U
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CallEvent {
    pub event_seq: U64,
    /// The engine's small integer: entry, exit, async.
    pub phase: u8,
    pub syscall_nr: u32,
    pub syscall_name: String,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub guest_ns: u64,
    pub ts_ms: Option<u64>,
    pub args: Option<Vec<Hex>>,
    pub result: Option<Decimal>,
    pub complete: bool,
    /// The engine's text.
    pub issues: Vec<String>,
    pub fields: Vec<CapturedField>,
}

/// The kernel's wait status of a task, decoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WaitStatusInfo {
    pub raw: i32,
    pub exited: bool,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub core_dumped: bool,
}

/// `recording.trace.get` (from `InvocationSummary`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Invocation {
    #[serde(rename = "ref")]
    pub call: CallRef,
    pub entry: Option<CallEvent>,
    pub exit: Option<CallEvent>,
    /// The kernel's record that the task ended inside the call.
    pub task_exit: Option<CallEvent>,
    /// At most 256 (`ASYNC_PREVIEW_LIMIT`).
    pub async_events: Vec<CallEvent>,
    pub async_saved: u64,
    pub async_omitted: u64,
    /// At most `NOTES_PER_CALL`: credentials and file hashes.
    pub kernel_notes: Vec<CallEvent>,
    pub task_exit_status: Option<WaitStatusInfo>,
}

// ---------------------------------------------------------------------
// Process tree

/// `recording.process.tree` row (from `CaptureProcess`), ordered by `pid`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessNode {
    pub pid: u32,
    /// 0 when unknown.
    pub parent_pid: u32,
    /// The command name, or the file name of the last program it executed. U
    pub name: String,
    /// The path of the last program it executed. U
    pub exe: Option<String>,
    /// Running when the capture started.
    pub at_start: bool,
    pub first_guest_ns: u64,
    pub last_guest_ns: u64,
    /// System calls observed (entry events).
    pub calls: u64,
    pub packets: u64,
    pub exited: bool,
    pub exit_code: Option<i32>,
}

/// The extras of the first page of `recording.process.tree`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessTreeNotes {
    /// The engine's issues, host paths removed.
    pub issues: Vec<String>,
    /// The 262 144-node limit cut the list.
    pub truncated: bool,
}

// ---------------------------------------------------------------------
// Triage

/// The process of a finding or file row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProcessRef {
    pub pid: u32,
    pub tid: u32,
    pub cookie: U64,
    /// U
    pub exe: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Execution,
    Persistence,
    Privilege,
    Evasion,
    Credential,
    Discovery,
    Injection,
    C2,
    Rootkit,
    Impact,
    Collection,
    Lateral,
    Exfiltration,
}

/// The flags of a finding row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum FindingFlag {
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "allow-listed")]
    AllowListed,
    #[serde(rename = "outside-scope")]
    OutsideScope,
    #[serde(rename = "vm-wide")]
    VmWide,
    #[serde(rename = "suppressed")]
    Suppressed,
    #[serde(rename = "async")]
    Async,
    #[serde(rename = "collapsed")]
    Collapsed,
    #[serde(rename = "capped")]
    Capped,
    #[serde(rename = "periodic")]
    Periodic,
    #[serde(rename = "repeated")]
    Repeated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Limited,
}

/// `recording.findings.list` row (from the Triage `Finding` model). Tones are
/// never sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    /// Opaque id of the row inside this `generation`.
    pub finding_id: String,
    pub rule: String,
    pub version: u32,
    /// After context.
    pub tier: Tier,
    /// The rule's own tier.
    pub base_tier: Tier,
    pub category: FindingCategory,
    /// ATT&CK technique and detection ids.
    pub techniques: Vec<String>,
    /// Occurrences folded into the row.
    pub count: u64,
    pub flags: Vec<FindingFlag>,
    pub hidden: bool,
    pub confidence: Confidence,
    /// Rule reference text.
    pub source: String,
    /// Matching facts. U
    pub summary: String,
    /// What repeats are folded by. U
    pub object: String,
    pub attempted: bool,
    /// Observed non-negative exit; null without an exit.
    pub success: Option<bool>,
    pub first_guest_ns: u64,
    pub last_guest_ns: u64,
    pub ts_ms: Option<u64>,
    /// U
    pub process: ProcessRef,
    /// The representative call.
    #[serde(rename = "ref")]
    pub call: CallRef,
    pub ret: Option<Decimal>,
}

/// `recording.findings.get`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FindingDetail {
    #[serde(flatten)]
    pub finding: Finding,
    /// The call of every folded occurrence, at most 256.
    pub evidence_refs: Vec<CallRef>,
    pub evidence_omitted: u64,
    /// The rule's one-line description.
    pub rule_text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    Endpoint,
    Domain,
    Url,
    Tls,
    File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorMatch {
    Matched,
    KnownFp,
    NoMatch,
    NotChecked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorSource {
    Pcap,
    Syscall,
    Disk,
    Static,
}

/// `recording.indicators.list` row (from `report::Indicator`). It keeps the raw
/// value; `defanged` is the safe form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Indicator {
    pub kind: IndicatorKind,
    /// The raw indicator. U
    pub value: String,
    /// The defanged form. U
    pub defanged: String,
    #[serde(rename = "match")]
    pub matching: IndicatorMatch,
    /// The dataset answer. U
    pub dataset: String,
    pub record_id: String,
    pub family: String,
    pub reference: String,
    pub confidence: Option<u32>,
    pub sources: Vec<IndicatorSource>,
    /// The one process that made a matching call. U
    pub process: String,
    pub first_us: u64,
    pub last_us: u64,
    pub count: u64,
    /// URL and TLS facts. U
    pub url: String,
    pub sni: String,
    pub ja3: String,
    pub ja4: String,
    pub ja3s: String,
    pub cert_sha1: String,
    /// File indicators. U
    pub path: String,
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
    pub file_role: Vec<String>,
    /// Always true: the value is raw and must not be rendered as active content.
    pub raw_indicators: bool,
}

/// The tabs of `recording.files.list`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
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

impl FileTab {
    /// `changed` has one row per changed file; every other tab lists operations.
    pub fn is_operation_tab(self) -> bool {
        self != Self::Changed
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileVia {
    Syscall,
    IoUring,
    #[serde(rename = "AIO")]
    Aio,
}

/// A row of an operation tab (`opened`, `created`, `read`, `written`,
/// `deleted`, `renamed`, `executed`, `attributes`, `probed`, `other`). All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileOperationRow {
    pub file_id: String,
    pub path: String,
    pub path_known: bool,
    pub old_path: Option<String>,
    pub new_path: Option<String>,
    /// The call as the tables name it.
    pub operation: String,
    pub via: FileVia,
    pub success: Option<bool>,
    pub access: String,
    pub fd: Option<i64>,
    pub read_size: Option<u64>,
    pub written_size: Option<u64>,
    pub requested_size: Option<u64>,
    pub offset: Option<U64>,
    pub count: u64,
    /// For a script.
    pub interpreter: Option<String>,
    /// The captured first octets as a lossy text preview, at most 256
    /// characters.
    pub content: String,
    pub content_gap: bool,
    pub process: ProcessRef,
    pub guest_ns: u64,
    pub ts_ms: Option<u64>,
    #[serde(rename = "ref")]
    pub call: CallRef,
}

/// How completely a changed file could be reconstructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Reconstruction {
    #[serde(rename = "complete")]
    Complete,
    #[serde(rename = "incomplete")]
    Incomplete,
    #[serde(rename = "not reconstructed")]
    NotReconstructed,
}

/// `file_before_store::Status`, plus `pending` while the layer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EarlierState {
    Copied,
    Created,
    NotCopied,
    Elsewhere,
    Unavailable,
    Pending,
}

/// A row of the `changed` tab. All U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileChangedRow {
    pub file_id: String,
    pub path: String,
    /// Every name seen.
    pub names: Vec<String>,
    /// `device:inode`.
    pub inode: Option<String>,
    pub standard_io: bool,
    pub created: bool,
    pub deleted: bool,
    pub original_size: Option<u64>,
    pub final_size: Option<u64>,
    pub diff_count: u64,
    pub complete: bool,
    pub reconstruction: Reconstruction,
    pub bytes_written: u64,
    pub bytes_not_captured: u64,
    pub bytes_unknown: u64,
    pub guest_sha256: Option<String>,
    pub earlier: EarlierState,
    pub first_guest_ns: u64,
    pub last_guest_ns: u64,
}

/// `recording.files.list` row: the shape depends on `tab`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum FileRow {
    Changed(FileChangedRow),
    Operation(FileOperationRow),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum VersionKind {
    Earlier,
    Later,
}

/// `recording.files.versions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileVersion {
    pub version_id: String,
    pub kind: VersionKind,
    pub size: u64,
    pub sha256: Option<String>,
    pub available: bool,
    pub status: EarlierState,
    pub reason: Option<String>,
}

/// The content of `recording.files.versions`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileVersions {
    pub versions: Vec<FileVersion>,
}

// ---------------------------------------------------------------------
// Network (in `types/network.rs`)

mod network;
pub use network::*;

// ---------------------------------------------------------------------
// Timeline

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TimelineKind {
    ProcessStart,
    ProcessExit,
    Finding,
    File,
    Network,
    Detection,
}

/// The row to open, by `kind`: `{finding_id}`, `{file_id}`,
/// `{capture_id, frame}`, `{detection_id}` or an invocation `ref`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum TimelineRef {
    Finding { finding_id: String },
    File { file_id: String },
    Frame { capture_id: String, frame: u64 },
    Detection { detection_id: String },
    Call(CallRef),
}

/// `recording.timeline` item. No merged timeline exists in the engine; this
/// object is composed from the models above.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TimelineEvent {
    pub ts_ms: u64,
    pub guest_ns: Option<u64>,
    pub kind: TimelineKind,
    pub pid: Option<u32>,
    /// For `finding` and `detection`.
    pub tier: Option<Tier>,
    /// One line, at most 200 characters. U
    pub title: String,
    #[serde(rename = "ref")]
    pub target: TimelineRef,
}

// ---------------------------------------------------------------------
// Summary

/// `recording.summary`: the assessment fields of the JSON report summary (5.4.3
/// without the policy `label` and `score`, which belong to a job).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Summary {
    pub assessment: crate::api::assessment::AssessmentKind,
    pub highest_tier: Tier,
    pub families: Vec<String>,
    pub counts: Counts,
    pub key_behaviours: Vec<KeyBehaviour>,
    pub detections: Vec<DetectionHit>,
    pub techniques: Vec<String>,
    pub ioc_dataset_count: u32,
    /// One sentence stating why.
    pub basis: String,
}

// ---------------------------------------------------------------------
// Cores, analysis, custody, terminal, artifacts

/// The `CoreReason` spelling is the engine's; carried as text.
/// `recording.cores.list` item. Registers, mappings and memory are not sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CoreInfo {
    pub core_id: String,
    pub state: ArtifactState,
    pub reason: Option<String>,
    pub requested_size: Option<u64>,
    pub accepted_size: Option<u64>,
    pub expected_size: Option<u64>,
    pub saved_size: Option<u64>,
    pub logical_size: Option<u64>,
    /// Counts only.
    pub threads: Option<u64>,
    pub mappings: Option<u64>,
    /// U
    pub warnings: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisKindName {
    Metadata,
    Structures,
    Strings,
    Regex,
    Entropy,
    Hardening,
    Rules,
    Identification,
    Capabilities,
    Disassembly,
    Decompilation,
    Embedded,
    Floss,
    Unpacking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisSectionState {
    Pending,
    Running,
    Complete,
    Partial,
    Unavailable,
    Timeout,
}

/// `AnalysisLimit`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisLimitInfo {
    pub kind: String,
    pub text: String,
    pub seconds: Option<u64>,
    pub setting: Option<String>,
}

/// The companion disassembly of a section (`AnalysisDisassembly`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GhidraInfo {
    pub tool: String,
    pub language: String,
    pub endian: String,
    pub pointer_bits: u32,
    pub functions: u64,
    pub instructions: u64,
    pub note: String,
}

/// `recording.analysis.list` item (`AnalysisSection`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisSection {
    pub kind: AnalysisKindName,
    pub state: AnalysisSectionState,
    /// One sentence. U
    pub summary: String,
    /// Tool names and versions.
    pub tools: Vec<String>,
    /// The kept listing.
    pub rows: u64,
    pub bytes: u64,
    pub truncated: bool,
    pub limits: Vec<AnalysisLimitInfo>,
    pub ghidra: Option<GhidraInfo>,
}

/// Where an analysis record sits in the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisLocation {
    /// `file_offset`, `object_address` or `relative_virtual_address`.
    pub kind: String,
    /// A hex string.
    pub value: Hex,
    pub file_range: Option<FileRange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct FileRange {
    pub offset: U64,
    pub len: u64,
}

/// The structured record of an entry (`AnalysisData`): `data` is the engine's
/// object with the tag `type`, one of `field`, `section`, `symbol`, `import`,
/// `export`, `string`, `entropy`, `property`, `instruction`, `function`,
/// `source_line`, `rule_match`, `capability`, `signature`, `floss_string`,
/// `layer`, `identification`. Its members are the engine's own, all class U.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisRecord {
    pub revision: u32,
    pub id: String,
    pub location: Option<AnalysisLocation>,
    pub data: serde_json::Value,
}

/// The entry of a listing (`AnalysisEntry`). U
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisEntry {
    pub label: String,
    pub value: String,
    /// File offset.
    pub offset: Option<U64>,
    pub record: Option<AnalysisRecord>,
}

/// A page item of `analysis.section` and `analysis.ghidra`: the listing row
/// index and the entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisRow {
    pub index: u64,
    pub entry: AnalysisEntry,
}

/// One function of a disassembly or decompilation page.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisFunctionLines {
    pub name: String,
    pub address: Hex,
    pub lines: u64,
}

/// The extras of a page of `analysis.section` and `analysis.ghidra`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AnalysisPageNotes {
    /// Disassembly and decompilation add the functions counted over the whole
    /// listing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub functions: Option<Vec<AnalysisFunctionLines>>,
    /// False for `disassembly` and `decompilation`: the engine drops `sort`.
    pub sorted: bool,
}

/// `recording.custody.list` item (`EventRow`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CustodyEntry {
    /// Number in the sample's chain, from 1.
    pub seq: u64,
    pub at_ms: u64,
    /// `app`, `auto:policy-<name>`, `web:<user>`, `local:<uid>`. U
    pub by: String,
    /// One of the names of `custody::KINDS` (plus `automation`).
    pub kind: String,
    /// The members of that `CustodyEvent` variant. A host path in `origin`,
    /// `path` or `from` is L: a remote reply carries the file name only. U
    pub data: BTreeMap<String, serde_json::Value>,
    /// Recorded before the log existed.
    pub before_chain: bool,
    pub prev: String,
    pub hash: String,
}

/// `recording.terminal.replay` item. Sample-controlled bytes: render only in a
/// terminal widget. U
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TerminalRecord {
    Output { data_b64: String },
    Resize { rows: u16, cols: u16 },
    Eof {},
}

/// What a file of the recording is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordingArtifactKind {
    TerminalJournal,
    TerminalScreen,
    RunRecord,
    ArtifactsRecord,
    TriageDigest,
    AnalysisReport,
    NetworkCapture,
    MemoryDump,
    CoreDump,
    FileBefore,
    // A timed screenshot of the VM screen (`screenshots/t+SSSSSS.s.png`); a
    // plain comment, so the schema keeps one enum list.
    Screenshot,
}

impl RecordingArtifactKind {
    /// `network_capture`, `memory_dump`, `core_dump`, `file_before` and
    /// `screenshot` are S.
    pub fn sensitive(self) -> bool {
        matches!(
            self,
            Self::NetworkCapture
                | Self::MemoryDump
                | Self::CoreDump
                | Self::FileBefore
                | Self::Screenshot
        )
    }
}

/// `recording.artifact.list` item. `telemetry.raw`, `manifest.json`,
/// `events.json` and the `objects/` store are the recorder's internal format
/// and are not listed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecordingArtifact {
    pub id: RecordingArtifactId,
    pub kind: RecordingArtifactKind,
    /// The relative file name.
    pub name: String,
    pub size: u64,
    /// Empty past the hashing limit.
    pub sha256: Option<Sha256Hex>,
    pub sensitive: bool,
    /// For a `screenshot`: milliseconds since the run started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_time_ms: Option<u64>,
}

/// The bytes of a read (`captured.read`, `files.content`, `artifact.get`,
/// `network.packet` bytes) on the socket: base64, with the range it covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BytesReply {
    pub offset: U64,
    pub len: u64,
    pub data_b64: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::syscall_groups::SyscallGroup;

    #[test]
    fn syscall_group_names_follow_the_engine() {
        assert_eq!(SyscallGroup::ALL.len(), SyscallGroupName::ALL.len());
        for (engine, name) in SyscallGroup::ALL.into_iter().zip(SyscallGroupName::ALL) {
            assert_eq!(SyscallGroupName::from(engine), name);
        }
    }

    #[test]
    fn u64_identifiers_are_decimal_strings() {
        let call = CallRef {
            stream: U64(u64::MAX),
            task: U64(9_007_199_254_740_993),
            call: U64(0),
        };
        let value = serde_json::to_value(call).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"stream": "18446744073709551615",
                "task": "9007199254740993", "call": "0"})
        );
        assert_eq!(serde_json::from_value::<CallRef>(value).unwrap(), call);
        assert!(
            serde_json::from_value::<U64>(serde_json::json!(5)).is_err(),
            "a number is refused"
        );
        assert!(serde_json::from_value::<U64>(serde_json::json!("05")).is_err());
        assert!(serde_json::from_value::<U64>(serde_json::json!("18446744073709551616")).is_err());
        assert!(serde_json::from_value::<U64>(serde_json::json!("-1")).is_err());
    }
}

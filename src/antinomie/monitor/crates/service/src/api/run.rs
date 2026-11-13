// SPDX-License-Identifier: GPL-3.0-only
//! `Run` (design 5.4.2) and the small enums around it: states, stages, wait
//! reasons, revert strategies, run end reasons, and the recording phase.

use super::ops::Permission;
use super::{
    artifact::Artifact,
    assessment::Assessment,
    failure::Failure,
    ids::{LaneId, RunId, Sha256Hex},
    spec::RunRequest,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// The run states of design 5.6. `state` and `outcome` are equal once terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    Running,
    Cancelling,
    Succeeded,
    Partial,
    Failed,
    Cancelled,
    Rejected,
}

impl RunState {
    pub fn is_terminal(self) -> bool {
        self.outcome().is_some()
    }

    /// The outcome a terminal state stands for.
    pub fn outcome(self) -> Option<Outcome> {
        match self {
            Self::Succeeded => Some(Outcome::Succeeded),
            Self::Partial => Some(Outcome::Partial),
            Self::Failed => Some(Outcome::Failed),
            Self::Cancelled => Some(Outcome::Cancelled),
            Self::Rejected => Some(Outcome::Rejected),
            Self::Queued | Self::Running | Self::Cancelling => None,
        }
    }
}

/// A terminal state: the set `outcome` takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Partial,
    Failed,
    Cancelled,
    Rejected,
}

impl From<Outcome> for RunState {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Succeeded => Self::Succeeded,
            Outcome::Partial => Self::Partial,
            Outcome::Failed => Self::Failed,
            Outcome::Cancelled => Self::Cancelled,
            Outcome::Rejected => Self::Rejected,
        }
    }
}

/// The pipeline stages (design 4.1), in order.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Prechecks,
    Provision,
    Upload,
    Launch,
    Run,
    Collect,
    Analyse,
    Report,
    Cleanup,
}

/// Why a `queued` run is not running yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WaitingFor {
    Lane,
    Resources,
    Dependency,
    /// A limit of the caller: also the caller already has `max_running`
    /// runs running (the run starts when one of them ends).
    Quota,
    QueuePaused,
    LayerPending,
    Backoff,
    LaneQuarantined,
}

/// How the lane VM was made clean (design 4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Revert {
    SnapshotDisk,
    SnapshotFull,
    Reset,
    Clone,
    None,
}

/// How the program's run ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EndReason {
    Exited,
    Signaled,
    TimeLimit,
    Stopped,
    GuestLost,
}

/// The recording phase of design 5.12.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordingPhase {
    Live,
    Finalizing,
    Complete,
    Interrupted,
}

/// The library sample of a run, once archived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunSample {
    pub sha256: Sha256Hex,
    pub size: u64,
    /// From `samples::detect_type`: `elf`, `sh`, `py`, ... (lower case).
    #[serde(rename = "type")]
    pub kind: String,
    /// `x86_64`, `AArch64`, ...; null when none.
    pub architecture: Option<String>,
    pub name: String,
}

/// The preset a run froze: its name and the digest of the exact content
/// used; for a Custom run (any override that changed a value) the name
/// `custom`, the digest of the resolved options, the preset it was based on
/// and the keys it changed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PresetRef {
    pub name: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub based_on: Option<PresetBase>,
    /// Dotted keys of the preset format (`program.run_time_s`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<String>,
}

/// One permission a run's options use: the permission, the preset key that
/// uses it, and where the caller's permission came from (`caller`: the
/// permission set of the caller, the only source before 0.9.1's roles and
/// grants).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PermissionUse {
    pub permission: Permission,
    /// The dotted preset key (`network.route`).
    pub field: String,
    pub source: String,
}

/// The preset a Custom run started from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PresetBase {
    pub name: String,
    pub digest: String,
}

/// The VM a run ran on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunVm {
    pub id: String,
    pub name: String,
    pub base_identity: Option<String>,
    pub revert: Revert,
}

/// One dump a dump trigger took (or tried to take).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunDump {
    /// The artifact state: `in_progress`, `complete`, `partial`,
    /// `interrupted` or `failed`. A core is usually `partial`: the guest
    /// copies only the pages that are resident.
    pub state: String,
    /// Bytes on disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Local-only, like `recording.directory`: absent from every remote reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// A suspicious-activity match that took a dump: the rule, its tier, the
/// process and call, and what became of the memory dump and the core.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunTrigger {
    pub rule: String,
    /// `low`, `medium` or `high`.
    pub tier: String,
    pub summary: String,
    pub syscall: String,
    pub pid: u32,
    /// Host Unix milliseconds of the match.
    pub at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<RunDump>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core: Option<RunDump>,
}

/// The program: the sample's execution inside the run. `id` is the engine's
/// id of that execution (the `run_id` of its recording).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunProgram {
    pub id: String,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub end_reason: Option<EndReason>,
    /// The exit code when the program exited.
    pub exit: Option<i32>,
    /// The signal number when it was killed by one.
    pub signal: Option<i32>,
    pub core_dumped: bool,
    /// The dumps the preset's dump trigger took, in order; empty when the
    /// trigger is off or took none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub triggers: Vec<RunTrigger>,
    /// What the trigger did when it took nothing, or took less than it was
    /// asked: "armed but no rule of that tier matched", matches that came too
    /// late, matches over the budget.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trigger_notes: Vec<String>,
    /// Evidence still being written when the collect wait ended and the
    /// recording was saved without it: `analysis` (the guest-side static
    /// checks). The run still succeeds. Empty when everything finished.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending: Vec<String>,
}

/// The recording of the run's program. `recording_key` is the address of
/// every `recording.*` read; `vm_id`, `boot_id` and `run_id` are the engine's
/// own ids of the recorded execution (`run_id` equals `program.id`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunRecording {
    pub vm_id: String,
    pub boot_id: String,
    pub run_id: String,
    pub recording_key: String,
    pub phase: RecordingPhase,
    /// Local-only; absent from every remote reply.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory: Option<String>,
}

/// A non-fatal note. Capped at 1000 entries; the 1001st is replaced by one
/// `warnings_truncated` entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Warning {
    pub code: String,
    pub text: String,
}

/// The run object returned by `run.get`, `run.submit` and `run.list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Run {
    pub api_version: u32,
    pub id: RunId,
    pub state: RunState,
    /// While `running` or `cancelling`; null otherwise.
    pub stage: Option<Stage>,
    /// While `queued`: why it is not running yet; null otherwise.
    pub waiting_for: Option<WaitingFor>,
    /// Null while not terminal.
    pub outcome: Option<Outcome>,
    pub created_ms: u64,
    pub started_ms: Option<u64>,
    pub finished_ms: Option<u64>,
    /// While `queued`: 0 is next.
    pub queue_position: Option<u32>,
    pub attempt: u32,
    pub max_attempts: u32,
    pub client_id: String,
    /// The request as stored: the preset's name and the priority filled in,
    /// `overrides` reduced to the keys that changed a value.
    pub request: RunRequest,
    pub sample: Option<RunSample>,
    /// The preset the run froze: its name and digest, or `custom` with the
    /// preset it was based on and the keys it changed.
    pub preset: PresetRef,
    /// Every resolved option of the run (the frozen preset, with the same
    /// tables and keys as a preset file).
    #[serde(default)]
    pub settings: Value,
    /// The permissions the run's options use, beside `runs.submit`, in the
    /// order of the access specification; checked at submit and again when
    /// the run starts.
    #[serde(default)]
    pub permissions_used: Vec<PermissionUse>,
    pub lane: Option<LaneId>,
    pub vm: Option<RunVm>,
    pub program: Option<RunProgram>,
    pub recording: Option<RunRecording>,
    pub assessment: Option<Assessment>,
    pub artifacts: Vec<Artifact>,
    pub warnings: Vec<Warning>,
    /// Set when `failed` or `rejected`. Null for `partial`: a partial run
    /// explains itself only through `warnings`.
    pub failure: Option<Failure>,
    pub repeat_of: Option<RunId>,
    pub labels: BTreeMap<String, String>,
    /// The host work items of the run (pipelined host stages, ANT-T0454):
    /// empty until `collect` has handed the run to the host work pool.
    #[serde(default)]
    pub host_work: Vec<HostItem>,
}

/// Where a host work item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HostItemState {
    /// In the pool's queue (first come, first served by run arrival).
    Queued,
    Running,
    Done,
    /// It ended with a problem (a warning of the run, or its failure when the
    /// preset requires the stage).
    Failed,
    /// It passed its time limit and was stopped.
    TimedOut,
    /// Not run: the run ended first (cancelled, failed, past its deadline).
    Skipped,
}

/// One piece of a run's host processing: a static tool (`static:floss`,
/// `static:decompilation`, ...), `triage`, `detection`, `assess` (digest and
/// label) or `report`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostItem {
    pub name: String,
    pub state: HostItemState,
    /// Names of the items it waits for.
    #[serde(default)]
    pub after: Vec<String>,
    /// The expected time (seconds): the larger of this host's recent median
    /// of the item and an estimate from the input size, else the fixed limit.
    pub expected_s: u64,
    /// Where `expected_s` came from: `median`, `estimate`, `fixed` or
    /// `preset` (a fixed limit the preset sets).
    pub basis: String,
    /// Its own time limit (seconds): `daemon.host_time_factor` x
    /// `expected_s`, or the preset's fixed limit. Time in the queue does not
    /// count.
    pub limit_s: u64,
    pub started_ms: Option<u64>,
    pub finished_ms: Option<u64>,
    /// A problem in words, when it had one.
    pub note: Option<String>,
}

/// The result of `run.submit`: the stored run, plus `replayed` when an
/// idempotency key returned the original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Submitted {
    #[serde(flatten)]
    pub run: Run,
    #[serde(default)]
    pub replayed: bool,
}

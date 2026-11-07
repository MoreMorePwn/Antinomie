// SPDX-License-Identifier: GPL-3.0-only
//! `Job` (design 5.4.2) and the small enums around it: states, stages, wait
//! reasons, revert strategies, run end reasons, and the recording phase.

use super::{
    artifact::Artifact,
    assessment::Assessment,
    failure::Failure,
    ids::{JobId, LaneId, Sha256Hex},
    spec::JobSpec,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The job states of design 5.6. `state` and `outcome` are equal once terminal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Cancelling,
    Succeeded,
    Partial,
    Failed,
    Cancelled,
    Rejected,
}

impl JobState {
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

impl From<Outcome> for JobState {
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

/// Why a `queued` job is not running yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum WaitingFor {
    Lane,
    Resources,
    Dependency,
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

/// The library sample of a job, once archived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobSample {
    pub sha256: Sha256Hex,
    pub size: u64,
    /// From `samples::detect_type`: `elf`, `sh`, `py`, ... (lower case).
    #[serde(rename = "type")]
    pub kind: String,
    /// `x86_64`, `AArch64`, ...; null when none.
    pub architecture: Option<String>,
    pub name: String,
}

/// The frozen policy: its name and the digest of the exact content used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyRef {
    pub name: String,
    pub digest: String,
}

/// The VM a job ran on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobVm {
    pub id: String,
    pub name: String,
    pub base_identity: Option<String>,
    pub revert: Revert,
}

/// The program's run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobRun {
    pub run_id: String,
    pub started_ms: Option<u64>,
    pub ended_ms: Option<u64>,
    pub end_reason: Option<EndReason>,
    /// The exit code when the program exited.
    pub exit: Option<i32>,
    /// The signal number when it was killed by one.
    pub signal: Option<i32>,
    pub core_dumped: bool,
}

/// The recording of the job's run. `run_key` is the address of every
/// `recording.*` read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobRecording {
    pub vm_id: String,
    pub boot_id: String,
    pub run_id: String,
    pub run_key: String,
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

/// The job object returned by `job.get`, `job.submit` and the list.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Job {
    pub api_version: u32,
    pub id: JobId,
    pub state: JobState,
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
    pub spec: JobSpec,
    pub sample: Option<JobSample>,
    pub policy: PolicyRef,
    pub lane: Option<LaneId>,
    pub vm: Option<JobVm>,
    pub run: Option<JobRun>,
    pub recording: Option<JobRecording>,
    pub assessment: Option<Assessment>,
    pub artifacts: Vec<Artifact>,
    pub warnings: Vec<Warning>,
    /// Set when `failed` or `rejected`. Null for `partial`: a partial job
    /// explains itself only through `warnings`.
    pub failure: Option<Failure>,
    pub repeat_of: Option<JobId>,
    pub labels: BTreeMap<String, String>,
}

/// The result of `job.submit`: the stored job, plus `replayed` when an
/// idempotency key returned the original.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Submitted {
    #[serde(flatten)]
    pub job: Job,
    #[serde(default)]
    pub replayed: bool,
}

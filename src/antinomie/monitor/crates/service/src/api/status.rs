// SPDX-License-Identifier: GPL-3.0-only
//! The state objects around the jobs: `Sample` (5.4.7), `QueueStatus`
//! (5.4.8), `Capabilities` (5.4.9), `health` (5.3) and the summaries of
//! policies, VMs and bases.

use super::{
    event::LaneState,
    ids::{JobId, LaneId, Sha256Hex},
    spec::{ReportFormat, Route, StaticCheck},
};
use crate::query::catalogue::QueryCatalogue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// A library tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Tag {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Sample {
    pub sha256: Sha256Hex,
    pub size: u64,
    /// From `detect_type` (lower case, for example `elf`).
    #[serde(rename = "type")]
    pub kind: String,
    /// `x86_64`, `AArch64`, ...; null when none.
    pub architecture: Option<String>,
    pub name: String,
    pub tags: Vec<Tag>,
    pub first_seen_ms: u64,
    /// Runs known to the library.
    pub run_count: u64,
    pub last_job: Option<JobId>,
    /// The cached chain check; null when not checked.
    pub custody_ok: Option<bool>,
}

/// Who holds the data directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum Owner {
    Daemon,
    Gui,
    CliDirect,
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PauseReason {
    Operator,
    LowDisk,
    NoKvm,
    LaneQuarantined,
    /// The `run/PAUSE` file.
    File,
}

/// Whether the lane VM has a pending run layer (5.12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskLayer {
    None,
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct LaneStatus {
    pub lane: LaneId,
    pub state: LaneState,
    pub job_id: Option<JobId>,
    pub vm_id: Option<String>,
    pub since_ms: u64,
    pub disk_layer: DiskLayer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueLimits {
    pub max_queue: u32,
    pub max_concurrent: u32,
    pub per_client_queued: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct QueueStatus {
    /// New jobs are not started.
    pub paused: bool,
    pub pause_reason: Option<PauseReason>,
    pub queued: u32,
    pub running: u32,
    pub lanes: Vec<LaneStatus>,
    pub limits: QueueLimits,
    pub owner: Owner,
}

/// A loaded indicator dataset and its entry count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct IocDataset {
    pub name: String,
    pub entries: u64,
}

/// Availability of the detection engines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetectionCaps {
    pub yara: bool,
    pub sigma: bool,
    pub ids: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Accelerator {
    Kvm,
    Tcg,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Capabilities {
    pub api_version: u32,
    /// `APP_VERSION`.
    pub app_version: String,
    /// `APP_REVISION`.
    pub app_revision: u32,
    /// Concurrent VMs (1 in the first release).
    pub lanes: u32,
    /// The minimum of 5.4.1 for the current lane.
    pub max_sample_bytes: u64,
    pub accept_types: Vec<String>,
    pub accept_arch: Vec<String>,
    /// Routes a caller may request under its policies (v1: a subset of
    /// `drop` and `inet_sim`).
    pub routes: Vec<Route>,
    pub report_formats: Vec<ReportFormat>,
    /// Available check names, tool presence considered.
    pub static_checks: Vec<StaticCheck>,
    pub detection: DetectionCaps,
    pub ioc_datasets: Vec<IocDataset>,
    /// A `tcg` service says so because runs are slow.
    pub accelerator: Accelerator,
    pub queries: QueryCatalogue,
    /// Strings such as `upload.chunked`, `events.resume`, `recording.query`,
    /// `lanes.multi`.
    pub features: Vec<String>,
}

/// The engine counters of `health` (numbers and enums only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EngineHealth {
    pub ui_dropped: u64,
    pub shedding: bool,
    pub reply_stalls: u64,
    pub read_gaps: ReadGaps,
    pub lane_states: Vec<LaneState>,
    pub queue_depth: u32,
    pub disk_free_gib: u64,
    pub ram_free_mib: u64,
    pub accelerator: Accelerator,
}

/// `Snapshot.health.read_gaps` reduced to numbers a client can chart.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReadGaps {
    pub count: u64,
    pub total_ns: u64,
    pub longest_ns: u64,
}

/// The result of `health`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HealthStatus {
    pub ok: bool,
    pub ready: bool,
    pub owner: Owner,
    pub reasons: Vec<String>,
    pub engine: EngineHealth,
}

/// A policy a caller may use (`policy.list`); never secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicySummary {
    pub name: String,
    pub description: String,
    /// The policy's ceilings by key (`max_run_s`, `max_sample_mib`, ...).
    pub ceilings: BTreeMap<String, Value>,
}

/// A VM a policy can use (`vm.list`); lane VMs carry `lane`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VmSummary {
    pub id: String,
    pub name: String,
    pub base_identity: Option<String>,
    pub lane: Option<LaneId>,
}

/// An installed base (`base.list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BaseSummary {
    pub identity: String,
    pub name: String,
    pub architecture: Option<String>,
}

/// The result of `custody.verify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CustodyVerification {
    pub ok: bool,
    /// The head hash of the verified chain, when one sample was asked for.
    pub head: Option<String>,
    pub problems: Vec<String>,
}

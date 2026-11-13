// SPDX-License-Identifier: GPL-3.0-only
//! The state objects around the runs: `Sample` (5.4.7), `QueueStatus`
//! (5.4.8), `Capabilities` (5.4.9), `health` (5.3) and the summaries of
//! presets, VMs and bases.

use super::{
    event::LaneState,
    ids::{LaneId, RunId, Sha256Hex},
    ops::Permission,
    spec::{ReportFormat, Route, StaticCheck},
};
use crate::query::catalogue::QueryCatalogue;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    pub last_run: Option<RunId>,
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
    pub run_id: Option<RunId>,
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
    /// New runs are not started.
    pub paused: bool,
    pub pause_reason: Option<PauseReason>,
    pub queued: u32,
    pub running: u32,
    pub lanes: Vec<LaneStatus>,
    pub limits: QueueLimits,
    pub owner: Owner,
    /// The host work pool (ANT-T0454).
    #[serde(default)]
    pub host_pool: HostPoolStatus,
}

/// The host work pool: one for every lane, at most `workers` items at once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct HostPoolStatus {
    /// `daemon.host_workers`.
    pub workers: u32,
    /// Items waiting to start (the queue length).
    pub queued: u32,
    pub running: u32,
    /// Runs with host work left.
    pub runs: u32,
    /// Why the first queued item does not start, when it waits for memory.
    pub waiting_for: Option<String>,
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
    /// The routes this node runs: `drop` and `inet_sim` (no live route is
    /// set up before 0.9.1).
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

/// A preset (`preset.list`): what its options need and whether the caller and
/// the node have it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PresetSummary {
    pub name: String,
    pub title: String,
    pub description: String,
    pub digest: String,
    /// One of the five presets that ship with the service (read-only).
    pub built_in: bool,
    /// The roles that see it on Submit (a list, not a lock).
    pub offered_to: Vec<String>,
    /// The permissions its options need, beside `runs.submit`.
    pub needs: Vec<Permission>,
    /// The ones of `needs` the caller lacks.
    pub missing: Vec<Permission>,
    /// What this node does not have for it ("route tor is not set up on
    /// this node"); a run of it is refused `unavailable_on_node`.
    pub unavailable: Vec<String>,
    /// The caller can run it as it is: nothing `missing`, nothing
    /// `unavailable`.
    pub usable: bool,
}

/// A VM a preset can use (`vm.list`); lane VMs carry `lane`.
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

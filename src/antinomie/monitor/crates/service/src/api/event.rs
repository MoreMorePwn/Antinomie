// SPDX-License-Identifier: GPL-3.0-only
//! Events and frames (design 5.5). One envelope for every event, stored per
//! job and engine-wide. `engine.hello` and `engine.ping` are frames, not
//! events.

use super::{
    artifact::Artifact,
    assessment::Assessment,
    failure::Failure,
    ids::{JobId, LaneId},
    job::{Job, JobState, Outcome, Stage, WaitingFor},
    ops::Permission,
    spec::Route,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventScope {
    Job,
    Engine,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Started,
    Finished,
    Skipped,
    Failed,
}

/// Vm figures of `job.metrics`; numbers only. `cpu_percent` is the host QEMU
/// process figure; the guest figures come from `VmResources.guest`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MetricsVm {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ram_used_mib: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_used_mib: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MetricsRun {
    pub live_tasks: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recorded_events: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MetricsHealth {
    pub dropped: u64,
    pub shedding: bool,
}

/// The `lane.state` values (design 5.4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LaneState {
    Idle,
    Busy,
    Quarantined,
    Starting,
    Stopped,
}

/// The type and `data` of an event. The wire form is
/// `{"type": "job.state", "data": {...}}` beside the envelope's other fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "data")]
pub enum EventBody {
    /// Accepted by `job.submit`.
    #[serde(rename = "job.created")]
    JobCreated { job: Box<Job> },
    /// Any change of state, stage or `waiting_for`.
    #[serde(rename = "job.state")]
    JobState {
        state: JobState,
        stage: Option<Stage>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        waiting_for: Option<WaitingFor>,
        attempt: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        queue_position: Option<u32>,
    },
    /// Per stage.
    #[serde(rename = "job.stage")]
    JobStage {
        stage: Stage,
        status: StageStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },
    /// Ephemeral: not stored, no `seq`. At most 4 per second per job.
    #[serde(rename = "job.progress")]
    JobProgress {
        stage: Stage,
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fraction: Option<f64>,
    },
    /// The program started.
    #[serde(rename = "job.run")]
    JobRun {
        run_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        route: Route,
    },
    #[serde(rename = "job.warning")]
    JobWarning { code: String, text: String },
    /// An artifact became available.
    #[serde(rename = "job.artifact")]
    JobArtifact { artifact: Artifact },
    /// The run's dump trigger matched and took a dump, or did nothing
    /// (`trigger` absent, `note` says why). No host paths.
    #[serde(rename = "job.trigger")]
    JobTrigger {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger: Option<Box<super::job::JobTrigger>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
    /// Triage finished.
    #[serde(rename = "job.assessment")]
    JobAssessment { assessment: Box<Assessment> },
    /// A retry was scheduled; a `job.state` event with `state: queued` follows.
    #[serde(rename = "job.requeued")]
    JobRequeued { attempt: u32, reason: String },
    /// The last event of a job.
    #[serde(rename = "job.finished")]
    JobFinished {
        outcome: Outcome,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure: Option<Failure>,
    },
    /// A lane changed state (engine scope).
    #[serde(rename = "lane.state")]
    LaneState {
        lane: LaneId,
        state: LaneState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<JobId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// Low disk, KVM lost, custody problem, a queue paused by a safety rule,
    /// `slow_consumer` (engine scope).
    #[serde(rename = "engine.alert")]
    EngineAlert { code: String, text: String },
    /// Ephemeral: not stored, no `seq`. While stage is `run`, at most one per
    /// 2 seconds.
    #[serde(rename = "job.metrics")]
    JobMetrics {
        stage: Stage,
        vm: MetricsVm,
        run: MetricsRun,
        health: MetricsHealth,
    },
}

impl EventBody {
    /// `job.progress` and `job.metrics` are not stored and carry no `seq`.
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, Self::JobProgress { .. } | Self::JobMetrics { .. })
    }

    /// The scope the type belongs to.
    pub fn scope(&self) -> EventScope {
        match self {
            Self::LaneState { .. } | Self::EngineAlert { .. } => EventScope::Engine,
            _ => EventScope::Job,
        }
    }

    /// The permission a subscriber needs to receive the event. Every kind
    /// is a fact about a run or the node that `runs.see_all` sees (the lanes
    /// page too); none carries evidence bytes, which stay behind
    /// `evidence.view` and `evidence.download` on their own reads.
    pub fn permission(&self) -> Permission {
        match self {
            Self::JobCreated { .. }
            | Self::JobState { .. }
            | Self::JobStage { .. }
            | Self::JobProgress { .. }
            | Self::JobRun { .. }
            | Self::JobWarning { .. }
            | Self::JobArtifact { .. }
            | Self::JobTrigger { .. }
            | Self::JobAssessment { .. }
            | Self::JobRequeued { .. }
            | Self::JobFinished { .. }
            | Self::JobMetrics { .. }
            | Self::LaneState { .. }
            | Self::EngineAlert { .. } => Permission::RunsSeeAll,
        }
    }
}

/// The envelope. `seq` counts within one job (job scope) or one service epoch
/// (engine scope) from 1; `gseq` is strictly increasing across the service,
/// persisted and never reused. Both are absent on ephemeral events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Event {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gseq: Option<u64>,
    /// The time the service recorded it.
    pub ts_ms: u64,
    pub scope: EventScope,
    pub job_id: Option<JobId>,
    #[serde(flatten)]
    pub body: EventBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HelloOwner {
    /// A separate service process.
    Daemon,
    /// The service runs inside the web process.
    Embedded,
}

/// The one hello shape (socket connection and `events.subscribe`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Hello {
    pub api_version: u32,
    pub app_version: String,
    pub owner: HelloOwner,
    /// A random id per daemon start.
    pub epoch: String,
    /// The highest stored `gseq`.
    pub gseq: u64,
    /// True when the requested resume point is older than the retained
    /// events; the client must re-synchronise with `job.list`.
    pub truncated: bool,
}

/// `engine.hello` and `engine.ping`: neither is an event (no `seq`, no
/// `gseq`, never stored). The wire form is
/// `{"frame": "engine.hello", "data": {...}}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "frame", content = "data")]
pub enum Frame {
    #[serde(rename = "engine.hello")]
    Hello(Hello),
    /// A subscription with no event for 15 seconds.
    #[serde(rename = "engine.ping")]
    Ping {},
}

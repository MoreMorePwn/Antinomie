// SPDX-License-Identifier: GPL-3.0-only
//! The operations of design 5.3 and the local socket framing of 5.9: the
//! stable operation names, their parameters and results, the caller and the
//! permissions it holds. The recording reads (`recording.*`) are in `query`.

use super::{
    artifact::Artifact,
    error::ApiError,
    event::{Event, Frame},
    ids::{ArtifactId, RunId, Sha256Hex, UploadId},
    run::{Outcome, Run, RunState},
    spec::{Overrides, ReportFormat, SampleSource},
    status::{Sample, Tag},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

/// The stable operation name used on the local socket (`op`) and in the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum Op {
    #[serde(rename = "capabilities")]
    Capabilities,
    #[serde(rename = "health")]
    Health,
    #[serde(rename = "upload.begin")]
    UploadBegin,
    #[serde(rename = "upload.put")]
    UploadPut,
    #[serde(rename = "upload.finish")]
    UploadFinish,
    #[serde(rename = "run.submit")]
    RunSubmit,
    #[serde(rename = "run.get")]
    RunGet,
    #[serde(rename = "run.list")]
    RunList,
    #[serde(rename = "run.cancel")]
    RunCancel,
    #[serde(rename = "run.rerun")]
    RunRerun,
    #[serde(rename = "run.delete")]
    RunDelete,
    #[serde(rename = "events.subscribe")]
    EventsSubscribe,
    #[serde(rename = "events.list")]
    EventsList,
    #[serde(rename = "artifact.list")]
    ArtifactList,
    #[serde(rename = "artifact.get")]
    ArtifactGet,
    #[serde(rename = "report.get")]
    ReportGet,
    #[serde(rename = "sample.list")]
    SampleList,
    #[serde(rename = "sample.get")]
    SampleGet,
    #[serde(rename = "sample.add")]
    SampleAdd,
    #[serde(rename = "sample.download")]
    SampleDownload,
    #[serde(rename = "sample.tag")]
    SampleTag,
    #[serde(rename = "preset.list")]
    PresetList,
    #[serde(rename = "preset.get")]
    PresetGet,
    #[serde(rename = "queue.status")]
    QueueStatus,
    #[serde(rename = "queue.pause")]
    QueuePause,
    #[serde(rename = "queue.resume")]
    QueueResume,
    #[serde(rename = "vm.list")]
    VmList,
    #[serde(rename = "base.list")]
    BaseList,
    #[serde(rename = "custody.verify")]
    CustodyVerify,
}

impl Op {
    /// The permissions the operation needs: holding any one of them lets the
    /// call through (the access specification's permission list). Finer
    /// checks follow inside the operation: `artifact.get` and `report.get` of
    /// a sensitive artifact need `evidence.download`, `run.cancel` of another
    /// client's run needs `runs.manage_any`, and `run.submit` checks each run
    /// option. Uploads serve both a run and a library add.
    pub fn needs(self) -> &'static [Permission] {
        use Permission as P;
        match self {
            Self::UploadBegin | Self::UploadPut | Self::UploadFinish => {
                &[P::RunsSubmit, P::SamplesAdd]
            }
            Self::RunSubmit | Self::RunRerun | Self::PresetList | Self::PresetGet => {
                &[P::RunsSubmit]
            }
            Self::RunCancel => &[P::RunsSubmit, P::RunsManageAny],
            Self::SampleAdd => &[P::SamplesAdd],
            Self::SampleDownload => &[P::SamplesDownload],
            Self::RunDelete => &[P::RunsDelete],
            Self::SampleTag => &[P::SamplesTag],
            Self::QueuePause | Self::QueueResume => &[P::QueueManage],
            Self::CustodyVerify => &[P::CustodyVerify],
            Self::Capabilities
            | Self::Health
            | Self::RunGet
            | Self::RunList
            | Self::EventsSubscribe
            | Self::EventsList
            | Self::ArtifactList
            | Self::ArtifactGet
            | Self::ReportGet
            | Self::SampleList
            | Self::SampleGet
            | Self::QueueStatus
            | Self::VmList
            | Self::BaseList => &[P::RunsSeeAll],
        }
    }
}

/// A permission the engine checks (the access specification: 37 permissions,
/// all but `users.manage` and `audit.read`, which stay in the web). A caller
/// holds a set of them; every operation, run option, event and frozen re-check
/// asks for one by name. The wire spelling is the dotted key.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Permission {
    #[serde(rename = "runs.see_all")]
    RunsSeeAll,
    #[serde(rename = "cases.create")]
    CasesCreate,
    #[serde(rename = "runs.share")]
    RunsShare,
    #[serde(rename = "cases.join_any")]
    CasesJoinAny,
    #[serde(rename = "evidence.view")]
    EvidenceView,
    #[serde(rename = "evidence.download")]
    EvidenceDownload,
    #[serde(rename = "samples.download")]
    SamplesDownload,
    #[serde(rename = "lookup.online")]
    LookupOnline,
    #[serde(rename = "samples.add")]
    SamplesAdd,
    #[serde(rename = "runs.submit")]
    RunsSubmit,
    #[serde(rename = "runs.manage_any")]
    RunsManageAny,
    #[serde(rename = "samples.tag")]
    SamplesTag,
    #[serde(rename = "runs.annotate")]
    RunsAnnotate,
    #[serde(rename = "indicators.mark_fp")]
    IndicatorsMarkFp,
    #[serde(rename = "runs.delete")]
    RunsDelete,
    #[serde(rename = "route.internet")]
    RouteInternet,
    #[serde(rename = "route.nat")]
    RouteNat,
    #[serde(rename = "route.tor")]
    RouteTor,
    #[serde(rename = "route.vpn")]
    RouteVpn,
    #[serde(rename = "route.socks5")]
    RouteSocks5,
    #[serde(rename = "route.lan")]
    RouteLan,
    #[serde(rename = "route.unfiltered")]
    RouteUnfiltered,
    #[serde(rename = "run.as_root")]
    RunAsRoot,
    #[serde(rename = "evidence.core_dump")]
    EvidenceCoreDump,
    #[serde(rename = "evidence.memory_dump")]
    EvidenceMemoryDump,
    #[serde(rename = "evidence.disk_dump")]
    EvidenceDiskDump,
    #[serde(rename = "run.keep_vm")]
    RunKeepVm,
    #[serde(rename = "interactive.watch")]
    InteractiveWatch,
    #[serde(rename = "interactive.control")]
    InteractiveControl,
    #[serde(rename = "presets.manage")]
    PresetsManage,
    #[serde(rename = "queue.manage")]
    QueueManage,
    #[serde(rename = "lanes.reset")]
    LanesReset,
    #[serde(rename = "lanes.extend_keep")]
    LanesExtendKeep,
    #[serde(rename = "custody.verify")]
    CustodyVerify,
    #[serde(rename = "node.manage")]
    NodeManage,
}

impl Permission {
    /// Every permission the engine checks, in the order of the access
    /// specification's table.
    pub const ALL: [Self; 35] = [
        Self::RunsSeeAll,
        Self::CasesCreate,
        Self::RunsShare,
        Self::CasesJoinAny,
        Self::EvidenceView,
        Self::EvidenceDownload,
        Self::SamplesDownload,
        Self::LookupOnline,
        Self::SamplesAdd,
        Self::RunsSubmit,
        Self::RunsManageAny,
        Self::SamplesTag,
        Self::RunsAnnotate,
        Self::IndicatorsMarkFp,
        Self::RunsDelete,
        Self::RouteInternet,
        Self::RouteNat,
        Self::RouteTor,
        Self::RouteVpn,
        Self::RouteSocks5,
        Self::RouteLan,
        Self::RouteUnfiltered,
        Self::RunAsRoot,
        Self::EvidenceCoreDump,
        Self::EvidenceMemoryDump,
        Self::EvidenceDiskDump,
        Self::RunKeepVm,
        Self::InteractiveWatch,
        Self::InteractiveControl,
        Self::PresetsManage,
        Self::QueueManage,
        Self::LanesReset,
        Self::LanesExtendKeep,
        Self::CustodyVerify,
        Self::NodeManage,
    ];

    /// The dotted key (`route.tor`), as on the wire and in `service.toml`.
    pub fn key(self) -> &'static str {
        match self {
            Self::RunsSeeAll => "runs.see_all",
            Self::CasesCreate => "cases.create",
            Self::RunsShare => "runs.share",
            Self::CasesJoinAny => "cases.join_any",
            Self::EvidenceView => "evidence.view",
            Self::EvidenceDownload => "evidence.download",
            Self::SamplesDownload => "samples.download",
            Self::LookupOnline => "lookup.online",
            Self::SamplesAdd => "samples.add",
            Self::RunsSubmit => "runs.submit",
            Self::RunsManageAny => "runs.manage_any",
            Self::SamplesTag => "samples.tag",
            Self::RunsAnnotate => "runs.annotate",
            Self::IndicatorsMarkFp => "indicators.mark_fp",
            Self::RunsDelete => "runs.delete",
            Self::RouteInternet => "route.internet",
            Self::RouteNat => "route.nat",
            Self::RouteTor => "route.tor",
            Self::RouteVpn => "route.vpn",
            Self::RouteSocks5 => "route.socks5",
            Self::RouteLan => "route.lan",
            Self::RouteUnfiltered => "route.unfiltered",
            Self::RunAsRoot => "run.as_root",
            Self::EvidenceCoreDump => "evidence.core_dump",
            Self::EvidenceMemoryDump => "evidence.memory_dump",
            Self::EvidenceDiskDump => "evidence.disk_dump",
            Self::RunKeepVm => "run.keep_vm",
            Self::InteractiveWatch => "interactive.watch",
            Self::InteractiveControl => "interactive.control",
            Self::PresetsManage => "presets.manage",
            Self::QueueManage => "queue.manage",
            Self::LanesReset => "lanes.reset",
            Self::LanesExtendKeep => "lanes.extend_keep",
            Self::CustodyVerify => "custody.verify",
            Self::NodeManage => "node.manage",
        }
    }

    /// The name people read ("the Tor route permission" uses `Tor route`).
    pub fn name(self) -> &'static str {
        match self {
            Self::RunsSeeAll => "See the node's runs",
            Self::CasesCreate => "Create cases",
            Self::RunsShare => "Move runs into a case",
            Self::CasesJoinAny => "Open as admin",
            Self::EvidenceView => "See evidence bytes",
            Self::EvidenceDownload => "Download evidence",
            Self::SamplesDownload => "Download samples",
            Self::LookupOnline => "Check online",
            Self::SamplesAdd => "Add samples to the library",
            Self::RunsSubmit => "Submit runs",
            Self::RunsManageAny => "Manage anyone's runs",
            Self::SamplesTag => "Tag samples",
            Self::RunsAnnotate => "Name, tag and note runs",
            Self::IndicatorsMarkFp => "Mark as false positive",
            Self::RunsDelete => "Delete runs",
            Self::RouteInternet => "Internet route",
            Self::RouteNat => "NAT",
            Self::RouteTor => "Tor route",
            Self::RouteVpn => "VPN route",
            Self::RouteSocks5 => "SOCKS5 route",
            Self::RouteLan => "Private network addresses",
            Self::RouteUnfiltered => "Turn off the abuse filter",
            Self::RunAsRoot => "Run as root",
            Self::EvidenceCoreDump => "Core dumps",
            Self::EvidenceMemoryDump => "Memory dumps",
            Self::EvidenceDiskDump => "Disk dumps",
            Self::RunKeepVm => "Keep the VM after a failure",
            Self::InteractiveWatch => "Watch a running VM",
            Self::InteractiveControl => "Type into a running VM",
            Self::PresetsManage => "Manage presets",
            Self::QueueManage => "Manage the queue",
            Self::LanesReset => "Reset lanes",
            Self::LanesExtendKeep => "Extend a kept VM",
            Self::CustodyVerify => "Verify custody",
            Self::NodeManage => "Set up the node",
        }
    }

    /// The permission spelled `key`, or `None`.
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.key() == key)
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.key())
    }
}

/// The limits a caller brings (the access specification's "Limits per role,
/// changeable per person"). Unset means the caller adds no limit of its own;
/// the node's ceilings still apply. `service.toml` sets them: `[limits.local]`
/// for the owner on the local socket and `priority_max` per watch folder.
/// Admission refuses a run above `priority_max` or `max_run_s`
/// (`limit_exceeded`) and a submit past `max_runs_per_day` (counted only when
/// set); `max_queued` is counted per caller at submit and `max_running` when
/// a lane takes the next run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Longest run in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_run_s: Option<u32>,
    /// Highest priority, 0 to 9.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_max: Option<u8>,
    /// Runs waiting at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_queued: Option<u32>,
    /// Runs accepted in the last 24 hours; unset is no daily limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_runs_per_day: Option<u32>,
    /// Runs running at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_running: Option<u32>,
}

impl Limits {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Who is asking. The CLI uses the OS user (`local:<uid>`, every
/// permission), a watch folder its preset (`auto:preset-<name>`, `runs.submit`
/// and the folder's `permissions`); a later web layer fills it from
/// authentication (`web:<user_id>`). The service never trusts a
/// client-supplied value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Caller {
    pub client_id: String,
    /// The permissions the caller holds.
    pub permissions: BTreeSet<Permission>,
    #[serde(default, skip_serializing_if = "Limits::is_empty")]
    pub limits: Limits,
}

impl Caller {
    /// A caller holding `permissions` and no limits of its own.
    pub fn new(client_id: impl Into<String>, permissions: &[Permission]) -> Self {
        Self {
            client_id: client_id.into(),
            permissions: permissions.iter().copied().collect(),
            limits: Limits::default(),
        }
    }

    /// A caller holding every permission the engine checks.
    pub fn with_every_permission(client_id: impl Into<String>) -> Self {
        Self::new(client_id, &Permission::ALL)
    }

    pub fn has(&self, permission: Permission) -> bool {
        self.permissions.contains(&permission)
    }

    /// `permission_denied` naming `permission` unless the caller holds it.
    pub fn require(&self, permission: Permission) -> Result<(), ApiError> {
        self.require_any(&[permission])
    }

    /// `permission_denied` naming every one of `any` unless the caller holds
    /// at least one. An empty list needs nothing.
    pub fn require_any(&self, any: &[Permission]) -> Result<(), ApiError> {
        if any.is_empty() || any.iter().any(|p| self.has(*p)) {
            Ok(())
        } else {
            Err(ApiError::permission_denied(any))
        }
    }
}

/// The request line of the local socket.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Request {
    pub id: u64,
    /// An [`Op`] spelling, a `recording.*` op, or `cancel`.
    pub op: String,
    #[serde(default)]
    pub params: Value,
}

/// A reply line: `{"id": 7, "ok": true, "result": {...}}`,
/// `{"id": 7, "ok": false, "error": {...}}`, an event line
/// `{"id": 7, "event": {...}}`, or a frame line (the hello that starts an
/// `events.subscribe` answer carries the request `id` beside `frame` and
/// `data`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Reply {
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event: Option<Box<Event>>,
    #[serde(flatten)]
    pub frame: Option<Frame>,
}

impl Reply {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            ok: Some(true),
            result: Some(result),
            error: None,
            event: None,
            frame: None,
        }
    }

    pub fn failed(id: u64, error: ApiError) -> Self {
        Self {
            id,
            ok: Some(false),
            result: None,
            error: Some(error),
            event: None,
            frame: None,
        }
    }

    pub fn event(id: u64, event: Event) -> Self {
        Self {
            id,
            ok: None,
            result: None,
            error: None,
            event: Some(Box::new(event)),
            frame: None,
        }
    }
}

// Parameters and results. Every request type refuses unknown fields.

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadBeginParams {
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Hex>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UploadBegun {
    pub upload_id: UploadId,
    /// The longest chunk one `upload.put` may carry.
    pub max_chunk: u64,
}

/// Strictly sequential: `offset` must equal `received`, else `conflict`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadPutParams {
    pub upload_id: UploadId,
    pub offset: u64,
    /// Base64, at most 1 MiB per call on the socket.
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UploadReceived {
    pub received: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UploadFinishParams {
    pub upload_id: UploadId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UploadFinished {
    pub upload_id: UploadId,
    pub sha256: Sha256Hex,
    pub size: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunIdParams {
    pub run_id: RunId,
}

/// 1 to 200, default 50, newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<RunState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Hex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunList {
    pub runs: Vec<Run>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunCancelParams {
    pub run_id: RunId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunRerunParams {
    pub run_id: RunId,
    /// Another preset, as it is now (default: the run's own options).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<Overrides>,
    /// 0 to 9 (default: the run's own, lowered to the caller's
    /// `priority_max` when above it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunDeleteParams {
    pub run_id: RunId,
    /// Also remove the recording (the sample is never removed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_recording: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Deleted {
    pub deleted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsSubscribeParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// With `run_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_seq: Option<u64>,
    /// Without `run_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_gseq: Option<u64>,
    /// Event type names (`run.state`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsListParams {
    pub run_id: RunId,
    pub after_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct EventList {
    pub events: Vec<Event>,
    pub next_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactList {
    pub artifacts: Vec<Artifact>,
}

/// A byte range of an artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ByteRange {
    pub offset: u64,
    pub len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactGetParams {
    pub artifact_id: ArtifactId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReportGetParams {
    pub run_id: RunId,
    pub format: ReportFormat,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    /// One tag as `KIND=VALUE` (a bare value is a custom tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// More tags a sample must also have (additive to the 5.3 table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Include samples whose archive was removed (additive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all: Option<bool>,
    /// Fill `custody_ok` by checking every chain (additive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SampleList {
    pub samples: Vec<Sample>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sha256Params {
    pub sha256: Sha256Hex,
}

/// `sample.get`: the sample, and on request the routes that brought it in, its
/// custody events and its runs (additive members of the 5.3 table).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleGetParams {
    pub sha256: Sha256Hex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origins: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub events: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runs: Option<bool>,
}

/// `sample.download`: a range of the library archive (an AES zip), at most
/// 1 MiB per call, as Base64.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleDownloadParams {
    pub sha256: Sha256Hex,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
}

/// `sample.add`: `sample.upload_id`, or `sample.path` (local-only).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleAddParams {
    pub sample: SampleSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<Tag>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SampleTagParams {
    pub sha256: Sha256Hex,
    pub tags: Vec<Tag>,
}

/// `preset.list`: every preset, with what its options need.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PresetList {
    pub presets: Vec<super::status::PresetSummary>,
}

/// `preset.get`: one preset by name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PresetGetParams {
    pub name: String,
}

/// The result of `preset.get`: the whole preset with the same tables and keys
/// as its file (`settings`, flattened), beside its name, digest and whether
/// it is built in.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PresetDetail {
    pub name: String,
    pub digest: String,
    pub built_in: bool,
    #[serde(flatten)]
    pub settings: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VmList {
    pub vms: Vec<super::status::VmSummary>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BaseList {
    pub bases: Vec<super::status::BaseSummary>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CustodyVerifyParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Sha256Hex>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn the_engine_checks_35_permissions_with_their_dotted_keys() {
        let keys: BTreeSet<&str> = Permission::ALL.iter().map(|p| p.key()).collect();
        assert_eq!(keys.len(), 35);
        // users.manage and audit.read stay in the web.
        assert!(!keys.contains("users.manage") && !keys.contains("audit.read"));
        for permission in Permission::ALL {
            assert_eq!(
                serde_json::to_value(permission).unwrap(),
                json!(permission.key())
            );
            assert_eq!(Permission::from_key(permission.key()), Some(permission));
            assert_eq!(permission.to_string(), permission.key());
            assert!(!permission.name().is_empty());
        }
        assert_eq!(Permission::from_key("users.manage"), None);
        assert!(serde_json::from_value::<Permission>(json!("manage")).is_err());
    }

    #[test]
    fn each_operation_needs_its_permissions() {
        use Permission as P;
        for (op, needs) in [
            (Op::RunSubmit, &[P::RunsSubmit][..]),
            (Op::RunRerun, &[P::RunsSubmit]),
            (Op::SampleAdd, &[P::SamplesAdd]),
            (Op::RunDelete, &[P::RunsDelete]),
            (Op::SampleTag, &[P::SamplesTag]),
            (Op::QueuePause, &[P::QueueManage]),
            (Op::CustodyVerify, &[P::CustodyVerify]),
            (Op::SampleDownload, &[P::SamplesDownload]),
            (Op::RunGet, &[P::RunsSeeAll]),
            (Op::Health, &[P::RunsSeeAll]),
        ] {
            assert_eq!(op.needs(), needs, "{op:?}");
        }
        // Cancel: an own run with runs.submit, any with runs.manage_any.
        assert_eq!(
            Op::RunCancel.needs(),
            [Permission::RunsSubmit, Permission::RunsManageAny]
        );
    }

    #[test]
    fn require_answers_permission_denied_naming_what_is_missing() {
        let caller = Caller::new("web:7", &[Permission::RunsSeeAll]);
        assert!(caller.require(Permission::RunsSeeAll).is_ok());
        assert!(caller.require_any(&[]).is_ok());
        let error = caller
            .require_any(&[Permission::RunsSubmit, Permission::SamplesAdd])
            .unwrap_err();
        assert_eq!(error.code, super::super::error::ErrorCode::PermissionDenied);
        assert_eq!(
            error.details["needs"],
            json!(["runs.submit", "samples.add"])
        );
        let owner = Caller::with_every_permission("local:1000");
        assert!(Permission::ALL.iter().all(|p| owner.has(*p)));
        // The wire form: permissions as keys, no limits when none are set.
        let value = serde_json::to_value(&caller).unwrap();
        assert_eq!(
            value,
            json!({"client_id": "web:7", "permissions": ["runs.see_all"]})
        );
        let limited = Caller {
            limits: Limits {
                priority_max: Some(5),
                ..Limits::default()
            },
            ..caller
        };
        assert_eq!(
            serde_json::to_value(&limited).unwrap()["limits"],
            json!({"priority_max": 5})
        );
    }
}

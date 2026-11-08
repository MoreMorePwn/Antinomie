// SPDX-License-Identifier: GPL-3.0-only
//! The operations of design 5.3 and the local socket framing of 5.9: the
//! stable operation names, their parameters and results, the caller and its
//! scopes (5.8). The recording reads (`recording.*`) are in `query`.

use super::{
    artifact::Artifact,
    error::ApiError,
    event::{Event, Frame},
    ids::{ArtifactId, JobId, Sha256Hex, UploadId},
    job::{Job, JobState, Outcome},
    spec::{Overrides, ReportFormat, SampleSource},
    status::{Sample, Tag},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    #[serde(rename = "job.submit")]
    JobSubmit,
    #[serde(rename = "job.get")]
    JobGet,
    #[serde(rename = "job.list")]
    JobList,
    #[serde(rename = "job.cancel")]
    JobCancel,
    #[serde(rename = "job.retry")]
    JobRetry,
    #[serde(rename = "job.delete")]
    JobDelete,
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
    #[serde(rename = "policy.list")]
    PolicyList,
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
    /// The scope the operation needs (design 5.8). `artifact.get` and
    /// `report.get` need `read` for an artifact with `sensitive: false` and
    /// `artifacts:sensitive` otherwise; the value here is the lower bound.
    pub fn scope(self) -> Scope {
        match self {
            Self::UploadBegin
            | Self::UploadPut
            | Self::UploadFinish
            | Self::JobSubmit
            | Self::SampleAdd
            | Self::JobCancel
            | Self::JobRetry => Scope::Submit,
            Self::SampleDownload => Scope::ArtifactsSensitive,
            Self::JobDelete
            | Self::SampleTag
            | Self::QueuePause
            | Self::QueueResume
            | Self::CustodyVerify => Scope::Manage,
            Self::Capabilities
            | Self::Health
            | Self::JobGet
            | Self::JobList
            | Self::EventsSubscribe
            | Self::EventsList
            | Self::ArtifactList
            | Self::ArtifactGet
            | Self::ReportGet
            | Self::SampleList
            | Self::SampleGet
            | Self::PolicyList
            | Self::QueueStatus
            | Self::VmList
            | Self::BaseList => Scope::Read,
        }
    }
}

/// A permission (design 5.8). Names are final.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub enum Scope {
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "submit")]
    Submit,
    #[serde(rename = "artifacts:sensitive")]
    ArtifactsSensitive,
    #[serde(rename = "manage")]
    Manage,
}

/// Who is asking. The CLI uses the OS user (`local:<uid>`), the web layer
/// fills it from authentication (`web:<user_id>`). The service never trusts a
/// client-supplied value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Caller {
    pub client_id: String,
    pub scopes: Vec<Scope>,
    /// Glob patterns of the policies the caller may use.
    pub policies: Vec<String>,
}

impl Caller {
    pub fn has(&self, scope: Scope) -> bool {
        self.scopes.contains(&scope)
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
pub struct JobIdParams {
    pub job_id: JobId,
}

/// 1 to 200, default 50, newest first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<JobState>,
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
pub struct JobList {
    pub jobs: Vec<Job>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobCancelParams {
    pub job_id: JobId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobRetryParams {
    pub job_id: JobId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overrides: Option<Overrides>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobDeleteParams {
    pub job_id: JobId,
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
    pub job_id: Option<JobId>,
    /// With `job_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_seq: Option<u64>,
    /// Without `job_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_gseq: Option<u64>,
    /// Event type names (`job.state`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsListParams {
    pub job_id: JobId,
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
    pub job_id: JobId,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PolicyList {
    pub policies: Vec<super::status::PolicySummary>,
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

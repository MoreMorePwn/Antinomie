// SPDX-License-Identifier: GPL-3.0-only
//! The requests of the `recording.*` operations (design 5.12.3, 5.12.4): one
//! parameter struct per operation, and `RecordingRead`, the sum the service
//! dispatches on. Every parameter struct refuses unknown fields.

use super::{
    key::RunKey,
    page::{Page, Single},
    types::*,
};
use crate::api::{
    assessment::Tier,
    error::ApiError,
    ids::{JobId, Sha256Hex},
    ops::ByteRange,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A `sort` request: ties keep the default order. Only the fields
/// `capabilities.queries` names for the operation are allowed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Sort {
    pub field: String,
    pub dir: SortDir,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SortDir {
    Asc,
    Desc,
}

macro_rules! params {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            $(
                $(#[$fmeta])*
                pub $field: $ty,
            )*
        }
    };
}

params!(
    /// `recording.run.list`. Newest first; not sortable.
    RunFilter {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vm_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sample_sha256: Option<Sha256Hex>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<JobId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<RunStateName>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        since_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.run.get`, `recording.summary`, `recording.network.summary`,
    /// `recording.network.captures`, `recording.cores.list`,
    /// `recording.artifact.list`: the run alone.
    RunParams {
        run_key: RunKey,
    }
);

params!(
    /// `recording.trace.page`: raw-file byte offset order, not sortable.
    TracePageParams {
        run_key: RunKey,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        hide_groups: Vec<SyscallGroupName>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.trace.get`.
    TraceGetParams {
        run_key: RunKey,
        #[serde(rename = "ref")]
        call: CallRef,
    }
);

params!(
    /// `recording.captured.read`: at most 65 536 bytes. Sensitive.
    CapturedReadParams {
        run_key: RunKey,
        /// From `Invocation`.
        field: String,
        offset: U64,
        len: u32,
    }
);

params!(
    /// `recording.process.tree`.
    ProcessTreeParams {
        run_key: RunKey,
        /// Default: the run's root `pid`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        root_pid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.findings.list`.
    FindingsListParams {
        run_key: RunKey,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tier: Option<Tier>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        category: Option<FindingCategory>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        rule: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sort: Option<Sort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.findings.get`.
    FindingGetParams {
        run_key: RunKey,
        finding_id: String,
    }
);

params!(
    /// `recording.indicators.list`.
    IndicatorsListParams {
        run_key: RunKey,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<IndicatorKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        matched: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        defang: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sort: Option<Sort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.files.list`.
    FilesListParams {
        run_key: RunKey,
        tab: FileTab,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sort: Option<Sort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.files.versions`.
    FileVersionsParams {
        run_key: RunKey,
        file_id: String,
    }
);

params!(
    /// `recording.files.content`: at most 1 MiB per call. Sensitive.
    FileContentParams {
        run_key: RunKey,
        version_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        range: Option<ByteRange>,
    }
);

params!(
    /// `recording.network.list`.
    NetworkListParams {
        run_key: RunKey,
        tab: NetworkTab,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sort: Option<Sort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.network.packets`: frame order; `filter` is a Wireshark
    /// display filter, at most 500 rows per page.
    NetworkPacketsParams {
        run_key: RunKey,
        capture_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        filter: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.network.packet`. Sensitive.
    NetworkPacketParams {
        run_key: RunKey,
        capture_id: String,
        n: u64,
    }
);

params!(
    /// `recording.timeline`: `ts_ms` order, not sortable.
    TimelineParams {
        run_key: RunKey,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        from_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        kinds: Vec<TimelineKind>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.analysis.list`: exactly one of `run_key` (the analysis linked
    /// to a run) or `job_id` (the host-side analysis of a job).
    AnalysisListParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_key: Option<RunKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<JobId>,
    }
);

params!(
    /// `recording.analysis.section`: at most 1024 rows per page.
    AnalysisSectionParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_key: Option<RunKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<JobId>,
        kind: AnalysisKindName,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sort: Option<Sort>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.analysis.ghidra`: address order, not sortable.
    AnalysisGhidraParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_key: Option<RunKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        job_id: Option<JobId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        q: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.custody.list`: `sha256` instead of `run_key`, or the run's
    /// sample when `run_key` is given.
    CustodyListParams {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        run_key: Option<RunKey>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sha256: Option<Sha256Hex>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.terminal.replay`: at most 256 records; the cursor is a
    /// journal byte offset.
    TerminalReplayParams {
        run_key: RunKey,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cursor: Option<String>,
    }
);

params!(
    /// `recording.artifact.get`: at most 1 MiB per call; a capture, memory
    /// dump, core or file copy is sensitive.
    ArtifactGetParams {
        run_key: RunKey,
        artifact_id: crate::api::ids::RecordingArtifactId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        range: Option<ByteRange>,
    }
);

/// What an analysis operation reads: a run's analysis or a job's host-side one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnalysisSubject {
    Run(RunKey),
    Job(JobId),
}

/// Exactly one of `run_key` and `job_id`, else `invalid_argument`.
pub fn analysis_subject(
    run_key: &Option<RunKey>,
    job_id: &Option<JobId>,
) -> Result<AnalysisSubject, ApiError> {
    match (run_key, job_id) {
        (Some(key), None) => Ok(AnalysisSubject::Run(key.clone())),
        (None, Some(job)) => Ok(AnalysisSubject::Job(job.clone())),
        _ => Err(ApiError::invalid_argument(
            "run_key",
            "exactly one of run_key or job_id is required",
        )),
    }
}

/// Every operation of 5.12.3 with its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordingRead {
    RunList(RunFilter),
    RunGet(RunParams),
    Summary(RunParams),
    TracePage(TracePageParams),
    TraceGet(TraceGetParams),
    CapturedRead(CapturedReadParams),
    ProcessTree(ProcessTreeParams),
    FindingsList(FindingsListParams),
    FindingsGet(FindingGetParams),
    IndicatorsList(IndicatorsListParams),
    FilesList(FilesListParams),
    FilesVersions(FileVersionsParams),
    FilesContent(FileContentParams),
    NetworkSummary(RunParams),
    NetworkList(NetworkListParams),
    NetworkCaptures(RunParams),
    NetworkPackets(NetworkPacketsParams),
    NetworkPacket(NetworkPacketParams),
    Timeline(TimelineParams),
    CoresList(RunParams),
    AnalysisList(AnalysisListParams),
    AnalysisSection(AnalysisSectionParams),
    AnalysisGhidra(AnalysisGhidraParams),
    CustodyList(CustodyListParams),
    TerminalReplay(TerminalReplayParams),
    ArtifactList(RunParams),
    ArtifactGet(ArtifactGetParams),
}

/// The names reserved by 5.12.9 and the other reserved namespaces: a binding
/// must not invent operations in them, and the service answers `unsupported`.
pub const RESERVED_PREFIXES: [&str; 8] = [
    "recording.memory.",
    "recording.disks.",
    "recording.cores.read",
    "recording.cores.disassemble",
    "recording.cores.strings",
    "recording.screenshot.",
    "recording.export.",
    "run.",
];

macro_rules! read_ops {
    ($($variant:ident => $op:literal : $params:ty),* $(,)?) => {
        impl RecordingRead {
            /// Every operation name, in the order of the design's table.
            pub const OPS: &'static [&'static str] = &[$($op),*];

            /// The stable operation name.
            pub fn op(&self) -> &'static str {
                match self {
                    $(Self::$variant(_) => $op,)*
                }
            }

            /// Parses the `op` and `params` of a socket request. An unknown
            /// field is `invalid_argument`; a reserved name is `unsupported`.
            pub fn parse(op: &str, params: Value) -> Result<Self, ApiError> {
                match op {
                    $($op => serde_json::from_value::<$params>(params)
                        .map(Self::$variant)
                        .map_err(|e| ApiError::invalid_argument("params", e.to_string())),)*
                    other if RESERVED_PREFIXES.iter().any(|p| other.starts_with(p)) => {
                        Err(ApiError::new(
                            crate::api::error::ErrorCode::Unsupported,
                            format!("{other} is reserved and not part of version 1"),
                        ))
                    }
                    other => Err(ApiError::invalid_argument(
                        "op",
                        format!("unknown operation {other}"),
                    )),
                }
            }

            /// The JSON Schema of an operation's parameters.
            pub fn params_schema(op: &str) -> Option<Value> {
                match op {
                    $($op => serde_json::to_value(schemars::schema_for!($params)).ok(),)*
                    _ => None,
                }
            }

            /// The parameters as JSON, for the socket and for tests.
            pub fn params(&self) -> Value {
                match self {
                    $(Self::$variant(p) => serde_json::to_value(p).unwrap_or(Value::Null),)*
                }
            }
        }
    };
}

read_ops!(
    RunList => "recording.run.list": RunFilter,
    RunGet => "recording.run.get": RunParams,
    Summary => "recording.summary": RunParams,
    TracePage => "recording.trace.page": TracePageParams,
    TraceGet => "recording.trace.get": TraceGetParams,
    CapturedRead => "recording.captured.read": CapturedReadParams,
    ProcessTree => "recording.process.tree": ProcessTreeParams,
    FindingsList => "recording.findings.list": FindingsListParams,
    FindingsGet => "recording.findings.get": FindingGetParams,
    IndicatorsList => "recording.indicators.list": IndicatorsListParams,
    FilesList => "recording.files.list": FilesListParams,
    FilesVersions => "recording.files.versions": FileVersionsParams,
    FilesContent => "recording.files.content": FileContentParams,
    NetworkSummary => "recording.network.summary": RunParams,
    NetworkList => "recording.network.list": NetworkListParams,
    NetworkCaptures => "recording.network.captures": RunParams,
    NetworkPackets => "recording.network.packets": NetworkPacketsParams,
    NetworkPacket => "recording.network.packet": NetworkPacketParams,
    Timeline => "recording.timeline": TimelineParams,
    CoresList => "recording.cores.list": RunParams,
    AnalysisList => "recording.analysis.list": AnalysisListParams,
    AnalysisSection => "recording.analysis.section": AnalysisSectionParams,
    AnalysisGhidra => "recording.analysis.ghidra": AnalysisGhidraParams,
    CustodyList => "recording.custody.list": CustodyListParams,
    TerminalReplay => "recording.terminal.replay": TerminalReplayParams,
    ArtifactList => "recording.artifact.list": RunParams,
    ArtifactGet => "recording.artifact.get": ArtifactGetParams,
);

/// A reply shape: one of the two shapes of version 1.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RecordingReply {
    Runs(Page<RunInfo>),
    Run(Single<RunDetail>),
    Summary(Single<Summary>),
    Trace(Page<TraceRow>),
    Invocation(Single<Invocation>),
    Bytes(Single<BytesReply>),
    Processes(Page<ProcessNode>),
    Findings(Page<Finding>),
    Finding(Single<FindingDetail>),
    Indicators(Page<Indicator>),
    Files(Page<FileRow>),
    Versions(Single<FileVersions>),
    NetworkSummary(Single<NetworkSummary>),
    Network(Page<NetworkRow>),
    Captures(Page<Capture>),
    Packets(Page<PacketRow>),
    Packet(Single<PacketDetail>),
    Timeline(Page<TimelineEvent>),
    Cores(Page<CoreInfo>),
    AnalysisSections(Page<AnalysisSection>),
    AnalysisRows(Page<AnalysisRow>),
    Custody(Page<CustodyEntry>),
    Terminal(Page<TerminalRecord>),
    Artifacts(Page<RecordingArtifact>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::error::ErrorCode;
    use serde_json::json;

    fn key() -> String {
        RunKey::new("vm_1", "b2", "r3").unwrap().to_string()
    }

    #[test]
    fn every_operation_parses_its_minimal_request() {
        let key = key();
        for op in RecordingRead::OPS {
            let params = match *op {
                "recording.run.list" => json!({}),
                "recording.trace.get" => {
                    json!({"run_key": key, "ref": {"stream": "1", "task": "2", "call": "3"}})
                }
                "recording.captured.read" => {
                    json!({"run_key": key, "field": "7:path", "offset": "0", "len": 16})
                }
                "recording.findings.get" => json!({"run_key": key, "finding_id": "f"}),
                "recording.files.list" => json!({"run_key": key, "tab": "changed"}),
                "recording.files.versions" => json!({"run_key": key, "file_id": "f"}),
                "recording.files.content" => json!({"run_key": key, "version_id": "v"}),
                "recording.network.list" => json!({"run_key": key, "tab": "dns"}),
                "recording.network.packets" => json!({"run_key": key, "capture_id": "c"}),
                "recording.network.packet" => json!({"run_key": key, "capture_id": "c", "n": 1}),
                "recording.analysis.list" => json!({"job_id": "j_00000000000000000000000000"}),
                "recording.analysis.section" => json!({"run_key": key, "kind": "strings"}),
                "recording.analysis.ghidra" => json!({"run_key": key}),
                "recording.custody.list" => json!({"sha256": "a".repeat(64)}),
                "recording.artifact.get" => {
                    json!({"run_key": key, "artifact_id": "ra_00000000000000000000000000"})
                }
                _ => json!({"run_key": key}),
            };
            let read =
                RecordingRead::parse(op, params.clone()).unwrap_or_else(|e| panic!("{op}: {e:?}"));
            assert_eq!(read.op(), *op);
            assert_eq!(read.params(), params, "{op} round-trips");
        }
    }

    #[test]
    fn unknown_fields_are_invalid_argument() {
        let error = RecordingRead::parse(
            "recording.run.get",
            json!({"run_key": key(), "colour": "red"}),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert!(error.message.contains("colour"), "{}", error.message);
    }

    #[test]
    fn a_run_key_the_service_did_not_make_is_refused() {
        let error =
            RecordingRead::parse("recording.run.get", json!({"run_key": "../../etc"})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
    }

    #[test]
    fn reserved_and_unknown_operations_differ() {
        for reserved in [
            "recording.memory.dumps",
            "recording.export.zip",
            "recording.cores.read",
            "run.list",
        ] {
            let error = RecordingRead::parse(reserved, json!({})).unwrap_err();
            assert_eq!(error.code, ErrorCode::Unsupported, "{reserved}");
        }
        let error = RecordingRead::parse("recording.nonsense", json!({})).unwrap_err();
        assert_eq!(error.code, ErrorCode::InvalidArgument);
        assert_eq!(error.field.as_deref(), Some("op"));
    }

    #[test]
    fn the_analysis_subject_is_exactly_one_of_run_or_job() {
        let run = RunKey::new("v", "b", "r").ok();
        let job = Some(JobId::from_parts(1, [0; 10]));
        assert!(matches!(
            analysis_subject(&run, &None),
            Ok(AnalysisSubject::Run(_))
        ));
        assert!(matches!(
            analysis_subject(&None, &job),
            Ok(AnalysisSubject::Job(_))
        ));
        assert!(analysis_subject(&run, &job).is_err());
        assert!(analysis_subject(&None, &None).is_err());
    }

    #[test]
    fn sort_directions_are_asc_and_desc() {
        let sort: Sort = serde_json::from_value(json!({"field": "count", "dir": "desc"})).unwrap();
        assert_eq!(sort.dir, SortDir::Desc);
        assert!(serde_json::from_value::<Sort>(json!({"field": "count", "dir": "down"})).is_err());
    }
}

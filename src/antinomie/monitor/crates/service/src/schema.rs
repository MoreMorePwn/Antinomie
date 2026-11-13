// SPDX-License-Identifier: GPL-3.0-only
//! The JSON Schema of the job and query API, generated from the Rust types
//! with `schemars` and checked in as `docs/job-api-1.schema.json`. A test fails
//! when regenerating changes the file; `UPDATE_SCHEMA=1 cargo test -p
//! antinomie-service --release schema` rewrites it. ANT-T0192's tests import
//! the file.

use crate::api::{
    self,
    artifact::Artifact,
    assessment::Assessment,
    error::ErrorBody,
    event::Event,
    event::Frame,
    failure::Failure,
    job::{Job, Submitted},
    ops,
    spec::JobSpec,
    status,
};
use schemars::generate::SchemaSettings;
use serde_json::{Map, Value, json};

/// The checked-in schema, relative to the repository root.
pub const SCHEMA_FILE: &str = "docs/job-api-1.schema.json";

/// The schema document: one `$defs` entry per type the API sends or accepts.
pub fn generate() -> Value {
    let mut generator = SchemaSettings::draft2020_12().into_generator();
    let mut roots: Vec<Value> = Vec::new();
    macro_rules! root {
        ($($ty:ty),* $(,)?) => {
            $(roots.push(generator.subschema_for::<$ty>().to_value());)*
        };
    }
    root!(
        JobSpec,
        Job,
        Submitted,
        Assessment,
        Artifact,
        Failure,
        Event,
        Frame,
        ErrorBody,
        status::Sample,
        status::QueueStatus,
        status::Capabilities,
        status::HealthStatus,
        status::PolicySummary,
        status::VmSummary,
        status::BaseSummary,
        status::CustodyVerification,
        ops::Request,
        ops::Reply,
        ops::Caller,
        ops::UploadBeginParams,
        ops::UploadBegun,
        ops::UploadPutParams,
        ops::UploadReceived,
        ops::UploadFinishParams,
        ops::UploadFinished,
        ops::JobIdParams,
        ops::JobListParams,
        ops::JobList,
        ops::JobCancelParams,
        ops::JobRetryParams,
        ops::JobDeleteParams,
        ops::Deleted,
        ops::EventsSubscribeParams,
        ops::EventsListParams,
        ops::EventList,
        ops::ArtifactList,
        ops::ArtifactGetParams,
        ops::ReportGetParams,
        ops::SampleListParams,
        ops::SampleList,
        ops::Sha256Params,
        ops::SampleGetParams,
        ops::SampleDownloadParams,
        ops::SampleAddParams,
        ops::SampleTagParams,
        ops::PolicyList,
        ops::VmList,
        ops::BaseList,
        ops::CustodyVerifyParams,
        ops::Op,
        ops::Permission,
        api::error::ErrorCode,
        api::error::ErrorReason,
    );
    {
        use crate::query::{
            catalogue::QueryCatalogue,
            page::{Page, PageRequest, Single},
            request::*,
            types::*,
        };
        root!(
            QueryCatalogue,
            PageRequest,
            Sort,
            Page<RunInfo>,
            Single<RunDetail>,
            Single<Summary>,
            Page<TraceRow>,
            Single<Invocation>,
            Single<BytesReply>,
            Page<ProcessNode>,
            ProcessTreeNotes,
            Page<Finding>,
            Single<FindingDetail>,
            Page<Indicator>,
            Page<FileRow>,
            Single<FileVersions>,
            Single<NetworkSummary>,
            Page<NetworkRow>,
            Page<Capture>,
            Page<PacketRow>,
            Single<PacketDetail>,
            Page<TimelineEvent>,
            Page<CoreInfo>,
            Page<AnalysisSection>,
            Page<AnalysisRow>,
            AnalysisPageNotes,
            Page<CustodyEntry>,
            Page<TerminalRecord>,
            Page<RecordingArtifact>,
            RunFilter,
            RunParams,
            TracePageParams,
            TraceGetParams,
            CapturedReadParams,
            ProcessTreeParams,
            FindingsListParams,
            FindingGetParams,
            IndicatorsListParams,
            FilesListParams,
            FileVersionsParams,
            FileContentParams,
            NetworkListParams,
            NetworkPacketsParams,
            NetworkPacketParams,
            TimelineParams,
            AnalysisListParams,
            AnalysisSectionParams,
            AnalysisGhidraParams,
            CustodyListParams,
            TerminalReplayParams,
            ArtifactGetParams,
        );
    }
    drop(roots);
    let definitions: Map<String, Value> = generator.take_definitions(true);
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://antinomie.invalid/schema/job-api-1.schema.json",
        "title": "Antinomie job and query API, version 1",
        "description": "Generated from the Rust types of the antinomie-service crate. Do not edit.",
        "$defs": definitions,
    })
}

/// The schema as the checked-in file spells it: pretty JSON, one newline.
pub fn render() -> String {
    let mut text = serde_json::to_string_pretty(&generate()).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn file() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../..")
            .join(SCHEMA_FILE)
    }

    #[test]
    fn the_checked_in_schema_is_current() {
        let current = render();
        if std::env::var_os("UPDATE_SCHEMA").is_some() {
            std::fs::write(file(), &current).unwrap();
        }
        let stored = std::fs::read_to_string(file())
            .unwrap_or_else(|e| panic!("{}: {e}; run with UPDATE_SCHEMA=1", file().display()));
        assert!(
            stored == current,
            "docs/job-api-1.schema.json is stale; regenerate it with UPDATE_SCHEMA=1"
        );
    }

    #[test]
    fn the_schema_defines_the_core_types() {
        let schema = generate();
        let defs = schema["$defs"].as_object().unwrap();
        for name in [
            "JobSpec",
            "Job",
            "Event",
            "ApiError",
            "Frame",
            "Capabilities",
        ] {
            assert!(defs.contains_key(name), "{name} missing from $defs");
        }
    }
}

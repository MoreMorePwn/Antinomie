// SPDX-License-Identifier: GPL-3.0-only
//! `Artifact` (design 5.4.4): a file a run produced.

use super::ids::{ArtifactId, RunId, Sha256Hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ArtifactKind {
    #[serde(rename = "report.html")]
    ReportHtml,
    #[serde(rename = "report.pdf")]
    ReportPdf,
    #[serde(rename = "report.json")]
    ReportJson,
    #[serde(rename = "report.misp")]
    ReportMisp,
    #[serde(rename = "report.stix")]
    ReportStix,
    #[serde(rename = "report.md")]
    ReportMd,
    #[serde(rename = "report.bundle")]
    ReportBundle,
    #[serde(rename = "network.pcap")]
    NetworkPcap,
    #[serde(rename = "memory.dump")]
    MemoryDump,
    #[serde(rename = "process.core")]
    ProcessCore,
    #[serde(rename = "log.job")]
    LogJob,
}

impl ArtifactKind {
    /// True for `network.pcap`, `memory.dump`, `process.core` and
    /// `report.bundle`. Not true for reports.
    pub fn sensitive(self) -> bool {
        matches!(
            self,
            Self::NetworkPcap | Self::MemoryDump | Self::ProcessCore | Self::ReportBundle
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum MediaType {
    #[serde(rename = "text/html")]
    TextHtml,
    #[serde(rename = "application/pdf")]
    ApplicationPdf,
    #[serde(rename = "application/json")]
    ApplicationJson,
    #[serde(rename = "text/markdown")]
    TextMarkdown,
    #[serde(rename = "application/vnd.tcpdump.pcap")]
    ApplicationPcap,
    #[serde(rename = "application/zip")]
    ApplicationZip,
    #[serde(rename = "application/octet-stream")]
    ApplicationOctetStream,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Artifact {
    pub id: ArtifactId,
    pub run_id: RunId,
    pub kind: ArtifactKind,
    /// Download file name.
    pub name: String,
    /// Bytes.
    pub size: u64,
    /// Of the stored bytes.
    pub sha256: Sha256Hex,
    pub media_type: MediaType,
    /// `artifact.get` needs `evidence.download`.
    pub sensitive: bool,
    /// The artifact keeps indicators raw (JSON, MISP, STIX, or an HTML, PDF or
    /// Markdown report exported without defang). Needs `runs.see_all`; clients must not
    /// render it as active content.
    pub raw_indicators: bool,
    pub created_ms: u64,
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The Triage report: one [`Report`] value, built once from a whole-run Triage
//! index, and written as HTML, PDF, JSON, MISP and STIX 2.1, with an optional
//! evidence bundle. The value holds only the sections the person chose; an
//! unchecked section is `None` and absent from every format.
//!
//! Layout: [`layout`] turns a report into the page model HTML and PDF both
//! draw; [`defang`] rewrites marked indicators for those two; [`misp`] and
//! [`stix`] build the exchange formats from the typed fields; [`bundle`]
//! packs the evidence; [`export`] writes the files. The JSON schema is
//! documented in `docs/triage-report.md` and versioned by [`SCHEMA_VERSION`].
use serde::{Deserialize, Serialize};

pub mod bundle;
pub mod defang;
pub mod export;
mod html;
pub mod layout;
pub mod misp;
mod pdf;
mod pdf_font;
mod pdf_layout;
pub mod stix;

/// The schema name every JSON export carries in `schema`.
pub const SCHEMA: &str = "antinomie-triage-report";
/// Bumped when a field changes meaning or goes away; a new optional field
/// does not bump it.
pub const SCHEMA_VERSION: u32 = 1;
/// Rows of one table in the HTML and the PDF; the JSON keeps every row the
/// index held. More are counted in the table's `omitted`.
pub const DOCUMENT_ROWS: usize = 1000;
/// The password of the dropped-files archive inside the evidence bundle: the
/// malware-sharing convention, the same the sample library uses.
pub const DROPPED_PASSWORD: &str = "infected";

/// The kinds of indicator the exchange formats and the defanger know.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndicatorKind {
    Endpoint,
    Domain,
    Url,
    Tls,
    File,
}

impl IndicatorKind {
    /// The kind a Triage indicator type id names.
    pub fn from_id(id: &str) -> Option<Self> {
        Some(match id {
            "endpoint" => Self::Endpoint,
            "domain" => Self::Domain,
            "url" => Self::Url,
            "tls" => Self::Tls,
            "file" => Self::File,
            _ => return None,
        })
    }
}

/// A table of the report: what a Triage table shows, as text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Table {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    /// Matching rows the index did not keep (its per-table cap).
    pub omitted: u64,
    /// Columns whose cells are indicators, so HTML and PDF can defang them.
    pub indicator_columns: Vec<IndicatorColumn>,
}

/// One column of a [`Table`] that holds indicators.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndicatorColumn {
    pub column: usize,
    pub kind: IndicatorKind,
}

/// A table with the name of the Triage tab it came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NamedTable {
    pub name: String,
    pub table: Table,
}

/// The run the report is about.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunInfo {
    pub vm_id: String,
    pub boot_id: String,
    pub run_id: String,
    /// Run start, ms since the epoch, when known.
    pub started_ms: Option<u64>,
    /// Whether the run had finished when the index was read.
    pub finished: bool,
}

/// The sample the run executed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SampleInfo {
    pub name: String,
    pub sha256: String,
    pub size: Option<u64>,
}

/// One rule of the behaviour engine that matched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Behaviour {
    pub rule: String,
    /// `high`, `medium`, `low` or `info`.
    pub tier: String,
    pub category: String,
    pub count: u64,
}

/// Whole-run counts shown first.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counts {
    pub processes: u64,
    pub findings: u64,
    pub indicators: u64,
    pub indicators_matched: u64,
    pub techniques: u64,
    pub files_changed: u64,
    pub files_opened: u64,
    pub endpoints: u64,
    pub domains: u64,
}

/// What the run showed, in a sentence and the numbers behind it. This is an
/// observation summary, not a verdict on the sample.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Summary {
    /// `matched_indicators`, `suspicious_behaviour`, `observed_only` or
    /// `no_findings`.
    pub assessment: String,
    /// The assessment in words, with its basis.
    pub statement: String,
    pub highest_tier: String,
    /// Families the stored datasets name for matched indicators.
    pub families: Vec<String>,
    /// HIGH and MEDIUM rules that matched, worst first.
    pub key_behaviours: Vec<Behaviour>,
    pub counts: Counts,
}

/// An indicator of compromise with the datasets' answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Indicator {
    /// `endpoint`, `domain`, `url`, `tls` or `file`.
    pub kind: String,
    pub value: String,
    /// File indicators: the guest path.
    pub path: String,
    pub detail: String,
    pub sources: String,
    pub process: String,
    pub first_seen: String,
    pub last_seen: String,
    pub count: String,
    /// The dataset answer: `matched`, `no match`, `not checked`, ...
    pub verdict: String,
    pub matched: bool,
    pub dataset: String,
    pub record_id: String,
    pub family: String,
    pub confidence: Option<u8>,
    pub reference: String,
    /// URL indicators: the normal form with the cleartext scheme, `http://host/path`.
    pub url: String,
    /// TLS indicators: server name, client fingerprints and certificate SHA-1.
    pub sni: String,
    pub ja3: String,
    pub ja4: String,
    pub cert_sha1: String,
    /// File indicators: the digests the guest or a disk dump gave.
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
}

/// An ATT&CK technique the run's rules cite.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub rules: Vec<String>,
    pub count: u64,
}

/// A rule of a detection engine that matched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Detection {
    pub engine: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub mitre: Vec<String>,
    pub count: u64,
}

/// What the Files > File activity window knows of one file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileRecord {
    pub path: String,
    pub created: bool,
    pub deleted: bool,
    pub changed: bool,
    pub final_size: Option<u64>,
    /// The hash the guest took after the last writer closed the file.
    pub guest_sha256: String,
    /// `complete`, `incomplete` or `not reconstructed`.
    pub reconstruction: String,
    pub bytes_written: u64,
    pub bytes_not_captured: u64,
    pub bytes_unknown: u64,
    /// The file's name inside the dropped-files archive, when it is in one.
    pub bundle_entry: String,
}

/// The file section: the Files tabs and the per-file history.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesSection {
    pub tabs: Vec<NamedTable>,
}

/// A file of the run folder the report refers to.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EvidenceRef {
    /// `telemetry`, `network capture`, `memory dump`, `core dump`, `disk`,
    /// `object store`, `reconstructed`, `other`.
    pub kind: String,
    /// Relative to the run folder.
    pub path: String,
    pub size: u64,
    /// Empty past the hashing limit.
    pub sha256: String,
}

/// The sample's custody log at export time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Custody {
    pub sample_sha256: String,
    pub entries: u64,
    pub head: String,
    pub verified: bool,
    pub library_head: String,
    pub problem: String,
}

/// The whole report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub schema: String,
    pub schema_version: u32,
    pub generated_ms: u64,
    pub app: String,
    pub run: RunInfo,
    pub sample: Option<SampleInfo>,
    pub summary: Option<Summary>,
    pub indicators: Option<Vec<Indicator>>,
    pub attack: Option<Vec<Technique>>,
    pub processes: Option<Table>,
    pub findings: Option<Table>,
    pub files: Option<FilesSection>,
    pub file_activity: Option<Vec<FileRecord>>,
    pub network: Option<Vec<NamedTable>>,
    pub detections: Option<Vec<Detection>>,
    pub evidence: Option<Vec<EvidenceRef>>,
    pub custody: Option<Custody>,
    /// What the report could not say: omitted rows, missing inputs.
    pub notes: Vec<String>,
}

impl Report {
    /// An empty report for `run`, stamped with the schema and `now_ms`.
    pub fn new(run: RunInfo, now_ms: u64) -> Self {
        Self {
            schema: SCHEMA.into(),
            schema_version: SCHEMA_VERSION,
            generated_ms: now_ms,
            app: format!("Antinomie {}", crate::api::APP_VERSION),
            run,
            ..Self::default()
        }
    }

    /// The versioned machine-readable form.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|error| error.to_string())
    }
}

/// The parts of a report, one checkbox each in the export dialog.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Part {
    Summary,
    Indicators,
    Attack,
    Processes,
    Findings,
    Files,
    FileActivity,
    Network,
    Detections,
    Evidence,
    Custody,
}

impl Part {
    pub const ALL: [Part; 11] = [
        Self::Summary,
        Self::Indicators,
        Self::Attack,
        Self::Processes,
        Self::Findings,
        Self::Files,
        Self::FileActivity,
        Self::Network,
        Self::Detections,
        Self::Evidence,
        Self::Custody,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary (assessment, family, key behaviours)",
            Self::Indicators => "Indicators of compromise",
            Self::Attack => "ATT&CK techniques",
            Self::Processes => "Processes",
            Self::Findings => "Suspicious activity (findings and rules)",
            Self::Files => "Files (every tab)",
            Self::FileActivity => "File activity and reconstruction",
            Self::Network => "Network (endpoints, domains, URLs, TLS)",
            Self::Detections => "Detection engines (YARA, IDS, Sigma)",
            Self::Evidence => "Evidence references",
            Self::Custody => "Custody log head",
        }
    }
}

/// The formats a report can be written in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Html,
    Pdf,
    Json,
    Misp,
    Stix,
}

impl Format {
    pub const ALL: [Format; 5] = [Self::Html, Self::Pdf, Self::Json, Self::Misp, Self::Stix];

    pub fn label(self) -> &'static str {
        match self {
            Self::Html => "HTML",
            Self::Pdf => "PDF",
            Self::Json => "JSON",
            Self::Misp => "MISP",
            Self::Stix => "STIX 2.1",
        }
    }

    /// The file name's ending after the base name.
    pub fn suffix(self) -> &'static str {
        match self {
            Self::Html => ".html",
            Self::Pdf => ".pdf",
            Self::Json => ".json",
            Self::Misp => ".misp.json",
            Self::Stix => ".stix.json",
        }
    }
}

/// What the person chose in the dialog; remembered between exports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Choices {
    pub parts: Vec<Part>,
    pub formats: Vec<Format>,
    pub bundle: bool,
    pub defang: bool,
    /// Where the files go; empty means `<recording>/report`.
    pub folder: String,
}

impl Default for Choices {
    fn default() -> Self {
        Self {
            parts: Part::ALL.to_vec(),
            formats: vec![Format::Html, Format::Pdf],
            bundle: false,
            defang: false,
            folder: String::new(),
        }
    }
}

impl Choices {
    pub fn has(&self, part: Part) -> bool {
        self.parts.contains(&part)
    }

    pub fn set(&mut self, part: Part, on: bool) {
        self.parts.retain(|p| *p != part);
        if on {
            self.parts.push(part);
        }
    }

    pub fn writes(&self, format: Format) -> bool {
        self.formats.contains(&format)
    }

    pub fn set_format(&mut self, format: Format, on: bool) {
        self.formats.retain(|f| *f != format);
        if on {
            self.formats.push(format);
        }
    }
}

/// `YYYY-MM-DD HH:MM:SS` UTC for ms since the epoch.
pub fn utc(ms: u64) -> String {
    let seconds = (ms / 1000) as i64;
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for ms since the epoch.
pub fn iso(ms: u64) -> String {
    let text = utc(ms);
    format!("{}T{}.{:03}Z", &text[..10], &text[11..], ms % 1000)
}

/// A version-5 UUID of `name` in a fixed namespace, so the same input gives
/// the same id in every export.
pub fn uuid5(name: &str) -> String {
    use sha1::{Digest, Sha1};
    // The DNS namespace.
    const NAMESPACE: [u8; 16] = [
        0x6b, 0xa7, 0xb8, 0x10, 0x9d, 0xad, 0x11, 0xd1, 0x80, 0xb4, 0x00, 0xc0, 0x4f, 0xd4, 0x30,
        0xc8,
    ];
    let mut hash = Sha1::new();
    hash.update(NAMESPACE);
    hash.update(name.as_bytes());
    let digest = hash.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests;

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

pub mod anchor;
pub mod bundle;
pub mod defang;
pub mod export;
pub mod fold;
mod html;
pub mod layout;
mod layout_files;
mod layout_parts;
pub mod markdown;
pub mod misp;
pub mod page;
mod pdf;
mod pdf_font;
mod pdf_layout;
mod pdf_wrap;
pub mod refs;
pub mod sample;
pub mod shared;
pub mod stix;

pub use refs::{KeyFinding, RowData};

/// The schema name every JSON export carries in `schema`.
pub const SCHEMA: &str = "antinomie-triage-report";
/// Bumped when a field changes meaning or goes away; a new optional field
/// does not bump it. Version 2: `summary.key_findings` are objects (the
/// version 1 sentences are `summary.key_findings_text`), and tables and
/// entries carry anchor `id`s, `*_ref` links and typed row values (`data`).
pub const SCHEMA_VERSION: u32 = 2;
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
    /// One per row when the table has them: the row's anchor id, its values
    /// as numbers (pid, times in ms, counts, bytes) and its links to other
    /// entries of the report. Empty for a table without them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub data: Vec<RowData>,
}

impl Table {
    /// The data of row `at`, when the table has data.
    pub fn row_data(&self, at: usize) -> Option<&RowData> {
        self.data.get(at)
    }
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
    /// The run's state in the app's words: "Stopped by you at 6 min 25 s ·
    /// root exited 0", "Ran for 1 min 20 s · exit 255", "Ended by VM stop".
    pub state: String,
    /// How the root program ended, "exit 0" or "signal 11 (SIGSEGV)"; empty
    /// when the guest never reported it.
    pub exit: String,
    /// The run was ended with Stop run.
    pub stopped_by_user: bool,
    /// When the run's process tree ended, ms since the epoch, when known.
    pub ended_ms: Option<u64>,
    /// Start to end (or to the Stop press), in ms, when both are known.
    pub duration_ms: Option<u64>,
    /// The command the run started when the run has no library sample (a
    /// shell running a one-liner, a preloaded library): path and arguments.
    pub command: String,
    /// The network route the run used, as the app words it.
    pub route: String,
    /// What the run was recorded on: base image, kernel, route, stealth
    /// profile, rule packs and tools.
    pub environment: Vec<Fact>,
}

/// A name and a value of a facts list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Fact {
    pub name: String,
    pub value: String,
}

impl Fact {
    pub fn new(name: &str, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

/// The sample the run executed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SampleInfo {
    pub name: String,
    pub sha256: String,
    pub size: Option<u64>,
    /// `preloaded library` when the run started another program (a shell)
    /// with this library in `LD_PRELOAD`; empty for the program itself.
    pub role: String,
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

/// Rules of the run that fired, by tier.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TierCounts {
    pub high: u64,
    pub medium: u64,
    pub low: u64,
    pub info: u64,
    /// INFO findings the run has but the report's tables do not list (the
    /// whole-run index keeps LOW and above in Suspicious activity).
    pub info_not_listed: u64,
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
    /// Families named by matched indicators (stored datasets), YARA rule
    /// metadata and IDS signature messages.
    pub families: Vec<String>,
    /// Who named each family: `Kaiji: IDS: ET MALWARE Kaiji Variant Activity (15)`.
    pub family_sources: Vec<String>,
    /// Families fewer or weaker rules named (one Mirai rule beside twenty
    /// Gafgyt ones): said, but not the report's family, MISP tag or STIX
    /// malware name.
    pub other_families: Vec<String>,
    /// HIGH and MEDIUM rules that matched, worst first.
    pub key_behaviours: Vec<Behaviour>,
    /// Behaviour rules that fired, by tier.
    pub tiers: TierCounts,
    /// The findings the app's Summary lists under Key findings, worst first.
    pub key_findings: Vec<KeyFinding>,
    /// The same as sentences, the form `key_findings` had in schema version 1.
    pub key_findings_text: Vec<String>,
    /// How many findings of LOW and above there are (`key_findings` holds the
    /// worst of them).
    pub key_findings_total: u64,
    pub counts: Counts,
}

/// An indicator of compromise with the datasets' answer.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Indicator {
    /// The anchor of its row: `ioc-<n>`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
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
    /// Why this is the base image's own traffic (clock sync, DHCP, apt) and not
    /// the sample's; empty for the run's indicators. Such rows are listed in the
    /// JSON only, not in the document tables, MISP or STIX.
    pub base_noise: String,
    /// For an endpoint on the Tor gateway's stand-in range: the name the
    /// run's DNS answers handed that address out for.
    pub stand_in: String,
    /// Why this indicator is in the document and the JSON but not in MISP and
    /// STIX (a stand-in address, a private one, a file with no content); empty
    /// for an indicator worth sharing.
    pub not_shared: String,
    /// The processes it was seen in, by pid (the `process` text names them).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pids: Vec<u32>,
    /// The entry it is about: an endpoint, domain or file row.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target_ref: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub process_refs: Vec<String>,
    /// The findings about the same object.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub finding_refs: Vec<String>,
}

impl Indicator {
    /// Whether MISP and STIX carry it: the run's own, with something a
    /// consumer could match.
    pub fn shared(&self) -> bool {
        self.base_noise.is_empty() && self.not_shared.is_empty()
    }
}

/// An ATT&CK technique the run's rules cite.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub rules: Vec<String>,
    pub count: u64,
    /// One per rule: the anchor of its first finding (`rule-<id>`) or its
    /// detection row (`det-…`); empty when the rule has no entry.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rule_refs: Vec<String>,
}

/// The header of the table column that names a technique's tactics; the HTML
/// and PDF exports colour what is in it (the names stay in the text).
pub(crate) const TACTIC_COLUMN: &str = "Tactic";

/// A technique's tactics as the table cell reads, "Privilege Escalation,
/// Stealth" in kill-chain order; empty for an id the bundled table lacks.
pub(crate) fn tactic_cell(id: &str) -> String {
    crate::mitre::tactics(id)
        .iter()
        .map(|tactic| tactic.name())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The tactics a [`tactic_cell`] names.
pub(crate) fn cell_tactics(cell: &str) -> Vec<crate::mitre::Tactic> {
    cell.split(',')
        .filter_map(crate::mitre::Tactic::from_label)
        .collect()
}

/// A rule of a detection engine that matched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Detection {
    /// The anchor of its row: `det-<engine>-<rule>`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub engine: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub mitre: Vec<String>,
    pub count: u64,
    /// The rule's author as the rule gives it; empty when it names none.
    pub author: String,
    /// The licence of the rule's pack.
    pub license: String,
    /// The rule pack the rule came from.
    pub source: String,
    /// The rule's own reference link, when it names one.
    pub reference: String,
    /// For a YARA match: how much it says about the sample (`strong`, `weak`,
    /// `wrong platform`), as Triage's detection cards judge it.
    pub strength: String,
    /// The family this rule names, when it names one.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub family: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attack_refs: Vec<String>,
}

/// What the Files > File activity window knows of one file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileRecord {
    /// The anchor of the file's entry: `file-<hash of the path>`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
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
    /// The process that created or changed it first.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub process_ref: String,
    /// The findings about this file.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub finding_refs: Vec<String>,
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
    /// A folder: how many files it holds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
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

    /// The run never started (the guest refused the launch, the route did not
    /// come up): there is a request and a sample, but no behaviour.
    pub fn not_started(&self) -> bool {
        self.run.state.starts_with("Not started")
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
    Markdown,
}

impl Format {
    pub const ALL: [Format; 6] = [
        Self::Html,
        Self::Pdf,
        Self::Markdown,
        Self::Json,
        Self::Misp,
        Self::Stix,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Html => "HTML",
            Self::Pdf => "PDF",
            Self::Json => "JSON",
            Self::Misp => "MISP",
            Self::Stix => "STIX 2.1",
            Self::Markdown => "Markdown",
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
            Self::Markdown => ".md",
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
    /// Keep the bytes a sample read in the JSON's Read files rows (clipped to
    /// 120 characters, never for a file the run wrote). Off by default: they
    /// can carry guest secrets and the sample's own bytes.
    pub include_content: bool,
    /// Where the files go; empty means `<recording>/report`.
    pub folder: String,
}

impl Default for Choices {
    fn default() -> Self {
        Self {
            parts: Part::ALL.to_vec(),
            formats: vec![Format::Html, Format::Pdf],
            bundle: false,
            // The readable formats defang by default, like the sample report.
            defang: true,
            include_content: false,
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
    crate::date::date_time_text((ms / 1000) as i64)
}

/// `YYYY-MM-DD HH:MM:SS (UTC+7)` in the zone the app shows times in: the
/// time a person reads in a report. Stored and machine-read times stay UTC
/// ([`utc`], [`iso`]).
pub fn shown(ms: u64) -> String {
    crate::date::display_date_time_text((ms / 1000) as i64)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` for ms since the epoch.
pub fn iso(ms: u64) -> String {
    let text = utc(ms);
    format!("{}T{}.{:03}Z", &text[..10], &text[11..], ms % 1000)
}

/// `HH:MM:SS.mmm` in the zone the app shows: a time of day in a table whose
/// date the document says once.
pub fn clock(ms: u64) -> String {
    let text = shown(ms);
    format!("{}.{:03}", &text[11..19], ms % 1000)
}

/// A time in a document table: `+5.463 s · 17:38:21.480`, the time since
/// the run's first call and the time of day; either alone when the other is
/// not known, empty when neither is.
pub fn stamp(relative_ms: Option<u64>, time_ms: Option<u64>) -> String {
    let relative = relative_ms.map(|ms| format!("+{}.{:03} s", ms / 1000, ms % 1000));
    match (relative, time_ms) {
        (Some(relative), Some(at)) => format!("{relative} \u{b7} {}", clock(at)),
        (Some(relative), None) => relative,
        (None, Some(at)) => clock(at),
        (None, None) => String::new(),
    }
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
mod format_tests;
#[cfg(test)]
mod link_tests;
#[cfg(test)]
mod tests;

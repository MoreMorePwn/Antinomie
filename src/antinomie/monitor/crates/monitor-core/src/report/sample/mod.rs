// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The sample report: one [`SampleReport`] value for a library sample, built
//! from what the Samples window knows (the library record, the static
//! report, every run's Triage digest, the lineage, the custody log, the notes
//! and the similar samples) and written as HTML, PDF, JSON, MISP, STIX 2.1
//! and Markdown.
//!
//! It reuses the run report's page model, HTML and PDF writers, defanger and
//! row cap ([`super::layout`], [`super::DOCUMENT_ROWS`]); the exchange formats
//! are sample-level: the sample itself, the indicators merged across its
//! runs, the rules that matched with their credits, the techniques and the
//! family, never the run's raw events. A report never holds sample bytes: it
//! names the sample by its hashes and quotes only the text of the analysis
//! results (FLOSS strings are cut and counted).
//!
//! [`build`] merges the inputs, [`layout`] makes the page model, [`markdown`],
//! [`misp`] and [`stix`] write the other formats, [`export`] writes the files
//! and notes the export in the sample's custody log. The JSON is described by
//! `docs/sample-report-schema-1.json`, versioned by [`SCHEMA_VERSION`].
use super::Technique;
use serde::{Deserialize, Serialize};

pub mod build;
pub mod export;
pub mod layout;
pub mod markdown;
pub mod misp;
pub mod stix;
#[cfg(test)]
mod tests;

/// The schema name every JSON export carries in `schema`.
pub const SCHEMA: &str = "antinomie-sample-report";
/// Bumped when a field changes meaning or goes away; a new optional field
/// does not bump it.
pub const SCHEMA_VERSION: u32 = 1;
/// Rows of one list the report keeps (the JSON, MISP and STIX hold all of
/// them); the rest are counted in [`Omitted`]. HTML, PDF and Markdown cut
/// each table again at [`super::DOCUMENT_ROWS`].
pub const LIST_ROWS: usize = 5_000;
/// The longest note text kept; a longer note is cut and says so.
pub const NOTE_CHARS: usize = 4_000;
/// FLOSS strings listed.
pub const FLOSS_ROWS: usize = 100;
/// The longest FLOSS string kept.
pub const STRING_CHARS: usize = 160;

/// One tag of the sample.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TagRow {
    /// `verdict`, `category`, `technique` or `custom`.
    pub kind: String,
    pub value: String,
}

/// A file name or path the sample went by.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NameRow {
    pub name: String,
    pub path: String,
    pub seen: String,
}

/// A route by which the sample reached the library.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OriginRow {
    /// The label (`Downloaded`, `Dropped by a run`, ...).
    pub kind: String,
    pub source: String,
    pub detail: String,
    pub name: String,
    pub path: String,
    pub vm: String,
    pub run_id: String,
    /// SHA-256 of the sample that wrote or fetched this one; empty when none.
    pub parent: String,
    pub at_ms: u64,
}

/// Who the sample is.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub sha256: String,
    pub sha1: String,
    pub md5: String,
    pub tlsh: String,
    pub name: String,
    pub description: String,
    pub size: u64,
    pub file_type: String,
    pub arch: String,
    pub family: String,
    /// When the library first held the bytes.
    pub added_ms: u64,
    /// When the archive was removed; the record stays.
    pub removed_ms: Option<u64>,
    /// The archive is on disk.
    pub archived: bool,
    /// The earliest of the library entry and the first run.
    pub first_seen_ms: Option<u64>,
    /// The latest run start or custody entry.
    pub last_seen_ms: Option<u64>,
    pub tags: Vec<TagRow>,
    pub names: Vec<NameRow>,
    pub origins: Vec<OriginRow>,
}

/// One check of the static analysis.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticCheck {
    pub label: String,
    /// `pending`, `running`, `complete`, `partial`, `unavailable` or `timeout`.
    pub state: String,
    /// Why it is not complete; empty when it is.
    pub reason: String,
    pub summary: String,
    pub tools: Vec<String>,
}

/// A layer of the unpack chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Layer {
    pub index: u32,
    pub method: String,
    pub sha256: String,
    pub size: u64,
    pub packer: String,
}

/// A capability capa reported.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Capability {
    pub name: String,
    pub namespace: String,
    pub attack: Vec<String>,
    pub mbc: Vec<String>,
}

/// A string FLOSS recovered, cut to [`STRING_CHARS`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct FlossRow {
    /// `decoded`, `stack`, `tight` or `language`.
    pub origin: String,
    pub text: String,
}

/// The static analysis the Summary reads: the newest finished report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StaticAnalysis {
    /// A finished static report exists.
    pub available: bool,
    /// `complete` or `partial` when available; otherwise empty.
    pub state: String,
    /// Why the section is empty or incomplete.
    pub reason: String,
    pub report_id: String,
    /// The run whose report it is, by number.
    pub from_run: Option<usize>,
    pub checks: Vec<StaticCheck>,
    /// The packer the Unpacking check names, or empty.
    pub packer: String,
    pub layers: Vec<Layer>,
    pub capabilities: Vec<Capability>,
    pub floss: Vec<FlossRow>,
    /// Strings FLOSS found, listed or not.
    pub floss_total: u64,
    /// Capabilities the report kept out (past [`LIST_ROWS`]).
    pub capabilities_omitted: u64,
}

/// A rule that matched, in the static scan or in runs, with its credit.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleHit {
    /// `YARA` (a run's detection report), `YARA (static)`, `Sigma` or `IDS`.
    pub engine: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub family: String,
    pub mitre: Vec<String>,
    /// Run numbers, ascending; empty for the static scan.
    pub runs: Vec<usize>,
    pub count: u64,
    /// The rule's author as the rule gives it; empty when it names none.
    pub author: String,
    pub license: String,
    pub source: String,
    pub reference: String,
}

/// One run of the sample.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunRow {
    /// Start order, run 1 is the oldest.
    pub number: usize,
    pub vm_id: String,
    pub vm_name: String,
    pub run_id: String,
    pub started_ms: Option<u64>,
    /// How the root process ended, as the run list says it.
    pub exit: String,
    /// The run's folder is on disk; a deleted run stays listed.
    pub folder_present: bool,
    /// Triage has read the run (it has a digest).
    pub triaged: bool,
    /// `matched_indicators`, `suspicious_behaviour`, `observed_only`,
    /// `no_findings`, or `not_read` when Triage never read the run.
    pub assessment: String,
    pub statement: String,
    pub highest_tier: String,
    pub rules: u64,
    pub indicators: u64,
    pub indicators_matched: u64,
    pub detections: u64,
    /// The run's folder, relative to the data directory.
    pub directory: String,
    /// The newest HTML report the run's Triage export wrote, or empty when it
    /// has none yet, relative to the data directory.
    pub report_file: String,
}

/// A file or command in the sample's lineage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LineageEntry {
    /// `parent` or `child`.
    pub role: String,
    /// Levels away from the sample, from 1.
    pub level: u32,
    /// `library sample`, `captured file`, `file without a hash` or `command`.
    pub kind: String,
    pub label: String,
    pub path: String,
    /// Empty when the hash is unknown.
    pub sha256: String,
    /// The library's verdict tag for a library sample.
    pub verdict: String,
    /// How it is joined to the sample (`dropped`, `executed`, ...).
    pub via: String,
    pub runs: Vec<usize>,
}

/// Where the sample came from and what it made.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Lineage {
    pub parents: Vec<LineageEntry>,
    pub children: Vec<LineageEntry>,
    /// Why a side is empty, or what was left out.
    pub reason: String,
}

/// An indicator merged across the runs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MergedIndicator {
    /// `endpoint`, `domain`, `url`, `tls` or `file`.
    pub kind: String,
    pub value: String,
    /// A stored dataset matched it in some run.
    pub matched: bool,
    pub runs: Vec<usize>,
    /// A file's path in the guest.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// Every run that has an indicator list had it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub every_run: bool,
    /// How it was observed: DNS query, connect, HTTP request, file write.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub observed: Vec<String>,
    /// First and last seen over the runs, Unix microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_us: Option<u64>,
    /// The dataset records that matched, `dataset: family (id)`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hits: Vec<String>,
}

/// One entry of the custody log.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustodyRow {
    pub seq: u64,
    pub at_ms: u64,
    pub by: String,
    pub event: String,
    pub detail: String,
    /// `verified`, `changed` or `unverified`.
    pub state: String,
    pub hash: String,
    pub before_chain: bool,
}

/// The custody log at export time. The export itself is noted after this
/// head, so the next read of the log has one more entry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustodySection {
    pub entries: u64,
    pub head: String,
    pub verified: bool,
    pub problem: String,
    pub log: Vec<CustodyRow>,
}

/// An analyst note.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NoteRow {
    pub id: i64,
    pub by: String,
    pub created_ms: u64,
    pub edited_ms: Option<u64>,
    pub text: String,
    /// The note was cut to [`NOTE_CHARS`].
    pub cut: bool,
    pub refs: Vec<String>,
}

/// A library sample like this one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SimilarRow {
    pub sha256: String,
    pub name: String,
    /// TLSH distance, lower is closer.
    pub distance: i32,
    /// What they share, as a count (`12 imports`); the shared texts are not
    /// copied.
    pub shared: String,
}

/// The comparison with the rest of the library.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SimilarSection {
    pub rows: Vec<SimilarRow>,
    /// Why there are none, or that the comparison was not made.
    pub reason: String,
}

/// Rows each list lost to its cap.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Omitted {
    pub indicators: u64,
    pub detections: u64,
    pub runs: u64,
    pub custody: u64,
    pub notes: u64,
    pub lineage: u64,
}

/// The whole report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SampleReport {
    pub schema: String,
    pub schema_version: u32,
    pub generated_ms: u64,
    pub app: String,
    pub sample: Identity,
    pub static_analysis: StaticAnalysis,
    pub detections: Vec<RuleHit>,
    pub runs: Vec<RunRow>,
    pub lineage: Lineage,
    pub indicators: Vec<MergedIndicator>,
    pub attack: Vec<Technique>,
    pub custody: CustodySection,
    pub notes: Vec<NoteRow>,
    pub similar: SimilarSection,
    pub omitted: Omitted,
    /// What the report could not say: missing inputs, cut lists.
    pub remarks: Vec<String>,
}

impl SampleReport {
    /// An empty report for `sample`, stamped with the schema and `now_ms`.
    pub fn new(sample: Identity, now_ms: u64) -> Self {
        Self {
            schema: SCHEMA.into(),
            schema_version: SCHEMA_VERSION,
            generated_ms: now_ms,
            app: format!("Antinomie {}", crate::api::APP_VERSION),
            sample,
            ..Self::default()
        }
    }

    /// The versioned machine-readable form.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|error| error.to_string())
    }

    /// The assessment of the whole sample: the strongest of its runs'.
    pub fn assessment(&self) -> &'static str {
        let worst = self
            .runs
            .iter()
            .map(|run| rank(&run.assessment))
            .min()
            .unwrap_or(4);
        ASSESSMENTS[worst.min(4)]
    }
}

/// From the strongest to the weakest; `not_read` is last.
const ASSESSMENTS: [&str; 5] = [
    "matched_indicators",
    "suspicious_behaviour",
    "observed_only",
    "no_findings",
    "not_read",
];

fn rank(assessment: &str) -> usize {
    ASSESSMENTS
        .iter()
        .position(|known| *known == assessment)
        .unwrap_or(4)
}

/// The formats a sample report can be written in.
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
        Self::Json,
        Self::Misp,
        Self::Stix,
        Self::Markdown,
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

/// What the person chose in the dialog.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Choices {
    pub formats: Vec<Format>,
    /// Defang indicators in HTML, PDF and Markdown (on unless switched off).
    pub defang: bool,
    /// Where the files go; empty means the dialog's default folder.
    pub folder: String,
}

impl Default for Choices {
    fn default() -> Self {
        Self {
            formats: vec![Format::Html, Format::Pdf],
            defang: true,
            folder: String::new(),
        }
    }
}

impl Choices {
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

/// `text` cut to `max` characters with an ellipsis; the flag says it was cut.
pub fn clip(text: &str, max: usize) -> (String, bool) {
    if text.chars().count() <= max {
        return (text.to_owned(), false);
    }
    let mut cut: String = text.chars().take(max).collect();
    cut.push('…');
    (cut, true)
}

/// Keep `max` rows of `rows`; the number dropped.
pub fn cap<T>(rows: &mut Vec<T>, max: usize) -> u64 {
    let dropped = rows.len().saturating_sub(max) as u64;
    rows.truncate(max);
    dropped
}

fn hex(text: &str) -> bool {
    !text.is_empty() && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The run report's [`super::Indicator`] for a merged one, so the MISP and
/// STIX writers of the run report turn it into attributes and patterns. The
/// digest keeps one text per indicator, so the form is read from its shape:
/// a URL gets the cleartext scheme when it has none, a TLS value of 32 hex
/// digits is a JA3 hash, of 40 (colons allowed) a certificate SHA-1, and
/// anything else a server name.
pub(crate) fn as_indicator(item: &MergedIndicator) -> super::Indicator {
    let mut out = super::Indicator {
        kind: item.kind.clone(),
        value: item.value.clone(),
        matched: item.matched,
        verdict: if item.matched { "matched" } else { "no match" }.into(),
        sources: format!(
            "run {}",
            item.runs
                .iter()
                .map(usize::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ..super::Indicator::default()
    };
    match item.kind.as_str() {
        "url" => {
            out.url = if item.value.contains("://") {
                item.value.clone()
            } else {
                format!("http://{}", item.value)
            };
        }
        "tls" => {
            let bare = item.value.replace(':', "");
            if hex(&bare) && bare.len() == 32 {
                out.ja3 = bare;
            } else if hex(&bare) && bare.len() == 40 {
                out.cert_sha1 = bare;
            } else {
                out.sni = item.value.clone();
            }
        }
        "file" if hex(&item.value) && item.value.len() == 64 => {
            out.sha256 = item.value.clone();
        }
        _ => {}
    }
    out
}

impl SampleReport {
    /// Apply the list caps and note what was cut or is missing. Call once,
    /// after the parts are filled in.
    pub fn seal(&mut self) {
        self.omitted.indicators += cap(&mut self.indicators, LIST_ROWS);
        self.omitted.detections += cap(&mut self.detections, LIST_ROWS);
        self.omitted.runs += cap(&mut self.runs, LIST_ROWS);
        self.omitted.lineage +=
            cap(&mut self.lineage.parents, LIST_ROWS) + cap(&mut self.lineage.children, LIST_ROWS);
        cap(&mut self.similar.rows, LIST_ROWS);
        let o = self.omitted.clone();
        for (count, what) in [
            (o.indicators, "indicators"),
            (o.detections, "rules"),
            (o.runs, "runs"),
            (o.lineage, "lineage entries"),
            (o.custody, "custody entries"),
            (o.notes, "notes"),
        ] {
            if count > 0 {
                self.remarks.push(format!(
                    "{count} {what} are left out because the report keeps at most {LIST_ROWS} of each list."
                ));
            }
        }
        let unread = self.runs.iter().filter(|run| !run.triaged).count();
        if unread > 0 {
            self.remarks.push(format!(
                "{unread} of {} run(s) have not been read by Triage, so their indicators, rules and assessments are missing.",
                self.runs.len()
            ));
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! Offline rule evaluation against identity-scoped retained evidence.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const JOURNAL_FILE: &str = "triage-events.jsonl";
/// Format of a journal written now. Version 2 adds the per-event `_inferred`
/// list; version 3 adds the guest kernel's credentials and file hashes (`User`,
/// `LogonId`, `Hashes`, `HashSkipped` and the auditd `uid` family). Older
/// journals lack them and still load and scan.
pub const JOURNAL_VERSION: u64 = 3;
/// Oldest journal format the reader and the Sigma adapter accept.
pub const JOURNAL_VERSION_MIN: u64 = 1;
pub const REPORT_LIMIT: usize = 32 * 1024 * 1024;
pub const MATCH_LIMIT: usize = 10_000;
/// Format of a report written now; see [`Report::format_version`].
pub const REPORT_FORMAT_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Engine {
    #[default]
    Yara,
    Ids,
    Sigma,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub yara_rules: String,
    pub ids_rules: String,
    pub sigma_rules: String,
    pub sigma_python: String,
    pub scan_memory: bool,
    pub scan_recovered: bool,
    /// Data directory whose `rules/` tree is the managed selection.
    /// Empty means no managed packs are included.
    pub rules_root: String,
    /// Manual scan of evidence that is still being captured.
    pub partial: bool,
    /// Identity of the evidence generation this request is allowed to scan.
    pub evidence_key: String,
}

impl Settings {
    /// The Sigma Python a scan runs: the one set here, else the Sigma tool
    /// installed in the data directory, else empty for the system Python.
    pub fn effective_sigma_python(&self) -> String {
        let configured = self.sigma_python.trim();
        if !configured.is_empty() || self.rules_root.is_empty() {
            return configured.to_owned();
        }
        crate::analysis_tools::managed_sigma_python(std::path::Path::new(&self.rules_root))
            .map(|python| python.display().to_string())
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub vm_id: String,
    pub boot_id: String,
    pub run_id: String,
    pub root_cookie: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSource {
    pub offset: u64,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    Call {
        stream: u64,
        cookie: u64,
        call: u64,
    },
    Packet {
        capture: PathBuf,
        frame: u64,
    },
    Bytes {
        path: PathBuf,
        offset: Option<u64>,
        address: Option<u64>,
        report_id: Option<String>,
        #[serde(default)]
        block: Option<ByteSource>,
    },
}

/// When a source recorded an event, in that source's own clock: calls carry
/// the guest's monotonic nanoseconds, packets the host's Unix microseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "clock", content = "value", rename_all = "snake_case")]
pub enum Moment {
    GuestNs(u64),
    EpochUs(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub category: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub evidence: Evidence,
    /// Absent in journals written before this was recorded, and when the
    /// source had no timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<Moment>,
    /// Names of fields in `fields` that were derived by correlation or by
    /// tracking state, not read from one call: the value may be wrong where
    /// the correlation was. Absent in version 1 journals, meaning none.
    #[serde(default, rename = "_inferred", skip_serializing_if = "Vec::is_empty")]
    pub inferred: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JournalSummary {
    pub sha256: String,
    pub events: u64,
    pub omitted: u64,
    pub complete: bool,
}

/// A bounded derived event index, independent of table filters and pagination.
pub struct EventJournal {
    file: File,
    temporary: PathBuf,
    destination: PathBuf,
    digest: Sha256,
    size: usize,
    count: u64,
    omitted: u64,
}

impl EventJournal {
    /// Start a new atomic index for the supplied run identity.
    pub fn new(directory: &Path, identity: &Identity) -> Result<Self, String> {
        if identity.root_cookie == 0
            || [&identity.vm_id, &identity.boot_id, &identity.run_id]
                .iter()
                .any(|id| id.is_empty() || id.len() > 128)
        {
            return Err("invalid normalized event run identity".into());
        }
        let temporary = directory.join(format!(".triage-events-{}", crate::storage::unique_id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        let mut journal = Self {
            file,
            temporary,
            destination: directory.join(JOURNAL_FILE),
            digest: Sha256::new(),
            size: 0,
            count: 0,
            omitted: 0,
        };
        journal
            .line(&serde_json::json!({"kind":"header", "format_version":JOURNAL_VERSION, "identity":identity}))?;
        Ok(journal)
    }
    fn line(&mut self, value: &impl Serialize) -> Result<(), String> {
        let mut encoded = serde_json::to_vec(value).map_err(|error| error.to_string())?;
        encoded.push(b'\n');
        self.file
            .write_all(&encoded)
            .map_err(|error| error.to_string())?;
        self.digest.update(&encoded);
        self.size += encoded.len();
        Ok(())
    }
    /// Retain one normalized observation. Oversized/unavailable fields are omitted.
    pub fn push(&mut self, event: Event) -> Result<(), String> {
        let oversized = event.category.len() > 64
            || event.fields.len() > 64
            || event.inferred.len() > 64
            || event.inferred.iter().any(|name| name.len() > 64)
            || event
                .fields
                .iter()
                .any(|(name, value)| name.len() > 64 || value.to_string().len() > 8192);
        if oversized || self.size > 128 * 1024 * 1024 - 64 * 1024 {
            self.omitted += 1;
            return Ok(());
        }
        let encoded = serde_json::to_value(&event).map_err(|error| error.to_string())?;
        if serde_json::to_vec(&encoded)
            .map_err(|error| error.to_string())?
            .len()
            > 60 * 1024
        {
            self.omitted += 1;
            return Ok(());
        }
        self.line(&serde_json::json!({"kind":"event", "event":encoded}))?;
        self.count += 1;
        Ok(())
    }
    /// Publish only a complete index operation; `complete` describes source coverage.
    pub fn finish(mut self, complete: bool) -> Result<JournalSummary, String> {
        let complete = complete && self.omitted == 0;
        self.line(&serde_json::json!({"kind":"end", "complete":complete, "events":self.count, "omitted":self.omitted}))?;
        self.file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&self.temporary, &self.destination).map_err(|error| error.to_string())?;
        File::open(
            self.destination
                .parent()
                .ok_or("journal directory missing")?,
        )
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
        Ok(JournalSummary {
            sha256: format!("{:x}", self.digest.clone().finalize()),
            events: self.count,
            omitted: self.omitted,
            complete,
        })
    }
}
impl Drop for EventJournal {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.temporary);
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Complete,
    Partial,
    Unavailable,
    /// The selection contains no enabled rules. This is not a zero-match scan.
    NoRules,
    /// The engine was ready but the evidence it needs is absent or still open.
    Missing,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Source {
    pub name: String,
    pub version: String,
    pub license: String,
    pub sha256: String,
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub source: String,
    pub license: String,
    /// Supplied authors, unchanged. Empty means the rule did not provide one.
    #[serde(default)]
    pub author: String,
    pub mitre: Vec<String>,
    pub count: u64,
    pub evidence: Vec<Evidence>,
    /// Sigma only: the one-based journal ordinal of the event behind each
    /// `evidence` entry, in the same order. Empty on other engines and on
    /// results saved before it was kept.
    #[serde(default)]
    pub events: Vec<u64>,
    pub details: String,
    /// Original rule body: one YARA rule, one Suricata rule, or one Sigma document.
    /// Empty on results saved before this was retained.
    #[serde(default)]
    pub rule_text: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub engine: Engine,
    pub identity: Identity,
    pub state: State,
    pub sources: Vec<Source>,
    pub findings: Vec<Finding>,
    pub scanned_rules: Option<u64>,
    #[serde(default)]
    pub scanned_objects: u64,
    pub skipped_rules: u64,
    pub skipped: Vec<String>,
    pub omitted_evidence: u64,
    pub warnings: Vec<String>,
    pub source_digest: Option<String>,
    /// Digest of the enabled packs, groups and disabled rule ids.
    #[serde(default)]
    pub selection: String,
    /// Evidence generation this report was admitted against. Empty on older reports.
    #[serde(default)]
    pub evidence_key: String,
    /// True when this run committed both its report and, when rules are managed,
    /// the selection manifest. Older reports leave this unset.
    #[serde(default)]
    pub provenance_saved: Option<bool>,
    /// Sigma rules whose logsource category is accepted by this adapter.
    #[serde(default)]
    pub category_accepted: u64,
    /// Sigma rules whose logsource category is outside the captured set.
    #[serde(default)]
    pub category_rejected: u64,
    /// Sigma rules rejected by the backend or the captured field schema.
    #[serde(default)]
    pub backend_rejected: u64,
    /// Events skipped because a field this rule uses was absent in this run.
    #[serde(default)]
    pub missing_field_events: u64,
    /// What the rules were run against. None on results saved before this
    /// was recorded.
    #[serde(default)]
    pub inputs: Option<Vec<ScannedInput>>,
    /// Report format. 0 is a result saved before it was recorded.
    ///
    /// Version 1 adds `coverage`. Rules that could not be loaded or did not
    /// apply no longer make a scan partial. A report saved earlier keeps the
    /// state it was stored with; it is not migrated, so an older IDS or Sigma
    /// result can still read "partial" for only those reasons.
    #[serde(default)]
    pub format_version: u64,
    /// IDS and Sigma rule counts. None on YARA and on results saved before version 1.
    #[serde(default)]
    pub coverage: Option<Coverage>,
}

impl Report {
    pub fn empty(engine: Engine, identity: Identity) -> Self {
        Self {
            engine,
            identity,
            state: State::Complete,
            sources: vec![],
            findings: vec![],
            scanned_rules: None,
            scanned_objects: 0,
            skipped_rules: 0,
            skipped: vec![],
            omitted_evidence: 0,
            warnings: vec![],
            source_digest: None,
            selection: String::new(),
            evidence_key: String::new(),
            provenance_saved: None,
            category_accepted: 0,
            category_rejected: 0,
            backend_rejected: 0,
            missing_field_events: 0,
            inputs: Some(Vec::new()),
            format_version: REPORT_FORMAT_VERSION,
            coverage: None,
        }
    }
    pub fn unavailable(engine: Engine, identity: Identity, reason: impl Into<String>) -> Self {
        let mut report = Self::empty(engine, identity);
        report.state = State::Unavailable;
        report.warnings.push(reason.into());
        report
    }
}

mod coverage;
mod ids;
mod inputs;
pub mod journal;
mod runner;
mod yara;
pub use coverage::{
    COVERAGE_LIST_LIMIT, Coverage, CoverageItem, CoverageReason, IDS_REASONS, SIGMA_REASONS,
};
pub use inputs::{InputKind, InputOutcome, SIGMA_COVERAGE_WARNING, ScannedInput};
pub use runner::{
    FrozenSelection, Request, load, read_evidence, result_directory, run, run_with_progress,
    worker_main_if_requested,
};

/// One step a running scan can name. YARA and Suricata are a single pass over
/// targets; Sigma walks rules.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScanTarget {
    Specimen,
    MemoryBlock {
        index: u64,
        total: u64,
    },
    RecoveredFile {
        index: u64,
        total: u64,
    },
    CaptureSegment {
        index: u64,
        total: u64,
    },
    SigmaRule {
        index: u64,
        total: u64,
        title: String,
    },
}

/// Structured scan progress written by the worker and read on the phase channel.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub target: ScanTarget,
    pub rules_loaded: u64,
}

/// Decimal grouping for counts shown beside a scan (`2094` → `2,094`).
pub fn group_digits(value: u64) -> String {
    let text = value.to_string();
    let mut out = String::with_capacity(text.len() + text.len() / 3);
    for (index, character) in text.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            out.push(',');
        }
        out.push(character);
    }
    out.chars().rev().collect()
}

/// Status text for one progress value.
pub fn progress_text(progress: &ScanProgress) -> String {
    match &progress.target {
        ScanTarget::SigmaRule {
            index,
            total,
            title,
        } => format!("rule {index} of {total} — {title}"),
        ScanTarget::Specimen => progress_target("specimen", progress.rules_loaded),
        ScanTarget::MemoryBlock { index, total } => progress_target(
            &format!("memory block {index} of {total}"),
            progress.rules_loaded,
        ),
        ScanTarget::RecoveredFile { index, total } => progress_target(
            &format!("recovered file {index} of {total}"),
            progress.rules_loaded,
        ),
        ScanTarget::CaptureSegment { index, total } => progress_target(
            &format!("capture segment {index} of {total}"),
            progress.rules_loaded,
        ),
    }
}

fn progress_target(stage: &str, rules_loaded: u64) -> String {
    if rules_loaded == 0 {
        stage.to_owned()
    } else {
        format!("{stage} · {} rules loaded", group_digits(rules_loaded))
    }
}

/// `index / total` for a counted target. A specimen has no fraction.
pub fn progress_fraction(progress: &ScanProgress) -> Option<f32> {
    let (done, total) = match &progress.target {
        ScanTarget::Specimen => return None,
        ScanTarget::MemoryBlock { index, total }
        | ScanTarget::RecoveredFile { index, total }
        | ScanTarget::CaptureSegment { index, total }
        | ScanTarget::SigmaRule { index, total, .. } => (*index, *total),
    };
    if total == 0 {
        None
    } else {
        Some((done as f32 / total as f32).clamp(0.0, 1.0))
    }
}

/// Keeps the newest progress and publishes at most a few times a second.
pub(super) struct ProgressCoalescer {
    interval: std::time::Duration,
    last_emit: Option<std::time::Instant>,
    pending: Option<ScanProgress>,
}

impl ProgressCoalescer {
    pub(super) fn new(interval: std::time::Duration) -> Self {
        Self {
            interval,
            last_emit: None,
            pending: None,
        }
    }

    pub(super) fn push(
        &mut self,
        progress: ScanProgress,
        now: std::time::Instant,
    ) -> Option<ScanProgress> {
        self.pending = Some(progress);
        self.poll(now)
    }

    pub(super) fn poll(&mut self, now: std::time::Instant) -> Option<ScanProgress> {
        let due = match self.last_emit {
            None => true,
            Some(then) => now.saturating_duration_since(then) >= self.interval,
        };
        if due && self.pending.is_some() {
            self.last_emit = Some(now);
            self.pending.take()
        } else {
            None
        }
    }

    /// A stage change is written by the caller. Drop any held update so it
    /// cannot replace that stage, and start a new interval.
    pub(super) fn force(&mut self, now: std::time::Instant) {
        self.pending = None;
        self.last_emit = Some(now);
    }
}

pub(crate) const RULE_TEXT_LIMIT: usize = 8192;
const RULE_TEXT_BUDGET: usize = 4 * 1024 * 1024;

pub(crate) fn clip_rule(text: &str) -> String {
    let mut out = String::new();
    for character in text.chars() {
        if out.len() + character.len_utf8() > RULE_TEXT_LIMIT {
            break;
        }
        out.push(character);
    }
    out
}

/// Caps stored rule bodies so a large match list still fits the result file.
pub(crate) struct RuleTextBudget {
    remaining: usize,
}

impl RuleTextBudget {
    pub(crate) fn new() -> Self {
        Self {
            remaining: RULE_TEXT_BUDGET,
        }
    }

    pub(crate) fn take(&mut self, text: &str) -> String {
        let clipped = clip_rule(text);
        if clipped.is_empty() || clipped.len() > self.remaining {
            return String::new();
        }
        self.remaining -= clipped.len();
        clipped
    }
}

/// Parse rule-supplied ATT&CK identifiers without inventing technique mappings.
pub fn mitre_references(text: &str) -> Vec<String> {
    let mut result = std::collections::BTreeSet::new();
    for token in
        text.split(|character: char| !character.is_ascii_alphanumeric() && character != '.')
    {
        let token = token.trim_matches('.').to_ascii_uppercase();
        let token = token.strip_prefix("ATTACK.").unwrap_or(&token);
        let valid = (token.len() == 5 || token.len() == 9)
            && token.starts_with('T')
            && token.as_bytes()[1..5].iter().all(u8::is_ascii_digit)
            && (token.len() == 5
                || token.as_bytes()[5] == b'.'
                    && token.as_bytes()[6..].iter().all(u8::is_ascii_digit));
        if valid {
            result.insert(token.to_owned());
        }
    }
    result.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_configured_python_wins_over_the_installed_sigma_tool() {
        let data = std::env::temp_dir().join(format!("ant-sigma-tool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let mut settings = Settings {
            rules_root: data.display().to_string(),
            ..Default::default()
        };
        assert_eq!(
            settings.effective_sigma_python(),
            "",
            "no tool: the system Python"
        );
        let tool = data.join("tools/sigma");
        std::fs::create_dir_all(tool.join("venv/bin")).unwrap();
        std::fs::write(tool.join("venv/bin/python"), b"").unwrap();
        std::fs::write(
            tool.join("tool.json"),
            br#"{"id":"sigma","version":"2.0.1"}"#,
        )
        .unwrap();
        // A different directory is not served from the previous answer.
        let other = Settings {
            rules_root: data.join("elsewhere").display().to_string(),
            ..Default::default()
        };
        assert_eq!(other.effective_sigma_python(), "");
        assert_eq!(
            crate::analysis_tools::managed_sigma_python(&data),
            Some(tool.join("venv/bin/python"))
        );
        settings.sigma_python = " /opt/python/bin/python ".into();
        assert_eq!(settings.effective_sigma_python(), "/opt/python/bin/python");
        settings.rules_root.clear();
        settings.sigma_python.clear();
        assert_eq!(settings.effective_sigma_python(), "", "no data directory");
        let _ = std::fs::remove_dir_all(&data);
    }
    #[test]
    fn journal_is_filter_independent_atomic_and_marks_omitted_events_partial() {
        let directory =
            std::env::temp_dir().join(format!("ant-events-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&directory).unwrap();
        let identity = Identity {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run".into(),
            root_cookie: 7,
        };
        let mut journal = EventJournal::new(&directory, &identity).unwrap();
        journal
            .push(Event {
                category: "process_creation".into(),
                fields: BTreeMap::from([("Image".into(), serde_json::json!("/bin/sh"))]),
                evidence: Evidence::Call {
                    stream: 1,
                    cookie: 7,
                    call: u64::MAX,
                },
                time: None,
                inferred: Vec::new(),
            })
            .unwrap();
        assert!(!directory.join(JOURNAL_FILE).exists());
        journal
            .push(Event {
                category: "x".repeat(65),
                fields: BTreeMap::new(),
                evidence: Evidence::Call {
                    stream: 1,
                    cookie: 7,
                    call: 2,
                },
                time: None,
                inferred: Vec::new(),
            })
            .unwrap();
        let result = journal.finish(true).unwrap();
        assert_eq!(
            (result.events, result.omitted, result.complete),
            (1, 1, false)
        );
        let content = fs::read(directory.join(JOURNAL_FILE)).unwrap();
        assert_eq!(result.sha256, crate::storage::sha256_hex(&content));
        assert!(
            String::from_utf8(content)
                .unwrap()
                .contains(&u64::MAX.to_string())
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn events_keep_their_time_and_journals_without_one_still_load() {
        let old = r#"{"category":"file_event","fields":{},"evidence":{"kind":"call","stream":1,"cookie":2,"call":3}}"#;
        let event: Event = serde_json::from_str(old).unwrap();
        assert_eq!(event.time, None);
        assert!(!serde_json::to_string(&event).unwrap().contains("time"));
        let timed = Event {
            time: Some(Moment::EpochUs(9)),
            ..event
        };
        let text = serde_json::to_string(&timed).unwrap();
        assert!(
            text.contains(r#""time":{"clock":"epoch_us","value":9}"#),
            "{text}"
        );
        assert_eq!(
            serde_json::from_str::<Event>(&text).unwrap().time,
            timed.time
        );
    }
    #[test]
    fn attack_reference_syntax_does_not_turn_arbitrary_numbers_into_techniques() {
        assert_eq!(
            mitre_references("attack.t1059.004 [T1105] T1105 task 123 T99999"),
            vec!["T1059.004", "T1105"]
        );
    }
    #[test]
    fn a_saved_finding_without_an_author_stays_unknown() {
        let saved = r#"{"rule_id":"old","title":"Old","severity":"low","source":"legacy","license":"","mitre":[],"count":1,"evidence":[],"details":""}"#;
        let finding: Finding = serde_json::from_str(saved).unwrap();
        assert!(finding.author.is_empty());
        assert!(finding.events.is_empty(), "no journal event numbers kept");
        let authored = Finding {
            author: "One Author, Second Author".into(),
            ..finding.clone()
        };
        let encoded = serde_json::to_string(&authored).unwrap();
        let reopened: Finding = serde_json::from_str(&encoded).unwrap();
        assert_eq!(reopened.author, "One Author, Second Author");
    }

    #[test]
    fn progress_text_names_sigma_rules_and_one_pass_targets() {
        assert_eq!(group_digits(0), "0");
        assert_eq!(group_digits(12), "12");
        assert_eq!(group_digits(2094), "2,094");
        let specimen = ScanProgress {
            target: ScanTarget::Specimen,
            rules_loaded: 2094,
        };
        assert_eq!(progress_text(&specimen), "specimen · 2,094 rules loaded");
        assert!(progress_fraction(&specimen).is_none());
        let memory = ScanProgress {
            target: ScanTarget::MemoryBlock {
                index: 3,
                total: 12,
            },
            rules_loaded: 2094,
        };
        assert_eq!(
            progress_text(&memory),
            "memory block 3 of 12 · 2,094 rules loaded"
        );
        assert_eq!(progress_fraction(&memory), Some(0.25));
        let recovered = ScanProgress {
            target: ScanTarget::RecoveredFile { index: 2, total: 8 },
            rules_loaded: 10,
        };
        assert_eq!(
            progress_text(&recovered),
            "recovered file 2 of 8 · 10 rules loaded"
        );
        let capture = ScanProgress {
            target: ScanTarget::CaptureSegment { index: 1, total: 3 },
            rules_loaded: 40_000,
        };
        assert_eq!(
            progress_text(&capture),
            "capture segment 1 of 3 · 40,000 rules loaded"
        );
        assert_eq!(progress_fraction(&capture), Some(1.0 / 3.0));
        let raw = r#"{"target":{"kind":"sigma_rule","index":2,"total":9,"title":"Curl pipe"},"rules_loaded":9}"#;
        let sigma: ScanProgress = serde_json::from_str(raw).unwrap();
        assert_eq!(progress_text(&sigma), "rule 2 of 9 — Curl pipe");
        let fraction = progress_fraction(&sigma).unwrap();
        assert!((fraction - 2.0 / 9.0).abs() < f32::EPSILON);
        let bare = ScanProgress {
            target: ScanTarget::Specimen,
            rules_loaded: 0,
        };
        assert_eq!(progress_text(&bare), "specimen");
    }

    #[test]
    fn progress_updates_coalesce_to_a_few_a_second_and_keep_the_latest() {
        let mut coalescer = ProgressCoalescer::new(std::time::Duration::from_millis(250));
        let start = std::time::Instant::now();
        let mut published = Vec::new();
        for index in 1..=20 {
            let progress = ScanProgress {
                target: ScanTarget::RecoveredFile { index, total: 20 },
                rules_loaded: 4,
            };
            if let Some(progress) = coalescer.push(progress, start) {
                published.push(progress);
            }
        }
        assert_eq!(published.len(), 1);
        assert!(matches!(
            published[0].target,
            ScanTarget::RecoveredFile {
                index: 1,
                total: 20
            }
        ));
        assert!(
            coalescer
                .poll(start + std::time::Duration::from_millis(249))
                .is_none()
        );
        let flushed = coalescer
            .poll(start + std::time::Duration::from_millis(250))
            .unwrap();
        assert_eq!(
            progress_text(&flushed),
            "recovered file 20 of 20 · 4 rules loaded"
        );
        let directory =
            std::env::temp_dir().join(format!("ant-progress-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("progress.json");
        super::runner::write_progress(&path, &flushed);
        let stored: ScanProgress = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored, flushed);
        let _ = std::fs::remove_dir_all(&directory);
    }
}

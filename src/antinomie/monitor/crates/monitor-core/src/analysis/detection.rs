// SPDX-License-Identifier: MIT
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
pub const REPORT_LIMIT: usize = 32 * 1024 * 1024;
pub const MATCH_LIMIT: usize = 10_000;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub category: String,
    pub fields: BTreeMap<String, serde_json::Value>,
    pub evidence: Evidence,
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
            .line(&serde_json::json!({"kind":"header", "format_version":1, "identity":identity}))?;
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
    pub mitre: Vec<String>,
    pub count: u64,
    pub evidence: Vec<Evidence>,
    pub details: String,
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
            category_accepted: 0,
            category_rejected: 0,
            backend_rejected: 0,
            missing_field_events: 0,
        }
    }
    pub fn unavailable(engine: Engine, identity: Identity, reason: impl Into<String>) -> Self {
        let mut report = Self::empty(engine, identity);
        report.state = State::Unavailable;
        report.warnings.push(reason.into());
        report
    }
}

mod ids;
mod runner;
mod yara;
pub use runner::{
    FrozenSelection, Request, load, read_evidence, result_directory, run, worker_main_if_requested,
};

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
    fn attack_reference_syntax_does_not_turn_arbitrary_numbers_into_techniques() {
        assert_eq!(
            mitre_references("attack.t1059.004 [T1105] T1105 task 123 T99999"),
            vec!["T1059.004", "T1105"]
        );
    }
}

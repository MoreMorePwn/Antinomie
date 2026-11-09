// SPDX-License-Identifier: GPL-3.0-only
//! What Triage found in one run, kept beside the run so the sample window can
//! add up many runs without reading their recordings again. Triage computes
//! everything from the recording when a run is opened; nothing else keeps it.
//! The digest is written when Triage finishes reading a finished run (the
//! behaviour findings and the indicators) and when a detection engine's
//! report for it exists, and a run that was never opened has none.
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

/// The digest's file name inside the run's folder.
pub const FILE: &str = "triage-digest.json";

/// Bumped when a field changes meaning; a digest of another version is read as
/// absent and written again the next time Triage opens the run.
pub const VERSION: u32 = 1;

/// Larger than this is not a digest (the writer caps every list).
const MAX_BYTES: u64 = 4 * 1024 * 1024;
/// Per list; a run with more keeps the first ones.
pub const MAX_ROWS: usize = 2_000;

/// A rule of the behaviour engine that matched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct BehaviourHit {
    pub rule: String,
    /// `high`, `medium`, `low` or `info`.
    pub tier: String,
    /// The finding category's tag (`execution`, `persistence`, `evasion` ...).
    pub category: String,
    /// ATT&CK technique and detection-strategy ids the rule maps to.
    pub attack: Vec<String>,
    pub count: u64,
    pub first_ns: u64,
}

/// One anti-analysis check a process of the run made.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EvasionCheck {
    /// `Virtual machine`, `Debugger`, `Sandbox` or `Timing`.
    pub category: String,
    pub rule: String,
    /// The file it read or the call it made.
    pub object: String,
    /// What Triage wrote about it, the answer the check got included.
    pub summary: String,
    pub process: String,
    pub count: u64,
    /// The task cookie of the process whose calls are the evidence (0 when
    /// unknown); digests written before 0.8.0 have none.
    #[serde(skip_serializing_if = "is_zero")]
    pub cookie: u64,
    /// The call ids that are the evidence, first first, at most
    /// [`EVIDENCE_CALLS`], so Syscall Trace can show them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub calls: Vec<u64>,
}

/// Evidence calls a check keeps for its link into Syscall Trace.
pub const EVIDENCE_CALLS: usize = 32;

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// What the behaviour engine found in the whole run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Behaviour {
    /// The highest tier of any finding; empty when there were none.
    pub highest: String,
    pub rules: Vec<BehaviourHit>,
    pub evasion: Vec<EvasionCheck>,
}

/// A rule of a detection engine that matched.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DetectionHit {
    /// `YARA`, `IDS` or `Sigma`.
    pub engine: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub mitre: Vec<String>,
    pub count: u64,
    /// The malware family a YARA rule names in its metadata; empty when the
    /// rule names none (and for the other engines).
    pub family: String,
    /// The rule's author as the rule gives it, unchanged; empty when it names
    /// none. A rule's licence asks for it to stay with every message that
    /// reports a match.
    pub author: String,
    /// The licence of the rule's pack.
    pub license: String,
    /// The rule pack the rule came from.
    pub source: String,
    /// The rule's own reference link, when it names one.
    pub reference: String,
}

impl DetectionHit {
    /// The ATT&CK ids this hit adds to the run's technique list. A Sigma rule
    /// of low or informational severity adds none (a rule such as "Program
    /// Executions in Suspicious Folders" fires in nearly every run, since
    /// samples run from /tmp, and would flood the list), and a Sigma tag for a
    /// technique a run cannot show (upstream T1584 and T1587 on that rule) is
    /// dropped. The hit itself stays in the detection results.
    pub fn attack_ids(&self) -> impl Iterator<Item = &String> {
        let sigma = self.engine.eq_ignore_ascii_case("sigma");
        let quiet = sigma
            && matches!(
                self.severity.to_ascii_lowercase().as_str(),
                "low" | "informational" | "info"
            );
        self.mitre
            .iter()
            .filter(move |id| !quiet && !(sigma && !crate::mitre::observable(id)))
    }
}

/// One indicator of compromise of the run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IndicatorEntry {
    /// `endpoint`, `domain`, `url`, `tls` or `file`.
    pub ty: String,
    pub value: String,
    /// A stored abuse.ch dataset matched it.
    pub matched: bool,
    /// The row's second line: protocol, how a name was seen, HTTP version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub sub: String,
    /// `pcap`, `syscall`, `disk` or `static`. Empty in a digest written before
    /// 0.8.2, which also has none of the fields below.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<String>,
    /// First and last seen in the run, Unix microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_us: Option<u64>,
    /// "9 connections", "3 requests".
    #[serde(skip_serializing_if = "String::is_empty")]
    pub count: String,
    /// The one process that made a matching call, `name · pid`; empty when
    /// none or several did.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub process: String,
    /// A file's path in the guest, a URL's normal form.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// A file's roles: sample, created, executed, deleted, written at close.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Why nothing was looked up (`private address`, `local name`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub not_checked: String,
    /// Why this is the base image's own traffic; empty for the sample's.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub noise: String,
    /// The stored dataset records that matched it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hits: Vec<IndicatorHit>,
}

/// A stored abuse.ch record that matched an indicator.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IndicatorHit {
    pub dataset: String,
    pub family: String,
    pub record_id: String,
    pub reference: String,
}

/// A file of the run that counts for lineage: an executable, a script, a
/// shared object or a download. Written config files stay in the IOC list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LineageFile {
    pub path: String,
    /// SHA-256 when the guest or a disk dump gave one; empty otherwise.
    pub sha256: String,
    /// `created`, `written at close`, `changed`, `deleted`, `sample`, `executed`.
    pub roles: Vec<String>,
    /// The image path of the process that wrote it; empty when not known.
    pub writer: String,
    /// Why the file has no hash, or where its hash came from ("hashed from
    /// the starting disk"); empty when the guest's hash needs no remark.
    pub hash_note: String,
}

/// A program one process started, from the image it ran before.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LineageExec {
    /// The image path of the process that started it; empty when not known.
    pub parent: String,
    pub path: String,
    pub sha256: String,
    /// For a shell or interpreter started with `-c`: the command line it ran.
    pub command: String,
    pub count: u64,
    /// As [`LineageFile::hash_note`], for the program's file.
    pub hash_note: String,
}

/// A file the run wrote, rewrote, deleted or renamed, as the Samples window
/// lists it under Artifacts.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct WrittenFile {
    pub path: String,
    /// `written` (the run created it), `rewritten` (it existed), `deleted` or
    /// `renamed to <name>`.
    pub state: String,
    /// The size of the final bytes the run saw, when it knew it.
    pub size: Option<u64>,
    /// SHA-256 of the final bytes the guest took; empty when it took none.
    pub sha256: String,
    /// Why there is no hash; empty when there is one.
    pub hash_note: String,
}

/// What a run's files and programs say about where its files came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Lineage {
    pub files: Vec<LineageFile>,
    pub execs: Vec<LineageExec>,
}

/// How much of the run the digest was built from, and why not all of it.
/// A digest written by the background build or the window says so here; one
/// written before 0.9.0 has no coverage and counts as built from the whole run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Coverage {
    /// The index behind the digest was partial (telemetry lost, a size or
    /// time budget reached, the recording still being saved, ...).
    pub partial: bool,
    /// One plain-words reason each; empty when `partial` is false.
    pub reasons: Vec<String>,
    /// Calls of the run's program the digest read.
    pub calls_read: u64,
    /// A size or time budget stopped the read before the end of the recording.
    pub budget_reached: bool,
    /// The partial state can still change (the recording or capture was being
    /// written): the build is repeated once the recording changes.
    pub revisit: bool,
    /// The recording's identity ([`source_stamp`]) when the digest was built.
    pub source: String,
}

/// What identifies the state of a run's recording, to tell a digest built from
/// an older state of it: sizes and times of the files the index reads.
pub fn source_stamp(run_directory: &Path) -> String {
    use std::os::unix::fs::MetadataExt;
    [
        "telemetry.raw",
        "artifacts.json",
        "run.json",
        "manifest.json",
    ]
    .iter()
    .map(|name| {
        std::fs::metadata(run_directory.join(name)).map_or_else(
            |_| "-".to_owned(),
            |meta| format!("{}.{}.{}", meta.len(), meta.mtime(), meta.mtime_nsec()),
        )
    })
    .collect::<Vec<_>>()
    .join("|")
}

/// Everything Triage knew about a run when it last read it. A part that was
/// never computed is `None`, which is not the same as an empty list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RunDigest {
    pub version: u32,
    /// When the digest was last written, ms since the epoch.
    pub written_ms: u64,
    pub behaviour: Option<Behaviour>,
    pub detections: Option<Vec<DetectionHit>>,
    pub indicators: Option<Vec<IndicatorEntry>>,
    pub lineage: Option<Lineage>,
    /// Every file the run changed (up to [`MAX_ROWS`]); `None` for a digest
    /// written before 0.8.2.
    pub files: Option<Vec<WrittenFile>>,
    /// Why the program never started, for a run whose launch failed. Such a
    /// run has nothing for Triage to read; its digest says so, with empty
    /// findings, so it is a run that did not start and not one still unread.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_failure: Option<String>,
    /// How much of the run the digest was built from (0.9.0); `None` for a
    /// digest of an older build.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<Coverage>,
}

/// Serialises read-modify-write cycles: the UI updates a digest from short
/// threads, and two of them must not lose each other's part.
static WRITE: Mutex<()> = Mutex::new(());

fn path(run_directory: &Path) -> PathBuf {
    run_directory.join(FILE)
}

impl RunDigest {
    /// The digest of a run whose launch failed: nothing was recorded, so
    /// every part is empty and `reason` says why.
    pub fn for_failed_launch(reason: &str) -> Self {
        Self {
            behaviour: Some(Behaviour::default()),
            detections: Some(Vec::new()),
            indicators: Some(Vec::new()),
            files: Some(Vec::new()),
            launch_failure: Some(reason.to_owned()),
            ..Self::default()
        }
    }

    /// The run's digest, or `None` when it has none, it is unreadable or it
    /// is of another version.
    pub fn read(run_directory: &Path) -> Option<Self> {
        let path = path(run_directory);
        let meta = std::fs::symlink_metadata(&path).ok()?;
        if !meta.file_type().is_file() || meta.len() > MAX_BYTES {
            return None;
        }
        let digest: Self = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
        (digest.version == VERSION).then_some(digest)
    }

    /// Change the run's digest with `change`; nothing is written when the
    /// result equals what is on disk. Returns whether a file was written.
    pub fn update(run_directory: &Path, change: impl FnOnce(&mut Self)) -> Result<bool, String> {
        let _guard = WRITE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let before = Self::read(run_directory);
        let mut digest = before.clone().unwrap_or_default();
        change(&mut digest);
        digest.cap();
        digest.version = VERSION;
        let mut compared = digest.clone();
        compared.written_ms = before.as_ref().map_or(0, |before| before.written_ms);
        if before.as_ref() == Some(&compared) {
            return Ok(false);
        }
        digest.written_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        crate::storage::atomic_json(&path(run_directory), &digest)?;
        Ok(true)
    }

    fn cap(&mut self) {
        if let Some(behaviour) = &mut self.behaviour {
            behaviour.rules.truncate(MAX_ROWS);
            behaviour.evasion.truncate(MAX_ROWS);
        }
        if let Some(detections) = &mut self.detections {
            detections.truncate(MAX_ROWS);
        }
        if let Some(indicators) = &mut self.indicators {
            indicators.truncate(MAX_ROWS);
        }
        if let Some(lineage) = &mut self.lineage {
            lineage.files.truncate(MAX_ROWS);
            lineage.execs.truncate(MAX_ROWS);
        }
    }
}

/// The evasion category a behaviour rule is a check of, or `None` when the
/// rule is something done to hide (clearing logs, disabling tools) rather
/// than a check made to decide whether to run.
pub fn evasion_category(rule: &str) -> Option<&'static str> {
    match rule {
        "evasion.sandbox_probe" | "evasion.container_check" => Some("Virtual machine"),
        "evasion.traceme" | "evasion.debugger_check" | "evasion.dumpable_off" => Some("Debugger"),
        "evasion.probe_then_exit" => Some("Sandbox"),
        "evasion.long_sleep" => Some("Timing"),
        _ => None,
    }
}

/// The check after which the sample quit: the one answer Triage has to
/// whether a check changed what the sample did ("tripped").
pub const TRIPPING_CHECK: &str = "evasion.probe_then_exit";

/// The evasion categories in the order the Summary lists them.
pub const EVASION_CATEGORIES: [&str; 4] = ["Virtual machine", "Debugger", "Sandbox", "Timing"];

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("ant-digest-{name}-{}", crate::storage::unique_id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_run_without_a_digest_reads_as_none_and_a_write_round_trips() {
        let dir = dir("round");
        assert!(RunDigest::read(&dir).is_none());
        let wrote = RunDigest::update(&dir, |digest| {
            digest.behaviour = Some(Behaviour {
                highest: "high".into(),
                rules: vec![BehaviourHit {
                    rule: "persistence.cron".into(),
                    tier: "high".into(),
                    category: "persistence".into(),
                    attack: vec!["T1053.003".into()],
                    count: 2,
                    first_ns: 5,
                }],
                evasion: Vec::new(),
            });
        })
        .unwrap();
        assert!(wrote);
        let read = RunDigest::read(&dir).unwrap();
        assert_eq!(read.behaviour.as_ref().unwrap().highest, "high");
        assert!(read.detections.is_none());
        assert_eq!(read.version, VERSION);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unchanged_update_writes_nothing_and_parts_are_kept() {
        let dir = dir("same");
        let set = |digest: &mut RunDigest| {
            digest.indicators = Some(vec![IndicatorEntry {
                ty: "domain".into(),
                value: "bad.example".into(),
                matched: true,
                ..Default::default()
            }]);
        };
        assert!(RunDigest::update(&dir, set).unwrap());
        let first = RunDigest::read(&dir).unwrap();
        assert!(!RunDigest::update(&dir, set).unwrap());
        assert_eq!(RunDigest::read(&dir).unwrap().written_ms, first.written_ms);
        // Another part is added without losing the first.
        assert!(RunDigest::update(&dir, |digest| digest.detections = Some(Vec::new())).unwrap());
        let both = RunDigest::read(&dir).unwrap();
        assert_eq!(both.indicators.as_ref().unwrap().len(), 1);
        assert_eq!(both.detections, Some(Vec::new()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn another_version_or_garbage_reads_as_none() {
        let dir = dir("version");
        std::fs::write(dir.join(FILE), br#"{"version":99,"behaviour":null}"#).unwrap();
        assert!(RunDigest::read(&dir).is_none());
        std::fs::write(dir.join(FILE), b"not json").unwrap();
        assert!(RunDigest::read(&dir).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_checks_have_an_evasion_category() {
        assert_eq!(
            evasion_category("evasion.sandbox_probe"),
            Some("Virtual machine")
        );
        assert_eq!(evasion_category("evasion.long_sleep"), Some("Timing"));
        assert_eq!(evasion_category("evasion.log_clear"), None);
        assert_eq!(evasion_category("persistence.cron"), None);
    }
}

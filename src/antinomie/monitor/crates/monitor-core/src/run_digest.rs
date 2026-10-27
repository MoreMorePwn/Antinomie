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
}

/// What a run's files and programs say about where its files came from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Lineage {
    pub files: Vec<LineageFile>,
    pub execs: Vec<LineageExec>,
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
}

/// Serialises read-modify-write cycles: the UI updates a digest from short
/// threads, and two of them must not lose each other's part.
static WRITE: Mutex<()> = Mutex::new(());

fn path(run_directory: &Path) -> PathBuf {
    run_directory.join(FILE)
}

impl RunDigest {
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

// SPDX-License-Identifier: GPL-3.0-only
//! What became of the artefacts of a sample's runs: kept in the library,
//! deleted by the analyst, left with the VM or kept in the sample record.
//!
//! The rows are written when a run is deleted (see [`super::delete_run`]);
//! the Output files table reads them so a deleted run's files stay listed
//! with their hash. This module also holds the artefact kinds, the short
//! SHA-256 every list shows, a cache of file hashes (hashing a memory dump
//! takes a while) and the sidecar a rule action writes into a run's folder
//! for the VM snapshots and files it saved.
use super::library::Library;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS artifact(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL REFERENCES sample(sha256) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    vm_id TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    hash TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    fate TEXT NOT NULL,
    stored TEXT NOT NULL DEFAULT '',
    because TEXT NOT NULL DEFAULT '',
    context TEXT NOT NULL DEFAULT '',
    at_ms INTEGER NOT NULL,
    UNIQUE(sha256, vm_id, run_id, kind, name)
);
CREATE INDEX IF NOT EXISTS artifact_sample ON artifact(sha256);
CREATE TABLE IF NOT EXISTS file_hash(
    path TEXT PRIMARY KEY,
    size INTEGER NOT NULL,
    mtime_ms INTEGER NOT NULL,
    sha256 TEXT NOT NULL
);
";

/// The sidecar in a run's folder that lists the snapshots and files a rule
/// saved during the run.
pub const SAVED_FILE: &str = "saved-artifacts.json";
/// Most bytes read from the sidecar.
const SAVED_LIMIT: u64 = 1 << 20;

/// The kind of an artefact. Files of one kind are named by the kind and the
/// first 8 hex of their SHA-256 wherever they are listed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Memory,
    Core,
    Capture,
    /// A VM snapshot a rule took during the run. It stays with the VM.
    Snapshot,
    /// A file a rule saved at the moment of an event.
    File,
    /// The static analysis report of a run; kept in the sample record.
    Static,
}

impl ArtifactKind {
    pub const ALL: [ArtifactKind; 6] = [
        Self::Memory,
        Self::Core,
        Self::Capture,
        Self::Snapshot,
        Self::File,
        Self::Static,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Core => "core",
            Self::Capture => "capture",
            Self::Snapshot => "snapshot",
            Self::File => "file",
            Self::Static => "static",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == text)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Memory => "Memory dump",
            Self::Core => "Core dump",
            Self::Capture => "Network capture",
            Self::Snapshot => "VM snapshot",
            Self::File => "Saved file",
            Self::Static => "Static report",
        }
    }

    pub fn plural(self) -> &'static str {
        match self {
            Self::Memory => "memory dumps",
            Self::Core => "core dumps",
            Self::Capture => "network captures",
            Self::Snapshot => "VM snapshots",
            Self::File => "saved files",
            Self::Static => "static reports",
        }
    }
}

/// The first 8 hex of a SHA-256, or a dash when the hash is not known.
pub fn short_hash(sha256: &str) -> String {
    sha256
        .get(..8)
        .map_or_else(|| "–".to_owned(), str::to_owned)
}

/// What became of an artefact when its run was deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fate {
    /// Moved into the library: Kept in Samples.
    Kept,
    /// Deleted by the analyst.
    Deleted,
    /// Left in the VM's recording or snapshots: With the VM.
    WithVm,
    /// Copied into the sample record: In the sample record.
    InRecord,
}

impl Fate {
    fn as_str(self) -> &'static str {
        match self {
            Self::Kept => "kept",
            Self::Deleted => "deleted",
            Self::WithVm => "vm",
            Self::InRecord => "record",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [Self::Kept, Self::Deleted, Self::WithVm, Self::InRecord]
            .into_iter()
            .find(|fate| fate.as_str() == text)
    }
}

/// An artefact whose run was deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptArtifact {
    pub kind: ArtifactKind,
    pub vm_id: String,
    pub run_id: String,
    /// The file name it had in the run.
    pub name: String,
    pub hash: String,
    pub size: u64,
    pub fate: Fate,
    /// Where a kept file is now.
    pub stored: PathBuf,
    /// Why it was saved ("Core dump on exit", a rule's name).
    pub because: String,
    /// The process or time it belongs to.
    pub context: String,
    /// When the run was deleted.
    pub at_ms: u64,
}

/// A row to record.
#[derive(Clone, Debug)]
pub struct NewArtifact {
    pub kind: ArtifactKind,
    pub vm_id: String,
    pub run_id: String,
    pub name: String,
    pub hash: String,
    pub size: u64,
    pub fate: Fate,
    pub stored: PathBuf,
    pub because: String,
    pub context: String,
}

/// A snapshot or file a rule saved during a run, as the sidecar lists it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedItem {
    pub kind: SavedKind,
    /// The snapshot's name, or the file's name.
    pub name: String,
    /// A saved file's path, relative to the run's folder.
    #[serde(default)]
    pub path: String,
    /// The file's SHA-256; a snapshot's memory image hash when it has one.
    #[serde(default)]
    pub sha256: String,
    #[serde(default)]
    pub size: u64,
    /// The rule that saved it.
    #[serde(default)]
    pub rule: String,
    /// The process or time it belongs to.
    #[serde(default)]
    pub context: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedKind {
    Snapshot,
    File,
}

impl SavedItem {
    pub fn artifact_kind(&self) -> ArtifactKind {
        match self.kind {
            SavedKind::Snapshot => ArtifactKind::Snapshot,
            SavedKind::File => ArtifactKind::File,
        }
    }

    /// Why it was saved, as the list words it.
    pub fn because(&self) -> String {
        if self.rule.is_empty() {
            "Rule".to_owned()
        } else {
            format!("Rule: {}", self.rule)
        }
    }

    /// The saved file inside `run_dir`; `None` for a snapshot or a path that
    /// would leave the folder.
    pub fn file_in(&self, run_dir: &Path) -> Option<PathBuf> {
        if self.kind != SavedKind::File || self.path.is_empty() {
            return None;
        }
        let relative = Path::new(&self.path);
        relative
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
            .then(|| run_dir.join(relative))
    }
}

/// What a run's rules saved. A missing, oversized or unreadable sidecar
/// reads as nothing saved.
pub fn saved_items(run_dir: &Path) -> Vec<SavedItem> {
    let path = run_dir.join(SAVED_FILE);
    let Ok(meta) = fs::symlink_metadata(&path) else {
        return Vec::new();
    };
    if !meta.file_type().is_file() || meta.len() > SAVED_LIMIT {
        return Vec::new();
    }
    fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Add an item to the run's sidecar (what a rule action calls once it has
/// saved a snapshot or a file).
pub fn record_saved(run_dir: &Path, item: SavedItem) -> Result<(), String> {
    let mut items = saved_items(run_dir);
    items.retain(|known| !(known.kind == item.kind && known.name == item.name));
    items.push(item);
    crate::storage::atomic_json(&run_dir.join(SAVED_FILE), &items)
}

/// SHA-256 of an artefact: a file's bytes, or for a memory dump folder the
/// bytes of its `memory.elf`. `None` when there is nothing to read.
pub fn artifact_sha256(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    if meta.is_dir() {
        return super::file_sha256(&path.join("memory.elf"));
    }
    super::file_sha256(path)
}

/// The bytes of an artefact that its hash covers.
pub fn hashed_file(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.join("memory.elf")
    } else {
        path.to_path_buf()
    }
}

impl Library {
    /// The artefacts of deleted runs of a sample, newest deletion first.
    pub fn artifacts(&self, sha256: &str) -> Result<Vec<KeptArtifact>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT kind, vm_id, run_id, name, hash, size, fate, stored, because, context, at_ms
                 FROM artifact WHERE sha256=?1 ORDER BY at_ms DESC, id DESC",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([sha256.to_ascii_lowercase()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                    row.get::<_, i64>(10)?,
                ))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                Some(KeptArtifact {
                    kind: ArtifactKind::parse(&row.0)?,
                    vm_id: row.1,
                    run_id: row.2,
                    name: row.3,
                    hash: row.4,
                    size: row.5.max(0) as u64,
                    fate: Fate::parse(&row.6)?,
                    stored: PathBuf::from(row.7),
                    because: row.8,
                    context: row.9,
                    at_ms: row.10.max(0) as u64,
                })
            })
            .collect())
    }

    /// Record what became of an artefact of `sha256`'s run.
    pub(super) fn record_artifact(
        &self,
        sha256: &str,
        artifact: &NewArtifact,
        at_ms: u64,
    ) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT OR REPLACE INTO artifact(sha256, kind, vm_id, run_id, name, hash, size,
                    fate, stored, because, context, at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    sha256.to_ascii_lowercase(),
                    artifact.kind.as_str(),
                    artifact.vm_id,
                    artifact.run_id,
                    artifact.name,
                    artifact.hash,
                    artifact.size as i64,
                    artifact.fate.as_str(),
                    artifact.stored.display().to_string(),
                    artifact.because,
                    artifact.context,
                    at_ms as i64
                ],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The SHA-256 of an artefact, from the cache when the file is as big
    /// and as new as when it was hashed, else read and cached. `None` when
    /// it cannot be read.
    pub fn artifact_hash(&self, path: &Path) -> Option<String> {
        let file = hashed_file(path);
        let meta = fs::metadata(&file).ok()?;
        if !meta.is_file() {
            return None;
        }
        let size = meta.len() as i64;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_millis() as i64);
        let key = file.display().to_string();
        let cached: Option<String> = self
            .connection
            .query_row(
                "SELECT sha256 FROM file_hash WHERE path=?1 AND size=?2 AND mtime_ms=?3",
                params![key, size, mtime],
                |row| row.get(0),
            )
            .ok();
        if cached.is_some() {
            return cached;
        }
        let hash = super::file_sha256(&file)?;
        let _ = self.connection.execute(
            "INSERT OR REPLACE INTO file_hash(path, size, mtime_ms, sha256) VALUES (?1, ?2, ?3, ?4)",
            params![key, size, mtime, hash],
        );
        Some(hash)
    }

    /// The cached SHA-256 of an artefact, without reading the file.
    pub fn cached_artifact_hash(&self, path: &Path) -> Option<String> {
        let file = hashed_file(path);
        let meta = fs::metadata(&file).ok()?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |since| since.as_millis() as i64);
        self.connection
            .query_row(
                "SELECT sha256 FROM file_hash WHERE path=?1 AND size=?2 AND mtime_ms=?3",
                params![file.display().to_string(), meta.len() as i64, mtime],
                |row| row.get(0),
            )
            .ok()
    }

    /// The folder kept artefacts move into.
    pub fn artifacts_dir(&self) -> PathBuf {
        self.root.join("artefacts")
    }
}

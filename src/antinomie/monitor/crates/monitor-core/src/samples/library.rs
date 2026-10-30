// SPDX-License-Identifier: GPL-3.0-only
//! The sample library: every archive under `<data>/samples` and what is known
//! about it, in one SQLite database next to the archives.
//!
//! Identity is the SHA-256 of the bytes. The same bytes reaching the library
//! by two routes are one sample with two origins. Archives are AES zips with
//! the password `infected` (see [`super::archive`]); the database holds
//! names, descriptions, tags, origins, sends and custody events. The
//! database is the record of what the analyst did; the archives are the
//! bytes. A missing archive shows as missing, never as silently absent.
use super::chain::ChainedEvents;
use super::custody::{CustodyEvent, CustodySink};
use super::{SampleInfo, archive};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Layout version stored in `meta`; a newer database is refused. Layout 2
/// adds notes and the kept-artefact tables; a layout 1 database gets them
/// the first time it is opened, its other tables unchanged.
const SCHEMA_VERSION: i64 = 2;
/// The database file inside `<data>/samples`.
pub const DATABASE: &str = "library.sqlite";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sample(
    sha256 TEXT PRIMARY KEY,
    sha1 TEXT NOT NULL DEFAULT '',
    md5 TEXT NOT NULL DEFAULT '',
    tlsh TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    size INTEGER NOT NULL DEFAULT 0,
    file_type TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    family TEXT NOT NULL DEFAULT '',
    added_ms INTEGER NOT NULL,
    removed_ms INTEGER,
    info TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS origin(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL REFERENCES sample(sha256) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    vm_id TEXT NOT NULL DEFAULT '',
    vm_name TEXT NOT NULL DEFAULT '',
    run_id TEXT NOT NULL DEFAULT '',
    parent TEXT NOT NULL DEFAULT '',
    at_ms INTEGER NOT NULL,
    before_custody INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS origin_sample ON origin(sha256);
CREATE TABLE IF NOT EXISTS push(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL REFERENCES sample(sha256) ON DELETE CASCADE,
    vm_id TEXT NOT NULL DEFAULT '',
    vm_name TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    at_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS push_sample ON push(sha256);
CREATE TABLE IF NOT EXISTS tag(
    sha256 TEXT NOT NULL REFERENCES sample(sha256) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    value TEXT NOT NULL,
    color TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(sha256, kind, value)
);
CREATE TABLE IF NOT EXISTS event(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256 TEXT NOT NULL,
    at_ms INTEGER NOT NULL,
    by TEXT NOT NULL DEFAULT '',
    kind TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS event_sample ON event(sha256);
CREATE TABLE IF NOT EXISTS seen_run(
    sha256 TEXT NOT NULL REFERENCES sample(sha256) ON DELETE CASCADE,
    vm_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    vm_name TEXT NOT NULL DEFAULT '',
    started_ms INTEGER,
    exit TEXT NOT NULL DEFAULT '',
    directory TEXT NOT NULL DEFAULT '',
    PRIMARY KEY(sha256, vm_id, run_id)
);
";

/// How bytes reached the library.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OriginKind {
    /// MalwareBazaar or MalShare.
    Download,
    /// Added from this computer (Add file…, Add to Samples).
    #[default]
    Added,
    /// Sent into a VM without running.
    Uploaded,
    /// Archived before a run started the program.
    Run,
    /// Written, downloaded or executed by another sample's run.
    Dropped,
    /// Promoted by the analyst from a run's files or processes.
    Promoted,
    /// A record from before the library existed.
    Migrated,
    /// An archive found without a record.
    Found,
}

impl OriginKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Added => "added",
            Self::Uploaded => "uploaded",
            Self::Run => "run",
            Self::Dropped => "dropped",
            Self::Promoted => "promoted",
            Self::Migrated => "migrated",
            Self::Found => "found",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "download" => Self::Download,
            "added" => Self::Added,
            "uploaded" => Self::Uploaded,
            "run" => Self::Run,
            "dropped" => Self::Dropped,
            "promoted" => Self::Promoted,
            "migrated" => Self::Migrated,
            _ => Self::Found,
        }
    }

    /// The word the origin list shows.
    pub fn label(self) -> &'static str {
        match self {
            Self::Download => "Downloaded",
            Self::Added => "Added from this computer",
            Self::Uploaded => "Uploaded to a VM",
            Self::Run => "Run program",
            Self::Dropped => "Dropped by a run",
            Self::Promoted => "Added from a run",
            Self::Migrated => "Recorded before the library",
            Self::Found => "Found in the archive folder",
        }
    }
}

/// A route by which a sample reached the library, as the caller states it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewOrigin {
    pub kind: OriginKind,
    /// MalwareBazaar, MalShare, the menu the file came from.
    pub source: String,
    /// A URL, a note.
    pub detail: String,
    /// The file name in this route.
    pub name: String,
    /// The path in this route (host or guest).
    pub path: String,
    pub vm_id: String,
    pub vm_name: String,
    pub run_id: String,
    /// SHA-256 of the sample that wrote or fetched this one.
    pub parent: String,
}

/// A stored origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    pub id: i64,
    pub kind: OriginKind,
    pub source: String,
    pub detail: String,
    pub name: String,
    pub path: String,
    pub vm_id: String,
    pub vm_name: String,
    pub run_id: String,
    pub parent: String,
    pub at_ms: u64,
    /// Made from a record that predates the custody log.
    pub before_custody: bool,
}

/// The group a tag belongs to; each draws differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagKind {
    Verdict,
    Category,
    /// A MITRE ATT&CK ID and name, such as `T1053.003 Cron`.
    Technique,
    Custom,
}

impl TagKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Verdict => "verdict",
            Self::Category => "category",
            Self::Technique => "technique",
            Self::Custom => "custom",
        }
    }

    fn parse(text: &str) -> Self {
        match text {
            "verdict" => Self::Verdict,
            "category" => Self::Category,
            "technique" => Self::Technique,
            _ => Self::Custom,
        }
    }
}

/// The built-in verdict tags.
pub const VERDICTS: [&str; 4] = ["malicious", "suspicious", "benign", "unknown"];
/// The built-in malware categories.
pub const CATEGORIES: [&str; 10] = [
    "miner",
    "botnet",
    "backdoor",
    "rootkit",
    "ransomware",
    "dropper",
    "loader",
    "infostealer",
    "worm",
    "proxy",
];
/// The nine theme colours a custom tag can take.
pub const TAG_COLORS: [&str; 9] = [
    "grey", "red", "orange", "yellow", "green", "cyan", "blue", "purple", "pink",
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Tag {
    pub kind: TagKind,
    pub value: String,
    /// One of [`TAG_COLORS`] for a custom tag, empty otherwise.
    pub color: String,
}

impl Tag {
    pub fn new(kind: TagKind, value: impl Into<String>) -> Self {
        Self {
            kind,
            value: value.into(),
            color: String::new(),
        }
    }

    /// A tag value must be short, printable and free of line breaks.
    pub fn validate(&self) -> Result<(), String> {
        if self.value.trim().is_empty()
            || self.value.len() > 128
            || self.value.chars().any(char::is_control)
        {
            return Err("a tag is 1 to 128 characters without control characters".into());
        }
        match self.kind {
            TagKind::Verdict if !VERDICTS.contains(&self.value.as_str()) => {
                Err(format!("{:?} is not a verdict", self.value))
            }
            TagKind::Category if !CATEGORIES.contains(&self.value.as_str()) => {
                Err(format!("{:?} is not a malware category", self.value))
            }
            TagKind::Technique if !technique_id(&self.value) => {
                Err(format!("{:?} is not an ATT&CK technique", self.value))
            }
            TagKind::Custom
                if !self.color.is_empty() && !TAG_COLORS.contains(&self.color.as_str()) =>
            {
                Err(format!("{:?} is not a tag colour", self.color))
            }
            _ => Ok(()),
        }
    }
}

/// A technique tag starts with its ATT&CK id (`T1053` or `T1053.003`).
fn technique_id(value: &str) -> bool {
    let id = value.split_whitespace().next().unwrap_or_default();
    let mut parts = id.splitn(2, '.');
    let main = parts.next().unwrap_or_default();
    let sub = parts.next();
    main.len() == 5
        && main.starts_with('T')
        && main[1..].bytes().all(|b| b.is_ascii_digit())
        && sub.is_none_or(|sub| sub.len() == 3 && sub.bytes().all(|b| b.is_ascii_digit()))
}

/// One library entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SampleRecord {
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
    pub added_ms: u64,
    /// When the archive was removed; the record stays.
    pub removed_ms: Option<u64>,
    /// The source's own record (MalwareBazaar), empty for local files.
    pub info: SampleInfo,
}

/// A file name or path a sample went by, with where it was seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alias {
    pub name: String,
    pub path: String,
    /// The run or source that used it.
    pub seen: String,
}

/// A run of a library sample, as recorded when its summary was read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeenRun {
    pub sha256: String,
    pub vm_id: String,
    pub vm_name: String,
    pub run_id: String,
    pub started_ms: Option<u64>,
    /// The root's exit as the run list words it ("Exit 0", "Running").
    pub exit: String,
    /// The run's folder; may no longer exist.
    pub directory: String,
}

/// What the list shows of a sample's runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RunStats {
    pub count: usize,
    pub latest: Option<SeenRun>,
}

/// A custody event as listed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventRow {
    /// The entry's number in the sample's chain, from 1.
    pub seq: u64,
    pub at_ms: u64,
    pub by: String,
    pub event: CustodyEvent,
    /// Recorded before the custody log existed and brought in with it.
    pub before_chain: bool,
    /// The hash of the entry before this one (zeros for the first).
    pub prev: String,
    /// This entry's own hash.
    pub hash: String,
}

/// Open the database, creating and checking its layout.
pub(super) fn connect(path: &Path) -> Result<Connection, String> {
    let connection = Connection::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    connection
        .execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|e| e.to_string())?;
    Ok(connection)
}

pub(super) fn now_ms() -> u64 {
    super::unix_ms()
}

/// The library of one data folder. Cheap to open; open one per use.
pub struct Library {
    pub(super) root: PathBuf,
    pub(super) connection: Connection,
    custody: Arc<dyn CustodySink>,
}

impl std::fmt::Debug for Library {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Library").field("root", &self.root).finish()
    }
}

impl Library {
    /// Open (and on first use create) the library of `data_dir`, bringing in
    /// records made by earlier versions. Events go to the custody chains.
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let root = super::samples_dir(data_dir);
        let database = root.join(DATABASE);
        Self::open_with(data_dir, Arc::new(ChainedEvents::new(&database)))
    }

    /// [`Library::open`] with another custody sink.
    pub fn open_with(data_dir: &Path, custody: Arc<dyn CustodySink>) -> Result<Self, String> {
        let root = super::samples_dir(data_dir);
        crate::storage::private_dir(&root).map_err(|e| format!("{}: {e}", root.display()))?;
        let database = root.join(DATABASE);
        let fresh = !database.exists();
        let connection = connect(&database)?;
        if fresh {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        // One transaction: creating the tables one by one is a sync each.
        connection
            .execute_batch(&format!(
                "BEGIN IMMEDIATE;{SCHEMA}\
                 {}{}{}INSERT OR IGNORE INTO meta(key, value) VALUES('schema', '{SCHEMA_VERSION}');\
                 UPDATE meta SET value='{SCHEMA_VERSION}' WHERE key='schema' AND CAST(value AS INTEGER) < {SCHEMA_VERSION};\
                 COMMIT;",
                super::chain::SCHEMA,
                super::notes::SCHEMA,
                super::kept::SCHEMA
            ))
            .map_err(|e| e.to_string())?;
        let version: Option<i64> = connection
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |row| {
                row.get::<_, String>(0)
            })
            .optional()
            .map_err(|e| e.to_string())?
            .and_then(|text| text.parse().ok());
        match version {
            None => {}
            Some(found) if found > SCHEMA_VERSION => {
                return Err(format!(
                    "the sample library was made by a newer Antinomie (layout {found})"
                ));
            }
            Some(_) => {}
        }
        custody.prepare()?;
        let mut library = Self {
            root,
            connection,
            custody,
        };
        library.migrate_legacy()?;
        Ok(library)
    }

    /// Report an event; the change it describes is already saved.
    pub(super) fn note(&self, sha256: &str, by: &str, event: CustodyEvent) -> Result<(), String> {
        self.custody
            .record(sha256, by, now_ms(), &event)
            .map_err(|e| format!("saved, but its custody event was not recorded: {e}"))
    }

    /// [`Self::record_event`] at a given time, for what the library reads from a run.
    pub(super) fn record_at(
        &self,
        sha256: &str,
        by: &str,
        at_ms: u64,
        event: &CustodyEvent,
    ) -> Result<(), String> {
        self.custody.record(sha256, by, at_ms, event)
    }

    /// Add an entry to a sample's custody log for something that happened
    /// outside the library (a run, an analyst action). The event's own type
    /// decides what it can hold; see [`CustodyEvent`].
    pub fn record_event(&self, sha256: &str, by: &str, event: CustodyEvent) -> Result<(), String> {
        self.note(sha256, by, event)
    }

    pub fn contains(&self, sha256: &str) -> Result<bool, String> {
        self.connection
            .query_row(
                "SELECT 1 FROM sample WHERE sha256=?1 AND removed_ms IS NULL",
                [sha256.to_ascii_lowercase()],
                |_| Ok(()),
            )
            .optional()
            .map(|found| found.is_some())
            .map_err(|e| e.to_string())
    }

    /// Where the archive of a sample is (it may not exist).
    pub fn archive_path(&self, sha256: &str) -> Result<PathBuf, String> {
        archive::shard_path(&self.root, sha256)
    }

    pub fn get(&self, sha256: &str) -> Result<Option<SampleRecord>, String> {
        self.connection
            .query_row(
                &format!("{SELECT_SAMPLE} WHERE sha256=?1"),
                [sha256.to_ascii_lowercase()],
                read_sample,
            )
            .optional()
            .map_err(|e| e.to_string())
    }

    /// Every sample, newest first, removed ones included.
    pub fn list(&self) -> Result<Vec<SampleRecord>, String> {
        let mut statement = self
            .connection
            .prepare(&format!("{SELECT_SAMPLE} ORDER BY added_ms DESC, sha256"))
            .map_err(|e| e.to_string())?;
        statement
            .query_map([], read_sample)
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn origins(&self, sha256: &str) -> Result<Vec<Origin>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT id, kind, source, detail, name, path, vm_id, vm_name, run_id, parent,
                        at_ms, before_custody FROM origin WHERE sha256=?1 ORDER BY at_ms, id",
            )
            .map_err(|e| e.to_string())?;
        statement
            .query_map([sha256.to_ascii_lowercase()], |row| {
                Ok(Origin {
                    id: row.get(0)?,
                    kind: OriginKind::parse(&row.get::<_, String>(1)?),
                    source: row.get(2)?,
                    detail: row.get(3)?,
                    name: row.get(4)?,
                    path: row.get(5)?,
                    vm_id: row.get(6)?,
                    vm_name: row.get(7)?,
                    run_id: row.get(8)?,
                    parent: row.get(9)?,
                    at_ms: row.get::<_, i64>(10)? as u64,
                    before_custody: row.get::<_, i64>(11)? != 0,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    /// File names only, one row per name and path, with the run or source
    /// that used it. Process names are not file names and are not here.
    pub fn aliases(&self, sha256: &str) -> Result<Vec<Alias>, String> {
        let mut rows: Vec<Alias> = Vec::new();
        for origin in self.origins(sha256)? {
            if origin.name.is_empty() {
                continue;
            }
            let seen = if !origin.run_id.is_empty() {
                format!("run {}", origin.run_id)
            } else if !origin.source.is_empty() {
                origin.source.clone()
            } else {
                origin.kind.label().to_owned()
            };
            match rows
                .iter_mut()
                .find(|row| row.name == origin.name && row.path == origin.path)
            {
                Some(row) => {
                    if !row.seen.contains(&seen) {
                        row.seen = format!("{}, {seen}", row.seen);
                    }
                }
                None => rows.push(Alias {
                    name: origin.name,
                    path: origin.path,
                    seen,
                }),
            }
        }
        Ok(rows)
    }

    pub fn pushes(&self, sha256: &str) -> Result<Vec<super::Push>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT vm_id, vm_name, path, at_ms FROM push WHERE sha256=?1 ORDER BY at_ms, id",
            )
            .map_err(|e| e.to_string())?;
        statement
            .query_map([sha256.to_ascii_lowercase()], |row| {
                Ok(super::Push {
                    vm_id: row.get(0)?,
                    vm_name: row.get(1)?,
                    path: row.get(2)?,
                    at_ms: row.get::<_, i64>(3)? as u64,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    pub fn tags(&self, sha256: &str) -> Result<Vec<Tag>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT kind, value, color FROM tag WHERE sha256=?1")
            .map_err(|e| e.to_string())?;
        let mut tags: Vec<Tag> = statement
            .query_map([sha256.to_ascii_lowercase()], |row| {
                Ok(Tag {
                    kind: TagKind::parse(&row.get::<_, String>(0)?),
                    value: row.get(1)?,
                    color: row.get(2)?,
                })
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?;
        tags.sort();
        Ok(tags)
    }

    /// The events of one sample, oldest first.
    pub fn events(&self, sha256: &str) -> Result<Vec<EventRow>, String> {
        Ok(self
            .custody_entries(sha256)?
            .iter()
            .filter_map(super::chain::row_of)
            .collect())
    }

    /// Replace a sample's tags. Every tag must be valid and a custom tag
    /// without a colour takes the first of the palette.
    pub fn set_tags(&mut self, sha256: &str, tags: &[Tag]) -> Result<(), String> {
        let sha256 = sha256.to_ascii_lowercase();
        for tag in tags {
            tag.validate()?;
        }
        if !self.contains(&sha256)? {
            return Err("no such sample".into());
        }
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        transaction
            .execute("DELETE FROM tag WHERE sha256=?1", [&sha256])
            .map_err(|e| e.to_string())?;
        for tag in tags {
            let color = if tag.kind == TagKind::Custom && tag.color.is_empty() {
                TAG_COLORS[0]
            } else {
                tag.color.as_str()
            };
            transaction
                .execute(
                    "INSERT OR REPLACE INTO tag(sha256, kind, value, color) VALUES (?1, ?2, ?3, ?4)",
                    params![sha256, tag.kind.as_str(), tag.value.trim(), color],
                )
                .map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())?;
        self.note(
            &sha256,
            "analyst",
            CustodyEvent::Edited {
                what: "tags".into(),
            },
        )
    }

    /// Name and description, as the analyst edits them.
    pub fn set_text(&mut self, sha256: &str, name: &str, description: &str) -> Result<(), String> {
        if name.len() > 256
            || description.len() > 4096
            || name.chars().any(char::is_control)
            || description.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err("the name or description is too long or has control characters".into());
        }
        let sha256 = sha256.to_ascii_lowercase();
        let changed = self
            .connection
            .execute(
                "UPDATE sample SET name=?2, description=?3 WHERE sha256=?1",
                params![sha256, name.trim(), description.trim()],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("no such sample".into());
        }
        self.note(
            &sha256,
            "analyst",
            CustodyEvent::Edited {
                what: "name and description".into(),
            },
        )
    }

    /// The library sample a launch runs: a program the library sent into
    /// `vm_id` at `path`, or at the script path given as the first argument
    /// of an interpreter. `None` for any other program.
    pub fn identify_run(
        &self,
        vm_id: &str,
        path: &str,
        args: &[String],
    ) -> Result<Option<super::SampleRef>, String> {
        let candidates = std::iter::once(path).chain(args.first().map(String::as_str));
        for candidate in candidates.filter(|path| path.starts_with('/')) {
            let found = self
                .connection
                .query_row(
                    "SELECT s.sha256, s.name FROM push p JOIN sample s ON s.sha256 = p.sha256
                     WHERE p.vm_id=?1 AND p.path=?2 AND s.removed_ms IS NULL
                     ORDER BY p.at_ms DESC, p.id DESC LIMIT 1",
                    params![vm_id, candidate],
                    |row| {
                        Ok(super::SampleRef {
                            sha256: row.get(0)?,
                            name: row.get(1)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| e.to_string())?;
            if found.is_some() {
                return Ok(found);
            }
        }
        Ok(None)
    }

    /// Remember runs that executed library samples. A run seen for the first
    /// time adds a "Seen in a run" event; a run seen again only refreshes its
    /// start and exit. Runs of samples not in the library are skipped.
    /// Returns how many were new.
    pub fn index_runs(&mut self, runs: &[SeenRun]) -> Result<usize, String> {
        let mut added = Vec::new();
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        for run in runs {
            let sha256 = run.sha256.to_ascii_lowercase();
            let known: bool = transaction
                .query_row(
                    "SELECT 1 FROM sample WHERE sha256=?1",
                    [&sha256],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .is_some();
            if !known {
                continue;
            }
            let seen: bool = transaction
                .query_row(
                    "SELECT 1 FROM seen_run WHERE sha256=?1 AND vm_id=?2 AND run_id=?3",
                    params![sha256, run.vm_id, run.run_id],
                    |_| Ok(()),
                )
                .optional()
                .map_err(|e| e.to_string())?
                .is_some();
            transaction
                .execute(
                    "INSERT INTO seen_run(sha256, vm_id, run_id, vm_name, started_ms, exit, directory)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                     ON CONFLICT(sha256, vm_id, run_id) DO UPDATE SET
                        vm_name=excluded.vm_name, started_ms=excluded.started_ms,
                        exit=excluded.exit, directory=excluded.directory",
                    params![
                        sha256,
                        run.vm_id,
                        run.run_id,
                        run.vm_name,
                        run.started_ms.map(|ms| ms as i64),
                        run.exit,
                        run.directory
                    ],
                )
                .map_err(|e| e.to_string())?;
            if !seen {
                added.push((sha256, run.vm_name.clone(), run.run_id.clone()));
            }
        }
        transaction.commit().map_err(|e| e.to_string())?;
        let count = added.len();
        for (sha256, vm, run) in added {
            self.note(&sha256, "app", CustodyEvent::SeenInRun { vm, run })?;
        }
        // What the sample did in each run, from the digest Triage left.
        for run in runs {
            if self.contains(&run.sha256)? {
                self.note_run_activity(run)?;
            }
        }
        Ok(count)
    }

    /// The runs of one sample, newest first.
    pub fn runs_of(&self, sha256: &str) -> Result<Vec<SeenRun>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sha256, vm_id, run_id, vm_name, started_ms, exit, directory FROM seen_run
                 WHERE sha256=?1 ORDER BY started_ms DESC, run_id DESC",
            )
            .map_err(|e| e.to_string())?;
        statement
            .query_map([sha256.to_ascii_lowercase()], read_seen_run)
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())
    }

    /// Run count and latest run of every sample that has run.
    pub fn run_stats(&self) -> Result<HashMap<String, RunStats>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sha256, vm_id, run_id, vm_name, started_ms, exit, directory FROM seen_run
                 ORDER BY started_ms ASC, run_id ASC",
            )
            .map_err(|e| e.to_string())?;
        let mut stats: HashMap<String, RunStats> = HashMap::new();
        for run in statement
            .query_map([], read_seen_run)
            .map_err(|e| e.to_string())?
        {
            let run = run.map_err(|e| e.to_string())?;
            let entry = stats.entry(run.sha256.clone()).or_default();
            entry.count += 1;
            entry.latest = Some(run);
        }
        Ok(stats)
    }

    /// Every sample's tags in one read.
    pub fn all_tags(&self) -> Result<HashMap<String, Vec<Tag>>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT sha256, kind, value, color FROM tag")
            .map_err(|e| e.to_string())?;
        let mut all: HashMap<String, Vec<Tag>> = HashMap::new();
        for row in statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    Tag {
                        kind: TagKind::parse(&row.get::<_, String>(1)?),
                        value: row.get(2)?,
                        color: row.get(3)?,
                    },
                ))
            })
            .map_err(|e| e.to_string())?
        {
            let (sha256, tag) = row.map_err(|e| e.to_string())?;
            all.entry(sha256).or_default().push(tag);
        }
        for tags in all.values_mut() {
            tags.sort();
        }
        Ok(all)
    }

    /// Known parents and children of every sample, from the origins that
    /// name a parent sample (dropped or promoted from its runs).
    pub fn lineage_counts(&self) -> Result<HashMap<String, (usize, usize)>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT DISTINCT sha256, parent FROM origin
                 WHERE parent <> '' AND parent <> sha256",
            )
            .map_err(|e| e.to_string())?;
        let mut counts: HashMap<String, (usize, usize)> = HashMap::new();
        for pair in statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?
        {
            let (child, parent) = pair.map_err(|e| e.to_string())?;
            counts.entry(child).or_default().0 += 1;
            counts.entry(parent).or_default().1 += 1;
        }
        Ok(counts)
    }

    /// Note that a sample was sent into a VM.
    pub fn record_push(&mut self, sha256: &str, push: super::Push) -> Result<(), String> {
        let sha256 = sha256.to_ascii_lowercase();
        if self.get(&sha256)?.is_none() {
            return Err("no such sample".into());
        }
        self.connection
            .execute(
                "INSERT INTO push(sha256, vm_id, vm_name, path, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![sha256, push.vm_id, push.vm_name, push.path, now_ms() as i64],
            )
            .map_err(|e| e.to_string())?;
        self.note(
            &sha256,
            "app",
            CustodyEvent::Sent {
                vm: push.vm_name,
                path: push.path,
            },
        )
    }
}

fn read_seen_run(row: &rusqlite::Row<'_>) -> rusqlite::Result<SeenRun> {
    Ok(SeenRun {
        sha256: row.get(0)?,
        vm_id: row.get(1)?,
        run_id: row.get(2)?,
        vm_name: row.get(3)?,
        started_ms: row.get::<_, Option<i64>>(4)?.map(|ms| ms as u64),
        exit: row.get(5)?,
        directory: row.get(6)?,
    })
}

const SELECT_SAMPLE: &str = "SELECT sha256, sha1, md5, tlsh, name, description, size, file_type,
    arch, family, added_ms, removed_ms, info FROM sample";

fn read_sample(row: &rusqlite::Row<'_>) -> rusqlite::Result<SampleRecord> {
    Ok(SampleRecord {
        sha256: row.get(0)?,
        sha1: row.get(1)?,
        md5: row.get(2)?,
        tlsh: row.get(3)?,
        name: row.get(4)?,
        description: row.get(5)?,
        size: row.get::<_, i64>(6)? as u64,
        file_type: row.get(7)?,
        arch: row.get(8)?,
        family: row.get(9)?,
        added_ms: row.get::<_, i64>(10)? as u64,
        removed_ms: row.get::<_, Option<i64>>(11)?.map(|ms| ms as u64),
        info: serde_json::from_str(&row.get::<_, String>(12)?).unwrap_or_default(),
    })
}

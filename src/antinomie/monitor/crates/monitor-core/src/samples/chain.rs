// SPDX-License-Identifier: GPL-3.0-only
//! The custody log in the library database: the sink that appends to it and
//! the library's way to read, check, migrate and purge it.
//!
//! `custody_entry` holds every sample's chain, `custody_index` the library
//! index chain (see [`super::chain_check`] for the rules). Appending an entry
//! and its index record is one transaction, so two writers cannot both extend
//! the same head. Nothing here edits or deletes an entry: a correction is a
//! new entry. The only deletion is [`Library::purge`], which the index
//! records first.
use super::{
    chain_check::{
        ChainCheck, Entry, IndexCheck, IndexRecord, ZERO, check_chain, check_index, heads_of,
    },
    custody::{CustodyEvent, CustodySink},
    library::{EventRow, Library, connect},
};
use rusqlite::{Connection, Transaction, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

pub(super) const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS custody_entry(
    sha256 TEXT NOT NULL,
    seq INTEGER NOT NULL,
    at_ms INTEGER NOT NULL,
    by TEXT NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    before_chain INTEGER NOT NULL DEFAULT 0,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL,
    PRIMARY KEY(sha256, seq)
);
CREATE TABLE IF NOT EXISTS custody_index(
    seq INTEGER PRIMARY KEY,
    at_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    entry_seq INTEGER NOT NULL,
    entry_hash TEXT NOT NULL,
    prev TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS custody_index_sample ON custody_index(sha256);
";

/// `meta` key set once the plain events of earlier builds are in the chain.
const MIGRATED: &str = "custody_migrated";

/// The sink the library opens with: every event is appended to the sample's
/// chain and to the library index chain.
pub struct ChainedEvents {
    database: PathBuf,
}

impl ChainedEvents {
    pub fn new(database: &Path) -> Self {
        Self {
            database: database.to_path_buf(),
        }
    }
}

/// Append one entry and its index record; returns the entry.
fn append(
    transaction: &Transaction,
    sha256: &str,
    by: &str,
    at_ms: u64,
    kind: &str,
    detail: &str,
    before_chain: bool,
) -> Result<Entry, String> {
    let (seq, prev): (i64, String) = transaction
        .query_row(
            "SELECT seq, hash FROM custody_entry WHERE sha256=?1 ORDER BY seq DESC LIMIT 1",
            [sha256],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok((0, ZERO.to_owned())),
            other => Err(other),
        })
        .map_err(|e| e.to_string())?;
    let mut entry = Entry {
        seq: seq as u64 + 1,
        at_ms,
        by: by.into(),
        kind: kind.into(),
        detail: detail.into(),
        before_chain,
        prev,
        hash: String::new(),
    };
    entry.hash = super::chain_check::entry_hash(sha256, &entry);
    transaction
        .execute(
            "INSERT INTO custody_entry(sha256, seq, at_ms, by, kind, detail, before_chain, prev, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                sha256,
                entry.seq as i64,
                at_ms as i64,
                by,
                kind,
                detail,
                before_chain,
                entry.prev,
                entry.hash
            ],
        )
        .map_err(|e| e.to_string())?;
    append_index(transaction, "head", sha256, entry.seq, &entry.hash)?;
    Ok(entry)
}

fn append_index(
    transaction: &Transaction,
    kind: &str,
    sha256: &str,
    entry_seq: u64,
    entry_hash: &str,
) -> Result<(), String> {
    let (seq, prev): (i64, String) = transaction
        .query_row(
            "SELECT seq, hash FROM custody_index ORDER BY seq DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok((0, ZERO.to_owned())),
            other => Err(other),
        })
        .map_err(|e| e.to_string())?;
    let mut record = IndexRecord {
        seq: seq as u64 + 1,
        at_ms: super::unix_ms(),
        kind: kind.into(),
        sha256: sha256.into(),
        entry_seq,
        entry_hash: entry_hash.into(),
        prev,
        hash: String::new(),
    };
    record.hash = super::chain_check::index_hash(&record);
    transaction
        .execute(
            "INSERT INTO custody_index(seq, at_ms, kind, sha256, entry_seq, entry_hash, prev, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.seq as i64,
                record.at_ms as i64,
                record.kind,
                record.sha256,
                record.entry_seq as i64,
                record.entry_hash,
                record.prev,
                record.hash
            ],
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

impl CustodySink for ChainedEvents {
    fn record(
        &self,
        sha256: &str,
        by: &str,
        at_ms: u64,
        event: &CustodyEvent,
    ) -> Result<(), String> {
        let detail = event.stored()?;
        let mut connection = connect(&self.database)?;
        let transaction = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| format!("custody log: {e}"))?;
        append(
            &transaction,
            &sha256.to_ascii_lowercase(),
            by,
            at_ms,
            event.key(),
            &detail,
            false,
        )
        .map_err(|e| format!("custody log: {e}"))?;
        transaction
            .commit()
            .map_err(|e| format!("custody log: {e}"))
    }

    fn prepare(&self) -> Result<(), String> {
        let mut connection = connect(&self.database)?;
        migrate_plain(&mut connection)
    }
}

/// Bring the plain events of earlier builds into the chain, once. The plain
/// rows stay where they are; the entries are marked as recorded before the
/// custody log.
fn migrate_plain(connection: &mut Connection) -> Result<(), String> {
    let transaction = connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let done: bool = transaction
        .query_row("SELECT 1 FROM meta WHERE key=?1", [MIGRATED], |_| Ok(()))
        .is_ok();
    if done {
        return Ok(());
    }
    let rows: Vec<(String, i64, String, String)> = {
        let mut statement = transaction
            .prepare("SELECT sha256, at_ms, by, detail FROM event ORDER BY id")
            .map_err(|e| e.to_string())?;
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?
    };
    for (sha256, at_ms, by, detail) in rows {
        // A row this build cannot read is left in the plain table.
        let Ok(event) = serde_json::from_str::<CustodyEvent>(&detail) else {
            continue;
        };
        append(
            &transaction,
            &sha256,
            &by,
            at_ms as u64,
            event.key(),
            &event.stored()?,
            true,
        )?;
    }
    transaction
        .execute("INSERT INTO meta(key, value) VALUES(?1, '1')", [MIGRATED])
        .map_err(|e| e.to_string())?;
    transaction.commit().map_err(|e| e.to_string())
}

/// What a check of the whole library found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LibraryCheck {
    pub index: IndexCheck,
    /// Every sample that has a log, by SHA-256.
    pub samples: BTreeMap<String, ChainCheck>,
}

impl LibraryCheck {
    /// The samples whose log did not verify.
    pub fn broken(&self) -> Vec<&str> {
        self.samples
            .iter()
            .filter(|(_, check)| !check.ok())
            .map(|(sha256, _)| sha256.as_str())
            .collect()
    }

    pub fn ok(&self) -> bool {
        self.index.problem.is_none() && self.samples.values().all(ChainCheck::ok)
    }

    /// One line for the page's notice.
    pub fn summary(&self) -> String {
        let bad = self.broken().len();
        match (&self.index.problem, bad) {
            (None, 0) => format!("checked {} custody logs: all verified", self.samples.len()),
            (Some(problem), _) => format!("the library index chain is broken: {}", problem.text),
            (None, bad) => format!(
                "{bad} of {} custody logs did not verify",
                self.samples.len()
            ),
        }
    }
}

/// A custody entry of any sample, for the global view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalRow {
    pub sha256: String,
    /// The sample's name, or empty after a purge.
    pub name: String,
    pub row: EventRow,
}

impl GlobalRow {
    /// The row has `needle` (lower case; empty matches all) in the sample's
    /// name or SHA-256, the actor, the event name or its detail.
    pub fn matches(&self, needle: &str) -> bool {
        needle.is_empty()
            || [
                self.name.as_str(),
                self.sha256.as_str(),
                self.row.by.as_str(),
                self.row.event.label(),
                &self.row.event.detail(),
            ]
            .iter()
            .any(|text| text.to_lowercase().contains(needle))
    }
}

/// What the global view asks for.
#[derive(Clone, Debug, Default)]
pub struct CustodyQuery {
    /// Event kind keys to show; empty shows every kind.
    pub kinds: BTreeSet<String>,
    /// Text in the sample name, SHA-256, actor or detail; empty matches all.
    pub text: String,
    /// The most rows returned, newest first (0 means 5000).
    pub limit: usize,
}

fn read_entries(
    connection: &Connection,
    filter: &str,
    args: &[&dyn rusqlite::ToSql],
) -> Result<Vec<(String, Entry)>, String> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT sha256, seq, at_ms, by, kind, detail, before_chain, prev, hash
             FROM custody_entry {filter}"
        ))
        .map_err(|e| e.to_string())?;
    statement
        .query_map(args, |row| {
            Ok((
                row.get::<_, String>(0)?,
                Entry {
                    seq: row.get::<_, i64>(1)? as u64,
                    at_ms: row.get::<_, i64>(2)? as u64,
                    by: row.get(3)?,
                    kind: row.get(4)?,
                    detail: row.get(5)?,
                    before_chain: row.get(6)?,
                    prev: row.get(7)?,
                    hash: row.get(8)?,
                },
            ))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())
}

fn read_index(connection: &Connection) -> Result<Vec<IndexRecord>, String> {
    let mut statement = connection
        .prepare(
            "SELECT seq, at_ms, kind, sha256, entry_seq, entry_hash, prev, hash
             FROM custody_index ORDER BY seq",
        )
        .map_err(|e| e.to_string())?;
    statement
        .query_map([], |row| {
            Ok(IndexRecord {
                seq: row.get::<_, i64>(0)? as u64,
                at_ms: row.get::<_, i64>(1)? as u64,
                kind: row.get(2)?,
                sha256: row.get(3)?,
                entry_seq: row.get::<_, i64>(4)? as u64,
                entry_hash: row.get(5)?,
                prev: row.get(6)?,
                hash: row.get(7)?,
            })
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())
}

pub(super) fn row_of(entry: &Entry) -> Option<EventRow> {
    let event: CustodyEvent = serde_json::from_str(&entry.detail).ok()?;
    Some(EventRow {
        seq: entry.seq,
        at_ms: entry.at_ms,
        by: entry.by.clone(),
        event,
        before_chain: entry.before_chain,
        prev: entry.prev.clone(),
        hash: entry.hash.clone(),
    })
}

impl Library {
    /// A sample's entries, oldest first.
    pub fn custody_entries(&self, sha256: &str) -> Result<Vec<Entry>, String> {
        Ok(read_entries(
            &self.connection,
            "WHERE sha256=?1 ORDER BY seq",
            &[&sha256.to_ascii_lowercase()],
        )?
        .into_iter()
        .map(|(_, entry)| entry)
        .collect())
    }

    /// The library index chain.
    pub fn custody_index(&self) -> Result<Vec<IndexRecord>, String> {
        read_index(&self.connection)
    }

    /// Check one sample's chain against the library index.
    pub fn custody_check(&self, sha256: &str) -> Result<ChainCheck, String> {
        let sha256 = sha256.to_ascii_lowercase();
        let entries = self.custody_entries(&sha256)?;
        let index = self.custody_index()?;
        Ok(check_chain(&sha256, &entries, &heads_of(&sha256, &index)))
    }

    /// Check the library index chain and every sample's chain.
    pub fn custody_check_all(&self) -> Result<LibraryCheck, String> {
        let index = self.custody_index()?;
        let mut chains: BTreeMap<String, Vec<Entry>> = BTreeMap::new();
        for (sha256, entry) in read_entries(&self.connection, "ORDER BY sha256, seq", &[])? {
            chains.entry(sha256).or_default().push(entry);
        }
        // A sample whose log was removed still has index records.
        for record in index.iter().filter(|record| record.kind == "head") {
            chains.entry(record.sha256.clone()).or_default();
        }
        let samples = chains
            .into_iter()
            .filter_map(|(sha256, entries)| {
                let heads = heads_of(&sha256, &index);
                // Purged and not seen again: nothing to check.
                (!(entries.is_empty() && heads.is_empty()))
                    .then(|| (sha256.clone(), check_chain(&sha256, &entries, &heads)))
            })
            .collect();
        Ok(LibraryCheck {
            index: check_index(&index),
            samples,
        })
    }

    /// The library index chain, checked.
    pub fn custody_index_check(&self) -> Result<IndexCheck, String> {
        Ok(check_index(&self.custody_index()?))
    }

    /// Every sample's entries, newest first, for the global view.
    pub fn custody_log(&self, query: &CustodyQuery) -> Result<Vec<GlobalRow>, String> {
        let mut filter = String::from("WHERE 1=1");
        let mut args: Vec<String> = Vec::new();
        if !query.kinds.is_empty() {
            filter.push_str(" AND kind IN (");
            for (at, kind) in query.kinds.iter().enumerate() {
                if at > 0 {
                    filter.push(',');
                }
                args.push(kind.clone());
                filter.push_str(&format!("?{}", args.len()));
            }
            filter.push(')');
        }
        filter.push_str(" ORDER BY at_ms DESC, sha256, seq DESC");
        let params: Vec<&dyn rusqlite::ToSql> =
            args.iter().map(|arg| arg as &dyn rusqlite::ToSql).collect();
        let names: BTreeMap<String, String> = self
            .list()?
            .into_iter()
            .map(|record| (record.sha256, record.name))
            .collect();
        let needle = query.text.trim().to_lowercase();
        let limit = if query.limit == 0 { 5000 } else { query.limit };
        let mut rows = Vec::new();
        for (sha256, entry) in read_entries(&self.connection, &filter, &params)? {
            let Some(row) = row_of(&entry) else { continue };
            let name = names.get(&sha256).cloned().unwrap_or_default();
            let found = GlobalRow { sha256, name, row };
            if !found.matches(&needle) {
                continue;
            }
            rows.push(found);
            if rows.len() >= limit {
                break;
            }
        }
        Ok(rows)
    }

    /// Delete a sample for good: its archive, its record and its log. The
    /// library index records the purge first (with the head the log had), so
    /// the missing log is accounted for. [`Library::remove`] is the usual,
    /// lighter action.
    pub fn purge(&mut self, sha256: &str) -> Result<(), String> {
        let sha256 = sha256.to_ascii_lowercase();
        let archive = self.archive_path(&sha256)?;
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|e| e.to_string())?;
        let (seq, hash): (i64, String) = transaction
            .query_row(
                "SELECT seq, hash FROM custody_entry WHERE sha256=?1 ORDER BY seq DESC LIMIT 1",
                [&sha256],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap_or((0, ZERO.to_owned()));
        append_index(&transaction, "purge", &sha256, seq as u64, &hash)?;
        for table in ["custody_entry", "event", "sample"] {
            transaction
                .execute(&format!("DELETE FROM {table} WHERE sha256=?1"), [&sha256])
                .map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())?;
        if archive.is_file() {
            std::fs::remove_file(&archive)
                .map_err(|e| format!("purged, but {}: {e}", archive.display()))?;
        }
        Ok(())
    }
}

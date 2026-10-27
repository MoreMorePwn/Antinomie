// SPDX-License-Identifier: GPL-3.0-only
//! What happens to a sample, as events a custody log can record.
//!
//! The library reports every change to a sample through a [`CustodySink`].
//! The default sink, [`PlainEvents`], keeps them as plain rows in the library
//! database, which the Samples window lists. It does not chain or sign them:
//! the custody log card replaces the sink with a hash chain per sample and a
//! library index chain without changing any caller.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One thing that happened to a sample.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CustodyEvent {
    /// The archive was written: where the bytes came from.
    Added { origin: String },
    /// The same bytes arrived by another route.
    OriginAdded { origin: String },
    /// The archive was read back and its SHA-256 compared.
    Verified { ok: bool, detail: String },
    /// The sample was sent into a VM.
    Sent { vm: String, path: String },
    /// A run started the sample.
    SeenInRun { vm: String, run: String },
    /// Tags, name or description changed.
    Edited { what: String },
    /// The archive was deleted; the record stays.
    Removed,
    /// The analyst asked for the file that was added to be deleted after the
    /// archive was read back and matched.
    OriginalDeleted { path: String },
    /// A record made before the custody log existed was brought in.
    Migrated { from: String },
}

impl CustodyEvent {
    /// The short name the list shows.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Added { .. } => "Added",
            Self::OriginAdded { .. } => "Origin added",
            Self::Verified { .. } => "Verified",
            Self::Sent { .. } => "Sent into VM",
            Self::SeenInRun { .. } => "Seen in a run",
            Self::Edited { .. } => "Edited",
            Self::Removed => "Removed",
            Self::OriginalDeleted { .. } => "Original deleted",
            Self::Migrated { .. } => "Migrated",
        }
    }

    /// What the list shows beside the name.
    pub fn detail(&self) -> String {
        match self {
            Self::Added { origin } | Self::OriginAdded { origin } => origin.clone(),
            Self::Verified { ok, detail } => {
                if *ok {
                    "SHA-256 matches".into()
                } else {
                    detail.clone()
                }
            }
            Self::Sent { vm, path } => format!("{vm}: {path}"),
            Self::SeenInRun { vm, run } => format!("{vm}, run {run}"),
            Self::Edited { what } => what.clone(),
            Self::Removed => String::new(),
            Self::OriginalDeleted { path } => path.clone(),
            Self::Migrated { from } => format!("recorded before the custody log ({from})"),
        }
    }
}

/// Where the library reports events. An implementation must not call back
/// into the library from `record`.
pub trait CustodySink: Send + Sync {
    /// Note `event` for the sample with this SHA-256, made by `by` (the app,
    /// or the analyst). A failure is reported to the caller, which decides
    /// whether the change it made stands.
    fn record(
        &self,
        sha256: &str,
        by: &str,
        at_ms: u64,
        event: &CustodyEvent,
    ) -> Result<(), String>;
}

/// The sink that keeps no custody: events are dropped. For tests.
pub struct NoCustody;

impl CustodySink for NoCustody {
    fn record(&self, _: &str, _: &str, _: u64, _: &CustodyEvent) -> Result<(), String> {
        Ok(())
    }
}

/// The default sink: one row per event in the library database, unchained.
pub struct PlainEvents {
    database: PathBuf,
}

impl PlainEvents {
    pub fn new(database: &Path) -> Self {
        Self {
            database: database.to_path_buf(),
        }
    }
}

impl CustodySink for PlainEvents {
    fn record(
        &self,
        sha256: &str,
        by: &str,
        at_ms: u64,
        event: &CustodyEvent,
    ) -> Result<(), String> {
        let connection = super::library::connect(&self.database)?;
        connection
            .execute(
                "INSERT INTO event(sha256, at_ms, by, kind, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    sha256,
                    at_ms as i64,
                    by,
                    event.label(),
                    serde_json::to_string(event).map_err(|e| e.to_string())?
                ],
            )
            .map_err(|e| format!("custody event: {e}"))?;
        Ok(())
    }
}

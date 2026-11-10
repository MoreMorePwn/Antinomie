// SPDX-License-Identifier: GPL-3.0-only
//! MalwareBazaar's record for a sample imported from a file, looked up by its
//! hash. Only for a user who turned the lookup on (Settings > Privacy) and
//! set their own abuse.ch key (Tools > API keys); the one thing sent is the
//! SHA-256 of the sample. The record's signature then counts as a family
//! candidate, shown with "looked up by hash".
use super::{Library, SampleInfo, bazaar::recorded_info};
use crate::samples::custody::CustodyEvent;
use rusqlite::params;
use std::path::Path;
use std::sync::atomic::AtomicBool;

/// What [`lookup_imported`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The lookup is off: nothing was sent.
    Off,
    /// The lookup is on but no abuse.ch key is set: nothing was sent.
    NoKey,
    /// The sample already has a record (a download, or an earlier lookup).
    Known,
    /// MalwareBazaar does not list the sample, or lists no signature or tag.
    NotListed,
    /// The record was found and kept with the sample.
    Recorded {
        signature: Option<String>,
        tags: usize,
    },
}

impl Lookup {
    /// One line for a notice; `None` when there is nothing to tell.
    pub fn notice(&self) -> Option<String> {
        match self {
            Lookup::Off | Lookup::Known => None,
            Lookup::NoKey => Some(
                "MalwareBazaar lookup is on but no abuse.ch key is set (Tools > API keys)".into(),
            ),
            Lookup::NotListed => Some("MalwareBazaar does not know this file".into()),
            Lookup::Recorded {
                signature: Some(name),
                ..
            } => Some(format!("MalwareBazaar names it {name}")),
            Lookup::Recorded { tags, .. } => {
                Some(format!("MalwareBazaar lists {tags} tags for it"))
            }
        }
    }
}

impl Library {
    /// Keep a looked-up record as the sample's own. The family column takes
    /// the signature only when it is empty; the custody log says where the
    /// record came from.
    pub fn record_lookup(&mut self, sha256: &str, mut info: SampleInfo) -> Result<(), String> {
        let sha256 = sha256.to_ascii_lowercase();
        info.looked_up = true;
        let json = serde_json::to_string(&info).map_err(|e| e.to_string())?;
        let changed = self
            .connection
            .execute(
                "UPDATE sample SET info=?2, family=CASE WHEN family='' THEN ?3 ELSE family END
                 WHERE sha256=?1",
                params![sha256, json, info.signature.clone().unwrap_or_default()],
            )
            .map_err(|e| e.to_string())?;
        if changed == 0 {
            return Err("no such sample".into());
        }
        let by = self.actor();
        self.note(
            &sha256,
            &by,
            CustodyEvent::Edited {
                what: "MalwareBazaar record (looked up by hash)".into(),
            },
        )
    }
}

/// Look up `sha256` at MalwareBazaar and keep its record, for a sample added
/// from a file. `allowed` is the user's opt-in; with it off, or with no key,
/// nothing is sent. A sample that already has a signature or tags is left alone.
pub fn lookup_imported(
    data_dir: &Path,
    curl: &Path,
    key: &str,
    allowed: bool,
    sha256: &str,
    cancel: &AtomicBool,
) -> Result<Lookup, String> {
    if !allowed {
        return Ok(Lookup::Off);
    }
    if key.trim().is_empty() {
        return Ok(Lookup::NoKey);
    }
    let sha256 = sha256.trim().to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("not a SHA-256".into());
    }
    if recorded_info(data_dir, &sha256).is_some() {
        return Ok(Lookup::Known);
    }
    let found = super::search(curl, key, &super::Query::Hash(sha256.clone()), 1, cancel)?;
    let Some(info) = found
        .into_iter()
        .find(|info| info.sha256_hash.eq_ignore_ascii_case(&sha256))
        .filter(|info| info.signature.is_some() || !info.tags.is_empty())
    else {
        return Ok(Lookup::NotListed);
    };
    let result = Lookup::Recorded {
        signature: info.signature.clone(),
        tags: info.tags.len(),
    };
    Library::open(data_dir)?.record_lookup(&sha256, info)?;
    Ok(result)
}

#[cfg(test)]
#[path = "lookup_tests.rs"]
mod tests;

// SPDX-License-Identifier: GPL-3.0-only
//! Bringing in what earlier versions kept: `samples/<sha256>.zip` with a
//! `<sha256>.json` record (Tools › Malware samples), and archives that lost
//! their record.
//!
//! The migration is idempotent and loses nothing. Each step is safe to
//! repeat: the database rows are inserted once, the archive is moved (a
//! rename within the folder, no copy) and the record is moved to
//! `samples/legacy/`, which keeps the old JSON. The entries are marked
//! "recorded before the custody log". A record whose archive is missing is
//! left where it is.
use super::{
    SampleInfo, StoredSample,
    custody::CustodyEvent,
    intake::NewSample,
    is_sha256,
    library::{Library, NewOrigin, OriginKind, now_ms},
};
use rusqlite::params;
use std::{fs, path::PathBuf};

/// The folder that keeps the legacy records after they were migrated.
pub const LEGACY_DIR: &str = "legacy";

impl Library {
    /// Bring in records of the old layout; returns how many samples were new.
    pub(super) fn migrate_legacy(&mut self) -> Result<usize, String> {
        let mut legacy: Vec<(PathBuf, String)> = fs::read_dir(&self.root)
            .map_err(|e| format!("{}: {e}", self.root.display()))?
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                let stem = path.file_stem()?.to_str()?.to_owned();
                (path.extension()? == "json" && is_sha256(&stem) && path.is_file())
                    .then_some((path, stem.to_ascii_lowercase()))
            })
            .collect();
        legacy.sort();
        let mut brought = 0;
        for (record_path, sha256) in legacy {
            let old_archive = self.root.join(format!("{sha256}.zip"));
            let new_archive = self.archive_path(&sha256)?;
            if !old_archive.is_file() && !new_archive.is_file() {
                continue;
            }
            let record: StoredSample = match fs::read(&record_path)
                .map_err(|e| e.to_string())
                .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
            {
                Ok(record) => record,
                // Not a record of ours: leave it alone.
                Err(_) => continue,
            };
            if !record.info.sha256_hash.is_empty()
                && !record.info.sha256_hash.eq_ignore_ascii_case(&sha256)
            {
                continue;
            }
            if self.insert_migrated(&sha256, &record)? {
                brought += 1;
            }
            if old_archive.is_file() {
                if let Some(dir) = new_archive.parent() {
                    crate::storage::private_dir(dir).map_err(|e| e.to_string())?;
                }
                if new_archive.exists() {
                    // Both exist (an interrupted move): the sharded one stands.
                    fs::remove_file(&old_archive).map_err(|e| e.to_string())?;
                } else {
                    fs::rename(&old_archive, &new_archive)
                        .map_err(|e| format!("{}: {e}", old_archive.display()))?;
                }
            }
            let kept = self.root.join(LEGACY_DIR);
            crate::storage::private_dir(&kept).map_err(|e| e.to_string())?;
            let name = record_path.file_name().ok_or("record has no name")?;
            fs::rename(&record_path, kept.join(name))
                .map_err(|e| format!("{}: {e}", record_path.display()))?;
        }
        Ok(brought)
    }

    /// Insert the rows of one legacy record; false when it was inserted
    /// before (an interrupted migration run again).
    pub(super) fn insert_migrated(
        &mut self,
        sha256: &str,
        record: &StoredSample,
    ) -> Result<bool, String> {
        let info: &SampleInfo = &record.info;
        let at = if record.downloaded_ms == 0 {
            now_ms()
        } else {
            record.downloaded_ms
        } as i64;
        let transaction = self.connection.transaction().map_err(|e| e.to_string())?;
        let inserted = transaction
            .execute(
                "INSERT OR IGNORE INTO sample(sha256, sha1, md5, name, size, file_type, arch,
                    family, added_ms, info) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    sha256,
                    info.sha1_hash,
                    info.md5_hash,
                    info.file_name,
                    info.file_size as i64,
                    info.file_type,
                    info.file_arch.clone().unwrap_or_default(),
                    info.signature.clone().unwrap_or_default(),
                    at,
                    serde_json::to_string(info).map_err(|e| e.to_string())?,
                ],
            )
            .map_err(|e| e.to_string())?;
        if inserted == 0 {
            return Ok(false);
        }
        transaction
            .execute(
                "INSERT INTO origin(sha256, kind, source, name, at_ms, before_custody)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1)",
                params![
                    sha256,
                    OriginKind::Download.as_str(),
                    record.source,
                    info.file_name,
                    at
                ],
            )
            .map_err(|e| e.to_string())?;
        for push in &record.pushes {
            transaction
                .execute(
                    "INSERT INTO push(sha256, vm_id, vm_name, path, at_ms) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![sha256, push.vm_id, push.vm_name, push.path, push.at_ms as i64],
                )
                .map_err(|e| e.to_string())?;
        }
        transaction.commit().map_err(|e| e.to_string())?;
        self.note(
            sha256,
            "app",
            CustodyEvent::Migrated {
                from: format!("Tools › Malware samples, {}", record.source),
            },
        )?;
        Ok(true)
    }

    /// Bring in archives that sit in the folder without a record (a lost or
    /// damaged database): each is decrypted in memory, checked against its
    /// name and recorded as `Found`.
    pub(super) fn adopt_unrecorded(&mut self) -> Result<usize, String> {
        let mut found = Vec::new();
        for shard in fs::read_dir(&self.root)
            .map_err(|e| e.to_string())?
            .flatten()
            .filter(|entry| {
                entry.file_name().len() == 2 && entry.file_type().is_ok_and(|kind| kind.is_dir())
            })
        {
            for file in fs::read_dir(shard.path()).into_iter().flatten().flatten() {
                let path = file.path();
                let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
                    continue;
                };
                if path.extension().is_some_and(|ext| ext == "zip") && is_sha256(stem) {
                    found.push(stem.to_ascii_lowercase());
                }
            }
        }
        let mut adopted = 0;
        for sha256 in found {
            if self.get(&sha256)?.is_some() {
                continue;
            }
            // A name that does not match its bytes is not adopted: Verify
            // reports it through the record it does not have.
            let Ok(bytes) = super::open_sample(&self.archive_path(&sha256)?, &sha256) else {
                continue;
            };
            self.add_bytes(
                &bytes,
                NewSample {
                    origin: NewOrigin {
                        kind: OriginKind::Found,
                        ..NewOrigin::default()
                    },
                    ..NewSample::default()
                },
            )?;
            adopted += 1;
        }
        Ok(adopted)
    }
}

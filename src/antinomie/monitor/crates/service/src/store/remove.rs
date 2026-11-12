// SPDX-License-Identifier: GPL-3.0-only
//! Removing finished jobs (`job.delete`, retention; card P4-3): the rows of
//! the job, its events and artifacts, and its folder under `jobs/`. Only a
//! job that has ended can go, and nothing outside its own folder is touched.

use super::{R, Store, db, internal, lifecycle::current};
use crate::api::{
    error::{ApiError, ErrorCode},
    ids::JobId,
};
use std::path::Path;

/// What a job removal freed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// Bytes of the job's folder.
    pub bytes: u64,
}

/// Bytes of the regular files below `path`, links not followed.
pub fn folder_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut pending = vec![path.to_path_buf()];
    let mut seen = 0usize;
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            seen += 1;
            if seen > 1_000_000 {
                return total;
            }
            let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                pending.push(entry.path());
            } else if meta.is_file() {
                total += meta.len();
            }
        }
    }
    total
}

impl Store {
    /// The jobs that have ended, oldest first: `(id, finished_ms)`. Never a
    /// queued, running or cancelling job.
    pub fn finished_jobs(&self) -> R<Vec<(JobId, u64)>> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT id, finished_ms FROM jobs
                 WHERE outcome IS NOT NULL AND finished_ms IS NOT NULL
                 ORDER BY finished_ms ASC, id ASC",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, finished) = row.map_err(db)?;
            out.push((JobId::try_from(id).map_err(internal)?, finished));
        }
        Ok(out)
    }

    /// Remove an ended job: its rows and events in one transaction, then its
    /// folder (a real folder inside `jobs/`, never through a link). A job
    /// that has not ended is a `conflict` and nothing changes.
    pub fn delete_job(&self, id: &JobId) -> R<Removed> {
        if self.read_only_store() {
            return Err(internal("this store is open for reading only"));
        }
        self.write(|tx| {
            let cur = current(tx, id)?;
            if !cur.state.is_terminal() {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    format!("job {id} has not ended; cancel it first"),
                )
                .with_detail("reason", serde_json::json!("invalid_transition")));
            }
            for table in [
                "attempts",
                "stages",
                "artifacts",
                "events",
                "host_work",
                "job_recordings",
            ] {
                tx.tx
                    .execute(
                        &format!("DELETE FROM {table} WHERE job_id = ?1"),
                        [id.as_str()],
                    )
                    .map_err(db)?;
            }
            tx.tx
                .execute("DELETE FROM jobs WHERE id = ?1", [id.as_str()])
                .map_err(db)?;
            Ok(())
        })?;
        let dir = self.job_dir(id);
        let bytes = match std::fs::symlink_metadata(&dir) {
            Ok(meta) if meta.is_dir() => {
                let bytes = folder_bytes(&dir);
                std::fs::remove_dir_all(&dir)
                    .map_err(|e| internal(format!("{}: {e}", dir.display())))?;
                bytes
            }
            // Gone already, or not a plain folder: left alone.
            _ => 0,
        };
        Ok(Removed { bytes })
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The items of a job's host work (ANT-T0454): one row per job in
//! `host_work`, the items of its current attempt as JSON. The pool writes
//! the row at every change, so `job.get` shows which items are queued,
//! running and done, and a restarted daemon finds them again.
use super::{
    R, Store, db,
    model::{from_json, to_json},
};
use crate::api::{ids::JobId, job::HostItem};
use rusqlite::{Connection, OptionalExtension};

/// The items of the job's current attempt (none for an older attempt's row).
pub(crate) fn items_of(conn: &Connection, job: &str) -> R<Vec<HostItem>> {
    let text: Option<String> = conn
        .query_row(
            "SELECT h.items_json FROM host_work h JOIN jobs j ON j.id = h.job_id
             WHERE h.job_id = ?1 AND h.attempt = j.attempt",
            [job],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    text.map_or_else(|| Ok(Vec::new()), |text| from_json(&text))
}

impl Store {
    /// Store the items of `id`'s current attempt. No event: the items are
    /// state, read with the job (`job.progress` lines tell a watcher).
    pub fn set_host_work(&self, id: &JobId, items: &[HostItem]) -> R<()> {
        self.write(|tx| {
            let attempt: Option<u32> = tx
                .tx
                .query_row(
                    "SELECT attempt FROM jobs WHERE id = ?1",
                    [id.as_str()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db)?;
            let Some(attempt) = attempt else {
                return Err(crate::api::error::ApiError::not_found("job"));
            };
            tx.tx
                .execute(
                    "INSERT INTO host_work(job_id, attempt, items_json, updated_ms)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(job_id) DO UPDATE SET attempt = ?2, items_json = ?3,
                     updated_ms = ?4",
                    rusqlite::params![id.as_str(), attempt, to_json(&items)?, tx.now],
                )
                .map_err(db)?;
            Ok(())
        })
    }
}

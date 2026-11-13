// SPDX-License-Identifier: GPL-3.0-only
//! Reading the `events` table (design 5.5): per job by `seq`, engine-wide by
//! `gseq`, and the engine-scope events the lanes emit.

use super::{R, Store, db, mirror::event_from_parts};
use crate::api::{
    error::ApiError,
    event::{Event, EventBody},
    ids::RunId,
};

/// Engine-scope events are kept 7 days or 100 000 rows (design 5.5).
pub const ENGINE_EVENT_DAYS: u64 = 7;
pub const ENGINE_EVENT_ROWS: u64 = 100_000;

impl Store {
    /// The highest `gseq` stored, 0 for none. Never goes down: the column
    /// is `AUTOINCREMENT`, so a deleted job's numbers are not reused.
    pub fn highest_gseq(&self) -> R<u64> {
        let conn = self.conn();
        let stored: u64 = conn
            .query_row("SELECT COALESCE(MAX(gseq), 0) FROM events", [], |r| {
                r.get(0)
            })
            .map_err(db)?;
        let sequence: Option<u64> = conn
            .query_row(
                "SELECT seq FROM sqlite_sequence WHERE name = 'events'",
                [],
                |r| r.get(0),
            )
            .ok();
        Ok(stored.max(sequence.unwrap_or(0)))
    }

    /// `events.list`: the stored events of a job after `after_seq`, and the
    /// `seq` to ask for next.
    pub fn events_list(&self, job: &RunId, after_seq: u64, limit: u32) -> R<(Vec<Event>, u64)> {
        let limit = limit.clamp(1, 1000);
        let conn = self.conn();
        let exists: bool = conn
            .query_row("SELECT 1 FROM jobs WHERE id = ?1", [job.as_str()], |_| {
                Ok(true)
            })
            .unwrap_or(false);
        if !exists {
            return Err(ApiError::not_found("run"));
        }
        let mut statement = conn
            .prepare(
                "SELECT gseq, seq, ts_ms, type, data_json FROM events
                 WHERE job_id = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(rusqlite::params![job.as_str(), after_seq, limit], row_parts)
            .map_err(db)?;
        let mut events = Vec::new();
        for row in rows {
            let (gseq, seq, ts_ms, kind, data) = row.map_err(db)?;
            events.push(event_from_parts(
                gseq,
                seq,
                ts_ms,
                &kind,
                &data,
                Some(job.clone()),
            )?);
        }
        let next = events.last().and_then(|e| e.seq).unwrap_or(after_seq);
        Ok((events, next))
    }

    /// The stored events of every job and of the engine after `since_gseq`, in
    /// `gseq` order (the all-jobs stream and its resume).
    pub fn events_since(&self, since_gseq: u64, limit: u32) -> R<Vec<Event>> {
        let limit = limit.clamp(1, 10_000);
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT gseq, seq, ts_ms, type, data_json, job_id FROM events
                 WHERE gseq > ?1 ORDER BY gseq LIMIT ?2",
            )
            .map_err(db)?;
        let rows = statement
            .query_map(rusqlite::params![since_gseq, limit], |row| {
                Ok((row_parts(row)?, row.get::<_, Option<String>>(5)?))
            })
            .map_err(db)?;
        let mut events = Vec::new();
        for row in rows {
            let ((gseq, seq, ts_ms, kind, data), job) = row.map_err(db)?;
            let job = job
                .map(|id| RunId::try_from(id).map_err(super::internal))
                .transpose()?;
            events.push(event_from_parts(gseq, seq, ts_ms, &kind, &data, job)?);
        }
        Ok(events)
    }

    /// The oldest `gseq` still stored; a resume point below it is `truncated`
    /// in `engine.hello`.
    pub fn oldest_retained_gseq(&self) -> R<Option<u64>> {
        self.conn()
            .query_row("SELECT MIN(gseq) FROM events", [], |r| r.get(0))
            .map_err(db)
    }

    /// Store and send an engine-scope event (`lane.state`, `engine.alert`).
    pub fn emit_engine(&self, body: EventBody) -> R<()> {
        debug_assert!(
            !body.is_ephemeral() && body.scope() == crate::api::event::EventScope::Engine
        );
        self.write(|tx| tx.emit(None, body))
    }

    /// Delete engine events older than 7 days, and the oldest above 100 000
    /// rows. Run events live as long as the job.
    pub fn prune_engine_events(&self) -> R<u64> {
        self.write(|tx| {
            let cutoff = tx.now.saturating_sub(ENGINE_EVENT_DAYS * 24 * 3600 * 1000);
            let mut n = tx
                .tx
                .execute(
                    "DELETE FROM events WHERE job_id IS NULL AND ts_ms < ?1",
                    [cutoff],
                )
                .map_err(db)? as u64;
            n += tx
                .tx
                .execute(
                    "DELETE FROM events WHERE job_id IS NULL AND gseq NOT IN
                     (SELECT gseq FROM events WHERE job_id IS NULL ORDER BY gseq DESC LIMIT ?1)",
                    [ENGINE_EVENT_ROWS],
                )
                .map_err(db)? as u64;
            Ok(n)
        })
    }
}

fn row_parts(row: &rusqlite::Row<'_>) -> rusqlite::Result<(u64, u64, u64, String, String)> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
    ))
}

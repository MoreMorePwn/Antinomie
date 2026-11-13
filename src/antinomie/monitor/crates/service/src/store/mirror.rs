// SPDX-License-Identifier: GPL-3.0-only
//! `jobs/<id>/events.ndjson`: the mirror of a job's stored events (design
//! 2.5, 4.8). The table is the source; a line is appended after the commit
//! and, on recovery, any line missing for a stored row is appended again.

use super::{Fault, R, Store, db, internal, model::from_json};
use crate::api::{event::Event, ids::RunId};
use rusqlite::Connection;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::Path,
};

pub(crate) fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

/// Write a file whole: temp file, fsync, rename, mode 0600.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)
}

fn line_of(event: &Event) -> R<String> {
    let mut line = serde_json::to_string(event).map_err(internal)?;
    line.push('\n');
    Ok(line)
}

impl Store {
    /// Append the lines of just-committed job events. Not finding the
    /// directory or failing to write is not an error of the transition: the
    /// state is committed and recovery repairs the mirror.
    pub(super) fn mirror(&self, events: &[Event]) -> R<()> {
        for event in events {
            let Some(job) = &event.run_id else { continue };
            let dir = self.job_dir(job);
            if private_dir(&dir).is_err() {
                continue;
            }
            let line = line_of(event)?;
            let Ok(mut file) = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(dir.join("events.ndjson"))
            else {
                continue;
            };
            if super::lock(&self.fault)
                .as_ref()
                .is_some_and(|(at, _)| *at == Fault::MidMirror)
            {
                let _ = file.write_all(&line.as_bytes()[..line.len() / 2]);
                let _ = file.sync_all();
                self.hit(Fault::MidMirror)?;
            }
            let _ = file.write_all(line.as_bytes());
        }
        Ok(())
    }

    /// Make `events.ndjson` of a job equal to its stored events: keep the
    /// longest run of lines that match, cut a torn last line, append the rest.
    /// Returns the number of lines added.
    pub(crate) fn repair_mirror(&self, conn: &Connection, job: &RunId) -> R<usize> {
        let stored = job_events(conn, job)?;
        let wanted: Vec<String> = stored.iter().map(line_of).collect::<R<_>>()?;
        let dir = self.job_dir(job);
        private_dir(&dir).map_err(|e| internal(format!("{}: {e}", dir.display())))?;
        let path = dir.join("events.ndjson");
        let have = fs::read(&path).unwrap_or_default();
        let mut kept = 0usize;
        let mut offset = 0usize;
        for line in &wanted {
            if have[offset..].starts_with(line.as_bytes()) {
                offset += line.len();
                kept += 1;
            } else {
                break;
            }
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| internal(format!("{}: {e}", path.display())))?;
        if have.len() != offset {
            // Anything after the matching lines is a torn or foreign tail.
            file.set_len(offset as u64)
                .map_err(|e| internal(e.to_string()))?;
        }
        let mut added = 0;
        for line in &wanted[kept..] {
            file.write_all(line.as_bytes())
                .map_err(|e| internal(e.to_string()))?;
            added += 1;
        }
        file.sync_all().map_err(|e| internal(e.to_string()))?;
        Ok(added)
    }
}

/// The stored events of a job in `seq` order.
pub(crate) fn job_events(conn: &Connection, job: &RunId) -> R<Vec<Event>> {
    let mut statement = conn
        .prepare(
            "SELECT gseq, seq, ts_ms, type, data_json FROM events WHERE job_id = ?1 ORDER BY seq",
        )
        .map_err(db)?;
    let rows = statement
        .query_map([job.as_str()], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, u64>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(db)?;
    let mut out = Vec::new();
    for row in rows {
        let (gseq, seq, ts_ms, kind, data) = row.map_err(db)?;
        out.push(event_from_parts(
            gseq,
            seq,
            ts_ms,
            &kind,
            &data,
            Some(job.clone()),
        )?);
    }
    Ok(out)
}

pub(crate) fn event_from_parts(
    gseq: u64,
    seq: u64,
    ts_ms: u64,
    kind: &str,
    data: &str,
    job_id: Option<RunId>,
) -> R<Event> {
    let value = serde_json::json!({"type": kind, "data": from_json::<serde_json::Value>(data)?});
    let body: crate::api::event::EventBody = serde_json::from_value(value)
        .map_err(|e| internal(format!("unreadable stored event {kind}: {e}")))?;
    Ok(Event {
        seq: Some(seq),
        gseq: Some(gseq),
        ts_ms,
        scope: body.scope(),
        run_id: job_id,
        body,
    })
}

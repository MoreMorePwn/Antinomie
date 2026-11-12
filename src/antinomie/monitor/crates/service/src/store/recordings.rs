// SPDX-License-Identifier: GPL-3.0-only
//! Every run a job recorded: one row per run in `job_recordings`, written
//! with the job's `recording`. An attempt that launched and was then retried
//! (a lost guest, a stop, a restart) leaves a run of its own; the job then
//! names only the last one, and retention and `job.delete` find the earlier
//! ones here.
use super::{
    R, Store, Tx, db, internal,
    model::{from_json, to_json},
};
use crate::api::{
    ids::{JobId, LaneId},
    job::JobRecording,
};

/// A run an earlier attempt of a job recorded, and the lane it ran on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EarlierRecording {
    pub attempt: u32,
    pub lane: Option<LaneId>,
    pub recording: JobRecording,
}

/// Remember `recording` as a run of `id`'s current attempt, on its lane; the
/// attempt's row names the run too.
pub(crate) fn remember(tx: &mut Tx<'_>, id: &JobId, recording: &JobRecording) -> R<()> {
    let (attempt, lane): (u32, Option<String>) = tx
        .tx
        .query_row(
            "SELECT attempt, lane FROM jobs WHERE id = ?1",
            [id.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(db)?;
    tx.tx
        .execute(
            "INSERT INTO job_recordings(job_id, run_key, attempt, lane, recording_json)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(job_id, run_key) DO UPDATE SET recording_json = ?5",
            rusqlite::params![
                id.as_str(),
                recording.run_key,
                attempt,
                lane,
                to_json(recording)?
            ],
        )
        .map_err(db)?;
    tx.tx
        .execute(
            "UPDATE attempts SET boot_id = ?3, run_id = ?4 WHERE job_id = ?1 AND n = ?2",
            rusqlite::params![id.as_str(), attempt, recording.boot_id, recording.run_id],
        )
        .map_err(db)?;
    Ok(())
}

impl Store {
    /// The runs `id`'s earlier attempts recorded, other than the one the job
    /// names now, oldest attempt first.
    pub fn earlier_recordings(&self, id: &JobId) -> R<Vec<EarlierRecording>> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT r.attempt, r.lane, r.recording_json FROM job_recordings r
                 JOIN jobs j ON j.id = r.job_id
                 WHERE r.job_id = ?1 AND (j.run_key IS NULL OR r.run_key != j.run_key)
                 ORDER BY r.attempt, r.run_key",
            )
            .map_err(db)?;
        let rows = statement
            .query_map([id.as_str()], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(db)?;
        let mut out = Vec::new();
        for row in rows {
            let (attempt, lane, json) = row.map_err(db)?;
            out.push(EarlierRecording {
                attempt,
                lane: lane
                    .map(|lane| LaneId::try_from(lane).map_err(internal))
                    .transpose()?,
                recording: from_json(&json)?,
            });
        }
        Ok(out)
    }
}

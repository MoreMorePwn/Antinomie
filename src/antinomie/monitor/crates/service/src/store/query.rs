// SPDX-License-Identifier: GPL-3.0-only
//! Reading jobs: one by id, and the filtered list with cursors (design 5.3).

use super::{
    R, Store, db,
    model::{JOB_COLUMNS, JobRow, assemble, load_job, load_terms, name_of},
};
use crate::api::{
    error::ApiError,
    ids::RunId,
    ops::{RunList, RunListParams},
    run::{Run, RunState},
};

const CURSOR_PREFIX: &str = "jc1.";

/// Counts for `queue.status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QueueCounts {
    pub queued: u32,
    pub running: u32,
}

impl Store {
    /// `run.get`.
    pub fn get(&self, id: &RunId) -> R<Run> {
        load_job(&self.conn(), id.as_str())
    }

    /// `run.list`: newest first (job ids are time-ordered), filtered; `limit`
    /// is 1 to 200, default 50. `visible` limits the list to one client's own
    /// jobs (a caller without `read` of the whole node).
    pub fn list(&self, params: &RunListParams, visible: Option<&str>) -> R<RunList> {
        let limit = params.limit.unwrap_or(50);
        if !(1..=200).contains(&limit) {
            return Err(ApiError::invalid_argument("limit", "1 to 200"));
        }
        let mut after = match &params.cursor {
            Some(cursor) => Some(
                cursor
                    .strip_prefix(CURSOR_PREFIX)
                    .and_then(|id| RunId::try_from(id.to_owned()).ok())
                    .ok_or_else(|| {
                        ApiError::invalid_argument("cursor", "not a cursor of this list")
                    })?,
            ),
            None => None,
        };
        let label = params
            .label
            .as_deref()
            .map(|text| match text.split_once('=') {
                Some((key, value)) => (key.to_owned(), Some(value.to_owned())),
                None => (text.to_owned(), None),
            });
        let conn = self.conn();
        let mut found: Vec<Run> = Vec::new();
        let mut more = false;
        'pages: loop {
            let mut sql = format!("SELECT {JOB_COLUMNS} FROM jobs WHERE 1 = 1");
            let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
            let mut add = |clause: &str, value: Box<dyn rusqlite::ToSql>| {
                args.push(value);
                sql.push_str(&format!(" AND {clause}?{}", args.len()));
            };
            if let Some(id) = &after {
                add("id < ", Box::new(id.as_str().to_owned()));
            }
            if let Some(state) = params.state {
                add("state = ", Box::new(name_of(&state)));
            }
            if let Some(outcome) = params.outcome {
                add("outcome = ", Box::new(name_of(&outcome)));
            }
            if let Some(sha) = &params.sha256 {
                add("sha256 = ", Box::new(sha.as_str().to_owned()));
            }
            if let Some(since) = params.since_ms {
                add("created_ms >= ", Box::new(since));
            }
            if let Some(client) = visible {
                add("client_id = ", Box::new(client.to_owned()));
            }
            sql.push_str(" ORDER BY id DESC LIMIT 200");
            let mut statement = conn.prepare(&sql).map_err(db)?;
            let rows: Vec<JobRow> = statement
                .query_map(
                    rusqlite::params_from_iter(args.iter().map(|a| a.as_ref())),
                    JobRow::read,
                )
                .map_err(db)?
                .collect::<Result<_, _>>()
                .map_err(db)?;
            let full = rows.len() == 200;
            for row in rows {
                after = RunId::try_from(row.id.clone()).ok();
                let job = assemble(&conn, row)?;
                if let Some((key, value)) = &label {
                    match job.labels.get(key) {
                        Some(v) if value.as_ref().is_none_or(|want| want == v) => {}
                        _ => continue,
                    }
                }
                if found.len() == limit as usize {
                    more = true;
                    break 'pages;
                }
                found.push(job);
            }
            if !full {
                break;
            }
        }
        let next_cursor = more
            .then(|| found.last().map(|job| format!("{CURSOR_PREFIX}{}", job.id)))
            .flatten();
        Ok(RunList {
            runs: found,
            next_cursor,
        })
    }

    /// The preset a job froze when it was submitted (design 5.6), with every
    /// option resolved: what the pipeline runs, whatever the files say now.
    pub fn frozen_preset(&self, id: &RunId) -> R<crate::config::LoadedPreset> {
        load_terms(&self.conn(), id.as_str())
    }

    /// Jobs per state that matter to `queue.status`.
    pub fn counts(&self) -> R<QueueCounts> {
        let conn = self.conn();
        let count = |states: &str| -> R<u32> {
            conn.query_row(
                &format!("SELECT COUNT(*) FROM jobs WHERE state IN ({states})"),
                [],
                |r| r.get(0),
            )
            .map_err(db)
        };
        Ok(QueueCounts {
            queued: count("'queued'")?,
            running: count("'running', 'cancelling'")?,
        })
    }

    /// Runs `client_id` had accepted since `since_ms` (rejected ones not
    /// counted): the daily count of `max_runs_per_day`.
    pub fn count_caller_runs_since(&self, client_id: &str, since_ms: u64) -> R<u32> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE client_id = ?1 AND created_ms >= ?2
                 AND state != 'rejected'",
                rusqlite::params![client_id, since_ms],
                |r| r.get(0),
            )
            .map_err(db)
    }

    /// How many jobs of a state exist.
    pub fn count_state(&self, state: RunState) -> R<u32> {
        self.conn()
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE state = ?1",
                [name_of(&state)],
                |r| r.get(0),
            )
            .map_err(db)
    }
}

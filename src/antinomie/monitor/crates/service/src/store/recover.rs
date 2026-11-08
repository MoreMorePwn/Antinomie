// SPDX-License-Identifier: GPL-3.0-only
//! Startup recovery (design 4.7.3, 4.8): what a process that died between two
//! steps left behind is put right before the first lane starts.
//!
//! * a job `running` is requeued as a new attempt (`guest_lost`, reason
//!   `service_restart`), not counted against `max_attempts` once per job;
//! * a job `cancelling` for the shutdown is requeued, one the user cancelled
//!   is `cancelled`;
//! * every event row has its line in `events.ndjson` and every job its
//!   `spec.json`.

use super::{
    R, Store, db, internal,
    lifecycle::{RequeueKind, current, requeue_in, terminate},
    model::{from_name, load_job},
};
use crate::api::{
    failure::{Failure, FailureCode},
    ids::JobId,
    job::{JobState, Outcome, Stage},
};

/// What `recover` did, for the log and the tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// Jobs found `running`/`cancelling` and put back in the queue.
    pub requeued: Vec<JobId>,
    /// Jobs found `running` that had used their restart credit and attempts.
    pub failed: Vec<JobId>,
    /// Jobs found `cancelling` for a user's cancel, now `cancelled`.
    pub cancelled: Vec<JobId>,
    /// Mirror lines appended again.
    pub mirror_lines: usize,
    /// `spec.json` files written again.
    pub spec_files: usize,
}

impl Store {
    /// Run the recovery of 4.8. Safe to run twice: the second run finds
    /// nothing to do.
    pub fn recover(&self) -> R<RecoveryReport> {
        let mut report = RecoveryReport::default();
        let stuck: Vec<String> = {
            let conn = self.conn();
            let mut statement = conn
                .prepare("SELECT id FROM jobs WHERE state IN ('running', 'cancelling') ORDER BY id")
                .map_err(db)?;
            statement
                .query_map([], |r| r.get(0))
                .map_err(db)?
                .collect::<Result<_, _>>()
                .map_err(db)?
        };
        for id in stuck {
            let id = JobId::try_from(id).map_err(internal)?;
            self.write(|tx| {
                let cur = current(tx, &id)?;
                let failure = Failure::new(
                    FailureCode::GuestLost,
                    cur.stage.unwrap_or(Stage::Prechecks),
                    "the service restarted while the job was running",
                    Some("service_restart"),
                );
                let restarts: u32 = tx
                    .tx
                    .query_row(
                        "SELECT COUNT(*) FROM attempts WHERE job_id = ?1 AND detail = 'service_restart'",
                        [id.as_str()],
                        |r| r.get(0),
                    )
                    .map_err(db)?;
                match cur.state {
                    JobState::Cancelling if !cur.cancel_shutdown => {
                        terminate(tx, &id, &cur, Outcome::Cancelled, None)?;
                        report.cancelled.push(id.clone());
                    }
                    JobState::Cancelling => {
                        requeue_in(tx, &id, &cur, RequeueKind::Shutdown, "service_shutdown", None, None)?;
                        report.requeued.push(id.clone());
                    }
                    _ => {
                        // Once per job the restart is free; after that it counts.
                        let kind = if restarts == 0 {
                            RequeueKind::ServiceRestart
                        } else {
                            RequeueKind::Retry
                        };
                        match requeue_in(tx, &id, &cur, kind, "service_restart", Some(&failure), None) {
                            Ok(()) => report.requeued.push(id.clone()),
                            Err(_) => {
                                // No attempt left: the job ends.
                                terminate(tx, &id, &cur, Outcome::Failed, Some(failure))?;
                                report.failed.push(id.clone());
                            }
                        }
                    }
                }
                Ok(())
            })?;
        }

        // Files: only jobs with events after the last recovery can be torn.
        let watermark: u64 = self
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = 'recovered_gseq'",
                [],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);
        let high = self.highest_gseq()?;
        let touched: Vec<String> = {
            let conn = self.conn();
            let mut statement = conn
                .prepare(
                    "SELECT DISTINCT job_id FROM events WHERE job_id IS NOT NULL AND gseq > ?1",
                )
                .map_err(db)?;
            statement
                .query_map([watermark], |r| r.get(0))
                .map_err(db)?
                .collect::<Result<_, _>>()
                .map_err(db)?
        };
        for id in touched {
            let id = JobId::try_from(id).map_err(internal)?;
            let conn = self.conn();
            report.mirror_lines += self.repair_mirror(&conn, &id)?;
            if !self.job_dir(&id).join("spec.json").exists() {
                let job = load_job(&conn, id.as_str())?;
                drop(conn);
                self.write_spec_file_for(&job);
                report.spec_files += 1;
            }
        }
        self.write(|tx| {
            tx.tx
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('recovered_gseq', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [high.to_string()],
                )
                .map_err(db)?;
            Ok(())
        })?;
        self.expire_idempotency_keys()?;
        Ok(report)
    }

    /// The state of a stored job by name, for tests and tools that read the
    /// raw column.
    pub fn raw_state(&self, id: &JobId) -> R<JobState> {
        let text: String = self
            .conn()
            .query_row("SELECT state FROM jobs WHERE id = ?1", [id.as_str()], |r| {
                r.get(0)
            })
            .map_err(db)?;
        from_name(&text)
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The transitions of design 5.6. Each is one transaction that updates the
//! `jobs` row, the `attempts` and `stages` rows it touches and inserts the
//! events (4.8). An edge that is not in [`machine::EDGES`] is a `conflict`
//! and changes nothing.

use super::{
    R, Store, Tx, db, internal, machine,
    model::{from_name, load_job, name_of, queue_position, to_json},
    submit::{QueueKey, queued_rows},
};
use crate::api::{
    error::{ApiError, ErrorCode},
    event::{EventBody, StageStatus},
    failure::{Failure, FailureCode},
    ids::{JobId, LaneId},
    job::{Job, JobState, Outcome, Stage, WaitingFor},
    ops::{Caller, Permission},
};
use rusqlite::OptionalExtension;

/// What the scheduler says about a queued job when a lane looks for work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eligibility {
    /// Start it now.
    Ready,
    /// Not yet: the job stays `queued` and says why.
    Wait(WaitingFor),
    /// Not for this lane: another lane takes it (several lanes, design
    /// 4.6.1). The job is left exactly as it is.
    Skip,
}

/// How a running job goes back to the queue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequeueKind {
    /// A retryable failure: the attempt counts against `max_attempts`.
    Retry,
    /// The daemon found the job `running` after a crash (4.7.3): the attempt
    /// is not counted, once per job (a second restart counts).
    ServiceRestart,
    /// The daemon is stopping with `shutdown = cancel` (2.7): not counted.
    Shutdown,
}

/// The state of a row, read inside a transaction.
pub(crate) struct Cur {
    pub state: JobState,
    pub stage: Option<Stage>,
    pub waiting_for: Option<WaitingFor>,
    pub attempt: u32,
    pub max_attempts: u32,
    pub forgiven: u32,
    pub cancel_reason: Option<String>,
    pub cancel_shutdown: bool,
    pub client_id: String,
}

pub(crate) fn current(tx: &Tx<'_>, id: &JobId) -> R<Cur> {
    let row = tx
        .tx
        .query_row(
            "SELECT state, stage, waiting_for, attempt, max_attempts, forgiven, cancel_reason,
                    cancel_shutdown, client_id FROM jobs WHERE id = ?1",
            [id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, u32>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, u32>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, bool>(7)?,
                    row.get::<_, String>(8)?,
                ))
            },
        )
        .optional()
        .map_err(db)?
        .ok_or_else(|| ApiError::not_found("job"))?;
    Ok(Cur {
        state: from_name(&row.0)?,
        stage: row.1.as_deref().map(from_name).transpose()?,
        waiting_for: row.2.as_deref().map(from_name).transpose()?,
        attempt: row.3,
        max_attempts: row.4,
        forgiven: row.5,
        cancel_reason: row.6,
        cancel_shutdown: row.7,
        client_id: row.8,
    })
}

pub(crate) fn conflict(id: &JobId, from: JobState, wanted: &str) -> ApiError {
    ApiError::new(
        ErrorCode::Conflict,
        format!("job {id} is {}; it cannot {wanted}", name_of(&from)),
    )
    .with_detail("reason", serde_json::json!("invalid_transition"))
}

fn require_edge(id: &JobId, from: JobState, to: JobState, wanted: &str) -> R<()> {
    if machine::allowed(from, to) {
        Ok(())
    } else {
        Err(conflict(id, from, wanted))
    }
}

/// Close the stage that is open for this attempt, with a status; emits
/// `job.stage`. Does nothing when none is open.
fn close_stage(tx: &mut Tx<'_>, id: &JobId, cur: &Cur, status: StageStatus) -> R<()> {
    let Some(stage) = cur.stage else {
        return Ok(());
    };
    let started: Option<u64> = tx
        .tx
        .query_row(
            "SELECT started_ms FROM stages WHERE job_id = ?1 AND attempt = ?2 AND stage = ?3
               AND finished_ms IS NULL",
            rusqlite::params![id.as_str(), cur.attempt, name_of(&stage)],
            |row| row.get(0),
        )
        .optional()
        .map_err(db)?;
    let Some(started) = started else {
        return Ok(());
    };
    tx.tx
        .execute(
            "UPDATE stages SET status = ?4, finished_ms = ?5
             WHERE job_id = ?1 AND attempt = ?2 AND stage = ?3",
            rusqlite::params![
                id.as_str(),
                cur.attempt,
                name_of(&stage),
                name_of(&status),
                tx.now
            ],
        )
        .map_err(db)?;
    let duration_ms = tx.now.saturating_sub(started);
    tx.emit(
        Some(id),
        EventBody::JobStage {
            stage,
            status,
            duration_ms: Some(duration_ms),
        },
    )
}

fn close_attempt(
    tx: &mut Tx<'_>,
    id: &JobId,
    cur: &Cur,
    code: Option<FailureCode>,
    detail: Option<&str>,
) -> R<()> {
    tx.tx
        .execute(
            "UPDATE attempts SET finished_ms = ?3, stage_reached = ?4, failure_code = ?5, detail = ?6
             WHERE job_id = ?1 AND n = ?2 AND finished_ms IS NULL",
            rusqlite::params![
                id.as_str(),
                cur.attempt,
                tx.now,
                cur.stage.as_ref().map(name_of),
                code.as_ref().map(name_of),
                detail
            ],
        )
        .map_err(db)?;
    Ok(())
}

/// Move a job to a terminal state: the shared tail of `finish`, `cancel`,
/// the wait expiry and recovery.
pub(crate) fn terminate(
    tx: &mut Tx<'_>,
    id: &JobId,
    cur: &Cur,
    outcome: Outcome,
    failure: Option<Failure>,
) -> R<()> {
    let to = JobState::from(outcome);
    require_edge(id, cur.state, to, &format!("become {}", name_of(&to)))?;
    let failure = match (outcome, failure) {
        (Outcome::Succeeded | Outcome::Partial, Some(_)) => {
            return Err(ApiError::invalid_argument(
                "failure",
                "a succeeded or partial job carries no failure",
            ));
        }
        (Outcome::Failed, None) => Some(Failure::new(
            FailureCode::Internal,
            cur.stage.unwrap_or(Stage::Prechecks),
            "the job failed",
            None,
        )),
        (Outcome::Cancelled, None) => Some(Failure::new(
            FailureCode::Cancelled,
            cur.stage.unwrap_or(Stage::Prechecks),
            cur.cancel_reason
                .as_deref()
                .unwrap_or("cancelled by request"),
            None,
        )),
        (Outcome::Rejected, _) => return Err(conflict(id, cur.state, "be rejected")),
        (_, failure) => failure,
    };
    let stage_status = if matches!(outcome, Outcome::Succeeded | Outcome::Partial) {
        StageStatus::Finished
    } else {
        StageStatus::Failed
    };
    close_stage(tx, id, cur, stage_status)?;
    if cur.state != JobState::Queued {
        close_attempt(tx, id, cur, failure.as_ref().map(|f| f.code), None)?;
    }
    tx.tx
        .execute(
            "UPDATE jobs SET state = ?2, outcome = ?2, finished_ms = ?3, stage = NULL,
                waiting_for = NULL, waiting_since_ms = NULL, not_before_ms = NULL,
                failure_code = ?4, failure_json = ?5 WHERE id = ?1",
            rusqlite::params![
                id.as_str(),
                name_of(&to),
                tx.now,
                failure.as_ref().map(|f| name_of(&f.code)),
                failure.as_ref().map(to_json).transpose()?,
            ],
        )
        .map_err(db)?;
    tx.emit(
        Some(id),
        EventBody::JobState {
            state: to,
            stage: None,
            waiting_for: None,
            attempt: cur.attempt,
            queue_position: None,
        },
    )?;
    tx.emit(Some(id), EventBody::JobFinished { outcome, failure })
}

fn set_waiting(tx: &mut Tx<'_>, id: &JobId, cur: &Cur, wait: Option<WaitingFor>) -> R<()> {
    if cur.waiting_for == wait {
        return Ok(());
    }
    tx.tx
        .execute(
            "UPDATE jobs SET waiting_for = ?2, waiting_since_ms = ?3 WHERE id = ?1",
            rusqlite::params![
                id.as_str(),
                wait.as_ref().map(name_of),
                wait.map(|_| tx.now)
            ],
        )
        .map_err(db)?;
    let (priority, created): (i64, u64) = tx
        .tx
        .query_row(
            "SELECT priority, created_ms FROM jobs WHERE id = ?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(db)?;
    let position = queue_position(&tx.tx, id.as_str(), priority, created)?;
    tx.emit(
        Some(id),
        EventBody::JobState {
            state: JobState::Queued,
            stage: None,
            waiting_for: wait,
            attempt: cur.attempt,
            queue_position: Some(position),
        },
    )
}

/// Rows the scheduler reads at a time.
const CLAIM_PAGE: u32 = 64;

/// One page of [`Store::claim_next`]: the first job of `candidates` the lane
/// may start, started; the others get their `waiting_for`.
fn claim_in(
    tx: &mut Tx<'_>,
    lane: &LaneId,
    paused: bool,
    now: u64,
    candidates: Vec<Job>,
    eligible: &mut dyn FnMut(&Job) -> Eligibility,
) -> R<Option<Job>> {
    for job in candidates {
        let cur = current(tx, &job.id)?;
        let backoff_until: Option<u64> = tx
            .tx
            .query_row(
                "SELECT not_before_ms FROM jobs WHERE id = ?1",
                [job.id.as_str()],
                |r| r.get(0),
            )
            .map_err(db)?;
        if paused {
            set_waiting(tx, &job.id, &cur, Some(WaitingFor::QueuePaused))?;
            continue;
        }
        if backoff_until.is_some_and(|until| until > now) {
            set_waiting(tx, &job.id, &cur, Some(WaitingFor::Backoff))?;
            continue;
        }
        match eligible(&job) {
            Eligibility::Skip => {}
            Eligibility::Wait(why) => set_waiting(tx, &job.id, &cur, Some(why))?,
            Eligibility::Ready => {
                start(tx, &job.id, &cur, lane)?;
                return Ok(Some(load_job(&tx.tx, job.id.as_str())?));
            }
        }
    }
    Ok(None)
}

impl Store {
    /// A lane looks for work: the first queued job (priority, then age) the
    /// scheduler calls [`Eligibility::Ready`] becomes `running` at stage
    /// `prechecks`, attempt counted up. Jobs it cannot start yet keep
    /// `queued` and get their `waiting_for`. A paused queue starts nothing.
    /// The whole queue is read, a page at a time, so a job this lane can run
    /// is found behind any number it cannot.
    pub fn claim_next(
        &self,
        lane: &LaneId,
        eligible: &mut dyn FnMut(&Job) -> Eligibility,
    ) -> R<Option<Job>> {
        let paused = self.pause_reason()?.is_some();
        self.write(|tx| {
            let now = tx.now;
            let mut after: Option<QueueKey> = None;
            loop {
                let candidates = queued_rows(&tx.tx, after.as_ref(), CLAIM_PAGE)?;
                let Some(last) = candidates.last() else {
                    return Ok(None);
                };
                after = Some(
                    tx.tx
                        .query_row(
                            "SELECT priority, created_ms, id FROM jobs WHERE id = ?1",
                            [last.id.as_str()],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .map_err(db)?,
                );
                if let Some(job) = claim_in(tx, lane, paused, now, candidates, eligible)? {
                    return Ok(Some(job));
                }
            }
        })
    }

    /// Enter a stage: the open stage (if any) finishes, the new one starts.
    pub fn begin_stage(&self, id: &JobId, stage: Stage) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            if cur.state != JobState::Running {
                return Err(conflict(id, cur.state, "start a stage"));
            }
            // A stage may be entered again in the same attempt only if its
            // last run did not finish: the host stages resume after a crash
            // (`started` is left behind) or are repeated after a failure.
            let earlier: Option<String> = tx
                .tx
                .query_row(
                    "SELECT status FROM stages WHERE job_id = ?1 AND attempt = ?2 AND stage = ?3",
                    rusqlite::params![id.as_str(), cur.attempt, name_of(&stage)],
                    |r| r.get(0),
                )
                .optional()
                .map_err(db)?;
            if earlier
                .as_deref()
                .is_some_and(|status| !matches!(status, "started" | "failed"))
            {
                return Err(ApiError::new(
                    ErrorCode::Conflict,
                    format!("stage {} already ran in this attempt", name_of(&stage)),
                ));
            }
            if cur.stage != Some(stage) {
                close_stage(tx, id, &cur, StageStatus::Finished)?;
            }
            if earlier.is_some() {
                tx.tx
                    .execute(
                        "UPDATE stages SET status = 'started', started_ms = ?4, finished_ms = NULL
                         WHERE job_id = ?1 AND attempt = ?2 AND stage = ?3",
                        rusqlite::params![id.as_str(), cur.attempt, name_of(&stage), tx.now],
                    )
                    .map_err(db)?;
            } else {
                insert_stage(tx, id, cur.attempt, stage)?;
            }
            tx.tx
                .execute(
                    "UPDATE jobs SET stage = ?2 WHERE id = ?1",
                    [id.as_str(), &name_of(&stage)],
                )
                .map_err(db)?;
            tx.emit(
                Some(id),
                EventBody::JobState {
                    state: JobState::Running,
                    stage: Some(stage),
                    waiting_for: None,
                    attempt: cur.attempt,
                    queue_position: None,
                },
            )?;
            emit_stage_started(tx, id, stage)?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// End the current stage with a status (`finished`, `skipped`, `failed`).
    /// The job keeps naming that stage until the next `begin_stage` or the end.
    pub fn end_stage(&self, id: &JobId, status: StageStatus) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            if !matches!(cur.state, JobState::Running | JobState::Cancelling) {
                return Err(conflict(id, cur.state, "end a stage"));
            }
            close_stage(tx, id, &cur, status)?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// End a job: `succeeded` or `partial` from `running`; `failed` from
    /// `queued`, `running` or `cancelling`; `cancelled` from `cancelling`.
    pub fn finish(&self, id: &JobId, outcome: Outcome, failure: Option<Failure>) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            terminate(tx, id, &cur, outcome, failure)?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// `job.cancel`. A queued job is `cancelled` at once; a running one goes to
    /// `cancelling` and the lane unwinds it; a `cancelling` one is returned as
    /// it is; a finished one is a `conflict`. The caller's own job needs
    /// `runs.submit`, anyone's `runs.manage_any` (else `permission_denied`).
    pub fn cancel(&self, id: &JobId, reason: Option<&str>, caller: &Caller) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            if cur.client_id == caller.client_id {
                caller.require_any(&[Permission::RunsSubmit, Permission::RunsManageAny])?;
            } else {
                caller.require(Permission::RunsManageAny)?;
            }
            let reason = reason.map(|r| r.chars().take(256).collect::<String>());
            match cur.state {
                JobState::Queued => {
                    let mut cur = cur;
                    cur.cancel_reason = reason;
                    terminate(tx, id, &cur, Outcome::Cancelled, None)?;
                }
                JobState::Running => {
                    request_cancel(tx, id, &cur, reason.as_deref(), false)?;
                }
                JobState::Cancelling => {
                    // A user's request outranks the daemon's own: the job is
                    // cancelled, not put back.
                    if cur.cancel_shutdown {
                        tx.tx
                            .execute(
                                "UPDATE jobs SET cancel_reason = ?2, cancel_shutdown = 0 WHERE id = ?1",
                                rusqlite::params![id.as_str(), reason],
                            )
                            .map_err(db)?;
                    }
                }
                state => return Err(conflict(id, state, "be cancelled")),
            }
            load_job(&tx.tx, id.as_str())
        })
    }

    /// The daemon is stopping (2.7, `shutdown = cancel`): `running` becomes
    /// `cancelling`, and [`Self::requeue`] with [`RequeueKind::Shutdown`]
    /// puts it back once the lane has unwound it.
    pub fn cancel_for_shutdown(&self, id: &JobId) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            if cur.state != JobState::Running {
                return Err(conflict(id, cur.state, "be stopped for shutdown"));
            }
            request_cancel(tx, id, &cur, Some("service_shutdown"), true)?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// Put a `running` job back in the queue (`running -> queued`), or a job
    /// `cancelling` for shutdown (`cancelling -> queued`). Emits
    /// `job.requeued` then `job.state`. A [`RequeueKind::Retry`] needs an
    /// attempt left, else it is a `conflict` and the caller fails the job.
    /// `backoff_s` makes the job wait (`waiting_for: backoff`).
    pub fn requeue(
        &self,
        id: &JobId,
        kind: RequeueKind,
        reason: &str,
        failure: Option<&Failure>,
        backoff_s: Option<u32>,
    ) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            requeue_in(tx, id, &cur, kind, reason, failure, backoff_s)?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// A running job cannot start yet and says why (design 4.1: waits are
    /// `queued` with `waiting_for`, not failures): back to the queue with the
    /// reason, the attempt not counted.
    pub fn requeue_waiting(&self, id: &JobId, waiting_for: WaitingFor, reason: &str) -> R<Job> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            requeue_in(
                tx,
                id,
                &cur,
                RequeueKind::ServiceRestart,
                reason,
                None,
                None,
            )?;
            set_waiting(tx, id, &cur, Some(waiting_for))?;
            load_job(&tx.tx, id.as_str())
        })
    }

    /// The failure codes of the job's finished attempts, oldest first
    /// (4.7.2: a sample that kills the guest twice is final).
    pub fn previous_failures(&self, id: &JobId) -> R<Vec<FailureCode>> {
        {
            let conn = self.conn();
            let mut statement = conn
                .prepare(
                    "SELECT failure_code FROM attempts
                     WHERE job_id = ?1 AND finished_ms IS NOT NULL AND failure_code IS NOT NULL
                     ORDER BY n",
                )
                .map_err(db)?;
            let rows = statement
                .query_map([id.as_str()], |r| r.get::<_, String>(0))
                .map_err(db)?;
            let mut codes = Vec::new();
            for row in rows {
                let text = row.map_err(db)?;
                if let Ok(code) = serde_json::from_value(serde_json::Value::String(text)) {
                    codes.push(code);
                }
            }
            Ok(codes)
        }
    }

    /// Whether the cancel the job is `cancelling` for is the daemon's own
    /// shutdown (it goes back to the queue) and not a user's (it ends
    /// `cancelled`).
    pub fn cancel_is_shutdown(&self, id: &JobId) -> R<bool> {
        self.conn()
            .query_row(
                "SELECT cancel_shutdown FROM jobs WHERE id = ?1",
                [id.as_str()],
                |r| r.get::<_, bool>(0),
            )
            .map_err(db)
    }

    /// Fail queued jobs that waited past `wait_s` for resources, a dependency,
    /// quota or a pending disk layer (5.6). The failure code is the wait's.
    pub fn expire_waits(&self) -> R<Vec<Job>> {
        self.write(|tx| {
            let rows: Vec<(String, String, u64, u64)> = {
                let mut statement = tx
                    .tx
                    .prepare(
                        "SELECT id, waiting_for, waiting_since_ms, wait_s FROM jobs
                         WHERE state = 'queued' AND waiting_for IN
                           ('resources', 'dependency', 'quota', 'layer_pending')
                           AND waiting_since_ms IS NOT NULL",
                    )
                    .map_err(db)?;
                statement
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
                    .map_err(db)?
                    .collect::<Result<_, _>>()
                    .map_err(db)?
            };
            let mut failed = Vec::new();
            for (id, wait, since, wait_s) in rows {
                if tx.now < since.saturating_add(wait_s.saturating_mul(1000)) {
                    continue;
                }
                let id = JobId::try_from(id).map_err(internal)?;
                let wait: WaitingFor = from_name(&wait)?;
                let code = match wait {
                    WaitingFor::Dependency => FailureCode::DependencyMissing,
                    WaitingFor::Quota => FailureCode::QuotaExceeded,
                    _ => FailureCode::HostResources,
                };
                let cur = current(tx, &id)?;
                let failure = Failure::new(
                    code,
                    Stage::Prechecks,
                    &format!("waited {wait_s} seconds for {}", name_of(&wait)),
                    None,
                );
                terminate(tx, &id, &cur, Outcome::Failed, Some(failure))?;
                failed.push(load_job(&tx.tx, id.as_str())?);
            }
            Ok(failed)
        })
    }

    /// Pause or resume starting new jobs (`queue.pause`, the `PAUSE` file, a
    /// low-disk rule). The flag is stored, so a restart keeps it. When it
    /// cannot be written (a full disk) it holds in this process all the same
    /// and the error is returned: the queue pauses even when the database is
    /// full (ANT-T0475).
    pub fn set_pause(&self, reason: Option<crate::api::status::PauseReason>) -> R<()> {
        let written = self.write_pause(reason);
        self.hold_pause(written.is_err().then_some(reason));
        written
    }

    fn write_pause(&self, reason: Option<crate::api::status::PauseReason>) -> R<()> {
        self.write(|tx| {
            match reason {
                Some(reason) => tx.tx.execute(
                    "INSERT INTO meta(key, value) VALUES ('pause_reason', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [name_of(&reason)],
                ),
                None => tx
                    .tx
                    .execute("DELETE FROM meta WHERE key = 'pause_reason'", []),
            }
            .map_err(db)?;
            Ok(())
        })
    }

    pub fn pause_reason(&self) -> R<Option<crate::api::status::PauseReason>> {
        if let Some(held) = self.held_pause() {
            return Ok(held);
        }
        let text: Option<String> = self
            .conn()
            .query_row(
                "SELECT value FROM meta WHERE key = 'pause_reason'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(db)?;
        text.as_deref().map(from_name).transpose()
    }
}

fn start(tx: &mut Tx<'_>, id: &JobId, cur: &Cur, lane: &LaneId) -> R<()> {
    require_edge(id, cur.state, JobState::Running, "start")?;
    let attempt = cur.attempt + 1;
    tx.tx
        .execute(
            "UPDATE jobs SET state = 'running', stage = 'prechecks', waiting_for = NULL,
                waiting_since_ms = NULL, not_before_ms = NULL, attempt = ?2, lane = ?3,
                started_ms = COALESCE(started_ms, ?4) WHERE id = ?1",
            rusqlite::params![id.as_str(), attempt, lane.as_str(), tx.now],
        )
        .map_err(db)?;
    tx.tx
        .execute(
            "INSERT INTO attempts(job_id, n, started_ms) VALUES (?1, ?2, ?3)",
            rusqlite::params![id.as_str(), attempt, tx.now],
        )
        .map_err(db)?;
    insert_stage(tx, id, attempt, Stage::Prechecks)?;
    tx.emit(
        Some(id),
        EventBody::JobState {
            state: JobState::Running,
            stage: Some(Stage::Prechecks),
            waiting_for: None,
            attempt,
            queue_position: None,
        },
    )?;
    emit_stage_started(tx, id, Stage::Prechecks)
}

fn insert_stage(tx: &mut Tx<'_>, id: &JobId, attempt: u32, stage: Stage) -> R<()> {
    tx.tx
        .execute(
            "INSERT INTO stages(job_id, attempt, stage, status, started_ms)
             VALUES (?1, ?2, ?3, 'started', ?4)",
            rusqlite::params![id.as_str(), attempt, name_of(&stage), tx.now],
        )
        .map_err(db)?;
    Ok(())
}

fn emit_stage_started(tx: &mut Tx<'_>, id: &JobId, stage: Stage) -> R<()> {
    tx.emit(
        Some(id),
        EventBody::JobStage {
            stage,
            status: StageStatus::Started,
            duration_ms: None,
        },
    )
}

fn request_cancel(
    tx: &mut Tx<'_>,
    id: &JobId,
    cur: &Cur,
    reason: Option<&str>,
    shutdown: bool,
) -> R<()> {
    require_edge(id, cur.state, JobState::Cancelling, "be cancelled")?;
    tx.tx
        .execute(
            "UPDATE jobs SET state = 'cancelling', cancel_reason = ?2, cancel_shutdown = ?3
             WHERE id = ?1",
            rusqlite::params![id.as_str(), reason, shutdown],
        )
        .map_err(db)?;
    tx.emit(
        Some(id),
        EventBody::JobState {
            state: JobState::Cancelling,
            stage: cur.stage,
            waiting_for: None,
            attempt: cur.attempt,
            queue_position: None,
        },
    )
}

pub(crate) fn requeue_in(
    tx: &mut Tx<'_>,
    id: &JobId,
    cur: &Cur,
    kind: RequeueKind,
    reason: &str,
    failure: Option<&Failure>,
    backoff_s: Option<u32>,
) -> R<()> {
    require_edge(id, cur.state, JobState::Queued, "be put back in the queue")?;
    if cur.state == JobState::Cancelling && !cur.cancel_shutdown {
        // A cancel the user asked for ends in `cancelled`, never in the queue.
        return Err(conflict(id, cur.state, "be put back in the queue"));
    }
    let forgiven = cur.forgiven + u32::from(kind != RequeueKind::Retry);
    if kind == RequeueKind::Retry && cur.attempt.saturating_sub(cur.forgiven) >= cur.max_attempts {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("job {id} has used its {} attempts", cur.max_attempts),
        ));
    }
    close_stage(tx, id, cur, StageStatus::Failed)?;
    close_attempt(tx, id, cur, failure.map(|f| f.code), Some(reason))?;
    let wait = backoff_s.filter(|s| *s > 0).map(|_| WaitingFor::Backoff);
    tx.tx
        .execute(
            "UPDATE jobs SET state = 'queued', stage = NULL, lane = NULL, forgiven = ?2,
                waiting_for = ?3, waiting_since_ms = ?4, not_before_ms = ?5,
                cancel_reason = NULL, cancel_shutdown = 0 WHERE id = ?1",
            rusqlite::params![
                id.as_str(),
                forgiven,
                wait.as_ref().map(name_of),
                wait.map(|_| tx.now),
                backoff_s
                    .filter(|s| *s > 0)
                    .map(|s| tx.now + u64::from(s) * 1000),
            ],
        )
        .map_err(db)?;
    tx.emit(
        Some(id),
        EventBody::JobRequeued {
            attempt: cur.attempt,
            reason: reason.to_owned(),
        },
    )?;
    let (priority, created): (i64, u64) = tx
        .tx
        .query_row(
            "SELECT priority, created_ms FROM jobs WHERE id = ?1",
            [id.as_str()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(db)?;
    let position = queue_position(&tx.tx, id.as_str(), priority, created)?;
    tx.emit(
        Some(id),
        EventBody::JobState {
            state: JobState::Queued,
            stage: None,
            waiting_for: wait,
            attempt: cur.attempt,
            queue_position: Some(position),
        },
    )
}

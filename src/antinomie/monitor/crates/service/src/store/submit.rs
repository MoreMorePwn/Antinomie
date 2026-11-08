// SPDX-License-Identifier: GPL-3.0-only
//! `job.submit` (design 5.3, 5.4.1, 5.6): validate synchronously, then store
//! the job `queued`, or `rejected` with the failure that explains it. Shape
//! errors, an unknown policy, a full queue and the v1 restrictions are errors
//! of the call and store nothing.

use super::{
    R, Store, Tx,
    admission::{self, Reject},
    canon::canonical,
    db,
    model::{JOB_COLUMNS, JobRow, assemble, load_job, name_of, to_json},
};
use crate::{
    api::{
        error::{ApiError, ErrorCode, ErrorReason},
        event::EventBody,
        failure::{Failure, FailureCode},
        ids::JobId,
        job::{Job, JobSample, JobState, Outcome, Stage, Submitted},
        ops::{Caller, Scope},
        spec::{JobSpec, SampleSource},
    },
    clock::new_job_id,
    config::{LoadedPolicy, PolicyLookup, service::OnDuplicate},
};
use rusqlite::OptionalExtension;
use serde_json::json;

/// An idempotency key is kept for 24 hours (design 5.2).
pub const IDEMPOTENCY_WINDOW_MS: u64 = 24 * 60 * 60 * 1000;

/// The queue caps of `service.toml [queue]` (design 2.4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitLimits {
    pub max_queued: u32,
    pub per_client_queued: u32,
}

impl Default for SubmitLimits {
    fn default() -> Self {
        Self {
            max_queued: 1000,
            per_client_queued: 100,
        }
    }
}

/// Why intake refused a sample (the code of a rejected job).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeError {
    pub code: FailureCode,
    pub message: String,
}

/// The intake of design 4.2: find or archive the sample and check its size,
/// type and architecture against the policy. `actor` is the custody actor
/// (`local:<uid>`, `web:<user>`, `auto:policy-<name>`).
pub trait SampleAdmission: Send + Sync {
    fn admit(
        &self,
        source: &SampleSource,
        name: Option<&str>,
        policy: &LoadedPolicy,
        actor: &str,
    ) -> Result<JobSample, IntakeError>;
}

/// What `submit` needs besides the spec.
pub struct SubmitContext<'a> {
    pub policies: &'a dyn PolicyLookup,
    pub intake: &'a dyn SampleAdmission,
    pub limits: SubmitLimits,
    /// A watch folder's `on_duplicate` replaces the policy's.
    pub on_duplicate: Option<OnDuplicate>,
}

fn invalid(error: crate::api::spec::SpecError) -> ApiError {
    ApiError::invalid_argument(&error.field, error.message)
}

/// A reply for a remote caller carries no host path (design 5.2, 5.5): the
/// spec's `sample.path`, the recording directory, and every absolute path in
/// the text of a warning or a failure.
pub fn redact_remote(job: &mut Job) {
    job.spec.sample.path = None;
    if let Some(recording) = &mut job.recording {
        recording.directory = None;
    }
    for warning in &mut job.warnings {
        warning.text = strip_paths(&warning.text);
    }
    if let Some(failure) = &mut job.failure {
        failure.message = strip_paths(&failure.message);
        failure.detail = failure.detail.as_deref().map(strip_paths);
    }
}

fn strip_paths(text: &str) -> String {
    text.split_inclusive(char::is_whitespace)
        .map(|word| {
            let body = word.trim_end();
            let tail = &word[body.len()..];
            let core = body.trim_matches(|c: char| "\"'`(),;:".contains(c));
            if core.starts_with('/') && core[1..].contains('/') {
                body.replace(core, "<path>") + tail
            } else {
                word.to_owned()
            }
        })
        .collect()
}

impl Store {
    /// `job.submit`. Returns the stored job: `queued`, or `rejected` with its
    /// `failure`; `replayed` when an idempotency key returned the original.
    pub fn submit(&self, caller: &Caller, spec: JobSpec, ctx: &SubmitContext<'_>) -> R<Submitted> {
        if !caller.has(Scope::Submit) {
            return Err(ApiError::new(
                ErrorCode::Forbidden,
                "the caller may not submit jobs",
            ));
        }
        spec.validate_shape().map_err(invalid)?;
        let remote =
            !caller.client_id.starts_with("local:") && !caller.client_id.starts_with("auto:");
        if remote && spec.sample.path.is_some() {
            return Err(ApiError::invalid_argument(
                "sample.path",
                "sample.path is local-only; upload the file and submit sample.upload_id",
            ));
        }
        if let Some(unsupported) = spec.v1_unsupported() {
            let reason = if unsupported.reason == "live_route_not_in_v1" {
                ErrorReason::LiveRouteNotInV1
            } else {
                ErrorReason::RunModeNotInV1
            };
            return Err(ApiError::new(
                ErrorCode::Unsupported,
                format!("{} is not available in v1", unsupported.field),
            )
            .with_field(unsupported.field)
            .with_reason(reason));
        }
        let policy_name = spec.policy.clone().unwrap_or_else(|| "default".into());
        let policy = ctx
            .policies
            .get(&policy_name)
            .ok_or_else(|| ApiError::not_found("policy").with_field("policy"))?;
        let canon = canonical(&spec);

        if let Some(key) = &spec.idempotency_key {
            let conn = self.conn();
            if let Some(job) = replay(&conn, caller, key, &canon, self.now_ms())? {
                return Ok(Submitted {
                    job,
                    replayed: true,
                });
            }
        }
        self.check_queue_caps(caller, &policy, ctx.limits)?;

        // Policy ceilings, then intake (which may archive the sample).
        let resolved = admission::resolve(&spec, caller, &policy);
        let admitted = match resolved {
            Err(reject) => Err(reject),
            Ok(resolved) => ctx
                .intake
                .admit(
                    &spec.sample,
                    spec.name.as_deref(),
                    &policy,
                    &caller.client_id,
                )
                .map(|sample| (resolved, sample))
                .map_err(|e| Reject {
                    code: e.code,
                    message: e.message,
                    field: Some("sample".into()),
                }),
        };

        self.write(|tx| {
            // The check above and this transaction are not atomic: look again.
            if let Some(key) = &spec.idempotency_key
                && let Some(job) = replay(&tx.tx, caller, key, &canon, tx.now)?
            {
                return Ok(Submitted {
                    job,
                    replayed: true,
                });
            }
            let id = new_job_id(tx.now);
            match admitted {
                Err(reject) => {
                    insert_rejected(tx, &id, caller, &spec, &policy, &canon, reject)?;
                }
                Ok((resolved, sample)) => {
                    let on_duplicate = ctx
                        .on_duplicate
                        .unwrap_or(policy.policy.sample.on_duplicate);
                    let earlier = latest_finished(&tx.tx, sample.sha256.as_str())?;
                    let mut repeat_of = None;
                    if let Some(earlier) = earlier {
                        match on_duplicate {
                            OnDuplicate::Reject => {
                                let reject = Reject {
                                    code: FailureCode::DuplicateDenied,
                                    message: format!(
                                        "sample {} was already analysed (job {})",
                                        sample.sha256, earlier.id
                                    ),
                                    field: Some("sample".into()),
                                };
                                insert_rejected(tx, &id, caller, &spec, &policy, &canon, reject)?;
                                return Ok(Submitted {
                                    job: load_job(&tx.tx, id.as_str())?,
                                    replayed: false,
                                });
                            }
                            OnDuplicate::Reuse
                                if matches!(
                                    earlier.state,
                                    JobState::Succeeded | JobState::Partial
                                ) && (earlier.digest == policy.digest
                                    || policy.policy.sample.reuse_across_policies) =>
                            {
                                return Ok(Submitted {
                                    job: load_job(&tx.tx, &earlier.id)?,
                                    replayed: true,
                                });
                            }
                            OnDuplicate::Run | OnDuplicate::Reuse => {
                                repeat_of = Some(earlier.id);
                            }
                        }
                    }
                    insert_queued(
                        tx, &id, caller, &resolved, &sample, &policy, &canon, repeat_of,
                    )?;
                }
            }
            Ok(Submitted {
                job: load_job(&tx.tx, id.as_str())?,
                replayed: false,
            })
        })
        .inspect(|submitted| {
            if !submitted.replayed {
                self.write_spec_file(&submitted.job);
            }
        })
    }

    /// Queue depth and per-client caps (design 2.4.2, 4.4): the smaller of the
    /// node cap and the policy cap applies to a client.
    fn check_queue_caps(
        &self,
        caller: &Caller,
        policy: &LoadedPolicy,
        limits: SubmitLimits,
    ) -> R<()> {
        let conn = self.conn();
        let queued: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE state = 'queued'",
                [],
                |r| r.get(0),
            )
            .map_err(db)?;
        if queued >= limits.max_queued {
            return Err(ApiError::new(ErrorCode::QuotaExceeded, "the queue is full")
                .with_detail("retry_after_s", json!(60)));
        }
        let mine: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM jobs WHERE state = 'queued' AND client_id = ?1",
                [&caller.client_id],
                |r| r.get(0),
            )
            .map_err(db)?;
        let cap = limits
            .per_client_queued
            .min(policy.policy.limits.max_queued_per_client);
        if mine >= cap {
            return Err(ApiError::new(
                ErrorCode::QuotaExceeded,
                format!("this client already has {mine} queued jobs (limit {cap})"),
            )
            .with_detail("retry_after_s", json!(60)));
        }
        Ok(())
    }

    pub(super) fn write_spec_file_for(&self, job: &Job) {
        self.write_spec_file(job);
    }

    fn write_spec_file(&self, job: &Job) {
        let dir = self.job_dir(&job.id);
        let _ = super::mirror::private_dir(&dir);
        if let Ok(text) = serde_json::to_vec_pretty(&job.spec) {
            let _ = super::mirror::write_private(&dir.join("spec.json"), &text);
        }
    }

    /// Clear idempotency keys older than 24 hours (the janitor of design 5.2).
    pub fn expire_idempotency_keys(&self) -> R<u64> {
        self.write(|tx| {
            let cutoff = tx.now.saturating_sub(IDEMPOTENCY_WINDOW_MS);
            let n = tx
                .tx
                .execute(
                    "UPDATE jobs SET idempotency_key = NULL
                     WHERE idempotency_key IS NOT NULL AND created_ms <= ?1",
                    [cutoff],
                )
                .map_err(db)?;
            Ok(n as u64)
        })
    }
}

/// The original job for a key that was used within 24 hours. The same spec
/// replays it; another spec is a `conflict`. An older key is cleared.
fn replay(
    conn: &rusqlite::Connection,
    caller: &Caller,
    key: &str,
    canon: &str,
    now: u64,
) -> R<Option<Job>> {
    let found: Option<(String, String, u64)> = conn
        .query_row(
            "SELECT id, canon_json, created_ms FROM jobs WHERE client_id = ?1 AND idempotency_key = ?2",
            [&caller.client_id, key],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(db)?;
    let Some((id, stored, created_ms)) = found else {
        return Ok(None);
    };
    if now.saturating_sub(created_ms) >= IDEMPOTENCY_WINDOW_MS {
        // The key is free again; the unique index must not see it.
        conn.execute(
            "UPDATE jobs SET idempotency_key = NULL WHERE id = ?1",
            [&id],
        )
        .map_err(db)?;
        return Ok(None);
    }
    if stored != canon {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            "this idempotency key was used with another spec",
        )
        .with_field("idempotency_key")
        .with_detail("job_id", json!(id)));
    }
    load_job(conn, &id).map(Some)
}

struct Earlier {
    id: String,
    state: JobState,
    digest: String,
}

/// The newest job of this sample that ran to an end (design 4.2.2).
fn latest_finished(tx: &rusqlite::Transaction<'_>, sha256: &str) -> R<Option<Earlier>> {
    tx.query_row(
        "SELECT id, state, policy_digest FROM jobs
         WHERE sha256 = ?1 AND state IN ('succeeded', 'partial', 'failed')
         ORDER BY created_ms DESC, id DESC LIMIT 1",
        [sha256],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    )
    .optional()
    .map_err(db)?
    .map(|(id, state, digest)| {
        Ok(Earlier {
            id,
            state: super::model::from_name(&state)?,
            digest,
        })
    })
    .transpose()
}

struct NewRow<'a> {
    id: &'a JobId,
    state: JobState,
    caller: &'a Caller,
    spec: &'a JobSpec,
    canon: &'a str,
    policy: &'a LoadedPolicy,
    sample: Option<&'a JobSample>,
    failure: Option<&'a Failure>,
    repeat_of: Option<&'a str>,
}

fn insert(tx: &mut Tx<'_>, row: NewRow<'_>) -> R<()> {
    let terminal = row.state.is_terminal();
    let spec_json = to_json(row.spec)?;
    let terms = to_json(row.policy)?;
    tx.tx
        .execute(
            "INSERT INTO jobs(id, created_ms, finished_ms, state, outcome, priority, wait_s,
                policy_name, policy_digest, terms_json, sha256, max_attempts, idempotency_key,
                client_id, repeat_of, failure_code, failure_json, spec_json, canon_json,
                labels_json, sample_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17,
                ?18, ?19, ?20, ?21)",
            rusqlite::params![
                row.id.as_str(),
                tx.now,
                terminal.then_some(tx.now),
                name_of(&row.state),
                row.state.outcome().map(|o| name_of(&o)),
                row.spec.priority.unwrap_or(admission::DEFAULT_PRIORITY) as i64,
                row.policy.policy.limits.wait_s,
                row.policy.name,
                row.policy.digest,
                terms,
                row.sample.map(|s| s.sha256.as_str().to_owned()),
                row.policy.policy.retry.max_attempts,
                row.spec.idempotency_key,
                row.caller.client_id,
                row.repeat_of,
                row.failure.map(|f| name_of(&f.code)),
                row.failure.map(to_json).transpose()?,
                spec_json,
                row.canon,
                to_json(&row.spec.labels)?,
                row.sample.map(to_json).transpose()?,
            ],
        )
        .map_err(db)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn insert_queued(
    tx: &mut Tx<'_>,
    id: &JobId,
    caller: &Caller,
    resolved: &JobSpec,
    sample: &JobSample,
    policy: &LoadedPolicy,
    canon: &str,
    repeat_of: Option<String>,
) -> R<()> {
    let mut spec = resolved.clone();
    spec.sample = SampleSource {
        sha256: Some(sample.sha256.clone()),
        path: resolved.sample.path.clone(),
        upload_id: None,
    };
    insert(
        tx,
        NewRow {
            id,
            state: JobState::Queued,
            caller,
            spec: &spec,
            canon,
            policy,
            sample: Some(sample),
            failure: None,
            repeat_of: repeat_of.as_deref(),
        },
    )?;
    let job = load_job(&tx.tx, id.as_str())?;
    tx.emit(Some(id), EventBody::JobCreated { job: Box::new(job) })
}

fn insert_rejected(
    tx: &mut Tx<'_>,
    id: &JobId,
    caller: &Caller,
    spec: &JobSpec,
    policy: &LoadedPolicy,
    canon: &str,
    reject: Reject,
) -> R<()> {
    let mut failure = Failure::new(
        reject.code,
        Stage::Prechecks,
        &reject.message,
        reject
            .field
            .as_ref()
            .map(|f| format!("field: {f}"))
            .as_deref(),
    );
    failure.retryable = false;
    let mut stored = spec.clone();
    stored.policy = Some(policy.name.clone());
    insert(
        tx,
        NewRow {
            id,
            state: JobState::Rejected,
            caller,
            spec: &stored,
            canon,
            policy,
            sample: None,
            failure: Some(&failure),
            repeat_of: None,
        },
    )?;
    let job = load_job(&tx.tx, id.as_str())?;
    tx.emit(Some(id), EventBody::JobCreated { job: Box::new(job) })?;
    tx.emit(
        Some(id),
        EventBody::JobFinished {
            outcome: Outcome::Rejected,
            failure: Some(failure),
        },
    )
}

/// The `count` newest queued jobs, for the scheduler.
pub(crate) fn queued_rows(conn: &rusqlite::Connection, limit: u32) -> R<Vec<Job>> {
    let mut statement = conn
        .prepare(&format!(
            "SELECT {JOB_COLUMNS} FROM jobs WHERE state = 'queued'
             ORDER BY priority DESC, created_ms, id LIMIT ?1"
        ))
        .map_err(db)?;
    let rows: Vec<JobRow> = statement
        .query_map([limit], JobRow::read)
        .map_err(db)?
        .collect::<Result<_, _>>()
        .map_err(db)?;
    rows.into_iter().map(|row| assemble(conn, row)).collect()
}

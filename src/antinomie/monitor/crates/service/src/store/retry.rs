// SPDX-License-Identifier: GPL-3.0-only
//! `job.retry` (design 5.3): a new job from a finished job's spec. The spec is
//! the one the client sent (the canonical submitted spec, 5.2), with the
//! sample now named by its library hash (an upload or a local path was
//! consumed by the first job) and the idempotency key dropped. `overrides`
//! replace the original's override fields one by one. The new job goes through
//! the whole of `job.submit` (policy, ceilings, quotas) under the current
//! policy, except the duplicate rule: a retry asks to run again. Its
//! `repeat_of` is the old job.

use super::{R, Store, SubmitContext, db, model::from_json};
use crate::api::{
    error::{ApiError, ErrorCode},
    ids::JobId,
    job::Submitted,
    ops::{Caller, Permission},
    spec::{JobSpec, Overrides, SampleSource},
};
use serde_json::Value;

impl Store {
    /// `job.retry`. The old job must be terminal and have an archived sample.
    /// Run again is part of `runs.submit`, on a run the caller can see: its
    /// own, or any with `runs.see_all`.
    pub fn retry(
        &self,
        caller: &Caller,
        id: &JobId,
        overrides: Option<&Overrides>,
        ctx: &SubmitContext<'_>,
    ) -> R<Submitted> {
        caller.require(Permission::RunsSubmit)?;
        let old = self.get(id)?;
        if old.client_id != caller.client_id {
            caller.require(Permission::RunsSeeAll)?;
        }
        if !old.state.is_terminal() {
            return Err(ApiError::new(
                ErrorCode::PreconditionFailed,
                "only a finished job can be retried",
            )
            .with_field("job_id"));
        }
        let Some(sample) = &old.sample else {
            return Err(ApiError::new(
                ErrorCode::PreconditionFailed,
                "the job has no archived sample to run again",
            )
            .with_field("job_id"));
        };
        let canon: String = self
            .conn()
            .query_row(
                "SELECT canon_json FROM jobs WHERE id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .map_err(db)?;
        let mut value: Value = from_json(&canon)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("idempotency_key");
            if let Some(changes) = overrides {
                let changes = serde_json::to_value(changes).map_err(super::internal)?;
                let merged = object
                    .entry("overrides")
                    .or_insert_with(|| Value::Object(Default::default()));
                if let (Some(merged), Some(changes)) = (merged.as_object_mut(), changes.as_object())
                {
                    for (key, change) in changes {
                        merged.insert(key.clone(), change.clone());
                    }
                }
            }
        }
        let mut spec: JobSpec = serde_json::from_value(value)
            .map_err(|e| ApiError::invalid_argument("overrides", e.to_string()))?;
        spec.sample = SampleSource {
            sha256: Some(sample.sha256.clone()),
            path: None,
            upload_id: None,
        };
        self.submit_with(caller, spec, ctx, Some(id))
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! `run.rerun` (design 5.3; Run again in the presets specification): a new job
//! from a finished one. The spec is the one the client sent (the canonical
//! submitted spec, 5.2), with the sample now named by its library hash (an
//! upload or a local path was consumed by the first job) and the idempotency
//! key dropped. A run of an unchanged preset runs again with the preset as it
//! is now; a Custom run runs again with its resolved options (every key of
//! its frozen preset as overrides of the preset it was based on), so it is
//! Custom again. `overrides` (a partial preset) are merged on top. The new job
//! goes through the whole of `run.submit` (preset, permissions, node, limits),
//! except the duplicate rule: a retry asks to run again. Its `repeat_of` is
//! the old job. The priority is the one asked for, else the old run's within
//! the rerunning caller's `priority_max` (lowered to it when above).

use super::{R, Store, SubmitContext, db, model::from_json};
use crate::api::{
    error::{ApiError, ErrorCode},
    ids::RunId,
    ops::{Caller, Permission},
    run::Submitted,
    spec::{Overrides, RunRequest, SampleSource},
};
use serde_json::{Map, Value};

/// Merge `changes` into `into`, table by table.
fn merge(into: &mut Map<String, Value>, changes: &Map<String, Value>) {
    for (key, change) in changes {
        match (into.get_mut(key), change) {
            (Some(Value::Object(inner)), Value::Object(more)) => merge(inner, more),
            _ => {
                into.insert(key.clone(), change.clone());
            }
        }
    }
}

impl Store {
    /// `run.rerun`. The old job must be terminal and have an archived sample.
    /// Run again is part of `runs.submit`, on a run the caller can see: its
    /// own, or any with `runs.see_all`.
    pub fn retry(
        &self,
        caller: &Caller,
        id: &RunId,
        overrides: Option<&Overrides>,
        ctx: &SubmitContext<'_>,
    ) -> R<Submitted> {
        self.rerun(caller, id, None, overrides, None, ctx)
    }

    /// `run.rerun` with `preset`: the run's sample and request under another
    /// preset as it is now (its own options, not the old run's), with
    /// `overrides` on top. Without `preset`, [`Store::retry`]. `priority`
    /// replaces the old run's.
    pub fn rerun(
        &self,
        caller: &Caller,
        id: &RunId,
        preset: Option<&str>,
        overrides: Option<&Overrides>,
        priority: Option<u8>,
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
                "only a finished run can be run again",
            )
            .with_field("run_id"));
        }
        let Some(sample) = &old.sample else {
            return Err(ApiError::new(
                ErrorCode::PreconditionFailed,
                "the run has no archived sample to run again",
            )
            .with_field("run_id"));
        };
        let canon: String = self
            .conn()
            .query_row(
                "SELECT canon_json FROM jobs WHERE id = ?1",
                [id.as_str()],
                |row| row.get(0),
            )
            .map_err(db)?;
        let frozen = self.frozen_preset(id)?;
        let mut value: Value = from_json(&canon)?;
        if let Some(object) = value.as_object_mut() {
            object.remove("idempotency_key");
            if let Some(preset) = preset {
                object.insert("preset".into(), Value::String(preset.to_owned()));
                object.remove("overrides");
            } else if let Some(base) = &frozen.based_on {
                // A Custom run: its resolved options onto the preset it was
                // based on.
                object.insert("preset".into(), Value::String(base.name.clone()));
                object.insert("overrides".into(), frozen.preset.to_json());
                if let Some(Value::Object(options)) = object.get_mut("overrides") {
                    for key in crate::config::preset::NOT_RUN_OPTIONS {
                        options.remove(key);
                    }
                }
            }
            if let Some(changes) = overrides {
                let merged = object
                    .entry("overrides")
                    .or_insert_with(|| Value::Object(Default::default()));
                if let Some(merged) = merged.as_object_mut() {
                    merge(merged, &changes.0);
                }
            }
        }
        let mut spec: RunRequest = serde_json::from_value(value)
            .map_err(|e| ApiError::invalid_argument("overrides", e.to_string()))?;
        spec.sample = SampleSource {
            sha256: Some(sample.sha256.clone()),
            path: None,
            upload_id: None,
        };
        // The old run's priority was within its own caller's ceiling; the
        // rerunning caller's may be lower.
        spec.priority = priority.or_else(|| {
            spec.priority
                .map(|old| caller.limits.priority_max.map_or(old, |most| old.min(most)))
        });
        self.submit_with(caller, spec, ctx, Some(id))
    }
}

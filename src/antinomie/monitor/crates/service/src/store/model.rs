// SPDX-License-Identifier: GPL-3.0-only
//! Rows to objects and back: the `Run` of the run API is assembled from the
//! `jobs` row, the `artifacts` rows and the queue position.

use super::{R, db, internal};
use crate::{
    api::{
        artifact::{Artifact, ArtifactKind, MediaType},
        error::ApiError,
        ids::{ArtifactId, LaneId, RunId, Sha256Hex},
        ops::Permission,
        run::{PermissionUse, PresetRef, Run, RunState, Warning},
    },
    config::LoadedPreset,
};
use rusqlite::{Connection, OptionalExtension, Row};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// The wire spelling of a unit-like enum value (`"queued"`).
pub(crate) fn name_of<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub(crate) fn from_name<T: DeserializeOwned>(text: &str) -> R<T> {
    serde_json::from_value(serde_json::Value::String(text.to_owned()))
        .map_err(|e| internal(format!("unknown stored value `{text}`: {e}")))
}

pub(crate) fn from_json<T: DeserializeOwned>(text: &str) -> R<T> {
    serde_json::from_str(text).map_err(|e| internal(format!("unreadable stored object: {e}")))
}

pub(crate) fn to_json<T: Serialize>(value: &T) -> R<String> {
    serde_json::to_string(value).map_err(internal)
}

fn opt_json<T: DeserializeOwned>(text: Option<String>) -> R<Option<T>> {
    text.map(|t| from_json(&t)).transpose()
}

pub(crate) const JOB_COLUMNS: &str = "id, created_ms, started_ms, finished_ms, state, stage, outcome, \
    priority, waiting_for, policy_name, policy_digest, attempt, max_attempts, lane, client_id, \
    repeat_of, failure_json, spec_json, labels_json, sample_json, vm_json, run_json, \
    recording_json, assessment_json, warnings_json, terms_json";

/// The columns of [`JOB_COLUMNS`], read by position.
pub(crate) struct JobRow {
    pub id: String,
    pub created_ms: u64,
    pub started_ms: Option<u64>,
    pub finished_ms: Option<u64>,
    pub state: String,
    pub stage: Option<String>,
    pub outcome: Option<String>,
    pub priority: i64,
    pub waiting_for: Option<String>,
    pub policy_name: String,
    pub policy_digest: String,
    pub attempt: u32,
    pub max_attempts: u32,
    pub lane: Option<String>,
    pub client_id: String,
    pub repeat_of: Option<String>,
    pub failure_json: Option<String>,
    pub spec_json: String,
    pub labels_json: String,
    pub sample_json: Option<String>,
    pub vm_json: Option<String>,
    pub run_json: Option<String>,
    pub recording_json: Option<String>,
    pub assessment_json: Option<String>,
    pub warnings_json: String,
    pub terms_json: String,
}

/// The frozen preset as the run object shows it: the reference, every
/// resolved option and the permissions those options use.
fn frozen_parts(
    terms_json: &str,
    name: String,
    digest: String,
) -> R<(PresetRef, Value, Vec<PermissionUse>)> {
    let frozen: LoadedPreset = from_json(terms_json)?;
    let settings = serde_json::to_value(&frozen.preset).map_err(internal)?;
    let used = super::admission::permissions_used(&frozen.preset)
        .into_iter()
        .filter(|used| used.permission != Permission::RunsSubmit)
        .map(|used| PermissionUse {
            permission: used.permission,
            field: used.field.unwrap_or_default().to_owned(),
            source: "caller".to_owned(),
        })
        .collect();
    let preset = PresetRef {
        name,
        digest,
        based_on: frozen.based_on,
        changes: frozen.changes,
    };
    Ok((preset, settings, used))
}

impl JobRow {
    pub fn read(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            created_ms: row.get(1)?,
            started_ms: row.get(2)?,
            finished_ms: row.get(3)?,
            state: row.get(4)?,
            stage: row.get(5)?,
            outcome: row.get(6)?,
            priority: row.get(7)?,
            waiting_for: row.get(8)?,
            policy_name: row.get(9)?,
            policy_digest: row.get(10)?,
            attempt: row.get(11)?,
            max_attempts: row.get(12)?,
            lane: row.get(13)?,
            client_id: row.get(14)?,
            repeat_of: row.get(15)?,
            failure_json: row.get(16)?,
            spec_json: row.get(17)?,
            labels_json: row.get(18)?,
            sample_json: row.get(19)?,
            vm_json: row.get(20)?,
            run_json: row.get(21)?,
            recording_json: row.get(22)?,
            assessment_json: row.get(23)?,
            warnings_json: row.get(24)?,
            terms_json: row.get(25)?,
        })
    }

    pub fn into_job(self, queue_position: Option<u32>, artifacts: Vec<Artifact>) -> R<Run> {
        let state: RunState = from_name(&self.state)?;
        let (preset, settings, permissions_used) =
            frozen_parts(&self.terms_json, self.policy_name, self.policy_digest)?;
        Ok(Run {
            api_version: crate::API_VERSION,
            id: RunId::try_from(self.id).map_err(internal)?,
            state,
            stage: self.stage.as_deref().map(from_name).transpose()?,
            waiting_for: self.waiting_for.as_deref().map(from_name).transpose()?,
            outcome: self.outcome.as_deref().map(from_name).transpose()?,
            created_ms: self.created_ms,
            started_ms: self.started_ms,
            finished_ms: self.finished_ms,
            queue_position,
            attempt: self.attempt,
            max_attempts: self.max_attempts,
            client_id: self.client_id,
            request: from_json(&self.spec_json)?,
            sample: opt_json(self.sample_json)?,
            preset,
            settings,
            permissions_used,
            lane: self
                .lane
                .map(|lane| LaneId::try_from(lane).map_err(internal))
                .transpose()?,
            vm: opt_json(self.vm_json)?,
            program: opt_json(self.run_json)?,
            recording: opt_json(self.recording_json)?,
            assessment: opt_json(self.assessment_json)?,
            artifacts,
            warnings: from_json::<Vec<Warning>>(&self.warnings_json)?,
            failure: opt_json(self.failure_json)?,
            repeat_of: self
                .repeat_of
                .map(|id| RunId::try_from(id).map_err(internal))
                .transpose()?,
            labels: from_json(&self.labels_json)?,
            host_work: Vec::new(),
        })
    }
}

pub(crate) fn artifacts_of(conn: &Connection, job: &str) -> R<Vec<Artifact>> {
    let mut statement = conn
        .prepare(
            "SELECT id, kind, name, size, sha256, media_type, sensitive, raw_indicators, created_ms
             FROM artifacts WHERE job_id = ?1 ORDER BY created_ms, id",
        )
        .map_err(db)?;
    let rows = statement
        .query_map([job], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, bool>(6)?,
                row.get::<_, bool>(7)?,
                row.get::<_, u64>(8)?,
            ))
        })
        .map_err(db)?;
    let mut out = Vec::new();
    for row in rows {
        let (id, kind, name, size, sha256, media, sensitive, raw, created_ms) = row.map_err(db)?;
        out.push(Artifact {
            id: ArtifactId::try_from(id).map_err(internal)?,
            run_id: RunId::try_from(job.to_owned()).map_err(internal)?,
            kind: from_name::<ArtifactKind>(&kind)?,
            name,
            size,
            sha256: Sha256Hex::try_from(sha256).map_err(internal)?,
            media_type: from_name::<MediaType>(&media)?,
            sensitive,
            raw_indicators: raw,
            created_ms,
        });
    }
    Ok(out)
}

/// Where a queued job stands: 0 is next (priority, then age, then id).
pub(crate) fn queue_position(
    conn: &Connection,
    id: &str,
    priority: i64,
    created_ms: u64,
) -> R<u32> {
    conn.query_row(
        "SELECT COUNT(*) FROM jobs WHERE state = 'queued' AND (priority > ?1
            OR (priority = ?1 AND (created_ms < ?2 OR (created_ms = ?2 AND id < ?3))))",
        rusqlite::params![priority, created_ms, id],
        |row| row.get(0),
    )
    .map_err(db)
}

/// One job by id, fully assembled.
pub(crate) fn load_job(conn: &Connection, id: &str) -> R<Run> {
    let row = conn
        .query_row(
            &format!("SELECT {JOB_COLUMNS} FROM jobs WHERE id = ?1"),
            [id],
            JobRow::read,
        )
        .optional()
        .map_err(db)?
        .ok_or_else(|| ApiError::not_found("run"))?;
    assemble(conn, row)
}

pub(crate) fn assemble(conn: &Connection, row: JobRow) -> R<Run> {
    let position = (row.state == "queued")
        .then(|| queue_position(conn, &row.id, row.priority, row.created_ms))
        .transpose()?;
    let artifacts = artifacts_of(conn, &row.id)?;
    let host_work = super::host_work::items_of(conn, &row.id)?;
    let mut job = row.into_job(position, artifacts)?;
    job.host_work = host_work;
    Ok(job)
}

/// The preset a job froze at submit (its resolved options).
pub(crate) fn load_terms(conn: &Connection, id: &str) -> R<LoadedPreset> {
    let text: String = conn
        .query_row("SELECT terms_json FROM jobs WHERE id = ?1", [id], |row| {
            row.get(0)
        })
        .optional()
        .map_err(db)?
        .ok_or_else(|| ApiError::not_found("run"))?;
    from_json(&text)
}

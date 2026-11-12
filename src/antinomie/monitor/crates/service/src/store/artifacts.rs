// SPDX-License-Identifier: GPL-3.0-only
//! The `artifacts` table: files a job produced (design 5.4.4).

use super::{
    R, Store, db,
    lifecycle::{conflict, current},
    model::{artifacts_of, name_of},
};
use crate::{
    api::{
        artifact::{Artifact, ArtifactKind, MediaType},
        error::ApiError,
        event::EventBody,
        ids::{ArtifactId, JobId, Sha256Hex},
        job::JobState,
    },
    clock::new_artifact_id,
};
use rusqlite::OptionalExtension;

/// An artifact to record. `location` is relative to the job directory (or to
/// the recording, for the large kinds).
#[derive(Clone, Debug)]
pub struct NewArtifact {
    pub kind: ArtifactKind,
    pub name: String,
    pub size: u64,
    pub sha256: Sha256Hex,
    pub media_type: MediaType,
    pub raw_indicators: bool,
    pub location: String,
}

impl Store {
    /// Record an artifact of a running job and send `job.artifact`. A row of
    /// the job at the same `location` is replaced: its file was written over
    /// (a job resumed at `analyse` writes its report again under the same
    /// names), so its hash and size no longer hold (BH-22).
    pub fn add_artifact(&self, id: &JobId, new: NewArtifact) -> R<Artifact> {
        self.write(|tx| {
            let cur = current(tx, id)?;
            if !matches!(cur.state, JobState::Running | JobState::Cancelling) {
                return Err(conflict(id, cur.state, "take an artifact"));
            }
            tx.tx
                .execute(
                    "DELETE FROM artifacts WHERE job_id = ?1 AND location = ?2",
                    rusqlite::params![id.as_str(), new.location],
                )
                .map_err(db)?;
            let artifact_id = new_artifact_id(tx.now);
            tx.tx
                .execute(
                    "INSERT INTO artifacts(id, job_id, kind, name, size, sha256, media_type,
                        sensitive, raw_indicators, location, created_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                    rusqlite::params![
                        artifact_id.as_str(),
                        id.as_str(),
                        name_of(&new.kind),
                        new.name,
                        new.size,
                        new.sha256.as_str(),
                        name_of(&new.media_type),
                        new.kind.sensitive(),
                        new.raw_indicators,
                        new.location,
                        tx.now,
                    ],
                )
                .map_err(db)?;
            let artifact = Artifact {
                id: artifact_id,
                job_id: id.clone(),
                kind: new.kind,
                name: new.name,
                size: new.size,
                sha256: new.sha256,
                media_type: new.media_type,
                sensitive: new.kind.sensitive(),
                raw_indicators: new.raw_indicators,
                created_ms: tx.now,
            };
            tx.emit(
                Some(id),
                EventBody::JobArtifact {
                    artifact: artifact.clone(),
                },
            )?;
            Ok(artifact)
        })
    }

    /// `artifact.list`.
    pub fn artifacts(&self, id: &JobId) -> R<Vec<Artifact>> {
        let conn = self.conn();
        exists(&conn, id)?;
        artifacts_of(&conn, id.as_str())
    }

    /// One artifact and where its bytes are (relative to the job directory).
    pub fn artifact(&self, id: &ArtifactId) -> R<(Artifact, String)> {
        let conn = self.conn();
        let job: Option<(String, String)> = conn
            .query_row(
                "SELECT job_id, location FROM artifacts WHERE id = ?1",
                [id.as_str()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(db)?;
        let (job, location) = job.ok_or_else(|| ApiError::not_found("artifact"))?;
        let artifact = artifacts_of(&conn, &job)?
            .into_iter()
            .find(|a| &a.id == id)
            .ok_or_else(|| ApiError::not_found("artifact"))?;
        Ok((artifact, location))
    }
}

fn exists(conn: &rusqlite::Connection, id: &JobId) -> R<()> {
    let found: Option<i64> = conn
        .query_row("SELECT 1 FROM jobs WHERE id = ?1", [id.as_str()], |r| {
            r.get(0)
        })
        .optional()
        .map_err(db)?;
    found.map(|_| ()).ok_or_else(|| ApiError::not_found("job"))
}

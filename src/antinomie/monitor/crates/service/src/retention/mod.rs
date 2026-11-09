// SPDX-License-Identifier: GPL-3.0-only
//! Retention and `auto gc` (design 4.12, card P4-3).
//!
//! | Item | Rule |
//! |---|---|
//! | Recordings of auto jobs | After `recordings_days` (14), through the engine's own deletion (`samples::delete_run` with a plan, as the window does); a failed job keeps its recording until `jobs_days` while `keep_failed` is set |
//! | Size cap | Above `max_recordings_gib` (200) the oldest recordings go first (those `keep_failed` protects last) |
//! | Job records and artifacts | After `jobs_days` (90): the rows, the events and the job's folder; a job whose recording is still there loses the recording first, or stays |
//! | Staged uploads | 24 hours (the staging store's own expiry) |
//! | Rejected inbox files | 7 days |
//! | Never | A job that has not ended, its recording, a recording with an open read, a run whose artifacts are still being written, the sample library, the custody log, `processed/` |
//!
//! A pass is a plan (what would go and what is skipped, and why) that is then
//! carried out, unless it is a dry run. Every deletion is logged with the job
//! and run id. A run folder that is gone is a recording that is gone: later
//! passes do not look for it again, and the job record outlives it.
//!
//! The run folder is removed by the engine's own deletion: kept files move to
//! the library, the run's record is copied into the sample's record, and
//! captures and dumps that live elsewhere in the VM's recording stay with the
//! VM, as they do when the window deletes a run.

mod runs;
#[cfg(test)]
mod tests;

pub use runs::{RealRuns, RunState, Runs};

use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::JobId,
        job::{Job, Outcome},
    },
    config::service::Retention as RetentionConfig,
    store::Store,
};
use serde::Serialize;
use std::{
    path::PathBuf,
    time::{Duration, SystemTime},
};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// How long a rejected inbox file stays.
pub const REJECTED_DAYS: u64 = 7;

/// What a pass did or would do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Action {
    /// `recording`, `job`, `upload`, `rejected_file`.
    pub kind: String,
    pub job: Option<String>,
    pub run: Option<String>,
    pub detail: String,
    pub bytes: u64,
    /// False in a dry run, or when the deletion failed (see `errors`).
    pub done: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Skip {
    pub kind: String,
    pub job: Option<String>,
    pub why: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct GcReport {
    pub dry_run: bool,
    pub now_ms: u64,
    pub actions: Vec<Action>,
    pub skipped: Vec<Skip>,
    pub errors: Vec<String>,
    /// Bytes the actions free (or would free).
    pub freed_bytes: u64,
}

impl GcReport {
    fn skip(&mut self, kind: &str, job: &JobId, why: impl Into<String>) {
        self.skipped.push(Skip {
            kind: kind.into(),
            job: Some(job.to_string()),
            why: why.into(),
        });
    }
}

/// What a pass needs.
pub struct Retention<'a> {
    pub store: &'a Store,
    pub runs: &'a dyn Runs,
    pub config: RetentionConfig,
    /// `<inbox>/rejected`.
    pub rejected_dir: PathBuf,
    /// The staging store's expiry: what would go, and going.
    pub uploads: Option<&'a dyn Uploads>,
    pub now_ms: u64,
    pub log: &'a dyn Fn(&str),
}

/// The staged uploads past their time.
pub trait Uploads: Send + Sync {
    fn expired(&self) -> usize;
    fn expire(&self) -> usize;
}

impl Uploads for crate::intake::staging::StagingStore {
    fn expired(&self) -> usize {
        self.expired_count()
    }
    fn expire(&self) -> usize {
        crate::intake::staging::StagingStore::expire(self)
    }
}

/// The custody actor of what retention does.
pub fn actor_for(job: &Job) -> String {
    crate::custody::automation_actor(job)
}

struct Held {
    job: Job,
    bytes: u64,
    kept: bool,
    finished_ms: u64,
}

impl Retention<'_> {
    /// One pass. A failure of one item is a line in `errors`; the pass goes
    /// on with the next.
    pub fn run(&self, dry_run: bool) -> GcReport {
        let mut report = GcReport {
            dry_run,
            now_ms: self.now_ms,
            ..GcReport::default()
        };
        let finished = match self.store.finished_jobs() {
            Ok(list) => list,
            Err(error) => {
                report
                    .errors
                    .push(format!("the job list: {}", error.message));
                return report;
            }
        };
        let recordings_cut = self
            .now_ms
            .saturating_sub(u64::from(self.config.recordings_days) * DAY_MS);
        let jobs_cut = self
            .now_ms
            .saturating_sub(u64::from(self.config.jobs_days) * DAY_MS);

        // Recordings that are still there, oldest first.
        let mut held: Vec<Held> = Vec::new();
        let mut by_age: Vec<usize> = Vec::new();
        for (id, finished_ms) in &finished {
            let Ok(job) = self.store.get(id) else {
                continue;
            };
            // A job that has not ended is never touched.
            if !job.state.is_terminal() || job.recording.is_none() {
                continue;
            }
            match self.runs.inspect(&job) {
                Ok(RunState::Gone) => {}
                Ok(RunState::Present { bytes, .. }) => {
                    let kept = self.config.keep_failed && job.outcome == Some(Outcome::Failed);
                    held.push(Held {
                        job,
                        bytes,
                        kept,
                        finished_ms: *finished_ms,
                    });
                    if *finished_ms <= recordings_cut {
                        by_age.push(held.len() - 1);
                    }
                }
                Err(why) => report.skip("recording", id, format!("not readable: {why}")),
            }
        }
        let mut gone = vec![false; held.len()];

        // Rule 1: older than `recordings_days`.
        for &index in &by_age {
            if held[index].kept {
                // Kept for diagnosis until the job record goes (which takes
                // the recording with it, below).
                if held[index].finished_ms > jobs_cut {
                    let job = held[index].job.id.clone();
                    report.skip(
                        "recording",
                        &job,
                        "a failed job's recording is kept until its record goes (keep_failed)",
                    );
                }
                continue;
            }
            let why = format!("older than {} days", self.config.recordings_days);
            gone[index] = self.remove_recording(&held[index], &why, &mut report);
        }

        // Rule 2: the size cap, oldest first, the protected ones last.
        let cap = u64::from(self.config.max_recordings_gib) << 30;
        let mut remaining: u64 = held
            .iter()
            .zip(&gone)
            .filter(|(_, g)| !**g)
            .map(|(h, _)| h.bytes)
            .sum();
        if remaining > cap {
            let mut order: Vec<usize> = (0..held.len()).filter(|i| !gone[*i]).collect();
            order.sort_by_key(|i| held[*i].kept);
            for index in order {
                if remaining <= cap {
                    break;
                }
                let why = format!(
                    "the recordings are above {} GiB; oldest first",
                    self.config.max_recordings_gib
                );
                if self.remove_recording(&held[index], &why, &mut report) {
                    gone[index] = true;
                    remaining = remaining.saturating_sub(held[index].bytes);
                }
            }
        }

        // Rule 3: job records older than `jobs_days`.
        for (id, finished_ms) in &finished {
            if *finished_ms > jobs_cut {
                break;
            }
            let Ok(job) = self.store.get(id) else {
                continue;
            };
            if !job.state.is_terminal() {
                continue;
            }
            if let Some(index) = held.iter().position(|h| h.job.id == *id)
                && !gone[index]
            {
                let why = "with its job record".to_owned();
                if !self.remove_recording(&held[index], &why, &mut report) {
                    report.skip("job", id, "its recording is still there");
                    continue;
                }
                gone[index] = true;
            }
            self.remove_job(&job, &mut report);
        }

        // Rule 4: uploads and rejected files.
        if let Some(uploads) = self.uploads {
            let count = if dry_run {
                uploads.expired()
            } else {
                uploads.expire()
            };
            if count > 0 {
                report.actions.push(Action {
                    kind: "upload".into(),
                    job: None,
                    run: None,
                    detail: format!("{count} staged upload(s) past their 24 hours"),
                    bytes: 0,
                    done: !dry_run,
                });
                if !dry_run {
                    (self.log)(&format!("gc: removed {count} expired staged upload(s)"));
                }
            }
        }
        self.expire_rejected(&mut report);
        report
    }

    fn remove_recording(&self, held: &Held, why: &str, report: &mut GcReport) -> bool {
        let job = &held.job;
        let run = job.recording.as_ref().map(|r| r.run_id.clone());
        if self.runs.is_open(job) {
            report.skip("recording", &job.id, "a read of the run is open");
            return false;
        }
        match self.runs.inspect(job) {
            Ok(RunState::Present {
                in_progress: true, ..
            }) => {
                report.skip(
                    "recording",
                    &job.id,
                    "its artifacts are still being written",
                );
                return false;
            }
            Ok(RunState::Present { .. }) => {}
            Ok(RunState::Gone) => return true,
            Err(why) => {
                report.skip("recording", &job.id, format!("not readable: {why}"));
                return false;
            }
        }
        let mut action = Action {
            kind: "recording".into(),
            job: Some(job.id.to_string()),
            run: run.clone(),
            detail: why.to_owned(),
            bytes: held.bytes,
            done: false,
        };
        if report.dry_run {
            report.freed_bytes += held.bytes;
            report.actions.push(action);
            return true;
        }
        match self.runs.delete(job, &actor_for(job)) {
            Ok(_) => {
                // The run's own folder is what went (the engine's count is of
                // the artefacts it listed, not of the folder).
                let freed = held.bytes;
                action.done = true;
                report.freed_bytes += freed;
                (self.log)(&format!(
                    "gc: deleted the recording of job={} run={} ({why}), freed {freed} bytes",
                    job.id,
                    run.as_deref().unwrap_or("?")
                ));
                report.actions.push(action);
                true
            }
            Err(error) => {
                (self.log)(&format!(
                    "gc: the recording of job={} run={} was not deleted: {error}",
                    job.id,
                    run.as_deref().unwrap_or("?")
                ));
                report
                    .errors
                    .push(format!("recording of job {}: {error}", job.id));
                false
            }
        }
    }

    fn remove_job(&self, job: &Job, report: &mut GcReport) {
        let dir_bytes = crate::store::remove::folder_bytes(&self.store.job_dir(&job.id));
        let mut action = Action {
            kind: "job".into(),
            job: Some(job.id.to_string()),
            run: None,
            detail: format!("finished more than {} days ago", self.config.jobs_days),
            bytes: dir_bytes,
            done: false,
        };
        if report.dry_run {
            report.freed_bytes += dir_bytes;
            report.actions.push(action);
            return;
        }
        match self.store.delete_job(&job.id) {
            Ok(removed) => {
                action.bytes = removed.bytes;
                action.done = true;
                report.freed_bytes += removed.bytes;
                (self.log)(&format!(
                    "gc: deleted job={} (record, events and artifacts), freed {} bytes",
                    job.id, removed.bytes
                ));
                report.actions.push(action);
            }
            Err(error) => {
                (self.log)(&format!(
                    "gc: job={} was not deleted: {}",
                    job.id, error.message
                ));
                report
                    .errors
                    .push(format!("job {}: {}", job.id, error.message));
            }
        }
    }

    fn expire_rejected(&self, report: &mut GcReport) {
        let Ok(entries) = std::fs::read_dir(&self.rejected_dir) else {
            return;
        };
        let limit = Duration::from_secs(REJECTED_DAYS * 24 * 3600);
        let now = SystemTime::UNIX_EPOCH + Duration::from_millis(self.now_ms);
        let mut names: Vec<_> = entries.flatten().collect();
        names.sort_by_key(|e| e.file_name());
        for entry in names {
            let path = entry.path();
            // Plain files only; a link or a folder is left alone.
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if !meta.is_file() {
                continue;
            }
            let old = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .is_some_and(|age| age >= limit);
            if !old {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let mut action = Action {
                kind: "rejected_file".into(),
                job: None,
                run: None,
                detail: format!("{} (older than {REJECTED_DAYS} days)", clean(&name)),
                bytes: meta.len(),
                done: false,
            };
            if report.dry_run {
                report.actions.push(action);
                continue;
            }
            match std::fs::remove_file(&path) {
                Ok(()) => {
                    action.done = true;
                    (self.log)(&format!("gc: deleted the rejected file {}", clean(&name)));
                    report.actions.push(action);
                }
                Err(error) => report
                    .errors
                    .push(format!("rejected file {}: {error}", clean(&name))),
            }
        }
    }
}

/// A name for the log: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// `job.delete`: remove an ended job and, when asked, its recording first. A
/// recording with an open read, or still being written, is a `conflict` and
/// nothing is removed.
pub fn delete_job(
    store: &Store,
    runs: &dyn Runs,
    id: &JobId,
    with_recording: bool,
    log: &dyn Fn(&str),
) -> Result<(), ApiError> {
    let job = store.get(id)?;
    if !job.state.is_terminal() {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("job {id} has not ended; cancel it first"),
        )
        .with_detail("reason", serde_json::json!("invalid_transition")));
    }
    if with_recording && job.recording.is_some() {
        match runs.inspect(&job).map_err(|e| {
            ApiError::new(
                ErrorCode::Internal,
                format!("the recording is not readable: {e}"),
            )
        })? {
            RunState::Gone => {}
            RunState::Present { in_progress, .. } => {
                if runs.is_open(&job) || in_progress {
                    return Err(ApiError::recording_open("open"));
                }
                let freed = match runs.inspect(&job) {
                    Ok(RunState::Present { bytes, .. }) => bytes,
                    _ => 0,
                };
                runs.delete(&job, &actor_for(&job))
                    .map_err(|e| ApiError::new(ErrorCode::Internal, format!("recording: {e}")))?;
                log(&format!(
                    "delete: deleted the recording of job={id} run={}, freed {freed} bytes",
                    job.recording.as_ref().map_or("?", |r| r.run_id.as_str())
                ));
            }
        }
    }
    let removed = store.delete_job(id)?;
    log(&format!(
        "delete: deleted job={id}, freed {} bytes",
        removed.bytes
    ));
    Ok(())
}

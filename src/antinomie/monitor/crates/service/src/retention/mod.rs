// SPDX-License-Identifier: GPL-3.0-only
//! Retention and `auto gc` (design 4.12, card P4-3).
//!
//! | Item | Rule |
//! |---|---|
//! | Recordings of auto jobs | Each run a job's attempts recorded (an attempt retried after its launch leaves one too). After `recordings_days` (14), through the engine's own deletion (`samples::delete_run` with a plan, as the window does); a failed job keeps its recording until `jobs_days` while `keep_failed` is set |
//! | Size cap | Above `max_recordings_gib` (200) the oldest recordings go first (those `keep_failed` protects last) |
//! | Run records and artifacts | After `jobs_days` (90): the rows, the events and the job's folder; a job whose recording is still there loses the recording first, or stays; so does a job whose recording cannot be read |
//! | Static analyses of auto runs (`<data>/analyses/<id>`) | With the run's record (`jobs_days`), with `auto delete --with-recording`, and when the run's record is already gone (a plain `auto delete`, or a record removed some other way). Only the folders the `analyse` stage marked as an auto run's; an analysis from the window or `auto analyze` is never removed |
//! | Staged uploads | 24 hours (the staging store's own expiry) |
//! | Rejected inbox files | 7 days |
//! | Processed inbox files | `[inbox] processed_keep_days` (7): plain files of `inbox/processed/` older than that |
//! | Never | A job that has not ended, its recording, a recording with an open read, a run whose artifacts are still being written, the sample library, the custody log, the VM-wide captures and dumps of a deleted run |
//!
//! A pass is a plan (what would go and what is skipped, and why) that is then
//! carried out, unless it is a dry run. Every deletion is logged with the job
//! and run id. A run folder that is gone is a recording that is gone: later
//! passes do not look for it again, and the job record outlives it.
//!
//! The run folder is removed by the engine's own deletion: kept files move to
//! the library, the run's record is copied into the sample's record, and
//! captures and dumps that live elsewhere in the VM's recording stay with the
//! VM, as they do when the window deletes a run. Retention leaves those
//! VM-wide captures and dumps alone on purpose (user decision, 0.9.0): they
//! may hold the traffic or memory of other runs of the VM, so they go only
//! with the VM, or when the user removes them.

pub mod analyses;
mod runs;
#[cfg(test)]
mod tests;

pub use runs::{RealRuns, RunState, Runs};

use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::RunId,
        ops::Leftover,
        run::{Outcome, Run},
    },
    config::service::Retention as RetentionConfig,
    store::Store,
};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;
/// How long a rejected inbox file stays.
pub const REJECTED_DAYS: u64 = 7;

/// What a pass did or would do.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Action {
    /// `recording`, `run` (the run's record), `analysis` (a static analysis
    /// folder of an auto run), `upload`, `rejected_file`, `processed_file`.
    pub kind: String,
    /// The run (`r_...`).
    #[serde(rename = "run")]
    pub job: Option<String>,
    /// The recording (`vm:boot:run`).
    #[serde(rename = "recording")]
    pub run: Option<String>,
    pub detail: String,
    pub bytes: u64,
    /// False in a dry run, or when the deletion failed (see `errors`).
    pub done: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Skip {
    pub kind: String,
    #[serde(rename = "run")]
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
    fn skip(&mut self, kind: &str, job: &RunId, why: impl Into<String>) {
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
    /// `<inbox>/processed`, and the days its files stay (`[inbox]
    /// processed_keep_days`).
    pub processed_dir: PathBuf,
    pub processed_keep_days: u32,
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
pub fn actor_for(job: &Run) -> String {
    crate::custody::automation_actor(job)
}

struct Held {
    job: Run,
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

        // Recordings that are still there, oldest first: each job's run and
        // the runs its earlier attempts recorded.
        let mut held: Vec<Held> = Vec::new();
        let mut by_age: Vec<usize> = Vec::new();
        // Jobs with a recording that could not be read: their records stay
        // (rule 3), or the recording would be left with nothing naming it.
        let mut unreadable: Vec<RunId> = Vec::new();
        for (id, finished_ms) in &finished {
            let Ok(job) = self.store.get(id) else {
                continue;
            };
            // A job that has not ended is never touched.
            if !job.state.is_terminal() {
                continue;
            }
            for run in self.recordings_of(&job, &mut report) {
                match self.runs.inspect(&run) {
                    Ok(RunState::Gone) => {}
                    Ok(RunState::Present { bytes, .. }) => {
                        let kept = self.config.keep_failed && run.outcome == Some(Outcome::Failed);
                        held.push(Held {
                            job: run,
                            bytes,
                            kept,
                            finished_ms: *finished_ms,
                        });
                        if *finished_ms <= recordings_cut {
                            by_age.push(held.len() - 1);
                        }
                    }
                    Err(why) => {
                        report.skip("recording", id, format!("not readable: {why}"));
                        unreadable.push(id.clone());
                    }
                }
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
            if unreadable.contains(id) {
                report.skip(
                    "run",
                    id,
                    "its recording could not be read, so the record stays with it",
                );
                continue;
            }
            let mut stays = false;
            for index in 0..held.len() {
                if held[index].job.id != *id || gone[index] {
                    continue;
                }
                let why = "with its job record".to_owned();
                if self.remove_recording(&held[index], &why, &mut report) {
                    gone[index] = true;
                } else {
                    stays = true;
                }
            }
            if stays {
                report.skip("run", id, "its recording is still there");
                continue;
            }
            self.remove_job(&job, &mut report);
        }

        // Rule 5 (before the files, so a dry run lists it with the rest).
        self.orphaned_analyses(&mut report);

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
        self.expire_files(
            &self.rejected_dir,
            "rejected_file",
            "rejected",
            REJECTED_DAYS,
            &mut report,
        );
        self.expire_files(
            &self.processed_dir,
            "processed_file",
            "processed",
            u64::from(self.processed_keep_days),
            &mut report,
        );
        report
    }

    /// The recordings of `job` as jobs [`Runs`] can read: the job itself
    /// for the run it names, and one copy for each run an earlier attempt
    /// recorded ([`earlier_runs`]).
    fn recordings_of(&self, job: &Run, report: &mut GcReport) -> Vec<Run> {
        let mut runs = Vec::new();
        if job.recording.is_some() {
            runs.push(job.clone());
        }
        match earlier_runs(self.store, job) {
            Ok(earlier) => runs.extend(earlier),
            Err(error) => report.errors.push(format!(
                "the recordings of earlier attempts of run {}: {}",
                job.id, error.message
            )),
        }
        runs
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
                    "gc: deleted the recording of run={} recording={} ({why}), freed {freed} bytes",
                    job.id,
                    run.as_deref().unwrap_or("?")
                ));
                report.actions.push(action);
                true
            }
            Err(error) => {
                (self.log)(&format!(
                    "gc: the recording of run={} recording={} was not deleted: {error}",
                    job.id,
                    run.as_deref().unwrap_or("?")
                ));
                report
                    .errors
                    .push(format!("recording of run {}: {error}", job.id));
                false
            }
        }
    }

    fn remove_job(&self, job: &Run, report: &mut GcReport) {
        let dir_bytes = crate::store::remove::folder_bytes(&self.store.job_dir(&job.id));
        let mut action = Action {
            kind: "run".into(),
            job: Some(job.id.to_string()),
            run: None,
            detail: format!("finished more than {} days ago", self.config.jobs_days),
            bytes: dir_bytes,
            done: false,
        };
        if report.dry_run {
            report.freed_bytes += dir_bytes;
            report.actions.push(action);
            self.remove_analyses(&job.id, "with the run's record", report);
            return;
        }
        match self.store.delete_job(&job.id) {
            Ok(removed) => {
                action.bytes = removed.bytes;
                action.done = true;
                report.freed_bytes += removed.bytes;
                (self.log)(&format!(
                    "gc: deleted run={} (record, events and artifacts), freed {} bytes",
                    job.id, removed.bytes
                ));
                report.actions.push(action);
                self.remove_analyses(&job.id, "with the run's record", report);
            }
            Err(error) => {
                (self.log)(&format!(
                    "gc: run={} was not deleted: {}",
                    job.id, error.message
                ));
                report
                    .errors
                    .push(format!("run {}: {}", job.id, error.message));
            }
        }
    }

    /// The auto analysis folders of the run `id`, or of a run whose record is
    /// gone when `id` is given by [`Self::orphaned_analyses`]: removed, or in
    /// a dry run only listed.
    fn remove_analyses(&self, id: &RunId, why: &str, report: &mut GcReport) {
        let roots = self.runs.analysis_roots();
        for folder in analyses::of_run(&roots, id) {
            self.remove_analysis(&folder, why, report);
        }
    }

    fn remove_analysis(&self, folder: &analyses::Folder, why: &str, report: &mut GcReport) {
        let name = folder
            .path
            .file_name()
            .map(|n| clean(&n.to_string_lossy()))
            .unwrap_or_default();
        let mut action = Action {
            kind: "analysis".into(),
            job: Some(folder.run.clone()),
            run: None,
            detail: format!("static analysis {name} ({why})"),
            bytes: folder.bytes,
            done: false,
        };
        if report.dry_run {
            report.freed_bytes += folder.bytes;
            report.actions.push(action);
            return;
        }
        match analyses::remove(folder) {
            Ok(()) => {
                action.done = true;
                report.freed_bytes += folder.bytes;
                (self.log)(&format!(
                    "gc: deleted the static analysis {name} of run={} ({why}), freed {} bytes",
                    folder.run, folder.bytes
                ));
                report.actions.push(action);
            }
            Err(error) => report.errors.push(format!(
                "static analysis {name} of run {}: {error}",
                folder.run
            )),
        }
    }

    /// Rule 5: the analysis folders of an auto run whose record is gone.
    fn orphaned_analyses(&self, report: &mut GcReport) {
        let roots = self.runs.analysis_roots();
        for folder in analyses::marked(&roots) {
            let Ok(id) = RunId::try_from(folder.run.clone()) else {
                continue;
            };
            match self.store.get(&id) {
                Err(error) if error.code == ErrorCode::NotFound => {
                    self.remove_analysis(&folder, "its run record is gone", report);
                }
                _ => {}
            }
        }
    }

    /// Plain files of `dir` older than `days`. `kind` is the action's kind and
    /// `label` the word in its text and log line.
    fn expire_files(&self, dir: &Path, kind: &str, label: &str, days: u64, report: &mut GcReport) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        let limit = Duration::from_secs(days * 24 * 3600);
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
                kind: kind.into(),
                job: None,
                run: None,
                detail: format!("{} (older than {days} days)", clean(&name)),
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
                    (self.log)(&format!("gc: deleted the {label} file {}", clean(&name)));
                    report.actions.push(action);
                }
                Err(error) => report
                    .errors
                    .push(format!("{label} file {}: {error}", clean(&name))),
            }
        }
    }
}

/// `job` once for each run an earlier attempt recorded (BH-02): the copy
/// names that run as its recording, and the lane it ran on, so [`Runs`]
/// inspects and deletes it like the job's own.
pub fn earlier_runs(store: &Store, job: &Run) -> Result<Vec<Run>, ApiError> {
    Ok(store
        .earlier_recordings(&job.id)?
        .into_iter()
        .map(|earlier| {
            let mut run = job.clone();
            if earlier.lane.is_some() && earlier.lane != job.lane {
                // Another lane's VM: its name is not the job's.
                run.vm = None;
                run.lane = earlier.lane;
            }
            run.recording = Some(earlier.recording);
            run
        })
        .collect())
}

/// A name for the log: control characters become spaces.
fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// What `run.delete` removed and what it left, in the words of the output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deletion {
    pub removed: Vec<Leftover>,
    pub kept: Vec<Leftover>,
}

/// `run.delete`: remove an ended job and, when asked, its recording and its
/// static analyses first. A recording with an open read, or still being
/// written, is a `conflict` and nothing is removed. Without
/// `with_recording` the recording and the analyses stay, and the answer says
/// where they are and how big (`auto gc` removes the analyses of a run whose
/// record is gone; the recording goes by its own age).
pub fn delete_job(
    store: &Store,
    runs: &dyn Runs,
    id: &RunId,
    with_recording: bool,
    log: &dyn Fn(&str),
) -> Result<Deletion, ApiError> {
    let job = store.get(id)?;
    if !job.state.is_terminal() {
        return Err(ApiError::new(
            ErrorCode::Conflict,
            format!("job {id} has not ended; cancel it first"),
        )
        .with_detail("reason", serde_json::json!("invalid_transition")));
    }
    let mut deletion = Deletion::default();
    // The job's run and every run an earlier attempt recorded: all are
    // checked first, so an open or unfinished one removes nothing.
    let mut all = Vec::new();
    if job.recording.is_some() {
        all.push(job.clone());
    }
    all.extend(earlier_runs(store, &job)?);
    let mut present = Vec::new();
    for run in all {
        let state = match runs.inspect(&run) {
            Ok(state) => state,
            // A recording nobody asked to delete need not be readable.
            Err(_) if !with_recording => continue,
            Err(e) => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    format!("the recording is not readable: {e}"),
                ));
            }
        };
        match state {
            RunState::Gone => {}
            RunState::Present { in_progress, bytes } => {
                if with_recording && (runs.is_open(&run) || in_progress) {
                    return Err(ApiError::recording_open("open"));
                }
                present.push((run, bytes));
            }
        }
    }
    for (run, freed) in present {
        let path = run
            .recording
            .as_ref()
            .and_then(|r| r.directory.clone())
            .unwrap_or_default();
        let leftover = Leftover {
            what: "recording".into(),
            path,
            bytes: freed,
        };
        if with_recording {
            runs.delete(&run, &actor_for(&run))
                .map_err(|e| ApiError::new(ErrorCode::Internal, format!("recording: {e}")))?;
            log(&format!(
                "delete: deleted the recording of run={id} recording={}, freed {freed} bytes",
                run.recording.as_ref().map_or("?", |r| r.run_id.as_str())
            ));
            deletion.removed.push(leftover);
        } else {
            deletion.kept.push(leftover);
        }
    }
    let roots = runs.analysis_roots();
    for folder in analyses::of_run(&roots, id) {
        let leftover = Leftover {
            what: "analysis".into(),
            path: folder.path.display().to_string(),
            bytes: folder.bytes,
        };
        if with_recording {
            analyses::remove(&folder).map_err(|e| {
                ApiError::new(
                    ErrorCode::Internal,
                    format!("static analysis {}: {e}", folder.path.display()),
                )
            })?;
            log(&format!(
                "delete: deleted the static analysis {} of run={id}, freed {} bytes",
                folder.path.display(),
                folder.bytes
            ));
            deletion.removed.push(leftover);
        } else {
            deletion.kept.push(leftover);
        }
    }
    let removed = store.delete_job(id)?;
    log(&format!(
        "delete: deleted run={id}, freed {} bytes",
        removed.bytes
    ));
    Ok(deletion)
}

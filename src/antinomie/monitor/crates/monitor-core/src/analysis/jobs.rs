// SPDX-License-Identifier: GPL-3.0-only
use super::progress::worker_deadline;
use super::sealed;
use super::worker::REPORT_MAX_SIZE;
use super::*;
use crate::{
    control,
    sandbox_process::{self, SandboxProcess},
    storage,
};
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::OwnedFd,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

mod acquisition;
mod adopt;
mod carry;
mod host_copy;
mod host_file;
mod layers;
pub(crate) mod live;
mod sandbox_account;
mod sandbox_run;
mod specimen_publication;
mod supplement;
mod worker_exe;
mod worker_spawn;
pub(super) use adopt::adopt_listings;
pub use live::owned_here;
pub(crate) use sandbox_account::host_user_name;
use sandbox_account::sandbox_passwd;
pub(crate) use sandbox_run::{Mounts, run_sandboxed, run_sandboxed_sized, run_sandboxed_with};
pub(in crate::analysis) use supplement::carried;
pub(crate) use worker_exe::worker_executable;
use worker_spawn::*;

static CLEANUP_PENDING: AtomicBool = AtomicBool::new(false);
static CLEANUP_CHILD: Mutex<Option<CleanupOwner>> = Mutex::new(None);

struct CleanupOwner {
    process: SandboxProcess,
    directory: PathBuf,
    report: AnalysisReport,
    reason: String,
}

pub(crate) struct Job {
    pub run_id: Option<String>,
    pub report: AnalysisReport,
    pub directory: PathBuf,
    handle: Option<u64>,
    total_len: u64,
    received_len: u64,
    file: Option<File>,
    deadline: Instant,
    child: Option<SandboxProcess>,
    cleanup_reason: Option<String>,
    reserved_len: u64,
    digest: Sha256,
    disk_len: u64,
    worker_len: u64,
    report_len: u64,
    specimen_publication: Option<storage::JsonReceipt>,
    progress: progress::Watch,
    /// The uploaded file staged on the host while the guest's hash is awaited.
    host_copy: Option<host_copy::HostCopy>,
    /// Set when the job runs checks added to a finished analysis.
    pub(super) supplement: Option<supplement::Supplement>,
}
#[derive(Default)]
pub(crate) struct Jobs {
    queue: VecDeque<Job>,
    active: Option<Job>,
    /// Acquisition progresses even while the single analysis worker is busy.
    acquiring: Option<Job>,
    release: VecDeque<u64>,
    retained_len: u64,
    updates: Vec<(Option<String>, AnalysisReport)>,
    /// `<data>/tools`, mounted read-only into the worker sandbox.
    tools_dir: Option<PathBuf>,
    /// Room the last submitter said the recordings have, for the analyses of
    /// unpacked layers that follow an analysis.
    available: u64,
    /// Ids of the jobs handed on by `detach_host_side`: still running, no
    /// longer this queue's, so not orphans.
    detached: Vec<String>,
    /// Queues of finished VM sessions whose analyses go on: host-side work
    /// does not depend on the VM that produced the specimen.
    carried: Vec<Jobs>,
    /// This queue's entry in the registry of analyses the process owns.
    owner: live::Owner,
}
pub(crate) enum Action {
    Read {
        id: u64,
        offset: u64,
        total: u64,
        capacity: u32,
    },
    Release(u64),
}
pub(crate) fn new_report(path: &str, selection: &AnalysisSelection) -> AnalysisReport {
    AnalysisReport {
        id: storage::unique_id(),
        state: AnalysisState::Acquiring,
        source_path: path.into(),
        specimen_sha256: None,
        specimen_len: None,
        reason: None,
        sections: selection
            .checks
            .iter()
            .map(|&kind| AnalysisSection {
                kind,
                state: AnalysisSectionState::Pending,
                summary: "pending acquisition".into(),
                tools: Vec::new(),
                listing: None,
                disassembly: None,
                entries: Vec::new(),
                limits: Vec::new(),
            })
            .collect(),
        layer: None,
        specimen_source: None,
        time_limit_seconds: time_limit_seconds(selection.time_limit_minutes),
        limits: selection.limits.for_report(),
    }
}
pub(crate) fn fail(report: &mut AnalysisReport, state: AnalysisState, reason: impl Into<String>) {
    report.state = state;
    let mut reason = reason.into();
    if reason.len() > 4096 {
        let mut end = 4096;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    report.reason = Some(reason);
    for section in &mut report.sections {
        if matches!(
            section.state,
            AnalysisSectionState::Pending | AnalysisSectionState::Running
        ) {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = report.reason.clone().unwrap_or_default();
        }
    }
}
/// Settle a report nothing owns any more (the run never started, the VM ended,
/// the job queue was lost on restart): a report still waiting or running
/// becomes unavailable, or partial when a worker had begun, with `reason`.
/// Returns whether the report changed.
pub(crate) fn abandon(report: &mut AnalysisReport, reason: impl Into<String>) -> bool {
    let state = match report.state {
        AnalysisState::Acquiring | AnalysisState::Queued => AnalysisState::Unavailable,
        AnalysisState::Running => AnalysisState::Partial,
        _ => return false,
    };
    fail(report, state, reason);
    true
}
impl Jobs {
    /// Whether a job for report `id` is still queued, acquiring or running.
    pub(crate) fn tracks(&self, id: &str) -> bool {
        self.queue
            .iter()
            .chain(self.active.iter())
            .chain(self.acquiring.iter())
            .any(|job| job.report.id == id)
            || self.detached.iter().any(|d| d == id)
            || self.carried.iter().any(|c| c.tracks(id))
    }
    pub fn with_tools(tools_dir: PathBuf) -> Self {
        let mut jobs = Self::default();
        jobs.tools_dir = Some(tools_dir);
        jobs
    }
    pub fn stored_len(&self) -> u64 {
        self.carried
            .iter()
            .map(Jobs::stored_len)
            .sum::<u64>()
            .saturating_add(self.retained_len)
            .saturating_add(self.active.as_ref().map_or(0, |j| j.reserved_len))
            .saturating_add(self.acquiring.as_ref().map_or(0, |j| j.reserved_len))
            .saturating_add(self.queue.iter().map(|j| j.reserved_len).sum::<u64>())
    }
    pub fn persisted_len(&self) -> u64 {
        let carried: u64 = self.carried.iter().map(Jobs::persisted_len).sum();
        self.retained_len.saturating_add(carried).saturating_add(
            self.active
                .iter()
                .chain(self.acquiring.iter())
                .chain(self.queue.iter())
                .map(|job| job.disk_len.saturating_add(job.worker_len))
                .sum::<u64>(),
        )
    }
    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.queue.len()
            + usize::from(self.active.is_some())
            + usize::from(self.acquiring.is_some())
    }
    pub fn submit(
        &mut self,
        run_id: Option<String>,
        mut report: AnalysisReport,
        directory: PathBuf,
        acquisition: Result<(u64, u64), String>,
        available: u64,
    ) -> AnalysisReport {
        let mut handle = None;
        self.available = available;
        let result: Result<(), String> = (|| {
            let (id, total_len) = acquisition?;
            handle = Some(id);
            fs::create_dir_all(&directory).map_err(|e| format!("analysis directory: {e}"))?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            if self.queue.len()
                + usize::from(self.active.is_some())
                + usize::from(self.acquiring.is_some())
                >= 9
            {
                return Err("analysis queue is full (nine pending jobs)".into());
            }
            let reserved_len = total_len
                .checked_add(
                    REPORT_MAX_SIZE as u64
                        + 64 * 1024 * 1024
                        + report
                            .limits
                            .unwrap_or_default()
                            .clamped()
                            .listings_reserve()
                        + layers::extra_reserve(&report)
                        + 8192,
                )
                .ok_or("analysis quota overflow")?;
            if reserved_len > available {
                return Err("recording quota cannot reserve specimen, report and bounded worker scratch/logs".into());
            }
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(directory.join("specimen.partial"))
                .map_err(|e| e.to_string())?;
            sealed::claim(&directory);
            let job = Job {
                run_id: run_id.clone(),
                report: report.clone(),
                directory: directory.clone(),
                handle: Some(id),
                total_len,
                received_len: 0,
                file: Some(file),
                deadline: Instant::now() + acquisition::transfer_deadline(total_len),
                child: None,
                cleanup_reason: None,
                reserved_len,
                digest: Sha256::new(),
                disk_len: 0,
                worker_len: 0,
                report_len: 0,
                specimen_publication: None,
                progress: Default::default(),
                host_copy: None,
                supplement: None,
            };
            self.queue.push_back(job);
            Ok(())
        })();
        if let Err(error) = result {
            if let Some(id) = handle {
                self.release.push_back(id);
            }
            fail(&mut report, AnalysisState::Unavailable, error);
        }
        if let Err(error) = fs::create_dir_all(&directory) {
            fail(
                &mut report,
                AnalysisState::Unavailable,
                format!("analysis directory: {error}"),
            );
        }
        if available < serde_json::to_vec(&report).map_or(u64::MAX, |v| v.len() as u64) {
            fail(
                &mut report,
                AnalysisState::Unavailable,
                "recording quota exhausted; analysis report not persisted",
            );
        } else if let Err(error) = persist_report(&directory, &report) {
            fail(
                &mut report,
                AnalysisState::Unavailable,
                format!("analysis report persistence: {error}"),
            );
        }
        if report.state == AnalysisState::Unavailable {
            if let Some(index) = self.queue.iter().position(|j| j.report.id == report.id)
                && let Some(mut job) = self.queue.remove(index)
                && let Some(id) = job.handle.take()
            {
                self.release.push_back(id);
            }
            self.retained_len = self
                .retained_len
                .saturating_add(directory_len(&directory).unwrap_or(0));
        } else if let Some(job) = self.queue.iter_mut().find(|job| job.report.id == report.id) {
            job.disk_len = fs::metadata(directory.join("report.json")).map_or(0, |m| m.len());
            job.report_len = job.disk_len;
        }
        self.updates.push((run_id, report.clone()));
        self.publish();
        report
    }
    fn finish(&mut self, mut job: Job) {
        job.discard_host_copy();
        if let Some(id) = job.handle.take() {
            self.release.push_back(id);
        }
        if let Some(mut child) = job.child.take() {
            let reason = job
                .cleanup_reason
                .get_or_insert_with(|| job.report.reason.clone().unwrap_or_default())
                .clone();
            let cleanup = child.cleanup_poll();
            if matches!(cleanup, Ok(true)) {
                job.report.reason = Some(cleanup_message(&reason, "worker cleanup completed"));
            } else {
                let detail = match cleanup {
                    Err(error) => format!("worker {} cleanup pending: {error}; no new worker will start", child.id()),
                    _ => "worker cleanup pending; no new worker will start until namespace exit and reap".into(),
                };
                let message = cleanup_message(&reason, &detail);
                let changed = job.report.reason.as_deref() != Some(message.as_str());
                job.report.reason = Some(message);
                job.child = Some(child);
                if changed {
                    if let Err(error) = persist_report(&job.directory, &job.report) {
                        job.report.reason = Some(cleanup_message(
                            &reason,
                            &format!("worker cleanup pending; report persistence failed: {error}"),
                        ));
                    }
                    let report_len = fs::metadata(job.directory.join("report.json"))
                        .map_or(job.report_len, |m| m.len());
                    job.disk_len = job
                        .disk_len
                        .saturating_sub(job.report_len)
                        .saturating_add(report_len);
                    job.report_len = report_len;
                    self.updates.push((job.run_id.clone(), job.report.clone()));
                }
                self.active = Some(job);
                return;
            }
        }
        job.seal_specimen();
        sealed::release(&job.directory);
        job.merge_supplement();
        super::capa::trim_cache(self.tools_dir.as_deref());
        self.queue_layers(&mut job);
        if let Err(error) = persist_report(&job.directory, &job.report) {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                format!("analysis report persistence failed: {error}"),
            );
        }
        let retained = job.retained_len();
        self.retained_len = self.retained_len.saturating_add(retained);
        self.updates.push((job.run_id, job.report));
    }
    pub fn next(&mut self) -> Option<Action> {
        if let Some(id) = self.release.pop_front() {
            return Some(Action::Release(id));
        }
        let action = self.acquire_next();
        self.worker_tick();
        self.tick_carried();
        action
    }
    fn worker_tick(&mut self) {
        if self.active.is_none() {
            self.active = self
                .queue
                .iter()
                .position(|job| job.report.state == AnalysisState::Queued)
                .and_then(|index| self.queue.remove(index));
        }
        let Some(mut job) = self.active.take() else {
            return;
        };
        job.worker_len = ["worker.log", "output/report.json"]
            .into_iter()
            .map(|name| fs::metadata(job.directory.join(name)).map_or(0, |m| m.len()))
            .sum::<u64>()
            .saturating_add(directory_len(&job.directory.join("output/listings")).unwrap_or(0))
            .saturating_add(directory_len(&job.directory.join("output/artifacts")).unwrap_or(0))
            .saturating_add(directory_len(&job.directory.join("output/progress")).unwrap_or(0));
        if matches!(
            job.report.state,
            AnalysisState::Cancelled | AnalysisState::Partial | AnalysisState::Unavailable
        ) && job.child.is_some()
        {
            self.finish(job);
            return;
        }
        if job.child.is_some() && Instant::now() >= job.deadline {
            job.keep_finished_sections();
            let overall = worker_deadline(&job.report);
            super::limits::stop_running(&mut job.report, overall);
            fail(
                &mut job.report,
                AnalysisState::Partial,
                "analysis deadline exceeded; worker stopped and incomplete evidence retained",
            );
            self.finish(job);
            return;
        }
        if let Some(child) = job.child.as_mut() {
            match child.poll_status() {
                Ok(Some(status)) => {
                    job.child = None;
                    if status.success() {
                        match read_report(
                            &job.directory.join("output/report.json"),
                            &job.report,
                            true,
                        ) {
                            Ok(report) => {
                                job.report = report;
                                adopt_listings(
                                    &job.directory,
                                    &mut job.report,
                                    supplement::carried(&job.supplement),
                                );
                            }
                            Err(error) => fail(&mut job.report, AnalysisState::Unavailable, error),
                        }
                    } else {
                        let kept = progress::salvage(&job.directory, &mut job.report);
                        if kept {
                            adopt_listings(
                                &job.directory,
                                &mut job.report,
                                supplement::carried(&job.supplement),
                            );
                        }
                        fail(
                            &mut job.report,
                            if kept {
                                AnalysisState::Partial
                            } else {
                                AnalysisState::Unavailable
                            },
                            format!("mandatory isolated worker failed ({status}); see worker.log"),
                        );
                    }
                    self.finish(job);
                    return;
                }
                Ok(None) => {
                    if let Some(progress) = job.progress.changed(&job.directory, &job.report) {
                        progress::merge(&mut job.report, progress, false);
                        self.updates.push((job.run_id.clone(), job.report.clone()));
                    }
                    self.active = Some(job);
                    return;
                }
                Err(error) => {
                    fail(
                        &mut job.report,
                        AnalysisState::Unavailable,
                        format!("worker {} wait: {error}", child.id()),
                    );
                    self.finish(job);
                    return;
                }
            }
        }
        match spawn_worker(&job, self.tools_dir.as_deref()) {
            Ok(child) => {
                job.disk_len = job.disk_len.saturating_add(
                    fs::metadata(job.directory.join("request.json")).map_or(0, |m| m.len()),
                );
                job.child = Some(child);
                job.report.state = AnalysisState::Running;
                for section in &mut job.report.sections {
                    if section.state == AnalysisSectionState::Pending {
                        section.summary = "waiting for the analysis worker".into();
                    }
                }
                job.deadline = Instant::now() + worker_deadline(&job.report);
                self.updates.push((job.run_id.clone(), job.report.clone()));
                self.active = Some(job);
            }
            Err(error) => {
                fail(&mut job.report, AnalysisState::Unavailable, error);
                self.finish(job);
            }
        }
    }
    pub fn chunk(
        &mut self,
        result: Result<Vec<u8>, String>,
        offset: u64,
        total: u64,
        capacity: u32,
    ) {
        let Some(mut job) = self.acquiring.take() else {
            return;
        };
        let result = result.and_then(|reply| {
            control::specimen_chunk(&reply, offset, total, capacity).map(|chunk| chunk.to_vec())
        });
        match result.and_then(|chunk| {
            job.file
                .as_mut()
                .ok_or("specimen file missing")?
                .write_all(&chunk)
                .map_err(|e| e.to_string())?;
            job.digest.update(&chunk);
            job.received_len = job.received_len.saturating_add(chunk.len() as u64);
            job.disk_len = job.disk_len.saturating_add(chunk.len() as u64);
            Ok(())
        }) {
            Ok(()) => {
                // Rotate transfers so every retained guest handle makes progress.
                self.queue.push_back(job);
            }
            Err(error) => {
                fail(
                    &mut job.report,
                    AnalysisState::Unavailable,
                    format!("specimen transfer failed; incomplete capture never analyzed: {error}"),
                );
                self.finish(job);
            }
        }
    }
    pub fn updates(&mut self) -> Vec<(Option<String>, AnalysisReport)> {
        let mut updates = std::mem::take(&mut self.updates);
        for carried in &mut self.carried {
            updates.extend(carried.updates());
        }
        self.rotate_published();
        updates
    }
    pub fn cancel(&mut self, id: &str) -> Result<(), String> {
        if let Some(carried) = self.carried.iter_mut().find(|c| c.tracks(id)) {
            return carried.cancel(id);
        }
        if self.acquiring.as_ref().is_some_and(|j| j.report.id == id) {
            if let Some(mut job) = self.acquiring.take() {
                fail(
                    &mut job.report,
                    AnalysisState::Cancelled,
                    "analysis acquisition cancelled",
                );
                self.finish(job);
            }
            return Ok(());
        }
        if self.active.as_ref().is_some_and(|j| j.report.id == id) {
            if let Some(mut job) = self.active.take() {
                fail(
                    &mut job.report,
                    AnalysisState::Cancelled,
                    "analysis cancelled; program execution continues",
                );
                self.finish(job);
            }
            return Ok(());
        }
        if let Some(index) = self.queue.iter().position(|j| j.report.id == id) {
            if let Some(mut job) = self.queue.remove(index) {
                fail(
                    &mut job.report,
                    AnalysisState::Cancelled,
                    "analysis cancelled before worker start",
                );
                self.finish(job);
            }
            return Ok(());
        }
        Err("analysis job is unknown or already completed".into())
    }
    pub fn shutdown(&mut self) {
        if let Some(mut job) = self.acquiring.take() {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                "VM ended during specimen acquisition",
            );
            self.finish(job);
        }
        if let Some(mut job) = self.active.take() {
            fail(
                &mut job.report,
                AnalysisState::Partial,
                "VM ended; analysis invalidated; worker cleanup requested",
            );
            self.finish(job);
        }
        while let Some(mut job) = self.queue.pop_front() {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                "VM ended before analysis completed",
            );
            self.finish(job);
        }
        let deadline = Instant::now() + Duration::from_secs(1);
        while self.active.is_some() && Instant::now() < deadline {
            if let Some(job) = self.active.take() {
                self.finish(job);
            }
            if self.active.is_some() {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        if let Some(mut job) = self.active.take() {
            if let Some(child) = job.child.take() {
                job.report.reason = Some(
                    "VM ended; worker cleanup pending in bounded reaper, not yet reaped".into(),
                );
                CLEANUP_PENDING.store(true, Ordering::Release);
                *CLEANUP_CHILD.lock().unwrap_or_else(|p| p.into_inner()) = Some(CleanupOwner {
                    process: child,
                    directory: job.directory.clone(),
                    report: job.report.clone(),
                    reason: job.cleanup_reason.clone().unwrap_or_default(),
                });
                let directory = job.directory.clone();
                let run_id = job.run_id.clone();
                let mut pending_report = job.report.clone();
                self.finish(job);
                let spawn = std::thread::Builder::new()
                    .name("analysis-reaper".into())
                    .spawn(|| {
                        let item = CLEANUP_CHILD
                            .lock()
                            .unwrap_or_else(|p| p.into_inner())
                            .take();
                        if let Some(mut owner) = item {
                            loop {
                                let cleaned = owner.process.cleanup_poll();
                                let done = matches!(cleaned, Ok(true));
                                let detail = match cleaned {
                                    Ok(true) => "VM ended; worker cleanup completed".into(),
                                    Ok(false) => "VM ended; worker cleanup pending until namespace exit and reap".into(),
                                    Err(error) => format!("VM ended; worker cleanup pending: {error}"),
                                };
                                let message = cleanup_message(&owner.reason, &detail);
                                if owner.report.reason.as_deref() != Some(message.as_str()) {
                                    owner.report.reason = Some(message);
                                    if let Err(error) = persist_report(&owner.directory, &owner.report) {
                                        eprintln!("analysis cleanup report persistence failed: {error}");
                                    }
                                }
                                if done {
                                    if let Err(error) = sealed::seal(&owner.directory) {
                                        eprintln!("retained specimen sealing failed: {error}");
                                    }
                                    CLEANUP_PENDING.store(false, Ordering::Release);
                                    break;
                                }
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        }
                    });
                if let Err(error) = spawn {
                    pending_report.reason = Some(format!(
                        "VM ended; worker cleanup pending; reaper start failed: {error}"
                    ));
                    if let Err(error) = persist_report(&directory, &pending_report) {
                        pending_report.reason = Some(format!(
                            "reaper start and pending report persistence failed: {error}"
                        ));
                    }
                    self.updates.push((run_id, pending_report));
                }
                return;
            }
            self.finish(job);
        }
    }
}

fn cleanup_message(reason: &str, detail: &str) -> String {
    if reason.is_empty() {
        detail.into()
    } else {
        format!("{reason}; {detail}")
    }
}

impl Drop for Jobs {
    fn drop(&mut self) {
        self.shutdown();
    }
}
/// Wall-clock budget of one worker: decompilers analyze the whole program.
/// Time the durable report of an acquired specimen has to be written.
const PUBLICATION_DEADLINE: Duration = Duration::from_secs(30);

fn persist_report(directory: &Path, report: &AnalysisReport) -> Result<(), String> {
    let encoded = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    if encoded.len() > REPORT_MAX_SIZE {
        return Err("normalized report exceeded 128 KiB persistence bound".into());
    }
    storage::atomic_bytes(&directory.join("report.json"), &encoded)
}
pub(super) fn directory_len(path: &Path) -> Result<u64, String> {
    let mut total = 0u64;
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("symlink in retained analysis directory".into());
        }
        total = total.saturating_add(if metadata.is_dir() {
            directory_len(&entry.path())?
        } else {
            metadata.len()
        });
    }
    Ok(total)
}
fn stage_static_rules(job_dir: &Path) -> Result<(), String> {
    let mut cursor = Some(job_dir.to_path_buf());
    for _ in 0..8 {
        let Some(dir) = cursor else {
            return Ok(());
        };
        if dir.join("rules/registry.json").is_file() {
            return crate::ruleset::publish_static(&dir, &job_dir.join("rules"));
        }
        cursor = dir.parent().map(Path::to_path_buf);
    }
    Ok(())
}

/// `last` is the worker's final report; otherwise a progress snapshot, which
/// may still be running with sections pending.
pub(super) fn read_report(
    path: &Path,
    expected: &AnalysisReport,
    last: bool,
) -> Result<AnalysisReport, String> {
    let mut encoded = Vec::new();
    crate::archive_io::open_regular(path.parent().ok_or("worker report has no directory")?, path)
        .and_then(|f| {
            f.take((REPORT_MAX_SIZE + 1) as u64)
                .read_to_end(&mut encoded)
        })
        .map_err(|e| format!("worker report: {e}"))?;
    if encoded.len() > REPORT_MAX_SIZE {
        return Err("worker report exceeded 128 KiB bound".into());
    }
    let mut report: AnalysisReport =
        serde_json::from_slice(&encoded).map_err(|e| format!("worker report malformed: {e}"))?;
    // Only the host says where the specimen came from.
    report.specimen_source = expected.specimen_source;
    super::validation::validate_report(&report)?;
    if report.id != expected.id
        || report.source_path != expected.source_path
        || report.specimen_len != expected.specimen_len
        || report.sections.len() != expected.sections.len()
        || report
            .sections
            .iter()
            .zip(&expected.sections)
            .any(|(s, e)| {
                s.kind != e.kind
                    || s.entries.len() > 2048
                    || s.summary.len() > 4096
                    || s.entries
                        .iter()
                        .any(|e| e.label.len() > 4096 || e.value.len() > 4096)
            })
        || !(if last {
            matches!(
                report.state,
                AnalysisState::Complete | AnalysisState::Partial
            ) && report.sections.iter().all(|s| {
                !matches!(
                    s.state,
                    AnalysisSectionState::Pending | AnalysisSectionState::Running
                )
            })
        } else {
            matches!(
                report.state,
                AnalysisState::Running | AnalysisState::Partial
            )
        })
        || report.specimen_sha256 != expected.specimen_sha256
        || report.layer != expected.layer
    {
        return Err("worker report violates normalized identity/bounds contract".into());
    }
    Ok(if last { report.settled() } else { report })
}

/// Read an archived report without acquiring or analyzing its specimen again.
pub fn open_report(directory: &Path) -> Result<AnalysisReport, String> {
    let path = directory.join("report.json");
    let mut encoded = Vec::new();
    crate::archive_io::open_regular(directory, &path)
        .and_then(|f| {
            f.take((REPORT_MAX_SIZE + 1) as u64)
                .read_to_end(&mut encoded)
        })
        .map_err(|e| e.to_string())?;
    if encoded.len() > REPORT_MAX_SIZE {
        return Err("archived analysis report exceeds bound".into());
    }
    let report: AnalysisReport = serde_json::from_slice(&encoded).map_err(|e| e.to_string())?;
    super::validation::validate_report(&report)?;
    Ok(report.settled())
}
#[cfg(test)]
mod progress_tests;
#[cfg(test)]
mod tests {
    use super::*;
    fn sandbox_test_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ant-sandbox-{}", storage::unique_id()));
        storage::private_dir(&dir).unwrap();
        dir
    }
    fn sandbox_test_log(dir: &Path) -> (PathBuf, Vec<u8>) {
        let paths: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|s| s == "log"))
            .collect();
        assert_eq!(paths.len(), 1);
        let path = paths[0].clone();
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.len() <= SANDBOX_LOG_MAX_SIZE);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        (path, bytes)
    }

    #[test]
    fn queued_transfers_rotate_and_keep_the_original_acquisition_deadline() {
        let root = std::env::temp_dir().join(format!("ant-analysis-qdl-{}", storage::unique_id()));
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut jobs = Jobs::default();
        let first = new_report("/tmp/first", &selection);
        let first_id = first.id.clone();
        jobs.submit(
            Some("a".into()),
            first,
            root.join("a"),
            Ok((1, 3)),
            512 * 1024 * 1024,
        );
        jobs.submit(
            Some("b".into()),
            new_report("/tmp/second", &selection),
            root.join("b"),
            Ok((2, 3)),
            512 * 1024 * 1024,
        );
        // Do not refresh an old handle's deadline just because it waited.
        let deadline = jobs.queue[1].deadline;
        jobs.cancel(&first_id).unwrap();
        assert!(matches!(jobs.next(), Some(Action::Release(1))));
        assert!(matches!(jobs.next(), Some(Action::Read { id: 2, .. })));
        let actual = jobs.acquiring.as_ref().unwrap().deadline;
        assert_eq!(actual, deadline);
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sandbox_job_cleanup_keeps_preexec_owner_and_original_failure() {
        for cancel in [true, false] {
            let directory = sandbox_test_dir();
            let (_errors, writer) = UnixStream::pair().unwrap();
            let mut command = Command::new("/usr/bin/bwrap");
            command.args([
                "--unshare-pid",
                "--unshare-user",
                "--die-with-parent",
                "--new-session",
                "--block-fd",
                "2",
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
            ]);
            let launch = sandbox_process::prepare(&mut command).unwrap();
            command
                .args(["--", "/bin/sleep", "30"])
                .stdout(Stdio::null())
                .stderr(Stdio::from(OwnedFd::from(writer)));
            let child = command.spawn().unwrap();
            drop(command);
            let mut report = new_report("/bin/sleep", &AnalysisSelection::default());
            report.state = AnalysisState::Queued;
            let id = report.id.clone();
            let mut jobs = Jobs {
                active: Some(Job {
                    run_id: None,
                    report,
                    directory: directory.clone(),
                    handle: None,
                    total_len: 0,
                    received_len: 0,
                    file: None,
                    deadline: Instant::now() + Duration::from_secs(30),
                    child: Some(SandboxProcess::adopt(child, launch)),
                    cleanup_reason: None,
                    reserved_len: 0,
                    digest: Sha256::new(),
                    disk_len: 0,
                    worker_len: 0,
                    report_len: 0,
                    specimen_publication: None,
                    progress: Default::default(),
                    host_copy: None,
                    supplement: None,
                }),
                queue: VecDeque::new(),
                acquiring: None,
                release: VecDeque::new(),
                retained_len: 0,
                updates: Vec::new(),
                tools_dir: None,
                available: 0,
                detached: Vec::new(),
                carried: Vec::new(),
                owner: Default::default(),
            };
            let launcher = jobs.active.as_ref().unwrap().child.as_ref().unwrap().id();
            let children = PathBuf::from(format!("/proc/{launcher}/task/{launcher}/children"));
            let deadline = Instant::now() + Duration::from_secs(60);
            let pid = loop {
                if let Some(pid) = fs::read_to_string(&children)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .and_then(|pid| pid.parse::<i32>().ok())
                {
                    break rustix::process::Pid::from_raw(pid).unwrap();
                }
                assert!(
                    Instant::now() < deadline,
                    "real sandbox init was not created"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            let witness =
                rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
            let exited = || {
                let mut polls = [rustix::event::PollFd::new(
                    &witness,
                    rustix::event::PollFlags::IN,
                )];
                rustix::event::poll(
                    &mut polls,
                    Some(&rustix::event::Timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    }),
                )
                .unwrap();
                polls[0].revents().contains(rustix::event::PollFlags::IN)
            };
            if cancel {
                jobs.cancel(&id).unwrap();
            } else {
                let mut job = jobs.active.take().unwrap();
                fail(
                    &mut job.report,
                    AnalysisState::Partial,
                    "analysis deadline exceeded",
                );
                jobs.finish(job);
            }
            // The tick must not wait for the sandbox: it only asks the launcher
            // to stop, so the namespace init (sleeping 30 s) is still alive when
            // it returns. Wall time is no measure of that: the tick also writes
            // and fsyncs the report, which stalls for seconds on a loaded
            // machine.
            assert!(!exited(), "cleanup tick waited for the sandbox to die");
            assert!(
                jobs.active.is_some(),
                "one STOP request is not cleanup completion"
            );
            let deadline = Instant::now() + Duration::from_secs(60);
            while jobs.active.is_some() && Instant::now() < deadline {
                jobs.next();
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(jobs.active.is_none(), "namespace cleanup did not finish");
            assert!(exited(), "owned init survived completion");
            let report = jobs.updates().pop().unwrap().1;
            let reason = report.reason.unwrap();
            assert!(
                reason.starts_with(if cancel {
                    "analysis cancelled"
                } else {
                    "analysis deadline exceeded"
                }),
                "original failure lost: {reason}"
            );
            assert!(reason.contains("worker cleanup completed"));
            assert!(!reason.contains("cleanup pending"));
            fs::remove_dir_all(directory).unwrap();
        }
    }
    #[test]
    #[ignore = "requires installed bubblewrap/prlimit/python3 and usable user namespaces"]
    fn sandbox_failure_retains_diagnostics_and_enforces_process_limits() {
        let dir = sandbox_test_dir();
        let script = r#"import errno, mmap, os, resource, sys
assert resource.getrlimit(resource.RLIMIT_AS) == (8589934592,8589934592)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == (1024,1024)
assert resource.getrlimit(resource.RLIMIT_CORE) == (0,0)
fds=[]
try:
    for i in range(1030): fds.append(os.open('/dev/null',os.O_RDONLY))
    raise AssertionError('FD limit did not reject opens')
except OSError as e:
    assert e.errno == errno.EMFILE
finally:
    for fd in fds: os.close(fd)
try:
    mmap.mmap(-1,9*1024*1024*1024)
    raise AssertionError('AS limit did not reject mapping')
except OSError as e:
    assert e.errno == errno.ENOMEM
print('stdout diagnostic: limits enforced',flush=True)
print('stderr diagnostic: deliberate failure',file=sys.stderr,flush=True)
sys.exit(23)
"#;
        let error = run_sandboxed(
            Path::new("/usr/bin/python3"),
            &["-c".into(), script.into()],
            &dir,
            &[],
            &[],
            Duration::from_secs(10),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        let (path, bytes) = sandbox_test_log(&dir);
        let log = String::from_utf8(bytes).unwrap();
        assert!(log.contains("stdout diagnostic: limits enforced"), "{log}");
        assert!(
            log.contains("stderr diagnostic: deliberate failure"),
            "{log}"
        );
        assert!(
            error.contains("23")
                && error.contains("deliberate failure")
                && error.contains(&path.display().to_string()),
            "{error}"
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    #[ignore = "requires installed bubblewrap/prlimit/python3 and usable user namespaces"]
    fn sandbox_large_output_cancel_reaps_descendants_and_caps_log() {
        let dir = sandbox_test_dir();
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let trigger = std::sync::Arc::clone(&cancel);
        let ready = dir.join("ready");
        let cancellation = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(60);
            while !ready.is_file() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            trigger.store(true, Ordering::Relaxed);
        });
        let script = r#"import os, sys, time
if os.fork()==0:
    time.sleep(2)
    open('descendant-survived','w').write('unexpected survivor')
    os._exit(0)
for i in range(384): os.write(1,b'x'*8192)
print('\nSPAM-FINAL-DIAGNOSTIC',file=sys.stderr,flush=True)
open('ready','w').write('ready')
time.sleep(30)
"#;
        let started = Instant::now();
        let error = run_sandboxed(
            Path::new("/usr/bin/python3"),
            &["-c".into(), script.into()],
            &dir,
            &[],
            &[],
            Duration::from_secs(10),
            &cancel,
        )
        .unwrap_err();
        cancellation.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(6), "{error}");
        let (path, bytes) = sandbox_test_log(&dir);
        let log = String::from_utf8(bytes).unwrap();
        assert!(
            log.contains("output truncated") && log.contains("SPAM-FINAL-DIAGNOSTIC"),
            "{}",
            log.chars().rev().take(500).collect::<String>()
        );
        assert!(
            error.contains("cancelled")
                && error.contains("SPAM-FINAL-DIAGNOSTIC")
                && error.contains(&path.display().to_string()),
            "{error}"
        );
        std::thread::sleep(Duration::from_millis(2200));
        assert!(
            !dir.join("descendant-survived").exists(),
            "sandbox descendant survived cancellation"
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    #[ignore = "requires installed bubblewrap/prlimit/python3 and usable user namespaces"]
    fn sandbox_terminal_burst_retains_final_diagnostic_beyond_one_drain() {
        let dir = sandbox_test_dir();
        let script = r#"import os, socket, sys
stream=socket.socket(fileno=1)
stream.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,16*1024*1024)
print('TERMINAL-SOCKET-BUFFER='+str(stream.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)),file=sys.stderr,flush=True)
os.write(1,b'x'*(2*1024*1024))
os.write(2,b'\nFINAL-TERMINAL-DIAGNOSTIC\n')
os._exit(31)
"#;
        let error = run_sandboxed(
            Path::new("/usr/bin/python3"),
            &["-c".into(), script.into()],
            &dir,
            &[],
            &[],
            Duration::from_secs(10),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        let (path, bytes) = sandbox_test_log(&dir);
        let log = String::from_utf8(bytes).unwrap();
        assert!(log.contains("TERMINAL-SOCKET-BUFFER="));
        assert!(log.contains("output truncated") && log.contains("FINAL-TERMINAL-DIAGNOSTIC"));
        assert!(
            error.contains("31")
                && error.contains("FINAL-TERMINAL-DIAGNOSTIC")
                && error.contains(&path.display().to_string()),
            "{error}"
        );
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    #[ignore = "requires installed bubblewrap/prlimit/python3 and usable user namespaces"]
    fn sandbox_timeout_reaps_descendants_and_retains_diagnostics() {
        let dir = sandbox_test_dir();
        let script = r#"import os, sys, time
if os.fork()==0:
    time.sleep(1)
    open('descendant-survived','w').write('unexpected survivor')
    os._exit(0)
print('timeout diagnostic',file=sys.stderr,flush=True)
time.sleep(30)
"#;
        let error = run_sandboxed(
            Path::new("/usr/bin/python3"),
            &["-c".into(), script.into()],
            &dir,
            &[],
            &[],
            Duration::from_millis(250),
            &AtomicBool::new(false),
        )
        .unwrap_err();
        let (_, bytes) = sandbox_test_log(&dir);
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains("timeout diagnostic")
        );
        assert!(
            error.contains("timed out") && error.contains("timeout diagnostic"),
            "{error}"
        );
        std::thread::sleep(Duration::from_millis(1200));
        assert!(!dir.join("descendant-survived").exists());
        fs::remove_dir_all(dir).unwrap();
    }
    /// One real sandboxed run of `checks` on `source`: the report as the host
    /// adopts it, the directory it is kept in and the time it took.
    fn production_run(
        source: &str,
        checks: Vec<AnalysisKind>,
        limits: AnalysisLimits,
    ) -> (PathBuf, AnalysisReport, Duration) {
        let executable = PathBuf::from(
            std::env::var_os("ANTINOMIE_TEST_WORKER_BINARY").expect("set the app ELF path"),
        );
        let directory =
            std::env::temp_dir().join(format!("ant-deep-smoke-{}", storage::unique_id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let specimen = fs::read(source).unwrap();
        fs::write(directory.join("specimen"), &specimen).unwrap();
        let selection = AnalysisSelection {
            enabled: true,
            checks,
            time_limit_minutes: 0,
            limits,
        };
        let mut report = new_report(source, &selection);
        report.state = AnalysisState::Queued;
        report.specimen_len = Some(specimen.len() as u64);
        report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
        let deadline = Instant::now() + worker_deadline(&report);
        let job = Job {
            run_id: None,
            report,
            directory: directory.clone(),
            handle: None,
            total_len: specimen.len() as u64,
            received_len: specimen.len() as u64,
            file: None,
            deadline,
            child: None,
            cleanup_reason: None,
            reserved_len: 0,
            digest: Sha256::new(),
            disk_len: 0,
            worker_len: 0,
            report_len: 0,
            specimen_publication: None,
            progress: Default::default(),
            host_copy: None,
            supplement: None,
        };
        let started = Instant::now();
        let mut child = spawn_worker_binary(
            &job,
            &executable,
            std::env::var_os("ANTINOMIE_TEST_TOOLS_DIR")
                .map(PathBuf::from)
                .as_deref(),
        )
        .unwrap();
        let status = loop {
            if let Some(status) = child.poll_status().unwrap() {
                break status;
            }
            if Instant::now() >= job.deadline {
                let mut log = SandboxLog::new(&directory).unwrap();
                cleanup_sandbox(&mut child, &mut log).unwrap();
                panic!("worker exceeded its deadline; see {}", directory.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(
            status.success(),
            "worker failed; see {}/worker.log",
            directory.display()
        );
        let mut report =
            read_report(&directory.join("output/report.json"), &job.report, true).unwrap();
        adopt_listings(&directory, &mut report, &[]);
        persist_report(&directory, &report).unwrap();
        for section in &report.sections {
            eprintln!(
                "{:?}: {:?}, {} rows, listing {:?}, tools {:?}\n    {}",
                section.kind,
                section.state,
                section.entries.len(),
                section.listing,
                section.tools,
                section.summary
            );
            assert!(!section.entries.iter().any(|row| row.label == "Engine"));
        }
        (directory, report, started.elapsed())
    }
    /// Every category in the real sandbox, listings adopted and paged.
    /// ANTINOMIE_TEST_SPECIMEN picks the program (default /usr/bin/true).
    #[test]
    #[ignore = "requires the app ELF in ANTINOMIE_TEST_WORKER_BINARY, bubblewrap and minutes of CPU"]
    fn production_worker_all_categories_with_listings() {
        let source = std::env::var("ANTINOMIE_TEST_SPECIMEN").unwrap_or("/usr/bin/true".into());
        let checks = AnalysisKind::TRIAGE
            .iter()
            .chain(AnalysisKind::DEEP)
            .copied()
            .collect();
        let (directory, report, elapsed) = production_run(&source, checks, Default::default());
        if std::env::var_os("ANTINOMIE_TEST_REQUIRE_GHIDRA_PROJECT").is_some() {
            let project = super::super::retained_ghidra_project(&directory, &report.id)
                .expect("real headless Ghidra must retain its native project");
            assert!(project.is_file());
            let destination = directory.join("native-project-export");
            let exported = super::super::export_analysis(
                &directory,
                &report.id,
                Some(AnalysisKind::Decompilation),
                super::super::AnalysisExportFormat::GhidraProject,
                &destination,
            )
            .expect("actual Ghidra database must export");
            assert_eq!(exported, destination);
            assert!(destination.join("antinomie.gpr").is_file());
            assert!(destination.join("antinomie.rep").is_dir());
            assert!(project.is_file(), "export preserves retained evidence");
        }
        if std::env::var_os("ANTINOMIE_TEST_REQUIRE_GHIDRA_PROJECT").is_some() {
            // The Ghidra run also exported its disassembly beside the decompilation.
            let ghidra = report
                .sections
                .iter()
                .find(|s| s.kind == AnalysisKind::Decompilation)
                .and_then(|s| s.disassembly.as_ref())
                .expect("Ghidra exports its disassembly listing");
            assert!(ghidra.instructions > 0 && ghidra.functions > 0);
            let page = super::super::read_ghidra_disassembly_page(
                &directory,
                &report.id,
                0,
                8,
                "",
                |_| true,
            )
            .unwrap();
            assert_eq!(page.rows.len(), 8);
            eprintln!("Ghidra listing: {ghidra:?}");
        }
        let disassembly = report
            .sections
            .iter()
            .find(|s| s.kind == AnalysisKind::Disassembly)
            .unwrap();
        // With Decompilation selected there is one Ghidra run and it carries the
        // listing; the Disassembly check keeps the built-in rows only.
        assert!(disassembly.disassembly.is_none());
        let ghidra = report.ghidra_disassembly();
        // The built-in rows exist for x86 and where objdump knows the
        // architecture; Ghidra's listing covers the rest.
        assert!(
            disassembly.listing.as_ref().is_some_and(|l| l.rows > 0) || ghidra.is_some(),
            "no disassembly at all: {}",
            disassembly.summary
        );
        if disassembly.listing.is_some() {
            let page = super::super::read_listing_page(
                &directory,
                &report.id,
                AnalysisKind::Disassembly,
                0,
                8,
                "",
            )
            .unwrap();
            assert_eq!(page.rows.len(), 8);
            let found = super::super::read_listing_page(
                &directory,
                &report.id,
                AnalysisKind::Disassembly,
                0,
                4,
                "call",
            )
            .unwrap();
            assert!(
                found.total > 0 && found.rows.iter().all(|(_, row)| row.value.contains("call"))
            );
        }
        eprintln!(
            "all categories in {elapsed:?}; report {} octets; kept at {}",
            fs::metadata(directory.join("report.json")).unwrap().len(),
            directory.display()
        );
    }
    /// A Disassembly-only run starts Ghidra in listing-only mode when the
    /// setting is on, and not when it is off (ANTINOMIE_TEST_SPECIMEN picks
    /// the program; needs Ghidra in ANTINOMIE_TEST_TOOLS_DIR).
    #[test]
    #[ignore = "requires the app ELF in ANTINOMIE_TEST_WORKER_BINARY, a Ghidra tools directory and bubblewrap"]
    fn production_worker_disassembly_only_starts_ghidra_unless_the_setting_is_off() {
        let source = std::env::var("ANTINOMIE_TEST_SPECIMEN").unwrap_or("/usr/bin/true".into());
        let (directory, report, elapsed) =
            production_run(&source, vec![AnalysisKind::Disassembly], Default::default());
        let section = &report.sections[0];
        let ghidra = section.disassembly.as_ref().expect("Ghidra's listing");
        // Ghidra's listing makes up for a built-in disassembler that has none.
        assert!(
            section.listing.is_some() || section.state == AnalysisSectionState::Complete,
            "{:?} {}",
            section.state,
            section.summary
        );
        assert!(ghidra.instructions > 0 && ghidra.functions > 0);
        // No decompilation: no Decompilation section and no Ghidra project.
        assert!(
            !report
                .sections
                .iter()
                .any(|s| s.kind == AnalysisKind::Decompilation)
        );
        assert!(!directory.join("artifacts/ghidra").exists());
        let page =
            super::super::read_ghidra_disassembly_page(&directory, &report.id, 0, 8, "", |_| true)
                .unwrap();
        assert_eq!(page.rows.len(), 8);
        eprintln!("Disassembly-only run in {elapsed:?}: {ghidra:?}");
        // ANTINOMIE_TEST_KEEP=1 leaves the retained directory for a look at it.
        if std::env::var_os("ANTINOMIE_TEST_KEEP").is_some() {
            eprintln!("kept at {}", directory.display());
        } else {
            fs::remove_dir_all(&directory).unwrap();
        }
        let off = AnalysisLimits {
            ghidra_disassembly: false,
            ..AnalysisLimits::default()
        };
        let (directory, report, _) = production_run(&source, vec![AnalysisKind::Disassembly], off);
        assert!(report.sections[0].disassembly.is_none());
        assert!(report.ghidra_disassembly().is_none());
        assert!(
            super::super::read_ghidra_disassembly_page(&directory, &report.id, 0, 8, "", |_| true)
                .is_err()
        );
        if std::env::var_os("ANTINOMIE_TEST_KEEP").is_some() {
            eprintln!("kept (setting off) at {}", directory.display());
        } else {
            fs::remove_dir_all(&directory).unwrap();
        }
    }
    #[test]
    #[ignore = "requires rebuilt feature ELF in ANTINOMIE_TEST_WORKER_BINARY and working bubblewrap"]
    fn production_worker_structured_report_and_verified_preview_smoke() {
        let executable = PathBuf::from(
            std::env::var_os("ANTINOMIE_TEST_WORKER_BINARY")
                .expect("set the rebuilt feature ELF path"),
        );
        assert!(executable.is_absolute());
        let retained = std::env::var_os("ANTINOMIE_TEST_REPORT_DIRECTORY").map(PathBuf::from);
        let directory = retained.clone().unwrap_or_else(|| {
            std::env::temp_dir().join(format!("ant-structured-smoke-{}", storage::unique_id()))
        });
        fs::create_dir(&directory).expect("smoke output directory must not already exist");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let specimen = fs::read("/usr/bin/true").unwrap();
        fs::write(directory.join("specimen"), &specimen).unwrap();
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![
                AnalysisKind::Metadata,
                AnalysisKind::Structures,
                AnalysisKind::Strings,
                AnalysisKind::Entropy,
            ],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut report = new_report("/usr/bin/true", &selection);
        report.state = AnalysisState::Queued;
        report.specimen_len = Some(specimen.len() as u64);
        report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
        let job = Job {
            run_id: None,
            report,
            directory: directory.clone(),
            handle: None,
            total_len: specimen.len() as u64,
            received_len: specimen.len() as u64,
            file: None,
            deadline: Instant::now() + Duration::from_secs(15),
            child: None,
            cleanup_reason: None,
            reserved_len: 0,
            digest: Sha256::new(),
            disk_len: 0,
            worker_len: 0,
            report_len: 0,
            specimen_publication: None,
            progress: Default::default(),
            host_copy: None,
            supplement: None,
        };
        let mut child = spawn_worker_binary(
            &job,
            &executable,
            std::env::var_os("ANTINOMIE_TEST_TOOLS_DIR")
                .map(PathBuf::from)
                .as_deref(),
        )
        .unwrap();
        let status = loop {
            if let Some(status) = child.poll_status().unwrap() {
                break status;
            }
            if Instant::now() >= job.deadline {
                let mut log = SandboxLog::new(&directory).unwrap();
                let cleanup = cleanup_sandbox(&mut child, &mut log);
                panic!("worker smoke exceeded 15 seconds: cleanup {cleanup:?}");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(
            status.success(),
            "worker failed; inspect {}",
            directory.join("worker.log").display()
        );
        let report = read_report(&directory.join("output/report.json"), &job.report, true).unwrap();
        persist_report(&directory, &report).unwrap();
        assert!(
            report
                .sections
                .iter()
                .flat_map(|section| &section.entries)
                .any(|row| row
                    .record
                    .as_ref()
                    .is_some_and(|record| matches!(record.data, AnalysisData::Section { .. })))
        );
        let page = super::super::read_specimen_range(&directory, &report.id, 0, 16).unwrap();
        assert_eq!(page.data, &specimen[..16]);
        eprintln!(
            "production structured report saved at {}; {} octets; {} retained rows",
            directory.display(),
            fs::metadata(directory.join("report.json")).unwrap().len(),
            report
                .sections
                .iter()
                .map(|section| section.entries.len())
                .sum::<usize>()
        );
        if retained.is_none() {
            fs::remove_dir_all(directory).unwrap();
        }
    }
    fn structured_fixture() -> AnalysisReport {
        let mut report = new_report(
            "/tmp/sample",
            &AnalysisSelection {
                enabled: true,
                checks: vec![AnalysisKind::Strings],
                time_limit_minutes: 0,
                limits: Default::default(),
            },
        );
        report.specimen_len = Some(16);
        report.sections[0].entries.push(AnalysisEntry {
            label: "ASCII".into(),
            value: "text".into(),
            offset: Some(2),
            record: Some(AnalysisRecord {
                revision: 1,
                id: 9,
                location: Some(AnalysisLocation {
                    kind: AnalysisAddressKind::FileOffset,
                    value: 2,
                    file_range: Some(AnalysisRange { offset: 2, len: 4 }),
                }),
                data: AnalysisData::String {
                    encoding: "ASCII".into(),
                    byte_len: 4,
                    retained_len: 4,
                },
            }),
        });
        report
    }
    #[test]
    fn legacy_reports_and_valid_typed_rows_share_archive_validation() {
        let mut report = structured_fixture();
        assert!(super::validation::validate_report(&report).is_ok());
        let entry: AnalysisEntry =
            serde_json::from_str(r#"{"label":"legacy","value":"kept verbatim","offset":null}"#)
                .unwrap();
        assert!(entry.record.is_none());
        report.sections[0].entries.push(entry);
        assert!(super::validation::validate_report(&report).is_ok());
        let encoded = serde_json::to_vec(&report).unwrap();
        let reopened: AnalysisReport = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(report, reopened);
    }
    #[test]
    fn malformed_revision_ids_locations_ranges_and_string_lengths_are_rejected() {
        let valid = structured_fixture();
        let mut report = valid.clone();
        report.sections[0].entries[0]
            .record
            .as_mut()
            .unwrap()
            .revision = 2;
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0].record.as_mut().unwrap().id = 0;
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        let duplicate = report.sections[0].entries[0].clone();
        report.sections[0].entries.push(duplicate);
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0]
            .record
            .as_mut()
            .unwrap()
            .location
            .as_mut()
            .unwrap()
            .file_range = Some(AnalysisRange {
            offset: u64::MAX,
            len: 2,
        });
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0]
            .record
            .as_mut()
            .unwrap()
            .location
            .as_mut()
            .unwrap()
            .value = 3;
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::String {
            encoding: "ASCII".into(),
            byte_len: 4,
            retained_len: 3,
        };
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].kind = AnalysisKind::Metadata;
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.specimen_len = None;
        assert!(super::validation::validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::Field {
            group: "x".repeat(4097),
        };
        assert!(super::validation::validate_report(&report).is_err());
    }
    #[test]
    fn malformed_section_flags_and_entropy_measurements_are_rejected() {
        let mut report = structured_fixture();
        report.sections[0].kind = AnalysisKind::Structures;
        let record = report.sections[0].entries[0].record.as_mut().unwrap();
        record.location = None;
        record.data = AnalysisData::Section {
            name: ".text".into(),
            address: 0,
            virtual_size: 16,
            file_size: None,
            raw_flags: "0x6".into(),
            flags: vec!["EXECINSTR".into(); 65],
        };
        assert!(super::validation::validate_report(&report).is_err());
        report.sections[0].kind = AnalysisKind::Entropy;
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::Entropy {
            range: AnalysisRange { offset: 0, len: 16 },
            milli_bits: 8001,
        };
        assert!(super::validation::validate_report(&report).is_err());
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::Entropy {
            range: AnalysisRange { offset: 1, len: 16 },
            milli_bits: 3000,
        };
        assert!(super::validation::validate_report(&report).is_err());
    }
    #[test]
    fn entropy_records_are_bounded_to_whole_file_and_sixty_four_regions() {
        let mut report = structured_fixture();
        report.sections[0].kind = AnalysisKind::Entropy;
        report.sections[0].entries.clear();
        for id in 1..=66 {
            report.sections[0].entries.push(AnalysisEntry {
                label: "region".into(),
                value: "0.000".into(),
                offset: None,
                record: Some(AnalysisRecord {
                    revision: 1,
                    id,
                    location: None,
                    data: AnalysisData::Entropy {
                        range: AnalysisRange { offset: 0, len: 1 },
                        milli_bits: 0,
                    },
                }),
            });
        }
        assert!(super::validation::validate_report(&report).is_err());
        report.sections[0].entries.pop();
        assert!(super::validation::validate_report(&report).is_ok());
    }
    #[test]
    fn one_active_acquisition_and_eight_waiting_jobs_are_the_hard_bound() {
        let root =
            std::env::temp_dir().join(format!("ant-analysis-queue-{}", storage::unique_id()));
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut jobs = Jobs::default();
        jobs.submit(
            None,
            new_report("/tmp/sample", &selection),
            root.join("active"),
            Ok((1, 3)),
            u64::MAX,
        );
        assert!(matches!(jobs.next(), Some(Action::Read { .. })));
        for index in 0..8 {
            let report = jobs.submit(
                None,
                new_report("/tmp/sample", &selection),
                root.join(format!("queued-{index}")),
                Ok((index + 2, 3)),
                u64::MAX,
            );
            assert_eq!(report.state, AnalysisState::Acquiring);
        }
        assert_eq!(jobs.pending_count(), 9);
        let rejected = jobs.submit(
            None,
            new_report("/tmp/sample", &selection),
            root.join("rejected"),
            Ok((20, 3)),
            u64::MAX,
        );
        assert_eq!(rejected.state, AnalysisState::Unavailable);
        assert_eq!(jobs.pending_count(), 9);
        assert!(jobs.persisted_len() < jobs.stored_len());
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn quota_and_cancel_keep_program_independent_and_reopen_typed_reports() {
        let root = std::env::temp_dir().join(format!("ant-analysis-{}", storage::unique_id()));
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut jobs = Jobs::default();
        let report = new_report("/tmp/sample", &selection);
        let unavailable = jobs.submit(
            Some("run".into()),
            report,
            root.join("quota"),
            Ok((1, 3)),
            0,
        );
        assert_eq!(unavailable.state, AnalysisState::Unavailable);
        assert_eq!(jobs.pending_count(), 0);
        let report = new_report("/tmp/sample", &selection);
        let id = report.id.clone();
        jobs.submit(
            Some("run".into()),
            report,
            root.join("cancel"),
            Ok((2, 3)),
            512 * 1024 * 1024,
        );
        assert_eq!(jobs.pending_count(), 1);
        jobs.cancel(&id).unwrap();
        assert_eq!(jobs.pending_count(), 0);
        assert_eq!(
            open_report(&root.join("cancel")).unwrap().state,
            AnalysisState::Cancelled
        );
        assert!(jobs.cancel(&id).is_err());
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn malformed_chunk_does_not_publish_or_analyze_partial_specimen() {
        let root =
            std::env::temp_dir().join(format!("ant-analysis-chunk-{}", storage::unique_id()));
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        };
        let mut jobs = Jobs::default();
        jobs.submit(
            None,
            new_report("/tmp/sample", &selection),
            root.clone(),
            Ok((1, 3)),
            512 * 1024 * 1024,
        );
        assert!(matches!(jobs.next(), Some(Action::Read { .. })));
        jobs.chunk(Ok(vec![0; 4]), 0, 3, 3);
        assert_eq!(jobs.pending_count(), 0);
        assert!(!root.join("specimen").exists());
        assert_eq!(
            open_report(&root).unwrap().state,
            AnalysisState::Unavailable
        );
        drop(jobs);
        fs::remove_dir_all(root).unwrap();
    }
}

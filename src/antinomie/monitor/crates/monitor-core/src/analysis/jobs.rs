// SPDX-License-Identifier: MIT
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
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
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
}
#[derive(Default)]
pub(crate) struct Jobs {
    queue: VecDeque<Job>,
    active: Option<Job>,
    release: VecDeque<u64>,
    retained_len: u64,
    updates: Vec<(Option<String>, AnalysisReport)>,
    /// `<data>/tools`, mounted read-only into the worker sandbox.
    tools_dir: Option<PathBuf>,
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
                entries: Vec::new(),
            })
            .collect(),
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
        if section.state == AnalysisSectionState::Pending {
            section.state = AnalysisSectionState::Unavailable;
            section.summary = report.reason.clone().unwrap_or_default();
        }
    }
}
impl Jobs {
    pub fn with_tools(tools_dir: PathBuf) -> Self {
        let mut jobs = Self::default();
        jobs.tools_dir = Some(tools_dir);
        jobs
    }
    pub fn stored_len(&self) -> u64 {
        self.retained_len
            .saturating_add(self.active.as_ref().map_or(0, |j| j.reserved_len))
            .saturating_add(self.queue.iter().map(|j| j.reserved_len).sum::<u64>())
    }
    pub fn persisted_len(&self) -> u64 {
        self.retained_len.saturating_add(
            self.active
                .iter()
                .chain(self.queue.iter())
                .map(|job| job.disk_len.saturating_add(job.worker_len))
                .sum::<u64>(),
        )
    }
    #[cfg(test)]
    pub fn pending_count(&self) -> usize {
        self.queue.len() + usize::from(self.active.is_some())
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
        let result: Result<(), String> = (|| {
            let (id, total_len) = acquisition?;
            handle = Some(id);
            fs::create_dir_all(&directory).map_err(|e| format!("analysis directory: {e}"))?;
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            if self.queue.len() >= 8 {
                return Err("analysis queue is full (eight waiting jobs)".into());
            }
            let reserved_len = total_len
                .checked_add(
                    REPORT_MAX_SIZE as u64
                        + 64 * 1024 * 1024
                        + super::listing::LISTINGS_MAX_TOTAL
                        + if report
                            .sections
                            .iter()
                            .any(|section| section.kind == AnalysisKind::Decompilation)
                        {
                            super::export::PROJECT_MAX_SIZE
                        } else {
                            0
                        }
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
            let job = Job {
                run_id: run_id.clone(),
                report: report.clone(),
                directory: directory.clone(),
                handle: Some(id),
                total_len,
                received_len: 0,
                file: Some(file),
                deadline: Instant::now() + Duration::from_secs(120),
                child: None,
                cleanup_reason: None,
                reserved_len,
                digest: Sha256::new(),
                disk_len: 0,
                worker_len: 0,
                report_len: 0,
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
        report
    }
    fn finish(&mut self, mut job: Job) {
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
        if let Err(error) = persist_report(&job.directory, &job.report) {
            fail(
                &mut job.report,
                AnalysisState::Unavailable,
                format!("analysis report persistence failed: {error}"),
            );
        }
        let retained = directory_len(&job.directory).unwrap_or(job.reserved_len);
        self.retained_len = self.retained_len.saturating_add(retained);
        self.updates.push((job.run_id, job.report));
    }
    pub fn next(&mut self) -> Option<Action> {
        if let Some(id) = self.release.pop_front() {
            return Some(Action::Release(id));
        }
        if self.active.is_none() {
            self.active = self.queue.pop_front();
        }
        let mut job = self.active.take()?;
        job.worker_len = ["worker.log", "output/report.json"]
            .into_iter()
            .map(|name| fs::metadata(job.directory.join(name)).map_or(0, |m| m.len()))
            .sum::<u64>()
            .saturating_add(directory_len(&job.directory.join("output/listings")).unwrap_or(0))
            .saturating_add(directory_len(&job.directory.join("output/artifacts")).unwrap_or(0));
        if matches!(
            job.report.state,
            AnalysisState::Cancelled | AnalysisState::Partial | AnalysisState::Unavailable
        ) && job.child.is_some()
        {
            self.finish(job);
            return None;
        }
        if Instant::now() >= job.deadline {
            fail(
                &mut job.report,
                AnalysisState::Partial,
                "analysis deadline exceeded; worker stopped and incomplete evidence retained",
            );
            self.finish(job);
            return None;
        }
        if let Some(child) = job.child.as_mut() {
            match child.poll_status() {
                Ok(Some(status)) => {
                    job.child = None;
                    if status.success() {
                        match read_report(&job.directory.join("output/report.json"), &job.report) {
                            Ok(report) => {
                                job.report = report;
                                adopt_listings(&job.directory, &mut job.report);
                            }
                            Err(error) => fail(&mut job.report, AnalysisState::Unavailable, error),
                        }
                    } else {
                        fail(
                            &mut job.report,
                            AnalysisState::Unavailable,
                            format!("mandatory isolated worker failed ({status}); see worker.log"),
                        );
                    }
                    self.finish(job);
                    return None;
                }
                Ok(None) => {
                    self.active = Some(job);
                    return None;
                }
                Err(error) => {
                    fail(
                        &mut job.report,
                        AnalysisState::Unavailable,
                        format!("worker {} wait: {error}", child.id()),
                    );
                    self.finish(job);
                    return None;
                }
            }
        }
        if job.received_len < job.total_len {
            let action = Action::Read {
                id: job.handle?,
                offset: job.received_len,
                total: job.total_len,
                capacity: (job.total_len - job.received_len)
                    .min(u64::from(control::SPECIMEN_CHUNK_SIZE)) as u32,
            };
            self.active = Some(job);
            return Some(action);
        }
        if let Some(file) = job.file.take() {
            let result = file.sync_all().and_then(|_| {
                fs::rename(
                    job.directory.join("specimen.partial"),
                    job.directory.join("specimen"),
                )
            });
            if let Err(error) = result {
                fail(
                    &mut job.report,
                    AnalysisState::Unavailable,
                    format!("specimen publication: {error}"),
                );
                self.finish(job);
                return None;
            }
        }
        if let Some(id) = job.handle.take() {
            self.release.push_back(id);
        }
        job.report.state = AnalysisState::Queued;
        job.report.specimen_len = Some(job.total_len);
        job.report.specimen_sha256 = Some(format!("{:x}", job.digest.clone().finalize()));
        match spawn_worker(&job, self.tools_dir.as_deref()) {
            Ok(child) => {
                job.disk_len = job.disk_len.saturating_add(
                    fs::metadata(job.directory.join("request.json")).map_or(0, |m| m.len()),
                );
                job.child = Some(child);
                job.report.state = AnalysisState::Running;
                job.deadline = Instant::now() + worker_deadline(&job.report);
                self.updates.push((job.run_id.clone(), job.report.clone()));
                self.active = Some(job);
            }
            Err(error) => {
                fail(&mut job.report, AnalysisState::Unavailable, error);
                self.finish(job);
            }
        }
        None
    }
    pub fn chunk(
        &mut self,
        result: Result<Vec<u8>, String>,
        offset: u64,
        total: u64,
        capacity: u32,
    ) {
        let Some(mut job) = self.active.take() else {
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
            Ok(()) => self.active = Some(job),
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
        std::mem::take(&mut self.updates)
    }
    pub fn cancel(&mut self, id: &str) -> Result<(), String> {
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
pub(crate) fn worker_deadline(report: &AnalysisReport) -> Duration {
    let has = |kind| report.sections.iter().any(|s| s.kind == kind);
    Duration::from_secs(if has(AnalysisKind::Decompilation) {
        super::worker::DECOMPILER_SECONDS + 120
    } else if has(AnalysisKind::Disassembly) || has(AnalysisKind::Capabilities) {
        300
    } else {
        60
    })
}
/// Move validated worker listings next to the report; a listing that fails
/// validation is dropped and its category marked partial.
fn adopt_listings(directory: &Path, report: &mut AnalysisReport) {
    let output = directory.join("output/listings");
    let target = directory.join("listings");
    let mut total = 0u64;
    let total_len = report.specimen_len;
    for section in &mut report.sections {
        let Some(listing) = section.listing.clone() else {
            continue;
        };
        let name = super::listing::file_name(section.kind);
        total = total.saturating_add(listing.bytes);
        let result = if total > super::listing::LISTINGS_MAX_TOTAL {
            Err("listings exceed their combined bound".to_string())
        } else {
            super::listing::validate(&output.join(name), section.kind, &listing, total_len)
                .and_then(|()| {
                    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o700))
                        .map_err(|e| e.to_string())?;
                    fs::rename(output.join(name), target.join(name)).map_err(|e| e.to_string())
                })
        };
        if let Err(error) = result {
            section.listing = None;
            section.state = AnalysisSectionState::Partial;
            section.summary = format!("{}; full listing rejected: {error}", section.summary);
            if section.summary.len() > 4096 {
                section.summary.truncate(4000);
            }
        }
    }
    let _ = fs::remove_dir_all(&output);
}
fn persist_report(directory: &Path, report: &AnalysisReport) -> Result<(), String> {
    let encoded = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    if encoded.len() > REPORT_MAX_SIZE {
        return Err("normalized report exceeded 128 KiB persistence bound".into());
    }
    storage::atomic_bytes(&directory.join("report.json"), &encoded)
}
fn directory_len(path: &Path) -> Result<u64, String> {
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

fn spawn_worker(job: &Job, tools: Option<&Path>) -> Result<SandboxProcess, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    spawn_worker_binary(job, &executable, tools)
}
fn spawn_worker_binary(
    job: &Job,
    executable: &Path,
    tools: Option<&Path>,
) -> Result<SandboxProcess, String> {
    crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
    if CLEANUP_PENDING.load(Ordering::Acquire) {
        return Err("a previous worker still awaits reap; isolation worker unavailable".into());
    }
    let account = sandbox_passwd(&job.directory)?;
    let output = job.directory.join("output");
    fs::create_dir(&output).map_err(|e| e.to_string())?;
    let listings = output.join("listings");
    fs::create_dir(&listings).map_err(|e| e.to_string())?;
    fs::set_permissions(&listings, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let artifacts = output.join("artifacts");
    fs::create_dir(&artifacts).map_err(|e| e.to_string())?;
    fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let has = |kind| job.report.sections.iter().any(|s| s.kind == kind);
    let decompiler = has(AnalysisKind::Decompilation);
    // capa unpacks itself into /tmp before it runs.
    let tmp_size = if decompiler {
        "2147483648"
    } else if has(AnalysisKind::Capabilities) {
        "1073741824"
    } else {
        "33554432"
    };
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(output.join("report.json"))
        .map_err(|e| e.to_string())?;
    storage::atomic_json(&job.directory.join("request.json"), &job.report)?;
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(job.directory.join("worker.log"))
        .map_err(|e| e.to_string())?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args([
        "--unshare-all",
        // A neutral host name: tools log it, and logs are kept.
        "--hostname",
        "analysis",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    // Read-only system configuration the optional tools need: the Java
    // runtime of a decompiler resolves itself through these.
    // Merged-/usr systems keep /bin, /sbin and /lib as links into /usr; tool
    // scripts start with #!/bin/sh, so recreate the links.
    for path in ["/bin", "/sbin", "/lib", "/lib64"] {
        if let Ok(target) = fs::read_link(path) {
            cmd.arg("--symlink").arg(target).arg(path);
        }
    }
    for path in [
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/java-17-openjdk",
        "/etc/java-21-openjdk",
        "/etc/ld.so.cache",
    ] {
        if Path::new(path).exists() && fs::read_link(path).is_err() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    cmd.arg("--ro-bind").arg(&account).arg("/etc/passwd");
    for path in [
        "/usr/lib/bfd-plugins",
        "/usr/lib/x86_64-linux-gnu/bfd-plugins",
    ] {
        if Path::new(path).is_dir() {
            cmd.args(["--size", "4096", "--tmpfs", path, "--remount-ro", path]);
        }
    }
    cmd.args([
        "--proc",
        "/proc",
        "--dir",
        "/dev",
        "--dev-bind",
        "/dev/null",
        "/dev/null",
        "--dev-bind",
        "/dev/urandom",
        "/dev/urandom",
        "--dev-bind",
        "/dev/random",
        "/dev/random",
        // Shell process substitution (the decompiler's launcher) needs these.
        "--symlink",
        "/proc/self/fd",
        "/dev/fd",
        "--symlink",
        "/proc/self/fd/0",
        "/dev/stdin",
        "--symlink",
        "/proc/self/fd/1",
        "/dev/stdout",
        "--symlink",
        "/proc/self/fd/2",
        "/dev/stderr",
        "--size",
    ])
    // A decompiler keeps its project database in /tmp.
    .arg(tmp_size)
    .args([
        "--tmpfs",
        "/tmp",
        "--dir",
        "/input",
        "--size",
        "33554432",
        "--tmpfs",
        "/output",
        "--ro-bind",
    ])
    .arg(executable)
    .arg("/worker")
    .arg("--ro-bind")
    .arg(job.directory.join("specimen"))
    .arg("/input/specimen");
    stage_static_rules(&job.directory)?;
    let rules = job.directory.join("rules");
    if rules.is_dir() {
        cmd.arg("--ro-bind").arg(&rules).arg("/input/rules");
    }
    cmd.arg("--ro-bind")
        .arg(job.directory.join("request.json"))
        .arg("/input/request.json")
        .arg("--bind")
        .arg(output.join("report.json"))
        .arg("/output/report.json")
        .arg("--bind")
        .arg(&listings)
        .arg("/output/listings")
        .arg("--bind")
        .arg(&artifacts)
        .arg("/output/artifacts");
    // Analysis tools Antinomie installed, read-only.
    if let Some(tools) = tools.filter(|tools| tools.is_dir()) {
        cmd.arg("--ro-bind")
            .arg(tools)
            .arg(crate::analysis_tools::SANDBOX_DIR);
    }
    if std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed") {
        cmd.args(["--setenv", "ANTINOMIE_ANALYSIS_TOOLS", "managed"]);
    }
    let launch = sandbox_process::prepare(&mut cmd)?;
    cmd.args([
        "--remount-ro",
        "/",
        "--setenv",
        "ANTINOMIE_ISOLATED_WORKER",
        "1",
        "--setenv",
        "LC_ALL",
        "C",
        "--setenv",
        "HOME",
        "/nonexistent",
        "--chdir",
        "/output",
        "--",
        "/worker",
        "--antinomie-analysis-worker",
    ])
    .env_clear()
    .stdout(Stdio::null())
    .stderr(Stdio::from(log));
    let spawned = cmd.spawn();
    drop(cmd);
    spawned
        .map(|child| SandboxProcess::adopt(child, launch))
        .map_err(|e| format!("mandatory bubblewrap isolation unavailable: {e}"))
}

/// Run an external analysis tool inside the same bubblewrap isolation as the
/// static-analysis worker. The host process is `bwrap`, not the tool itself.
/// A private, unique log retains at most 2 MiB, including the final output tail.
/// Limits apply to each descendant process, not aggregate process-tree RSS.
pub(crate) fn run_sandboxed(
    program: &Path,
    args: &[String],
    writable: &Path,
    extra_read_only: &[PathBuf],
    env: &[(&str, &str)],
    timeout: Duration,
    cancel: &AtomicBool,
) -> Result<(), String> {
    crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
    crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "prlimit")?;
    let account = sandbox_passwd(writable)?;
    let mut log = SandboxLog::new(writable)?;
    let (mut reader, writer) = UnixStream::pair().map_err(|e| e.to_string())?;
    reader.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stderr = writer.try_clone().map_err(|e| e.to_string())?;
    let mut cmd = Command::new("/usr/bin/bwrap");
    cmd.args([
        "--unshare-all",
        "--hostname",
        "analysis",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    for path in ["/bin", "/sbin", "/lib", "/lib64"] {
        if let Ok(target) = fs::read_link(path) {
            cmd.arg("--symlink").arg(target).arg(path);
        }
    }
    for path in [
        "/lib",
        "/lib64",
        "/etc/alternatives",
        "/etc/java-17-openjdk",
        "/etc/java-21-openjdk",
        "/etc/ld.so.cache",
    ] {
        if Path::new(path).exists() && fs::read_link(path).is_err() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    cmd.arg("--ro-bind").arg(&account).arg("/etc/passwd");
    cmd.args([
        "--proc",
        "/proc",
        "--dir",
        "/dev",
        "--dev-bind",
        "/dev/null",
        "/dev/null",
        "--dev-bind",
        "/dev/urandom",
        "/dev/urandom",
        "--dev-bind",
        "/dev/random",
        "/dev/random",
        "--symlink",
        "/proc/self/fd",
        "/dev/fd",
        "--symlink",
        "/proc/self/fd/0",
        "/dev/stdin",
        "--symlink",
        "/proc/self/fd/1",
        "/dev/stdout",
        "--symlink",
        "/proc/self/fd/2",
        "/dev/stderr",
        "--size",
        "2147483648",
        "--tmpfs",
        "/tmp",
        "--bind",
    ])
    .arg(writable)
    .arg(writable);
    for path in extra_read_only {
        if path.exists() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    cmd.args(["--remount-ro", "/", "--setenv", "LC_ALL", "C"]);
    for (key, value) in env {
        cmd.arg("--setenv").arg(key).arg(value);
    }
    let launch = sandbox_process::prepare(&mut cmd)?;
    cmd.arg("--chdir")
        .arg(writable)
        .args([
            "--",
            "/usr/bin/prlimit",
            "--as=8589934592",
            "--nofile=1024",
            "--core=0",
            "--",
        ])
        .arg(program);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env_clear()
        .stdout(Stdio::from(OwnedFd::from(writer)))
        .stderr(Stdio::from(OwnedFd::from(stderr)));
    let spawned = cmd.spawn();
    // Command owns its configured descriptors even after spawn; release them so
    // EOF reflects only the sandbox and its descendants.
    drop(cmd);
    let mut child = match spawned {
        Ok(child) => SandboxProcess::adopt(child, launch),
        Err(error) => {
            let reason = format!("mandatory bubblewrap isolation unavailable: {error}");
            let reason = match log.finish() {
                Ok(()) => reason,
                Err(persist) => format!("{reason}; diagnostics persistence failed: {persist}"),
            };
            return Err(log.error(&reason));
        }
    };
    let deadline = Instant::now().checked_add(timeout);
    let mut result = (|| {
        let deadline = deadline.ok_or("sandbox deadline overflow")?;
        loop {
            log.drain(&mut reader)?;
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            if Instant::now() >= deadline {
                return Err("Isolated analysis timed out.".into());
            }
            match child
                .poll_status()
                .map_err(|e| format!("sandbox wait: {e}"))?
            {
                Some(status) if status.success() => return Ok(()),
                Some(status) => {
                    return Err(format!(
                        "sandboxed Ghidra exited with {status}. sparse-plan.txt is not a load result."
                    ));
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
    })();
    if result.is_err() {
        // Retain both launcher and namespace ownership on this background
        // caller until exact cleanup is confirmed, including early setup.
        if let Err(error) = cleanup_sandbox(&mut child, &mut log) {
            result = Err(format!("sandbox cleanup failed: {error}; {result:?}"));
        }
    }
    let final_drain = log.drain_final(&mut reader);
    let persistence = log.finish();
    let diagnostics = match (final_drain, persistence) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(drain), Err(persist)) => Err(format!("{drain}; persistence failed: {persist}")),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
    };
    if let Err(error) = diagnostics {
        result = Err(format!(
            "sandbox diagnostics persistence failed: {error}; {result:?}"
        ));
    }
    result.map_err(|error| log.error(&error))
}

fn cleanup_sandbox(process: &mut SandboxProcess, log: &mut SandboxLog) -> Result<(), String> {
    let started = Instant::now();
    let mut failure = None;
    let mut noted = false;
    loop {
        match process.cleanup_poll() {
            Ok(true) => return failure.map_or(Ok(()), Err),
            Ok(false) => {}
            Err(error) => failure = Some(error),
        }
        if !noted && (failure.is_some() || started.elapsed() >= Duration::from_secs(1)) {
            let detail = failure
                .as_deref()
                .unwrap_or("namespace termination and reap are pending");
            let message =
                format!("\n[sandbox cleanup pending: {detail}; owned process retained]\n");
            if let Err(error) = log
                .record(message.as_bytes())
                .and_then(|()| log.file.flush().map_err(|e| e.to_string()))
            {
                failure = Some(format!("cleanup pending diagnostics: {error}; {detail}"));
            }
            noted = true;
        }
        std::thread::sleep(Duration::from_millis(if noted { 50 } else { 10 }));
    }
}

/// Resolve only the actual host UID's local account, never an inherited USER.
/// This bounded lookup is for background analysis/export work, not rendering.
pub(crate) fn host_user_name() -> Result<String, String> {
    const ACCOUNT_DATABASE_MAX_SIZE: u64 = 1024 * 1024;
    let mut encoded = Vec::new();
    File::open("/etc/passwd")
        .and_then(|file| {
            file.take(ACCOUNT_DATABASE_MAX_SIZE + 1)
                .read_to_end(&mut encoded)
        })
        .map_err(|error| format!("analysis account lookup unavailable: {error}"))?;
    if encoded.len() as u64 > ACCOUNT_DATABASE_MAX_SIZE {
        return Err("analysis account lookup exceeded 1 MiB bound".into());
    }
    let uid = rustix::process::getuid().as_raw();
    let mut matched = None;
    for line in encoded.split(|byte| *byte == b'\n') {
        let mut fields = line.split(|byte| *byte == b':');
        let name = fields.next().unwrap_or_default();
        let _password = fields.next();
        let candidate = fields
            .next()
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u32>().ok());
        if candidate != Some(uid) {
            continue;
        }
        if matched.is_some() {
            return Err("analysis account lookup is ambiguous for current UID".into());
        }
        if name.is_empty()
            || name.len() > 64
            || !name
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(byte))
        {
            return Err("analysis account has an unsupported user name; Ghidra ownership cannot be established".into());
        }
        matched = Some(String::from_utf8(name.to_vec()).map_err(|error| error.to_string())?);
    }
    matched.ok_or_else(|| {
        "current UID has no local account; Ghidra ownership cannot be established".into()
    })
}

fn sandbox_passwd(directory: &Path) -> Result<PathBuf, String> {
    let name = host_user_name()?;
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    let path = directory.join(format!("sandbox-account-{}.passwd", storage::unique_id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|error| format!("sandbox account mapping: {error}"))?;
    // Only one name/UID/GID crosses the boundary. No host home, shell, password,
    // GECOS, or other account is exposed. JVM settings stay in bounded tmpfs.
    writeln!(file, "{name}:x:{uid}:{gid}::/tmp:/bin/false")
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("sandbox account mapping: {error}"))?;
    Ok(path)
}

const SANDBOX_LOG_MAX_SIZE: usize = 2 * 1024 * 1024;
const SANDBOX_TAIL_MAX_SIZE: usize = 8192;
const SANDBOX_LOG_HEAD_SIZE: usize = SANDBOX_LOG_MAX_SIZE - SANDBOX_TAIL_MAX_SIZE - 256;

struct SandboxLog {
    file: File,
    path: PathBuf,
    head_len: usize,
    total_len: u64,
    tail: VecDeque<u8>,
}
impl SandboxLog {
    fn new(directory: &Path) -> Result<Self, String> {
        let path = directory.join(format!("ghidra-{}.log", storage::unique_id()));
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("sandbox diagnostics {}: {e}", path.display()))?;
        Ok(Self {
            file,
            path,
            head_len: 0,
            total_len: 0,
            tail: VecDeque::with_capacity(SANDBOX_TAIL_MAX_SIZE),
        })
    }
    /// True means the stream reached EOF or has no queued output at this instant.
    fn drain(&mut self, reader: &mut UnixStream) -> Result<bool, String> {
        let mut chunk = [0u8; 8192];
        // Finite drain work keeps cancellation/deadline polling responsive even
        // when a malfunctioning tool produces output continuously.
        for _ in 0..32 {
            let len = match reader.read(&mut chunk) {
                Ok(0) => return Ok(true),
                Ok(len) => len,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("sandbox output: {e}")),
            };
            self.record(&chunk[..len])?;
        }
        Ok(false)
    }
    fn record(&mut self, chunk: &[u8]) -> Result<(), String> {
        self.total_len = self.total_len.saturating_add(chunk.len() as u64);
        let keep = chunk.len().min(SANDBOX_LOG_HEAD_SIZE - self.head_len);
        self.file
            .write_all(&chunk[..keep])
            .map_err(|e| e.to_string())?;
        self.head_len += keep;
        let discard = self
            .tail
            .len()
            .saturating_add(chunk.len())
            .saturating_sub(SANDBOX_TAIL_MAX_SIZE);
        self.tail.drain(..discard);
        self.tail.extend(chunk);
        Ok(())
    }
    fn drain_final(&mut self, reader: &mut UnixStream) -> Result<(), String> {
        // Socket send buffers can exceed the ordinary per-poll drain budget.
        // Once the sandbox has exited/been reaped, consume queued data until
        // idle, while bounding work even if a hidden writer retained a handle.
        let deadline = Instant::now() + Duration::from_secs(1);
        for _ in 0..256 {
            if Instant::now() >= deadline {
                return Err(
                    "incomplete sandbox diagnostics: final drain exceeded one second".into(),
                );
            }
            if self.drain(reader)? {
                return Ok(());
            }
        }
        Err("incomplete sandbox diagnostics: final drain exceeded 64 MiB work bound".into())
    }
    fn finish(&mut self) -> Result<(), String> {
        if self.total_len > self.head_len as u64 {
            writeln!(
                self.file,
                "\n[output truncated; {} octets observed; final observed output tail follows]",
                self.total_len
            )
            .map_err(|e| e.to_string())?;
            let (a, b) = self.tail.as_slices();
            self.file
                .write_all(a)
                .and_then(|()| self.file.write_all(b))
                .map_err(|e| e.to_string())?;
        }
        self.file.sync_all().map_err(|e| e.to_string())
    }
    fn error(&self, reason: &str) -> String {
        let tail: Vec<u8> = self
            .tail
            .iter()
            .skip(self.tail.len().saturating_sub(2048))
            .copied()
            .collect();
        let mut text = format!(
            "{reason}\nDiagnostics: {}\n{}",
            self.path.display(),
            String::from_utf8_lossy(&tail)
        );
        if text.len() > 4096 {
            let mut end = 4096;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        text
    }
}

fn read_report(path: &Path, expected: &AnalysisReport) -> Result<AnalysisReport, String> {
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
    let report: AnalysisReport =
        serde_json::from_slice(&encoded).map_err(|e| format!("worker report malformed: {e}"))?;
    validate_report(&report)?;
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
        || !matches!(
            report.state,
            AnalysisState::Complete | AnalysisState::Partial
        )
        || report.specimen_sha256 != expected.specimen_sha256
    {
        return Err("worker report violates normalized identity/bounds contract".into());
    }
    Ok(report)
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
    validate_report(&report)?;
    Ok(report)
}
pub(crate) fn validate_report(report: &AnalysisReport) -> Result<(), String> {
    if serde_json::to_vec(report).map_err(|e| e.to_string())?.len() > REPORT_MAX_SIZE
        || report.sections.len() > 10
        || report.id.len() > 128
        || report.source_path.len() > 4096
        || report.reason.as_ref().is_some_and(|s| s.len() > 4096)
        || report
            .specimen_len
            .is_some_and(|len| len > u64::from(control::SPECIMEN_MAX_SIZE))
        || report
            .specimen_sha256
            .as_ref()
            .is_some_and(|hash| hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()))
        || report.sections.iter().any(|s| {
            s.entries.len() > 2048
                || s.tools.len() > 16
                || s.tools.iter().any(|t| t.len() > 256)
                || s.listing
                    .as_ref()
                    .is_some_and(|l| l.bytes > super::listing::LISTING_MAX_SIZE)
                || s.summary.len() > 4096
                || s.entries
                    .iter()
                    .any(|e| e.label.len() > 4096 || e.value.len() > 4096)
        })
    {
        return Err("analysis report violates archive bounds".into());
    }
    for (index, section) in report.sections.iter().enumerate() {
        if report.sections[..index]
            .iter()
            .any(|s| s.kind == section.kind)
        {
            return Err("duplicate archived analysis section".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut entropy_count = 0;
        for entry in &section.entries {
            if let Some(record) = &entry.record {
                if matches!(record.data, AnalysisData::Entropy { .. }) {
                    entropy_count += 1;
                    if entropy_count > 65 {
                        return Err(
                            "entropy section exceeds whole-file plus 64-region bound".into()
                        );
                    }
                }
                if record.revision != 1 || record.id == 0 || !ids.insert(record.id) {
                    return Err("invalid revision or duplicate/zero analysis record id".into());
                }
                validate_record(section.kind, entry, record, report.specimen_len)?;
            }
        }
    }
    Ok(())
}
fn validate_range(range: AnalysisRange, total_len: Option<u64>) -> Result<(), String> {
    let total_len = total_len.ok_or("analysis file range has no complete specimen length")?;
    if range
        .offset
        .checked_add(range.len)
        .is_none_or(|end| end > total_len)
    {
        return Err("analysis file range exceeds specimen or overflows".into());
    }
    Ok(())
}
pub(super) fn validate_record(
    kind: AnalysisKind,
    entry: &AnalysisEntry,
    record: &AnalysisRecord,
    total_len: Option<u64>,
) -> Result<(), String> {
    let location = record.location.as_ref();
    if let Some(location) = location {
        if let Some(range) = location.file_range {
            validate_range(range, total_len)?;
            if location.kind == AnalysisAddressKind::FileOffset && location.value != range.offset {
                return Err("file-offset location disagrees with range".into());
            }
            if entry.offset.is_some_and(|offset| offset != range.offset) {
                return Err("legacy file offset disagrees with structured range".into());
            }
        }
        if location.kind == AnalysisAddressKind::FileOffset
            && total_len.is_none_or(|len| location.value > len)
        {
            return Err("file-offset location exceeds specimen length".into());
        }
    }
    let bounded = |text: &str| text.len() <= 4096;
    let address_location = |address: Option<u64>| {
        location
            .is_none_or(|l| l.kind != AnalysisAddressKind::FileOffset && Some(l.value) == address)
    };
    let valid = match &record.data {
        AnalysisData::Field { group } => bounded(group),
        AnalysisData::Section {
            name,
            address,
            file_size,
            raw_flags,
            flags,
            ..
        } => {
            kind == AnalysisKind::Structures
                && bounded(name)
                && bounded(raw_flags)
                && flags.len() <= 64
                && flags.iter().all(|f| bounded(f))
                && address_location(Some(*address))
                && location
                    .and_then(|l| l.file_range)
                    .is_none_or(|r| Some(r.len) == *file_size)
        }
        AnalysisData::Symbol {
            name,
            kind: symbol_kind,
            scope,
            undefined,
            address,
            size,
        } => {
            kind == AnalysisKind::Structures
                && bounded(name)
                && bounded(symbol_kind)
                && bounded(scope)
                && (!*undefined || address.is_none())
                && address_location(*address)
                && location
                    .and_then(|l| l.file_range)
                    .is_none_or(|r| r.len == *size)
        }
        AnalysisData::Import {
            name,
            library,
            ordinal,
        } => {
            kind == AnalysisKind::Structures
                && name.is_some() != ordinal.is_some()
                && name.as_ref().is_none_or(|s| bounded(s))
                && library.as_ref().is_none_or(|s| bounded(s))
                && location.is_none()
        }
        AnalysisData::Export {
            name,
            ordinal,
            address,
        } => {
            kind == AnalysisKind::Structures
                && name.is_some() != ordinal.is_some()
                && name.as_ref().is_none_or(|s| bounded(s))
                && address_location(*address)
        }
        AnalysisData::String {
            encoding,
            byte_len,
            retained_len,
        } => {
            kind == AnalysisKind::Strings
                && bounded(encoding)
                && !encoding.is_empty()
                && *retained_len == entry.value.len() as u64
                && (!matches!(encoding.as_str(), "ASCII" | "UTF-8") || *retained_len <= *byte_len)
                && location.is_none_or(|l| {
                    l.kind == AnalysisAddressKind::FileOffset
                        && l.file_range.is_none_or(|r| r.len == *byte_len)
                })
        }
        AnalysisData::Entropy { range, milli_bits } => {
            validate_range(*range, total_len)?;
            kind == AnalysisKind::Entropy
                && *milli_bits <= 8000
                && location.is_none_or(|l| {
                    l.kind == AnalysisAddressKind::FileOffset
                        && l.value == range.offset
                        && l.file_range == Some(*range)
                })
        }
        AnalysisData::Property {
            scope,
            observed,
            evidence,
        } => {
            kind == AnalysisKind::Hardening
                && bounded(scope)
                && bounded(observed)
                && bounded(evidence)
        }
        AnalysisData::Instruction {
            address,
            bytes,
            mnemonic,
            operands,
            function,
        } => {
            kind == AnalysisKind::Disassembly
                && bytes.len() <= 64
                && bytes.bytes().all(|c| c.is_ascii_hexdigit() || c == b' ')
                && bounded(mnemonic)
                && bounded(operands)
                && function.as_deref().is_none_or(bounded)
                && address_location(Some(*address))
        }
        AnalysisData::Function { name, address, .. } => {
            matches!(
                kind,
                AnalysisKind::Disassembly | AnalysisKind::Decompilation
            ) && bounded(name)
                && address_location(Some(*address))
        }
        AnalysisData::SourceLine {
            function, address, ..
        } => kind == AnalysisKind::Decompilation && bounded(function) && address_location(*address),
        AnalysisData::RuleMatch {
            rule,
            namespace,
            tags,
            ruleset,
        } => {
            matches!(kind, AnalysisKind::Rules | AnalysisKind::Identification)
                && bounded(rule)
                && !rule.is_empty()
                && bounded(namespace)
                && bounded(ruleset)
                && tags.len() <= 64
                && tags.iter().all(|t| bounded(t))
        }
        AnalysisData::Capability {
            name,
            namespace,
            attack,
            mbc,
        } => {
            kind == AnalysisKind::Capabilities
                && bounded(name)
                && !name.is_empty()
                && bounded(namespace)
                && attack.len() <= 64
                && mbc.len() <= 64
                && attack.iter().chain(mbc.iter()).all(|t| bounded(t))
        }
        AnalysisData::Identification {
            category,
            name,
            version,
        } => {
            kind == AnalysisKind::Identification
                && bounded(category)
                && bounded(name)
                && !name.is_empty()
                && version.as_deref().is_none_or(bounded)
        }
    };
    if !valid {
        return Err("structured analysis record violates kind, text or evidence bounds".into());
    }
    Ok(())
}
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
                }),
                queue: VecDeque::new(),
                release: VecDeque::new(),
                retained_len: 0,
                updates: Vec::new(),
                tools_dir: None,
            };
            let launcher = jobs.active.as_ref().unwrap().child.as_ref().unwrap().id();
            let children = PathBuf::from(format!("/proc/{launcher}/task/{launcher}/children"));
            let deadline = Instant::now() + Duration::from_secs(2);
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
            let started = Instant::now();
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
            assert!(
                started.elapsed() < Duration::from_millis(250),
                "cleanup tick blocked"
            );
            assert!(
                jobs.active.is_some(),
                "one STOP request is not cleanup completion"
            );
            let deadline = Instant::now() + Duration::from_secs(2);
            while jobs.active.is_some() && Instant::now() < deadline {
                jobs.next();
                std::thread::sleep(Duration::from_millis(5));
            }
            assert!(jobs.active.is_none(), "namespace cleanup did not finish");
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
            assert!(
                polls[0].revents().contains(rustix::event::PollFlags::IN),
                "owned init survived completion"
            );
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
            let deadline = Instant::now() + Duration::from_secs(5);
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
    /// Every category in the real sandbox, listings adopted and paged.
    /// ANTINOMIE_TEST_SPECIMEN picks the program (default /usr/bin/true).
    #[test]
    #[ignore = "requires the app ELF in ANTINOMIE_TEST_WORKER_BINARY, bubblewrap and minutes of CPU"]
    fn production_worker_all_categories_with_listings() {
        let executable = PathBuf::from(
            std::env::var_os("ANTINOMIE_TEST_WORKER_BINARY").expect("set the app ELF path"),
        );
        let source = std::env::var("ANTINOMIE_TEST_SPECIMEN").unwrap_or("/usr/bin/true".into());
        let directory =
            std::env::temp_dir().join(format!("ant-deep-smoke-{}", storage::unique_id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let specimen = fs::read(&source).unwrap();
        fs::write(directory.join("specimen"), &specimen).unwrap();
        let selection = AnalysisSelection {
            enabled: true,
            checks: AnalysisKind::TRIAGE
                .iter()
                .chain(AnalysisKind::DEEP)
                .copied()
                .collect(),
        };
        let mut report = new_report(&source, &selection);
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
        let mut report = read_report(&directory.join("output/report.json"), &job.report).unwrap();
        adopt_listings(&directory, &mut report);
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
        let disassembly = report
            .sections
            .iter()
            .find(|s| s.kind == AnalysisKind::Disassembly)
            .unwrap();
        assert!(disassembly.listing.as_ref().is_some_and(|l| l.rows > 0));
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
        assert!(found.total > 0 && found.rows.iter().all(|(_, row)| row.value.contains("call")));
        eprintln!(
            "all categories in {:?}; report {} octets; kept at {}",
            started.elapsed(),
            fs::metadata(directory.join("report.json")).unwrap().len(),
            directory.display()
        );
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
        let report = read_report(&directory.join("output/report.json"), &job.report).unwrap();
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
        assert!(validate_report(&report).is_ok());
        let entry: AnalysisEntry =
            serde_json::from_str(r#"{"label":"legacy","value":"kept verbatim","offset":null}"#)
                .unwrap();
        assert!(entry.record.is_none());
        report.sections[0].entries.push(entry);
        assert!(validate_report(&report).is_ok());
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
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0].record.as_mut().unwrap().id = 0;
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        let duplicate = report.sections[0].entries[0].clone();
        report.sections[0].entries.push(duplicate);
        assert!(validate_report(&report).is_err());
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
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0]
            .record
            .as_mut()
            .unwrap()
            .location
            .as_mut()
            .unwrap()
            .value = 3;
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::String {
            encoding: "ASCII".into(),
            byte_len: 4,
            retained_len: 3,
        };
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].kind = AnalysisKind::Metadata;
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        report.specimen_len = None;
        assert!(validate_report(&report).is_err());
        let mut report = valid.clone();
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::Field {
            group: "x".repeat(4097),
        };
        assert!(validate_report(&report).is_err());
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
        assert!(validate_report(&report).is_err());
        report.sections[0].kind = AnalysisKind::Entropy;
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::Entropy {
            range: AnalysisRange { offset: 0, len: 16 },
            milli_bits: 8001,
        };
        assert!(validate_report(&report).is_err());
        report.sections[0].entries[0].record.as_mut().unwrap().data = AnalysisData::Entropy {
            range: AnalysisRange { offset: 1, len: 16 },
            milli_bits: 3000,
        };
        assert!(validate_report(&report).is_err());
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
        assert!(validate_report(&report).is_err());
        report.sections[0].entries.pop();
        assert!(validate_report(&report).is_ok());
    }
    #[test]
    fn one_active_acquisition_and_eight_waiting_jobs_are_the_hard_bound() {
        let root =
            std::env::temp_dir().join(format!("ant-analysis-queue-{}", storage::unique_id()));
        let selection = AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
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

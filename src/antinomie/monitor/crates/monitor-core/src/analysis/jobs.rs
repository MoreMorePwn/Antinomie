// SPDX-License-Identifier: MIT
use super::worker::REPORT_MAX_SIZE;
use super::*;
use crate::{control, storage};
use sha2::{Digest, Sha256};
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
static CLEANUP_PENDING: AtomicBool = AtomicBool::new(false);
static CLEANUP_CHILD: Mutex<Option<(Child, PathBuf, AnalysisReport)>> = Mutex::new(None);

pub(crate) struct Job {
    pub run_id: Option<String>,
    pub report: AnalysisReport,
    pub directory: PathBuf,
    handle: Option<u64>,
    total_len: u64,
    received_len: u64,
    file: Option<File>,
    deadline: Instant,
    child: Option<Child>,
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
            let kill = child.kill();
            match child.try_wait() {
                Ok(Some(_)) => {
                    job.report.reason=Some(if job.report.state==AnalysisState::Cancelled {"analysis cancelled; worker cleanup completed; program execution continues"}else{"analysis incomplete; worker cleanup completed"}.into());
                }
                Ok(None) => {
                    job.report.reason=Some("analysis stopped; worker cleanup pending, no new worker will start until reap".into());
                    job.child = Some(child);
                    if let Err(error) = persist_report(&job.directory, &job.report) {
                        job.report.reason = Some(format!(
                            "worker cleanup pending; report persistence failed: {error}"
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
                    self.active = Some(job);
                    return;
                }
                Err(error) => {
                    job.report.reason = Some(format!(
                        "worker reap pending after wait error: {error}; kill error {:?}",
                        kill.err()
                    ));
                    job.child = Some(child);
                    self.active = Some(job);
                    return;
                }
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
            .saturating_add(directory_len(&job.directory.join("output/listings")).unwrap_or(0));
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
            match child.try_wait() {
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
                        format!("worker wait: {error}"),
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
                *CLEANUP_CHILD.lock().unwrap_or_else(|p| p.into_inner()) =
                    Some((child, job.directory.clone(), job.report.clone()));
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
                        if let Some((mut child, directory, mut report)) = item {
                            let reaped = match child.wait() {
                                Ok(_) => {
                                    report.reason =
                                        Some("VM ended; stopped worker cleanup completed".into());
                                    true
                                }
                                Err(error) => {
                                    report.reason =
                                        Some(format!("VM ended; worker reap failed: {error}"));
                                    false
                                }
                            };
                            if let Err(error) = persist_report(&directory, &report) {
                                eprintln!("analysis cleanup report persistence failed: {error}");
                            }
                            if reaped {
                                CLEANUP_PENDING.store(false, Ordering::Release);
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
fn spawn_worker(job: &Job, tools: Option<&Path>) -> Result<Child, String> {
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    spawn_worker_binary(job, &executable, tools)
}
fn spawn_worker_binary(
    job: &Job,
    executable: &Path,
    tools: Option<&Path>,
) -> Result<Child, String> {
    crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
    if CLEANUP_PENDING.load(Ordering::Acquire) {
        return Err("a previous worker still awaits reap; isolation worker unavailable".into());
    }
    let output = job.directory.join("output");
    fs::create_dir(&output).map_err(|e| e.to_string())?;
    let listings = output.join("listings");
    fs::create_dir(&listings).map_err(|e| e.to_string())?;
    fs::set_permissions(&listings, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
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
    .arg("/input/specimen")
    .arg("--ro-bind")
    .arg(job.directory.join("request.json"))
    .arg("/input/request.json")
    .arg("--bind")
    .arg(output.join("report.json"))
    .arg("/output/report.json")
    .arg("--bind")
    .arg(&listings)
    .arg("/output/listings");
    // Analysis tools Antinomie installed, read-only.
    if let Some(tools) = tools.filter(|tools| tools.is_dir()) {
        cmd.arg("--ro-bind")
            .arg(tools)
            .arg(crate::analysis_tools::SANDBOX_DIR);
    }
    if std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed") {
        cmd.args(["--setenv", "ANTINOMIE_ANALYSIS_TOOLS", "managed"]);
    }
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
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::from(log));
    cmd.spawn()
        .map_err(|e| format!("mandatory bubblewrap isolation unavailable: {e}"))
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
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= job.deadline {
                let _ = child.kill();
                let _ = child.wait();
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
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= job.deadline {
                let kill = child.kill();
                let reap = child.wait();
                panic!("worker smoke exceeded 15 seconds: kill {kill:?}; reap {reap:?}");
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

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
                .checked_add(REPORT_MAX_SIZE as u64 + 64 * 1024 * 1024 + 8192)
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
            if let Some(index) = self.queue.iter().position(|j| j.report.id == report.id) {
                if let Some(mut job) = self.queue.remove(index) {
                    if let Some(id) = job.handle.take() {
                        self.release.push_back(id);
                    }
                }
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
            .sum();
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
                            Ok(report) => job.report = report,
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
        match spawn_worker(&job) {
            Ok(child) => {
                job.disk_len = job.disk_len.saturating_add(
                    fs::metadata(job.directory.join("request.json")).map_or(0, |m| m.len()),
                );
                job.child = Some(child);
                job.report.state = AnalysisState::Running;
                job.deadline = Instant::now()
                    + Duration::from_secs(
                        if job
                            .report
                            .sections
                            .iter()
                            .any(|s| AnalysisKind::DEEP.contains(&s.kind))
                        {
                            120
                        } else {
                            30
                        },
                    );
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
fn spawn_worker(job: &Job) -> Result<Child, String> {
    if CLEANUP_PENDING.load(Ordering::Acquire) {
        return Err("a previous worker still awaits reap; isolation worker unavailable".into());
    }
    let executable = std::env::current_exe().map_err(|e| e.to_string())?;
    let output = job.directory.join("output");
    fs::create_dir(&output).map_err(|e| e.to_string())?;
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
    for path in ["/lib", "/lib64"] {
        if Path::new(path).exists() {
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
        "--size",
        "33554432",
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
    .args([
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
        || report.sections.iter().any(|s| {
            s.entries.len() > 2048
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
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
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
            128 * 1024 * 1024,
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
            128 * 1024 * 1024,
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

// SPDX-License-Identifier: GPL-3.0-only
//! The lane state file `<service>/lanes/lane-N.json` (design 2.5, 4.5.3).
//!
//! One small JSON file per lane: the lane's VM and clean snapshot, the
//! quarantine flag, the job the lane is working on and how far it got, the
//! jobs whose `collect` finished but whose host stages are still to run, and
//! the QEMU process of the lane's VM. The file is **not** the truth about the
//! engine: on start the service rebuilds lane state from this file *and* the
//! engine's `Snapshot` and never trusts the file alone (4.8).
//!
//! Crash safety: every change is written to a temporary file in the same
//! directory, synced, renamed over the old file, and the directory is synced.
//! A process killed at any point leaves either the old file or the new one,
//! never half of one; a leftover temporary file is ignored and swept at the
//! next load. The file carries a `version`; a file of a newer version is
//! refused, never rewritten.
use crate::api::{failure::FailureCode, ids::JobId, ids::LaneId, job::Stage};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// The version this build writes and reads.
pub const LANE_FILE_VERSION: u32 = 1;

/// Consecutive `vm_start_failed` / `guest_unreachable` that quarantine a lane
/// (4.5.3).
pub const QUARANTINE_AFTER: u32 = 3;

/// Why a lane file could not be used.
#[derive(Debug, thiserror::Error)]
pub enum LaneStateError {
    #[error("{path}: {message}")]
    Io { path: PathBuf, message: String },
    /// The file is not valid JSON of the right shape (edited by hand, or a
    /// disk fault). It is left as it is.
    #[error("{path}: the lane file is damaged: {message}")]
    Corrupt { path: PathBuf, message: String },
    /// A newer Antinomie wrote it.
    #[error(
        "{path}: the lane file has version {found}, this build reads up to {LANE_FILE_VERSION}"
    )]
    TooNew { path: PathBuf, found: u64 },
    #[error("there is no state file for {0}")]
    Missing(LaneId),
}

/// How far a stage got.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Checkpoint {
    /// Written before the stage's first engine command.
    Started,
    /// Written after the stage's exit condition held.
    Finished,
}

/// The job a lane is working on: `provision` to `collect` of one job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneWork {
    pub job_id: JobId,
    pub attempt: u32,
    pub stage: Stage,
    pub checkpoint: Checkpoint,
    /// Wall time of the last checkpoint, for display only.
    pub updated_ms: u64,
}

/// A job whose lane stages are over: the VM is stopped, the recording is
/// final and the layer settled, so the lane is free. Its host stages
/// (`analyse` and later) run elsewhere; the entry stays until they begin, so a
/// crash in between resumes at `analyse` instead of running the VM again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collected {
    pub job_id: JobId,
    pub attempt: u32,
    pub collected_ms: u64,
}

/// The QEMU process of the lane's VM, as recorded when the VM started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QemuRecord {
    pub pid: u32,
    /// Field 22 of `/proc/<pid>/stat` when recorded: with the pid it names one
    /// process, not a later one that reused the number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_ticks: Option<u64>,
    /// A text the process's command line must contain (the lane VM's id).
    pub marker: String,
    pub recorded_ms: u64,
}

/// Why a lane takes no job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quarantine {
    /// `revert_failed`, `lane_changed`, `vm_start_failed` or
    /// `guest_unreachable`.
    pub reason: FailureCode,
    pub detail: String,
    pub since_ms: u64,
}

/// `lanes/lane-N.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaneFile {
    pub version: u32,
    pub lane: LaneId,
    pub vm_id: String,
    /// The id of the `auto-clean` Disk snapshot (checked before every job;
    /// a different id means the VM was used by hand: `lane_changed`).
    pub clean_snapshot_id: String,
    pub base_identity: String,
    pub created_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<Quarantine>,
    /// Consecutive `vm_start_failed` / `guest_unreachable` on this lane.
    #[serde(default)]
    pub failures: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current: Option<LaneWork>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collected: Vec<Collected>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu: Option<QemuRecord>,
    pub updated_ms: u64,
}

impl LaneFile {
    pub fn new(
        lane: LaneId,
        vm_id: &str,
        clean_snapshot_id: &str,
        base_identity: &str,
        now_ms: u64,
    ) -> Self {
        Self {
            version: LANE_FILE_VERSION,
            lane,
            vm_id: vm_id.to_owned(),
            clean_snapshot_id: clean_snapshot_id.to_owned(),
            base_identity: base_identity.to_owned(),
            created_ms: now_ms,
            quarantine: None,
            failures: 0,
            current: None,
            collected: Vec::new(),
            qemu: None,
            updated_ms: now_ms,
        }
    }

    pub fn is_quarantined(&self) -> bool {
        self.quarantine.is_some()
    }

    /// The lane takes a job: stage `prechecks` is the job's, the lane's own
    /// work begins at `provision`.
    pub fn begin_work(&mut self, job_id: JobId, attempt: u32, now_ms: u64) {
        self.current = Some(LaneWork {
            job_id,
            attempt,
            stage: Stage::Provision,
            checkpoint: Checkpoint::Started,
            updated_ms: now_ms,
        });
        self.updated_ms = now_ms;
    }

    /// Record a stage checkpoint of the current job. Returns false when the
    /// lane has no work.
    pub fn checkpoint(&mut self, stage: Stage, checkpoint: Checkpoint, now_ms: u64) -> bool {
        let Some(work) = self.current.as_mut() else {
            return false;
        };
        work.stage = stage;
        work.checkpoint = checkpoint;
        work.updated_ms = now_ms;
        self.updated_ms = now_ms;
        true
    }

    /// `collect` finished: the lane is free, the job waits for the host
    /// stages. Returns false when the lane has no work.
    pub fn collected(&mut self, now_ms: u64) -> bool {
        let Some(work) = self.current.take() else {
            return false;
        };
        self.collected.push(Collected {
            job_id: work.job_id,
            attempt: work.attempt,
            collected_ms: now_ms,
        });
        self.qemu = None;
        self.updated_ms = now_ms;
        true
    }

    /// The host stages of `job` began (or the job ended): forget the entry.
    pub fn release(&mut self, job: &JobId, now_ms: u64) {
        self.collected.retain(|c| &c.job_id != job);
        self.updated_ms = now_ms;
    }

    /// The current job left the lane without finishing `collect` (failed,
    /// cancelled, requeued).
    pub fn end_work(&mut self, now_ms: u64) {
        self.current = None;
        self.updated_ms = now_ms;
    }

    pub fn set_qemu(&mut self, record: QemuRecord) {
        self.updated_ms = record.recorded_ms;
        self.qemu = Some(record);
    }

    pub fn clear_qemu(&mut self, now_ms: u64) {
        self.qemu = None;
        self.updated_ms = now_ms;
    }

    /// Stop the lane taking jobs. Only the four reasons of 4.5.3 quarantine.
    pub fn quarantine(&mut self, reason: FailureCode, detail: &str, now_ms: u64) {
        debug_assert!(matches!(
            reason,
            FailureCode::RevertFailed
                | FailureCode::LaneChanged
                | FailureCode::VmStartFailed
                | FailureCode::GuestUnreachable
        ));
        if self.quarantine.is_none() {
            self.quarantine = Some(Quarantine {
                reason,
                detail: detail.to_owned(),
                since_ms: now_ms,
            });
        }
        self.updated_ms = now_ms;
    }

    /// `auto lane unquarantine` / a successful `reset`: the flag and the
    /// failure count go.
    pub fn unquarantine(&mut self, now_ms: u64) {
        self.quarantine = None;
        self.failures = 0;
        self.updated_ms = now_ms;
    }

    /// A `vm_start_failed` or `guest_unreachable` happened. True when this one
    /// quarantined the lane (the third in a row).
    pub fn note_start_failure(&mut self, reason: FailureCode, detail: &str, now_ms: u64) -> bool {
        self.failures += 1;
        self.updated_ms = now_ms;
        if self.failures >= QUARANTINE_AFTER && self.quarantine.is_none() {
            self.quarantine(reason, detail, now_ms);
            return true;
        }
        false
    }

    /// A job reached `launch`: the run of failures is over.
    pub fn note_start_success(&mut self, now_ms: u64) {
        self.failures = 0;
        self.updated_ms = now_ms;
    }
}

/// Where in a write a test makes the process "die".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteFault {
    /// The temporary file is created and partly written.
    DuringTemp,
    /// The temporary file is complete and synced, the rename did not happen.
    BeforeRename,
    /// The rename happened, the directory was not synced.
    AfterRename,
}

/// The `lanes/` directory.
pub struct LaneDir {
    dir: PathBuf,
    fault: Mutex<Option<WriteFault>>,
}

static TEMP: AtomicU64 = AtomicU64::new(0);

fn io(path: &Path, error: std::io::Error) -> LaneStateError {
    LaneStateError::Io {
        path: path.to_owned(),
        message: error.to_string(),
    }
}

impl LaneDir {
    /// The lanes of the service directory (`<data>/service`).
    pub fn new(service_dir: &Path) -> Self {
        Self {
            dir: service_dir.join("lanes"),
            fault: Mutex::new(None),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn path(&self, lane: &LaneId) -> PathBuf {
        self.dir.join(format!("{}.json", lane.as_str()))
    }

    /// Make the next [`save`](Self::save) stop at `fault` with an error, as a
    /// killed process would leave things.
    pub fn inject_fault(&self, fault: WriteFault) {
        *self.fault.lock().unwrap() = Some(fault);
    }

    /// The lanes that have a file, in order.
    pub fn lanes(&self) -> Result<Vec<LaneId>, LaneStateError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io(&self.dir, e)),
        };
        let mut lanes: Vec<LaneId> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                LaneId::try_from(name.strip_suffix(".json")?.to_owned()).ok()
            })
            .collect();
        lanes.sort();
        Ok(lanes)
    }

    /// Delete the temporary files an interrupted write left. Only names this
    /// module makes (`.lane-N.json.<pid>.<n>.tmp`) are touched.
    pub fn sweep_temp(&self) -> usize {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return 0;
        };
        let mut removed = 0;
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".lane-")
                && name.ends_with(".tmp")
                && fs::remove_file(entry.path()).is_ok()
            {
                removed += 1;
            }
        }
        removed
    }

    /// Read a lane's file. `None` when the lane has none.
    pub fn load(&self, lane: &LaneId) -> Result<Option<LaneFile>, LaneStateError> {
        let path = self.path(lane);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(&path, e)),
        };
        let corrupt = |message: String| LaneStateError::Corrupt {
            path: path.clone(),
            message,
        };
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| corrupt(e.to_string()))?;
        let version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| corrupt("no version".into()))?;
        if version > u64::from(LANE_FILE_VERSION) {
            return Err(LaneStateError::TooNew {
                path,
                found: version,
            });
        }
        let file: LaneFile = serde_json::from_value(value).map_err(|e| corrupt(e.to_string()))?;
        if &file.lane != lane {
            return Err(corrupt(format!("the file says it is {}", file.lane)));
        }
        Ok(Some(file))
    }

    /// Write a lane's file atomically (see the module text).
    pub fn save(&self, file: &LaneFile) -> Result<(), LaneStateError> {
        let path = self.path(&file.lane);
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(&self.dir).map_err(|e| io(&self.dir, e))?;
        let temp = self.dir.join(format!(
            ".{}.json.{}.{}.tmp",
            file.lane.as_str(),
            std::process::id(),
            TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        let mut bytes = serde_json::to_vec_pretty(file).map_err(|e| LaneStateError::Io {
            path: path.clone(),
            message: e.to_string(),
        })?;
        bytes.push(b'\n');
        let fault = self.fault.lock().unwrap().take();
        let killed = |at: &str| LaneStateError::Io {
            path: path.clone(),
            message: format!("killed {at} (test fault)"),
        };
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| io(&temp, e))?;
        if fault == Some(WriteFault::DuringTemp) {
            out.write_all(&bytes[..bytes.len() / 2])
                .map_err(|e| io(&temp, e))?;
            return Err(killed("while writing the temporary file"));
        }
        out.write_all(&bytes).map_err(|e| io(&temp, e))?;
        out.sync_all().map_err(|e| io(&temp, e))?;
        drop(out);
        if fault == Some(WriteFault::BeforeRename) {
            return Err(killed("before the rename"));
        }
        fs::rename(&temp, &path).map_err(|e| io(&path, e))?;
        if fault == Some(WriteFault::AfterRename) {
            return Err(killed("after the rename"));
        }
        fs::File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| io(&self.dir, e))
    }

    /// Load, change and save a lane's file; the value `change` returns.
    pub fn update<T>(
        &self,
        lane: &LaneId,
        change: impl FnOnce(&mut LaneFile) -> T,
    ) -> Result<T, LaneStateError> {
        let mut file = self
            .load(lane)?
            .ok_or_else(|| LaneStateError::Missing(lane.clone()))?;
        let value = change(&mut file);
        self.save(&file)?;
        Ok(value)
    }
}

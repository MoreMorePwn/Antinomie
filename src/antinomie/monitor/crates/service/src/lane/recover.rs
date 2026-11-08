// SPDX-License-Identifier: GPL-3.0-only
//! Recovery of the lanes at start (design 4.7.3, 4.8): the process that ran
//! them died, possibly in the middle of a stage, and left a lane file, a QEMU
//! process, a VM the new engine does not run, and jobs `running` in the store.
//!
//! Order, for the whole service ([`recover_startup`]):
//!
//! 1. Leftover temporary lane files are swept; every lane file is read.
//! 2. A job whose lane stages finished (`collected` in the lane file) and
//!    whose store row is still `running` at or after `collect` is **kept**:
//!    it resumes at `analyse`, the VM is not run again (4.1).
//! 3. The store recovers (`Store::recover_keeping`): every other `running`
//!    job becomes a new attempt, the first restart free, and `cancelling`
//!    jobs are put right.
//! 4. For each lane: a recorded QEMU pid is ended **only if** its command line
//!    and start time still say it is that VM's QEMU; a VM the engine reports
//!    as not stopped is stopped; the wait for a pending disk layer runs (the
//!    engine finishes it at its own start, up to the copier timeout); the
//!    clean snapshot is looked up; the lane file is written without the dead
//!    process's work. A snapshot id that is gone while the VM's snapshots are
//!    listed means the VM was used by hand: the lane is quarantined
//!    (`lane_changed`, G15) and `lane.state` and `engine.alert` are stored.
//!
//! Nothing here runs a VM or a stage. It leaves the lane stopped, settled and
//! free, or says why not.
use super::{
    check::{LaneProblem, check_lane, layer_pending},
    process::{Processes, is_recorded_qemu},
    state::{Collected, LaneDir, LaneFile, LaneStateError, LaneWork},
};
use crate::{
    api::{
        error::ApiError,
        event::{EventBody, LaneState},
        failure::FailureCode,
        ids::{JobId, LaneId},
        job::{JobState, Stage},
    },
    engine::Engine,
    store::{Store, recover::RecoveryReport},
    waiter::{SETTLE_WAIT, WaitError, Waiter, settled_after_stop},
};
use std::{collections::HashSet, time::Duration};

/// How long recovery waits for the engine.
#[derive(Clone, Copy, Debug)]
pub struct RecoverOptions {
    /// For a VM the engine reports as running to stop and settle.
    pub stop_wait: Duration,
    /// For a pending disk layer or recording flush (`layer_s`, 4.1).
    pub layer_wait: Duration,
}

impl Default for RecoverOptions {
    fn default() -> Self {
        Self {
            stop_wait: Duration::from_secs(120),
            layer_wait: SETTLE_WAIT,
        }
    }
}

/// What became of the lane's file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileState {
    /// Read, put right and written again.
    Recovered,
    /// Unusable (damaged, or written by a newer version). Left untouched;
    /// the lane takes no job until a person looks.
    Unreadable(String),
}

/// What recovery did about the recorded QEMU process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuOutcome {
    /// The file recorded none.
    NotRecorded,
    /// The process is gone.
    Gone(u32),
    /// The process matched and was ended.
    Killed(u32),
    /// The pid belongs to something else now; left alone.
    NotOurs(u32),
    /// The process matched and would not end. The lane is quarantined.
    KillFailed(u32, String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRecovery {
    pub lane: LaneId,
    pub file: FileState,
    /// The job the lane was working on when the process died. The store has
    /// already requeued it (a new attempt).
    pub interrupted: Option<LaneWork>,
    pub qemu: QemuOutcome,
    /// Recovery stopped a VM the engine reported as not stopped.
    pub stopped_vm: bool,
    /// A disk layer or recording flush of the lane VM was still going when the
    /// wait ended; `provision` waits (`waiting_for: layer_pending`).
    pub layer_pending: bool,
    pub problems: Vec<LaneProblem>,
    /// Set when this lane is quarantined (before or by this recovery).
    pub quarantined: Option<FailureCode>,
    /// Jobs whose lane stages were finished and that resume at `analyse`.
    pub resume: Vec<JobId>,
    /// `collected` entries whose job no longer needs them.
    pub dropped: Vec<JobId>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartupRecovery {
    pub jobs: RecoveryReport,
    pub lanes: Vec<LaneRecovery>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecoverError {
    #[error("{0}")]
    Store(ApiError),
    #[error("{0}")]
    Lane(#[from] LaneStateError),
    #[error("the engine failed during recovery: {0}")]
    Engine(WaitError),
}

impl From<ApiError> for RecoverError {
    fn from(error: ApiError) -> Self {
        Self::Store(error)
    }
}

/// Run the recovery of 4.7.3 and 4.8. Call after the engine started, the
/// first snapshot arrived, and the data directory is owned.
pub fn recover_startup<E: Engine>(
    store: &Store,
    lanes: &LaneDir,
    waiter: &mut Waiter<E>,
    procs: &dyn Processes,
    options: &RecoverOptions,
) -> Result<StartupRecovery, RecoverError> {
    lanes.sweep_temp();
    let mut loaded = Vec::new();
    for lane in lanes.lanes()? {
        let file = lanes.load(&lane);
        loaded.push((lane, file));
    }

    // Which collected jobs resume at analyse.
    let mut keep = HashSet::new();
    let mut resumable: Vec<(Vec<JobId>, Vec<JobId>)> = Vec::new();
    for (_, file) in &loaded {
        let (mut resume, mut dropped) = (Vec::new(), Vec::new());
        if let Ok(Some(file)) = file {
            for entry in &file.collected {
                if still_needed(store, entry) {
                    keep.insert(entry.job_id.clone());
                    resume.push(entry.job_id.clone());
                } else {
                    dropped.push(entry.job_id.clone());
                }
            }
        }
        resumable.push((resume, dropped));
    }

    let jobs = store.recover_keeping(&keep)?;
    let mut report = StartupRecovery {
        jobs,
        lanes: Vec::new(),
    };
    for ((lane, file), (resume, dropped)) in loaded.into_iter().zip(resumable) {
        report.lanes.push(match file {
            Err(error) => LaneRecovery {
                lane,
                file: FileState::Unreadable(error.to_string()),
                interrupted: None,
                qemu: QemuOutcome::NotRecorded,
                stopped_vm: false,
                layer_pending: false,
                problems: Vec::new(),
                quarantined: None,
                resume: Vec::new(),
                dropped: Vec::new(),
            },
            Ok(None) => continue,
            Ok(Some(file)) => {
                recover_lane(store, lanes, waiter, procs, options, file, resume, dropped)?
            }
        });
    }
    Ok(report)
}

/// A `collected` entry matters while its job is `running` at or after
/// `collect`, in the attempt that collected.
fn still_needed(store: &Store, entry: &Collected) -> bool {
    store.get(&entry.job_id).is_ok_and(|job| {
        job.state == JobState::Running
            && job.attempt == entry.attempt
            && job.stage.is_some_and(|stage| stage >= Stage::Collect)
    })
}

#[allow(clippy::too_many_arguments)]
fn recover_lane<E: Engine>(
    store: &Store,
    lanes: &LaneDir,
    waiter: &mut Waiter<E>,
    procs: &dyn Processes,
    options: &RecoverOptions,
    mut file: LaneFile,
    resume: Vec<JobId>,
    dropped: Vec<JobId>,
) -> Result<LaneRecovery, RecoverError> {
    let now = waiter.now_ms();
    let was_quarantined = file.is_quarantined();
    let interrupted = file.current.take();

    // 1. The QEMU process the dead service started.
    let qemu = match file.qemu.take() {
        None => QemuOutcome::NotRecorded,
        Some(record) => match procs.info(record.pid) {
            None => QemuOutcome::Gone(record.pid),
            Some(info) if is_recorded_qemu(&record, &info) => match procs.kill(record.pid) {
                Ok(()) => QemuOutcome::Killed(record.pid),
                Err(message) => {
                    let pid = record.pid;
                    file.qemu = Some(record);
                    QemuOutcome::KillFailed(pid, message)
                }
            },
            Some(_) => QemuOutcome::NotOurs(record.pid),
        },
    };
    if let QemuOutcome::KillFailed(pid, message) = &qemu {
        file.quarantine(
            FailureCode::LaneChanged,
            &format!("the QEMU process {pid} of the lane VM would not end: {message}"),
            now,
        );
    }

    // 2. The engine side: stopped, settled.
    waiter.drain().map_err(RecoverError::Engine)?;
    let mut stopped_vm = false;
    if waiter.snapshot().state != antinomie_monitor_core::VmState::Stopped {
        stopped_vm = true;
        match waiter.stop_vm(&file.vm_id, Some(options.stop_wait)) {
            Ok(_) | Err(WaitError::Failed(_) | WaitError::TimedOut { .. }) => {}
            Err(other) => return Err(RecoverError::Engine(other)),
        }
    }
    let mut pending = false;
    if layer_pending(waiter.snapshot(), &file.vm_id) {
        let vm = file.vm_id.clone();
        match waiter.wait_until(
            "the disk layer of the lane VM to settle",
            Some(options.layer_wait),
            |snapshot| settled_after_stop(snapshot, &vm),
        ) {
            Ok(()) => {}
            Err(WaitError::TimedOut { .. }) => pending = true,
            Err(other) => return Err(RecoverError::Engine(other)),
        }
    }

    // 3. The lane against the engine.
    let problems = check_lane(&file, waiter.snapshot());
    for problem in &problems {
        if let LaneProblem::SnapshotMissing {
            id,
            verifiable: true,
        } = problem
        {
            file.quarantine(
                FailureCode::LaneChanged,
                &format!("the clean snapshot {id} is no longer among the snapshots of the lane VM"),
                now,
            );
        }
    }

    // 4. Write the lane without the dead process's work.
    file.collected
        .retain(|entry| !dropped.contains(&entry.job_id));
    file.updated_ms = now;
    lanes.save(&file)?;

    let quarantined = file.quarantine.as_ref().map(|q| q.reason);
    if let (Some(quarantine), false) = (&file.quarantine, was_quarantined) {
        store.emit_engine(EventBody::LaneState {
            lane: file.lane.clone(),
            state: LaneState::Quarantined,
            job_id: interrupted.as_ref().map(|w| w.job_id.clone()),
            reason: Some(serde_json::to_value(quarantine.reason).map_or_else(
                |_| "lane_changed".into(),
                |v| v.as_str().unwrap_or("lane_changed").to_owned(),
            )),
        })?;
        store.emit_engine(EventBody::EngineAlert {
            code: "lane_quarantined".into(),
            text: format!("{}: {}", file.lane, quarantine.detail),
        })?;
    } else if interrupted.is_some() && quarantined.is_none() {
        store.emit_engine(EventBody::LaneState {
            lane: file.lane.clone(),
            state: LaneState::Idle,
            job_id: interrupted.as_ref().map(|w| w.job_id.clone()),
            reason: Some("service_restart".into()),
        })?;
    }

    Ok(LaneRecovery {
        lane: file.lane,
        file: FileState::Recovered,
        interrupted,
        qemu,
        stopped_vm,
        layer_pending: pending,
        problems,
        quarantined,
        resume,
        dropped,
    })
}

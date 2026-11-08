// SPDX-License-Identifier: GPL-3.0-only
//! The lane stages `prechecks` to `launch` (design 4.1, 4.5; card P3-4b).
//!
//! [`LaneStages`] holds what a lane needs (the engine waiter, the store, the
//! lane files, the host and process seams) and has one method per stage. Each
//! returns what the next needs or a [`StageStop`]:
//!
//! * `Failed(Failure)`: the stage's failure code of 4.1; retry, backoff and
//!   the end of the job are the caller's (card P3-4c). The lane's own
//!   bookkeeping that belongs to the failure (a quarantine after a failed
//!   revert or a changed clean snapshot, the count of start failures) is done
//!   here, because it needs the engine's evidence.
//! * `Wait`: not a failure; the job waits `queued` with `waiting_for`.
//! * `Cancelled`: the job was cancelled between stages.
//! * `Abort`: a signal or a dead engine.
//!
//! [`LaneStages::run_to_launch`] drives the five stages with the store's stage
//! records and the lane file's checkpoints, so a crash at any boundary is one
//! recovery handles (`lane::recover`).
//!
//! Departures from the text of 4.1, found by the spike (ANT-T0345): a Disk
//! restore starts the VM itself, so `provision` waits for it and does not
//! send `Start`; only `reset` sends `Start`. The first upload after boot may
//! fail with "read-only file system" and is retried inside `upload_s`.
mod launch;
pub mod plan;
mod prechecks;
mod provision;
#[cfg(test)]
mod tests;
mod upload;

use crate::{
    api::{
        event::{EventBody, StageStatus},
        failure::Failure,
        ids::LaneId,
        job::{Job, JobState, Stage, WaitingFor},
    },
    config::{LoadedPolicy, PolicyLookup},
    engine::Engine,
    lane::{LaneDir, LaneFile, LaneStateError, Processes, state::Checkpoint},
    store::{Eligibility, Store},
    waiter::{WaitError, Waiter},
};
use antinomie_monitor_core::RunSummary;
pub use plan::Effective;
use std::time::Duration;

/// `precheck_s`.
pub const PRECHECK_WAIT: Duration = Duration::from_secs(60);
/// `stop_s`.
pub const STOP_WAIT: Duration = Duration::from_secs(120);

/// Why a stage did not complete.
#[derive(Debug)]
pub enum StageStop {
    Failed(Failure),
    /// Not a failure: the job waits `queued`.
    Wait {
        waiting_for: WaitingFor,
        detail: String,
    },
    Cancelled,
    /// A signal or a dead engine.
    Abort(WaitError),
}

impl From<WaitError> for StageStop {
    fn from(error: WaitError) -> Self {
        Self::Abort(error)
    }
}

impl From<crate::waiter::Stop> for StageStop {
    fn from(stop: crate::waiter::Stop) -> Self {
        match stop {
            crate::waiter::Stop::Failed(failure) => Self::Failed(failure),
            crate::waiter::Stop::Abort(error) => Self::Abort(error),
        }
    }
}

impl StageStop {
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Self::Failed(failure) => Some(failure),
            _ => None,
        }
    }
}

/// What the host checks of `prechecks` can say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostProblem {
    /// Wait (`resources` or `dependency`); the wait's own limit is `wait_s`.
    Wait(WaitingFor, String),
    /// Fail now: `host_resources`, `quota_exceeded`, `dependency_missing`.
    Fail(crate::api::failure::FailureCode, String),
}

/// Host resources, dependencies for the job's options and KVM. The service's
/// real checks with injected probes are card P3-5c; these are the seam.
pub trait HostChecks {
    fn check(&self, job: &Job, policy: &crate::config::Policy) -> Result<(), HostProblem>;
}

/// Every check passes.
pub struct NoHostChecks;

impl HostChecks for NoHostChecks {
    fn check(&self, _: &Job, _: &crate::config::Policy) -> Result<(), HostProblem> {
        Ok(())
    }
}

/// What `prechecks` hands to the later stages.
#[derive(Clone, Debug)]
pub struct Prepared {
    pub policy: LoadedPolicy,
    pub effective: Effective,
    pub lane: LaneFile,
}

/// What `provision` leaves running.
#[derive(Clone, Debug)]
pub struct Provisioned {
    pub vm_id: String,
    pub boot_id: Option<String>,
    pub guest_revision: Option<u32>,
}

/// The program's run, started.
#[derive(Clone, Debug)]
pub struct Launched {
    pub run: RunSummary,
    pub guest_path: String,
}

/// What the stages share with the service.
pub struct LaneEnv<'a> {
    pub store: &'a Store,
    pub lanes: &'a LaneDir,
    pub policies: &'a dyn PolicyLookup,
    pub procs: &'a dyn Processes,
    pub host: &'a dyn HostChecks,
}

pub struct LaneStages<'a, E: Engine> {
    pub waiter: &'a mut Waiter<E>,
    pub env: LaneEnv<'a>,
    pub lane: LaneId,
}

impl<E: Engine> LaneStages<'_, E> {
    pub(crate) fn lane_file(&self) -> Result<LaneFile, StageStop> {
        match self.env.lanes.load(&self.lane) {
            Ok(Some(file)) => Ok(file),
            Ok(None) => Err(self.internal(
                crate::api::failure::FailureCode::NoVm,
                Stage::Prechecks,
                "the lane has no state file; run `auto init`",
                None,
            )),
            Err(error) => Err(self.internal(
                crate::api::failure::FailureCode::Internal,
                Stage::Prechecks,
                "the lane state file cannot be used",
                Some(&error.to_string()),
            )),
        }
    }

    pub(crate) fn internal(
        &self,
        code: crate::api::failure::FailureCode,
        stage: Stage,
        message: &str,
        detail: Option<&str>,
    ) -> StageStop {
        StageStop::Failed(Failure::new(code, stage, message, detail))
    }

    pub(crate) fn update_lane<T>(
        &self,
        change: impl FnOnce(&mut LaneFile) -> T,
    ) -> Result<T, StageStop> {
        self.env
            .lanes
            .update(&self.lane, change)
            .map_err(|error: LaneStateError| {
                self.internal(
                    crate::api::failure::FailureCode::Internal,
                    Stage::Provision,
                    "the lane state file cannot be written",
                    Some(&error.to_string()),
                )
            })
    }

    pub(crate) fn store_error(
        &self,
        stage: Stage,
        error: crate::api::error::ApiError,
    ) -> StageStop {
        self.internal(
            crate::api::failure::FailureCode::Internal,
            stage,
            "the job store failed",
            Some(&error.to_string()),
        )
    }

    /// A progress line of `stage` (ephemeral: not stored).
    pub(crate) fn progress(&self, job: &Job, stage: Stage, text: &str) {
        self.env.store.publish_ephemeral(
            &job.id,
            EventBody::JobProgress {
                stage,
                text: text.to_owned(),
                fraction: None,
            },
        );
    }

    /// Whether the lane can take a job now, for `Store::claim_next`: the lane
    /// has a file, is not quarantined or busy, and its VM has no pending layer.
    pub fn eligibility(&mut self) -> Eligibility {
        if self.waiter.drain().is_err() {
            return Eligibility::Wait(WaitingFor::Lane);
        }
        match self.env.lanes.load(&self.lane) {
            Ok(Some(file)) => prechecks::lane_eligibility(&file, self.waiter.snapshot()),
            _ => Eligibility::Wait(WaitingFor::Lane),
        }
    }

    fn cancelled(&self, job: &Job) -> bool {
        self.env
            .store
            .get(&job.id)
            .is_ok_and(|job| job.state == JobState::Cancelling)
    }

    /// Run `prechecks` to `launch` for a job `claim_next` started. Writes the
    /// store's stage records and the lane file's checkpoints around each
    /// stage; a failed stage is ended `failed` and its stop returned. The job
    /// stays `running`: ending it or retrying is the caller's.
    pub fn run_to_launch(&mut self, job: &Job) -> Result<Launched, StageStop> {
        let store = self.env.store;
        let now = self.waiter.now_ms();
        let prepared = self.stage(job, Stage::Prechecks, false, |this| this.prechecks(job))?;
        self.cancel_point(job)?;
        self.update_lane(|file| file.begin_work(job.id.clone(), job.attempt, now))?;
        store
            .emit_engine(EventBody::LaneState {
                lane: self.lane.clone(),
                state: crate::api::event::LaneState::Busy,
                job_id: Some(job.id.clone()),
                reason: None,
            })
            .map_err(|e| self.store_error(Stage::Provision, e))?;
        let provisioned = self.stage(job, Stage::Provision, true, |this| {
            this.provision(job, &prepared)
        })?;
        self.cancel_point(job)?;
        self.stage(job, Stage::Upload, true, |this| this.upload(job, &prepared))?;
        self.cancel_point(job)?;
        let launched = self.stage(job, Stage::Launch, true, |this| {
            this.launch(job, &prepared, &provisioned)
        })?;
        store
            .end_stage(&job.id, StageStatus::Finished)
            .map_err(|e| self.store_error(Stage::Launch, e))?;
        Ok(launched)
    }

    fn cancel_point(&self, job: &Job) -> Result<(), StageStop> {
        if self.cancelled(job) {
            Err(StageStop::Cancelled)
        } else {
            Ok(())
        }
    }

    /// One stage with its records: the store's `stage` rows (`prechecks` is
    /// already begun by the claim) and the lane checkpoints.
    fn stage<T>(
        &mut self,
        job: &Job,
        stage: Stage,
        lane_stage: bool,
        run: impl FnOnce(&mut Self) -> Result<T, StageStop>,
    ) -> Result<T, StageStop> {
        let store = self.env.store;
        if stage != Stage::Prechecks {
            store
                .begin_stage(&job.id, stage)
                .map_err(|e| self.store_error(stage, e))?;
        }
        if lane_stage {
            let now = self.waiter.now_ms();
            self.update_lane(|file| file.checkpoint(stage, Checkpoint::Started, now))?;
        }
        match run(self) {
            Ok(value) => {
                if lane_stage {
                    let now = self.waiter.now_ms();
                    self.update_lane(|file| file.checkpoint(stage, Checkpoint::Finished, now))?;
                }
                Ok(value)
            }
            Err(stop) => {
                if matches!(stop, StageStop::Failed(_)) {
                    let _ = store.end_stage(&job.id, StageStatus::Failed);
                }
                Err(stop)
            }
        }
    }
}

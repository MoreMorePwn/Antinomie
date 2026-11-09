// SPDX-License-Identifier: GPL-3.0-only
//! One job through the lane, with its ending (design 4.1, 4.7; card P3-4c).
//!
//! [`LaneStages::drive`] runs `prechecks` to `collect` and then does what the
//! outcome needs:
//!
//! | The cycle ends with | The lane | The job |
//! |---|---|---|
//! | `collect` finished | `collected` entry, free for the next job | stays `running`; the host stages (`analyse`, `report`) are the next card; [`LaneStages::finish_collected`] ends it meanwhile |
//! | a failure the policy retries | VM stopped and settled, work ended | `queued` again after the backoff (`job.requeued`), attempt kept in the store |
//! | any other failure | the same | `failed` with the failure |
//! | a cancel | the same; the recording is kept | `cancelled` (or back in the queue when the daemon is shutting down) |
//! | the watchdog (`job_hard_s`) | the same | `failed`, `internal`, detail `watchdog`, never retried |
//! | a wait (host, lane) | untouched | `queued` with `waiting_for`, no attempt used |
//! | a signal or a dead engine | untouched: recovery finishes it | untouched |
//!
//! Cancellation is polled inside every wait of every stage through the
//! waiter's cancel hook (a subscription to the store's `job.state` events), so
//! a cancel during the 180 s boot ends the wait within 100 ms; the run and
//! collect stages act on it themselves because they must still stop the run and
//! the VM.
use super::{
    LaneStages, Launched, STOP_WAIT, StageStop, Stopped,
    collect::CollectEnd,
    plan,
    retry::{self, Decision, FinalReason},
};
use crate::{
    api::{
        event::{EventBody, StageStatus},
        failure::{Failure, FailureCode},
        job::{Job, JobState, Outcome, RecordingPhase, Stage, WaitingFor},
    },
    engine::Engine,
    lane::{recover::announce_quarantine, state::Checkpoint},
    store::RequeueKind,
    waiter::{BOOT_WAIT, WaitError},
    watchdog::job_hard,
};

/// What became of the job.
#[derive(Debug)]
pub enum Driven {
    /// Every lane stage finished.
    Collected(Box<CollectEnd>),
    /// The job failed and was queued for another attempt.
    Retried { failure: Failure, backoff_s: u32 },
    /// The job ended `failed`.
    Failed(Failure),
    /// The job ended `cancelled`.
    Cancelled,
    /// A shutdown cancel: the job is back in the queue.
    Requeued,
    /// The job is `queued` again, waiting for `waiting_for`.
    Waiting {
        waiting_for: WaitingFor,
        detail: String,
    },
    /// A signal or a dead engine: nothing was changed.
    Aborted(WaitError),
}

impl<E: Engine> LaneStages<'_, E> {
    /// Run the job through the lane and end or requeue it.
    pub fn drive(&mut self, job: &Job) -> Driven {
        match self.arm(job) {
            Ok(()) => {}
            Err(stop) => return self.settle(job, Err(stop)),
        }
        let result = self.lane_cycle(job);
        self.waiter.clear_cancel();
        self.waiter.clear_deadline();
        self.settle(job, result)
    }

    /// The job limit and the cancel hook.
    fn arm(&mut self, job: &Job) -> Result<(), StageStop> {
        let frozen = self
            .env
            .store
            .frozen_policy(&job.id)
            .map_err(|e| self.store_error(Stage::Prechecks, e))?;
        let limit = plan::effective(job, &frozen.policy).run_limit;
        self.waiter.deadline_in(job_hard(limit));
        self.cancel_hook(job);
        Ok(())
    }

    /// Arm the waiter's cancel hook for `job`: a subscription to the store's
    /// `job.state` events that turns true on this job's `cancelling`.
    pub(super) fn cancel_hook(&mut self, job: &Job) {
        let events = self.env.store.subscribe();
        let id = job.id.clone();
        self.waiter.cancel_when(true, move || {
            let mut cancel = false;
            while let Ok(event) = events.try_recv() {
                cancel |= event.job_id.as_ref() == Some(&id)
                    && matches!(
                        event.body,
                        EventBody::JobState {
                            state: JobState::Cancelling,
                            ..
                        }
                    );
            }
            cancel
        });
    }

    fn lane_cycle(&mut self, job: &Job) -> Result<CollectEnd, StageStop> {
        self.cancel_point(job)?;
        let (prepared, launched) = self.launch_cycle(job)?;
        self.cancel_point(job)?;
        self.stage(job, Stage::Run, true, |this| {
            this.run(job, &prepared, &launched)
        })?;
        self.collect_stage(job, &launched)
    }

    /// `collect` with its records. Unlike the other lane stages its
    /// `finished` checkpoint is the move into `collected` (one atomic write of
    /// the lane file), so a crash leaves either "collect started" (a new
    /// attempt) or "collected" (the job resumes at `analyse`), never both.
    pub(super) fn collect_stage(
        &mut self,
        job: &Job,
        launched: &Launched,
    ) -> Result<CollectEnd, StageStop> {
        let store = self.env.store;
        store
            .begin_stage(&job.id, Stage::Collect)
            .map_err(|e| self.store_error(Stage::Collect, e))?;
        let now = self.waiter.now_ms();
        self.update_lane(|file| file.checkpoint(Stage::Collect, Checkpoint::Started, now))?;
        let end = match self.collect(job, launched) {
            Ok(mut end) => {
                // A run stopped for the disk floor is a partial result.
                if store
                    .get(&job.id)
                    .is_ok_and(|stored| stored.warnings.iter().any(|w| w.code == "low_disk"))
                {
                    end.outcome = Outcome::Partial;
                }
                end
            }
            Err(stop) => {
                if matches!(stop, StageStop::Failed(_)) {
                    let _ = store.end_stage(&job.id, StageStatus::Failed);
                }
                return Err(stop);
            }
        };
        // A cancel that came in while the VM was stopping is honoured now:
        // the recording is complete and kept.
        if end.cancelled || self.cancelled(job) {
            let _ = store.end_stage(&job.id, StageStatus::Finished);
            return Err(StageStop::Cancelled);
        }
        let now = self.waiter.now_ms();
        self.update_lane(|file| file.collected(now))?;
        store
            .end_stage(&job.id, StageStatus::Finished)
            .map_err(|e| self.store_error(Stage::Collect, e))?;
        Ok(end)
    }

    /// End a collected job with the outcome `collect` found, until the host
    /// stages exist: the lane forgets the `collected` entry and the job
    /// finishes.
    pub fn finish_collected(&mut self, job: &Job, end: &CollectEnd) -> Result<Job, StageStop> {
        let now = self.waiter.now_ms();
        self.update_lane(|file| file.release(&job.id, now))?;
        self.env
            .store
            .finish(&job.id, end.outcome, None)
            .map_err(|e| self.store_error(Stage::Cleanup, e))
    }

    fn settle(&mut self, job: &Job, result: Result<CollectEnd, StageStop>) -> Driven {
        let stop = match result {
            Ok(end) => return Driven::Collected(Box::new(end)),
            Err(stop) => stop,
        };
        match stop {
            StageStop::Abort(error @ (WaitError::Disconnected(_) | WaitError::Interrupted)) => {
                Driven::Aborted(error)
            }
            StageStop::Abort(WaitError::DeadlineExceeded) => self.end_by_watchdog(job),
            StageStop::Abort(WaitError::Cancelled) | StageStop::Cancelled => {
                self.end_cancelled(job)
            }
            // A send that failed, or an engine that stopped answering.
            StageStop::Abort(other) => {
                let stage = self.job_stage(job);
                let failure = Failure::new(
                    FailureCode::Internal,
                    stage,
                    "the engine failed the lane",
                    Some(&other.to_string()),
                );
                self.end_failed(job, failure)
            }
            StageStop::Wait {
                waiting_for,
                detail,
            } => self.end_waiting(job, waiting_for, detail),
            StageStop::Failed(failure) => self.end_failed(job, failure),
        }
    }

    fn job_stage(&self, job: &Job) -> Stage {
        self.env
            .store
            .get(&job.id)
            .ok()
            .and_then(|job| job.stage)
            .unwrap_or(Stage::Prechecks)
    }

    /// The lane lets go of a job that did not finish `collect`: its VM is
    /// stopped and settled, then the work ends. A lane that never took this
    /// job is left alone.
    fn leave_lane(&mut self, job: &Job) -> Result<(), WaitError> {
        self.waiter.clear_cancel();
        self.waiter.clear_deadline();
        let Ok(file) = self.lane_file() else {
            return Ok(());
        };
        if file.current.as_ref().map(|work| &work.job_id) != Some(&job.id) {
            return Ok(());
        }
        // A command a cancel or the job limit interrupted is still running
        // in the engine; the VM state is only known once it has ended.
        let _ = self.waiter.finish_abandoned(STOP_WAIT + BOOT_WAIT);
        let mut settled = match self.stop_lane_vm(job, &file.vm_id, STOP_WAIT + BOOT_WAIT) {
            Ok(stopped) => stopped,
            Err(StageStop::Abort(error)) => return Err(error),
            Err(_) => Stopped::Unsettled("the lane state could not be used".into()),
        };
        // A launch given up as silent may have started the program: the stop
        // ended it, and the job names its run.
        self.link_late_launch(job);
        if settled != Stopped::Settled {
            // The forced kill leaves the engine in `Failed`: it is asked to
            // stop once more, and that answer is the last one.
            self.warn(
                job,
                "vm_not_stopped",
                &format!("the lane VM was not left stopped and settled: {settled:?}"),
            );
            settled = match self.stop_lane_vm(job, &file.vm_id, STOP_WAIT) {
                Ok(stopped) => stopped,
                Err(StageStop::Abort(error)) => return Err(error),
                Err(_) => Stopped::Unsettled("the lane state could not be used".into()),
            };
        }
        let now = self.waiter.now_ms();
        let clean = settled == Stopped::Settled;
        if clean
            && let Ok(stored) = self.env.store.get(&job.id)
            && stored.recording.as_ref().map(|r| r.phase) == Some(RecordingPhase::Finalizing)
        {
            // The VM is stopped and the recording settled: it is complete.
            let _ = self.set_recording_phase(job, RecordingPhase::Complete);
        }
        let quarantined = self.update_lane(|file| {
            file.end_work(now);
            if clean {
                file.clear_qemu(now);
                None
            } else {
                // A VM that will not stop cannot be reverted: the next job
                // would start on a machine the engine still holds. The
                // closest reason of 4.5.3 is `revert_failed`, which also
                // keeps the lane out of service until `auto lane reset`.
                file.quarantine(
                    FailureCode::RevertFailed,
                    &format!(
                        "the lane VM did not stop and settle after a forced stop: {settled:?}"
                    ),
                    now,
                );
                Some(file.clone())
            }
        });
        if let Ok(Some(file)) = quarantined {
            let _ = announce_quarantine(self.env.store, &file, Some(job.id.clone()));
        }
        Ok(())
    }

    fn end_failed(&mut self, job: &Job, failure: Failure) -> Driven {
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        let store = self.env.store;
        let policy = match store.frozen_policy(&job.id) {
            Ok(frozen) => frozen.policy.retry,
            Err(_) => crate::config::policy::RetryPolicy::default(),
        };
        let history = store.previous_failures(&job.id).unwrap_or_default();
        match retry::decide(&failure, &policy, &history, &job.id) {
            Decision::Retry { backoff_s } => {
                let reason = format!("{:?}", failure.code).to_ascii_lowercase();
                match store.requeue(
                    &job.id,
                    RequeueKind::Retry,
                    &reason,
                    Some(&failure),
                    Some(backoff_s),
                ) {
                    Ok(_) => Driven::Retried { failure, backoff_s },
                    // No attempt left.
                    Err(_) => self.finish_failed(job, failure, None),
                }
            }
            Decision::Final(reason) => self.finish_failed(job, failure, Some(reason)),
        }
    }

    fn finish_failed(&mut self, job: &Job, failure: Failure, why: Option<FinalReason>) -> Driven {
        let store = self.env.store;
        if failure.code == FailureCode::GuestLost && why == Some(FinalReason::Repeated) {
            let _ = store.add_warning(
                &job.id,
                "crashes_guest",
                "the sample ended the guest in two attempts; it is not run again",
            );
            match self.env.tags.add_tag(job, super::host::CRASHES_GUEST_TAG) {
                Ok(_) => {}
                Err(error) => {
                    let _ = store.add_warning(
                        &job.id,
                        "tag_failed",
                        &format!(
                            "the library tag {} was not written: {error}",
                            super::host::CRASHES_GUEST_TAG
                        ),
                    );
                }
            }
        }
        match store.finish(&job.id, Outcome::Failed, Some(failure.clone())) {
            Ok(_) => Driven::Failed(failure),
            Err(error) => Driven::Aborted(WaitError::Failed(error.to_string())),
        }
    }

    fn end_cancelled(&mut self, job: &Job) -> Driven {
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        let store = self.env.store;
        if store.cancel_is_shutdown(&job.id).unwrap_or(false) {
            return match store.requeue(
                &job.id,
                RequeueKind::Shutdown,
                "service_shutdown",
                None,
                None,
            ) {
                Ok(_) => Driven::Requeued,
                Err(error) => Driven::Aborted(WaitError::Failed(error.to_string())),
            };
        }
        match store.finish(&job.id, Outcome::Cancelled, None) {
            Ok(_) => Driven::Cancelled,
            Err(error) => Driven::Aborted(WaitError::Failed(error.to_string())),
        }
    }

    fn end_by_watchdog(&mut self, job: &Job) -> Driven {
        let stage = self.job_stage(job);
        let failure = Failure::new(
            FailureCode::Internal,
            stage,
            "the job passed its time limit and was stopped",
            Some("watchdog"),
        );
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        self.finish_failed(job, failure, None)
    }

    fn end_waiting(&mut self, job: &Job, waiting_for: WaitingFor, detail: String) -> Driven {
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        match self
            .env
            .store
            .requeue_waiting(&job.id, waiting_for, &detail)
        {
            Ok(_) => Driven::Waiting {
                waiting_for,
                detail,
            },
            Err(error) => Driven::Aborted(WaitError::Failed(error.to_string())),
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! One job through the lane, with its ending (design 4.1, 4.7; card P3-4c).
//!
//! [`LaneStages::drive`] runs `prechecks` to `collect` and then does what the
//! outcome needs:
//!
//! | The cycle ends with | The lane | The job |
//! |---|---|---|
//! | `collect` finished | `collected` entry, free for the next job | stays `running`; the host stages (`analyse`, `report`) are the next card; [`LaneStages::finish_collected`] ends it meanwhile |
//! | a failure the policy retries | VM stopped and settled, work ended | `queued` again after the backoff (`run.requeued`), attempt kept in the store |
//! | any other failure | the same | `failed` with the failure |
//! | a cancel | the same; the recording is kept | `cancelled` (or back in the queue when the daemon is shutting down) |
//! | the watchdog (`job_hard_s`) | the same | `failed`, `internal`, detail `watchdog`, never retried |
//! | a wait (host, lane) | untouched | `queued` with `waiting_for`, no attempt used |
//! | a signal or a dead engine | untouched: recovery finishes it | untouched |
//!
//! Cancellation is polled inside every wait of every stage through the
//! waiter's cancel hook (a subscription to the store's `run.state` events), so
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
        run::{Outcome, RecordingPhase, Run, RunState, Stage, WaitingFor},
    },
    engine::Engine,
    lane::{recover::announce_quarantine, state::Checkpoint},
    store::RequeueKind,
    waiter::{BOOT_WAIT, WaitError},
    watchdog::job_hard,
};

/// How often a write the disk was too full for is tried again.
pub(crate) const FULL_RETRY: std::time::Duration = std::time::Duration::from_secs(5);

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
    pub fn drive(&mut self, job: &Run) -> Driven {
        let driven = self.drive_job(job);
        // `launch_cycle` named the job's caller as the engine's custody
        // actor; the lane's next work is not this job's.
        let _ = self.waiter.engine_mut().set_custody_actor(None);
        driven
    }

    fn drive_job(&mut self, job: &Run) -> Driven {
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
    fn arm(&mut self, job: &Run) -> Result<(), StageStop> {
        let frozen = self
            .env
            .store
            .frozen_preset(&job.id)
            .map_err(|e| self.store_error(Stage::Prechecks, e))?;
        let limit = plan::effective(&frozen.preset, self.env.revert).run_limit;
        self.waiter.deadline_in(job_hard(limit));
        self.cancel_hook(job);
        Ok(())
    }

    /// Arm the waiter's cancel hook for `job`: a subscription to the store's
    /// `run.state` events that turns true on this job's `cancelling`.
    pub(crate) fn cancel_hook(&mut self, job: &Run) {
        let events = self.env.store.subscribe();
        let id = job.id.clone();
        self.waiter.cancel_when(true, move || {
            let mut cancel = false;
            while let Ok(event) = events.try_recv() {
                cancel |= event.run_id.as_ref() == Some(&id)
                    && matches!(
                        event.body,
                        EventBody::RunState {
                            state: RunState::Cancelling,
                            ..
                        }
                    );
            }
            cancel
        });
    }

    fn lane_cycle(&mut self, job: &Run) -> Result<CollectEnd, StageStop> {
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
        job: &Run,
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
                if self.floor_stopped(job) {
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

    /// The run was stopped for the disk floor (its `low_disk` warning, which
    /// the run stage writes once the run's end is written).
    pub(super) fn floor_stopped(&self, job: &Run) -> bool {
        self.env
            .store
            .get(&job.id)
            .is_ok_and(|stored| stored.warnings.iter().any(|w| w.code == "low_disk"))
    }

    /// End a collected job with the outcome `collect` found, until the host
    /// stages exist: the lane forgets the `collected` entry and the job
    /// finishes.
    pub fn finish_collected(&mut self, job: &Run, end: &CollectEnd) -> Result<Run, StageStop> {
        let now = self.waiter.now_ms();
        self.update_lane(|file| file.release(&job.id, now))?;
        self.env
            .store
            .finish(&job.id, end.outcome, None)
            .map_err(|e| self.store_error(Stage::Cleanup, e))
    }

    fn settle(&mut self, job: &Run, result: Result<CollectEnd, StageStop>) -> Driven {
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
            // The engine refused or cancelled a guest command while it was
            // recovering the guest: not an engine failure (ANT-T0479). The
            // stages that send guest commands decide this themselves; this
            // is the rule for any path that did not.
            StageStop::Abort(WaitError::GuestTransition(words)) => {
                let stage = self.job_stage(job);
                let failure = crate::waiter::transition_failure(stage, &words);
                self.end_failed(job, failure)
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

    /// [`settle`](Self::settle) with a stop, for the tests of an ending.
    #[cfg(test)]
    pub(super) fn settle_for_test(&mut self, job: &Run, stop: StageStop) -> Driven {
        self.settle(job, Err(stop))
    }

    fn job_stage(&self, job: &Run) -> Stage {
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
    fn leave_lane(&mut self, job: &Run) -> Result<(), WaitError> {
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
        if let Stopped::Deferred(words) = &settled {
            // Stopped, but the disk is too full to finish the recording: no
            // second stop and no quarantine. The layer stays pending, which
            // keeps the lane from the next job until the engine finishes it.
            self.warn(
                job,
                "low_disk",
                &format!(
                    "the VM is stopped; its recording is finished when the disk has room again: {words}"
                ),
            );
        } else if settled != Stopped::Settled {
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
        let stopped = clean || matches!(settled, Stopped::Deferred(_));
        if clean
            && let Ok(stored) = self.env.store.get(&job.id)
            && stored.recording.as_ref().map(|r| r.phase) == Some(RecordingPhase::Finalizing)
        {
            // The VM is stopped and the recording settled: it is complete.
            let _ = self.set_recording_phase(job, RecordingPhase::Complete);
        }
        // The lane's end of work must be written, or the lane stays busy for
        // good: on a full disk it is tried again until it is.
        let quarantined = self.until_written(job, "the lane file", |this| {
            this.env.lanes.update(&this.lane, |file| {
                file.end_work(now);
                if stopped {
                    file.clear_qemu(now);
                    None
                } else {
                    // A VM that will not stop cannot be reverted: the next
                    // job would start on a machine the engine still holds.
                    // The closest reason of 4.5.3 is `revert_failed`, which
                    // also keeps the lane out of service until `auto lane
                    // reset`.
                    file.quarantine(
                        FailureCode::RevertFailed,
                        &format!(
                            "the lane VM did not stop and settle after a forced stop: {settled:?}"
                        ),
                        now,
                    );
                    Some(file.clone())
                }
            })
        })?;
        if let Ok(Some(file)) = quarantined {
            let _ = announce_quarantine(self.env.store, &file, Some(job.id.clone()));
        }
        Ok(())
    }

    /// A write the lane cannot leave out (the lane file's end of work, the
    /// job's end or requeue, the run's end). While it fails because the disk
    /// is full it is tried again every [`FULL_RETRY`], with the queue paused
    /// `low_disk` (held in memory when the database cannot take it either);
    /// any other result is the caller's. Only a signal, the job's limit or a
    /// dead engine end the wait (ANT-T0475: a job must not hang on a full
    /// disk, nor fail without a record of it).
    pub(crate) fn until_written<T, X: std::fmt::Display>(
        &mut self,
        job: &Run,
        what: &str,
        mut write: impl FnMut(&Self) -> Result<T, X>,
    ) -> Result<Result<T, X>, WaitError> {
        let mut noted = false;
        loop {
            match write(self) {
                Err(error) if crate::resources::disk_full(&error.to_string()) => {
                    if !noted {
                        noted = true;
                        let words = format!("{what} could not be written: {error}");
                        crate::resources::pause_for_low_disk(self.env.store, &words);
                        let stage = self.job_stage(job);
                        self.progress(
                            job,
                            stage,
                            &format!("{words}; trying again until the disk has room"),
                        );
                    }
                    self.waiter.pause(FULL_RETRY)?;
                }
                other => return Ok(other),
            }
        }
    }

    fn end_failed(&mut self, job: &Run, failure: Failure) -> Driven {
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        let store = self.env.store;
        let policy = match store.frozen_preset(&job.id) {
            Ok(frozen) => frozen.preset.retry,
            Err(_) => crate::config::preset::Retry::default(),
        };
        let history = store.previous_failures(&job.id).unwrap_or_default();
        match retry::decide(&failure, &policy, &history, &job.id) {
            Decision::Retry { backoff_s } => {
                let reason = format!("{:?}", failure.code).to_ascii_lowercase();
                let requeued = self.until_written(job, "the job's retry", |this| {
                    this.env.store.requeue(
                        &job.id,
                        RequeueKind::Retry,
                        &reason,
                        Some(&failure),
                        Some(backoff_s),
                    )
                });
                match requeued {
                    Ok(Ok(_)) => Driven::Retried { failure, backoff_s },
                    // No attempt left.
                    Ok(Err(_)) => self.finish_failed(job, failure, None),
                    Err(error) => Driven::Aborted(error),
                }
            }
            Decision::Final(reason) => self.finish_failed(job, failure, Some(reason)),
        }
    }

    fn finish_failed(&mut self, job: &Run, failure: Failure, why: Option<FinalReason>) -> Driven {
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
        let finished = self.until_written(job, "the job's end", |this| {
            this.env
                .store
                .finish(&job.id, Outcome::Failed, Some(failure.clone()))
        });
        match finished {
            Ok(Ok(_)) => Driven::Failed(failure),
            Ok(Err(error)) => Driven::Aborted(WaitError::Failed(error.to_string())),
            Err(error) => Driven::Aborted(error),
        }
    }

    fn end_cancelled(&mut self, job: &Run) -> Driven {
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        let store = self.env.store;
        if store.cancel_is_shutdown(&job.id).unwrap_or(false) {
            let requeued = self.until_written(job, "the job's requeue", |this| {
                this.env.store.requeue(
                    &job.id,
                    RequeueKind::Shutdown,
                    "service_shutdown",
                    None,
                    None,
                )
            });
            return match requeued {
                Ok(Ok(_)) => Driven::Requeued,
                Ok(Err(error)) => Driven::Aborted(WaitError::Failed(error.to_string())),
                Err(error) => Driven::Aborted(error),
            };
        }
        let finished = self.until_written(job, "the job's end", |this| {
            this.env.store.finish(&job.id, Outcome::Cancelled, None)
        });
        match finished {
            Ok(Ok(_)) => Driven::Cancelled,
            Ok(Err(error)) => Driven::Aborted(WaitError::Failed(error.to_string())),
            Err(error) => Driven::Aborted(error),
        }
    }

    fn end_by_watchdog(&mut self, job: &Run) -> Driven {
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

    fn end_waiting(&mut self, job: &Run, waiting_for: WaitingFor, detail: String) -> Driven {
        if let Err(error) = self.leave_lane(job) {
            return Driven::Aborted(error);
        }
        let requeued = self.until_written(job, "the job's wait", |this| {
            this.env
                .store
                .requeue_waiting(&job.id, waiting_for, &detail)
        });
        match requeued {
            Ok(Ok(_)) => Driven::Waiting {
                waiting_for,
                detail,
            },
            Ok(Err(error)) => Driven::Aborted(WaitError::Failed(error.to_string())),
            Err(error) => Driven::Aborted(error),
        }
    }
}

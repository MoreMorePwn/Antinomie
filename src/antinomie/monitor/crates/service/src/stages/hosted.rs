// SPDX-License-Identifier: GPL-3.0-only
//! The host stages of a collected job, with their ending (design 4.1, 4.7;
//! card P3-5): `analyse`, `report`, `cleanup`.
//!
//! [`LaneStages::host`] takes a job `drive` collected ([`Driven::Collected`])
//! and ends it, running its work items ([`super::items`]) one after another on
//! the waiter it is given. The daemon does not call it: it hands the job to the
//! host work pool ([`crate::pool`]), which runs the same items on its own
//! waiters beside the next job's lane stages (ANT-T0454); this sequential
//! form is the pool's order for one job, and what the stage tests drive.
//!
//! | The stages end with | The job |
//! |---|---|
//! | all of them worked | the outcome `collect` found (`succeeded`, or `partial` for incomplete evidence) |
//! | a problem in a stage the policy does not require | `partial`, one warning per problem |
//! | a failure in a required stage (`analysis.required_stages`) | `failed`, `analysis_failed` |
//! | a cancel | `cancelled`; the recording and the reports written so far are kept |
//! | a shutdown cancel | back in the queue (a new attempt: the VM runs again) |
//! | a signal or a dead engine | untouched: the lane file keeps the `collected` entry, and recovery resumes the job at `analyse` ([`LaneStages::resume_host`]) |
//!
//! `analysis_failed` is retried in place when the policy lists it in
//! `retry.retry_on` (4.7.2: "`analyse` and `report` only, no VM re-run"), up to
//! `max_attempts` runs of the two stages, with no backoff: the cause is not a
//! machine that needs time.
use super::{
    LaneStages, StageStop,
    collect::CollectEnd,
    items::{ItemKind, JobWork, PhaseEnd, items_for},
    plan,
    timing::{self, Timing},
};
use crate::{
    api::{
        event::StageStatus,
        failure::{Failure, FailureCode},
        job::{Job, Outcome, Stage},
    },
    engine::Engine,
    store::{RequeueKind, lock},
    waiter::{WaitError, incomplete_parts},
};
use std::{sync::Mutex, time::Duration};

/// What became of a job in the host stages.
#[derive(Debug)]
pub enum Hosted {
    /// The job is terminal (`succeeded` or `partial`).
    Finished(Box<Job>),
    /// The job ended `failed`.
    Failed(Box<Job>),
    /// The job ended `cancelled`.
    Cancelled(Box<Job>),
    /// A shutdown cancel: the job is queued again.
    Requeued,
    /// A signal or a dead engine: nothing was changed.
    Aborted(WaitError),
}

impl<E: Engine> LaneStages<'_, E> {
    /// Run the host stages of a job `drive` collected.
    pub fn host(&mut self, job: &Job, end: &CollectEnd) -> Hosted {
        match self.fresh(job) {
            Ok(job) => self.host_from(&job, end.outcome),
            Err(stop) => self.settle_host(job, Err(stop)),
        }
    }

    /// The job as the store has it now: the one a caller holds was claimed
    /// before the lane stages filled in its sample, run and recording.
    fn fresh(&self, job: &Job) -> Result<Job, StageStop> {
        self.env
            .store
            .get(&job.id)
            .map_err(|e| self.store_error(Stage::Analyse, e))
    }

    /// Resume a job after a restart: its lane stages finished (the lane file
    /// has it `collected`, `recover` lists it in `resume`), so the host stages
    /// run again from `analyse`. The outcome `collect` found is read again
    /// from the run's evidence; its warnings are already in the job.
    pub fn resume_host(&mut self, job: &Job) -> Hosted {
        let job = &match self.fresh(job) {
            Ok(job) => job,
            Err(stop) => return self.settle_host(job, Err(stop)),
        };
        let outcome = self.resumed_outcome(job);
        self.host_from(job, outcome)
    }

    /// The outcome `collect` found for a job resumed after a restart, read
    /// again from the run's evidence.
    pub(crate) fn resumed_outcome(&self, job: &Job) -> Outcome {
        self.env
            .triage
            .open_run(job)
            .ok()
            .and_then(|saved| {
                let evidence = (self.env.evidence)(&saved.run.directory).ok()?;
                Some(
                    if incomplete_parts(&saved.run, evidence.as_ref()).is_empty() {
                        Outcome::Succeeded
                    } else {
                        Outcome::Partial
                    },
                )
            })
            .unwrap_or(Outcome::Succeeded)
    }

    fn host_from(&mut self, job: &Job, outcome: Outcome) -> Hosted {
        self.cancel_hook(job);
        let result = self.host_stages(job, outcome);
        self.waiter.clear_cancel();
        self.settle_host(job, result)
    }

    /// The items of the job one after another, in their dependency order:
    /// the host work pool's order for a single job ([`super::items`]).
    fn host_stages(
        &mut self,
        job: &Job,
        outcome: Outcome,
    ) -> Result<(Job, Option<String>), StageStop> {
        self.cancel_point(job)?;
        let store = self.env.store;
        let frozen = store
            .frozen_policy(&job.id)
            .map_err(|e| self.store_error(Stage::Analyse, e))?;
        let plan = plan::hosted(job, &frozen.policy);
        let items = items_for(&plan);
        let inputs = timing::inputs_of(job, self.env.triage.load_scale());
        let rules = Timing::default();
        let limits: Vec<Duration> = items
            .iter()
            .map(|item| Duration::from_secs(rules.of(&item.kind, &plan, &inputs).limit_s))
            .collect();
        let work = Mutex::new(JobWork::new(plan.clone(), outcome));
        'tries: loop {
            self.begin_analyse(job, &plan)?;
            for (index, item) in items.iter().enumerate() {
                if item.kind.is_analyse() {
                    self.cancel_point(job)?;
                    self.run_item(job, &work, &item.kind, limits[index])?;
                }
            }
            if self.end_analyse(job, &mut lock(&work))? == PhaseEnd::Again {
                continue 'tries;
            }
            if let Some(index) = items.iter().position(|i| i.kind == ItemKind::Report) {
                self.begin_report(job)?;
                self.run_item(job, &work, &ItemKind::Report, limits[index])?;
                if self.end_report(job, &mut lock(&work))? == PhaseEnd::Again {
                    continue 'tries;
                }
            }
            break;
        }
        let work = lock(&work);
        self.conclude(job, &work)
    }

    /// `[verdict] tag_library` (coordinator decision for 0.9.0, design
    /// 4.9.3): the sample gets the library tags `auto:label=<label>` and
    /// `auto:policy=<name>`, written under the automation actor
    /// (`auto:policy-<name>`) in its custody chain. A tag that cannot be
    /// written is a warning; the job does not fail for it.
    pub(super) fn tag_library(&mut self, job: &Job, frozen: &crate::config::LoadedPolicy) {
        if !frozen.policy.verdict.tag_library {
            return;
        }
        let Ok(fresh) = self.env.store.get(&job.id) else {
            return;
        };
        let mut tags = vec![format!("auto:policy={}", frozen.name)];
        if let Some(label) = fresh.assessment.as_ref().and_then(|a| a.label) {
            let name = serde_json::to_value(label)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            tags.push(format!("auto:label={name}"));
        }
        for tag in tags {
            if let Err(error) = self.env.tags.add_tag(&fresh, &tag) {
                self.warn(
                    job,
                    "library_tag",
                    &format!("the tag {tag} was not written: {error}"),
                );
            }
        }
    }

    pub(super) fn skip_stage(&mut self, job: &Job, stage: Stage) -> Result<(), StageStop> {
        let store = self.env.store;
        store
            .begin_stage(&job.id, stage)
            .and_then(|_| store.end_stage(&job.id, StageStatus::Skipped))
            .map(|_| ())
            .map_err(|e| self.store_error(stage, e))
    }

    pub(crate) fn settle_host(
        &mut self,
        job: &Job,
        result: Result<(Job, Option<String>), StageStop>,
    ) -> Hosted {
        let store = self.env.store;
        let stop = match result {
            Ok((done, _problem)) => return Hosted::Finished(Box::new(done)),
            Err(stop) => stop,
        };
        let now = self.waiter.now_ms();
        let release = |this: &mut Self| {
            let _ = this.update_lane(|file| file.release(&job.id, now));
        };
        match stop {
            StageStop::Abort(error @ (WaitError::Disconnected(_) | WaitError::Interrupted)) => {
                Hosted::Aborted(error)
            }
            StageStop::Abort(WaitError::Cancelled) | StageStop::Cancelled => {
                release(self);
                if store.cancel_is_shutdown(&job.id).unwrap_or(false) {
                    return match store.requeue(
                        &job.id,
                        RequeueKind::Shutdown,
                        "service_shutdown",
                        None,
                        None,
                    ) {
                        Ok(_) => Hosted::Requeued,
                        Err(error) => Hosted::Aborted(WaitError::Failed(error.to_string())),
                    };
                }
                match self.end_job(job, Outcome::Cancelled, None) {
                    Ok((done, _)) => Hosted::Cancelled(Box::new(done)),
                    Err(StageStop::Abort(error)) => Hosted::Aborted(error),
                    Err(_) => {
                        Hosted::Aborted(WaitError::Failed("the job could not be ended".into()))
                    }
                }
            }
            StageStop::Abort(other) => self.fail_host(
                job,
                Failure::new(
                    FailureCode::Internal,
                    self.host_stage(job),
                    "the engine failed the host stages",
                    Some(&other.to_string()),
                ),
            ),
            StageStop::Failed(failure) => self.fail_host(job, failure),
            StageStop::Wait { detail, .. } => self.fail_host(
                job,
                Failure::new(
                    FailureCode::Internal,
                    self.host_stage(job),
                    "a host stage waited, which it cannot",
                    Some(&detail),
                ),
            ),
        }
    }

    fn host_stage(&self, job: &Job) -> Stage {
        self.env
            .store
            .get(&job.id)
            .ok()
            .and_then(|job| job.stage)
            .unwrap_or(Stage::Analyse)
    }

    fn fail_host(&mut self, job: &Job, failure: Failure) -> Hosted {
        match self.end_job(job, Outcome::Failed, Some(failure)) {
            Ok((done, _)) => Hosted::Failed(Box::new(done)),
            Err(StageStop::Abort(error)) => Hosted::Aborted(error),
            Err(_) => Hosted::Aborted(WaitError::Failed("the job could not be ended".into())),
        }
    }
}

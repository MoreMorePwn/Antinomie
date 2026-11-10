// SPDX-License-Identifier: GPL-3.0-only
//! The host stages of a collected job, with their ending (design 4.1, 4.7;
//! card P3-5): `analyse`, `report`, `cleanup`.
//!
//! [`LaneStages::host`] takes a job `drive` collected ([`Driven::Collected`])
//! and ends it. The lane is free by then, so these stages run beside the next
//! job's lane stages when the caller has a second waiter; this card runs them
//! on the waiter it is given (the daemon cards decide the threads).
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
    analyse::Analysed,
    collect::CollectEnd,
    plan::{self, HostPlan},
};
use crate::{
    api::{
        event::StageStatus,
        failure::{Failure, FailureCode},
        job::{Job, Outcome, Stage},
    },
    engine::Engine,
    store::RequeueKind,
    waiter::{WaitError, incomplete_parts},
};

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
        let triage = self.env.triage;
        let outcome = triage
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
            .unwrap_or(Outcome::Succeeded);
        self.host_from(job, outcome)
    }

    fn host_from(&mut self, job: &Job, outcome: Outcome) -> Hosted {
        self.cancel_hook(job);
        let result = self.host_stages(job, outcome);
        self.waiter.clear_cancel();
        self.settle_host(job, result)
    }

    fn host_stages(
        &mut self,
        job: &Job,
        mut outcome: Outcome,
    ) -> Result<(Job, Option<String>), StageStop> {
        self.cancel_point(job)?;
        let store = self.env.store;
        let frozen = store
            .frozen_policy(&job.id)
            .map_err(|e| self.store_error(Stage::Analyse, e))?;
        let plan = plan::hosted(job, &frozen.policy);
        let mut tries = 0;
        let analysed = loop {
            tries += 1;
            match self.analyse_and_report(job, &plan, &mut outcome) {
                Err(StageStop::Failed(failure))
                    if failure.code == FailureCode::AnalysisFailed
                        && plan.retry_analysis
                        && tries < plan.max_attempts.max(1) =>
                {
                    self.warn(
                        job,
                        "analysis_retry",
                        &format!("{}; the stages are run again", failure.message),
                    );
                }
                other => break other?,
            }
        };
        let _ = analysed;
        self.cancel_point(job)?;
        store
            .begin_stage(&job.id, Stage::Cleanup)
            .map_err(|e| self.store_error(Stage::Cleanup, e))?;
        self.tag_library(job, &frozen);
        self.end_job(job, outcome, None)
    }

    /// `[verdict] tag_library` (coordinator decision for 0.9.0, design
    /// 4.9.3): the sample gets the library tags `auto:label=<label>` and
    /// `auto:policy=<name>`, written under the automation actor
    /// (`auto:policy-<name>`) in its custody chain. A tag that cannot be
    /// written is a warning; the job does not fail for it.
    fn tag_library(&mut self, job: &Job, frozen: &crate::config::LoadedPolicy) {
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

    /// `analyse` then `report`, each with its records; a problem in a stage
    /// the policy does not require is a warning and makes the job `partial`.
    fn analyse_and_report(
        &mut self,
        job: &Job,
        plan: &HostPlan,
        outcome: &mut Outcome,
    ) -> Result<Analysed, StageStop> {
        let store = self.env.store;
        let mut analysed = Analysed {
            scan: None,
            problems: Vec::new(),
            incomplete: Vec::new(),
        };
        if plan.analyse_skipped() {
            self.skip_stage(job, Stage::Analyse)?;
            // Triage did not run: the job still gets its (inconclusive) label.
            let mut none = Vec::new();
            self.assess(job, None, &mut none)?;
        } else {
            analysed = self.stage(job, Stage::Analyse, false, |this| this.analyse(job, plan))?;
            store
                .end_stage(&job.id, StageStatus::Finished)
                .map_err(|e| self.store_error(Stage::Analyse, e))?;
            for problem in &analysed.problems {
                self.warn(job, "analysis_failed", problem);
            }
            for note in &analysed.incomplete {
                self.warn(job, "static_check_incomplete", note);
            }
            if !analysed.problems.is_empty() || !analysed.incomplete.is_empty() {
                *outcome = Outcome::Partial;
            }
        }
        self.cancel_point(job)?;
        if plan.report_skipped() {
            self.skip_stage(job, Stage::Report)?;
            return Ok(analysed);
        }
        match self.stage(job, Stage::Report, false, |this| {
            this.report(job, plan, &analysed)
        }) {
            Ok(_) => {
                store
                    .end_stage(&job.id, StageStatus::Finished)
                    .map_err(|e| self.store_error(Stage::Report, e))?;
            }
            Err(StageStop::Failed(failure)) if !plan.requires(Stage::Report) => {
                self.warn(
                    job,
                    "report_failed",
                    &format!(
                        "{}{}",
                        failure.message,
                        failure
                            .detail
                            .as_deref()
                            .map(|d| format!(": {d}"))
                            .unwrap_or_default()
                    ),
                );
                *outcome = Outcome::Partial;
            }
            Err(other) => return Err(other),
        }
        Ok(analysed)
    }

    fn skip_stage(&mut self, job: &Job, stage: Stage) -> Result<(), StageStop> {
        let store = self.env.store;
        store
            .begin_stage(&job.id, stage)
            .and_then(|_| store.end_stage(&job.id, StageStatus::Skipped))
            .map(|_| ())
            .map_err(|e| self.store_error(stage, e))
    }

    fn settle_host(
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

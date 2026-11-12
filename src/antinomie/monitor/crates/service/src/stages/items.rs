// SPDX-License-Identifier: GPL-3.0-only
//! The host work of a collected job as separate items (ANT-T0454, user
//! decision 2026-11-11 section 2), so a slow one does not hold up the rest.
//!
//! | Item | Does | Waits for |
//! |---|---|---|
//! | `triage` | opens the saved run and indexes it | nothing |
//! | `static:<tool>` | one static tool on the library copy (`static:strings+regex`: Regex reads the strings) | nothing |
//! | `detection` | YARA, Sigma and IDS over the indexed run | `triage` |
//! | `assess` | the run's digest and the assessment (label) | `triage`, `detection` |
//! | `report` | the report files | every item above |
//!
//! The items of a job are listed in that order, which is a dependency order;
//! the host work pool ([`crate::pool`]) starts them first come, first served
//! by job arrival, and [`LaneStages::host`] runs them one after another. The
//! job-level steps between them are here too: the end of `analyse` (the
//! problems become warnings, or the failure of a required stage, or a retry),
//! the end of `report`, and the ending of the job (`cleanup`).
use super::{LaneStages, StageStop, plan::HostPlan};
use crate::{
    api::{
        event::StageStatus,
        failure::{Failure, FailureCode},
        job::{HostItem, HostItemState, Job, Outcome, Stage},
    },
    engine::Engine,
    store::lock,
};
use antinomie_monitor_core::analysis::{AnalysisKind, detection::Engine as DetectionEngine};
use antinomie_triage::{ArchiveScan, SavedRun, detection::Outcome as DetectOutcome};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemKind {
    Triage,
    /// One static tool, or Strings (or FLOSS) with Regex.
    Static(Vec<AnalysisKind>),
    Detection,
    Assess,
    Report,
}

impl ItemKind {
    /// The name in `job.host_work` and in the run-time history.
    pub fn name(&self) -> String {
        match self {
            Self::Triage => "triage".into(),
            Self::Static(group) => format!(
                "static:{}",
                group
                    .iter()
                    .map(|k| format!("{k:?}").to_lowercase())
                    .collect::<Vec<_>>()
                    .join("+")
            ),
            Self::Detection => "detection".into(),
            Self::Assess => "assess".into(),
            Self::Report => "report".into(),
        }
    }

    /// The item belongs to the `analyse` stage (everything but the report).
    pub fn is_analyse(&self) -> bool {
        !matches!(self, Self::Report)
    }
}

/// One item of a job's list: what it is and the items (by index) it waits for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemSpec {
    pub kind: ItemKind,
    pub after: Vec<usize>,
}

/// The static checks as items: one per tool, Regex with Strings (else with
/// FLOSS), whose strings it matches.
pub fn static_groups(checks: &[AnalysisKind]) -> Vec<Vec<AnalysisKind>> {
    let mut groups: Vec<Vec<AnalysisKind>> = checks
        .iter()
        .filter(|k| **k != AnalysisKind::Regex)
        .map(|k| vec![*k])
        .collect();
    if checks.contains(&AnalysisKind::Regex) {
        let at = groups
            .iter()
            .position(|g| g[0] == AnalysisKind::Strings)
            .or_else(|| groups.iter().position(|g| g[0] == AnalysisKind::Floss));
        match at {
            Some(at) => groups[at].push(AnalysisKind::Regex),
            None => groups.push(vec![AnalysisKind::Regex]),
        }
    }
    groups
}

/// The items of a job with `plan`, in dependency order.
pub fn items_for(plan: &HostPlan) -> Vec<ItemSpec> {
    let mut items: Vec<ItemSpec> = Vec::new();
    let push = |items: &mut Vec<ItemSpec>, kind, after| {
        items.push(ItemSpec { kind, after });
        items.len() - 1
    };
    if plan.analyse_skipped() {
        // Nothing to analyse: the job still gets its (inconclusive) label.
        push(&mut items, ItemKind::Assess, Vec::new());
    } else {
        let triage = (plan.triage || !plan.engines.is_empty())
            .then(|| push(&mut items, ItemKind::Triage, Vec::new()));
        for group in static_groups(&plan.static_checks) {
            push(&mut items, ItemKind::Static(group), Vec::new());
        }
        let detection = (!plan.engines.is_empty()).then(|| {
            push(
                &mut items,
                ItemKind::Detection,
                triage.into_iter().collect(),
            )
        });
        push(
            &mut items,
            ItemKind::Assess,
            triage.into_iter().chain(detection).collect(),
        );
    }
    if !plan.report_skipped() {
        let all = (0..items.len()).collect();
        push(&mut items, ItemKind::Report, all);
    }
    items
}

/// What the items of a job share while it is in the host stages.
pub struct JobWork {
    pub plan: HostPlan,
    /// The outcome so far: what `collect` found, `partial` after a problem.
    pub outcome: Outcome,
    pub scan: Option<Arc<(SavedRun, ArchiveScan)>>,
    pub outcomes: Arc<Vec<(DetectionEngine, DetectOutcome)>>,
    /// Steps that failed, in words.
    pub problems: Vec<String>,
    /// Static checks that ran out of time or stopped short.
    pub incomplete: Vec<String>,
    pub digest_note: Option<String>,
    /// The report's failure, read by [`LaneStages::end_report`].
    pub report_failure: Option<Failure>,
    /// Runs of the two stages so far (an `analysis_failed` retry is another).
    pub tries: u32,
}

impl JobWork {
    pub fn new(plan: HostPlan, outcome: Outcome) -> Self {
        Self {
            plan,
            outcome,
            scan: None,
            outcomes: Arc::new(Vec::new()),
            problems: Vec::new(),
            incomplete: Vec::new(),
            digest_note: None,
            report_failure: None,
            tries: 1,
        }
    }

    /// Forget what the last run of the stages found: they run again.
    pub fn again(&mut self) {
        self.scan = None;
        self.outcomes = Arc::new(Vec::new());
        self.problems.clear();
        self.incomplete.clear();
        self.digest_note = None;
        self.report_failure = None;
        self.tries += 1;
    }
}

/// How an item ended, when it did not stop the job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemEnd {
    pub state: HostItemState,
    pub note: Option<String>,
    /// Milliseconds it waited for the engine to start it (a static item in
    /// the engine's own queue): not its own run time.
    pub waited_ms: u64,
}

fn ended(state: HostItemState, note: Option<String>) -> ItemEnd {
    ItemEnd {
        state,
        note,
        waited_ms: 0,
    }
}

/// What a job-level step decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PhaseEnd {
    /// The stages run again (an `analysis_failed` retry in place).
    Again,
    /// Go on.
    Next,
}

/// The view of an item in `job.host_work`.
pub fn host_item(spec: &ItemSpec, all: &[ItemSpec], time: &super::timing::ItemTime) -> HostItem {
    HostItem {
        name: spec.kind.name(),
        state: HostItemState::Queued,
        after: spec.after.iter().map(|i| all[*i].kind.name()).collect(),
        expected_s: time.expected_s,
        basis: time.basis.to_owned(),
        limit_s: time.limit_s,
        started_ms: None,
        finished_ms: None,
        note: None,
    }
}

impl<E: Engine> LaneStages<'_, E> {
    /// Run one item with no job deadline; what it found goes into `work`.
    pub fn run_item(
        &mut self,
        job: &Job,
        work: &Mutex<JobWork>,
        kind: &ItemKind,
        limit: Duration,
    ) -> Result<ItemEnd, StageStop> {
        self.run_item_until(job, work, kind, limit, Duration::MAX)
    }

    /// Run one item; `until` is the time left before the job's deadline,
    /// which also bounds the wait for the engine to take a static item.
    pub fn run_item_until(
        &mut self,
        job: &Job,
        work: &Mutex<JobWork>,
        kind: &ItemKind,
        limit: Duration,
        until: Duration,
    ) -> Result<ItemEnd, StageStop> {
        let (plan, scan, outcomes) = {
            let w = lock(work);
            (w.plan.clone(), w.scan.clone(), Arc::clone(&w.outcomes))
        };
        match kind {
            ItemKind::Triage => match self.triage_item(job, limit)? {
                Ok(done) => {
                    lock(work).scan = Some(Arc::new(done));
                    Ok(ended(HostItemState::Done, None))
                }
                Err((problem, timed_out)) => {
                    lock(work).problems.push(problem.clone());
                    Ok(ended(
                        if timed_out {
                            HostItemState::TimedOut
                        } else {
                            HostItemState::Failed
                        },
                        Some(problem),
                    ))
                }
            },
            ItemKind::Static(group) => {
                let (outcome, timed_out, waited_ms) =
                    self.static_item(job, &plan, group, limit, until)?;
                let words: Vec<String> =
                    outcome.hard.iter().chain(&outcome.soft).cloned().collect();
                let state = if timed_out {
                    HostItemState::TimedOut
                } else if words.is_empty() {
                    HostItemState::Done
                } else {
                    HostItemState::Failed
                };
                let mut w = lock(work);
                w.problems.extend(outcome.hard);
                w.incomplete.extend(outcome.soft);
                Ok(ItemEnd {
                    waited_ms,
                    ..ended(state, (!words.is_empty()).then(|| words.join("; ")))
                })
            }
            ItemKind::Detection => {
                let Some(scan) = scan else {
                    return Ok(ended(
                        HostItemState::Skipped,
                        Some("there is no Triage scan to run the engines on".into()),
                    ));
                };
                let (found, problems, timed_out) = self.detection_item(job, &plan, &scan, limit)?;
                let state = if timed_out {
                    HostItemState::TimedOut
                } else if problems.is_empty() {
                    HostItemState::Done
                } else {
                    HostItemState::Failed
                };
                let note = (!problems.is_empty()).then(|| problems.join("; "));
                let mut w = lock(work);
                w.outcomes = Arc::new(found);
                w.problems.extend(problems);
                Ok(ended(state, note))
            }
            ItemKind::Assess => self.assess_item(job, work, &plan, scan, &outcomes, limit),
            ItemKind::Report => match self.report(job, &plan, scan.as_deref(), limit) {
                Ok(_) => Ok(ended(HostItemState::Done, None)),
                Err(StageStop::Failed(failure)) => {
                    let note = format!(
                        "{}{}",
                        failure.message,
                        failure
                            .detail
                            .as_deref()
                            .map(|d| format!(": {d}"))
                            .unwrap_or_default()
                    );
                    lock(work).report_failure = Some(failure);
                    Ok(ended(HostItemState::Failed, Some(note)))
                }
                Err(other) => Err(other),
            },
        }
    }

    /// The `assess` item: the digest, then the assessment. The item's limit
    /// covers the three steps together.
    fn assess_item(
        &mut self,
        job: &Job,
        work: &Mutex<JobWork>,
        plan: &HostPlan,
        scan: Option<Arc<(SavedRun, ArchiveScan)>>,
        outcomes: &[(DetectionEngine, DetectOutcome)],
        limit: Duration,
    ) -> Result<ItemEnd, StageStop> {
        let began = self.waiter.now_ms();
        let left = |this: &Self| {
            limit.saturating_sub(Duration::from_millis(
                this.waiter.now_ms().saturating_sub(began),
            ))
        };
        if plan.analyse_skipped() {
            self.skip_stage(job, Stage::Analyse)?;
            let mut none = Vec::new();
            self.assess(job, None, &mut none, limit)?;
            return Ok(ended(HostItemState::Done, None));
        }
        let mut problems = Vec::new();
        if let Some(scan) = &scan
            && let Some(problem) = self.save_digest_item(scan, outcomes, left(self))?
        {
            problems.push(problem);
        }
        let note = self.digest(job, left(self))?;
        let triage_ran = plan.triage && scan.is_some();
        self.assess(
            job,
            scan.as_deref().filter(|_| triage_ran),
            &mut problems,
            left(self),
        )?;
        let words = (!problems.is_empty()).then(|| problems.join("; "));
        let mut w = lock(work);
        w.digest_note = note;
        w.problems.extend(problems);
        Ok(ended(
            if words.is_some() {
                HostItemState::Failed
            } else {
                HostItemState::Done
            },
            words,
        ))
    }

    /// The first `analyse` item starts: the stage begins (not when the
    /// analysis was skipped; `assess` records that).
    pub fn begin_analyse(&mut self, job: &Job, plan: &HostPlan) -> Result<(), StageStop> {
        self.cancel_point(job)?;
        if plan.analyse_skipped() {
            return Ok(());
        }
        self.env
            .store
            .begin_stage(&job.id, Stage::Analyse)
            .map(|_| ())
            .map_err(|e| self.store_error(Stage::Analyse, e))
    }

    /// Every `analyse` item has ended: a problem in a required stage fails
    /// it (or the stages run again), otherwise each problem is a warning and
    /// the job is `partial`. A skipped report is recorded here.
    pub fn end_analyse(&mut self, job: &Job, work: &mut JobWork) -> Result<PhaseEnd, StageStop> {
        let store = self.env.store;
        if !work.plan.analyse_skipped() {
            if !work.problems.is_empty() && work.plan.requires(Stage::Analyse) {
                let _ = store.end_stage(&job.id, StageStatus::Failed);
                let failure = Failure::new(
                    FailureCode::AnalysisFailed,
                    Stage::Analyse,
                    "the analysis of the recording failed",
                    Some(&work.problems.join("; ")),
                );
                return self.retry_or_fail(job, work, failure);
            }
            store
                .end_stage(&job.id, StageStatus::Finished)
                .map_err(|e| self.store_error(Stage::Analyse, e))?;
            if let Some(note) = &work.digest_note {
                let _ = store.add_warning(&job.id, "digest_incomplete", note);
            }
            for problem in &work.problems {
                self.warn(job, "analysis_failed", problem);
            }
            for note in &work.incomplete {
                self.warn(job, "static_check_incomplete", note);
            }
            if !work.problems.is_empty() || !work.incomplete.is_empty() {
                work.outcome = Outcome::Partial;
            }
        }
        self.cancel_point(job)?;
        if work.plan.report_skipped() {
            self.skip_stage(job, Stage::Report)?;
        }
        Ok(PhaseEnd::Next)
    }

    fn retry_or_fail(
        &mut self,
        job: &Job,
        work: &mut JobWork,
        failure: Failure,
    ) -> Result<PhaseEnd, StageStop> {
        if failure.code == FailureCode::AnalysisFailed
            && work.plan.retry_analysis
            && work.tries < work.plan.max_attempts.max(1)
        {
            self.warn(
                job,
                "analysis_retry",
                &format!("{}; the stages are run again", failure.message),
            );
            work.again();
            return Ok(PhaseEnd::Again);
        }
        Err(StageStop::Failed(failure))
    }

    /// The report item starts.
    pub fn begin_report(&mut self, job: &Job) -> Result<(), StageStop> {
        self.cancel_point(job)?;
        self.env
            .store
            .begin_stage(&job.id, Stage::Report)
            .map(|_| ())
            .map_err(|e| self.store_error(Stage::Report, e))
    }

    /// The report item has ended.
    pub fn end_report(&mut self, job: &Job, work: &mut JobWork) -> Result<PhaseEnd, StageStop> {
        let store = self.env.store;
        let Some(failure) = work.report_failure.take() else {
            store
                .end_stage(&job.id, StageStatus::Finished)
                .map_err(|e| self.store_error(Stage::Report, e))?;
            return Ok(PhaseEnd::Next);
        };
        let _ = store.end_stage(&job.id, StageStatus::Failed);
        if !work.plan.requires(Stage::Report) {
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
            work.outcome = Outcome::Partial;
            return Ok(PhaseEnd::Next);
        }
        self.retry_or_fail(job, work, failure)
    }

    /// `cleanup`: the library tags and the end of the job.
    pub fn conclude(
        &mut self,
        job: &Job,
        work: &JobWork,
    ) -> Result<(Job, Option<String>), StageStop> {
        self.cancel_point(job)?;
        let store = self.env.store;
        let frozen = store
            .frozen_policy(&job.id)
            .map_err(|e| self.store_error(Stage::Cleanup, e))?;
        store
            .begin_stage(&job.id, Stage::Cleanup)
            .map_err(|e| self.store_error(Stage::Cleanup, e))?;
        self.tag_library(job, &frozen);
        self.end_job(job, work.outcome, None)
    }
}

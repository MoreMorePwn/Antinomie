// SPDX-License-Identifier: GPL-3.0-only
//! `analyse` (design 4.1; card P3-5): the host-side work on a finished,
//! settled recording.
//!
//! 1. **Static analysis of the library copy**, `Command::AnalyzeSample` in
//!    bubblewrap (outside the lane, so the VM is not busy), for the policy's
//!    checks, bounded by `static_s` = tools x limit x 60 + 60.
//! 2. **The Triage scan**, then **the detection engines** over the finished
//!    recording, then the run's **digest**. These are the builders the GUI and
//!    `antinomie-cli triage/detect` call (`antinomie_triage`); they run on a
//!    worker thread bounded by `analyse_s` (900 s) and a cancel flag.
//! 3. **The assessment**: the Triage summary and the detections go through the
//!    policy's verdict mapping ([`crate::verdict`]); the result is stored with
//!    the job (`job.assessment`). It is computed here and not in `report`, so
//!    a job that asks for no report still has its label (departure from 4.1,
//!    which has `report` build it).
//!
//! A step that fails is a *problem*. If the policy requires the `analyse`
//! stage (`analysis.required_stages`) the stage fails `analysis_failed`;
//! otherwise each problem is a job warning, the job ends `partial`, and a job
//! whose Triage scan failed gets the label `inconclusive`.
use super::{
    LaneStages, StageStop,
    host::{Built, HostTriage},
    plan::{ANALYSE_WAIT, HostPlan},
};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        job::{Job, Stage},
    },
    engine::Engine,
    verdict::{Facts, Mapping, assessment_of},
    waiter::{WaitError, millis},
};
use antinomie_monitor_core::{
    Command,
    analysis::{
        AnalysisLimits, AnalysisSelection, AnalysisState, detection::Engine as DetectionEngine,
    },
    report::{Choices, Part},
};
use antinomie_triage::{ArchiveScan, SavedRun, detection::Outcome};
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

/// How often a bounded worker is looked at; the engine is pumped meanwhile.
const POLL: Duration = Duration::from_millis(20);

/// What `analyse` leaves for `report`.
pub struct Analysed {
    /// The saved run and its index, when Triage ran.
    pub scan: Option<(SavedRun, ArchiveScan)>,
    /// Steps that failed, in words (the job has them as warnings).
    pub problems: Vec<String>,
}

/// Why a bounded worker did not hand back its result.
pub(crate) enum Bounded {
    TimedOut,
    Cancelled,
    Aborted(WaitError),
    Panicked,
}

impl Bounded {
    /// The stage stop for a worker that was cancelled or whose engine died;
    /// `None` for a timeout and a panic, which the stage turns into a problem.
    pub(crate) fn stop(&self) -> Option<StageStop> {
        match self {
            Self::Cancelled => Some(StageStop::Cancelled),
            Self::Aborted(error) => Some(StageStop::Abort(error.clone())),
            Self::TimedOut | Self::Panicked => None,
        }
    }

    pub(crate) fn words(&self, what: &str) -> String {
        match self {
            Self::TimedOut => format!("{what} did not finish in time and was stopped"),
            Self::Panicked => format!("{what} failed unexpectedly"),
            Self::Cancelled => format!("{what} was cancelled"),
            Self::Aborted(error) => format!("{what} was interrupted: {error}"),
        }
    }
}

impl<E: Engine> LaneStages<'_, E> {
    /// Run `work` on a thread, pumping the engine and honouring a cancel and
    /// `limit`. The worker is told to stop through its cancel flag and is
    /// always joined before this returns.
    pub(crate) fn bounded<T: Send>(
        &mut self,
        limit: Duration,
        work: impl FnOnce(&Arc<AtomicBool>) -> T + Send,
    ) -> Result<T, Bounded> {
        let cancel = Arc::new(AtomicBool::new(false));
        let deadline = self.waiter.now_ms() + millis(limit);
        let mut stop: Option<Bounded> = None;
        let result = std::thread::scope(|scope| {
            let flag = Arc::clone(&cancel);
            let handle = scope.spawn(move || work(&flag));
            while !handle.is_finished() {
                if stop.is_none() {
                    if self.waiter.cancel_requested() {
                        stop = Some(Bounded::Cancelled);
                    } else if self.waiter.now_ms() >= deadline {
                        stop = Some(Bounded::TimedOut);
                    }
                    if stop.is_some() {
                        cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                match self.waiter.pump(POLL) {
                    Ok(_) => {}
                    Err(error) => {
                        if stop.is_none() {
                            stop = Some(Bounded::Aborted(error));
                            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            handle.join()
        });
        match (stop, result) {
            (Some(why), _) => Err(why),
            (None, Ok(value)) => Ok(value),
            (None, Err(_)) => Err(Bounded::Panicked),
        }
    }

    /// The library copy through `AnalyzeSample`.
    fn static_analysis(&mut self, job: &Job, plan: &HostPlan) -> Result<Option<String>, StageStop> {
        let Some(sample) = job.sample.as_ref() else {
            return Ok(Some("the job has no sample to analyse".into()));
        };
        let selection = AnalysisSelection {
            enabled: true,
            checks: plan.static_checks.clone(),
            time_limit_minutes: plan.static_limit_min,
            limits: AnalysisLimits::default(),
        };
        self.progress(job, Stage::Analyse, "static analysis of the library copy");
        let limit = plan.static_wait();
        let began = self.waiter.now_ms();
        let id = match self.waiter.command(
            Command::AnalyzeSample {
                sha256: sample.sha256.to_string(),
                selection,
            },
            Some(limit),
        ) {
            Ok(id) => id,
            Err(WaitError::Failed(message)) => {
                return Ok(Some(format!("static analysis was refused: {message}")));
            }
            Err(WaitError::TimedOut { .. }) => {
                return Ok(Some("static analysis did not start in time".into()));
            }
            Err(other) => return Err(StageStop::Abort(other)),
        };
        let left = limit.saturating_sub(Duration::from_millis(self.waiter.now_ms() - began));
        let finished = |report: &antinomie_monitor_core::analysis::AnalysisReport| {
            !matches!(
                report.state,
                AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
            )
        };
        let watched = id.clone();
        match self
            .waiter
            .wait_until("the static analysis to finish", Some(left), move |s| {
                s.analysis_reports
                    .iter()
                    .any(|r| r.id == watched && finished(r))
            }) {
            Ok(()) => {}
            Err(WaitError::TimedOut { .. }) => {
                return Ok(Some(format!(
                    "static analysis did not finish within {} seconds",
                    limit.as_secs()
                )));
            }
            Err(other) => return Err(StageStop::Abort(other)),
        }
        let report = self
            .waiter
            .snapshot()
            .analysis_reports
            .iter()
            .find(|r| r.id == id)
            .cloned();
        Ok(match report.map(|r| (r.state, r.reason)) {
            Some((AnalysisState::Complete, _)) => None,
            Some((AnalysisState::Partial, _)) => {
                Some("static analysis finished partly (a tool ran out of time)".into())
            }
            Some((state, reason)) => Some(format!(
                "static analysis ended {state:?}{}",
                reason.map(|r| format!(": {r}")).unwrap_or_default()
            )),
            None => Some("static analysis left no report".into()),
        })
    }

    /// The Triage scan, the engines and the digest.
    fn triage(
        &mut self,
        job: &Job,
        plan: &HostPlan,
        problems: &mut Vec<String>,
    ) -> Result<Option<(SavedRun, ArchiveScan)>, StageStop> {
        let triage: &dyn HostTriage = self.env.triage;
        let engines: Vec<DetectionEngine> = plan.engines.clone();
        self.progress(job, Stage::Analyse, "indexing the recording");
        let worked = self.bounded(ANALYSE_WAIT, |cancel| {
            let saved = triage.open_run(job)?;
            let scan = triage.index(&saved, cancel)?;
            let mut notes = Vec::new();
            let outcomes = if engines.is_empty() {
                Vec::new()
            } else {
                match triage.detect(&saved, &scan, &engines, cancel) {
                    Ok(outcomes) => outcomes,
                    Err(error) => {
                        notes.push(format!("the detection engines did not run: {error}"));
                        Vec::new()
                    }
                }
            };
            if let Err(error) = triage.save_digest(&saved, &scan, &outcomes) {
                notes.push(format!("the run's digest was not written: {error}"));
            }
            Ok::<_, String>((saved, scan, outcomes, notes))
        });
        let (saved, scan, outcomes, notes) = match worked {
            Ok(Ok(done)) => done,
            Ok(Err(error)) => {
                problems.push(format!("the Triage scan failed: {error}"));
                return Ok(None);
            }
            Err(why) => {
                if let Some(stop) = why.stop() {
                    return Err(stop);
                }
                problems.push(why.words("the Triage scan"));
                return Ok(None);
            }
        };
        problems.extend(notes);
        for (engine, outcome) in outcomes {
            let name = antinomie_triage::detection::name(engine);
            match outcome {
                Outcome::Scanned(_) => {}
                Outcome::Skipped(_, words) => {
                    let _ = self.env.store.add_warning(
                        &job.id,
                        "detection_skipped",
                        &format!("{name} was not run: {words}"),
                    );
                }
                Outcome::Failed(error) => {
                    problems.push(format!("the {name} engine failed: {error}"));
                }
            }
        }
        Ok(Some((saved, scan)))
    }

    /// The summary and detections of the scanned run, through the mapping.
    pub(super) fn assess(
        &mut self,
        job: &Job,
        scanned: Option<&(SavedRun, ArchiveScan)>,
        problems: &mut Vec<String>,
    ) -> Result<(), StageStop> {
        let store = self.env.store;
        let frozen = store
            .frozen_policy(&job.id)
            .map_err(|e| self.store_error(Stage::Analyse, e))?;
        let current = store
            .get(&job.id)
            .map_err(|e| self.store_error(Stage::Analyse, e))?;
        let end_reason = current.run.as_ref().and_then(|run| run.end_reason);
        let triage: &dyn HostTriage = self.env.triage;
        let datasets = triage.ioc_datasets();
        let mapping = match Mapping::compile(&frozen.policy.verdict) {
            Ok(mapping) => mapping,
            Err(error) => {
                problems.push(format!("the verdict mapping cannot be used: {error}"));
                Mapping::compile(&Default::default()).expect("the default mapping compiles")
            }
        };
        let facts = match scanned {
            None => Facts::without_triage(end_reason, datasets),
            Some((saved, scan)) => {
                let choices = Choices {
                    parts: vec![Part::Summary, Part::Attack, Part::Detections],
                    formats: Vec::new(),
                    bundle: false,
                    ..Choices::default()
                };
                let now = super::host::now_ms();
                let built = self.bounded(ANALYSE_WAIT, |_| {
                    triage
                        .build(saved, scan, choices, now)
                        .map(|built| facts_of(&built, end_reason, datasets))
                });
                match built {
                    Ok(Ok(facts)) => facts,
                    Ok(Err(error)) => {
                        problems.push(format!("the summary could not be built: {error}"));
                        Facts::without_triage(end_reason, datasets)
                    }
                    Err(why) => {
                        if let Some(stop) = why.stop() {
                            return Err(stop);
                        }
                        problems.push(why.words("the summary"));
                        Facts::without_triage(end_reason, datasets)
                    }
                }
            }
        };
        let verdict = mapping.judge(&facts);
        store
            .set_assessment(&job.id, &assessment_of(&facts, &verdict))
            .map_err(|e| self.store_error(Stage::Analyse, e))?;
        Ok(())
    }

    /// The `analyse` stage. `Ok` carries the problems that did not fail it.
    pub fn analyse(&mut self, job: &Job, plan: &HostPlan) -> Result<Analysed, StageStop> {
        let mut problems = Vec::new();
        if !plan.static_checks.is_empty() {
            if let Some(problem) = self.static_analysis(job, plan)? {
                problems.push(problem);
            }
            self.cancel_point(job)?;
        }
        let scanned = if plan.triage || !plan.engines.is_empty() {
            self.triage(job, plan, &mut problems)?
        } else {
            None
        };
        self.cancel_point(job)?;
        let triage_ran = plan.triage && scanned.is_some();
        self.assess(job, scanned.as_ref().filter(|_| triage_ran), &mut problems)?;
        if !problems.is_empty() && plan.requires(Stage::Analyse) {
            return Err(StageStop::Failed(Failure::new(
                FailureCode::AnalysisFailed,
                Stage::Analyse,
                "the analysis of the recording failed",
                Some(&problems.join("; ")),
            )));
        }
        Ok(Analysed {
            scan: scanned,
            problems,
        })
    }
}

fn facts_of(built: &Built, end_reason: Option<crate::api::job::EndReason>, datasets: u32) -> Facts {
    let report = built.report();
    Facts::of_report(
        &built.summary(),
        report.detections.as_deref().unwrap_or_default(),
        report.attack.as_deref().unwrap_or_default(),
        end_reason,
        datasets,
    )
}

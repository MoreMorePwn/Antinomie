// SPDX-License-Identifier: GPL-3.0-only
//! `analyse` (design 4.1; card P3-5): the host-side work on a finished,
//! settled recording, as the separate work items of the host work pool
//! (ANT-T0454, [`super::items`]).
//!
//! 1. **Static analysis of the library copy**, `Command::AnalyzeSample` in
//!    bubblewrap (outside the lane, so the VM is not busy): one item per tool
//!    (Regex goes with Strings, or FLOSS, whose strings it reads), each
//!    bounded by its own limit ([`super::timing`]).
//! 2. **The Triage scan** (item `triage`), then **the detection engines**
//!    (item `detection`) over the finished recording, then the run's
//!    **digest** (item `assess`). These are the builders the GUI and
//!    `antinomie-cli triage/detect` call (`antinomie_triage`); they run on a
//!    worker thread bounded by the item's limit and a cancel flag.
//! 3. **The assessment** (item `assess`): the Triage summary and the
//!    detections go through the policy's verdict mapping ([`crate::verdict`]);
//!    the result is stored with the job (`job.assessment`). It is computed
//!    here and not in `report`, so a job that asks for no report still has
//!    its label (departure from 4.1, which has `report` build it).
//!
//! A static check that ran out of time or stopped short is not a problem of
//! the stage: it is a job warning (`static_check_incomplete`) and the job ends
//! `partial`, unless the policy lists the check in `analysis.required_checks`
//! (default none), when it is a problem like any other.
//!
//! A step that fails is a *problem*. If the policy requires the `analyse`
//! stage (`analysis.required_stages`) the stage fails `analysis_failed`;
//! otherwise each problem is a job warning, the job ends `partial`, and a job
//! whose Triage scan failed gets the label `inconclusive`.
use super::{
    LaneStages, StageStop,
    host::{Built, HostTriage},
    plan::HostPlan,
};
use crate::{
    api::job::{Job, Stage},
    engine::Engine,
    verdict::{Facts, Mapping, assessment_of},
    waiter::{WaitError, millis},
};
use antinomie_monitor_core::{
    Command,
    analysis::{
        AnalysisKind, AnalysisLimits, AnalysisReport, AnalysisSectionState, AnalysisSelection,
        AnalysisState, detection::Engine as DetectionEngine,
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

/// How long a static item may wait for the engine to take it and start it
/// (the engine runs one standalone analysis at a time, and its command
/// queue may be busy with the lane): not counted against the item's limit.
pub const ENGINE_QUEUE_WAIT: Duration = Duration::from_secs(4 * 3600);

/// Beyond the grace of a stop (`daemon.stop_grace_s`), how long a static item
/// waits for the engine to report its stopped analysis ended (the cleanup
/// and the engine's own tick).
const STOP_MARGIN: Duration = Duration::from_secs(10);

/// A standalone analysis that has ended.
fn analysis_finished(report: &AnalysisReport) -> bool {
    !matches!(
        report.state,
        AnalysisState::Acquiring | AnalysisState::Queued | AnalysisState::Running
    )
}

/// A Triage scan, or the problem in words with whether the limit ended it.
pub(super) type TriageDone = Result<(SavedRun, ArchiveScan), (String, bool)>;
/// The detection engines' outcomes, the problems, and whether the limit ended
/// the item.
pub(super) type DetectionDone = (Vec<(DetectionEngine, Outcome)>, Vec<String>, bool);

/// What the static analysis left: `hard` is a failure of the analysis
/// itself (or of a required check), `soft` a check that stopped short.
#[derive(Default)]
pub(super) struct StaticOutcome {
    pub(super) hard: Vec<String>,
    pub(super) soft: Vec<String>,
}

impl StaticOutcome {
    fn hard(text: impl Into<String>) -> Self {
        Self {
            hard: vec![text.into()],
            soft: Vec::new(),
        }
    }

    /// A timeout of the whole analysis: which check it cut is not known, so
    /// it fails the stage only when the policy requires some check.
    fn unfinished(plan: &HostPlan, text: String) -> Self {
        if plan.required_checks.is_empty() {
            Self {
                hard: Vec::new(),
                soft: vec![text],
            }
        } else {
            Self::hard(text)
        }
    }
}

fn check_name(kind: AnalysisKind) -> String {
    format!("{kind:?}").to_lowercase()
}

/// Read the sections of a finished report: a check that ran out of time or
/// stopped short is `soft`, and `hard` when the policy requires it.
fn judge_report(plan: &HostPlan, report: &AnalysisReport) -> StaticOutcome {
    let mut out = StaticOutcome::default();
    for section in &report.sections {
        let required = plan.required_checks.contains(&section.kind);
        let words = match section.state {
            AnalysisSectionState::Timeout => "ran out of time and was stopped",
            AnalysisSectionState::Partial => "finished partly",
            AnalysisSectionState::Unavailable if required => "was not available",
            _ => continue,
        };
        let text = format!("the {} check {words}", check_name(section.kind));
        if required {
            out.hard.push(format!("{text} (a required check)"));
        } else {
            out.soft.push(text);
        }
    }
    if report.state == AnalysisState::Partial && out.hard.is_empty() && out.soft.is_empty() {
        // Name the checks that had nothing to give (one item per tool since
        // ANT-T0454, so each warning says which).
        let unavailable: Vec<String> = report
            .sections
            .iter()
            .filter(|s| s.state == AnalysisSectionState::Unavailable)
            .map(|s| check_name(s.kind))
            .collect();
        out.soft.push(if unavailable.is_empty() {
            "static analysis finished partly (a tool stopped short)".into()
        } else {
            format!(
                "static analysis finished partly: the {} check was not available",
                unavailable.join(" and ")
            )
        });
    }
    out
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

    /// One static item: the library copy through `AnalyzeSample` for the
    /// checks of `group`. The engine runs one standalone analysis at a time,
    /// so the time it sits in the engine's queue is not counted: `limit`
    /// starts when the engine reports it running. `until`, the time left
    /// before the job's deadline, bounds the two waits together. Past either
    /// the analysis is cancelled (`CancelAnalysis`: the engine stops its
    /// worker with SIGTERM, then SIGKILL after the grace), the item waits for
    /// it to end, and the item has timed out.
    pub(super) fn static_item(
        &mut self,
        job: &Job,
        plan: &HostPlan,
        group: &[AnalysisKind],
        limit: Duration,
        until: Duration,
    ) -> Result<(StaticOutcome, bool, u64), StageStop> {
        let Some(sample) = job.sample.as_ref() else {
            return Ok((
                StaticOutcome::hard("the job has no sample to analyse"),
                false,
                0,
            ));
        };
        let asked = self.waiter.now_ms();
        let words = group
            .iter()
            .map(|k| check_name(*k))
            .collect::<Vec<_>>()
            .join(" and ");
        // The engine's own limit per tool: the policy's fixed one (stretched
        // on a loaded host like the guest waits), else the item's whole limit
        // so the item's own deadline is the one that ends it.
        let minutes = match plan.static_limit_min {
            Some(0) => 0,
            Some(minutes) => {
                (f64::from(minutes) * self.env.triage.load_scale().max(1.0)).ceil() as u32
            }
            None => limit.as_secs().div_ceil(60) as u32,
        }
        .min(antinomie_monitor_core::analysis::TIME_LIMIT_MAX_MINUTES);
        let selection = AnalysisSelection {
            enabled: true,
            checks: group.to_vec(),
            time_limit_minutes: minutes,
            limits: AnalysisLimits::default(),
        };
        self.progress(
            job,
            Stage::Analyse,
            &format!("static analysis of the library copy: {words}"),
        );
        let id = match self.waiter.command(
            Command::AnalyzeSample {
                sha256: sample.sha256.to_string(),
                selection,
            },
            Some(ENGINE_QUEUE_WAIT),
        ) {
            Ok(id) => id,
            Err(WaitError::Failed(message)) => {
                return Ok((
                    StaticOutcome::hard(format!("static analysis was refused: {message}")),
                    false,
                    0,
                ));
            }
            Err(WaitError::TimedOut { .. }) => {
                return Ok((
                    StaticOutcome::unfinished(plan, "static analysis did not start in time".into()),
                    true,
                    0,
                ));
            }
            Err(other) => return Err(StageStop::Abort(other)),
        };
        let waiting = |r: &AnalysisReport| {
            matches!(r.state, AnalysisState::Acquiring | AnalysisState::Queued)
        };
        let watched = id.clone();
        match self.waiter.wait_until_report(
            "the static analysis to start",
            ENGINE_QUEUE_WAIT.min(until),
            &watched,
            move |r| !waiting(r),
        ) {
            Ok(()) => {}
            Err(WaitError::TimedOut { .. }) => {
                let _ = self.waiter.send(Command::CancelAnalysis {
                    analysis_id: id.clone(),
                });
                return Ok((
                    StaticOutcome::unfinished(plan, "static analysis did not start in time".into()),
                    true,
                    0,
                ));
            }
            Err(other) => return Err(StageStop::Abort(other)),
        }
        // The time it waited for the engine is not its own (the run-time
        // history records only the time it ran).
        let waited = self.waiter.now_ms().saturating_sub(asked);
        let limit = limit.min(until.saturating_sub(Duration::from_millis(waited)));
        match self.waiter.wait_until_report(
            "the static analysis to finish",
            limit,
            &watched,
            analysis_finished,
        ) {
            Ok(()) => {}
            Err(WaitError::TimedOut { .. }) => {
                let _ = self.waiter.send(Command::CancelAnalysis {
                    analysis_id: id.clone(),
                });
                self.wait_stopped(&watched)?;
                return Ok((
                    StaticOutcome::unfinished(
                        plan,
                        format!(
                            "static analysis ({words}) did not finish within {} seconds",
                            limit.as_secs()
                        ),
                    ),
                    true,
                    waited,
                ));
            }
            Err(other) => return Err(StageStop::Abort(other)),
        }
        Ok((
            match self.waiter.analysis(&id) {
                Some(r) if matches!(r.state, AnalysisState::Complete | AnalysisState::Partial) => {
                    judge_report(plan, &r)
                }
                Some(r) => StaticOutcome::hard(format!(
                    "static analysis ended {:?}{}",
                    r.state,
                    r.reason.map(|r| format!(": {r}")).unwrap_or_default()
                )),
                None => StaticOutcome::hard("static analysis left no report"),
            },
            false,
            waited,
        ))
    }

    /// After `CancelAnalysis` the engine stops the analysis worker
    /// gracefully (SIGTERM, `daemon.stop_grace_s`, SIGKILL): wait until the
    /// analysis has ended, so the item ends when its process has. A wait that
    /// runs out or a cancel of the job ends the item all the same.
    fn wait_stopped(&mut self, id: &str) -> Result<(), StageStop> {
        let wait = antinomie_monitor_core::host_stop_grace() + STOP_MARGIN;
        match self.waiter.wait_until_report(
            "the stopped static analysis to end",
            wait,
            id,
            analysis_finished,
        ) {
            Ok(()) | Err(WaitError::TimedOut { .. } | WaitError::Cancelled) => Ok(()),
            Err(other) => Err(StageStop::Abort(other)),
        }
    }

    /// The Triage item: open the saved run and index it. `Err` in the inner
    /// result is the problem in words, with whether the limit ended it.
    pub(super) fn triage_item(
        &mut self,
        job: &Job,
        limit: Duration,
    ) -> Result<TriageDone, StageStop> {
        let triage: &dyn HostTriage = self.env.triage;
        self.progress(job, Stage::Analyse, "indexing the recording");
        let worked = self.bounded(limit, |cancel| {
            let saved = triage.open_run(job)?;
            let scan = triage.index(&saved, cancel)?;
            Ok::<_, String>((saved, scan))
        });
        Ok(match worked {
            Ok(Ok(done)) => Ok(done),
            Ok(Err(error)) => Err((format!("the Triage scan failed: {error}"), false)),
            Err(why) => {
                if let Some(stop) = why.stop() {
                    return Err(stop);
                }
                Err((
                    why.words("the Triage scan"),
                    matches!(why, Bounded::TimedOut),
                ))
            }
        })
    }

    /// The detection item: the policy's engines over the indexed run. A
    /// skipped engine is a warning at once; the problems are returned, with
    /// whether the limit ended the item.
    pub(super) fn detection_item(
        &mut self,
        job: &Job,
        plan: &HostPlan,
        scanned: &(SavedRun, ArchiveScan),
        limit: Duration,
    ) -> Result<DetectionDone, StageStop> {
        let triage: &dyn HostTriage = self.env.triage;
        let engines: Vec<DetectionEngine> = plan.engines.clone();
        let (saved, scan) = scanned;
        self.progress(job, Stage::Analyse, "running the detection engines");
        let worked = self.bounded(limit, |cancel| triage.detect(saved, scan, &engines, cancel));
        let mut problems = Vec::new();
        let outcomes = match worked {
            Ok(Ok(outcomes)) => outcomes,
            Ok(Err(error)) => {
                problems.push(format!("the detection engines did not run: {error}"));
                Vec::new()
            }
            Err(why) => {
                if let Some(stop) = why.stop() {
                    return Err(stop);
                }
                let timed_out = matches!(why, Bounded::TimedOut);
                problems.push(why.words("the detection engines"));
                return Ok((Vec::new(), problems, timed_out));
            }
        };
        for (engine, outcome) in &outcomes {
            let name = antinomie_triage::detection::name(*engine);
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
        Ok((outcomes, problems, false))
    }

    /// The digest of an indexed run with the engines' results.
    pub(super) fn save_digest_item(
        &mut self,
        scanned: &(SavedRun, ArchiveScan),
        outcomes: &[(DetectionEngine, Outcome)],
        limit: Duration,
    ) -> Result<Option<String>, StageStop> {
        let triage: &dyn HostTriage = self.env.triage;
        let (saved, scan) = scanned;
        match self.bounded(limit, |_| triage.save_digest(saved, scan, outcomes)) {
            Ok(Ok(())) => Ok(None),
            Ok(Err(error)) => Ok(Some(format!("the run's digest was not written: {error}"))),
            Err(why) => match why.stop() {
                Some(stop) => Err(stop),
                None => Ok(Some(why.words("the run's digest"))),
            },
        }
    }
    /// The summary and detections of the scanned run, through the mapping.
    pub(super) fn assess(
        &mut self,
        job: &Job,
        scanned: Option<&(SavedRun, ArchiveScan)>,
        problems: &mut Vec<String>,
        limit: Duration,
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
                let built = self.bounded(limit, |_| {
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

    /// Every finished run gets its digest, whatever the policy asked of
    /// Triage: when the scan left none (not planned, failed, out of time), a
    /// budgeted read makes it, partial when the budget ended it. Never fails
    /// the stage; what is missing is a warning of the job, which the caller
    /// adds once the stage is not failing (a retry makes the digest again).
    pub(super) fn digest(
        &mut self,
        job: &Job,
        limit: Duration,
    ) -> Result<Option<String>, StageStop> {
        if job.recording.is_none() {
            return Ok(None);
        }
        let triage: &dyn HostTriage = self.env.triage;
        let note = match self.bounded(limit, |cancel| triage.ensure_digest(job, cancel)) {
            Ok(Ok(note)) => note,
            Ok(Err(error)) => Some(format!("the run's digest was not made: {error}")),
            Err(why) => {
                if let Some(stop) = why.stop() {
                    return Err(stop);
                }
                Some(why.words("the run's digest"))
            }
        };
        Ok(note)
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

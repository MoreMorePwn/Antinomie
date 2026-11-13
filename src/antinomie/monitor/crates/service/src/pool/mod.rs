// SPDX-License-Identifier: GPL-3.0-only
//! The host work pool (ANT-T0454; addendum P5-1 card A; user decision
//! 2026-11-11 sections 2 and 5): the pipelining of design 4.6.1.
//!
//! Once `collect` has finished, the lane hands the job to the pool and claims
//! the next job: the VM is free while the job's host work runs. The work is
//! split into items ([`crate::stages::items`]): each static tool, `triage`,
//! `detection`, `assess` and `report`. At most `daemon.host_workers` items
//! (default 2) run at once, across every job and every lane: there is one pool
//! per daemon, keyed by job arrival and not by lane, so more lanes plug into
//! the same queue.
//!
//! | Rule | Detail |
//! |---|---|
//! | Order | First come, first served by job arrival; within a job, list (dependency) order, but an item whose dependencies have ended starts while an earlier one waits for its own (ANT-T0464); no item of a newer job starts before every item of the older one has ([`state`]) |
//! | Memory | Before an item starts, `MemAvailable` must be at least [`ITEM_FLOOR_MIB`]; below it the head waits (`status` names the wait) |
//! | Limits | Each item has an expected time and a limit of `daemon.host_time_factor` x that ([`crate::stages::timing`]); time in the queue does not count |
//! | Run deadline | `host_time_factor` x (the expected time of the items ahead of it when it arrived + its own), at least the work ahead plus its own items' limits. A running item's limit ends at the deadline at the latest; at the deadline running items are stopped (SIGTERM, `stop_grace_s`, SIGKILL) and end `timed_out`, queued ones are `skipped`, and the job fails `deadline_exceeded` (ANT-T0471) |
//! | Stops | An item past its limit is stopped gracefully: its cancel flag, SIGTERM to a sandboxed tool, SIGKILL after `daemon.stop_grace_s` (30 s) |
//! | Engine | Each worker has its own waiter on the shared engine ([`crate::engine::mux`]): `AnalyzeSample` results come back to the worker that asked |
//! | Cancel | A cancelled job's queued items are skipped, its running ones stop at their next wait; the job ends `cancelled` (or back in the queue at a shutdown cancel) |
//! | Shutdown (2.7) | The pool goes on with its queue for `shutdown_host_grace_s`; then the waits are interrupted and the jobs stay `running` with their `collected` entry |
//! | Restart (4.8) | Recovery hands the collected jobs back; their items are queued again in the same order (job arrival), static items that had finished are kept |
//! | Visible state | `job.host_work` lists every item with its state, expected time and limit; `status` has `host_pool` with the queue length |
pub mod state;
#[cfg(test)]
mod tests;

use crate::{
    api::{
        failure::{Failure, FailureCode},
        ids::{LaneId, RunId},
        run::{HostItem, HostItemState, Outcome, Run, RunState, Stage},
        status::HostPoolStatus,
    },
    clock::Clock,
    daemon::Controls,
    engine::Engine,
    lane::{LaneDir, ProcFs},
    resources::Probes,
    stages::{
        LaneEnv, LaneStages, NoHostChecks, StageStop,
        host::{HostTriage, SampleTags},
        items::{JobWork, PhaseEnd, host_item, items_for},
        plan,
        timing::{Timing, inputs_of},
    },
    store::{Store, lock},
    waiter::{WaitError, Waiter},
};
use state::{Concluded, JobPhase, PoolJob, PoolState, PoolStop, Task};
use std::{
    path::PathBuf,
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};

/// The memory an item needs free before it starts: the host worker headroom
/// of design 4.6.3.
pub const ITEM_FLOOR_MIB: u64 = 2048;
/// How often an idle worker looks again (memory, cancels, deadlines).
const IDLE: Duration = Duration::from_millis(500);

/// What the pool needs from the daemon.
pub struct PoolEnv {
    pub store: Arc<Store>,
    pub lanes: LaneDir,
    pub triage: Arc<dyn HostTriage>,
    pub tags: Arc<dyn SampleTags>,
    /// How a run's evidence is read (a plain function: the pool is shared
    /// between threads).
    pub evidence:
        fn(&std::path::Path) -> Result<Option<antinomie_monitor_core::RunArtifacts>, String>,
    pub data_dir: PathBuf,
    pub probes: Arc<dyn Probes>,
    pub floor_mib: u64,
    pub controls: Arc<Controls>,
    pub clock: Arc<dyn Clock>,
    pub log: Arc<dyn Fn(&str) + Send + Sync>,
    pub workers: u32,
    pub timing: Timing,
}

pub struct HostPool {
    env: PoolEnv,
    state: Mutex<PoolState>,
    wake: Condvar,
    /// Store writes of the items, in the order of the changes.
    persist: Mutex<()>,
    dead: std::sync::atomic::AtomicBool,
}

fn stop_of(stop: StageStop) -> PoolStop {
    match stop {
        StageStop::Cancelled | StageStop::Abort(WaitError::Cancelled) => PoolStop::Cancelled,
        StageStop::Failed(failure) => PoolStop::Failed(failure),
        StageStop::Abort(error) => PoolStop::Aborted(error),
        StageStop::Wait { detail, .. } => PoolStop::Failed(Failure::new(
            FailureCode::Internal,
            Stage::Analyse,
            "a host stage waited, which it cannot",
            Some(&detail),
        )),
    }
}

fn stage_stop(stop: PoolStop) -> StageStop {
    match stop {
        PoolStop::Cancelled => StageStop::Cancelled,
        PoolStop::Failed(failure) => StageStop::Failed(failure),
        PoolStop::Aborted(error) => StageStop::Abort(error),
    }
}

/// The failure of a job past its host-stage deadline (ANT-T0471): the
/// detail names the items the deadline stopped and those that never started.
pub(crate) fn deadline_failure(job: &Run, items: &[HostItem]) -> Failure {
    let names = |state: HostItemState| {
        items
            .iter()
            .filter(|item| item.state == state)
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    let (stopped, queued) = (names(HostItemState::TimedOut), names(HostItemState::Queued));
    let mut detail = Vec::new();
    if !stopped.is_empty() {
        detail.push(format!("timed out: {stopped}"));
    }
    if !queued.is_empty() {
        detail.push(format!("not started: {queued}"));
    }
    Failure::new(
        FailureCode::DeadlineExceeded,
        job.stage.unwrap_or(Stage::Analyse),
        "the job passed its host-stage deadline: its running items were stopped and the rest did not start",
        (!detail.is_empty()).then(|| detail.join("; ")).as_deref(),
    )
}

impl HostPool {
    pub fn new(env: PoolEnv) -> Arc<Self> {
        let workers = env.workers.max(1) as usize;
        Arc::new(Self {
            env,
            state: Mutex::new(PoolState::new(workers)),
            wake: Condvar::new(),
            persist: Mutex::new(()),
            dead: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn workers(&self) -> u32 {
        self.env.workers.max(1)
    }

    fn log(&self, line: &str) {
        (self.env.log)(line);
    }

    fn stages<'a, E: Engine>(
        &'a self,
        waiter: &'a mut Waiter<E>,
        procs: &'a ProcFs,
        lane: LaneId,
    ) -> LaneStages<'a, E> {
        LaneStages {
            waiter,
            env: LaneEnv {
                store: &self.env.store,
                lanes: &self.env.lanes,
                // The pool runs no lane stages.
                revert: Default::default(),
                // The pool runs no prechecks.
                callers: &crate::config::callers::LocalOnly,
                procs,
                host: &NoHostChecks,
                evidence: &self.env.evidence,
                triage: &*self.env.triage,
                tags: &*self.env.tags,
                data_dir: &self.env.data_dir,
            },
            lane,
        }
    }

    /// A job whose `collect` finished: its items join the queue. `outcome`
    /// is what `collect` found. `kept` are items a restart found finished.
    fn enter(&self, job: &Run, outcome: Outcome, kept: &[HostItem]) {
        let job = self.env.store.get(&job.id).unwrap_or_else(|_| job.clone());
        let frozen = match self.env.store.frozen_preset(&job.id) {
            Ok(frozen) => frozen,
            Err(error) => {
                self.log(&format!(
                    "run={} cannot enter the host pool: {error}",
                    job.id
                ));
                return;
            }
        };
        let plan = plan::hosted(&frozen.preset);
        let items = items_for(&plan);
        let inputs = inputs_of(&job, self.env.triage.load_scale());
        let mut views: Vec<HostItem> = items
            .iter()
            .map(|spec| {
                host_item(
                    spec,
                    &items,
                    &self.env.timing.of(&spec.kind, &plan, &inputs),
                )
            })
            .collect();
        // Only a static tool that finished is kept: everything else is made
        // again (Triage's index lives in memory).
        for view in &mut views {
            if view.name.starts_with("static:")
                && let Some(old) = kept
                    .iter()
                    .find(|k| k.name == view.name && k.state == HostItemState::Done)
            {
                *view = old.clone();
            }
        }
        let own: u64 = views
            .iter()
            .filter(|v| v.state == HostItemState::Queued)
            .map(|v| v.expected_s)
            .sum();
        let own_limits: u64 = views
            .iter()
            .filter(|v| v.state == HostItemState::Queued)
            .map(|v| v.limit_s)
            .sum();
        let now = self.env.clock.now_ms();
        let key = PoolState::key(&job);
        let view_copy = views.clone();
        {
            let _order = lock(&self.persist);
            let mut state = lock(&self.state);
            let ahead = state.ahead_s(&key);
            let budget = PoolState::budget_floor_ms(ahead, own, own_limits, self.env.timing.factor);
            let id = job.id.clone();
            state.jobs.insert(
                key,
                PoolJob {
                    work: Arc::new(Mutex::new(JobWork::new(plan, outcome))),
                    job,
                    items,
                    views,
                    deadline_ms: now + budget,
                    phase: JobPhase::Analyse,
                    begun: false,
                    busy: false,
                    running: 0,
                    stop: None,
                },
            );
            drop(state);
            if let Err(error) = self.env.store.set_host_work(&id, &view_copy) {
                self.log(&format!(
                    "run={id}: the host work cannot be stored: {error}"
                ));
            }
            self.log(&format!(
                "run={id} entered the host pool: {} item(s), {ahead} s of work ahead, deadline in {} s",
                view_copy.len(),
                budget / 1000
            ));
        }
        self.wake.notify_all();
    }

    /// A job the lane collected.
    pub fn admit(&self, job: &Run, outcome: Outcome) {
        self.enter(job, outcome, &[]);
    }

    /// A job recovery found collected: the outcome is read again from the
    /// run's evidence, and its finished static items are kept.
    pub fn resume<E: Engine>(&self, job: &Run, waiter: &mut Waiter<E>) {
        let fresh = self.env.store.get(&job.id).unwrap_or_else(|_| job.clone());
        let procs = ProcFs;
        let lane = fresh.lane.clone().unwrap_or_else(|| LaneId::new(1));
        let outcome = self.stages(waiter, &procs, lane).resumed_outcome(&fresh);
        self.log(&format!("run={} resuming in the host pool", fresh.id));
        let kept = fresh.host_work.clone();
        self.enter(&fresh, outcome, &kept);
    }

    pub fn status(&self) -> HostPoolStatus {
        let state = lock(&self.state);
        let (queued, running) = state.counts();
        HostPoolStatus {
            workers: self.workers(),
            queued,
            running,
            runs: state.jobs.len() as u32,
            waiting_for: state.waiting_for.clone(),
        }
    }

    /// Jobs with host work left.
    pub fn busy(&self) -> bool {
        !lock(&self.state).jobs.is_empty()
    }

    /// The jobs in the pool, oldest first.
    pub fn jobs(&self) -> Vec<RunId> {
        lock(&self.state)
            .jobs
            .values()
            .map(|j| j.job.id.clone())
            .collect()
    }

    pub fn is_dead(&self) -> bool {
        self.dead.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wake idle workers (a stop, a new job).
    pub fn poke(&self) {
        self.wake.notify_all();
    }

    fn store_view(&self, id: &RunId, view: Option<Vec<HostItem>>) {
        if let Some(view) = view
            && let Err(error) = self.env.store.set_host_work(id, &view)
        {
            self.log(&format!(
                "run={id}: the host work cannot be stored: {error}"
            ));
        }
    }

    /// Change the state and store the job's items, in the order of changes.
    fn change<T>(&self, id: &RunId, edit: impl FnOnce(&mut PoolState) -> T) -> T {
        let _order = lock(&self.persist);
        let (out, view) = {
            let mut state = lock(&self.state);
            let out = edit(&mut state);
            (out, state.get(id).map(|j| j.views.clone()))
        };
        self.store_view(id, view);
        self.wake.notify_all();
        out
    }

    /// Jobs cancelled while their items waited.
    fn mark_cancels(&self) {
        let ids: Vec<RunId> = {
            let state = lock(&self.state);
            state
                .jobs
                .values()
                .filter(|j| j.stop.is_none())
                .map(|j| j.job.id.clone())
                .collect()
        };
        for id in ids {
            if self
                .env
                .store
                .get(&id)
                .is_ok_and(|job| job.state == RunState::Cancelling)
            {
                let mut state = lock(&self.state);
                if let Some(job) = state.get_mut(&id)
                    && job.stop.is_none()
                {
                    job.stop = Some(PoolStop::Cancelled);
                }
            }
        }
    }

    fn take_task(&self) -> Option<(Task, Option<Vec<HostItem>>)> {
        let _order = lock(&self.persist);
        let mut state = lock(&self.state);
        let probes = &self.env.probes;
        let floor = self.env.floor_mib;
        let mut memory = || {
            let available = probes.mem_available_mib()?;
            (available < floor).then(|| {
                format!("memory: {available} MiB are available, an item needs {floor} MiB")
            })
        };
        let deadline = |job: &Run, items: &[HostItem]| deadline_failure(job, items);
        let task = state.next(self.env.clock.now_ms(), &mut memory, &deadline)?;
        let id = match &task {
            Task::Item { job, .. }
            | Task::EndAnalyse(job)
            | Task::Conclude(job)
            | Task::Settle(job, _) => job.clone(),
        };
        let view = state.get(&id).map(|j| j.views.clone());
        drop(state);
        self.store_view(&id, view);
        Some((task, None))
    }

    /// One worker: take tasks until the daemon stops (and the pool is empty)
    /// or the waits are interrupted.
    pub fn work<E: Engine>(&self, waiter: &mut Waiter<E>) {
        let procs = ProcFs;
        let mut last_scan = 0u64;
        loop {
            if self.env.controls.interrupted() || self.is_dead() {
                return;
            }
            if let Err(error) = waiter.drain() {
                self.lost(&error);
                return;
            }
            let now = self.env.clock.now_ms();
            if now.saturating_sub(last_scan) >= IDLE.as_millis() as u64 {
                self.mark_cancels();
                last_scan = now;
            }
            match self.take_task() {
                Some((task, _)) => self.run(task, waiter, &procs),
                None => {
                    let state = lock(&self.state);
                    if self.env.controls.stopping() && state.jobs.is_empty() {
                        return;
                    }
                    let _ = self.wake.wait_timeout(state, IDLE);
                }
            }
        }
    }

    fn lost(&self, error: &WaitError) {
        if matches!(error, WaitError::Disconnected(_)) {
            self.dead.store(true, std::sync::atomic::Ordering::SeqCst);
            self.env.controls.engine_lost();
            self.log(&format!("host pool: the engine is gone: {error}"));
        }
        self.wake.notify_all();
    }

    fn job_of(&self, id: &RunId) -> Option<(Run, Arc<Mutex<JobWork>>)> {
        let state = lock(&self.state);
        state.get(id).map(|j| (j.job.clone(), Arc::clone(&j.work)))
    }

    fn run<E: Engine>(&self, task: Task, waiter: &mut Waiter<E>, procs: &ProcFs) {
        let id = match &task {
            Task::Item { job, .. }
            | Task::EndAnalyse(job)
            | Task::Conclude(job)
            | Task::Settle(job, _) => job.clone(),
        };
        let Some((job, work)) = self.job_of(&id) else {
            return;
        };
        let lane = job.lane.clone().unwrap_or_else(|| LaneId::new(1));
        match task {
            Task::Item {
                index,
                kind,
                limit,
                until,
                begin_analyse,
                ..
            } => {
                let name = kind.name();
                self.log(&format!(
                    "run={id} item={name} started (limit {} s)",
                    limit.as_secs()
                ));
                let began = waiter.now_ms();
                let mut stages = self.stages(waiter, procs, lane);
                stages.cancel_hook(&job);
                let plan = lock(&work).plan.clone();
                let result = if begin_analyse {
                    stages.begin_analyse(&job, &plan)
                } else if !kind.is_analyse() {
                    stages.begin_report(&job)
                } else {
                    Ok(())
                }
                .and_then(|()| stages.run_item_until(&job, &work, &kind, limit, until));
                stages.waiter.clear_cancel();
                let seconds = waiter.now_ms().saturating_sub(began) / 1000;
                if let Ok(end) = &result
                    && end.state == HostItemState::Done
                {
                    let ran = waiter.now_ms().saturating_sub(began + end.waited_ms);
                    self.env.timing.medians.record(&name, ran / 1000);
                }
                let disconnected =
                    matches!(&result, Err(StageStop::Abort(WaitError::Disconnected(_))));
                self.log(&format!(
                    "run={id} item={name} ended after {seconds} s: {}",
                    match &result {
                        Ok(end) => format!("{:?}", end.state).to_lowercase(),
                        Err(stop) => format!("{stop:?}"),
                    }
                ));
                let now = self.env.clock.now_ms();
                self.change(&id, |state| {
                    state.item_ended(
                        &id,
                        index,
                        now,
                        result.map(|end| (end.state, end.note)).map_err(stop_of),
                    )
                });
                if disconnected {
                    self.lost(&WaitError::Disconnected("the engine is gone".into()));
                }
            }
            Task::EndAnalyse(_) => {
                let mut stages = self.stages(waiter, procs, lane);
                let result = stages.end_analyse(&job, &mut lock(&work)).map_err(stop_of);
                if matches!(result, Ok(PhaseEnd::Again)) {
                    self.log(&format!("run={id}: the host stages run again"));
                }
                self.change(&id, |state| state.analyse_ended(&id, result));
            }
            Task::Conclude(_) => {
                let mut stages = self.stages(waiter, procs, lane);
                let has_report = lock(&work).plan.report_skipped().then_some(()).is_none();
                let result = (|| {
                    let mut w = lock(&work);
                    if has_report && stages.end_report(&job, &mut w)? == PhaseEnd::Again {
                        return Ok(Concluded::Again);
                    }
                    stages.conclude(&job, &w).map(|(done, problem)| {
                        if let Some(problem) = problem {
                            self.log(&format!("run={id}: {problem}"));
                        }
                        self.log(&format!(
                            "run={id} left the host pool: {}",
                            format!("{:?}", done.state).to_lowercase()
                        ));
                        Concluded::Done
                    })
                })()
                .unwrap_or_else(|stop| Concluded::Stopped(stop_of(stop)));
                self.change(&id, |state| {
                    state.concluded(&id, result);
                });
            }
            Task::Settle(_, stop) => {
                if !matches!(stop, PoolStop::Aborted(_)) {
                    let mut stages = self.stages(waiter, procs, lane);
                    let hosted = stages.settle_host(&job, Err(stage_stop(stop)));
                    self.log(&format!("run={id} left the host pool: {hosted:?}"));
                } else {
                    self.log(&format!(
                        "run={id} left in its host stages for the next start"
                    ));
                }
                self.change(&id, |state| {
                    state.remove(&id);
                });
            }
        }
    }
}

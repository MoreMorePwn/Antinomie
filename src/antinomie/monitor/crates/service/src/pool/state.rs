// SPDX-License-Identifier: GPL-3.0-only
//! The pool's queue and its one scheduling rule, without threads or an engine
//! (so the order is tested on its own).
//!
//! **First come, first served by job arrival** (user decision 2026-11-11,
//! sections 2 and 5). Jobs are ordered by `created_ms`, then id; a job's
//! items by their list order, which is a dependency order. The queue's head
//! is the first item, of the oldest job, that has not started. Only the head
//! may start, and only when a worker is free, the items it waits for have
//! ended and the memory floor is met. While the head waits for any of these,
//! no item of a newer job starts: a small item never goes ahead of a heavy
//! one. Once every item of a job has started, the head moves to the next job.
//!
//! The steps between items that are the job's own (the end of `analyse`, the
//! end of `report` and `cleanup`, the ending of a cancelled or failed job) are
//! quick store writes; they are handed out as tasks too, but take no worker
//! slot.
use crate::{
    api::{
        failure::Failure,
        ids::JobId,
        job::{HostItem, HostItemState, Job},
    },
    stages::items::{ItemKind, ItemSpec, JobWork, PhaseEnd},
    waiter::WaitError,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

/// Why a job's host work stopped early.
#[derive(Clone, Debug)]
pub enum PoolStop {
    Cancelled,
    Failed(Failure),
    /// A signal or a dead engine: the job is left for recovery.
    Aborted(WaitError),
}

/// Where a job is between its items.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobPhase {
    Analyse,
    Report,
}

pub struct PoolJob {
    pub job: Job,
    pub items: Vec<ItemSpec>,
    pub views: Vec<HostItem>,
    pub work: Arc<Mutex<JobWork>>,
    /// The job's host-stage deadline (wall clock of the pool's clock).
    pub deadline_ms: u64,
    pub phase: JobPhase,
    /// The `analyse` stage has begun in this run of the stages.
    pub begun: bool,
    /// A job-level step is running.
    pub busy: bool,
    pub running: usize,
    pub stop: Option<PoolStop>,
}

impl PoolJob {
    fn finished(&self, index: usize) -> bool {
        !matches!(
            self.views[index].state,
            HostItemState::Queued | HostItemState::Running
        )
    }

    fn in_phase(&self, index: usize) -> bool {
        match self.phase {
            JobPhase::Analyse => self.items[index].kind.is_analyse(),
            JobPhase::Report => !self.items[index].kind.is_analyse(),
        }
    }

    fn phase_done(&self) -> bool {
        (0..self.items.len())
            .filter(|i| self.in_phase(*i))
            .all(|i| self.finished(i))
    }

    /// Expected seconds of the items not ended yet.
    pub fn remaining_s(&self) -> u64 {
        (0..self.items.len())
            .filter(|i| !self.finished(*i))
            .map(|i| self.views[i].expected_s)
            .sum()
    }

    fn reset(&mut self) {
        for view in &mut self.views {
            view.state = HostItemState::Queued;
            view.started_ms = None;
            view.finished_ms = None;
            view.note = None;
        }
        self.phase = JobPhase::Analyse;
        self.begun = false;
    }
}

/// What a worker does next.
#[derive(Clone, Debug)]
pub enum Task {
    Item {
        job: JobId,
        index: usize,
        kind: ItemKind,
        limit: Duration,
        /// The first `analyse` item of this run of the stages.
        begin_analyse: bool,
    },
    /// Every `analyse` item has ended.
    EndAnalyse(JobId),
    /// The report has ended (or there is none): `report`'s end and `cleanup`.
    Conclude(JobId),
    /// End a job whose host work stopped.
    Settle(JobId, PoolStop),
}

/// How a `Conclude` task ended.
#[derive(Clone, Debug)]
pub enum Concluded {
    Done,
    Again,
    Stopped(PoolStop),
}

#[derive(Default)]
pub struct PoolState {
    pub workers: usize,
    pub running: usize,
    pub jobs: BTreeMap<(u64, JobId), PoolJob>,
    /// Why the head waits, when it waits for memory.
    pub waiting_for: Option<String>,
}

impl PoolState {
    pub fn new(workers: usize) -> Self {
        Self {
            workers: workers.max(1),
            ..Self::default()
        }
    }

    pub fn key(job: &Job) -> (u64, JobId) {
        (job.created_ms, job.id.clone())
    }

    pub fn get_mut(&mut self, id: &JobId) -> Option<&mut PoolJob> {
        self.jobs.values_mut().find(|j| &j.job.id == id)
    }

    pub fn get(&self, id: &JobId) -> Option<&PoolJob> {
        self.jobs.values().find(|j| &j.job.id == id)
    }

    pub fn remove(&mut self, id: &JobId) -> Option<PoolJob> {
        let key = self.jobs.iter().find(|(_, j)| &j.job.id == id)?.0.clone();
        self.jobs.remove(&key)
    }

    /// Expected seconds of every item not ended yet, of jobs older than `key`.
    pub fn ahead_s(&self, key: &(u64, JobId)) -> u64 {
        self.jobs
            .range(..key.clone())
            .map(|(_, j)| j.remaining_s())
            .sum()
    }

    /// A job's host-stage budget in milliseconds (user decision 2026-11-11
    /// section 5): `factor` x (the expected seconds of the work ahead of it
    /// when it arrived + its own), so a long queue never times a job out.
    pub fn budget_ms(ahead_s: u64, own_s: u64, factor: f64) -> u64 {
        ((ahead_s + own_s) as f64 * factor.max(1.0) * 1000.0).ceil() as u64
    }

    /// [`Self::budget_ms`], but never less than the factor times the work
    /// ahead plus the sum of the job's own item limits (`own_limits_s`): every
    /// item may take at least [`crate::stages::timing::MIN_LIMIT`], so with
    /// small expected times the job's whole budget could be shorter than the
    /// limit of its first item.
    pub fn budget_floor_ms(ahead_s: u64, own_s: u64, own_limits_s: u64, factor: f64) -> u64 {
        let ahead_ms = (ahead_s as f64 * factor.max(1.0) * 1000.0).ceil() as u64;
        Self::budget_ms(ahead_s, own_s, factor)
            .max(ahead_ms.saturating_add(own_limits_s.saturating_mul(1000)))
    }

    /// Items waiting to start, and items running.
    pub fn counts(&self) -> (u32, u32) {
        let queued = self
            .jobs
            .values()
            .filter(|j| j.stop.is_none())
            .flat_map(|j| j.views.iter())
            .filter(|v| v.state == HostItemState::Queued)
            .count();
        (queued as u32, self.running as u32)
    }

    /// The next task under the rule of the module text. `memory` says why
    /// the floor is not met, or `None`. `deadline` is the failure of a job
    /// past its host-stage deadline.
    pub fn next(
        &mut self,
        now_ms: u64,
        memory: &mut dyn FnMut() -> Option<String>,
        deadline: &dyn Fn(&Job) -> Failure,
    ) -> Option<Task> {
        let free = self.running < self.workers;
        let mut head_seen = false;
        let mut start: Option<((u64, JobId), usize)> = None;
        self.waiting_for = None;
        for (key, job) in self.jobs.iter_mut() {
            let has_queued = job.views.iter().any(|v| v.state == HostItemState::Queued);
            if job.busy {
                head_seen |= has_queued;
                continue;
            }
            if job.stop.is_none() && now_ms >= job.deadline_ms {
                if job.running > 0 {
                    // Each running item is bounded by its own limit: the
                    // deadline never cuts one short. The job fails once they
                    // end, and starts nothing new meanwhile (it keeps its
                    // place at the head, as a busy job does).
                    head_seen |= has_queued;
                    continue;
                }
                job.stop = Some(PoolStop::Failed(deadline(&job.job)));
            }
            if let Some(stop) = &job.stop {
                for view in &mut job.views {
                    if view.state == HostItemState::Queued {
                        view.state = HostItemState::Skipped;
                    }
                }
                if job.running == 0 {
                    job.busy = true;
                    return Some(Task::Settle(job.job.id.clone(), stop.clone()));
                }
                continue;
            }
            if job.running == 0 && job.phase_done() {
                job.busy = true;
                return Some(match job.phase {
                    JobPhase::Analyse => Task::EndAnalyse(job.job.id.clone()),
                    JobPhase::Report => Task::Conclude(job.job.id.clone()),
                });
            }
            if !has_queued || head_seen {
                continue;
            }
            head_seen = true;
            // The head of the queue: the job's first item not started.
            let Some(index) =
                (0..job.items.len()).find(|i| job.views[*i].state == HostItemState::Queued)
            else {
                continue;
            };
            if !free
                || !job.in_phase(index)
                || !job.items[index].after.iter().all(|d| job.finished(*d))
            {
                continue;
            }
            if let Some(why) = memory() {
                self.waiting_for = Some(why);
                continue;
            }
            start = Some((key.clone(), index));
        }
        let (key, index) = start?;
        let job = self.jobs.get_mut(&key)?;
        let view = &mut job.views[index];
        view.state = HostItemState::Running;
        view.started_ms = Some(now_ms);
        let kind = job.items[index].kind.clone();
        let begin_analyse = kind.is_analyse() && !job.begun;
        job.begun |= kind.is_analyse();
        job.running += 1;
        self.running += 1;
        Some(Task::Item {
            job: job.job.id.clone(),
            index,
            limit: Duration::from_secs(view.limit_s),
            kind,
            begin_analyse,
        })
    }

    /// An item ended (`Err`: it stopped the job's host work).
    pub fn item_ended(
        &mut self,
        id: &JobId,
        index: usize,
        now_ms: u64,
        result: Result<(HostItemState, Option<String>), PoolStop>,
    ) {
        self.running = self.running.saturating_sub(1);
        let Some(job) = self.get_mut(id) else {
            return;
        };
        job.running = job.running.saturating_sub(1);
        let view = &mut job.views[index];
        view.finished_ms = Some(now_ms);
        match result {
            Ok((state, note)) => {
                view.state = state;
                view.note = note;
            }
            Err(stop) => {
                view.state = HostItemState::Failed;
                view.note = Some(match &stop {
                    PoolStop::Cancelled => "cancelled".into(),
                    PoolStop::Failed(failure) => failure.message.clone(),
                    PoolStop::Aborted(error) => error.to_string(),
                });
                // A signal or a dead engine wins: nothing is ended then.
                if job.stop.is_none() || matches!(stop, PoolStop::Aborted(_)) {
                    job.stop = Some(stop);
                }
            }
        }
    }

    /// The end of `analyse` was decided.
    pub fn analyse_ended(&mut self, id: &JobId, result: Result<PhaseEnd, PoolStop>) {
        let Some(job) = self.get_mut(id) else {
            return;
        };
        job.busy = false;
        match result {
            Ok(PhaseEnd::Next) => job.phase = JobPhase::Report,
            Ok(PhaseEnd::Again) => job.reset(),
            Err(stop) => job.stop = Some(stop),
        }
    }

    /// The end of `report` and `cleanup`; a finished job leaves the pool.
    pub fn concluded(&mut self, id: &JobId, result: Concluded) -> Option<PoolJob> {
        let job = self.get_mut(id)?;
        job.busy = false;
        match result {
            Concluded::Done => self.remove(id),
            Concluded::Again => {
                job.reset();
                None
            }
            Concluded::Stopped(stop) => {
                job.stop = Some(stop);
                None
            }
        }
    }
}

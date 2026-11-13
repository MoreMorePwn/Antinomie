// SPDX-License-Identifier: GPL-3.0-only
//! The lane's thread: it owns the engine and runs one job at a time, lane
//! stages then host stages on the same waiter (coordinator decision for
//! 0.9.0: the host stages are serialised on the lane's own waiter, so the
//! pipelining of design 4.6.1 waits for a second engine connection).
//!
//! The loop, every turn: keep the engine's snapshot current, run the
//! periodic work (the resource governor every 5 s, the wait expiry every
//! 30 s, the hourly janitor), serve a lane command when idle, then claim the
//! next job the queue and the lane allow. With nothing to do it sleeps until
//! a submit wakes it or a second passes.
//!
//! [`LaneRunner`] is the seam between the loop and the stages, so the
//! scheduling and the shutdown rules are tested without an engine.
//!
//! With several lanes (ANT-T0455 card C) every lane has a loop of its own on
//! its own engine; they share the store and the [`LaneBoard`], which spreads
//! the jobs over the free lanes (design 4.6.1). Only the first lane's loop
//! does the daemon's upkeep (the wait expiry and the janitor). Every lane's
//! loop runs the resource governor, so the `run/PAUSE` file, low disk and a
//! missing KVM stop every free lane within seconds while lane 1 runs a job.

use super::{
    Controls, Phase,
    board::{LaneBoard, LaneProfile},
};
use crate::{
    api::{error::ApiError, ids::LaneId, job::Job},
    clock::Clock,
    store::{Eligibility, Store},
};
use serde_json::Value;
use std::{
    sync::{Arc, Mutex, mpsc},
    time::Duration,
};

/// How a job left the lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobEnd {
    /// The job is terminal, or queued again by a retry or a cancel for
    /// shutdown.
    Done,
    /// A signal or a dead engine: the job was left for recovery.
    Aborted,
}

/// A lane command (`lane.reset`, `lane.unquarantine`) with its answer.
pub struct LaneCommand {
    pub op: String,
    pub params: Value,
    pub reply: mpsc::Sender<Result<Value, ApiError>>,
    /// A command the asker stopped waiting for is dropped, never run late.
    pub deadline: std::time::Instant,
}

/// What the loop needs from a lane.
pub trait LaneRunner {
    /// Keep the engine's snapshot current; `Err` when the engine is gone.
    fn tick(&mut self) -> Result<(), String>;
    /// Whether the lane can take a job now.
    fn eligibility(&mut self) -> Eligibility;
    /// Run a claimed job through the lane and the host stages. `to_host` is
    /// called once, when the lane stages are over and the host stages begin.
    fn run_job(&mut self, job: &Job, to_host: &mut dyn FnMut()) -> JobEnd;
    /// The host stages of a job recovery found collected.
    fn resume(&mut self, job: &Job) -> JobEnd;
    /// The resource governor (design 4.6.3).
    fn govern(&mut self, now_ms: u64);
    /// A lane command, served while no job runs.
    fn command(&mut self, op: &str, params: Value) -> Result<Value, ApiError>;
    /// What the lane runs, for the lane choice with several lanes.
    fn profile(&mut self) -> Option<LaneProfile> {
        None
    }
    /// The lane VM of the job's lane group (`[lanes] vm`).
    fn lane_vm(&self, _job: &Job) -> Option<String> {
        None
    }
    /// How many runs the job's client may have running at once
    /// (`max_running`), as the service reads it now.
    fn running_cap(&self, _job: &Job) -> Option<u32> {
        None
    }
}

/// How often the loop does its periodic work.
#[derive(Clone, Copy, Debug)]
pub struct Periods {
    pub govern_ms: u64,
    pub expire_ms: u64,
    pub janitor_ms: u64,
    pub idle_wait: Duration,
}

impl Default for Periods {
    fn default() -> Self {
        Self {
            govern_ms: 5_000,
            expire_ms: 30_000,
            janitor_ms: 3_600_000,
            idle_wait: Duration::from_secs(1),
        }
    }
}

pub struct LaneLoop<'a> {
    pub lane: LaneId,
    pub store: &'a Store,
    pub controls: &'a Controls,
    pub phase: &'a Mutex<Phase>,
    pub wake: &'a mpsc::Receiver<()>,
    pub commands: &'a mpsc::Receiver<LaneCommand>,
    pub clock: Arc<dyn Clock>,
    pub periods: Periods,
    /// Called hourly: expire staged uploads and old idempotency keys, prune
    /// engine events.
    pub janitor: &'a mut dyn FnMut(),
    pub log: &'a (dyn Fn(&str) + Send + Sync),
    /// The lanes of the daemon when it runs more than one; `None`: this lane
    /// takes every job it can, as with one lane.
    pub board: Option<&'a LaneBoard>,
    /// This loop does the daemon's upkeep (the wait expiry and the janitor).
    pub upkeep: bool,
}

fn set(phase: &Mutex<Phase>, value: Phase) {
    *crate::store::lock(phase) = value;
}

impl LaneLoop<'_> {
    /// Run until the daemon stops or the engine is gone. Jobs in `resume`
    /// (collected before a crash) run their host stages first.
    pub fn run(&mut self, runner: &mut dyn LaneRunner, resume: &[Job]) {
        for job in resume {
            if self.controls.interrupted() {
                return;
            }
            set(self.phase, Phase::Host(job.id.clone()));
            (self.log)(&format!("job={} resuming at analyse", job.id));
            let end = runner.resume(job);
            set(self.phase, Phase::Idle);
            if end == JobEnd::Aborted {
                return;
            }
        }
        let mut next_govern = 0;
        let mut next_expire = 0;
        let mut next_janitor = 0;
        loop {
            if self.controls.interrupted() {
                return;
            }
            if let Err(error) = runner.tick() {
                (self.log)(&format!("the engine is gone: {error}"));
                self.controls.engine_lost();
                return;
            }
            let now = self.clock.now_ms();
            if now >= next_govern {
                runner.govern(now);
                next_govern = now + self.periods.govern_ms;
            }
            if self.upkeep && now >= next_expire {
                if let Err(error) = self.store.expire_waits() {
                    (self.log)(&format!("wait expiry: {error}"));
                }
                next_expire = now + self.periods.expire_ms;
            }
            if self.upkeep && now >= next_janitor {
                (self.janitor)();
                next_janitor = now + self.periods.janitor_ms;
            }
            if self.controls.stopping() {
                return;
            }
            while let Ok(command) = self.commands.try_recv() {
                if std::time::Instant::now() >= command.deadline {
                    continue;
                }
                set(self.phase, Phase::Command(command.op.clone()));
                let answer = runner.command(&command.op, command.params);
                set(self.phase, Phase::Idle);
                let _ = command.reply.send(answer);
            }
            let eligibility = runner.eligibility();
            let profile = if self.board.is_some() {
                runner.profile()
            } else {
                None
            };
            let claimed = {
                let runner = &*runner;
                let cap = |job: &Job| runner.running_cap(job);
                match self.board {
                    None => self
                        .store
                        .claim_next_within(&self.lane, &cap, &mut |_| eligibility),
                    Some(board) => {
                        let now = self.clock.now_ms();
                        board.post(&self.lane, eligibility, profile, now);
                        match eligibility {
                            Eligibility::Wait(mine) => match board.report(&self.lane, mine, now) {
                                Some(why) => {
                                    self.store.claim_next_within(&self.lane, &cap, &mut |_| {
                                        Eligibility::Wait(why)
                                    })
                                }
                                None => Ok(None),
                            },
                            _ => {
                                let lane = &self.lane;
                                self.store.claim_next_within(lane, &cap, &mut |job| {
                                    board.decide(lane, job, runner.lane_vm(job).as_deref(), now)
                                })
                            }
                        }
                    }
                }
            };
            if let (Some(board), Ok(Some(_))) = (self.board, &claimed) {
                board.claimed(&self.lane, self.clock.now_ms());
            }
            match claimed {
                Ok(Some(job)) => {
                    set(self.phase, Phase::Lane(job.id.clone()));
                    (self.log)(&format!("job={} started, attempt {}", job.id, job.attempt));
                    let id = job.id.clone();
                    let phase = self.phase;
                    let end = runner.run_job(&job, &mut || set(phase, Phase::Host(id.clone())));
                    set(self.phase, Phase::Idle);
                    let state = self
                        .store
                        .get(&job.id)
                        .map(|j| format!("{:?}", j.state).to_lowercase())
                        .unwrap_or_default();
                    (self.log)(&format!("job={} left the lane: {state}", job.id));
                    if end == JobEnd::Aborted {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = self.wake.recv_timeout(self.periods.idle_wait);
                }
                Err(error) => {
                    (self.log)(&format!("the queue cannot be read: {error}"));
                    let _ = self.wake.recv_timeout(self.periods.idle_wait);
                }
            }
        }
    }
}

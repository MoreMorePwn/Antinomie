// SPDX-License-Identifier: GPL-3.0-only
//! The real [`LaneRunner`]: the stages of cards P3-4 and P3-5 on the lane's
//! waiter, the resource governor of P3-5c, and the lane commands of P3-5b.

use super::lane::{JobEnd, LaneRunner};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::LaneId,
        job::Job,
    },
    config::PolicyLookup,
    engine::Engine,
    lane::{LaneDir, Processes, provision},
    resources::Governor,
    stages::{
        Driven, HostChecks, Hosted, LaneEnv, LaneStages,
        host::{HostTriage, SampleTags},
    },
    store::{Eligibility, Store},
    waiter::Waiter,
};
use serde_json::Value;

/// What the stages borrow from the daemon's thread.
pub struct RunnerEnv<'a> {
    pub store: &'a Store,
    pub lanes: &'a LaneDir,
    pub policies: &'a dyn PolicyLookup,
    pub callers: &'a dyn crate::config::callers::CallerLookup,
    pub procs: &'a dyn Processes,
    pub host: &'a dyn HostChecks,
    pub triage: &'a dyn HostTriage,
    pub tags: &'a dyn SampleTags,
    pub data_dir: &'a std::path::Path,
}

pub struct StagesRunner<'a, E: Engine> {
    pub waiter: Waiter<E>,
    pub env: RunnerEnv<'a>,
    pub lane: LaneId,
    pub governor: Option<Governor<'a>>,
    pub log: &'a (dyn Fn(&str) + Send + Sync),
    /// The host work pool: a collected job goes there and the lane is free
    /// at once (ANT-T0454). `None` runs the host stages on the lane's thread.
    pub pool: Option<&'a crate::pool::HostPool>,
}

impl<'a, E: Engine> StagesRunner<'a, E> {
    fn stages(&mut self) -> LaneStages<'_, E> {
        LaneStages {
            waiter: &mut self.waiter,
            env: LaneEnv {
                store: self.env.store,
                lanes: self.env.lanes,
                policies: self.env.policies,
                callers: self.env.callers,
                procs: self.env.procs,
                host: self.env.host,
                evidence: &crate::waiter::load_artifacts,
                triage: self.env.triage,
                tags: self.env.tags,
                data_dir: self.env.data_dir,
            },
            lane: self.lane.clone(),
        }
    }

    /// The waiter back, for the engine's shutdown.
    pub fn into_waiter(self) -> Waiter<E> {
        self.waiter
    }
}

/// What `lane` runs, from its lane file and its engine's snapshot.
pub fn profile_of(
    lanes: &LaneDir,
    lane: &LaneId,
    snapshot: &antinomie_monitor_core::Snapshot,
) -> Option<super::board::LaneProfile> {
    let file = lanes.load(lane).ok().flatten()?;
    Some(super::board::LaneProfile {
        vm_name: snapshot
            .vms
            .iter()
            .find(|vm| vm.id == file.vm_id)
            .map(|vm| vm.name.clone()),
        arch: snapshot
            .bases
            .iter()
            .find(|base| base.id == file.base_identity)
            .map(|base| base.arch),
        vm_id: file.vm_id,
        base_identity: file.base_identity,
    })
}

fn hosted_end(hosted: &Hosted) -> JobEnd {
    match hosted {
        Hosted::Aborted(_) => JobEnd::Aborted,
        _ => JobEnd::Done,
    }
}

impl<E: Engine> LaneRunner for StagesRunner<'_, E> {
    fn tick(&mut self) -> Result<(), String> {
        self.waiter.drain().map_err(|e| e.to_string())
    }

    fn eligibility(&mut self) -> Eligibility {
        self.stages().eligibility()
    }

    fn run_job(&mut self, job: &Job, to_host: &mut dyn FnMut()) -> JobEnd {
        let pool = self.pool;
        let mut stages = self.stages();
        match stages.drive(job) {
            Driven::Collected(end) => match pool {
                Some(pool) => {
                    pool.admit(job, end.outcome);
                    JobEnd::Done
                }
                None => {
                    to_host();
                    hosted_end(&stages.host(job, &end))
                }
            },
            Driven::Aborted(_) => JobEnd::Aborted,
            _ => JobEnd::Done,
        }
    }

    fn resume(&mut self, job: &Job) -> JobEnd {
        match self.pool {
            Some(pool) => {
                pool.resume(job, &mut self.waiter);
                JobEnd::Done
            }
            None => hosted_end(&self.stages().resume_host(job)),
        }
    }

    fn govern(&mut self, now_ms: u64) {
        if let Some(governor) = &mut self.governor
            && let Err(error) = governor.tick(now_ms)
        {
            (self.log)(&format!("resource check: {error}"));
        }
    }

    fn profile(&mut self) -> Option<super::board::LaneProfile> {
        profile_of(self.env.lanes, &self.lane, self.waiter.snapshot())
    }

    fn lane_vm(&self, job: &Job) -> Option<String> {
        self.env
            .policies
            .get(&job.policy.name)
            .and_then(|policy| policy.policy.vm.lane_vm.clone())
    }

    fn command(&mut self, op: &str, params: Value) -> Result<Value, ApiError> {
        let request: super::lane_ops::LaneParams = super::service::params(params)?;
        let lane = request.lane.unwrap_or_else(|| self.lane.clone());
        if lane != self.lane {
            // Each lane's engine serves its own lane only.
            return Err(ApiError::new(
                ErrorCode::Internal,
                format!("{op} for {lane} reached the thread of {}", self.lane),
            ));
        }
        let log = self.log;
        let summary = match op {
            "lane.reset" => provision::reset_lane(
                &mut self.waiter,
                self.env.lanes,
                &lane,
                self.env.procs,
                &mut |text| log(&format!("{lane} reset: {text}")),
            )?,
            "lane.unquarantine" => {
                provision::unquarantine_lane(&mut self.waiter, self.env.lanes, &lane)?
            }
            _ => {
                return Err(ApiError::new(
                    ErrorCode::Unsupported,
                    format!("{op} is not a lane command"),
                ));
            }
        };
        if let Ok(file) = self.env.lanes.load(&lane)
            && let Some(file) = file
        {
            let _ = self
                .env
                .store
                .emit_engine(crate::api::event::EventBody::LaneState {
                    lane: lane.clone(),
                    state: if file.is_quarantined() {
                        crate::api::event::LaneState::Quarantined
                    } else {
                        crate::api::event::LaneState::Idle
                    },
                    job_id: None,
                    reason: Some(op.to_owned()),
                });
        }
        super::service::to_value(&summary)
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! `prechecks` (design 4.1): re-check what can change since submit, then
//! choose the lane. Nothing here touches the VM.
use super::{HostProblem, LaneStages, Prepared, StageStop, plan};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        job::{Job, Stage, WaitingFor},
        ops::Scope,
    },
    engine::Engine,
    lane::{LaneFile, LaneProblem, check_lane, layer_pending, recover::announce_quarantine},
    store::Eligibility,
    waiter::WaitError,
};
use antinomie_monitor_core::{Command, Snapshot, VmState};
use std::time::Duration;

fn fail(code: FailureCode, message: &str, detail: Option<&str>) -> StageStop {
    StageStop::Failed(Failure::new(code, Stage::Prechecks, message, detail))
}

/// Whether a lane can take a job (the scheduler's question for `claim_next`).
pub fn lane_eligibility(file: &LaneFile, snapshot: &Snapshot) -> Eligibility {
    if file.is_quarantined() {
        return Eligibility::Wait(WaitingFor::LaneQuarantined);
    }
    if file.current.is_some() {
        return Eligibility::Wait(WaitingFor::Lane);
    }
    if layer_pending(snapshot, &file.vm_id) {
        return Eligibility::Wait(WaitingFor::LayerPending);
    }
    if snapshot.state != VmState::Stopped {
        return Eligibility::Wait(WaitingFor::Lane);
    }
    Eligibility::Ready
}

/// How long `prechecks` waits for the engine to list the lane VM's snapshots.
const TREE_WAIT: Duration = Duration::from_secs(60);

impl<E: Engine> LaneStages<'_, E> {
    /// A fresh engine lists its VMs before their snapshots: a daemon that
    /// just started may take a requeued job before the engine has read the
    /// lane VM's snapshot tree (ANT-T0474). Ask for it and wait for it, so
    /// the clean snapshot is checked against the real list. A signal or a
    /// dead engine ends the wait; a refresh that fails leaves the check to
    /// say the tree is not there.
    fn load_snapshot_tree(&mut self, vm_id: &str) -> Result<(), StageStop> {
        let snapshot = self.waiter.snapshot();
        if !snapshot.vms.iter().any(|vm| vm.id == vm_id)
            || snapshot.vm_snapshot_trees.contains_key(vm_id)
        {
            return Ok(());
        }
        let refresh = Command::RefreshVmSnapshots {
            vm_id: vm_id.to_owned(),
        };
        match self.waiter.command(refresh, Some(TREE_WAIT)) {
            Ok(_) | Err(WaitError::Failed(_) | WaitError::TimedOut { .. }) => {}
            Err(other) => return Err(StageStop::Abort(other)),
        }
        let id = vm_id.to_owned();
        match self
            .waiter
            .wait_until("the lane VM's snapshots", Some(Duration::from_secs(10)), {
                move |s| s.vm_snapshot_trees.contains_key(&id)
            }) {
            Ok(()) | Err(WaitError::TimedOut { .. }) => Ok(()),
            Err(other) => Err(StageStop::Abort(other)),
        }
    }

    /// The frozen policy still exists and still allows the job; the host has
    /// room; the lane is usable (not quarantined, free, its clean snapshot
    /// unchanged).
    pub fn prechecks(&mut self, job: &Job) -> Result<Prepared, StageStop> {
        let store = self.env.store;
        let frozen = store
            .frozen_policy(&job.id)
            .map_err(|e| self.store_error(Stage::Prechecks, e))?;
        match self.env.policies.get(&frozen.name) {
            None => {
                return Err(fail(
                    FailureCode::PolicyDenied,
                    "the policy of the job no longer exists",
                    Some(&frozen.name),
                ));
            }
            Some(current) if !current.allows(&job.client_id, Scope::Submit) => {
                return Err(fail(
                    FailureCode::PolicyDenied,
                    "the policy no longer allows this client",
                    Some(&frozen.name),
                ));
            }
            Some(_) => {}
        }

        match self.env.host.check(job, &frozen.policy) {
            Ok(()) => {}
            Err(HostProblem::Wait(waiting_for, detail)) => {
                return Err(StageStop::Wait {
                    waiting_for,
                    detail,
                });
            }
            Err(HostProblem::Fail(code, detail)) => {
                return Err(fail(code, "the host cannot run the job", Some(&detail)));
            }
        }

        let mut file = self.lane_file()?;
        self.waiter.drain()?;
        if let Some(quarantine) = &file.quarantine {
            return Err(StageStop::Wait {
                waiting_for: WaitingFor::LaneQuarantined,
                detail: quarantine.detail.clone(),
            });
        }
        if let Some(work) = &file.current {
            return Err(StageStop::Wait {
                waiting_for: WaitingFor::Lane,
                detail: format!("the lane is working on {}", work.job_id),
            });
        }
        self.load_snapshot_tree(&file.vm_id)?;
        for problem in check_lane(&file, self.waiter.snapshot()) {
            match problem {
                LaneProblem::NoVm => {
                    return Err(fail(
                        FailureCode::NoVm,
                        "the lane VM does not exist",
                        Some(&file.vm_id),
                    ));
                }
                // The engine has not listed the VM's snapshots: nothing is
                // known to be wrong, so the job waits (ANT-T0474).
                LaneProblem::SnapshotMissing {
                    verifiable: false, ..
                } => {
                    return Err(StageStop::Wait {
                        waiting_for: WaitingFor::Lane,
                        detail: format!(
                            "the engine has not listed the snapshots of {} yet",
                            file.vm_id
                        ),
                    });
                }
                LaneProblem::SnapshotMissing { id, verifiable } => {
                    let detail = format!(
                        "the clean snapshot {id} is not among the snapshots of {}",
                        file.vm_id
                    );
                    if verifiable {
                        let now = self.waiter.now_ms();
                        file.quarantine(FailureCode::LaneChanged, &detail, now);
                        self.env.lanes.save(&file).map_err(|e| {
                            self.internal(
                                FailureCode::Internal,
                                Stage::Prechecks,
                                "the lane state file cannot be written",
                                Some(&e.to_string()),
                            )
                        })?;
                        announce_quarantine(store, &file, Some(job.id.clone()))
                            .map_err(|e| self.store_error(Stage::Prechecks, e))?;
                    }
                    return Err(fail(
                        FailureCode::LaneChanged,
                        "the lane VM was changed outside the service",
                        Some(&detail),
                    ));
                }
                LaneProblem::NotStopped(state) => {
                    return Err(StageStop::Wait {
                        waiting_for: WaitingFor::Lane,
                        detail: format!("the engine's VM is {state}"),
                    });
                }
                // `provision` waits this one out: the job is already ours.
                LaneProblem::LayerPending | LaneProblem::Quarantined(_) => {}
            }
        }
        let effective = plan::effective(job, &frozen.policy);
        Ok(Prepared {
            policy: frozen,
            effective,
            lane: file,
        })
    }
}

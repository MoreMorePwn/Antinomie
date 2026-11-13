// SPDX-License-Identifier: GPL-3.0-only
//! What must hold before a lane takes a job (design 4.5.3, 4.1 `prechecks`):
//! one function shared by `prechecks`, recovery and `auto lane unquarantine`
//! ("snapshot present with the recorded id, VM stopped, no pending layer").
use super::state::LaneFile;
use crate::api::{failure::FailureCode, run::WaitingFor};
use antinomie_monitor_core::{Snapshot, VmState};

/// One thing that keeps the lane from taking a job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneProblem {
    /// The lane VM is not in the engine's list.
    NoVm,
    /// The clean snapshot of the lane file is not among the VM's snapshots.
    /// `verifiable` says the engine listed the VM's snapshots at all.
    SnapshotMissing { id: String, verifiable: bool },
    /// The engine has a VM running or changing state (its name).
    NotStopped(String),
    /// The lane VM has a pending disk layer or its recording is still saved.
    LayerPending,
    /// The lane is quarantined.
    Quarantined(FailureCode),
}

impl LaneProblem {
    /// The failure code the problem gives a job, when it is a failure.
    pub fn failure_code(&self) -> Option<FailureCode> {
        match self {
            Self::NoVm => Some(FailureCode::NoVm),
            Self::SnapshotMissing { .. } => Some(FailureCode::LaneChanged),
            _ => None,
        }
    }

    /// The `waiting_for` of a job that has to wait out the problem.
    pub fn waiting_for(&self) -> Option<WaitingFor> {
        match self {
            Self::LayerPending => Some(WaitingFor::LayerPending),
            Self::Quarantined(_) => Some(WaitingFor::LaneQuarantined),
            _ => None,
        }
    }
}

/// Is the VM's disk layer or recording still being finished?
pub fn layer_pending(snapshot: &Snapshot, vm_id: &str) -> bool {
    snapshot.recording_flush.is_some() || snapshot.disk_layers.iter().any(|l| l.vm_id == vm_id)
}

/// Every problem with the lane, given the engine's latest snapshot.
pub fn check_lane(file: &LaneFile, snapshot: &Snapshot) -> Vec<LaneProblem> {
    let mut problems = Vec::new();
    if let Some(quarantine) = &file.quarantine {
        problems.push(LaneProblem::Quarantined(quarantine.reason));
    }
    if !snapshot.vms.iter().any(|vm| vm.id == file.vm_id) {
        problems.push(LaneProblem::NoVm);
    } else {
        let tree = snapshot.vm_snapshot_trees.get(&file.vm_id);
        let present =
            tree.is_some_and(|tree| tree.nodes.iter().any(|n| n.id == file.clean_snapshot_id));
        if !present {
            problems.push(LaneProblem::SnapshotMissing {
                id: file.clean_snapshot_id.clone(),
                verifiable: tree.is_some(),
            });
        }
    }
    if snapshot.state != VmState::Stopped {
        problems.push(LaneProblem::NotStopped(format!("{:?}", snapshot.state)));
    }
    if layer_pending(snapshot, &file.vm_id) {
        problems.push(LaneProblem::LayerPending);
    }
    problems
}

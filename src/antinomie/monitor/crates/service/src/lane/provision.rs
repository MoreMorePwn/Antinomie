// SPDX-License-Identifier: GPL-3.0-only
//! Making and mending a lane (design 4.5.3, 3.4.4; card P3-5b): `auto init`,
//! `auto lane list`, `auto lane reset` and `auto lane unquarantine`, on any
//! [`Engine`] (the command's own in direct mode, the lane's in the daemon).
//!
//! `auto init` (4.5.3 step 1): create the lane VM with the `VmConfig` the
//! caller built (routed, not NAT, not isolated), boot it once, wait for the
//! guest to answer the INFO probe and to finish booting (`AwaitBoot`: its
//! root file system mounted, so the initramfs no longer grows it; a guest
//! kernel that crashed on the way fails the command), stop it and wait for
//! the run layer to settle, take the Disk snapshot (`auto-clean`), and write
//! `lanes/lane-N.json` with the VM, the snapshot id and the base identity.
//! A lane that exists is refused unless `replace` is asked; a replaced lane
//! that still has work is refused too. Nothing is left half made: a failure
//! after the VM was created says which VM is left so the person can delete
//! it, and no lane file is written.
//!
//! `lane reset` redoes the revert now (the clean snapshot restored, the
//! guest answering, the VM stopped and settled); when it worked a quarantine
//! is lifted. `lane unquarantine` runs the checks only (the snapshot with the
//! recorded id, the VM stopped, no pending layer) and lifts the flag without
//! reverting; a failed check keeps it (audit C19).

use super::{
    check::{LaneProblem, check_lane},
    process::Processes,
    reset::{ResetRefused, clear_for_reset},
    state::{LaneDir, LaneFile},
};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ids::LaneId,
    },
    engine::Engine,
    waiter::{BOOT_WAIT, SETTLE_WAIT, WaitError, Waiter},
};
use antinomie_monitor_core::{Command, SnapshotRequest, VmSnapshotMode, VmState};
use serde::Serialize;
use std::time::Duration;

/// The snapshot name `auto init` takes by default (and the default policy's
/// `vm.revert_to`).
pub const CLEAN_SNAPSHOT: &str = "auto-clean";

/// What `auto init` is asked to do.
#[derive(Clone, Debug)]
pub struct InitPlan {
    pub lane: LaneId,
    /// `Create` or `CreateWithCredentials` with the lane VM's config.
    pub create: Command,
    /// The VM's name (the policy's `vm.lane_vm`).
    pub vm_name: String,
    pub base_identity: String,
    pub snapshot: String,
    pub replace: bool,
    /// The guest revision the policies need (15 when one allows core dumps).
    pub need_revision: Option<u32>,
}

/// What `auto init` made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InitReport {
    pub lane: LaneId,
    pub vm_id: String,
    pub vm_name: String,
    pub base_identity: String,
    pub snapshot_id: String,
    pub snapshot_name: String,
    pub guest_revision: Option<u32>,
    pub boot_ms: u64,
    /// The VM of the lane this one replaced (kept; delete it by hand).
    pub replaced_vm: Option<String>,
}

/// One lane as `lane list` shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaneSummary {
    pub lane: LaneId,
    pub vm_id: String,
    pub vm_name: Option<String>,
    pub clean_snapshot_id: String,
    pub base_identity: String,
    pub quarantine: Option<String>,
    pub quarantine_detail: Option<String>,
    pub failures: u32,
    pub busy_with: Option<String>,
    pub collected: usize,
    /// The checks of `lane unquarantine`, as words; empty when it may run.
    pub problems: Vec<String>,
}

fn conflict(message: impl Into<String>) -> ApiError {
    ApiError::new(ErrorCode::Conflict, message)
}

fn engine_error(error: WaitError, doing: &str) -> ApiError {
    let code = match &error {
        WaitError::Interrupted | WaitError::Cancelled => ErrorCode::Unavailable,
        WaitError::TimedOut { .. } | WaitError::DeadlineExceeded => ErrorCode::Unavailable,
        // The engine is recovering the guest: not an engine failure.
        WaitError::GuestTransition(_) => ErrorCode::Unavailable,
        WaitError::Failed(_) => ErrorCode::PreconditionFailed,
        _ => ErrorCode::Internal,
    };
    ApiError::new(code, format!("{doing}: {error}"))
}

/// A lane problem in words.
pub fn problem_words(problem: &LaneProblem) -> String {
    match problem {
        LaneProblem::NoVm => "the lane VM is not in the data folder".into(),
        LaneProblem::SnapshotMissing { id, .. } => {
            format!("the clean snapshot {id} is not among the VM's snapshots")
        }
        LaneProblem::NotStopped(state) => format!("the engine's VM is not stopped ({state})"),
        LaneProblem::LayerPending => "the VM's last run is still being saved".into(),
        LaneProblem::Quarantined(reason) => format!(
            "quarantined ({})",
            serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default()
        ),
    }
}

/// `auto init`.
pub fn init_lane<E: Engine>(
    waiter: &mut Waiter<E>,
    lanes: &LaneDir,
    plan: &InitPlan,
    progress: &mut dyn FnMut(&str),
) -> Result<InitReport, ApiError> {
    let existing = lanes
        .load(&plan.lane)
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let replaced_vm = match (&existing, plan.replace) {
        (Some(file), false) => {
            return Err(conflict(format!(
                "{} exists (VM {}); `auto init --replace` makes a new lane VM",
                plan.lane, file.vm_id
            )));
        }
        (Some(file), true) if file.current.is_some() || !file.collected.is_empty() => {
            return Err(conflict(format!(
                "{} still has a job; wait until it is idle",
                plan.lane
            )));
        }
        (Some(file), true) => Some(file.vm_id.clone()),
        (None, _) => None,
    };
    if waiter
        .snapshot()
        .vms
        .iter()
        .any(|vm| vm.name == plan.vm_name)
    {
        return Err(conflict(format!(
            "a VM named {:?} exists already; choose another --name",
            plan.vm_name
        )));
    }
    let before: Vec<String> = waiter
        .snapshot()
        .vms
        .iter()
        .map(|vm| vm.id.clone())
        .collect();
    progress(&format!("creating the lane VM {:?}", plan.vm_name));
    waiter
        .command(plan.create.clone(), Some(Duration::from_secs(1800)))
        .map_err(|e| engine_error(e, "the lane VM was not created"))?;
    waiter
        .wait_until("the new VM", Some(Duration::from_secs(30)), |s| {
            s.vms.iter().any(|vm| !before.contains(&vm.id))
        })
        .map_err(|e| engine_error(e, "the new VM did not appear"))?;
    let vm_id = waiter
        .snapshot()
        .vms
        .iter()
        .find(|vm| !before.contains(&vm.id))
        .map(|vm| vm.id.clone())
        .expect("the wait above found it");
    let left = |error: ApiError| {
        let message = format!(
            "{}; the VM {vm_id} ({}) is left as it is: delete it with `antinomie-cli vm delete {vm_id} --yes`",
            error.message, plan.vm_name
        );
        ApiError { message, ..error }
    };

    progress("first boot: waiting for the guest to answer");
    let began = waiter.now_ms();
    waiter
        .start_command(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            BOOT_WAIT,
        )
        .map_err(|e| left(engine_error(e, "the lane VM did not start")))?;
    let id = vm_id.clone();
    let limit = waiter.guest_wait(BOOT_WAIT);
    waiter
        .wait_until("the guest to answer", Some(limit), move |s| {
            s.active_vm.as_deref() == Some(id.as_str())
                && s.state == VmState::Running
                && s.guest_kernel.is_some()
        })
        .map_err(|e| left(engine_error(e, "the guest did not answer")))?;
    let boot_ms = waiter.now_ms().saturating_sub(began);
    let guest_revision = waiter
        .snapshot()
        .guest_kernel
        .as_ref()
        .and_then(|kernel| kernel.revision);
    if let (Some(need), Some(have)) = (plan.need_revision, guest_revision)
        && have < need
    {
        let _ = waiter.stop_vm(&vm_id, Some(SETTLE_WAIT));
        return Err(left(ApiError::new(
            ErrorCode::PreconditionFailed,
            format!("the guest is revision {have}; a policy needs {need} (core dumps)"),
        )));
    }
    // The control channel answers from the initramfs, which may still be
    // growing the root file system to the lane disk: a stop now would keep a
    // half-grown one in the clean snapshot, and every job's boot from it
    // would crash the guest kernel (ANT-T0476).
    progress("waiting for the guest to finish booting");
    waiter
        .await_boot(&vm_id)
        .map_err(|e| left(engine_error(e, "the guest did not finish booting")))?;
    if let Some(line) = waiter.kernel_crash() {
        let _ = waiter.stop_vm(&vm_id, Some(SETTLE_WAIT));
        return Err(left(ApiError::new(
            ErrorCode::PreconditionFailed,
            format!(
                "the guest kernel crashed during the first boot; no clean snapshot was taken: {line}"
            ),
        )));
    }
    progress("stopping the VM and waiting for its disk to settle");
    waiter
        .stop_vm(&vm_id, Some(SETTLE_WAIT))
        .map_err(|e| left(engine_error(e, "the VM did not stop and settle")))?;

    progress(&format!("taking the Disk snapshot {:?}", plan.snapshot));
    waiter
        .command(
            Command::CreateVmSnapshot {
                vm_id: vm_id.clone(),
                request: SnapshotRequest {
                    name: plan.snapshot.clone(),
                    description: "Auto mode: the clean state every job starts from".into(),
                    mode: VmSnapshotMode::Disk,
                },
            },
            Some(Duration::from_secs(1800)),
        )
        .map_err(|e| left(engine_error(e, "the clean snapshot was not taken")))?;
    let (id, name) = (vm_id.clone(), plan.snapshot.clone());
    waiter
        .wait_until("the snapshot", Some(Duration::from_secs(60)), move |s| {
            s.vm_snapshot_trees
                .get(&id)
                .is_some_and(|tree| tree.nodes.iter().any(|n| n.name == name))
        })
        .map_err(|e| left(engine_error(e, "the snapshot did not appear")))?;
    let snapshot_id = waiter.snapshot().vm_snapshot_trees[&vm_id]
        .nodes
        .iter()
        .find(|n| n.name == plan.snapshot)
        .map(|n| n.id.clone())
        .expect("the wait above found it");

    let file = LaneFile::new(
        plan.lane.clone(),
        &vm_id,
        &snapshot_id,
        &plan.base_identity,
        waiter.now_ms(),
    );
    lanes
        .save(&file)
        .map_err(|e| left(ApiError::new(ErrorCode::Internal, e.to_string())))?;
    Ok(InitReport {
        lane: plan.lane.clone(),
        vm_id,
        vm_name: plan.vm_name.clone(),
        base_identity: plan.base_identity.clone(),
        snapshot_id,
        snapshot_name: plan.snapshot.clone(),
        guest_revision,
        boot_ms,
        replaced_vm,
    })
}

/// `lane list`: every lane file with its checks against the engine's
/// snapshot (when one is at hand).
pub fn list_lanes(
    lanes: &LaneDir,
    snapshot: Option<&antinomie_monitor_core::Snapshot>,
) -> Result<Vec<LaneSummary>, ApiError> {
    list_lanes_with(lanes, &|_| snapshot)
}

/// [`list_lanes`] with each lane checked against its own engine's snapshot
/// (several lanes, one engine each); `None` skips a lane's checks.
pub fn list_lanes_with<'a>(
    lanes: &LaneDir,
    snapshot_of: &dyn Fn(&LaneId) -> Option<&'a antinomie_monitor_core::Snapshot>,
) -> Result<Vec<LaneSummary>, ApiError> {
    let ids = lanes
        .lanes()
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    let mut out = Vec::new();
    for lane in ids {
        let file = match lanes.load(&lane) {
            Ok(Some(file)) => file,
            Ok(None) => continue,
            Err(error) => {
                return Err(ApiError::new(
                    ErrorCode::Internal,
                    format!("{lane}: {error}"),
                ));
            }
        };
        let snapshot = snapshot_of(&lane);
        let problems = snapshot
            .map(|s| {
                check_lane(&file, s)
                    .iter()
                    .filter(|p| !matches!(p, LaneProblem::Quarantined(_)))
                    .map(problem_words)
                    .collect()
            })
            .unwrap_or_default();
        out.push(LaneSummary {
            vm_name: snapshot.and_then(|s| {
                s.vms
                    .iter()
                    .find(|vm| vm.id == file.vm_id)
                    .map(|vm| vm.name.clone())
            }),
            lane,
            vm_id: file.vm_id.clone(),
            clean_snapshot_id: file.clean_snapshot_id.clone(),
            base_identity: file.base_identity.clone(),
            quarantine: file.quarantine.as_ref().map(|q| {
                serde_json::to_value(q.reason)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
            }),
            quarantine_detail: file.quarantine.as_ref().map(|q| q.detail.clone()),
            failures: file.failures,
            busy_with: file.current.as_ref().map(|w| w.job_id.to_string()),
            collected: file.collected.len(),
            problems,
        });
    }
    Ok(out)
}

fn idle_file(lanes: &LaneDir, lane: &LaneId) -> Result<LaneFile, ApiError> {
    let file = lanes
        .load(lane)
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?
        .ok_or_else(|| ApiError::not_found("lane").with_field("lane"))?;
    if file.current.is_some() || !file.collected.is_empty() {
        return Err(conflict(format!("{lane} has a job; wait until it is idle")));
    }
    Ok(file)
}

/// Ask the engine for the VM's snapshot tree (a fresh engine may not have
/// loaded it yet) and wait a little for it. A VM the engine does not know is
/// left to the checks (`NoVm`).
fn load_tree<E: Engine>(waiter: &mut Waiter<E>, vm_id: &str) {
    if waiter
        .command(
            Command::RefreshVmSnapshots {
                vm_id: vm_id.to_owned(),
            },
            Some(Duration::from_secs(60)),
        )
        .is_ok()
    {
        let id = vm_id.to_owned();
        let _ = waiter.wait_until(
            "the snapshot tree",
            Some(Duration::from_secs(10)),
            move |s| s.vm_snapshot_trees.contains_key(&id),
        );
    }
}

/// `lane unquarantine`: the checks only; the flag goes when they pass.
pub fn unquarantine_lane<E: Engine>(
    waiter: &mut Waiter<E>,
    lanes: &LaneDir,
    lane: &LaneId,
) -> Result<LaneSummary, ApiError> {
    let file = idle_file(lanes, lane)?;
    load_tree(waiter, &file.vm_id);
    let snapshot = waiter.snapshot();
    let problems: Vec<String> = check_lane(&file, snapshot)
        .iter()
        .filter(|p| !matches!(p, LaneProblem::Quarantined(_)))
        .map(problem_words)
        .collect();
    if !problems.is_empty() {
        return Err(ApiError::new(
            ErrorCode::PreconditionFailed,
            format!(
                "{lane} stays quarantined: {}; `auto lane reset` reverts it",
                problems.join("; ")
            ),
        ));
    }
    let now = waiter.now_ms();
    lanes
        .update(lane, |file| file.unquarantine(now))
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    list_lanes(lanes, Some(waiter.snapshot()))?
        .into_iter()
        .find(|s| &s.lane == lane)
        .ok_or_else(|| ApiError::not_found("lane"))
}

/// `lane reset`: the revert now, then the VM stopped and settled; a
/// quarantine is lifted when it worked.
pub fn reset_lane<E: Engine>(
    waiter: &mut Waiter<E>,
    lanes: &LaneDir,
    lane: &LaneId,
    procs: &dyn Processes,
    progress: &mut dyn FnMut(&str),
) -> Result<LaneSummary, ApiError> {
    let file = idle_file(lanes, lane)?;
    if waiter.snapshot().state != VmState::Stopped {
        let active = waiter.snapshot().active_vm.clone().unwrap_or_default();
        progress("stopping the running VM first");
        waiter
            .stop_vm(&active, Some(SETTLE_WAIT))
            .map_err(|e| engine_error(e, "the running VM did not stop"))?;
    }
    let now = waiter.now_ms();
    clear_for_reset(lanes, lane, procs, now).map_err(|refused| match refused {
        ResetRefused::QemuAlive(pid) => conflict(format!(
            "the lane VM's QEMU process {pid} still runs; stop it first"
        )),
        ResetRefused::State(e) => ApiError::new(ErrorCode::Internal, e.to_string()),
    })?;
    progress("restoring the clean snapshot");
    // The restore boots the VM inside the command: a silence limit, like Start.
    waiter
        .start_command(
            Command::RestoreVmSnapshot {
                vm_id: file.vm_id.clone(),
                snapshot_id: file.clean_snapshot_id.clone(),
                boot_from_disk: true,
                save_current: None,
                confirmed: true,
                switch_profile: false,
            },
            BOOT_WAIT,
        )
        .map_err(|e| engine_error(e, "the revert failed; the lane stays as it was"))?;
    let id = file.vm_id.clone();
    let limit = waiter.guest_wait(BOOT_WAIT);
    waiter
        .wait_until("the guest to answer", Some(limit), move |s| {
            s.active_vm.as_deref() == Some(id.as_str())
                && s.state == VmState::Running
                && s.guest_kernel.is_some()
        })
        .map_err(|e| engine_error(e, "the reverted guest did not answer"))?;
    progress("waiting for the guest to finish booting");
    waiter
        .await_boot(&file.vm_id)
        .map_err(|e| engine_error(e, "the reverted guest did not finish booting"))?;
    if let Some(line) = waiter.kernel_crash() {
        let _ = waiter.stop_vm(&file.vm_id, Some(SETTLE_WAIT));
        return Err(ApiError::new(
            ErrorCode::PreconditionFailed,
            format!(
                "the guest kernel crashed while the reverted VM booted; the lane stays as it was: {line}"
            ),
        ));
    }
    progress("stopping the VM and waiting for its disk to settle");
    waiter
        .stop_vm(&file.vm_id, Some(SETTLE_WAIT))
        .map_err(|e| engine_error(e, "the VM did not stop and settle"))?;
    let now = waiter.now_ms();
    lanes
        .update(lane, |file| file.unquarantine(now))
        .map_err(|e| ApiError::new(ErrorCode::Internal, e.to_string()))?;
    list_lanes(lanes, Some(waiter.snapshot()))?
        .into_iter()
        .find(|s| &s.lane == lane)
        .ok_or_else(|| ApiError::not_found("lane"))
}

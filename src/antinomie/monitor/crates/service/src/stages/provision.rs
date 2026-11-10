// SPDX-License-Identifier: GPL-3.0-only
//! `provision` (design 4.1, 4.5.2, 4.5.3): make the lane VM clean and running.
//!
//! 1. Wait for the previous boot's disk layer and recording flush (`layer_s`).
//! 2. Stop the VM if the engine still runs it.
//! 3. Revert: a Disk or Full snapshot restore (`RestoreVmSnapshot`, which
//!    starts the VM itself), or `Reset` then `Start`. A failed restore is
//!    retried once at once; a second failure quarantines the lane
//!    (`revert_failed`). There is **no `Reset` fallback** on a snapshot lane
//!    (a snapshot lane cannot be reset, audit G4).
//! 4. Wait for the guest to answer (`boot_s`), and check its revision against
//!    the options (a core dump needs revision 15).
//! 5. Find the VM's QEMU process and record it in the lane file, so recovery
//!    can end it after a crash.
//!
//! `vm_start_failed` and `guest_unreachable` count toward the quarantine of
//! three in a row.
use super::{
    LaneStages, Prepared, Provisioned, STOP_WAIT, StageStop,
    plan::{CORE_REVISION, TRIGGER_CORE_REVISION},
};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        job::{Job, Revert, Stage},
    },
    config::policy::RevertMode,
    engine::Engine,
    lane::{QemuRecord, recover::announce_quarantine},
    store::JobPatch,
    waiter::{BOOT_WAIT, SETTLE_WAIT, WaitError, settled_after_stop},
};
use antinomie_monitor_core::{Command, VmState};

fn fail(code: FailureCode, message: &str, detail: Option<&str>) -> StageStop {
    StageStop::Failed(Failure::new(code, Stage::Provision, message, detail))
}

impl<E: Engine> LaneStages<'_, E> {
    pub fn provision(&mut self, job: &Job, prepared: &Prepared) -> Result<Provisioned, StageStop> {
        let file = self.lane_file()?;
        let vm = file.vm_id.clone();

        // 1. The previous boot's layer.
        self.waiter.drain()?;
        if crate::lane::layer_pending(self.waiter.snapshot(), &vm) {
            self.progress(
                job,
                Stage::Provision,
                "waiting for the previous recording's disk layer",
            );
            let id = vm.clone();
            self.waiter
                .wait_until(
                    "the previous recording's disk layer",
                    Some(SETTLE_WAIT),
                    |s| crate::lane::layer_pending(s, &id).then_some(()).is_none(),
                )
                .map_err(|error| match error {
                    WaitError::TimedOut { what } => fail(
                        FailureCode::VmStartFailed,
                        "the previous boot's disk layer did not settle",
                        Some(&what),
                    ),
                    other => StageStop::Abort(other),
                })?;
        }

        // 2. A VM still running is stopped first.
        if self.waiter.snapshot().state != VmState::Stopped {
            if self.waiter.snapshot().active_vm.as_deref() != Some(vm.as_str()) {
                return Err(fail(
                    FailureCode::VmStartFailed,
                    "another VM is running in the engine",
                    self.waiter.snapshot().active_vm.as_deref(),
                ));
            }
            self.progress(job, Stage::Provision, "stopping the VM before the revert");
            self.waiter
                .stop_vm(&vm, Some(STOP_WAIT))
                .map_err(|error| match error {
                    WaitError::Failed(_) | WaitError::TimedOut { .. } => fail(
                        FailureCode::VmStartFailed,
                        "the lane VM would not stop",
                        Some(&error.to_string()),
                    ),
                    other => StageStop::Abort(other),
                })?;
        }
        if !settled_after_stop(self.waiter.snapshot(), &vm) {
            return Err(fail(
                FailureCode::VmStartFailed,
                "the lane VM has recordings or a layer still being saved",
                None,
            ));
        }

        // 3. Revert.
        self.progress(job, Stage::Provision, "reverting the lane VM");
        let revert = match prepared.effective.revert {
            RevertMode::SnapshotDisk => Revert::SnapshotDisk,
            RevertMode::SnapshotFull => Revert::SnapshotFull,
            RevertMode::Reset => Revert::Reset,
        };
        match prepared.effective.revert {
            RevertMode::Reset => {
                self.revert_with(
                    job,
                    Command::Reset {
                        vm_id: vm.clone(),
                        confirmed: true,
                    },
                )?;
                self.start_vm(&vm)?;
            }
            mode => {
                let restore = Command::RestoreVmSnapshot {
                    vm_id: vm.clone(),
                    snapshot_id: file.clean_snapshot_id.clone(),
                    boot_from_disk: mode == RevertMode::SnapshotDisk,
                    save_current: None,
                    confirmed: true,
                    switch_profile: false,
                };
                self.revert_with(job, restore)?;
            }
        }

        // 4. The guest answers.
        self.progress(job, Stage::Provision, "waiting for the guest to answer");
        let id = vm.clone();
        // Stretched for a TCG boot like the engine's own waits on the guest.
        let limit = self.waiter.guest_wait(BOOT_WAIT);
        let waited = self
            .waiter
            .wait_until("the guest to answer", Some(limit), move |s| {
                s.state == VmState::Failed
                    || (s.active_vm.as_deref() == Some(id.as_str())
                        && s.state == VmState::Running
                        && s.guest_kernel.is_some())
            });
        match waited {
            Ok(()) => {}
            Err(WaitError::TimedOut { .. }) => {
                return Err(self.start_failure(
                    FailureCode::GuestUnreachable,
                    "the guest did not answer in time",
                    None,
                )?);
            }
            Err(other) => return Err(StageStop::Abort(other)),
        }
        if self.waiter.snapshot().state == VmState::Failed {
            let detail = self.waiter.snapshot().last_error.clone();
            return Err(self.start_failure(
                FailureCode::VmStartFailed,
                "the VM failed while it started",
                detail.as_deref(),
            )?);
        }
        let revision = self
            .waiter
            .snapshot()
            .guest_kernel
            .as_ref()
            .and_then(|kernel| kernel.revision);
        if prepared.effective.request.core_dump_on_exit
            && revision.is_none_or(|revision| revision < CORE_REVISION)
        {
            return Err(fail(
                FailureCode::DependencyMissing,
                "the guest is too old for a core dump",
                Some(&format!(
                    "revision {} found, {CORE_REVISION} needed",
                    revision.map_or("none".to_owned(), |r| r.to_string())
                )),
            ));
        }
        if prepared
            .effective
            .request
            .dump_trigger
            .as_ref()
            .is_some_and(|plan| plan.core)
            && revision.is_none_or(|revision| revision < TRIGGER_CORE_REVISION)
        {
            return Err(fail(
                FailureCode::DependencyMissing,
                "the guest is too old for a core on suspicious activity",
                Some(&format!(
                    "revision {} found, {TRIGGER_CORE_REVISION} needed",
                    revision.map_or("none".to_owned(), |r| r.to_string())
                )),
            ));
        }
        let now = self.waiter.now_ms();
        self.update_lane(|file| file.note_start_success(now))?;

        // 5. The QEMU process, for recovery.
        self.record_qemu(job, &vm)?;

        // 6. What the job learned.
        let snapshot = self.waiter.snapshot();
        let name = snapshot
            .vms
            .iter()
            .find(|config| config.id == vm)
            .map_or_else(|| vm.clone(), |config| config.name.clone());
        let boot_id = snapshot.boot_id.clone();
        self.env
            .store
            .patch(
                &job.id,
                JobPatch {
                    vm: Some(crate::api::job::JobVm {
                        id: vm.clone(),
                        name,
                        base_identity: Some(file.base_identity.clone()),
                        revert,
                    }),
                    ..JobPatch::default()
                },
            )
            .map_err(|e| self.store_error(Stage::Provision, e))?;
        Ok(Provisioned {
            vm_id: vm,
            boot_id,
            guest_revision: revision,
        })
    }

    /// Send the revert command; one immediate retry; then quarantine. A
    /// restore boots the VM inside the command, so `BOOT_WAIT` is a silence
    /// limit as for `Start` (the engine's note of the slow TCG boot restarts
    /// it; `START_HARD_WAIT` bounds it).
    fn revert_with(&mut self, job: &Job, command: Command) -> Result<(), StageStop> {
        let mut last = String::new();
        for attempt in 1..=2 {
            match self.waiter.start_command(command.clone(), BOOT_WAIT) {
                Ok(_) => return Ok(()),
                Err(WaitError::Failed(message)) => last = message,
                Err(WaitError::TimedOut { .. }) => {
                    last = "the restore did not finish in time".into()
                }
                Err(other) => return Err(StageStop::Abort(other)),
            }
            if attempt == 1 {
                self.progress(job, Stage::Provision, "the revert failed; trying once more");
            }
        }
        let detail = format!("the revert failed twice: {last}");
        let now = self.waiter.now_ms();
        let file = self.update_lane(|file| {
            file.quarantine(FailureCode::RevertFailed, &detail, now);
            file.clone()
        })?;
        announce_quarantine(self.env.store, &file, Some(job.id.clone()))
            .map_err(|e| self.store_error(Stage::Provision, e))?;
        Err(fail(
            FailureCode::RevertFailed,
            "the lane VM could not be reverted; the lane is quarantined",
            Some(&last),
        ))
    }

    fn start_vm(&mut self, vm: &str) -> Result<(), StageStop> {
        match self.waiter.start_command(
            Command::Start {
                vm_id: vm.to_owned(),
            },
            BOOT_WAIT,
        ) {
            Ok(_) => Ok(()),
            Err(WaitError::Failed(message)) => Err(self.start_failure(
                FailureCode::VmStartFailed,
                "the VM did not start",
                Some(&message),
            )?),
            Err(WaitError::TimedOut { .. }) => Err(self.start_failure(
                FailureCode::VmStartFailed,
                "the VM did not start in time",
                None,
            )?),
            Err(other) => Err(StageStop::Abort(other)),
        }
    }

    /// A start failure: counted on the lane, the third in a row quarantines.
    /// Returns the stop to hand back, or the error of writing the lane file.
    fn start_failure(
        &self,
        code: FailureCode,
        message: &str,
        detail: Option<&str>,
    ) -> Result<StageStop, StageStop> {
        let now = self.waiter.now_ms();
        let text = detail.unwrap_or(message).to_owned();
        let (quarantined, file) = self.update_lane(|file| {
            let quarantined = file.note_start_failure(code, &text, now);
            (quarantined, file.clone())
        })?;
        if quarantined {
            announce_quarantine(self.env.store, &file, None)
                .map_err(|e| self.store_error(Stage::Provision, e))?;
        }
        Ok(fail(code, message, detail))
    }

    /// Record the VM's QEMU process in the lane file. A VM whose process
    /// cannot be told apart is a warning, not a failure.
    fn record_qemu(&mut self, job: &Job, vm: &str) -> Result<(), StageStop> {
        let marker = self
            .waiter
            .snapshot()
            .vm_locations
            .iter()
            .find(|location| location.vm_id == vm)
            .map_or_else(
                || vm.to_owned(),
                |location| location.disk_directory.display().to_string(),
            );
        let found = self.env.procs.find_qemu(&marker);
        let now = self.waiter.now_ms();
        match found.as_slice() {
            [(pid, info)] => {
                let record = QemuRecord {
                    pid: *pid,
                    start_ticks: info.start_ticks,
                    marker,
                    recorded_ms: now,
                };
                self.update_lane(|file| file.set_qemu(record))
            }
            other => {
                let text = format!(
                    "{} QEMU processes match the lane VM's folder; the pid is not recorded",
                    other.len()
                );
                let _ = self
                    .env
                    .store
                    .add_warning(&job.id, "qemu_pid_unknown", &text);
                self.update_lane(|file| file.clear_qemu(now))
            }
        }
    }
}

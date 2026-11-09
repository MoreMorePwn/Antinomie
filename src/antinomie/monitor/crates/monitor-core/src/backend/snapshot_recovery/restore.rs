// SPDX-License-Identifier: GPL-3.0-only
//! The inner snapshot restore transaction (moved out of `snapshot_recovery`).
use super::*;

impl Worker {
    pub(super) fn restore_vm_snapshot_inner(
        &mut self,
        id: &str,
        snapshot_id: &str,
        boot_from_disk: bool,
        save_current: Option<SnapshotRequest>,
        switch: Option<crate::stealth::StealthProfile>,
    ) -> Result<String, String> {
        if self.deferred_flush.is_some() || !self.flusher.can_submit_retired() {
            return Err(
                "recording flush queue is full; wait for saved recordings before restoring a snapshot".into(),
            );
        }
        let mut vm = self.snapshot_vm(id)?;
        // Checked against the profile the snapshot asks for; the current one is
        // what a "save current" snapshot records, and is replaced after it.
        if let Some(profile) = &switch {
            vm.stealth = profile.clone();
        }
        if let Some(session) = self.session.as_ref() {
            session.manual_snapshot_guard()?;
        }
        let debug_pause = self.debug.pause();
        if self.session.is_some() && self.snapshot.active_vm.as_deref() != Some(id) {
            return Err("stop the other VM before restoring".into());
        }
        // Validate the target before saving or touching current state.
        let tree = snapshots::list(&self.options, &vm)?;
        let node = tree
            .nodes
            .iter()
            .find(|node| node.id == snapshot_id && !node.deleted)
            .ok_or("unknown snapshot")?;
        let resume = node.mode == VmSnapshotMode::Full && !boot_from_disk;
        let bundle = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        let fingerprint = if resume {
            Some(VmProcess::compatibility_for(&self.options, &vm, &bundle)?)
        } else {
            None
        };
        if resume && snapshots::compatibility(&self.options, &vm, snapshot_id)? != fingerprint {
            return Err("full snapshot requires the original QEMU, hardware configuration and kernel; choose disk reboot".into());
        }
        snapshots::preflight_restore(&self.options, &vm, snapshot_id, !resume)?;
        let disk_bundle: Bundle =
            storage::read_json(&storage::vm_dir(&self.options, id)?.join("bundle.json"))?;
        disk_bundle.verify_installed()?;
        let checkpoint = if resume {
            let value = snapshots::host_checkpoint(&self.options, &vm, snapshot_id)?
                .ok_or("snapshot has no host context")?;
            let saved: HostCheckpoint = serde_json::from_value(value)
                .map_err(|error| format!("invalid host checkpoint: {error}"))?;
            saved.validate(&vm, &bundle, &disk_bundle)?;
            Some(saved)
        } else {
            None
        };
        if let Some(request) = save_current {
            self.take_vm_snapshot(id, &request).map_err(|error| {
                format!("current state was not saved: {error}; restore cancelled")
            })?;
        }
        if switch.is_some() {
            self.use_vm_profile(&vm)?;
        }
        if self.snapshot.network_capture.is_some() {
            self.stop_network_capture()?;
        }
        if let Some(session) = self.session.as_mut() {
            session.suspend_run_network("snapshot restore seals the previous network interval")?;
        }
        let prepared = snapshots::prepare_restore(&self.options, &vm, snapshot_id, !resume)?;
        if (prepared.mode == VmSnapshotMode::Full) != resume
            || (resume && prepared.compatibility != fingerprint)
        {
            snapshots::cancel_restore(&self.options, &vm, &prepared)?;
            return Err("restore candidate capability changed".into());
        }
        let _transition = self.begin_guest_transition()?;
        self.snapshot_stage(id, "Preparing snapshot recovery");
        if let Some(mut old) = self.session.take() {
            for run in old.runs.values_mut() {
                if let Some(log) = run.custody.as_mut() {
                    log.action(
                        crate::samples::ActionKind::SnapshotRestore,
                        &format!("snapshot {snapshot_id} restored; this run ends here"),
                    );
                }
            }
            let boot_id = old.boot_id.clone();
            let steps = old.seal("snapshot-branch-sealed", &mut self.snapshot);
            self.carry_analyses(&mut old);
            let stop = old.process.force_stop();
            drop(old);
            self.submit_sealed_flush(boot_id, steps);
            if let Err(error) = stop {
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                let cleanup = snapshots::cancel_restore(&self.options, &vm, &prepared);
                return Err(format!("{error}; restore cancellation {:?}", cleanup.err()));
            }
        }
        self.snapshot.active_vm = None;
        self.snapshot.state = VmState::Starting;
        // The old QEMU has stopped: put the checkpoint's UEFI variables back
        // before the restored guest (or the rebooted one) reads them.
        if let Err(error) = snapshots::restore_efi_vars(&self.options, &vm, &prepared) {
            let cleanup = snapshots::cancel_restore(&self.options, &vm, &prepared);
            self.snapshot.state = VmState::Stopped;
            return Err(format!(
                "snapshot restore failed: {error}; cleanup {:?}",
                cleanup.err()
            ));
        }
        let recovery = (|| -> Result<Option<Session>, String> {
            if !resume {
                snapshots::commit_restore(&self.options, &vm, &prepared)?;
                return Ok(None);
            }
            let checkpoint = checkpoint.ok_or("snapshot has no host context")?;
            let effective = vm.clone();
            // The restored timeline's disk, before the guest runs again: a new
            // empty overlay on the checkpoint's frozen layers.
            let disk_start = crate::disk_start::DiskStart::capture(
                &prepared.active_disk,
                "",
                crate::disk_start::Via::Restore,
            );
            let mut process = VmProcess::launch_incoming(
                &self.options,
                &effective,
                &bundle,
                &prepared.active_disk,
            )?;
            self.snapshot.accelerator = Some(AcceleratorUsed {
                record: process.accel.record(),
                fallback_warning: process.accel.fallback_warning(&effective.name),
                guest_wait_factor: process.waits.guest_factor(),
            });
            process.load_state(
                prepared
                    .memory_path
                    .as_deref()
                    .ok_or("snapshot has no memory state")?,
            )?;
            process.verify_ram_layout()?;
            let transport = Transport::open_pending(
                &process.ram_path,
                process.ram_layout,
                process.bootstrap,
                &process.waits,
            )?;
            let mut session = Session::restored(
                &self.options,
                effective,
                bundle,
                disk_bundle,
                RestoredGuest { process, transport },
                checkpoint,
                Some(snapshot_id),
            )?;
            // Namespace exists and request is published before CPUs run. A short
            // handshake run is staged on the candidate child, never the old future.
            session.process.resume()?;
            session
                .transport
                .finish_resume(session.process.waits.resume_ms())?;
            session
                .transport
                .set_send_wait(session.vm.transport.send_wait_us())?;
            if session.vm.transport.lossless {
                session
                    .transport
                    .set_host_timeout(LOSSLESS_HOST_TIMEOUT_MS)?;
            }
            session.process.pause()?;
            session.transport.suspend_heartbeats()?;
            snapshots::commit_restore(&self.options, &vm, &prepared)?;
            session.process.resume()?;
            session.transport.resume_heartbeats()?;
            if let Err(error) = session.resume_run_network(&self.options) {
                self.snapshot.last_error = Some(error.clone());
                self.emit(Notification::CommandResult {
                    id: 0,
                    success: false,
                    message: error,
                });
            }
            if let Some(boot_dir) = session.capture.directory.parent() {
                let _ = crate::disk_start::DiskStart {
                    boot_id: session.boot_id.clone(),
                    ..disk_start
                }
                .save(boot_dir);
            }
            session.capture.queue_manifest(
                &session.vm,
                &session.bundle,
                &session.disk_bundle,
                "snapshot-resumed",
            )?;
            Ok(Some(session))
        })();
        match recovery {
            Ok(Some(session)) => {
                self.snapshot.health = Health::default();
                self.snapshot.events.clear();
                self.snapshot.captures.clear();
                self.snapshot.capture_events.clear();
                self.snapshot.capture_processes.clear();
                self.snapshot.process_page = None;
                self.snapshot.guest_kernel = None;
                self.snapshot.guest_core_limits = None;
                self.snapshot.guest_tracer = None;
                self.snapshot.network_capture = None;
                self.snapshot.active_vm = Some(id.into());
                self.snapshot.state = VmState::Running;
                self.snapshot.boot_id = Some(session.boot_id.clone());
                self.snapshot.capture_dir = Some(session.capture.directory.clone());
                self.snapshot.serial_log = Some(session.process.runtime_dir.join("serial.log"));
                self.snapshot
                    .vm_screen
                    .clone_from(&session.process.screen_socket);
                self.snapshot
                    .stealth_fallbacks
                    .clone_from(&session.process.stealth_fallbacks);
                session.update_runs(&mut self.snapshot);
                session.update_captures(&mut self.snapshot);
                self.session = Some(session);
                self.stopping.store(false, Ordering::Relaxed);
                drop(debug_pause);
                self.debug_guest_moved("the snapshot was restored", true);
                Ok("Snapshot resumed in a new recording timeline".into())
            }
            Ok(None) => {
                self.snapshot.state = VmState::Stopped;
                // A rebooted guest has no debug sessions.
                self.end_debug();
                drop(debug_pause);
                self.start_restored_disk(id)?;
                Ok("Snapshot disk restored; guest booted in a new timeline".into())
            }
            Err(error) => {
                let cleanup = snapshots::cancel_restore(&self.options, &vm, &prepared);
                self.snapshot.active_vm = None;
                self.snapshot.state = VmState::Stopped;
                Err(format!(
                    "snapshot restore failed: {error}; disk branches retained; check snapshot recovery status before restarting; cleanup {:?}",
                    cleanup.err()
                ))
            }
        }
    }
}

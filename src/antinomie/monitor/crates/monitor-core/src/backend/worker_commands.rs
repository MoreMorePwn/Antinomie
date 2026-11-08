// SPDX-License-Identifier: GPL-3.0-only
//! Commands from the frontend that do not need a running guest.
use super::*;

impl Worker {
    pub(super) fn ensure_stopped(&self, id: &str) -> Result<(), String> {
        if self.snapshot.active_vm.as_deref() == Some(id) {
            Err("stop the VM before modifying its disk or configuration".into())
        } else {
            Ok(())
        }
    }
    pub(super) fn command_at_epoch(
        &mut self,
        epoch: u64,
        command: Command,
    ) -> Result<String, String> {
        if guest_scoped_command(&command) && epoch != self.guest_epoch.load(Ordering::Acquire) {
            return Err("command cancelled at snapshot/reconnect boundary; submit it explicitly in the current timeline".into());
        }
        self.command(command)
    }
    pub(super) fn begin_guest_transition(&self) -> Result<GuestTransition, String> {
        self.guest_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                value.checked_add(2).map(|_| value + 1)
            })
            .map_err(|_| "guest command epoch exhausted")?;
        Ok(GuestTransition(self.guest_epoch.clone()))
    }
    /// Run one command behind the disk-job lease: refused while a disk job
    /// reads the VM's chain, and a view of a chain the command changed is
    /// closed once it succeeded.
    pub(super) fn command(&mut self, command: Command) -> Result<String, String> {
        self.disk_lease_gate(&command)?;
        self.wait_snapshot_recordings(&command)?;
        let after = super::worker_disks::effect(&command)
            .is_some()
            .then(|| command.clone());
        let result = self.run_command(command);
        if result.is_ok()
            && let Some(command) = after
        {
            self.close_disk_view_after(&command);
        }
        result
    }
    fn run_command(&mut self, command: Command) -> Result<String, String> {
        if matches!(
            command,
            Command::Stop
                | Command::DumpMemory
                | Command::CreateVmSnapshot { .. }
                | Command::RestoreVmSnapshot { .. }
                | Command::ReconnectTransport
        ) && let Some(job) = self.keyboard.take()
        {
            let result = job.cancel_and_join();
            self.emit(Notification::CommandResult {
                id: 0,
                success: result.is_ok(),
                message: result.unwrap_or_else(|error| error),
            });
        }
        // QEMU keeps the guest paused while it writes a memory dump: a guest
        // command would only time out.
        if self.snapshot.memory_dump.is_some() && command.needs_running_guest() {
            return Err(
                "the VM is paused while its memory is written; try again in a moment".into(),
            );
        }
        match command {
            Command::TypeClipboard {
                vm_id,
                boot_id,
                text,
            } => self.type_clipboard(vm_id, boot_id, text),
            Command::RefreshVmSnapshots { vm_id } => {
                self.refresh_vm_snapshots(&vm_id)?;
                Ok("Snapshots refreshed".into())
            }
            Command::CreateVmSnapshot { vm_id, request } => {
                self.create_vm_snapshot(&vm_id, request)
            }
            Command::RestoreVmSnapshot {
                vm_id,
                snapshot_id,
                boot_from_disk,
                save_current,
                confirmed,
                switch_profile,
            } => self.restore_snapshot(
                vm_id,
                snapshot_id,
                boot_from_disk,
                save_current,
                confirmed,
                switch_profile,
            ),
            Command::RenameVmSnapshot {
                vm_id,
                snapshot_id,
                name,
            } => self.rename_snapshot(vm_id, snapshot_id, name),
            Command::DeleteVmSnapshot {
                vm_id,
                snapshot_id,
                confirmed,
            } => self.delete_snapshot(vm_id, snapshot_id, confirmed),
            Command::ReconnectTransport => self.reconnect_transport(),
            Command::CancelLaunchWait => {
                self.boot_wait_state.cancel = self.boot_wait_state.waiting;
                Ok("launch cancelled".into())
            }
            Command::Create(vm) => self.create(vm, None),
            Command::CreateWithCredentials { vm, credentials } => {
                self.create(vm, Some(credentials))
            }
            Command::ImportBase { directory } => self.import_base(directory),
            Command::RefreshRemoteBases => self.refresh_remote_bases(),
            Command::CancelRefresh => {
                let job = self
                    .refresh
                    .as_ref()
                    .ok_or("no catalog refresh is running")?;
                job.cancel.cancel();
                Ok("cancelling the catalog refresh".into())
            }
            Command::DownloadBase { identity } => self.download_base(identity),
            Command::CancelDownload => self.cancel_download(),
            Command::BuildBase { request } => self.build_base(request),
            Command::InstallTool { id } => self.install_tool(id),
            Command::CancelToolInstall => {
                let job = self
                    .tool
                    .as_ref()
                    .ok_or("no tool installation is running")?;
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling tool installation".into())
            }
            Command::RemoveTool { id } => self.remove_tool(id),
            Command::CancelBuild => {
                let job = self.build.as_ref().ok_or("no base build is running")?;
                job.cancel.store(true, Ordering::Relaxed);
                Ok("cancelling the base build".into())
            }
            Command::DeleteBase {
                identity,
                confirmed,
            } => self.delete_base(identity, confirmed),
            // Dispatched by the worker loop, which answers it when the
            // deletion thread is done (see `start_evidence_delete`).
            Command::DeleteEvidence { .. } => {
                Err("evidence deletion is handled by the worker loop".into())
            }
            Command::Save(vm) => self.save_vm(vm),
            Command::Rename { vm_id, name } => self.rename_vm(vm_id, name),
            Command::Duplicate { vm_id, name } => self.duplicate_vm(vm_id, name),
            Command::Delete { vm_id, confirmed } => self.delete_vm(vm_id, confirmed),
            Command::Reset { vm_id, confirmed } => self.reset_vm(vm_id, confirmed),
            Command::UpdateOptions {
                bundle_dir,
                capture_quota_size,
                shutdown_timeout_secs,
                start,
            } => self.update_options(bundle_dir, capture_quota_size, shutdown_timeout_secs, start),
            Command::OpenRecording { directory } => Err(format!(
                "open {} with the independent recording reader",
                directory.display()
            )),
            Command::Start { vm_id } => self.start(&vm_id),
            Command::StartNetworkCapture => self.start_network_capture(),
            Command::StopNetworkCapture => self.stop_network_capture(),
            Command::DumpMemory => self.start_memory_dump(),
            Command::MeasureDisk {
                vm_id,
                source,
                partition,
            } => self.measure_disk(&vm_id, &source, partition),
            Command::OpenCurrentDisk {
                vm_id,
                source,
                partition,
            } => self.open_current_disk(&vm_id, &source, partition),
            Command::CloseCurrentDisk { vm_id } => self.close_current_disk(&vm_id),
            Command::OpenDiskReference { vm_id, source } => {
                self.open_disk_reference(&vm_id, &source)
            }
            Command::CloseDiskReference { vm_id } => self.close_disk_reference_for(&vm_id),
            Command::DumpDisk {
                vm_id,
                source,
                partition,
                hash,
                layer_digests,
            } => self.dump_disk(&vm_id, &source, partition, hash, layer_digests),
            Command::SaveDiskPartition {
                vm_id,
                source,
                partition,
                path,
            } => self.save_disk_partition(&vm_id, &source, partition, &path),
            Command::ImportQcow2Disk { vm_id, path, hash } => {
                self.import_qcow2_disk(&vm_id, &path, hash)
            }
            Command::KeepCurrentDiskAsDump {
                vm_id,
                hash,
                layer_digests,
            } => self.keep_current_disk(&vm_id, hash, layer_digests),
            Command::CancelDiskJob { vm_id } => self.cancel_disk_job(&vm_id),
            Command::AnalyzeHostFile {
                vm_id,
                path,
                analysis,
            } => self.analyze_host_file(&vm_id, &path, analysis),
            Command::AnalyzeSample { sha256, selection } => self.analyze_sample(&sha256, selection),
            Command::AnalyzeMore {
                directory,
                run_id,
                checks,
                time_limit_seconds,
                limits,
            } => self.analyze_more(&directory, run_id, &checks, time_limit_seconds, limits),
            Command::CancelAnalysis { analysis_id }
                if self.host_analysis.cancel(&analysis_id).is_ok() =>
            {
                self.host_analysis_tick();
                Ok("analysis cancelled".into())
            }
            Command::Stop => {
                self.stop()?;
                Ok("VM stopped; recordings are being saved in the background".into())
            }
            Command::Close => {
                self.closing.store(true, Ordering::Relaxed);
                self.stop()?;
                Ok("backend closed".into())
            }
            other => self.guest_command(other),
        }
    }
    /// `bundle` with the base's UEFI disk as the VM's backing, laying the
    /// disk out first if the base has none yet; the stages show in the
    /// snapshot while it runs.
    pub(super) fn uefi_bundle(&mut self, mut bundle: Bundle) -> Result<Bundle, String> {
        let base = bundle
            .name
            .clone()
            .or_else(|| {
                bundle
                    .base_identity
                    .as_ref()
                    .map(|id| id.chars().take(12).collect())
            })
            .unwrap_or_default();
        let qemu_img = self.options.qemu_img.clone();
        let mut stage = |text: &str| {
            self.snapshot.base_layout = Some(crate::api::BaseLayoutProgress {
                base: base.clone(),
                stage: text.to_owned(),
            });
            self.publish();
        };
        let disk = crate::uefi_disk::derive(&qemu_img, &bundle, &mut stage);
        self.snapshot.base_layout = None;
        self.publish();
        bundle.uefi.uefi_disk = Some(disk?);
        Ok(bundle)
    }

    /// Show a VM being created or duplicated, at `step`, and publish it.
    pub(super) fn vm_step(&mut self, id: &str, name: &str, copy_of: Option<&str>, step: &str) {
        match self.snapshot.vm_work.iter_mut().find(|work| work.id == id) {
            Some(work) => work.step = step.to_owned(),
            None => self.snapshot.vm_work.push(VmWork {
                id: id.to_owned(),
                name: name.to_owned(),
                copy_of: copy_of.map(str::to_owned),
                step: step.to_owned(),
                started_ms: unix_ms(),
            }),
        }
        self.publish();
    }

    /// The work on `id` is over (the saved VM, or the error, is published with the command's result).
    pub(super) fn vm_work_end(&mut self, id: &str) {
        self.snapshot.vm_work.retain(|work| work.id != id);
    }

    pub(super) fn create(
        &mut self,
        mut vm: VmConfig,
        credentials: Option<GuestCredentials>,
    ) -> Result<String, String> {
        if vm.id.is_empty() {
            vm.id = storage::vm_id(&vm.name);
        }
        let id = vm.id.clone();
        let result = self.create_checked(vm, credentials);
        self.vm_work_end(&id);
        result
    }

    fn create_checked(
        &mut self,
        mut vm: VmConfig,
        credentials: Option<GuestCredentials>,
    ) -> Result<String, String> {
        if self.session.is_some() || self.snapshot.active_vm.is_some() {
            return Err("stop VM before creating another VM".into());
        }
        let id = vm.id.clone();
        let name = vm.name.clone();
        storage::validate_vm(&vm)?;
        vm.launch.validate_for(&self.options)?;
        if self.snapshot.vms.iter().any(|current| current.id == vm.id) {
            return Err("VM identity already exists".into());
        }
        let bundle = crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        storage::validate_boot_display(&vm, &bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &bundle)?;
        let requires_credentials = bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials);
        if requires_credentials != credentials.is_some() {
            return Err(if requires_credentials {
                "guest credentials are required"
            } else {
                "this base does not accept guest credentials"
            }
            .into());
        }
        vm.base_identity = bundle.base_identity.clone();
        // A UEFI profile on a base with a UEFI layout: the VM's disk is an
        // overlay of the base's UEFI disk (laid out now if this is the first).
        let bundle = if requires_credentials && crate::uefi_disk::wanted(&bundle, &vm.stealth) {
            self.vm_step(
                &id,
                &name,
                None,
                "Laying out the base's UEFI disk (once per base)",
            );
            self.uefi_bundle(bundle)?
        } else {
            bundle
        };
        let location = crate::locations::prepare(&self.options, &mut vm)?;
        let dir = &location.disk_directory;
        fs::create_dir(dir).map_err(|e| e.to_string())?;
        let build = |worker: &mut Worker, again: bool| -> Result<(), String> {
            worker.vm_step(&id, &name, None, "Creating the disk");
            storage::private_dir(dir).map_err(|e| e.to_string())?;
            storage::create_overlay(&worker.options, dir, vm.disk_gib, &bundle)?;
            if let Some(credentials) = credentials.clone() {
                worker.vm_step(
                    &id,
                    &name,
                    None,
                    if again {
                        "Setting up the guest account again (the host was busy)"
                    } else {
                        "Setting up the guest account (starts the guest once; slow without KVM)"
                    },
                );
                let account = crate::guest_account::GuestAccount::create(
                    credentials,
                    &dir.join("disk.qcow2"),
                    vm.ram_mib,
                    crate::guest_account::provisioned_interface(
                        &bundle.stealth_support,
                        &vm.stealth,
                        bundle.arch,
                    ),
                    crate::guest_account::boot_disk(&vm.stealth),
                    crate::guest_account::ProvisionBoot::for_bundle(&worker.options, &bundle)?
                        .as_ref(),
                )?;
                account.save(dir)?;
            }
            worker.vm_step(&id, &name, None, "Saving the configuration");
            storage::atomic_json(&dir.join("config.json"), &vm)?;
            storage::sync_directory_parent(dir)
        };
        let mut result = build(self, false);
        // A busy host can run the credential tool past its deadline: start
        // again from a fresh disk once before giving up.
        if matches!(&result, Err(error) if error.contains(crate::guest_account::TOOL_TIMEOUT)) {
            let _ = fs::remove_file(dir.join("disk.qcow2"));
            result = build(self, true);
        }
        if let Err(error) = result {
            let cleanup = fs::remove_dir_all(dir);
            let removed = match cleanup {
                Ok(()) => "the unfinished disk was removed".to_owned(),
                Err(e) => format!(
                    "the unfinished disk could not be removed ({e}); delete it from the VM folder"
                ),
            };
            let reason = if error.contains(crate::guest_account::TOOL_TIMEOUT) {
                "the host was too busy to prepare the guest account in time (tried twice); try again when it is less loaded".to_owned()
            } else {
                error
            };
            return Err(format!("VM creation failed: {reason}; {removed}"));
        }
        let publication = crate::locations::publish(&self.options, &location);
        if let Err(error) = &publication
            && !error.published
        {
            let cleanup = fs::remove_dir_all(dir);
            return Err(format!("{error}; creation rollback {:?}", cleanup.err()));
        }
        self.snapshot.vms.push(vm);
        self.refresh_locations()?;
        publication?;
        Ok("VM created".into())
    }
}

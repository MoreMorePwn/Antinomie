// SPDX-License-Identifier: GPL-3.0-only
//! Commands that change a stopped VM's saved configuration or the settings.
use super::*;

impl Worker {
    /// Validate and save a stopped VM's configuration.
    pub(super) fn save_vm(&mut self, mut vm: VmConfig) -> Result<String, String> {
        storage::validate_vm(&vm)?;
        vm.launch.validate_for(&self.options)?;
        self.ensure_stopped(&vm.id)?;
        let current = self
            .snapshot
            .vms
            .iter()
            .find(|v| v.id == vm.id)
            .ok_or("unknown VM")?;
        let boot_bundle =
            crate::locations::boot_bundle(&self.options, vm.base_identity.as_deref())?;
        storage::validate_boot_display(&vm, &boot_bundle)?;
        let location = crate::locations::future_recordings(&self.options, current, &mut vm)?;
        let dir = storage::vm_dir(&self.options, &vm.id)?;
        let disk_bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
        storage::validate_guest_transition(&disk_bundle, &boot_bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &disk_bundle)?;
        storage::validate_vm_bundle(&self.options, &vm, &boot_bundle)?;
        if vm.disk_gib < current.disk_gib {
            return Err("persistent VM disks cannot be shrunk".into());
        }
        if vm.disk_gib != current.disk_gib {
            if !crate::snapshots::list(&self.options, current)?
                .nodes
                .is_empty()
            {
                return Err("disk resizing is blocked while snapshots retain disk geometry".into());
            }
            crate::snapshots::run_layer::ensure_idle(&self.options, &current.id)?;
            let disk = crate::snapshots::active_disk(&self.options, current)?;
            let output = std::process::Command::new(&self.options.qemu_img)
                .arg("resize")
                .arg(&disk)
                .arg(format!("{}G", vm.disk_gib))
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err(format!(
                    "disk resize: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            // A provisioned (partitioned) root grows with its disk.
            if disk_bundle
                .guest
                .as_ref()
                .is_some_and(|guest| guest.requires_credentials)
            {
                crate::guest_account::grow_disk(&disk)?;
            }
        }
        // The disk was installed for the firmware its profile booted
        // when it was created (a UEFI disk on a base with a UEFI
        // layout); a profile that no longer matches it needs a new VM.
        if disk_bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials)
        {
            let installed = disk_bundle.uefi.uefi_disk.is_some();
            if crate::uefi_disk::wanted(&boot_bundle, &vm.stealth) != installed
                && crate::uefi_disk::wanted(&boot_bundle, &current.stealth) == installed
            {
                return Err(format!(
                    "this VM's disk was installed for {}; for a profile that boots {}, \
                     create a new VM",
                    crate::uefi_disk::installed_for(&disk_bundle),
                    if installed { "BIOS" } else { "UEFI" }
                ));
            }
        }
        // A base that names its NIC by slot: a new profile whose
        // machine has its LAN elsewhere moves the NIC, and the disk's
        // network configuration follows. (A disk provisioned before
        // keeps the interface its record names until then.)
        let moved =
            crate::guest_account::provisioned_interface(&boot_bundle.stealth_support, &vm.stealth)
                .filter(|interface| {
                    Some(*interface)
                        != crate::guest_account::provisioned_interface(
                            &boot_bundle.stealth_support,
                            &current.stealth,
                        )
                });
        if disk_bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials)
            && let Some(interface) = moved
        {
            let mut account = crate::guest_account::GuestAccount::load(&dir)?;
            if account.interface() != interface {
                if !crate::snapshots::list(&self.options, current)?
                    .nodes
                    .is_empty()
                {
                    return Err(format!(
                        "this profile moves the network card to {}, which its \
                         snapshots' disks do not configure; delete the snapshots \
                         or keep a machine with the same chipset",
                        crate::stealth::NicSlot::from_interface(interface)
                            .unwrap_or_default()
                            .label()
                    ));
                }
                let disk = crate::snapshots::active_disk(&self.options, current)?;
                account.set_interface(&disk, interface)?;
                account.save(&dir)?;
            }
        }
        // A new disk bus renames the disk in the guest: grub-pc's
        // debconf answer on a BIOS disk follows, as it does for the
        // active disk only (a snapshot's disk keeps its own answer,
        // which matters only to a grub-pc upgrade there).
        let boot_disk = crate::guest_account::boot_disk(&vm.stealth);
        if disk_bundle
            .guest
            .as_ref()
            .is_some_and(|guest| guest.requires_credentials)
            && disk_bundle.uefi.uefi_disk.is_none()
            && boot_disk != crate::guest_account::boot_disk(&current.stealth)
        {
            let mut account = crate::guest_account::GuestAccount::load(&dir)?;
            if account.boot_disk() != boot_disk {
                let disk = crate::snapshots::active_disk(&self.options, current)?;
                account.set_boot_disk(&disk, boot_disk)?;
                account.save(&dir)?;
            }
        }
        let previous = current.clone();
        let publication = storage::save_vm_config(&self.options, &dir, &previous, &vm, &location);
        if let Err(error) = &publication
            && !error.published
        {
            return Err(error.to_string());
        }
        let slot = self
            .snapshot
            .vms
            .iter_mut()
            .find(|v| v.id == vm.id)
            .ok_or("unknown VM")?;
        *slot = vm;
        self.refresh_locations()?;
        publication?;
        Ok("VM saved".into())
    }

    /// Rename a VM; its identity, disk and recordings stay.
    pub(super) fn rename_vm(&mut self, vm_id: String, name: String) -> Result<String, String> {
        let mut vm = self
            .snapshot
            .vms
            .iter()
            .find(|vm| vm.id == vm_id)
            .ok_or("unknown VM")?
            .clone();
        vm.name = name;
        storage::validate_vm(&vm)?;
        let dir = storage::vm_dir(&self.options, &vm_id)?;
        storage::atomic_json(&dir.join("config.json"), &vm)?;
        if let Some(slot) = self.snapshot.vms.iter_mut().find(|vm| vm.id == vm_id) {
            *slot = vm;
        }
        Ok("VM renamed; identity, disk and recordings retained".into())
    }

    /// Copy a stopped VM with an independent disk.
    pub(super) fn duplicate_vm(&mut self, vm_id: String, name: String) -> Result<String, String> {
        self.ensure_stopped(&vm_id)?;
        let source = self
            .snapshot
            .vms
            .iter()
            .find(|vm| vm.id == vm_id)
            .ok_or("unknown VM")?
            .clone();
        source.launch.validate_for(&self.options)?;
        if source.launch.resolution.dimensions().is_some() {
            let boot =
                crate::locations::boot_bundle(&self.options, source.base_identity.as_deref())?;
            storage::validate_boot_display(&source, &boot)?;
        }
        // A copy's identity is made when it is saved; until then it is its name.
        let id = format!("copy:{name}");
        self.vm_step(&id, &name, Some(&source.name), "Copying the disk");
        let result = storage::duplicate_vm(&self.options, &source, name);
        self.vm_work_end(&id);
        if result.is_err() {
            self.snapshot.vms = storage::load_vms(&self.options)?;
            self.refresh_locations()?;
        }
        let vm = result?;
        self.snapshot.vms.push(vm);
        self.refresh_locations()?;
        Ok("VM duplicated with an independent disk; no history copied".into())
    }

    /// Delete a stopped VM's disk and configuration.
    pub(super) fn delete_vm(&mut self, vm_id: String, confirmed: bool) -> Result<String, String> {
        if !confirmed {
            return Err("disk deletion requires explicit confirmation".into());
        }
        self.ensure_stopped(&vm_id)?;
        if !self.snapshot.vms.iter().any(|v| v.id == vm_id) {
            return Err("unknown VM".into());
        }
        let result = storage::delete_vm(&self.options, &vm_id);
        if result.is_err() {
            self.snapshot.vms = storage::load_vms(&self.options)?;
            self.refresh_locations()?;
            result?;
        }
        self.snapshot.vms.retain(|v| v.id != vm_id);
        self.refresh_locations()?;
        Ok("VM disk and configuration deleted; recordings retained".into())
    }

    /// Reset a stopped VM's disk to its base.
    pub(super) fn reset_vm(&mut self, vm_id: String, confirmed: bool) -> Result<String, String> {
        if !confirmed {
            return Err("disk reset requires explicit confirmation".into());
        }
        self.ensure_stopped(&vm_id)?;
        let vm = self
            .snapshot
            .vms
            .iter()
            .find(|v| v.id == vm_id)
            .ok_or("unknown VM")?;
        let dir = storage::vm_dir(&self.options, &vm_id)?;
        let mut bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
        let vm = vm.clone();
        // A UEFI disk that is gone is laid out again.
        if bundle.uefi.uefi_disk.is_some() {
            bundle.uefi.uefi_disk = None;
            bundle = self.uefi_bundle(bundle)?;
        }
        storage::reset_vm_disk(&self.options, &dir, &vm, &bundle)?;
        Ok("VM reset to base".into())
    }

    /// Change the settings of a stopped backend.
    pub(super) fn update_options(
        &mut self,
        bundle_dir: PathBuf,
        capture_quota_size: u64,
        shutdown_timeout_secs: u64,
        start: StartSettings,
    ) -> Result<String, String> {
        if self.session.is_some() {
            return Err("stop VM before changing settings".into());
        }
        if capture_quota_size < 1024 || !(1..=120).contains(&shutdown_timeout_secs) {
            return Err(
                "capture quota must be at least 1024 and shutdown timeout 1..120 seconds".into(),
            );
        }
        start.validate()?;
        self.options.bundle_dir = bundle_dir;
        self.options.capture_quota_size = capture_quota_size;
        self.options.shutdown_timeout = Duration::from_secs(shutdown_timeout_secs);
        self.options.start = start;
        Ok("settings updated".into())
    }

    /// Restore a snapshot once the user confirmed it.
    pub(super) fn restore_snapshot(
        &mut self,
        vm_id: String,
        snapshot_id: String,
        boot_from_disk: bool,
        save_current: Option<SnapshotRequest>,
        confirmed: bool,
        switch_profile: bool,
    ) -> Result<String, String> {
        if !confirmed {
            return Err("restore requires confirmation".into());
        }
        self.restore_vm_snapshot(
            &vm_id,
            &snapshot_id,
            boot_from_disk,
            save_current,
            switch_profile,
        )
    }

    /// Rename a snapshot.
    pub(super) fn rename_snapshot(
        &mut self,
        vm_id: String,
        snapshot_id: String,
        name: String,
    ) -> Result<String, String> {
        let vm = self.snapshot_vm(&vm_id)?;
        crate::snapshots::rename(&self.options, &vm, &snapshot_id, &name)?;
        self.refresh_vm_snapshots(&vm_id)?;
        Ok("Snapshot renamed".into())
    }

    /// Hide a snapshot of a stopped VM once the user confirmed it.
    pub(super) fn delete_snapshot(
        &mut self,
        vm_id: String,
        snapshot_id: String,
        confirmed: bool,
    ) -> Result<String, String> {
        if !confirmed {
            return Err("snapshot deletion requires confirmation".into());
        }
        self.ensure_stopped(&vm_id)?;
        let vm = self.snapshot_vm(&vm_id)?;
        crate::snapshots::logical_delete(&self.options, &vm, &snapshot_id)?;
        self.refresh_vm_snapshots(&vm_id)?;
        Ok("Snapshot hidden; dependent disk layers retained".into())
    }
}

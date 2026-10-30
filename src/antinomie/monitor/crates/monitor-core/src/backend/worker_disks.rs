// SPDX-License-Identifier: GPL-3.0-only
//! The Disks tab's commands and the disk-job lease.
//!
//! While a disk job reads a VM's image chain, no command may change that
//! chain, and the VM may not start (QEMU's own image lock is the backstop).
//! An open view is independent of the chain, so it only has to be closed when
//! the chain changes or its VM starts. The decisions are in [`lease`], a
//! pure function the tests drive through every command.
use super::*;
use crate::disks::{
    self, DiskSourceKind, DiskSourceRecord, DiskSourceSpec,
    job::{DumpPlan, ImportSpec, Job, JobResult, JobSpec},
};
use std::path::Path;

/// What a command does to the VM's disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DiskEffect {
    /// Reads the chain (`qemu-img` on it): allowed beside a view, refused
    /// beside a job.
    Reads,
    /// Starts QEMU on the chain.
    Starts,
    /// Changes the chain or its identity.
    Changes,
}

/// The VM whose disk `command` touches, and how.
pub(super) fn effect(command: &Command) -> Option<(&str, DiskEffect)> {
    Some(match command {
        Command::Start { vm_id } => (vm_id, DiskEffect::Starts),
        Command::Reset { vm_id, .. }
        | Command::RestoreVmSnapshot { vm_id, .. }
        | Command::CreateVmSnapshot { vm_id, .. }
        | Command::Delete { vm_id, .. } => (vm_id, DiskEffect::Changes),
        Command::Duplicate { vm_id, .. } => (vm_id, DiskEffect::Reads),
        _ => return None,
    })
}

pub(super) const LEASE_MESSAGE: &str = "the VM's disk is being read for the Disks tab (inspection or dump); wait for it to finish or cancel it before ";
const BUSY_MESSAGE: &str =
    "another disk inspection or dump is still running; wait for it or cancel it";
const RUNNING_MESSAGE: &str = "stop the VM before inspecting or dumping its disk";

/// Refuse `command` while `job_vm`'s image is held by a disk job.
pub(super) fn lease(job_vm: Option<&str>, command: &Command) -> Result<(), String> {
    let Some(job_vm) = job_vm else {
        return Ok(());
    };
    match command {
        Command::MeasureDisk { .. }
        | Command::OpenCurrentDisk { .. }
        | Command::OpenDiskReference { .. }
        | Command::DumpDisk { .. }
        | Command::SaveDiskPartition { .. }
        | Command::ImportQcow2Disk { .. }
        | Command::KeepCurrentDiskAsDump { .. } => {
            return Err(BUSY_MESSAGE.into());
        }
        _ => {}
    }
    match effect(command) {
        Some((vm, DiskEffect::Starts)) if vm == job_vm => {
            Err(format!("{LEASE_MESSAGE}starting the VM"))
        }
        Some((vm, DiskEffect::Changes | DiskEffect::Reads)) if vm == job_vm => {
            Err(format!("{LEASE_MESSAGE}changing or copying its disk"))
        }
        _ => Ok(()),
    }
}

impl Worker {
    /// The gate in front of every command.
    pub(super) fn disk_lease_gate(&self, command: &Command) -> Result<(), String> {
        // An import reads no chain: only the one-job rule applies to it.
        let job_vm = self
            .disk_job
            .as_ref()
            .filter(|job| job.holds_chain)
            .map(|job| job.vm_id.as_str());
        lease(job_vm, command)?;
        // A resize reads and rewrites the chain's header.
        if let (Some(job_vm), Command::Save(vm)) = (job_vm, command)
            && vm.id == job_vm
            && self
                .snapshot
                .vms
                .iter()
                .any(|current| current.id == vm.id && current.disk_gib != vm.disk_gib)
        {
            return Err(format!("{LEASE_MESSAGE}resizing its disk"));
        }
        Ok(())
    }

    /// Close the view of `vm_id` after a command changed its chain, or the
    /// VM started. Says why in the Activity log.
    pub(super) fn close_disk_view_after(&mut self, command: &Command) {
        let Some((vm, effect)) = effect(command) else {
            return;
        };
        if effect == DiskEffect::Reads {
            return;
        }
        let why = if effect == DiskEffect::Starts {
            "VM started"
        } else {
            "the VM's disk changed"
        };
        if self
            .snapshot
            .current_disk
            .as_ref()
            .is_some_and(|view| view.vm_id == vm)
        {
            self.close_disk_view();
            self.emit(Notification::CommandResult {
                id: 0,
                success: true,
                message: format!("Current disk view closed: {why}"),
            });
        }
        if self
            .snapshot
            .disk_reference
            .as_ref()
            .is_some_and(|view| view.vm_id == vm)
        {
            self.close_disk_reference();
        }
        if self
            .snapshot
            .disk_measure
            .as_ref()
            .is_some_and(|measure| measure.vm_id == vm)
        {
            self.snapshot.disk_measure = None;
        }
    }

    /// Delete the open view's scratch image, and the reference image beside
    /// it (a diff needs both).
    pub(super) fn close_disk_view(&mut self) {
        if let Some(view) = self.snapshot.current_disk.take() {
            disks::remove_scratch(&view);
        }
        self.close_disk_reference();
    }

    pub(super) fn close_disk_reference(&mut self) {
        if let Some(view) = self.snapshot.disk_reference.take() {
            disks::remove_scratch(&view);
        }
    }

    /// Remove every scratch folder and unfinished dump left by an earlier run
    /// of the app.
    pub(super) fn sweep_disk_scratch(&mut self) {
        let roots: Vec<_> = self
            .snapshot
            .vm_locations
            .iter()
            .flat_map(|location| location.recording_directories.iter().cloned())
            .collect();
        for root in roots {
            let disks = disks::disks_dir(&root);
            disks::sweep_scratch(&disks, None);
            disks::dump::sweep_partial(&disks);
        }
    }

    /// Leave nothing behind when the backend closes.
    pub(super) fn shutdown_disks(&mut self) {
        self.disk_job = None;
        self.snapshot.disk_job = None;
        self.close_disk_view();
    }

    fn disk_preconditions(&self, vm_id: &str) -> Result<(VmConfig, PathBuf), String> {
        if self.snapshot.active_vm.as_deref() == Some(vm_id) {
            return Err(RUNNING_MESSAGE.into());
        }
        if self.disk_job.is_some() {
            return Err(BUSY_MESSAGE.into());
        }
        let vm = self.snapshot_vm(vm_id)?;
        crate::dependencies::require_tool(&self.options.qemu_img, "qemu-utils")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "util-linux")?;
        let dir = storage::vm_dir(&self.options, vm_id)?;
        Ok((vm, dir))
    }

    /// The chain top of `source`, its identity and the folder views go to;
    /// the same checks `start()` runs on the disk. Safe because the VM is
    /// off.
    fn disk_job_spec(
        &self,
        vm: &VmConfig,
        dir: &Path,
        source: &DiskSourceSpec,
        partition: Option<u32>,
    ) -> Result<JobSpec, String> {
        crate::snapshots::recover_pending(&self.options, vm)?;
        let bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
        crate::snapshots::validate_active(&self.options, vm, bundle.vm_disk())?;
        let relative = |path: &Path| {
            path.strip_prefix(dir)
                .unwrap_or(path)
                .to_string_lossy()
                .into_owned()
        };
        let (top, record) = match source {
            DiskSourceSpec::Current => {
                let top = crate::snapshots::active_disk(&self.options, vm)?;
                let record = DiskSourceRecord {
                    kind: DiskSourceKind::Current,
                    active_layer: relative(&top),
                    active_parent_id: crate::snapshots::list(&self.options, vm)?.active_parent_id,
                    ..DiskSourceRecord::default()
                };
                (top, record)
            }
            DiskSourceSpec::Checkpoint(id) => {
                let checkpoint = crate::snapshots::checkpoint_disk(&self.options, vm, id)?;
                // The layer's whole chain must be the VM's own, down to the
                // pinned base.
                crate::snapshots::validate_disk(
                    &self.options,
                    vm,
                    &checkpoint.path,
                    bundle.vm_disk(),
                )?;
                let record = DiskSourceRecord {
                    kind: DiskSourceKind::Checkpoint {
                        id: checkpoint.id,
                        name: checkpoint.name,
                    },
                    active_layer: relative(&checkpoint.path),
                    active_parent_id: checkpoint.parent_id,
                    ..DiskSourceRecord::default()
                };
                (checkpoint.path, record)
            }
            DiskSourceSpec::Base => {
                let base = fs::canonicalize(bundle.vm_disk())
                    .map_err(|error| format!("{}: {error}", bundle.vm_disk().display()))?;
                if !fs::metadata(&base).is_ok_and(|metadata| metadata.is_file()) {
                    return Err("the VM's installed base image is missing".into());
                }
                let record = DiskSourceRecord {
                    kind: DiskSourceKind::Base,
                    active_layer: relative(&base),
                    ..DiskSourceRecord::default()
                };
                (base, record)
            }
        };
        let recordings = crate::locations::locations(&self.options, &vm.id)?.recording_directory;
        Ok(JobSpec {
            qemu_img: self.options.qemu_img.clone(),
            vm_id: vm.id.clone(),
            vm_dir: dir.to_path_buf(),
            top,
            source: record,
            disks_dir: disks::disks_dir(&recordings),
            quota: self.options.capture_quota_size,
            partition,
            keep_scratch: None,
        })
    }

    /// What a dump records about the VM and its guest.
    fn dump_plan(
        &self,
        vm: &VmConfig,
        dir: &Path,
        hash: bool,
        layer_digests: bool,
    ) -> Result<DumpPlan, String> {
        let bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
        let system = match &bundle.name {
            Some(name) => format!("Linux {} · {name}", bundle.kernel_version),
            None => format!("Linux {}", bundle.kernel_version),
        };
        Ok(DumpPlan {
            vm_name: vm.name.clone(),
            system,
            hash,
            layer_digests,
        })
    }

    fn start_disk_job(&mut self, job: Job) {
        self.snapshot.disk_job = Some(job.progress());
        self.disk_job = Some(job);
        self.publish();
    }

    pub(super) fn measure_disk(
        &mut self,
        vm_id: &str,
        source: &DiskSourceSpec,
        partition: Option<u32>,
    ) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let spec = self.disk_job_spec(&vm, &dir, source, partition)?;
        self.snapshot.disk_measure = None;
        self.start_disk_job(Job::measure(spec)?);
        Ok("measuring the VM's disk".into())
    }

    pub(super) fn open_current_disk(
        &mut self,
        vm_id: &str,
        source: &DiskSourceSpec,
        partition: Option<u32>,
    ) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let spec = self.disk_job_spec(&vm, &dir, source, partition)?;
        // Opening again replaces the open view (and its reference image).
        self.close_disk_view();
        self.start_disk_job(Job::view(spec)?);
        Ok("reading the VM's disk".into())
    }

    /// A second scratch image, beside the open view, to diff against.
    pub(super) fn open_disk_reference(
        &mut self,
        vm_id: &str,
        source: &DiskSourceSpec,
    ) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let mut spec = self.disk_job_spec(&vm, &dir, source, None)?;
        spec.keep_scratch = self
            .snapshot
            .current_disk
            .as_ref()
            .and_then(|view| view.image.parent().map(Path::to_path_buf));
        self.close_disk_reference();
        self.start_disk_job(Job::reference(spec)?);
        Ok("reading the reference disk".into())
    }

    pub(super) fn save_disk_partition(
        &mut self,
        vm_id: &str,
        source: &DiskSourceSpec,
        partition: u32,
        path: &Path,
    ) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        if !path.is_absolute() {
            return Err("the destination must be an absolute path".into());
        }
        let spec = self.disk_job_spec(&vm, &dir, source, Some(partition))?;
        self.start_disk_job(Job::carve(spec, path.to_path_buf())?);
        Ok("saving the partition".into())
    }

    /// Convert an imported qcow2 in the sandbox. It reads no VM chain, so the
    /// VM may run; only one disk job at a time.
    pub(super) fn import_qcow2_disk(
        &mut self,
        vm_id: &str,
        path: &Path,
        hash: bool,
    ) -> Result<String, String> {
        if self.disk_job.is_some() {
            return Err(BUSY_MESSAGE.into());
        }
        let vm = self.snapshot_vm(vm_id)?;
        crate::dependencies::require_tool(&self.options.qemu_img, "qemu-utils")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/bwrap"), "bubblewrap")?;
        crate::dependencies::require_tool(Path::new("/usr/bin/prlimit"), "util-linux")?;
        let recordings = crate::locations::locations(&self.options, vm_id)?.recording_directory;
        let spec = ImportSpec {
            qemu_img: self.options.qemu_img.clone(),
            vm_id: vm.id.clone(),
            vm_name: vm.name.clone(),
            source: path.to_path_buf(),
            disks_dir: disks::disks_dir(&recordings),
            hash,
        };
        self.start_disk_job(Job::import_qcow2(spec)?);
        Ok("converting the qcow2 image in the sandbox".into())
    }

    pub(super) fn dump_disk(
        &mut self,
        vm_id: &str,
        source: &DiskSourceSpec,
        partition: Option<u32>,
        hash: bool,
        layer_digests: bool,
    ) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let spec = self.disk_job_spec(&vm, &dir, source, partition)?;
        let plan = self.dump_plan(&vm, &dir, hash, layer_digests)?;
        self.start_disk_job(Job::dump(spec, plan)?);
        Ok("dumping the VM's disk".into())
    }

    pub(super) fn keep_current_disk(
        &mut self,
        vm_id: &str,
        hash: bool,
        layer_digests: bool,
    ) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let view = self
            .snapshot
            .current_disk
            .clone()
            .filter(|view| view.vm_id == vm_id)
            .ok_or("no disk view is open for this VM")?;
        // The job only names the chain; Keep reads the scratch image.
        let spec = self.disk_job_spec(&vm, &dir, &DiskSourceSpec::Current, None)?;
        let plan = self.dump_plan(&vm, &dir, hash, layer_digests)?;
        self.start_disk_job(Job::keep(spec, plan, view)?);
        Ok("keeping the open disk view as a dump".into())
    }

    pub(super) fn close_current_disk(&mut self, vm_id: &str) -> Result<String, String> {
        if self
            .snapshot
            .current_disk
            .as_ref()
            .is_none_or(|view| view.vm_id != vm_id)
        {
            return Err("no disk view is open for this VM".into());
        }
        self.close_disk_view();
        Ok("Current disk view closed".into())
    }

    pub(super) fn close_disk_reference_for(&mut self, vm_id: &str) -> Result<String, String> {
        if self
            .snapshot
            .disk_reference
            .as_ref()
            .is_none_or(|view| view.vm_id != vm_id)
        {
            return Err("no reference disk is open for this VM".into());
        }
        self.close_disk_reference();
        Ok("Reference disk closed".into())
    }

    pub(super) fn cancel_disk_job(&mut self, vm_id: &str) -> Result<String, String> {
        match &self.disk_job {
            Some(job) if job.vm_id == vm_id => {
                job.cancel();
                Ok("cancelling the disk read".into())
            }
            _ => Err("no disk job is running for this VM".into()),
        }
    }

    /// Follow the running job and take its result.
    pub(super) fn poll_disk_job(&mut self) {
        let Some(job) = self.disk_job.as_mut() else {
            return;
        };
        let progress = job.progress();
        let result = job.finish();
        if self.snapshot.disk_job.as_ref() != Some(&progress) {
            self.snapshot.disk_job = Some(progress);
            self.publish();
        }
        let Some(result) = result else {
            return;
        };
        self.disk_job = None;
        self.snapshot.disk_job = None;
        let (success, message) = match result {
            Ok(JobResult::Measured(measure)) => {
                self.snapshot.disk_measure = Some(measure);
                (true, "disk measured".to_string())
            }
            Ok(JobResult::Reference(view)) => {
                let message = format!("{} read for comparison", view.source.kind.label());
                self.snapshot.disk_reference = Some(view);
                (true, message)
            }
            Ok(JobResult::Carved(path, size)) => (
                true,
                format!(
                    "Partition saved to {} ({})",
                    path.display(),
                    disks::format_size(size)
                ),
            ),
            Ok(JobResult::Opened(view)) => {
                let message = format!(
                    "{} of {} opened ({})",
                    view.source.kind.label(),
                    view.vm_id,
                    view.fs_state.label()
                );
                self.snapshot.current_disk = Some(view);
                (true, message)
            }
            Ok(JobResult::Dumped(dump)) => (
                true,
                format!(
                    "Disk dump of {} saved ({}, {})",
                    dump.vm_name,
                    dump.fs_state.label(),
                    disks::format_size(dump.allocated_size.unwrap_or(0))
                ),
            ),
            Ok(JobResult::Kept(dump, view)) => {
                self.snapshot.current_disk = Some(*view);
                (
                    true,
                    format!("Current disk of {} kept as a dump", dump.vm_name),
                )
            }
            Err(error) if error == "cancelled" => (true, "disk job cancelled".to_string()),
            Err(error) => {
                self.snapshot.last_error = Some(error.clone());
                (false, error)
            }
        };
        self.emit(Notification::CommandResult {
            id: 0,
            success,
            message,
        });
        self.publish();
    }

    /// Queue static analysis of a host file (extracted from a disk view).
    pub(super) fn analyze_host_file(
        &mut self,
        vm_id: &str,
        path: &Path,
        analysis: crate::analysis::AnalysisSelection,
    ) -> Result<String, String> {
        analysis.validate()?;
        if !analysis.enabled {
            return Err("static analysis is not selected".into());
        }
        if self.snapshot.analysis_reports.len() >= 8 {
            return Err("the eight standalone analysis limit is reached".into());
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !metadata.file_type().is_file() {
            return Err(format!("{} is not a regular file", path.display()));
        }
        let name = path.to_string_lossy().into_owned();
        crate::control::string(&name, true)?;
        let report = crate::analysis::jobs::new_report(&name, &analysis);
        let directory = crate::locations::locations(&self.options, vm_id)?
            .recording_directory
            .join("analyses")
            .join(&report.id);
        let report = self.host_analysis.submit_host_file(
            report,
            directory,
            path,
            self.options.capture_quota_size,
        );
        self.host_analysis_updates();
        if report.state == crate::analysis::AnalysisState::Unavailable {
            return Err(report
                .reason
                .unwrap_or_else(|| "analysis unavailable".into()));
        }
        Ok("static analysis of the extracted file queued".into())
    }

    /// Queue checks that a finished analysis in `directory` does not have. The
    /// analysis is not repeated; the new sections join its report.
    pub(super) fn analyze_more(
        &mut self,
        directory: &Path,
        run_id: Option<String>,
        checks: &[crate::analysis::AnalysisKind],
        time_limit_seconds: Option<u64>,
    ) -> Result<String, String> {
        if directory
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
            || !directory.is_absolute()
        {
            return Err("the analysis folder is not a plain absolute path".into());
        }
        self.host_analysis.analyze_more(
            run_id,
            directory,
            checks,
            time_limit_seconds,
            self.options.capture_quota_size,
        )?;
        self.host_analysis_updates();
        Ok("added checks queued".into())
    }

    /// Advance host-file analysis jobs and publish their reports.
    pub(super) fn host_analysis_tick(&mut self) {
        // Host jobs never ask for guest reads; a release of the unused handle
        // is the only action they can return.
        for _ in 0..8 {
            if self.host_analysis.next().is_none() {
                break;
            }
        }
        self.host_analysis_updates();
    }

    fn host_analysis_updates(&mut self) {
        for (run_id, report) in self.host_analysis.updates() {
            // Checks added to a run's analysis: the run holds the report.
            if let Some(id) = &run_id {
                if let Some(session) = self.session.as_mut() {
                    session.run_analysis(id, &report);
                    session.update_runs(&mut self.snapshot);
                }
                let _ = self
                    .sender
                    .try_send(Notification::AnalysisUpdated { run_id, report });
                self.publish();
                continue;
            }
            if let Some(existing) = self
                .snapshot
                .analysis_reports
                .iter_mut()
                .find(|existing| existing.id == report.id)
            {
                *existing = report.clone();
            } else {
                if self.snapshot.analysis_reports.len() == 8 {
                    self.snapshot.analysis_reports.remove(0);
                }
                self.snapshot.analysis_reports.push(report.clone());
            }
            let _ = self
                .sender
                .try_send(Notification::AnalysisUpdated { run_id, report });
            self.publish();
        }
    }
}

#[cfg(test)]
mod tests;

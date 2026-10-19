// SPDX-License-Identifier: MIT
//! The Disks tab's commands and the disk-job lease.
//!
//! While a disk job reads a VM's image chain, no command may change that
//! chain, and the VM may not start (QEMU's own image lock is the backstop).
//! An open view is independent of the chain, so it only has to be closed when
//! the chain changes or its VM starts. The decisions are in [`lease`], a
//! pure function the tests drive through every command.
use super::*;
use crate::disks::{
    self, DiskSourceRecord,
    job::{Job, JobResult, JobSpec},
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
        Command::MeasureDisk { .. } | Command::OpenCurrentDisk { .. } => {
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
        let job_vm = self.disk_job.as_ref().map(|job| job.vm_id.as_str());
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
            .disk_measure
            .as_ref()
            .is_some_and(|measure| measure.vm_id == vm)
        {
            self.snapshot.disk_measure = None;
        }
    }

    /// Delete the open view's scratch image.
    pub(super) fn close_disk_view(&mut self) {
        if let Some(view) = self.snapshot.current_disk.take() {
            disks::remove_scratch(&view);
        }
    }

    /// Remove every scratch folder left by an earlier run of the app.
    pub(super) fn sweep_disk_scratch(&mut self) {
        let roots: Vec<_> = self
            .snapshot
            .vm_locations
            .iter()
            .flat_map(|location| location.recording_directories.iter().cloned())
            .collect();
        for root in roots {
            disks::sweep_scratch(&disks::disks_dir(&root), None);
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

    /// The chain top, its identity and the folder views go to; the same
    /// checks `start()` runs on the disk. Safe because the VM is off.
    fn disk_job_spec(&self, vm: &VmConfig, dir: &Path) -> Result<JobSpec, String> {
        crate::snapshots::recover_pending(&self.options, vm)?;
        let bundle: Bundle = storage::read_json(&dir.join("bundle.json"))?;
        crate::snapshots::validate_active(&self.options, vm, &bundle.base_disk)?;
        let top = crate::snapshots::active_disk(&self.options, vm)?;
        let source = DiskSourceRecord {
            active_layer: top
                .strip_prefix(dir)
                .unwrap_or(&top)
                .to_string_lossy()
                .into_owned(),
            active_parent_id: crate::snapshots::list(&self.options, vm)?.active_parent_id,
            ..DiskSourceRecord::default()
        };
        let recordings = crate::locations::locations(&self.options, &vm.id)?.recording_directory;
        Ok(JobSpec {
            qemu_img: self.options.qemu_img.clone(),
            vm_id: vm.id.clone(),
            vm_dir: dir.to_path_buf(),
            top,
            source,
            disks_dir: disks::disks_dir(&recordings),
        })
    }

    fn start_disk_job(&mut self, job: Job) {
        self.snapshot.disk_job = Some(job.progress());
        self.disk_job = Some(job);
        self.publish();
    }

    pub(super) fn measure_disk(&mut self, vm_id: &str) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let spec = self.disk_job_spec(&vm, &dir)?;
        self.snapshot.disk_measure = None;
        self.start_disk_job(Job::measure(spec)?);
        Ok("measuring the VM's disk".into())
    }

    pub(super) fn open_current_disk(&mut self, vm_id: &str) -> Result<String, String> {
        let (vm, dir) = self.disk_preconditions(vm_id)?;
        let spec = self.disk_job_spec(&vm, &dir)?;
        // Opening again replaces the open view.
        self.close_disk_view();
        self.start_disk_job(Job::view(spec)?);
        Ok("reading the VM's disk".into())
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
            Ok(JobResult::Opened(view)) => {
                let message = format!(
                    "Current disk of {} opened ({})",
                    view.vm_id,
                    view.fs_state.label()
                );
                self.snapshot.current_disk = Some(view);
                (true, message)
            }
            Err(error) if error == "cancelled" => (true, "disk read cancelled".to_string()),
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

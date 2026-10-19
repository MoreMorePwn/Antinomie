// SPDX-License-Identifier: MIT
//! The Disks tab's host: what it shows from the backend's snapshot and what
//! its actions send.
use super::*;
use crate::disk_view::{DiskAction, DiskContext};

impl MonitorApp {
    pub(super) fn disks_panel(&mut self, ui: &mut egui::Ui) {
        let vm_id = self.selected.clone();
        let vm = self
            .snapshot
            .vms
            .iter()
            .find(|config| Some(&config.id) == vm_id.as_ref())
            .cloned();
        let vm_off = vm_id.is_some() && self.snapshot.active_vm != vm_id;
        let ours = |id: &str| Some(id) == vm_id.as_deref();
        let current_disk = self
            .snapshot
            .current_disk
            .clone()
            .filter(|view| ours(&view.vm_id));
        let measure = self
            .snapshot
            .disk_measure
            .clone()
            .filter(|measure| ours(&measure.vm_id));
        let job = self
            .snapshot
            .disk_job
            .clone()
            .filter(|job| ours(&job.vm_id));
        let other_job = self
            .snapshot
            .disk_job
            .as_ref()
            .is_some_and(|job| !ours(&job.vm_id));
        let can_stop_vm = self.can_stop_vm() && !self.closing;
        let locations = self
            .snapshot
            .vm_locations
            .iter()
            .find(|location| Some(&location.vm_id) == vm_id.as_ref());
        let recordings = locations.map(|location| location.recording_directory.clone());
        let recording_roots = locations
            .map(|location| location.recording_directories.clone())
            .unwrap_or_default();
        let action = self.disk_view.show(
            ui,
            DiskContext {
                vm: vm.as_ref(),
                recordings: recordings.as_deref(),
                recording_roots: &recording_roots,
                qemu_img: &self.options.qemu_img,
                vm_off,
                can_stop_vm,
                current_disk: current_disk.as_ref(),
                measure: measure.as_ref(),
                job: job.as_ref(),
                other_job,
                font_size: self.settings.font_size,
                settings: &mut self.settings.disks,
            },
        );
        self.disk_action(ui.ctx(), action);
    }

    pub(super) fn disk_action(&mut self, ctx: &egui::Context, action: Option<DiskAction>) {
        let Some(action) = action else {
            return;
        };
        let vm_id = self.selected.clone();
        match (action, vm_id) {
            (DiskAction::StopVm, _) => self.send(Command::Stop),
            (DiskAction::Measure, Some(vm_id)) => self.send(Command::MeasureDisk { vm_id }),
            (DiskAction::Open, Some(vm_id)) => self.send(Command::OpenCurrentDisk { vm_id }),
            (DiskAction::Close, Some(vm_id)) => self.send(Command::CloseCurrentDisk { vm_id }),
            (DiskAction::Cancel, Some(vm_id)) => self.send(Command::CancelDiskJob { vm_id }),
            (DiskAction::Dump, Some(vm_id)) => self.send(Command::DumpDisk {
                vm_id,
                hash: self.settings.disks.dump_hash,
                layer_digests: self.settings.disks.source_digests,
            }),
            (DiskAction::Keep, Some(vm_id)) => self.send(Command::KeepCurrentDiskAsDump {
                vm_id,
                hash: self.settings.disks.dump_hash,
                layer_digests: self.settings.disks.source_digests,
            }),
            (DiskAction::Delete(dump), _) => {
                let name = crate::disk_view::dump_name(&dump);
                self.ask_delete_evidence(crate::evidence_delete::Deletion::disk(
                    &dump.dir,
                    &name,
                    dump.imported,
                ));
            }
            (DiskAction::ViewBytes { key, title, bytes }, _) => {
                self.data_windows.open_bytes(ctx, key, title, bytes);
            }
            (DiskAction::OpenWith(path), _) => crate::folders::open_file_detached(path),
            (DiskAction::Analyze(path), Some(vm_id)) => {
                // The launch form's selection when it enables analysis, else
                // the default triage set.
                let mut analysis = self.exec.analysis.clone();
                analysis.enabled = true;
                if analysis.checks.is_empty() {
                    analysis.checks = antinomie_monitor_core::AnalysisKind::TRIAGE.to_vec();
                }
                self.send(Command::AnalyzeHostFile {
                    vm_id,
                    path,
                    analysis,
                });
                self.focus_panel = Some(Panel::StaticAnalysis);
            }
            _ => {}
        }
    }
}

// SPDX-License-Identifier: MIT
//! The list of entries on the left: "Current disk (VM off)", the buttons to
//! dump the disk or import an image, and the saved dumps (see [`super::dumps`]).
use super::*;
use crate::{network_view::capture_row, theme};
use antinomie_monitor_core::disks::{DiskJobPurpose, DiskJobStage};

impl DiskView {
    pub(super) fn entries(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>) {
        ui.horizontal(|ui| {
            theme::section(ui, "Disks");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can_measure = cx.vm.is_some()
                    && cx.vm_off
                    && cx.current_disk.is_none()
                    && cx.job.is_none()
                    && !cx.other_job
                    && self.waiting.is_none();
                if ui
                    .add(egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false))
                    .on_hover_text("Read the list of dumps again and measure the current disk")
                    .clicked()
                {
                    // The list is read again on the next frame.
                    self.dumps_for = None;
                    if can_measure {
                        self.measured_for = None;
                        self.wait_for(true);
                        self.action = Some(DiskAction::Measure(self.pick.clone()));
                    }
                }
            });
        });
        let Some(vm) = cx.vm else {
            ui.add_space(6.0);
            ui.colored_label(theme::muted(), "Select a VM to inspect its disk.");
            return;
        };
        let (title, detail, color) = self.current_row(cx, vm);
        if capture_row(
            ui,
            self.entry == Entry::Current,
            (&title, color),
            &detail,
            cx.font_size,
        )
        .clicked()
        {
            self.entry = Entry::Current;
        }
        ui.add_space(4.0);
        self.dump_button(ui, cx, true);
        if ui
            .add_enabled(
                cx.recordings.is_some(),
                egui::Button::new(format!(
                    "{} Import image…",
                    egui_phosphor::regular::FILE_ARROW_UP
                ))
                .min_size(egui::vec2(ui.available_width(), 0.0)),
            )
            .on_hover_text(
                "Browse a raw ext4 image made elsewhere (the file stays where it is), or \
                 convert a qcow2 image in the sandbox into a dump",
            )
            .on_disabled_hover_text("Select a VM: imported images are kept with its recordings")
            .clicked()
        {
            self.open_import();
        }
        ui.add_space(4.0);
        ui.separator();
        self.dump_list(ui, cx);
    }

    /// Title, detail and color of the Current disk row.
    fn current_row(&self, cx: &DiskContext<'_>, vm: &VmConfig) -> (String, String, egui::Color32) {
        let title = self.source_title(&self.pick.source);
        let _ = vm;
        if !cx.vm_off {
            return (
                title,
                "VM running — stop it to inspect".into(),
                theme::muted(),
            );
        }
        let detail = if let Some(job) = cx.job {
            match (&job.stage, job.purpose) {
                (DiskJobStage::Measuring, _) => "measuring…".to_string(),
                (DiskJobStage::Converting { percent }, DiskJobPurpose::Dump) => {
                    format!("dumping… {percent:.0} %")
                }
                (DiskJobStage::Converting { percent }, DiskJobPurpose::Reference) => {
                    format!("reading the reference… {percent:.0} %")
                }
                (DiskJobStage::Converting { percent }, DiskJobPurpose::Carve) => {
                    format!("saving the partition… {percent:.0} %")
                }
                (DiskJobStage::Converting { percent }, DiskJobPurpose::Import) => {
                    format!("converting… {percent:.0} %")
                }
                (DiskJobStage::Converting { percent }, _) => format!("reading… {percent:.0} %"),
                (DiskJobStage::Hashing { done, total }, _) => {
                    format!(
                        "hashing… {:.0} %",
                        *done as f32 / (*total).max(1) as f32 * 100.0
                    )
                }
                (DiskJobStage::Finalizing, _) => "finishing…".to_string(),
            }
        } else if let Some(view) = cx.current_disk {
            format!(
                "open · {} · {}",
                view.fs_state.label(),
                clock(view.taken_ms / 1000)
            )
        } else if let Some(measure) = self
            .current_measure(cx)
            .filter(|measure| measure.error.is_none())
        {
            if measure.unsupported().is_some() {
                "unsupported filesystem".to_string()
            } else {
                format!("not opened · ≈ {}", format_size(measure.allocated_estimate))
            }
        } else {
            "not opened".into()
        };
        (title, detail, theme::heading())
    }
}

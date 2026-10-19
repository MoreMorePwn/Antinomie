// SPDX-License-Identifier: MIT
//! The list of entries on the left: "Current disk (VM off)" now; saved dumps
//! and imported images join it in phase 2.
use super::*;
use crate::{network_view::capture_row, theme};
use antinomie_monitor_core::disks::DiskJobStage;

impl DiskView {
    pub(super) fn entries(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>) {
        ui.horizontal(|ui| {
            theme::section(ui, "Disks");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let can = cx.vm.is_some()
                    && cx.vm_off
                    && cx.current_disk.is_none()
                    && cx.job.is_none()
                    && !cx.other_job
                    && self.waiting.is_none();
                if ui
                    .add_enabled(
                        can,
                        egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false),
                    )
                    .on_hover_text("Measure the current disk again")
                    .on_disabled_hover_text(
                        "Measuring needs the VM off, no open view and no running disk job",
                    )
                    .clicked()
                {
                    self.measured_for = None;
                    self.waiting = Some(Instant::now());
                    self.action = Some(DiskAction::Measure);
                }
            });
        });
        let Some(vm) = cx.vm else {
            ui.add_space(6.0);
            ui.colored_label(theme::muted(), "Select a VM to inspect its disk.");
            return;
        };
        let (title, detail, color) = self.current_row(cx, vm);
        // The one entry; it stays selected.
        capture_row(ui, true, (&title, color), &detail, cx.font_size);
        ui.add_space(6.0);
        ui.separator();
        ui.colored_label(
            theme::muted(),
            "Saved disk dumps and imported images are not available yet.",
        );
    }

    /// Title, detail and color of the Current disk row.
    fn current_row(&self, cx: &DiskContext<'_>, vm: &VmConfig) -> (String, String, egui::Color32) {
        let title = "Current disk (VM off)".to_string();
        let _ = vm;
        if !cx.vm_off {
            return (
                title,
                "VM running — stop it to inspect".into(),
                theme::muted(),
            );
        }
        let detail = if let Some(job) = cx.job {
            match &job.stage {
                DiskJobStage::Measuring => "measuring…".to_string(),
                DiskJobStage::Converting { percent } => format!("reading… {percent:.0} %"),
                DiskJobStage::Finalizing => "finishing…".to_string(),
            }
        } else if let Some(view) = cx.current_disk {
            format!(
                "open · {} · {}",
                view.fs_state.label(),
                clock(view.taken_ms / 1000)
            )
        } else if let Some(measure) = cx.measure.filter(|measure| measure.error.is_none()) {
            format!("not opened · ≈ {}", format_size(measure.allocated_estimate))
        } else {
            "not opened".into()
        };
        (title, detail, theme::heading())
    }
}

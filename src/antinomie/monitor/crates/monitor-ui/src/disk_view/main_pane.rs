// SPDX-License-Identifier: MIT
//! The main pane: one of the states of the Current disk entry (no VM, VM
//! running, measured, job running, open).
use super::*;
use crate::theme;
use antinomie_monitor_core::disks::DiskJobStage;

impl DiskView {
    pub(super) fn main_pane(&mut self, ui: &mut egui::Ui, cx: &mut DiskContext<'_>) {
        let Some(vm) = cx.vm else {
            hint(ui, "Select a VM to inspect its disk.");
            return;
        };
        if !cx.vm_off {
            self.running_notice(ui, cx);
            return;
        }
        if let Some(job) = cx.job {
            self.job_card(ui, job);
            return;
        }
        if cx.current_disk.is_some() {
            self.open_view_pane(ui, cx);
            return;
        }
        self.measure_card(ui, cx, vm);
    }

    /// The VM runs: inspection needs it off. The shortcut is the toolbar's
    /// Stop, with its label, tooltip and (absent) confirmation.
    fn running_notice(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>) {
        ui.add_space(24.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(560.0);
            ui.label(
                egui::RichText::new(egui_phosphor::regular::HARD_DRIVES)
                    .size(28.0)
                    .color(theme::muted()),
            );
            ui.add(
                egui::Label::new(
                    egui::RichText::new(
                        "Disk inspection and new dumps need the VM to be off. Saved dumps stay \
                         available in the list.",
                    )
                    .strong()
                    .color(theme::heading()),
                )
                .wrap(),
            );
            ui.add_space(10.0);
            if ui
                .add_enabled(
                    cx.can_stop_vm,
                    egui::Button::new(format!("{} Stop VM", egui_phosphor::regular::STOP)),
                )
                .on_hover_text("Shut down the running VM")
                .on_disabled_hover_text("No VM is running")
                .clicked()
            {
                self.action = Some(DiskAction::StopVm);
            }
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(
                        "Stopping ends the running analysis session: open runs and captures \
                         are sealed.",
                    )
                    .color(theme::muted()),
                )
                .wrap(),
            );
            ui.add_space(6.0);
            ui.add(
                egui::Label::new(
                    egui::RichText::new(
                        "The current disk is read directly from the VM's image; it cannot be \
                         read while QEMU writes it.",
                    )
                    .color(theme::muted()),
                )
                .wrap(),
            );
            if let Some(notice) = &self.notice {
                ui.add_space(8.0);
                crate::activity::warning(ui, notice);
            }
        });
    }

    fn job_card(&mut self, ui: &mut egui::Ui, job: &DiskJobProgress) {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            theme::spinner(ui);
            ui.label(
                egui::RichText::new(match &job.stage {
                    DiskJobStage::Measuring => "Measuring the current disk…".to_string(),
                    DiskJobStage::Converting { percent } => {
                        format!("Reading the current disk… {percent:.0} %")
                    }
                    DiskJobStage::Finalizing => "Checking the image…".to_string(),
                })
                .strong()
                .color(theme::heading()),
            );
        });
        if let DiskJobStage::Converting { percent } = &job.stage {
            ui.add(
                egui::ProgressBar::new((percent / 100.0).clamp(0.0, 1.0))
                    .desired_width(360.0)
                    .show_percentage(),
            );
        }
        if job.estimate > 0 {
            ui.colored_label(
                theme::muted(),
                format!(
                    "About {} to write into {}",
                    format_size(job.estimate),
                    "the scratch image"
                ),
            );
        }
        if ui.button("Cancel").clicked() {
            self.action = Some(DiskAction::Cancel);
        }
        ui.add_space(4.0);
        ui.colored_label(
            theme::muted(),
            "The VM's disk is held while it is read; starting the VM waits for this to finish \
             or be cancelled.",
        );
    }

    fn measure_card(&mut self, ui: &mut egui::Ui, cx: &DiskContext<'_>, vm: &VmConfig) {
        ui.add_space(8.0);
        ui.label(
            egui::RichText::new(format!("Current disk of {} (VM off)", vm.name))
                .strong()
                .color(theme::heading()),
        );
        if let Some(notice) = &self.notice {
            crate::activity::warning(ui, notice);
        }
        let mut can_open = false;
        match cx.measure {
            None => {
                ui.horizontal(|ui| {
                    theme::spinner(ui);
                    ui.colored_label(theme::muted(), "Measuring the disk…");
                });
            }
            Some(measure) => {
                if let Some(error) = &measure.error {
                    crate::activity::error(ui, error);
                } else {
                    can_open = true;
                }
                if measure.logical_size > 0 {
                    ui.label(format!(
                        "{} logical · ≈ {} allocated",
                        format_size(measure.logical_size),
                        format_size(measure.allocated_estimate)
                    ));
                    if !measure.source.active_layer.is_empty() {
                        ui.colored_label(
                            theme::muted(),
                            format!("source {}", measure.source.active_layer),
                        );
                    }
                    ui.colored_label(
                        theme::muted(),
                        format!(
                            "{} free in {}",
                            format_size(measure.free_space),
                            measure.directory.display()
                        ),
                    );
                    if !measure.sparse_supported {
                        crate::activity::warning(
                            ui,
                            "That folder's filesystem cannot hold sparse files: the image takes \
                             the disk's full size.",
                        );
                    }
                }
            }
        }
        ui.add_space(6.0);
        let why = if self.waiting.is_some() {
            Some("A request is on its way")
        } else if cx.other_job {
            Some("Another disk job is running")
        } else if !can_open {
            Some("The disk could not be measured")
        } else {
            None
        };
        ui.horizontal(|ui| {
            if ui
                .add_enabled(why.is_none(), egui::Button::new("Open"))
                .on_hover_text("Copy the allocated data into a temporary image and browse it")
                .on_disabled_hover_text(why.unwrap_or(""))
                .clicked()
            {
                self.waiting = Some(Instant::now());
                self.action = Some(DiskAction::Open);
            }
        });
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                egui::RichText::new(
                    "Opening copies the allocated data into a temporary image; nothing is \
                     written to the VM's disk. The image is deleted when you close the view or \
                     start the VM.",
                )
                .color(theme::muted()),
            )
            .wrap(),
        );
    }

    fn open_view_pane(&mut self, ui: &mut egui::Ui, cx: &mut DiskContext<'_>) {
        let Some(view) = self.bound.clone() else {
            ui.horizontal(|ui| {
                theme::spinner(ui);
                ui.colored_label(theme::muted(), "Opening the view…");
            });
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "Current disk (VM off) · read {} · {} · {}",
                    clock(view.taken_ms / 1000),
                    view.fs_state.label(),
                    view.source.active_layer
                ))
                .strong()
                .color(theme::heading()),
            );
        });
        ui.horizontal_wrapped(|ui| {
            if ui.button("Close").clicked() {
                self.action = Some(DiskAction::Close);
            }
            ui.checkbox(&mut cx.settings.hide_dotfiles, "Hide dotfiles");
            ui.checkbox(&mut cx.settings.numeric_modes, "Numeric modes");
        });
        if view.fs_state == antinomie_monitor_core::disks::Ext4State::NotClean {
            crate::activity::warning(ui, view.fs_state.explanation());
        }
        if let Some(Err(error)) = &self.probe {
            crate::activity::error(ui, error);
        }
        if let Some((message, failed)) = &self.status {
            if *failed {
                crate::activity::error(ui, message);
            } else {
                ui.colored_label(theme::good(), message);
            }
        }
        self.find_bar(ui);
        ui.add_space(2.0);
        let height = ui.available_height().max(60.0);
        let selected = self
            .selection
            .as_ref()
            .map(|selection| selection.path.clone());
        let events = self.tree.show(
            ui,
            &tree::Options {
                selected: selected.as_deref(),
                numeric_modes: cx.settings.numeric_modes,
                height,
            },
        );
        for event in events {
            self.tree_event(ui, event);
        }
    }

    fn tree_event(&mut self, ui: &egui::Ui, event: tree::Event) {
        match event {
            tree::Event::Select(path) => self.select(path),
            tree::Event::Menu(path, entry, choice) => self.menu(ui, path, entry, choice),
        }
    }
}

fn hint(ui: &mut egui::Ui, text: &str) {
    ui.add_space(12.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(520.0);
        ui.add(egui::Label::new(egui::RichText::new(text).color(theme::muted())).wrap());
    });
}

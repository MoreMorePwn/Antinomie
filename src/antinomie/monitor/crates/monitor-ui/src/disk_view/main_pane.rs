// SPDX-License-Identifier: MIT
//! The main pane: one of the states of the Current disk entry (no VM, VM
//! running, measured, job running, open), or the browser of a saved dump.
use super::*;
use crate::theme;
use antinomie_monitor_core::disks::{DiskJobPurpose, DiskJobStage};

impl DiskView {
    pub(super) fn main_pane(&mut self, ui: &mut egui::Ui, cx: &mut DiskContext<'_>) {
        let Some(vm) = cx.vm else {
            hint(ui, "Select a VM to inspect its disk.");
            return;
        };
        // Work that is not the entry's own: a qcow2 conversion or a partition
        // save shows its progress above whatever is selected.
        if let Some(job) = cx
            .job
            .filter(|job| matches!(job.purpose, DiskJobPurpose::Import | DiskJobPurpose::Carve))
        {
            self.job_strip(ui, job);
        }
        if let Entry::Dump(_) = self.entry {
            self.dump_pane(ui, cx);
            return;
        }
        if !cx.vm_off {
            self.running_notice(ui, cx);
            return;
        }
        if let Some(job) = cx.job {
            // Keeping the open view leaves its tree visible beneath the bar.
            if matches!(
                job.purpose,
                DiskJobPurpose::Keep | DiskJobPurpose::Reference
            ) && self.bound.is_some()
            {
                self.job_strip(ui, job);
                self.open_view_pane(ui, cx);
            } else {
                self.job_card(ui, job);
            }
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

    /// What a job is doing, as a sentence.
    fn job_text(job: &DiskJobProgress) -> String {
        let what = match job.purpose {
            DiskJobPurpose::Measure => "Measuring the disk",
            DiskJobPurpose::View => "Reading the disk",
            DiskJobPurpose::Dump => "Dumping the disk",
            DiskJobPurpose::Keep => "Keeping the open view as a dump",
            DiskJobPurpose::Reference => "Reading the reference disk",
            DiskJobPurpose::Carve => "Saving the partition",
            DiskJobPurpose::Import => "Converting the qcow2 image in the sandbox",
        };
        match &job.stage {
            DiskJobStage::Measuring => match job.purpose {
                DiskJobPurpose::Import => "Inspecting the qcow2 image in the sandbox…".to_string(),
                _ => "Measuring the disk…".to_string(),
            },
            DiskJobStage::Converting { percent } => format!("{what}… {percent:.0} %"),
            DiskJobStage::Hashing { done, total } => format!(
                "Computing the SHA-256… {:.0} %",
                *done as f32 / (*total).max(1) as f32 * 100.0
            ),
            DiskJobStage::Finalizing => "Checking the image…".to_string(),
        }
    }

    /// The fraction a job has done, when it knows.
    fn job_fraction(job: &DiskJobProgress) -> Option<f32> {
        match &job.stage {
            DiskJobStage::Converting { percent } => Some(percent / 100.0),
            DiskJobStage::Hashing { done, total } => Some(*done as f32 / (*total).max(1) as f32),
            _ => None,
        }
    }

    /// A compact progress line with Cancel, above a pane that stays usable.
    pub(super) fn job_strip(&mut self, ui: &mut egui::Ui, job: &DiskJobProgress) {
        ui.horizontal(|ui| {
            theme::spinner(ui);
            ui.label(egui::RichText::new(Self::job_text(job)).color(theme::heading()));
            if let Some(fraction) = Self::job_fraction(job) {
                ui.add(
                    egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                        .desired_width(160.0)
                        .show_percentage(),
                );
            }
            if ui.button("Cancel").clicked() {
                self.action = Some(DiskAction::Cancel);
            }
        });
    }

    fn job_card(&mut self, ui: &mut egui::Ui, job: &DiskJobProgress) {
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            theme::spinner(ui);
            ui.label(
                egui::RichText::new(Self::job_text(job))
                    .strong()
                    .color(theme::heading()),
            );
        });
        if let Some(fraction) = Self::job_fraction(job) {
            ui.add(
                egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
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
                    match job.purpose {
                        DiskJobPurpose::Dump => "the new dump",
                        _ => "the scratch image",
                    }
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
        let busy = self.waiting.is_some() || cx.job.is_some() || cx.other_job;
        ui.label(
            egui::RichText::new(format!(
                "{} of {} (VM off)",
                self.source_name(&self.pick.source),
                vm.name
            ))
            .strong()
            .color(theme::heading()),
        );
        self.source_picker(ui, !busy);
        if let Some(notice) = &self.notice {
            crate::activity::warning(ui, notice);
        }
        let measure = self.current_measure(cx);
        let mut can_open = false;
        match measure {
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
                    can_open = measure.unsupported().is_none();
                }
                if measure.logical_size > 0 {
                    ui.label(format!(
                        "{} logical · ≈ {} allocated{}",
                        format_size(measure.logical_size),
                        format_size(measure.allocated_estimate),
                        measure
                            .selected()
                            .map(|partition| format!(" · partition {}", partition.index))
                            .unwrap_or_default()
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
                self.partition_list(ui, measure, busy);
            }
        }
        ui.add_space(6.0);
        let why = if self.waiting.is_some() {
            Some("A request is on its way")
        } else if cx.other_job || cx.job.is_some() {
            Some("Another disk job is running")
        } else if !can_open {
            Some("This disk cannot be opened: see the message above")
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
                self.wait_for(true);
                self.action = Some(DiskAction::Open(self.pick.clone()));
            }
            self.dump_button(ui, cx, false);
        });
        if let Some(quota) = measure.and_then(|measure| measure.quota_error()) {
            crate::activity::warning(ui, quota);
        }
        ui.add_space(4.0);
        ui.add(
            egui::Label::new(
                egui::RichText::new(
                    "Opening copies the allocated data into a temporary image; nothing is \
                     written to the VM's disk. The image is deleted when you close the view or \
                     start the VM, unless you keep it as a dump. Dump disk writes the image \
                     straight into the VM's recordings. A checkpoint is read exactly like the \
                     current disk, and also only while the VM is off.",
                )
                .color(theme::muted()),
            )
            .wrap(),
        );
    }

    fn open_view_pane(&mut self, ui: &mut egui::Ui, cx: &mut DiskContext<'_>) {
        let Some(view) = self.bound.as_ref().and_then(|bound| match &bound.what {
            What::Current(view) => Some((**view).clone()),
            What::Dump => None,
        }) else {
            ui.horizontal(|ui| {
                theme::spinner(ui);
                ui.colored_label(theme::muted(), "Opening the view…");
            });
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "{} (VM off) · read {} · {} · {}{}",
                    view.source.kind.label(),
                    clock(view.taken_ms / 1000),
                    view.fs_state.label(),
                    view.source.active_layer,
                    view.source
                        .partition
                        .as_ref()
                        .map(|partition| format!(" · partition {}", partition.index))
                        .unwrap_or_default()
                ))
                .strong()
                .color(theme::heading()),
            );
        });
        let keep_blocked = self.keep_blocked(cx);
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(keep_blocked.is_none(), egui::Button::new("Keep as dump"))
                .on_hover_text("Promote this image to a saved dump: a rename, no second conversion")
                .on_disabled_hover_text(keep_blocked.clone().unwrap_or_default())
                .clicked()
            {
                self.wait_for(false);
                self.action = Some(DiskAction::Keep);
            }
            if ui.button("Close").clicked() {
                self.action = Some(DiskAction::Close);
            }
            ui.checkbox(&mut cx.settings.hide_dotfiles, "Hide dotfiles");
            ui.checkbox(&mut cx.settings.numeric_modes, "Numeric modes");
        });
        if view.kept_as.is_some() {
            ui.colored_label(
                theme::good(),
                "Kept as a dump: this view now reads the dump's image, which stays when the \
                 view is closed.",
            );
        }
        self.browser_body(ui, cx, view.fs_state);
    }

    /// The pane of a saved dump: its header, then the same browser.
    fn dump_pane(&mut self, ui: &mut egui::Ui, cx: &mut DiskContext<'_>) {
        let Some(row) = self.selected_dump() else {
            hint(ui, "Select an entry.");
            return;
        };
        let (dump, missing, browsable) = (row.dump.clone(), row.missing, row.browsable());
        if let Some(job) = cx.job.filter(|job| job.purpose != DiskJobPurpose::Measure) {
            self.job_strip(ui, job);
        }
        let title = crate::evidence::title(ui, &dump.dir, &dumps::dump_title(&dump));
        ui.horizontal_wrapped(|ui| {
            ui.label(
                egui::RichText::new(format!(
                    "Dump · {title} · {} · {}",
                    dump.fs_state.label(),
                    dump.file
                        .file_name()
                        .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
                ))
                .strong()
                .color(theme::heading()),
            );
        });
        if let Some(error) = &dump.error {
            crate::activity::error(ui, format!("This dump failed: {error}"));
            return;
        }
        if dump.finished_ms.is_none() {
            crate::activity::warning(ui, "This dump was never completed.");
            return;
        }
        if missing {
            crate::activity::warning(
                ui,
                format!(
                    "The imported image is no longer at {}. Delete this entry, or put the file back and refresh the list.",
                    dump.path().display()
                ),
            );
            return;
        }
        if !browsable {
            crate::activity::warning(
                ui,
                "This dump was made by a newer version and its format cannot be opened here.",
            );
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut cx.settings.hide_dotfiles, "Hide dotfiles");
            ui.checkbox(&mut cx.settings.numeric_modes, "Numeric modes");
        });
        if self.bound.is_none() {
            ui.horizontal(|ui| {
                theme::spinner(ui);
                ui.colored_label(theme::muted(), "Opening the dump…");
            });
            return;
        }
        self.browser_body(ui, cx, dump.fs_state);
    }

    /// Warnings, the Find bar and the tree, shared by the view and the dumps.
    fn browser_body(
        &mut self,
        ui: &mut egui::Ui,
        cx: &mut DiskContext<'_>,
        fs_state: antinomie_monitor_core::disks::Ext4State,
    ) {
        if fs_state == antinomie_monitor_core::disks::Ext4State::NotClean {
            crate::activity::warning(ui, fs_state.explanation());
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
        if self.diff.is_some() {
            self.diff_pane(ui, cx);
            return;
        }
        ui.horizontal_wrapped(|ui| self.compare_menu(ui, cx));
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

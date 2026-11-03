// SPDX-License-Identifier: GPL-3.0-only
//! The rows of the core list: one function per kind of core.
use super::list::{
    acquired_filter_row, core_file_menu, core_project_menu, imported_filter_row, manual_filter_row,
};
use super::*;
use crate::evidence_delete::{Deletion, Kind as DeleteKind};

/// What a click or a menu in the list asks for, gathered over the rows.
#[derive(Default)]
pub(super) struct ListOutcome {
    pub(super) acquired_selection: Option<(PathBuf, Option<PathBuf>)>,
    pub(super) imported_selection: Option<CoreRecord>,
    pub(super) file_action: Option<(bool, PathBuf)>,
    pub(super) project_action: Option<PathBuf>,
    pub(super) delete: Option<Deletion>,
    pub(super) action: Option<CoreAction>,
}

/// What every row of the list reads besides its core.
#[derive(Clone, Copy)]
pub(super) struct RowContext<'a> {
    pub(super) filter_id: egui::Id,
    pub(super) font_size: f32,
    pub(super) can_cancel: bool,
    pub(super) boot_id: Option<&'a str>,
    pub(super) note_vm: Option<&'a str>,
}

/// Which cores of each kind the filter keeps.
pub(super) struct Shown {
    pub(super) filter_id: egui::Id,
    pub(super) manual: Vec<bool>,
    pub(super) acquired: Vec<bool>,
    pub(super) imported: Vec<bool>,
}

impl CoreView {
    /// The title row, the capture and import buttons and the cancel buttons.
    pub(super) fn list_actions(
        &mut self,
        ui: &mut egui::Ui,
        unavailable: Option<&str>,
        can_cancel: bool,
        boot_id: Option<&str>,
    ) -> Option<CoreAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            crate::theme::section(ui, "Core dumps");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(
                        self.job.is_none(),
                        egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false),
                    )
                    .on_hover_text("Refresh the list")
                    .clicked()
                {
                    self.invalidate_catalog();
                    self.start_catalog();
                    ui.ctx().request_repaint_after(Duration::from_millis(200));
                }
            });
        });
        if ui.add_enabled(unavailable.is_none(), egui::Button::new(format!("{} Dump core", egui_phosphor::regular::FILE))
            .min_size(egui::vec2(ui.available_width(), 0.0)))
            .on_hover_text("Pause a selected process, capture its resident memory and thread context, then resume")
            .on_disabled_hover_text(unavailable.unwrap_or_default())
            .clicked() {
            action = Some(CoreAction::Dump);
        }
        if let Some(reason) = unavailable {
            ui.add(
                egui::Label::new(RichText::new(reason).small().color(crate::theme::muted())).wrap(),
            );
        }
        if let Some(cancel) = self.cancel_buttons(ui, can_cancel, boot_id) {
            action = Some(cancel);
        }
        if ui
            .add_enabled(
                !self.roots.is_empty() && self.job.is_none(),
                egui::Button::new(format!(
                    "{} Import core…",
                    egui_phosphor::regular::FILE_ARROW_UP
                ))
                .min_size(egui::vec2(ui.available_width(), 0.0)),
            )
            .on_hover_text(
                "Reference a Linux x86-64 process core made elsewhere. The file stays where it is.",
            )
            .on_disabled_hover_text(
                "Select a VM with a recording folder; wait for any current operation to finish.",
            )
            .clicked()
        {
            self.import_open = true;
            self.status.clear();
        }
        action
    }

    /// The filter bar, the count, and which cores of each kind the filter keeps.
    pub(super) fn shown_cores(&mut self, ui: &mut egui::Ui) -> Shown {
        let mut fields = crate::query::LABEL_FIELDS.to_vec();
        fields.extend(crate::query::CAPTURE_FIELDS);
        fields.extend([
            crate::query::FieldSpec::text("name", "Displayed core name"),
            crate::query::FieldSpec::text("state", "Capture or imported core state"),
            crate::query::FieldSpec::number("pid", "Captured process ID, when retained"),
            crate::query::FieldSpec::number("threads", "Inspected core thread count"),
            crate::query::FieldSpec::number("mappings", "Inspected core mapping count"),
            crate::query::FieldSpec::number("size", "Stored core size in octets, when retained"),
            crate::query::FieldSpec::number("core.thread_count", "Inspected core thread count"),
            crate::query::FieldSpec::boolean(
                "core.partial",
                "Explicit partial acquisition; missing when undetermined",
            ),
            crate::query::FieldSpec::number(
                "core.signal",
                "Signal recorded in an inspected core thread note",
            ),
        ]);
        let tags: Vec<_> = self
            .manual
            .iter()
            .map(|core| &core.directory)
            .chain(self.acquired.iter().map(|core| &core.directory))
            .chain(self.records.iter().map(|record| &record.dir))
            .filter_map(|directory| crate::evidence::annotation(ui, directory))
            .flat_map(|annotation| annotation.tags)
            .collect();
        let filter = crate::query::table_filter(
            ui,
            "core-history",
            "entry.name contains crash",
            &fields,
            &tags,
        );
        let filter_id = ui.id().with(("table-filter", "core-history"));
        let manual_shown: Vec<_> = self
            .manual
            .iter()
            .map(|core| filter.keep_table(&manual_filter_row(ui, core)))
            .collect();
        let acquired_shown: Vec<_> = self
            .acquired
            .iter()
            .map(|core| filter.keep_table(&acquired_filter_row(ui, core)))
            .collect();
        let imported_shown: Vec<_> = self
            .records
            .iter()
            .map(|record| filter.keep_table(&imported_filter_row(ui, record)))
            .collect();
        let matched = manual_shown
            .iter()
            .chain(&acquired_shown)
            .chain(&imported_shown)
            .filter(|shown| **shown)
            .count();
        ui.weak(format!(
            "{matched} / {} cores",
            self.manual.len() + self.acquired.len() + self.records.len()
        ));
        if let Some(directory) = self.selected_directory.as_ref() {
            let visible = self
                .manual
                .iter()
                .zip(&manual_shown)
                .any(|(core, shown)| *shown && &core.directory == directory)
                || self
                    .acquired
                    .iter()
                    .zip(&acquired_shown)
                    .any(|(core, shown)| *shown && &core.directory == directory)
                || self
                    .records
                    .iter()
                    .zip(&imported_shown)
                    .any(|(record, shown)| *shown && &record.dir == directory);
            let known = self.manual.iter().any(|core| &core.directory == directory)
                || self
                    .acquired
                    .iter()
                    .any(|core| &core.directory == directory)
                || self.records.iter().any(|record| &record.dir == directory);
            if known && !visible {
                self.selected = None;
                self.selected_directory = None;
                self.page = None;
            }
        }
        Shown {
            filter_id,
            manual: manual_shown,
            acquired: acquired_shown,
            imported: imported_shown,
        }
    }

    /// The rows of the cores captured by hand.
    pub(super) fn manual_rows(
        &self,
        ui: &mut egui::Ui,
        manual_shown: &[bool],
        context: &RowContext<'_>,
        outcome: &mut ListOutcome,
    ) {
        let RowContext {
            filter_id,
            font_size,
            can_cancel,
            boot_id,
            ..
        } = *context;
        let ListOutcome {
            acquired_selection,
            file_action,
            project_action,
            delete,
            action,
            ..
        } = outcome;
        for (index, core) in self.manual.iter().enumerate() {
            if !manual_shown[index] {
                continue;
            }
            let fallback = format!("PID {} · {}", core.target.tgid, core.id);
            let title = crate::evidence::title(ui, &core.directory, &fallback);
            let selected = self.selected_directory.as_ref() == Some(&core.directory);
            let state = manual_status(core);
            let color = if core.issue.is_some() {
                crate::theme::error()
            } else {
                crate::theme::text()
            };
            let row =
                crate::network_view::capture_row(ui, selected, (&title, color), &state, font_size)
                    .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
            let core_file = core.file.clone();
            row.context_menu(|ui| {
                crate::evidence::menu(ui, &core.directory);
                crate::query::table_row_menu_with(
                    ui,
                    filter_id,
                    &manual_filter_row(ui, core),
                    crate::query::RowMenuExtras {
                        note: Some((
                            None,
                            antinomie_monitor_core::samples::NoteRef::new(
                                antinomie_monitor_core::samples::RefKind::ProcessCore,
                                antinomie_monitor_core::samples::core_target(&core.vm_id, &core.id),
                                format!("Core PID {} · {}", core.target.tgid, core.id),
                            ),
                        )),
                        ..Default::default()
                    },
                );
                core_file_menu(ui, core_file.as_deref(), file_action);
                core_project_menu(ui, &core.directory, self.job.is_none(), project_action);
                if core.phase != ProcessCorePhase::Finished
                    && can_cancel
                    && ui.button("Cancel capture and resume").clicked()
                {
                    *action = Some(CoreAction::Cancel(core.id.clone()));
                    ui.close();
                }
                let capturing = (core.phase != ProcessCorePhase::Finished
                    && Some(core.boot_id.as_str()) == boot_id)
                    .then_some(crate::evidence_delete::CORE_CAPTURING);
                if crate::evidence_delete::menu_item(ui, capturing) {
                    *delete = Some(Deletion::core(&core.directory, &title, DeleteKind::Core));
                }
            });
            if row.clicked() && self.job.is_none() {
                *acquired_selection = Some((core.directory.clone(), core.file.clone()));
            }
        }
    }

    /// The rows of the cores runs took.
    pub(super) fn acquired_rows(
        &self,
        ui: &mut egui::Ui,
        acquired_shown: &[bool],
        context: &RowContext<'_>,
        outcome: &mut ListOutcome,
    ) {
        let RowContext {
            filter_id,
            font_size,
            boot_id,
            ..
        } = *context;
        let ListOutcome {
            acquired_selection,
            file_action,
            project_action,
            delete,
            ..
        } = outcome;
        for (index, core) in self.acquired.iter().enumerate() {
            if !acquired_shown[index] {
                continue;
            }
            let fallback = format!("Run {}", core.run_id);
            let title = crate::evidence::title(ui, &core.directory, &fallback);
            let selected = self.selected_directory.as_ref() == Some(&core.directory)
                || self
                    .selected
                    .as_ref()
                    .is_some_and(|record| record.dir == core.directory);
            let state = core.status_text();
            let state = state.as_str();
            let color = match core.state {
                antinomie_monitor_core::RunArtifactState::Failed => crate::theme::error(),
                antinomie_monitor_core::RunArtifactState::Partial
                | antinomie_monitor_core::RunArtifactState::Interrupted => crate::theme::warn(),
                _ => crate::theme::text(),
            };
            let row =
                crate::network_view::capture_row(ui, selected, (&title, color), state, font_size)
                    .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
            let core_file = core.file.clone();
            // A core a run took is an artifact of that run's sample.
            let note = crate::query::NoteRun::find(ui.ctx(), &core.vm_id, &core.run_id)
                .map(|run| {
                    let name = core
                        .file
                        .as_deref()
                        .and_then(|file| file.file_name())
                        .map_or_else(String::new, |name| name.to_string_lossy().into_owned());
                    run.extras(Some(antinomie_monitor_core::samples::NoteRef::new(
                        antinomie_monitor_core::samples::RefKind::Artifact,
                        antinomie_monitor_core::samples::artifact_target(
                            "core",
                            &core.vm_id,
                            &core.run_id,
                            &name,
                        ),
                        format!("Core dump · run {}", core.run_id),
                    )))
                })
                .unwrap_or_default();
            row.context_menu(|ui| {
                crate::query::table_row_menu_with(
                    ui,
                    filter_id,
                    &acquired_filter_row(ui, core),
                    note,
                );
                // A deleted core has no files left to open or delete.
                if core.deleted.is_some() {
                    return;
                }
                crate::evidence::menu(ui, &core.directory);
                core_file_menu(ui, core_file.as_deref(), file_action);
                core_project_menu(ui, &core.directory, self.job.is_none(), project_action);
                let capturing = (core.state.in_progress()
                    && Some(core.boot_id.as_str()) == boot_id)
                    .then_some(crate::evidence_delete::CORE_CAPTURING);
                if crate::evidence_delete::menu_item(ui, capturing) {
                    *delete = Some(Deletion::core(&core.directory, &title, DeleteKind::Core));
                }
            });
            if row.clicked() && self.job.is_none() {
                *acquired_selection = Some((core.directory.clone(), core.file.clone()));
            }
        }
    }

    /// The rows of the imported cores.
    pub(super) fn imported_rows(
        &self,
        ui: &mut egui::Ui,
        imported_shown: &[bool],
        context: &RowContext<'_>,
        outcome: &mut ListOutcome,
    ) {
        let RowContext {
            filter_id,
            font_size,
            note_vm,
            ..
        } = *context;
        let ListOutcome {
            imported_selection,
            file_action,
            project_action,
            delete,
            ..
        } = outcome;
        for (index, record) in self.records.iter().enumerate() {
            if !imported_shown[index] {
                continue;
            }
            let title = crate::evidence::title(ui, &record.dir, &record.label);
            let selected = self.selected_directory.as_ref() == Some(&record.dir)
                || self
                    .selected
                    .as_ref()
                    .is_some_and(|current| current.dir == record.dir);
            let detail = format!(
                "{} threads · {} mappings",
                record.core.threads.len(),
                record.core.mappings.len()
            );
            let row = crate::network_view::capture_row(
                ui,
                selected,
                (&title, crate::theme::text()),
                &detail,
                font_size,
            )
            .on_hover_text(record.core.source.display().to_string());
            let core_file = record.core.source.clone();
            row.context_menu(|ui| {
                crate::evidence::menu(ui, &record.dir);
                let folder = record
                    .dir
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned());
                let note = note_vm.zip(folder).map(|(vm, folder)| {
                    (
                        None,
                        antinomie_monitor_core::samples::NoteRef::new(
                            antinomie_monitor_core::samples::RefKind::ProcessCore,
                            antinomie_monitor_core::samples::imported_core_target(vm, &folder),
                            format!("Imported core {}", record.label),
                        ),
                    )
                });
                crate::query::table_row_menu_with(
                    ui,
                    filter_id,
                    &imported_filter_row(ui, record),
                    crate::query::RowMenuExtras {
                        no_note: note.is_none().then_some("Select a VM first"),
                        note,
                        ..Default::default()
                    },
                );
                core_file_menu(ui, Some(&core_file), file_action);
                core_project_menu(ui, &record.dir, self.job.is_none(), project_action);
                if crate::evidence_delete::menu_item(ui, None) {
                    *delete = Some(Deletion::core(
                        &record.dir,
                        &title,
                        DeleteKind::ImportedCore,
                    ));
                }
            });
            if row.clicked() && self.job.is_none() {
                *imported_selection = Some(record.clone());
            }
        }
    }
}

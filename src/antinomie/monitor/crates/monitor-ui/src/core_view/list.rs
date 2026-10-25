// SPDX-License-Identifier: GPL-3.0-only
//! The core list, its filters, and project export and import.
use super::*;
use crate::evidence_delete::{Deletion, Kind as DeleteKind};

impl CoreView {
    pub(super) fn list_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(egui_phosphor::regular::SIDEBAR_SIMPLE)
                        .frame(false)
                        .selected(!self.hide_list),
                )
                .on_hover_text(if self.hide_list {
                    "Show the core list"
                } else {
                    "Hide the core list"
                })
                .clicked()
            {
                self.hide_list = !self.hide_list;
            }
            let title = self
                .selected
                .as_ref()
                .map(|record| record.label.clone())
                .or_else(|| {
                    self.manual
                        .iter()
                        .find(|core| Some(&core.directory) == self.selected_directory.as_ref())
                        .map(|core| format!("PID {} · {}", core.target.tgid, core.id))
                });
            match title {
                Some(title) => {
                    ui.label(RichText::new(title).strong().color(crate::theme::heading()));
                }
                None => {
                    ui.colored_label(crate::theme::muted(), "No core open");
                }
            }
        });
    }

    /// One "Cancel process core" button per capture still in progress in the
    /// running boot, manual or on exit; none while nothing is being captured.
    fn cancel_buttons(
        &self,
        ui: &mut egui::Ui,
        can_cancel: bool,
        boot_id: Option<&str>,
    ) -> Option<CoreAction> {
        use antinomie_monitor_core::RunArtifactState::{InProgress, WaitingForRootExit};
        if !can_cancel {
            return None;
        }
        let mut pending: Vec<(String, CoreAction)> = self
            .manual
            .iter()
            .filter(|core| {
                core.phase != ProcessCorePhase::Finished && Some(core.boot_id.as_str()) == boot_id
            })
            .map(|core| {
                (
                    format!("PID {}", core.target.tgid),
                    CoreAction::Cancel(core.id.clone()),
                )
            })
            .chain(
                self.acquired
                    .iter()
                    .filter(|core| {
                        matches!(core.state, WaitingForRootExit | InProgress)
                            && Some(core.boot_id.as_str()) == boot_id
                    })
                    .map(|core| {
                        (
                            format!("run {}", core.run_id),
                            CoreAction::CancelRun(core.run_id.clone()),
                        )
                    }),
            )
            .collect();
        let several = pending.len() > 1;
        let mut action = None;
        for (what, cancel) in pending.drain(..) {
            let label = if several {
                format!("Cancel process core ({what})")
            } else {
                "Cancel process core".to_owned()
            };
            if ui
                .button(label)
                .on_hover_text("Stop this capture and let the process continue")
                .clicked()
            {
                action = Some(cancel);
            }
        }
        action
    }

    pub(super) fn dump_list(
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
        if self.job.is_some() {
            ui.horizontal_wrapped(|ui| {
                crate::theme::spinner(ui);
                ui.label("Working…");
                if self.project_export_active && ui.button("Cancel export").clicked() {
                    self.cancelled.store(true, Ordering::Relaxed);
                }
            });
        }
        let mut acquired_selection = None;
        let mut imported_selection = None;
        let mut file_action: Option<(bool, PathBuf)> = None;
        let mut project_action = None;
        let mut delete = None;
        let font_size = egui::TextStyle::Body.resolve(ui.style()).size;
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
        egui::ScrollArea::vertical()
            .id_salt("core_capture_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if self.acquired.is_empty() && self.records.is_empty() && self.manual.is_empty() {
                    crate::theme::empty_state(ui, "No cores yet.");
                }
                for (index, core) in self.manual.iter().enumerate() {
                    if !manual_shown[index] {
                        continue;
                    }
                    let fallback = format!("PID {} · {}", core.target.tgid, core.id);
                    let title = crate::evidence::title(ui, &core.directory, &fallback);
                    let selected = self.selected_directory.as_ref() == Some(&core.directory);
                    let state = manual_status(core);
                    let color = if core.issue.is_some() {
                        crate::theme::warn()
                    } else {
                        crate::theme::text()
                    };
                    let row = crate::network_view::capture_row(
                        ui,
                        selected,
                        (&title, color),
                        &state,
                        font_size,
                    )
                    .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
                    let core_file = core.file.clone();
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &core.directory);
                        crate::query::table_row_menu(ui, filter_id, &manual_filter_row(ui, core));
                        core_file_menu(ui, core_file.as_deref(), &mut file_action);
                        core_project_menu(
                            ui,
                            &core.directory,
                            self.job.is_none(),
                            &mut project_action,
                        );
                        if core.phase != ProcessCorePhase::Finished
                            && can_cancel
                            && ui.button("Cancel capture and resume").clicked()
                        {
                            action = Some(CoreAction::Cancel(core.id.clone()));
                            ui.close_menu();
                        }
                        let capturing = (core.phase != ProcessCorePhase::Finished
                            && Some(core.boot_id.as_str()) == boot_id)
                            .then_some(crate::evidence_delete::CORE_CAPTURING);
                        if crate::evidence_delete::menu_item(ui, capturing) {
                            delete =
                                Some(Deletion::core(&core.directory, &title, DeleteKind::Core));
                        }
                    });
                    if row.clicked() && self.job.is_none() {
                        acquired_selection = Some((core.directory.clone(), core.file.clone()));
                    }
                }
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
                        | antinomie_monitor_core::RunArtifactState::Interrupted => {
                            crate::theme::warn()
                        }
                        _ => crate::theme::text(),
                    };
                    let row = crate::network_view::capture_row(
                        ui,
                        selected,
                        (&title, color),
                        state,
                        font_size,
                    )
                    .on_hover_text(format!("{title}\n{state}\n{}", core.directory.display()));
                    let core_file = core.file.clone();
                    row.context_menu(|ui| {
                        crate::query::table_row_menu(ui, filter_id, &acquired_filter_row(ui, core));
                        // A deleted core has no files left to open or delete.
                        if core.deleted.is_some() {
                            return;
                        }
                        crate::evidence::menu(ui, &core.directory);
                        core_file_menu(ui, core_file.as_deref(), &mut file_action);
                        core_project_menu(
                            ui,
                            &core.directory,
                            self.job.is_none(),
                            &mut project_action,
                        );
                        let capturing = (core.state.in_progress()
                            && Some(core.boot_id.as_str()) == boot_id)
                            .then_some(crate::evidence_delete::CORE_CAPTURING);
                        if crate::evidence_delete::menu_item(ui, capturing) {
                            delete =
                                Some(Deletion::core(&core.directory, &title, DeleteKind::Core));
                        }
                    });
                    if row.clicked() && self.job.is_none() {
                        acquired_selection = Some((core.directory.clone(), core.file.clone()));
                    }
                }
                if !self.records.is_empty() && !self.acquired.is_empty() {
                    ui.add_space(8.0);
                    crate::theme::section(ui, "Imported cores");
                }
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
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &imported_filter_row(ui, record),
                        );
                        core_file_menu(ui, Some(&core_file), &mut file_action);
                        core_project_menu(ui, &record.dir, self.job.is_none(), &mut project_action);
                        if crate::evidence_delete::menu_item(ui, None) {
                            delete = Some(Deletion::core(
                                &record.dir,
                                &title,
                                DeleteKind::ImportedCore,
                            ));
                        }
                    });
                    if row.clicked() && self.job.is_none() {
                        imported_selection = Some(record.clone());
                    }
                }
            });
        if let Some((directory, file)) = acquired_selection {
            self.selected_directory = Some(directory);
            self.selected = None;
            self.status.clear();
            if let Some(file) = file {
                self.open(&file);
            }
        } else if let Some(mut record) = imported_selection {
            self.selected_directory = Some(record.dir.clone());
            self.selected = None;
            self.status.clear();
            self.start(move || {
                record.core =
                    CoreDump::open(&record.core.source).map_err(|error| error.to_string())?;
                let code = match fs::File::open(record.dir.join("disassembly.txt")) {
                    Ok(file) => {
                        let mut text = String::new();
                        file.take(1024 * 1024)
                            .read_to_string(&mut text)
                            .map_err(|error| error.to_string())?;
                        text
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                    Err(error) => return Err(error.to_string()),
                };
                Ok(opened_reply(record, code))
            });
        }
        if let Some((export, path)) = file_action {
            if export {
                self.export_source(path);
            } else {
                let parent = path.parent().unwrap_or(Path::new("/")).to_owned();
                self.start(move || {
                    reveal(&parent).map(|()| Reply::Done("Opened core file directory.".into()))
                });
            }
        }
        if let Some(source) = project_action {
            self.export_project(source);
        }
        if let Some(deletion) = delete {
            action = Some(CoreAction::Delete(deletion));
        }
        action
    }

    fn export_project(&mut self, source: PathBuf) {
        if self.job.is_some() {
            return;
        }
        self.cancelled.store(false, Ordering::Relaxed);
        self.project_export_active = true;
        let cancelled = Arc::clone(&self.cancelled);
        self.start(move || {
            let Some(destination) = choose_path(
                true,
                "Export Ghidra project — choose a new directory path",
                &cancelled,
            )?
            else {
                return Ok(Reply::Done("Ghidra project export cancelled.".into()));
            };
            if cancelled.load(Ordering::Relaxed) {
                return Ok(Reply::Done("Ghidra project export cancelled.".into()));
            }
            antinomie_monitor_core::analysis::copy_project(&source, &destination)?;
            if cancelled.load(Ordering::Relaxed) {
                fs::remove_dir_all(&destination).map_err(|error| {
                    format!("Ghidra export cancelled; partial project cleanup failed: {error}")
                })?;
                return Ok(Reply::Done("Ghidra project export cancelled.".into()));
            }
            Ok(Reply::Done(format!(
                "Exported Ghidra project to {}",
                destination.display()
            )))
        });
        if self.job.is_none() {
            self.project_export_active = false;
        }
    }

    fn export_source(&mut self, source: PathBuf) {
        let cancelled = self.cancelled.clone();
        self.start(move || {
            let Some(destination) = choose_file(true, &cancelled)? else {
                return Ok(Reply::Done("Export cancelled.".into()));
            };
            if destination.exists() {
                return Err("Export destination already exists; choose a new filename.".into());
            }
            let mut input = fs::File::open(&source).map_err(|error| error.to_string())?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&destination)
                .map_err(|error| error.to_string())?;
            let mut buffer = vec![0; 256 * 1024];
            loop {
                if cancelled.load(Ordering::Relaxed) {
                    return Err(
                        "Core export cancelled; destination contains only the exported prefix."
                            .into(),
                    );
                }
                let size = input.read(&mut buffer).map_err(|error| error.to_string())?;
                if size == 0 {
                    break;
                }
                output
                    .write_all(&buffer[..size])
                    .map_err(|error| error.to_string())?;
            }
            output.sync_all().map_err(|error| error.to_string())?;
            Ok(Reply::Done(format!("Exported {}", destination.display())))
        });
    }

    pub(super) fn import_dialog(&mut self, ctx: &egui::Context) {
        if !self.import_open {
            return;
        }
        let mut open = true;
        let mut cancel = false;
        crate::widgets::window("Import process core")
            .id(egui::Id::new("core_import"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(480.0)
            .show(ctx, |ui| {
                ui.add(egui::Label::new("Linux x86-64 ELF process core. The original file stays in place; reference metadata is saved with the selected VM.").wrap());
                ui.label("Core file");
                ui.add(egui::TextEdit::singleline(&mut self.source_path).desired_width(f32::INFINITY));
                if ui.add_enabled(self.job.is_none(), egui::Button::new("Browse…")).clicked() {
                    let cancelled = self.cancelled.clone();
                    self.start(move || choose_file(false, &cancelled).map(Reply::Chosen));
                }
                ui.label("Recording folder");
                egui::ComboBox::from_id_salt("core_recording_root")
                    .width(ui.available_width())
                    .selected_text(self.roots.get(self.destination).map_or_else(
                        || "Select recording folder".into(),
                        |root| root.file_name().unwrap_or(root.as_os_str()).to_string_lossy().into_owned(),
                    ))
                    .show_ui(ui, |ui| {
                        for (index, root) in self.roots.iter().enumerate() {
                            ui.selectable_value(&mut self.destination, index, root.display().to_string());
                        }
                    });
                if self.roots.is_empty() {
                    ui.label("Select a VM with a recording folder first.");
                }
                if !self.status.is_empty() {
                    self.show_status(ui);
                }
                if self.job.is_some() {
                    crate::theme::spinner(ui);
                }
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(self.job.is_none() && self.roots.get(self.destination).is_some() && !self.source_path.trim().is_empty(), egui::Button::new("Import core")).clicked() {
                        if let Some(root) = self.roots.get(self.destination).cloned() {
                            let path = crate::folders::user_path(&self.source_path);
                            self.start(move || CoreRecord::import(&path, &root).map(|record| opened_reply(record, String::new())).map_err(|error| error.to_string()));
                        }
                    }
                    cancel = ui.button(if self.job.is_some() { "Close" } else { "Cancel" }).clicked();
                });
            });
        self.import_open = open && !cancel;
    }
}

fn core_file_menu(ui: &mut egui::Ui, file: Option<&Path>, action: &mut Option<(bool, PathBuf)>) {
    let Some(file) = file else { return };
    if ui.button("Open core file directory").clicked() {
        *action = Some((false, file.to_owned()));
        ui.close_menu();
    }
    if ui.button("Export core…").clicked() {
        *action = Some((true, file.to_owned()));
        ui.close_menu();
    }
}

fn core_project_menu(
    ui: &mut egui::Ui,
    directory: &Path,
    enabled: bool,
    action: &mut Option<PathBuf>,
) {
    let source = directory.join("ghidra-project");
    if source.join("antinomie.gpr").is_file()
        && source.join("antinomie.rep").is_dir()
        && ui
            .add_enabled(enabled, egui::Button::new("Export Ghidra project…"))
            .clicked()
    {
        *action = Some(source);
        ui.close_menu();
    }
}

fn manual_filter_row(
    ui: &egui::Ui,
    core: &antinomie_monitor_core::ProcessCoreCapture,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let mut row = core_history_row(
        ui,
        &core.directory,
        &core.id,
        &format!("PID {} · {}", core.target.tgid, core.id),
        &manual_status(core),
        CoreRowMetrics {
            pid: Some(u64::from(core.target.tgid)),
            size: Some(core.stored_size),
            ..Default::default()
        },
    );
    row.extend([
        ("vm.id", V::Text(core.vm_id.clone())),
        ("boot.id", V::Text(core.boot_id.clone())),
        (
            "run.id",
            core.source_run_id
                .as_ref()
                .map_or(V::Missing, |id| V::Text(id.clone())),
        ),
        (
            "entry.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        (
            "capture.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        (
            "capture.run_id",
            core.source_run_id
                .as_ref()
                .map_or(V::Missing, |id| V::Text(id.clone())),
        ),
        (
            "capture.expected_size",
            core.expected_size
                .or(core.guest_size)
                .map_or(V::Missing, |size| V::Number(i128::from(size))),
        ),
        (
            "capture.requested_size",
            V::Number(i128::from(core.requested_max_size.unwrap_or(core.max_size))),
        ),
        (
            "capture.accepted_size",
            V::Number(i128::from(core.max_size)),
        ),
        (
            "capture.saved_size",
            core.allocated_size
                .map_or(V::Missing, |size| V::Number(i128::from(size))),
        ),
        (
            "capture.logical_size",
            V::Number(i128::from(core.stored_size)),
        ),
        ("capture.reason", reason_value(core.reason.as_ref())),
        (
            "core.partial",
            match core.state {
                antinomie_monitor_core::RunArtifactState::Complete => V::Bool(false),
                antinomie_monitor_core::RunArtifactState::Partial => V::Bool(true),
                _ => V::Missing,
            },
        ),
    ]);
    row
}

fn number_value(size: Option<u64>) -> crate::query::RowValue {
    size.map_or(crate::query::RowValue::Missing, |size| {
        crate::query::RowValue::Number(i128::from(size))
    })
}

/// The reason code as filter text (`budget`, `guest_memory`, ...); missing when complete.
fn reason_value(reason: Option<&antinomie_monitor_core::CoreReason>) -> crate::query::RowValue {
    reason.map_or(crate::query::RowValue::Missing, |reason| {
        let code = serde_json::to_value(reason.code)
            .ok()
            .and_then(|value| value.as_str().map(str::to_owned))
            .unwrap_or_default();
        crate::query::RowValue::Text(code)
    })
}

fn acquired_filter_row(
    ui: &egui::Ui,
    core: &AcquiredCore,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let mut row = core_history_row(
        ui,
        &core.directory,
        &core.run_id,
        &format!("Run {}", core.run_id),
        core.status(),
        CoreRowMetrics::default(),
    );
    row.extend([
        ("vm.id", V::Text(core.vm_id.clone())),
        ("boot.id", V::Text(core.boot_id.clone())),
        ("run.id", V::Text(core.run_id.clone())),
        (
            "entry.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        (
            "capture.complete",
            V::Bool(core.state == antinomie_monitor_core::RunArtifactState::Complete),
        ),
        ("capture.run_id", V::Text(core.run_id.clone())),
        (
            "capture.requested_size",
            number_value(core.sizes.as_ref().and_then(|sizes| sizes.requested)),
        ),
        (
            "capture.accepted_size",
            number_value(core.sizes.as_ref().and_then(|sizes| sizes.accepted)),
        ),
        (
            "capture.saved_size",
            number_value(core.sizes.as_ref().and_then(|sizes| sizes.saved)),
        ),
        (
            "capture.logical_size",
            number_value(core.sizes.as_ref().and_then(|sizes| sizes.logical)),
        ),
        (
            "capture.expected_size",
            number_value(core.sizes.as_ref().and_then(|sizes| sizes.expected)),
        ),
        (
            "capture.reason",
            reason_value(core.sizes.as_ref().and_then(|sizes| sizes.reason.as_ref())),
        ),
        (
            "core.partial",
            match core.state {
                antinomie_monitor_core::RunArtifactState::Complete => V::Bool(false),
                antinomie_monitor_core::RunArtifactState::Partial => V::Bool(true),
                _ => V::Missing,
            },
        ),
    ]);
    row
}

fn imported_filter_row(
    ui: &egui::Ui,
    record: &CoreRecord,
) -> Vec<(&'static str, crate::query::RowValue)> {
    let mut row = core_history_row(
        ui,
        &record.dir,
        &record.dir.display().to_string(),
        &record.label,
        "imported",
        CoreRowMetrics {
            threads: Some(record.core.threads.len() as u64),
            mappings: Some(record.core.mappings.len() as u64),
            size: Some(record.core.source_size),
            ..Default::default()
        },
    );
    row.push((
        "core.signal",
        record
            .core
            .threads
            .first()
            .map_or(crate::query::RowValue::Missing, |thread| {
                crate::query::RowValue::Number(i128::from(thread.signal))
            }),
    ));
    row
}

fn core_history_row(
    ui: &egui::Ui,
    directory: &Path,
    id: &str,
    fallback: &str,
    state: &str,
    metrics: CoreRowMetrics,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;
    let CoreRowMetrics {
        pid,
        threads,
        mappings,
        size,
    } = metrics;
    let annotation = crate::evidence::annotation(ui, directory);
    let mut row = crate::query::label_row(
        id,
        annotation.as_ref().map_or("", |value| &value.name),
        &directory.display().to_string(),
        annotation
            .as_ref()
            .map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("capture.kind", RowValue::Text("core".into())),
        ("capture.state", RowValue::Text(state.into())),
        (
            "capture.size",
            size.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "core.thread_count",
            threads.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("entry.kind", RowValue::Text("core".into())),
        ("entry.state", RowValue::Text(state.into())),
        (
            "entry.size",
            size.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "name",
            RowValue::Text(
                annotation
                    .as_ref()
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| fallback.into(), |value| value.name.clone()),
            ),
        ),
        ("state", RowValue::Text(state.into())),
        (
            "pid",
            pid.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "threads",
            threads.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "mappings",
            mappings.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "size",
            size.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
    ]);
    row
}

fn choose_file(save: bool, cancelled: &AtomicBool) -> Result<Option<PathBuf>, String> {
    choose_path(save, "Select process core", cancelled)
}

fn choose_path(save: bool, title: &str, cancelled: &AtomicBool) -> Result<Option<PathBuf>, String> {
    let mut command = Command::new("zenity");
    command.args(["--file-selection", "--title", title]);
    if save {
        command.args(["--save", "--confirm-overwrite"]);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            format!("File picker unavailable ({error}); type the file path instead.")
        })?;
    let status = loop {
        if cancelled.load(Ordering::Relaxed) {
            let kill = child.kill();
            let wait = child.wait();
            return Err(format!(
                "File selection cancelled; cleanup {kill:?}, {wait:?}"
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(error) => {
                let kill = child.kill();
                let wait = child.wait();
                return Err(format!(
                    "File picker wait failed: {error}; cleanup {kill:?}, {wait:?}"
                ));
            }
        }
    };
    let mut output = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or("file picker output unavailable")?
        .take(8193)
        .read_to_end(&mut output);
    if let Err(error) = read {
        let kill = child.kill();
        let wait = child.wait();
        return Err(format!(
            "File picker read failed: {error}; cleanup {kill:?}, {wait:?}"
        ));
    }
    if output.len() > 8192 {
        let kill = child.kill();
        let wait = child.wait();
        return Err(format!(
            "File picker path exceeds limit; cleanup {kill:?}, {wait:?}"
        ));
    }
    if status.code() == Some(1) {
        return Ok(None);
    }
    if !status.success() {
        return Err(format!("File picker failed: {status}"));
    }
    let text = String::from_utf8(output).map_err(|error| error.to_string())?;
    let text = text.strip_suffix('\n').unwrap_or(&text);
    Ok((!text.is_empty()).then(|| PathBuf::from(text)))
}

pub(super) fn reveal(path: &Path) -> Result<(), String> {
    crate::folders::show(path)
}

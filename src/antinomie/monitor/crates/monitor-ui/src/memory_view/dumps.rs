// SPDX-License-Identifier: GPL-3.0-only
//! The list of RAM dumps, their identity and deletion.
use super::*;

impl MemoryView {
    pub(crate) fn open_dump(&mut self, directory: &std::path::Path) {
        self.select(
            directory
                .file_name()
                .map(|name| name.to_string_lossy().into_owned()),
        );
        self.dumps_for = None;
    }
    pub(super) fn scan(&mut self, roots: &[PathBuf]) {
        self.dumps = memory::list(roots);
        self.dumps_for = Some(roots.to_vec());
        if self
            .selected
            .as_ref()
            .is_none_or(|id| !self.dumps.iter().any(|dump| &dump.id == id))
        {
            let first = self
                .dumps
                .iter()
                .find(|dump| dump.complete())
                .or(self.dumps.first());
            self.select(first.map(|dump| dump.id.clone()));
        } else {
            // A run link can select an ID before this refreshed list contains it.
            self.reload_runs();
            let selected = self
                .selected_run
                .clone()
                .filter(|id| self.runs.iter().any(|run| &run.id == id))
                .or_else(|| self.runs.first().map(|run| run.id.clone()));
            self.open_run(selected);
        }
    }

    pub(super) fn select(&mut self, id: Option<String>) {
        if self.selected == id && self.dumps_for.is_some() && !self.runs.is_empty() {
            return;
        }
        self.selected = id;
        self.status = None;
        self.reload_runs();
        let newest = self.runs.first().map(|run| run.id.clone());
        self.open_run(newest);
    }

    pub(super) fn dump(&self) -> Option<&MemoryDump> {
        let id = self.selected.as_ref()?;
        self.dumps.iter().find(|dump| &dump.id == id)
    }

    pub(super) fn reload_runs(&mut self) {
        self.runs = self.dump().map(MemoryDump::runs).unwrap_or_default();
    }

    pub(super) fn list_toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .add(
                    egui::Button::new(egui_phosphor::regular::SIDEBAR_SIMPLE)
                        .frame(false)
                        .selected(!self.hide_list),
                )
                .on_hover_text(if self.hide_list {
                    "Show the dump list"
                } else {
                    "Hide the dump list"
                })
                .clicked()
            {
                self.hide_list = !self.hide_list;
            }
            match self.dump() {
                Some(dump) => {
                    ui.label(
                        RichText::new(dump_title(dump))
                            .strong()
                            .color(theme::heading()),
                    );
                }
                None => {
                    ui.colored_label(theme::muted(), "No dump open");
                }
            }
        });
    }

    pub(super) fn dump_list(
        &mut self,
        ui: &mut egui::Ui,
        cx: &MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let mut action = None;
        ui.horizontal(|ui| {
            theme::section(ui, "Memory dumps");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add(egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE).frame(false))
                    .on_hover_text("Refresh the list")
                    .clicked()
                {
                    self.scan(cx.recording_roots);
                }
            });
        });
        let why = if cx.vm.is_none() {
            Some("Select a VM")
        } else if !cx.running {
            Some("Start the VM to dump its memory")
        } else if cx.dumping.is_some() {
            Some("A dump is being written")
        } else {
            None
        };
        let full = egui::vec2(ui.available_width(), 0.0);
        if ui
            .add_enabled(
                why.is_none() && !cx.pending,
                egui::Button::new(format!("{} Dump memory", egui_phosphor::regular::MEMORY))
                    .min_size(full),
            )
            .on_hover_text(
                "Write the VM's RAM to a dump for analysis. The VM pauses while it is \
                 written (seconds to minutes, by RAM size and disk speed) and then continues.",
            )
            .on_disabled_hover_text(why.unwrap_or("Waiting for the VM"))
            .clicked()
        {
            action = Some(MemoryAction::Dump);
        }
        if ui
            .add_enabled(
                cx.vm.is_some() && cx.recordings.is_some(),
                egui::Button::new(format!(
                    "{} Import dump…",
                    egui_phosphor::regular::FILE_ARROW_UP
                ))
                .min_size(full),
            )
            .on_hover_text(
                "Analyse a dump made elsewhere (raw, LiME, ELF core, crash dump, VMware or \
                 VirtualBox memory, hibernation file). The file stays where it is.",
            )
            .on_disabled_hover_text("Select a VM: imported dumps are kept with its recordings")
            .clicked()
            && self.import.is_none()
        {
            self.import = Some(Import {
                path: String::new(),
                os: Os::Linux,
                base: None,
                picker: None,
                error: None,
            });
        }
        ui.add_space(2.0);
        let mut fields = crate::query::LABEL_FIELDS.to_vec();
        fields.extend(crate::query::CAPTURE_FIELDS);
        fields.extend([
            crate::query::FieldSpec::text("name", "Displayed dump name"),
            crate::query::FieldSpec::text("state", "Dump state"),
            crate::query::FieldSpec::text("os", "Guest operating system"),
            crate::query::FieldSpec::text("system", "Recorded guest system"),
            crate::query::FieldSpec::number("size", "Dump size in octets"),
            crate::query::FieldSpec::number("ram_mib", "Configured RAM in MiB"),
            crate::query::FieldSpec::boolean("imported", "Imported dump"),
            crate::query::FieldSpec::boolean("symbols", "Retained symbol table"),
        ]);
        let annotations: Vec<_> = self
            .dumps
            .iter()
            .map(|dump| crate::evidence::annotation(ui, &dump.dir))
            .collect();
        let tags: Vec<_> = annotations
            .iter()
            .flatten()
            .flat_map(|value| value.tags.iter().cloned())
            .collect();
        let filter = crate::query::table_filter(
            ui,
            "memory-dump-history",
            "entry.name contains win10",
            &fields,
            &tags,
        );
        let filter_id = ui.id().with(("table-filter", "memory-dump-history"));
        let shown: Vec<_> = self
            .dumps
            .iter()
            .enumerate()
            .filter(|(index, dump)| {
                filter.keep_table(&memory_dump_row(dump, annotations[*index].as_ref()))
            })
            .map(|(_, dump)| dump)
            .collect();
        ui.weak(format!("{} / {} dumps", shown.len(), self.dumps.len()));
        if self
            .selected
            .as_ref()
            .is_some_and(|selected| !shown.iter().any(|dump| &dump.id == selected))
        {
            self.selected = None;
            self.selected_run = None;
            self.result = None;
        }
        let mut select = None;
        let mut delete = None;
        let font_size = cx.font_size;
        egui::ScrollArea::vertical()
            .id_salt("memory_dump_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                if let Some(progress) = cx.dumping {
                    let fraction = progress.completed as f32 / progress.total.max(1) as f32;
                    capture_row(
                        ui,
                        false,
                        (
                            &format!("{} Writing dump", egui_phosphor::regular::RECORD),
                            theme::error(),
                        ),
                        &format!(
                            "{:.0}% of {} · VM paused",
                            fraction * 100.0,
                            crate::values::file_size(progress.total)
                        ),
                        font_size,
                    );
                    ui.add(egui::ProgressBar::new(fraction).desired_height(4.0));
                }
                for dump in shown {
                    if cx
                        .dumping
                        .is_some_and(|progress| progress.dump.id == dump.id)
                    {
                        continue;
                    }
                    let selected = self.selected.as_ref() == Some(&dump.id);
                    let color = if dump.error.is_some() {
                        theme::error()
                    } else {
                        theme::text()
                    };
                    let title = crate::evidence::title(ui, &dump.dir, &dump_title(dump));
                    let row =
                        capture_row(ui, selected, (&title, color), &dump_detail(dump), font_size)
                            .on_hover_text(format!(
                                "{}\n{}{}",
                                dump.path().display(),
                                dump.boot_id
                                    .as_ref()
                                    .map(|boot| format!("Boot {boot}\n"))
                                    .unwrap_or_default(),
                                if dump.symbols {
                                    "Symbol table of its base included"
                                } else {
                                    "No symbol table: Volatility looks for one itself, MemNixFS rebuilds one from the kernel"
                                }
                            ));
                    if row.clicked() {
                        select = Some(dump.id.clone());
                    }
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &dump.dir);
                        let annotation = crate::evidence::annotation(ui, &dump.dir);
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &memory_dump_row(dump, annotation.as_ref()),
                        );
                        ui.separator();
                        if ui.button("Open folder").clicked() {
                            if let Err(error) = open_directory(&dump.dir) {
                                self.status = Some((error, true));
                            }
                            ui.close_menu();
                        }
                        if ui.button("Copy path").clicked() {
                            ui.ctx().copy_text(dump.path().display().to_string());
                            ui.close_menu();
                        }
                        ui.separator();
                        let label = if dump.imported {
                            "Remove from list (keeps the file)"
                        } else {
                            "Delete dump and results"
                        };
                        if ui
                            .button(RichText::new(label).color(theme::error()))
                            .clicked()
                        {
                            delete = Some(dump.id.clone());
                            ui.close_menu();
                        }
                    });
                }
                if self.dumps.is_empty() && cx.dumping.is_none() {
                    theme::empty_state(ui, "No memory dumps for this VM");
                }
            });
        if let Some(id) = select {
            self.select(Some(id));
        }
        if let Some(id) = delete {
            self.confirm_delete = Some(id);
        }
        self.delete_window(ui.ctx(), cx);
        action
    }

    fn delete_window(&mut self, ctx: &egui::Context, cx: &MemoryContext<'_>) {
        let Some(id) = self.confirm_delete.clone() else {
            return;
        };
        let Some(dump) = self.dumps.iter().find(|dump| dump.id == id).cloned() else {
            self.confirm_delete = None;
            return;
        };
        let mut open = true;
        let mut done = false;
        crate::widgets::window("Delete memory dump")
            .id(egui::Id::new("memory_delete"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .show(ctx, |ui| {
                ui.label(format!("{} — {}", dump_title(&dump), dump_detail(&dump)));
                let runs = dump.runs().len();
                ui.colored_label(
                    theme::muted(),
                    if dump.imported {
                        format!("Its {runs} saved results are deleted; the imported file stays.")
                    } else {
                        format!("The dump file and its {runs} saved results are deleted.")
                    },
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .add(
                            egui::Button::new(
                                RichText::new("Delete").color(theme::palette().primary_text),
                            )
                            .fill(theme::error()),
                        )
                        .clicked()
                    {
                        if let Err(error) = memory::delete(&dump) {
                            self.status = Some((error, true));
                        }
                        done = true;
                    }
                    if ui.button("Cancel").clicked() {
                        done = true;
                    }
                });
            });
        if done || !open || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.confirm_delete = None;
            ctx.request_repaint();
            if done {
                self.scan(cx.recording_roots);
            }
        }
    }
}

pub(super) fn format_elapsed(ms: u64) -> String {
    if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{} min {} s", ms / 60_000, ms / 1000 % 60)
    }
}

/// The time of day (UTC) of a date-time.
pub(super) fn clock(ms: u64) -> String {
    let date = format_date(ms / 1000);
    date.split_whitespace().nth(1).unwrap_or(&date).to_owned()
}

pub(super) fn dump_title(dump: &MemoryDump) -> String {
    if dump.imported {
        dump.file.file_name().map_or_else(
            || "Imported dump".into(),
            |name| name.to_string_lossy().into_owned(),
        )
    } else {
        format_date(dump.started_ms / 1000)
            .trim_end_matches(" UTC")
            .to_owned()
    }
}

fn dump_detail(dump: &MemoryDump) -> String {
    let size = dump
        .bytes
        .map(crate::values::file_size)
        .unwrap_or_else(|| "…".into());
    if let Some(error) = &dump.error {
        return format!("Failed: {error}");
    }
    if dump.missing() {
        return format!("{size} · file missing");
    }
    if dump.imported {
        format!("Imported · {size} · {}", dump.system)
    } else {
        format!("{size} · {}", dump.system)
    }
}

pub(super) fn open_directory(path: &Path) -> Result<(), String> {
    crate::folders::show_detached(path.to_owned());
    Ok(())
}

/// A base in the symbol table list: its name and the version it is for.
pub(super) fn base_choice(base: &BaseSummary) -> String {
    match &base.min_app_version {
        Some(version) => format!("{} · Antinomie {version}", base.label),
        None => base.label.clone(),
    }
}

/// A muted hint centered near the top of an empty area.
pub(super) fn empty_state(ui: &mut egui::Ui, text: &str) {
    ui.add_space(12.0);
    ui.vertical_centered(|ui| {
        ui.set_max_width(560.0);
        ui.label(
            RichText::new(egui_phosphor::regular::MEMORY)
                .size(28.0)
                .color(theme::muted()),
        );
        ui.add(egui::Label::new(RichText::new(text).color(theme::muted())).wrap());
    });
}

fn memory_dump_row(
    dump: &MemoryDump,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;

    let mut row = crate::query::label_row(
        &dump.id,
        annotation.map_or("", |value| &value.name),
        &dump.path().display().to_string(),
        annotation.map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        ("capture.kind", RowValue::Text("memory".into())),
        (
            "capture.started_ms",
            RowValue::Number(i128::from(dump.started_ms)),
        ),
        (
            "capture.ended_ms",
            dump.finished_ms.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        (
            "capture.size",
            dump.bytes.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("capture.complete", RowValue::Bool(dump.complete())),
        (
            "capture.state",
            RowValue::Text(
                if dump.error.is_some() {
                    "failed"
                } else if dump.finished_ms.is_some() {
                    "finished"
                } else {
                    "writing"
                }
                .into(),
            ),
        ),
        ("entry.kind", RowValue::Text("memory".into())),
        ("entry.complete", RowValue::Bool(dump.complete())),
        (
            "entry.time_ms",
            RowValue::Number(i128::from(dump.started_ms)),
        ),
        (
            "entry.size",
            dump.bytes.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("vm.id", RowValue::Text(dump.vm_id.clone())),
        (
            "boot.id",
            dump.boot_id
                .as_ref()
                .map_or(RowValue::Missing, |value| RowValue::Text(value.clone())),
        ),
        (
            "entry.state",
            RowValue::Text(
                if dump.error.is_some() {
                    "failed"
                } else if dump.finished_ms.is_some() {
                    "finished"
                } else {
                    "writing"
                }
                .into(),
            ),
        ),
        (
            "name",
            RowValue::Text(
                annotation
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| dump_title(dump), |value| value.name.clone()),
            ),
        ),
        (
            "state",
            RowValue::Text(
                if dump.error.is_some() {
                    "failed"
                } else if dump.finished_ms.is_some() {
                    "finished"
                } else {
                    "writing"
                }
                .into(),
            ),
        ),
        ("os", RowValue::Text(format!("{:?}", dump.os))),
        ("system", RowValue::Text(dump.system.clone())),
        (
            "size",
            dump.bytes.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
        ("ram_mib", RowValue::Number(i128::from(dump.ram_mib))),
        ("imported", RowValue::Bool(dump.imported)),
        ("symbols", RowValue::Bool(dump.symbols)),
    ]);

    row
}

pub(super) fn add_dump_identity(
    row: &mut Vec<(&'static str, crate::query::RowValue)>,
    vm_id: Option<&str>,
    boot_id: Option<&str>,
) {
    if let Some(vm_id) = vm_id {
        row.push(("vm.id", crate::query::RowValue::Text(vm_id.to_owned())));
    }
    if let Some(boot_id) = boot_id {
        row.push(("boot.id", crate::query::RowValue::Text(boot_id.to_owned())));
    }
}

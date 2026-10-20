// SPDX-License-Identifier: MIT
//! Registers, mappings and notes of the selected core.
use super::*;

impl CoreView {
    pub(super) fn analysis(&mut self, ui: &mut egui::Ui) {
        if !self.status.is_empty() {
            self.show_status(ui);
        }
        if !self.catalog_issues.is_empty() {
            egui::CollapsingHeader::new(format!("Capture issues ({})", self.catalog_issues.len()))
                .show(ui, |ui| {
                    for issue in &self.catalog_issues {
                        crate::activity::warning(ui, issue);
                    }
                });
        }
        let Some(record) = self.selected.clone() else {
            if let Some(core) = self
                .manual
                .iter()
                .find(|core| Some(&core.directory) == self.selected_directory.as_ref())
            {
                let title = crate::evidence::title(
                    ui,
                    &core.directory,
                    &format!("PID {} · {}", core.target.tgid, core.id),
                );
                crate::theme::section(ui, &title);
                ui.add(egui::Label::new(manual_status(core)).wrap());
                if let Some(details) = sizes::manual_details(core) {
                    ui.add(egui::Label::new(egui::RichText::new(details).weak()).wrap());
                }
                ui.label(format!(
                    "PID {} · task {} · start {} ns",
                    core.target.tgid, core.target.task_cookie, core.target.start_boot_ns
                ));
                if let Some(run_id) = &core.source_run_id {
                    ui.label(format!("Related run: {run_id}"));
                }
                ui.label(match core.pause_released {
                    Some(true) => "Capture pause released",
                    Some(false) => "Capture pause has not been released yet",
                    None => "Capture pause status unknown",
                });
                if let Some(issue) = &core.issue {
                    crate::activity::warning(ui, issue);
                }
                if core.file.is_some() {
                    ui.label("Select this capture to open its retained data.");
                } else {
                    ui.add(egui::Label::new("No core file is retained yet. This view shows the recorded capture status; it does not wait for process exit.").wrap());
                }
                return;
            }
            if let Some(core) = self
                .acquired
                .iter()
                .find(|core| Some(&core.directory) == self.selected_directory.as_ref())
            {
                let title =
                    crate::evidence::title(ui, &core.directory, &format!("Run {}", core.run_id));
                crate::theme::section(ui, &title);
                ui.label(core.status_text());
                if let Some(sizes) = &core.sizes
                    && let Some(details) = sizes::details(
                        sizes.requested,
                        sizes.accepted,
                        None,
                        sizes.expected,
                        sizes.saved,
                        sizes.logical,
                        sizes.reason.as_ref(),
                    )
                {
                    ui.add(egui::Label::new(egui::RichText::new(details).weak()).wrap());
                }
                ui.add(egui::Label::new(format!("Run {}", core.run_id)).wrap());
                let explanation = if core.deleted.is_some() {
                    "This core was deleted. The run keeps its record."
                } else if core.file.is_some() {
                    "Select this capture to open its currently recorded data."
                } else if matches!(
                    core.state,
                    antinomie_monitor_core::RunArtifactState::WaitingForRootExit
                        | antinomie_monitor_core::RunArtifactState::InProgress
                ) {
                    "No core file is recorded yet. The capture is waiting for process exit or acquisition; recorded context and memory can be opened when available."
                } else {
                    "This capture retained no core file. Check run history for acquisition details."
                };
                ui.add(egui::Label::new(explanation).wrap());
            } else if self.job.is_some() {
                crate::theme::loading(ui, "Opening core…");
            } else {
                crate::theme::section(ui, "Process core");
                ui.add(egui::Label::new("Select a core from the list to inspect its threads, memory mappings, disassembly and recovered notes.").wrap());
            }
            return;
        };
        let title = crate::evidence::title(ui, &record.dir, &record.label);
        crate::theme::section(ui, &title);
        let source_path = record.core.source.display().to_string();
        ui.add(egui::Label::new(&source_path).truncate())
            .on_hover_text(&source_path)
            .context_menu(|ui| {
                if ui.button("Copy core path").clicked() {
                    ui.ctx().copy_text(source_path);
                    ui.close_menu();
                }
            });
        if !record.core.warnings.is_empty() {
            egui::CollapsingHeader::new(format!("Core warnings ({})", record.core.warnings.len()))
                .show(ui, |ui| {
                    for warning in &record.core.warnings {
                        crate::activity::warning(ui, warning);
                    }
                });
        }
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Context, "Context");
            ui.selectable_value(&mut self.tab, Tab::Mappings, "Memory mappings");
            ui.selectable_value(&mut self.tab, Tab::Code, "Disassembly");
            ui.selectable_value(&mut self.tab, Tab::Notes, "Recovered notes");
        });
        ui.separator();
        match self.tab {
            Tab::Context => self.context(ui, &record),
            Tab::Mappings => self.mappings(ui, &record),
            Tab::Code => self.disassembly(ui, &record),
            Tab::Notes => notes_table(ui, &record, &mut self.notes_query),
        }
    }
    fn register_cell(&mut self, ui: &mut egui::Ui, record: &CoreRecord, name: &str, value: u64) {
        let name_color = match name {
            "rip" | "eip" | "pc" => crate::theme::error(),
            "rsp" | "esp" | "rbp" | "ebp" => crate::theme::warn(),
            "rflags" | "eflags" | "flags" => crate::theme::value(crate::theme::ValueKind::Flags),
            _ => crate::theme::value(crate::theme::ValueKind::Name),
        };
        let value_color = if matches!(name, "rflags" | "eflags" | "flags") {
            crate::theme::value(crate::theme::ValueKind::Flags)
        } else {
            crate::theme::value(crate::theme::ValueKind::Pointer)
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(name).monospace().color(name_color));
            ui.label(
                RichText::new(format!("0x{value:016x}"))
                    .monospace()
                    .color(value_color),
            );
            if ui.small_button("Copy").clicked() {
                ui.ctx().copy_text(format!("0x{value:x}"));
            }
            if (name == "rip" || name == "rsp")
                && ui
                    .small_button(egui_phosphor::regular::MEMORY)
                    .on_hover_text("View memory at this register")
                    .clicked()
            {
                if let Some(index) = record
                    .core
                    .mappings
                    .iter()
                    .position(|mapping| value >= mapping.start && value < mapping.end())
                {
                    self.mapping_index = index;
                    self.window_offset =
                        (value - record.core.mappings[index].start) / WINDOW_SIZE * WINDOW_SIZE;
                    self.page = None;
                    self.tab = Tab::Mappings;
                } else {
                    self.warning("Register points to an unmapped address.".into());
                }
            }
        });
    }

    pub(super) fn context(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        egui::ComboBox::from_id_salt("core-thread")
            .selected_text(format!(
                "Thread {}",
                record
                    .core
                    .threads
                    .get(self.thread_index)
                    .map_or(0, |thread| thread.tid)
            ))
            .show_ui(ui, |ui| {
                for (index, thread) in record.core.threads.iter().enumerate() {
                    ui.selectable_value(
                        &mut self.thread_index,
                        index,
                        format!("TID {} · signal {}", thread.tid, thread.signal),
                    );
                }
            });
        let Some(thread) = record.core.threads.get(self.thread_index) else {
            return;
        };
        ui.label(format!(
            "TID {} · parent PID {} · current signal {}",
            thread.tid, thread.parent_pid, thread.signal
        ));
        egui::ScrollArea::both().id_salt("core-registers").show(ui, |ui| {
            let groups: &[(&str, &[&str])] = &[
                ("Instruction pointer", &["rip", "eip", "pc"]),
                ("Stack and frame", &["rsp", "esp", "rbp", "ebp"]),
                ("Flags", &["rflags", "eflags", "flags"]),
                (
                    "General",
                    &[
                        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12",
                        "r13", "r14", "r15", "eax", "ebx", "ecx", "edx", "esi", "edi",
                    ],
                ),
            ];
            let mut shown = std::collections::BTreeSet::new();
            for (title, names) in groups {
                let present: Vec<_> = names
                    .iter()
                    .filter_map(|name| {
                        thread
                            .registers
                            .iter()
                            .find(|(register, _)| register == name)
                    })
                    .collect();
                if present.is_empty() {
                    continue;
                }
                ui.label(RichText::new(*title).strong().color(crate::theme::heading()));
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    for (name, value) in present {
                        shown.insert(name.clone());
                        self.register_cell(ui, record, name, *value);
                    }
                });
            }
            let other: Vec<_> = thread
                .registers
                .iter()
                .filter(|(name, _)| !shown.contains(name))
                .collect();
            if !other.is_empty() {
                ui.label(RichText::new("Other").strong().color(crate::theme::heading()));
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 16.0;
                    for (name, value) in other {
                        self.register_cell(ui, record, name, *value);
                    }
                });
            }
            ui.label("Register values are recovered evidence. Stack unwinding, pointer chains, and debugger execution are not available.");
        });
    }
    pub(super) fn mappings(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        let mut requested_page = None;
        let filter = crate::query::table_filter(
            ui,
            ("core-mappings", &record.dir),
            "memory.size > 4096",
            MAPPING_FIELDS,
            &[],
        );
        let filter_id = ui
            .id()
            .with(("table-filter", ("core-mappings", &record.dir)));
        let shown: Vec<_> = record
            .core
            .mappings
            .iter()
            .enumerate()
            .filter(|(_, mapping)| filter.keep_table(&mapping_filter_row(&record.core, mapping)))
            .map(|(index, _)| index)
            .collect();
        ui.weak(format!(
            "{} / {} mappings",
            shown.len(),
            record.core.mappings.len()
        ));
        if !shown.contains(&self.mapping_index) {
            self.mapping_index = usize::MAX;
            self.page = None;
            self.window_offset = 0;
        }
        let choices = mapping_choices(&record.core);
        let (selected_label, selected_tip) = choices
            .get(self.mapping_index)
            .map(|(label, tip)| (label.clone(), tip.clone()))
            .unwrap_or_else(|| {
                (
                    "Select a mapping".into(),
                    "Select a retained mapping matching the filter.".into(),
                )
            });
        egui::ComboBox::from_id_salt("core-mapping")
            .width(ui.available_width())
            .selected_text(selected_label)
            .show_ui(ui, |ui| {
                for &index in &shown {
                    let (label, tip) = &choices[index];
                    let row = ui
                        .selectable_value(&mut self.mapping_index, index, label)
                        .on_hover_text(tip);
                    if row.changed() {
                        self.window_offset = 0;
                        self.page = None;
                    }
                    row.context_menu(|ui| {
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &mapping_filter_row(&record.core, &record.core.mappings[index]),
                        )
                    });
                }
            })
            .response
            .on_hover_text(selected_tip);
        let Some(mapping) = record.core.mappings.get(self.mapping_index) else {
            ui.label(if shown.is_empty() {
                "No retained mapping matches this filter."
            } else {
                "Select a mapping to inspect its captured bytes."
            });
            return;
        };
        let wide = ui.available_width() >= 760.0;
        if wide {
            egui::SidePanel::right("core-mapping-info")
                .resizable(true)
                .default_width(280.0)
                .width_range(220.0..=460.0)
                .show_separator_line(true)
                .frame(egui::Frame::new().inner_margin(egui::Margin {
                    left: 12,
                    right: 8,
                    top: 4,
                    bottom: 4,
                }))
                .show_inside(ui, |ui| self.mapping_panel(ui, mapping));
        } else {
            egui::CollapsingHeader::new("Mapping details")
                .default_open(true)
                .show(ui, |ui| self.mapping_panel(ui, mapping));
        }
        let span = mapping
            .memory_size
            .saturating_sub(self.window_offset)
            .min(WINDOW_SIZE);
        ui.add(egui::Label::new(format!("Offset 0x{:x}–0x{:x} of 0x{:x}",self.window_offset,self.window_offset+span,mapping.memory_size)).wrap())
                .on_hover_text("Scroll this span, advance to another span, or jump to an offset to inspect the entire mapping.");
        let row_count = usize::try_from(span.div_ceil(16)).unwrap_or(0);
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace) + 2.0;
        egui::ScrollArea::both()
            .id_salt(("core-hex", self.mapping_index, self.window_offset))
            .show_rows(ui, row_height, row_count, |ui, range| {
                for row in range {
                    let address = mapping.start + self.window_offset + row as u64 * 16;
                    let line = crate::hex_view::row_text(address, |at| {
                        if at >= mapping.end() {
                            return crate::hex_view::Cell::Outside;
                        }
                        let value = self
                            .page
                            .as_ref()
                            .filter(|(base, data)| at >= *base && at - *base < data.len() as u64)
                            .map(|(base, data)| data[(at - *base) as usize]);
                        match value {
                            Some(Some(byte)) => crate::hex_view::Cell::Byte(byte),
                            Some(None) => crate::hex_view::Cell::Unavailable,
                            None => {
                                if requested_page.is_none() {
                                    requested_page = Some(at / PAGE_SIZE as u64 * PAGE_SIZE as u64);
                                }
                                crate::hex_view::Cell::Loading
                            }
                        }
                    });
                    crate::hex_view::paint_row(ui, line);
                }
            });
        if let Some(address) = requested_page {
            if self.job.is_none() {
                let core = record.core.clone();
                self.start(move || {
                    let size = (PAGE_SIZE * 2)
                        .min(usize::try_from(u64::MAX - address).unwrap_or(usize::MAX));
                    core.read_virtual(address, size)
                        .map(|data| Reply::Page(address, data))
                        .map_err(|error| error.to_string())
                });
            }
        }
    }
    fn mapping_panel(&mut self, ui: &mut egui::Ui, mapping: &CoreMapping) {
        ui.label(
            RichText::new("Mapping")
                .strong()
                .color(crate::theme::heading()),
        );
        ui.label(format!(
            "{} / {} octets captured",
            mapping.available_size, mapping.memory_size
        ));
        ui.add(egui::Label::new("?? = unavailable; 00 = captured zero.").wrap())
            .on_hover_text(
                "Unavailable memory can be absent, omitted by the memory filter, or truncated in the saved core.",
            );
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(self.window_offset > 0, egui::Button::new("Previous span"))
                .clicked()
            {
                self.window_offset = self.window_offset.saturating_sub(WINDOW_SIZE);
                self.page = None;
            }
            if ui
                .add_enabled(
                    self.window_offset.saturating_add(WINDOW_SIZE) < mapping.memory_size,
                    egui::Button::new("Next span"),
                )
                .clicked()
            {
                self.window_offset = self.window_offset.saturating_add(WINDOW_SIZE);
                self.page = None;
            }
        });
        ui.label("Mapping offset (hex)");
        ui.horizontal_wrapped(|ui| {
            let input_width = ui.available_width().min(160.0);
            ui.add(egui::TextEdit::singleline(&mut self.jump).desired_width(input_width));
            if ui.button("Jump").clicked() {
                match parse_address(&self.jump) {
                    Ok(offset) if offset < mapping.memory_size => {
                        self.window_offset = offset / 16 * 16;
                        self.page = None;
                    }
                    _ => self.warning("Offset must lie inside the selected mapping.".into()),
                }
            }
        });
    }
}

pub(super) fn mapping_filter_row(
    core: &CoreDump,
    mapping: &CoreMapping,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let paths: Vec<_> = core
        .files
        .iter()
        .filter(|file| {
            file.start < mapping.end() && mapping.start < file.end && !file.path.is_empty()
        })
        .map(|file| file.path.clone())
        .collect();
    vec![
        ("memory.start", V::Number(i128::from(mapping.start))),
        ("memory.end", V::Number(i128::from(mapping.end()))),
        ("memory.size", V::Number(i128::from(mapping.memory_size))),
        (
            "memory.captured_size",
            V::Number(i128::from(mapping.available_size)),
        ),
        ("memory.permissions", V::Text(mapping.permissions())),
        (
            "memory.path",
            if paths.is_empty() {
                V::Missing
            } else {
                V::List(paths)
            },
        ),
        ("memory.available", V::Bool(mapping.available_size > 0)),
    ]
}

pub(super) fn function_filter_row(
    function: &CoreFunction,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    vec![
        ("function.name", V::Text(function.name.clone())),
        ("function.address", V::Number(i128::from(function.address))),
        ("function.size", V::Number(i128::from(function.size))),
    ]
}

fn mapping_name(core: &CoreDump, mapping: &CoreMapping) -> String {
    let mut paths = Vec::new();
    for file in &core.files {
        let path = file.path.trim();
        if path.is_empty() {
            continue;
        }
        if file.start < mapping.end()
            && mapping.start < file.end
            && !paths.iter().any(|existing| existing == path)
        {
            paths.push(path.to_owned());
        }
    }
    match paths.as_slice() {
        [] => "unknown".into(),
        [one] => one.clone(),
        [first, rest @ ..] => format!("{first} (+{} file extents)", rest.len()),
    }
}

pub(super) fn mapping_choices(core: &CoreDump) -> Vec<(String, String)> {
    let names: Vec<String> = core
        .mappings
        .iter()
        .map(|mapping| mapping_name(core, mapping))
        .collect();
    core.mappings
        .iter()
        .zip(names)
        .map(|(mapping, name)| {
            let permissions = mapping.permissions();
            let shown = if name == "unknown" || name.starts_with("unknown ") {
                "unknown".to_owned()
            } else if name.ends_with(" file extents)") {
                name.clone()
            } else {
                Path::new(&name)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&name)
                    .to_owned()
            };
            let label = format!(
                "mmap {:x}-{:x} {permissions} [{shown}]",
                mapping.start,
                mapping.end()
            );
            let label = ellipsize(&label, 96);
            let tip = if shown == "unknown" {
                format!("{name}\nNo NT_FILE name overlaps this mapping.")
            } else {
                name
            };
            (label, tip)
        })
        .collect()
}

fn ellipsize(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let keep = limit.saturating_sub(1);
    let end = text
        .char_indices()
        .nth(keep)
        .map(|(index, _)| index)
        .unwrap_or(text.len());
    format!("{}…", &text[..end])
}

/// A typed address is used only when a captured byte exists there.
/// Otherwise the instruction pointer is used when it is captured, then the
/// first executable mapping that actually contains captured bytes.
pub(super) fn captured_code_origin(core: &CoreDump, typed: &str) -> Result<u64, String> {
    if let Ok(address) = parse_address(typed) {
        if captured_byte(core, address) {
            return Ok(address);
        }
    }
    if let Some(thread) = core.threads.first() {
        for name in ["rip", "eip", "pc"] {
            if let Some(address) = thread.register(name) {
                if captured_byte(core, address) {
                    return Ok(address);
                }
            }
        }
    }
    core.mappings
        .iter()
        .find(|mapping| mapping.flags & 1 != 0 && mapping.available_size > 0)
        .map(|mapping| mapping.start)
        .ok_or_else(|| {
            "No captured executable bytes. This core has no executable mapping with captured data."
                .to_owned()
        })
}

pub(super) fn captured_byte(core: &CoreDump, address: u64) -> bool {
    core.mappings.iter().any(|mapping| {
        let available = mapping.available_size.min(mapping.memory_size);
        let end = mapping.start.saturating_add(available);
        address >= mapping.start && address < end
    })
}

fn notes_table(ui: &mut egui::Ui, record: &CoreRecord, query: &mut String) {
    use egui_extras::{Column, TableBuilder};
    const EM_DASH: &str = "—";
    ui.label(
        "Other notes are inventoried below; floating-point/XSAVE payloads are not decoded here.",
    );
    crate::query::filter_edit(
        ui,
        query,
        "note.name == CORE",
        ui.available_width(),
        crate::query::FilterScope::Table(NOTE_FIELDS),
    );
    let filter = crate::query::applied_table(ui, query, NOTE_FIELDS, ("core-notes", &record.dir));
    if crate::query::compile_table(query, NOTE_FIELDS)
        .error
        .is_none()
    {
        crate::query::remember_valid_filter(ui, query);
    }
    #[derive(Clone)]
    struct NoteRow {
        kind: &'static str,
        name: String,
        thread: &'static str,
        value: String,
        source: &'static str,
        availability: &'static str,
        number: Option<u64>,
    }
    let mut rows = Vec::new();
    for (key, value) in &record.core.auxv {
        rows.push(NoteRow {
            kind: "AUXV",
            name: key.to_string(),
            thread: EM_DASH,
            value: format!("0x{value:x}"),
            source: "NT_AUXV",
            availability: "captured",
            number: Some(*value),
        });
    }
    for note in &record.core.notes {
        rows.push(NoteRow {
            kind: "Note",
            name: note.clone(),
            thread: EM_DASH,
            value: EM_DASH.to_string(),
            source: "core note",
            availability: "captured",
            number: None,
        });
    }
    for file in &record.core.files {
        rows.push(NoteRow {
            kind: "File",
            name: file.path.clone(),
            thread: EM_DASH,
            value: format!(
                "{:016x}-{:016x} file+0x{:x}",
                file.start, file.end, file.file_offset
            ),
            source: "NT_FILE",
            availability: "captured",
            number: None,
        });
    }
    let total = rows.len();
    impl NoteRow {
        fn values(&self) -> Vec<(&'static str, crate::query::RowValue)> {
            let row = self;
            use crate::query::RowValue;
            vec![
                ("note.kind", RowValue::Text(row.kind.into())),
                ("note.name", RowValue::Text(row.name.clone())),
                ("note.thread_id", RowValue::Missing),
                ("note.source", RowValue::Text(row.source.into())),
                (
                    "note.complete",
                    RowValue::Bool(row.availability == "captured"),
                ),
                (
                    "note.summary",
                    RowValue::Text(if row.value == EM_DASH {
                        row.name.clone()
                    } else {
                        row.value.clone()
                    }),
                ),
                ("kind", RowValue::Text(row.kind.into())),
                ("name", RowValue::Text(row.name.clone())),
                ("thread", RowValue::Missing),
                (
                    "value",
                    if row.value == EM_DASH {
                        RowValue::Missing
                    } else {
                        RowValue::Text(row.value.clone())
                    },
                ),
                (
                    "value.num",
                    row.number.map_or(RowValue::Missing, |value| {
                        RowValue::Number(i128::from(value))
                    }),
                ),
                ("source", RowValue::Text(row.source.into())),
                ("availability", RowValue::Text(row.availability.into())),
            ]
        }
    }
    rows.retain(|row| filter.keep_table(&row.values()));
    let row_count = rows.len();
    ui.weak(format!("{row_count} / {total} notes"));
    let selection_id = ui.id().with(("core-note-detail", &record.dir));
    if ui
        .data(|data| data.get_temp::<NoteRow>(selection_id))
        .is_some_and(|selected| !filter.keep_table(&selected.values()))
    {
        ui.data_mut(|data| data.remove::<NoteRow>(selection_id));
    }

    let selected_detail = ui.data(|data| data.get_temp::<NoteRow>(selection_id));
    let detail_height = if selected_detail.is_some() {
        160.0
    } else {
        0.0
    };
    let header_height =
        ui.text_style_height(&egui::TextStyle::Body).max(20.0) + ui.spacing().item_spacing.y;
    let table_height = (ui.available_height() - detail_height - header_height).max(80.0);
    TableBuilder::new(ui)
        .max_scroll_height(table_height)
        .striped(true)
        .sense(egui::Sense::click())
        .column(Column::auto().at_least(64.0))
        .column(Column::remainder().at_least(120.0))
        .column(Column::auto().at_least(64.0))
        .column(Column::remainder().at_least(160.0))
        .column(Column::auto().at_least(80.0))
        .column(Column::auto().at_least(88.0))
        .header(20.0, |mut header| {
            for title in ["Kind", "Name", "Thread", "Value", "Source", "Availability"] {
                header.col(|ui| {
                    ui.strong(title);
                });
            }
        })
        .body(|body| {
            body.rows(18.0, row_count, |mut row| {
                let note = &rows[row.index()];
                for text in [
                    note.kind,
                    note.name.as_str(),
                    note.thread,
                    note.value.as_str(),
                    note.source,
                    note.availability,
                ] {
                    row.col(|ui| {
                        ui.add(egui::Label::new(text).truncate())
                            .on_hover_text(text);
                    });
                }
                if row.response().clicked() {
                    row.response().request_focus();
                    row.response().ctx.data_mut(|data| {
                        data.insert_temp(selection_id, note.clone());
                    });
                }
                row.response().context_menu(|ui| {
                    crate::query::value_menu(
                        ui,
                        "name",
                        &crate::query::RowValue::Text(note.name.clone()),
                        query,
                    );
                    ui.menu_button("Filter by field", |ui| {
                        for (field, value) in note.values() {
                            ui.menu_button(field, |ui| {
                                crate::query::value_menu(ui, field, &value, query)
                            });
                        }
                    });
                    if ui.button("Copy complete note").clicked() {
                        ui.ctx().copy_text(format!(
                            "{}\t{}\t{}\t{}\t{}\t{}",
                            note.kind,
                            note.name,
                            note.thread,
                            note.value,
                            note.source,
                            note.availability
                        ));
                        ui.close_menu();
                    }
                });
            });
        });
    if let Some(note) = ui.data(|data| data.get_temp::<NoteRow>(selection_id)) {
        let detail = format!(
            "{} · {} · {}\n{}",
            note.kind, note.name, note.source, note.value
        );
        egui::CollapsingHeader::new("Selected note")
            .default_open(true)
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt(("core-note-detail-scroll", &record.dir))
                    .max_height(128.0)
                    .show(ui, |ui| {
                        ui.set_max_width((ui.clip_rect().right() - ui.max_rect().left()).max(80.0));
                        ui.add(egui::Label::new(detail).selectable(true).wrap());
                    });
            });
    }
}

fn parse_address(text: &str) -> Result<u64, String> {
    u64::from_str_radix(text.trim().trim_start_matches("0x"), 16)
        .map_err(|error| format!("Invalid hexadecimal address: {error}"))
}

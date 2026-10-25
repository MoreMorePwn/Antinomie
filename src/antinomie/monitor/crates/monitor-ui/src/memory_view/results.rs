// SPDX-License-Identifier: GPL-3.0-only
//! Loading a saved plugin result and showing it as a table.
use super::*;

impl MemoryView {
    pub(super) fn open_run(&mut self, id: Option<String>) {
        if self.selected_run != id {
            self.sort = None;
            self.filter.clear();
        }
        self.selected_run = id.clone();
        self.selected_row = None;
        self.show_log = false;
        self.result = None;
        let Some(run) = id.and_then(|id| self.runs.iter().find(|run| run.id == id).cloned()) else {
            self.cancel_result_load();
            return;
        };
        if self.jobs.iter().any(|job| job.run.id == run.id) {
            self.cancel_result_load();
            return;
        }
        self.request_result(ResultRequest {
            vm_id: self.dump().map(|dump| dump.vm_id.clone()),
            boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
            run_id: run.id.clone(),
            source: run.output(),
            query: self.filter.clone(),
            sort: self.sort,
            start: 0,
        });
    }

    pub(super) fn cancel_result_load(&mut self) {
        if let Some(load) = &self.loading {
            load.cancel.store(true, Ordering::Relaxed);
        }
        self.pending_result = None;
    }

    fn request_result(&mut self, request: ResultRequest) {
        if self.pending_result.as_ref() == Some(&request) {
            return;
        }
        if self
            .loading
            .as_ref()
            .is_some_and(|load| load.request == request && !load.cancel.load(Ordering::Relaxed))
        {
            return;
        }
        if let Some(load) = &self.loading {
            load.cancel.store(true, Ordering::Relaxed);
        }
        self.pending_result = Some(request);
        self.selected_row = None;
        self.start_result_load();
    }

    pub(super) fn start_result_load(&mut self) {
        if self.loading.is_some() {
            return;
        }
        let Some(request) = self.pending_result.take() else {
            return;
        };
        let Some(run) = self
            .runs
            .iter()
            .find(|run| run.id == request.run_id)
            .cloned()
        else {
            return;
        };
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let worker_request = request.clone();
        match std::thread::Builder::new()
            .name("memory-result-query".into())
            .spawn(move || {
                let result = load_result(run, &worker_request, &worker_cancel);
                let _ = sender.send(result);
            }) {
            Ok(_) => {
                self.loading = Some(ResultLoad {
                    request,
                    cancel,
                    receiver,
                })
            }
            Err(error) => self.status = Some((format!("Cannot start result query: {error}"), true)),
        }
    }

    pub(super) fn result_view(&mut self, ui: &mut egui::Ui, dump: &MemoryDump, font_size: f32) {
        let Some(run_id) = self.selected_run.clone() else {
            empty_state(ui, "Run a plugin.");
            return;
        };
        if let Some(job) = self.jobs.iter().find(|job| job.run.id == run_id) {
            let progress = job.progress();
            ui.add_space(12.0);
            ui.vertical_centered(|ui| {
                crate::theme::spinner(ui);
                ui.label(format!(
                    "Running {} on {}",
                    job.run.plugin,
                    dump_title(dump)
                ));
                // MemNixFS reports no percentage: only its current step.
                let counted = job.run.analyzer == Analyzer::Volatility;
                ui.colored_label(
                    theme::muted(),
                    if progress.step.is_empty() {
                        format!("Starting {}…", job.run.analyzer.product())
                    } else if counted {
                        format!("{:.0}% {}", progress.percent, progress.step)
                    } else {
                        progress.step.clone()
                    },
                );
                if counted {
                    ui.add(egui::ProgressBar::new(progress.percent / 100.0).desired_width(320.0));
                } else {
                    ui.spinner();
                }
                if ui.button("Cancel").clicked() {
                    job.cancel();
                }
            });
            return;
        }
        if self
            .result
            .as_ref()
            .is_none_or(|result| result.run.id != run_id)
        {
            let mut cancel = false;
            let mut retry = false;
            ui.horizontal(|ui| {
                if self.loading.is_some() {
                    crate::theme::spinner(ui);
                    ui.colored_label(theme::muted(), "Loading the result…");
                    cancel = ui.button("Cancel query").clicked();
                } else {
                    ui.label("Result not loaded.");
                    retry = ui.button("Load result").clicked();
                }
            });
            if cancel {
                self.cancel_result_load();
            }
            if retry {
                self.open_run(Some(run_id.clone()));
            }
            return;
        }
        let mut request = None;
        if let Some(result) = self.result.as_ref() {
            if let Ok(table) = &result.table {
                let annotation = crate::evidence::annotation(ui, &result.run.dir);
                let mut record = plugin_result_record(&result.run, annotation.as_ref());
                add_dump_identity(
                    &mut record,
                    self.dump().map(|dump| dump.vm_id.as_str()),
                    self.dump().and_then(|dump| dump.boot_id.as_deref()),
                );
                let tags: &[String] = annotation
                    .as_ref()
                    .map_or(&[], |annotation| annotation.tags.as_slice());
                let names = column_fields(&table.columns);
                let fields = result_fields(&names, &table.columns);
                crate::query::filter_edit_fields(
                    ui,
                    &mut self.filter,
                    "tag == malware",
                    ui.available_width(),
                    &fields,
                    tags,
                );
                let compiled = crate::query::compile_table(&self.filter, &fields);
                if let Some(error) = compiled.error {
                    crate::activity::warning(
                        ui,
                        format!("{error} · showing the last valid filter"),
                    );
                } else {
                    crate::query::remember_valid_filter(ui, &self.filter);
                    if result.filter != self.filter
                        || result.sort != self.sort
                        || result.record != record
                    {
                        request = Some(ResultRequest {
                            vm_id: self.dump().map(|dump| dump.vm_id.clone()),
                            boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
                            run_id: result.run.id.clone(),
                            source: result.run.output(),
                            query: self.filter.clone(),
                            sort: self.sort,
                            start: 0,
                        });
                    }
                }
                let page_count = result.total.div_ceil(RESULT_PAGE_LEN as u64).max(1);
                let page_number = result.start / RESULT_PAGE_LEN as u64 + 1;
                let mut start = None;
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .add_enabled(
                            self.loading.is_none() && result.start > 0,
                            egui::Button::new("Previous"),
                        )
                        .clicked()
                    {
                        start = Some(result.start.saturating_sub(RESULT_PAGE_LEN as u64));
                    }
                    ui.label(format!(
                        "Page {page_number}/{page_count} · {} matching / {} retained rows",
                        result.total, result.source_rows
                    ));
                    let mut page = page_number;
                    ui.label("Go to page");
                    if ui
                        .add_enabled(
                            self.loading.is_none(),
                            egui::DragValue::new(&mut page).range(1..=page_count),
                        )
                        .changed()
                    {
                        start = Some((page - 1).saturating_mul(RESULT_PAGE_LEN as u64));
                    }
                    if ui
                        .add_enabled(
                            self.loading.is_none()
                                && result.start + (table.rows.len() as u64) < result.total,
                            egui::Button::new("Next"),
                        )
                        .clicked()
                    {
                        start = Some(result.start + RESULT_PAGE_LEN as u64);
                    }
                    if ui
                        .add_enabled(self.loading.is_none(), egui::Button::new("Refresh"))
                        .clicked()
                    {
                        start = Some(result.start);
                    }
                });
                if let Some(start) = start {
                    request = Some(ResultRequest {
                        vm_id: self.dump().map(|dump| dump.vm_id.clone()),
                        boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
                        run_id: result.run.id.clone(),
                        source: result.run.output(),
                        query: result.filter.clone(),
                        sort: result.sort,
                        start,
                    });
                }
                if result.skipped_lines > 0 {
                    crate::activity::warning(
                        ui,
                        format!(
                            "{} incomplete or invalid saved lines were unavailable",
                            result.skipped_lines
                        ),
                    );
                }
            } else if ui.button("Retry result").clicked() {
                request = Some(ResultRequest {
                    vm_id: self.dump().map(|dump| dump.vm_id.clone()),
                    boot_id: self.dump().and_then(|dump| dump.boot_id.clone()),
                    run_id: result.run.id.clone(),
                    source: result.run.output(),
                    query: self.filter.clone(),
                    sort: self.sort,
                    start: 0,
                });
            }
        }
        if let Some(request) = request {
            self.request_result(request);
        }
        if self.loading.is_some() {
            let mut cancel = false;
            ui.horizontal_wrapped(|ui| {
                crate::theme::spinner(ui);
                ui.label("Querying every retained row…");
                cancel = ui.button("Cancel query").clicked();
            });
            if cancel {
                self.cancel_result_load();
                if let Some(result) = &self.result {
                    self.filter.clone_from(&result.filter);
                    self.sort = result.sort;
                }
            }
        }
        let Some(result) = self.result.as_mut() else {
            return;
        };
        if let Some(error) = &result.filter_error {
            crate::activity::warning(ui, error);
        }
        let mut status = None;
        // The controls keep their size; the title takes what is left.
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.toggle_value(&mut self.show_log, "Messages")
                    .on_hover_text(format!(
                        "{}'s messages for this run",
                        result.run.analyzer.label()
                    ));
                let text = self.text_view;
                if crate::widgets::tab(ui, text, &crate::widgets::TabItem::new("Text"))
                    .on_hover_text("The result as plain text")
                    .clicked()
                {
                    self.text_view = true;
                }
                if crate::widgets::tab(ui, !text, &crate::widgets::TabItem::new("Table"))
                    .on_hover_text("Columns colored by type; click a column name to sort")
                    .clicked()
                {
                    self.text_view = false;
                }
                ui.separator();
                let files = std::fs::read_dir(result.run.files())
                    .map(|mut entries| entries.next().is_some())
                    .unwrap_or(false);
                if files
                    && ui
                        .button(format!("{} Files", egui_phosphor::regular::FOLDER_OPEN))
                        .on_hover_text("Open the files this run wrote")
                        .clicked()
                {
                    if let Err(error) = open_directory(&result.run.files()) {
                        status = Some(error);
                    }
                }
                if let Ok(table) = &result.table {
                    if ui
                        .button(format!("{} Copy", egui_phosphor::regular::COPY))
                        .on_hover_text(if self.text_view {
                            "Copy this page as plain text"
                        } else {
                            "Copy this page as tab-separated text"
                        })
                        .clicked()
                    {
                        ui.ctx().copy_text(if self.text_view {
                            memory::result_text(table, &result.shown)
                        } else {
                            result_tsv(&table.columns, table, &result.shown)
                        });
                    }
                }
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    let mut title = egui::text::LayoutJob::default();
                    let mono = theme::mono(font_size - 1.0);
                    title.append(
                        &result.run.plugin,
                        0.0,
                        egui::TextFormat::simple(mono.clone(), theme::heading()),
                    );
                    if !result.run.args.is_empty() {
                        title.append(
                            &args_summary(&result.run),
                            8.0,
                            egui::TextFormat::simple(mono, theme::value(ValueKind::Flags)),
                        );
                    }
                    if let Ok(table) = &result.table {
                        let rows = format!("{} rows on this page", table.rows.len());
                        title.append(
                            &rows,
                            10.0,
                            egui::TextFormat::simple(
                                egui::TextStyle::Body.resolve(ui.style()),
                                theme::muted(),
                            ),
                        );
                    }
                    let hover = title.text.clone();
                    ui.add(egui::Label::new(title).truncate())
                        .on_hover_text(hover);
                });
            })
        });
        if let Some(error) = status {
            self.status = Some((error, true));
        }
        if result.run.state == RunState::Failed {
            crate::activity::error(
                ui,
                result
                    .run
                    .error
                    .clone()
                    .unwrap_or_else(|| format!("{} failed", result.run.analyzer.product())),
            );
            self.show_log = true;
        }
        // A finished result that is known to miss something says so.
        if result.run.state == RunState::Finished && !result.run.partial.is_empty() {
            crate::activity::warning_details(
                ui,
                format!(
                    "Partial result: {}",
                    result.run.partial.first().map_or("", String::as_str)
                ),
                result.run.partial.join("\n"),
            );
        }
        if let Some(format) = &result.run.dump_format {
            ui.colored_label(
                theme::muted(),
                format!(
                    "{} {} · dump read as {format}",
                    result.run.analyzer.label(),
                    result.run.tool_version.as_deref().unwrap_or("")
                ),
            );
        }
        if self.show_log {
            egui::TopBottomPanel::bottom("memory_log")
                .resizable(true)
                .default_height(140.0)
                .show_inside(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt("memory_log_text")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            let text = if result.log.trim().is_empty() {
                                "No messages"
                            } else {
                                result.log.as_str()
                            };
                            ui.label(
                                RichText::new(text)
                                    .font(theme::mono(font_size - 2.0))
                                    .color(theme::muted()),
                            );
                        });
                });
        }
        let table = match &result.table {
            Ok(table) => table,
            Err(error) => {
                // A failed run's reason is shown above.
                if result.run.state != RunState::Failed {
                    crate::activity::warning(ui, format!("No result saved: {error}"));
                }
                return;
            }
        };
        if table.columns.is_empty() {
            ui.colored_label(theme::muted(), "The plugin wrote no result.");
            return;
        }
        if table.rows.is_empty() {
            ui.colored_label(
                theme::muted(),
                if result.source_rows == 0 {
                    "The plugin saved no result rows."
                } else {
                    "No retained row matches the filter."
                },
            );
        }
        let mono = theme::mono(font_size - 1.0);
        if self.text_view {
            let lines = result.text.get_or_insert_with(|| {
                memory::result_text(table, &result.shown)
                    .lines()
                    .map(str::to_owned)
                    .collect()
            });
            let line_height = ui.fonts(|fonts| fonts.row_height(&mono)) + 2.0;
            egui::Frame::new()
                .fill(theme::bg())
                .corner_radius(4.0)
                .inner_margin(egui::Margin::symmetric(10, 6))
                .show(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt(("memory_result_text", &result.run.id))
                        .auto_shrink([false, false])
                        .show_rows(ui, line_height, lines.len(), |ui, range| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for line in &lines[range] {
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(expand_tabs(line)).font(mono.clone()),
                                    )
                                    .extend(),
                                );
                            }
                        });
                });
            return;
        }
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let row_height = theme::row_height(font_size);
        let widths = column_widths(table, char_width);
        let total: f32 = widths.iter().sum();
        // Wider than the panel: every column keeps its width and the table
        // scrolls sideways; otherwise the last column takes the rest.
        let fits = total <= ui.available_width();
        // Sorted rows lose their tree: shown flat, with no branches.
        let selected_row = self.selected_row;
        let mut clicked_row = None;
        let mut clicked_header = None;
        egui::ScrollArea::horizontal()
            .id_salt(("memory_result_wide", &result.run.id))
            .auto_shrink([false, false])
            .show(ui, |ui| {
                crate::widgets::table::begin(ui);
                let mut builder = TableBuilder::new(ui)
                    .id_salt(("memory_result", &result.run.id))
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .max_scroll_height(f32::INFINITY)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false]);
                for (index, width) in widths.iter().enumerate() {
                    builder = if index + 1 == widths.len() && fits {
                        builder.column(
                            Column::remainder()
                                .at_least(width.min(char_width * 12.0))
                                .clip(true),
                        )
                    } else {
                        builder.column(
                            Column::initial(*width)
                                .at_least(char_width * 4.0)
                                .clip(true),
                        )
                    };
                }
                builder
                    .header(row_height + 4.0, |mut header| {
                        for (index, column) in table.columns.iter().enumerate() {
                            header.col(|ui| {
                                crate::widgets::table::head_bg(ui);
                                let arrow = match result.sort {
                                    Some(sort) if sort.column == index && sort.descending => {
                                        format!(" {}", egui_phosphor::regular::CARET_DOWN)
                                    }
                                    Some(sort) if sort.column == index => {
                                        format!(" {}", egui_phosphor::regular::CARET_UP)
                                    }
                                    _ => String::new(),
                                };
                                let response = ui
                                    .add(
                                        egui::Label::new(
                                            RichText::new(format!("{}{arrow}", column.name))
                                                .strong()
                                                .color(theme::muted()),
                                        )
                                        .truncate()
                                        .sense(egui::Sense::click()),
                                    )
                                    .on_hover_text(
                                        "Sort: ascending, descending, then as the analyser gave it",
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand);
                                if response.clicked() {
                                    clicked_header = Some(index);
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_height, result.shown.len(), |mut row| {
                            let row_index = result.shown[row.index()];
                            let data = &table.rows[row_index];
                            let row_selected = selected_row == Some(row_index);
                            row.set_selected(row_selected);
                            let branch = result.branches.get(row.index());
                            for (index, (value, column)) in
                                data.values.iter().zip(&table.columns).enumerate()
                            {
                                row.col(|ui| {
                                    crate::widgets::table::row_mark(
                                        ui,
                                        if row_selected && index == 0 {
                                            crate::widgets::table::Mark::Selected
                                        } else {
                                            crate::widgets::table::Mark::None
                                        },
                                    );
                                    if let Some(branch) = branch.filter(|_| index == 0) {
                                        let reach = ui.spacing().item_spacing.y * 0.5;
                                        let lines = ui.max_rect().expand2(egui::vec2(0.0, reach));
                                        branch.paint(ui.painter(), lines, char_width);
                                        ui.add_space(branch.width(char_width));
                                    }
                                    let text = memory::value_text(column.kind, value);
                                    let mut label = RichText::new(&text)
                                        .font(mono.clone())
                                        .color(value_color(column.kind, value));
                                    if value.get("absent").is_some() {
                                        label = label.italics();
                                    }
                                    let response = ui.add(
                                        egui::Label::new(label)
                                            .truncate()
                                            .sense(egui::Sense::click()),
                                    );
                                    if response.clicked() {
                                        clicked_row = Some(row_index);
                                    }
                                    response.context_menu(|ui| {
                                        if ui.button("Copy value").clicked() {
                                            ui.ctx().copy_text(text.clone());
                                            ui.close_menu();
                                        }
                                        if ui.button("Copy row").clicked() {
                                            ui.ctx().copy_text(row_text(&table.columns, data));
                                            ui.close_menu();
                                        }
                                        let names = column_fields(&table.columns);
                                        let mut values = result_row(&names, &table.columns, data);
                                        values.extend(result.record.iter().cloned());
                                        if let Some((field, value)) = values.get(index + 1) {
                                            crate::query::value_menu(
                                                ui,
                                                field,
                                                value,
                                                &mut self.filter,
                                            );
                                        }
                                        ui.menu_button("Filter result metadata", |ui| {
                                            for (field, value) in &result.record {
                                                ui.menu_button(*field, |ui| {
                                                    crate::query::value_menu(
                                                        ui,
                                                        field,
                                                        value,
                                                        &mut self.filter,
                                                    )
                                                });
                                            }
                                        });
                                    });
                                });
                            }
                            if row.response().clicked() {
                                clicked_row = Some(row_index);
                            }
                        });
                    });
            });
        if clicked_row.is_some() {
            self.selected_row = clicked_row;
        }
        if let Some(column) = clicked_header {
            self.sort = next_sort(self.sort, column);
        }
    }
}

/// The next order after a click on `column`'s header.
pub(super) fn next_sort(sort: Option<Sort>, column: usize) -> Option<Sort> {
    match sort {
        Some(Sort {
            column: current,
            descending: false,
        }) if current == column => Some(Sort {
            column,
            descending: true,
        }),
        Some(Sort {
            column: current,
            descending: true,
        }) if current == column => None,
        _ => Some(Sort {
            column,
            descending: false,
        }),
    }
}

pub(super) fn value_color(kind: ColumnKind, value: &serde_json::Value) -> egui::Color32 {
    if value.is_null() || value.get("absent").is_some() {
        return theme::muted();
    }
    match kind {
        ColumnKind::Hex | ColumnKind::Bin => theme::value(ValueKind::Pointer),
        ColumnKind::Int => theme::value(ValueKind::Number),
        ColumnKind::Bool => theme::value(ValueKind::Flags),
        ColumnKind::Bytes | ColumnKind::Disasm => theme::value(ValueKind::Text),
        ColumnKind::Time => theme::muted(),
        ColumnKind::Str => theme::text(),
    }
}

/// The tree branches of the shown rows, a tree of the rows a filter left.
pub(super) fn result_branches(
    table: &ResultTable,
    shown: &[usize],
) -> Vec<crate::tree_lines::Prefix> {
    crate::tree_lines::prefixes(
        &shown
            .iter()
            .map(|&row| usize::from(table.rows[row].depth))
            .collect::<Vec<_>>(),
    )
}

pub(super) fn load_result(
    run: PluginRun,
    request: &ResultRequest,
    cancel: &AtomicBool,
) -> LoadedResult {
    let annotation = antinomie_monitor_core::annotations::load(&run.dir);
    let mut record = plugin_result_record(&run, annotation.as_ref().ok());
    add_dump_identity(
        &mut record,
        request.vm_id.as_deref(),
        request.boot_id.as_deref(),
    );
    let mut compiled = None;
    let mut names = Vec::new();
    let mut filter_error = None;
    let page = memory::read_result_page_with(
        &request.source,
        request.start,
        RESULT_PAGE_LEN,
        request.sort.map(|sort| (sort.column, sort.descending)),
        cancel,
        |columns, row| {
            if compiled.is_none() {
                names = column_fields(columns);
                let fields = result_fields(&names, columns);
                let query = crate::query::compile_table(&request.query, &fields);
                filter_error = query.error.clone();
                compiled = Some(query);
            }
            compiled.as_ref().is_some_and(|query| {
                let mut values = result_row(&names, columns, row);
                values.extend(record.iter().cloned());
                query.keep_table(&values)
            })
        },
    );
    let (table, total, source_rows, start, skipped_lines) = match page {
        Ok(page) => (
            Ok(page.table),
            page.total,
            page.source_rows,
            page.start,
            page.skipped_lines,
        ),
        Err(error) => (Err(error), 0, 0, request.start, 0),
    };
    let mut data = Vec::new();
    let mut log = match std::fs::File::open(run.log()) {
        Ok(file) => match file.take(RESULT_LOG_SIZE + 1).read_to_end(&mut data) {
            Ok(_) => {
                let truncated = data.len() as u64 > RESULT_LOG_SIZE;
                data.truncate(RESULT_LOG_SIZE as usize);
                let mut text = String::from_utf8_lossy(&data).into_owned();
                if truncated {
                    text.push_str("\nLog preview truncated at 2 MiB; open the result directory for the complete log.");
                }
                text
            }
            Err(error) => format!("Cannot read retained log: {error}"),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => format!("Cannot read retained log: {error}"),
    };
    if let Err(error) = annotation {
        log.push_str(&format!("\nAnnotation unavailable: {error}"));
    }
    let shown: Vec<usize> = table
        .as_ref()
        .map(|table| (0..table.rows.len()).collect())
        .unwrap_or_default();
    let branches = match (&table, request.sort) {
        (Ok(table), None) => result_branches(table, &shown),
        _ => Vec::new(),
    };
    LoadedResult {
        run,
        table,
        shown,
        branches,
        filter: request.query.clone(),
        filter_error,
        sort: request.sort,
        text: None,
        log,
        total,
        source_rows,
        start,
        skipped_lines,
        record,
    }
}

pub(super) fn column_fields(columns: &[ResultColumn]) -> Vec<String> {
    let mut used = std::collections::BTreeSet::from(["depth".to_owned()]);
    columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let mut name: String = column
                .name
                .to_lowercase()
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || ch == '_' {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect();
            if name.is_empty()
                || name.starts_with(|ch: char| ch.is_ascii_digit())
                || matches!(
                    name.as_str(),
                    "and" | "or" | "not" | "contains" | "in" | "exists" | "missing" | "lower"
                )
            {
                name = format!("column_{index}_{name}");
            }
            let base = name.clone();
            let mut suffix = 0;
            while !used.insert(name.clone()) {
                name = format!("{base}_{index}_{suffix}");
                suffix += 1;
            }
            name
        })
        .collect()
}

pub(super) fn result_fields<'a>(
    names: &'a [String],
    columns: &'a [ResultColumn],
) -> Vec<crate::query::FieldSpec<'a>> {
    let mut fields = vec![crate::query::FieldSpec::number(
        "depth",
        "Result tree depth",
    )];
    fields.extend(crate::query::LABEL_FIELDS);
    fields.extend(
        names
            .iter()
            .zip(columns)
            .map(|(name, column)| crate::query::FieldSpec {
                name,
                detail: &column.name,
                kind: match column.kind {
                    ColumnKind::Int | ColumnKind::Hex | ColumnKind::Bin => "integer",
                    ColumnKind::Bool => "boolean",
                    _ => "text",
                },
            }),
    );
    fields
}

pub(super) fn result_row<'a>(
    names: &'a [String],
    columns: &[ResultColumn],
    row: &memory::ResultRow,
) -> Vec<(&'a str, crate::query::RowValue)> {
    use crate::query::RowValue;
    let mut values = vec![("depth", RowValue::Number(i128::from(row.depth)))];
    values.extend(
        names
            .iter()
            .zip(columns)
            .enumerate()
            .map(|(index, (name, column))| {
                let value = row.values.get(index);
                let value = match value {
                    None | Some(serde_json::Value::Null) => RowValue::Missing,
                    Some(value) if value.get("absent").is_some() => RowValue::Missing,
                    Some(value) => match column.kind {
                        ColumnKind::Int | ColumnKind::Hex | ColumnKind::Bin => value
                            .as_i64()
                            .map(i128::from)
                            .or_else(|| value.as_u64().map(i128::from))
                            .or_else(|| {
                                value.as_str().and_then(|text| {
                                    text.strip_prefix("0x").map_or_else(
                                        || text.parse().ok(),
                                        |text| i128::from_str_radix(text, 16).ok(),
                                    )
                                })
                            })
                            .map_or(RowValue::Missing, RowValue::Number),
                        ColumnKind::Bool => {
                            value.as_bool().map_or(RowValue::Missing, RowValue::Bool)
                        }
                        _ => RowValue::Text(memory::value_text(column.kind, value)),
                    },
                };
                (name.as_str(), value)
            }),
    );
    values
}

/// One row as tab-separated text.
pub(super) fn row_text(columns: &[ResultColumn], row: &memory::ResultRow) -> String {
    row.values
        .iter()
        .zip(columns)
        .map(|(value, column)| memory::value_text(column.kind, value))
        .collect::<Vec<_>>()
        .join("\t")
}

/// The result as tab-separated text, with its column names.
pub(super) fn result_tsv(columns: &[ResultColumn], table: &ResultTable, rows: &[usize]) -> String {
    let mut text = columns
        .iter()
        .map(|column| column.name.as_str())
        .collect::<Vec<_>>()
        .join("\t");
    for &index in rows {
        let row = &table.rows[index];
        text.push('\n');
        text.push_str(&"  ".repeat(row.depth as usize));
        text.push_str(
            &row.values
                .iter()
                .zip(columns)
                .map(|(value, column)| memory::value_text(column.kind, value))
                .collect::<Vec<_>>()
                .join("\t"),
        );
    }
    text
}

/// Tabs to the next multiple of 8 columns, as a terminal shows them.
pub(super) fn expand_tabs(line: &str) -> String {
    let mut out = String::with_capacity(line.len() + 16);
    let mut column = 0;
    for ch in line.chars() {
        if ch == '\t' {
            let next = (column / 8 + 1) * 8;
            out.extend(std::iter::repeat_n(' ', next - column));
            column = next;
        } else {
            out.push(ch);
            column += 1;
        }
    }
    out
}

/// Initial column widths from the header and the first rows' values.
pub(super) fn column_widths(table: &ResultTable, char_width: f32) -> Vec<f32> {
    table
        .columns
        .iter()
        .enumerate()
        .map(|(index, column)| {
            let longest = table
                .rows
                .iter()
                .take(200)
                .map(|row| {
                    row.values.get(index).map_or(0, |value| {
                        memory::value_text(column.kind, value).chars().count()
                    }) + if index == 0 {
                        row.depth as usize * crate::tree_lines::CELL_CHARS + 1
                    } else {
                        0
                    }
                })
                .max()
                .unwrap_or(0)
                .max(column.name.chars().count());
            (longest.clamp(4, 48) as f32 + 2.0) * char_width
        })
        .collect()
}

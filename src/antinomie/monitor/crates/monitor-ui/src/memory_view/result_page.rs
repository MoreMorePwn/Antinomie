// SPDX-License-Identifier: GPL-3.0-only
//! The parts of the plugin result page: the running job, the query bar, the header and the table.
use super::*;

/// The page of a plugin that is still running.
pub(super) fn running_job(ui: &mut egui::Ui, job: &RunHandle, dump: &MemoryDump) {
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
}

impl MemoryView {
    /// The page of a result that is not loaded, or is still being loaded.
    pub(super) fn unloaded_result(&mut self, ui: &mut egui::Ui, run_id: &str) {
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
            self.open_run(Some(run_id.to_owned()));
        }
    }

    /// The query bar and the paging row of a loaded result: the request they ask for.
    pub(super) fn result_request(&mut self, ui: &mut egui::Ui) -> Option<ResultRequest> {
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
                    crate::activity::inline_only(
                        ui,
                        crate::activity::Level::Warn,
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
                        crate::values::thousands(result.total),
                        crate::values::thousands(result.source_rows)
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
        request
    }

    /// The filter's error and the title row with its controls.
    pub(super) fn result_head(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let Some(result) = self.result.as_ref() else {
            return;
        };
        if let Some(error) = &result.filter_error {
            crate::activity::inline_only(ui, crate::activity::Level::Warn, error);
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
                if result.has_files
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
    }

    /// What the run itself says: its failure, a partial result, the dump format and the messages.
    pub(super) fn result_notices(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let Some(result) = self.result.as_ref() else {
            return;
        };
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
            // The outputs an unvalidated page-table root leaves unreliable
            // can be read by Volatility 3 in one click.
            if result.run.analyzer == Analyzer::MemNixFs
                && result
                    .run
                    .partial
                    .iter()
                    .any(|note| note == antinomie_monitor_core::memory::memnixfs::ROOT_NOTE)
            {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(theme::muted(), "Run in Volatility 3:");
                    for (plugin, what) in antinomie_monitor_core::memory::memnixfs::ROOT_FALLBACKS {
                        if ui
                            .button(format!("{what} ({plugin})"))
                            .on_hover_text(format!(
                                "Switch to Volatility 3 and run {plugin} on this dump"
                            ))
                            .clicked()
                        {
                            self.analyzer = Analyzer::Volatility;
                            self.pending_plugin = Some((*plugin).to_owned());
                        }
                    }
                });
            }
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
            egui::Panel::bottom("memory_log")
                .resizable(true)
                .default_size(140.0)
                .show(ui, |ui| {
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
    }

    /// The rows of a loaded result, as text or as a table.
    pub(super) fn result_body(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let Some(result) = self.result.as_ref() else {
            return;
        };
        let table = match &result.table {
            Ok(table) => table,
            Err(error) => {
                // A failed run's reason is shown above.
                if result.run.state != RunState::Failed {
                    crate::activity::error(
                        ui,
                        format!("No result saved: {error}. Run the plugin again."),
                    );
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
            self.result_text(ui, &mono);
            return;
        }
        self.result_grid(ui, font_size, &mono);
    }

    fn result_text(&mut self, ui: &mut egui::Ui, mono: &egui::FontId) {
        let Some(result) = self.result.as_mut() else {
            return;
        };
        let Ok(table) = &result.table else {
            return;
        };
        let lines = result.text.get_or_insert_with(|| {
            memory::result_text(table, &result.shown)
                .lines()
                .map(str::to_owned)
                .collect()
        });
        let line_height = ui.fonts_mut(|fonts| fonts.row_height(mono)) + 2.0;
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
    }

    fn result_grid(&mut self, ui: &mut egui::Ui, font_size: f32, mono: &egui::FontId) {
        let Some(result) = self.result.as_ref() else {
            return;
        };
        let Ok(table) = &result.table else {
            return;
        };
        let char_width = ui.fonts_mut(|fonts| fonts.glyph_width(mono, '0'));
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
        ui.scope(|ui| {
            let mut builder = FitBuilder::new(ui)
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
                        Col::rest(80.0)
                            .at_least(width.min(char_width * 12.0))
                            .clip(true),
                    )
                } else {
                    builder.column(Col::flex(*width).at_least(char_width * 4.0).clip(true))
                };
            }
            builder
                .header(row_height + 4.0, |mut header| {
                    for (index, column) in table.columns.iter().enumerate() {
                        header.col(|ui| {
                            crate::widgets::fit_table::head_bg(ui);
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
                                crate::widgets::fit_table::row_mark(
                                    ui,
                                    if row_selected && index == 0 {
                                        crate::widgets::fit_table::Mark::Selected
                                    } else {
                                        crate::widgets::fit_table::Mark::None
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
                                        ui.close();
                                    }
                                    if ui.button("Copy row").clicked() {
                                        ui.ctx().copy_text(row_text(&table.columns, data));
                                        ui.close();
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

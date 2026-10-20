// SPDX-License-Identifier: MIT
//! Live and recorded trace table.
use super::*;

impl MonitorApp {
    pub(super) fn invocations(&self) -> Vec<InvocationSummary> {
        if self.trace_archive_directory().is_some() {
            return self.archive_page.clone();
        }
        if self.selected.is_some()
            && self.snapshot.active_vm.is_some()
            && self.selected != self.snapshot.active_vm
        {
            return Vec::new();
        }
        if let Some(id) = &self.selected_capture {
            return self
                .snapshot
                .capture_events
                .get(id)
                .map(|events| match self.selected_process {
                    Some(pid) => pair_events(
                        &events
                            .iter()
                            .filter(|event| event.pid == pid)
                            .cloned()
                            .collect::<Vec<_>>(),
                    ),
                    None => pair_events(events),
                })
                .unwrap_or_default();
        }
        let events: Vec<_> = self
            .snapshot
            .events
            .iter()
            .filter(|event| self.selected_process.is_none_or(|pid| event.pid == pid))
            .filter(|event| {
                self.selected_run.as_ref().is_none_or(|id| {
                    self.snapshot
                        .runs
                        .iter()
                        .find(|run| &run.id == id)
                        .is_some_and(|run| event.root_task_cookie == run.root_task_cookie)
                })
            })
            .cloned()
            .collect();
        pair_events(&events)
    }

    /// A valid trace box becomes the applied filter. An invalid expression
    /// keeps the previous one; an empty applied filter matches every row.
    pub(super) fn commit_trace_filter(&mut self) -> crate::query::Compiled {
        let draft = crate::query::compile_note(&self.filter);
        if draft.error.is_none() {
            let changed = self.applied_filter != self.filter;
            self.applied_filter.clone_from(&self.filter);
            if changed {
                self.trace_evidence = None;
            }
            if changed && self.trace_archive_directory().is_some() {
                self.refresh_archive_matches(&draft);
            }
        }
        draft
    }

    pub(super) fn refresh_archive_matches(&mut self, filter: &crate::query::Compiled) {
        let hidden = &self.settings.hidden_trace_categories;
        if self.selected_event.is_some_and(|selected| {
            !self.archive_page.iter().any(|row| {
                trace::key(row) == selected
                    && filter.keep(row)
                    && trace::representative(row).is_some_and(|event| {
                        SyscallGroup::of(&event.syscall_name)
                            .is_none_or(|group| !hidden.contains(&group))
                    })
            })
        }) {
            self.selected_event = None;
            self.inspector.clear();
        }
        self.archive_previous.clear();
        self.archive_next = None;
        self.request_page(0);
    }

    pub(super) fn events(&mut self, ui: &mut egui::Ui) {
        if self.no_live_trace() {
            self.empty_trace(ui);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            theme::section(ui, "Syscalls");
            self.show_trace_run_selector(ui);
            if let Some(capture) = self.selected_capture_summary() {
                ui.add(egui::Label::new(captures::scope(&capture.scope)).truncate())
                    .on_hover_text(&capture.id);
            }
            let selection = self
                .capture_process_list()
                .filter(|list| !list.is_empty())
                .and_then(|processes| captures::process_menu(ui, processes, self.selected_process));
            if let Some(selection) = selection {
                self.select_process(selection);
            }
            if self.trace_archive_directory().is_some() {
                let mut size = self.settings.trace_page_size;
                ui.label("Calls/page");
                if ui
                    .add(egui::DragValue::new(&mut size).range(1..=256))
                    .on_hover_text("Saved syscall page size (1–256); saved across restarts")
                    .changed()
                {
                    self.set_trace_page_size(size);
                }
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_LEFT,
                    "Previous archive page",
                    !self.archive_pending && !self.archive_previous.is_empty(),
                ) {
                    if let Some(offset) = self.archive_previous.pop() {
                        self.request_page(offset);
                    }
                }
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_RIGHT,
                    "Next archive page",
                    !self.archive_pending && self.archive_next.is_some(),
                ) {
                    self.next_archive_page();
                }
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_CLOCKWISE,
                    "Reload archive page",
                    !self.archive_pending,
                ) {
                    let offset = if self.archive_page_generation != self.archive_generation
                        && self.archive_previous.is_empty()
                    {
                        0
                    } else {
                        self.archive_offset
                    };
                    self.request_page(offset);
                }
                if self.archive_total.is_none()
                    && !self.archive_pending
                    && self.archive_page_generation == self.archive_generation
                    && self.archive_error.is_none()
                {
                    ui.horizontal(|ui| {
                        theme::spinner(ui);
                        ui.label(format!(
                            "Page {} · counting matches…",
                            self.archive_previous.len() + 1
                        ));
                    });
                }
                if let Some(total) = self.archive_total {
                    if self.archive_page_generation == self.archive_generation {
                        ui.label(format!(
                            "Page {} of {} · {} calls/page · {total} matching / {} saved calls",
                            self.archive_previous.len() + 1,
                            total.div_ceil(self.settings.trace_page_size as u64).max(1),
                            self.settings.trace_page_size,
                            self.archive_source_total.unwrap_or(total)
                        ));
                    } else {
                        ui.label(format!(
                            "Previous results: {total} matching / {} saved calls",
                            self.archive_source_total.unwrap_or(total)
                        ));
                    }
                }
                if self.archive_pending {
                    theme::spinner(ui);
                }
                ui.label(if self.archive_pending {
                    if self.archive_page.is_empty() {
                        "Reading archive matches…"
                    } else {
                        "Reading matches · previous results shown"
                    }
                } else if self.archive_page_generation != self.archive_generation
                    && !self.archive_page.is_empty()
                {
                    "Previous results · refresh to retry"
                } else {
                    "History"
                });
            }
            let filter_width = ui.available_width().max(180.0);
            crate::query::filter_edit(
                ui,
                &mut self.filter,
                "syscall == openat",
                filter_width,
                crate::query::FilterScope::Syscall,
            )
            .on_hover_text(crate::query::HELP);
        });
        if let Some(run) = self.selected_vm_run() {
            crate::run_recording::show(ui, run);
        }
        if let Some(error) = &self.archive_error {
            crate::activity::warning(ui, error).on_hover_text(error);
        }
        let draft = self.commit_trace_filter();
        if let Some(error) = &draft.error {
            crate::activity::warning(ui, error);
        }
        let filter = if draft.error.is_none() {
            draft
        } else {
            crate::query::compile_note(&self.applied_filter)
        };
        let all = self.invocations();
        self.trace_categories(ui, &all);
        let archived = self.trace_archive_directory().is_some();
        if archived
            && self.trace_evidence.is_none()
            && self.archive_hidden_categories != self.settings.hidden_trace_categories
        {
            self.refresh_archive_matches(&filter);
        }
        let total = all.len();
        let hidden = self.settings.hidden_trace_categories.clone();
        let invocations: Vec<_> = all
            .into_iter()
            .filter(|invocation| {
                let Some(event) = trace::representative(invocation) else {
                    return false;
                };
                if !archived
                    && SyscallGroup::of(&event.syscall_name)
                        .is_some_and(|group| hidden.contains(&group))
                {
                    return false;
                }
                archived || filter.keep(invocation)
            })
            .collect();
        let mut invocations = invocations;
        if let Some((column, descending)) = self.trace_sort {
            sort_invocations(&mut invocations, column, descending);
            if archived {
                ui.colored_label(theme::muted(), "Sort applies to this page");
            }
        }
        if invocations.len() != total {
            ui.colored_label(
                theme::muted(),
                format!("Showing {} of {total} calls", invocations.len()),
            );
        }
        let font = self.settings.font_size;
        let height = theme::row_height(font);
        let header_height = font + 12.0;
        let table_height = (ui.available_height() - header_height).max(0.0);
        let mono = theme::mono(font - 1.0);
        let body_font = egui::FontId::proportional(font);
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let chars = |count: f32| count * char_width + 14.0;
        let mut widths = [
            chars(9.0),
            chars(8.0),
            chars(5.0),
            chars(3.0),
            font * 8.5,
            chars(14.0),
        ];
        // Narrow panels shrink the fixed columns so Info stays in view.
        let room = ui.available_width() - font * 6.0 - 7.0 * ui.spacing().item_spacing.x;
        let needed: f32 = widths.iter().sum();
        let mut scale = 1.0;
        if needed > room {
            scale = (room / needed).max(0.35);
            for width in &mut widths {
                *width *= scale;
            }
        }
        // Initial widths apply once per table id: a new width class (narrow
        // panel, other text size) starts from fitting widths again.
        let width_class = ((scale * 10.0).round() as i32, font as i32);
        // Row hover is known only once the row is drawn; tinted rows use the
        // previous frame's to brighten under the pointer.
        let hover_id = ui.id().with("trace_hovered_row");
        let hovered_row: Option<usize> = ui.data_mut(|data| data.remove_temp(hover_id));
        let palette = *theme::palette();
        let trace_colors = self.settings.trace_colors;
        egui::ScrollArea::horizontal()
            .id_salt("syscalls_horizontal")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width((font / 16.0 * 760.0).max(ui.available_width()));
                crate::widgets::table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt(("syscall_table", width_class))
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .max_scroll_height(table_height)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false])
                    .column(Column::initial(widths[0]).at_least(48.0).clip(true))
                    .column(Column::initial(widths[1]).at_least(40.0).clip(true))
                    .column(Column::initial(widths[2]).at_least(32.0).clip(true))
                    .column(Column::initial(widths[3]).at_least(30.0).clip(true))
                    .column(Column::initial(widths[4]).at_least(70.0).clip(true))
                    .column(Column::initial(widths[5]).at_least(50.0).clip(true))
                    .column(Column::remainder().at_least(130.0).clip(true))
                    .header(header_height, |mut header| {
                        for column in TraceColumn::ALL {
                            header.col(|ui| {
                                crate::widgets::table::head_bg(ui);
                                let sorted =
                                    self.trace_sort.filter(|(sorted, _)| *sorted == column);
                                let mut job = egui::text::LayoutJob::default();
                                job.append(
                                    column.title(),
                                    0.0,
                                    egui::TextFormat::simple(body_font.clone(), palette.muted),
                                );
                                if let Some((_, descending)) = sorted {
                                    job.append(
                                        if descending {
                                            egui_phosphor::regular::CARET_DOWN
                                        } else {
                                            egui_phosphor::regular::CARET_UP
                                        },
                                        font * 0.3,
                                        egui::TextFormat::simple(body_font.clone(), palette.accent),
                                    );
                                }
                                let response = ui
                                    .add(
                                        egui::Label::new(job)
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(format!(
                                        "{}\nClick to sort by {}",
                                        column.description(),
                                        column.title()
                                    ));
                                if response.clicked() {
                                    // A new column sorts ascending; the same column flips.
                                    self.trace_sort = Some((
                                        column,
                                        sorted.is_some_and(|(_, descending)| !descending),
                                    ));
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(height, invocations.len(), |mut row| {
                            let index = row.index();
                            let invocation = &invocations[index];
                            let event =
                                trace::representative(invocation).expect("filtered observation");
                            let key = trace::key(invocation);
                            let selected = self.selected_event == Some(key);
                            let group = SyscallGroup::of(&event.syscall_name);
                            let fill = if selected {
                                Some(palette.selection)
                            } else {
                                group.filter(|_| trace_colors).and_then(theme::syscall_tint)
                            };
                            let hovered = hovered_row == Some(index) && !selected;
                            let result = invocation.exit.as_ref().and_then(|event| event.result);
                            let failed = result.is_some_and(values::is_error);
                            let cells = trace::cells(invocation);
                            for (column, (parts, hover)) in cells.into_iter().enumerate() {
                                row.col(|ui| {
                                    // Paint the cell and half of each gap so a tinted
                                    // row reads as one band, as in Wireshark.
                                    let cell = ui.max_rect().expand2(egui::vec2(
                                        ui.spacing().item_spacing.x / 2.0,
                                        ui.spacing().item_spacing.y / 2.0,
                                    ));
                                    if let Some(fill) = fill {
                                        ui.painter().rect_filled(cell, 0.0, fill);
                                    }
                                    if hovered {
                                        ui.painter().rect_filled(
                                            cell,
                                            0.0,
                                            if theme::is_light() {
                                                egui::Color32::from_black_alpha(14)
                                            } else {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    255, 255, 255, 14,
                                                )
                                            },
                                        );
                                    }
                                    if selected {
                                        let stroke = egui::Stroke::new(1.0_f32, palette.accent);
                                        ui.painter().hline(
                                            cell.x_range(),
                                            cell.top() + 0.5,
                                            stroke,
                                        );
                                        ui.painter().hline(
                                            cell.x_range(),
                                            cell.bottom() - 0.5,
                                            stroke,
                                        );
                                    }
                                    if column == 0 && (failed || selected) {
                                        let mut bar = ui.max_rect().expand2(egui::vec2(
                                            0.0,
                                            ui.spacing().item_spacing.y / 2.0,
                                        ));
                                        bar.set_width(3.0);
                                        ui.painter().rect_filled(
                                            bar,
                                            0.0,
                                            if failed {
                                                palette.error
                                            } else {
                                                palette.accent
                                            },
                                        );
                                    }
                                    let font = if matches!(column, 4 | 6) {
                                        body_font.clone()
                                    } else {
                                        mono.clone()
                                    };
                                    let mut job = egui::text::LayoutJob::default();
                                    for (text, tone) in parts {
                                        job.append(
                                            &text,
                                            0.0,
                                            egui::TextFormat::simple(font.clone(), tone.color()),
                                        );
                                    }
                                    if column == 0 {
                                        // Clear of the failure and selection bar.
                                        ui.add_space(3.0);
                                    }
                                    ui.add(
                                        egui::Label::new(job)
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::hover()),
                                    )
                                    .on_hover_text(hover);
                                });
                            }
                            let response = row.response();
                            if response.hovered() {
                                response
                                    .ctx
                                    .data_mut(|data| data.insert_temp(hover_id, index));
                            }
                            if response.clicked() {
                                self.selected_event = Some(key);
                                self.inspector.clear();
                            }
                        });
                    });
            });
    }

    /// Category filter above the trace: one chip per syscall group (with
    /// its row count) shows or hides that group's rows, and "All" shows or
    /// hides every group; the chips wrap to a second line when narrow. The
    /// choice is saved with the settings; row colors are switched in Settings.
    fn trace_categories(&mut self, ui: &mut egui::Ui, invocations: &[InvocationSummary]) {
        let mut counts = std::collections::BTreeMap::<SyscallGroup, usize>::new();
        for invocation in invocations {
            if let Some(group) = trace::representative(invocation)
                .and_then(|event| SyscallGroup::of(&event.syscall_name))
            {
                *counts.entry(group).or_default() += 1;
            }
        }
        let previous_hidden = self.settings.hidden_trace_categories.clone();
        let hidden = &mut self.settings.hidden_trace_categories;
        // Chips wrap onto a second line instead of overflowing a narrow
        // panel; past two lines (large text) they scroll within those two.
        let roomy = !theme::is_compact();
        let chip_height =
            egui::TextStyle::Small.resolve(ui.style()).size + if roomy { 10.0 } else { 6.0 };
        egui::ScrollArea::vertical()
            .id_salt("trace_categories")
            .max_height(chip_height * 2.0 + if roomy { 8.0 } else { 5.0 })
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = if roomy {
                        egui::vec2(8.0, 6.0)
                    } else {
                        egui::vec2(5.0, 4.0)
                    };
                    ui.spacing_mut().button_padding = if roomy {
                        egui::vec2(10.0, 2.0)
                    } else {
                        egui::vec2(7.0, 1.0)
                    };
                    ui.spacing_mut().interact_size.y = chip_height;
                    let all_shown = hidden.is_empty();
                    let all = egui::Button::new(RichText::new("All").small().color(if all_shown {
                        theme::palette().primary_text
                    } else {
                        theme::text()
                    }))
                    .fill(if all_shown {
                        theme::primary()
                    } else {
                        theme::panel()
                    })
                    .stroke(egui::Stroke::new(1.0_f32, theme::line()))
                    .corner_radius(8.0);
                    if ui
                        .add(all)
                        .on_hover_text(if all_shown {
                            "Hide every category"
                        } else {
                            "Show every category"
                        })
                        .clicked()
                    {
                        if all_shown {
                            *hidden = SyscallGroup::ALL.to_vec();
                        } else {
                            hidden.clear();
                        }
                    }
                    for group in SyscallGroup::ALL {
                        let shown = !hidden.contains(&group);
                        let swatch = theme::syscall_tint(group).unwrap_or(theme::raised());
                        let count = counts.get(&group).copied().unwrap_or(0);
                        let text = RichText::new(format!("{} {count}", group.label()))
                            .small()
                            .color(if shown { theme::text() } else { theme::muted() });
                        let text = if shown { text } else { text.strikethrough() };
                        let border = if theme::is_light() {
                            swatch.gamma_multiply(0.8)
                        } else {
                            swatch.gamma_multiply(1.6)
                        };
                        let button = egui::Button::new(text)
                            .fill(if shown { swatch } else { theme::panel() })
                            .stroke(egui::Stroke::new(1.0_f32, border))
                            .corner_radius(8.0);
                        if ui
                            .add(button)
                            .on_hover_text(if shown {
                                "Click to hide these syscalls"
                            } else {
                                "Click to show these syscalls"
                            })
                            .clicked()
                        {
                            if shown {
                                hidden.push(group);
                            } else {
                                hidden.retain(|other| *other != group);
                            }
                        }
                    }
                })
            });
        if self.settings.hidden_trace_categories.len() == SyscallGroup::ALL.len() {
            ui.colored_label(
                theme::muted(),
                "All categories are hidden; click All to show them.",
            );
        }
        if self.settings.hidden_trace_categories != previous_hidden {
            self.trace_evidence = None;
        }
    }

    /// The selected VM has no live trace (it is not running) and nothing
    /// is opened from its history.
    pub(super) fn no_live_trace(&self) -> bool {
        self.selected.is_some()
            && self.snapshot.active_vm != self.selected
            && self.selected_run.is_none()
            && self.selected_capture.is_none()
            && self.trace_archive_directory().is_none()
    }

    /// The trace panel without a live trace: what to do, and the VM's latest
    /// runs and captures to open (as a double click in Run History does).
    fn empty_trace(&mut self, ui: &mut egui::Ui) {
        let Some(vm_id) = self.selected.clone() else {
            return;
        };
        // Run History lists one of runs and captures; ask for the other once.
        let asked_id = ui.id().with("empty_trace_lists");
        let asked = (vm_id.clone(), self.history_generation, self.capture_tab);
        if ui.data(|data| data.get_temp::<(String, u64, bool)>(asked_id)) != Some(asked.clone())
            && self.pending_archive.is_none()
        {
            let options = self.options.clone();
            let generation = self.history_generation;
            let carried = self.carried_run_directories();
            self.queue_archive(if self.capture_tab {
                Request::ListVm {
                    options,
                    vm_id: vm_id.clone(),
                    generation,
                    carried,
                }
            } else {
                Request::ListCaptures {
                    options,
                    vm_id: vm_id.clone(),
                    generation,
                }
            });
            ui.data_mut(|data| data.insert_temp(asked_id, asked));
        }
        let mut runs: Vec<RunSummary> = self
            .snapshot
            .runs
            .iter()
            .chain(&self.history)
            .filter(|run| run.vm_id == vm_id)
            .cloned()
            .collect();
        let mut seen = std::collections::HashSet::new();
        runs.retain(|run| seen.insert(run.id.clone()));
        let mut captures: Vec<CaptureSummary> = self
            .snapshot
            .captures
            .iter()
            .chain(&self.capture_history)
            .filter(|capture| capture.vm_id == vm_id)
            .cloned()
            .collect();
        seen.clear();
        captures.retain(|capture| seen.insert(capture.id.clone()));
        // Newest first, by when their recordings last changed.
        let times_id = ui.id().with("empty_trace_times");
        let mut times: BTreeMap<PathBuf, Option<SystemTime>> =
            ui.data(|data| data.get_temp(times_id)).unwrap_or_default();
        let mut time = |directory: &PathBuf| {
            *times.entry(directory.clone()).or_insert_with(|| {
                std::fs::metadata(directory)
                    .and_then(|metadata| metadata.modified())
                    .ok()
            })
        };
        runs.sort_by_cached_key(|run| std::cmp::Reverse(time(&run.directory)));
        captures.sort_by_cached_key(|capture| std::cmp::Reverse(time(&capture.directory)));
        ui.data_mut(|data| data.insert_temp(times_id, times));
        runs.truncate(6);
        captures.truncate(6);

        let mut open = None;
        ui.horizontal(|ui| self.show_trace_run_selector(ui));
        egui::ScrollArea::vertical()
            .id_salt("empty_trace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width().min(620.0);
                ui.add_space(((ui.available_height() - 360.0) / 3.0).clamp(12.0, 80.0));
                ui.horizontal(|ui| {
                    ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(width);
                        let size = self.settings.font_size;
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(egui_phosphor::regular::PULSE)
                                    .size(size * 2.0)
                                    .color(theme::muted()),
                            );
                            ui.vertical(|ui| {
                                ui.label(RichText::new("No live trace").size(size + 4.0));
                                ui.colored_label(
                                    theme::muted(),
                                    "Start the VM to trace programs as they run, or open a \
                                     recording.",
                                );
                            });
                        });
                        ui.add_space(8.0);
                        let stopped = self.snapshot.active_vm.is_none();
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(
                                    stopped && !self.closing,
                                    egui::Button::new(format!(
                                        "{} Start VM",
                                        egui_phosphor::regular::PLAY
                                    )),
                                )
                                .clicked()
                            {
                                open = Some(EmptyTraceAction::Start);
                            }
                            if !stopped {
                                ui.colored_label(
                                    theme::muted(),
                                    "Another VM is running; stop it first",
                                );
                            }
                        });
                        ui.add_space(12.0);
                        theme::section(ui, "Recent runs");
                        if runs.is_empty() {
                            ui.colored_label(theme::muted(), "No recorded runs yet");
                        }
                        for run in &runs {
                            let detail = format!(
                                "{}  \u{00b7}  {}",
                                run_status(run),
                                run.request.args.join(" ")
                            );
                            if recent_row(
                                ui,
                                egui_phosphor::regular::TERMINAL_WINDOW,
                                &run.request.path,
                                detail.trim_end_matches("  \u{00b7}  "),
                            )
                            .on_hover_text(format!(
                                "Open this run's recording in the trace\n{}",
                                run.directory.display()
                            ))
                            .clicked()
                            {
                                open = Some(EmptyTraceAction::Run(run.id.clone()));
                            }
                        }
                        ui.add_space(10.0);
                        theme::section(ui, "Recent captures");
                        if captures.is_empty() {
                            ui.colored_label(theme::muted(), "No captures yet");
                        }
                        for capture in &captures {
                            if recent_row(
                                ui,
                                egui_phosphor::regular::RECORD,
                                &captures::scope(&capture.scope),
                                captures::status(capture.state),
                            )
                            .on_hover_text(format!(
                                "Open this capture in the trace\n{}",
                                capture.directory.display()
                            ))
                            .clicked()
                            {
                                open = Some(EmptyTraceAction::Capture(capture.id.clone()));
                            }
                        }
                        ui.add_space(10.0);
                        ui.colored_label(
                            theme::muted(),
                            "Run History lists every run and capture of this VM.",
                        );
                    });
                });
            });
        match open {
            Some(EmptyTraceAction::Start) => self.new_run(),
            Some(EmptyTraceAction::Run(id)) => self.select_archive_run(id),
            Some(EmptyTraceAction::Capture(id)) => self.select_capture(id, true),
            None => {}
        }
    }

    pub(super) fn details(&mut self, ui: &mut egui::Ui) {
        if let Some(run) = self.selected_vm_run() {
            crate::run_recording::show(ui, run);
        }
        let invocations = self.invocations();
        let invocation = invocations
            .iter()
            .find(|invocation| Some(trace::key(invocation)) == self.selected_event);
        let directory = self.invocation_directory(invocation);
        let read = self.inspector.show(ui, invocation, directory.is_some());
        for request in std::mem::take(&mut self.inspector.open_data) {
            self.data_windows.open(ui.ctx(), request, directory.clone());
        }
        if let Some(wanted) = self.inspector.take_async_read() {
            match directory.clone() {
                Some(directory) => self.queue_archive(Request::AsyncObservations {
                    generation: wanted.generation,
                    directory,
                    capture: self.selected_capture.is_some(),
                    call: wanted.call,
                    from: wanted.from,
                    cancel: wanted.cancel,
                }),
                None => self
                    .inspector
                    .fail_async(wanted.generation, "No saved recording to read from"),
            }
        }
        if let Some((field, offset, data_len)) = read {
            if let Some(directory) = directory {
                self.inspector.generation = self.inspector.generation.wrapping_add(1);
                let request = Request::Captured {
                    generation: self.inspector.generation,
                    directory,
                    field,
                    offset,
                    data_len,
                };
                self.queue_archive(request);
                self.inspector.pending = true;
            }
        }
    }

    pub(super) fn invocation_directory(
        &self,
        invocation: Option<&InvocationSummary>,
    ) -> Option<PathBuf> {
        if let Some(capture) = self.selected_capture_summary() {
            return Some(capture.directory.clone());
        }
        if let Some(run) = self.offline_run() {
            return Some(run.directory.clone());
        }
        let invocation = invocation?;
        let root = invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
            .map(|event| event.root_task_cookie)
            .find(|root| *root != 0)
            .unwrap_or(0);
        if root == 0 {
            return self.snapshot.capture_dir.clone();
        }
        self.snapshot
            .runs
            .iter()
            .find(|run| run.root_task_cookie == root)
            .map(|run| run.directory.clone())
    }
}

/// A clickable line of the empty trace panel: icon, title, muted detail.
fn recent_row(ui: &mut egui::Ui, icon: &str, title: &str, detail: &str) -> egui::Response {
    let size = egui::TextStyle::Body.resolve(ui.style()).size;
    let height = theme::row_height(size) + 4.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter_at(rect);
        if response.hovered() {
            painter.rect_filled(rect, 4.0, theme::palette().hover);
        }
        let y = rect.center().y;
        let font = egui::FontId::proportional(size);
        painter.text(
            egui::pos2(rect.left() + 6.0, y),
            egui::Align2::LEFT_CENTER,
            icon,
            font.clone(),
            theme::blue(),
        );
        let mut job =
            egui::text::LayoutJob::simple_singleline(title.to_owned(), font.clone(), theme::text());
        job.wrap = egui::text::TextWrapping::truncate_at_width(rect.width() * 0.6);
        let title = painter.layout_job(job);
        let title_x = rect.left() + 6.0 + size * 1.6;
        let title_width = title.size().x;
        painter.galley(
            egui::pos2(title_x, y - title.size().y / 2.0),
            title,
            theme::text(),
        );
        let detail_x = title_x + title_width + size * 0.8;
        let mut job = egui::text::LayoutJob::simple_singleline(
            detail.to_owned(),
            egui::FontId::proportional(size - 1.0),
            theme::muted(),
        );
        job.wrap = egui::text::TextWrapping::truncate_at_width(rect.right() - detail_x - 6.0);
        let detail = painter.layout_job(job);
        painter.galley(
            egui::pos2(detail_x, y - detail.size().y / 2.0),
            detail,
            theme::muted(),
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Orders the table by one column. Ties keep time, then sequence, order; a
/// call without an exit sorts after every returned value.
pub(super) fn sort_invocations(
    invocations: &mut [InvocationSummary],
    column: TraceColumn,
    descending: bool,
) {
    use std::cmp::Ordering;
    let time = |invocation: &InvocationSummary| {
        trace::representative(invocation).map(|event| (event.timestamp_ns, event.event_seq))
    };
    let compare = |a: &InvocationSummary, b: &InvocationSummary| -> Ordering {
        let (Some(x), Some(y)) = (trace::representative(a), trace::representative(b)) else {
            return Ordering::Equal;
        };
        match column {
            TraceColumn::Time => x.timestamp_ns.cmp(&y.timestamp_ns),
            TraceColumn::Sequence => x.event_seq.cmp(&y.event_seq),
            TraceColumn::Tid => x.tid.cmp(&y.tid),
            TraceColumn::Cpu => x.cpu.cmp(&y.cpu),
            TraceColumn::Syscall => x
                .syscall_name
                .cmp(&y.syscall_name)
                .then(x.syscall_nr.cmp(&y.syscall_nr)),
            TraceColumn::Return => {
                let result = |invocation: &InvocationSummary| {
                    invocation.exit.as_ref().and_then(|exit| exit.result)
                };
                match (result(a), result(b)) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }
            }
            TraceColumn::Info => Ordering::Equal,
        }
    };
    if column == TraceColumn::Info {
        // The info text is built once per row, not once per comparison.
        if descending {
            invocations.sort_by_cached_key(|invocation| {
                (std::cmp::Reverse(trace::info(invocation)), time(invocation))
            });
        } else {
            invocations
                .sort_by_cached_key(|invocation| (trace::info(invocation), time(invocation)));
        }
        return;
    }
    invocations.sort_by(|a, b| {
        let order = compare(a, b);
        let order = if descending { order.reverse() } else { order };
        order.then_with(|| time(a).cmp(&time(b)))
    });
}

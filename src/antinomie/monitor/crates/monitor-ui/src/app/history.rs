// SPDX-License-Identifier: GPL-3.0-only
//! Run and capture history views.
use super::*;

impl MonitorApp {
    pub(super) fn refresh_captures(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.history_generation = self.history_generation.wrapping_add(1);
            self.queue_archive(Request::ListCaptures {
                options: self.options.clone(),
                vm_id,
                generation: self.history_generation,
            });
        }
    }

    pub(super) fn refresh_history(&mut self) {
        if self.capture_tab {
            self.refresh_captures();
            return;
        }
        self.refresh_run_history();
    }

    pub(super) fn refresh_run_history(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.history_generation = self.history_generation.wrapping_add(1);
            let carried = self.carried_run_directories();
            self.queue_archive(Request::ListVm {
                options: self.options.clone(),
                vm_id,
                generation: self.history_generation,
                carried,
            });
        }
    }

    /// Shows every run again: the state tabs and the typed filter.
    pub(super) fn clear_run_filter(&mut self) {
        self.run_filter = RunFilter::All;
        self.run_query.clear();
        self.applied_run_query.clear();
        self.run_query_error = None;
    }

    pub(super) fn run_history(&mut self, ui: &mut egui::Ui) {
        let Some(vm_id) = self.selected.clone() else {
            ui.colored_label(theme::muted(), "No VM selected");
            return;
        };
        let mut captures = self.capture_tab;
        if crate::widgets::tabs(
            ui,
            [(false, "Runs"), (true, "Captures")].map(|(value, label)| (value, label.into())),
            &mut captures,
        ) {
            self.capture_tab = captures;
            if captures {
                self.refresh_captures();
            } else {
                self.refresh_history();
            }
        }
        if self.capture_tab {
            self.capture_history_view(ui, &vm_id);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (filter, label) in [
                (RunFilter::All, "All"),
                (RunFilter::Live, "Live"),
                (RunFilter::Past, "Past"),
            ] {
                if crate::widgets::tab(
                    ui,
                    self.run_filter == filter,
                    &crate::widgets::TabItem::new(label),
                )
                .clicked()
                {
                    self.run_filter = filter;
                }
            }
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Refresh Run History",
                true,
            ) {
                self.refresh_history();
            }
        });
        let fields = crate::run_filter::fields();
        crate::query::filter_edit_fields(
            ui,
            &mut self.run_query,
            "process.exe contains \"sample\" && run.has_static",
            ui.available_width(),
            &fields,
            &[],
        );
        // Copies for drawing only: they keep whether a report exists, not the
        // report's rows. The listing is rebuilt only when the runs it shows
        // change, not every frame.
        let key = self.run_list_key(&vm_id);
        if self
            .run_list_cache
            .as_ref()
            .is_none_or(|(cached, _)| *cached != key)
        {
            let listing = self.run_listing(&vm_id);
            self.run_list_cache = Some((key, Arc::new(listing)));
        }
        let mut runs = self
            .run_list_cache
            .as_ref()
            .map(|(_, listing)| Arc::clone(listing))
            .unwrap_or_default();
        let selected_listed = self.selected_run.as_ref().is_some_and(|id| {
            self.snapshot
                .runs
                .iter()
                .chain(&self.history)
                .any(|run| &run.id == id && run.vm_id == vm_id)
        });
        let unfiltered_count = runs.len();
        let draft = crate::run_filter::compile(&self.run_query, &fields);
        if let Some(error) = draft.error.as_ref() {
            self.run_query_error = Some(error.clone());
            crate::activity::error(ui, format!("{error} · showing last valid filter"));
        } else {
            self.applied_run_query.clone_from(&self.run_query);
            self.run_query_error = None;
            crate::query::remember_valid_filter(ui, &self.run_query);
        }
        let compiled = crate::run_filter::compile(&self.applied_run_query, &fields);
        // An empty filter keeps every run without building its filter row.
        if !compiled.keeps_everything() {
            crate::run_filter::refresh_facts(ui, &runs);
            let mut kept = (*runs).clone();
            kept.retain(|run| {
                let annotation = crate::evidence::annotation(ui, &run.directory);
                let mut row = crate::run_filter::row(
                    run,
                    annotation.as_ref(),
                    run_status(run),
                    root_exit(run),
                );
                crate::run_filter::append_facts(ui, run, &mut row);
                compiled.keep_table(&row)
            });
            runs = Arc::new(kept);
        }
        ui.weak(format!("{} of {unfiltered_count} runs", runs.len()));
        // The selection is shared with the Triage and trace dropdowns, so a
        // list filter may hide the selected run but never deselects it.
        if selected_listed
            && self
                .selected_run
                .as_ref()
                .is_some_and(|id| !runs.iter().any(|run| &run.id == id))
        {
            ui.colored_label(theme::muted(), "The selected run is hidden by this filter.");
            if ui.link("Clear filter").clicked() {
                self.clear_run_filter();
            }
        }
        // Header clicks reorder the rows; the keyboard walks them as shown.
        let order =
            crate::table_sort::order(ui.ctx(), "run_history", runs.len(), |column, a, b| {
                let (a, b) = (&runs[a], &runs[b]);
                match column {
                    0 => a.started_ms.cmp(&b.started_ms),
                    1 => a
                        .request
                        .path
                        .to_lowercase()
                        .cmp(&b.request.path.to_lowercase()),
                    2 => a
                        .request
                        .args
                        .join(" ")
                        .to_lowercase()
                        .cmp(&b.request.args.join(" ").to_lowercase()),
                    3 => run_status(a).cmp(run_status(b)),
                    _ => root_exit(a).cmp(&root_exit(b)),
                }
            });
        let runs: Vec<&RunSummary> = order.iter().map(|&index| &runs[index]).collect();
        let pane_id = ui.id().with("run-history-focus");
        let pane = ui.interact(
            ui.available_rect_before_wrap(),
            pane_id,
            egui::Sense::click(),
        );
        if pane.clicked() {
            pane.request_focus();
        }
        let navigation =
            if !runs.is_empty() && ui.memory(|memory| memory.focused()) == Some(pane_id) {
                let selected = runs
                    .iter()
                    .position(|run| self.selected_run.as_ref() == Some(&run.id));
                ui.input_mut(|input| {
                    if input.consume_key(egui::Modifiers::NONE, egui::Key::Home) {
                        Some(0)
                    } else if input.consume_key(egui::Modifiers::NONE, egui::Key::End) {
                        Some(runs.len() - 1)
                    } else if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                        Some(selected.map_or(0, |index| (index + 1).min(runs.len() - 1)))
                    } else if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                        Some(selected.map_or(runs.len() - 1, |index| index.saturating_sub(1)))
                    } else {
                        None
                    }
                })
            } else {
                None
            };
        let height = (ui.available_height() - 36.0).max(50.0);
        let mut inspect = navigation.map(|index| (runs[index].id.clone(), false));
        let mut reopen = None;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height + 28.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                crate::widgets::table::begin(ui);
                let mut table = TableBuilder::new(ui)
                    .id_salt("run_history")
                    .column(Column::initial(225.0).at_least(150.0))
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::remainder().at_least(120.0))
                    .column(Column::initial(180.0).range(90.0..=400.0))
                    .column(Column::initial(190.0).range(90.0..=320.0))
                    .column(Column::initial(110.0).range(70.0..=220.0))
                    .column(Column::exact(72.0))
                    .resizable(true)
                    .striped(true)
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0);
                if let Some(index) = navigation { table = table.scroll_to_row(index, Some(egui::Align::Center)); }
                table.header(28.0, |mut header| {
                        for (column, name) in ["Start time", "Executable", "Arguments", "Tree status", "Root exit"].into_iter().enumerate() {
                            header.col(|ui| crate::table_sort::header(ui, "run_history", column, name));
                        }
                        header.col(|ui| crate::widgets::table::head(ui, ""));
                    })
                    .body(|body| {
                        body.rows(self.settings.font_size + 16.0, runs.len(), |mut row| {
                            let run = &runs[row.index()];
                            row.set_selected(self.selected_run.as_ref() == Some(&run.id));
                            row.col(|ui| { ui.add(egui::Label::new(crate::time_format::unix_ms(run.started_ms)).truncate().selectable(false).sense(egui::Sense::hover())); });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(format!("{}{}", crate::evidence::title(ui, &run.directory, &run.request.path), if run.analysis.is_some() { "  [static analysis]" } else { "" }))
                                        .selectable(false)
                                        .sense(egui::Sense::hover())
                                        .truncate(),
                                )
                                .on_hover_text(&run.request.path);
                            });
                            row.col(|ui| {
                                let args = run.request.args.join(" ");
                                ui.add(
                                    egui::Label::new(&args)
                                        .selectable(false)
                                        .sense(egui::Sense::hover())
                                        .truncate(),
                                )
                                .on_hover_text(run.request.args.join("\n"));
                            });
                            row.col(|ui| {
                                let detail = [execution_detail(run), crate::run_recording::tooltip(run)];
                                ui.add(
                                    egui::Label::new(run_status(run))
                                        .selectable(false)
                                        .sense(egui::Sense::hover()),
                                )
                                .on_hover_text(detail.join("\n"));
                                if let Some(badge) = crate::run_recording::badge(run) {
                                    ui.colored_label(theme::warn(), badge);
                                }
                            });
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(root_exit(run))
                                        .selectable(false)
                                        .sense(egui::Sense::hover()),
                                )
                                .on_hover_text(format!(
                                    "Wait status: {:?}{}",
                                    run.execution
                                        .as_ref()
                                        .and_then(|status| status.root_wait_status),
                                    if run.request.run_in
                                        == antinomie_monitor_core::RunIn::GuestDesktopTerminal
                                    {
                                        "\nThis is the desktop terminal launcher's status. The program's own status appears in its guest terminal and captured process tree."
                                    } else {
                                        ""
                                    }
                                ));
                            });
                            row.col(|ui| {
                                if icon(
                                    ui,
                                    egui_phosphor::regular::TERMINAL_WINDOW,
                                    "Open terminal",
                                    true,
                                ) {
                                    reopen = Some(run.id.clone());
                                }
                                if icon(
                                    ui,
                                    egui_phosphor::regular::STOP,
                                    "Stop run and descendants",
                                    self.snapshot.runs.iter().any(|live| live.id == run.id)
                                        && matches!(
                                            run.state,
                                            RunState::Running | RunState::TerminalClosed
                                        )
                                        && !self.closing
                                        && self.running()
                                        && self.pending_kill.is_none(),
                                ) {
                                    self.request_kill(Some(&run.id));
                                }
                            });
                            let response = row.response();
                            response.context_menu(|ui| {
                                crate::evidence::menu(ui, &run.directory);
                                let annotation = crate::evidence::annotation(ui, &run.directory);
                                for (field, value) in crate::run_filter::row(run, annotation.as_ref(), run_status(run), root_exit(run)) {
                                    crate::query::value_menu(ui, field, &value, &mut self.run_query);
                                }
                            });
                            if response.clicked() || response.double_clicked() {
                                pane.request_focus();
                                inspect = Some((run.id.clone(), response.double_clicked()));
                            }
                        });
                    });
            },
        );
        // The terminal keeps the complete run, not the drawing copy.
        if let Some(run) = reopen.and_then(|id| {
            self.snapshot
                .runs
                .iter()
                .chain(&self.history)
                .find(|run| run.id == id && run.vm_id == vm_id)
                .cloned()
        }) {
            self.reopen(run);
        }
        // A click or arrow key only selects the run; a double click opens it.
        if let Some((id, open)) = inspect {
            self.select_run(Some(id));
            if open {
                self.focus_panel = Some(Panel::Triage);
            }
        }
        if runs.is_empty() {
            ui.colored_label(theme::muted(), "No retained runs for this VM");
        } else if self.selected_run.is_some() {
            ui.colored_label(
                theme::muted(),
                "Run details are in the Details panel below.",
            );
        }
    }

    pub(super) fn history_detail(&mut self, ui: &mut egui::Ui) {
        // The same run or capture keeps its scroll position across repaints.
        let selection = (
            self.capture_tab,
            self.selected.clone(),
            self.selected_run.clone(),
            self.selected_capture.clone(),
        );
        crate::details_scroll::show(ui, "history_details_scroll", selection, |ui, viewport| {
            self.history_detail_content(ui, viewport)
        });
    }

    fn history_detail_content(&mut self, ui: &mut egui::Ui, viewport: f32) {
        if self.capture_tab {
            self.capture_detail(ui, viewport);
            return;
        }
        let Some(vm_id) = self.selected.clone() else {
            ui.colored_label(theme::muted(), "No VM selected");
            return;
        };
        let run = self
            .snapshot
            .runs
            .iter()
            .chain(&self.history)
            .find(|run| self.selected_run.as_ref() == Some(&run.id) && run.vm_id == vm_id)
            .cloned();
        let Some(run) = run else {
            ui.colored_label(theme::muted(), "Select a run in Run History.");
            return;
        };
        // A warning or note about the recording shows only when there is one.
        crate::run_recording::show(ui, &run);
        self.run_tree_view(ui, &run, viewport);
        ui.add_space(6.0);
        let labels = self.run_labels.of(ui.ctx(), &run);
        crate::route_ui::line(
            ui,
            &crate::route_ui::describe(run.route.as_ref(), labels.and_then(|labels| labels.route)),
        );
        enabled_features(ui, &run, labels);
        launch_details(ui, &run);
    }

    fn capture_detail(&mut self, ui: &mut egui::Ui, viewport: f32) {
        let Some(id) = self.selected_capture.clone() else {
            ui.colored_label(theme::muted(), "Select a capture in Run History.");
            return;
        };
        let capture = self
            .snapshot
            .captures
            .iter()
            .chain(&self.capture_history)
            .find(|capture| capture.id == id)
            .cloned();
        if let Some(capture) = capture {
            captures::detail(ui, &capture);
        }
        // Borrowed, not copied: the list can hold tens of thousands of processes.
        let font_size = self.settings.font_size;
        let selected = self.selected_process;
        let selection = match self.snapshot.capture_processes.get(&id) {
            Some(live) => Some(Ok(live.as_slice())),
            None => match &self.archived_processes {
                Some((loaded, result)) if *loaded == id => Some(result.as_ref().map(Vec::as_slice)),
                _ => None,
            },
        };
        let selection = match selection {
            Some(Err(error)) => {
                crate::activity::warning(ui, format!("Process tree unavailable: {error}"));
                None
            }
            None | Some(Ok([])) => {
                ui.colored_label(
                    theme::muted(),
                    "No process tree (captures before Antinomie 0.3.0 keep one combined trace)",
                );
                None
            }
            Some(Ok(processes)) => bounded_tree(ui, viewport, |ui| {
                captures::process_tree(ui, processes, selected, font_size)
            }),
        };
        if let Some(selection) = selection {
            self.select_process(selection);
            self.focus_trace();
        }
    }

    fn run_tree_view(&mut self, ui: &mut egui::Ui, run: &RunSummary, viewport: f32) {
        ui.horizontal_wrapped(|ui| {
            ui.strong("Recorded process tree");
            if ui.button("Refresh tree").clicked() {
                self.run_tree = None;
            }
            ui.colored_label(
                theme::muted(),
                "Through the last saved packet; refresh ongoing runs",
            );
        });
        if self.run_tree.as_ref().is_none_or(|(id, _)| id != &run.id)
            && self.run_tree_pending.is_none()
            && self.pending_archive.is_none()
            && !self.archive_pending
        {
            self.queue_archive(Request::ProcessTree {
                run_id: run.id.clone(),
                directory: run.directory.clone(),
                root_pid: run.pid,
                path: run.request.path.clone(),
            });
            self.run_tree_pending = Some(run.id.clone());
        }
        // Drawn from the stored result, not a copy of it: the list can hold
        // tens of thousands of processes.
        let font_size = self.settings.font_size;
        let selected = self.selected_process;
        let mut selection = None;
        match self.run_tree.as_ref().filter(|(id, _)| id == &run.id) {
            Some((_, Ok((processes, issues)))) => {
                for issue in issues {
                    crate::activity::warning(ui, issue);
                }
                selection = bounded_tree(ui, viewport, |ui| {
                    captures::process_tree(ui, processes, selected, font_size)
                });
            }
            Some((_, Err(error))) => {
                crate::activity::warning(ui, error);
            }
            None => {
                crate::theme::loading(ui, "Reading saved lifecycle records…");
            }
        }
        if let Some(selection) = selection {
            self.select_process(selection);
            self.focus_trace();
        }
    }

    fn capture_history_view(&mut self, ui: &mut egui::Ui, vm_id: &str) {
        ui.horizontal_wrapped(|ui| {
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Refresh Capture History",
                true,
            ) {
                self.refresh_captures();
            }
        });
        let mut items: Vec<_> = self
            .snapshot
            .captures
            .iter()
            .filter(|capture| capture.vm_id == vm_id)
            .cloned()
            .collect();
        for capture in self
            .capture_history
            .iter()
            .filter(|capture| capture.vm_id == vm_id)
        {
            if !items.iter().any(|live| live.id == capture.id) {
                items.push(capture.clone());
            }
        }
        if let Some((id, archive)) = captures::history(
            ui,
            &items,
            self.selected_capture.as_deref(),
            self.settings.font_size,
        ) {
            self.select_capture(id, archive);
        }
        if self.selected_capture.as_ref().is_some_and(|id| {
            items.iter().any(|capture| &capture.id == id)
                && !items.iter().any(|capture| {
                    &capture.id == id && captures::matches_capture_filter(ui, capture)
                })
        }) {
            ui.colored_label(
                theme::muted(),
                "The selected capture is hidden by this filter.",
            );
            if ui.link("Clear filter").clicked() {
                captures::clear_capture_filter(ui);
            }
        }
        if self.selected_capture.is_some() {
            ui.colored_label(
                theme::muted(),
                "Capture details are in the Details panel below.",
            );
        }
    }

    pub(super) fn select_process(&mut self, selection: captures::ProcessSelection) {
        self.selected_process = match selection {
            captures::ProcessSelection::All => None,
            captures::ProcessSelection::Process(pid) => Some(pid),
        };
        self.reset_trace_selection();
        if self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
    }

    /// The selected capture's process tree: live, or as saved.
    pub(super) fn capture_process_list(&self) -> Option<&[CaptureProcess]> {
        let id = self.selected_capture.as_ref()?;
        if let Some(live) = self.snapshot.capture_processes.get(id) {
            return Some(live);
        }
        match &self.archived_processes {
            Some((loaded, Ok(list))) if loaded == id => Some(list),
            _ => None,
        }
    }

    /// Remember the newest program each VM ran; the sidebar shows it.
    pub(super) fn note_last_runs(&mut self) {
        let now = unix_seconds();
        for vm in &self.snapshot.vms {
            let Some(newest) = self
                .snapshot
                .runs
                .iter()
                .rev()
                .find(|run| run.vm_id == vm.id)
            else {
                continue;
            };
            if self
                .settings
                .last_runs
                .get(&vm.id)
                .is_some_and(|last| last.run_id == newest.id)
            {
                continue;
            }
            self.settings.last_runs.insert(
                vm.id.clone(),
                LastRun {
                    run_id: newest.id.clone(),
                    program: newest.request.path.clone(),
                    started: now,
                },
            );
        }
        let vms = &self.snapshot.vms;
        if !vms.is_empty() {
            self.settings
                .last_runs
                .retain(|id, _| vms.iter().any(|vm| &vm.id == id));
        }
    }

    /// What Run History's listing depends on: the selected VM, the Live/Past
    /// filter, and each of that VM's runs as far as a row shows it.
    fn run_list_key(&self, vm_id: &str) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        vm_id.hash(&mut hasher);
        std::mem::discriminant(&self.run_filter).hash(&mut hasher);
        for (live, run) in self
            .snapshot
            .runs
            .iter()
            .map(|run| (true, run))
            .chain(self.history.iter().map(|run| (false, run)))
            .filter(|(_, run)| run.vm_id == vm_id)
        {
            live.hash(&mut hasher);
            run.id.hash(&mut hasher);
            run.boot_id.hash(&mut hasher);
            std::mem::discriminant(&run.state).hash(&mut hasher);
            run.terminal_eof.hash(&mut hasher);
            run.started_ms.hash(&mut hasher);
            run.pid.hash(&mut hasher);
            run.request.path.hash(&mut hasher);
            run.recording_error.hash(&mut hasher);
            run.notes.hash(&mut hasher);
            run.analysis
                .as_ref()
                .map(|report| (&report.id, std::mem::discriminant(&report.state)))
                .hash(&mut hasher);
        }
        // Which runs count as live depends on the session as well.
        std::mem::discriminant(&self.snapshot.state).hash(&mut hasher);
        self.snapshot.active_vm.hash(&mut hasher);
        self.snapshot.boot_id.hash(&mut hasher);
        hasher.finish()
    }

    /// The selected VM's runs, live ones first and then saved ones, under the
    /// Live/Past filter, newest first.
    fn run_listing(&self, vm_id: &str) -> Vec<RunSummary> {
        let mut runs: Vec<_> = self
            .snapshot
            .runs
            .iter()
            .filter(|run| run.vm_id == vm_id)
            .map(listed)
            .collect();
        let live: std::collections::HashSet<_> = runs.iter().map(|run| run.id.clone()).collect();
        runs.extend(
            self.history
                .iter()
                .filter(|run| run.vm_id == vm_id && !live.contains(&run.id))
                .map(listed),
        );
        runs.retain(|run| match self.run_filter {
            RunFilter::All => true,
            RunFilter::Live => self.live_history_run(run),
            RunFilter::Past => !self.live_history_run(run),
        });
        runs.sort_by(|a, b| {
            b.started_ms
                .cmp(&a.started_ms)
                .then_with(|| b.id.cmp(&a.id))
        });
        runs
    }

    pub(super) fn live_history_run(&self, run: &RunSummary) -> bool {
        self.snapshot.runs.iter().any(|live| live.id == run.id)
            && matches!(
                run.state,
                RunState::Running | RunState::StopRequested | RunState::TerminalClosed
            )
    }
}

/// `run` for listing: everything but the static-analysis rows. Whether a
/// report exists stays visible to the row, filter and `[static analysis]` mark.
pub(super) fn listed(run: &RunSummary) -> RunSummary {
    RunSummary {
        started_ms: run.started_ms,
        clock_anchor: run.clock_anchor,
        id: run.id.clone(),
        vm_id: run.vm_id.clone(),
        boot_id: run.boot_id.clone(),
        session_id: run.session_id,
        root_task_cookie: run.root_task_cookie,
        pid: run.pid,
        request: run.request.clone(),
        directory: run.directory.clone(),
        terminal_eof: run.terminal_eof,
        state: run.state.clone(),
        notes: run.notes.clone(),
        route: run.route.clone(),
        recording_error: run.recording_error.clone(),
        execution: run.execution.clone(),
        analysis: run
            .analysis
            .as_ref()
            .map(|report| antinomie_monitor_core::AnalysisReport {
                id: report.id.clone(),
                state: report.state,
                source_path: String::new(),
                specimen_sha256: None,
                specimen_len: report.specimen_len,
                reason: None,
                sections: Vec::new(),
                layer: None,
            }),
    }
}

pub(super) fn run_status(run: &RunSummary) -> &'static str {
    match run.state {
        RunState::Unknown => "Unknown",
        RunState::Running => "Running",
        RunState::StopRequested => "Stop requested",
        RunState::Finished => "Finished",
        RunState::Stopped => "Stopped",
        RunState::TerminalClosed => "PTY closed",
        RunState::Finalized => "Recording ended",
    }
}

pub(super) fn root_exit(run: &RunSummary) -> String {
    match run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref())
    {
        Some(WaitStatus::Exited { code }) => format!("Exit {code}"),
        Some(WaitStatus::Signaled {
            signal,
            core_dumped,
        }) => format!(
            "Signal {signal}{}",
            if *core_dumped { " (core)" } else { "" }
        ),
        None => "Unknown".into(),
    }
}

pub(super) fn execution_detail(run: &RunSummary) -> String {
    match &run.execution {
        Some(status) => format!(
            "{}; {} live tasks; {} pending async; {} total tasks; {} async losses; flags {:#x}; generation {}{}",
            run_status(run),
            status.live_task_count,
            status.pending_async_count,
            status.total_task_count,
            status.async_loss_count,
            status.flags,
            status.generation,
            if status.kill_escalated() {
                "; Stop needed SIGKILL after the grace period"
            } else {
                ""
            }
        ),
        None => format!(
            "{}; full-tree execution evidence unavailable",
            run_status(run)
        ),
    }
}

/// The process tree in a box that is taller in a taller window and that the
/// user can resize. The Details scroll area gives no height of its own, and
/// the tree scrolls inside the box, both ways.
fn bounded_tree<R>(ui: &mut egui::Ui, viewport: f32, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let height = crate::details_scroll::tree_height(ui, viewport);
    let result = ui
        .allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height),
            egui::Layout::top_down(egui::Align::Min),
            add,
        )
        .inner;
    crate::details_scroll::tree_splitter(ui, height);
    result
}

/// The run's program tree ended and its terminal is closed: its archive is
/// complete and no more live events arrive for it.
pub(super) fn run_recording_complete(run: &RunSummary) -> bool {
    run.terminal_eof
        && matches!(
            run.state,
            RunState::Finished | RunState::Stopped | RunState::Finalized
        )
}

pub(super) fn run_in_live_session(snapshot: &Snapshot, run: &RunSummary) -> bool {
    // Tree completion does not end the VM boot's terminal/capture ownership.
    matches!(snapshot.state, VmState::Running | VmState::Stopping)
        && snapshot.active_vm.as_ref() == Some(&run.vm_id)
        && !run.boot_id.is_empty()
        && snapshot.runs.iter().any(|current| {
            current.id == run.id && current.vm_id == run.vm_id && current.boot_id == run.boot_id
        })
}

/// What the run was started with: the static analyses and the capture
/// options that were switched on, in the order the launch dialog lists them.
fn enabled_features(ui: &mut egui::Ui, run: &RunSummary, labels: Option<run_labels::Labels>) {
    let request = &run.request;
    let mut features = Vec::new();
    if request.analysis.enabled {
        features.extend(
            request
                .analysis
                .checks
                .iter()
                .map(|kind| format!("Static analysis: {}", kind.label())),
        );
    }
    for (on, label) in [
        (request.memory_dump_on_exit, "Memory dump on exit"),
        (request.core_dump_on_exit, "Core dump on exit"),
        (request.debug_on_start, "Debug on start"),
        (request.capture_network, "Network capture"),
    ] {
        if on {
            // What became of the capture and the core, once the run saved them.
            let state = labels.and_then(|labels| match label {
                "Core dump on exit" => Some(labels.core),
                "Network capture" => Some(labels.network),
                _ => None,
            });
            let budget = (label == "Core dump on exit")
                .then_some(request.core_max_size)
                .flatten()
                .map(|size| {
                    let deadline = request.core_timeout_ms.map_or(String::new(), |ms| {
                        format!(" · deadline {:.1} s", f64::from(ms) / 1000.0)
                    });
                    format!(" · budget {} MiB{deadline}", size >> 20)
                })
                .unwrap_or_default();
            features.push(match state {
                Some(state) => format!("{label}{budget} · {state}"),
                None => format!("{label}{budget}"),
            });
        }
    }
    ui.strong("Analysis enabled");
    if features.is_empty() {
        ui.colored_label(
            theme::muted(),
            "No analysis features were enabled for this run.",
        );
    }
    for feature in &features {
        ui.label(format!("{}  {feature}", egui_phosphor::regular::CHECK));
    }
}

/// How the run was launched and where it is recorded, folded away by default.
fn launch_details(ui: &mut egui::Ui, run: &RunSummary) {
    egui::CollapsingHeader::new("Launch")
        .id_salt("run_launch_details")
        .default_open(false)
        .show(ui, |ui| {
            // Vertical scrolling is the Details panel's; wide values scroll here.
            egui::ScrollArea::horizontal()
                .id_salt("launch_metadata")
                .show(ui, |ui| {
                    egui::Grid::new("run_metadata")
                        .num_columns(2)
                        .show(ui, |ui| {
                            for (label, value) in [
                                ("Executable", run.request.path.clone()),
                                ("Arguments", format!("{:?}", run.request.args)),
                                ("Working directory", run.request.cwd.clone()),
                                ("Environment", run.request.env.join("\n")),
                                (
                                    "UID / GID",
                                    format!("{} / {}", run.request.uid, run.request.gid),
                                ),
                                ("Boot", run.boot_id.clone()),
                                ("Session", run.session_id.to_string()),
                                ("Recording", run.directory.display().to_string()),
                            ] {
                                ui.label(label);
                                ui.add(egui::Label::new(value).selectable(true));
                                ui.end_row();
                            }
                        });
                });
        });
}

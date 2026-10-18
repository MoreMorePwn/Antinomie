// SPDX-License-Identifier: MIT
//! Run and capture history views.
use super::*;

impl MonitorApp {
    fn refresh_captures(&mut self) {
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
        if let Some(vm_id) = self.selected.clone() {
            self.history_generation = self.history_generation.wrapping_add(1);
            self.queue_archive(Request::ListVm {
                options: self.options.clone(),
                vm_id,
                generation: self.history_generation,
            });
        }
    }

    pub(super) fn run_history(&mut self, ui: &mut egui::Ui) {
        let Some(vm_id) = self.selected.clone() else {
            ui.colored_label(theme::muted(), "No VM selected");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            if ui.selectable_label(!self.capture_tab, "Runs").clicked() && self.capture_tab {
                self.capture_tab = false;
                self.refresh_history();
            }
            if ui.selectable_label(self.capture_tab, "Captures").clicked() && !self.capture_tab {
                self.capture_tab = true;
                self.refresh_captures();
            }
        });
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
                ui.selectable_value(&mut self.run_filter, filter, label);
            }
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Refresh Run History",
                true,
            ) {
                self.refresh_history();
            }
            if ui
                .selectable_label(
                    self.selected_run.is_none() && self.selected_capture.is_none(),
                    "All live traces",
                )
                .clicked()
            {
                self.select_run(None);
            }
        });
        let fields = crate::run_filter::fields();
        crate::query::filter_edit_fields(
            ui,
            &mut self.run_query,
            "Filter runs: pid == 123 && analysis.available",
            ui.available_width(),
            &fields,
            &[],
        );
        // Copies for drawing only: they keep whether a report exists, not the
        // report's rows, so this list does not duplicate every retained run's
        // analysis each frame.
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
        let unfiltered_count = runs.len();
        let draft = crate::query::compile_table(&self.run_query, &fields);
        if let Some(error) = draft.error.as_ref() {
            self.run_query_error = Some(error.clone());
            ui.colored_label(
                theme::error(),
                format!("{error} · showing last valid filter"),
            );
        } else {
            self.applied_run_query.clone_from(&self.run_query);
            self.run_query_error = None;
            crate::query::remember_valid_filter(ui, &self.run_query);
        }
        let compiled = crate::query::compile_table(&self.applied_run_query, &fields);
        crate::run_filter::refresh_facts(ui, &runs);
        runs.retain(|run| {
            let annotation = crate::evidence::annotation(ui, &run.directory);
            let mut row = crate::run_filter::row(run, annotation.as_ref(), run_status(run));
            crate::run_filter::append_facts(ui, run, &mut row);
            compiled.keep_table(&row)
        });
        ui.weak(format!("{} of {unfiltered_count} runs", runs.len()));
        if self
            .selected_run
            .as_ref()
            .is_some_and(|id| !runs.iter().any(|run| &run.id == id))
        {
            self.select_run(None);
            ui.weak("The selected run is hidden by this filter.");
        }
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
                let mut table = TableBuilder::new(ui)
                    .id_salt("run_history")
                    .column(Column::initial(225.0).at_least(150.0))
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::remainder().at_least(120.0))
                    .column(Column::initial(180.0).range(90.0..=400.0))
                    .column(Column::initial(110.0).range(70.0..=220.0))
                    .column(Column::initial(110.0).range(70.0..=220.0))
                    .column(Column::exact(72.0))
                    .resizable(true)
                    .striped(true)
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0);
                if let Some(index) = navigation { table = table.scroll_to_row(index, Some(egui::Align::Center)); }
                table.header(28.0, |mut header| {
                        for name in ["Start time", "Executable", "Arguments", "Tree status", "Root exit", ""] {
                            header.col(|ui| {
                                ui.strong(name);
                            });
                        }
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
                                ui.add(
                                    egui::Label::new(run_status(run))
                                        .selectable(false)
                                        .sense(egui::Sense::hover()),
                                )
                                .on_hover_text(execution_detail(run));
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
                                        && !self.closing,
                                ) {
                                    self.send(Command::StopRun {
                                        run_id: run.id.clone(),
                                    });
                                }
                            });
                            let response = row.response();
                            response.context_menu(|ui| {
                                crate::evidence::menu(ui, &run.directory);
                                let annotation = crate::evidence::annotation(ui, &run.directory);
                                for (field, value) in crate::run_filter::row(run, annotation.as_ref(), run_status(run)) {
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
        if let Some((id, open)) = inspect {
            let _ = open;
            self.select_run(Some(id));
            self.focus_panel = Some(Panel::Triage);
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
        if self.capture_tab {
            self.capture_detail(ui);
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
        ui.horizontal_wrapped(|ui| {
            if run.analysis.is_some() && ui.button("Open static analysis").clicked() {
                self.selected_analysis = None;
                self.focus_panel = Some(Panel::StaticAnalysis);
            }
        });
        self.run_artifacts_view(ui, &run);
        self.run_tree_view(ui, &run);
        egui::CollapsingHeader::new("Launch details")
            .default_open(false)
            .show(ui, |ui| {
                egui::ScrollArea::both()
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
                                    ("Run in", run.request.run_in.label().to_owned()),
                                    (
                                        "UID / GID",
                                        format!("{} / {}", run.request.uid, run.request.gid),
                                    ),
                                    ("Run", run.id.clone()),
                                    ("Boot", run.boot_id.clone()),
                                    (
                                        "Session / root task / PID",
                                        format!(
                                            "{} / {} / {}",
                                            run.session_id, run.root_task_cookie, run.pid
                                        ),
                                    ),
                                    ("Tree", execution_detail(&run)),
                                    ("Root exit", root_exit(&run)),
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

    fn capture_detail(&mut self, ui: &mut egui::Ui) {
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
                ui.colored_label(theme::warn(), format!("Process tree unavailable: {error}"));
                None
            }
            None | Some(Ok([])) => {
                ui.colored_label(
                    theme::muted(),
                    "No process tree (captures before Antinomie 0.3.0 keep one combined trace)",
                );
                None
            }
            Some(Ok(processes)) => captures::process_tree(ui, processes, selected, font_size),
        };
        if let Some(selection) = selection {
            self.select_process(selection);
            self.focus_trace();
        }
    }

    fn run_artifacts_view(&mut self, ui: &mut egui::Ui, run: &RunSummary) {
        let manual: Vec<_> = self
            .snapshot
            .process_cores
            .iter()
            .filter(|capture| {
                capture.vm_id == run.vm_id
                    && capture.boot_id == run.boot_id
                    && capture.source_run_id.as_deref() == Some(run.id.as_str())
            })
            .cloned()
            .collect();
        if !manual.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Recent manual process cores: {}", manual.len()));
                for (index, capture) in manual.into_iter().enumerate() {
                    if ui.link(format!("Open manual core {}", index + 1)).clicked() {
                        self.core_view.select_manual(capture);
                        self.focus_panel = Some(Panel::CoreDump);
                    }
                }
            });
        }
        let cache_id = egui::Id::new(("run-artifacts", &run.directory));
        let cached = ui.ctx().data_mut(|data| {
            type Cached = (
                Instant,
                Result<Option<antinomie_monitor_core::RunArtifacts>, String>,
            );
            let cached = data.get_temp_mut_or_insert_with::<Cached>(cache_id, || {
                (
                    Instant::now(),
                    antinomie_monitor_core::RunArtifacts::load(&run.directory),
                )
            });
            if cached.0.elapsed() >= Duration::from_secs(1) {
                *cached = (
                    Instant::now(),
                    antinomie_monitor_core::RunArtifacts::load(&run.directory),
                );
            }
            cached.1.clone()
        });
        match cached {
            Ok(Some(artifacts))
                if artifacts.run_id == run.id
                    && artifacts.vm_id == run.vm_id
                    && artifacts.boot_id == run.boot_id =>
            {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!(
                        "Network: {:?} · Post-exit RAM: {:?} · Process core: {}",
                        artifacts.network_state,
                        artifacts.memory_state,
                        core_capture_status(artifacts.core_state)
                    ));
                    for (index, file) in artifacts.network_captures.iter().enumerate() {
                        if ui.link(format!("Network segment {}", index + 1)).clicked() {
                            self.network_view.open(Some(file.clone()));
                            self.focus_panel = Some(Panel::Network);
                        }
                    }
                    if let Some(directory) = &artifacts.memory_dump {
                        if ui.link("Open memory dump").clicked() {
                            self.memory_view.open_dump(directory);
                            self.focus_panel = Some(Panel::Memory);
                        }
                    }
                    if let Some(file) = &artifacts.core_dump {
                        if ui.link("Open process core").clicked() {
                            self.core_view.open(file);
                            self.focus_panel = Some(Panel::CoreDump);
                        }
                        if ui.link("Open core directory").clicked() {
                            if let Some(directory) = file.parent() {
                                open_directory(directory);
                            }
                        }
                    }
                    if matches!(
                        artifacts.core_state,
                        antinomie_monitor_core::RunArtifactState::WaitingForRootExit
                            | antinomie_monitor_core::RunArtifactState::InProgress
                    ) && self.snapshot.active_vm.as_deref() == Some(run.vm_id.as_str())
                        && self.snapshot.boot_id.as_deref() == Some(run.boot_id.as_str())
                        && ui.button("Cancel process core").clicked()
                    {
                        self.send(Command::CancelProcessCore {
                            run_id: run.id.clone(),
                        });
                    }
                });
                for issue in &artifacts.issues {
                    ui.colored_label(theme::warn(), issue);
                }
            }
            Ok(Some(_)) => {
                ui.colored_label(
                    theme::warn(),
                    "Artifact metadata identity does not match this run",
                );
            }
            Ok(None) => {}
            Err(error) => {
                ui.colored_label(theme::warn(), error);
            }
        }
    }

    fn run_tree_view(&mut self, ui: &mut egui::Ui, run: &RunSummary) {
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
                    ui.colored_label(theme::warn(), issue);
                }
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), ui.available_height().min(220.0)),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        selection = captures::process_tree(ui, processes, selected, font_size);
                    },
                );
            }
            Some((_, Err(error))) => {
                ui.colored_label(theme::warn(), error);
            }
            None => {
                ui.spinner();
                ui.label("Reading saved lifecycle records…");
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
            if ui
                .selectable_label(
                    self.selected_capture.is_none() && self.selected_run.is_none(),
                    "All live traces",
                )
                .clicked()
            {
                self.select_run(None);
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
            !items
                .iter()
                .any(|capture| &capture.id == id && captures::matches_capture_filter(ui, capture))
        }) {
            self.select_run(None);
            ui.weak("The selected capture is hidden by this filter.");
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
            "{}; {} live tasks; {} pending async; {} total tasks; {} async losses; flags {:#x}; generation {}",
            run_status(run),
            status.live_task_count,
            status.pending_async_count,
            status.total_task_count,
            status.async_loss_count,
            status.flags,
            status.generation
        ),
        None => format!(
            "{}; full-tree execution evidence unavailable",
            run_status(run)
        ),
    }
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

// SPDX-License-Identifier: MIT
//! Workspace panels and terminal viewports.
use super::*;

impl MonitorApp {
    pub(super) fn draw(&mut self, ctx: &egui::Context) {
        if self.activity_notices_due {
            self.collect_notices(ctx);
            self.activity_notices_due = false;
        }
        self.activity.ingest(ctx);
        self.escape(ctx);
        self.performance.show(ctx, &self.options.data_dir);
        if self.settings.show_fps {
            self.performance.show_fps(ctx);
        }
        self.shortcuts(ctx);
        self.accept_dropped_file(ctx);
        if self.dependencies.show(ctx, &self.options) {
            self.folder_picker.refresh(ctx);
        }
        self.menus(ctx);
        self.toolbar(ctx);
        self.dump_pause_banner(ctx);
        self.health(ctx);
        self.sidebar(ctx);
        let mut layout = std::mem::take(&mut self.layout);
        if let Some(panel) = self.focus_panel.take() {
            layout.focus(panel);
        }
        layout.show(self, ctx);
        self.layout = layout;
        self.dialogs(ctx);
        self.data_windows.show(ctx);
        self.file_drop_overlay(ctx);
        self.activity.ingest(ctx);
        let enabled = match self.process_picker.purpose {
            captures::ProcessPurpose::Core => self.manual_core_unavailable().is_none(),
            captures::ProcessPurpose::Debug => self.debugger_unavailable().is_none(),
            captures::ProcessPurpose::Attach => self.observer_start_enabled(),
        };
        self.debugger_window(ctx);
        if self
            .process_picker
            .selected
            .as_ref()
            .is_some_and(|identity| self.snapshot.boot_id.as_ref() != Some(&identity.boot_id))
        {
            self.process_picker.selected = None;
        }
        let page = self
            .snapshot
            .process_page
            .as_ref()
            .filter(|page| self.snapshot.boot_id.as_ref() == Some(&page.boot_id));
        let core_context = captures::CoreContext {
            limits: self.snapshot.guest_core_limits,
            default_mib: self.settings.core_budget_mib,
            available: self
                .snapshot
                .vm_resources
                .as_ref()
                .and_then(|resources| resources.guest.as_ref())
                .filter(|guest| !guest.stale)
                .and_then(|guest| guest.memory_available_size),
        };
        if let Some(action) =
            self.process_picker
                .show(ctx, page, enabled, self.settings.font_size, core_context)
        {
            match action {
                captures::ProcessAction::Refresh(after_pid) => {
                    self.send(Command::ListProcesses { after_pid })
                }
                captures::ProcessAction::Attach(identity) => {
                    if self.snapshot.boot_id.as_ref() == Some(&identity.boot_id) && enabled {
                        self.process_picker.open = false;
                        self.send(Command::AttachProcess { identity });
                    }
                }
                captures::ProcessAction::Debug(identity) => {
                    if self.snapshot.boot_id.as_ref() == Some(&identity.boot_id) && enabled {
                        self.process_picker.open = false;
                        self.send(Command::DebugAttach { identity });
                    }
                }
                captures::ProcessAction::DumpCore(identity, max_size, timeout_ms) => {
                    if self.snapshot.boot_id.as_ref() == Some(&identity.boot_id)
                        && self.manual_core_unavailable().is_none()
                    {
                        if let Some(vm_id) = self.snapshot.active_vm.clone() {
                            self.process_picker.open = false;
                            self.send(Command::DumpProcessCore {
                                request: ProcessCoreRequest {
                                    vm_id,
                                    target: identity,
                                    max_size,
                                    timeout_ms,
                                    ..ProcessCoreRequest::default()
                                },
                            });
                            if let Some(picked) = self.process_picker.core_picked.take() {
                                self.settings.core_budget_mib = picked >> 20;
                            }
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn terminal_views(&self) -> Vec<(String, bool)> {
        self.terminals
            .iter()
            .map(|(id, terminal)| (id.clone(), terminal.open))
            .collect()
    }

    pub(crate) fn close_terminal_view(&mut self, id: &str) {
        if let Some(terminal) = self.terminals.get_mut(id) {
            terminal.close_view();
        }
    }

    pub(crate) fn activity_title(&self) -> egui::WidgetText {
        self.activity.title(self.settings.font_size)
    }

    pub(crate) fn panel_title(&self, panel: &Panel) -> String {
        match panel {
            Panel::AnalysisSection { report_id, kind } => {
                let path = self
                    .analysis_windows
                    .get(report_id)
                    .map(|report| report.source_path.as_str())
                    .unwrap_or("Unavailable");
                let name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(path);
                let mut name_title: String = name.chars().take(24).collect();
                if name.chars().count() > 24 {
                    name_title.push_str("..");
                }
                let id_title: String = report_id.chars().take(8).collect();
                format!(
                    "{} / {} / {}",
                    crate::analysis::section_title(*kind),
                    name_title,
                    id_title
                )
            }
            Panel::Terminal(id) => self
                .terminals
                .get(id)
                .map(|terminal| format!("{} / PID {}", terminal.run.request.path, terminal.run.pid))
                .unwrap_or_else(|| "Terminal".into()),
            _ => panel.title().into(),
        }
    }

    pub(crate) fn show_panel(&mut self, ui: &mut egui::Ui, panel: &Panel) {
        ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
        self.details_follow.drawn(ui, panel);
        match panel {
            Panel::Summary => {
                crate::summary::show(
                    ui,
                    &self.snapshot,
                    &self.history,
                    self.selected.as_deref(),
                    self.settings.quota_gib,
                    &self.cpu_history,
                );
                let id = egui::Id::new(crate::summary::configuration::CONFIGURE);
                let configure = ui.ctx().data_mut(|data| data.remove_temp::<bool>(id));
                if configure == Some(true) && self.can_configure_vm() {
                    self.configure_vm();
                }
            }
            Panel::Trace => self.events(ui),
            Panel::Network => {
                let vm = self.selected.clone();
                let active = self
                    .snapshot
                    .network_capture
                    .clone()
                    .filter(|_| vm.is_some() && vm == self.snapshot.active_vm);
                let locations = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == vm.as_ref());
                let recordings = locations.map(|location| location.recording_directory.clone());
                let recording_roots = locations
                    .map(|location| location.recording_directories.as_slice())
                    .unwrap_or_default();
                let nat = self.snapshot.vms.iter().any(|config| {
                    Some(&config.id) == vm.as_ref() && (config.nat || config.isolated_network)
                });
                let action = self.network_view.show(
                    ui,
                    NetworkContext {
                        active: active.as_ref(),
                        recordings: recordings.as_deref(),
                        recording_roots,
                        nat,
                        running: self.running()
                            && !self.closing
                            && vm.is_some()
                            && vm == self.snapshot.active_vm,
                        boot_id: self
                            .snapshot
                            .boot_id
                            .as_deref()
                            .filter(|_| vm.is_some() && vm == self.snapshot.active_vm),
                        pending: self.pending_network.is_some(),
                        font_size: self.settings.font_size,
                    },
                );
                match action {
                    Some(NetworkAction::Delete(deletion)) => self.ask_delete_evidence(deletion),
                    Some(NetworkAction::Start) if self.network_toggle_enabled() => {
                        self.send(Command::StartNetworkCapture);
                    }
                    Some(NetworkAction::Stop) if self.network_toggle_enabled() => {
                        self.send(Command::StopNetworkCapture);
                    }
                    _ => {}
                }
            }
            Panel::CoreDump => {
                let roots = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == self.selected.as_ref())
                    .map(|location| location.recording_directories.clone())
                    .unwrap_or_default();
                let unavailable = self.manual_core_unavailable();
                self.core_view
                    .set_tools_dir(antinomie_monitor_core::analysis_tools::tools_dir(
                        &self.options.data_dir,
                    ));
                let action = self.core_view.show(
                    ui,
                    &roots,
                    self.selected.as_deref(),
                    self.selected.is_some() && self.selected == self.snapshot.active_vm,
                    crate::core_view::CoreControls {
                        unavailable,
                        captures: &self.snapshot.process_cores,
                        boot_id: self.snapshot.boot_id.as_deref(),
                        can_cancel: self.running()
                            && !self.closing
                            && self.snapshot.memory_dump.is_none()
                            && self.selected == self.snapshot.active_vm,
                    },
                );
                match action {
                    Some(crate::core_view::CoreAction::Dump) => self.open_core_picker(),
                    Some(crate::core_view::CoreAction::Cancel(capture_id)) => {
                        self.send(Command::CancelCoreCapture { capture_id })
                    }
                    Some(crate::core_view::CoreAction::CancelRun(run_id)) => {
                        self.send(Command::CancelProcessCore { run_id })
                    }
                    Some(crate::core_view::CoreAction::Delete(deletion)) => {
                        self.ask_delete_evidence(deletion)
                    }
                    None => {}
                }
            }
            Panel::Memory => {
                let vm_id = self.selected.clone();
                let vm = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|config| Some(&config.id) == vm_id.as_ref())
                    .cloned();
                let locations = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == vm_id.as_ref())
                    .cloned();
                let running = self.running()
                    && !self.closing
                    && vm_id.is_some()
                    && vm_id == self.snapshot.active_vm;
                let dumping = self
                    .snapshot
                    .memory_dump
                    .clone()
                    .filter(|progress| Some(&progress.dump.vm_id) == vm_id.as_ref());
                let volatility = self
                    .snapshot
                    .analysis_tools
                    .iter()
                    .find(|tool| tool.id == "volatility3");
                let installing = self
                    .snapshot
                    .tool_install
                    .as_ref()
                    .is_some_and(|install| install.id == "volatility3" && !install.finished);
                let action = self.memory_view.show(
                    ui,
                    crate::memory_view::MemoryContext {
                        vm: vm.as_ref(),
                        recordings: locations
                            .as_ref()
                            .map(|location| location.recording_directory.as_path()),
                        recording_roots: locations
                            .as_ref()
                            .map(|location| location.recording_directories.as_slice())
                            .unwrap_or_default(),
                        running,
                        dumping: dumping.as_ref(),
                        pending: false,
                        data_dir: &self.options.data_dir,
                        volatility_installed: volatility
                            .is_some_and(|tool| tool.installed.is_some()),
                        volatility_installing: installing,
                        bases: &self.snapshot.bases,
                        font_size: self.settings.font_size,
                        online_symbols: self.settings.memory_online_symbols,
                        curl: &self.options.curl,
                    },
                );
                match action {
                    Some(crate::memory_view::MemoryAction::Dump) => self.send(Command::DumpMemory),
                    Some(crate::memory_view::MemoryAction::InstallVolatility) => {
                        self.send(Command::InstallTool {
                            id: "volatility3".into(),
                        })
                    }
                    Some(crate::memory_view::MemoryAction::OnlineSymbols(on)) => {
                        self.settings.memory_online_symbols = on;
                    }
                    None => {}
                }
            }
            Panel::Disks => self.disks_panel(ui),
            Panel::Library(page) => self.library_panel(ui, *page),
            Panel::AnalysisSection { report_id, kind } => {
                let key = format!("section:{report_id}:{kind:?}");
                let report = self.analysis_windows.get(report_id).cloned();
                let labels = report
                    .as_ref()
                    .map(|report| self.analysis_labels(ui, report));
                let identities = report
                    .as_ref()
                    .map(|report| self.analysis_identities(&report.id))
                    .unwrap_or_default();
                let view = self.analysis_views.entry(key.clone()).or_default();
                view.bind(report.as_ref().map(|report| report.id.as_str()));
                if let Some(labels) = labels.zip(report.as_ref()) {
                    view.set_record(labels.1, labels.0, identities);
                }
                let action = crate::analysis::workspace_section(
                    ui,
                    report.as_ref(),
                    *kind,
                    &mut view.state,
                    view.preview.as_ref(),
                    view.listing.as_ref(),
                );
                self.analysis_action(&key, action);
            }
            Panel::Triage => self.show_triage(ui),
            Panel::StaticAnalysis => {
                let mut reports = BTreeMap::new();
                for run in self.snapshot.runs.iter().chain(&self.history) {
                    if let Some(report) = &run.analysis {
                        reports.entry(report.id.clone()).or_insert_with(|| {
                            format!("{} — run {} ({:?})", run.request.path, run.id, report.state)
                        });
                    }
                }
                for report in &self.snapshot.analysis_reports {
                    reports.entry(report.id.clone()).or_insert_with(|| {
                        format!(
                            "{} — analysis only ({:?})",
                            report.source_path, report.state
                        )
                    });
                }
                let current = self
                    .selected_analysis
                    .as_ref()
                    .and_then(|id| reports.get(id))
                    .cloned()
                    .unwrap_or_else(|| "Selected run".into());
                ui.horizontal(|ui| {
                    ui.label("Report");
                    egui::ComboBox::from_id_salt("analysis-source")
                        .selected_text(current)
                        .width(ui.available_width())
                        .truncate()
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.selected_analysis, None, "Selected run");
                            for (id, label) in &reports {
                                let label = self
                                    .analysis_directory(id)
                                    .map(|dir| crate::evidence::title(ui, &dir, label))
                                    .unwrap_or_else(|| label.clone());
                                ui.selectable_value(
                                    &mut self.selected_analysis,
                                    Some(id.clone()),
                                    label,
                                );
                            }
                        });
                });
                let shown = self.selected_analysis.clone().or_else(|| {
                    self.selected_run
                        .as_deref()
                        .and_then(|id| {
                            if self.archive_selected {
                                self.history
                                    .iter()
                                    .find(|run| run.id == id)
                                    .or_else(|| self.run(id))
                            } else {
                                self.run(id)
                            }
                        })
                        .and_then(|run| run.analysis.as_ref())
                        .map(|r| r.id.clone())
                });
                let report = shown
                    .as_deref()
                    .and_then(|id| self.analysis_report(id))
                    .cloned();
                crate::analysis::other_progress(
                    ui,
                    self.snapshot
                        .runs
                        .iter()
                        .chain(&self.history)
                        .filter_map(|run| run.analysis.as_ref())
                        .chain(&self.snapshot.analysis_reports),
                    shown.as_deref(),
                );
                if let Some(id) = shown.as_deref() {
                    let related: Vec<_> = self
                        .snapshot
                        .runs
                        .iter()
                        .chain(&self.history)
                        .filter(|run| run.analysis.as_ref().is_some_and(|r| r.id == id))
                        .map(|run| (run.id.clone(), run.request.path.clone()))
                        .collect();
                    if let Some((run_id, path)) = related.first() {
                        if ui
                            .link(format!("{path} ({run_id})"))
                            .on_hover_text("Open the related run")
                            .clicked()
                        {
                            self.select_run(Some(run_id.clone()));
                            self.focus_panel = Some(Panel::RunHistory);
                        }
                    }
                }
                let labels = report
                    .as_ref()
                    .map(|report| self.analysis_labels(ui, report));
                let identities = report
                    .as_ref()
                    .map(|report| self.analysis_identities(&report.id))
                    .unwrap_or_default();
                let view = self.analysis_views.entry("workspace".into()).or_default();
                view.bind(report.as_ref().map(|report| report.id.as_str()));
                if let Some(labels) = labels.zip(report.as_ref()) {
                    view.set_record(labels.1, labels.0, identities);
                }
                let action = crate::analysis::workspace(
                    ui,
                    report.as_ref(),
                    &mut view.state,
                    view.preview.as_ref(),
                    view.listing.as_ref(),
                );
                self.analysis_action("workspace", action);
            }
            Panel::RunHistory => self.run_history(ui),
            Panel::Details => match self.details_follow.of(ui.ctx()) {
                crate::workspace::DetailsOf::Packet => {
                    self.network_view.details(ui, self.settings.font_size)
                }
                crate::workspace::DetailsOf::MemoryRow => {
                    self.memory_view.details(ui, self.settings.font_size)
                }
                crate::workspace::DetailsOf::DiskEntry => {
                    let action = self.disk_view.details(ui);
                    self.disk_action(ui.ctx(), action);
                }
                crate::workspace::DetailsOf::History => self.history_detail(ui),
                crate::workspace::DetailsOf::Triage => self.show_triage_details(ui),
                crate::workspace::DetailsOf::Syscall => self.details(ui),
                crate::workspace::DetailsOf::Core => self.core_view.details(ui),
                crate::workspace::DetailsOf::Static => crate::analysis::details(ui),
            },
            Panel::Activity => self.activity(ui),
            Panel::Terminal(id) => {
                let live = self
                    .terminals
                    .get(id)
                    .is_some_and(|terminal| run_in_live_session(&self.snapshot, &terminal.run));
                let mut commands = Vec::new();
                if let Some(terminal) = self.terminals.get_mut(id) {
                    ui.horizontal(|ui| {
                        ui.label(run_status(&terminal.run));
                        ui.label(format!("Root: {}", root_exit(&terminal.run)));
                        if let Some(error) = terminal
                            .snapshot_error
                            .as_ref()
                            .or(terminal.replay_error.as_ref())
                        {
                            crate::activity::warning(ui, error);
                        }
                    });
                    terminal.last_paint = Some(Instant::now());
                    let interactive = live && terminal.interactive() && !self.closing;
                    let (data, resize) = if live {
                        terminal.terminal.show(ui, interactive)
                    } else {
                        terminal.terminal.show_grid(ui, false, false)
                    };
                    if !data.is_empty() {
                        commands.push(Command::TerminalInput {
                            run_id: id.clone(),
                            data,
                        });
                    }
                    if interactive {
                        if let Some((rows, cols)) = resize {
                            commands.push(Command::TerminalResize {
                                run_id: id.clone(),
                                rows,
                                cols,
                            });
                        }
                    }
                }
                for command in commands {
                    self.send(command);
                }
            }
        }
    }
}

#[cfg(test)]
pub(super) fn show_terminal_viewport(
    ctx: &egui::Context,
    class: egui::ViewportClass,
    terminal: &mut RunTerminal,
    live: bool,
    interactive: bool,
) -> Vec<Command> {
    let close_requested = ctx.input(|input| input.viewport().close_requested());
    let id = terminal.run.id.clone();
    let mut commands = Vec::new();
    let content = |ui: &mut egui::Ui| {
        let (data, resize) = if live {
            terminal.terminal.show(ui, interactive)
        } else {
            terminal.terminal.show_grid(ui, false, false)
        };
        if !data.is_empty() {
            commands.push(Command::TerminalInput {
                run_id: id.clone(),
                data,
            });
        }
        if let Some((rows, cols)) = resize {
            if interactive {
                commands.push(Command::TerminalResize {
                    run_id: id.clone(),
                    rows,
                    cols,
                });
            }
        }
    };
    if class == egui::ViewportClass::Embedded {
        let mut open = terminal.open;
        crate::widgets::window(format!(
            "{} / PID {}",
            terminal.run.request.path, terminal.run.pid
        ))
        .id(egui::Id::new(("terminal-fallback", &id)))
        .open(&mut open)
        .default_size([720.0, 400.0])
        .show(ctx, content);
        terminal.open = open;
    } else {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::terminal())
                    .inner_margin(egui::Margin::same(4)),
            )
            .show(ctx, content);
    }
    if close_requested {
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        terminal.close_view();
    }
    commands
}

pub(super) fn terminal_capacity_message() -> String {
    format!("Terminal view limit reached ({TERMINAL_VIEW_LIMIT}); close a history window")
}

pub(super) fn available_terminal_slots(
    terminals: &BTreeMap<String, RunTerminal>,
    snapshot: &Snapshot,
) -> usize {
    let reclaimable = terminals
        .values()
        .filter(|terminal| !terminal.open && !run_in_live_session(snapshot, &terminal.run))
        .count();
    TERMINAL_VIEW_LIMIT.saturating_sub(terminals.len().saturating_sub(reclaimable))
}

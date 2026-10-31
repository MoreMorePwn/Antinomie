// SPDX-License-Identifier: GPL-3.0-only
//! The Runs tab: Run History filtered to the sample. The runs of every VM
//! (a sample's runs span VMs), the All / Live / Past tabs and a filter field,
//! and below the list the run's details: the recorded process tree with the
//! processes that run library samples tinted, the network route, the machine,
//! what analysis was enabled, and how it was launched and what it ran in.
use super::{parts, summary::vm_name, *};
use crate::app::captures::{self, ProcessSelection};
use crate::widgets::table;
use antinomie_monitor_core::capture_processes::CaptureProcess;
use egui_extras::{Column, TableBuilder};
use std::sync::mpsc;

/// The process tree of the run shown below the list.
enum Tree {
    Reading {
        run_id: String,
        receiver: Receiver<crate::archive::ProcessTreeResult>,
        cancel: Arc<AtomicBool>,
    },
    Ready(String, crate::archive::ProcessTreeResult),
}

impl Tree {
    fn run_id(&self) -> &str {
        match self {
            Self::Reading { run_id, .. } | Self::Ready(run_id, _) => run_id,
        }
    }
}

pub(super) struct RunsTab {
    filter: RunFilter,
    query: String,
    /// The last query that compiled; shown while a typed one does not.
    applied: String,
    selected: Option<String>,
    tree: Option<Tree>,
}

impl Default for RunsTab {
    fn default() -> Self {
        Self {
            filter: RunFilter::All,
            query: String::new(),
            applied: String::new(),
            selected: None,
            tree: None,
        }
    }
}

impl Drop for RunsTab {
    fn drop(&mut self) {
        if let Some(Tree::Reading { cancel, .. }) = &self.tree {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// What a click in the tab asks of the app.
enum Go {
    Triage(String),
    Trace(String, u32),
    Terminal(String),
    Stop(String),
    /// Delete the run (the dialog asks first).
    Delete(String),
}

impl RunsTab {
    #[cfg(test)]
    pub(super) fn select_for_test(&mut self, id: String) {
        self.selected = Some(id);
    }

    /// A run is selected: its details show in the Details panel.
    pub(super) fn has_selection(&self) -> bool {
        self.selected.is_some()
    }

    /// Read the process tree of `run` on a thread, once.
    fn read_tree(&mut self, ctx: &egui::Context, run: &RunSummary) {
        if self
            .tree
            .as_ref()
            .is_some_and(|tree| tree.run_id() == run.id)
        {
            return;
        }
        if let Some(Tree::Reading { cancel, .. }) = &self.tree {
            cancel.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let (sender, receiver) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker = Arc::clone(&cancel);
        let (directory, pid, path) = (run.directory.clone(), run.pid, run.request.path.clone());
        let wake = ctx.clone();
        let spawned = std::thread::Builder::new()
            .name("sample-run-tree".into())
            .spawn(move || {
                // A deleted run's record keeps the tree it had.
                let result = match antinomie_monitor_core::samples::saved_process_tree(&directory) {
                    Some(tree) => Ok(tree),
                    None => Ok(antinomie_monitor_core::recording::Recording {
                        directory,
                        manifest: serde_json::Value::Null,
                        events: Vec::new(),
                    })
                    .and_then(|recording| recording.process_tree_cancellable(pid, &path, &worker))
                    .map_err(|error| error.to_string()),
                };
                let _ = sender.send(result);
                wake.request_repaint();
            });
        self.tree = Some(match spawned {
            Ok(_) => Tree::Reading {
                run_id: run.id.clone(),
                receiver,
                cancel,
            },
            Err(error) => Tree::Ready(run.id.clone(), Err(error.to_string())),
        });
    }

    fn poll(&mut self) {
        if let Some(Tree::Reading {
            run_id, receiver, ..
        }) = &self.tree
        {
            if let Ok(result) = receiver.try_recv() {
                self.tree = Some(Tree::Ready(run_id.clone(), result));
            }
        }
    }
}

impl MonitorApp {
    pub(super) fn runs_tab(&mut self, ui: &mut egui::Ui, data: &Arc<Data>) {
        let Some(detail) = self.samples_page.detail.as_mut() else {
            return;
        };
        let mut state = std::mem::take(&mut detail.runs);
        state.poll();
        let mut go = None;
        self.runs_body(ui, data, &mut state, &mut go);
        if let Some(detail) = self.samples_page.detail.as_mut() {
            detail.runs = state;
        }
        self.apply_go(ui.ctx(), data, go);
    }

    /// Carry out what a click in the tab or in the details asked for.
    fn apply_go(&mut self, ctx: &egui::Context, data: &Arc<Data>, go: Option<Go>) {
        match go {
            Some(Go::Triage(id)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.run.id == id) {
                    self.open_sample_run(&entry.run, crate::workspace::Panel::Triage, None);
                }
            }
            Some(Go::Trace(id, pid)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.run.id == id) {
                    self.open_sample_run(
                        &entry.run,
                        crate::workspace::Panel::Trace,
                        Some(format!("process.pid == {pid}")),
                    );
                }
            }
            Some(Go::Terminal(id)) => {
                if let Some(run) = self.run(&id).cloned() {
                    self.reopen(run);
                }
            }
            Some(Go::Stop(id)) => self.request_kill(Some(&id)),
            Some(Go::Delete(id)) => {
                if let Some(entry) = data.runs.iter().find(|entry| entry.run.id == id) {
                    self.start_delete_run(ctx, data, entry.number, &entry.run);
                }
            }
            None => {}
        }
    }

    /// The Details panel while the Samples page is on screen: the run
    /// selected on the open sample's Runs tab, as Run History shows a run's
    /// details, with the processes that run library samples tinted.
    pub(in crate::app) fn sample_run_details(&mut self, ui: &mut egui::Ui) {
        let Some(detail) = self.samples_page.detail.as_mut() else {
            crate::widgets::info_panel(ui, &Self::no_sample_run_panel());
            return;
        };
        let Some(data) = detail.data.clone() else {
            return;
        };
        let mut state = std::mem::take(&mut detail.runs);
        state.poll();
        let selected = state
            .selected
            .clone()
            .and_then(|id| data.runs.iter().find(|entry| entry.run.id == id));
        let mut go = None;
        match selected {
            Some(entry) => {
                crate::details_scroll::show(
                    ui,
                    "sample_run_details_scroll",
                    entry.run.id.clone(),
                    |ui, _| self.run_details(ui, &data, entry, &mut state, &mut go),
                );
            }
            None => crate::widgets::info_panel(ui, &Self::no_sample_run_panel()),
        }
        if let Some(detail) = self.samples_page.detail.as_mut() {
            detail.runs = state;
        }
        self.apply_go(ui.ctx(), &data, go);
    }

    fn no_sample_run_panel() -> crate::widgets::InfoPanel<'static> {
        crate::widgets::InfoPanel {
            icon: egui_phosphor::regular::LIST_MAGNIFYING_GLASS,
            title: "Select a run to view its details",
            about: "Details show a run's recorded process tree, analysis checklist, \
                    route, machine and environment.",
            steps_title: "To see a run",
            steps: &["Open a sample, then select a run on its Runs tab."],
        }
    }

    fn runs_body(
        &mut self,
        ui: &mut egui::Ui,
        data: &Arc<Data>,
        state: &mut RunsTab,
        go: &mut Option<Go>,
    ) {
        ui.horizontal_wrapped(|ui| {
            for (filter, label) in [
                (RunFilter::All, "All"),
                (RunFilter::Live, "Live"),
                (RunFilter::Past, "Past"),
            ] {
                if widgets::tab(ui, state.filter == filter, &widgets::TabItem::new(label)).clicked()
                {
                    state.filter = filter;
                }
            }
            widgets::chip(ui, format!("sample == {}", data.record.name), Tone::Accent)
                .on_hover_text("The runs of this sample, on every VM");
        });
        let fields = crate::run_filter::fields();
        crate::query::filter_edit_fields(
            ui,
            &mut state.query,
            "process.exe contains \"sample\" && run.has_static",
            ui.available_width(),
            &fields,
            &[],
        );
        let draft = crate::run_filter::compile(&state.query, &fields);
        if let Some(error) = draft.error.as_ref() {
            crate::activity::error(ui, format!("{error} · showing last valid filter"));
        } else {
            state.applied.clone_from(&state.query);
        }
        let compiled = crate::run_filter::compile(&state.applied, &fields);
        let listing: Vec<&RunEntry> = data
            .runs
            .iter()
            .filter(|entry| match state.filter {
                RunFilter::All => true,
                RunFilter::Live => self.live_history_run(&entry.run),
                RunFilter::Past => !self.live_history_run(&entry.run),
            })
            .collect();
        let shown: Vec<&RunEntry> = if compiled.keeps_everything() {
            listing.clone()
        } else {
            let runs: Vec<RunSummary> = listing.iter().map(|entry| entry.run.clone()).collect();
            crate::run_filter::refresh_facts(ui, &runs);
            listing
                .iter()
                .filter(|entry| {
                    let annotation = crate::evidence::annotation(ui, &entry.run.directory);
                    let mut row = crate::run_filter::row(
                        &entry.run,
                        annotation.as_ref(),
                        run_status(&entry.run),
                        root_exit(&entry.run),
                    );
                    crate::run_filter::append_facts(ui, &entry.run, &mut row);
                    compiled.keep_table(&row)
                })
                .copied()
                .collect()
        };
        ui.weak(format!("{} of {} runs", shown.len(), data.runs.len()));
        if data.runs.is_empty() {
            parts::muted_line(ui, "Never run.");
            return;
        }
        let hint_height = ui.spacing().interact_size.y + 8.0;
        let list_height = (ui.available_height() - hint_height - 28.0).max(120.0);
        self.run_table(ui, &shown, state, go, list_height);
        ui.add_space(6.0);
        if state.selected.is_some() {
            parts::muted_line(ui, "Run details are in the Details panel below.");
        } else {
            parts::muted_line(ui, "Select a run for its details.");
        }
    }

    fn run_table(
        &mut self,
        ui: &mut egui::Ui,
        shown: &[&RunEntry],
        state: &mut RunsTab,
        go: &mut Option<Go>,
        height: f32,
    ) {
        let font = self.settings.font_size;
        let order =
            crate::table_sort::order(ui.ctx(), "sample_runs", shown.len(), |column, a, b| {
                let (a, b) = (&shown[a].run, &shown[b].run);
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
                    4 => root_exit(a).cmp(&root_exit(b)),
                    _ => vm_name(a).cmp(&vm_name(b)),
                }
            });
        let mut select = None;
        let start_width = parts::fitted_up_to(
            ui,
            &egui::TextStyle::Body.resolve(ui.style()),
            shown
                .iter()
                .map(|entry| crate::time_format::unix_ms(entry.run.started_ms)),
            460.0,
        );
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height + 28.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt("sample_runs")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .resizable(true)
                    .column(Column::initial(start_width).at_least(110.0))
                    .column(Column::remainder().at_least(150.0).resizable(false))
                    .column(Column::initial(110.0).range(70.0..=320.0))
                    .column(Column::initial(100.0).range(70.0..=220.0))
                    .column(Column::initial(85.0).range(60.0..=160.0))
                    .column(Column::initial(80.0).range(60.0..=200.0))
                    .column(Column::exact(72.0))
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(28.0, |mut header| {
                        for (column, name) in [
                            "Start time",
                            "Executable",
                            "Arguments",
                            "Tree status",
                            "Root exit",
                            "VM",
                        ]
                        .into_iter()
                        .enumerate()
                        {
                            header.col(|ui| {
                                crate::table_sort::header(ui, "sample_runs", column, name)
                            });
                        }
                        header.col(|ui| table::head(ui, ""));
                    })
                    .body(|body| {
                        body.rows(font + 16.0, shown.len(), |mut row| {
                            let entry = shown[order[row.index()]];
                            let run = &entry.run;
                            row.set_selected(state.selected.as_deref() == Some(run.id.as_str()));
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(crate::time_format::unix_ms(run.started_ms))
                                        .truncate()
                                        .selectable(false),
                                );
                            });
                            row.col(|ui| {
                                let title =
                                    crate::evidence::title(ui, &run.directory, &run.request.path);
                                crate::app::history_columns::executable_cell(ui, title, run);
                            });
                            row.col(|ui| {
                                let args = run.request.args.join(" ");
                                ui.add(egui::Label::new(&args).selectable(false).truncate())
                                    .on_hover_text(run.request.args.join("\n"));
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(run_status(run)).selectable(false))
                                    .on_hover_text(execution_detail(run));
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(root_exit(run)).selectable(false));
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(vm_name(run)).selectable(false).truncate());
                            });
                            row.col(|ui| {
                                let known = self.run(&run.id).is_some();
                                if parts_icon(
                                    ui,
                                    egui_phosphor::regular::TERMINAL_WINDOW,
                                    if known {
                                        "Open terminal"
                                    } else {
                                        "Open the run's VM in the sidebar first"
                                    },
                                    known,
                                ) {
                                    *go = Some(Go::Terminal(run.id.clone()));
                                }
                                let live = self.snapshot.runs.iter().any(|live| live.id == run.id)
                                    && matches!(
                                        run.state,
                                        RunState::Running | RunState::TerminalClosed
                                    )
                                    && !self.closing
                                    && self.running()
                                    && self.pending_kill.is_none();
                                if parts_icon(
                                    ui,
                                    egui_phosphor::regular::STOP,
                                    "Stop run and descendants",
                                    live,
                                ) {
                                    *go = Some(Go::Stop(run.id.clone()));
                                }
                            });
                            let response = row.response();
                            response.context_menu(|ui| {
                                if ui
                                    .add_enabled(entry.folder, egui::Button::new("Open Triage"))
                                    .clicked()
                                {
                                    *go = Some(Go::Triage(run.id.clone()));
                                    ui.close_menu();
                                }
                                if entry.folder {
                                    crate::evidence::menu(ui, &run.directory);
                                }
                                self.delete_run_item(ui, entry, go);
                                super::super::notes::menu_item(ui, || run_reference(entry));
                            });
                            if response.clicked() || response.double_clicked() {
                                select = Some(run.id.clone());
                                if response.double_clicked() && entry.folder {
                                    *go = Some(Go::Triage(run.id.clone()));
                                }
                            }
                        });
                    });
            },
        );
        if let Some(id) = select {
            state.selected = Some(id);
        }
    }

    fn run_details(
        &mut self,
        ui: &mut egui::Ui,
        data: &Arc<Data>,
        entry: &RunEntry,
        state: &mut RunsTab,
        go: &mut Option<Go>,
    ) {
        let run = &entry.run;
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.label(
                    RichText::new(format!(
                        "{} · {} · {}",
                        parts::run_name(entry.number),
                        vm_name(run),
                        crate::time_format::unix_ms(run.started_ms)
                    ))
                    .strong()
                    .color(theme::palette().heading),
                );
            },
            |ui| {
                self.delete_run_item(ui, entry, go);
                if ui
                    .add_enabled(entry.folder, egui::Button::new("Open Triage"))
                    .on_disabled_hover_text("The run's folder was deleted")
                    .clicked()
                {
                    *go = Some(Go::Triage(run.id.clone()));
                }
            },
        );
        crate::run_recording::show(ui, run);
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            ui.strong("Recorded process tree");
            if ui.button("Refresh tree").clicked() {
                state.tree = None;
            }
            // The tint legend: two entries.
            for (color, label) in [
                (theme::error(), "runs this sample"),
                (theme::palette().string, "runs another library sample"),
            ] {
                ui.label(RichText::new("■").color(color));
                ui.label(RichText::new(label).small().color(theme::muted()));
            }
        });
        let kept_tree = !entry.folder
            && run
                .directory
                .join(antinomie_monitor_core::samples::PROCESS_TREE_FILE)
                .is_file();
        if entry.folder || kept_tree {
            state.read_tree(ui.ctx(), run);
        }
        let font = self.settings.font_size;
        let own = paths_of(data, run, true);
        let other = paths_of(data, run, false);
        let root = run.pid;
        let tint = move |process: &CaptureProcess| -> Option<egui::Color32> {
            let exe = process.exe.as_deref().unwrap_or_default();
            if (process.pid == root && root != 0) || (!exe.is_empty() && own.contains(exe)) {
                Some(theme::error())
            } else if !exe.is_empty() && other.contains(exe) {
                Some(theme::palette().string)
            } else {
                None
            }
        };
        match &state.tree {
            Some(Tree::Ready(_, Ok((processes, issues)))) => {
                for issue in issues {
                    crate::activity::warning(ui, issue);
                }
                let height = 240.0;
                let selection = ui
                    .allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| captures::process_tree_tinted(ui, processes, None, font, &tint),
                    )
                    .inner;
                if let Some(ProcessSelection::Process(pid)) = selection {
                    *go = Some(Go::Trace(run.id.clone(), pid));
                }
            }
            Some(Tree::Ready(_, Err(error))) => {
                crate::activity::warning(ui, error);
            }
            Some(Tree::Reading { .. }) => {
                theme::loading(ui, "Reading saved lifecycle records…");
            }
            None => {
                if !entry.folder {
                    parts::muted_line(ui, "The run's folder was deleted and no tree was kept.");
                }
            }
        }
        ui.add_space(6.0);
        let labels = self.run_labels.of(ui.ctx(), run);
        crate::route_ui::line(
            ui,
            &crate::route_ui::describe(run.route.as_ref(), labels.and_then(|labels| labels.route)),
        );
        if let Some(machine) = &run.machine {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Machine").color(theme::muted()));
                ui.label(
                    RichText::new(format!("looks like a {}", machine.summary()))
                        .color(theme::text()),
                )
                .on_hover_text(machine_hover(machine));
            });
        }
        enabled_features(ui, run, labels);
        launch_details(ui, run);
        environment(ui, run);
    }
}

/// The guest paths a run's tree is tinted by: where this sample was sent on
/// the run's VM (`own`), or where any other library sample was.
fn paths_of(data: &Data, run: &RunSummary, own: bool) -> std::collections::HashSet<String> {
    let mut paths: std::collections::HashSet<String> = data
        .sent
        .iter()
        .filter(|sent| sent.vm_id == run.vm_id && (sent.sha256 == data.record.sha256) == own)
        .map(|sent| sent.path.clone())
        .collect();
    if own {
        paths.insert(run.request.path.clone());
        if let Some(script) = run.request.args.first().filter(|arg| arg.starts_with('/')) {
            paths.insert(script.clone());
        }
    }
    paths
}

fn parts_icon(ui: &mut egui::Ui, glyph: &str, tooltip: &str, enabled: bool) -> bool {
    ui.add_enabled(enabled, egui::Button::new(glyph).frame(false))
        .on_hover_text(tooltip)
        .on_disabled_hover_text(tooltip)
        .clicked()
}

/// The environment the run started in, folded away by default.
fn environment(ui: &mut egui::Ui, run: &RunSummary) {
    egui::CollapsingHeader::new("Environment")
        .id_salt("sample_run_environment")
        .default_open(false)
        .show(ui, |ui| {
            let Some(environment) = &run.environment else {
                parts::muted_line(ui, "Not recorded: this run started before 0.8.0.");
                return;
            };
            egui::ScrollArea::horizontal()
                .id_salt("sample_run_environment_scroll")
                .show(ui, |ui| {
                    egui::Grid::new("sample_run_environment_grid")
                        .num_columns(2)
                        .spacing([12.0, 4.0])
                        .show(ui, |ui| {
                            parts::row(
                                ui,
                                "VM",
                                format!(
                                    "{} · {} CPUs · {} MiB RAM · {} GiB disk",
                                    environment.vm_name,
                                    environment.cpus,
                                    environment.ram_mib,
                                    environment.disk_gib
                                ),
                            );
                            parts::row(ui, "Network", environment.network.clone());
                            parts::row(ui, "Device profile", environment.stealth.clone());
                            parts::row(
                                ui,
                                "Base image",
                                format!(
                                    "{}{}{}",
                                    environment.base_name,
                                    environment
                                        .base_revision
                                        .map_or(String::new(), |r| format!(" revision {r}")),
                                    if environment.base_identity.is_empty() {
                                        String::new()
                                    } else {
                                        format!(
                                            " · {}",
                                            &environment.base_identity
                                                [..environment.base_identity.len().min(8)]
                                        )
                                    }
                                ),
                            );
                            parts::row(
                                ui,
                                "Guest kernel",
                                format!(
                                    "{}{}{}",
                                    environment.kernel_release,
                                    if environment.arch.is_x86_64() {
                                        String::new()
                                    } else {
                                        format!(" · {}", environment.arch.label())
                                    },
                                    if environment.patch_series.is_empty() {
                                        String::new()
                                    } else {
                                        format!(
                                            " · patch series {}",
                                            &environment.patch_series
                                                [..environment.patch_series.len().min(8)]
                                        )
                                    }
                                ),
                            );
                            parts::row(
                                ui,
                                "Detection rules",
                                if environment.rule_packs.is_empty() {
                                    "None installed".to_owned()
                                } else {
                                    environment.rule_packs.join(" · ")
                                },
                            );
                            parts::row(
                                ui,
                                "Tools",
                                if environment.tools.is_empty() {
                                    "None".to_owned()
                                } else {
                                    environment.tools.join(" · ")
                                },
                            );
                            parts::row(ui, "App", format!("Antinomie {}", environment.app_version));
                            parts::copyable(ui, "Environment hash", &environment.hash);
                        });
                });
        });
}

/// The reference a note on this run carries.
fn run_reference(entry: &RunEntry) -> antinomie_monitor_core::samples::NoteRef {
    antinomie_monitor_core::samples::NoteRef::new(
        antinomie_monitor_core::samples::RefKind::Run,
        format!("{}/{}", entry.run.vm_id, entry.run.id),
        parts::run_name(entry.number),
    )
}

impl MonitorApp {
    /// "Delete run…": enabled for a run with a folder that is not running.
    fn delete_run_item(&self, ui: &mut egui::Ui, entry: &RunEntry, go: &mut Option<Go>) {
        let live = self.sample_run_live(&entry.run);
        let enabled = entry.folder && !live;
        let response = ui
            .add_enabled(enabled, egui::Button::new("Delete run…"))
            .on_disabled_hover_text(if live {
                "The run is still running; stop it first"
            } else {
                "The run's folder was already deleted"
            });
        if response.clicked() {
            *go = Some(Go::Delete(entry.run.id.clone()));
            ui.close_menu();
        }
    }
}

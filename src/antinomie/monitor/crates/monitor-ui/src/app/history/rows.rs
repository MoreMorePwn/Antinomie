// SPDX-License-Identifier: GPL-3.0-only
//! The parts of the run history list: the state tabs, the filtered runs, the keys and the rows.
use super::*;

/// What a click in the run list asks for, gathered over the rows.
pub(super) struct RunClicks {
    pub(super) inspect: Option<(String, bool)>,
    pub(super) reopen: Option<String>,
    pub(super) delete: Option<crate::evidence_delete::Deletion>,
}

impl MonitorApp {
    /// The All, Live and Past tabs and the refresh button.
    pub(super) fn run_filter_tabs(&mut self, ui: &mut egui::Ui) {
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
    }

    /// The runs of the VM that the filter keeps, with their count.
    pub(super) fn filtered_runs(
        &mut self,
        ui: &mut egui::Ui,
        vm_id: &str,
        fields: &[crate::query::FieldSpec<'_>],
    ) -> Arc<Vec<RunSummary>> {
        // Copies for drawing only: they keep whether a report exists, not the
        // report's rows. The listing is rebuilt only when the runs it shows
        // change, not every frame.
        let key = self.run_list_key(vm_id);
        if self
            .run_list_cache
            .as_ref()
            .is_none_or(|(cached, _)| *cached != key)
        {
            let listing = self.run_listing(vm_id);
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
        let draft = crate::run_filter::compile(&self.run_query, fields);
        if let Some(error) = draft.error.as_ref() {
            crate::activity::inline_only(
                ui,
                crate::activity::Level::Warn,
                format!("{error} · showing last valid filter"),
            );
        } else {
            self.applied_run_query.clone_from(&self.run_query);
            crate::query::remember_valid_filter(ui, &self.run_query);
        }
        let compiled = crate::run_filter::compile(&self.applied_run_query, fields);
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
            ui.colored_label(theme::muted(), "Hidden by filter.");
            if ui.link("Clear filter").clicked() {
                self.clear_run_filter();
            }
        }
        runs
    }

    /// Home, End and the arrow keys over the focused list: the row they move to.
    pub(super) fn history_navigation(
        &self,
        ui: &mut egui::Ui,
        runs: &[&RunSummary],
        pane_id: egui::Id,
    ) -> Option<usize> {
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
        }
    }

    /// One row of the run list: its cells, its icons, its menu and its clicks.
    pub(super) fn run_history_row(
        &mut self,
        mut row: egui_extras::TableRow<'_, '_>,
        run: &RunSummary,
        widths: &HistoryColumns,
        pane: &egui::Response,
        clicks: &mut RunClicks,
    ) {
        let RunClicks {
            inspect,
            reopen,
            delete,
        } = clicks;
        row.set_selected(self.selected_run.as_ref() == Some(&run.id));
        row.col(|ui| {
            ui.add(
                egui::Label::new(crate::time_format::unix_ms(run.started_ms))
                    .truncate()
                    .selectable(false)
                    .sense(egui::Sense::hover()),
            );
        });
        row.col(|ui| {
            let title = crate::evidence::title(ui, &run.directory, &run.request.path);
            executable_cell(ui, title, run);
        });
        if widths.wide {
            row.col(|ui| match &run.request.sample {
                Some(sample) => {
                    ui.add(
                        egui::Label::new(&sample.name)
                            .selectable(false)
                            .sense(egui::Sense::hover())
                            .truncate(),
                    )
                    .on_hover_text(format!("Library sample {}", sample.sha256));
                }
                None => {
                    ui.add(
                        egui::Label::new(theme::hint_text("-"))
                            .selectable(false)
                            .sense(egui::Sense::hover()),
                    );
                }
            });
        }
        if widths.wide {
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
        }
        row.col(|ui| {
            let detail = [execution_detail(run), crate::run_recording::tooltip(run)];
            ui.add(
                egui::Label::new(crate::run_state_line::text(run, run_status(run)))
                    .selectable(false)
                    .sense(egui::Sense::hover()),
            )
            .on_hover_text(detail.join("\n"));
            if let Some(badge) = crate::run_recording::badge(run) {
                ui.colored_label(theme::error(), badge);
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
                *reopen = Some(run.id.clone());
            }
            if icon(
                ui,
                egui_phosphor::regular::STOP,
                "Stop run and descendants",
                self.snapshot.runs.iter().any(|live| live.id == run.id)
                    && run.state.can_stop()
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
            // A run that never ran holds no recording: it can go. The
            // item sits with the run's own actions, above the filters.
            if run.state.never_recorded() {
                let live = self.snapshot.runs.iter().any(|live| live.id == run.id);
                let blocked = live.then_some(FAILED_RUN_CLEANING);
                if crate::evidence_delete::menu_item(ui, blocked) {
                    let title = crate::evidence::title(ui, &run.directory, &run.request.path);
                    *delete = Some(crate::evidence_delete::Deletion::failed_run(
                        &run.directory,
                        &title,
                    ));
                }
                ui.separator();
            }
            let annotation = crate::evidence::annotation(ui, &run.directory);
            let fields =
                crate::run_filter::row(run, annotation.as_ref(), run_status(run), root_exit(run));
            // A run of a library sample can be noted: the note goes to that sample.
            let note = run.request.sample.as_ref().map(|sample| {
                (
                    Some(sample.sha256.clone()),
                    antinomie_monitor_core::samples::NoteRef::new(
                        antinomie_monitor_core::samples::RefKind::Run,
                        format!("{}/{}", run.vm_id, run.id),
                        format!(
                            "Run {} · {}",
                            run.id,
                            crate::time_format::unix_ms(run.started_ms)
                        ),
                    ),
                )
            });
            crate::query::row_menu_into(
                ui,
                egui::Id::new(("run-history-row-menu", "run_history")),
                &mut self.run_query,
                &fields,
                crate::query::RowMenuExtras {
                    no_note: note
                        .is_none()
                        .then_some("This run did not start a sample of the library"),
                    note,
                    columns: &[
                        ("Executable", "process.exe"),
                        ("Sample", "sample"),
                        ("Arguments", "process.argv"),
                        ("Tree status", "run.state"),
                        ("Root exit", "run.root_exit"),
                    ],
                    ..Default::default()
                },
            );
        });
        if response.clicked() || response.double_clicked() {
            pane.request_focus();
            *inspect = Some((run.id.clone(), response.double_clicked()));
        }
    }
}

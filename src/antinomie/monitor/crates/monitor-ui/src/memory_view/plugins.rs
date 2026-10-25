// SPDX-License-Identifier: GPL-3.0-only
//! Choosing a Volatility plugin and its options, and the saved runs.
use super::*;

impl MemoryView {
    pub(super) fn analysis(
        &mut self,
        ui: &mut egui::Ui,
        cx: &MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let mut action = None;
        let Some(dump) = self.dump().cloned() else {
            empty_state(
                ui,
                if cx.vm.is_none() {
                    "Select a VM to see its memory dumps."
                } else if cx.running {
                    "Dump the VM's memory, then pick a Volatility plugin or a MemNixFS report \
                     to run on it. Every result is saved with its dump."
                } else {
                    "Start the VM and dump its memory, or import a dump made elsewhere. \
                     Volatility 3 or MemNixFS then analyses it: processes, open files, \
                     network connections, kernel modules, injected code and more."
                },
            );
            return None;
        };
        ui.add_space(2.0);
        self.analyzer_tabs(ui);
        match self.analyzer {
            Analyzer::Volatility => {
                if let Some(next) = self.volatility_banner(ui, cx) {
                    action = Some(next);
                }
            }
            Analyzer::MemNixFs => {
                if let Some(next) = self.engine_banner(ui, cx) {
                    action = Some(next);
                }
            }
        }
        if !dump.complete() {
            ui.add_space(8.0);
            if let Some(error) = &dump.error {
                crate::activity::error(ui, error);
            } else {
                ui.colored_label(theme::muted(), "This dump is still being written.");
            }
            return action;
        }
        match self.analyzer {
            Analyzer::Volatility => {
                if let Some(next) = self.plugin_bar(ui, &dump, cx) {
                    action = Some(next);
                }
            }
            Analyzer::MemNixFs => self.report_bar(ui, &dump, cx.font_size),
        }
        crate::toasts::take_failure(ui.ctx(), &mut self.status);
        if let Some((message, _)) = &self.status {
            ui.colored_label(theme::muted(), message);
        }
        ui.add_space(4.0);
        egui::SidePanel::left("memory_runs")
            .resizable(true)
            .default_width(230.0)
            .width_range(170.0..=420.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| self.run_list(ui, cx.font_size));
        egui::CentralPanel::default()
            .frame(egui::Frame::new())
            .show_inside(ui, |ui| self.result_view(ui, &dump, cx.font_size));
        action
    }

    /// The state of Volatility's plugin list: loading, or why it failed.
    fn volatility_banner(
        &mut self,
        ui: &mut egui::Ui,
        cx: &MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let mut action = None;
        let failed = match &self.catalog {
            Catalog::Failed(error) => Some(error.clone()),
            _ => None,
        };
        match &self.catalog {
            Catalog::Ready(..) => {}
            Catalog::Loading(_) | Catalog::Unknown => {
                theme::loading_colored(ui, theme::muted(), "Listing Volatility plugins…");
            }
            Catalog::Failed(_) => {
                let error = failed.unwrap_or_default();
                egui::Frame::new()
                    .fill(theme::raised())
                    .corner_radius(4.0)
                    .inner_margin(8.0)
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            crate::activity::error(ui, &error);
                            if cx.volatility_installed {
                                if ui.button("Try again").clicked() {
                                    self.catalog = Catalog::Unknown;
                                }
                            } else if cx.volatility_installing {
                                theme::loading(ui, "Installing Volatility 3…");
                            } else {
                                ui.label(
                                    "Memory analysis runs Volatility 3 on the system Python 3. \
                                     Install it once (about 5 MB, pinned release):",
                                );
                                if ui
                                    .add(
                                        egui::Button::new(
                                            RichText::new("Install Volatility 3")
                                                .color(theme::palette().primary_text),
                                        )
                                        .fill(theme::primary()),
                                    )
                                    .clicked()
                                {
                                    action = Some(MemoryAction::InstallVolatility);
                                }
                            }
                        });
                    });
            }
        }
        action
    }

    fn plugin_bar(
        &mut self,
        ui: &mut egui::Ui,
        dump: &MemoryDump,
        cx: &MemoryContext<'_>,
    ) -> Option<MemoryAction> {
        let (data_dir, font_size) = (cx.data_dir, cx.font_size);
        let Catalog::Ready(volatility, catalog) = &self.catalog else {
            return None;
        };
        let mut action = None;
        let plugins = &catalog.plugins;
        let failures = &catalog.failures;
        for failure in failures {
            crate::activity::report(
                ui.ctx(),
                crate::activity::Level::Error,
                format!(
                    "Failed to load Volatility plugin: {}",
                    failure.trim_start_matches("volatility3.plugins.")
                ),
            );
        }
        let mut reload = false;
        let list_os = match &self.list_os {
            Some((id, os)) if id == &dump.id => *os,
            _ => dump.os,
        };
        let community_os = &self.community_os;
        // A catalog plugin's system is in its manifest; others' in their name.
        let os_of = |plugin: &PluginInfo| {
            plugin.os().or_else(|| {
                plugin
                    .community
                    .then(|| plugin.name.split('.').next())
                    .flatten()
                    .and_then(|id| community_os.get(id).copied())
            })
        };
        let applies = |plugin: &&PluginInfo| {
            os_of(plugin).is_none_or(|os| os == list_os)
                && !matches!(
                    plugin.name.as_str(),
                    "configwriter.ConfigWriter"
                        | "layerwriter.LayerWriter"
                        | "frameworkinfo.FrameworkInfo"
                )
        };
        if self.plugin.as_ref().is_none_or(|name| {
            !plugins
                .iter()
                .any(|plugin| &plugin.name == name && applies(&plugin))
        }) {
            let default = format!("{}.pslist.PsList", list_os.prefix());
            self.plugin = plugins
                .iter()
                .find(|plugin| plugin.name == default)
                .or_else(|| plugins.iter().find(applies))
                .map(|plugin| plugin.name.clone());
        }
        let current = self
            .plugin
            .as_ref()
            .and_then(|name| plugins.iter().find(|plugin| &plugin.name == name))
            .cloned()?;
        let mut chosen = None;
        let mut run = None;
        let mut chosen_os = None;
        ui.horizontal(|ui| {
            for os in Os::ALL {
                if crate::widgets::tab(ui, list_os == os, &crate::widgets::TabItem::new(os.label()))
                    .on_hover_text(format!("List the plugins for {} dumps", os.label()))
                    .clicked()
                {
                    chosen_os = Some(os);
                }
            }
            if list_os != dump.os {
                crate::activity::warning(
                    ui,
                    format!(
                        "This dump is {}: {} plugins will not find what they look for",
                        dump.os.label(),
                        list_os.label()
                    ),
                );
            }
            ui.separator();
            ui.label(RichText::new("Plugin").color(theme::muted()));
            egui::ComboBox::from_id_salt("memory_plugin")
                .width(360.0)
                .height(480.0)
                .selected_text(RichText::new(&current.name).font(theme::mono(font_size - 1.0)))
                .show_ui(ui, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text(crate::theme::hint_text("Search plugins"))
                            .desired_width(f32::INFINITY),
                    )
                    .request_focus();
                    ui.checkbox(&mut self.show_deprecated, "Show deprecated names");
                    ui.separator();
                    let needle = self.search.trim().to_lowercase();
                    let mut group = String::new();
                    // Volatility's own plugins, then the community folder's.
                    let ordered = plugins
                        .iter()
                        .filter(|plugin| !plugin.community)
                        .chain(plugins.iter().filter(|plugin| plugin.community));
                    for plugin in ordered.filter(applies) {
                        if plugin.deprecated() && !self.show_deprecated {
                            continue;
                        }
                        if !needle.is_empty()
                            && !plugin.name.to_lowercase().contains(&needle)
                            && !plugin.help.to_lowercase().contains(&needle)
                        {
                            continue;
                        }
                        let area = if plugin.community {
                            let os = os_of(plugin).map_or("generic", Os::prefix);
                            format!("community · {os}")
                        } else {
                            plugin_area(&plugin.name)
                        };
                        if area != group {
                            group = area.clone();
                            ui.add_space(2.0);
                            ui.label(RichText::new(area).small().color(theme::heading()));
                        }
                        let selected = plugin.name == current.name;
                        if ui
                            .selectable_label(
                                selected,
                                RichText::new(&plugin.name).font(theme::mono(font_size - 1.0)),
                            )
                            .on_hover_text(&plugin.help)
                            .clicked()
                        {
                            chosen = Some(plugin.name.clone());
                        }
                    }
                });
            let running = self
                .jobs
                .iter()
                .any(|job| job.run.dump_id == dump.id && job.run.plugin == current.name);
            if ui
                .add_enabled(
                    !running,
                    egui::Button::new(
                        RichText::new(format!("{} Run", egui_phosphor::regular::PLAY))
                            .color(theme::palette().primary_text),
                    )
                    .fill(theme::primary()),
                )
                .on_hover_text("Run the plugin on this dump; the result is saved with it")
                .on_disabled_hover_text("This plugin is already running on this dump")
                .clicked()
            {
                let values = self.values.get(&current.name).cloned().unwrap_or_default();
                run = Some(memory::plugin_args(&current, &values));
            }
            ui.menu_button(egui_phosphor::regular::GEAR, |ui| {
                ui.set_max_width(440.0);
                let mut online = cx.online_symbols;
                if ui
                    .checkbox(&mut online, "Look up symbol tables online")
                    .changed()
                {
                    action = Some(MemoryAction::OnlineSymbols(online));
                }
                ui.label(
                    RichText::new(format!(
                        "For Linux and macOS dumps without a symbol table of their own (imported \
                         dumps): after Volatility's folders, the table of the dump's kernel is \
                         looked up by its banner in {} on GitHub, about 11,000 distribution \
                         kernels, and kept in Volatility's cache. Dumps of Antinomie's VMs carry \
                         their base's table and stay offline.",
                        memory::ONLINE_SYMBOLS_NAME
                    ))
                    .color(theme::muted()),
                );
            })
            .response
            .on_hover_text("Memory analysis options");
            let community = plugins.iter().filter(|plugin| plugin.community).count();
            let label = if failures.is_empty() {
                format!(
                    "{} Community ({community})",
                    egui_phosphor::regular::PUZZLE_PIECE
                )
            } else {
                format!(
                    "{} Community ({community}, {} failed)",
                    egui_phosphor::regular::PUZZLE_PIECE,
                    failures.len()
                )
            };
            ui.menu_button(label, |ui| {
                ui.set_max_width(420.0);
                if !failures.is_empty() {
                    for failure in failures {
                        crate::activity::error(
                            ui,
                            format!(
                                "Failed to load Volatility plugin: {}",
                                failure.trim_start_matches("volatility3.plugins.")
                            ),
                        );
                    }
                }
                ui.separator();
                if ui
                    .button(format!(
                        "{} Plugin catalog…",
                        egui_phosphor::regular::STOREFRONT
                    ))
                    .on_hover_text("Download community plugins checked for this Volatility")
                    .clicked()
                {
                    self.catalog_open = true;
                    ui.close_menu();
                }
                if ui.button("Open community plugins folder").clicked() {
                    let dir = memory::plugins_dir(data_dir);
                    let opened = std::fs::create_dir_all(&dir)
                        .map_err(|error| format!("{}: {error}", dir.display()))
                        .and_then(|()| open_directory(&dir));
                    if let Err(error) = opened {
                        self.status = Some((error, true));
                    }
                    ui.close_menu();
                }
                if ui
                    .button("Reload plugin list")
                    .on_hover_text("After adding, changing or removing plugins")
                    .clicked()
                {
                    reload = true;
                    ui.close_menu();
                }
            });
            // Truncated: a long description must not widen the tab.
            ui.add(egui::Label::new(RichText::new(&current.help).color(theme::muted())).truncate())
                .on_hover_text(&current.help);
        });
        if !current.options.is_empty() {
            let values = self.values.entry(current.name.clone()).or_default();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                for option in &current.options {
                    let at = match values.iter().position(|(name, _)| name == &option.name) {
                        Some(at) => at,
                        None => {
                            values.push((option.name.clone(), String::new()));
                            values.len() - 1
                        }
                    };
                    let value = &mut values[at].1;
                    let help = if option.help.is_empty() {
                        option.flag()
                    } else {
                        format!("{}\n{}", option.flag(), option.help)
                    };
                    match option.kind {
                        OptionKind::Bool => {
                            let mut on = value == "true";
                            if ui
                                .checkbox(&mut on, option.name.replace('_', " "))
                                .on_hover_text(help)
                                .changed()
                            {
                                *value = if on { "true".into() } else { String::new() };
                            }
                        }
                        OptionKind::Choice => {
                            ui.label(option.name.replace('_', " ")).on_hover_text(&help);
                            egui::ComboBox::from_id_salt(("memory_choice", &option.name))
                                .selected_text(if value.is_empty() {
                                    "default".to_owned()
                                } else {
                                    value.clone()
                                })
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(value, String::new(), "default");
                                    for choice in &option.choices {
                                        ui.selectable_value(value, choice.clone(), choice);
                                    }
                                });
                        }
                        _ => {
                            ui.label(option.name.replace('_', " ")).on_hover_text(&help);
                            let hint = match option.kind {
                                OptionKind::List => "values, comma-separated".to_owned(),
                                _ => option
                                    .default
                                    .as_ref()
                                    .map(|value| value.to_string())
                                    .unwrap_or_default(),
                            };
                            ui.add(
                                egui::TextEdit::singleline(value)
                                    .hint_text(crate::theme::hint_text(hint))
                                    .font(egui::TextStyle::Monospace)
                                    .margin(theme::TEXT_EDIT_MARGIN)
                                    .desired_width(if option.kind == OptionKind::Int {
                                        90.0
                                    } else {
                                        170.0
                                    }),
                            )
                            .on_hover_text(help);
                        }
                    }
                }
            });
        }
        if let Some(name) = chosen {
            self.plugin = Some(name);
            self.search.clear();
        }
        if let Some(os) = chosen_os {
            self.list_os = Some((dump.id.clone(), os));
        }
        if reload {
            self.catalog = Catalog::Unknown;
            return action;
        }
        match run {
            Some(Ok(args)) => {
                match volatility.start(dump, &current.name, args, cx.online_symbols) {
                    Ok(job) => {
                        let id = job.run.id.clone();
                        self.jobs.push(job);
                        self.reload_runs();
                        self.selected_run = Some(id);
                        self.result = None;
                        self.status = None;
                    }
                    Err(error) => self.status = Some((error, true)),
                }
            }
            Some(Err(error)) => self.status = Some((error, true)),
            None => {}
        }
        action
    }

    fn run_list(&mut self, ui: &mut egui::Ui, font_size: f32) {
        theme::section(ui, "Results");
        let mut fields = crate::query::LABEL_FIELDS.to_vec();
        fields.extend([
            crate::query::FieldSpec::text("name", "Displayed plugin result name"),
            crate::query::FieldSpec::text("plugin", "Full plugin name"),
            crate::query::FieldSpec::text("state", "Plugin result state"),
            crate::query::FieldSpec::text("args", "Plugin arguments"),
            crate::query::FieldSpec::number("rows", "Retained result rows"),
            crate::query::FieldSpec::number("exit_code", "Tool exit code"),
            crate::query::FieldSpec::text("analyzer", "Analysis backend (volatility or memnixfs)"),
            crate::query::FieldSpec::boolean("partial", "Result known to miss something"),
        ]);
        let annotations: Vec<_> = self
            .runs
            .iter()
            .map(|run| crate::evidence::annotation(ui, &run.dir))
            .collect();
        let tags: Vec<_> = annotations
            .iter()
            .flatten()
            .flat_map(|value| value.tags.iter().cloned())
            .collect();
        let filter = crate::query::table_filter(
            ui,
            "memory-plugin-history",
            "entry.name contains pslist",
            &fields,
            &tags,
        );
        let filter_id = ui.id().with(("table-filter", "memory-plugin-history"));
        let shown: Vec<_> = self
            .runs
            .iter()
            .enumerate()
            .filter(|(index, run)| {
                filter.keep_table(&plugin_run_row(run, annotations[*index].as_ref()))
            })
            .map(|(_, run)| run)
            .collect();
        ui.weak(format!("{} / {} results", shown.len(), self.runs.len()));
        if self
            .selected_run
            .as_ref()
            .is_some_and(|selected| !shown.iter().any(|run| &run.id == selected))
        {
            self.selected_run = None;
            self.result = None;
        }
        let mut open = None;
        let mut delete = None;
        let mut rerun = None;
        egui::ScrollArea::vertical()
            .id_salt("memory_run_list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for run in shown {
                    let job = self.jobs.iter().find(|job| job.run.id == run.id);
                    let progress = job.map(RunHandle::progress);
                    let color = match (job, run.state) {
                        (Some(_), _) => theme::info(),
                        (None, RunState::Failed) => theme::error(),
                        (None, RunState::Cancelled | RunState::Running) => theme::muted(),
                        (None, RunState::Finished) => theme::text(),
                    };
                    let mut title = run.short_name().to_owned();
                    if run.analyzer != Analyzer::Volatility {
                        title.push_str(" · ");
                        title.push_str(run.analyzer.label());
                    }
                    if !run.args.is_empty() {
                        title.push(' ');
                        title.push_str(&args_summary(run));
                    }
                    let title = crate::evidence::title(ui, &run.dir, &title);
                    let row = capture_row(
                        ui,
                        self.selected_run.as_ref() == Some(&run.id),
                        (&title, color),
                        &run_detail(run, progress.as_ref()),
                        font_size,
                    )
                    .on_hover_text(format!(
                        "{} {}\nStarted {}{}",
                        run.plugin,
                        args_summary(run),
                        format_date(run.started_ms / 1000),
                        if run.symbols_online.is_some() {
                            format!(
                                "\nSymbol table looked up online ({})",
                                memory::ONLINE_SYMBOLS_NAME
                            )
                        } else {
                            String::new()
                        }
                    ));
                    if row.clicked() {
                        open = Some(run.id.clone());
                    }
                    row.context_menu(|ui| {
                        crate::evidence::menu(ui, &run.dir);
                        let annotation = crate::evidence::annotation(ui, &run.dir);
                        crate::query::table_row_menu(
                            ui,
                            filter_id,
                            &plugin_run_row(run, annotation.as_ref()),
                        );
                        ui.separator();
                        if let Some(job) = job {
                            if ui.button("Cancel run").clicked() {
                                job.cancel();
                                ui.close_menu();
                            }
                            return;
                        }
                        if ui
                            .button("Set up again")
                            .on_hover_text("Choose this plugin with these options")
                            .clicked()
                        {
                            rerun = Some(run.clone());
                            ui.close_menu();
                        }
                        if ui.button("Open its folder").clicked() {
                            if let Err(error) = open_directory(&run.dir) {
                                self.status = Some((error, true));
                            }
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .button(RichText::new("Delete result").color(theme::error()))
                            .clicked()
                        {
                            delete = Some(run.clone());
                            ui.close_menu();
                        }
                    });
                    if let Some(progress) = &progress {
                        ui.add(
                            egui::ProgressBar::new(progress.percent / 100.0).desired_height(3.0),
                        );
                    }
                }
                if self.runs.is_empty() {
                    ui.colored_label(
                        theme::muted(),
                        "No results yet: pick a plugin or report and Run",
                    );
                }
            });
        if let Some(run) = delete {
            if let Err(error) = memory::delete_run(&run) {
                self.status = Some((error, true));
            }
            self.reload_runs();
            if self.selected_run.as_ref() == Some(&run.id) {
                let newest = self.runs.first().map(|run| run.id.clone());
                self.open_run(newest);
            }
        }
        if let Some(run) = rerun {
            self.analyzer = run.analyzer;
            if run.analyzer == Analyzer::MemNixFs {
                self.report = Some(run.plugin.trim_start_matches("memnixfs.").to_owned());
            } else {
                self.plugin = Some(run.plugin.clone());
            }
            if let Catalog::Ready(_, catalog) = &self.catalog {
                self.values
                    .insert(run.plugin.clone(), args_values(&run, &catalog.plugins));
            }
        }
        if let Some(id) = open {
            self.open_run(Some(id));
        }
    }

    /// The Details panel while it follows the Memory tab: every value of the
    /// selected result row, in full.
    pub(crate) fn details(&mut self, ui: &mut egui::Ui, font_size: f32) {
        let row = self.result.as_ref().and_then(|result| {
            let table = result.table.as_ref().ok()?;
            let row = table.rows.get(self.selected_row?)?;
            Some((
                result.run.plugin.clone(),
                table.columns.clone(),
                row.clone(),
            ))
        });
        let Some((plugin, columns, row)) = row else {
            ui.add_space(6.0);
            ui.colored_label(theme::muted(), "Select a row.");
            return;
        };
        let mono = theme::mono(font_size - 1.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(&plugin)
                    .font(mono.clone())
                    .color(theme::heading()),
            );
            if ui
                .button(format!("{} Copy row", egui_phosphor::regular::COPY))
                .clicked()
            {
                ui.ctx().copy_text(row_text(&columns, &row));
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("memory_row_details")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("memory_row_grid")
                    .num_columns(2)
                    .spacing([16.0, 4.0])
                    .striped(true)
                    .show(ui, |ui| {
                        for (value, column) in row.values.iter().zip(&columns) {
                            ui.label(RichText::new(&column.name).color(theme::muted()));
                            let text = memory::value_text(column.kind, value);
                            let response = ui.add(
                                egui::Label::new(
                                    RichText::new(&text)
                                        .font(mono.clone())
                                        .color(value_color(column.kind, value)),
                                )
                                .wrap()
                                .sense(egui::Sense::click()),
                            );
                            response.context_menu(|ui| {
                                if ui.button("Copy value").clicked() {
                                    ui.ctx().copy_text(text.clone());
                                    ui.close_menu();
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
    }
}

/// The run's options in a short form.
pub(super) fn args_summary(run: &PluginRun) -> String {
    run.args.join(" ")
}

pub(super) fn run_detail(run: &PluginRun, job: Option<&memory::Progress>) -> String {
    if let Some(progress) = job {
        return if progress.step.is_empty() {
            "Running…".into()
        } else {
            format!("{:.0}% {}", progress.percent, progress.step)
        };
    }
    let took = run
        .finished_ms
        .map(|end| format_elapsed(end.saturating_sub(run.started_ms)))
        .unwrap_or_default();
    match run.state {
        RunState::Running => "Did not finish (the app closed)".into(),
        RunState::Finished if !run.partial.is_empty() => format!(
            "{} · {} rows · {took} · partial",
            clock(run.started_ms),
            run.rows
        ),
        RunState::Finished => format!("{} · {} rows · {took}", clock(run.started_ms), run.rows),
        RunState::Cancelled => format!("{} · cancelled", clock(run.started_ms)),
        RunState::Failed => format!(
            "{} · failed: {}",
            clock(run.started_ms),
            run.error.as_deref().unwrap_or("see its messages")
        ),
    }
}

pub(super) fn memory_symbols_file() -> &'static str {
    antinomie_monitor_core::storage::SYMBOLS_FILE
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |time| time.as_millis() as u64)
}

/// The plugin's group in the picker: its OS and module (`linux.malware`).
pub(super) fn plugin_area(name: &str) -> String {
    let parts: Vec<&str> = name.split('.').collect();
    match parts.as_slice() {
        [os, "malware" | "tracing" | "graphics" | "registry", ..] => format!("{os} · {}", parts[1]),
        [os, _, _, ..] if Os::ALL.iter().any(|known| known.prefix() == *os) => (*os).to_owned(),
        _ => "generic".to_owned(),
    }
}

/// Option values of a saved run, to set the same run up again.
pub(super) fn args_values(run: &PluginRun, plugins: &[PluginInfo]) -> Vec<(String, String)> {
    let Some(plugin) = plugins.iter().find(|plugin| plugin.name == run.plugin) else {
        return Vec::new();
    };
    let mut values: Vec<(String, String)> = Vec::new();
    let mut current: Option<&memory::PluginOption> = None;
    for arg in &run.args {
        if let Some(option) = plugin.options.iter().find(|option| &option.flag() == arg) {
            current = Some(option);
            if option.kind == OptionKind::Bool {
                values.push((option.name.clone(), "true".into()));
                current = None;
            }
            continue;
        }
        if let Some(option) = current {
            match values.iter_mut().find(|(name, _)| name == &option.name) {
                Some((_, value)) => {
                    value.push_str(", ");
                    value.push_str(arg);
                }
                None => values.push((option.name.clone(), arg.clone())),
            }
        }
    }
    values
}

pub(super) fn plugin_result_record(
    run: &PluginRun,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, crate::query::RowValue)> {
    plugin_run_row(run, annotation)
        .into_iter()
        .filter(|(field, _)| {
            crate::query::LABEL_FIELDS
                .iter()
                .any(|spec| spec.name == *field)
        })
        .collect()
}

pub(super) fn plugin_run_row(
    run: &PluginRun,
    annotation: Option<&antinomie_monitor_core::annotations::Annotation>,
) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue;

    let mut row = crate::query::label_row(
        &run.id,
        annotation.map_or("", |value| &value.name),
        &run.dir.display().to_string(),
        annotation.map_or(&[], |value| value.tags.as_slice()),
    );
    row.extend([
        (
            "entry.kind",
            RowValue::Text(run.analyzer.label().to_lowercase()),
        ),
        ("entry.state", RowValue::Text(format!("{:?}", run.state))),
        (
            "entry.complete",
            RowValue::Bool(run.state == RunState::Finished),
        ),
        (
            "entry.time_ms",
            RowValue::Number(i128::from(run.started_ms)),
        ),
        ("run.id", RowValue::Text(run.id.clone())),
        (
            "name",
            RowValue::Text(
                annotation
                    .filter(|value| !value.name.is_empty())
                    .map_or_else(|| run.short_name().to_owned(), |value| value.name.clone()),
            ),
        ),
        ("plugin", RowValue::Text(run.plugin.clone())),
        (
            "analyzer",
            RowValue::Text(run.analyzer.label().to_lowercase()),
        ),
        ("partial", RowValue::Bool(!run.partial.is_empty())),
        ("state", RowValue::Text(format!("{:?}", run.state))),
        ("args", RowValue::Text(run.args.join(" "))),
        ("rows", RowValue::Number(i128::from(run.rows))),
        (
            "exit_code",
            run.exit_code.map_or(RowValue::Missing, |value| {
                RowValue::Number(i128::from(value))
            }),
        ),
    ]);

    row
}

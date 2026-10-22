// SPDX-License-Identifier: GPL-3.0-only
//! The Volatility install, plugin catalog and import windows.
use super::*;

impl MemoryView {
    /// Volatility was installed or removed: list its plugins again.
    pub(super) fn check_catalog(&mut self, installed: bool) {
        let ready = matches!(self.catalog, Catalog::Ready(..));
        let failed = matches!(self.catalog, Catalog::Failed(_));
        if (installed && failed) || (!installed && ready) {
            self.catalog = Catalog::Unknown;
        }
    }

    pub(super) fn import_window(&mut self, ctx: &egui::Context, cx: &MemoryContext<'_>) {
        let Some(import) = self.import.as_mut() else {
            return;
        };
        let mut open = true;
        let mut close = false;
        let mut done = None;
        let with_symbols: Vec<&BaseSummary> = cx
            .bases
            .iter()
            .filter(|base| base.directory.join(memory_symbols_file()).is_file())
            .collect();
        crate::widgets::window("Import memory dump")
            .id(egui::Id::new("memory_import"))
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .show(ctx, |ui| {
                egui::Grid::new("memory_import_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("Dump file");
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut import.path)
                                    .hint_text(crate::theme::hint_text("/path/to/memory.raw"))
                                    .font(egui::TextStyle::Monospace)
                                    .margin(theme::TEXT_EDIT_MARGIN)
                                    .desired_width(320.0),
                            );
                            if ui
                                .add_enabled(import.picker.is_none(), egui::Button::new("Browse…"))
                                .on_disabled_hover_text("The file chooser is open")
                                .clicked()
                            {
                                match Command::new("zenity")
                                    .args(["--file-selection", "--title=Choose a memory dump"])
                                    .stdout(Stdio::piped())
                                    .stderr(Stdio::null())
                                    .spawn()
                                {
                                    Ok(child) => import.picker = Some(child),
                                    Err(error) => {
                                        import.error = Some(format!("File chooser (zenity): {error}"))
                                    }
                                }
                            }
                        });
                        ui.end_row();
                        ui.label("System");
                        ui.horizontal(|ui| {
                            for os in Os::ALL {
                                ui.selectable_value(&mut import.os, os, os.label());
                            }
                        });
                        ui.end_row();
                        ui.label("Symbol table");
                        ui.add_enabled_ui(import.os == Os::Linux, |ui| {
                            let automatic = if cx.online_symbols {
                                "Find it: Volatility's folders, then online"
                            } else {
                                "Find it in Volatility's folders"
                            };
                            let selected = import
                                .base
                                .as_ref()
                                .and_then(|dir| with_symbols.iter().find(|base| &base.directory == dir))
                                .map_or(automatic.to_owned(), |base| base_choice(base));
                            egui::ComboBox::from_id_salt("memory_import_symbols")
                                .width(360.0)
                                .selected_text(selected)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut import.base, None, automatic);
                                    for base in cx.bases {
                                        let has = with_symbols
                                            .iter()
                                            .any(|other| other.directory == base.directory);
                                        ui.add_enabled_ui(has, |ui| {
                                            ui.selectable_value(
                                                &mut import.base,
                                                Some(base.directory.clone()),
                                                base_choice(base),
                                            )
                                            .on_disabled_hover_text(
                                                "Built before Antinomie 0.4.0: its kernel has no \
                                                 symbol table. Download the 0.4.0 base for one.",
                                            );
                                        });
                                    }
                                });
                        });
                        ui.end_row();
                    });
                ui.colored_label(
                    theme::muted(),
                    match import.os {
                        Os::Windows => "Windows symbols are downloaded from Microsoft's symbol server when a plugin first needs them.",
                        Os::Linux => "Linux dumps need the symbol table of their exact kernel: pick the base a dump of an Antinomie VM was taken from; for other machines, Volatility finds distribution kernels' tables.",
                        Os::Mac => "macOS dumps need a symbol table for their kernel in Volatility's symbol folders.",
                    },
                );
                if let Some(error) = &import.error {
                    crate::activity::error(ui, error);
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let ready = !import.path.trim().is_empty();
                    if ui
                        .add_enabled(
                            ready,
                            egui::Button::new(RichText::new("Import").color(theme::palette().primary_text))
                                .fill(theme::primary()),
                        )
                        .clicked()
                    {
                        let path = crate::folders::user_path(&import.path);
                        let symbols = import.base.as_ref().and_then(|dir| {
                            with_symbols
                                .iter()
                                .find(|base| &base.directory == dir)
                                .map(|base| (dir.join(memory_symbols_file()), base.label.clone()))
                        });
                        match (cx.recordings, cx.vm) {
                            (Some(recordings), Some(vm)) => match memory::import(
                                recordings,
                                vm,
                                &path,
                                import.os,
                                symbols.as_ref().map(|(path, label)| (path.as_path(), label.clone())),
                            ) {
                                Ok(dump) => done = Some(dump.id),
                                Err(error) => import.error = Some(error),
                            },
                            _ => import.error = Some("Select a VM first".into()),
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                });
            });
        if done.is_some()
            || close
            || !open
            || ctx.input(|input| input.key_pressed(egui::Key::Escape))
        {
            ctx.request_repaint();
            if let Some(mut child) = self.import.take().and_then(|import| import.picker) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        if let Some(id) = done {
            self.scan(cx.recording_roots);
            self.select(Some(id));
        }
    }

    pub(super) fn catalog_window(&mut self, ctx: &egui::Context, cx: &MemoryContext<'_>) {
        if !self.catalog_open {
            return;
        }
        let plugins_dir = memory::plugins_dir(cx.data_dir);
        let installed = self
            .catalog_installed
            .get_or_insert_with(|| community::installed(&plugins_dir))
            .clone();
        let entries = community::catalog();
        let mut open = true;
        let mut install = None;
        let mut remove = None;
        crate::widgets::window("Community plugin catalog")
            .id(egui::Id::new("memory_plugin_catalog"))
            .collapsible(false)
            .resizable(true)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(ctx.screen_rect().center())
            .default_width(680.0)
            .default_height(560.0)
            .open(&mut open)
            .show(ctx, |ui| {
                ui.add(
                    egui::Label::new(
                        RichText::new(
                            "Volatility 3 plugins by other authors. Each is downloaded from its \
                             author's repository at the commit listed and checked against its \
                             SHA-256; Antinomie only applies the compatibility edits shown. They \
                             are ordinary Python and run as you, outside any sandbox: read the \
                             source before installing.",
                        )
                        .color(theme::muted()),
                    )
                    .wrap(),
                );
                if let Some((message, error)) = &self.catalog_status {
                    if *error {
                        crate::activity::error_toast(ui, message);
                    } else {
                        ui.colored_label(theme::good(), message);
                    };
                }
                ui.add_space(6.0);
                let entries = match &entries {
                    Ok(entries) => entries,
                    Err(error) => {
                        crate::activity::error(ui, error);
                        return;
                    }
                };
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for plugin in entries {
                            let present = installed.iter().find(|i| i.plugin.id == plugin.id);
                            egui::Frame::new()
                                .fill(theme::raised())
                                .corner_radius(6.0)
                                .inner_margin(egui::Margin::symmetric(12, 10))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(RichText::new(&plugin.name).strong());
                                        ui.colored_label(
                                            theme::muted(),
                                            format!("by {}", plugin.author),
                                        );
                                        ui.label(
                                            RichText::new(plugin.os.label())
                                                .small()
                                                .color(theme::value(ValueKind::Name)),
                                        );
                                        ui.label(
                                            RichText::new(&plugin.license)
                                                .small()
                                                .color(theme::value(ValueKind::Flags)),
                                        );
                                    });
                                    ui.add(
                                        egui::Label::new(
                                            RichText::new(&plugin.summary).color(theme::text()),
                                        )
                                        .wrap(),
                                    );
                                    ui.label(
                                        RichText::new(format!(
                                            "{} {}",
                                            egui_phosphor::regular::CHECK_CIRCLE,
                                            plugin.tested
                                        ))
                                        .small()
                                        .color(theme::muted()),
                                    );
                                    for caveat in &plugin.caveats {
                                        crate::activity::warning(
                                            ui,
                                            format!("{} {caveat}", egui_phosphor::regular::WARNING),
                                        );
                                    }
                                    for need in &plugin.requires {
                                        crate::activity::warning(ui, format!("Needs {need}"));
                                    }
                                    for file in &plugin.files {
                                        for edit in &file.edits {
                                            ui.label(
                                                RichText::new(format!(
                                                    "Compatibility edit in {}: {} → {}",
                                                    file.to, edit.find, edit.replace
                                                ))
                                                .small()
                                                .font(theme::mono(cx.font_size - 3.0))
                                                .color(theme::muted()),
                                            );
                                        }
                                    }
                                    ui.add_space(4.0);
                                    ui.horizontal(|ui| {
                                        if let Some(job) = self.installs.get(&plugin.id) {
                                            let (got, total) =
                                                *job.progress.lock().expect("install progress");
                                            ui.add(
                                                egui::ProgressBar::new(
                                                    got as f32 / total.max(1) as f32,
                                                )
                                                .desired_width(160.0),
                                            );
                                            if ui.button("Cancel").clicked() {
                                                job.cancel.store(true, Ordering::Relaxed);
                                            }
                                        } else if let Some(present) = present {
                                            if present.outdated(entries)
                                                && ui.button("Update").clicked()
                                            {
                                                install = Some(plugin.clone());
                                            }
                                            ui.colored_label(theme::good(), "Installed");
                                            if ui.button("Remove").clicked() {
                                                remove = Some(plugin.id.clone());
                                            }
                                        } else if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new(format!(
                                                        "{} Install",
                                                        egui_phosphor::regular::DOWNLOAD_SIMPLE
                                                    ))
                                                    .color(theme::palette().primary_text),
                                                )
                                                .fill(theme::primary()),
                                            )
                                            .clicked()
                                        {
                                            install = Some(plugin.clone());
                                        }
                                        ui.hyperlink_to(
                                            format!(
                                                "Source {}",
                                                egui_phosphor::regular::ARROW_SQUARE_OUT
                                            ),
                                            plugin.source_url(),
                                        )
                                        .on_hover_text(
                                            format!(
                                                "{} at commit {}",
                                                plugin.repo,
                                                &plugin.commit[..12]
                                            ),
                                        );
                                        ui.colored_label(
                                            theme::muted(),
                                            crate::values::file_size(plugin.size()),
                                        );
                                    });
                                });
                            ui.add_space(8.0);
                        }
                    });
            });
        if let Some(plugin) = install {
            let progress = Arc::new(Mutex::new((0, plugin.size())));
            let cancel = Arc::new(AtomicBool::new(false));
            let (sender, done) = mpsc::channel();
            let (curl, staging) = (
                cx.curl.to_path_buf(),
                antinomie_monitor_core::analysis_tools::tools_dir(cx.data_dir).join(".downloads"),
            );
            let (shared, stop, id) = (progress.clone(), cancel.clone(), plugin.id.clone());
            std::thread::spawn(move || {
                let result = community::install(
                    &curl,
                    &plugins_dir,
                    &staging,
                    &plugin,
                    &stop,
                    |got, total| {
                        if let Ok(mut progress) = shared.lock() {
                            *progress = (got, total);
                        }
                    },
                );
                let _ = sender.send(result);
            });
            self.catalog_status = None;
            self.installs.insert(
                id,
                PluginInstall {
                    progress,
                    cancel,
                    done,
                },
            );
        }
        if let Some(id) = remove {
            self.catalog_status = Some(
                match community::remove(&memory::plugins_dir(cx.data_dir), &id) {
                    Ok(()) => (format!("{id} removed"), false),
                    Err(error) => (error, true),
                },
            );
            self.catalog_installed = None;
            self.catalog = Catalog::Unknown;
        }
        if !open || ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.catalog_open = false;
            self.catalog_installed = None;
            ctx.request_repaint();
        }
    }

    pub(super) fn poll_picker(&mut self) {
        let Some(import) = self.import.as_mut() else {
            return;
        };
        let Some(child) = import.picker.as_mut() else {
            return;
        };
        let Ok(Some(status)) = child.try_wait() else {
            return;
        };
        let mut child = import.picker.take().expect("picker is running");
        let mut text = String::new();
        if let (true, Some(stdout)) = (status.success(), child.stdout.take()) {
            use std::io::Read;
            let _ = stdout.take(8192).read_to_string(&mut text);
        }
        // Already exited (try_wait reaped it); this only collects the status.
        let _ = child.wait();
        let path = text.trim_end_matches('\n');
        if !path.is_empty() {
            import.path = path.to_owned();
        }
    }
}

// SPDX-License-Identifier: MIT
//! Menu bar, toolbar and keyboard shortcuts.
use super::*;

impl MonitorApp {
    /// Menu shortcuts; they wait while a text field or terminal has the
    /// keyboard.
    pub(super) fn shortcuts(&mut self, ctx: &egui::Context) {
        if self.vm_snapshots.decision_open() {
            return;
        }
        if ctx.memory(|memory| memory.focused().is_some()) {
            return;
        }
        let pressed = |shortcut: egui::KeyboardShortcut| {
            ctx.input_mut(|input| input.consume_shortcut(&shortcut))
        };
        // Shift+F5 first: F5 alone would also match it.
        if pressed(keys::STOP_VM) && self.can_stop_vm() {
            self.send(Command::Stop);
        }
        if pressed(keys::START_VM) && self.can_start_vm() {
            self.new_run();
        }
        if pressed(keys::NEW_VM) && self.snapshot.active_vm.is_none() {
            self.new_image();
        }
        if pressed(keys::RUN_PROGRAM) && self.running() {
            self.launch_open = true;
        }
        if pressed(keys::UPLOAD) && self.running() {
            self.open_upload();
        }
        if pressed(keys::TYPE_CLIPBOARD) && self.clipboard_enabled() {
            self.request_clipboard(ctx);
        }
        if pressed(keys::SETTINGS) {
            self.settings_open = true;
        }
        if pressed(keys::QUIT) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    pub(super) fn menus(&mut self, ctx: &egui::Context) {
        let stopped = self.snapshot.active_vm.is_none();
        let selected = self.selected.is_some() && stopped;
        let item = |label: &str, shortcut: Option<egui::KeyboardShortcut>| {
            let button = egui::Button::new(label);
            match shortcut {
                Some(shortcut) => button.shortcut_text(ctx.format_shortcut(&shortcut)),
                None => button,
            }
        };
        egui::TopBottomPanel::top("menus")
            .exact_height(self.settings.font_size + 16.0)
            .frame(theme::frame(theme::panel()))
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        if ui
                            .add_enabled(stopped, item("New VM…", Some(keys::NEW_VM)))
                            .clicked()
                        {
                            self.new_image();
                            ui.close_menu();
                        }
                        ui.menu_button("Add base", |ui| {
                            // Room between an item and its shortcut.
                            ui.set_min_width(ui.spacing().menu_width);
                            if ui
                                .add_enabled(stopped, item("Import base…", None))
                                .clicked()
                            {
                                self.import_open = true;
                                ui.close_menu();
                            }
                            if ui.button("Download base…").clicked() {
                                self.open_downloads();
                                ui.close_menu();
                            }
                            if ui.button("Build base…").clicked() {
                                self.build_open = true;
                                ui.close_menu();
                            }
                        });
                        ui.separator();
                        if ui.add(item("Exit", Some(keys::QUIT))).clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("VM", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        if ui
                            .add_enabled(
                                self.can_start_vm(),
                                item("Start VM", Some(keys::START_VM)),
                            )
                            .clicked()
                        {
                            self.new_run();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(self.can_stop_vm(), item("Stop VM", Some(keys::STOP_VM)))
                            .clicked()
                        {
                            self.send(Command::Stop);
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(self.can_configure_vm(), item("Configuration…", None))
                            .clicked()
                        {
                            self.configure_vm();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.selected.is_some() && !self.closing,
                                item("Snapshots…", None),
                            )
                            .clicked()
                        {
                            self.open_snapshots();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.running()
                                    && !self.closing
                                    && self.vm_snapshots.pending.is_none(),
                                item("Reconnect telemetry", None),
                            )
                            .clicked()
                        {
                            self.send(Command::ReconnectTransport);
                            ui.close_menu();
                        }
                        let vm = self.selected_vm().cloned();
                        if ui.add_enabled(self.clipboard_enabled(),
                            item("Type host clipboard into VM", Some(keys::TYPE_CLIPBOARD)))
                            .on_hover_text("Types into the guest's focused input using a US keyboard layout; Caps Lock should be off. Newlines press Enter. Maximum 4 KiB.")
                            .clicked()
                        {
                            self.request_clipboard(ctx);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(vm.is_some() && !self.closing, item("Rename…", None))
                            .clicked()
                        {
                            if let Some(vm) = &vm {
                                self.name_action = Some((vm.id.clone(), false, vm.name.clone()));
                            }
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(selected && !self.closing, item("Duplicate…", None))
                            .clicked()
                        {
                            if let Some(vm) = &vm {
                                self.name_action =
                                    Some((vm.id.clone(), true, format!("{} copy", vm.name)));
                            }
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(vm.is_some(), item("Open directory", None))
                            .clicked()
                        {
                            if let Some(vm) = vm {
                                self.open_vm_directory(&vm.id);
                            }
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(selected, item("Reset disk to base…", None))
                            .clicked()
                        {
                            self.confirm = self.selected.clone().map(Confirm::Reset);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(selected, item("Delete VM and disk…", None))
                            .clicked()
                        {
                            self.confirm = self.selected.clone().map(Confirm::Delete);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Run", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        if ui
                            .add_enabled(
                                self.running(),
                                item("Run program…", Some(keys::RUN_PROGRAM)),
                            )
                            .clicked()
                        {
                            self.launch_open = true;
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(self.running(), item("Upload file…", Some(keys::UPLOAD)))
                            .clicked()
                        {
                            self.open_upload();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(
                                self.observer_start_enabled(),
                                item("Attach to process…", None),
                            )
                            .clicked()
                        {
                            self.open_process_picker();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(self.observer_start_enabled(), item("Capture all", None))
                            .clicked()
                        {
                            self.send(Command::CaptureAll);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(self.can_stop_capture(), item("Stop capture", None))
                            .clicked()
                        {
                            self.stop_observer();
                            ui.close_menu();
                        }
                        if self.running() && !self.observer_supported() {
                            ui.colored_label(
                                theme::muted(),
                                "Capture unavailable: needs a base for Antinomie 0.2.0 or newer",
                            );
                        }
                        ui.separator();
                        if ui
                            .add_enabled(
                                self.network_toggle_enabled(),
                                item(
                                    if self.snapshot.network_capture.is_some() {
                                        "Stop network capture"
                                    } else {
                                        "Capture network"
                                    },
                                    None,
                                ),
                            )
                            .on_disabled_hover_text(self.network_toggle_label())
                            .clicked()
                        {
                            self.toggle_network_capture();
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("View", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        for view in Panel::MAIN.into_iter().chain([Panel::Details, Panel::Activity]) {
                            if ui.button(view.title()).clicked() {
                                self.focus_panel = Some(view);
                                ui.close_menu();
                            }
                        }
                        ui.separator();
                        if ui.button("Reset layout").clicked() {
                            self.layout = WorkspaceLayout::default();
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Tools", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        if ui.add(item("Settings…", Some(keys::SETTINGS))).clicked() {
                            self.settings_open = true;
                            ui.close_menu();
                        }
                        if ui.button("Analysis tools…").clicked() {
                            self.tools_open = true;
                            ui.close_menu();
                        }
                        if ui.button("Rule manager…").clicked() {
                            self.rules_open = true;
                            ui.close_menu();
                        }
                        if ui
                            .button(format!(
                                "{} Malware samples…",
                                egui_phosphor::regular::BIOHAZARD
                            ))
                            .clicked()
                        {
                            self.samples.open = true;
                            ui.close_menu();
                        }
                        if ui.button("App dependencies…").clicked() {
                            self.folder_picker.refresh(ctx);
                            self.dependencies.open = true;
                            ui.close_menu();
                        }
                        if ui.button("UI performance…").clicked() {
                            self.performance.open = true;
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(self.running(), item("Refresh recorder statistics", None))
                            .clicked()
                        {
                            self.send(Command::RecorderStats);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        if ui.button("Getting started").clicked() {
                            self.open_getting_started();
                            ui.close_menu();
                        }
                        if ui.button("About Antinomie").clicked() {
                            self.about_open = true;
                            ui.close_menu();
                        }
                        if ui.button("Filter guide").clicked() {
                            crate::query::open_guide(ui.ctx());
                            ui.close_menu();
                        }
                    });
                    if self.snapshot.bases.is_empty() && !self.snapshot.bases_checking {
                        ui.separator();
                        if ui
                            .add(egui::Button::new(
                                RichText::new(format!(
                                    "{}  No base image: add one",
                                    egui_phosphor::regular::WARNING
                                ))
                                .color(theme::warn()),
                            ))
                            .clicked()
                        {
                            self.open_downloads();
                        }
                    }
                });
            });
    }

    /// The main actions only: the VM, running a program and the captures.
    /// Everything else is in the menus and the sidebar's right-click menus.
    pub(super) fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar")
            .exact_height(self.settings.font_size + 22.0)
            .frame(theme::frame(theme::panel()))
            .show(ctx, |ui| {
                egui::ScrollArea::horizontal()
                    .id_salt("toolbar_controls")
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                    .show(ui, |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            ui.spacing_mut().item_spacing.x = 4.0;
                            let shortcut = |text: &str, shortcut| {
                                format!("{text} ({})", ctx.format_shortcut(&shortcut))
                            };
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::PLAY,
                                    label: "Start",
                                    tooltip: &shortcut("Start the selected VM", keys::START_VM),
                                    enabled: self.can_start_vm(),
                                    tone: theme::good(),
                                    strong: true,
                                    active: false,
                                },
                            ) {
                                self.new_run();
                            }
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::STOP,
                                    label: "Stop",
                                    tooltip: &shortcut("Shut down the running VM", keys::STOP_VM),
                                    enabled: self.can_stop_vm(),
                                    tone: theme::error(),
                                    strong: true,
                                    active: false,
                                },
                            ) {
                                self.send(Command::Stop);
                            }
                            ui.separator();
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::CLOCK_COUNTER_CLOCKWISE,
                                    label: "Snapshots",
                                    tooltip: "Save, restore and branch this VM's disk and memory",
                                    enabled: self.selected.is_some() && !self.closing,
                                    tone: theme::blue(),
                                    strong: false,
                                    active: false,
                                },
                            ) {
                                self.open_snapshots();
                            }
                            ui.separator();
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::X_CIRCLE,
                                    label: "Kill",
                                    tooltip: "Terminate the selected active run and descendants; keep the VM running. Select a live run in Run history when several are active.",
                                    enabled: self.kill_target().is_some(),
                                    tone: theme::error(),
                                    strong: false,
                                    active: false,
                                },
                            ) {
                                self.request_kill(None);
                            }
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::TERMINAL_WINDOW,
                                    label: "Run program",
                                    tooltip: &shortcut(
                                        "Run a program in the VM and record it",
                                        keys::RUN_PROGRAM,
                                    ),
                                    enabled: self.running(),
                                    tone: theme::blue(),
                                    strong: false,
                                    active: self.launch_open,
                                },
                            ) {
                                self.launch_open = true;
                            }
                            ui.separator();
                            // Toggles: lit while their capture runs; a click stops it.
                            let observer = self.active_observer().map(|capture| {
                                format!(
                                    "Stop capture ({}); programs keep running",
                                    captures::scope(&capture.scope)
                                )
                            });
                            let capturing = observer.is_some();
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::RECORD,
                                    label: "Capture all",
                                    tooltip: observer.as_deref().unwrap_or(
                                        "Record every process in the VM (Run > Attach to process \
                                         records one)",
                                    ),
                                    enabled: if capturing {
                                        self.can_stop_capture()
                                    } else {
                                        self.observer_start_enabled()
                                    },
                                    tone: theme::error(),
                                    strong: false,
                                    active: capturing,
                                },
                            ) {
                                if capturing {
                                    self.stop_observer();
                                } else {
                                    self.send(Command::CaptureAll);
                                }
                            }
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::NETWORK,
                                    label: "Capture network",
                                    tooltip: self.network_toggle_label(),
                                    enabled: self.network_toggle_enabled(),
                                    tone: theme::info(),
                                    strong: false,
                                    active: self.snapshot.network_capture.is_some(),
                                },
                            ) {
                                self.toggle_network_capture();
                            }
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::DATABASE,
                                    label: "Dump memory",
                                    tooltip: "Save the running VM's RAM",
                                    enabled: self.running()
                                        && !self.closing
                                        && self.snapshot.memory_dump.is_none(),
                                    tone: theme::info(),
                                    strong: false,
                                    active: self.snapshot.memory_dump.is_some(),
                                },
                            ) {
                                self.send(Command::DumpMemory);
                                self.focus_panel = Some(Panel::Memory);
                            }
                            if tool_button(
                                ui,
                                ToolButton {
                                    icon: egui_phosphor::regular::FILE,
                                    label: "Dump core",
                                    tooltip: self.manual_core_unavailable().unwrap_or(
                                        "Pause a selected process, capture its core, then resume",
                                    ),
                                    enabled: self.manual_core_unavailable().is_none(),
                                    tone: theme::info(),
                                    strong: false,
                                    active: false,
                                },
                            ) {
                                self.open_core_picker();
                            }
                            if ui.available_width() > 160.0 {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        ui.add_space(4.0);
                                        let active = self.snapshot.vms.iter().find(|vm| {
                                            Some(&vm.id) == self.snapshot.active_vm.as_ref()
                                        });
                                        let (word, color) = match active {
                                            Some(_) => vm_state_word(&self.snapshot.state),
                                            None => ("Stopped", theme::muted()),
                                        };
                                        let name = active.map(|vm| vm.name.as_str()).unwrap_or(
                                            if self.snapshot.capture_dir.is_some() {
                                                "Last recording"
                                            } else {
                                                "No VM running"
                                            },
                                        );
                                        if active.is_some() {
                                            ui.label(RichText::new(word).color(color).strong());
                                            if matches!(
                                                self.snapshot.state,
                                                VmState::Starting | VmState::Stopping
                                            ) {
                                                theme::spinner(ui);
                                            }
                                        }
                                        ui.add(
                                            egui::Label::new(RichText::new(name).color(
                                                if active.is_some() {
                                                    theme::text()
                                                } else {
                                                    theme::muted()
                                                },
                                            ))
                                            .truncate(),
                                        )
                                        .on_hover_text(name);
                                        ui.colored_label(color, "●");
                                    },
                                );
                            }
                        });
                    });
            });
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! Menu bar, toolbar and keyboard shortcuts.
use super::*;

/// The web documentation, opened in the system browser from the Help menu.
const DOCUMENTATION_URL: &str = "https://antinomie.moremorepwn.blog/docs/";

/// What the Tools menu is wider than the others: icons before the labels.
const TOOLS_MENU_EXTRA_WIDTH: f32 = 90.0;

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
                            .add_enabled(
                                self.debugger_unavailable().is_none(),
                                item("Attach debugger…", None),
                            )
                            .on_disabled_hover_text(
                                self.debugger_unavailable().unwrap_or_default(),
                            )
                            .clicked()
                        {
                            self.open_debug_picker();
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
                        // Room for the longest label with its icon, and between
                        // an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width + TOOLS_MENU_EXTRA_WIDTH);
                        if ui
                            .add(item(
                                &format!("{} Settings…", egui_phosphor::regular::GEAR),
                                Some(keys::SETTINGS),
                            ))
                            .clicked()
                        {
                            self.settings_open = true;
                            ui.close_menu();
                        }
                        if ui.button(format!("{} Analysis tools", egui_phosphor::regular::WRENCH)).clicked() {
                            self.open_library(LibraryPage::Tools);
                            ui.close_menu();
                        }
                        if ui.button(format!("{} Detection rules", egui_phosphor::regular::SHIELD_CHECK)).clicked() {
                            self.open_library(LibraryPage::Rules);
                            ui.close_menu();
                        }
                        if ui
                            .button(format!(
                                "{} Download malware samples…",
                                egui_phosphor::regular::BIOHAZARD
                            ))
                            .clicked()
                        {
                            self.samples.open = true;
                            ui.close_menu();
                        }
                        if ui
                            .button(format!("{} API keys…", egui_phosphor::regular::KEY))
                            .clicked()
                        {
                            self.api_keys.open = true;
                            ui.close_menu();
                        }
                        if ui.button(format!("{} App dependencies…", egui_phosphor::regular::PACKAGE)).clicked() {
                            self.folder_picker.refresh(ctx);
                            self.dependencies.open = true;
                            ui.close_menu();
                        }
                        if ui.button(format!("{} UI performance…", egui_phosphor::regular::GAUGE)).clicked() {
                            self.performance.open = true;
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(self.running(), item(
                                &format!(
                                    "{} Refresh recorder statistics",
                                    egui_phosphor::regular::ARROWS_CLOCKWISE
                                ),
                                None,
                            ))
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
                        if ui.button("Online documentation").clicked() {
                            ui.ctx()
                                .open_url(egui::OpenUrl::new_tab(DOCUMENTATION_URL));
                            ui.close_menu();
                        }
                        if ui.button("Check for updates…").clicked() {
                            let outbound = self.settings.outbound_catalog;
                            self.updates.request(ctx, &self.options.curl, outbound);
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
    ///
    /// The row never passes the window: the buttons that fit stay, in the
    /// order of [`TOOL_PRIORITY`] (the most useful stay longest), and the
    /// others move into the "more" menu at the end of the row. The selected
    /// VM's name and state take what is left of the row and cut the name with
    /// an ellipsis (the whole text is on hover).
    pub(super) fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar")
            .exact_height(self.settings.font_size + 22.0)
            .frame(theme::frame(theme::panel()))
            .show(ctx, |ui| {
                let specs = self.tool_specs(ctx);
                let shown = tool_layout(ui, &specs);
                let hidden: Vec<usize> =
                    (0..specs.len()).filter(|at| !shown.contains(at)).collect();
                let mut chosen = None;
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    let mut last_group = None;
                    for (at, spec) in specs.iter().enumerate() {
                        if !shown.contains(&at) {
                            continue;
                        }
                        if last_group.is_some_and(|group| group != spec.group) {
                            ui.separator();
                        }
                        last_group = Some(spec.group);
                        if tool_button(ui, spec.button()) {
                            chosen = Some(spec.action);
                        }
                    }
                    if !hidden.is_empty() {
                        ui.menu_button(egui_phosphor::regular::CARET_RIGHT, |ui| {
                            for &at in &hidden {
                                let spec = &specs[at];
                                let text = format!("{} {}", spec.icon, spec.label);
                                if ui
                                    .add_enabled(spec.enabled, egui::Button::new(text))
                                    .on_hover_text(&spec.tooltip)
                                    .on_disabled_hover_text(&spec.tooltip)
                                    .clicked()
                                {
                                    chosen = Some(spec.action);
                                    ui.close_menu();
                                }
                            }
                        })
                        .response
                        .on_hover_text("More buttons");
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_space(4.0);
                        self.toolbar_status(ui);
                    });
                });
                if let Some(action) = chosen {
                    self.run_tool(action);
                }
            });
    }

    /// The selected VM's state word, name and dot, right to left.
    fn toolbar_status(&self, ui: &mut egui::Ui) {
        let active = self
            .snapshot
            .vms
            .iter()
            .find(|vm| Some(&vm.id) == self.snapshot.active_vm.as_ref());
        let (word, color) = match active {
            Some(_) => vm_state_word(&self.snapshot.state),
            None => ("Stopped", theme::muted()),
        };
        let name =
            active
                .map(|vm| vm.name.as_str())
                .unwrap_or(if self.snapshot.capture_dir.is_some() {
                    "Last recording"
                } else {
                    "No VM running"
                });
        // The state stays whole; the name takes the rest and is cut.
        let state = active.map(|_| {
            let spinner = matches!(self.snapshot.state, VmState::Starting | VmState::Stopping);
            (word, spinner)
        });
        if let Some((word, spinner)) = state {
            ui.label(RichText::new(word).color(color).strong());
            if spinner {
                theme::spinner(ui);
            }
        }
        ui.scope(|ui| {
            // Less the dot that follows the name.
            let room = (ui.available_width() - 20.0).max(24.0);
            ui.set_max_width(room);
            ui.add(
                egui::Label::new(RichText::new(name).color(if active.is_some() {
                    theme::text()
                } else {
                    theme::muted()
                }))
                .truncate(),
            )
            .on_hover_text(name);
        });
        ui.colored_label(color, "●");
    }

    /// The toolbar's buttons in the order they are drawn.
    fn tool_specs(&self, ctx: &egui::Context) -> Vec<ToolSpec> {
        let shortcut =
            |text: &str, shortcut| format!("{text} ({})", ctx.format_shortcut(&shortcut));
        let observer = self.active_observer().map(|capture| {
            format!(
                "Stop capture ({}); programs keep running",
                captures::scope(&capture.scope)
            )
        });
        let capturing = observer.is_some();
        use egui_phosphor::regular as icon;
        vec![
            ToolSpec::new(ToolAction::Start, 0, icon::PLAY, "Start", shortcut("Start the selected VM", keys::START_VM), self.can_start_vm(), theme::good(), true, false),
            ToolSpec::new(ToolAction::Stop, 0, icon::STOP, "Stop", shortcut("Shut down the running VM", keys::STOP_VM), self.can_stop_vm(), theme::error(), true, false),
            ToolSpec::new(ToolAction::Snapshots, 1, icon::CLOCK_COUNTER_CLOCKWISE, "Snapshots", "Save, restore and branch this VM's disk and memory".into(), self.selected.is_some() && !self.closing, theme::blue(), false, false),
            ToolSpec::new(ToolAction::Kill, 2, icon::X_CIRCLE, "Kill", "Terminate the selected active run and descendants; keep the VM running. Select a live run in Run history when several are active.".into(), self.kill_target().is_some(), theme::error(), false, false),
            ToolSpec::new(ToolAction::RunProgram, 2, icon::TERMINAL_WINDOW, "Run program", shortcut("Run a program in the VM and record it", keys::RUN_PROGRAM), self.running(), theme::blue(), false, self.launch_open),
            ToolSpec::new(
                ToolAction::CaptureAll,
                3,
                icon::RECORD,
                "Capture all",
                observer.unwrap_or_else(|| "Record every process in the VM (Run > Attach to process records one)".into()),
                if capturing { self.can_stop_capture() } else { self.observer_start_enabled() },
                theme::error(),
                false,
                capturing,
            ),
            ToolSpec::new(ToolAction::CaptureNetwork, 3, icon::NETWORK, "Capture network", self.network_toggle_label().into(), self.network_toggle_enabled(), theme::info(), false, self.snapshot.network_capture.is_some()),
            ToolSpec::new(ToolAction::DumpMemory, 3, icon::DATABASE, "Dump memory", "Save the running VM's RAM".into(), self.running() && !self.closing && self.snapshot.memory_dump.is_none(), theme::info(), false, self.snapshot.memory_dump.is_some()),
            ToolSpec::new(ToolAction::DumpCore, 3, icon::FILE, "Dump core", self.manual_core_unavailable().unwrap_or("Pause a selected process, capture its core, then resume").to_owned(), self.manual_core_unavailable().is_none(), theme::info(), false, false),
        ]
    }

    fn run_tool(&mut self, action: ToolAction) {
        match action {
            ToolAction::Start => self.new_run(),
            ToolAction::Stop => self.send(Command::Stop),
            ToolAction::Snapshots => self.open_snapshots(),
            ToolAction::Kill => self.request_kill(None),
            ToolAction::RunProgram => self.launch_open = true,
            ToolAction::CaptureAll => {
                if self.active_observer().is_some() {
                    self.stop_observer();
                } else {
                    self.send(Command::CaptureAll);
                }
            }
            ToolAction::CaptureNetwork => self.toggle_network_capture(),
            ToolAction::DumpMemory => {
                self.send(Command::DumpMemory);
                self.focus_panel = Some(Panel::Memory);
            }
            ToolAction::DumpCore => self.open_core_picker(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ToolAction {
    Start,
    Stop,
    Snapshots,
    Kill,
    RunProgram,
    CaptureAll,
    CaptureNetwork,
    DumpMemory,
    DumpCore,
}

/// Which buttons stay when the row is too narrow: first in this list stays
/// longest; the last ones move into the "more" menu first (Dump core, Dump
/// memory, Capture network, Capture all, Snapshots, Kill, Run program, Stop,
/// Start).
pub(super) const TOOL_PRIORITY: [ToolAction; 9] = [
    ToolAction::Start,
    ToolAction::Stop,
    ToolAction::RunProgram,
    ToolAction::Kill,
    ToolAction::Snapshots,
    ToolAction::CaptureAll,
    ToolAction::CaptureNetwork,
    ToolAction::DumpMemory,
    ToolAction::DumpCore,
];

pub(super) struct ToolSpec {
    pub(super) action: ToolAction,
    /// Buttons of one group sit together; a rule separates groups.
    group: u8,
    icon: &'static str,
    label: &'static str,
    tooltip: String,
    enabled: bool,
    tone: egui::Color32,
    strong: bool,
    active: bool,
}

impl ToolSpec {
    #[allow(clippy::too_many_arguments)]
    fn new(
        action: ToolAction,
        group: u8,
        icon: &'static str,
        label: &'static str,
        tooltip: String,
        enabled: bool,
        tone: egui::Color32,
        strong: bool,
        active: bool,
    ) -> Self {
        Self {
            action,
            group,
            icon,
            label,
            tooltip,
            enabled,
            tone,
            strong,
            active,
        }
    }

    fn button(&self) -> ToolButton<'_> {
        ToolButton {
            icon: self.icon,
            label: self.label,
            tooltip: &self.tooltip,
            enabled: self.enabled,
            tone: self.tone,
            strong: self.strong,
            active: self.active,
        }
    }
}

/// The indexes of `specs` that fit the row, by priority: the row keeps room
/// for the status text (at least 150 px) and, when something is left out, for
/// the "more" button.
fn tool_layout(ui: &egui::Ui, specs: &[ToolSpec]) -> Vec<usize> {
    let spacing = 4.0;
    let font = egui::TextStyle::Button.resolve(ui.style());
    let width_of = |spec: &ToolSpec| -> f32 {
        let text = format!("{}      {}", spec.icon, spec.label);
        ui.fonts(|fonts| {
            fonts
                .layout_no_wrap(text, font.clone(), egui::Color32::WHITE)
                .size()
                .x
        }) + ui.spacing().button_padding.x * 2.0
            + spacing
    };
    let more = ui.spacing().interact_size.y + 12.0;
    let status = 150.0;
    let budget = ui.available_width() - status - 12.0;
    let order: Vec<usize> = TOOL_PRIORITY
        .iter()
        .filter_map(|action| specs.iter().position(|spec| spec.action == *action))
        .collect();
    let total: f32 = specs.iter().map(&width_of).sum::<f32>() + 3.0 * 12.0;
    if total <= budget {
        return (0..specs.len()).collect();
    }
    let mut used = more;
    let mut shown = Vec::new();
    for at in order {
        let width = width_of(&specs[at]) + 8.0;
        if used + width > budget {
            break;
        }
        used += width;
        shown.push(at);
    }
    shown
}

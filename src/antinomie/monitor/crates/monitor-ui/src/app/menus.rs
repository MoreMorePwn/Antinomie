// SPDX-License-Identifier: GPL-3.0-only
//! Menu bar, toolbar and keyboard shortcuts.
use super::*;

/// What the Tools menu is wider than the others: icons before the labels.
const TOOLS_MENU_EXTRA_WIDTH: f32 = 90.0;

impl MonitorApp {
    /// Global shortcuts. They wait while a text field or the terminal has the
    /// keyboard (`typing`), so typing never triggers one, and while a snapshot
    /// decision waits for its answer. The palette, tab and `?` shortcuts also
    /// wait behind a confirmation.
    pub(super) fn shortcuts(&mut self, ctx: &egui::Context) {
        if self.vm_snapshots.decision_open() || crate::typing::typing(ctx) {
            return;
        }
        let pressed = |shortcut: egui::KeyboardShortcut| {
            ctx.input_mut(|input| input.consume_shortcut(&shortcut))
        };
        // Shift+F5 first: F5 alone would also match it.
        let mut asked = Vec::new();
        for action in [
            Action::StopVm,
            Action::StartVm,
            Action::NewVm,
            Action::RunProgram,
            Action::UploadFile,
            Action::AttachDebugger,
            Action::TypeClipboard,
            Action::Settings,
            Action::Quit,
        ] {
            if action.shortcut().is_some_and(pressed) {
                asked.push(action);
            }
        }
        // The new shortcuts do not reach behind a confirmation.
        let modal = self.confirm.is_some();
        if !modal {
            if pressed(keys::PALETTE) {
                asked.push(Action::Palette);
            }
            if let Some(position) = (0..keys::TAB_KEYS.len())
                .find(|position| keys::tab_shortcut(*position).is_some_and(pressed))
            {
                if let Some(panel) = self.layout.work_tabs().get(position) {
                    asked.push(Action::Go(panel.clone()));
                }
            }
            for panel in [Panel::Activity, Panel::Jobs] {
                if Action::Go(panel.clone()).shortcut().is_some_and(pressed) {
                    asked.push(Action::Go(panel));
                }
            }
            if crate::typing::question_mark_pressed(ctx) {
                asked.push(Action::Shortcuts);
            }
        }
        for action in asked {
            self.run_action(ctx, action);
        }
    }

    pub(super) fn menus(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("menus")
            .exact_height(self.settings.font_size + 16.0)
            .frame(theme::frame(theme::panel()))
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        // Room between an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width);
                        self.menu_item(ui, Action::NewVm, None);
                        ui.menu_button("Add base", |ui| {
                            ui.set_min_width(ui.spacing().menu_width);
                            self.menu_item(ui, Action::ImportBase, None);
                            self.menu_item(ui, Action::DownloadBase, None);
                            self.menu_item(ui, Action::BuildBase, None);
                        });
                        ui.separator();
                        self.menu_item(ui, Action::Quit, None);
                    });
                    ui.menu_button("VM", |ui| {
                        ui.set_min_width(ui.spacing().menu_width);
                        self.menu_item(ui, Action::StartVm, None);
                        self.menu_item(ui, Action::StopVm, None);
                        ui.separator();
                        self.menu_item(ui, Action::ConfigureVm, None);
                        self.menu_item(ui, Action::Snapshots, None);
                        self.menu_item(ui, Action::ReconnectTelemetry, None);
                        self.menu_item(ui, Action::TypeClipboard, None);
                        self.menu_item(ui, Action::RenameVm, None);
                        self.menu_item(ui, Action::DuplicateVm, None);
                        self.menu_item(ui, Action::OpenVmDirectory, None);
                        ui.separator();
                        self.menu_item(ui, Action::ResetDisk, None);
                        self.menu_item(ui, Action::DeleteVm, None);
                    });
                    ui.menu_button("Run", |ui| {
                        ui.set_min_width(ui.spacing().menu_width);
                        self.menu_item(ui, Action::RunProgram, None);
                        self.menu_item(ui, Action::UploadFile, None);
                        ui.separator();
                        self.menu_item(ui, Action::AttachProcess, None);
                        self.menu_item(ui, Action::AttachDebugger, None);
                        self.menu_item(ui, Action::CaptureAll, None);
                        self.menu_item(ui, Action::StopCapture, None);
                        if self.running() && !self.observer_supported() {
                            ui.colored_label(
                                theme::muted(),
                                "Capture unavailable: needs a base for Antinomie 0.2.0 or newer",
                            );
                        }
                        ui.separator();
                        self.menu_item(ui, Action::NetworkCapture, None);
                    });
                    ui.menu_button("View", |ui| {
                        ui.set_min_width(ui.spacing().menu_width);
                        for view in Panel::MAIN.into_iter().chain([
                            Panel::Details,
                            Panel::Activity,
                            Panel::Jobs,
                        ]) {
                            self.menu_item(ui, Action::Go(view), None);
                        }
                        ui.separator();
                        self.menu_item(ui, Action::ResetLayout, None);
                    });
                    ui.menu_button("Tools", |ui| {
                        // Room for the longest label with its icon, and between
                        // an item and its shortcut.
                        ui.set_min_width(ui.spacing().menu_width + TOOLS_MENU_EXTRA_WIDTH);
                        self.menu_item(ui, Action::Settings, Some(egui_phosphor::regular::GEAR));
                        self.menu_item(
                            ui,
                            Action::AnalysisTools,
                            Some(egui_phosphor::regular::WRENCH),
                        );
                        self.menu_item(
                            ui,
                            Action::DetectionRules,
                            Some(egui_phosphor::regular::SHIELD_CHECK),
                        );
                        self.menu_item(
                            ui,
                            Action::MalwareSamples,
                            Some(egui_phosphor::regular::BIOHAZARD),
                        );
                        self.menu_item(ui, Action::ApiKeys, Some(egui_phosphor::regular::KEY));
                        self.menu_item(
                            ui,
                            Action::Dependencies,
                            Some(egui_phosphor::regular::PACKAGE),
                        );
                        self.menu_item(
                            ui,
                            Action::UiPerformance,
                            Some(egui_phosphor::regular::GAUGE),
                        );
                        ui.separator();
                        self.menu_item(
                            ui,
                            Action::RecorderStats,
                            Some(egui_phosphor::regular::ARROWS_CLOCKWISE),
                        );
                    });
                    ui.menu_button("Help", |ui| {
                        ui.set_min_width(ui.spacing().menu_width);
                        self.menu_item(ui, Action::GettingStarted, None);
                        self.menu_item(ui, Action::About, None);
                        self.menu_item(ui, Action::FilterGuide, None);
                        self.menu_item(ui, Action::Documentation, None);
                        self.menu_item(ui, Action::CheckUpdates, None);
                        ui.separator();
                        self.menu_item(ui, Action::Palette, None);
                        self.menu_item(ui, Action::Shortcuts, None);
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
                    // Always reachable by mouse, also while a text field or the
                    // terminal keeps Ctrl+K for itself.
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let text = format!(
                            "{} Search  {}",
                            egui_phosphor::regular::MAGNIFYING_GLASS,
                            ctx.format_shortcut(&keys::PALETTE)
                        );
                        if ui
                            .add(egui::Button::new(text).frame(false))
                            .on_hover_text(
                                "Command palette: find any action, tab, VM, run or sample",
                            )
                            .clicked()
                        {
                            self.run_action(ctx, Action::Palette);
                        }
                    });
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
        let shortcut = |text: &str, action: Action| self.with_shortcut(ctx, text, &action);
        let observer = self.active_observer().map(|capture| {
            format!(
                "Stop capture ({}); programs keep running",
                captures::scope(&capture.scope)
            )
        });
        let capturing = observer.is_some();
        use egui_phosphor::regular as icon;
        vec![
            ToolSpec::new(ToolAction::Start, 0, icon::PLAY, "Start", shortcut("Start the selected VM", Action::StartVm), self.can_start_vm(), theme::good(), true, false),
            ToolSpec::new(ToolAction::Stop, 0, icon::STOP, "Stop", shortcut("Shut down the running VM", Action::StopVm), self.can_stop_vm(), theme::error(), true, false),
            ToolSpec::new(ToolAction::Snapshots, 1, icon::CLOCK_COUNTER_CLOCKWISE, "Snapshots", "Save, restore and branch this VM's disk and memory".into(), self.selected.is_some() && !self.closing, theme::blue(), false, false),
            ToolSpec::new(ToolAction::Kill, 2, icon::X_CIRCLE, "Kill", "Terminate the selected active run and descendants; keep the VM running. Select a live run in Run history when several are active.".into(), self.kill_target().is_some(), theme::error(), false, false),
            ToolSpec::new(ToolAction::RunProgram, 2, icon::TERMINAL_WINDOW, "Run program", shortcut("Run a program in the VM and record it", Action::RunProgram), self.running(), theme::blue(), false, self.launch_open),
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
        // As `tool_button` lays it out: the icon, 6 px, the label.
        let measure = |text: &str| {
            ui.fonts(|fonts| {
                fonts
                    .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::WHITE)
                    .size()
                    .x
            })
        };
        measure(spec.icon)
            + 6.0
            + measure(spec.label)
            + ui.spacing().button_padding.x * 2.0
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

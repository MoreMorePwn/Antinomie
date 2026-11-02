// SPDX-License-Identifier: GPL-3.0-only
//! The actions the menus, the keyboard shortcuts and the command palette share.
//!
//! One list answers three questions about each action: what it is called and
//! which shortcut it has, whether it can run now (and if not, why), and what
//! it does. The menus, `MonitorApp::shortcuts` and the palette all go through
//! it, so a menu item, its shortcut and its palette entry cannot disagree.
use super::*;

/// What a menu item, a shortcut or a palette entry asks for.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Action {
    NewVm,
    ImportBase,
    DownloadBase,
    BuildBase,
    Quit,
    StartVm,
    StopVm,
    ConfigureVm,
    Snapshots,
    ReconnectTelemetry,
    TypeClipboard,
    RenameVm,
    DuplicateVm,
    OpenVmDirectory,
    ResetDisk,
    DeleteVm,
    RunProgram,
    UploadFile,
    AttachProcess,
    AttachDebugger,
    CaptureAll,
    StopCapture,
    NetworkCapture,
    KillRun,
    DumpMemory,
    DumpCore,
    /// Show a view in the work area (the View menu).
    Go(Panel),
    ResetLayout,
    Settings,
    AnalysisTools,
    DetectionRules,
    MalwareSamples,
    ApiKeys,
    Dependencies,
    UiPerformance,
    RecorderStats,
    GettingStarted,
    About,
    FilterGuide,
    Documentation,
    CheckUpdates,
    Palette,
    Shortcuts,
}

const DOCUMENTATION_URL: &str = "https://antinomie.moremorepwn.blog/docs/";

impl Action {
    /// Every action the palette offers, in the order of the menus. Views are
    /// not here: the palette lists the open tabs instead.
    pub(super) const PALETTE: [Self; 42] = [
        Self::NewVm,
        Self::ImportBase,
        Self::DownloadBase,
        Self::BuildBase,
        Self::Quit,
        Self::StartVm,
        Self::StopVm,
        Self::ConfigureVm,
        Self::Snapshots,
        Self::ReconnectTelemetry,
        Self::TypeClipboard,
        Self::RenameVm,
        Self::DuplicateVm,
        Self::OpenVmDirectory,
        Self::ResetDisk,
        Self::DeleteVm,
        Self::RunProgram,
        Self::UploadFile,
        Self::AttachProcess,
        Self::AttachDebugger,
        Self::CaptureAll,
        Self::StopCapture,
        Self::NetworkCapture,
        Self::KillRun,
        Self::DumpMemory,
        Self::DumpCore,
        Self::ResetLayout,
        Self::Settings,
        Self::AnalysisTools,
        Self::DetectionRules,
        Self::MalwareSamples,
        Self::ApiKeys,
        Self::Dependencies,
        Self::UiPerformance,
        Self::RecorderStats,
        Self::GettingStarted,
        Self::About,
        Self::FilterGuide,
        Self::Documentation,
        Self::CheckUpdates,
        Self::Palette,
        Self::Shortcuts,
    ];

    /// The menu the action lives in.
    pub(super) fn group(&self) -> &'static str {
        match self {
            Self::NewVm | Self::ImportBase | Self::DownloadBase | Self::BuildBase | Self::Quit => {
                "File"
            }
            Self::StartVm
            | Self::StopVm
            | Self::ConfigureVm
            | Self::Snapshots
            | Self::ReconnectTelemetry
            | Self::TypeClipboard
            | Self::RenameVm
            | Self::DuplicateVm
            | Self::OpenVmDirectory
            | Self::ResetDisk
            | Self::DeleteVm => "VM",
            Self::RunProgram
            | Self::UploadFile
            | Self::AttachProcess
            | Self::AttachDebugger
            | Self::CaptureAll
            | Self::StopCapture
            | Self::NetworkCapture
            | Self::KillRun
            | Self::DumpMemory
            | Self::DumpCore => "Run",
            Self::Go(_) | Self::ResetLayout => "View",
            Self::Settings
            | Self::AnalysisTools
            | Self::DetectionRules
            | Self::MalwareSamples
            | Self::ApiKeys
            | Self::Dependencies
            | Self::UiPerformance
            | Self::RecorderStats => "Tools",
            Self::GettingStarted
            | Self::About
            | Self::FilterGuide
            | Self::Documentation
            | Self::CheckUpdates
            | Self::Palette
            | Self::Shortcuts => "Help",
        }
    }

    /// The shortcut that always means this action. A view's Ctrl+digit moves
    /// with its tab (`MonitorApp::shortcut_text`).
    pub(super) fn shortcut(&self) -> Option<egui::KeyboardShortcut> {
        Some(match self {
            Self::NewVm => keys::NEW_VM,
            Self::StartVm => keys::START_VM,
            Self::StopVm => keys::STOP_VM,
            Self::RunProgram => keys::RUN_PROGRAM,
            Self::UploadFile => keys::UPLOAD,
            Self::AttachDebugger => keys::ATTACH_DEBUGGER,
            Self::TypeClipboard => keys::TYPE_CLIPBOARD,
            Self::Settings => keys::SETTINGS,
            Self::Quit => keys::QUIT,
            Self::Palette => keys::PALETTE,
            _ => return None,
        })
    }

    /// The words of the menu item, without icon or shortcut.
    pub(super) fn label(&self, app: &MonitorApp) -> String {
        match self {
            Self::NewVm => "New VM…".into(),
            Self::ImportBase => "Import base…".into(),
            Self::DownloadBase => "Download base…".into(),
            Self::BuildBase => "Build base…".into(),
            Self::Quit => "Exit".into(),
            Self::StartVm => "Start VM".into(),
            Self::StopVm => "Stop VM".into(),
            Self::ConfigureVm => "Configuration…".into(),
            Self::Snapshots => "Snapshots…".into(),
            Self::ReconnectTelemetry => "Reconnect telemetry".into(),
            Self::TypeClipboard => "Type host clipboard into VM".into(),
            Self::RenameVm => "Rename…".into(),
            Self::DuplicateVm => "Duplicate…".into(),
            Self::OpenVmDirectory => "Open directory".into(),
            Self::ResetDisk => "Reset disk to base…".into(),
            Self::DeleteVm => "Delete VM and disk…".into(),
            Self::RunProgram => "Run program…".into(),
            Self::UploadFile => "Upload file…".into(),
            Self::AttachProcess => "Attach to process…".into(),
            Self::AttachDebugger => "Attach debugger…".into(),
            Self::CaptureAll => "Capture all".into(),
            Self::StopCapture => "Stop capture".into(),
            Self::NetworkCapture => if app.snapshot.network_capture.is_some() {
                "Stop network capture"
            } else {
                "Capture network"
            }
            .into(),
            Self::KillRun => "Kill run".into(),
            Self::DumpMemory => "Dump memory".into(),
            Self::DumpCore => "Dump core…".into(),
            Self::Go(panel) => panel.title().into(),
            Self::ResetLayout => "Reset layout".into(),
            Self::Settings => "Settings…".into(),
            Self::AnalysisTools => "Analysis tools".into(),
            Self::DetectionRules => "Detection rules".into(),
            Self::MalwareSamples => "Download malware samples…".into(),
            Self::ApiKeys => "API keys…".into(),
            Self::Dependencies => "App dependencies…".into(),
            Self::UiPerformance => "UI performance…".into(),
            Self::RecorderStats => "Refresh recorder statistics".into(),
            Self::GettingStarted => "Getting started".into(),
            Self::About => "About Antinomie".into(),
            Self::FilterGuide => "Filter guide".into(),
            Self::Documentation => "Online documentation".into(),
            Self::CheckUpdates => "Check for updates…".into(),
            Self::Palette => "Command palette".into(),
            Self::Shortcuts => "Keyboard shortcuts".into(),
        }
    }

    /// A sentence for the tooltip, where the label is not enough.
    pub(super) fn hint(&self) -> Option<&'static str> {
        match self {
            Self::TypeClipboard => Some(
                "Types into the guest's focused input using a US keyboard layout; Caps Lock \
                 should be off. Newlines press Enter. Maximum 4 KiB.",
            ),
            _ => None,
        }
    }
}

impl MonitorApp {
    /// Why the selected VM cannot take an action that needs it running.
    fn not_running_reason(&self) -> String {
        if self.selected.is_none() {
            "Select a VM first.".into()
        } else if self.snapshot.active_vm != self.selected {
            "Start the selected VM first.".into()
        } else if self.snapshot.memory_dump.is_some() {
            "Wait for the VM RAM dump to finish; the guest is paused.".into()
        } else {
            "Wait until the VM is running.".into()
        }
    }

    /// Why a capture cannot start now.
    fn capture_start_reason(&self) -> String {
        if !self.running() {
            self.not_running_reason()
        } else if self.closing {
            "The app is closing.".into()
        } else if !self.observer_supported() {
            "Capture needs a base for Antinomie 0.2.0 or newer.".into()
        } else {
            "A capture is already running or starting.".into()
        }
    }

    /// Why `action` cannot run now, or `None` when it can. The text is what a
    /// disabled menu item and a palette entry show.
    pub(super) fn action_unavailable(&self, action: &Action) -> Option<String> {
        let stopped = self.snapshot.active_vm.is_none();
        let stopped_selection = self.selected.is_some() && stopped;
        let reason = |ok: bool, text: &str| (!ok).then(|| text.to_owned());
        match action {
            Action::NewVm | Action::ImportBase => reason(stopped, "Stop the running VM first."),
            Action::StartVm => {
                if self.can_start_vm() {
                    None
                } else if self.snapshot.active_vm.is_some() {
                    Some("A VM is already running.".into())
                } else {
                    Some("Select a VM first.".into())
                }
            }
            Action::StopVm => reason(self.can_stop_vm(), "No VM is running."),
            Action::ConfigureVm => {
                if self.can_configure_vm() {
                    None
                } else if self.selected.is_none() {
                    Some("Select a VM first.".into())
                } else {
                    Some("Stop the VM to change its configuration.".into())
                }
            }
            Action::Snapshots => {
                if self.selected.is_none() {
                    Some("Select a VM first.".into())
                } else {
                    reason(!self.closing, "The app is closing.")
                }
            }
            Action::ReconnectTelemetry => {
                if !self.running() {
                    Some(self.not_running_reason())
                } else {
                    reason(
                        !self.closing && self.vm_snapshots.pending.is_none(),
                        "Wait for the running operation to finish.",
                    )
                }
            }
            Action::TypeClipboard => {
                if self.clipboard_enabled() {
                    None
                } else if !self.running() {
                    Some(self.not_running_reason())
                } else {
                    Some("Wait for the running operation to finish.".into())
                }
            }
            Action::RenameVm => {
                if self.selected_vm().is_none() {
                    Some("Select a VM first.".into())
                } else {
                    reason(!self.closing, "The app is closing.")
                }
            }
            Action::DuplicateVm => {
                if !stopped_selection {
                    Some("Select a stopped VM first.".into())
                } else {
                    reason(!self.closing, "The app is closing.")
                }
            }
            Action::OpenVmDirectory => reason(self.selected_vm().is_some(), "Select a VM first."),
            Action::ResetDisk | Action::DeleteVm => {
                reason(stopped_selection, "Select a stopped VM first.")
            }
            Action::RunProgram | Action::UploadFile => {
                reason(self.running(), &self.not_running_reason())
            }
            Action::AttachProcess | Action::CaptureAll => {
                reason(self.observer_start_enabled(), &self.capture_start_reason())
            }
            Action::AttachDebugger => self.debugger_unavailable().map(str::to_owned),
            Action::StopCapture => {
                if self.can_stop_capture() {
                    None
                } else if !self.running() {
                    Some(self.not_running_reason())
                } else {
                    Some("No capture is running.".into())
                }
            }
            Action::NetworkCapture => {
                if self.network_toggle_enabled() {
                    None
                } else if !self.running() {
                    Some(self.not_running_reason())
                } else if self.pending_network.is_some() {
                    Some("Wait for the network capture to change.".into())
                } else {
                    Some(self.network_toggle_label().into())
                }
            }
            Action::KillRun => reason(
                self.kill_target().is_some(),
                "No active run to kill. Select a live run in Run history.",
            ),
            Action::DumpMemory => {
                if !self.running() {
                    Some(self.not_running_reason())
                } else {
                    reason(
                        !self.closing && self.snapshot.memory_dump.is_none(),
                        "A memory dump is already running.",
                    )
                }
            }
            Action::DumpCore => self.manual_core_unavailable().map(str::to_owned),
            Action::RecorderStats => reason(self.running(), &self.not_running_reason()),
            Action::Go(_)
            | Action::Quit
            | Action::DownloadBase
            | Action::BuildBase
            | Action::ResetLayout
            | Action::Settings
            | Action::AnalysisTools
            | Action::DetectionRules
            | Action::MalwareSamples
            | Action::ApiKeys
            | Action::Dependencies
            | Action::UiPerformance
            | Action::GettingStarted
            | Action::About
            | Action::FilterGuide
            | Action::Documentation
            | Action::CheckUpdates
            | Action::Palette
            | Action::Shortcuts => None,
        }
    }

    /// The shortcut text of `action` for a menu or a tooltip: its own key, or
    /// for a view the Ctrl+digit of its place in the work area.
    pub(super) fn shortcut_text(&self, ctx: &egui::Context, action: &Action) -> Option<String> {
        match action {
            Action::Go(panel) => self
                .layout
                .tab_key_position(panel)
                .and_then(keys::tab_shortcut)
                .map(|shortcut| ctx.format_shortcut(&shortcut)),
            Action::Shortcuts => Some(keys::SHORTCUT_LIST.into()),
            other => other
                .shortcut()
                .map(|shortcut| ctx.format_shortcut(&shortcut)),
        }
    }

    /// `text` with the shortcut of `action` after it, for a tooltip.
    pub(super) fn with_shortcut(&self, ctx: &egui::Context, text: &str, action: &Action) -> String {
        match self.shortcut_text(ctx, action) {
            Some(shortcut) => format!("{text} ({shortcut})"),
            None => text.into(),
        }
    }

    /// Run `action` if it can run now. Everything that does something for a
    /// menu item, a shortcut or a palette entry is here.
    pub(super) fn run_action(&mut self, ctx: &egui::Context, action: Action) {
        if self.action_unavailable(&action).is_some() {
            return;
        }
        match action {
            Action::NewVm => self.new_image(),
            Action::ImportBase => self.import_open = true,
            Action::DownloadBase => self.open_downloads(),
            Action::BuildBase => self.build_open = true,
            Action::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Action::StartVm => self.new_run(),
            Action::StopVm => self.send(Command::Stop),
            Action::ConfigureVm => self.configure_vm(),
            Action::Snapshots => self.open_snapshots(),
            Action::ReconnectTelemetry => self.send(Command::ReconnectTransport),
            Action::TypeClipboard => self.request_clipboard(ctx),
            Action::RenameVm => {
                if let Some(vm) = self.selected_vm().cloned() {
                    self.name_action = Some((vm.id.clone(), false, vm.name));
                }
            }
            Action::DuplicateVm => {
                if let Some(vm) = self.selected_vm().cloned() {
                    self.name_action = Some((vm.id.clone(), true, format!("{} copy", vm.name)));
                }
            }
            Action::OpenVmDirectory => {
                if let Some(vm) = self.selected_vm().cloned() {
                    self.open_vm_directory(&vm.id);
                }
            }
            Action::ResetDisk => self.confirm = self.selected.clone().map(Confirm::Reset),
            Action::DeleteVm => self.confirm = self.selected.clone().map(Confirm::Delete),
            Action::RunProgram => self.launch_open = true,
            Action::UploadFile => self.open_upload(),
            Action::AttachProcess => self.open_process_picker(),
            Action::AttachDebugger => self.open_debug_picker(),
            Action::CaptureAll => self.send(Command::CaptureAll),
            Action::StopCapture => self.stop_observer(),
            Action::NetworkCapture => self.toggle_network_capture(),
            Action::KillRun => self.request_kill(None),
            Action::DumpMemory => {
                self.send(Command::DumpMemory);
                self.focus_panel = Some(Panel::Memory);
            }
            Action::DumpCore => self.open_core_picker(),
            Action::Go(panel) => self.focus_panel = Some(panel),
            Action::ResetLayout => self.layout = WorkspaceLayout::default(),
            Action::Settings => self.settings_open = true,
            Action::AnalysisTools => self.open_library(LibraryPage::Tools),
            Action::DetectionRules => self.open_library(LibraryPage::Rules),
            Action::MalwareSamples => self.samples.open = true,
            Action::ApiKeys => self.api_keys.open = true,
            Action::Dependencies => {
                self.folder_picker.refresh(ctx);
                self.dependencies.open = true;
            }
            Action::UiPerformance => self.performance.open = true,
            Action::RecorderStats => self.send(Command::RecorderStats),
            Action::GettingStarted => self.open_getting_started(),
            Action::About => self.about_open = true,
            Action::FilterGuide => crate::query::open_guide(ctx),
            Action::Documentation => ctx.open_url(egui::OpenUrl::new_tab(DOCUMENTATION_URL)),
            Action::CheckUpdates => {
                let outbound = self.settings.outbound_catalog;
                self.updates.request(ctx, &self.options.curl, outbound);
            }
            Action::Palette => self.shortcut_ui.open_palette(),
            Action::Shortcuts => self.shortcut_ui.list_open = true,
        }
    }

    /// One menu item: label, shortcut, disabled with the reason as its
    /// tooltip. `icon` is a phosphor glyph some menus put before the label.
    pub(super) fn menu_item(&mut self, ui: &mut egui::Ui, action: Action, icon: Option<&str>) {
        let label = action.label(self);
        let text = match icon {
            Some(icon) => format!("{icon} {label}"),
            None => label,
        };
        let mut button = egui::Button::new(text);
        if let Some(shortcut) = self.shortcut_text(ui.ctx(), &action) {
            button = button.shortcut_text(shortcut);
        }
        let reason = self.action_unavailable(&action);
        let mut response = ui.add_enabled(reason.is_none(), button);
        if let Some(reason) = &reason {
            response = response.on_disabled_hover_text(reason);
        }
        if let Some(hint) = action.hint() {
            response = response.on_hover_text(hint);
        }
        if response.clicked() {
            let ctx = ui.ctx().clone();
            self.run_action(&ctx, action);
            ui.close_menu();
        }
    }
}

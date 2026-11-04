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
    /// Fold the sidebar to its icon rail, or open it again.
    ToggleSidebar,
    /// Fold the Details, Activity and Jobs pane to its tab strip, or open it again.
    ToggleBottomPane,
    Settings,
    AnalysisTools,
    DetectionRules,
    MalwareSamples,
    ApiKeys,
    Dependencies,
    UiPerformance,
    RecorderStats,
    GettingStarted,
    /// Getting started, opened on its Appearance step.
    GettingStartedAppearance,
    About,
    FilterGuide,
    Documentation,
    CheckUpdates,
    Palette,
    Shortcuts,
    /// Settings, opened on one page.
    SettingsTo(settings_window::SettingsPage),
    /// The Base images page of the Library.
    BaseImages,
    /// The Samples page of the Library.
    SamplesPage,
    /// The Screenshots page of the Library.
    ScreenshotsPage,
    /// The Samples page with its Add file window.
    AddSampleFile,
    /// The Detection rules page on one engine tab ("yara", "ids", "sigma",
    /// "regex" or "ioc"), on its Catalog list when `true`.
    RulesEngine(&'static str, bool),
    /// Getting started, opened on one step.
    GettingStartedStep(crate::getting_started::Step),
    /// The Memory tab's Import dump window.
    ImportMemoryDump,
    /// The Memory tab's community Plugin catalog window.
    PluginCatalog,
    /// The Disks tab's Import image window.
    ImportDiskImage,
    /// The Core dumps tab's Import core window.
    ImportCore,
    /// Choose the host folder the sidebar's Explorer shows.
    ExplorerFolder,
    /// The selected VM's Telemetry transport window.
    TelemetryTransport,
    /// The selected VM's Device profile window.
    DeviceProfile,
    /// The terminal of the selected run, as its Run History row opens it.
    OpenTerminal,
    /// Edit tags of the selected run.
    EditRunTags,
    /// Delete the selected run (one that never recorded).
    DeleteRun,
    /// Triage > Export report of the selected run.
    ExportReport,
    /// The details of the rule selected in Detection rules.
    RuleDetails,
    /// The IDS rules' abuse.ch packs tab.
    AbusechPacks,
}

const DOCUMENTATION_URL: &str = "https://antinomie.moremorepwn.blog/docs/";

impl Action {
    /// Every action the palette offers, in the order of the menus. Views are
    /// not here: the palette lists the open tabs instead.
    pub(super) const PALETTE: [Self; 45] = [
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
        Self::ToggleSidebar,
        Self::ToggleBottomPane,
        Self::Settings,
        Self::AnalysisTools,
        Self::DetectionRules,
        Self::MalwareSamples,
        Self::ApiKeys,
        Self::Dependencies,
        Self::UiPerformance,
        Self::RecorderStats,
        Self::GettingStarted,
        Self::GettingStartedAppearance,
        Self::About,
        Self::FilterGuide,
        Self::Documentation,
        Self::CheckUpdates,
        Self::Palette,
        Self::Shortcuts,
    ];

    /// The entries the palette adds to the menus' own: the windows, pages and
    /// steps that only a button inside a page opens.
    pub(super) fn palette_pages() -> Vec<Self> {
        use crate::getting_started::Step;
        let mut actions: Vec<Self> = settings_window::SettingsPage::ALL
            .into_iter()
            .map(Self::SettingsTo)
            .collect();
        actions.extend([
            Self::BaseImages,
            Self::SamplesPage,
            Self::ScreenshotsPage,
            Self::AddSampleFile,
        ]);
        for engine in ["yara", "ids", "sigma"] {
            actions.push(Self::RulesEngine(engine, false));
            actions.push(Self::RulesEngine(engine, true));
        }
        actions.extend([
            Self::RulesEngine("regex", false),
            Self::RulesEngine("ioc", false),
        ]);
        actions.extend(
            Step::ALL
                .into_iter()
                .filter(|step| *step != Step::Appearance)
                .map(Self::GettingStartedStep),
        );
        actions.extend([
            Self::ImportMemoryDump,
            Self::PluginCatalog,
            Self::ImportDiskImage,
            Self::ImportCore,
            Self::ExplorerFolder,
            Self::TelemetryTransport,
            Self::DeviceProfile,
            Self::OpenTerminal,
            Self::EditRunTags,
            Self::DeleteRun,
            Self::ExportReport,
            Self::RuleDetails,
            Self::AbusechPacks,
        ]);
        actions
    }

    /// Other words that find the action in the palette.
    pub(super) fn keywords(&self) -> &'static str {
        match self {
            Self::NewVm => "create machine virtual",
            Self::ImportBase => "add base image file",
            Self::DownloadBase => "add base image catalog get",
            Self::BuildBase => "add base image create make",
            Self::Quit => "close exit leave",
            Self::ConfigureVm => "settings hardware cpu memory network disk",
            Self::Snapshots => "restore checkpoint save state",
            Self::UploadFile => "send copy file guest",
            Self::AttachProcess => "pid running process",
            Self::AttachDebugger => "gdb breakpoint step",
            Self::DumpMemory => "ram volatility",
            Self::DumpCore => "process core gcore",
            Self::Go(Panel::Jobs) => "running finished background tasks window",
            Self::Go(Panel::Activity) => "log messages notifications",
            Self::Settings => "preferences options configuration",
            Self::AnalysisTools => "install static tools library",
            Self::DetectionRules => "yara suricata sigma ids packs library",
            Self::MalwareSamples => "bazaar malshare download fetch",
            Self::ApiKeys => "abuse.ch malshare token credentials",
            Self::Dependencies => "packages requirements qemu tshark install",
            Self::UiPerformance => "fps frame time speed profiler",
            Self::GettingStarted | Self::GettingStartedAppearance => "welcome tour setup wizard",
            Self::GettingStartedStep(_) => "welcome tour setup wizard step",
            Self::About => "version licence license",
            Self::FilterGuide => "query search syntax help",
            Self::CheckUpdates => "upgrade new version release",
            Self::Palette => "search find commands",
            Self::Shortcuts => "keys keyboard hotkeys help",
            Self::SettingsTo(page) => match page {
                settings_window::SettingsPage::Appearance => {
                    "theme dark light font size text zoom colour color time zone"
                }
                settings_window::SettingsPage::Recording => "capture save folder retention",
                settings_window::SettingsPage::Detection => "yara ids sigma scan triage",
                settings_window::SettingsPage::Notifications => "toast sound alert",
                settings_window::SettingsPage::NetworkLookup => {
                    "whois dns reverse geoip virustotal address ip outbound"
                }
                settings_window::SettingsPage::NetworkRoutes => {
                    "proxy tor vpn internet gateway sinkhole"
                }
                settings_window::SettingsPage::AnalysisTools => "ghidra capa floss tools paths",
                settings_window::SettingsPage::Disks => "ext4 image partition dump",
                settings_window::SettingsPage::Keyboard => "shortcut keys bindings hotkeys 60%",
                settings_window::SettingsPage::Advanced => "rows page limit developer",
            },
            Self::BaseImages => "library bases guest images",
            Self::SamplesPage => "library malware files hashes tags",
            Self::ScreenshotsPage => "library screenshots gallery images vm screen pictures png",
            Self::AddSampleFile => "samples library import hash add",
            Self::RulesEngine("yara", _) => "rules packs library scan",
            Self::RulesEngine("ids", _) => "suricata network rules packs library abuse.ch",
            Self::RulesEngine("sigma", _) => "log rules packs library",
            Self::RulesEngine("regex", _) => "strings patterns",
            Self::RulesEngine("ioc", _) => {
                "indicators abuse.ch urlhaus threatfox feodo download datasets"
            }
            Self::RulesEngine(..) => "rules",
            Self::ImportMemoryDump => "ram volatility open analyse",
            Self::PluginCatalog => "volatility community download memory",
            Self::ImportDiskImage => "ext4 qcow2 raw open analyse",
            Self::ImportCore => "process core elf open analyse",
            Self::ExplorerFolder => "sidebar host files browse",
            Self::TelemetryTransport => "vm configuration channel serial vsock connection",
            Self::DeviceProfile => "stealth firmware bios uefi cpu identity hardware profile",
            Self::OpenTerminal => "shell console run program output",
            Self::EditRunTags => "label annotate run history evidence",
            Self::DeleteRun => "remove failed run history evidence",
            Self::ExportReport => "html pdf json misp stix write triage",
            Self::RuleDetails => "yara suricata sigma source text sid",
            Self::AbusechPacks => "suricata ids rules update check live feed",
            Self::Go(Panel::Debugger) => "gdb breakpoints attach process",
            Self::Go(Panel::VmScreen) => "display monitor console vnc keyboard mouse",
            _ => "",
        }
    }

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
            Self::Go(_) | Self::ResetLayout | Self::ToggleSidebar | Self::ToggleBottomPane => {
                "View"
            }
            Self::SettingsTo(_) => "Settings",
            Self::BaseImages | Self::SamplesPage | Self::ScreenshotsPage | Self::AddSampleFile => {
                "Library"
            }
            Self::RulesEngine(..) => "Rules",
            Self::ImportMemoryDump | Self::PluginCatalog => "Memory",
            Self::ImportDiskImage => "Disks",
            Self::ImportCore => "Core dumps",
            Self::ExplorerFolder => "Explorer",
            Self::TelemetryTransport | Self::DeviceProfile => "VM",
            Self::OpenTerminal | Self::EditRunTags | Self::DeleteRun | Self::ExportReport => "Run",
            Self::RuleDetails | Self::AbusechPacks => "Rules",
            Self::Settings
            | Self::AnalysisTools
            | Self::DetectionRules
            | Self::MalwareSamples
            | Self::ApiKeys
            | Self::Dependencies
            | Self::UiPerformance
            | Self::RecorderStats => "Tools",
            Self::GettingStarted
            | Self::GettingStartedAppearance
            | Self::GettingStartedStep(_)
            | Self::About
            | Self::FilterGuide
            | Self::Documentation
            | Self::CheckUpdates
            | Self::Palette
            | Self::Shortcuts => "Help",
        }
    }

    /// The shortcut this action has until Settings > Keyboard changes it (see
    /// `MonitorApp::shortcut_of`). A view's Ctrl+digit moves with its tab
    /// (`MonitorApp::shortcut_text`).
    pub(super) fn default_shortcut(&self) -> Option<egui::KeyboardShortcut> {
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
            Self::ToggleSidebar => keys::TOGGLE_SIDEBAR,
            Self::ToggleBottomPane => keys::TOGGLE_BOTTOM_PANE,
            Self::Go(Panel::Activity) => keys::SHOW_ACTIVITY,
            Self::Go(Panel::Jobs) => keys::SHOW_JOBS,
            Self::Go(Panel::Details) => keys::SHOW_DETAILS,
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
            Self::ToggleSidebar => "Fold or open the sidebar".into(),
            Self::ToggleBottomPane => "Fold or open Details, Activity and Jobs".into(),
            Self::Settings => "Settings…".into(),
            Self::AnalysisTools => "Analysis tools".into(),
            Self::DetectionRules => "Detection rules".into(),
            Self::MalwareSamples => "Download malware samples…".into(),
            Self::ApiKeys => "API keys…".into(),
            Self::Dependencies => "App dependencies…".into(),
            Self::UiPerformance => "UI performance…".into(),
            Self::RecorderStats => "Refresh recorder statistics".into(),
            Self::GettingStarted => "Getting started".into(),
            Self::GettingStartedAppearance => "Getting started: Appearance".into(),
            Self::About => "About Antinomie".into(),
            Self::FilterGuide => "Filter guide".into(),
            Self::Documentation => "Online documentation".into(),
            Self::CheckUpdates => "Check for updates…".into(),
            Self::Palette => "Command palette".into(),
            Self::Shortcuts => "Keyboard shortcuts".into(),
            Self::SettingsTo(page) => format!("Settings: {}", page.label()),
            Self::BaseImages => "Base images".into(),
            Self::SamplesPage => "Samples".into(),
            Self::ScreenshotsPage => "Screenshots".into(),
            Self::AddSampleFile => "Add file to Samples…".into(),
            Self::RulesEngine(engine, catalog) => {
                let name = match *engine {
                    "yara" => "YARA rules",
                    "ids" => "IDS rules",
                    "sigma" => "Sigma rules",
                    "regex" => "Strings regex rules",
                    _ => "IOC datasets and downloads",
                };
                if *catalog {
                    format!("{name}: download catalog")
                } else {
                    name.into()
                }
            }
            Self::GettingStartedStep(step) => format!("Getting started: {}", step.title()),
            Self::ImportMemoryDump => "Import memory dump…".into(),
            Self::PluginCatalog => "Memory plugin catalog…".into(),
            Self::ImportDiskImage => "Import disk image…".into(),
            Self::ImportCore => "Import process core…".into(),
            Self::ExplorerFolder => "Choose Explorer folder…".into(),
            Self::TelemetryTransport => "Telemetry transport…".into(),
            Self::DeviceProfile => "Device profile…".into(),
            Self::OpenTerminal => "Open terminal of the selected run".into(),
            Self::EditRunTags => "Edit tags of the selected run…".into(),
            Self::DeleteRun => "Delete the selected run…".into(),
            Self::ExportReport => "Export report…".into(),
            Self::RuleDetails => "Rule details".into(),
            Self::AbusechPacks => "IDS rules: abuse.ch packs".into(),
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
            Action::ImportMemoryDump
            | Action::PluginCatalog
            | Action::ImportDiskImage
            | Action::ImportCore => {
                if matches!(action, Action::PluginCatalog) {
                    None
                } else {
                    reason(self.selected.is_some(), "Select a VM first.")
                }
            }
            Action::ExplorerFolder => reason(
                self.folder_picker.available(),
                "Install Zenity to choose a folder.",
            ),
            Action::TelemetryTransport | Action::DeviceProfile => {
                if self.can_configure_vm() {
                    None
                } else if self.selected.is_none() {
                    Some("Select a VM first.".into())
                } else {
                    Some("Stop the VM to change its configuration.".into())
                }
            }
            Action::OpenTerminal | Action::EditRunTags | Action::ExportReport => {
                reason(self.selected_vm_run().is_some(), "Select a run first.")
            }
            Action::DeleteRun => match self.selected_vm_run() {
                None => Some("Select a run first.".into()),
                Some(run) if !run.state.never_recorded() => Some(
                    "Only a run that never recorded is deleted here; delete the others from \
                     their sample in Samples."
                        .into(),
                ),
                Some(run) if self.snapshot.runs.iter().any(|live| live.id == run.id) => Some(
                    "The VM still owns this launch's cleanup; try again after it stops.".into(),
                ),
                Some(_) => None,
            },
            Action::RuleDetails => reason(
                self.rules_ui.has_rule_selected(),
                "Select a rule in Detection rules first.",
            ),
            Action::Go(Panel::VmScreen) => self.vm_screen_unavailable(),
            Action::Go(Panel::Debugger) => reason(
                self.snapshot.debug.is_some(),
                "No debugger is attached; attach one to a process first.",
            ),
            Action::AbusechPacks
            | Action::Go(_)
            | Action::Quit
            | Action::DownloadBase
            | Action::BuildBase
            | Action::ResetLayout
            | Action::ToggleSidebar
            | Action::ToggleBottomPane
            | Action::Settings
            | Action::AnalysisTools
            | Action::DetectionRules
            | Action::MalwareSamples
            | Action::ApiKeys
            | Action::Dependencies
            | Action::UiPerformance
            | Action::GettingStarted
            | Action::GettingStartedAppearance
            | Action::About
            | Action::FilterGuide
            | Action::Documentation
            | Action::CheckUpdates
            | Action::Palette
            | Action::Shortcuts
            | Action::SettingsTo(_)
            | Action::BaseImages
            | Action::SamplesPage
            | Action::ScreenshotsPage
            | Action::AddSampleFile
            | Action::RulesEngine(..)
            | Action::GettingStartedStep(_) => None,
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
                .or_else(|| self.shortcut_of(action))
                .map(|shortcut| ctx.format_shortcut(&shortcut)),
            Action::Shortcuts => Some(
                self.shortcut_of(action)
                    .map_or_else(|| keys::SHORTCUT_LIST.into(), |s| ctx.format_shortcut(&s)),
            ),
            other => self
                .shortcut_of(other)
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
            Action::AttachDebugger => {
                let picker = &mut self.process_picker;
                if picker.open && picker.purpose == captures::ProcessPurpose::Debug {
                    // The list is already open: the key attaches the selected process.
                    picker.confirm = true;
                } else {
                    self.open_debug_picker();
                }
            }
            Action::CaptureAll => self.send(Command::CaptureAll),
            Action::StopCapture => self.stop_observer(),
            Action::NetworkCapture => self.toggle_network_capture(),
            Action::KillRun => self.request_kill(None),
            Action::DumpMemory => {
                self.send(Command::DumpMemory);
                self.focus_panel = Some(Panel::Memory);
            }
            Action::DumpCore => self.open_core_picker(),
            Action::Go(Panel::VmScreen) => {
                self.set_vm_screen_closed(false);
                self.vm_screen_request = true;
            }
            Action::Go(panel) => self.show_panel_asked(panel),
            Action::ResetLayout => self.layout = WorkspaceLayout::default(),
            Action::ToggleSidebar => self.toggle_sidebar(),
            Action::ToggleBottomPane => self.layout.toggle_bottom(),
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
            Action::GettingStartedAppearance => {
                self.open_getting_started();
                self.getting_started.step = crate::getting_started::Step::Appearance;
            }
            Action::About => self.about_open = true,
            Action::FilterGuide => crate::query::open_guide(ctx),
            Action::Documentation => ctx.open_url(egui::OpenUrl::new_tab(DOCUMENTATION_URL)),
            Action::CheckUpdates => {
                let outbound = self.settings.outbound_catalog;
                self.updates.request(ctx, &self.options.curl, outbound);
            }
            Action::Palette => self.shortcut_ui.open_palette(),
            Action::Shortcuts => self.shortcut_ui.list_open = true,
            Action::SettingsTo(page) => self.open_settings_page(page.label()),
            Action::BaseImages => self.open_library(LibraryPage::BaseImages),
            Action::SamplesPage => self.open_library(LibraryPage::Samples),
            Action::ScreenshotsPage => self.open_library(LibraryPage::Screenshots),
            Action::AddSampleFile => {
                self.open_library(LibraryPage::Samples);
                self.samples_page.open_add(None);
            }
            Action::RulesEngine(engine, catalog) => {
                self.rules_ui.show_engine(engine, catalog);
                self.open_library(LibraryPage::Rules);
            }
            Action::GettingStartedStep(step) => {
                self.open_getting_started();
                self.getting_started.step = step;
            }
            Action::ImportMemoryDump => {
                self.memory_view.open_import();
                self.focus_panel = Some(Panel::Memory);
            }
            Action::PluginCatalog => {
                self.memory_view.open_plugin_catalog();
                self.focus_panel = Some(Panel::Memory);
            }
            Action::ImportDiskImage => {
                self.disk_view.open_import();
                self.focus_panel = Some(Panel::Disks);
            }
            Action::ImportCore => {
                self.core_view.open_import_window();
                self.focus_panel = Some(Panel::CoreDump);
            }
            Action::TelemetryTransport => {
                self.configure_vm();
                self.transport_open = true;
            }
            Action::DeviceProfile => {
                self.configure_vm();
                self.stealth_open = true;
            }
            Action::OpenTerminal => {
                if let Some(run) = self.selected_vm_run().cloned() {
                    self.reopen(run);
                }
            }
            Action::EditRunTags => {
                if let Some(run) = self.selected_vm_run() {
                    crate::evidence::edit_tags(ctx, &run.directory);
                }
            }
            Action::DeleteRun => {
                if let Some(run) = self.selected_vm_run().cloned() {
                    let title = run
                        .request
                        .path
                        .rsplit('/')
                        .next()
                        .unwrap_or("run")
                        .to_owned();
                    self.ask_delete_evidence(crate::evidence_delete::Deletion::failed_run(
                        &run.directory,
                        &title,
                    ));
                }
            }
            Action::ExportReport => {
                self.triage.request_report();
                self.focus_panel = Some(Panel::Triage);
            }
            Action::RuleDetails => self.open_library(LibraryPage::Rules),
            Action::AbusechPacks => {
                self.rules_ui.show_abusech();
                self.open_library(LibraryPage::Rules);
            }
            Action::ExplorerFolder => {
                if let Err(error) = self.folder_picker.choose(FolderTarget {
                    generation: self.explorer_browser.generation,
                    kind: FolderKind::ExplorerRoot,
                }) {
                    self.report_error(format!("Explorer folder: {error}"));
                }
            }
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
            ui.close();
        }
    }
}

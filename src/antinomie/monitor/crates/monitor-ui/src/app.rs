// SPDX-License-Identifier: MIT
//! The monitor window: application state, its construction and the frame loop.
//!
//! Each child module adds one area of behaviour to [`MonitorApp`] in its own
//! `impl` block. Types shared between areas stay here.
mod analysis_windows;
mod bases;
mod capture;
mod captures;
mod clipboard;
mod debugger;
mod dialogs;
mod disks;
mod dump_pause;
mod evidence_delete;
mod explorer;
mod file_drop;
mod getting_started;
mod history;
mod history_sync;
mod menus;
mod notices;
mod panels;
mod recording;
mod rules;
mod run_kill;
mod run_labels;
mod run_selector;
mod session;
mod sidebar;
mod stealth;
mod trace_paging;
mod trace_view;
mod triage_pcap;
mod triage_ui;
mod upload;
mod upload_browser;
pub(crate) use upload_browser::{DEPTH_LIMIT, DIRECTORY_LIMIT, PAGE_LEN};
mod vm;
mod widgets;

use crate::{
    archive::{Answer, ArchiveWorker, Request},
    build_wizard,
    folders::{FolderPicker, Kind as FolderKind, Target as FolderTarget},
    network_view::{NetworkAction, NetworkContext},
    runs::RunTerminal,
    theme,
    trace::{self, Inspector, InvocationKey},
    values,
    workspace::{Panel, WorkspaceLayout},
};
use antinomie_monitor_core::{
    capture_processes::CaptureProcess, pair_events, syscall_groups::SyscallGroup, Backend,
    BackendOptions, BaseSummary, CaptureState, CaptureSummary, Command, DisplayResolution,
    ExecRequest, GuestCredentials, InvocationSummary, Notification, ProcessCorePhase,
    ProcessCoreRequest, RevisionStatus, RunState, RunSummary, Snapshot, TerminalRecord,
    TransportSettings, VmAcceleration, VmConfig, VmCpuModel, VmLaunchOptions, VmState, WaitStatus,
    APP_REVISION, APP_VERSION,
};
pub(crate) use bases::selected_base;
pub(crate) use capture::core_capture_status;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use {bases::*, dialogs::*, history::*, panels::*, vm::*, widgets::*};

#[derive(Clone, Debug, Default)]
struct PendingSession {
    vm_id: Option<String>,
    boot_id: Option<String>,
    vm_only: bool,
}

struct PendingLaunch {
    id: u64,
    vm_id: Option<String>,
    boot_id: Option<String>,
    request: ExecRequest,
    runs_before: BTreeSet<String>,
    preview_run: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    triage_detection: antinomie_monitor_core::analysis::detection::Settings,
    bundle: String,
    quota_gib: u32,
    /// Default stored-byte budget of a process core, MiB (clamped to what each guest accepts).
    core_budget_mib: u32,
    timeout: u64,
    font_size: f32,
    /// Tint syscall trace rows by syscall group.
    trace_colors: bool,
    /// Maximum calls in a saved syscall page; constrained to the archive API.
    #[serde(deserialize_with = "trace_paging::deserialize_page_size")]
    trace_page_size: usize,
    /// Syscall groups hidden from the trace.
    hidden_trace_categories: Vec<SyscallGroup>,
    /// The chosen theme (Settings > Appearance). `None` on settings saved
    /// before themes were selectable, which only have `light_theme`.
    theme: Option<theme::Theme>,
    /// Light palette instead of the dark one; kept so an older build reads
    /// the choice too.
    light_theme: bool,
    /// Compact spacing and table rows (Comfortable when false).
    compact: bool,
    /// Memory tab: look up symbol tables online for dumps without one.
    memory_online_symbols: bool,
    /// Disks tab: extraction and hash limits, tree toggles.
    disks: crate::disk_view::DiskSettings,
    /// Public destination country and organization. Local addresses are never queried.
    address_lookup: crate::triage::AddressLookup,
    /// Scan retained evidence when it becomes ready. Manual Scan still works.
    automatic_detection: bool,
    /// Allow the explicit catalog check and rule-pack download buttons.
    outbound_catalog: bool,
    /// Debug: draw the repaint rate in a corner of the window.
    show_fps: bool,
    /// Sidebar sections folded away.
    vms_collapsed: bool,
    bases_collapsed: bool,
    /// Sidebar host-file explorer; no guest paths or upload intent are persisted.
    explorer_collapsed: bool,
    explorer_root: Option<PathBuf>,
    /// Help > Getting started: skipped steps and whether it has been shown.
    getting_started: crate::getting_started::Progress,
    /// The latest program each VM ran, for the sidebar.
    last_runs: BTreeMap<String, LastRun>,
}

/// The latest program a VM ran and when it started.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct LastRun {
    run_id: String,
    program: String,
    /// Seconds since the Unix epoch.
    started: u64,
}

impl Settings {
    /// The theme to show: the chosen one, else the legacy light/dark flag.
    fn active_theme(&self) -> theme::Theme {
        self.theme.unwrap_or(if self.light_theme {
            theme::Theme::Light
        } else {
            theme::Theme::Dark
        })
    }

    fn set_theme(&mut self, theme: theme::Theme) {
        self.theme = Some(theme);
        self.light_theme = theme.is_light();
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            triage_detection: Default::default(),
            bundle: String::new(),
            quota_gib: 4,
            core_budget_mib: crate::core_budget::default_mib(),
            timeout: 10,
            font_size: 16.0,
            trace_colors: true,
            trace_page_size: 100,
            hidden_trace_categories: Vec::new(),
            theme: None,
            light_theme: false,
            compact: true,
            memory_online_symbols: true,
            disks: Default::default(),
            address_lookup: crate::triage::AddressLookup::Tshark,
            automatic_detection: true,
            outbound_catalog: false,
            show_fps: false,
            vms_collapsed: false,
            bases_collapsed: false,
            explorer_collapsed: false,
            explorer_root: None,
            getting_started: Default::default(),
            last_runs: BTreeMap::new(),
        }
    }
}

enum Confirm {
    KillRun(run_kill::Target),
    Reset(String),
    Delete(String),
    DeleteBase(String),
    /// A saved network capture or core, by name and size.
    DeleteEvidence(crate::evidence_delete::Deletion),
    Upload(upload::Intent),
    Clipboard {
        intent: clipboard::Intent,
        text: antinomie_monitor_core::clipboard::Text,
    },
    Nat {
        vm: Box<VmConfig>,
        creating: bool,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum RunFilter {
    All,
    Live,
    Past,
}

const TERMINAL_VIEW_LIMIT: usize = 128;
const PENDING_SESSION_LIMIT: usize = 256;
const STALE_COMMAND_LIMIT: usize = 1024;
const CAPTURE_HISTORY_LIMIT: usize = 1024;

#[derive(Default)]
struct AnalysisView {
    state: crate::analysis::WorkspaceState,
    report_id: Option<String>,
    preview: Option<Result<antinomie_monitor_core::AnalysisSpecimenPage, String>>,
    pending: Option<(u64, u64, usize)>,
    listing: Option<Result<antinomie_monitor_core::AnalysisListingPage, String>>,
    /// Generation and request of the listing page being read.
    listing_pending: Option<(u64, antinomie_monitor_core::AnalysisKind, u64, String)>,
    record_context: Option<Vec<(&'static str, crate::query::RowValue)>>,
}

impl AnalysisView {
    fn set_record(
        &mut self,
        report: &antinomie_monitor_core::AnalysisReport,
        labels: (String, String, String, Vec<String>),
        identities: Vec<(&'static str, crate::query::RowValue)>,
    ) {
        let (id, name, path, tags) = labels;
        self.state.set_record(&id, &name, &path, tags);
        self.state.set_identities(identities);
        let context = self.state.record_context(report);
        if self.record_context.as_ref() != Some(&context) {
            self.listing = None;
            self.listing_pending = None;
            self.record_context = Some(context);
        }
    }

    fn bind(&mut self, report_id: Option<&str>) {
        if self.report_id.as_deref() != report_id {
            self.report_id = report_id.map(str::to_owned);
            self.state = crate::analysis::WorkspaceState::default();
            self.preview = None;
            self.pending = None;
            self.listing = None;
            self.listing_pending = None;
            self.record_context = None;
        }
    }
}

#[derive(Default)]
struct CredentialForm {
    username: String,
    password: String,
    confirmation: String,
}

impl CredentialForm {
    fn reset(&mut self) {
        *self = Self {
            username: "analyst".into(),
            ..Self::default()
        };
    }

    fn credentials(&self) -> Result<GuestCredentials, String> {
        if self.password != self.confirmation {
            return Err("password confirmation does not match".into());
        }
        GuestCredentials::new(self.username.clone(), self.password.clone())
    }
}

pub struct MonitorApp {
    performance: crate::ui_performance::Performance,
    last_frame_start: Option<Instant>,
    backend: Option<Backend>,
    snapshot: Snapshot,
    selected: Option<String>,
    /// Base image highlighted in the sidebar; selection only, actions are on right-click.
    selected_base: Option<String>,
    settings: Settings,
    options: BackendOptions,
    settings_open: bool,
    create_open: bool,
    config_open: bool,
    launch_open: bool,
    upload_open: bool,
    draft: VmConfig,
    draft_generation: u64,
    folder_picker: FolderPicker,
    credentials: CredentialForm,
    import_open: bool,
    import_directory: String,
    download_open: bool,
    build_open: bool,
    about_open: bool,
    tools_open: bool,
    rules_open: bool,
    rules_ui: crate::rules_window::Model,
    rules_summary: String,
    rules_generation: u64,
    vm_snapshots: crate::snapshots::SnapshotManager,
    samples: crate::samples_view::SamplesView,
    dependencies: crate::dependencies_window::DependenciesWindow,
    getting_started: crate::getting_started::GettingStarted,
    /// Download base: also list bases for earlier Antinomie versions.
    show_older_bases: bool,
    build_wizard: build_wizard::BuildWizard,
    confirm: Option<Confirm>,
    clipboard_request: Option<clipboard::Intent>,
    pending_kill: Option<u64>,
    name_action: Option<(String, bool, String)>,
    status: String,
    filter: String,
    /// Last syscall filter that compiled. An invalid expression leaves this in place.
    applied_filter: String,
    /// Trace table order: the clicked column and whether it is descending.
    trace_sort: Option<(TraceColumn, bool)>,
    selected_event: Option<InvocationKey>,
    trace_evidence: Option<InvocationKey>,
    selected_run: Option<String>,
    selected_capture: Option<String>,
    /// Guest process (thread group ID) the selected capture's trace shows.
    selected_process: Option<u32>,
    /// The VM dialog's Telemetry transport window is open.
    transport_open: bool,
    /// VM configuration > Stealth profile window.
    stealth_open: bool,
    network_view: crate::network_view::NetworkView,
    memory_view: crate::memory_view::MemoryView,
    disk_view: crate::disk_view::DiskView,
    core_view: crate::core_view::CoreView,
    triage: crate::triage::TriageView,
    cpu_history: crate::summary::CpuHistory,
    /// What the disk said about the capture Triage shows; see `triage_pcap`.
    triage_pcap: std::cell::RefCell<triage_pcap::PcapLookup>,
    /// The state of the selected run's saved captures and core.
    run_labels: run_labels::RunLabels,
    run_tree: Option<(String, crate::archive::ProcessTreeResult)>,
    run_tree_pending: Option<String>,
    archive_total: Option<u64>,
    archive_source_total: Option<u64>,
    evidence_jobs: crate::evidence_jobs::EvidenceJobs,
    /// Whether the Details panel shows the selected packet or syscall.
    pub(crate) details_follow: crate::workspace::DetailsFollow,
    /// Process tree of a selected capture that is not live (processes.json).
    archived_processes: Option<(String, Result<Vec<CaptureProcess>, String>)>,
    capture_history: Vec<CaptureSummary>,
    capture_tab: bool,
    process_picker: captures::ProcessPicker,
    /// The in-app debugger panel's own state (inputs, requests in flight).
    debugger: debugger::DebuggerPanel,
    pending_observer: Option<u64>,
    pending_core: Option<u64>,
    /// A network capture start or stop request in flight.
    pending_network: Option<u64>,
    /// Evidence deletions in flight, by request, until the backend answers.
    pending_deletions: Vec<(u64, crate::evidence_delete::Deletion)>,
    selected_analysis: Option<String>,
    analysis_windows: BTreeMap<String, antinomie_monitor_core::AnalysisReport>,
    analysis_directories: BTreeMap<String, PathBuf>,
    pending_analysis_sections: Vec<(String, antinomie_monitor_core::AnalysisKind)>,
    analysis_views: BTreeMap<String, AnalysisView>,
    analysis_generation: u64,
    archive_selected: bool,
    history_generation: u64,
    run_filter: RunFilter,
    run_query: String,
    /// Last run-history filter that compiled. An invalid expression keeps this.
    applied_run_query: String,
    run_query_error: Option<String>,
    terminals: BTreeMap<String, RunTerminal>,
    archive: Option<ArchiveWorker>,
    pending_archive: Option<Request>,
    history: Vec<RunSummary>,
    /// Keeps `history` complete as the live snapshot changes.
    history_sync: history_sync::HistorySync,
    archive_generation: u64,
    archive_page_generation: u64,
    archive_page: Vec<InvocationSummary>,
    archive_offset: u64,
    archive_next: Option<u64>,
    archive_previous: Vec<u64>,
    archive_pending: bool,
    archive_error: Option<String>,
    archive_read_cancel: Option<Arc<AtomicBool>>,
    archive_hidden_categories: Vec<SyscallGroup>,
    inspector: Inspector,
    data_windows: crate::data_view::DataWindows,
    layout: WorkspaceLayout,
    focus_panel: Option<Panel>,
    activity: crate::activity::Journal,
    activity_notices_due: bool,
    status_notice: Option<(crate::activity::Level, String)>,
    exec: ExecRequest,
    args: String,
    env: String,
    source: String,
    destination: String,
    executable: bool,
    overwrite: bool,
    upload_browser: upload_browser::Browser,
    explorer_browser: upload_browser::Browser,
    pending_upload: Option<upload::Pending>,
    pending_launch: Option<u64>,
    pending_launch_context: Option<PendingLaunch>,
    pending_sessions: BTreeMap<u64, PendingSession>,
    stale_command_ids: VecDeque<u64>,
    backend_disconnected: bool,
    /// The status text when the current backend error arrived. The error shows
    /// on the status line until a newer status message replaces that text.
    error_status_mark: Option<String>,
    /// Run History's listing of the selected VM's runs before the text filter,
    /// with the key of the runs it was built from.
    run_list_cache: Option<(u64, Arc<Vec<RunSummary>>)>,
    /// The run dropdowns' listing, with the key of the runs it was built from.
    run_selector_cache: std::cell::RefCell<Option<(u64, Arc<Vec<RunSummary>>)>>,
    started: Instant,
    smoke: Option<Duration>,
    closing: bool,
    #[cfg(test)]
    submitted: Vec<Command>,
    #[cfg(test)]
    launch_action_rects: Option<(egui::Rect, egui::Rect)>,
}

impl MonitorApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        mut options: BackendOptions,
        smoke: Option<Duration>,
        restore_bundle: bool,
    ) -> Self {
        theme::install(&cc.egui_ctx);
        let mut settings: Settings = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, "settings"))
            .unwrap_or_default();
        if settings.bundle.is_empty() || !restore_bundle {
            settings.bundle = options.bundle_dir.to_string_lossy().into_owned();
        }
        settings.font_size = settings.font_size.clamp(12.0, 24.0);
        theme::apply_theme(&cc.egui_ctx, settings.active_theme());
        theme::set_compact(&cc.egui_ctx, settings.compact);
        theme::text_size(&cc.egui_ctx, settings.font_size);
        options.bundle_dir = crate::folders::user_path(&settings.bundle);
        options.capture_quota_size = u64::from(settings.quota_gib) * 1024 * 1024 * 1024;
        options.shutdown_timeout = Duration::from_secs(settings.timeout);
        let (backend, status) = match Backend::new_with_wake(options.clone(), {
            let ctx = cc.egui_ctx.clone();
            std::sync::Arc::new(move || ctx.request_repaint_of(egui::ViewportId::ROOT))
        }) {
            Ok(backend) => (Some(backend), String::new()),
            Err(error) => (None, error),
        };
        let exec = ExecRequest::default();
        let env = exec.env.join("\n");
        let dependencies =
            crate::dependencies_window::DependenciesWindow::start(&options, &cc.egui_ctx);
        let mut folder_picker = FolderPicker::new();
        folder_picker.refresh(&cc.egui_ctx);
        let mut explorer_browser = upload_browser::Browser::default();
        if let Some(root) = settings.explorer_root.clone() {
            explorer_browser.reset(root);
        }
        let mut app = Self {
            performance: crate::ui_performance::Performance::new(cc.gl.as_deref()),
            last_frame_start: None,
            backend,
            snapshot: Snapshot::default(),
            selected: None,
            selected_base: None,
            settings,
            options,
            settings_open: false,
            create_open: false,
            config_open: false,
            launch_open: false,
            upload_open: false,
            draft: VmConfig::default(),
            draft_generation: 0,
            folder_picker,
            credentials: CredentialForm::default(),
            import_open: false,
            import_directory: String::new(),
            download_open: false,
            build_open: false,
            about_open: false,
            tools_open: false,
            rules_open: false,
            rules_ui: crate::rules_window::Model::default(),
            rules_summary: String::new(),
            rules_generation: 0,
            vm_snapshots: crate::snapshots::SnapshotManager::default(),
            samples: crate::samples_view::SamplesView::default(),
            dependencies,
            getting_started: Default::default(),
            show_older_bases: false,
            build_wizard: build_wizard::BuildWizard::default(),
            confirm: None,
            clipboard_request: None,
            pending_kill: None,
            name_action: None,
            status,
            filter: String::new(),
            applied_filter: String::new(),
            trace_sort: None,
            selected_event: None,
            trace_evidence: None,
            selected_run: None,
            selected_capture: None,
            selected_process: None,
            transport_open: false,
            stealth_open: false,
            network_view: Default::default(),
            memory_view: Default::default(),
            disk_view: Default::default(),
            core_view: Default::default(),
            triage: Default::default(),
            cpu_history: Default::default(),
            triage_pcap: Default::default(),
            run_labels: Default::default(),
            run_tree: None,
            run_tree_pending: None,
            archive_total: None,
            archive_source_total: None,
            evidence_jobs: Default::default(),
            details_follow: Default::default(),
            archived_processes: None,
            capture_history: Vec::new(),
            capture_tab: false,
            process_picker: captures::ProcessPicker::default(),
            debugger: debugger::DebuggerPanel::default(),
            pending_observer: None,
            pending_core: None,
            pending_network: None,
            pending_deletions: Vec::new(),
            selected_analysis: None,
            analysis_windows: BTreeMap::new(),
            analysis_directories: BTreeMap::new(),
            pending_analysis_sections: Vec::new(),
            analysis_views: BTreeMap::new(),
            analysis_generation: 0,
            archive_selected: false,
            history_generation: 0,
            run_filter: RunFilter::All,
            run_query: String::new(),
            applied_run_query: String::new(),
            run_query_error: None,
            terminals: BTreeMap::new(),
            archive: None,
            pending_archive: None,
            history: Vec::new(),
            history_sync: Default::default(),
            archive_generation: 0,
            archive_page_generation: 0,
            archive_page: Vec::new(),
            archive_offset: 0,
            archive_next: None,
            archive_previous: Vec::new(),
            archive_pending: false,
            archive_error: None,
            archive_read_cancel: None,
            archive_hidden_categories: Vec::new(),
            inspector: Inspector::default(),
            data_windows: crate::data_view::DataWindows::default(),
            layout: WorkspaceLayout::restore(
                cc.storage
                    .and_then(|storage| eframe::get_value(storage, "workspace_layout")),
            ),
            focus_panel: None,
            activity: crate::activity::Journal::restore(cc.storage),
            activity_notices_due: true,
            status_notice: None,
            exec,
            args: String::new(),
            env,
            source: String::new(),
            destination: "/tmp/program".into(),
            // The Upload dialog starts with both options on.
            executable: true,
            overwrite: true,
            upload_browser: Default::default(),
            explorer_browser,
            pending_upload: None,
            pending_launch: None,
            pending_launch_context: None,
            pending_sessions: BTreeMap::new(),
            stale_command_ids: VecDeque::new(),
            backend_disconnected: false,
            error_status_mark: None,
            run_list_cache: None,
            run_selector_cache: Default::default(),
            started: Instant::now(),
            smoke,
            closing: false,
            #[cfg(test)]
            submitted: Vec::new(),
            #[cfg(test)]
            launch_action_rects: None,
        };
        app.configure_detection();
        match ArchiveWorker::new(Some(cc.egui_ctx.clone())) {
            Ok(worker) => {
                app.archive = Some(worker);
                app.refresh_history();
            }
            Err(error) => app.status = format!("Archive worker: {error}"),
        }
        app.layout.validate();
        if !app.status.is_empty() {
            app.log("ERROR", app.status.clone());
        }
        app
    }
}

impl eframe::App for MonitorApp {
    /// Seams between panels show the theme, not eframe's near-black default.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::panel().to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut frame_started = Instant::now();
        let pause = crate::ui_performance::throttle_sleep(
            self.last_frame_start,
            frame_started,
            crate::ui_performance::MIN_FRAME_INTERVAL,
            crate::ui_performance::VSYNC,
        );
        if !pause.is_zero() {
            std::thread::sleep(pause);
            frame_started = Instant::now();
        }
        self.last_frame_start = Some(frame_started);
        self.dependencies.poll();
        self.drain();
        self.getting_started_tick();
        self.poll_rules(ctx);
        self.receive_clipboard(ctx);
        self.cpu_history
            .observe(&self.snapshot, self.selected.as_deref());
        self.flush_archive();
        self.drain_archive();
        self.resync_terminals();
        // Triage belongs to one explicit program run, including its saved prefix.
        // The run is borrowed field by field, not cloned with its analysis
        // report every frame.
        let triage_run_id = self
            .selected_run
            .as_deref()
            .and_then(|id| self.run(id))
            .filter(|run| {
                self.selected.as_ref() == Some(&run.vm_id)
                    && run.root_task_cookie != 0
                    && self.selected_capture.is_none()
            })
            .map(|run| run.id.clone());
        let (triage_pcap, run_finished) = match triage_run_id.as_deref().and_then(|id| self.run(id))
        {
            Some(run) => (self.owned_triage_pcap(), !self.live_history_run(run)),
            None => (None, true),
        };
        let triage_run = triage_run_id.as_deref().and_then(|id| {
            self.snapshot
                .runs
                .iter()
                .find(|run| run.id == id)
                .or_else(|| self.history.iter().find(|run| run.id == id))
        });
        let input = triage_run
            .map(|run| crate::triage::TriageInput {
                analysis: run.analysis.as_ref(),
                invocations: &[],
                vm_id: Some(&run.vm_id),
                boot_id: Some(&run.boot_id),
                run_id: Some(&run.id),
                archive: Some(&run.directory),
                pcap: triage_pcap.as_ref().map(|owned| owned.0.as_path()),
                pcap_open: triage_pcap.as_ref().is_some_and(|owned| owned.1),
                clock_anchor: run.clock_anchor,
                started_ms: run.started_ms,
                root_cookie: run.root_task_cookie,
                run_finished,
                current_boot: self.snapshot.active_vm.as_deref() == Some(run.vm_id.as_str())
                    && self.snapshot.boot_id.as_deref() == Some(run.boot_id.as_str()),
            })
            .unwrap_or_else(crate::triage::TriageInput::empty);
        self.triage.tick(ctx, input);
        self.triage.show_finding_windows(ctx);
        let close = ctx.input(|input| input.viewport().close_requested())
            || self
                .smoke
                .is_some_and(|timeout| self.started.elapsed() >= timeout);
        if close && !self.closing {
            self.closing = true;
            self.send(Command::Close);
        }
        if self.closing {
            if self.snapshot.active_vm.is_some() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        self.draw(ctx);
        ctx.request_repaint_after(crate::ui_performance::repaint_delay(
            self.snapshot.active_vm.is_some() || self.closing || self.folder_picker.pending(),
        ));
        if let Some(smoke) = self.smoke {
            ctx.request_repaint_after(smoke.saturating_sub(self.started.elapsed()));
        }
        self.performance.record(frame_started.elapsed());
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        self.settings.triage_detection = self.triage.detection_settings().clone();
        self.settings.triage_detection.rules_root.clear();
        eframe::set_value(storage, "settings", &self.settings);
        eframe::set_value(storage, "workspace_layout", &self.layout);
        self.activity.save(storage);
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(backend) = &mut self.backend {
            if let Err(error) = backend.shutdown() {
                eprintln!("shutdown failed: {error}");
            }
        }
    }
}

/// What a click in the empty trace panel asks for.
enum EmptyTraceAction {
    Start,
    Run(String),
    Capture(String),
}

/// A sortable column of the syscall trace table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceColumn {
    Time,
    Sequence,
    Tid,
    Cpu,
    Syscall,
    Return,
    Info,
}

impl TraceColumn {
    const ALL: [Self; 7] = [
        Self::Time,
        Self::Sequence,
        Self::Tid,
        Self::Cpu,
        Self::Syscall,
        Self::Return,
        Self::Info,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Time => "Time (s)",
            Self::Sequence => "Record",
            Self::Tid => "TID",
            Self::Cpu => "CPU",
            Self::Syscall => "Syscall",
            Self::Return => "Return",
            Self::Info => "Info",
        }
    }

    /// What the column shows, for its header tooltip.
    fn description(self) -> &'static str {
        match self {
            Self::Time => "Guest time in seconds since boot, to the microsecond",
            Self::Sequence => {
                "Trace record numbers of the call's Entry \u{2192} Exit events: \
                 the order the guest emitted them"
            }
            Self::Tid => "Thread that made the call (hover a cell for its process)",
            Self::Cpu => "CPU the call entered on (\u{2192} the one it returned on)",
            Self::Syscall => "Syscall name and number",
            Self::Return => {
                "Return value: counts and descriptors in decimal, addresses in hex, \
                 errors by name"
            }
            Self::Info => "Arguments by meaning; captured data replaces its pointer",
        }
    }
}

/// Dialogs and tool windows that Escape closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dialog {
    Confirm,
    Name,
    Transport,
    Stealth,
    Vm,
    Launch,
    Upload,
    Settings,
    Import,
    Download,
    Tools,
    Rules,
    Samples,
    Snapshots,
    SnapshotDecision,
    Dependencies,
    GettingStarted,
    Performance,
    About,
    Build,
    Attach,
}

impl Dialog {
    const ALL: [Dialog; 21] = [
        Dialog::Confirm,
        Dialog::Name,
        Dialog::Transport,
        Dialog::Stealth,
        Dialog::Vm,
        Dialog::Launch,
        Dialog::Upload,
        Dialog::Settings,
        Dialog::Import,
        Dialog::Download,
        Dialog::Tools,
        Dialog::Rules,
        Dialog::Samples,
        Dialog::Snapshots,
        Dialog::SnapshotDecision,
        Dialog::Dependencies,
        Dialog::GettingStarted,
        Dialog::Performance,
        Dialog::About,
        Dialog::Build,
        Dialog::Attach,
    ];

    /// The window's egui ID (its layer ID).
    fn window_id(self) -> egui::Id {
        egui::Id::new(match self {
            Dialog::Confirm => "confirm_action",
            Dialog::Name => "name_action",
            Dialog::Transport => "vm_transport",
            Dialog::Stealth => "vm_stealth",
            Dialog::Vm => "vm_configuration",
            Dialog::Launch => "run_program",
            Dialog::Upload => "upload_file",
            Dialog::Settings => "settings",
            Dialog::Import => "import_base",
            Dialog::Download => "download_base",
            Dialog::Tools => crate::tools_window::WINDOW_ID,
            Dialog::Rules => crate::rules_window::WINDOW_ID,
            Dialog::Samples => crate::samples_view::WINDOW_ID,
            Dialog::Snapshots => crate::snapshots::WINDOW_ID,
            Dialog::SnapshotDecision => "snapshot_decision",
            Dialog::Dependencies => crate::dependencies_window::WINDOW_ID,
            Dialog::GettingStarted => crate::getting_started::WINDOW_ID,
            Dialog::Performance => "ui-performance",
            Dialog::About => "about",
            Dialog::Build => "build_base",
            Dialog::Attach => "attach_process",
        })
    }
}

/// Keyboard shortcuts of menu actions.
mod keys {
    use eframe::egui::{Key, KeyboardShortcut, Modifiers};
    pub const NEW_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::N);
    pub const START_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::NONE, Key::F5);
    pub const STOP_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::SHIFT, Key::F5);
    pub const RUN_PROGRAM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::R);
    pub const UPLOAD: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::U);
    pub const TYPE_CLIPBOARD: KeyboardShortcut =
        KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::Y);
    pub const SETTINGS: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Comma);
    pub const QUIT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Q);
}

/// Right-click actions of a sidebar VM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmAction {
    Start,
    Stop,
    Configure,
    Snapshots,
    Rename,
    Duplicate,
    OpenDirectory,
    Reset,
    Delete,
}

/// Right-click actions of a sidebar base image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BaseAction {
    NewVm,
    OpenDirectory,
    Delete,
}

/// A sidebar entry: a colored mark, the name, an optional state on the
/// right, then detail lines in small text. The whole row is one target.
struct SidebarRow<'a> {
    mark: (&'a str, egui::Color32),
    name: &'a str,
    state: Option<(&'a str, egui::Color32)>,
    details: Vec<Vec<(String, egui::Color32)>>,
    selected: bool,
}

struct SectionHeader<'a> {
    title: &'a str,
    count: usize,
    tooltip: &'a str,
    action: &'a str,
    enabled: bool,
    open: bool,
}

/// A toolbar button: the icon in its `tone` and a label. `active` (a
/// capture running, a dialog open) fills it with a tint of the tone.
struct ToolButton<'a> {
    icon: &'a str,
    label: &'a str,
    tooltip: &'a str,
    enabled: bool,
    tone: egui::Color32,
    active: bool,
    /// The label takes the tone too (Start, Stop).
    strong: bool,
}

#[cfg(test)]
pub(crate) mod tests;

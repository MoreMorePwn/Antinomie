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
#[path = "captures.rs"]
mod captures;
#[path = "upload_dialog.rs"]
mod upload;
#[path = "upload_browser.rs"]
mod upload_browser;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    bundle: String,
    quota_gib: u32,
    timeout: u64,
    font_size: f32,
    /// Tint syscall trace rows by syscall group.
    trace_colors: bool,
    /// Syscall groups hidden from the trace.
    hidden_trace_categories: Vec<SyscallGroup>,
    /// Light palette instead of the dark one.
    light_theme: bool,
    /// Compact spacing and table rows (Comfortable when false).
    compact: bool,
    /// Memory tab: look up symbol tables online for dumps without one.
    memory_online_symbols: bool,
    /// Sidebar sections folded away.
    vms_collapsed: bool,
    bases_collapsed: bool,
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

impl Default for Settings {
    fn default() -> Self {
        Self {
            bundle: String::new(),
            quota_gib: 4,
            timeout: 10,
            font_size: 16.0,
            trace_colors: true,
            hidden_trace_categories: Vec::new(),
            light_theme: false,
            compact: true,
            memory_online_symbols: true,
            vms_collapsed: false,
            bases_collapsed: false,
            last_runs: BTreeMap::new(),
        }
    }
}

enum Confirm {
    Reset(String),
    Delete(String),
    DeleteBase(String),
    Upload(upload::Intent),
    Nat { vm: VmConfig, creating: bool },
}

#[derive(Clone, Copy, PartialEq)]
enum RunFilter {
    All,
    Live,
    Past,
}

struct Activity {
    time: String,
    level: &'static str,
    message: String,
}

const ACTIVITY_LIMIT: usize = 256;
const TERMINAL_VIEW_LIMIT: usize = 128;
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
    vm_snapshots: crate::snapshots::SnapshotManager,
    samples: crate::samples_view::SamplesView,
    dependencies: crate::dependencies_window::DependenciesWindow,
    /// Download base: also list bases for earlier Antinomie versions.
    show_older_bases: bool,
    build_wizard: build_wizard::BuildWizard,
    confirm: Option<Confirm>,
    name_action: Option<(String, bool, String)>,
    status: String,
    filter: String,
    /// Last syscall filter that compiled. An invalid expression leaves this in place.
    applied_filter: String,
    /// Trace table order: the clicked column and whether it is descending.
    trace_sort: Option<(TraceColumn, bool)>,
    selected_event: Option<InvocationKey>,
    selected_run: Option<String>,
    selected_capture: Option<String>,
    /// Guest process (thread group ID) the selected capture's trace shows.
    selected_process: Option<u32>,
    /// The VM dialog's Telemetry transport window is open.
    transport_open: bool,
    network_view: crate::network_view::NetworkView,
    memory_view: crate::memory_view::MemoryView,
    core_view: crate::core_view::CoreView,
    triage: crate::triage::TriageView,
    cpu_history: crate::summary::CpuHistory,
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
    pending_observer: Option<u64>,
    pending_core: Option<u64>,
    /// A network capture start or stop request in flight.
    pending_network: Option<u64>,
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
    activity: VecDeque<Activity>,
    exec: ExecRequest,
    args: String,
    env: String,
    source: String,
    destination: String,
    executable: bool,
    overwrite: bool,
    upload_browser: upload_browser::Browser,
    pending_upload: Option<upload::Pending>,
    pending_launch: Option<u64>,
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
        theme::apply(&cc.egui_ctx, settings.light_theme);
        theme::set_compact(&cc.egui_ctx, settings.compact);
        theme::text_size(&cc.egui_ctx, settings.font_size);
        options.bundle_dir = crate::folders::user_path(&settings.bundle);
        options.capture_quota_size = u64::from(settings.quota_gib) * 1024 * 1024 * 1024;
        options.shutdown_timeout = Duration::from_secs(settings.timeout);
        let (backend, status) = match Backend::new(options.clone()) {
            Ok(backend) => (Some(backend), String::new()),
            Err(error) => (None, error),
        };
        let exec = ExecRequest::default();
        let env = exec.env.join("\n");
        let dependencies = crate::dependencies_window::DependenciesWindow::start(&options);
        let mut app = Self {
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
            folder_picker: FolderPicker::new(),
            credentials: CredentialForm::default(),
            import_open: false,
            import_directory: String::new(),
            download_open: false,
            build_open: false,
            about_open: false,
            tools_open: false,
            vm_snapshots: crate::snapshots::SnapshotManager::default(),
            samples: crate::samples_view::SamplesView::default(),
            dependencies,
            show_older_bases: false,
            build_wizard: build_wizard::BuildWizard::default(),
            confirm: None,
            name_action: None,
            status,
            filter: String::new(),
            applied_filter: String::new(),
            trace_sort: None,
            selected_event: None,
            selected_run: None,
            selected_capture: None,
            selected_process: None,
            transport_open: false,
            network_view: Default::default(),
            memory_view: Default::default(),
            core_view: Default::default(),
            triage: Default::default(),
            cpu_history: Default::default(),
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
            pending_observer: None,
            pending_core: None,
            pending_network: None,
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
            activity: VecDeque::new(),
            exec,
            args: String::new(),
            env,
            source: String::new(),
            destination: "/tmp/program".into(),
            executable: false,
            overwrite: false,
            upload_browser: Default::default(),
            pending_upload: None,
            pending_launch: None,
            started: Instant::now(),
            smoke,
            closing: false,
            #[cfg(test)]
            submitted: Vec::new(),
            #[cfg(test)]
            launch_action_rects: None,
        };
        match ArchiveWorker::new() {
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

    fn send(&mut self, command: Command) {
        self.send_request(command);
    }

    /// Return the accepted request identity for workflows waiting on completion.
    fn send_request(&mut self, command: Command) -> Option<u64> {
        let vm_snapshot = matches!(
            &command,
            Command::RefreshVmSnapshots { .. }
                | Command::CreateVmSnapshot { .. }
                | Command::RestoreVmSnapshot { .. }
                | Command::RenameVmSnapshot { .. }
                | Command::DeleteVmSnapshot { .. }
                | Command::ReconnectTransport
        );
        if let Err(error) = self
            .dependencies
            .require(&command, &self.options, &self.snapshot)
        {
            self.dependencies.open = true;
            if vm_snapshot {
                self.vm_snapshots.result = Some((false, error.clone()));
            }
            self.status = error.clone();
            self.log("ERROR", error);
            return None;
        }
        let launch = matches!(&command, Command::Execute(_));
        let observer = matches!(
            &command,
            Command::AttachProcess { .. } | Command::CaptureAll | Command::StopCapture { .. }
        );
        let process_list = matches!(&command, Command::ListProcesses { .. });
        let core_capture = matches!(&command, Command::DumpProcessCore { .. });
        let sample = matches!(&command, Command::UploadSample { .. });
        let network = matches!(
            &command,
            Command::StartNetworkCapture | Command::StopNetworkCapture
        );
        let admission = if launch {
            self.launch_admission()
        } else {
            Ok(())
        };
        if let Err(error) = admission {
            self.status = error.clone();
            self.log("ERROR", error);
            return None;
        }
        #[cfg(test)]
        if self.submitted.len() < 1024 {
            self.submitted.push(command.clone());
        }
        let mut failure = None;
        let mut accepted = None;
        if let Some(backend) = &self.backend {
            match backend.send(command) {
                Ok(id) => {
                    accepted = Some(id);
                    if vm_snapshot {
                        self.vm_snapshots.pending = Some(id);
                        self.vm_snapshots.result = None;
                    }
                    if observer {
                        self.pending_observer = Some(id);
                    }
                    if core_capture {
                        self.pending_core = Some(id);
                    }
                    if process_list {
                        self.process_picker.pending = Some(id);
                    }
                    if network {
                        self.pending_network = Some(id);
                    }
                    if launch {
                        self.pending_launch = Some(id);
                    }
                    if sample {
                        self.samples.sent(id);
                    }
                    self.status = "Request queued".into();
                }
                Err(error) => {
                    self.status = error.clone();
                    failure = Some(error);
                }
            }
        }
        if let Some(error) = failure {
            if vm_snapshot {
                self.vm_snapshots.result = Some((false, error.clone()));
            }
            self.log("ERROR", error);
        }
        #[cfg(test)]
        if self.backend.is_none() {
            accepted = Some(self.submitted.len() as u64);
        }
        accepted
    }

    fn drain(&mut self) {
        if let Some((target, result)) = self.folder_picker.poll() {
            match result {
                Ok(Some(path)) => match target.kind {
                    FolderKind::BaseImport => {
                        self.import_directory = path.to_string_lossy().into_owned()
                    }
                    FolderKind::Disk if target.generation == self.draft_generation => {
                        self.draft.disk_root = Some(path)
                    }
                    FolderKind::Recording if target.generation == self.draft_generation => {
                        self.draft.recording_root = Some(path)
                    }
                    FolderKind::UploadRoot
                        if self.upload_open
                            && target.generation == self.upload_browser.generation =>
                    {
                        self.upload_browser.reset(path);
                        self.source.clear();
                    }
                    _ => {}
                },
                Err(error) => {
                    self.status = format!("Host folder: {error}");
                    self.log("ERROR", self.status.clone());
                }
                _ => {}
            }
        }
        let mut activity = Vec::new();
        // A sample sent into the guest that is to run next.
        let mut launch_sample = None;
        let mut upload_result = None;
        let mut analysis_changed = false;
        let was_offline = self.trace_archive_directory().is_some();
        if let Some(backend) = &self.backend {
            for _ in 0..256 {
                match backend.try_recv() {
                    Some(Notification::Snapshot(snapshot)) => {
                        if snapshot.state != self.snapshot.state {
                            activity.push(("INFO", format!("Session {:?}", snapshot.state)));
                        }
                        if snapshot.last_error != self.snapshot.last_error {
                            if let Some(error) = &snapshot.last_error {
                                activity.push(("ERROR", error.clone()));
                            }
                        }
                        if snapshot.health.persistence_error
                            != self.snapshot.health.persistence_error
                        {
                            if let Some(error) = &snapshot.health.persistence_error {
                                activity.push(("ERROR", format!("Saving stopped: {error}")));
                            }
                        }
                        if snapshot.health.ui_dropped > self.snapshot.health.ui_dropped {
                            for terminal in self.terminals.values_mut() {
                                terminal.dirty = true;
                            }
                        }
                        let new_run = snapshot.runs.iter().any(|run| {
                            run_in_live_session(&snapshot, run)
                                && !self.terminals.contains_key(&run.id)
                        });
                        sync_runs(&mut self.terminals, &snapshot);
                        if new_run {
                            self.pending_launch = None;
                        }
                        if let Some(capture) = self
                            .selected_capture_summary()
                            .filter(|capture| {
                                !snapshot
                                    .captures
                                    .iter()
                                    .any(|current| current.id == capture.id)
                            })
                            .cloned()
                        {
                            if !self
                                .capture_history
                                .iter()
                                .any(|saved| saved.id == capture.id)
                            {
                                if self.capture_history.len() >= CAPTURE_HISTORY_LIMIT {
                                    self.capture_history.remove(0);
                                }
                                self.capture_history.push(capture);
                            }
                        }
                        self.snapshot = snapshot;
                        analysis_changed = true;
                    }
                    Some(Notification::CommandResult {
                        id,
                        success,
                        message,
                    }) => {
                        self.vm_snapshots.complete(id, success, &message);
                        if let Some(run) = self.samples.complete(id, success, &message) {
                            launch_sample = Some(run);
                        }
                        if self
                            .pending_upload
                            .as_ref()
                            .is_some_and(|upload| upload.id == id)
                        {
                            upload_result = Some((id, success));
                        }
                        if self.pending_observer == Some(id) {
                            self.pending_observer = None;
                        }
                        if self.pending_core == Some(id) {
                            self.pending_core = None;
                        }
                        if self.pending_network == Some(id) {
                            self.pending_network = None;
                        }
                        if self.process_picker.pending == Some(id) {
                            self.process_picker.pending = None;
                        }
                        for terminal in self.terminals.values_mut() {
                            if terminal.snapshot_request == Some(id) {
                                terminal.snapshot_request = None;
                                terminal.snapshot_started = None;
                                if !success {
                                    terminal.snapshot_error = Some(message.clone());
                                }
                            }
                        }
                        resolve_launch_result(&mut self.pending_launch, id, success);
                        self.status = if success {
                            message
                        } else {
                            format!("Failed: {message}")
                        };
                        if !success || !self.status.starts_with("terminal input accepted") {
                            activity.push((
                                if success { "INFO" } else { "ERROR" },
                                self.status.clone(),
                            ));
                        }
                    }
                    Some(Notification::RunStarted(run)) => {
                        self.pending_launch = None;
                        activity.push((
                            "INFO",
                            format!("Started {} (PID {})", run.request.path, run.pid),
                        ));
                        if let Some(current) = self
                            .snapshot
                            .runs
                            .iter_mut()
                            .find(|current| current.id == run.id)
                        {
                            *current = run;
                        } else {
                            self.snapshot.runs.push(run);
                        }
                        sync_runs(&mut self.terminals, &self.snapshot);
                    }
                    Some(Notification::AnalysisUpdated { run_id, report }) => {
                        if let Some(current) = self.analysis_windows.get_mut(&report.id) {
                            current.clone_from(&report);
                        }
                        if let Some(id) = run_id {
                            for run in self.snapshot.runs.iter_mut().chain(self.history.iter_mut())
                            {
                                if run.id == id {
                                    run.analysis = Some(report.clone());
                                }
                            }
                        } else if let Some(current) = self
                            .snapshot
                            .analysis_reports
                            .iter_mut()
                            .find(|current| current.id == report.id)
                        {
                            *current = report;
                        } else {
                            if self.snapshot.analysis_reports.len() >= 8 {
                                self.snapshot.analysis_reports.remove(0);
                            }
                            self.selected_analysis = Some(report.id.clone());
                            self.snapshot.analysis_reports.push(report);
                        }
                    }
                    Some(Notification::Terminal {
                        run_id,
                        sequence,
                        data,
                        eof,
                    }) => {
                        if let Some(terminal) = self.terminals.get_mut(&run_id) {
                            terminal.output(sequence, &data, eof);
                        }
                    }
                    Some(Notification::TerminalScreen {
                        run_id,
                        sequence,
                        rows,
                        cols,
                        data,
                    }) => {
                        if let Some(terminal) = self.terminals.get_mut(&run_id) {
                            terminal.screen(sequence, rows, cols, &data);
                        }
                    }
                    None => break,
                }
            }
        }
        if analysis_changed {
            self.refresh_analysis_windows();
        }
        if self
            .selected
            .as_ref()
            .is_some_and(|id| !self.snapshot.vms.iter().any(|vm| &vm.id == id))
        {
            self.selected = None;
        }
        if self.selected.is_none() {
            self.selected = self.snapshot.vms.first().map(|vm| vm.id.clone());
            self.refresh_history();
        }
        for (level, message) in activity {
            self.log(level, message);
        }
        if let Some(run) = launch_sample {
            self.launch_sample(run);
        }
        if let Some((id, success)) = upload_result {
            self.complete_upload(id, success);
        }
        if self
            .pending_upload
            .as_ref()
            .is_some_and(|upload| !upload.intent.same_session(&self.snapshot))
        {
            self.pending_upload = None;
        }
        if !was_offline && self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
    }

    fn running(&self) -> bool {
        self.snapshot.state == VmState::Running && self.snapshot.active_vm == self.selected
    }

    /// The selected VM's base has a graphical desktop a program can join.
    fn selected_vm_graphical(&self) -> bool {
        self.snapshot
            .vms
            .iter()
            .find(|vm| self.selected.as_ref() == Some(&vm.id))
            .and_then(|vm| selected_base(&self.snapshot, vm.base_identity.as_deref()))
            .and_then(|base| base.guest.as_ref())
            .is_some_and(|guest| guest.graphical)
    }

    fn launch_admission(&self) -> Result<(), String> {
        if self.pending_launch.is_some() {
            return Err("A program launch is still pending".into());
        }
        if available_terminal_slots(&self.terminals, &self.snapshot) == 0 {
            return Err(terminal_capacity_message());
        }
        Ok(())
    }

    fn new_image(&mut self) {
        self.draft_generation = self.draft_generation.wrapping_add(1);
        self.draft = VmConfig::default();
        self.draft.name = "New VM".into();
        self.draft.base_identity =
            preferred_new_base(&self.snapshot, &self.settings.bundle).map(|base| base.id.clone());
        self.credentials.reset();
        self.create_open = true;
    }

    /// Start a new VM pinned to a specific installed base.
    fn new_image_from(&mut self, base_identity: String) {
        self.new_image();
        self.draft.base_identity = Some(base_identity);
    }

    fn create_vm(&mut self) -> Result<(), String> {
        let requires_credentials = self
            .snapshot
            .bases
            .iter()
            .find(|base| Some(&base.id) == self.draft.base_identity.as_ref())
            .and_then(|base| base.guest.as_ref())
            .is_some_and(|guest| guest.requires_credentials);
        if let Some(error) = self.create_validation_error(requires_credentials) {
            return Err(error);
        }
        let command = if requires_credentials {
            Command::CreateWithCredentials {
                vm: self.draft.clone(),
                credentials: self.credentials.credentials()?,
            }
        } else {
            Command::Create(self.draft.clone())
        };
        self.update_options();
        self.send(command);
        self.credentials.reset();
        Ok(())
    }

    fn create_validation_error(&self, requires_credentials: bool) -> Option<String> {
        if self.snapshot.active_vm.is_some() {
            return Some("Stop the running VM before creating another VM".into());
        }
        if self.draft.name.trim().is_empty() {
            return Some("Enter a VM name".into());
        }
        if let Err(error) = self.draft.launch.validate_for(&self.options) {
            return Some(error);
        }
        if let Some(error) = self.fixed_display_error(&self.draft) {
            return Some(error);
        }
        if requires_credentials {
            if let Err(error) = self.dependencies.require_dependencies(&[
                antinomie_monitor_core::dependencies::Dependency::QemuImg,
                antinomie_monitor_core::dependencies::Dependency::DebianAccount,
            ]) {
                return Some(error);
            }
            return self.credentials.credentials().err();
        }
        self.dependencies
            .require_dependencies(&[antinomie_monitor_core::dependencies::Dependency::QemuImg])
            .err()
    }

    fn save_validation_error(&self, vm: &VmConfig) -> Option<String> {
        if self.snapshot.active_vm.as_ref() == Some(&vm.id) {
            return Some("Stop this VM before saving its configuration".into());
        }
        if !self.snapshot.vms.iter().any(|saved| saved.id == vm.id) {
            return Some("This VM is no longer available".into());
        }
        if vm.name.trim().is_empty() {
            return Some("Enter a VM name".into());
        }
        vm.launch
            .validate_for(&self.options)
            .err()
            .or_else(|| self.fixed_display_error(vm))
    }

    fn fixed_display_error(&self, vm: &VmConfig) -> Option<String> {
        if vm.launch.resolution.dimensions().is_some()
            && !selected_base(&self.snapshot, vm.base_identity.as_deref())
                .is_some_and(|base| base.fixed_display)
        {
            return Some("This base does not support fixed resolutions. Select a refreshed base or choose Auto.".into());
        }
        None
    }

    fn save_vm(&mut self, vm: VmConfig) -> Result<(), String> {
        if let Some(error) = self.save_validation_error(&vm) {
            return Err(error);
        }
        self.send(Command::Save(vm));
        Ok(())
    }

    fn new_run(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.send(Command::Start { vm_id });
        }
    }

    fn configure_vm(&mut self) {
        self.credentials.reset();
        self.draft_generation = self.draft_generation.wrapping_add(1);
        if let Some(vm) = self
            .snapshot
            .vms
            .iter()
            .find(|vm| Some(&vm.id) == self.selected.as_ref())
        {
            self.draft = vm.clone();
            self.config_open = true;
        }
    }

    fn run(&self, id: &str) -> Option<&RunSummary> {
        self.snapshot
            .runs
            .iter()
            .find(|run| run.id == id)
            .or_else(|| self.history.iter().find(|run| run.id == id))
    }

    fn offline_run(&self) -> Option<&RunSummary> {
        let id = self.selected_run.as_ref()?;
        let run = self.run(id)?;
        (self.archive_selected || !run_in_live_session(&self.snapshot, run)).then_some(run)
    }

    fn capture(&self, id: &str) -> Option<&CaptureSummary> {
        self.snapshot
            .captures
            .iter()
            .chain(&self.capture_history)
            .find(|capture| capture.id == id)
    }

    fn selected_capture_summary(&self) -> Option<&CaptureSummary> {
        self.selected_capture
            .as_deref()
            .and_then(|id| self.capture(id))
    }

    fn trace_archive_directory(&self) -> Option<PathBuf> {
        if let Some(capture) = self.selected_capture_summary() {
            if self.archive_selected || !self.snapshot.capture_events.contains_key(&capture.id) {
                return Some(capture.directory.clone());
            }
            return None;
        }
        self.offline_run().map(|run| run.directory.clone())
    }

    fn observer_supported(&self) -> bool {
        self.running()
            && !self.closing
            && self
                .snapshot
                .guest_kernel
                .as_ref()
                .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 11))
    }

    fn active_observer(&self) -> Option<&CaptureSummary> {
        self.snapshot.captures.iter().find(|capture| {
            Some(&capture.vm_id) == self.snapshot.active_vm.as_ref()
                && matches!(capture.state, CaptureState::Active | CaptureState::Unknown)
        })
    }

    fn observer_start_enabled(&self) -> bool {
        self.observer_supported()
            && self.pending_observer.is_none()
            && self.active_observer().is_none()
    }

    fn open_process_picker(&mut self) {
        self.process_picker.purpose = captures::ProcessPurpose::Attach;
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
    }

    fn manual_core_unavailable(&self) -> Option<&'static str> {
        if !self.running()
            || self.closing
            || self.selected.is_none()
            || self.selected != self.snapshot.active_vm
        {
            Some("Start the selected VM to dump a process core.")
        } else if self.snapshot.memory_dump.is_some() {
            Some("Wait for the VM RAM dump to finish; the guest is paused.")
        } else if !self
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 16))
        {
            Some("Live core capture needs a guest base with revision 16 or newer.")
        } else if self.pending_core.is_some()
            || self.snapshot.process_cores.iter().any(|capture| {
                Some(&capture.vm_id) == self.snapshot.active_vm.as_ref()
                    && matches!(
                        capture.phase,
                        ProcessCorePhase::Admission
                            | ProcessCorePhase::UnknownAdmission
                            | ProcessCorePhase::GuestCapture
                    )
            })
        {
            Some("Wait for the current process capture to release its pause.")
        } else {
            None
        }
    }

    fn open_core_picker(&mut self) {
        if self.manual_core_unavailable().is_some() {
            return;
        }
        self.process_picker.purpose = captures::ProcessPurpose::Core;
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
        self.focus_panel = Some(Panel::CoreDump);
    }

    fn stop_observer(&mut self) {
        if self.observer_supported() && self.pending_observer.is_none() {
            if let Some(capture) = self.active_observer() {
                self.send(Command::StopCapture {
                    capture_id: capture.id.clone(),
                });
            }
        }
    }

    /// The running VM has NAT networking.
    fn running_nat(&self) -> bool {
        self.snapshot.vms.iter().any(|vm| {
            Some(&vm.id) == self.snapshot.active_vm.as_ref() && (vm.nat || vm.isolated_network)
        })
    }

    /// A network capture can be started or stopped now.
    fn network_toggle_enabled(&self) -> bool {
        self.running()
            && !self.closing
            && self.pending_network.is_none()
            && (self.snapshot.network_capture.is_some() || self.running_nat())
    }

    fn toggle_network_capture(&mut self) {
        if self.network_toggle_enabled() {
            self.send(if self.snapshot.network_capture.is_some() {
                Command::StopNetworkCapture
            } else {
                Command::StartNetworkCapture
            });
        }
    }

    fn network_toggle_label(&self) -> &'static str {
        if self.snapshot.network_capture.is_some() {
            "Stop network capture"
        } else if self.running() && !self.running_nat() {
            "Capture network (choose Isolated or NAT network in VM settings)"
        } else {
            "Capture network"
        }
    }

    fn refresh_captures(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.history_generation = self.history_generation.wrapping_add(1);
            self.queue_archive(Request::ListCaptures {
                options: self.options.clone(),
                vm_id,
                generation: self.history_generation,
            });
        }
    }

    fn refresh_history(&mut self) {
        if self.capture_tab {
            self.refresh_captures();
            return;
        }
        if let Some(vm_id) = self.selected.clone() {
            self.history_generation = self.history_generation.wrapping_add(1);
            self.queue_archive(Request::ListVm {
                options: self.options.clone(),
                vm_id,
                generation: self.history_generation,
            });
        }
    }

    fn queue_archive(&mut self, request: Request) {
        if let Some(old) = self.pending_archive.replace(request) {
            match old {
                Request::ProcessTree { run_id, .. }
                    if self.run_tree_pending.as_ref() == Some(&run_id) =>
                {
                    self.run_tree_pending = None;
                }
                Request::Invocations {
                    generation, cancel, ..
                } => {
                    cancel.store(true, Ordering::Relaxed);
                    if generation == self.archive_generation {
                        self.archive_pending = false;
                        self.archive_error = Some("Read superseded".into());
                    }
                }
                Request::Captured { generation, .. } if generation == self.inspector.generation => {
                    self.inspector.pending = false;
                    self.inspector.error = Some("Read superseded".into());
                }
                Request::Specimen {
                    view_key,
                    generation,
                    ..
                } => self.fail_analysis_read(&view_key, generation, "Read superseded"),
                // A superseded listing read is simply asked for again.
                Request::Listing { view_key, .. } => {
                    if let Some(view) = self.analysis_views.get_mut(&view_key) {
                        view.listing_pending = None;
                    }
                }
                _ => {}
            }
        }
    }

    fn flush_archive(&mut self) {
        let Some(request) = self.pending_archive.take() else {
            return;
        };
        let Some(worker) = &self.archive else {
            self.archive_pending = false;
            self.inspector.pending = false;
            self.archive_error = Some("Archive worker unavailable".into());
            match request {
                Request::ProcessTree { run_id, .. } => {
                    self.run_tree_pending = None;
                    self.run_tree = Some((run_id, Err("Archive worker unavailable".into())));
                }
                Request::Specimen {
                    view_key,
                    generation,
                    ..
                } => self.fail_analysis_read(&view_key, generation, "Archive worker unavailable"),
                Request::Listing { view_key, .. } => {
                    self.fail_listing_read(&view_key, "Archive worker unavailable")
                }
                _ => {}
            }
            return;
        };
        match worker.try_request(request) {
            Ok(()) => {}
            Err(error) => match *error {
                std::sync::mpsc::TrySendError::Full(request) => {
                    self.pending_archive = Some(request)
                }
                std::sync::mpsc::TrySendError::Disconnected(request) => {
                    self.archive_pending = false;
                    self.inspector.pending = false;
                    self.archive_error = Some("Archive worker disconnected".into());
                    match request {
                        Request::ProcessTree { run_id, .. } => {
                            self.run_tree_pending = None;
                            self.run_tree =
                                Some((run_id, Err("Archive worker disconnected".into())));
                        }
                        Request::Specimen {
                            view_key,
                            generation,
                            ..
                        } => self.fail_analysis_read(
                            &view_key,
                            generation,
                            "Archive worker disconnected",
                        ),
                        Request::Listing { view_key, .. } => {
                            self.fail_listing_read(&view_key, "Archive worker disconnected")
                        }
                        _ => {}
                    }
                }
            },
        }
    }

    fn fail_listing_read(&mut self, view_key: &str, reason: &str) {
        if let Some(view) = self.analysis_views.get_mut(view_key) {
            view.listing_pending = None;
            view.listing = Some(Err(reason.into()));
        }
    }

    fn select_run(&mut self, id: Option<String>) {
        self.selected_capture = None;
        self.selected_process = None;
        self.archive_selected = false;
        self.selected_analysis = None;
        self.analysis_views.remove("workspace");
        self.selected_run = id;
        self.run_tree = None;
        self.run_tree_pending = None;
        self.pending_archive = None;
        self.reset_trace_selection();
        if self.offline_run().is_some() {
            self.request_page(0);
        }
    }

    fn reset_trace_selection(&mut self) {
        if let Some(cancel) = self.archive_read_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        self.selected_event = None;
        self.inspector.clear();
        if matches!(
            self.pending_archive,
            Some(Request::Invocations { .. } | Request::Captured { .. })
        ) {
            self.pending_archive = None;
        }
        self.archive_generation = self.archive_generation.wrapping_add(1);
        self.archive_page.clear();
        self.archive_page_generation = 0;
        self.archive_previous.clear();
        self.archive_next = None;
        self.archive_total = None;
        self.archive_source_total = None;
        self.archive_offset = 0;
        self.archive_pending = false;
        self.archive_error = None;
    }

    fn request_page(&mut self, offset: u64) {
        let Some(directory) = self.trace_archive_directory() else {
            return;
        };
        self.archive_generation = self.archive_generation.wrapping_add(1);
        if let Some(cancel) = self.archive_read_cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.archive_read_cancel = Some(Arc::clone(&cancel));
        self.archive_hidden_categories
            .clone_from(&self.settings.hidden_trace_categories);
        self.archive_pending = false;
        self.archive_error = None;
        let request = Request::Invocations {
            generation: self.archive_generation,
            directory,
            offset,
            capture: self.selected_capture.is_some(),
            pid: self.selected_process,
            query: self.applied_filter.clone(),
            hidden_categories: self.archive_hidden_categories.clone(),
            cancel,
        };
        self.queue_archive(request);
        self.archive_pending = true;
    }

    fn next_archive_page(&mut self) {
        if let Some(offset) = self.archive_next {
            self.archive_previous.push(self.archive_offset);
            self.request_page(offset);
        }
    }

    fn reopen(&mut self, run: RunSummary) {
        let live = run_in_live_session(&self.snapshot, &run);
        let reserved = usize::from(self.pending_launch.is_some());
        let consumes_slot = self.terminals.get(&run.id).is_none_or(|terminal| {
            !terminal.open && !run_in_live_session(&self.snapshot, &terminal.run)
        });
        if consumes_slot && available_terminal_slots(&self.terminals, &self.snapshot) <= reserved {
            self.status = terminal_capacity_message();
            return;
        }
        if let Some(terminal) = self.terminals.get_mut(&run.id) {
            terminal.open = true;
            terminal.terminal.invalidate_resize();
            if live {
                terminal.dirty = true;
                terminal.snapshot_error = None;
            } else {
                terminal.begin_replay();
            }
            return;
        }
        if self.terminals.len() >= TERMINAL_VIEW_LIMIT {
            let reclaim = self
                .terminals
                .iter()
                .find(|(_, terminal)| {
                    !terminal.open && !run_in_live_session(&self.snapshot, &terminal.run)
                })
                .map(|(id, _)| id.clone());
            if let Some(id) = reclaim {
                self.terminals.remove(&id);
            }
        }
        if self.terminals.len() >= TERMINAL_VIEW_LIMIT {
            self.status = terminal_capacity_message();
            return;
        }
        let mut terminal = RunTerminal::new(run.clone());
        if !live {
            terminal.begin_replay();
        } else {
            terminal.dirty = true;
        }
        self.terminals.insert(run.id.clone(), terminal);
    }

    fn run_history(&mut self, ui: &mut egui::Ui) {
        let Some(vm_id) = self.selected.clone() else {
            ui.colored_label(theme::muted(), "No VM selected");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            if ui.selectable_label(!self.capture_tab, "Runs").clicked() && self.capture_tab {
                self.capture_tab = false;
                self.refresh_history();
            }
            if ui.selectable_label(self.capture_tab, "Captures").clicked() && !self.capture_tab {
                self.capture_tab = true;
                self.refresh_captures();
            }
        });
        if self.capture_tab {
            self.capture_history_view(ui, &vm_id);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            for (filter, label) in [
                (RunFilter::All, "All"),
                (RunFilter::Live, "Live"),
                (RunFilter::Past, "Past"),
            ] {
                ui.selectable_value(&mut self.run_filter, filter, label);
            }
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Refresh Run History",
                true,
            ) {
                self.refresh_history();
            }
            if ui
                .selectable_label(
                    self.selected_run.is_none() && self.selected_capture.is_none(),
                    "All live traces",
                )
                .clicked()
            {
                self.select_run(None);
            }
        });
        let fields = crate::run_filter::fields();
        crate::query::filter_edit_fields(
            ui,
            &mut self.run_query,
            "Filter runs: pid == 123 && analysis.available",
            ui.available_width(),
            &fields,
            &[],
        );
        let mut runs: Vec<_> = self
            .snapshot
            .runs
            .iter()
            .filter(|run| run.vm_id == vm_id)
            .cloned()
            .collect();
        runs.extend(
            self.history
                .iter()
                .filter(|run| run.vm_id == vm_id && !runs.iter().any(|live| live.id == run.id))
                .cloned()
                .collect::<Vec<_>>(),
        );
        runs.retain(|run| match self.run_filter {
            RunFilter::All => true,
            RunFilter::Live => self.live_history_run(run),
            RunFilter::Past => !self.live_history_run(run),
        });
        let unfiltered_count = runs.len();
        let draft = crate::query::compile_table(&self.run_query, &fields);
        if let Some(error) = draft.error.as_ref() {
            self.run_query_error = Some(error.clone());
            ui.colored_label(
                theme::error(),
                format!("{error} · showing last valid filter"),
            );
        } else {
            self.applied_run_query.clone_from(&self.run_query);
            self.run_query_error = None;
            crate::query::remember_valid_filter(ui, &self.run_query);
        }
        let compiled = crate::query::compile_table(&self.applied_run_query, &fields);
        crate::run_filter::refresh_facts(ui, &runs);
        runs.retain(|run| {
            let annotation = crate::evidence::annotation(ui, &run.directory);
            let mut row = crate::run_filter::row(run, annotation.as_ref(), run_status(run));
            crate::run_filter::append_facts(ui, run, &mut row);
            compiled.keep_table(&row)
        });
        ui.weak(format!("{} of {unfiltered_count} runs", runs.len()));
        if self
            .selected_run
            .as_ref()
            .is_some_and(|id| !runs.iter().any(|run| &run.id == id))
        {
            self.select_run(None);
            ui.weak("The selected run is hidden by this filter.");
        }
        let pane_id = ui.id().with("run-history-focus");
        let pane = ui.interact(
            ui.available_rect_before_wrap(),
            pane_id,
            egui::Sense::click(),
        );
        if pane.clicked() {
            pane.request_focus();
        }
        let navigation =
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
            };
        let height = (ui.available_height() - 36.0).max(50.0);
        let mut inspect = navigation.map(|index| (runs[index].id.clone(), false));
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height + 28.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                let mut table = TableBuilder::new(ui)
                    .id_salt("run_history")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::remainder().at_least(120.0))
                    .column(Column::initial(180.0).range(90.0..=400.0))
                    .column(Column::initial(110.0).range(70.0..=220.0))
                    .column(Column::initial(110.0).range(70.0..=220.0))
                    .column(Column::exact(72.0))
                    .resizable(true)
                    .striped(true)
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0);
                if let Some(index) = navigation { table = table.scroll_to_row(index, Some(egui::Align::Center)); }
                table.header(28.0, |mut header| {
                        for name in ["Executable", "Arguments", "Tree status", "Root exit", ""] {
                            header.col(|ui| {
                                ui.strong(name);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(self.settings.font_size + 16.0, runs.len(), |mut row| {
                            let run = &runs[row.index()];
                            row.set_selected(self.selected_run.as_ref() == Some(&run.id));
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(format!("{}{}", crate::evidence::title(ui, &run.directory, &run.request.path), if run.analysis.is_some() { "  [static analysis]" } else { "" }))
                                        .selectable(false)
                                        .sense(egui::Sense::hover())
                                        .truncate(),
                                )
                                .on_hover_text(&run.request.path);
                            });
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
                            row.col(|ui| {
                                ui.add(
                                    egui::Label::new(run_status(run))
                                        .selectable(false)
                                        .sense(egui::Sense::hover()),
                                )
                                .on_hover_text(execution_detail(run));
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
                                    self.reopen(run.clone());
                                }
                                if icon(
                                    ui,
                                    egui_phosphor::regular::STOP,
                                    "Stop run and descendants",
                                    self.snapshot.runs.iter().any(|live| live.id == run.id)
                                        && matches!(
                                            run.state,
                                            RunState::Running | RunState::TerminalClosed
                                        )
                                        && !self.closing,
                                ) {
                                    self.send(Command::StopRun {
                                        run_id: run.id.clone(),
                                    });
                                }
                            });
                            let response = row.response();
                            response.context_menu(|ui| {
                                crate::evidence::menu(ui, &run.directory);
                                let annotation = crate::evidence::annotation(ui, &run.directory);
                                for (field, value) in crate::run_filter::row(run, annotation.as_ref(), run_status(run)) {
                                    crate::query::value_menu(ui, field, &value, &mut self.run_query);
                                }
                            });
                            if response.clicked() || response.double_clicked() {
                                pane.request_focus();
                                inspect = Some((run.id.clone(), response.double_clicked()));
                            }
                        });
                    });
            },
        );
        if let Some((id, open)) = inspect {
            if open {
                self.select_archive_run(id);
            } else {
                self.select_run(Some(id));
            }
        }
        if runs.is_empty() {
            ui.colored_label(theme::muted(), "No retained runs for this VM");
        } else if self.selected_run.is_some() {
            ui.colored_label(
                theme::muted(),
                "Run details are in the Details panel below.",
            );
        }
    }

    fn history_detail(&mut self, ui: &mut egui::Ui) {
        if self.capture_tab {
            self.capture_detail(ui);
            return;
        }
        let Some(vm_id) = self.selected.clone() else {
            ui.colored_label(theme::muted(), "No VM selected");
            return;
        };
        let run = self
            .snapshot
            .runs
            .iter()
            .chain(&self.history)
            .find(|run| self.selected_run.as_ref() == Some(&run.id) && run.vm_id == vm_id)
            .cloned();
        let Some(run) = run else {
            ui.colored_label(theme::muted(), "Select a run in Run History.");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            if run.analysis.is_some() && ui.button("Open static analysis").clicked() {
                self.selected_analysis = None;
                self.focus_panel = Some(Panel::StaticAnalysis);
            }
        });
        self.run_artifacts_view(ui, &run);
        self.run_tree_view(ui, &run);
        egui::CollapsingHeader::new("Launch details")
            .default_open(false)
            .show(ui, |ui| {
                egui::ScrollArea::both()
                    .id_salt("launch_metadata")
                    .show(ui, |ui| {
                        egui::Grid::new("run_metadata")
                            .num_columns(2)
                            .show(ui, |ui| {
                                for (label, value) in [
                                    ("Executable", run.request.path.clone()),
                                    ("Arguments", format!("{:?}", run.request.args)),
                                    ("Working directory", run.request.cwd.clone()),
                                    ("Environment", run.request.env.join("\n")),
                                    ("Run in", run.request.run_in.label().to_owned()),
                                    (
                                        "UID / GID",
                                        format!("{} / {}", run.request.uid, run.request.gid),
                                    ),
                                    ("Run", run.id.clone()),
                                    ("Boot", run.boot_id.clone()),
                                    (
                                        "Session / root task / PID",
                                        format!(
                                            "{} / {} / {}",
                                            run.session_id, run.root_task_cookie, run.pid
                                        ),
                                    ),
                                    ("Tree", execution_detail(&run)),
                                    ("Root exit", root_exit(&run)),
                                    ("Recording", run.directory.display().to_string()),
                                ] {
                                    ui.label(label);
                                    ui.add(egui::Label::new(value).selectable(true));
                                    ui.end_row();
                                }
                            });
                    });
            });
    }

    fn capture_detail(&mut self, ui: &mut egui::Ui) {
        let Some(id) = self.selected_capture.clone() else {
            ui.colored_label(theme::muted(), "Select a capture in Run History.");
            return;
        };
        let capture = self
            .snapshot
            .captures
            .iter()
            .chain(&self.capture_history)
            .find(|capture| capture.id == id)
            .cloned();
        if let Some(capture) = capture {
            captures::detail(ui, &capture);
        }
        let processes = match self.snapshot.capture_processes.get(&id) {
            Some(live) => Ok(live.clone()),
            None => match &self.archived_processes {
                Some((loaded, result)) if *loaded == id => result.clone(),
                _ => Ok(Vec::new()),
            },
        };
        match processes {
            Err(error) => {
                ui.colored_label(theme::warn(), format!("Process tree unavailable: {error}"));
            }
            Ok(processes) if processes.is_empty() => {
                ui.colored_label(
                    theme::muted(),
                    "No process tree (captures before Antinomie 0.3.0 keep one combined trace)",
                );
            }
            Ok(processes) => {
                if let Some(selection) = captures::process_tree(
                    ui,
                    &processes,
                    self.selected_process,
                    self.settings.font_size,
                ) {
                    self.select_process(selection);
                    self.focus_trace();
                }
            }
        }
    }

    fn run_artifacts_view(&mut self, ui: &mut egui::Ui, run: &RunSummary) {
        let manual: Vec<_> = self
            .snapshot
            .process_cores
            .iter()
            .filter(|capture| {
                capture.vm_id == run.vm_id
                    && capture.boot_id == run.boot_id
                    && capture.source_run_id.as_deref() == Some(run.id.as_str())
            })
            .cloned()
            .collect();
        if !manual.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Recent manual process cores: {}", manual.len()));
                for (index, capture) in manual.into_iter().enumerate() {
                    if ui.link(format!("Open manual core {}", index + 1)).clicked() {
                        self.core_view.select_manual(capture);
                        self.focus_panel = Some(Panel::CoreDump);
                    }
                }
            });
        }
        let cache_id = egui::Id::new(("run-artifacts", &run.directory));
        let cached = ui.ctx().data_mut(|data| {
            type Cached = (
                Instant,
                Result<Option<antinomie_monitor_core::RunArtifacts>, String>,
            );
            let cached = data.get_temp_mut_or_insert_with::<Cached>(cache_id, || {
                (
                    Instant::now(),
                    antinomie_monitor_core::RunArtifacts::load(&run.directory),
                )
            });
            if cached.0.elapsed() >= Duration::from_secs(1) {
                *cached = (
                    Instant::now(),
                    antinomie_monitor_core::RunArtifacts::load(&run.directory),
                );
            }
            cached.1.clone()
        });
        match cached {
            Ok(Some(artifacts))
                if artifacts.run_id == run.id
                    && artifacts.vm_id == run.vm_id
                    && artifacts.boot_id == run.boot_id =>
            {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!(
                        "Network: {:?} · Post-exit RAM: {:?} · Process core: {}",
                        artifacts.network_state,
                        artifacts.memory_state,
                        core_capture_status(artifacts.core_state)
                    ));
                    for (index, file) in artifacts.network_captures.iter().enumerate() {
                        if ui.link(format!("Network segment {}", index + 1)).clicked() {
                            self.network_view.open(Some(file.clone()));
                            self.focus_panel = Some(Panel::Network);
                        }
                    }
                    if let Some(directory) = &artifacts.memory_dump {
                        if ui.link("Open memory dump").clicked() {
                            self.memory_view.open_dump(directory);
                            self.focus_panel = Some(Panel::Memory);
                        }
                    }
                    if let Some(file) = &artifacts.core_dump {
                        if ui.link("Open process core").clicked() {
                            self.core_view.open(file);
                            self.focus_panel = Some(Panel::CoreDump);
                        }
                        if ui.link("Open core directory").clicked() {
                            if let Some(directory) = file.parent() {
                                open_directory(directory, &mut self.status);
                            }
                        }
                    }
                    if matches!(
                        artifacts.core_state,
                        antinomie_monitor_core::RunArtifactState::WaitingForRootExit
                            | antinomie_monitor_core::RunArtifactState::InProgress
                    ) && self.snapshot.active_vm.as_deref() == Some(run.vm_id.as_str())
                        && self.snapshot.boot_id.as_deref() == Some(run.boot_id.as_str())
                        && ui.button("Cancel process core").clicked()
                    {
                        self.send(Command::CancelProcessCore {
                            run_id: run.id.clone(),
                        });
                    }
                });
                for issue in &artifacts.issues {
                    ui.colored_label(theme::warn(), issue);
                }
            }
            Ok(Some(_)) => {
                ui.colored_label(
                    theme::warn(),
                    "Artifact metadata identity does not match this run",
                );
            }
            Ok(None) => {}
            Err(error) => {
                ui.colored_label(theme::warn(), error);
            }
        }
    }

    fn run_tree_view(&mut self, ui: &mut egui::Ui, run: &RunSummary) {
        ui.horizontal_wrapped(|ui| {
            ui.strong("Recorded process tree");
            if ui.button("Refresh tree").clicked() {
                self.run_tree = None;
            }
            ui.colored_label(
                theme::muted(),
                "Through the last saved packet; refresh ongoing runs",
            );
        });
        if self.run_tree.as_ref().is_none_or(|(id, _)| id != &run.id)
            && self.run_tree_pending.is_none()
            && self.pending_archive.is_none()
            && !self.archive_pending
        {
            self.queue_archive(Request::ProcessTree {
                run_id: run.id.clone(),
                directory: run.directory.clone(),
                root_pid: run.pid,
                path: run.request.path.clone(),
            });
            self.run_tree_pending = Some(run.id.clone());
        }
        let tree = self
            .run_tree
            .as_ref()
            .filter(|(id, _)| id == &run.id)
            .map(|(_, result)| result.clone());
        match tree {
            Some(Ok((processes, issues))) => {
                for issue in issues {
                    ui.colored_label(theme::warn(), issue);
                }
                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), ui.available_height().min(220.0)),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        if let Some(selection) = captures::process_tree(
                            ui,
                            &processes,
                            self.selected_process,
                            self.settings.font_size,
                        ) {
                            self.select_process(selection);
                            self.focus_trace();
                        }
                    },
                );
            }
            Some(Err(error)) => {
                ui.colored_label(theme::warn(), error);
            }
            None => {
                ui.spinner();
                ui.label("Reading saved lifecycle records…");
            }
        }
    }

    fn focus_trace(&mut self) {
        self.focus_panel = Some(Panel::Trace);
    }

    fn select_capture(&mut self, id: String, archive: bool) {
        self.selected_run = None;
        self.reset_trace_selection();
        if self.selected_capture.as_ref() != Some(&id) {
            self.selected_process = None;
        }
        if !self.snapshot.capture_processes.contains_key(&id)
            && self
                .archived_processes
                .as_ref()
                .is_none_or(|(loaded, _)| *loaded != id)
        {
            if let Some(capture) = self.capture(&id) {
                let processes =
                    antinomie_monitor_core::capture::capture_processes(&capture.directory);
                self.archived_processes = Some((id.clone(), processes));
            }
        }
        self.selected_capture = Some(id);
        self.archive_selected = archive;
        if self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
        if archive {
            self.focus_trace();
        }
    }

    fn capture_history_view(&mut self, ui: &mut egui::Ui, vm_id: &str) {
        ui.horizontal_wrapped(|ui| {
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Refresh Capture History",
                true,
            ) {
                self.refresh_captures();
            }
            if ui
                .selectable_label(
                    self.selected_capture.is_none() && self.selected_run.is_none(),
                    "All live traces",
                )
                .clicked()
            {
                self.select_run(None);
            }
        });
        let mut items: Vec<_> = self
            .snapshot
            .captures
            .iter()
            .filter(|capture| capture.vm_id == vm_id)
            .cloned()
            .collect();
        for capture in self
            .capture_history
            .iter()
            .filter(|capture| capture.vm_id == vm_id)
        {
            if !items.iter().any(|live| live.id == capture.id) {
                items.push(capture.clone());
            }
        }
        if let Some((id, archive)) = captures::history(
            ui,
            &items,
            self.selected_capture.as_deref(),
            self.settings.font_size,
        ) {
            self.select_capture(id, archive);
        }
        if self.selected_capture.as_ref().is_some_and(|id| {
            !items
                .iter()
                .any(|capture| &capture.id == id && captures::matches_capture_filter(ui, capture))
        }) {
            self.select_run(None);
            ui.weak("The selected capture is hidden by this filter.");
        }
        if self.selected_capture.is_some() {
            ui.colored_label(
                theme::muted(),
                "Capture details are in the Details panel below.",
            );
        }
    }

    fn select_process(&mut self, selection: captures::ProcessSelection) {
        self.selected_process = match selection {
            captures::ProcessSelection::All => None,
            captures::ProcessSelection::Process(pid) => Some(pid),
        };
        self.reset_trace_selection();
        if self.trace_archive_directory().is_some() {
            self.request_page(0);
        }
    }

    /// The selected capture's process tree: live, or as saved.
    fn capture_process_list(&self) -> Option<Vec<CaptureProcess>> {
        let id = self.selected_capture.as_ref()?;
        if let Some(live) = self.snapshot.capture_processes.get(id) {
            return Some(live.clone());
        }
        match &self.archived_processes {
            Some((loaded, Ok(list))) if loaded == id => Some(list.clone()),
            _ => None,
        }
    }

    fn select_archive_run(&mut self, id: String) {
        self.select_run(Some(id));
        self.archive_selected = true;
        self.request_page(0);
        self.focus_trace();
    }

    fn handle_archive_answer(&mut self, answer: Answer) {
        match answer {
            Answer::ListCaptures {
                vm_id,
                generation,
                result,
            } => {
                if self.selected.as_ref() != Some(&vm_id) || generation != self.history_generation {
                    return;
                }
                match result {
                    Ok(captures) => self.capture_history = captures,
                    Err(error) => {
                        self.status = format!("Capture History: {error}");
                        self.log("ERROR", self.status.clone());
                    }
                }
            }
            Answer::Listing {
                view_key,
                generation,
                result,
            } => {
                let Some(view) = self.analysis_views.get_mut(&view_key) else {
                    return;
                };
                if view
                    .listing_pending
                    .as_ref()
                    .is_some_and(|(pending, ..)| *pending == generation)
                {
                    view.listing_pending = None;
                    let report_id = view.report_id.clone();
                    view.listing = Some(result.and_then(|page| {
                        if report_id.as_deref() != Some(page.report_id.as_str()) {
                            return Err("Listing page identity mismatch".into());
                        }
                        Ok(page)
                    }));
                }
            }
            Answer::Specimen {
                view_key,
                generation,
                report_id,
                offset,
                data_len,
                result,
            } => {
                if let Some(view) = self.analysis_views.get_mut(&view_key) {
                    if view.report_id.as_deref() != Some(&report_id)
                        || view.pending != Some((generation, offset, data_len))
                    {
                        return;
                    }
                    view.pending = None;
                    view.preview = Some(result.and_then(|page| {
                        if page.report_id != report_id
                            || page.offset != offset
                            || page.data.len() != data_len
                        {
                            return Err("Specimen preview identity mismatch".into());
                        }
                        Ok(page)
                    }));
                }
            }
            Answer::ListVm {
                vm_id,
                generation,
                result,
            } => {
                if self.selected.as_ref() != Some(&vm_id) || generation != self.history_generation {
                    return;
                }
                match result {
                    Ok(runs) => self.history = runs,
                    Err(error) => {
                        self.status = format!("History: {error}");
                        self.log("ERROR", self.status.clone());
                    }
                }
            }
            #[cfg(test)]
            Answer::List(result) => match result {
                Ok(mut runs) => {
                    runs.extend(
                        self.history
                            .iter()
                            .filter(|run| run.id.starts_with("archive:"))
                            .cloned(),
                    );
                    self.history = runs;
                }
                Err(error) => {
                    self.status = format!("History: {error}");
                    self.log("ERROR", self.status.clone());
                }
            },
            Answer::Invocations {
                generation,
                offset,
                total,
                source_total,
                result,
            } if generation == self.archive_generation
                && self.trace_archive_directory().is_some() =>
            {
                self.archive_pending = false;
                match result {
                    Ok(page) => {
                        self.archive_total = total;
                        self.archive_source_total = source_total;
                        self.archive_page = page.invocations;
                        self.archive_page_generation = generation;
                        if self.selected_event.is_some_and(|selected| {
                            !self
                                .archive_page
                                .iter()
                                .any(|row| trace::key(row) == selected)
                        }) {
                            self.selected_event = None;
                            self.inspector.clear();
                        }
                        self.archive_offset = offset;
                        self.archive_next = page.next_offset;
                        self.archive_error =
                            (!page.issues.is_empty()).then(|| page.issues.join("; "));
                    }
                    Err(error) => self.archive_error = Some(error),
                }
            }
            Answer::ProcessTree { run_id, result } => {
                if self.run_tree_pending.as_ref() == Some(&run_id)
                    && self.selected_run.as_ref() == Some(&run_id)
                {
                    self.run_tree_pending = None;
                    self.run_tree = Some((run_id, result));
                }
            }
            Answer::Captured {
                generation,
                offset,
                result,
            } if generation == self.inspector.generation => {
                self.inspector.pending = false;
                match result {
                    Ok(data) => {
                        self.inspector.data = data;
                        self.inspector.data_offset = offset;
                        self.inspector.error = None;
                    }
                    Err(error) => self.inspector.error = Some(error),
                }
            }
            Answer::Terminal {
                run_id,
                generation,
                result,
            } => {
                if let Some(terminal) = self.terminals.get_mut(&run_id) {
                    if terminal.generation != generation {
                        return;
                    }
                    terminal.replay_pending = false;
                    match result {
                        Ok(replay) => {
                            for record in replay.page.records {
                                match record {
                                    TerminalRecord::Output(data) => {
                                        terminal.terminal.process(&data)
                                    }
                                    TerminalRecord::Resize { rows, cols } => {
                                        terminal.terminal.replay_resize(rows, cols)
                                    }
                                    TerminalRecord::Eof => terminal.run.terminal_eof = true,
                                }
                            }
                            terminal.replay_offset = replay.page.next_offset;
                            if let Some(warning) = replay.screen_warning {
                                terminal.replay_error = Some(warning.clone());
                                self.status = warning;
                            }
                        }
                        Err(error) => {
                            terminal.replay_offset = None;
                            terminal.replay_error = Some(error.clone());
                            self.status = format!("Terminal history: {error}");
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn drain_archive(&mut self) {
        for _ in 0..8 {
            let Some(answer) = self.archive.as_ref().and_then(|worker| worker.receive()) else {
                break;
            };
            self.handle_archive_answer(answer);
        }
        // At most one disk request is queued; closed history views pause their replay.
        if self.pending_archive.is_some() {
            return;
        }
        for terminal in self.terminals.values_mut() {
            let on_screen = terminal
                .last_paint
                .is_some_and(|painted| painted.elapsed() < Duration::from_secs(1));
            if (!terminal.open && !on_screen) || terminal.replay_pending {
                continue;
            }
            if let Some(offset) = terminal.replay_offset {
                if let Some(worker) = &self.archive {
                    if worker
                        .request(Request::Terminal {
                            run_id: terminal.run.id.clone(),
                            generation: terminal.generation,
                            directory: terminal.run.directory.clone(),
                            offset,
                        })
                        .is_ok()
                    {
                        terminal.replay_pending = true;
                    }
                }
            }
        }
    }

    fn resync_terminals(&mut self) {
        if let Some(backend) = &self.backend {
            for terminal in self.terminals.values_mut() {
                if terminal
                    .snapshot_started
                    .is_some_and(|started| started.elapsed() > Duration::from_secs(5))
                {
                    terminal.snapshot_request = None;
                    terminal.snapshot_started = None;
                    terminal.snapshot_error =
                        Some("Terminal screen reply timed out; reopen to retry".into());
                    self.status =
                        format!("Terminal screen reply timed out for {}", terminal.run.id);
                }
                if terminal.dirty
                    && terminal.snapshot_request.is_none()
                    && terminal.snapshot_error.is_none()
                    && run_in_live_session(&self.snapshot, &terminal.run)
                {
                    match backend.send(Command::TerminalSnapshot {
                        run_id: terminal.run.id.clone(),
                    }) {
                        Ok(id) => {
                            terminal.snapshot_request = Some(id);
                            terminal.snapshot_started = Some(Instant::now());
                        }
                        Err(error) => {
                            terminal.snapshot_error = Some(error.clone());
                            self.status = format!("Terminal resync: {error}");
                        }
                    }
                }
            }
        }
    }

    fn can_start_vm(&self) -> bool {
        self.selected.is_some() && self.snapshot.active_vm.is_none()
    }

    fn can_stop_vm(&self) -> bool {
        self.snapshot.active_vm.is_some()
    }

    fn can_configure_vm(&self) -> bool {
        self.selected.is_some() && self.snapshot.active_vm != self.selected
    }

    fn can_stop_capture(&self) -> bool {
        self.observer_supported()
            && self.pending_observer.is_none()
            && self.active_observer().is_some()
    }

    fn open_downloads(&mut self) {
        self.download_open = true;
        if !self.snapshot.remote_refreshing {
            self.send(Command::RefreshRemoteBases);
        }
    }

    fn selected_vm(&self) -> Option<&VmConfig> {
        self.snapshot
            .vms
            .iter()
            .find(|vm| Some(&vm.id) == self.selected.as_ref())
    }

    /// Malware samples > Send and run…: the sample is in the guest; the Run
    /// program window opens with it as the program, to be run as any other
    /// (arguments, user, where it runs, analysis) once the user presses Run.
    fn launch_sample(&mut self, run: ExecRequest) {
        self.exec.path = run.path;
        self.exec.uid = run.uid;
        self.exec.gid = run.gid;
        self.exec.cwd = run.cwd;
        self.args = run.args.join("\n");
        self.launch_open = true;
        self.status = "Sample sent: set how it runs, then press Run".into();
    }

    fn open_snapshots(&mut self) {
        if let Some(vm) = self.selected_vm().cloned() {
            self.vm_snapshots.bind(&vm.id, &vm.name);
            if self.vm_snapshots.pending.is_none() {
                self.send(Command::RefreshVmSnapshots { vm_id: vm.id });
            }
        }
    }

    /// Menu shortcuts; they wait while a text field or terminal has the
    /// keyboard.
    fn shortcuts(&mut self, ctx: &egui::Context) {
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
        if pressed(keys::SETTINGS) {
            self.settings_open = true;
        }
        if pressed(keys::QUIT) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    fn menus(&mut self, ctx: &egui::Context) {
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
                        for view in [
                            Panel::Summary,
                            Panel::Trace,
                            Panel::Network,
                            Panel::Memory,
                            Panel::CoreDump,
                            Panel::StaticAnalysis,
                            Panel::RunHistory,
                            Panel::Details,
                            Panel::Activity,
                        ] {
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
                            self.dependencies.open = true;
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
    fn toolbar(&mut self, ctx: &egui::Context) {
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

    /// Remember the newest program each VM ran; the sidebar shows it.
    fn note_last_runs(&mut self) {
        let now = unix_seconds();
        for vm in &self.snapshot.vms {
            let Some(newest) = self
                .snapshot
                .runs
                .iter()
                .rev()
                .find(|run| run.vm_id == vm.id)
            else {
                continue;
            };
            if self
                .settings
                .last_runs
                .get(&vm.id)
                .is_some_and(|last| last.run_id == newest.id)
            {
                continue;
            }
            self.settings.last_runs.insert(
                vm.id.clone(),
                LastRun {
                    run_id: newest.id.clone(),
                    program: newest.request.path.clone(),
                    started: now,
                },
            );
        }
        let vms = &self.snapshot.vms;
        if !vms.is_empty() {
            self.settings
                .last_runs
                .retain(|id, _| vms.iter().any(|vm| &vm.id == id));
        }
    }

    fn open_vm_directory(&mut self, vm_id: &str) {
        match self
            .snapshot
            .vm_locations
            .iter()
            .find(|location| location.vm_id == vm_id)
        {
            Some(location) => open_directory(&location.disk_directory, &mut self.status),
            None => self.status = "VM directory unavailable".into(),
        }
    }

    /// The sidebar row of one VM: its state, base, size and latest run.
    fn vm_row(&self, ui: &mut egui::Ui, vm: &VmConfig, now: u64) -> egui::Response {
        let active = self.snapshot.active_vm.as_ref() == Some(&vm.id);
        let (word, color) = if active {
            vm_state_word(&self.snapshot.state)
        } else {
            ("Stopped", theme::muted())
        };
        let number = theme::value(theme::ValueKind::Number);
        let mut machine = Vec::new();
        match selected_base(&self.snapshot, vm.base_identity.as_deref()) {
            Some(base) => {
                let current =
                    RevisionStatus::of_base(base.revision, base.min_app_version.as_deref())
                        == RevisionStatus::Current;
                machine.push((
                    if current {
                        base.label.clone()
                    } else {
                        format!("{} {}", base.label, egui_phosphor::regular::WARNING)
                    },
                    if current {
                        theme::text()
                    } else {
                        theme::warn()
                    },
                ));
            }
            None => machine.push(("Base unavailable".into(), theme::warn())),
        }
        machine.extend([
            (" · ".into(), theme::muted()),
            (vm.cpus.to_string(), number),
            (" CPU · ".into(), theme::muted()),
            (vm.ram_mib.to_string(), number),
            (" MiB".into(), theme::muted()),
        ]);
        if vm.isolated_network {
            machine.push((" · Isolated network".into(), theme::good()));
        } else if vm.nat {
            machine.push((" · ".into(), theme::muted()));
            machine.push(("NAT".into(), theme::info()));
        }
        let last = match self.settings.last_runs.get(&vm.id) {
            Some(last) => vec![
                (
                    format!(
                        "{} {}",
                        egui_phosphor::regular::TERMINAL_WINDOW,
                        program_name(&last.program)
                    ),
                    theme::value(theme::ValueKind::Name),
                ),
                (
                    format!(" · {}", relative_time(now.saturating_sub(last.started))),
                    theme::muted(),
                ),
            ],
            // Saved runs carry no start time; the history of the selected
            // VM still tells how many there are.
            None if self.selected.as_ref() == Some(&vm.id) && !self.history.is_empty() => vec![
                (self.history.len().to_string(), number),
                (
                    format!(
                        " recorded run{}",
                        if self.history.len() == 1 { "" } else { "s" }
                    ),
                    theme::muted(),
                ),
            ],
            None => vec![("No recent run".into(), theme::muted())],
        };
        let response = sidebar_row(
            ui,
            SidebarRow {
                mark: ("●", color),
                name: &vm.name,
                state: Some((word, color)),
                details: vec![machine, last],
                selected: self.selected.as_ref() == Some(&vm.id),
            },
        );
        response.on_hover_ui(|ui| {
            ui.label(RichText::new(&vm.name).strong());
            ui.label(format!(
                "{} CPU / {} MiB RAM / {} GiB disk\nNetwork: {}",
                vm.cpus,
                vm.ram_mib,
                vm.disk_gib,
                if vm.isolated_network {
                    "isolated"
                } else if vm.nat {
                    "NAT"
                } else {
                    "disconnected"
                }
            ));
            if let Some(last) = self.settings.last_runs.get(&vm.id) {
                ui.label(format!("Latest run: {}", last.program));
            }
            ui.weak("Right-click for actions");
        })
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        self.note_last_runs();
        let now = unix_seconds();
        let mut selected_vm = None;
        let mut action: Option<(VmConfig, VmAction)> = None;
        let mut base_action: Option<(String, BaseAction)> = None;
        let mut clicked_base: Option<String> = None;
        let mut open_downloads = false;
        let mut new_vm = false;
        egui::SidePanel::left("vms")
            // Room for the VM details, but the trace keeps most of a small
            // screen.
            .default_width((ctx.screen_rect().width() * 0.2).clamp(200.0, 300.0))
            .min_width(200.0)
            .max_width(380.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel())
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                let stopped = self.snapshot.active_vm.is_none();
                if section_header(
                    ui,
                    SectionHeader {
                        title: "Virtual machines",
                        count: self.snapshot.vms.len(),
                        tooltip: "Virtual machines: click to fold",
                        action: "New VM",
                        enabled: stopped,
                        open: false,
                    },
                    &mut self.settings.vms_collapsed,
                )
                .clicked()
                {
                    new_vm = true;
                }
                if !self.settings.vms_collapsed {
                    let budget = ui.available_height();
                    egui::ScrollArea::vertical()
                        .id_salt("vm_list")
                        .max_height(if self.settings.bases_collapsed {
                            budget - ui.spacing().interact_size.y - 16.0
                        } else {
                            budget * 0.6
                        }
                        .max(80.0))
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            if self.snapshot.vms.is_empty() {
                                ui.label(RichText::new("No saved VMs").color(theme::muted()));
                            }
                            for vm in &self.snapshot.vms {
                                let response = self.vm_row(ui, vm, now);
                                if response.clicked() || response.secondary_clicked() {
                                    selected_vm = Some(vm.id.clone());
                                }
                                response.context_menu(|ui| {
                                    let active = self.snapshot.active_vm.as_ref() == Some(&vm.id);
                                    let stopped = !active && !self.closing;
                                    for (label, enabled, choice) in [
                                        ("Start VM", self.snapshot.active_vm.is_none() && !self.closing, VmAction::Start),
                                        ("Stop VM", active, VmAction::Stop),
                                        ("Configuration…", stopped, VmAction::Configure),
                                        ("Snapshots…", !self.closing, VmAction::Snapshots),
                                        ("Rename…", !self.closing, VmAction::Rename),
                                        ("Duplicate…", stopped, VmAction::Duplicate),
                                        ("Open directory", true, VmAction::OpenDirectory),
                                        ("Reset disk to base…", self.snapshot.active_vm.is_none(), VmAction::Reset),
                                        ("Delete VM and disk…", stopped, VmAction::Delete),
                                    ] {
                                        if matches!(choice, VmAction::Configure | VmAction::Reset) {
                                            ui.separator();
                                        }
                                        if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                                            action = Some((vm.clone(), choice));
                                            ui.close_menu();
                                        }
                                    }
                                });
                            }
                        });
                }
                ui.add_space(6.0);
                let add_base = egui::Id::new("add_base_menu");
                let open = ui.memory(|memory| memory.is_popup_open(add_base));
                let header = section_header(
                    ui,
                    SectionHeader {
                        title: "Base images",
                        count: self.snapshot.bases.len(),
                        tooltip: "Installed base images: click to fold",
                        action: "Add base",
                        enabled: true,
                        open,
                    },
                    &mut self.settings.bases_collapsed,
                );
                if header.clicked() {
                    ui.memory_mut(|memory| memory.toggle_popup(add_base));
                }
                egui::popup::popup_below_widget(
                    ui,
                    add_base,
                    &header,
                    egui::PopupCloseBehavior::CloseOnClick,
                    |ui| {
                        ui.set_min_width(140.0);
                        if ui
                            .add_enabled(
                                self.snapshot.active_vm.is_none(),
                                egui::Button::new("Import base…"),
                            )
                            .clicked()
                        {
                            self.import_open = true;
                        }
                        if ui.button("Download base…").clicked() {
                            open_downloads = true;
                        }
                        if ui.button("Build base…").clicked() {
                            self.build_open = true;
                        }
                    },
                );
                if self.settings.bases_collapsed {
                    return;
                }
                egui::ScrollArea::vertical()
                    .id_salt("base_list")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.snapshot.bases_checking {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    RichText::new("Checking base images…").color(theme::muted()),
                                )
                                .on_hover_text(
                                    "The first start after an update or import checks each base once",
                                );
                            });
                        } else if self.snapshot.bases.is_empty() {
                            ui.label(RichText::new("No base images").color(theme::muted()));
                            if ui.button("Add base…").clicked() {
                                open_downloads = true;
                            }
                        }
                        for base in &self.snapshot.bases {
                            let dependents = self
                                .snapshot
                                .vms
                                .iter()
                                .filter(|vm| vm.base_identity.as_deref() == Some(base.id.as_str()))
                                .count();
                            let guest = base
                                .guest
                                .as_ref()
                                .map_or("Linux 6.12.94".to_string(), |guest| guest.id.clone());
                            let base_status = RevisionStatus::of_base(
                                base.revision,
                                base.min_app_version.as_deref(),
                            );
                            let name = versioned_label(
                                &base.label,
                                base.revision,
                                base.min_app_version.as_deref(),
                            );
                            let mark = match base_status {
                                RevisionStatus::Current => theme::good(),
                                RevisionStatus::NeedsNewerApp => theme::error(),
                                _ => theme::warn(),
                            };
                            let number = theme::value(theme::ValueKind::Number);
                            let response = sidebar_row(
                                ui,
                                SidebarRow {
                                    mark: (egui_phosphor::regular::HARD_DRIVE, mark),
                                    name: &name,
                                    state: None,
                                    details: vec![vec![
                                        (
                                            format!("{:.1}", base.size_bytes as f64 / 1073741824.0),
                                            number,
                                        ),
                                        (" GiB  ·  ".into(), theme::muted()),
                                        (dependents.to_string(), number),
                                        (
                                            format!(
                                                " VM{}  ·  {guest}",
                                                if dependents == 1 { "" } else { "s" }
                                            ),
                                            theme::muted(),
                                        ),
                                    ]],
                                    selected: self.selected_base.as_deref()
                                        == Some(base.id.as_str()),
                                },
                            )
                            .on_hover_text(format!(
                                "{}\n{}\n{:.1} GiB on disk · guest {guest} · used by {} VM(s)\n\
                                 {}\nRight-click for actions",
                                name,
                                base.directory.display(),
                                base.size_bytes as f64 / 1073741824.0,
                                dependents,
                                describe_base(base)
                            ));
                            if response.clicked() || response.secondary_clicked() {
                                clicked_base = Some(base.id.clone());
                            }
                            if base_status != RevisionStatus::Current {
                                let hint = match base_status {
                                    RevisionStatus::NeedsNewerApp => "Needs a newer Antinomie",
                                    _ if newer_base(&self.snapshot, base).is_some() => {
                                        "Outdated · newer base available"
                                    }
                                    _ => "Outdated · built for an earlier Antinomie",
                                };
                                ui.horizontal(|ui| {
                                    ui.add_space(30.0);
                                    if ui
                                        .add(
                                            egui::Label::new(
                                                RichText::new(hint).small().color(theme::warn()),
                                            )
                                            .sense(egui::Sense::click()),
                                        )
                                        .on_hover_text(
                                            "Open Add base > Download base for the base made for this version",
                                        )
                                        .clicked()
                                    {
                                        open_downloads = true;
                                    }
                                });
                            }
                            response.context_menu(|ui| {
                                if ui.button("New VM from this base…").clicked() {
                                    base_action = Some((base.id.clone(), BaseAction::NewVm));
                                    ui.close_menu();
                                }
                                if ui.button("Open directory").clicked() {
                                    base_action = Some((base.id.clone(), BaseAction::OpenDirectory));
                                    ui.close_menu();
                                }
                                ui.separator();
                                if ui
                                    .add_enabled(
                                        self.snapshot.active_vm.is_none(),
                                        egui::Button::new("Delete base…"),
                                    )
                                    .clicked()
                                {
                                    base_action = Some((base.id.clone(), BaseAction::Delete));
                                    ui.close_menu();
                                }
                            });
                        }
                    });
            });
        if new_vm {
            self.new_image();
        }
        if open_downloads {
            self.open_downloads();
        }
        if let Some(identity) = clicked_base {
            self.selected_base = Some(identity);
        }
        if let Some((identity, action)) = base_action {
            match action {
                BaseAction::NewVm => self.new_image_from(identity),
                BaseAction::OpenDirectory => {
                    if let Some(base) = self.snapshot.bases.iter().find(|base| base.id == identity)
                    {
                        open_directory(&base.directory.clone(), &mut self.status);
                    }
                }
                BaseAction::Delete => self.confirm = Some(Confirm::DeleteBase(identity)),
            }
        }
        if let Some(vm_id) = selected_vm {
            if self.selected.as_ref() != Some(&vm_id) {
                self.selected = Some(vm_id);
                self.history.clear();
                self.select_run(None);
                self.refresh_history();
            }
        }
        if let Some((vm, action)) = action {
            match action {
                VmAction::Start => {
                    if self.selected.as_ref() == Some(&vm.id) {
                        self.new_run();
                    }
                }
                VmAction::Stop => self.send(Command::Stop),
                VmAction::Snapshots => {
                    self.vm_snapshots.bind(&vm.id, &vm.name);
                    if self.vm_snapshots.pending.is_none() {
                        self.send(Command::RefreshVmSnapshots { vm_id: vm.id });
                    }
                }
                VmAction::Configure => {
                    self.credentials.reset();
                    self.draft_generation = self.draft_generation.wrapping_add(1);
                    self.draft = vm;
                    self.config_open = true;
                }
                VmAction::Rename => self.name_action = Some((vm.id, false, vm.name)),
                VmAction::Duplicate => {
                    self.name_action = Some((vm.id, true, format!("{} copy", vm.name)))
                }
                VmAction::OpenDirectory => self.open_vm_directory(&vm.id),
                VmAction::Reset => self.confirm = Some(Confirm::Reset(vm.id)),
                VmAction::Delete => self.confirm = Some(Confirm::Delete(vm.id)),
            }
        }
    }

    /// The status line. Losses and the app version sit on the right:
    /// `TRL x UIL y STL z CAP p/q GiB Antinomie x.y.z`.
    fn health(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("health")
            .frame(theme::frame(theme::raised()))
            .show(ctx, |ui| {
                let dropped = self.snapshot.health.dropped;
                let attempted = self.snapshot.health.attempted;
                let ui_dropped = self.snapshot.health.ui_dropped;
                let storage_dropped = self.snapshot.health.storage_dropped_packets;
                let persisted = self.snapshot.health.persisted_len;
                let quota = self.settings.quota_gib;
                let shedding = self.snapshot.health.shedding;
                let persistence = self.snapshot.health.persistence_error.clone();
                let last_error = self.snapshot.last_error.clone();
                let status = self.status.clone();
                let closing = self.closing;
                let loss = |count: u64| if count == 0 { theme::good() } else { theme::warn() };
                let saved = persisted as f64 / 1_073_741_824.0;
                ui.add_space(3.0);
                // Allocate the right-aligned figures first. The remaining
                // left rectangle bounds both message layout and painting.
                let row_size = egui::vec2(ui.available_width(), ui.spacing().interact_size.y);
                ui.allocate_ui_with_layout(row_size, egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    // A name stays next to its number. Groups are separated.
                    ui.spacing_mut().item_spacing.x = 8.0;
                    let version = ui.monospace(format!("Antinomie {APP_VERSION}"));
                    ui.add_space(16.0);
                    let cap = ui.monospace(format!("CAP {saved:.1}/{quota} GiB"));
                    ui.add_space(16.0);
                    let storage_color = if persistence.is_some() {
                        theme::error()
                    } else {
                        loss(storage_dropped)
                    };
                    let stl =
                        status_value_rtl(ui, "STL", &storage_dropped.to_string(), storage_color);
                    ui.add_space(16.0);
                    let uil =
                        status_value_rtl(ui, "UIL", &ui_dropped.to_string(), loss(ui_dropped));
                    ui.add_space(16.0);
                    let trl = status_value_rtl(ui, "TRL", &dropped.to_string(), loss(dropped));
                    let meters = version | cap | stl | uil | trl;
                    meters.on_hover_text(format!(
                        "TRL transport loss: {dropped} of {attempted} records the guest could not hand over\n\
                         UIL interface loss: {ui_dropped} preview records not drawn\n\
                         STL storage loss: {storage_dropped} packets not retained\n\
                         CAP saved / quota: {saved:.1} / {quota} GiB\n\
                         Capture All shedding: {}\n\
                         Antinomie {APP_VERSION}",
                        if shedding { "dropping events" } else { "off" }
                    ));
                    ui.add_space(16.0);
                    let message_size = ui.available_size();
                    ui.allocate_ui_with_layout(message_size, egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.set_clip_rect(ui.max_rect().intersect(ui.clip_rect()));
                        if let Some(error) = &persistence {
                            status_line(
                                ui,
                                egui_phosphor::regular::WARNING,
                                &format!("Saving stopped: {error}"),
                                theme::error(),
                            );
                        } else if let Some(error) = &last_error {
                            status_line(
                                ui,
                                egui_phosphor::regular::WARNING_CIRCLE,
                                error,
                                theme::error(),
                            );
                        } else if closing {
                            ui.spinner();
                            let message = "Waiting for guest shutdown and recording finalization…";
                            ui.add(egui::Label::new(RichText::new(message).color(theme::warn())).truncate())
                                .on_hover_text(message);
                        } else if !status.is_empty() {
                            status_line(ui, egui_phosphor::regular::INFO, &status, theme::info());
                        }
                    });
                });
                ui.add_space(3.0);
            });
    }

    fn log(&mut self, level: &'static str, message: String) {
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            % 86400;
        if self.activity.len() == ACTIVITY_LIMIT {
            self.activity.pop_front();
        }
        self.activity.push_back(Activity {
            time: format!(
                "{:02}:{:02}:{:02}",
                time / 3600,
                (time / 60) % 60,
                time % 60
            ),
            level,
            message,
        });
    }

    fn activity(&mut self, ui: &mut egui::Ui) {
        if self.activity.is_empty() {
            ui.label(RichText::new("No activity").color(theme::muted()));
            return;
        }
        let height = (ui.available_height() - 30.0).max(0.0);
        TableBuilder::new(ui)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(84.0))
            .column(Column::exact(60.0))
            .column(Column::remainder())
            .min_scrolled_height(0.0)
            .max_scroll_height(height)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .header(30.0, |mut header| {
                for text in ["Time", "Level", "Message"] {
                    header.col(|ui| {
                        ui.label(RichText::new(text).color(theme::muted()));
                    });
                }
            })
            .body(|body| {
                body.rows(30.0, self.activity.len(), |mut row| {
                    let activity = &self.activity[row.index()];
                    row.col(|ui| {
                        ui.monospace(&activity.time).on_hover_text("UTC");
                    });
                    row.col(|ui| {
                        ui.colored_label(
                            if activity.level == "ERROR" {
                                theme::error()
                            } else {
                                theme::muted()
                            },
                            activity.level,
                        );
                    });
                    row.col(|ui| {
                        ui.add(egui::Label::new(&activity.message).truncate())
                            .on_hover_text(&activity.message);
                    });
                });
            });
    }

    fn launch_form(&mut self, ui: &mut egui::Ui) {
        ui.add_enabled_ui(self.running() && self.pending_launch.is_none(), |ui| {
            let selection_error = self.exec.analysis.validate().err();
            let graphical = self.selected_vm_graphical();
            let core_on_exit = self
                .snapshot
                .guest_kernel
                .as_ref()
                .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 15));
            let footer = ui.spacing().interact_size.y
                + 24.0
                + if selection_error.is_some() {
                    ui.text_style_height(&egui::TextStyle::Body) + 10.0
                } else {
                    0.0
                };
            egui::ScrollArea::vertical()
                .id_salt("run-setup")
                .max_height((ui.available_height() - footer).max(80.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    if crate::analysis::launch_fields(
                        ui,
                        &mut self.exec,
                        &mut self.args,
                        &mut self.env,
                        &self.snapshot.analysis_tools,
                        crate::analysis::LaunchCapabilities {
                            graphical,
                            core_on_exit,
                        },
                    ) {
                        self.tools_open = true;
                    }
                });
            ui.separator();
            if let Some(reason) = selection_error {
                ui.colored_label(theme::error(), reason);
            }
            ui.horizontal(|ui| {
                let run = ui
                    .add_enabled(
                        !self.exec.path.trim().is_empty() && self.exec.analysis.validate().is_ok(),
                        primary_button(&format!("{} Run", egui_phosphor::regular::PLAY)),
                    )
                    .on_disabled_hover_text("Enter the executable to run");
                if run.clicked() {
                    match crate::analysis::snapshot(&self.exec, &self.args, &self.env, graphical) {
                        Ok(request) => self.send(Command::Execute(request)),
                        Err(reason) => self.status = reason,
                    }
                    if self.pending_launch.is_some() {
                        self.launch_open = false;
                    }
                }
                let analyze = ui.add_enabled(
                    self.exec.analysis.enabled
                        && !self.exec.path.trim().is_empty()
                        && self.exec.analysis.validate().is_ok(),
                    egui::Button::new("Analyze Only"),
                );
                if analyze.clicked() {
                    self.send(Command::AnalyzeOnly {
                        path: self.exec.path.clone(),
                        uid: self.exec.uid,
                        gid: self.exec.gid,
                        analysis: self.exec.analysis.clone(),
                    });
                    self.focus_panel = Some(Panel::StaticAnalysis);
                }
                if ui.button("Cancel").clicked() {
                    self.launch_open = false;
                }
                #[cfg(test)]
                {
                    self.launch_action_rects = Some((run.rect, analyze.rect));
                }
            });
        });
    }

    fn invocations(&self) -> Vec<InvocationSummary> {
        if self.trace_archive_directory().is_some() {
            return self.archive_page.clone();
        }
        if self.selected.is_some()
            && self.snapshot.active_vm.is_some()
            && self.selected != self.snapshot.active_vm
        {
            return Vec::new();
        }
        if let Some(id) = &self.selected_capture {
            return self
                .snapshot
                .capture_events
                .get(id)
                .map(|events| match self.selected_process {
                    Some(pid) => pair_events(
                        &events
                            .iter()
                            .filter(|event| event.pid == pid)
                            .cloned()
                            .collect::<Vec<_>>(),
                    ),
                    None => pair_events(events),
                })
                .unwrap_or_default();
        }
        let events: Vec<_> = self
            .snapshot
            .events
            .iter()
            .filter(|event| self.selected_process.is_none_or(|pid| event.pid == pid))
            .filter(|event| {
                self.selected_run.as_ref().is_none_or(|id| {
                    self.snapshot
                        .runs
                        .iter()
                        .find(|run| &run.id == id)
                        .is_some_and(|run| event.root_task_cookie == run.root_task_cookie)
                })
            })
            .cloned()
            .collect();
        pair_events(&events)
    }

    fn live_history_run(&self, run: &RunSummary) -> bool {
        self.snapshot.runs.iter().any(|live| live.id == run.id)
            && matches!(
                run.state,
                RunState::Running | RunState::StopRequested | RunState::TerminalClosed
            )
    }

    /// A valid trace box becomes the applied filter. An invalid expression
    /// keeps the previous one; an empty applied filter matches every row.
    fn commit_trace_filter(&mut self) -> crate::query::Compiled {
        let draft = crate::query::compile_note(&self.filter);
        if draft.error.is_none() {
            let changed = self.applied_filter != self.filter;
            self.applied_filter.clone_from(&self.filter);
            if changed && self.trace_archive_directory().is_some() {
                self.refresh_archive_matches(&draft);
            }
        }
        draft
    }

    fn refresh_archive_matches(&mut self, filter: &crate::query::Compiled) {
        let hidden = &self.settings.hidden_trace_categories;
        if self.selected_event.is_some_and(|selected| {
            !self.archive_page.iter().any(|row| {
                trace::key(row) == selected
                    && filter.keep(row)
                    && trace::representative(row).is_some_and(|event| {
                        SyscallGroup::of(&event.syscall_name)
                            .is_none_or(|group| !hidden.contains(&group))
                    })
            })
        }) {
            self.selected_event = None;
            self.inspector.clear();
        }
        self.archive_previous.clear();
        self.archive_next = None;
        self.request_page(0);
    }

    fn events(&mut self, ui: &mut egui::Ui) {
        if self.no_live_trace() {
            self.empty_trace(ui);
            return;
        }
        ui.horizontal_wrapped(|ui| {
            theme::section(ui, "Syscalls");
            if let Some(capture) = self.selected_capture_summary() {
                ui.add(egui::Label::new(captures::scope(&capture.scope)).truncate())
                    .on_hover_text(&capture.id);
            }
            if let Some(processes) = self.capture_process_list().filter(|list| !list.is_empty()) {
                if let Some(selection) =
                    captures::process_menu(ui, &processes, self.selected_process)
                {
                    self.select_process(selection);
                }
            }
            if self.trace_archive_directory().is_some() {
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_LEFT,
                    "Previous archive page",
                    !self.archive_pending && !self.archive_previous.is_empty(),
                ) {
                    if let Some(offset) = self.archive_previous.pop() {
                        self.request_page(offset);
                    }
                }
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_RIGHT,
                    "Next archive page",
                    !self.archive_pending && self.archive_next.is_some(),
                ) {
                    self.next_archive_page();
                }
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_CLOCKWISE,
                    "Reload archive page",
                    !self.archive_pending,
                ) {
                    let offset = if self.archive_page_generation != self.archive_generation
                        && self.archive_previous.is_empty()
                    {
                        0
                    } else {
                        self.archive_offset
                    };
                    self.request_page(offset);
                }
                if let Some(total) = self.archive_total {
                    if self.archive_page_generation == self.archive_generation {
                        ui.label(format!(
                            "Page {} of {} · 100 calls/page · {total} matching / {} saved calls",
                            self.archive_previous.len() + 1,
                            total.div_ceil(100).max(1),
                            self.archive_source_total.unwrap_or(total)
                        ));
                    } else {
                        ui.label(format!(
                            "Previous results: {total} matching / {} saved calls",
                            self.archive_source_total.unwrap_or(total)
                        ));
                    }
                }
                ui.label(if self.archive_pending {
                    if self.archive_page.is_empty() {
                        "Reading archive matches..."
                    } else {
                        "Reading matches · previous results shown"
                    }
                } else if self.archive_page_generation != self.archive_generation
                    && !self.archive_page.is_empty()
                {
                    "Previous results · refresh to retry"
                } else {
                    "History"
                });
            }
            let filter_width = ui.available_width().max(180.0);
            crate::query::filter_edit(
                ui,
                &mut self.filter,
                "Filter syscall rows",
                filter_width,
                crate::query::FilterScope::Syscall,
            )
            .on_hover_text(crate::query::HELP);
        });
        if let Some(error) = &self.archive_error {
            ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).truncate())
                .on_hover_text(error);
        }
        let draft = self.commit_trace_filter();
        if let Some(error) = &draft.error {
            ui.colored_label(theme::warn(), error);
        }
        let filter = if draft.error.is_none() {
            draft
        } else {
            crate::query::compile_note(&self.applied_filter)
        };
        let all = self.invocations();
        self.trace_categories(ui, &all);
        let archived = self.trace_archive_directory().is_some();
        if archived && self.archive_hidden_categories != self.settings.hidden_trace_categories {
            self.refresh_archive_matches(&filter);
        }
        let total = all.len();
        let hidden = self.settings.hidden_trace_categories.clone();
        let invocations: Vec<_> = all
            .into_iter()
            .filter(|invocation| {
                let Some(event) = trace::representative(invocation) else {
                    return false;
                };
                if !archived
                    && SyscallGroup::of(&event.syscall_name)
                        .is_some_and(|group| hidden.contains(&group))
                {
                    return false;
                }
                archived || filter.keep(invocation)
            })
            .collect();
        let mut invocations = invocations;
        if let Some((column, descending)) = self.trace_sort {
            sort_invocations(&mut invocations, column, descending);
            if archived {
                ui.colored_label(theme::muted(), "Sort applies to this page");
            }
        }
        if invocations.len() != total {
            ui.colored_label(
                theme::muted(),
                format!("Showing {} of {total} calls", invocations.len()),
            );
        }
        let font = self.settings.font_size;
        let height = theme::row_height(font);
        let header_height = font + 12.0;
        let table_height = (ui.available_height() - header_height).max(0.0);
        let mono = theme::mono(font - 1.0);
        let body_font = egui::FontId::proportional(font);
        let char_width = ui.fonts(|fonts| fonts.glyph_width(&mono, '0'));
        let chars = |count: f32| count * char_width + 14.0;
        let mut widths = [
            chars(9.0),
            chars(8.0),
            chars(5.0),
            chars(3.0),
            font * 8.5,
            chars(14.0),
        ];
        // Narrow panels shrink the fixed columns so Info stays in view.
        let room = ui.available_width() - font * 6.0 - 7.0 * ui.spacing().item_spacing.x;
        let needed: f32 = widths.iter().sum();
        let mut scale = 1.0;
        if needed > room {
            scale = (room / needed).max(0.35);
            for width in &mut widths {
                *width *= scale;
            }
        }
        // Initial widths apply once per table id: a new width class (narrow
        // panel, other text size) starts from fitting widths again.
        let width_class = ((scale * 10.0).round() as i32, font as i32);
        // Row hover is known only once the row is drawn; tinted rows use the
        // previous frame's to brighten under the pointer.
        let hover_id = ui.id().with("trace_hovered_row");
        let hovered_row: Option<usize> = ui.data_mut(|data| data.remove_temp(hover_id));
        let palette = *theme::palette();
        let trace_colors = self.settings.trace_colors;
        egui::ScrollArea::horizontal()
            .id_salt("syscalls_horizontal")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width((font / 16.0 * 760.0).max(ui.available_width()));
                TableBuilder::new(ui)
                    .id_salt(("syscall_table", width_class))
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .max_scroll_height(table_height)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false])
                    .column(Column::initial(widths[0]).at_least(48.0).clip(true))
                    .column(Column::initial(widths[1]).at_least(40.0).clip(true))
                    .column(Column::initial(widths[2]).at_least(32.0).clip(true))
                    .column(Column::initial(widths[3]).at_least(30.0).clip(true))
                    .column(Column::initial(widths[4]).at_least(70.0).clip(true))
                    .column(Column::initial(widths[5]).at_least(50.0).clip(true))
                    .column(Column::remainder().at_least(130.0).clip(true))
                    .header(header_height, |mut header| {
                        for column in TraceColumn::ALL {
                            header.col(|ui| {
                                let cell = ui.max_rect().expand2(egui::vec2(
                                    ui.spacing().item_spacing.x / 2.0,
                                    ui.spacing().item_spacing.y / 2.0,
                                ));
                                ui.painter().rect_filled(cell, 0.0, palette.raised);
                                ui.painter().hline(
                                    cell.x_range(),
                                    cell.bottom() - 0.5,
                                    egui::Stroke::new(1.0_f32, palette.line),
                                );
                                let sorted =
                                    self.trace_sort.filter(|(sorted, _)| *sorted == column);
                                let mut job = egui::text::LayoutJob::default();
                                job.append(
                                    column.title(),
                                    0.0,
                                    egui::TextFormat::simple(body_font.clone(), palette.text),
                                );
                                if let Some((_, descending)) = sorted {
                                    job.append(
                                        if descending {
                                            egui_phosphor::regular::CARET_DOWN
                                        } else {
                                            egui_phosphor::regular::CARET_UP
                                        },
                                        font * 0.3,
                                        egui::TextFormat::simple(body_font.clone(), palette.accent),
                                    );
                                }
                                let response = ui
                                    .add(
                                        egui::Label::new(job)
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(format!(
                                        "{}\nClick to sort by {}",
                                        column.description(),
                                        column.title()
                                    ));
                                if response.clicked() {
                                    // A new column sorts ascending; the same column flips.
                                    self.trace_sort = Some((
                                        column,
                                        sorted.is_some_and(|(_, descending)| !descending),
                                    ));
                                }
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(height, invocations.len(), |mut row| {
                            let index = row.index();
                            let invocation = &invocations[index];
                            let event =
                                trace::representative(invocation).expect("filtered observation");
                            let key = trace::key(invocation);
                            let selected = self.selected_event == Some(key);
                            let group = SyscallGroup::of(&event.syscall_name);
                            let fill = if selected {
                                Some(palette.selection)
                            } else {
                                group.filter(|_| trace_colors).and_then(theme::syscall_tint)
                            };
                            let hovered = hovered_row == Some(index) && !selected;
                            let result = invocation.exit.as_ref().and_then(|event| event.result);
                            let failed = result.is_some_and(values::is_error);
                            let cells = trace::cells(invocation);
                            for (column, (parts, hover)) in cells.into_iter().enumerate() {
                                row.col(|ui| {
                                    // Paint the cell and half of each gap so a tinted
                                    // row reads as one band, as in Wireshark.
                                    let cell = ui.max_rect().expand2(egui::vec2(
                                        ui.spacing().item_spacing.x / 2.0,
                                        ui.spacing().item_spacing.y / 2.0,
                                    ));
                                    if let Some(fill) = fill {
                                        ui.painter().rect_filled(cell, 0.0, fill);
                                    }
                                    if hovered {
                                        ui.painter().rect_filled(
                                            cell,
                                            0.0,
                                            if theme::is_light() {
                                                egui::Color32::from_black_alpha(14)
                                            } else {
                                                egui::Color32::from_rgba_unmultiplied(
                                                    255, 255, 255, 14,
                                                )
                                            },
                                        );
                                    }
                                    if selected {
                                        let stroke = egui::Stroke::new(1.0_f32, palette.accent);
                                        ui.painter().hline(
                                            cell.x_range(),
                                            cell.top() + 0.5,
                                            stroke,
                                        );
                                        ui.painter().hline(
                                            cell.x_range(),
                                            cell.bottom() - 0.5,
                                            stroke,
                                        );
                                    }
                                    if column == 0 && (failed || selected) {
                                        let mut bar = ui.max_rect().expand2(egui::vec2(
                                            0.0,
                                            ui.spacing().item_spacing.y / 2.0,
                                        ));
                                        bar.set_width(3.0);
                                        ui.painter().rect_filled(
                                            bar,
                                            0.0,
                                            if failed {
                                                palette.error
                                            } else {
                                                palette.accent
                                            },
                                        );
                                    }
                                    let font = if matches!(column, 4 | 6) {
                                        body_font.clone()
                                    } else {
                                        mono.clone()
                                    };
                                    let mut job = egui::text::LayoutJob::default();
                                    for (text, tone) in parts {
                                        job.append(
                                            &text,
                                            0.0,
                                            egui::TextFormat::simple(font.clone(), tone.color()),
                                        );
                                    }
                                    if column == 0 {
                                        // Clear of the failure and selection bar.
                                        ui.add_space(3.0);
                                    }
                                    ui.add(
                                        egui::Label::new(job)
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::hover()),
                                    )
                                    .on_hover_text(hover);
                                });
                            }
                            let response = row.response();
                            if response.hovered() {
                                response
                                    .ctx
                                    .data_mut(|data| data.insert_temp(hover_id, index));
                            }
                            if response.clicked() {
                                self.selected_event = Some(key);
                                self.inspector.clear();
                            }
                        });
                    });
            });
    }

    /// Category filter above the trace: one chip per syscall group (with
    /// its row count) shows or hides that group's rows, and "All" shows or
    /// hides every group; the chips wrap to a second line when narrow. The
    /// choice is saved with the settings; row colors are switched in Settings.
    fn trace_categories(&mut self, ui: &mut egui::Ui, invocations: &[InvocationSummary]) {
        let mut counts = std::collections::BTreeMap::<SyscallGroup, usize>::new();
        for invocation in invocations {
            if let Some(group) = trace::representative(invocation)
                .and_then(|event| SyscallGroup::of(&event.syscall_name))
            {
                *counts.entry(group).or_default() += 1;
            }
        }
        let hidden = &mut self.settings.hidden_trace_categories;
        // Chips wrap onto a second line instead of overflowing a narrow
        // panel; past two lines (large text) they scroll within those two.
        let roomy = !theme::is_compact();
        let chip_height =
            egui::TextStyle::Small.resolve(ui.style()).size + if roomy { 10.0 } else { 6.0 };
        egui::ScrollArea::vertical()
            .id_salt("trace_categories")
            .max_height(chip_height * 2.0 + if roomy { 8.0 } else { 5.0 })
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = if roomy {
                        egui::vec2(8.0, 6.0)
                    } else {
                        egui::vec2(5.0, 4.0)
                    };
                    ui.spacing_mut().button_padding = if roomy {
                        egui::vec2(10.0, 2.0)
                    } else {
                        egui::vec2(7.0, 1.0)
                    };
                    ui.spacing_mut().interact_size.y = chip_height;
                    let all_shown = hidden.is_empty();
                    let all = egui::Button::new(RichText::new("All").small().color(if all_shown {
                        theme::palette().primary_text
                    } else {
                        theme::text()
                    }))
                    .fill(if all_shown {
                        theme::primary()
                    } else {
                        theme::panel()
                    })
                    .stroke(egui::Stroke::new(1.0_f32, theme::line()))
                    .corner_radius(8.0);
                    if ui
                        .add(all)
                        .on_hover_text(if all_shown {
                            "Hide every category"
                        } else {
                            "Show every category"
                        })
                        .clicked()
                    {
                        if all_shown {
                            *hidden = SyscallGroup::ALL.to_vec();
                        } else {
                            hidden.clear();
                        }
                    }
                    for group in SyscallGroup::ALL {
                        let shown = !hidden.contains(&group);
                        let swatch = theme::syscall_tint(group).unwrap_or(theme::raised());
                        let count = counts.get(&group).copied().unwrap_or(0);
                        let text = RichText::new(format!("{} {count}", group.label()))
                            .small()
                            .color(if shown { theme::text() } else { theme::muted() });
                        let text = if shown { text } else { text.strikethrough() };
                        let border = if theme::is_light() {
                            swatch.gamma_multiply(0.8)
                        } else {
                            swatch.gamma_multiply(1.6)
                        };
                        let button = egui::Button::new(text)
                            .fill(if shown { swatch } else { theme::panel() })
                            .stroke(egui::Stroke::new(1.0_f32, border))
                            .corner_radius(8.0);
                        if ui
                            .add(button)
                            .on_hover_text(if shown {
                                "Click to hide these syscalls"
                            } else {
                                "Click to show these syscalls"
                            })
                            .clicked()
                        {
                            if shown {
                                hidden.push(group);
                            } else {
                                hidden.retain(|other| *other != group);
                            }
                        }
                    }
                })
            });
        if self.settings.hidden_trace_categories.len() == SyscallGroup::ALL.len() {
            ui.colored_label(
                theme::muted(),
                "All categories are hidden; click All to show them.",
            );
        }
    }

    /// The selected VM has no live trace (it is not running) and nothing
    /// is opened from its history.
    fn no_live_trace(&self) -> bool {
        self.selected.is_some()
            && self.snapshot.active_vm != self.selected
            && self.selected_run.is_none()
            && self.selected_capture.is_none()
            && self.trace_archive_directory().is_none()
    }

    /// The trace panel without a live trace: what to do, and the VM's latest
    /// runs and captures to open (as a double click in Run History does).
    fn empty_trace(&mut self, ui: &mut egui::Ui) {
        let Some(vm_id) = self.selected.clone() else {
            return;
        };
        // Run History lists one of runs and captures; ask for the other once.
        let asked_id = ui.id().with("empty_trace_lists");
        let asked = (vm_id.clone(), self.history_generation, self.capture_tab);
        if ui.data(|data| data.get_temp::<(String, u64, bool)>(asked_id)) != Some(asked.clone())
            && self.pending_archive.is_none()
        {
            let options = self.options.clone();
            let generation = self.history_generation;
            self.queue_archive(if self.capture_tab {
                Request::ListVm {
                    options,
                    vm_id: vm_id.clone(),
                    generation,
                }
            } else {
                Request::ListCaptures {
                    options,
                    vm_id: vm_id.clone(),
                    generation,
                }
            });
            ui.data_mut(|data| data.insert_temp(asked_id, asked));
        }
        let mut runs: Vec<RunSummary> = self
            .snapshot
            .runs
            .iter()
            .chain(&self.history)
            .filter(|run| run.vm_id == vm_id)
            .cloned()
            .collect();
        let mut seen = std::collections::HashSet::new();
        runs.retain(|run| seen.insert(run.id.clone()));
        let mut captures: Vec<CaptureSummary> = self
            .snapshot
            .captures
            .iter()
            .chain(&self.capture_history)
            .filter(|capture| capture.vm_id == vm_id)
            .cloned()
            .collect();
        seen.clear();
        captures.retain(|capture| seen.insert(capture.id.clone()));
        // Newest first, by when their recordings last changed.
        let times_id = ui.id().with("empty_trace_times");
        let mut times: BTreeMap<PathBuf, Option<SystemTime>> =
            ui.data(|data| data.get_temp(times_id)).unwrap_or_default();
        let mut time = |directory: &PathBuf| {
            *times.entry(directory.clone()).or_insert_with(|| {
                std::fs::metadata(directory)
                    .and_then(|metadata| metadata.modified())
                    .ok()
            })
        };
        runs.sort_by_cached_key(|run| std::cmp::Reverse(time(&run.directory)));
        captures.sort_by_cached_key(|capture| std::cmp::Reverse(time(&capture.directory)));
        ui.data_mut(|data| data.insert_temp(times_id, times));
        runs.truncate(6);
        captures.truncate(6);

        let mut open = None;
        egui::ScrollArea::vertical()
            .id_salt("empty_trace")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let width = ui.available_width().min(620.0);
                ui.add_space(((ui.available_height() - 360.0) / 3.0).clamp(12.0, 80.0));
                ui.horizontal(|ui| {
                    ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
                    ui.vertical(|ui| {
                        ui.set_width(width);
                        let size = self.settings.font_size;
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(egui_phosphor::regular::PULSE)
                                    .size(size * 2.0)
                                    .color(theme::muted()),
                            );
                            ui.vertical(|ui| {
                                ui.label(RichText::new("No live trace").size(size + 4.0));
                                ui.colored_label(
                                    theme::muted(),
                                    "Start the VM to trace programs as they run, or open a \
                                     recording.",
                                );
                            });
                        });
                        ui.add_space(8.0);
                        let stopped = self.snapshot.active_vm.is_none();
                        ui.horizontal_wrapped(|ui| {
                            if ui
                                .add_enabled(
                                    stopped && !self.closing,
                                    egui::Button::new(format!(
                                        "{} Start VM",
                                        egui_phosphor::regular::PLAY
                                    )),
                                )
                                .clicked()
                            {
                                open = Some(EmptyTraceAction::Start);
                            }
                            if !stopped {
                                ui.colored_label(
                                    theme::muted(),
                                    "Another VM is running; stop it first",
                                );
                            }
                        });
                        ui.add_space(12.0);
                        theme::section(ui, "Recent runs");
                        if runs.is_empty() {
                            ui.colored_label(theme::muted(), "No recorded runs yet");
                        }
                        for run in &runs {
                            let detail = format!(
                                "{}  \u{00b7}  {}",
                                run_status(run),
                                run.request.args.join(" ")
                            );
                            if recent_row(
                                ui,
                                egui_phosphor::regular::TERMINAL_WINDOW,
                                &run.request.path,
                                detail.trim_end_matches("  \u{00b7}  "),
                            )
                            .on_hover_text(format!(
                                "Open this run's recording in the trace\n{}",
                                run.directory.display()
                            ))
                            .clicked()
                            {
                                open = Some(EmptyTraceAction::Run(run.id.clone()));
                            }
                        }
                        ui.add_space(10.0);
                        theme::section(ui, "Recent captures");
                        if captures.is_empty() {
                            ui.colored_label(theme::muted(), "No captures yet");
                        }
                        for capture in &captures {
                            if recent_row(
                                ui,
                                egui_phosphor::regular::RECORD,
                                &captures::scope(&capture.scope),
                                captures::status(capture.state),
                            )
                            .on_hover_text(format!(
                                "Open this capture in the trace\n{}",
                                capture.directory.display()
                            ))
                            .clicked()
                            {
                                open = Some(EmptyTraceAction::Capture(capture.id.clone()));
                            }
                        }
                        ui.add_space(10.0);
                        ui.colored_label(
                            theme::muted(),
                            "Run History lists every run and capture of this VM.",
                        );
                    });
                });
            });
        match open {
            Some(EmptyTraceAction::Start) => self.new_run(),
            Some(EmptyTraceAction::Run(id)) => self.select_archive_run(id),
            Some(EmptyTraceAction::Capture(id)) => self.select_capture(id, true),
            None => {}
        }
    }

    fn details(&mut self, ui: &mut egui::Ui) {
        let invocations = self.invocations();
        let invocation = invocations
            .iter()
            .find(|invocation| Some(trace::key(invocation)) == self.selected_event);
        let directory = self.invocation_directory(invocation);
        let read = self.inspector.show(ui, invocation, directory.is_some());
        for request in std::mem::take(&mut self.inspector.open_data) {
            self.data_windows.open(ui.ctx(), request, directory.clone());
        }
        if let Some((field, offset, data_len)) = read {
            if let Some(directory) = directory {
                self.inspector.generation = self.inspector.generation.wrapping_add(1);
                let request = Request::Captured {
                    generation: self.inspector.generation,
                    directory,
                    field,
                    offset,
                    data_len,
                };
                self.queue_archive(request);
                self.inspector.pending = true;
            }
        }
    }

    fn invocation_directory(&self, invocation: Option<&InvocationSummary>) -> Option<PathBuf> {
        if let Some(capture) = self.selected_capture_summary() {
            return Some(capture.directory.clone());
        }
        if let Some(run) = self.offline_run() {
            return Some(run.directory.clone());
        }
        let invocation = invocation?;
        let root = invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
            .map(|event| event.root_task_cookie)
            .find(|root| *root != 0)
            .unwrap_or(0);
        if root == 0 {
            return self.snapshot.capture_dir.clone();
        }
        self.snapshot
            .runs
            .iter()
            .find(|run| run.root_task_cookie == root)
            .map(|run| run.directory.clone())
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        crate::evidence::dialogs(ctx);
        self.evidence_jobs.show(ctx);
        if self.vm_snapshots.open {
            let tree = self
                .vm_snapshots
                .vm_id
                .as_ref()
                .and_then(|id| self.snapshot.vm_snapshot_trees.get(id));
            let progress = self
                .snapshot
                .vm_snapshot_progress
                .as_ref()
                .filter(|progress| self.vm_snapshots.vm_id.as_deref() == Some(&progress.vm_id));
            if let Some(command) = self.vm_snapshots.show(ctx, tree, progress, !self.closing) {
                self.send(command);
            }
        }
        if self.import_open {
            let mut open = true;
            let mut import = false;
            let mut cancel = false;
            egui::Window::new("Import base")
                .id(Dialog::Import.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    dialog_section(ui, "Base folder");
                    ui.label(
                        RichText::new(
                            "A built base: the folder holds bundle.json, the kernel and base.qcow2.",
                        )
                        .color(theme::muted()),
                    );
                    ui.horizontal(|ui| {
                        ui.add(
                            // A fixed width: "all available" would grow the
                            // window every frame.
                            text_field(&mut self.import_directory)
                                .desired_width(560.0)
                                .font(egui::TextStyle::Monospace)
                                .hint_text(RichText::new("Bundle directory").color(theme::muted())),
                        );
                        if icon(
                            ui,
                            egui_phosphor::regular::FOLDER_OPEN,
                            "Choose bundle directory",
                            self.folder_picker.available(),
                        ) {
                            if let Err(error) = self.folder_picker.choose(FolderTarget {
                                generation: 0,
                                kind: FolderKind::BaseImport,
                            }) {
                                self.status = error;
                            }
                        }
                    });
                    dialog_footer(ui, |ui| {
                        import = ui
                            .add_enabled(
                                self.snapshot.active_vm.is_none()
                                    && !self.import_directory.trim().is_empty(),
                                primary_button("Import"),
                            )
                            .on_disabled_hover_text("Choose a folder; stop the running VM first")
                            .clicked();
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            self.import_open = open && !cancel;
            if import {
                self.send(Command::ImportBase {
                    directory: crate::folders::user_path(&self.import_directory),
                });
                self.import_open = false;
            }
        }
        if self.download_open {
            let mut open = true;
            if let Some(command) = self.download_window(ctx, &mut open) {
                self.send(command);
            }
            self.download_open = open;
        }
        if self.tools_open {
            let mut open = true;
            if let Some(command) = crate::tools_window::show(
                ctx,
                &mut open,
                &self.snapshot.analysis_tools,
                self.snapshot.tool_install.as_ref(),
                !self.closing,
            ) {
                self.send(command);
            }
            self.tools_open = open;
        }
        if self.samples.open {
            let vm = self.selected_vm().cloned();
            let action = self.samples.show(
                ctx,
                &crate::samples_view::SamplesContext {
                    data_dir: &self.options.data_dir,
                    curl: &self.options.curl,
                    running: self.running(),
                    vm_name: vm.as_ref().map(|vm| vm.name.as_str()),
                    nat: vm.as_ref().is_some_and(|vm| vm.nat),
                    font_size: self.settings.font_size,
                },
            );
            if let Some(crate::samples_view::SamplesAction::Push {
                sha256,
                destination,
                ..
            }) = action
            {
                self.send(Command::UploadSample {
                    sha256,
                    destination,
                    executable: true,
                });
            }
        }
        if self.about_open {
            let mut open = true;
            egui::Window::new("About Antinomie")
                .id(Dialog::About.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(format!("Antinomie {APP_VERSION}"))
                            .size(ui.text_style_height(&egui::TextStyle::Heading))
                            .color(theme::heading()),
                    );
                    ui.label("Run programs in a QEMU VM and record every system call they make.");
                    dialog_section(ui, "Versions");
                    form_grid("about", ui).show(ui, |ui| {
                        ui.label(RichText::new("Guest kernel").color(theme::muted()));
                        ui.label("Linux 6.12.94 (Debian 6.12.94-1 source)");
                        ui.end_row();
                        ui.label(RichText::new("Bases").color(theme::muted()));
                        ui.label(format!(
                            "{} or newer",
                            RevisionStatus::describe(Some(APP_REVISION), None)
                        ));
                        ui.end_row();
                    });
                });
            self.about_open = open;
        }
        crate::query::guide(ctx);
        if self.build_open {
            let mut open = true;
            let build = self.snapshot.build.clone();
            let mut action = None;
            egui::Window::new("Build base")
                .id(Dialog::Build.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_size([900.0, 640.0])
                .min_size([720.0, 480.0])
                .show(ctx, |ui| {
                    action = self
                        .build_wizard
                        .show(ui, build.as_ref(), &self.options.data_dir);
                });
            self.build_open = open;
            match action {
                Some(build_wizard::Action::Build(request)) => {
                    self.send(Command::BuildBase { request: *request })
                }
                Some(build_wizard::Action::Cancel) => self.send(Command::CancelBuild),
                None => {}
            }
        }
        if let Some((vm_id, duplicate, name)) = &mut self.name_action {
            let mut open = true;
            let mut save = false;
            let mut cancel = false;
            egui::Window::new(if *duplicate { "Duplicate VM" } else { "Rename VM" })
                .id(Dialog::Name.window_id())
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    form_grid("name_action_form", ui).show(ui, |ui| {
                        ui.label(if *duplicate { "New name" } else { "Name" });
                        let edit = ui.add(text_field(name).desired_width(300.0));
                        if edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter)) {
                            save = true;
                        }
                        ui.end_row();
                    });
                    if *duplicate {
                        ui.label(
                            RichText::new(
                                "Copies the current disk with a new VM identity. Run history remains with the source VM.",
                            )
                            .color(theme::muted()),
                        );
                    }
                    let allowed = !name.trim().is_empty()
                        && (!*duplicate || self.snapshot.active_vm.as_ref() != Some(vm_id));
                    dialog_footer(ui, |ui| {
                        save = ui
                            .add_enabled(
                                allowed,
                                primary_button(if *duplicate { "Duplicate" } else { "Rename" }),
                            )
                            .clicked()
                            || (save && allowed);
                        cancel = ui.button("Cancel").clicked();
                    });
                });
            if save {
                if let Some((vm_id, duplicate, name)) = self.name_action.take() {
                    self.send(if duplicate {
                        Command::Duplicate { vm_id, name }
                    } else {
                        Command::Rename { vm_id, name }
                    });
                }
            } else if !open || cancel {
                self.name_action = None;
            }
        }
        if self.create_open || self.config_open {
            self.vm_dialog(ctx);
        }
        if self.launch_open {
            let mut open = true;
            let viewport = ctx.screen_rect();
            let width = 1000.0_f32.min((viewport.width() - 50.0).max(300.0));
            egui::Window::new("Run program")
                .id(Dialog::Launch.window_id())
                .open(&mut open)
                .collapsible(false)
                .movable(true)
                .resizable(true)
                .default_width(width)
                .default_height((ctx.screen_rect().height() - 100.0).max(240.0))
                .default_pos(egui::pos2(
                    viewport.center().x - width * 0.5,
                    viewport.top() + 32.0,
                ))
                .max_width((ctx.screen_rect().width() - 50.0).max(300.0))
                .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    self.launch_form(ui);
                });
            self.launch_open &= open;
        }
        if self.upload_open {
            let mut open = true;
            egui::Window::new("Upload file")
                .id(Dialog::Upload.window_id())
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_width(660.0)
                .default_height(0.0)
                .max_width((ctx.screen_rect().width() - 50.0).max(300.0))
                .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    scroll_dialog(ui, ctx, |ui| {
                        self.upload_form(ui);
                    });
                });
            if !open {
                self.close_upload();
            }
        }
        if self.settings_open {
            self.settings_window(ctx);
        }
        if let Some(confirm) = &self.confirm {
            let (title, text, button, destructive) = match confirm {
                Confirm::Reset(_) => (
                    "Reset disk",
                    "Reset this VM's disk to the base image? All VM disk changes will be lost.",
                    "Reset disk",
                    true,
                ),
                Confirm::Delete(_) => (
                    "Delete VM",
                    "Delete this VM configuration, disk and all snapshots? All saved disk layers and memory states will be lost. Retained run recordings and terminal history are preserved.",
                    "Delete VM",
                    true,
                ),
                Confirm::DeleteBase(_) => (
                    "Delete base",
                    "Delete this base image? This cannot be undone. VMs that reference it must be deleted first.",
                    "Delete base",
                    true,
                ),
                Confirm::Upload(_) => (
                    "Overwrite file",
                    "Overwrite the chosen guest path with this host file?",
                    "Overwrite",
                    true,
                ),
                Confirm::Nat { .. } => (
                    "Enable NAT",
                    "Enable NAT? The guest can connect to the host network and Internet.",
                    "Enable NAT",
                    false,
                ),
            };
            let mut yes = false;
            let mut cancel = false;
            let modal = egui::Modal::new(Dialog::Confirm.window_id()).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(egui_phosphor::regular::WARNING)
                            .size(ui.text_style_height(&egui::TextStyle::Heading))
                            .color(if destructive {
                                theme::error()
                            } else {
                                theme::warn()
                            }),
                    );
                    ui.label(
                        RichText::new(title)
                            .size(ui.text_style_height(&egui::TextStyle::Heading))
                            .color(theme::heading()),
                    );
                });
                ui.add_space(4.0);
                ui.label(text);
                let enabled = !self.closing
                    && match confirm {
                        Confirm::Reset(_) | Confirm::Delete(_) | Confirm::DeleteBase(_) => {
                            self.snapshot.active_vm.is_none()
                        }
                        Confirm::Upload(intent) => {
                            intent.same_session(&self.snapshot)
                                && self.snapshot.state == VmState::Running
                                && self.pending_upload.is_none()
                        }
                        Confirm::Nat { vm, creating } => {
                            if *creating {
                                self.snapshot.active_vm.is_none()
                            } else {
                                self.snapshot.active_vm.as_ref() != Some(&vm.id)
                            }
                        }
                    };
                dialog_footer(ui, |ui| {
                    yes = ui
                        .add_enabled(
                            enabled,
                            if destructive {
                                danger_button(button)
                            } else {
                                primary_button(button)
                            },
                        )
                        .clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
            // A click beside the dialog cancels it; Escape is handled with
            // the other dialogs.
            cancel |= modal.backdrop_response.clicked();
            if yes {
                if let Some(confirm) = self.confirm.take() {
                    match confirm {
                        Confirm::Reset(vm_id) => self.send(Command::Reset {
                            vm_id,
                            confirmed: true,
                        }),
                        Confirm::Delete(vm_id) => self.send(Command::Delete {
                            vm_id,
                            confirmed: true,
                        }),
                        Confirm::DeleteBase(identity) => self.send(Command::DeleteBase {
                            identity,
                            confirmed: true,
                        }),
                        Confirm::Upload(intent) => self.submit_upload(intent, true),
                        Confirm::Nat { mut vm, creating } => {
                            vm.nat = true;
                            vm.isolated_network = false;
                            if self.draft.id == vm.id {
                                self.draft.nat = true;
                                self.draft.isolated_network = false;
                            }
                            if !creating {
                                if let Err(error) = self.save_vm(vm) {
                                    self.status = error;
                                }
                            }
                        }
                    }
                }
            }
            if cancel {
                self.confirm = None;
            }
        }
    }

    /// New VM / VM configuration: the machine, display and emulation on the
    /// left; storage, the guest account and networking on the right (one
    /// column on a narrow screen). The buttons stay below the form.
    fn vm_dialog(&mut self, ctx: &egui::Context) {
        let creating = self.create_open;
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let mut reset = false;
        let mut delete = false;
        let mut nat = false;
        let mut credentials_required = false;
        let label_width = form_label_width(ctx);
        let column = label_width + 340.0;
        let screen = ctx.screen_rect();
        let wide = screen.width() - 60.0 >= column * 2.0 + 24.0;
        let width = if wide {
            column * 2.0 + 24.0
        } else {
            column.min(screen.width() - 60.0)
        };
        egui::Window::new(if creating {
            "New VM"
        } else {
            "VM configuration"
        })
        .id(Dialog::Vm.window_id())
        .collapsible(false)
        .resizable(false)
        .default_width(width)
        .default_height(0.0)
        .max_height((screen.height() - 90.0).max(200.0))
        .open(&mut open)
        .show(ctx, |ui| {
            ui.set_width(width);
            let editable = if creating {
                self.snapshot.active_vm.is_none()
            } else {
                self.snapshot.active_vm.as_ref() != Some(&self.draft.id)
                    && self.snapshot.vms.iter().any(|vm| vm.id == self.draft.id)
            };
            let disk_default = if creating {
                self.options.data_dir.clone()
            } else {
                self.snapshot
                    .vm_locations
                    .iter()
                    .find(|location| location.vm_id == self.draft.id)
                    .and_then(|location| location.disk_directory.parent())
                    .unwrap_or(&self.options.data_dir)
                    .to_path_buf()
            };
            // Measure against the viewport, not last frame's window size,
            // so the window takes its full height at once.
            let height = (screen.height() - 110.0).max(150.0);
            ui.set_max_height(height);
            let footer = ui.spacing().interact_size.y * 3.0 + 40.0;
            egui::ScrollArea::vertical()
                .id_salt("vm_dialog_form")
                .max_height((height - footer).max(120.0))
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add_enabled_ui(editable, |ui| {
                        let machine = |app: &mut Self, ui: &mut egui::Ui, credentials_required: &mut bool| {
                            dialog_section(ui, "Machine");
                            form_grid("vm_machine", ui).show(ui, |ui| {
                                let old_base = app.draft.base_identity.clone();
                                ui.label("Installed base");
                                base_selector(ui, &app.snapshot, &mut app.draft.base_identity, "vm_base");
                                ui.end_row();
                                if old_base != app.draft.base_identity {
                                    app.credentials.reset();
                                }
                                let base = app
                                    .snapshot
                                    .bases
                                    .iter()
                                    .find(|base| Some(&base.id) == app.draft.base_identity.as_ref());
                                let min_ram = base.map_or(256, |base| base.min_ram_mib);
                                let min_disk = base.map_or(1, |base| base.min_disk_gib);
                                *credentials_required = creating
                                    && base
                                        .and_then(|base| base.guest.as_ref())
                                        .is_some_and(|guest| guest.requires_credentials);
                                app.draft.ram_mib = app.draft.ram_mib.max(min_ram);
                                if creating {
                                    app.draft.disk_gib = app.draft.disk_gib.max(min_disk);
                                }
                                ui.label("Name");
                                ui.add(text_field(&mut app.draft.name).desired_width(280.0));
                                ui.end_row();
                                ui.label("CPU count");
                                ui.add(egui::DragValue::new(&mut app.draft.cpus).range(1..=64));
                                ui.end_row();
                                ui.label("RAM");
                                ui.add(
                                    egui::DragValue::new(&mut app.draft.ram_mib)
                                        .range(min_ram..=antinomie_monitor_core::storage::MAX_RAM_MIB)
                                        .suffix(" MiB"),
                                )
                                .on_hover_text(format!("At least {min_ram} MiB for this base"));
                                ui.end_row();
                                ui.label("Disk");
                                if creating {
                                    ui.add(
                                        egui::DragValue::new(&mut app.draft.disk_gib)
                                            .range(min_disk..=2048)
                                            .suffix(" GiB"),
                                    )
                                    .on_hover_text(format!("At least {min_disk} GiB for this base"));
                                } else {
                                    ui.label(
                                        RichText::new(format!("{} GiB", app.draft.disk_gib))
                                            .monospace(),
                                    )
                                    .on_hover_text("Set when the VM was created");
                                }
                                ui.end_row();
                            });
                            dialog_section(ui, "Display and emulation");
                            form_grid("vm_display", ui).show(ui, |ui| {
                                launch_options(ui, &mut app.draft.launch);
                            });
                        };
                        let storage = |app: &mut Self, ui: &mut egui::Ui, credentials_required: bool, nat: &mut bool| {
                            dialog_section(ui, "Storage");
                            form_grid("vm_storage", ui).show(ui, |ui| {
                                ui.label("Disk parent");
                                ui.add_enabled_ui(creating, |ui| {
                                    directory_input(
                                        ui,
                                        &mut app.draft.disk_root,
                                        &disk_default,
                                        &mut app.folder_picker,
                                        FolderTarget {
                                            generation: app.draft_generation,
                                            kind: FolderKind::Disk,
                                        },
                                        &mut app.status,
                                    );
                                });
                                ui.end_row();
                                ui.label("Recording parent");
                                let recording_default = if creating {
                                    app.draft.disk_root.as_ref().unwrap_or(&disk_default)
                                } else {
                                    &disk_default
                                }
                                .clone();
                                directory_input(
                                    ui,
                                    &mut app.draft.recording_root,
                                    &recording_default,
                                    &mut app.folder_picker,
                                    FolderTarget {
                                        generation: app.draft_generation,
                                        kind: FolderKind::Recording,
                                    },
                                    &mut app.status,
                                );
                                ui.end_row();
                            });
                            if !creating {
                                if let Some(location) = app
                                    .snapshot
                                    .vm_locations
                                    .iter()
                                    .find(|location| location.vm_id == app.draft.id)
                                {
                                    for (name, path) in [
                                        ("Disk", &location.disk_directory),
                                        ("Recordings", &location.recording_directory),
                                    ] {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(name).color(theme::muted()));
                                            ui.add(
                                                egui::Label::new(
                                                    RichText::new(path.display().to_string())
                                                        .monospace(),
                                                )
                                                .truncate(),
                                            )
                                            .on_hover_text(path.display().to_string());
                                        });
                                    }
                                }
                                ui.label(
                                    RichText::new(
                                        "Recording parent changes apply to future recordings. Earlier recordings are retained.",
                                    )
                                    .small()
                                    .color(theme::muted()),
                                );
                            }
                            if credentials_required {
                                dialog_section(ui, "Guest account");
                                form_grid("vm_account", ui).show(ui, |ui| {
                                    ui.label("Username");
                                    ui.add(
                                        text_field(&mut app.credentials.username)
                                            .char_limit(32)
                                            .desired_width(280.0),
                                    );
                                    ui.end_row();
                                    ui.label("Password");
                                    password_input(ui, &mut app.credentials.password, "guest_password");
                                    ui.end_row();
                                    ui.label("Confirm password");
                                    password_input(
                                        ui,
                                        &mut app.credentials.confirmation,
                                        "guest_confirmation",
                                    );
                                    ui.end_row();
                                });
                            }
                            dialog_section(ui, "Network and telemetry");
                            form_grid("vm_network", ui).show(ui, |ui| {
                                ui.label("Network");
                                let mut mode = if app.draft.isolated_network { 1 } else if app.draft.nat { 2 } else { 0 };
                                let previous = mode;
                                egui::ComboBox::from_id_salt("network-mode").selected_text(["Disconnected", "Isolated", "NAT (Internet)"][mode])
                                    .show_ui(ui, |ui| { for (value, label) in ["Disconnected", "Isolated", "NAT (Internet)"].iter().enumerate() {
                                        ui.selectable_value(&mut mode, value, *label);
                                    } });
                                if mode != previous {
                                    app.draft.nat = false;
                                    app.draft.isolated_network = mode == 1;
                                    if mode == 2 { *nat = true; }
                                }
                                ui.end_row();
                                ui.label("Transport");
                                if ui
                                    .button("Telemetry transport…")
                                    .on_hover_text(
                                        "Guest buffers, never-drop mode and the host event table",
                                    )
                                    .clicked()
                                {
                                    app.transport_open = !app.transport_open;
                                }
                                ui.end_row();
                            });
                            if app.draft.isolated_network {
                                ui.colored_label(theme::muted(), "Working interface with host/LAN/Internet forwarding blocked. Packet capture remains available.");
                            }
                            if app.draft.nat {
                                ui.colored_label(
                                    theme::warn(),
                                    "NAT permits guest access to the host network and Internet.",
                                );
                            }
                        };
                        if wide {
                            ui.columns(2, |columns| {
                                machine(self, &mut columns[0], &mut credentials_required);
                                storage(self, &mut columns[1], credentials_required, &mut nat);
                            });
                        } else {
                            machine(self, ui, &mut credentials_required);
                            storage(self, ui, credentials_required, &mut nat);
                        }
                    });
                });
            let form_error = if creating {
                self.create_validation_error(credentials_required)
            } else {
                self.save_validation_error(&self.draft)
            };
            ui.separator();
            // Above the buttons, so it stays in view.
            if let Some(error) = &form_error {
                ui.add(egui::Label::new(RichText::new(error).color(theme::warn())).wrap());
            }
            ui.horizontal(|ui| {
                save = ui
                    .add_enabled(
                        editable && form_error.is_none(),
                        primary_button(if creating {
                            "Create VM"
                        } else {
                            "Save configuration"
                        }),
                    )
                    .clicked();
                cancel = ui.button("Cancel").clicked();
                if !creating {
                    ui.separator();
                    let stopped = self.snapshot.active_vm.is_none();
                    reset = ui
                        .add_enabled(stopped, danger_text_button("Reset disk…"))
                        .on_hover_text("Reset disk to base")
                        .clicked();
                    delete = ui
                        .add_enabled(stopped, danger_text_button("Delete VM…"))
                        .on_hover_text("Delete VM and disk")
                        .clicked();
                }
            });
        });
        if self.transport_open && open && !cancel {
            let tunable = self
                .snapshot
                .bases
                .iter()
                .find(|base| Some(&base.id) == self.draft.base_identity.as_ref())
                .is_some_and(|base| base.revision.is_some_and(|revision| revision >= 13));
            let editable = creating || self.snapshot.active_vm.as_ref() != Some(&self.draft.id);
            transport_window(
                ctx,
                &mut self.transport_open,
                &mut self.draft.transport,
                self.draft.cpus,
                tunable,
                editable,
            );
        }
        let open = open && !cancel;
        if !open {
            self.transport_open = false;
        }
        self.create_open = creating && open;
        self.config_open = !creating && open;
        if !open {
            self.credentials.reset();
        }
        if nat {
            self.confirm = Some(Confirm::Nat {
                vm: self.draft.clone(),
                creating,
            });
        }
        if reset {
            self.confirm = Some(Confirm::Reset(self.draft.id.clone()));
        }
        if delete {
            self.confirm = Some(Confirm::Delete(self.draft.id.clone()));
        }
        if save {
            if creating {
                if let Err(error) = self.create_vm() {
                    self.status = error;
                    return;
                }
            } else if let Err(error) = self.save_vm(self.draft.clone()) {
                self.status = error;
                return;
            }
            self.create_open = false;
            self.config_open = false;
        }
    }

    /// Settings: appearance (applies at once) and recording (applies on
    /// Save).
    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        egui::Window::new("Settings")
            .id(Dialog::Settings.window_id())
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(520.0)
            .default_height(0.0)
            .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
            .show(ctx, |ui| {
                scroll_dialog(ui, ctx, |ui| {
                    dialog_section(ui, "Appearance");
                    form_grid("settings_appearance", ui).show(ui, |ui| {
                        ui.label("Theme");
                        ui.horizontal(|ui| {
                            let before = self.settings.light_theme;
                            ui.selectable_value(&mut self.settings.light_theme, false, "Dark");
                            ui.selectable_value(&mut self.settings.light_theme, true, "Light");
                            if self.settings.light_theme != before {
                                theme::apply(ctx, self.settings.light_theme);
                                theme::text_size(ctx, self.settings.font_size);
                            }
                        });
                        ui.end_row();
                        ui.label("Text size");
                        let before = self.settings.font_size;
                        text_size_control(ui, &mut self.settings.font_size);
                        if self.settings.font_size != before {
                            theme::text_size(ctx, self.settings.font_size);
                            for terminal in self.terminals.values_mut() {
                                terminal.terminal.invalidate_resize();
                            }
                        }
                        ui.end_row();
                        ui.label("Density");
                        ui.horizontal(|ui| {
                            let before = self.settings.compact;
                            ui.selectable_value(&mut self.settings.compact, true, "Compact")
                                .on_hover_text("Tight rows and spacing: more on screen");
                            ui.selectable_value(&mut self.settings.compact, false, "Comfortable")
                                .on_hover_text(
                                    "Taller rows, roomier spacing and margins everywhere",
                                );
                            if self.settings.compact != before {
                                theme::set_compact(ctx, self.settings.compact);
                            }
                        });
                        ui.end_row();
                        ui.label("Trace colors");
                        ui.checkbox(
                            &mut self.settings.trace_colors,
                            "Color syscall rows by category",
                        )
                        .on_hover_text(
                            "Tint each syscall by its category, like Wireshark's coloring rules",
                        );
                        ui.end_row();
                    });
                    ui.label(
                        RichText::new("Appearance changes apply at once.")
                            .small()
                            .color(theme::muted()),
                    );
                    dialog_section(ui, "Recording");
                    ui.add_enabled_ui(self.snapshot.active_vm.is_none(), |ui| {
                        form_grid("settings_recording", ui).show(ui, |ui| {
                            ui.label("Installed base");
                            let mut base = self
                                .snapshot
                                .bases
                                .iter()
                                .find(|base| {
                                    base.directory == std::path::Path::new(&self.settings.bundle)
                                })
                                .or_else(|| {
                                    preferred_new_base(&self.snapshot, &self.settings.bundle)
                                })
                                .map(|base| base.id.clone());
                            base_selector(ui, &self.snapshot, &mut base, "settings_base");
                            if let Some(base) = base.and_then(|id| {
                                self.snapshot.bases.iter().find(|base| base.id == id)
                            }) {
                                self.settings.bundle =
                                    base.directory.to_string_lossy().into_owned();
                            }
                            ui.end_row();
                            ui.label("Recording quota");
                            ui.add(
                                egui::DragValue::new(&mut self.settings.quota_gib)
                                    .range(1..=4096)
                                    .suffix(" GiB"),
                            );
                            ui.end_row();
                            ui.label("Shutdown timeout");
                            ui.add(
                                egui::DragValue::new(&mut self.settings.timeout)
                                    .range(1..=120)
                                    .suffix(" s"),
                            );
                            ui.end_row();
                            if let Some(path) = &self.snapshot.capture_dir {
                                ui.label("Recording");
                                ui.add(
                                    egui::Label::new(
                                        RichText::new(path.display().to_string()).monospace(),
                                    )
                                    .truncate(),
                                )
                                .on_hover_text(path.display().to_string());
                                ui.end_row();
                            }
                        });
                    });
                    if self.snapshot.active_vm.is_some() {
                        ui.colored_label(theme::warn(), "Stop the running VM to change these.");
                    }
                    dialog_footer(ui, |ui| {
                        save = ui
                            .add_enabled(
                                self.snapshot.active_vm.is_none(),
                                primary_button("Save settings"),
                            )
                            .clicked();
                        cancel = ui.button("Close").clicked();
                    });
                });
            });
        self.settings_open = open && !cancel;
        if save {
            self.update_options();
            self.settings_open = false;
        }
    }

    fn dialog_open(&self, dialog: Dialog) -> bool {
        match dialog {
            Dialog::Confirm => self.confirm.is_some(),
            Dialog::Name => self.name_action.is_some(),
            Dialog::Transport => self.transport_open && (self.create_open || self.config_open),
            Dialog::Vm => self.create_open || self.config_open,
            Dialog::Launch => self.launch_open,
            Dialog::Upload => self.upload_open,
            Dialog::Settings => self.settings_open,
            Dialog::Import => self.import_open,
            Dialog::Download => self.download_open,
            Dialog::Tools => self.tools_open,
            Dialog::Samples => self.samples.open,
            Dialog::Snapshots => self.vm_snapshots.open,
            Dialog::SnapshotDecision => self.vm_snapshots.decision_open(),
            Dialog::Dependencies => self.dependencies.open,
            Dialog::About => self.about_open,
            Dialog::Build => self.build_open,
            Dialog::Attach => self.process_picker.open,
        }
    }

    fn close_dialog(&mut self, dialog: Dialog) {
        match dialog {
            Dialog::Confirm => self.confirm = None,
            Dialog::Name => self.name_action = None,
            Dialog::Transport => self.transport_open = false,
            Dialog::Vm => {
                self.create_open = false;
                self.config_open = false;
                self.transport_open = false;
                self.credentials.reset();
            }
            Dialog::Launch => self.launch_open = false,
            Dialog::Upload => self.close_upload(),
            Dialog::Settings => self.settings_open = false,
            Dialog::Import => self.import_open = false,
            Dialog::Download => self.download_open = false,
            Dialog::Tools => self.tools_open = false,
            Dialog::Samples => self.samples.open = false,
            Dialog::Snapshots | Dialog::SnapshotDecision => self.vm_snapshots.close(),
            Dialog::Dependencies => self.dependencies.open = false,
            Dialog::About => self.about_open = false,
            Dialog::Build => self.build_open = false,
            Dialog::Attach => self.process_picker.open = false,
        }
    }

    /// The open dialog on top: the confirmation (modal), else the window
    /// raised last. A window not drawn yet was opened this frame, so it is
    /// on top.
    fn topmost_dialog(&self, ctx: &egui::Context) -> Option<Dialog> {
        if self.confirm.is_some() {
            return Some(Dialog::Confirm);
        }
        let order: Vec<egui::Id> =
            ctx.memory(|memory| memory.layer_ids().map(|layer| layer.id).collect());
        Dialog::ALL
            .into_iter()
            .filter(|dialog| self.dialog_open(*dialog))
            .max_by_key(|dialog| {
                order
                    .iter()
                    .position(|id| *id == dialog.window_id())
                    .unwrap_or(usize::MAX)
            })
    }

    /// Escape closes the topmost dialog. An open popup (a combo box list,
    /// a menu) takes the key first, and so does a widget that keeps the
    /// keyboard (a terminal).
    fn escape(&mut self, ctx: &egui::Context) {
        if !ctx.input(|input| input.key_pressed(egui::Key::Escape))
            || ctx.memory(|memory| memory.any_popup_open() || memory.focused().is_some())
        {
            return;
        }
        if let Some(dialog) = self.topmost_dialog(ctx) {
            ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape));
            self.close_dialog(dialog);
        }
    }

    fn draw(&mut self, ctx: &egui::Context) {
        self.escape(ctx);
        self.shortcuts(ctx);
        self.dependencies.show(ctx, &self.options);
        self.menus(ctx);
        self.toolbar(ctx);
        self.health(ctx);
        self.sidebar(ctx);
        let mut layout = std::mem::take(&mut self.layout);
        if let Some(panel) = self.focus_panel.take() {
            layout.focus(panel);
        }
        layout.show(self, ctx);
        self.layout = layout;
        self.dialogs(ctx);
        self.data_windows.show(ctx);
        let enabled = if self.process_picker.purpose == captures::ProcessPurpose::Core {
            self.manual_core_unavailable().is_none()
        } else {
            self.observer_start_enabled()
        };
        if self
            .process_picker
            .selected
            .as_ref()
            .is_some_and(|identity| self.snapshot.boot_id.as_ref() != Some(&identity.boot_id))
        {
            self.process_picker.selected = None;
        }
        let page = self
            .snapshot
            .process_page
            .as_ref()
            .filter(|page| self.snapshot.boot_id.as_ref() == Some(&page.boot_id));
        if let Some(action) = self
            .process_picker
            .show(ctx, page, enabled, self.settings.font_size)
        {
            match action {
                captures::ProcessAction::Refresh(after_pid) => {
                    self.send(Command::ListProcesses { after_pid })
                }
                captures::ProcessAction::Attach(identity) => {
                    if self.snapshot.boot_id.as_ref() == Some(&identity.boot_id) && enabled {
                        self.process_picker.open = false;
                        self.send(Command::AttachProcess { identity });
                    }
                }
                captures::ProcessAction::DumpCore(identity) => {
                    if self.snapshot.boot_id.as_ref() == Some(&identity.boot_id)
                        && self.manual_core_unavailable().is_none()
                    {
                        if let Some(vm_id) = self.snapshot.active_vm.clone() {
                            self.process_picker.open = false;
                            self.send(Command::DumpProcessCore {
                                request: ProcessCoreRequest {
                                    vm_id,
                                    target: identity,
                                    ..ProcessCoreRequest::default()
                                },
                            });
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn terminal_views(&self) -> Vec<(String, bool)> {
        self.terminals
            .iter()
            .map(|(id, terminal)| (id.clone(), terminal.open))
            .collect()
    }

    pub(crate) fn close_terminal_view(&mut self, id: &str) {
        if let Some(terminal) = self.terminals.get_mut(id) {
            terminal.close_view();
        }
    }

    fn analysis_report(&self, id: &str) -> Option<&antinomie_monitor_core::AnalysisReport> {
        self.snapshot
            .runs
            .iter()
            .chain(&self.history)
            .filter_map(|run| run.analysis.as_ref())
            .chain(&self.snapshot.analysis_reports)
            .find(|report| report.id == id)
            .or_else(|| self.analysis_windows.get(id))
    }

    fn refresh_analysis_windows(&mut self) {
        for (id, current) in &mut self.analysis_windows {
            if let Some(report) = self
                .snapshot
                .runs
                .iter()
                .chain(&self.history)
                .filter_map(|run| run.analysis.as_ref())
                .chain(&self.snapshot.analysis_reports)
                .find(|report| &report.id == id)
            {
                if current != report {
                    current.clone_from(report);
                }
            }
        }
    }

    fn fail_analysis_read(&mut self, view_key: &str, generation: u64, reason: &str) {
        if let Some(view) = self.analysis_views.get_mut(view_key) {
            if view.pending.is_some_and(|ticket| ticket.0 == generation) {
                view.pending = None;
                view.preview = Some(Err(reason.into()));
            }
        }
    }

    fn analysis_labels(
        &self,
        ui: &egui::Ui,
        report: &antinomie_monitor_core::AnalysisReport,
    ) -> (String, String, String, Vec<String>) {
        let annotation = self
            .analysis_directory(&report.id)
            .and_then(|directory| crate::evidence::annotation(ui, &directory))
            .unwrap_or_else(|| antinomie_monitor_core::annotations::Annotation {
                name: String::new(),
                tags: Vec::new(),
            });
        (
            report.id.clone(),
            annotation.name,
            report.source_path.clone(),
            annotation.tags,
        )
    }

    fn analysis_identities(&self, report_id: &str) -> Vec<(&'static str, crate::query::RowValue)> {
        use crate::query::RowValue as V;
        self.snapshot
            .runs
            .iter()
            .chain(&self.history)
            .find(|run| {
                run.analysis
                    .as_ref()
                    .is_some_and(|report| report.id == report_id)
            })
            .map_or_else(Vec::new, |run| {
                vec![
                    ("vm.id", V::Text(run.vm_id.clone())),
                    ("boot.id", V::Text(run.boot_id.clone())),
                    ("run.id", V::Text(run.id.clone())),
                ]
            })
    }

    fn analysis_directory(&self, report_id: &str) -> Option<PathBuf> {
        if let Some(run) = self.snapshot.runs.iter().chain(&self.history).find(|run| {
            run.analysis
                .as_ref()
                .is_some_and(|report| report.id == report_id)
        }) {
            return Some(run.directory.join("analysis"));
        }
        if let Some(directory) = self.analysis_directories.get(report_id) {
            return Some(directory.clone());
        }
        if report_id.is_empty()
            || !report_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || !self
                .snapshot
                .analysis_reports
                .iter()
                .any(|report| report.id == report_id)
        {
            return None;
        }
        let vm_id = self
            .snapshot
            .active_vm
            .as_ref()
            .or(self.selected.as_ref())?;
        self.snapshot
            .vm_locations
            .iter()
            .find(|location| &location.vm_id == vm_id)
            .map(|location| {
                location
                    .recording_directory
                    .join("analyses")
                    .join(report_id)
            })
    }

    fn analysis_action(&mut self, view_key: &str, action: Option<crate::analysis::ReportAction>) {
        match action {
            Some(crate::analysis::ReportAction::Export {
                report_id,
                kind,
                format,
            }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs
                        .export(directory, report_id, kind, format);
                } else {
                    self.status = "Retained result directory is unavailable".into();
                }
            }
            Some(crate::analysis::ReportAction::ShowDirectory { report_id }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs.reveal(directory);
                } else {
                    self.status = "Retained result directory is unavailable".into();
                }
            }
            Some(crate::analysis::ReportAction::OpenGhidra { report_id }) => {
                if let Some(directory) = self.analysis_directory(&report_id) {
                    self.evidence_jobs.open_ghidra(
                        directory,
                        report_id,
                        self.options.data_dir.join("tools"),
                    );
                } else {
                    self.status = "Retained result directory is unavailable".into();
                }
            }
            Some(crate::analysis::ReportAction::Cancel(analysis_id)) => {
                self.send(Command::CancelAnalysis { analysis_id })
            }
            Some(crate::analysis::ReportAction::OpenAnalysisTools) => self.tools_open = true,
            Some(crate::analysis::ReportAction::OpenSection { report_id, kind }) => {
                if let Err(reason) = self.open_analysis_section(report_id, kind) {
                    self.status = reason;
                }
            }
            Some(crate::analysis::ReportAction::ReadSpecimen {
                report_id,
                offset,
                data_len,
            }) => {
                let directory = self.analysis_directory(&report_id);
                let Some(view) = self.analysis_views.get_mut(view_key) else {
                    return;
                };
                if view.report_id.as_deref() != Some(&report_id) {
                    return;
                }
                view.preview = None;
                let Some(directory) = directory else {
                    view.pending = None;
                    view.preview = Some(Err("Retained specimen directory unavailable".into()));
                    return;
                };
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
                let generation = self.analysis_generation;
                view.pending = Some((generation, offset, data_len));
                self.queue_archive(Request::Specimen {
                    view_key: view_key.into(),
                    generation,
                    directory,
                    report_id,
                    offset,
                    data_len,
                });
            }
            Some(crate::analysis::ReportAction::ReadListing {
                report_id,
                kind,
                start,
                query,
            }) => {
                let directory = self.analysis_directory(&report_id);
                let report = self.analysis_report(&report_id).cloned();
                let Some(view) = self.analysis_views.get_mut(view_key) else {
                    return;
                };
                if view.report_id.as_deref() != Some(&report_id)
                    || view
                        .listing_pending
                        .as_ref()
                        .is_some_and(|(_, k, s, q)| *k == kind && *s == start && *q == query)
                {
                    return;
                }
                let Some(directory) = directory else {
                    view.listing = Some(Err("Retained analysis directory unavailable".into()));
                    return;
                };
                self.analysis_generation = self.analysis_generation.wrapping_add(1);
                let generation = self.analysis_generation;
                view.listing_pending = Some((generation, kind, start, query.clone()));
                let record_context = report
                    .as_ref()
                    .map(|report| view.state.record_context_for(report, kind))
                    .unwrap_or_default();
                self.queue_archive(Request::Listing {
                    view_key: view_key.into(),
                    generation,
                    directory,
                    report_id,
                    kind,
                    start,
                    query,
                    record_context,
                });
            }
            None => {}
        }
    }

    /// Add base > Download base: bases for this version first, older ones
    /// behind a toggle; one row per base with its action on the right and
    /// persistent progress and Cancel above the scrollable catalog.
    fn download_window(&mut self, ctx: &egui::Context, open: &mut bool) -> Option<Command> {
        let mut command = None;
        let installed: Vec<String> = self.snapshot.bases.iter().map(|b| b.id.clone()).collect();
        let download = self.snapshot.download.clone();
        let busy = download.as_ref().is_some_and(|status| !status.finished);
        let (current, rest): (Vec<_>, Vec<_>) = self
            .snapshot
            .remote_bases
            .iter()
            .cloned()
            .partition(remote_is_current);
        let (older, other): (Vec<_>, Vec<_>) = rest.into_iter().partition(|base| {
            matches!(
                RevisionStatus::of_base(base.revision, base.min_app_version.as_deref()),
                RevisionStatus::Outdated | RevisionStatus::Legacy
            )
        });
        let show_older = &mut self.show_older_bases;
        egui::Window::new("Download base")
            .id(Dialog::Download.window_id())
            .open(open)
            .collapsible(false)
            .resizable(true)
            .default_size([760.0, 520.0])
            .min_width(520.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            !self.snapshot.remote_refreshing,
                            egui::Button::new("Refresh catalog"),
                        )
                        .clicked()
                    {
                        command = Some(Command::RefreshRemoteBases);
                    }
                    if self.snapshot.remote_refreshing {
                        ui.spinner();
                        ui.label("Fetching catalog…");
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add_enabled(
                            !older.is_empty(),
                            egui::Checkbox::new(
                                show_older,
                                format!("Show older bases ({})", older.len()),
                            ),
                        )
                        .on_hover_text("Bases built for earlier Antinomie versions");
                    });
                });
                if let Some(error) = &self.snapshot.remote_error {
                    ui.colored_label(theme::error(), error);
                }
                if let Some(status) = download.as_ref().filter(|status| !status.finished) {
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(!status.installing, egui::Button::new("Cancel"))
                            .on_disabled_hover_text("Finishing the base installation")
                            .clicked()
                        {
                            command = Some(Command::CancelDownload);
                        }
                        ui.label(if status.installing {
                            format!("{}: installing…", status.label)
                        } else {
                            status.label.clone()
                        });
                    });
                    let fraction = if status.total > 0 {
                        (status.received as f32 / status.total as f32).clamp(0.0, 1.0)
                    } else {
                        0.0
                    };
                    ui.add(egui::ProgressBar::new(fraction).text(format!(
                        "{} of {}",
                        human_bytes(status.received),
                        human_bytes(status.total)
                    )));
                }
                if let Some(status) = download.as_ref().filter(|status| status.finished) {
                    match &status.error {
                        Some(error) if error.contains("cancelled") => {
                            ui.colored_label(
                                theme::muted(),
                                format!(
                                    "{}: download cancelled; it resumes where it stopped",
                                    status.label
                                ),
                            );
                        }
                        Some(error) => {
                            ui.colored_label(theme::error(), format!("{}: {error}", status.label));
                        }
                        None => {
                            ui.colored_label(theme::good(), format!("{} installed", status.label));
                        }
                    }
                }
                ui.separator();
                if current.is_empty() && older.is_empty() && other.is_empty() {
                    ui.colored_label(theme::muted(), "No bases listed yet: refresh the catalog.");
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let rows = current
                            .iter()
                            .chain(other.iter())
                            .chain(older.iter().filter(|_| *show_older));
                        if !current.is_empty() {
                            theme::section(ui, &format!("For Antinomie {APP_VERSION}"));
                        }
                        for (index, base) in rows.enumerate() {
                            if index == current.len() && !other.is_empty() {
                                ui.add_space(6.0);
                                theme::section(ui, "Other bases");
                            }
                            if index == current.len() + other.len() && *show_older {
                                ui.add_space(6.0);
                                theme::section(ui, "Older bases");
                            }
                            egui::Frame::group(ui.style())
                                .inner_margin(egui::Margin::symmetric(10, 8))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    if let Some(next) =
                                        download_row(ui, base, &installed, download.as_ref(), busy)
                                    {
                                        command = Some(next);
                                    }
                                });
                        }
                    });
            });
        command
    }

    fn open_analysis_section(
        &mut self,
        report_id: String,
        kind: antinomie_monitor_core::AnalysisKind,
    ) -> Result<(), String> {
        if !self.analysis_windows.contains_key(&report_id) {
            if self.analysis_windows.len() >= 8 {
                return Err("Eight analysis reports are open. Close a result window before opening another report.".into());
            }
            let report = self
                .analysis_report(&report_id)
                .ok_or("The retained analysis report is unavailable")?
                .clone();
            if let Some(directory) = self.analysis_directory(&report_id) {
                self.analysis_directories
                    .insert(report_id.clone(), directory);
            }
            self.analysis_windows.insert(report_id.clone(), report);
        }
        let request = (report_id, kind);
        if !self.pending_analysis_sections.contains(&request) {
            self.pending_analysis_sections.push(request);
        }
        Ok(())
    }

    pub(crate) fn take_analysis_sections(
        &mut self,
    ) -> Vec<(String, antinomie_monitor_core::AnalysisKind)> {
        std::mem::take(&mut self.pending_analysis_sections)
    }

    pub(crate) fn retain_analysis_windows(&mut self, ids: &[String]) {
        self.analysis_windows.retain(|id, _| {
            ids.contains(id)
                || self
                    .pending_analysis_sections
                    .iter()
                    .any(|(pending, _)| pending == id)
        });
        self.analysis_views.retain(|key, view| {
            key == "workspace"
                || view
                    .report_id
                    .as_ref()
                    .is_some_and(|id| self.analysis_windows.contains_key(id))
        });
        self.analysis_directories
            .retain(|id, _| self.analysis_windows.contains_key(id));
    }

    pub(crate) fn panel_title(&self, panel: &Panel) -> String {
        match panel {
            Panel::AnalysisSection { report_id, kind } => {
                let path = self
                    .analysis_windows
                    .get(report_id)
                    .map(|report| report.source_path.as_str())
                    .unwrap_or("Unavailable");
                let name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(path);
                let mut name_title: String = name.chars().take(24).collect();
                if name.chars().count() > 24 {
                    name_title.push_str("..");
                }
                let id_title: String = report_id.chars().take(8).collect();
                format!(
                    "{} / {} / {}",
                    crate::analysis::section_title(*kind),
                    name_title,
                    id_title
                )
            }
            Panel::Terminal(id) => self
                .terminals
                .get(id)
                .map(|terminal| format!("{} / PID {}", terminal.run.request.path, terminal.run.pid))
                .unwrap_or_else(|| "Terminal".into()),
            _ => panel.title().into(),
        }
    }

    /// Loaded packets have no run id. Show them only when they belong to this
    /// selection; otherwise triage gets an empty slice.
    ///
    /// A selected observation capture contributes packets only when
    /// `loaded_path` equals that capture's pcap file. `CaptureSummary` stores
    /// an observation directory and has no pcap path, so the comparison fails
    /// and the slice is empty. An archived trace, or a selected run that is
    /// not the live running run, also has no proven pcap join. Anything else
    /// is the live VM and keeps the packets currently loaded.
    fn triage_hides_packets(&self) -> bool {
        if self.selected_capture.is_some() {
            return !self.selected_capture_owns_loaded_pcap();
        }
        if let Some(id) = self.selected_run.clone() {
            let owned = self
                .run(&id)
                .cloned()
                .is_some_and(|run| self.loaded_pcap_belongs_to_run(&run));
            if owned {
                return false;
            }
        }
        self.trace_archive_directory().is_some()
            || self
                .selected_run
                .as_ref()
                .is_some_and(|id| !self.run(id).is_some_and(|run| self.live_history_run(run)))
    }

    /// The loaded pcap is one this run recorded: the live boot capture, or a
    /// path listed in that run's artifacts. A path that is merely open is not
    /// treated as this run's capture.
    fn loaded_pcap_belongs_to_run(&self, run: &RunSummary) -> bool {
        let Some(loaded) = self.network_view.loaded_path() else {
            return false;
        };
        if self
            .snapshot
            .network_capture
            .as_ref()
            .is_some_and(|capture| capture.file == loaded && capture.boot_id == run.boot_id)
        {
            return true;
        }
        antinomie_monitor_core::RunArtifacts::load(&run.directory)
            .ok()
            .flatten()
            .is_some_and(|artifacts| {
                artifacts.run_id == run.id
                    && artifacts
                        .network_captures
                        .iter()
                        .any(|file| file.as_path() == loaded)
            })
    }

    /// A pcap this selection recorded. An observation directory with no pcap
    /// file stays empty; the loaded preview is not substituted.
    fn owned_triage_pcap(&self) -> Option<(std::path::PathBuf, bool)> {
        if let Some(capture) = self.selected_capture_summary() {
            return capture_pcap_file(capture).map(|file| (file, false));
        }
        let id = self.selected_run.clone()?;
        let run = self.run(&id)?.clone();
        if let Some(capture) = &self.snapshot.network_capture {
            if capture.boot_id == run.boot_id && capture.file.is_file() && pcap_magic(&capture.file)
            {
                return Some((capture.file.clone(), capture.stopped_ms.is_none()));
            }
        }
        let artifacts = antinomie_monitor_core::RunArtifacts::load(&run.directory)
            .ok()
            .flatten()?;
        if artifacts.run_id != run.id {
            return None;
        }
        artifacts
            .network_captures
            .into_iter()
            .find(|file| file.is_file() && pcap_magic(file))
            .map(|file| (file, false))
    }

    fn selected_capture_owns_loaded_pcap(&self) -> bool {
        let Some(loaded) = self
            .network_view
            .loaded_path()
            .map(std::path::Path::to_path_buf)
        else {
            return false;
        };
        self.selected_capture_summary()
            .and_then(capture_pcap_file)
            .is_some_and(|file| file == loaded)
    }

    pub(crate) fn show_panel(&mut self, ui: &mut egui::Ui, panel: &Panel) {
        ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
        self.details_follow.drawn(ui, panel);
        match panel {
            Panel::Summary => crate::summary::show(
                ui,
                &self.snapshot,
                self.selected.as_deref(),
                self.settings.quota_gib,
                &self.cpu_history,
            ),
            Panel::Trace => self.events(ui),
            Panel::Network => {
                let vm = self.selected.clone();
                let active = self
                    .snapshot
                    .network_capture
                    .clone()
                    .filter(|_| vm.is_some() && vm == self.snapshot.active_vm);
                let locations = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == vm.as_ref());
                let recordings = locations.map(|location| location.recording_directory.clone());
                let recording_roots = locations
                    .map(|location| location.recording_directories.as_slice())
                    .unwrap_or_default();
                let nat = self.snapshot.vms.iter().any(|config| {
                    Some(&config.id) == vm.as_ref() && (config.nat || config.isolated_network)
                });
                let action = self.network_view.show(
                    ui,
                    NetworkContext {
                        active: active.as_ref(),
                        recordings: recordings.as_deref(),
                        recording_roots,
                        nat,
                        running: self.running()
                            && !self.closing
                            && vm.is_some()
                            && vm == self.snapshot.active_vm,
                        pending: self.pending_network.is_some(),
                        font_size: self.settings.font_size,
                    },
                );
                if let (Some(action), true) = (action, self.network_toggle_enabled()) {
                    self.send(match action {
                        NetworkAction::Start => Command::StartNetworkCapture,
                        NetworkAction::Stop => Command::StopNetworkCapture,
                    });
                }
            }
            Panel::CoreDump => {
                let roots = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == self.selected.as_ref())
                    .map(|location| location.recording_directories.clone())
                    .unwrap_or_default();
                let unavailable = self.manual_core_unavailable();
                self.core_view
                    .set_tools_dir(antinomie_monitor_core::analysis_tools::tools_dir(
                        &self.options.data_dir,
                    ));
                let action = self.core_view.show(
                    ui,
                    &roots,
                    self.selected.as_deref(),
                    self.selected.is_some() && self.selected == self.snapshot.active_vm,
                    crate::core_view::CoreControls {
                        unavailable,
                        captures: &self.snapshot.process_cores,
                        can_cancel: self.running()
                            && !self.closing
                            && self.snapshot.memory_dump.is_none()
                            && self.selected == self.snapshot.active_vm,
                    },
                );
                match action {
                    Some(crate::core_view::CoreAction::Dump) => self.open_core_picker(),
                    Some(crate::core_view::CoreAction::Cancel(capture_id)) => {
                        self.send(Command::CancelCoreCapture { capture_id })
                    }
                    None => {}
                }
            }
            Panel::Memory => {
                let vm_id = self.selected.clone();
                let vm = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|config| Some(&config.id) == vm_id.as_ref())
                    .cloned();
                let locations = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == vm_id.as_ref())
                    .cloned();
                let running = self.running()
                    && !self.closing
                    && vm_id.is_some()
                    && vm_id == self.snapshot.active_vm;
                let dumping = self
                    .snapshot
                    .memory_dump
                    .clone()
                    .filter(|progress| Some(&progress.dump.vm_id) == vm_id.as_ref());
                let volatility = self
                    .snapshot
                    .analysis_tools
                    .iter()
                    .find(|tool| tool.id == "volatility3");
                let installing = self
                    .snapshot
                    .tool_install
                    .as_ref()
                    .is_some_and(|install| install.id == "volatility3" && !install.finished);
                let action = self.memory_view.show(
                    ui,
                    crate::memory_view::MemoryContext {
                        vm: vm.as_ref(),
                        recordings: locations
                            .as_ref()
                            .map(|location| location.recording_directory.as_path()),
                        recording_roots: locations
                            .as_ref()
                            .map(|location| location.recording_directories.as_slice())
                            .unwrap_or_default(),
                        running,
                        dumping: dumping.as_ref(),
                        pending: false,
                        data_dir: &self.options.data_dir,
                        volatility_installed: volatility
                            .is_some_and(|tool| tool.installed.is_some()),
                        volatility_installing: installing,
                        bases: &self.snapshot.bases,
                        font_size: self.settings.font_size,
                        online_symbols: self.settings.memory_online_symbols,
                        curl: &self.options.curl,
                    },
                );
                match action {
                    Some(crate::memory_view::MemoryAction::Dump) => self.send(Command::DumpMemory),
                    Some(crate::memory_view::MemoryAction::InstallVolatility) => {
                        self.send(Command::InstallTool {
                            id: "volatility3".into(),
                        })
                    }
                    Some(crate::memory_view::MemoryAction::OnlineSymbols(on)) => {
                        self.settings.memory_online_symbols = on;
                    }
                    None => {}
                }
            }
            Panel::AnalysisSection { report_id, kind } => {
                let key = format!("section:{report_id}:{kind:?}");
                let report = self.analysis_windows.get(report_id).cloned();
                let labels = report
                    .as_ref()
                    .map(|report| self.analysis_labels(ui, report));
                let identities = report
                    .as_ref()
                    .map(|report| self.analysis_identities(&report.id))
                    .unwrap_or_default();
                let view = self.analysis_views.entry(key.clone()).or_default();
                view.bind(report.as_ref().map(|report| report.id.as_str()));
                if let Some(labels) = labels.zip(report.as_ref()) {
                    view.set_record(labels.1, labels.0, identities);
                }
                let action = crate::analysis::workspace_section(
                    ui,
                    report.as_ref(),
                    *kind,
                    &mut view.state,
                    view.preview.as_ref(),
                    view.listing.as_ref(),
                );
                self.analysis_action(&key, action);
            }
            Panel::Triage => {
                let invocations = self.invocations();
                if self.trace_archive_directory().is_some() {
                    let archive_offset = self.archive_offset;
                    let archive_page_len = self.archive_page.len();
                    let archive_total = self
                        .archive_total
                        .map(|total| total.to_string())
                        .unwrap_or_else(|| "—".to_string());
                    ui.colored_label(
                        theme::muted(),
                        format!(
                            "Triage is archive page offset {archive_offset}, {archive_page_len} calls of {archive_total} saved."
                        ),
                    );
                    if self.archive_next.is_some()
                        && !self.archive_pending
                        && ui.button("Next archive page").clicked()
                    {
                        self.next_archive_page();
                    }
                }
                let hide_packets = self.triage_hides_packets();
                if hide_packets {
                    ui.colored_label(
                        theme::muted(),
                        "Packet rows are hidden because the open capture is not this run.",
                    );
                }
                let (frame_owned, frame_note) = if hide_packets {
                    (None, None)
                } else {
                    self.network_view.captured_payloads()
                };
                let packets = if hide_packets {
                    &[]
                } else {
                    self.network_view.loaded_packets()
                };
                if let Some(note) = &frame_note {
                    ui.colored_label(theme::muted(), note);
                }
                let frames = frame_owned.as_deref();
                let vm_id = self.selected.clone();
                let run_id = self.selected_run.clone();
                let boot_id = run_id
                    .as_ref()
                    .and_then(|id| self.run(id))
                    .map(|run| run.boot_id.clone());
                let archive_dir = self.trace_archive_directory();
                let owned_pcap = archive_dir.as_ref().and_then(|_| self.owned_triage_pcap());
                let coverage = if archive_dir.is_some() {
                    "visible archive page until the saved-recording index reports its own coverage"
                } else {
                    "syscalls loaded in this session; not a finished whole-run index"
                };
                if let Some(call_id) = self.triage.show(
                    ui,
                    crate::triage::TriageInput {
                        invocations: &invocations,
                        packets,
                        frames,
                        vm_id: vm_id.as_deref(),
                        boot_id: boot_id.as_deref(),
                        run_id: run_id.as_deref(),
                        coverage,
                        archive: archive_dir.as_deref(),
                        pcap: owned_pcap.as_ref().map(|owned| owned.0.as_path()),
                        pcap_open: owned_pcap.as_ref().is_some_and(|owned| owned.1),
                    },
                ) {
                    self.filter = format!("call.id == {call_id}");
                    self.applied_filter = format!("call.id == {call_id}");
                    self.focus_trace();
                }
                if let Some(frame_number) = self.triage.take_packet_jump() {
                    match self.network_view.jump_to_frame(frame_number) {
                        Ok(()) => self.focus_panel = Some(Panel::Network),
                        Err(error) => {
                            self.status = error.clone();
                            self.log("ERROR", error);
                        }
                    }
                }
            }
            Panel::StaticAnalysis => {
                let mut reports = BTreeMap::new();
                for run in self.snapshot.runs.iter().chain(&self.history) {
                    if let Some(report) = &run.analysis {
                        reports.entry(report.id.clone()).or_insert_with(|| {
                            format!("{} — run {} ({:?})", run.request.path, run.id, report.state)
                        });
                    }
                }
                for report in &self.snapshot.analysis_reports {
                    reports.entry(report.id.clone()).or_insert_with(|| {
                        format!(
                            "{} — analysis only ({:?})",
                            report.source_path, report.state
                        )
                    });
                }
                let current = self
                    .selected_analysis
                    .as_ref()
                    .and_then(|id| reports.get(id))
                    .cloned()
                    .unwrap_or_else(|| "Selected run".into());
                ui.horizontal(|ui| {
                    ui.label("Report");
                    egui::ComboBox::from_id_salt("analysis-source")
                        .selected_text(current)
                        .width(ui.available_width())
                        .truncate()
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.selected_analysis, None, "Selected run");
                            for (id, label) in &reports {
                                let label = self
                                    .analysis_directory(id)
                                    .map(|dir| crate::evidence::title(ui, &dir, label))
                                    .unwrap_or_else(|| label.clone());
                                ui.selectable_value(
                                    &mut self.selected_analysis,
                                    Some(id.clone()),
                                    label,
                                );
                            }
                        });
                });
                let shown = self.selected_analysis.clone().or_else(|| {
                    self.selected_run
                        .as_deref()
                        .and_then(|id| {
                            if self.archive_selected {
                                self.history
                                    .iter()
                                    .find(|run| run.id == id)
                                    .or_else(|| self.run(id))
                            } else {
                                self.run(id)
                            }
                        })
                        .and_then(|run| run.analysis.as_ref())
                        .map(|r| r.id.clone())
                });
                let report = shown
                    .as_deref()
                    .and_then(|id| self.analysis_report(id))
                    .cloned();
                crate::analysis::other_progress(
                    ui,
                    self.snapshot
                        .runs
                        .iter()
                        .chain(&self.history)
                        .filter_map(|run| run.analysis.as_ref())
                        .chain(&self.snapshot.analysis_reports),
                    shown.as_deref(),
                );
                if let Some(id) = shown.as_deref() {
                    let related: Vec<_> = self
                        .snapshot
                        .runs
                        .iter()
                        .chain(&self.history)
                        .filter(|run| run.analysis.as_ref().is_some_and(|r| r.id == id))
                        .map(|run| (run.id.clone(), run.request.path.clone()))
                        .collect();
                    if let Some((run_id, path)) = related.first() {
                        if ui
                            .link(format!("{path} ({run_id})"))
                            .on_hover_text("Open the related run")
                            .clicked()
                        {
                            self.select_run(Some(run_id.clone()));
                            self.focus_panel = Some(Panel::RunHistory);
                        }
                    }
                }
                let labels = report
                    .as_ref()
                    .map(|report| self.analysis_labels(ui, report));
                let identities = report
                    .as_ref()
                    .map(|report| self.analysis_identities(&report.id))
                    .unwrap_or_default();
                let view = self.analysis_views.entry("workspace".into()).or_default();
                view.bind(report.as_ref().map(|report| report.id.as_str()));
                if let Some(labels) = labels.zip(report.as_ref()) {
                    view.set_record(labels.1, labels.0, identities);
                }
                let action = crate::analysis::workspace(
                    ui,
                    report.as_ref(),
                    &mut view.state,
                    view.preview.as_ref(),
                    view.listing.as_ref(),
                );
                self.analysis_action("workspace", action);
            }
            Panel::RunHistory => self.run_history(ui),
            Panel::Details => match self.details_follow.of(ui.ctx()) {
                crate::workspace::DetailsOf::Packet => {
                    self.network_view.details(ui, self.settings.font_size)
                }
                crate::workspace::DetailsOf::MemoryRow => {
                    self.memory_view.details(ui, self.settings.font_size)
                }
                crate::workspace::DetailsOf::History => self.history_detail(ui),
                crate::workspace::DetailsOf::Syscall => self.details(ui),
            },
            Panel::Activity => self.activity(ui),
            Panel::Terminal(id) => {
                let live = self
                    .terminals
                    .get(id)
                    .is_some_and(|terminal| run_in_live_session(&self.snapshot, &terminal.run));
                let mut commands = Vec::new();
                if let Some(terminal) = self.terminals.get_mut(id) {
                    ui.horizontal(|ui| {
                        ui.label(run_status(&terminal.run));
                        ui.label(format!("Root: {}", root_exit(&terminal.run)));
                        if let Some(error) = terminal
                            .snapshot_error
                            .as_ref()
                            .or(terminal.replay_error.as_ref())
                        {
                            ui.colored_label(theme::warn(), error);
                        }
                    });
                    terminal.last_paint = Some(Instant::now());
                    let interactive = live && terminal.interactive() && !self.closing;
                    let (data, resize) = if live {
                        terminal.terminal.show(ui, interactive)
                    } else {
                        terminal.terminal.show_grid(ui, false, false)
                    };
                    if !data.is_empty() {
                        commands.push(Command::TerminalInput {
                            run_id: id.clone(),
                            data,
                        });
                    }
                    if interactive {
                        if let Some((rows, cols)) = resize {
                            commands.push(Command::TerminalResize {
                                run_id: id.clone(),
                                rows,
                                cols,
                            });
                        }
                    }
                }
                for command in commands {
                    self.send(command);
                }
            }
        }
    }

    fn update_options(&mut self) {
        self.options.bundle_dir = crate::folders::user_path(&self.settings.bundle);
        self.send(Command::UpdateOptions {
            bundle_dir: crate::folders::user_path(&self.settings.bundle),
            capture_quota_size: u64::from(self.settings.quota_gib) * 1073741824,
            shutdown_timeout_secs: self.settings.timeout,
        });
    }
}

impl eframe::App for MonitorApp {
    /// Seams between panels show the theme, not eframe's near-black default.
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        theme::panel().to_normalized_gamma_f32()
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.dependencies.poll();
        self.drain();
        self.cpu_history
            .observe(&self.snapshot, self.selected.as_deref());
        self.flush_archive();
        self.drain_archive();
        self.resync_terminals();
        // Index retained run data independently of whether Triage is visible.
        let triage_archive = self.trace_archive_directory();
        let triage_pcap = triage_archive
            .as_ref()
            .and_then(|_| self.owned_triage_pcap());
        let triage_run = self.selected_run.clone();
        let triage_boot = triage_run
            .as_ref()
            .and_then(|id| self.run(id))
            .map(|run| run.boot_id.clone());
        self.triage.tick(
            ctx,
            crate::triage::TriageInput {
                invocations: &[],
                packets: &[],
                frames: None,
                vm_id: self.selected.as_deref(),
                boot_id: triage_boot.as_deref(),
                run_id: triage_run.as_deref(),
                coverage: "retained recording index",
                archive: triage_archive.as_deref(),
                pcap: triage_pcap.as_ref().map(|owned| owned.0.as_path()),
                pcap_open: triage_pcap.as_ref().is_some_and(|owned| owned.1),
            },
        );
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
        ctx.request_repaint_after(Duration::from_millis(50));
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "settings", &self.settings);
        eframe::set_value(storage, "workspace_layout", &self.layout);
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(backend) = &mut self.backend {
            if let Err(error) = backend.shutdown() {
                eprintln!("shutdown failed: {error}");
            }
        }
    }
}

/// Compact byte size for catalog rows and download progress.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn run_status(run: &RunSummary) -> &'static str {
    match run.state {
        RunState::Unknown => "Unknown",
        RunState::Running => "Running",
        RunState::StopRequested => "Stop requested",
        RunState::Finished => "Finished",
        RunState::Stopped => "Stopped",
        RunState::TerminalClosed => "PTY closed",
        RunState::Finalized => "Recording ended",
    }
}

fn root_exit(run: &RunSummary) -> String {
    match run
        .execution
        .as_ref()
        .and_then(|status| status.root_exit.as_ref())
    {
        Some(WaitStatus::Exited { code }) => format!("Exit {code}"),
        Some(WaitStatus::Signaled {
            signal,
            core_dumped,
        }) => format!(
            "Signal {signal}{}",
            if *core_dumped { " (core)" } else { "" }
        ),
        None => "Unknown".into(),
    }
}

fn execution_detail(run: &RunSummary) -> String {
    match &run.execution {
        Some(status) => format!(
            "{}; {} live tasks; {} pending async; {} total tasks; {} async losses; flags {:#x}; generation {}",
            run_status(run),
            status.live_task_count,
            status.pending_async_count,
            status.total_task_count,
            status.async_loss_count,
            status.flags,
            status.generation
        ),
        None => format!(
            "{}; full-tree execution evidence unavailable",
            run_status(run)
        ),
    }
}

fn base_selector(
    ui: &mut egui::Ui,
    snapshot: &Snapshot,
    identity: &mut Option<String>,
    salt: &str,
) {
    let label = if identity.is_none() {
        match selected_base(snapshot, None) {
            Some(base) if !base.fixed_display => "Application default (legacy)".into(),
            _ => "Application default".into(),
        }
    } else {
        selected_base(snapshot, identity.as_deref())
            .map(base_choice_label)
            .unwrap_or_else(|| "Linux 6.12.94 (unavailable)".into())
    };
    // A fixed width, the name cut to fit (whole on hover): a long base name
    // would otherwise push into the column beside the form. egui cuts the
    // text at the width available, so the box gets exactly the Name field's.
    let width = 296.0;
    ui.allocate_ui_with_layout(
        egui::vec2(width, ui.spacing().interact_size.y),
        egui::Layout::left_to_right(egui::Align::Center),
        |ui| {
            ui.set_max_width(width);
            egui::ComboBox::from_id_salt(salt)
                .selected_text(label.clone())
                .width(width)
                .truncate()
                .show_ui(ui, |ui| {
                    for base in &snapshot.bases {
                        ui.selectable_value(
                            identity,
                            Some(base.id.clone()),
                            base_choice_label(base),
                        )
                        .on_hover_text(base.directory.display().to_string());
                    }
                })
                .response
                .on_hover_text(label);
        },
    );
}

/// One catalog base: name and facts on the left; installed, Download, or
/// the running download's state on the right. Cancel stays above the list.
fn download_row(
    ui: &mut egui::Ui,
    base: &antinomie_monitor_core::RemoteBase,
    installed: &[String],
    download: Option<&antinomie_monitor_core::DownloadStatus>,
    busy: bool,
) -> Option<Command> {
    let mut command = None;
    let status = RevisionStatus::of_base(base.revision, base.min_app_version.as_deref());
    let running = download.filter(|d| d.identity == base.identity && !d.finished);
    ui.horizontal(|ui| {
        let action_width = 150.0;
        ui.allocate_ui_with_layout(
            egui::vec2((ui.available_width() - action_width).max(200.0), 0.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.label(
                    RichText::new(versioned_label(
                        &base.label,
                        base.revision,
                        base.min_app_version.as_deref(),
                    ))
                    .strong(),
                );
                let short = &base.identity[..12.min(base.identity.len())];
                let mut facts = vec![
                    format!("Linux {}", base.kernel_version),
                    human_bytes(base.total_size),
                    format!(
                        "{} MiB RAM, {} GiB disk minimum",
                        base.min_ram_mib, base.min_disk_gib
                    ),
                    short.to_string(),
                ];
                if status == RevisionStatus::Outdated {
                    facts.insert(0, "Outdated".into());
                }
                ui.label(
                    RichText::new(facts.join("  ·  "))
                        .small()
                        .color(theme::muted()),
                );
            },
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if installed.contains(&base.identity) {
                ui.colored_label(
                    theme::good(),
                    format!("{} Installed", egui_phosphor::regular::CHECK),
                );
            } else if running.is_some() {
                ui.label(if running.is_some_and(|status| status.installing) {
                    "Installing…"
                } else {
                    "Downloading…"
                });
            } else if status == RevisionStatus::NeedsNewerApp {
                ui.add_enabled(false, egui::Button::new("Download"))
                    .on_disabled_hover_text(format!(
                        "Built for a newer Antinomie (this is Antinomie {APP_VERSION})"
                    ));
            } else if ui
                .add_enabled(
                    !busy,
                    primary_button(&format!(
                        "{} Download",
                        egui_phosphor::regular::DOWNLOAD_SIMPLE
                    )),
                )
                .on_disabled_hover_text("Another download is in progress")
                .clicked()
            {
                command = Some(Command::DownloadBase {
                    identity: base.identity.clone(),
                });
            }
        });
    });
    command
}

/// A base's name with the Antinomie version it is for, e.g.
/// "Debian 13 (GNOME) · Antinomie 0.2.0".
fn versioned_label(label: &str, revision: Option<u32>, min_app_version: Option<&str>) -> String {
    match antinomie_monitor_core::base_app_version(revision, min_app_version) {
        Some(version) => format!("{label} · Antinomie {version}"),
        None => label.to_string(),
    }
}

/// Whether a remote base is for this app version (not an older one, and
/// not one this app is too old for).
fn remote_is_current(base: &antinomie_monitor_core::RemoteBase) -> bool {
    RevisionStatus::of_base(base.revision, base.min_app_version.as_deref())
        == RevisionStatus::Current
}

/// The catalog base that replaces an outdated installed one: same name,
/// built for this app version.
fn newer_base<'a>(
    snapshot: &'a Snapshot,
    base: &BaseSummary,
) -> Option<&'a antinomie_monitor_core::RemoteBase> {
    snapshot
        .remote_bases
        .iter()
        .find(|remote| remote.label == base.label && remote_is_current(remote))
}

fn base_choice_label(base: &BaseSummary) -> String {
    let name = versioned_label(&base.label, base.revision, base.min_app_version.as_deref());
    let label = if base.fixed_display {
        name
    } else {
        format!("{name} (legacy)")
    };
    if RevisionStatus::of_base(base.revision, base.min_app_version.as_deref())
        == RevisionStatus::Current
    {
        label
    } else {
        format!("{label} · {}", describe_base(base))
    }
}

/// "for Antinomie 0.1.0" etc., plus the version that built the base.
fn describe_base(base: &BaseSummary) -> String {
    let status = RevisionStatus::describe(base.revision, base.min_app_version.as_deref());
    match &base.built_with {
        Some(version) => format!("{status} (built with {version})"),
        None => status,
    }
}

/// Resolve the explicit base or the same legacy default used by VM configuration.
pub(crate) fn selected_base<'a>(
    snapshot: &'a Snapshot,
    identity: Option<&str>,
) -> Option<&'a BaseSummary> {
    if let Some(identity) = identity {
        return snapshot.bases.iter().find(|base| base.id == identity);
    }
    snapshot
        .bases
        .iter()
        .find(|base| base.guest.is_none())
        .or_else(|| snapshot.bases.first())
}

fn preferred_new_base<'a>(snapshot: &'a Snapshot, directory: &str) -> Option<&'a BaseSummary> {
    let configured = snapshot
        .bases
        .iter()
        .find(|base| base.directory == std::path::Path::new(directory))
        .or_else(|| selected_base(snapshot, None));
    if let Some(configured) = configured {
        return Some(configured)
            .filter(|base| base.fixed_display)
            .or_else(|| {
                snapshot.bases.iter().find(|base| {
                    base.fixed_display
                        && base.guest.as_ref().map(|guest| &guest.id)
                            == configured.guest.as_ref().map(|guest| &guest.id)
                })
            })
            .or(Some(configured));
    }
    snapshot
        .bases
        .iter()
        .find(|base| base.fixed_display)
        .or_else(|| snapshot.bases.first())
}

fn launch_options(ui: &mut egui::Ui, launch: &mut VmLaunchOptions) {
    ui.label("Resolution");
    egui::ComboBox::from_id_salt("vm_resolution")
        .selected_text(launch.resolution.label())
        .width(260.0)
        .height(320.0)
        .show_ui(ui, |ui| {
            for &resolution in DisplayResolution::ALL {
                ui.selectable_value(&mut launch.resolution, resolution, resolution.label());
            }
        });
    ui.end_row();
    ui.label("Window");
    ui.checkbox(&mut launch.fullscreen, "Fullscreen");
    ui.end_row();
    ui.label("");
    ui.checkbox(&mut launch.fit_to_window, "Fit to window");
    ui.end_row();
    ui.label("Acceleration");
    egui::ComboBox::from_id_salt("vm_acceleration")
        .selected_text(launch.acceleration.label())
        .width(260.0)
        .show_ui(ui, |ui| {
            for &acceleration in VmAcceleration::ALL {
                ui.selectable_value(&mut launch.acceleration, acceleration, acceleration.label());
            }
        });
    ui.end_row();
    ui.label("CPU model");
    egui::ComboBox::from_id_salt("vm_cpu_model")
        .selected_text(launch.cpu_model.label())
        .width(260.0)
        .show_ui(ui, |ui| {
            for &cpu_model in VmCpuModel::ALL {
                ui.selectable_value(&mut launch.cpu_model, cpu_model, cpu_model.label());
            }
        });
    ui.end_row();
}

/// VM settings > Telemetry transport: how telemetry travels from the guest.
/// Edits the VM draft; Save or Create in the VM dialog applies them.
fn transport_window(
    ctx: &egui::Context,
    open: &mut bool,
    transport: &mut TransportSettings,
    cpus: u16,
    tunable: bool,
    editable: bool,
) {
    let mut closed = false;
    egui::Window::new("Telemetry transport")
        .id(egui::Id::new("vm_transport"))
        // Beside the top of the VM dialog, not over its buttons.
        .pivot(egui::Align2::CENTER_TOP)
        .default_pos(egui::pos2(ctx.screen_rect().center().x, 60.0))
        .open(open)
        .collapsible(false)
        .resizable(false)
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.add_enabled_ui(editable, |ui| {
                transport_options(ui, transport, cpus, tunable)
            });
            if !editable {
                ui.colored_label(theme::warn(), "Stop the VM to change these settings.");
            }
            let mut close = false;
            dialog_footer(ui, |ui| {
                close = ui.button("Done").clicked();
                ui.label(
                    RichText::new("Save the VM configuration to apply.").color(theme::muted()),
                );
            });
            if close {
                closed = true;
            }
        });
    if closed {
        *open = false;
    }
}

fn transport_options(
    ui: &mut egui::Ui,
    transport: &mut TransportSettings,
    cpus: u16,
    tunable: bool,
) {
    if !tunable {
        ui.colored_label(
            theme::warn(),
            "This base predates Antinomie 0.3.0: it always uses 256 KiB buffers \
             and drops telemetry when they are full. These settings apply to \
             newer bases.",
        );
    }
    dialog_section(ui, "Guest to host");
    form_grid("vm_transport_grid", ui)
        .min_col_width(ui.text_style_height(&egui::TextStyle::Body) * 11.0)
        .show(ui, |ui| {
            ui.label("Guest buffer per vCPU");
            egui::ComboBox::from_id_salt("vm_ring_kib")
                .selected_text(ring_label(transport.ring_kib))
                .show_ui(ui, |ui| {
                    for &kib in &TransportSettings::RING_KIB {
                        ui.selectable_value(&mut transport.ring_kib, kib, ring_label(kib));
                    }
                });
            ui.end_row();
            ui.label("");
            ui.weak(format!(
                "{} of guest memory for {cpus} vCPU{}",
                ring_label(transport.ring_kib.saturating_mul(u32::from(cpus))),
                if cpus == 1 { "" } else { "s" }
            ));
            ui.end_row();
            ui.label("When buffers fill");
            ui.vertical(|ui| {
                ui.radio_value(&mut transport.lossless, false, "Drop new telemetry");
                ui.radio_value(
                    &mut transport.lossless,
                    true,
                    "Never drop: slow the guest down",
                );
            });
            ui.end_row();
            ui.label("Longest wait per event");
            ui.add_enabled(
                transport.lossless,
                egui::DragValue::new(&mut transport.max_wait_ms)
                    .range(1..=10_000)
                    .suffix(" ms"),
            );
            ui.end_row();
            ui.label("Host event table");
            ui.add(
                egui::DragValue::new(&mut transport.event_table)
                    .range(TransportSettings::EVENT_TABLE)
                    .speed(256.0)
                    .suffix(" events"),
            );
            ui.end_row();
        });
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Never drop makes a guest system call wait while the host saves \
             telemetry, so heavy tracing runs slower but nothing is lost. The \
             event table holds calls still being assembled; finished calls \
             leave it first. Settings apply at the next VM start.",
        )
        .small()
        .color(theme::muted()),
    );
}

fn ring_label(kib: u32) -> String {
    if kib >= 1024 && kib.is_multiple_of(1024) {
        format!("{} MiB", kib / 1024)
    } else {
        format!("{kib} KiB")
    }
}

fn password_input(ui: &mut egui::Ui, text: &mut String, salt: &str) {
    let mut output = egui::TextEdit::singleline(text)
        .id(egui::Id::new(salt))
        .password(true)
        .margin(theme::TEXT_EDIT_MARGIN)
        .char_limit(128)
        .desired_width(280.0)
        .show(ui);
    // Do not let reopening the form restore a prior secret through undo.
    output.state.clear_undoer();
    output.state.store(ui.ctx(), output.response.id);
}

fn directory_input(
    ui: &mut egui::Ui,
    path: &mut Option<PathBuf>,
    default_parent: &std::path::Path,
    picker: &mut FolderPicker,
    target: FolderTarget,
    status: &mut String,
) {
    let mut text = path
        .as_deref()
        .unwrap_or(default_parent)
        .to_string_lossy()
        .into_owned();
    ui.horizontal(|ui| {
        if ui
            .add(
                text_field(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(235.0),
            )
            .on_hover_text(text.clone())
            .changed()
        {
            *path = (!text.trim().is_empty()).then(|| crate::folders::user_path(&text));
        }
        if icon(
            ui,
            egui_phosphor::regular::FOLDER_OPEN,
            "Choose host folder",
            picker.available(),
        ) {
            if let Err(error) = picker.choose(target) {
                *status = format!("Host folder: {error}");
            }
        }
    });
}

#[cfg(test)]
fn show_terminal_viewport(
    ctx: &egui::Context,
    class: egui::ViewportClass,
    terminal: &mut RunTerminal,
    live: bool,
    interactive: bool,
) -> Vec<Command> {
    let close_requested = ctx.input(|input| input.viewport().close_requested());
    let id = terminal.run.id.clone();
    let mut commands = Vec::new();
    let content = |ui: &mut egui::Ui| {
        let (data, resize) = if live {
            terminal.terminal.show(ui, interactive)
        } else {
            terminal.terminal.show_grid(ui, false, false)
        };
        if !data.is_empty() {
            commands.push(Command::TerminalInput {
                run_id: id.clone(),
                data,
            });
        }
        if let Some((rows, cols)) = resize {
            if interactive {
                commands.push(Command::TerminalResize {
                    run_id: id.clone(),
                    rows,
                    cols,
                });
            }
        }
    };
    if class == egui::ViewportClass::Embedded {
        let mut open = terminal.open;
        egui::Window::new(format!(
            "{} / PID {}",
            terminal.run.request.path, terminal.run.pid
        ))
        .id(egui::Id::new(("terminal-fallback", &id)))
        .open(&mut open)
        .default_size([720.0, 400.0])
        .show(ctx, content);
        terminal.open = open;
    } else {
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::terminal())
                    .inner_margin(egui::Margin::same(4)),
            )
            .show(ctx, content);
    }
    if close_requested {
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        terminal.close_view();
    }
    commands
}

fn terminal_capacity_message() -> String {
    format!("Terminal view limit reached ({TERMINAL_VIEW_LIMIT}); close a history window")
}

/// A file in the observation directory whose first four bytes are a classic
/// pcap magic. A directory with no such file is not a packet capture.
fn capture_pcap_file(capture: &CaptureSummary) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(&capture.directory).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() && pcap_magic(&path) {
            return Some(path);
        }
    }
    None
}

fn pcap_magic(path: &std::path::Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    if std::io::Read::read_exact(&mut file, &mut magic).is_err() {
        return false;
    }
    matches!(magic, [0xd4, 0xc3, 0xb2, 0xa1] | [0xa1, 0xb2, 0xc3, 0xd4])
}

fn run_in_live_session(snapshot: &Snapshot, run: &RunSummary) -> bool {
    // Tree completion does not end the VM boot's terminal/capture ownership.
    matches!(snapshot.state, VmState::Running | VmState::Stopping)
        && snapshot.active_vm.as_ref() == Some(&run.vm_id)
        && !run.boot_id.is_empty()
        && snapshot.runs.iter().any(|current| {
            current.id == run.id && current.vm_id == run.vm_id && current.boot_id == run.boot_id
        })
}

fn available_terminal_slots(
    terminals: &BTreeMap<String, RunTerminal>,
    snapshot: &Snapshot,
) -> usize {
    let reclaimable = terminals
        .values()
        .filter(|terminal| !terminal.open && !run_in_live_session(snapshot, &terminal.run))
        .count();
    TERMINAL_VIEW_LIMIT.saturating_sub(terminals.len().saturating_sub(reclaimable))
}

fn resolve_launch_result(pending: &mut Option<u64>, id: u64, success: bool) {
    // Success retains the reserved view until RunStarted or the snapshot supplies its run.
    if !success && *pending == Some(id) {
        *pending = None;
    }
}

fn sync_runs(terminals: &mut BTreeMap<String, RunTerminal>, snapshot: &Snapshot) {
    for run in &snapshot.runs {
        if let Some(terminal) = terminals.get_mut(&run.id) {
            terminal.run = run.clone();
        } else if run_in_live_session(snapshot, run) {
            if terminals.len() >= TERMINAL_VIEW_LIMIT {
                let reclaim = terminals
                    .iter()
                    .find(|(_, terminal)| {
                        !terminal.open && !run_in_live_session(snapshot, &terminal.run)
                    })
                    .map(|(id, _)| id.clone());
                if let Some(id) = reclaim {
                    terminals.remove(&id);
                }
            }
            if terminals.len() < TERMINAL_VIEW_LIMIT {
                let mut terminal = RunTerminal::new(run.clone());
                terminal.dirty = true;
                terminals.insert(run.id.clone(), terminal);
            }
        }
    }
    for terminal in terminals.values_mut() {
        if terminal.dirty && !run_in_live_session(snapshot, &terminal.run) {
            terminal.begin_replay();
        }
    }
}

/// What a click in the empty trace panel asks for.
enum EmptyTraceAction {
    Start,
    Run(String),
    Capture(String),
}

/// A clickable line of the empty trace panel: icon, title, muted detail.
fn recent_row(ui: &mut egui::Ui, icon: &str, title: &str, detail: &str) -> egui::Response {
    let size = egui::TextStyle::Body.resolve(ui.style()).size;
    let height = theme::row_height(size) + 4.0;
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    if ui.is_rect_visible(rect) {
        let painter = ui.painter_at(rect);
        if response.hovered() {
            painter.rect_filled(rect, 4.0, theme::palette().hover);
        }
        let y = rect.center().y;
        let font = egui::FontId::proportional(size);
        painter.text(
            egui::pos2(rect.left() + 6.0, y),
            egui::Align2::LEFT_CENTER,
            icon,
            font.clone(),
            theme::blue(),
        );
        let mut job =
            egui::text::LayoutJob::simple_singleline(title.to_owned(), font.clone(), theme::text());
        job.wrap = egui::text::TextWrapping::truncate_at_width(rect.width() * 0.6);
        let title = painter.layout_job(job);
        let title_x = rect.left() + 6.0 + size * 1.6;
        let title_width = title.size().x;
        painter.galley(
            egui::pos2(title_x, y - title.size().y / 2.0),
            title,
            theme::text(),
        );
        let detail_x = title_x + title_width + size * 0.8;
        let mut job = egui::text::LayoutJob::simple_singleline(
            detail.to_owned(),
            egui::FontId::proportional(size - 1.0),
            theme::muted(),
        );
        job.wrap = egui::text::TextWrapping::truncate_at_width(rect.right() - detail_x - 6.0);
        let detail = painter.layout_job(job);
        painter.galley(
            egui::pos2(detail_x, y - detail.size().y / 2.0),
            detail,
            theme::muted(),
        );
    }
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
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

/// Orders the table by one column. Ties keep time, then sequence, order; a
/// call without an exit sorts after every returned value.
fn sort_invocations(invocations: &mut [InvocationSummary], column: TraceColumn, descending: bool) {
    use std::cmp::Ordering;
    let time = |invocation: &InvocationSummary| {
        trace::representative(invocation).map(|event| (event.timestamp_ns, event.event_seq))
    };
    let compare = |a: &InvocationSummary, b: &InvocationSummary| -> Ordering {
        let (Some(x), Some(y)) = (trace::representative(a), trace::representative(b)) else {
            return Ordering::Equal;
        };
        match column {
            TraceColumn::Time => x.timestamp_ns.cmp(&y.timestamp_ns),
            TraceColumn::Sequence => x.event_seq.cmp(&y.event_seq),
            TraceColumn::Tid => x.tid.cmp(&y.tid),
            TraceColumn::Cpu => x.cpu.cmp(&y.cpu),
            TraceColumn::Syscall => x
                .syscall_name
                .cmp(&y.syscall_name)
                .then(x.syscall_nr.cmp(&y.syscall_nr)),
            TraceColumn::Return => {
                let result = |invocation: &InvocationSummary| {
                    invocation.exit.as_ref().and_then(|exit| exit.result)
                };
                match (result(a), result(b)) {
                    (Some(x), Some(y)) => x.cmp(&y),
                    (Some(_), None) => Ordering::Less,
                    (None, Some(_)) => Ordering::Greater,
                    (None, None) => Ordering::Equal,
                }
            }
            TraceColumn::Info => Ordering::Equal,
        }
    };
    if column == TraceColumn::Info {
        // The info text is built once per row, not once per comparison.
        if descending {
            invocations.sort_by_cached_key(|invocation| {
                (std::cmp::Reverse(trace::info(invocation)), time(invocation))
            });
        } else {
            invocations
                .sort_by_cached_key(|invocation| (trace::info(invocation), time(invocation)));
        }
        return;
    }
    invocations.sort_by(|a, b| {
        let order = compare(a, b);
        let order = if descending { order.reverse() } else { order };
        order.then_with(|| time(a).cmp(&time(b)))
    });
}

/// Dialogs and tool windows that Escape closes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dialog {
    Confirm,
    Name,
    Transport,
    Vm,
    Launch,
    Upload,
    Settings,
    Import,
    Download,
    Tools,
    Samples,
    Snapshots,
    SnapshotDecision,
    Dependencies,
    About,
    Build,
    Attach,
}

impl Dialog {
    const ALL: [Dialog; 17] = [
        Dialog::Confirm,
        Dialog::Name,
        Dialog::Transport,
        Dialog::Vm,
        Dialog::Launch,
        Dialog::Upload,
        Dialog::Settings,
        Dialog::Import,
        Dialog::Download,
        Dialog::Tools,
        Dialog::Samples,
        Dialog::Snapshots,
        Dialog::SnapshotDecision,
        Dialog::Dependencies,
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
            Dialog::Vm => "vm_configuration",
            Dialog::Launch => "run_program",
            Dialog::Upload => "upload_file",
            Dialog::Settings => "settings",
            Dialog::Import => "import_base",
            Dialog::Download => "download_base",
            Dialog::Tools => crate::tools_window::WINDOW_ID,
            Dialog::Samples => crate::samples_view::WINDOW_ID,
            Dialog::Snapshots => crate::snapshots::WINDOW_ID,
            Dialog::SnapshotDecision => "snapshot_decision",
            Dialog::Dependencies => crate::dependencies_window::WINDOW_ID,
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

/// A VM state as a word and its color.
fn vm_state_word(state: &VmState) -> (&'static str, egui::Color32) {
    match state {
        VmState::Running => ("Running", theme::good()),
        VmState::Starting => ("Starting", theme::warn()),
        VmState::Stopping => ("Stopping", theme::warn()),
        VmState::Failed => ("Failed", theme::error()),
        VmState::Stopped => ("Stopped", theme::muted()),
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// "just now", "5 min ago", "3 h ago", "2 d ago".
fn relative_time(seconds: u64) -> String {
    match seconds {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", seconds / 60),
        3600..86400 => format!("{} h ago", seconds / 3600),
        _ => format!("{} d ago", seconds / 86400),
    }
}

/// The file name of a program path.
fn program_name(path: &str) -> &str {
    path.rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or(path)
}

pub(crate) fn core_capture_status(state: antinomie_monitor_core::RunArtifactState) -> &'static str {
    use antinomie_monitor_core::RunArtifactState;
    match state {
        RunArtifactState::Disabled => "Disabled",
        RunArtifactState::WaitingForRootExit => "Waiting for root process exit",
        RunArtifactState::WaitingForTreeExit => "Waiting for process tree exit",
        RunArtifactState::Recording => "Recording",
        RunArtifactState::Queued => "Queued",
        RunArtifactState::InProgress => "Acquiring",
        RunArtifactState::Complete => "Complete",
        RunArtifactState::Partial => "Partial capture",
        RunArtifactState::Interrupted => "Interrupted",
        RunArtifactState::Failed => "Failed",
    }
}

fn open_directory(directory: &std::path::Path, status: &mut String) {
    match std::process::Command::new("xdg-open")
        .arg(directory)
        .spawn()
    {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(error) => *status = format!("Open directory: {error}"),
    }
}

/// One line of colored text pieces, cut with "…" at `width`.
fn line_galley(
    ui: &egui::Ui,
    pieces: &[(String, egui::Color32)],
    font: &egui::FontId,
    width: f32,
) -> std::sync::Arc<egui::Galley> {
    let mut job = egui::text::LayoutJob::default();
    for (text, color) in pieces {
        job.append(text, 0.0, egui::TextFormat::simple(font.clone(), *color));
    }
    job.wrap = egui::text::TextWrapping::truncate_at_width(width.max(1.0));
    ui.fonts(|fonts| fonts.layout_job(job))
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

fn sidebar_row(ui: &mut egui::Ui, row: SidebarRow<'_>) -> egui::Response {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let small = egui::TextStyle::Small.resolve(ui.style());
    let (body_height, small_height) =
        ui.fonts(|fonts| (fonts.row_height(&body), fonts.row_height(&small)));
    let padding = egui::vec2(8.0, 5.0);
    let gap = 2.0;
    let height = padding.y * 2.0 + body_height + row.details.len() as f32 * (small_height + gap);
    let (rect, response) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), height),
        egui::Sense::click(),
    );
    if !ui.is_rect_visible(rect) {
        return response;
    }
    let palette = theme::palette();
    if row.selected {
        ui.painter().rect_filled(rect, 4.0, palette.selection);
        ui.painter().rect_filled(
            egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height())),
            2.0,
            palette.accent,
        );
    } else if response.hovered() {
        ui.painter().rect_filled(rect, 4.0, palette.hover);
    }
    let left = rect.left() + padding.x;
    let right = rect.right() - padding.x;
    let top = rect.top() + padding.y;
    let mark = line_galley(
        ui,
        &[(row.mark.0.to_owned(), row.mark.1)],
        &body,
        f32::INFINITY,
    );
    let text_left = left + mark.size().x.max(body.size) + 6.0;
    ui.painter().galley(egui::pos2(left, top), mark, row.mark.1);
    let mut name_right = right;
    if let Some((word, color)) = row.state {
        let state = line_galley(ui, &[(word.to_owned(), color)], &small, f32::INFINITY);
        let position = egui::pos2(
            right - state.size().x,
            top + (body_height - small_height) * 0.5,
        );
        name_right = position.x - 8.0;
        ui.painter().galley(position, state, color);
    }
    let name = line_galley(
        ui,
        &[(row.name.to_owned(), theme::text())],
        &body,
        name_right - text_left,
    );
    ui.painter()
        .galley(egui::pos2(text_left, top), name, theme::text());
    let mut y = top + body_height + gap;
    for line in &row.details {
        let galley = line_galley(ui, line, &small, right - text_left);
        ui.painter()
            .galley(egui::pos2(text_left, y), galley, theme::muted());
        y += small_height + gap;
    }
    response
}

struct SectionHeader<'a> {
    title: &'a str,
    count: usize,
    tooltip: &'a str,
    action: &'a str,
    enabled: bool,
    open: bool,
}

/// A sidebar section title: a fold arrow and the title in the heading color
/// (click to fold), a muted count, and a "+" action on the right; a
/// separator below. The "+" lights up while hovered, or while its menu is
/// `open`. Returns the "+" response.
fn section_header(
    ui: &mut egui::Ui,
    header: SectionHeader<'_>,
    collapsed: &mut bool,
) -> egui::Response {
    let size = ui.spacing().interact_size.y;
    let response = ui
        .horizontal(|ui| {
            let title_width = (ui.available_width() - size - ui.spacing().item_spacing.x).max(0.0);
            let (rect, title) =
                ui.allocate_exact_size(egui::vec2(title_width, size), egui::Sense::click());
            if title.clicked() {
                *collapsed = !*collapsed;
            }
            if ui.is_rect_visible(rect) {
                let body = egui::TextStyle::Body.resolve(ui.style());
                let small = egui::TextStyle::Small.resolve(ui.style());
                let color = if title.hovered() {
                    theme::blue()
                } else {
                    theme::heading()
                };
                let caret = line_galley(
                    ui,
                    &[(
                        if *collapsed {
                            egui_phosphor::regular::CARET_RIGHT
                        } else {
                            egui_phosphor::regular::CARET_DOWN
                        }
                        .to_owned(),
                        color,
                    )],
                    &small,
                    f32::INFINITY,
                );
                let caret_width = small.size + 4.0;
                ui.painter().galley(
                    egui::pos2(rect.left(), rect.center().y - caret.size().y * 0.5),
                    caret,
                    color,
                );
                let count = line_galley(
                    ui,
                    &[(header.count.to_string(), theme::muted())],
                    &small,
                    f32::INFINITY,
                );
                let name = line_galley(
                    ui,
                    &[(header.title.to_owned(), color)],
                    &body,
                    rect.width() - caret_width - count.size().x - 8.0,
                );
                let name_left = rect.left() + caret_width;
                let name_right = name_left + name.size().x;
                ui.painter().galley(
                    egui::pos2(name_left, rect.center().y - name.size().y * 0.5),
                    name,
                    color,
                );
                ui.painter().galley(
                    egui::pos2(name_right + 8.0, rect.center().y - count.size().y * 0.5),
                    count,
                    theme::muted(),
                );
            }
            title.on_hover_text(header.tooltip);
            let sense = if header.enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            };
            let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), sense);
            let lit = header.enabled && (response.hovered() || header.open);
            if ui.is_rect_visible(rect) {
                if lit {
                    ui.painter().rect_filled(rect, 4.0, theme::primary());
                }
                let color = match (header.enabled, lit) {
                    (false, _) => theme::muted().gamma_multiply(0.5),
                    (true, true) => theme::palette().primary_text,
                    (true, false) => theme::text(),
                };
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    egui_phosphor::regular::PLUS,
                    egui::FontId::proportional(ui.text_style_height(&egui::TextStyle::Body)),
                    color,
                );
            }
            if header.enabled {
                response.on_hover_text(header.action)
            } else {
                response.on_hover_text(format!("{} (stop the running VM first)", header.action))
            }
        })
        .inner;
    ui.separator();
    response
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

fn tool_button(ui: &mut egui::Ui, button: ToolButton<'_>) -> bool {
    let font = egui::TextStyle::Button.resolve(ui.style());
    let (icon, label) = if button.enabled {
        (
            button.tone,
            if button.active || button.strong {
                button.tone
            } else {
                theme::text()
            },
        )
    } else {
        (theme::muted(), theme::muted())
    };
    let mut job = egui::text::LayoutJob::default();
    job.append(
        button.icon,
        0.0,
        egui::TextFormat::simple(font.clone(), icon),
    );
    job.append(button.label, 6.0, egui::TextFormat::simple(font, label));
    let mut widget = egui::Button::new(job).min_size(egui::vec2(0.0, ui.spacing().interact_size.y));
    if button.active {
        widget = widget
            .fill(button.tone.gamma_multiply(0.18))
            .stroke(egui::Stroke::new(1.0_f32, button.tone));
    }
    ui.add_enabled(button.enabled, widget)
        .on_hover_text(button.tooltip)
        .on_disabled_hover_text(button.tooltip)
        .clicked()
}

/// The main action of a dialog, in the primary color.
fn primary_button<'a>(text: &str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(theme::palette().primary_text))
        .fill(theme::primary())
}

/// A destructive confirmation, in the error color.
fn danger_button<'a>(text: &str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(theme::palette().primary_text)).fill(theme::error())
}

/// A secondary destructive action: error-colored text on a plain button.
fn danger_text_button<'a>(text: &str) -> egui::Button<'a> {
    egui::Button::new(RichText::new(text).color(theme::error()))
}

/// A single-line text field with room around the text.
fn text_field(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text).margin(theme::TEXT_EDIT_MARGIN)
}

/// A titled group of fields in a dialog.
fn dialog_section(ui: &mut egui::Ui, title: &str) {
    // theme::section leaves the room above a heading that follows something.
    theme::section(ui, title);
    ui.add_space(2.0);
}

/// Width of a dialog's label column: the longest label ("Recording
/// parent", "Confirm password") at the current text size.
fn form_label_width(ctx: &egui::Context) -> f32 {
    ctx.style()
        .text_styles
        .get(&egui::TextStyle::Body)
        .map_or(16.0, |font| font.size)
        * 9.5
}

/// A label / field grid whose label column has the same width in every
/// section, so the fields line up.
fn form_grid(id: &str, ui: &egui::Ui) -> egui::Grid {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([14.0, 8.0])
        .min_col_width(form_label_width(ui.ctx()))
}

/// A separator and the dialog's buttons, main action first.
fn dialog_footer(ui: &mut egui::Ui, buttons: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(4.0);
    ui.separator();
    ui.horizontal(buttons);
}

/// Settings > Text size: smaller and larger buttons around the size, and a
/// slider with a filled track.
fn text_size_control(ui: &mut egui::Ui, size: &mut f32) {
    ui.horizontal(|ui| {
        if ui
            .add_enabled(*size > 12.0, egui::Button::new("A−"))
            .on_hover_text("Smaller text")
            .clicked()
        {
            *size = (*size - 1.0).max(12.0);
        }
        ui.scope(|ui| {
            let visuals = ui.visuals_mut();
            visuals.slider_trailing_fill = true;
            visuals.selection.bg_fill = theme::primary();
            visuals.widgets.inactive.bg_fill = theme::line();
            ui.spacing_mut().slider_width = 140.0;
            ui.add(
                egui::Slider::new(size, 12.0..=24.0)
                    .step_by(1.0)
                    .show_value(false),
            );
        });
        if ui
            .add_enabled(*size < 24.0, egui::Button::new("A+"))
            .on_hover_text("Larger text")
            .clicked()
        {
            *size = (*size + 1.0).min(24.0);
        }
        ui.label(RichText::new(format!("{size:.0} px")).monospace());
    });
}

/// A status bar figure inside a right-to-left row. The value is added first so
/// it sits to the right of its name: `TRL 0`.
fn status_value_rtl(
    ui: &mut egui::Ui,
    name: &str,
    value: &str,
    color: egui::Color32,
) -> egui::Response {
    let value = ui.label(RichText::new(value).monospace().color(color));
    let name = ui.label(RichText::new(name).color(theme::muted()));
    value | name
}

/// A status bar message line: an icon and the text in `color`, cut to fit.
fn status_line(ui: &mut egui::Ui, icon: &str, text: &str, color: egui::Color32) {
    ui.horizontal(|ui| {
        ui.colored_label(color, icon);
        ui.add(egui::Label::new(RichText::new(text).color(color)).truncate());
    })
    .response
    .on_hover_text(text);
}

fn icon(ui: &mut egui::Ui, icon: &str, tooltip: &str, enabled: bool) -> bool {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(icon).size(ui.text_style_height(&egui::TextStyle::Body)))
            .frame(false)
            .min_size(egui::vec2(
                ui.spacing().interact_size.y,
                ui.spacing().interact_size.y,
            )),
    )
    .on_hover_text(tooltip)
    .clicked()
}

fn scroll_dialog(ui: &mut egui::Ui, ctx: &egui::Context, content: impl FnOnce(&mut egui::Ui)) {
    let height = (ctx.screen_rect().height() - 110.0).max(150.0);
    // Measure against the viewport even when restored window geometry is short.
    ui.set_max_height(height);
    egui::ScrollArea::vertical()
        .max_height(height)
        .auto_shrink([false, true])
        .show(ui, content);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_startup_dependency_blocks_a_command_before_submission() {
        let mut app = app();
        app.dependencies = crate::dependencies_window::DependenciesWindow::missing_for_test(
            antinomie_monitor_core::dependencies::Dependency::Gtk,
        );
        app.send(Command::Start {
            vm_id: "test".into(),
        });
        assert!(app.submitted.is_empty());
        assert!(app.dependencies.open);
        assert!(app.status.contains("missing test dependency"));
        app.send(Command::Close);
        assert!(matches!(app.submitted.last(), Some(Command::Close)));
    }
    use antinomie_monitor_core::RunIn;

    fn app() -> MonitorApp {
        let exec = ExecRequest::default();
        // Trace behavior fixtures explicitly open Trace; production opens Summary.
        let mut layout = WorkspaceLayout::default();
        layout.focus(Panel::Trace);
        MonitorApp {
            backend: None,
            snapshot: Snapshot::default(),
            selected: None,
            selected_base: None,
            settings: Settings::default(),
            options: BackendOptions::default(),
            settings_open: false,
            create_open: false,
            config_open: false,
            launch_open: false,
            upload_open: false,
            draft: VmConfig::default(),
            confirm: None,
            draft_generation: 0,
            folder_picker: FolderPicker::new(),
            status: String::new(),
            credentials: CredentialForm::default(),
            import_open: false,
            import_directory: String::new(),
            download_open: false,
            build_open: false,
            about_open: false,
            tools_open: false,
            vm_snapshots: crate::snapshots::SnapshotManager::default(),
            samples: crate::samples_view::SamplesView::default(),
            dependencies: crate::dependencies_window::DependenciesWindow::ready_for_test(),
            show_older_bases: false,
            build_wizard: build_wizard::BuildWizard::default(),
            name_action: None,
            filter: String::new(),
            applied_filter: String::new(),
            trace_sort: None,
            selected_event: None,
            selected_run: None,
            selected_capture: None,
            selected_process: None,
            transport_open: false,
            network_view: Default::default(),
            memory_view: Default::default(),
            core_view: Default::default(),
            triage: Default::default(),
            cpu_history: Default::default(),
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
            pending_observer: None,
            pending_core: None,
            pending_network: None,
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
            layout,
            focus_panel: None,
            activity: VecDeque::new(),
            env: exec.env.join("\n"),
            exec,
            args: String::new(),
            source: String::new(),
            destination: "/tmp/program".into(),
            executable: false,
            overwrite: false,
            upload_browser: Default::default(),
            pending_upload: None,
            pending_launch: None,
            started: Instant::now(),
            smoke: None,
            closing: false,
            submitted: Vec::new(),
            launch_action_rects: None,
        }
    }

    fn upload_app() -> MonitorApp {
        let mut app = app();
        app.selected = Some("vm".into());
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.boot_id = Some("boot".into());
        app.snapshot.capture_dir = Some(PathBuf::from("/tmp/session"));
        app.source = "/tmp/host file".into();
        app.destination = "/tmp/guest file".into();
        app.open_upload();
        app
    }

    #[test]
    fn upload_and_run_waits_for_matching_success_without_executing() {
        let mut app = upload_app();
        app.args = "--keep-this-setting".into();
        app.request_upload(true);
        let id = app.pending_upload.as_ref().unwrap().id;
        assert!(matches!(&app.submitted[0], Command::Upload {
            destination, executable: true, overwrite: false, ..
        } if destination == "/tmp/guest file"));
        assert!(!app.launch_open);
        app.complete_upload(id + 1, true);
        assert!(app.pending_upload.is_some() && !app.launch_open);
        // A later edit cannot change the destination of the queued transfer.
        app.destination = "/tmp/another".into();
        app.complete_upload(id, true);
        assert!(app.launch_open && !app.upload_open);
        assert_eq!(app.exec.path, "/tmp/guest file");
        assert_eq!(app.args, "--keep-this-setting");
        assert!(!app
            .submitted
            .iter()
            .any(|command| matches!(command, Command::Execute(_))));
    }

    #[test]
    fn upload_failure_plain_upload_and_closed_handoffs_never_open_run() {
        for (run_after, success, close) in [
            (true, false, false),
            (false, true, false),
            (true, true, true),
        ] {
            let mut app = upload_app();
            app.request_upload(run_after);
            let id = app.pending_upload.as_ref().unwrap().id;
            if close {
                app.close_dialog(Dialog::Upload);
            }
            app.complete_upload(id, success);
            assert!(app.pending_upload.is_none() && !app.launch_open);
            assert_eq!(app.submitted.len(), 1);
        }
    }

    #[test]
    fn upload_handoff_rejects_changed_vm_boot_recording_selection_and_shutdown() {
        for change in 0..6 {
            let mut app = upload_app();
            app.request_upload(true);
            let id = app.pending_upload.as_ref().unwrap().id;
            match change {
                0 => app.snapshot.active_vm = Some("other".into()),
                1 => app.snapshot.boot_id = Some("restored".into()),
                2 => app.snapshot.capture_dir = Some(PathBuf::from("/tmp/restored")),
                3 => app.selected = Some("other".into()),
                4 => app.snapshot.state = VmState::Stopping,
                _ => app.closing = true,
            }
            app.complete_upload(id, true);
            assert!(!app.launch_open, "change {change}");
            assert!(app.pending_upload.is_none());
        }
    }

    #[test]
    fn upload_overwrite_confirmation_freezes_action_and_session() {
        for change_session in [false, true] {
            let mut app = upload_app();
            app.overwrite = true;
            app.request_upload(true);
            assert!(app.submitted.is_empty());
            let Some(Confirm::Upload(intent)) = app.confirm.take() else {
                panic!("confirmation")
            };
            app.destination = "/tmp/edited".into();
            if change_session {
                app.snapshot.capture_dir = Some(PathBuf::from("/tmp/restored"));
            }
            app.submit_upload(intent, true);
            if change_session {
                assert!(app.submitted.is_empty() && app.pending_upload.is_none());
            } else {
                assert!(matches!(&app.submitted[0], Command::Upload {
                    destination, overwrite: true, executable: true, ..
                } if destination == "/tmp/guest file"));
                let id = app.pending_upload.as_ref().unwrap().id;
                app.complete_upload(id, true);
                assert!(app.launch_open);
            }
        }
    }

    #[test]
    fn upload_rejects_duplicates_and_stopped_guests() {
        let mut app = upload_app();
        app.request_upload(true);
        app.request_upload(true);
        assert_eq!(app.submitted.len(), 1);
        let mut stopped = upload_app();
        stopped.snapshot.state = VmState::Stopped;
        stopped.request_upload(true);
        assert!(stopped.submitted.is_empty() && stopped.pending_upload.is_none());
    }

    #[test]
    fn upload_tree_preserves_exact_selected_host_path() {
        let mut app = upload_app();
        let path = PathBuf::from("/tmp/ folder / file with trailing space ");
        app.upload_browser.selected = Some(path.clone());
        app.source = path.to_string_lossy().into_owned();
        app.request_upload(false);
        assert!(matches!(&app.submitted[0], Command::Upload { source, .. } if source == &path));
    }

    #[test]
    fn upload_buttons_pointer_clicks_chain_to_run_at_normal_and_large_fonts() {
        for (size, font_size) in [
            (egui::vec2(1280.0, 900.0), 16.0),
            (egui::vec2(800.0, 700.0), 24.0),
        ] {
            let mut app = upload_app();
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font_size);
            click_label(&mut app, &ctx, size, "Upload and Run");
            let id = app
                .pending_upload
                .as_ref()
                .expect("button submits upload")
                .id;
            app.complete_upload(id, true);
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let visible = texts(&render(&mut app, &ctx, size));
            assert!(visible.iter().any(|(text, _)| text == "Run program"));
            assert!(!visible.iter().any(|(text, _)| text == "Upload file"));
            assert_eq!(app.exec.path, "/tmp/guest file");
        }
    }

    #[test]
    fn upload_tree_expands_subfolders_and_selects_file_and_guest_basename() {
        let fixture = upload_browser::tests::Fixture::new();
        let directory = fixture.0.join("nested samples");
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("sample script.sh");
        std::fs::write(&path, b"#!/bin/sh\necho test\n").unwrap();
        let mut app = upload_app();
        app.upload_browser.reset(fixture.0.clone());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        let wait_for = |app: &mut MonitorApp, label: &str| {
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let output = render(app, &ctx, size);
                if texts(&output).iter().any(|(text, _)| text == label) {
                    break;
                }
                assert!(Instant::now() < deadline, "missing {label}");
                std::thread::sleep(Duration::from_millis(10));
            }
        };
        wait_for(&mut app, "nested samples");
        click_label(&mut app, &ctx, size, "nested samples");
        wait_for(&mut app, "sample script.sh");
        click_label(&mut app, &ctx, size, "sample script.sh");
        assert_eq!(app.upload_browser.selected.as_ref(), Some(&path));
        assert_eq!(app.source, path.to_str().unwrap());
        assert_eq!(app.destination, "/tmp/sample script.sh");
        click_label(&mut app, &ctx, size, "Upload and Run");
        assert!(matches!(&app.submitted[0], Command::Upload { source, .. } if source == &path));
    }

    fn event(phase: u8, cpu: u32) -> antinomie_monitor_core::EventSummary {
        antinomie_monitor_core::EventSummary {
            root_task_cookie: 7,
            stream_id: 1,
            task_cookie: 3,
            call_id: 2,
            event_seq: u64::from(phase),
            phase,
            syscall_nr: 0,
            syscall_name: "read".into(),
            pid: 42,
            tid: 42,
            cpu,
            timestamp_ns: 1000,
            args: Some([3, 0x1000, 8, 0, 0, 0]),
            result: (phase == 2).then_some(4),
            complete: true,
            issues: Vec::new(),
            fields: Vec::new(),
        }
    }

    #[test]
    fn invalid_syscall_filter_keeps_the_previous_applied_filter() {
        let mut app = app();
        let invocation = InvocationSummary {
            stream_id: 1,
            task_cookie: 3,
            call_id: 2,
            entry: Some(event(1, 0)),
            exit: None,
            async_events: Vec::new(),
            task_exit: None,
        };
        assert_eq!(app.applied_filter, "");
        assert!(crate::query::compile_note(&app.applied_filter).keep(&invocation));

        app.filter = "read".into();
        let note = app.commit_trace_filter();
        assert!(note.error.is_none());
        assert_eq!(app.applied_filter, "read");
        assert!(crate::query::compile_note(&app.applied_filter).keep(&invocation));

        app.filter = "syscall.typo == 9".into();
        let note = app.commit_trace_filter();
        assert!(note.error.is_some());
        assert_eq!(app.applied_filter, "read");
        assert!(crate::query::compile_note(&app.applied_filter).keep(&invocation));
        assert!(!crate::query::compile_note(&app.filter).keep(&invocation));
    }

    #[test]
    fn archive_filter_changes_cancel_old_scan_preserve_page_and_reject_invalid_draft() {
        let mut app = app();
        let mut past = run("past");
        past.state = RunState::Finalized;
        app.history.push(past);
        app.select_run(Some("past".into()));
        let old_generation = app.archive_generation;
        let old_cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
        app.archive_page = pair_events(&[event(1, 0)]);
        app.archive_previous = vec![0, 100];
        app.selected_event = Some(trace::key(&app.archive_page[0]));
        app.filter = "syscall.num == 9".into();
        assert!(app.commit_trace_filter().error.is_none());
        assert!(old_cancel.load(Ordering::Relaxed));
        assert!(app.archive_previous.is_empty());
        assert_eq!(app.archive_page.len(), 1);
        assert!(app.selected_event.is_none());
        assert!(
            matches!(&app.pending_archive, Some(Request::Invocations { offset: 0, query, .. }) if query == "syscall.num == 9")
        );
        let generation = app.archive_generation;
        app.filter = "syscall.num ==".into();
        assert!(app.commit_trace_filter().error.is_some());
        assert_eq!(app.applied_filter, "syscall.num == 9");
        assert_eq!(app.archive_generation, generation);
        assert!(!app
            .archive_read_cancel
            .as_ref()
            .unwrap()
            .load(Ordering::Relaxed));
        app.handle_archive_answer(Answer::Invocations {
            generation: old_generation,
            offset: 99,
            total: Some(9),
            source_total: Some(350),
            result: Ok(antinomie_monitor_core::InvocationPage {
                invocations: Vec::new(),
                next_offset: None,
                issues: Vec::new(),
            }),
        });
        assert_eq!(app.archive_page.len(), 1);
        assert!(app.archive_pending);
        let selected_cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
        app.select_process(captures::ProcessSelection::Process(99));
        assert!(selected_cancel.load(Ordering::Relaxed));
        assert!(
            matches!(&app.pending_archive, Some(Request::Invocations { offset: 0, pid: Some(99), query, .. }) if query == "syscall.num == 9")
        );
    }

    #[test]
    fn archive_category_predicate_restarts_global_matches_and_retains_visible_selection() {
        let mut app = app();
        let mut past = run("past");
        past.state = RunState::Finalized;
        app.history.push(past);
        app.select_run(Some("past".into()));
        app.archive_page = pair_events(&[event(1, 0)]);
        let selected = trace::key(&app.archive_page[0]);
        app.selected_event = Some(selected);
        app.filter = "syscall.num == 0".into();
        assert!(app.commit_trace_filter().error.is_none());
        assert_eq!(app.selected_event, Some(selected));
        let cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
        let group = SyscallGroup::of("read").unwrap();
        app.settings.hidden_trace_categories = vec![group];
        app.refresh_archive_matches(&crate::query::compile_note(&app.applied_filter));
        assert!(cancel.load(Ordering::Relaxed));
        assert!(app.selected_event.is_none());
        assert_eq!(app.archive_page.len(), 1);
        assert!(
            matches!(&app.pending_archive, Some(Request::Invocations { offset: 0, hidden_categories, .. }) if hidden_categories == &[group])
        );
    }

    #[test]
    fn triage_packets_stay_with_the_live_vm_only() {
        let mut live = app();
        live.network_view
            .open(Some(PathBuf::from("/tmp/live.pcap")));
        assert!(!live.triage_hides_packets());

        live.snapshot.state = VmState::Running;
        live.snapshot.active_vm = Some("vm".into());
        live.snapshot.runs.push(run("live"));
        live.selected_run = Some("live".into());
        assert!(!live.triage_hides_packets());

        let mut past = run("old");
        past.state = RunState::Finished;
        live.history.push(past);
        live.selected_run = Some("old".into());
        assert!(live.triage_hides_packets());

        let mut captured = app();
        captured
            .snapshot
            .captures
            .push(observer("cap", CaptureState::Active));
        captured.selected_capture = Some("cap".into());
        captured
            .network_view
            .open(Some(PathBuf::from("/tmp/live.pcap")));
        assert!(captured.triage_hides_packets());
        assert_eq!(
            captured.network_view.loaded_path(),
            Some(std::path::Path::new("/tmp/live.pcap"))
        );
    }

    fn run(id: &str) -> RunSummary {
        RunSummary {
            id: id.into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            session_id: 1,
            root_task_cookie: 7,
            pid: 42,
            request: ExecRequest::default(),
            directory: PathBuf::new(),
            terminal_eof: false,
            state: RunState::Running,
            recording_error: None,
            execution: None,
            analysis: None,
        }
    }

    fn observer_fixture(app: &mut MonitorApp) {
        app.selected = Some("vm".into());
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.boot_id = Some("boot".into());
        app.snapshot.guest_kernel = Some(antinomie_monitor_core::GuestKernel {
            revision: Some(11),
            source: None,
            release: None,
        });
        app.snapshot.vms.push(VmConfig {
            id: "vm".into(),
            name: "Capture QA".into(),
            ..VmConfig::default()
        });
    }
    #[test]
    fn selecting_another_run_cancels_queued_tree_and_stale_answer() {
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.runs.extend([run("old"), run("new")]);
        app.run_tree_pending = Some("old".into());
        app.pending_archive = Some(Request::ProcessTree {
            run_id: "old".into(),
            directory: PathBuf::new(),
            root_pid: 42,
            path: "/bin/a".into(),
        });
        app.select_run(Some("new".into()));
        assert!(app.run_tree_pending.is_none());
        assert!(app.run_tree.is_none());
        app.handle_archive_answer(Answer::ProcessTree {
            run_id: "old".into(),
            result: Ok((Vec::new(), Vec::new())),
        });
        assert!(app.run_tree.is_none());
    }

    #[test]
    fn run_descendant_filter_applies_to_live_and_saved_trace_requests() {
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.runs.push(run("tree"));
        app.select_run(Some("tree".into()));
        let mut child = event(1, 0);
        child.pid = 99;
        child.tid = 99;
        child.task_cookie = 99;
        app.snapshot.events = vec![event(1, 0), child];
        app.select_process(captures::ProcessSelection::Process(99));
        assert_eq!(app.invocations().len(), 1);
        assert_eq!(app.invocations()[0].entry.as_ref().unwrap().pid, 99);
        app.archive_selected = true;
        app.request_page(0);
        assert!(matches!(
            app.pending_archive,
            Some(Request::Invocations { pid: Some(99), .. })
        ));
    }

    fn observer(id: &str, state: CaptureState) -> CaptureSummary {
        CaptureSummary {
            id: id.into(),
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            capture_cookie: 42,
            scope: antinomie_monitor_core::CaptureScope::AllUserspace,
            directory: PathBuf::from(format!("/capture/{id}")),
            state,
            recording_error: None,
            start_ns: Some(1),
            stop_ns: None,
            incomplete_reason: Some("Admission stop does not fence delivery".into()),
        }
    }

    #[test]
    fn capture_selection_has_independent_events_archive_and_no_terminal() {
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.runs.push(run("launched"));
        app.snapshot.events.push(event(1, 0));
        app.selected_analysis = Some("static-report".into());
        app.analysis_views.insert(
            "workspace".into(),
            AnalysisView {
                report_id: Some("static-report".into()),
                ..Default::default()
            },
        );
        let mut observed = event(1, 2);
        observed.call_id = 77;
        app.snapshot
            .captures
            .push(observer("observation", CaptureState::Stopped));
        app.snapshot
            .capture_events
            .insert("observation".into(), vec![observed]);
        app.select_capture("observation".into(), false);
        assert_eq!(app.invocations()[0].call_id, 77);
        assert_eq!(
            app.invocation_directory(app.invocations().first()),
            Some("/capture/observation".into())
        );
        assert_eq!(app.snapshot.events.len(), 1);
        assert!(app.selected_run.is_none());
        assert!(app.terminals.is_empty());
        assert_eq!(app.selected_analysis.as_deref(), Some("static-report"));
        assert_eq!(
            app.analysis_views["workspace"].report_id.as_deref(),
            Some("static-report")
        );
        app.select_capture("observation".into(), true);
        assert!(
            matches!(&app.pending_archive, Some(Request::Invocations { directory, capture: true, .. }) if directory == &PathBuf::from("/capture/observation"))
        );
        let generation = app.archive_generation;
        app.select_run(Some("launched".into()));
        app.handle_archive_answer(Answer::Invocations {
            generation,
            offset: 0,
            total: None,
            source_total: None,
            result: Ok(antinomie_monitor_core::InvocationPage {
                invocations: pair_events(&[event(1, 9)]),
                next_offset: None,
                issues: Vec::new(),
            }),
        });
        assert!(app.selected_capture.is_none());
        assert_eq!(app.invocations()[0].entry.as_ref().unwrap().cpu, 0);
        assert!(app.terminals.is_empty());
    }

    #[test]
    fn older_observation_uses_archive_when_live_preview_is_absent() {
        let mut app = app();
        observer_fixture(&mut app);
        app.capture_history
            .push(observer("past", CaptureState::Finalized));
        app.select_capture("past".into(), false);
        assert!(matches!(
            app.pending_archive,
            Some(Request::Invocations { capture: true, .. })
        ));
        let generation = app.archive_generation;
        app.handle_archive_answer(Answer::Invocations {
            generation,
            offset: 0,
            total: None,
            source_total: None,
            result: Ok(antinomie_monitor_core::InvocationPage {
                invocations: pair_events(&[event(1, 4)]),
                next_offset: Some(64),
                issues: vec!["Pending tails".into()],
            }),
        });
        assert_eq!(app.invocations()[0].entry.as_ref().unwrap().cpu, 4);
        assert_eq!(app.archive_next, Some(64));
        assert_eq!(app.archive_error.as_deref(), Some("Pending tails"));
        app.history_generation = 2;
        app.handle_archive_answer(Answer::ListCaptures {
            vm_id: "other".into(),
            generation: 2,
            result: Ok(Vec::new()),
        });
        assert_eq!(app.capture_history.len(), 1);
    }

    #[test]
    fn stop_capture_never_submits_program_or_vm_termination() {
        let mut app = app();
        observer_fixture(&mut app);
        assert!(app.observer_start_enabled());
        app.snapshot
            .captures
            .push(observer("active", CaptureState::Active));
        assert!(!app.observer_start_enabled());
        app.stop_observer();
        assert_eq!(app.submitted.len(), 1);
        assert!(
            matches!(&app.submitted[0], Command::StopCapture { capture_id } if capture_id == "active")
        );
        app.pending_observer = Some(9);
        app.stop_observer();
        assert_eq!(app.submitted.len(), 1);
        for revision in [None, Some(10)] {
            app.pending_observer = None;
            app.snapshot.guest_kernel.as_mut().unwrap().revision = revision;
            assert!(!app.observer_supported());
            app.stop_observer();
        }
        assert_eq!(app.submitted.len(), 1);
    }

    #[test]
    fn unknown_quiet_capture_start_remains_stoppable_without_a_cookie() {
        let mut app = app();
        observer_fixture(&mut app);
        let mut capture = observer("unacknowledged", CaptureState::Unknown);
        capture.capture_cookie = 0;
        app.snapshot.captures.push(capture);
        assert!(!app.observer_start_enabled());
        app.stop_observer();
        assert!(
            matches!(&app.submitted[..], [Command::StopCapture { capture_id }] if capture_id == "unacknowledged")
        );
        assert!(app.terminals.is_empty());
    }

    #[test]
    fn process_picker_preserves_task_identity_and_rejects_reused_pid_and_boot() {
        let mut app = app();
        observer_fixture(&mut app);
        let identity = antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 55,
            tgid: 42,
            start_boot_ns: 100,
        };
        app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
            boot_id: "boot".into(),
            after_pid: 0,
            next_pid: 42,
            processes: vec![antinomie_monitor_core::GuestProcess {
                identity: identity.clone(),
                parent_tgid: 1,
                uid: 1000,
                gid: 1000,
                thread_count: 3,
                command: "guest-target".into(),
            }],
        });
        app.open_process_picker();
        assert!(matches!(
            app.submitted.last(),
            Some(Command::ListProcesses { after_pid: 0 })
        ));
        app.process_picker.selected = Some(identity.clone());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(800.0, 600.0);
        render(&mut app, &ctx, size);
        assert_eq!(app.process_picker.selected.as_ref(), Some(&identity));
        app.snapshot.process_page.as_mut().unwrap().processes[0]
            .identity
            .task_cookie = 56;
        render(&mut app, &ctx, size);
        assert!(app.process_picker.selected.is_none());
        app.process_picker.selected = Some(identity);
        app.snapshot.boot_id = Some("new-boot".into());
        render(&mut app, &ctx, size);
        assert!(app.process_picker.selected.is_none());
        assert!(app
            .submitted
            .iter()
            .all(|command| matches!(command, Command::ListProcesses { .. })));
    }

    #[test]
    fn capture_process_and_history_layout_remain_visible_with_large_fonts() {
        for size in [egui::vec2(800.0, 600.0), egui::vec2(1280.0, 820.0)] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, 24.0);
            let mut app = app();
            observer_fixture(&mut app);
            app.settings.font_size = 24.0;
            app.process_picker.open = true;
            let identity = antinomie_monitor_core::GuestProcessIdentity {
                boot_id: "boot".into(),
                task_cookie: 55,
                tgid: 42,
                start_boot_ns: 100,
            };
            app.process_picker.selected = Some(identity.clone());
            app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
                boot_id: "boot".into(),
                processes: (1..=64)
                    .map(|index| antinomie_monitor_core::GuestProcess {
                        identity: antinomie_monitor_core::GuestProcessIdentity {
                            task_cookie: if index == 1 { 55 } else { index },
                            ..identity.clone()
                        },
                        parent_tgid: 1,
                        uid: 1000,
                        gid: 1000,
                        thread_count: 3,
                        command: format!("guest-process-{index}"),
                    })
                    .collect(),
                ..Default::default()
            });
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            let visible = texts(&output);
            assert!(
                visible
                    .iter()
                    .any(|(text, _)| text == &format!("{} Attach", egui_phosphor::regular::PLUG)),
                "selected64rowpickeractionsclipped: {visible:?}"
            );
            for label in [
                "Attach to process",
                "PID",
                "Name",
                "UID",
                "Threads",
                "Cancel",
            ] {
                assert!(
                    visible.iter().any(|(text, _)| text == label),
                    "missing or clipped {label} at {size:?}: {visible:?}"
                );
            }
            app.process_picker.open = false;
            app.capture_tab = true;
            app.snapshot
                .captures
                .push(observer("active", CaptureState::Active));
            app.layout.focus(Panel::RunHistory);
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            assert!(texts(&output).iter().any(|(text, _)| text == "Captures"));
        }
    }

    #[test]
    fn history_tabs_switch_back_from_captures_with_empty_and_populated_lists() {
        for populated in [false, true] {
            for (size, font_size) in [
                (egui::vec2(1280.0, 820.0), 16.0),
                (egui::vec2(800.0, 600.0), 24.0),
            ] {
                let ctx = egui::Context::default();
                theme::install(&ctx);
                theme::text_size(&ctx, font_size);
                let mut app = app();
                observer_fixture(&mut app);
                app.settings.font_size = font_size;
                if populated {
                    app.snapshot.runs.push(run("live-run"));
                    app.snapshot
                        .captures
                        .push(observer("active", CaptureState::Active));
                }
                app.layout.focus(Panel::RunHistory);
                for _ in 0..3 {
                    click_label(&mut app, &ctx, size, "Captures");
                    assert!(app.capture_tab, "Captures must open at {size:?}");
                    click_label(&mut app, &ctx, size, "Runs");
                    assert!(
                        !app.capture_tab,
                        "Runs must reopen at {size:?}, populated={populated}"
                    );
                }
            }
        }
    }

    #[test]
    fn core_picker_captures_the_complete_identity_and_requires_supported_selected_vm() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(15);
        app.open_core_picker();
        assert!(!app.process_picker.open);
        assert!(app
            .manual_core_unavailable()
            .unwrap()
            .contains("revision 16"));
        app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(16);
        let identity = antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 55,
            tgid: 42,
            start_boot_ns: 100,
        };
        app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
            boot_id: "boot".into(),
            after_pid: 0,
            next_pid: 42,
            processes: vec![antinomie_monitor_core::GuestProcess {
                identity: identity.clone(),
                parent_tgid: 1,
                uid: 1000,
                gid: 1000,
                thread_count: 3,
                command: "core-target".into(),
            }],
        });
        app.open_core_picker();
        assert!(matches!(
            app.submitted.last(),
            Some(Command::ListProcesses { after_pid: 0 })
        ));
        let size = egui::vec2(1000.0, 800.0);
        click_label(&mut app, &ctx, size, "core-target");
        assert_eq!(app.process_picker.selected.as_ref(), Some(&identity));
        // The foreground picker and background panel share the same action
        // name. Click the foreground button rather than the toolbar/panel.
        let output = render(&mut app, &ctx, size);
        let label = format!("{} Dump core", egui_phosphor::regular::FILE);
        let position = texts(&output)
            .iter()
            .rfind(|(text, _)| text == &label)
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events: vec![
                        egui::Event::PointerMoved(position),
                        egui::Event::PointerButton {
                            pos: position,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert!(
            matches!(app.submitted.last(), Some(Command::DumpProcessCore { request })
            if request.target == identity && request.vm_id == "vm" && request.max_size == 64 * 1024 * 1024
                && request.timeout_ms == 5000 && request.source_run_id.is_none())
        );
        assert!(!app.process_picker.open);
        assert!(!app
            .submitted
            .iter()
            .any(|command| matches!(command, Command::AttachProcess { .. })));
        app.selected = Some("other-vm".into());
        assert!(app.manual_core_unavailable().is_some());
        app.open_core_picker();
        assert!(!app.process_picker.open);
    }

    #[test]
    fn process_picker_click_attaches_the_complete_identity_and_filters() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        observer_fixture(&mut app);
        let identity = antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 55,
            tgid: 42,
            start_boot_ns: 100,
        };
        app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
            boot_id: "boot".into(),
            after_pid: 0,
            next_pid: 42,
            processes: vec![antinomie_monitor_core::GuestProcess {
                identity: identity.clone(),
                parent_tgid: 1,
                uid: 1000,
                gid: 1000,
                thread_count: 3,
                command: "guest-target".into(),
            }],
        });
        app.open_process_picker();
        let size = egui::vec2(800.0, 600.0);
        click_label(&mut app, &ctx, size, "guest-target");
        assert_eq!(app.process_picker.selected.as_ref(), Some(&identity));
        click_label(
            &mut app,
            &ctx,
            size,
            &format!("{} Attach", egui_phosphor::regular::PLUG),
        );
        assert!(
            matches!(app.submitted.last(), Some(Command::AttachProcess { identity: selected }) if selected == &identity)
        );
        assert!(!app.process_picker.open);
        assert!(app.terminals.is_empty());
        // The backend lists every page at once; the picker filters by name or PID.
        app.open_process_picker();
        for (filter, shown) in [("target", true), ("4", true), ("sshd", false)] {
            app.process_picker.filter = filter.into();
            for _ in 0..2 {
                render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            assert_eq!(
                texts(&output)
                    .iter()
                    .any(|(text, _)| text == "guest-target"),
                shown,
                "{filter}"
            );
        }
    }

    #[test]
    #[ignore = "requires X11 capture controls preview; automatically exits after 12 seconds"]
    fn native_capture_controls_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct QaApp {
            app: MonitorApp,
            deadline: Instant,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                if Instant::now() >= self.deadline {
                    eprintln!("native capture QA commands: {:?}", self.app.submitted);
                    assert!(self.app.terminals.is_empty());
                    assert!(self.app.submitted.iter().all(|command| matches!(
                        command,
                        Command::ListProcesses { .. }
                            | Command::AttachProcess { .. }
                            | Command::CaptureAll
                            | Command::StopCapture { .. }
                    )));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return;
                }
                eframe::App::update(&mut self.app, ctx, frame);
            }
        }
        let small = std::env::var_os("ANTINOMIE_CAPTURE_QA_SMALL").is_some();
        let picker = std::env::var_os("ANTINOMIE_CAPTURE_QA_PICKER").is_some();
        eframe::run_native(
            "Antinomie Capture QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size(if small {
                    [800.0, 600.0]
                } else {
                    [1280.0, 820.0]
                }),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 18.0 });
                let mut app = app();
                observer_fixture(&mut app);
                app.settings.font_size = if small { 24.0 } else { 18.0 };
                app.snapshot
                    .captures
                    .push(observer("previous-observation", CaptureState::Stopped));
                app.snapshot.capture_events.insert(
                    "previous-observation".into(),
                    vec![event(1, 0), event(2, 1)],
                );
                app.capture_tab = true;
                app.layout.focus(Panel::RunHistory);
                if picker {
                    app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
                        boot_id: "boot".into(),
                        after_pid: 0,
                        next_pid: 64,
                        processes: (1..=64)
                            .map(|pid| antinomie_monitor_core::GuestProcess {
                                identity: antinomie_monitor_core::GuestProcessIdentity {
                                    boot_id: "boot".into(),
                                    task_cookie: u64::from(pid),
                                    tgid: pid,
                                    start_boot_ns: u64::from(pid) * 100,
                                },
                                parent_tgid: 1,
                                uid: 1000,
                                gid: 1000,
                                thread_count: 2,
                                command: format!("guest-process-{pid}"),
                            })
                            .collect(),
                    });
                    app.open_process_picker();
                }
                Ok(Box::new(QaApp {
                    app,
                    deadline: Instant::now() + Duration::from_secs(12),
                }))
            }),
        )
        .unwrap();
    }

    fn render(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        )
    }

    fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect)> {
        fn collect(shape: &egui::Shape, clip: egui::Rect, texts: &mut Vec<(String, egui::Rect)>) {
            match shape {
                egui::Shape::Text(text) => {
                    let rect = text.visual_bounding_rect();
                    if clip.contains_rect(rect) {
                        // Dock tab names carry padding spaces.
                        texts.push((text.galley.text().trim().to_owned(), rect));
                    }
                }
                egui::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, clip, texts);
                    }
                }
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, shape.clip_rect, &mut texts);
        }
        texts
    }

    fn click_label(app: &mut MonitorApp, ctx: &egui::Context, size: egui::Vec2, label: &str) {
        for _ in 0..3 {
            render(app, ctx, size);
        }
        let output = render(app, ctx, size);
        let visible = texts(&output);
        let pos = visible
            .iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing or clipped {label}: {visible:?}"))
            .1
            .center();
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
    }

    #[test]
    fn long_health_messages_do_not_overlap_figures_and_keep_full_hover_text() {
        let error = "guest command 25713 timed out: outcome unknown; run status polling paused until its reply arrives or transport reconnects";
        let closing = "Waiting for guest shutdown and recording finalization…";
        for (width, font_size) in [(1280.0, 16.0), (800.0, 24.0)] {
            for shutting_down in [false, true] {
                let mut app = app();
                let ctx = egui::Context::default();
                theme::install(&ctx);
                theme::text_size(&ctx, font_size);
                ctx.style_mut(|style| {
                    style.interaction.tooltip_delay = 0.0;
                    style.interaction.tooltip_grace_time = 0.0;
                });
                app.closing = shutting_down;
                let message = if shutting_down { closing } else { error };
                if !shutting_down {
                    app.snapshot.last_error = Some(error.into());
                }
                let size = egui::vec2(width, 900.0);
                let mut output = egui::FullOutput::default();
                for frame in 0..4 {
                    output = ctx.run(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                            time: Some(frame as f64),
                            ..Default::default()
                        },
                        |ctx| app.health(ctx),
                    );
                }
                let visible = texts(&output);
                let message_rect = visible
                    .iter()
                    .find(|(text, _)| text == message)
                    .unwrap_or_else(|| {
                        panic!("missing bounded message at {width}/{font_size}: {visible:?}")
                    })
                    .1;
                let mut figure_rects = Vec::new();
                let app_label = format!("Antinomie {APP_VERSION}");
                for label in ["TRL", "UIL", "STL", "CAP 0.0/4 GiB", &app_label] {
                    let rect = visible
                        .iter()
                        .find(|(text, _)| text == label)
                        .unwrap_or_else(|| panic!("missing figure {label}: {visible:?}"))
                        .1;
                    assert!(
                        rect.min.x >= 0.0 && rect.max.x <= width,
                        "figure remains inside viewport"
                    );
                    assert!(
                        !rect.intersects(message_rect),
                        "message overlaps {label}: {message_rect:?} / {rect:?}"
                    );
                    figure_rects.push(rect);
                }
                assert!(
                    message_rect.max.x
                        < figure_rects
                            .iter()
                            .map(|rect| rect.min.x)
                            .fold(f32::INFINITY, f32::min)
                );
                assert!(
                    message_rect.height() <= font_size * 1.6,
                    "status stays one compact row"
                );
                let mut hovered = output;
                for frame in 4..8 {
                    hovered = ctx.run(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                            time: Some(frame as f64),
                            events: vec![egui::Event::PointerMoved(message_rect.center())],
                            ..Default::default()
                        },
                        |ctx| app.health(ctx),
                    );
                }
                assert!(
                    texts(&hovered)
                        .iter()
                        .any(|(text, rect)| text == message && rect.min.y < message_rect.min.y),
                    "hover preserves the complete message above the footer"
                );
            }
        }
    }

    #[test]
    fn launch_controls_edit_create_and_save_owned_configurations() {
        let mut app = app();
        app.snapshot.bases.push(test_base("capable", true));
        app.new_image();
        app.draft.disk_root = Some("/disks".into());
        app.draft.recording_root = Some("/recordings".into());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for label in [
            "Auto",
            "1920 x 1080",
            "Fullscreen",
            "Fit to window",
            "Default",
            "TCG",
            "Default",
            "max",
            "Create VM",
        ] {
            click_label(&mut app, &ctx, size, label);
        }
        let mut created = app
            .submitted
            .iter()
            .find_map(|command| match command {
                Command::Create(vm) => Some(vm.clone()),
                _ => None,
            })
            .expect("create command");
        assert_eq!(
            created.launch,
            VmLaunchOptions {
                resolution: DisplayResolution::R1920x1080,
                fullscreen: true,
                fit_to_window: true,
                acceleration: VmAcceleration::Tcg,
                cpu_model: VmCpuModel::Max,
            }
        );
        assert_eq!(created.disk_root, Some(PathBuf::from("/disks")));
        assert_eq!(created.recording_root, Some(PathBuf::from("/recordings")));
        assert!(!app.create_open);
        created.id = "created".into();
        app.selected = Some(created.id.clone());
        app.snapshot.vms.push(created.clone());
        app.configure_vm();
        assert_eq!(app.draft.launch, created.launch);
        for label in [
            "1920 x 1080",
            "1280 x 800",
            "max",
            "qemu64",
            "Save configuration",
        ] {
            click_label(&mut app, &ctx, size, label);
        }
        let saved = app
            .submitted
            .iter()
            .find_map(|command| match command {
                Command::Save(vm) => Some(vm),
                _ => None,
            })
            .expect("save command");
        assert_eq!(saved.launch.resolution, DisplayResolution::R1280x800);
        assert_eq!(saved.launch.cpu_model, VmCpuModel::Qemu64);
        assert!(saved.launch.fullscreen && saved.launch.fit_to_window);
        assert_eq!(saved.launch.acceleration, VmAcceleration::Tcg);
        assert_eq!(saved.disk_root, created.disk_root);
        assert_eq!(saved.recording_root, created.recording_root);
        assert!(!app.config_open);
    }

    #[test]
    fn invalid_launch_options_explain_create_and_save_rejection() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for (acceleration, force_tcg) in [
            (VmAcceleration::Tcg, false),
            (VmAcceleration::Default, true),
            (VmAcceleration::Kvm, true),
        ] {
            let mut app = app();
            app.new_image();
            app.options.force_tcg = force_tcg;
            app.draft.launch.cpu_model = VmCpuModel::Host;
            app.draft.launch.acceleration = acceleration;
            app.credentials.password = "private-test-secret".into();
            let error = app.create_vm().unwrap_err();
            assert!(error.contains("requires KVM"));
            assert!(!error.contains(&app.credentials.password));
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            assert!(texts(&output).iter().any(|(text, _)| text == &error));
            click_label(&mut app, &ctx, size, "Create VM");
            assert!(app.submitted.is_empty());
            assert!(app.create_open);

            app.create_open = false;
            app.draft.id = "saved".into();
            app.snapshot.vms.push(app.draft.clone());
            app.config_open = true;
            assert_eq!(app.save_vm(app.draft.clone()).unwrap_err(), error);
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            assert!(texts(&output).iter().any(|(text, _)| text == &error));
            click_label(&mut app, &ctx, size, "Save configuration");
            assert!(app.submitted.is_empty());
            assert!(app.config_open);
        }
    }

    #[test]
    fn launch_settings_save_requires_a_stopped_existing_vm() {
        let mut app = app();
        app.draft.id = "vm".into();
        app.snapshot.vms.push(app.draft.clone());
        app.snapshot.active_vm = Some("vm".into());
        app.config_open = true;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, 24.0);
        let size = egui::vec2(1280.0, 900.0);
        click_label(&mut app, &ctx, size, "Fullscreen");
        click_label(&mut app, &ctx, size, "Save configuration");
        assert!(!app.draft.launch.fullscreen);
        assert!(app
            .save_vm(app.draft.clone())
            .unwrap_err()
            .contains("Stop this VM"));
        assert!(app.submitted.is_empty());
        app.snapshot.active_vm = None;
        app.snapshot.vms.clear();
        assert!(app
            .save_vm(app.draft.clone())
            .unwrap_err()
            .contains("no longer available"));
        assert!(app.submitted.is_empty());
    }

    fn test_base(id: &str, fixed_display: bool) -> BaseSummary {
        BaseSummary {
            id: id.into(),
            label: "Linux 6.12.94".into(),
            directory: PathBuf::from(format!("/bases/{id}")),
            guest: None,
            min_ram_mib: 256,
            min_disk_gib: 1,
            fixed_display,
            size_bytes: 0,
            revision: Some(APP_REVISION),
            min_app_version: None,
            built_with: None,
        }
    }

    #[test]
    fn trace_coloring_is_on_by_default_and_old_settings_still_load() {
        let settings = Settings::default();
        assert!(settings.trace_colors);
        assert!(settings.hidden_trace_categories.is_empty());
        // Groups hidden from the earlier color legend are not carried over.
        let earlier: Settings =
            serde_json::from_str(r#"{"hidden_trace_groups": ["File"]}"#).unwrap();
        assert!(earlier.hidden_trace_categories.is_empty());
        let old: Settings = serde_json::from_str(
            r#"{"bundle": "", "quota_gib": 4, "timeout": 10, "font_size": 16.0}"#,
        )
        .unwrap();
        assert!(old.trace_colors);
    }

    #[test]
    fn download_catalog_prioritizes_current_bases_and_hides_older_ones() {
        let mut app = app();
        app.download_open = true;
        app.snapshot.remote_bases = vec![
            catalog_base("old", Some(9)),
            catalog_base("future", Some(APP_REVISION + 1)),
            catalog_base("current", Some(APP_REVISION)),
            catalog_base("legacy", None),
        ];
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let visible = texts(&render(&mut app, &ctx, size));
        assert!(visible.iter().any(|(text, _)| text
            == &format!(
                "current · Antinomie {}",
                antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
            )));
        assert!(!visible
            .iter()
            .any(|(text, _)| text.starts_with("old ·") || text == "legacy"));
        let current = visible
            .iter()
            .find(|(text, _)| text.starts_with("current ·"))
            .unwrap()
            .1;
        let future = visible.iter().find(|(text, _)| text == "future").unwrap().1;
        assert!(current.top() < future.top());
        click_label(&mut app, &ctx, size, "Show older bases (2)");
        let visible = texts(&render(&mut app, &ctx, size));
        assert!(visible
            .iter()
            .any(|(text, _)| text == "old · Antinomie 0.1.0"));
        assert!(visible.iter().any(|(text, _)| text == "legacy"));
        assert_eq!(
            RevisionStatus::of_base(Some(APP_REVISION), Some("0.3.0")),
            RevisionStatus::Current
        );
    }

    fn catalog_base(label: &str, revision: Option<u32>) -> antinomie_monitor_core::RemoteBase {
        antinomie_monitor_core::RemoteBase {
            identity: format!("{label:0<64}"),
            label: label.into(),
            kind: "busybox".into(),
            kernel_version: "6.12.94".into(),
            fixed_display: true,
            min_ram_mib: 256,
            min_disk_gib: 1,
            total_size: 1024 * 1024,
            revision,
            min_app_version: None,
            built_with: None,
        }
    }

    #[test]
    fn cancel_remains_reachable_when_the_active_base_is_hidden_or_removed() {
        for size in [egui::vec2(800.0, 600.0), egui::vec2(1440.0, 900.0)] {
            let mut app = app();
            app.download_open = true;
            let old = catalog_base("old", Some(APP_REVISION - 1));
            app.snapshot.download = Some(antinomie_monitor_core::DownloadStatus {
                identity: old.identity.clone(),
                label: old.label.clone(),
                received: 128,
                total: old.total_size,
                ..Default::default()
            });
            app.snapshot.remote_bases = vec![old, catalog_base("current", Some(APP_REVISION))];
            let ctx = egui::Context::default();
            theme::install(&ctx);
            click_label(&mut app, &ctx, size, "Cancel");
            assert!(matches!(
                app.submitted.last(),
                Some(Command::CancelDownload)
            ));
            app.snapshot.remote_bases.clear();
            app.submitted.clear();
            click_label(&mut app, &ctx, size, "Cancel");
            assert!(matches!(
                app.submitted.last(),
                Some(Command::CancelDownload)
            ));
            app.snapshot.download.as_mut().unwrap().installing = true;
            app.submitted.clear();
            click_label(&mut app, &ctx, size, "Cancel");
            assert!(
                app.submitted.is_empty(),
                "installation must finish before another action"
            );
        }
    }

    #[test]
    fn startup_checking_does_not_show_a_missing_base_warning() {
        let mut app = app();
        app.snapshot.bases_checking = true;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let visible = texts(&render(&mut app, &ctx, size));
        assert!(visible
            .iter()
            .any(|(text, _)| text == "Checking base images…"));
        assert!(!visible.iter().any(|(text, _)| text == "No base images"));
        app.snapshot.bases_checking = false;
        assert!(texts(&render(&mut app, &ctx, size))
            .iter()
            .any(|(text, _)| text == "No base images"));
    }

    #[test]
    fn base_labels_name_outdated_newer_and_unrecorded_revisions() {
        let mut base = base_summary_for_revision(Some(APP_REVISION));
        assert_eq!(
            base_choice_label(&base),
            format!(
                "Debian · Antinomie {}",
                antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
            )
        );
        base.revision = Some(APP_REVISION - 1);
        assert!(base_choice_label(&base).ends_with(", outdated"));
        base.revision = Some(APP_REVISION + 1);
        assert!(base_choice_label(&base).contains("needs a newer Antinomie"));
        base.revision = None;
        assert!(base_choice_label(&base).contains("built before versioning"));
    }

    fn base_summary_for_revision(revision: Option<u32>) -> BaseSummary {
        BaseSummary {
            id: "b".repeat(64),
            label: "Debian".into(),
            directory: PathBuf::from("/bases/b"),
            guest: None,
            min_ram_mib: 256,
            min_disk_gib: 1,
            fixed_display: true,
            size_bytes: 0,
            revision,
            min_app_version: None,
            built_with: None,
        }
    }

    #[test]
    fn base_rows_are_left_aligned_and_a_click_only_selects() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = app();
        app.snapshot.bases = vec![test_base("first", true), test_base("second", true)];
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let texts = texts(&render(&mut app, &ctx, size));
        let rows: Vec<_> = texts
            .iter()
            .filter(|(text, _)| {
                text.contains(&format!(
                    "Linux 6.12.94 · Antinomie {}",
                    antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
                ))
            })
            .map(|(_, rect)| *rect)
            .collect();
        let title = texts
            .iter()
            .find(|(text, _)| text == "Base images")
            .expect("base images title")
            .1;
        assert_eq!(rows.len(), 2);
        // Left-aligned with the section title (after the row's status
        // mark), not centred in the sidebar.
        assert!(
            rows.iter().all(|row| row.left() < title.left() + 16.0),
            "{rows:?} {title:?}"
        );
        let target = rows[1].center();
        let click = |pressed| egui::Event::PointerButton {
            pos: target,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        };
        for events in [
            vec![egui::Event::PointerMoved(target)],
            vec![click(true)],
            vec![click(false)],
        ] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events,
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert_eq!(app.selected_base.as_deref(), Some("second"));
        // Selecting a base starts nothing: no dialog, no command.
        assert!(app.submitted.is_empty());
        assert!(app.confirm.is_none());
    }

    #[test]
    fn section_headers_share_a_layout_and_the_add_control_lights_on_hover() {
        fn lit(output: &egui::FullOutput, point: egui::Pos2) -> bool {
            fn find(shape: &egui::Shape, point: egui::Pos2) -> bool {
                match shape {
                    egui::Shape::Rect(rect) => {
                        rect.fill == theme::primary() && rect.rect.contains(point)
                    }
                    egui::Shape::Vec(shapes) => shapes.iter().any(|shape| find(shape, point)),
                    _ => false,
                }
            }
            output.shapes.iter().any(|shape| find(&shape.shape, point))
        }
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = app();
        app.snapshot.bases = vec![test_base("first", true)];
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let shown = texts(&output);
        let header = |title: &str| {
            let title = shown
                .iter()
                .find(|(text, _)| text == title)
                .unwrap_or_else(|| panic!("missing {title}"))
                .1;
            let add = shown
                .iter()
                .find(|(text, rect)| {
                    text == egui_phosphor::regular::PLUS
                        && rect.center().y > title.top()
                        && rect.center().y < title.bottom()
                })
                .unwrap_or_else(|| panic!("missing + beside {title:?}"))
                .1;
            (title, add)
        };
        let (vm_title, vm_add) = header("Virtual machines");
        let (base_title, base_add) = header("Base images");
        // Glyph side bearings differ by about a pixel between the two titles.
        assert!(
            (vm_title.left() - base_title.left()).abs() < 2.0,
            "{vm_title:?} {base_title:?}"
        );
        assert!((vm_add.center().x - base_add.center().x).abs() < 0.5);
        assert!((vm_add.height() - base_add.height()).abs() < 0.5);
        assert!(!lit(&output, base_add.center()));

        let target = base_add.center();
        let frame = |app: &mut MonitorApp, events| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events,
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            )
        };
        let _ = frame(&mut app, vec![egui::Event::PointerMoved(target)]);
        let hovered = frame(&mut app, vec![]);
        assert!(lit(&hovered, target), "hovered + must light up");
        let click = |pressed| egui::Event::PointerButton {
            pos: target,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::default(),
        };
        let _ = frame(&mut app, vec![click(true)]);
        let _ = frame(&mut app, vec![click(false)]);
        let opened = frame(&mut app, vec![]);
        assert!(texts(&opened)
            .iter()
            .any(|(text, _)| text == "Import base…"));
        assert!(lit(&opened, target), "+ stays lit while its menu is open");
    }

    fn press(
        app: &mut MonitorApp,
        ctx: &egui::Context,
        size: egui::Vec2,
        key: egui::Key,
        modifiers: egui::Modifiers,
    ) {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                modifiers,
                events: vec![egui::Event::Key {
                    key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers,
                }],
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }

    /// The color of the first text shape that reads `label`.
    fn text_color(output: &egui::FullOutput, label: &str) -> Option<egui::Color32> {
        fn find(shape: &egui::Shape, label: &str) -> Option<egui::Color32> {
            match shape {
                egui::Shape::Text(text) if text.galley.text() == label => Some(
                    text.galley
                        .job
                        .sections
                        .first()
                        .map_or(text.fallback_color, |section| section.format.color),
                ),
                egui::Shape::Vec(shapes) => shapes.iter().find_map(|shape| find(shape, label)),
                _ => None,
            }
        }
        output
            .shapes
            .iter()
            .find_map(|shape| find(&shape.shape, label))
    }

    #[test]
    fn escape_closes_the_topmost_dialog_first() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        let mut app = app();
        observer_fixture(&mut app);
        app.settings_open = true;
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        // Opened later, so drawn on top.
        app.upload_open = true;
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        press(
            &mut app,
            &ctx,
            size,
            egui::Key::Escape,
            egui::Modifiers::NONE,
        );
        assert!(!app.upload_open, "Escape closes the window on top");
        assert!(app.settings_open, "and only that one");
        render(&mut app, &ctx, size);
        press(
            &mut app,
            &ctx,
            size,
            egui::Key::Escape,
            egui::Modifiers::NONE,
        );
        assert!(!app.settings_open);

        // A confirmation is modal: Escape cancels it and leaves its dialog.
        app.snapshot.active_vm = None;
        app.new_image();
        app.confirm = Some(Confirm::Nat {
            vm: app.draft.clone(),
            creating: true,
        });
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        press(
            &mut app,
            &ctx,
            size,
            egui::Key::Escape,
            egui::Modifiers::NONE,
        );
        assert!(app.confirm.is_none());
        assert!(app.create_open);
        assert!(app.submitted.is_empty());
        render(&mut app, &ctx, size);
        press(
            &mut app,
            &ctx,
            size,
            egui::Key::Escape,
            egui::Modifiers::NONE,
        );
        assert!(!app.create_open);

        // Every dialog Escape knows about closes.
        for dialog in Dialog::ALL {
            let mut app = super::tests::app();
            match dialog {
                Dialog::Confirm => app.confirm = Some(Confirm::Delete("vm".into())),
                Dialog::Name => app.name_action = Some(("vm".into(), false, "VM".into())),
                Dialog::Transport => {
                    app.new_image();
                    app.transport_open = true;
                }
                Dialog::Vm => app.new_image(),
                Dialog::Launch => app.launch_open = true,
                Dialog::Upload => app.upload_open = true,
                Dialog::Settings => app.settings_open = true,
                Dialog::Import => app.import_open = true,
                Dialog::Download => app.download_open = true,
                Dialog::Tools => app.tools_open = true,
                Dialog::Samples => app.samples.open = true,
                Dialog::Dependencies => app.dependencies.open = true,
                Dialog::About => app.about_open = true,
                Dialog::Build => app.build_open = true,
                Dialog::Attach => app.process_picker.open = true,
                Dialog::Snapshots => app.vm_snapshots.bind("vm", "VM"),
                Dialog::SnapshotDecision => {
                    app.vm_snapshots.bind("vm", "VM");
                    app.vm_snapshots.ask_create();
                }
            }
            let ctx = egui::Context::default();
            theme::install(&ctx);
            for _ in 0..3 {
                render(&mut app, &ctx, size);
            }
            assert!(app.dialog_open(dialog), "{dialog:?}");
            press(
                &mut app,
                &ctx,
                size,
                egui::Key::Escape,
                egui::Modifiers::NONE,
            );
            assert!(!app.dialog_open(dialog), "Escape left {dialog:?} open");
        }
    }

    #[test]
    fn toolbar_keeps_the_main_actions_and_menus_reach_the_rest() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.vms[0].nat = true;
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let shown = texts(&output);
        let run = shown
            .iter()
            .find(|(text, _)| text.ends_with("Run program"))
            .expect("Run program on the toolbar")
            .1;
        let toolbar: Vec<String> = shown
            .iter()
            .filter(|(text, rect)| {
                (rect.center().y - run.center().y).abs() < 6.0 && text.chars().count() > 1
            })
            .map(|(text, _)| text.chars().filter(|c| c.is_ascii()).collect())
            .collect();
        assert_eq!(
            toolbar,
            [
                "Start",
                "Stop",
                "Snapshots",
                "Run program",
                "Capture all",
                "Capture network",
                "Dump memory",
                "Dump core"
            ],
            "{shown:?}"
        );
        // Running VM: Stop is red and Start is grayed out.
        let colored = |label: &str| {
            text_color(
                &output,
                &shown
                    .iter()
                    .find(|(text, _)| text.ends_with(label))
                    .unwrap()
                    .0,
            )
        };
        assert_eq!(colored("Stop"), Some(theme::error()));
        assert_eq!(colored("Start"), Some(theme::muted()));
        assert_eq!(colored("Run program"), Some(theme::blue()));

        // The actions that left the toolbar are in the menus.
        for (menu, items) in [
            ("File", vec!["New VM…", "Exit"]),
            (
                "VM",
                vec![
                    "Start VM",
                    "Stop VM",
                    "Configuration…",
                    "Reset disk to base…",
                ],
            ),
            (
                "Run",
                vec![
                    "Run program…",
                    "Upload file…",
                    "Attach to process…",
                    "Capture all",
                    "Stop capture",
                    "Capture network",
                ],
            ),
            (
                "Tools",
                vec!["Settings…", "Analysis tools…", "App dependencies…"],
            ),
        ] {
            click_label(&mut app, &ctx, size, menu);
            let output = render(&mut app, &ctx, size);
            let shown = texts(&output);
            for item in items {
                assert!(
                    shown.iter().any(|(text, _)| text == item),
                    "{menu} menu lacks {item}: {shown:?}"
                );
            }
            click_label(&mut app, &ctx, size, menu);
        }
        assert!(app.submitted.is_empty());

        // Shortcuts open the dialogs and stop the VM.
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = super::tests::app();
        observer_fixture(&mut app);
        render(&mut app, &ctx, size);
        press(
            &mut app,
            &ctx,
            size,
            egui::Key::Comma,
            egui::Modifiers::COMMAND,
        );
        assert!(app.settings_open);
        press(&mut app, &ctx, size, egui::Key::R, egui::Modifiers::COMMAND);
        assert!(app.launch_open);
        press(&mut app, &ctx, size, egui::Key::U, egui::Modifiers::COMMAND);
        assert!(app.upload_open);
        press(&mut app, &ctx, size, egui::Key::F5, egui::Modifiers::SHIFT);
        assert!(matches!(app.submitted.as_slice(), [Command::Stop]));
        // F5 starts the selected VM once none runs.
        app.snapshot.active_vm = None;
        app.snapshot.state = VmState::Stopped;
        press(&mut app, &ctx, size, egui::Key::F5, egui::Modifiers::NONE);
        assert!(matches!(app.submitted.last(), Some(Command::Start { vm_id }) if vm_id == "vm"));
    }

    #[test]
    fn sidebar_shows_each_vm_state_resources_and_latest_run() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.bases.push(test_base("base", true));
        app.snapshot.vms[0].base_identity = Some("base".into());
        app.snapshot.vms[0].cpus = 2;
        app.snapshot.vms[0].ram_mib = 1024;
        app.snapshot.vms.push(VmConfig {
            id: "idle".into(),
            name: "Idle VM".into(),
            ..VmConfig::default()
        });
        let mut sample = run("run-1");
        sample.request.path = "/usr/bin/sample".into();
        app.snapshot.runs.push(sample);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let shown = texts(&output);
        let title = shown
            .iter()
            .find(|(text, _)| text == "Virtual machines")
            .unwrap()
            .1;
        let sidebar: Vec<&(String, egui::Rect)> = shown
            .iter()
            .filter(|(_, rect)| rect.right() <= title.left() + 260.0 && rect.top() > title.bottom())
            .collect();
        let row = |name: &str| {
            sidebar
                .iter()
                .find(|(text, _)| text == name)
                .unwrap_or_else(|| panic!("missing {name}: {sidebar:?}"))
                .1
        };
        let state_beside = |name: &str, state: &str| {
            let name = row(name);
            sidebar
                .iter()
                .find(|(text, rect)| {
                    text == state && (rect.center().y - name.center().y).abs() < 6.0
                })
                .unwrap_or_else(|| panic!("no {state} beside {name:?}"))
                .1
        };
        state_beside("Capture QA", "Running");
        state_beside("Idle VM", "Stopped");
        assert_eq!(text_color(&output, "Running"), Some(theme::good()));
        let details: Vec<&String> = sidebar.iter().map(|(text, _)| text).collect();
        assert!(
            details.iter().any(|text| text.starts_with("Linux 6.12.94")
                && text.contains("2 CPU")
                && text.contains("1024 MiB")),
            "{details:?}"
        );
        assert!(
            details
                .iter()
                .any(|text| text.contains("sample") && text.contains("just now")),
            "{details:?}"
        );
        assert!(details.iter().any(|text| text.as_str() == "No recent run"));
        assert_eq!(
            app.settings
                .last_runs
                .get("vm")
                .map(|last| last.program.as_str()),
            Some("/usr/bin/sample")
        );

        // The base section folds away.
        assert!(details
            .iter()
            .any(|text| text.contains("Linux 6.12.94 · Antinomie")));
        click_label(&mut app, &ctx, size, "Base images");
        assert!(app.settings.bases_collapsed);
        let output = render(&mut app, &ctx, size);
        assert!(!texts(&output)
            .iter()
            .any(|(text, _)| text.contains("Linux 6.12.94 · Antinomie")));
        assert!(app.selected_base.is_none() && app.submitted.is_empty());
    }

    #[test]
    fn relative_times_and_program_names_read_briefly() {
        assert_eq!(relative_time(5), "just now");
        assert_eq!(relative_time(125), "2 min ago");
        assert_eq!(relative_time(7300), "2 h ago");
        assert_eq!(relative_time(3 * 86400), "3 d ago");
        assert_eq!(program_name("/usr/bin/sample"), "sample");
        assert_eq!(program_name("/bin/"), "bin");
        assert_eq!(program_name("ls"), "ls");
    }

    #[test]
    fn trace_columns_sort_both_ways_with_stable_ties() {
        let call = |call_id: u64, tid: u32, time: u64, result: Option<i64>| {
            let mut entry = event(1, 0);
            entry.call_id = call_id;
            entry.tid = tid;
            entry.timestamp_ns = time;
            entry.event_seq = call_id * 2;
            let mut exit = entry.clone();
            exit.phase = 2;
            exit.event_seq += 1;
            exit.result = result;
            vec![entry, exit]
        };
        let events: Vec<_> = [
            call(1, 30, 300, Some(5)),
            call(2, 10, 100, Some(-2)),
            call(3, 20, 200, Some(5)),
        ]
        .concat();
        let order = |column, descending| {
            let mut invocations = antinomie_monitor_core::pair_events(&events);
            sort_invocations(&mut invocations, column, descending);
            invocations.iter().map(|i| i.call_id).collect::<Vec<_>>()
        };
        assert_eq!(order(TraceColumn::Time, false), [2, 3, 1]);
        assert_eq!(order(TraceColumn::Time, true), [1, 3, 2]);
        assert_eq!(order(TraceColumn::Tid, false), [2, 3, 1]);
        assert_eq!(order(TraceColumn::Tid, true), [1, 3, 2]);
        // Equal returns keep time order in both directions.
        assert_eq!(order(TraceColumn::Return, false), [2, 3, 1]);
        assert_eq!(order(TraceColumn::Return, true), [3, 1, 2]);
    }

    #[test]
    fn clicking_a_trace_header_sorts_and_shows_the_direction() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = app();
        app.snapshot.events = vec![event(1, 0), event(2, 3)];
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let header = |app: &mut MonitorApp| {
            texts(&render(app, &ctx, size))
                .into_iter()
                .find(|(text, _)| text.starts_with("TID"))
                .expect("TID header")
        };
        let (text, rect) = header(&mut app);
        assert_eq!(text, "TID");
        let click = |app: &mut MonitorApp| {
            let pos = rect.center();
            for events in [
                vec![egui::Event::PointerMoved(pos)],
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::default(),
                }],
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::default(),
                }],
            ] {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events,
                        ..Default::default()
                    },
                    |ctx| app.draw(ctx),
                );
            }
        };
        click(&mut app);
        assert_eq!(app.trace_sort, Some((TraceColumn::Tid, false)));
        assert_eq!(
            header(&mut app).0,
            format!("TID{}", egui_phosphor::regular::CARET_UP)
        );
        click(&mut app);
        assert_eq!(app.trace_sort, Some((TraceColumn::Tid, true)));
        assert_eq!(
            header(&mut app).0,
            format!("TID{}", egui_phosphor::regular::CARET_DOWN)
        );
    }

    #[test]
    fn fixed_resolution_requires_a_capable_base_for_create_and_save() {
        let mut app = app();
        app.snapshot.bases = vec![test_base("legacy", false), test_base("capable", true)];
        app.new_image();
        app.draft.base_identity = Some("legacy".into());
        app.draft.launch.resolution = DisplayResolution::R1280x720;
        let error = app.create_vm().unwrap_err();
        assert!(error.contains("Select a refreshed base or choose Auto"));
        assert!(app.submitted.is_empty());
        app.draft.id = "vm".into();
        app.snapshot.vms.push(app.draft.clone());
        assert_eq!(app.save_vm(app.draft.clone()).unwrap_err(), error);
        assert!(app.submitted.is_empty());

        let ctx = egui::Context::default();
        theme::install(&ctx);
        for _ in 0..3 {
            render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
        }
        let output = render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
        assert!(texts(&output).iter().any(|(text, _)| text == &error));

        app.draft.base_identity = Some("missing".into());
        assert_eq!(app.create_vm().unwrap_err(), error);
        app.draft.base_identity = Some("capable".into());
        assert!(app.create_validation_error(false).is_none());
        assert!(app.save_validation_error(&app.draft).is_none());
        app.draft.base_identity = Some("legacy".into());
        app.draft.launch.resolution = DisplayResolution::Auto;
        assert!(app.create_validation_error(false).is_none());
        assert!(app.save_validation_error(&app.draft).is_none());
    }

    #[test]
    fn new_vm_prefers_capable_bases_and_existing_defaults_remain_implicit() {
        let mut app = app();
        app.snapshot.bases = vec![test_base("legacy", false), test_base("capable", true)];
        app.settings.bundle = "/bases/legacy".into();
        app.new_image();
        assert_eq!(app.draft.base_identity.as_deref(), Some("capable"));
        let legacy = VmConfig {
            id: "legacy-vm".into(),
            ..VmConfig::default()
        };
        app.create_open = false;
        app.selected = Some(legacy.id.clone());
        app.snapshot.vms.push(legacy.clone());
        app.configure_vm();
        let ctx = egui::Context::default();
        theme::install(&ctx);
        for _ in 0..3 {
            render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
        }
        assert!(app.draft.base_identity.is_none());
        assert_eq!(app.snapshot.vms[0], legacy);
        assert!(app.save_validation_error(&app.draft).is_none());
        app.draft.launch.resolution = DisplayResolution::R1280x720;
        assert!(app.fixed_display_error(&app.draft).is_some());
        app.snapshot.bases[0].fixed_display = true;
        assert!(app.fixed_display_error(&app.draft).is_none());

        app.settings.bundle = "/bases/capable".into();
        app.new_image();
        assert_eq!(app.draft.base_identity.as_deref(), Some("capable"));
        app.snapshot.bases[0].fixed_display = false;
        app.snapshot.bases[1].fixed_display = false;
        app.settings.bundle = "/bases/legacy".into();
        app.new_image();
        assert_eq!(app.draft.base_identity.as_deref(), Some("legacy"));
        assert_eq!(
            base_choice_label(&app.snapshot.bases[0]),
            format!(
                "Linux 6.12.94 · Antinomie {} (legacy)",
                antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
            )
        );
        app.snapshot.bases[1].fixed_display = true;
        assert_eq!(
            base_choice_label(&app.snapshot.bases[1]),
            format!(
                "Linux 6.12.94 · Antinomie {}",
                antinomie_monitor_core::first_app_version(APP_REVISION).unwrap()
            )
        );
    }

    #[test]
    fn default_base_selection_preserves_guest_profile_and_backend_fallback() {
        let mut app = app();
        let mut custom = test_base("custom", false);
        custom.guest = Some(antinomie_monitor_core::GuestProfile {
            id: "custom".into(),
            label: "Custom guest".into(),
            min_ram_mib: 256,
            min_disk_gib: 1,
            requires_credentials: false,
            graphical: false,
        });
        app.snapshot.bases = vec![custom.clone(), test_base("busybox", true)];
        app.settings.bundle = "/bases/custom".into();
        app.new_image();
        assert_eq!(app.draft.base_identity.as_deref(), Some("custom"));
        assert_eq!(selected_base(&app.snapshot, None).unwrap().id, "busybox");
        assert_eq!(
            preferred_new_base(&app.snapshot, "/missing-source")
                .unwrap()
                .id,
            "busybox"
        );

        custom.id = "refreshed-custom".into();
        custom.directory = "/bases/refreshed-custom".into();
        custom.fixed_display = true;
        app.snapshot.bases.push(custom);
        app.new_image();
        assert_eq!(app.draft.base_identity.as_deref(), Some("refreshed-custom"));
    }

    #[test]
    fn password_widget_does_not_retain_undo_history() {
        let ctx = egui::Context::default();
        let mut password = "first-private-password".to_owned();
        for text in ["first-private-password", "second-private-password", ""] {
            password.clear();
            password.push_str(text);
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| password_input(ui, &mut password, "private_qa"));
            });
            let state =
                egui::widgets::text_edit::TextEditState::load(&ctx, egui::Id::new("private_qa"))
                    .unwrap();
            assert!(state
                .undoer()
                .undo(&(Default::default(), String::new()))
                .is_none());
        }
    }

    #[test]
    fn creation_guards_explain_rejection_without_submitting() {
        let mut app = app();
        app.new_image();
        app.draft.name.clear();
        assert_eq!(app.create_vm().unwrap_err(), "Enter a VM name");
        assert!(app.submitted.is_empty());

        app.draft.name = "New VM".into();
        app.snapshot.active_vm = Some("running".into());
        assert_eq!(
            app.create_vm().unwrap_err(),
            "Stop the running VM before creating another VM"
        );
        assert!(app.submitted.is_empty());
        app.snapshot.active_vm = None;
        assert!(app.create_validation_error(false).is_none());
        assert!(app
            .create_validation_error(true)
            .unwrap()
            .contains("8..128"));
        app.credentials.password = "test-secret-only".into();
        assert_eq!(
            app.create_validation_error(true).unwrap(),
            "password confirmation does not match"
        );
        app.credentials.confirmation = app.credentials.password.clone();
        assert!(app.create_validation_error(true).is_none());
        app.credentials.username = "root".into();
        assert!(app
            .create_validation_error(true)
            .unwrap()
            .contains("non-root"));
        app.create_vm().unwrap();
        assert!(app
            .submitted
            .iter()
            .any(|command| matches!(command, Command::Create(_))));
    }

    #[test]
    fn default_folder_paths_are_visible_without_changing_automatic_choices() {
        let mut app = app();
        app.options.data_dir = "/vm-data".into();
        app.new_image();
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert_eq!(
            texts(&output)
                .iter()
                .filter(|(text, _)| text == "/vm-data")
                .count(),
            2
        );
        assert!(app.draft.disk_root.is_none());
        assert!(app.draft.recording_root.is_none());

        app.draft.disk_root = Some("/disks".into());
        render(&mut app, &ctx, size);
        let output = render(&mut app, &ctx, size);
        assert_eq!(
            texts(&output)
                .iter()
                .filter(|(text, _)| text == "/disks")
                .count(),
            2
        );
        assert!(app.draft.recording_root.is_none());

        app.draft.recording_root = Some("/captures".into());
        let output = render(&mut app, &ctx, size);
        assert!(texts(&output).iter().any(|(text, _)| text == "/captures"));
        assert_eq!(app.draft.disk_root, Some(PathBuf::from("/disks")));
    }

    #[test]
    fn editing_and_clearing_folder_text_preserves_automatic_fallback() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut path = None;
        let mut picker = FolderPicker::new();
        let mut status = String::new();
        let mut draw = |path: &mut Option<PathBuf>, events: Vec<egui::Event>| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(640.0, 480.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        directory_input(
                            ui,
                            path,
                            std::path::Path::new("/automatic"),
                            &mut picker,
                            FolderTarget {
                                generation: 0,
                                kind: FolderKind::Disk,
                            },
                            &mut status,
                        );
                    });
                },
            )
        };
        draw(&mut path, vec![]);
        let output = draw(&mut path, vec![]);
        let pos = texts(&output)
            .iter()
            .find(|(text, _)| text == "/automatic")
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            draw(
                &mut path,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        let select_all = || egui::Event::Key {
            key: egui::Key::A,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers {
                ctrl: true,
                command: true,
                ..Default::default()
            },
        };
        draw(
            &mut path,
            vec![select_all(), egui::Event::Text("/chosen".into())],
        );
        assert_eq!(path, Some(PathBuf::from("/chosen")));

        draw(
            &mut path,
            vec![
                select_all(),
                egui::Event::Key {
                    key: egui::Key::Backspace,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        assert!(path.is_none());
        let output = draw(&mut path, vec![]);
        assert!(texts(&output).iter().any(|(text, _)| text == "/automatic"));
        assert!(path.is_none());
    }

    #[test]
    fn snapshot_decision_blocks_global_shortcuts_without_editor_focus() {
        let mut app = app();
        app.selected = Some("vm".into());
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.vm_snapshot_trees.insert(
            "vm".into(),
            antinomie_monitor_core::VmSnapshotTree {
                vm_id: "vm".into(),
                capabilities: antinomie_monitor_core::VmSnapshotCapabilities {
                    can_create_disk: true,
                    ..Default::default()
                },
                ..Default::default()
            },
        );
        app.vm_snapshots.bind("vm", "Test VM");
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        click_label(&mut app, &ctx, size, "New snapshot…");
        assert!(app.vm_snapshots.decision_open());
        ctx.memory_mut(|memory| {
            if let Some(id) = memory.focused() {
                memory.surrender_focus(id);
            }
        });
        let _ = ctx.run(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key: keys::RUN_PROGRAM.logical_key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: keys::RUN_PROGRAM.modifiers,
                }],
                modifiers: keys::RUN_PROGRAM.modifiers,
                ..Default::default()
            },
            |ctx| app.shortcuts(ctx),
        );
        assert!(!app.launch_open);
        app.vm_snapshots.close();
        let _ = ctx.run(
            egui::RawInput {
                events: vec![egui::Event::Key {
                    key: keys::RUN_PROGRAM.logical_key,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: keys::RUN_PROGRAM.modifiers,
                }],
                modifiers: keys::RUN_PROGRAM.modifiers,
                ..Default::default()
            },
            |ctx| app.shortcuts(ctx),
        );
        assert!(app.launch_open);
    }

    #[test]
    fn existing_vm_recording_default_uses_registered_disk_location() {
        let mut app = app();
        app.draft.id = "legacy".into();
        app.snapshot.vms.push(app.draft.clone());
        app.snapshot
            .vm_locations
            .push(antinomie_monitor_core::VmLocations {
                vm_id: "legacy".into(),
                disk_directory: "/legacy/vms/legacy".into(),
                recording_directory: "/legacy/vms/legacy".into(),
                recording_directories: vec!["/legacy/vms/legacy".into()],
            });
        app.config_open = true;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert_eq!(
            texts(&output)
                .iter()
                .filter(|(text, _)| text == "/legacy/vms")
                .count(),
            2
        );
        assert!(app.draft.disk_root.is_none());
        assert!(app.draft.recording_root.is_none());
    }

    #[test]
    fn running_vm_creation_error_remains_visible_outside_disabled_form() {
        let mut app = app();
        app.new_image();
        app.snapshot.active_vm = Some("running".into());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert!(texts(&output)
            .iter()
            .any(|(text, _)| text == "Stop the running VM before creating another VM"));
    }

    #[test]
    fn debian_credentials_are_transient_and_creation_uses_validated_api() {
        let mut app = app();
        app.snapshot
            .bases
            .push(antinomie_monitor_core::BaseSummary {
                id: "debian".into(),
                label: "Debian 13 (Xfce)".into(),
                directory: "/bases/debian".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                fixed_display: true,
                size_bytes: 0,
                revision: Some(APP_REVISION),
                min_app_version: None,
                built_with: None,
                guest: Some(antinomie_monitor_core::GuestProfile {
                    id: "debian-xfce".into(),
                    label: "Debian 13 (Xfce)".into(),
                    min_ram_mib: 2048,
                    min_disk_gib: 8,
                    requires_credentials: true,
                    graphical: true,
                }),
            });
        app.new_image();
        app.draft.base_identity = Some("debian".into());
        app.draft.launch.resolution = DisplayResolution::R1600x900;
        assert!(app.create_vm().is_err());
        app.credentials.password = "test-password-only".into();
        app.credentials.confirmation = "wrong-password".into();
        assert!(app.create_vm().is_err());
        app.credentials.confirmation = app.credentials.password.clone();
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        for _ in 0..4 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let pos = texts(&output)
            .iter()
            .find(|(text, _)| text == "Create VM")
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert!(!app.create_open);
        assert!(app
            .submitted
            .iter()
            .any(|command| matches!(command, Command::CreateWithCredentials { vm, .. } if vm.launch.resolution == DisplayResolution::R1600x900)));
        assert!(app.credentials.password.is_empty());
        assert!(app.credentials.confirmation.is_empty());
        assert!(!format!("{:?}", app.submitted).contains("test-password-only"));
        assert!(!serde_json::to_string(&app.settings)
            .unwrap()
            .contains("password"));
        app.credentials.password = "discard-on-new-vm".into();
        app.new_image();
        assert!(app.credentials.password.is_empty());
    }

    #[test]
    fn debian_new_vm_dialog_fits_large_text_and_enforces_profile_minima() {
        let mut app = app();
        app.snapshot
            .bases
            .push(antinomie_monitor_core::BaseSummary {
                id: "debian".into(),
                label: "Debian 13 (Xfce)".into(),
                directory: "/bases/debian".into(),
                min_ram_mib: 2048,
                min_disk_gib: 8,
                fixed_display: true,
                size_bytes: 0,
                revision: Some(APP_REVISION),
                min_app_version: None,
                built_with: None,
                guest: Some(antinomie_monitor_core::GuestProfile {
                    id: "debian-xfce".into(),
                    label: "Debian 13 (Xfce)".into(),
                    min_ram_mib: 2048,
                    min_disk_gib: 8,
                    requires_credentials: true,
                    graphical: true,
                }),
            });
        app.new_image();
        app.draft.ram_mib = 256;
        app.draft.disk_gib = 1;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        app.settings.font_size = 24.0;
        theme::text_size(&ctx, 24.0);
        for _ in 0..4 {
            render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
        }
        let output = render(&mut app, &ctx, egui::vec2(1280.0, 900.0));
        assert_eq!(app.draft.ram_mib, 2048);
        assert_eq!(app.draft.disk_gib, 8);
        let visible = texts(&output);
        for label in [
            "Resolution",
            "Fullscreen",
            "Fit to window",
            "Acceleration",
            "CPU model",
            "Username",
            "Password",
            "Confirm password",
            "Create VM",
        ] {
            assert!(
                visible.iter().any(|(text, _)| text == label),
                "missing or clipped {label}"
            );
        }
        let fit = visible
            .iter()
            .find(|(text, _)| text == "Fit to window")
            .unwrap()
            .1;
        let acceleration = visible
            .iter()
            .find(|(text, _)| text == "Acceleration")
            .unwrap()
            .1;
        assert!(
            fit.bottom() < acceleration.top(),
            "fit checkbox overlaps acceleration row"
        );
        assert!(
            visible
                .iter()
                .any(|(text, _)| text.contains("password must be 8..128")),
            "visible dialog text: {visible:?}"
        );
    }

    #[test]
    #[ignore = "requires X11 native rendering; exits after 20 seconds"]
    fn native_debian_setup_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct QaApp {
            app: MonitorApp,
            deadline: Instant,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                eframe::App::update(&mut self.app, ctx, frame);
            }
        }
        eframe::run_native(
            "Antinomie Debian Setup QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 900.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(|cc| {
                theme::install(&cc.egui_ctx);
                let mut app = app();
                app.snapshot
                    .bases
                    .push(antinomie_monitor_core::BaseSummary {
                        id: "debian".into(),
                        label: "Debian 13 (Xfce)".into(),
                        directory: "/bases/debian".into(),
                        min_ram_mib: 2048,
                        min_disk_gib: 8,
                        fixed_display: true,
                        size_bytes: 0,
                        revision: Some(APP_REVISION),
                        min_app_version: None,
                        built_with: None,
                        guest: Some(antinomie_monitor_core::GuestProfile {
                            id: "debian-xfce".into(),
                            label: "Debian 13 (Xfce)".into(),
                            min_ram_mib: 2048,
                            min_disk_gib: 8,
                            requires_credentials: true,
                            graphical: true,
                        }),
                    });
                app.new_image();
                app.settings.font_size = 24.0;
                theme::text_size(&cc.egui_ctx, 24.0);
                Ok(Box::new(QaApp {
                    app,
                    deadline: Instant::now() + Duration::from_secs(20),
                }))
            }),
        )
        .unwrap();
    }

    #[test]
    fn missing_final_screen_preserves_a_valid_terminal_journal_prefix() {
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                if let Err(error) = std::fs::remove_dir_all(&self.0) {
                    eprintln!("terminal fixture cleanup: {error}");
                }
            }
        }
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fixture = Fixture(
            std::env::temp_dir().join(format!("ant-ui-terminal-{}-{unique}", std::process::id())),
        );
        std::fs::create_dir(&fixture.0).unwrap();
        std::fs::write(fixture.0.join("manifest.json"), b"{}").unwrap();
        std::fs::write(fixture.0.join("events.json"), b"[]").unwrap();
        let data = b"retained prefix\r\n";
        let mut journal = vec![1];
        journal.extend((data.len() as u32).to_le_bytes());
        journal.extend(data);
        std::fs::write(fixture.0.join("terminal.journal"), journal).unwrap();
        assert!(!fixture.0.join("terminal-screen.ansi").exists());
        let worker = ArchiveWorker::new().unwrap();
        let mut app = app();
        let mut history = run("partial");
        history.state = RunState::Finalized;
        history.directory = fixture.0.clone();
        app.reopen(history);
        let generation = app.terminals["partial"].generation;
        worker
            .request(Request::Terminal {
                run_id: "partial".into(),
                generation,
                directory: fixture.0.clone(),
                offset: 0,
            })
            .unwrap();
        let answer = worker
            .wait_answer(Duration::from_secs(5))
            .expect("archive worker must finish the small fixture");
        app.handle_archive_answer(answer);
        assert!(app.terminals["partial"]
            .terminal
            .contents()
            .contains("retained prefix"));
        assert_eq!(app.terminals["partial"].replay_offset, None);
        assert!(app.status.contains("Final terminal screen unavailable"));
        assert!(app.terminals["partial"]
            .replay_error
            .as_ref()
            .unwrap()
            .contains("Final terminal screen unavailable"));
    }

    #[test]
    fn launch_rejects_full_open_history_without_evicting_a_view() {
        let mut app = app();
        for index in 0..TERMINAL_VIEW_LIMIT {
            let mut history = run(&format!("history-{index}"));
            history.state = RunState::Finalized;
            app.terminals
                .insert(history.id.clone(), RunTerminal::new(history));
        }
        assert_eq!(available_terminal_slots(&app.terminals, &app.snapshot), 0);
        app.send(Command::Execute(ExecRequest::default()));
        assert!(app.status.contains("close a history window"));
        assert!(app.pending_launch.is_none());
        assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
        assert!(app.terminals.values().all(|terminal| terminal.open));
    }

    #[test]
    fn pending_launch_reserves_last_slot_against_history_reopen() {
        let mut app = app();
        for index in 0..TERMINAL_VIEW_LIMIT - 1 {
            let mut history = run(&format!("history-{index}"));
            history.state = RunState::Finalized;
            app.terminals
                .insert(history.id.clone(), RunTerminal::new(history));
        }
        assert!(app.launch_admission().is_ok());
        app.pending_launch = Some(77);
        let mut extra = run("extra-history");
        extra.state = RunState::Finalized;
        app.reopen(extra.clone());
        assert!(!app.terminals.contains_key(&extra.id));
        assert!(app.status.contains("close a history window"));
        resolve_launch_result(&mut app.pending_launch, 77, true);
        assert_eq!(app.pending_launch, Some(77));
        app.reopen(extra);
        assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT - 1);
        let launched = run("launched");
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs = vec![launched];
        sync_runs(&mut app.terminals, &app.snapshot);
        assert!(app.terminals["launched"].open);
        assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
    }

    #[test]
    fn closed_history_slot_is_reclaimable_but_cannot_be_reopened_while_reserved() {
        let mut app = app();
        for index in 0..TERMINAL_VIEW_LIMIT {
            let mut history = run(&format!("history-{index}"));
            history.state = RunState::Finalized;
            app.terminals
                .insert(history.id.clone(), RunTerminal::new(history));
        }
        let closed = app.terminals["history-0"].run.clone();
        app.terminals.get_mut(&closed.id).unwrap().close_view();
        assert!(app.launch_admission().is_ok());
        app.pending_launch = Some(77);
        app.reopen(closed.clone());
        assert!(!app.terminals[&closed.id].open);
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs = vec![run("launched")];
        sync_runs(&mut app.terminals, &app.snapshot);
        assert!(app.terminals["launched"].open);
        assert!(!app.terminals.contains_key(&closed.id));
        assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
    }

    #[test]
    fn failed_launch_releases_its_reservation_only_for_the_matching_command() {
        let mut app = app();
        for index in 0..TERMINAL_VIEW_LIMIT - 1 {
            let mut history = run(&format!("history-{index}"));
            history.state = RunState::Finalized;
            app.terminals
                .insert(history.id.clone(), RunTerminal::new(history));
        }
        app.pending_launch = Some(77);
        resolve_launch_result(&mut app.pending_launch, 76, false);
        assert_eq!(app.pending_launch, Some(77));
        resolve_launch_result(&mut app.pending_launch, 77, false);
        assert!(app.pending_launch.is_none());
        assert!(app.launch_admission().is_ok());
        let mut extra = run("extra-history");
        extra.state = RunState::Finalized;
        app.reopen(extra);
        assert!(app.terminals["extra-history"].open);
        assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
    }

    #[test]
    fn all_live_capture_reads_use_the_invocation_owner_directory() {
        let mut app = app();
        let mut first = run("one");
        first.directory = "/archive/one".into();
        let mut second = run("two");
        second.root_task_cookie = 8;
        second.directory = "/archive/two".into();
        app.snapshot.runs = vec![first, second];
        app.snapshot.capture_dir = Some("/archive/unassigned".into());
        let mut event = event(1, 0);
        event.root_task_cookie = 8;
        let invocation = pair_events(&[event.clone()]).remove(0);
        assert_eq!(
            app.invocation_directory(Some(&invocation)),
            Some(PathBuf::from("/archive/two"))
        );
        event.root_task_cookie = 0;
        let legacy = pair_events(&[event.clone()]).remove(0);
        assert_eq!(
            app.invocation_directory(Some(&legacy)),
            app.snapshot.capture_dir
        );
        event.root_task_cookie = 999;
        let unknown = pair_events(&[event]).remove(0);
        assert!(app.invocation_directory(Some(&unknown)).is_none());
    }

    #[test]
    fn imported_archive_selection_survives_run_list_refresh() {
        let mut app = app();
        let mut imported = run("archive:/legacy");
        imported.state = RunState::Finalized;
        app.history.push(imported);
        app.select_run(Some("archive:/legacy".into()));
        app.handle_archive_answer(Answer::List(Ok(vec![run("listed")])));
        assert_eq!(app.offline_run().unwrap().id, "archive:/legacy");
        assert_eq!(app.history.len(), 2);
    }

    #[test]
    #[ignore = "requires explicit X11 native automation; exits after 120 seconds"]
    fn native_workspace_fixture() {
        use std::sync::{Arc, Mutex};
        use winit::platform::x11::EventLoopBuilderExtX11;

        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).expect("remove QA fixture");
            }
        }
        #[derive(Default)]
        struct Evidence {
            first: Vec<u8>,
            second: Vec<u8>,
            archive_selected: bool,
            first_preserved: bool,
            second_preserved: bool,
        }
        struct QaApp {
            app: MonitorApp,
            deadline: Instant,
            evidence: Arc<Mutex<Evidence>>,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                let close = ctx.input(|input| input.viewport().close_requested())
                    || Instant::now() >= self.deadline;
                if close {
                    let mut evidence = self.evidence.lock().expect("QA evidence");
                    *evidence = Evidence::default();
                    for command in &self.app.submitted {
                        if let Command::TerminalInput { run_id, data } = command {
                            match run_id.as_str() {
                                "terminal-a" => evidence.first.extend(data),
                                "terminal-b" => evidence.second.extend(data),
                                _ => {}
                            }
                        }
                    }
                    evidence.archive_selected = self.app.archive_selected
                        && self.app.selected_run.as_deref() == Some("saved-run")
                        && !self.app.archive_page.is_empty()
                        && self.app.snapshot.events.len() == 1;
                    evidence.first_preserved = self.app.terminals["terminal-a"]
                        .terminal
                        .contents()
                        .contains("TERMINAL A RETAINED");
                    evidence.second_preserved = self.app.terminals["terminal-b"]
                        .terminal
                        .contents()
                        .contains("TERMINAL B RETAINED");
                    self.app.snapshot.active_vm = None;
                    self.app.snapshot.state = VmState::Stopped;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                eframe::App::update(&mut self.app, ctx, frame);
            }
        }
        let fixture = Fixture(std::env::temp_dir().join(format!(
                "antinomie-native-qa-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
            )));
        std::fs::create_dir_all(&fixture.0).expect("QA directory");
        let mut first = run("terminal-a");
        first.request.path = "/bin/terminal-a".into();
        first.directory = fixture.0.clone();
        first.execution = Some(antinomie_monitor_core::RunExecution {
            generation: 1,
            live_task_count: 2,
            pending_async_count: 1,
            flags: 1,
            root_wait_status: Some(7 << 8),
            root_exit: Some(WaitStatus::Exited { code: 7 }),
            async_loss_count: 0,
            total_task_count: 3,
        });
        let mut second = run("terminal-b");
        second.request.path = "/bin/terminal-b".into();
        second.pid = 43;
        second.root_task_cookie = 8;
        second.directory = fixture.0.clone();
        let mut saved = run("saved-run");
        saved.request.path = "/usr/bin/saved-program".into();
        saved.request.args = vec!["--output".into(), "/tmp/path with spaces".into()];
        saved.request.env.push("QA=value with spaces".into());
        saved.root_task_cookie = 9;
        saved.state = RunState::Finished;
        saved.terminal_eof = true;
        saved.directory = fixture.0.clone();
        saved.boot_id = "previous-boot".into();
        saved.execution = Some(antinomie_monitor_core::RunExecution {
            generation: 1,
            live_task_count: 0,
            pending_async_count: 0,
            flags: 7,
            root_wait_status: Some(0),
            root_exit: Some(WaitStatus::Exited { code: 0 }),
            async_loss_count: 0,
            total_task_count: 1,
        });
        let mut entry = event(1, 0);
        entry.root_task_cookie = 9;
        entry.syscall_nr = 257;
        entry.syscall_name = "openat".into();
        entry.args = Some([u64::MAX - 99, 0x1000, 0x80002 | (1 << 60), 0, 0, 0]);
        entry.fields.push(antinomie_monitor_core::FieldSummary {
            object_id: 1,
            key: "path".into(),
            layout: "char[]".into(),
            logical_len: Some(20),
            captured_len: 20,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: b"/tmp/native-fixture\0".to_vec(),
            raw_path: None,
            ranges: vec![(0, 20)],
        });
        let mut exit = entry.clone();
        exit.phase = 2;
        exit.args = None;
        exit.result = Some(3);
        std::fs::write(
            fixture.0.join("manifest.json"),
            serde_json::to_vec(
                &serde_json::json!({"run":saved,"terminal_rows":4,"terminal_cols":40}),
            )
            .expect("manifest"),
        )
        .expect("write manifest");
        std::fs::write(
            fixture.0.join("events.json"),
            serde_json::to_vec(&vec![entry.clone(), exit.clone()]).expect("events"),
        )
        .expect("write events");
        let mut raw = Vec::new();
        for event in [entry, exit] {
            for fragment in [1, 5] {
                let mut body = vec![0; if fragment == 1 { 120 } else { 32 }];
                if fragment == 1 {
                    if let Some(args) = event.args {
                        for (index, value) in args.iter().enumerate() {
                            body[index * 8..index * 8 + 8].copy_from_slice(&value.to_le_bytes());
                        }
                        body[48] = 4;
                    }
                    if let Some(result) = event.result {
                        body[49] = 1;
                        body[56..64].copy_from_slice(&result.to_le_bytes());
                    }
                }
                let mut packet = vec![0; 136];
                packet[..4].copy_from_slice(b"ANTT");
                packet[4..6].copy_from_slice(&1u16.to_le_bytes());
                packet[6..8].copy_from_slice(&1u16.to_le_bytes());
                packet[8..10].copy_from_slice(&136u16.to_le_bytes());
                packet[10..12].copy_from_slice(&1u16.to_le_bytes());
                packet[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
                packet[20..24].copy_from_slice(&1u32.to_le_bytes());
                packet[24..32].copy_from_slice(&event.stream_id.to_le_bytes());
                packet[32..40].copy_from_slice(&event.task_cookie.to_le_bytes());
                packet[40..48].copy_from_slice(&event.call_id.to_le_bytes());
                packet[48..56]
                    .copy_from_slice(&(event.event_seq + u64::from(event.phase)).to_le_bytes());
                packet[56..64].copy_from_slice(&(raw.len() as u64).to_le_bytes());
                packet[64..72].copy_from_slice(&event.timestamp_ns.to_le_bytes());
                packet[76..80].copy_from_slice(&event.tid.to_le_bytes());
                packet[88..96].copy_from_slice(&event.syscall_nr.to_le_bytes());
                packet[96..98].copy_from_slice(&1u16.to_le_bytes());
                packet[98] = event.phase;
                packet[99] = fragment;
                packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
                packet[128..136].copy_from_slice(&event.root_task_cookie.to_le_bytes());
                packet.extend(body);
                raw.extend((packet.len() as u32).to_le_bytes());
                raw.extend(packet);
            }
        }
        std::fs::write(fixture.0.join("telemetry.raw"), raw).expect("write raw recording");
        let output = b"SAVED TERMINAL HISTORY\r\n";
        let mut journal = vec![1];
        journal.extend((output.len() as u32).to_le_bytes());
        journal.extend(output);
        std::fs::write(fixture.0.join("terminal.journal"), journal).expect("write journal");
        std::fs::write(fixture.0.join("terminal-screen.ansi"), output).expect("write screen");
        let evidence = Arc::new(Mutex::new(Evidence::default()));
        let finish = Arc::clone(&evidence);
        eframe::run_native(
            "Antinomie Native QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 820.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                let mut app = app();
                app.selected = Some("vm".into());
                app.snapshot.active_vm = Some("vm".into());
                app.snapshot.state = VmState::Running;
                app.snapshot.vms = vec![
                    VmConfig {
                        id: "vm".into(),
                        name: "Native workspace QA".into(),
                        ..VmConfig::default()
                    },
                    VmConfig {
                        id: "other-vm".into(),
                        name: "Other VM".into(),
                        ..VmConfig::default()
                    },
                ];
                app.snapshot.runs = vec![first.clone(), second.clone()];
                app.snapshot.events = vec![event(1, 0)];
                app.history = vec![saved];
                let mut a = RunTerminal::new(first);
                a.terminal.process(b"TERMINAL A RETAINED\r\n$ ");
                app.terminals.insert(a.run.id.clone(), a);
                let mut b = RunTerminal::new(second);
                b.terminal.process(b"TERMINAL B RETAINED\r\n$ ");
                app.terminals.insert(b.run.id.clone(), b);
                app.archive = Some(ArchiveWorker::new().expect("archive worker"));
                Ok(Box::new(QaApp {
                    app,
                    deadline: Instant::now() + Duration::from_secs(120),
                    evidence: finish,
                }))
            }),
        )
        .expect("native QA window");
        let evidence = evidence.lock().expect("QA evidence");
        assert_eq!(
            evidence.first, b"qa-a\r",
            "input must have one terminal-a owner"
        );
        assert_eq!(
            evidence.second, b"qa-b\r",
            "input must have one terminal-b owner"
        );
        assert!(
            evidence.archive_selected,
            "double-click saved history while live snapshot remains"
        );
        assert!(
            evidence.first_preserved && evidence.second_preserved,
            "panel moves and close/reopen preserve terminal parsers"
        );
    }

    #[test]
    fn history_answers_from_another_vm_cannot_replace_selected_vm() {
        let mut app = app();
        app.selected = Some("selected".into());
        let mut current = run("current");
        current.vm_id = "selected".into();
        app.history = vec![current];
        app.handle_archive_answer(Answer::ListVm {
            vm_id: "other".into(),
            generation: app.history_generation,
            result: Ok(vec![run("stale")]),
        });
        assert_eq!(app.history[0].id, "current");
        app.refresh_history();
        assert!(
            matches!(&app.pending_archive, Some(Request::ListVm { vm_id, .. }) if vm_id == "selected")
        );
        let old_generation = app.history_generation;
        app.refresh_history();
        app.handle_archive_answer(Answer::ListVm {
            vm_id: "selected".into(),
            generation: old_generation,
            result: Ok(vec![run("outdated-roots")]),
        });
        assert_eq!(app.history[0].id, "current");
    }

    #[test]
    fn selected_vm_hides_another_vms_live_trace_and_finished_runs_are_past() {
        let mut app = app();
        app.selected = Some("other-vm".into());
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.events = vec![event(1, 0)];
        app.snapshot.runs = vec![run("current")];
        assert!(app.invocations().is_empty());
        app.selected = Some("vm".into());
        assert_eq!(app.invocations().len(), 1);
        assert!(app.live_history_run(&app.snapshot.runs[0]));
        app.snapshot.runs[0].state = RunState::Finished;
        assert!(!app.live_history_run(&app.snapshot.runs[0]));
    }

    #[test]
    fn async_only_row_keeps_missing_phases_and_renders_observation_loss() {
        let mut observed = event(3, 2);
        observed.args = None;
        observed.result = Some(-61);
        observed.fields = vec![antinomie_monitor_core::FieldSummary {
            object_id: 1,
            key: "async.stage".into(),
            layout: "u64".into(),
            logical_len: Some(8),
            captured_len: 8,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: 6u64.to_le_bytes().to_vec(),
            raw_path: None,
            ranges: vec![(0, 8)],
        }];
        let mut row = InvocationSummary {
            stream_id: observed.stream_id,
            task_cookie: observed.task_cookie,
            call_id: observed.call_id,
            entry: None,
            exit: None,
            async_events: vec![observed.clone()],
            task_exit: None,
        };
        assert_eq!(trace::representative(&row).unwrap().tid, 42);
        assert!(trace::info(&row)
            .contains("missing Entry; missing Exit; Async: Observation unavailable"));
        assert!(!trace::info(&row).contains("Canceled"));
        row.async_events[0].fields[0].preview = 99u64.to_le_bytes().to_vec();
        assert!(trace::info(&row).contains("Unknown stage 99"));
        row.async_events[0] = observed;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut inspector = trace::Inspector::default();
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                inspector.show(ui, Some(&row), false);
            });
        });
        assert!(texts(&output).iter().any(|(label, _)| label == "Async (1)"));
        assert!(row.entry.is_none() && row.exit.is_none());
        inspector.selection = Some(trace::Selection::AsyncCaptured {
            event_seq: 3,
            object_id: 1,
        });
        assert_eq!(inspector.field(&row).unwrap().key, "async.stage");
    }

    #[test]
    fn a_call_the_task_ended_in_shows_how_it_ended_and_empty_reads_say_why() {
        let render = |row: &InvocationSummary| {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut inspector = trace::Inspector::default();
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1400.0, 900.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        inspector.show(ui, Some(row), false);
                    });
                },
            );
            texts(&output)
                .into_iter()
                .map(|(text, _)| text)
                .collect::<Vec<_>>()
        };
        let mut entry = event(1, 0);
        entry.syscall_nr = 231;
        entry.syscall_name = "exit_group".into();
        entry.args = Some([1, 0, 0, 0, 0, 0]);
        let mut ended = entry.clone();
        ended.phase = 3;
        ended.event_seq = 9;
        ended.fields = vec![antinomie_monitor_core::FieldSummary {
            object_id: 1,
            key: "lifecycle.task_exit".into(),
            layout: String::new(),
            logical_len: Some(8),
            captured_len: 8,
            status: Some(0),
            capture_error: 0,
            complete: true,
            // exit_group(1): the kernel keeps the wait status 1 << 8.
            preview: 0x100u64.to_le_bytes().to_vec(),
            raw_path: None,
            ranges: vec![(0, 8)],
        }];
        let mut row = InvocationSummary {
            stream_id: 1,
            task_cookie: 3,
            call_id: 2,
            entry: Some(entry),
            exit: None,
            async_events: Vec::new(),
            task_exit: Some(ended),
        };
        let cells = trace::cells(&row);
        assert_eq!(cells[1].0[0].0, "1\u{2192}9");
        assert_eq!(cells[5].0[0].0, "exit 1");
        assert!(!trace::info(&row).contains("missing Exit"));
        let shown = render(&row);
        assert!(shown.iter().any(|text| text == "Task ended"), "{shown:?}");
        assert!(shown.iter().any(|text| text == "exit 1"));
        assert!(!shown.iter().any(|text| text == "missing Exit"));
        // Without the kernel's record the Exit is reported missing as before.
        row.task_exit = None;
        assert_eq!(trace::cells(&row)[5].0[0].0, "missing Exit");

        // read() at end of file returns 0 and captures no buffer.
        let mut exit = event(2, 0);
        exit.result = Some(0);
        let read = InvocationSummary {
            stream_id: 1,
            task_cookie: 3,
            call_id: 2,
            entry: Some(event(1, 0)),
            exit: Some(exit),
            async_events: Vec::new(),
            task_exit: None,
        };
        assert!(render(&read)
            .iter()
            .any(|text| text == "nothing to capture: the call returned 0 bytes"));
    }

    #[test]
    fn details_values_copy_in_many_forms_and_captured_fields_open_data_windows() {
        let mut exit = event(2, 0);
        exit.result = Some(-2);
        exit.fields = vec![antinomie_monitor_core::FieldSummary {
            object_id: 5,
            key: "buf".into(),
            layout: String::new(),
            logical_len: Some(8),
            captured_len: 4,
            status: Some(1),
            capture_error: -14,
            complete: false,
            preview: b"abcd".to_vec(),
            raw_path: None,
            ranges: vec![(0, 4)],
        }];
        let row = InvocationSummary {
            stream_id: 1,
            task_cookie: 3,
            call_id: 2,
            entry: Some(event(1, 0)),
            exit: Some(exit),
            async_events: Vec::new(),
            task_exit: None,
        };
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut inspector = trace::Inspector::default();
        let frame = |inspector: &mut trace::Inspector, events: Vec<egui::Event>| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1400.0, 900.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        inspector.show(ui, Some(&row), false);
                    });
                },
            )
        };
        let click = |inspector: &mut trace::Inspector, pos: egui::Pos2, button| {
            let mut copied = Vec::new();
            for events in [
                vec![egui::Event::PointerMoved(pos)],
                vec![egui::Event::PointerButton {
                    pos,
                    button,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                }],
                vec![egui::Event::PointerButton {
                    pos,
                    button,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                Vec::new(),
            ] {
                let output = frame(inspector, events);
                for command in output.platform_output.commands {
                    if let egui::OutputCommand::CopyText(text) = command {
                        copied.push(text);
                    }
                }
            }
            (frame(inspector, Vec::new()), copied)
        };
        let find = |output: &egui::FullOutput, label: &str| {
            texts(output)
                .into_iter()
                .find(|(text, _)| text == label)
                .map(|(_, rect)| rect.center())
        };
        let (output, _) = click(
            &mut inspector,
            egui::pos2(-10.0, -10.0),
            egui::PointerButton::Primary,
        );
        // The return value reads by meaning: the error name, its number in
        // the copy menu.
        assert!(find(&output, "ENOENT").is_some(), "error shown by name");
        let target = find(&output, "Return").expect("return value shown");
        let (output, _) = click(&mut inspector, target, egui::PointerButton::Secondary);
        for (label, value) in [
            ("Signed decimal", "-2"),
            ("Hex", "0xfffffffffffffffe"),
            ("Decimal", "18446744073709551614"),
        ] {
            assert!(find(&output, label).is_some(), "{label} offered");
            assert!(find(&output, value).is_some(), "{value} previewed");
        }
        // The menu is drawn last, over the numeric view's own "Hex" row.
        let hex = texts(&output)
            .into_iter()
            .filter(|(text, _)| text == "Hex")
            .map(|(_, rect)| rect.center())
            .next_back()
            .unwrap();
        let (output, copied) = click(&mut inspector, hex, egui::PointerButton::Primary);
        assert_eq!(copied, ["0xfffffffffffffffe"]);

        // A captured field: right-click offers its data window. The
        // argument row shows the pointer; the Exit data sits under it.
        assert!(find(&output, "0x1000").is_some(), "pointer argument in hex");
        let argument = find(&output, "buf").expect("argument row");
        let (mut output, _) = click(&mut inspector, argument, egui::PointerButton::Primary);
        for _ in 0..20 {
            output = frame(&mut inspector, Vec::new());
        }
        assert!(matches!(
            inspector.selection,
            Some(trace::Selection::Argument { index: 1, .. })
        ));
        let mut rows: Vec<_> = texts(&output)
            .into_iter()
            .filter(|(text, rect)| text == "buf" && rect.left() < 600.0)
            .map(|(_, rect)| rect)
            .collect();
        rows.sort_by(|a, b| a.top().total_cmp(&b.top()));
        assert_eq!(rows.len(), 2, "argument row and its captured field");
        assert!(
            rows[1].left() > rows[0].left(),
            "field indented under argument"
        );
        let field = rows[1].center();
        let (output, _) = click(&mut inspector, field, egui::PointerButton::Secondary);
        let open = find(
            &output,
            &format!("{} Open data…", egui_phosphor::regular::ARROW_SQUARE_OUT),
        )
        .expect("Open data offered");
        click(&mut inspector, open, egui::PointerButton::Primary);
        assert_eq!(inspector.open_data.len(), 1);
        assert_eq!(inspector.open_data[0].field.object_id, 5);
        assert_eq!(inspector.open_data[0].title, "buf / read call 2");

        // The selected field names its partial capture instead of "x bytes captured".
        inspector.selection = Some(trace::Selection::Captured {
            phase: 2,
            object_id: 5,
        });
        let output = frame(&mut inspector, Vec::new());
        let shown = texts(&output);
        assert!(shown
            .iter()
            .any(|(text, _)| text == "Captured bytes (4 of 8 bytes, copy fault)"));
        assert!(!shown
            .iter()
            .any(|(text, _)| text.contains("bytes captured;")));
    }

    #[test]
    fn saved_trace_selection_never_replaces_live_collector_or_terminal() {
        let mut app = app();
        let live = run("live");
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs = vec![live.clone()];
        app.snapshot.events = vec![event(1, 0)];
        sync_runs(&mut app.terminals, &app.snapshot);
        app.select_archive_run("live".into());
        assert!(app.offline_run().is_some());
        assert!(matches!(
            &app.pending_archive,
            Some(Request::Invocations { .. })
        ));
        assert_eq!(app.snapshot.events.len(), 1);
        assert_eq!(app.snapshot.runs[0].state, RunState::Running);
        assert!(app.terminals["live"].open && app.terminals["live"].interactive());
    }

    #[test]
    fn root_exit_is_independent_of_full_tree_completion_and_legacy_state() {
        let mut run = run("descendants");
        run.execution = Some(antinomie_monitor_core::RunExecution {
            generation: 2,
            live_task_count: 3,
            pending_async_count: 1,
            flags: 1,
            root_wait_status: Some(7 << 8),
            root_exit: Some(WaitStatus::Exited { code: 7 }),
            async_loss_count: 0,
            total_task_count: 4,
        });
        assert_eq!(run_status(&run), "Running");
        assert_eq!(root_exit(&run), "Exit 7");
        assert!(execution_detail(&run).contains("3 live tasks; 1 pending async"));
        run.execution = None;
        run.state = RunState::Finalized;
        assert_eq!(root_exit(&run), "Unknown");
        assert_eq!(run_status(&run), "Recording ended");
    }

    #[test]
    fn finalized_dirty_run_and_reopen_replay_archive_with_fresh_generation() {
        let mut app = app();
        let mut finished = run("finished");
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs.push(finished.clone());
        app.reopen(finished.clone());
        app.terminals
            .get_mut("finished")
            .unwrap()
            .output(3, b"missing tail", false);
        finished.state = RunState::Finalized;
        app.snapshot.active_vm = None;
        app.snapshot.state = VmState::Stopped;
        app.snapshot.runs = vec![finished.clone()];
        sync_runs(&mut app.terminals, &app.snapshot);
        let terminal = &app.terminals["finished"];
        assert!(!terminal.dirty);
        assert_eq!(terminal.replay_offset, Some(0));
        let old_generation = terminal.generation;
        app.snapshot.runs[0] = finished.clone();
        app.terminals.get_mut("finished").unwrap().close_view();
        app.reopen(finished);
        assert_ne!(app.terminals["finished"].generation, old_generation);
        app.handle_archive_answer(Answer::Terminal {
            run_id: "finished".into(),
            generation: old_generation,
            result: Ok(crate::archive::TerminalReplay {
                page: antinomie_monitor_core::TerminalPage {
                    records: vec![TerminalRecord::Output(b"stale".to_vec())],
                    next_offset: None,
                },
                screen_warning: None,
            }),
        });
        assert!(!app.terminals["finished"]
            .terminal
            .contents()
            .contains("stale"));
        assert_eq!(app.terminals["finished"].replay_offset, Some(0));
    }

    #[test]
    fn past_boot_finished_and_stopped_terminals_reclaim_closed_slots() {
        for state in [RunState::Finished, RunState::Stopped] {
            let mut app = app();
            for index in 0..TERMINAL_VIEW_LIMIT {
                let mut past = run(&format!("past-{index}"));
                past.state = state.clone();
                past.boot_id = "previous-boot".into();
                app.terminals
                    .insert(past.id.clone(), RunTerminal::new(past));
            }
            let closed = app.terminals["past-0"].run.clone();
            app.terminals.get_mut(&closed.id).unwrap().close_view();
            app.snapshot.active_vm = Some("vm".into());
            app.snapshot.state = VmState::Running;
            app.snapshot.runs = vec![run("new-launch")];
            assert_eq!(available_terminal_slots(&app.terminals, &app.snapshot), 1);
            assert!(app.launch_admission().is_ok());
            app.pending_launch = Some(77);
            app.reopen(closed.clone());
            assert!(!app.terminals[&closed.id].open);
            sync_runs(&mut app.terminals, &app.snapshot);
            assert!(!app.terminals.contains_key(&closed.id));
            assert!(app.terminals["new-launch"].open);
            assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
        }
    }

    #[test]
    fn ended_boot_finished_and_stopped_runs_reopen_from_archive() {
        for state in [RunState::Finished, RunState::Stopped] {
            let mut app = app();
            let mut past = run("past");
            past.state = state;
            app.snapshot.runs = vec![past.clone()];
            let mut terminal = RunTerminal::new(past.clone());
            terminal.terminal.process(b"outdated screen");
            terminal.dirty = true;
            terminal.close_view();
            app.terminals.insert(past.id.clone(), terminal);
            sync_runs(&mut app.terminals, &app.snapshot);
            let previous_generation = app.terminals["past"].generation;
            app.reopen(past);
            let terminal = &app.terminals["past"];
            assert!(terminal.open && !terminal.dirty);
            assert_eq!(terminal.replay_offset, Some(0));
            assert!(terminal.generation > previous_generation);
            assert!(!terminal.terminal.contents().contains("outdated screen"));
            app.select_run(Some("past".into()));
            assert!(app.offline_run().is_some());
            assert!(matches!(
                app.pending_archive,
                Some(Request::Invocations { .. })
            ));
        }
    }

    #[test]
    fn current_boot_finished_and_stopped_terminals_preserve_live_session_state() {
        for state in [RunState::Finished, RunState::Stopped] {
            let mut app = app();
            let mut current = run("current");
            current.state = state;
            app.snapshot.active_vm = Some("vm".into());
            app.snapshot.state = VmState::Running;
            app.snapshot.runs = vec![current.clone()];
            app.reopen(current.clone());
            app.terminals
                .get_mut("current")
                .unwrap()
                .terminal
                .process(b"retained current screen");
            app.terminals.get_mut("current").unwrap().close_view();
            for index in 1..TERMINAL_VIEW_LIMIT {
                let past = run(&format!("open-history-{index}"));
                app.terminals
                    .insert(past.id.clone(), RunTerminal::new(past));
            }
            assert_eq!(available_terminal_slots(&app.terminals, &app.snapshot), 0);
            assert!(app.launch_admission().is_err());
            let generation = app.terminals["current"].generation;
            app.pending_launch = Some(77);
            app.reopen(current);
            sync_runs(&mut app.terminals, &app.snapshot);
            let terminal = &app.terminals["current"];
            assert!(terminal.open && terminal.dirty);
            assert_eq!(terminal.generation, generation);
            assert!(terminal.replay_offset.is_none());
            assert!(terminal
                .terminal
                .contents()
                .contains("retained current screen"));
            app.select_run(Some("current".into()));
            assert!(app.offline_run().is_none());
        }
    }

    #[test]
    fn live_terminal_ownership_requires_matching_vm_boot_and_attached_session() {
        let current = run("current");
        let mut snapshot = Snapshot {
            active_vm: Some("vm".into()),
            state: VmState::Running,
            runs: vec![current.clone()],
            ..Snapshot::default()
        };
        assert!(run_in_live_session(&snapshot, &current));
        let mut past = current.clone();
        past.boot_id = "previous-boot".into();
        assert!(!run_in_live_session(&snapshot, &past));
        past = current.clone();
        past.vm_id = "other-vm".into();
        assert!(!run_in_live_session(&snapshot, &past));
        snapshot.state = VmState::Starting;
        assert!(!run_in_live_session(&snapshot, &current));
        snapshot.state = VmState::Stopping;
        assert!(run_in_live_session(&snapshot, &current));
        snapshot.active_vm = None;
        assert!(!run_in_live_session(&snapshot, &current));
    }

    #[test]
    fn snapshot_recovers_missing_launch_notification_and_preserves_closed_views() {
        let mut app = app();
        let run = run("missed");
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs = vec![run];
        sync_runs(&mut app.terminals, &app.snapshot);
        assert!(app.terminals["missed"].open && app.terminals["missed"].dirty);
        let terminal = app.terminals.get_mut("missed").unwrap();
        terminal.output(1, b"kept", false);
        terminal.close_view();
        sync_runs(&mut app.terminals, &app.snapshot);
        assert!(!app.terminals["missed"].open);
        assert_eq!(app.terminals["missed"].terminal.contents(), "kept");
        assert_eq!(app.terminals.len(), 1);
    }

    #[test]
    fn stale_archive_and_capture_answers_cannot_replace_new_selection() {
        let mut app = app();
        let mut old = run("past");
        old.state = RunState::Finalized;
        app.history.push(old);
        app.select_run(Some("past".into()));
        let generation = app.archive_generation;
        app.archive_page = pair_events(&[event(1, 0)]);
        app.handle_archive_answer(Answer::Invocations {
            generation: generation.wrapping_sub(1),
            offset: 99,
            total: None,
            source_total: None,
            result: Ok(antinomie_monitor_core::InvocationPage {
                invocations: pair_events(&[event(2, 3)]),
                next_offset: None,
                issues: vec![],
            }),
        });
        assert!(app.archive_page[0].entry.is_some());
        assert_eq!(app.archive_offset, 0);
        app.inspector.clear();
        let old_generation = app.inspector.generation;
        app.inspector.clear();
        app.handle_archive_answer(Answer::Captured {
            generation: old_generation,
            offset: 8,
            result: Ok(vec![1, 2, 3]),
        });
        assert!(app.inspector.data.is_empty());
        app.select_run(None);
        app.handle_archive_answer(Answer::Invocations {
            generation,
            offset: 99,
            total: None,
            source_total: None,
            result: Ok(antinomie_monitor_core::InvocationPage {
                invocations: pair_events(&[event(2, 3)]),
                next_offset: None,
                issues: vec![],
            }),
        });
        assert!(app.archive_page.is_empty());
    }

    #[test]
    fn paired_selection_uses_task_call_stream_despite_cpu_migration() {
        let mut app = app();
        app.snapshot.events = vec![event(1, 0), event(2, 3)];
        let rows = app.invocations();
        assert_eq!(rows.len(), 1);
        assert_eq!(trace::key(&rows[0]), (1, 3, 2));
        assert_eq!(rows[0].exit.as_ref().unwrap().cpu, 3);
        assert!(trace::info(&rows[0]).contains("fd=3 buf=0x1000 count=8"));
        app.selected_event = Some((1, 3, 2));
        assert_eq!(
            app.invocations()
                .iter()
                .filter(|row| Some(trace::key(row)) == app.selected_event)
                .count(),
            1
        );
    }

    #[test]
    fn history_selection_keeps_live_snapshot_and_stale_answers_are_ignored() {
        let mut app = app();
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.events = vec![event(1, 0)];
        app.snapshot.runs.push(run("live"));
        let mut old = run("past");
        old.state = RunState::Finalized;
        app.history.push(old);
        app.select_run(Some("past".into()));
        app.archive_page = pair_events(&[event(2, 1)]);
        assert!(app.invocations()[0].entry.is_none());
        assert_eq!(app.snapshot.events.len(), 1);
        let generation = app.archive_generation;
        app.select_run(Some("live".into()));
        assert_ne!(generation, app.archive_generation);
        assert!(app.invocations()[0].entry.is_some());
        assert!(app.snapshot.events[0].result.is_none());
    }

    #[test]
    fn all_live_windows_keep_independent_run_identity_when_one_closes() {
        let mut app = app();
        app.snapshot.runs = vec![run("one"), run("two")];
        app.reopen(run("one"));
        app.reopen(run("two"));
        app.terminals.get_mut("one").unwrap().close_view();
        assert!(!app.terminals["one"].open);
        assert!(app.terminals["two"].open);
        assert_eq!(app.snapshot.runs[0].state, RunState::Running);
        app.reopen(run("one"));
        assert!(app.terminals["one"].open);
    }

    #[test]
    fn terminal_close_flushes_queued_enter_before_hiding_and_stops_at_focus_loss() {
        fn enter() -> egui::Event {
            egui::Event::Key {
                key: egui::Key::Enter,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            }
        }
        for (focused, events, expected) in [
            (
                true,
                vec![egui::Event::Text("echo queued".into()), enter()],
                b"echo queued\r".to_vec(),
            ),
            (
                false,
                vec![
                    egui::Event::Text("echo queued".into()),
                    enter(),
                    egui::Event::WindowFocused(false),
                    egui::Event::Text("late".into()),
                    enter(),
                ],
                b"echo queued\r".to_vec(),
            ),
            (
                false,
                vec![
                    egui::Event::WindowFocused(false),
                    egui::Event::Text("late".into()),
                    enter(),
                ],
                vec![],
            ),
        ] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut terminal = RunTerminal::new(run("fast-close"));
            let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(820.0, 520.0));
            let render = |terminal: &mut RunTerminal, input: egui::RawInput| {
                let mut commands = Vec::new();
                let output = ctx.run(input, |ctx| {
                    commands = show_terminal_viewport(
                        ctx,
                        egui::ViewportClass::Immediate,
                        terminal,
                        true,
                        true,
                    );
                });
                (commands, output)
            };
            for _ in 0..2 {
                let _ = render(
                    &mut terminal,
                    egui::RawInput {
                        screen_rect: Some(screen),
                        ..Default::default()
                    },
                );
            }
            let pos = egui::pos2(20.0, 20.0);
            for pressed in [true, false] {
                let _ = render(
                    &mut terminal,
                    egui::RawInput {
                        screen_rect: Some(screen),
                        events: vec![
                            egui::Event::PointerMoved(pos),
                            egui::Event::PointerButton {
                                pos,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::NONE,
                            },
                        ],
                        ..Default::default()
                    },
                );
            }
            assert!(ctx.memory(|memory| memory.focused().is_some()));
            let mut input = egui::RawInput {
                screen_rect: Some(screen),
                focused,
                events,
                ..Default::default()
            };
            input
                .viewports
                .get_mut(&egui::ViewportId::ROOT)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
            let (commands, output) = render(&mut terminal, input);
            let mut received = Vec::new();
            for command in commands {
                match command {
                    Command::TerminalInput { run_id, data } => {
                        assert_eq!(run_id, "fast-close");
                        received.extend(data);
                    }
                    Command::TerminalResize { run_id, .. } => assert_eq!(run_id, "fast-close"),
                    other => {
                        panic!("closing presentation must not send a lifecycle command: {other:?}")
                    }
                }
            }
            assert_eq!(received, expected);
            assert!(!terminal.open);
            assert_eq!(terminal.run.state, RunState::Running);
            assert!(output.viewport_output[&egui::ViewportId::ROOT]
                .commands
                .iter()
                .any(|command| matches!(command, egui::ViewportCommand::CancelClose)));
        }
    }

    #[test]
    fn clicking_trace_cell_text_selects_its_invocation() {
        for label in [
            "0.000001",
            "1\u{2192}2",
            "42",
            "0\u{2192}3",
            "read (0)",
            "4",
            "fd=3 buf=0x1000 count=8",
        ] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            let mut app = app();
            app.snapshot.events = vec![event(1, 0), event(2, 3)];
            let size = egui::vec2(1280.0, 820.0);
            for _ in 0..3 {
                let _ = render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            let text = texts(&output)
                .into_iter()
                .find(|(text, _)| text == label)
                .unwrap_or_else(|| panic!("missing trace cell {label}"));
            let pos = text.1.center();
            for events in [
                vec![egui::Event::PointerMoved(pos)],
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                }],
                vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            ] {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events,
                        ..Default::default()
                    },
                    |ctx| app.draw(ctx),
                );
            }
            assert_eq!(
                app.selected_event,
                Some((1, 3, 2)),
                "click on {label} must select its row"
            );
        }
    }

    #[test]
    fn double_click_history_text_opens_archive_and_metadata_stays_in_panel() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        app.selected = Some("vm".into());
        let mut saved = run("saved");
        saved.state = RunState::Finished;
        saved.request.path = "/usr/bin/history-row".into();
        saved.request.env = vec!["LONG=value with spaces".into()];
        app.history = vec![saved];
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(900.0, 500.0));
        let draw = |app: &mut MonitorApp, events: Vec<egui::Event>, time: f64| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(screen),
                    events,
                    time: Some(time),
                    ..Default::default()
                },
                |ctx| {
                    egui::TopBottomPanel::bottom("history-details")
                        .exact_height(180.0)
                        .show(ctx, |ui| app.history_detail(ui));
                    egui::CentralPanel::default().show(ctx, |ui| app.run_history(ui));
                },
            )
        };
        for index in 0..3 {
            let _ = draw(&mut app, vec![], f64::from(index) * 0.01);
        }
        let output = draw(&mut app, vec![], 0.03);
        let pos = texts(&output)
            .into_iter()
            .find(|(label, _)| label == "/usr/bin/history-row")
            .expect("history row text")
            .1
            .center();
        let mut time = 0.04;
        let mut output = output;
        for pressed in [true, false, true, false] {
            output = draw(
                &mut app,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                time,
            );
            time += 0.05;
        }
        assert!(app.archive_selected && app.selected_run.as_deref() == Some("saved"));
        assert!(matches!(
            app.pending_archive,
            Some(Request::Invocations { .. })
        ));
        let metadata = texts(&output)
            .into_iter()
            .find(|(label, _)| label == "Launch details")
            .expect("expandable launch details visible below history rows");
        assert!(metadata.1.bottom() < screen.bottom());
    }

    #[test]
    fn trace_categories_hide_and_show_their_rows() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        app.snapshot.events = vec![event(1, 0), event(2, 0)];
        let size = egui::vec2(1280.0, 820.0);
        let row_visible = |app: &mut MonitorApp| {
            for _ in 0..2 {
                let _ = render(app, &ctx, size);
            }
            texts(&render(app, &ctx, size))
                .iter()
                .any(|(text, _)| text == "read (0)")
        };
        assert!(row_visible(&mut app));
        app.settings.hidden_trace_categories = vec![SyscallGroup::File];
        assert!(!row_visible(&mut app));
        app.settings.hidden_trace_categories = vec![SyscallGroup::Network];
        assert!(row_visible(&mut app));
        let labels: Vec<_> = texts(&render(&mut app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert!(labels.contains(&"All".to_string()));
        assert!(
            labels.contains(&"File & filesystem 1".to_string()),
            "{labels:?}"
        );
    }

    #[test]
    fn stopped_vm_trace_offers_its_recent_runs_and_captures() {
        let size = egui::vec2(1280.0, 820.0);
        let fixture = || {
            let mut app = app();
            app.selected = Some("vm".into());
            let mut saved = run("saved");
            saved.state = RunState::Finished;
            saved.request.path = "/usr/bin/recent-run".into();
            app.history = vec![saved];
            app.capture_history = vec![observer("cap", CaptureState::Finalized)];
            // Stale events of an ended session are not a live trace.
            app.snapshot.events = vec![event(1, 0), event(2, 0)];
            app.snapshot.vms = vec![VmConfig {
                id: "vm".into(),
                ..VmConfig::default()
            }];
            app
        };
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = fixture();
        assert!(app.no_live_trace());
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        for label in [
            "No live trace",
            "Recent runs",
            "/usr/bin/recent-run",
            "Recent captures",
            "All guest programs",
        ] {
            assert!(shown.iter().any(|text| text == label), "{label}: {shown:?}");
        }
        assert!(!shown.iter().any(|text| text == "read (0)"));
        // Run History lists runs; the panel asked for the captures too.
        assert!(matches!(
            app.pending_archive,
            Some(Request::ListCaptures { ref vm_id, .. }) if vm_id == "vm"
        ));

        click_label(&mut app, &ctx, size, "/usr/bin/recent-run");
        assert_eq!(app.selected_run.as_deref(), Some("saved"));
        assert!(app.archive_selected);
        assert!(matches!(
            app.pending_archive,
            Some(Request::Invocations { capture: false, .. })
        ));
        assert!(!app.no_live_trace());

        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = fixture();
        click_label(&mut app, &ctx, size, "All guest programs");
        assert_eq!(app.selected_capture.as_deref(), Some("cap"));
        assert!(matches!(
            app.pending_archive,
            Some(Request::Invocations { capture: true, .. })
        ));

        // A running VM shows its live trace instead.
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = fixture();
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        assert!(!app.no_live_trace());
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        assert!(texts(&render(&mut app, &ctx, size))
            .iter()
            .any(|(text, _)| text == "read (0)"));
    }

    #[test]
    fn category_chips_wrap_to_two_lines_inside_the_panel() {
        for (size, font) in [
            (egui::vec2(1280.0, 820.0), 16.0),
            (egui::vec2(800.0, 600.0), 16.0),
            (egui::vec2(800.0, 600.0), 24.0),
        ] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font);
            let mut app = app();
            app.settings.font_size = font;
            app.snapshot.events = vec![event(1, 0), event(2, 0)];
            for _ in 0..3 {
                let _ = render(&mut app, &ctx, size);
            }
            let texts = texts(&render(&mut app, &ctx, size));
            let chips: Vec<_> = texts
                .iter()
                .filter(|(text, _)| {
                    text == "All"
                        || SyscallGroup::ALL.iter().any(|group| {
                            text.strip_prefix(group.label())
                                .and_then(|count| count.strip_prefix(' '))
                                .is_some_and(|count| count.parse::<usize>().is_ok())
                        })
                })
                .map(|(_, rect)| *rect)
                .collect();
            let mut lines: Vec<f32> = Vec::new();
            for chip in &chips {
                if !lines
                    .iter()
                    .any(|line| (line - chip.center().y).abs() < 8.0)
                {
                    lines.push(chip.center().y);
                }
                assert!(chip.right() <= size.x, "chip overflows at {size:?}/{font}");
            }
            assert!(lines.len() <= 2, "chip lines {lines:?} at {size:?}/{font}");
            if size.x > 1000.0 {
                // Wide enough for every chip within the two lines.
                assert_eq!(chips.len(), SyscallGroup::ALL.len() + 1);
                assert_eq!(lines.len(), 2);
            }
            let header = texts
                .iter()
                .find(|(text, _)| text == "Record")
                .expect("table header stays in view")
                .1;
            assert!(chips.iter().all(|chip| chip.bottom() < header.top()));
        }
    }

    #[test]
    fn native_layout_keeps_controls_and_trace_panels_separate_at_all_text_sizes() {
        for size in [egui::vec2(800.0, 600.0), egui::vec2(1280.0, 820.0)] {
            for font in [12.0, 16.0, 24.0] {
                let ctx = egui::Context::default();
                theme::install(&ctx);
                theme::text_size(&ctx, font);
                let mut app = app();
                app.settings.font_size = font;
                app.snapshot.events = vec![event(1, 0), event(2, 3)];
                app.snapshot.health.dropped = 3;
                for _ in 0..3 {
                    let _ = render(&mut app, &ctx, size);
                }
                let output = render(&mut app, &ctx, size);
                let texts = texts(&output);
                let rect = |label: &str| {
                    texts
                        .iter()
                        .find(|(text, _)| text == label)
                        .unwrap_or_else(|| panic!("missing {label} at {size:?}/{font}: {texts:?}"))
                        .1
                };
                assert!(rect("Syscalls").bottom() < rect("Details").top());
                assert!(rect("Details").bottom() < rect("TRL").top());
                // The status bar value sits beside its name, colored as a loss.
                let label = rect("TRL");
                let loss = texts
                    .iter()
                    .find(|(text, value)| {
                        text == "3" && (value.center().y - label.center().y).abs() < 4.0
                    })
                    .expect("transport loss value")
                    .1;
                assert!(label.right() < loss.left());
                assert!(
                    rect(&format!("Antinomie {APP_VERSION}")).right() > size.x - 48.0,
                    "loss meters must sit on the right edge"
                );
                assert!(rect("File").bottom() < rect("Syscalls").top());
                let title = rect("Virtual machines");
                let add = texts
                    .iter()
                    .find(|(text, rect)| {
                        text == egui_phosphor::regular::PLUS
                            && rect.top() < title.bottom()
                            && rect.bottom() > title.top()
                    })
                    .expect("sidebar Add control must remain visible")
                    .1;
                assert!(
                    title.right() <= add.left(),
                    "sidebar title {title:?} overlaps Add {add:?} at {font}"
                );
                assert!(rect("Return").right() <= rect("Info").left());
                assert!(!texts.iter().any(|(text, _)| text == "Terminal"));
                // DejaVu Sans Mono runs wider; data text is one point smaller.
                assert_eq!(
                    ctx.style().text_styles[&egui::TextStyle::Monospace].size,
                    font - 1.0
                );
            }
        }
    }

    fn analysis_setup_fixture() -> MonitorApp {
        let mut app = app();
        app.snapshot.state = VmState::Running;
        app.selected = Some("vm".into());
        app.snapshot.active_vm = app.selected.clone();
        let vm = VmConfig {
            id: "vm".into(),
            name: "Analysis QA".into(),
            ..VmConfig::default()
        };
        app.snapshot.vms.push(vm);
        app.launch_open = true;
        app.exec.path = "/usr/bin/sample".into();
        app.exec.analysis.enabled = true;
        app.exec.analysis.checks = vec![
            antinomie_monitor_core::AnalysisKind::Metadata,
            antinomie_monitor_core::AnalysisKind::Structures,
        ];
        app
    }

    #[test]
    fn run_setup_title_can_move_and_reopen_without_resetting_position() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 900.0);
        let mut app = analysis_setup_fixture();
        for _ in 0..4 {
            render(&mut app, &ctx, size);
        }
        let before = egui::AreaState::load(&ctx, Dialog::Launch.window_id())
            .unwrap()
            .rect();
        let output = render(&mut app, &ctx, size);
        let start = texts(&output)
            .iter()
            .find(|(text, _)| text == "Run program")
            .unwrap()
            .1
            .center();
        let end = start + egui::vec2(32.0, -12.0);
        for events in [
            vec![egui::Event::PointerMoved(start)],
            vec![egui::Event::PointerButton {
                pos: start,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
            vec![egui::Event::PointerMoved(end)],
            vec![egui::Event::PointerButton {
                pos: end,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        ] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events,
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let moved = egui::AreaState::load(&ctx, Dialog::Launch.window_id())
            .unwrap()
            .rect();
        assert!(
            moved.min.x > before.min.x + 12.0 && moved.min.y < before.min.y - 4.0,
            "title drag must move the dialog: {before:?} -> {moved:?}"
        );
        app.launch_open = false;
        render(&mut app, &ctx, size);
        app.launch_open = true;
        render(&mut app, &ctx, size);
        let reopened = egui::AreaState::load(&ctx, Dialog::Launch.window_id())
            .unwrap()
            .rect();
        assert!(
            (reopened.min - moved.min).length() < 1.0,
            "reopen retains the moved position"
        );
        let (run, analyze) = app.launch_action_rects.unwrap();
        assert!(run.bottom() < size.y && analyze.bottom() < size.y);
    }

    #[test]
    fn run_setup_keeps_final_actions_visible_and_dispatches_a_selection_snapshot() {
        for (size, font) in [
            (egui::vec2(1280.0, 820.0), 18.0),
            (egui::vec2(1280.0, 820.0), 24.0),
            (egui::vec2(800.0, 600.0), 24.0),
        ] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font);
            let mut app = analysis_setup_fixture();
            app.settings.font_size = font;
            for _ in 0..3 {
                let _ = render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            let visible = texts(&output);
            let action = |suffix: &str| {
                visible
                    .iter()
                    .find(|(text, _)| text.ends_with(suffix))
                    .unwrap_or_else(|| panic!("missing {suffix} at {size:?}/{font}: {visible:?}"))
                    .1
            };
            let run_rect = action(" Run");
            assert!(run_rect.bottom() < size.y);
            let _ = action("Analyze Only");
            let (run_rect, analyze_rect) = app.launch_action_rects.unwrap();
            assert!((analyze_rect.center().y - run_rect.center().y).abs() < 1.0);
            assert!(run_rect.right() < analyze_rect.left());
            for pressed in [true, false] {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events: vec![
                            egui::Event::PointerMoved(run_rect.center()),
                            egui::Event::PointerButton {
                                pos: run_rect.center(),
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::NONE,
                            },
                        ],
                        ..Default::default()
                    },
                    |ctx| app.draw(ctx),
                );
            }
            assert!(app.submitted.iter().any(|command| matches!(command, Command::Execute(request) if request.analysis.enabled && request.analysis.checks.len() == 2)), "Run action did not submit at {size:?}/{font}");
            app.exec.analysis.checks.clear();
            assert!(app.submitted.iter().any(|command| matches!(command, Command::Execute(request) if request.analysis.checks.len() == 2)));
        }
    }

    #[test]
    fn run_in_is_offered_for_graphical_bases_remembered_and_sent_with_the_launch() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = analysis_setup_fixture();
        app.exec.analysis.enabled = false;
        app.exec.run_in = RunIn::GuestDesktop;
        let click_run = |app: &mut MonitorApp| {
            for _ in 0..3 {
                let _ = render(app, &ctx, size);
            }
            let output = render(app, &ctx, size);
            let visible = texts(&output);
            let offered = visible.iter().any(|(text, _)| text == "Run in");
            let run = app.launch_action_rects.unwrap().0.center();
            for pressed in [true, false] {
                let _ = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events: vec![
                            egui::Event::PointerMoved(run),
                            egui::Event::PointerButton {
                                pos: run,
                                button: egui::PointerButton::Primary,
                                pressed,
                                modifiers: egui::Modifiers::NONE,
                            },
                        ],
                        ..Default::default()
                    },
                    |ctx| app.draw(ctx),
                );
            }
            let sent = app
                .submitted
                .iter()
                .rev()
                .find_map(|command| match command {
                    Command::Execute(request) => Some(request.run_in),
                    _ => None,
                });
            (offered, sent)
        };
        // A base without a desktop hides the choice and runs in the app.
        assert_eq!(click_run(&mut app), (false, Some(RunIn::AppTerminal)));
        assert_eq!(app.exec.run_in, RunIn::GuestDesktop);

        let mut app = analysis_setup_fixture();
        app.exec.analysis.enabled = false;
        app.exec.run_in = RunIn::GuestDesktopTerminal;
        app.snapshot
            .bases
            .push(antinomie_monitor_core::BaseSummary {
                id: "gnome".into(),
                label: "Debian 13 (GNOME)".into(),
                directory: "/bases/gnome".into(),
                min_ram_mib: 4096,
                min_disk_gib: 16,
                fixed_display: true,
                size_bytes: 0,
                revision: Some(APP_REVISION),
                min_app_version: None,
                built_with: None,
                guest: Some(antinomie_monitor_core::GuestProfile {
                    id: "debian-gnome".into(),
                    label: "Debian 13 (GNOME)".into(),
                    min_ram_mib: 4096,
                    min_disk_gib: 16,
                    requires_credentials: true,
                    graphical: true,
                }),
            });
        app.snapshot.vms[0].base_identity = Some("gnome".into());
        assert_eq!(
            click_run(&mut app),
            (true, Some(RunIn::GuestDesktopTerminal))
        );
        // The dialog keeps the choice for the next launch.
        assert_eq!(app.exec.run_in, RunIn::GuestDesktopTerminal);
    }

    #[test]
    fn static_analysis_uses_selected_archive_report_without_submitting_work() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        let mut live = run("same-run");
        let report = |id: &str| antinomie_monitor_core::AnalysisReport {
            id: id.into(),
            state: antinomie_monitor_core::AnalysisState::Unavailable,
            source_path: "/sample".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: Some("Acquisition unavailable in fixture".into()),
            sections: Vec::new(),
        };
        live.analysis = Some(report("live-report"));
        app.snapshot.runs.push(live.clone());
        live.analysis = Some(report("archive-report"));
        app.history.push(live);
        app.selected_run = Some("same-run".into());
        app.archive_selected = true;
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default()
                .show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
        });
        let visible = texts(&output);
        assert!(visible
            .iter()
            .any(|(text, _)| text.contains("archive-report")));
        assert!(!visible.iter().any(|(text, _)| text.contains("live-report")));
        assert!(app.submitted.is_empty());
    }

    #[test]
    fn specimen_answers_require_the_current_pane_report_and_selection_ticket() {
        let mut app = app();
        let view = app.analysis_views.entry("workspace".into()).or_default();
        view.bind(Some("selected-report"));
        view.pending = Some((7, 16, 4));
        let answer = |view_key: &str, generation, report_id: &str| Answer::Specimen {
            view_key: view_key.into(),
            generation,
            report_id: report_id.into(),
            offset: 16,
            data_len: 4,
            result: Ok(antinomie_monitor_core::AnalysisSpecimenPage {
                report_id: report_id.into(),
                offset: 16,
                total_len: 64,
                data: b"data".to_vec(),
            }),
        };
        app.handle_archive_answer(answer("workspace", 6, "selected-report"));
        app.handle_archive_answer(answer("workspace", 7, "different-report"));
        app.handle_archive_answer(answer("closed-pane", 7, "selected-report"));
        assert!(app.analysis_views["workspace"].preview.is_none());
        assert_eq!(app.analysis_views["workspace"].pending, Some((7, 16, 4)));
        app.handle_archive_answer(answer("workspace", 7, "selected-report"));
        assert_eq!(
            app.analysis_views["workspace"]
                .preview
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .data,
            b"data"
        );
        assert!(app.analysis_views["workspace"].pending.is_none());
        app.analysis_views
            .get_mut("workspace")
            .unwrap()
            .bind(Some("new-report"));
        app.handle_archive_answer(answer("workspace", 7, "selected-report"));
        assert!(app.analysis_views["workspace"].preview.is_none());
    }

    #[test]
    fn specimen_requests_use_retained_directories_and_supersession_clears_pending() {
        let mut app = app();
        let mut saved = run("saved-run");
        saved.analysis = Some(section_report("saved-report", "SAVED"));
        saved.directory = "/saved/run".into();
        app.history.push(saved);
        app.analysis_views
            .entry("workspace".into())
            .or_default()
            .bind(Some("saved-report"));
        app.analysis_action(
            "workspace",
            Some(crate::analysis::ReportAction::ReadSpecimen {
                report_id: "saved-report".into(),
                offset: 0,
                data_len: 4,
            }),
        );
        assert!(
            matches!(app.pending_archive, Some(Request::Specimen { ref directory, ref report_id, .. })
            if directory == &PathBuf::from("/saved/run/analysis") && report_id == "saved-report")
        );
        app.queue_archive(Request::ListVm {
            options: app.options.clone(),
            vm_id: "vm".into(),
            generation: 1,
        });
        assert!(app.analysis_views["workspace"].pending.is_none());
        assert!(app.analysis_views["workspace"]
            .preview
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap_err()
            .contains("superseded"));
        assert!(app.submitted.is_empty());
    }

    #[test]
    fn closed_analysis_panes_release_their_state_and_late_answers() {
        let mut app = app();
        app.analysis_views
            .entry("workspace".into())
            .or_default()
            .bind(Some("main"));
        let section = app
            .analysis_views
            .entry("section:closed:Strings".into())
            .or_default();
        section.bind(Some("closed"));
        section.pending = Some((2, 0, 1));
        app.retain_analysis_windows(&[]);
        assert_eq!(app.analysis_views.len(), 1);
        app.handle_archive_answer(Answer::Specimen {
            view_key: "section:closed:Strings".into(),
            generation: 2,
            report_id: "closed".into(),
            offset: 0,
            data_len: 1,
            result: Err("late error".into()),
        });
        assert_eq!(app.analysis_views.len(), 1);
    }

    #[test]
    fn detached_analysis_retains_its_directory_after_vm_history_changes() {
        let mut app = app();
        let mut saved = run("saved-run");
        saved.directory = "/saved/run".into();
        saved.analysis = Some(section_report("saved-report", "SAVED"));
        app.history.push(saved);
        app.open_analysis_section(
            "saved-report".into(),
            antinomie_monitor_core::AnalysisKind::Strings,
        )
        .unwrap();
        app.take_analysis_sections();
        app.history.clear();
        assert_eq!(
            app.analysis_directory("saved-report"),
            Some(PathBuf::from("/saved/run/analysis"))
        );
        app.retain_analysis_windows(&[]);
        assert!(app.analysis_directory("saved-report").is_none());
    }

    #[test]
    fn missing_specimen_reader_is_an_explicit_error_not_a_stuck_request() {
        let mut app = app();
        let mut saved = run("saved-run");
        saved.analysis = Some(section_report("saved-report", "SAVED"));
        app.history.push(saved);
        app.analysis_views
            .entry("workspace".into())
            .or_default()
            .bind(Some("saved-report"));
        app.analysis_action(
            "workspace",
            Some(crate::analysis::ReportAction::ReadSpecimen {
                report_id: "saved-report".into(),
                offset: 0,
                data_len: 1,
            }),
        );
        app.flush_archive();
        assert!(app.analysis_views["workspace"].pending.is_none());
        assert!(app.analysis_views["workspace"]
            .preview
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap_err()
            .contains("unavailable"));
    }

    #[test]
    fn analyze_only_and_cancel_do_not_launch_or_stop_a_program() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1280.0, 820.0);
        let mut app = analysis_setup_fixture();
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let target = texts(&output)
            .into_iter()
            .find(|(text, _)| text == "Analyze Only")
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events: vec![
                        egui::Event::PointerMoved(target),
                        egui::Event::PointerButton {
                            pos: target,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert!(app.submitted.iter().any(|command| matches!(command, Command::AnalyzeOnly { analysis, path, .. } if analysis.enabled && path == "/usr/bin/sample")));
        assert!(app.pending_launch.is_none() && app.terminals.is_empty());
        app.launch_open = false;
        app.snapshot
            .analysis_reports
            .push(antinomie_monitor_core::AnalysisReport {
                id: "standalone-job".into(),
                state: antinomie_monitor_core::AnalysisState::Running,
                source_path: "/sample".into(),
                specimen_sha256: None,
                specimen_len: None,
                reason: None,
                sections: Vec::new(),
            });
        app.selected_analysis = Some("standalone-job".into());
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default()
                .show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
        });
        let target = texts(&output)
            .into_iter()
            .find(|(text, _)| text == egui_phosphor::regular::X)
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    events: vec![
                        egui::Event::PointerMoved(target),
                        egui::Event::PointerButton {
                            pos: target,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default()
                        .show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
                },
            );
        }
        assert!(app.submitted.iter().any(|command| matches!(command, Command::CancelAnalysis { analysis_id } if analysis_id == "standalone-job")));
        assert!(!app
            .submitted
            .iter()
            .any(|command| matches!(command, Command::Execute(_) | Command::StopRun { .. })));
        assert!(app.pending_launch.is_none() && app.terminals.is_empty());
    }

    #[test]
    #[ignore = "requires X11 native rendering; exits after 20 seconds"]
    fn native_analysis_setup_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct QaApp {
            app: MonitorApp,
            deadline: Instant,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                if Instant::now() >= self.deadline {
                    self.app.snapshot.active_vm = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                eframe::App::update(&mut self.app, ctx, frame);
            }
        }
        let small = std::env::var_os("ANTINOMIE_ANALYSIS_QA_SMALL").is_some();
        let size = if small {
            [800.0, 600.0]
        } else {
            [1280.0, 820.0]
        };
        eframe::run_native(
            "Antinomie Run Setup QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size(size),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11();
                    builder.with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                let mut app = analysis_setup_fixture();
                app.settings.font_size = if small { 24.0 } else { 18.0 };
                theme::text_size(&cc.egui_ctx, app.settings.font_size);
                Ok(Box::new(QaApp {
                    app,
                    deadline: Instant::now() + Duration::from_secs(20),
                }))
            }),
        )
        .unwrap();
    }

    #[test]
    #[ignore = "requires decorated X11; automatically checks terminal geometry and exits"]
    fn native_terminal_geometry_regression() {
        use std::sync::{Arc, Mutex};
        use winit::platform::x11::EventLoopBuilderExtX11;
        #[derive(Default)]
        struct Evidence {
            samples: Vec<(f32, egui::Pos2, egui::Vec2)>,
            raw_geometry: Vec<(f32, egui::Rect, egui::Rect)>,
            decorated: bool,
            retained: bool,
            reopened: bool,
        }
        struct QaApp {
            app: MonitorApp,
            started: Instant,
            evidence: Arc<Mutex<Evidence>>,
            moved: bool,
            closed: bool,
            reopened: bool,
            settled_after: Option<f32>,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                let elapsed = self.started.elapsed().as_secs_f32();
                let viewport = egui::ViewportId::from_hash_of(("workspace", 1usize));
                if elapsed >= 8.0 {
                    self.app.snapshot.active_vm = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                eframe::App::update(&mut self.app, ctx, frame);
                if elapsed >= 0.5 && (!self.closed || self.reopened) {
                    if let Some((outer, inner)) = ctx.input_for(viewport, |input| {
                        Some((input.viewport().outer_rect?, input.viewport().inner_rect?))
                    }) {
                        let mut evidence = self.evidence.lock().expect("geometry evidence");
                        evidence.raw_geometry.push((elapsed, outer, inner));
                        if inner.min.y - outer.min.y >= 10.0 {
                            evidence.decorated = true;
                            self.settled_after.get_or_insert(elapsed + 0.7);
                        }
                        if self.settled_after.is_some_and(|after| elapsed >= after) {
                            evidence.samples.push((elapsed, outer.min, inner.size()));
                        }
                    }
                }
                if elapsed >= 3.0 && !self.moved {
                    self.moved = true;
                    ctx.send_viewport_cmd_to(
                        viewport,
                        egui::ViewportCommand::OuterPosition(egui::pos2(140.0, 100.0)),
                    );
                    ctx.send_viewport_cmd_to(
                        viewport,
                        egui::ViewportCommand::InnerSize(egui::vec2(740.0, 460.0)),
                    );
                }
                if elapsed >= 5.0 && !self.closed {
                    self.closed = true;
                    self.settled_after = None;
                    self.app.close_terminal_view("geometry-terminal");
                }
                if elapsed >= 5.5 && !self.reopened {
                    self.reopened = true;
                    let terminal = self
                        .app
                        .terminals
                        .get_mut("geometry-terminal")
                        .expect("retained terminal");
                    terminal.open = true;
                    let mut evidence = self.evidence.lock().expect("geometry evidence");
                    evidence.retained = terminal
                        .terminal
                        .contents()
                        .contains("GEOMETRY BUFFER RETAINED");
                    evidence.reopened = true;
                }
                ctx.request_repaint_after(Duration::from_millis(10));
            }
        }
        let evidence = Arc::new(Mutex::new(Evidence::default()));
        let result = evidence.clone();
        eframe::run_native(
            "Antinomie Terminal Geometry QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 720.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                let mut app = app();
                let run = run("geometry-terminal");
                app.snapshot.runs.push(run.clone());
                let mut terminal = RunTerminal::new(run);
                terminal.output(1, b"GEOMETRY BUFFER RETAINED\r\n", false);
                app.terminals.insert("geometry-terminal".into(), terminal);
                Ok(Box::new(QaApp {
                    app,
                    started: Instant::now(),
                    evidence,
                    moved: false,
                    closed: false,
                    reopened: false,
                    settled_after: None,
                }))
            }),
        )
        .expect("native geometry fixture");
        let evidence = result.lock().expect("geometry evidence");
        eprintln!(
            "Decorated: {}; samples: {}; buffer retained: {}; reopened: {}",
            evidence.decorated,
            evidence.samples.len(),
            evidence.retained,
            evidence.reopened
        );
        assert!(
            evidence.decorated,
            "fixture requires a decorating X11 window manager"
        );
        eprintln!(
            "Raw geometry (time, outer rect, inner rect): {:?}",
            evidence.raw_geometry
        );
        for (start, end) in [(1.2, 2.8), (3.8, 4.9), (6.2, 7.8)] {
            let samples: Vec<_> = evidence
                .samples
                .iter()
                .filter(|(time, _, _)| *time >= start && *time <= end)
                .collect();
            assert!(
                samples.len() >= 10,
                "insufficient geometry samples: {}",
                samples.len()
            );
            let (_, origin, size) = samples[0];
            let max_drift = samples
                .iter()
                .map(|(_, next, _)| next.distance(*origin))
                .fold(0.0_f32, f32::max);
            let max_resize = samples
                .iter()
                .map(|(_, _, next)| (*next - *size).length())
                .fold(0.0_f32, f32::max);
            eprintln!(
                "Phase {start}..{end}: {} samples; outer origin {origin:?}; inner size {size:?}; max drift {max_drift}; max resize {max_resize}",
                samples.len()
            );
            assert!(
                max_drift <= 2.0,
                "terminal outer origin drifted {max_drift} points"
            );
            assert!(
                max_resize <= 2.0,
                "terminal inner size drifted {max_resize} points"
            );
            if start == 3.8 {
                assert!(
                    origin.distance(egui::pos2(140.0, 100.0)) <= 2.0,
                    "move target was not applied: {origin:?}"
                );
                assert!(
                    (*size - egui::vec2(740.0, 460.0)).length() <= 2.0,
                    "resize target was not applied: {size:?}"
                );
            }
            if start == 6.2 {
                assert!(
                    (*size - egui::vec2(820.0, 520.0)).length() <= 2.0,
                    "reopened viewport did not expose fresh default geometry: {size:?}"
                );
                assert!(
                    origin.x >= 0.0
                        && origin.y >= 0.0
                        && origin.x + size.x <= 1600.0
                        && origin.y + size.y <= 1000.0,
                    "reopened window is not on screen: {origin:?}/{size:?}"
                );
            }
        }
        assert!(evidence.retained && evidence.reopened);
    }

    #[test]
    #[ignore = "requires decorated X11; maximizes a terminal window and exits"]
    fn native_terminal_window_maximizes_and_grows_its_grid() {
        use std::sync::{Arc, Mutex};
        use winit::platform::x11::EventLoopBuilderExtX11;
        #[derive(Default)]
        struct Evidence {
            before: Option<(egui::Vec2, (u16, u16))>,
            after: Option<(egui::Vec2, (u16, u16), bool)>,
        }
        struct QaApp {
            app: MonitorApp,
            started: Instant,
            evidence: Arc<Mutex<Evidence>>,
            maximized: bool,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                let elapsed = self.started.elapsed().as_secs_f32();
                let viewport = egui::ViewportId::from_hash_of(("workspace", 1usize));
                if elapsed >= 5.0 {
                    self.app.snapshot.active_vm = None;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                eframe::App::update(&mut self.app, ctx, frame);
                let inner = ctx.input_for(viewport, |input| input.viewport().inner_rect);
                let maximized = ctx.input_for(viewport, |input| input.viewport().maximized);
                let grid = self.app.terminals["maximize"].terminal.size();
                let mut evidence = self.evidence.lock().expect("maximize evidence");
                if elapsed >= 1.5 && !self.maximized {
                    self.maximized = true;
                    evidence.before = inner.map(|inner| (inner.size(), grid));
                    // The same request the window manager's maximize button makes.
                    ctx.send_viewport_cmd_to(viewport, egui::ViewportCommand::Maximized(true));
                }
                if elapsed >= 4.0 {
                    evidence.after =
                        inner.map(|inner| (inner.size(), grid, maximized == Some(true)));
                }
                ctx.request_repaint_after(Duration::from_millis(10));
            }
        }
        let evidence = Arc::new(Mutex::new(Evidence::default()));
        let result = evidence.clone();
        eframe::run_native(
            "Antinomie Terminal Maximize QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 720.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                let mut app = app();
                app.snapshot.state = VmState::Running;
                app.snapshot.active_vm = Some("vm".into());
                let run = run("maximize");
                app.snapshot.runs.push(run.clone());
                app.terminals
                    .insert("maximize".into(), RunTerminal::new(run));
                Ok(Box::new(QaApp {
                    app,
                    started: Instant::now(),
                    evidence,
                    maximized: false,
                }))
            }),
        )
        .expect("native maximize fixture");
        let evidence = result.lock().expect("maximize evidence");
        let (size, grid) = evidence.before.expect("terminal window before maximizing");
        let (maximized_size, maximized_grid, maximized) =
            evidence.after.expect("terminal window after maximizing");
        eprintln!("Before: {size:?} {grid:?}; after: {maximized_size:?} {maximized_grid:?}");
        assert!(
            maximized,
            "window manager did not maximize the terminal window"
        );
        assert!(maximized_size.x > size.x + 100.0 && maximized_size.y > size.y + 100.0);
        assert!(maximized_grid.0 > grid.0 && maximized_grid.1 > grid.1);
    }

    fn section_report(id: &str, marker: &str) -> antinomie_monitor_core::AnalysisReport {
        use antinomie_monitor_core::{
            AnalysisEntry, AnalysisKind, AnalysisReport, AnalysisSection, AnalysisSectionState,
            AnalysisState,
        };
        AnalysisReport {
            id: id.into(),
            state: AnalysisState::Partial,
            source_path: format!("/fixture/{marker}"),
            specimen_sha256: None,
            specimen_len: Some(4096),
            reason: Some("Synthetic UI fixture; no analyzer was run".into()),
            sections: vec![
                AnalysisSection {
                    kind: AnalysisKind::Metadata,
                    state: AnalysisSectionState::Complete,
                    summary: format!("{marker} metadata"),
                    tools: Vec::new(),
                    listing: None,
                    entries: vec![AnalysisEntry {
                        label: "Identity".into(),
                        value: marker.into(),
                        offset: None,
                        record: None,
                    }],
                },
                AnalysisSection {
                    kind: AnalysisKind::Structures,
                    state: AnalysisSectionState::Unavailable,
                    summary: format!("{marker} structures unavailable"),
                    tools: Vec::new(),
                    listing: None,
                    entries: Vec::new(),
                },
                AnalysisSection {
                    kind: AnalysisKind::Strings,
                    state: AnalysisSectionState::Partial,
                    summary: "Bounded synthetic rows".into(),
                    tools: Vec::new(),
                    listing: None,
                    entries: (0..2048)
                        .map(|index| AnalysisEntry {
                            label: format!("Row {index}"),
                            value: "Synthetic evidence".into(),
                            offset: Some(index),
                            record: None,
                        })
                        .collect(),
                },
            ],
        }
    }

    #[test]
    fn section_windows_keep_report_identity_and_prune_only_unreferenced_reports() {
        use antinomie_monitor_core::AnalysisKind;
        let mut app = app();
        let mut archived = run("archived");
        archived.analysis = Some(section_report("archive-a", "ARCHIVE A"));
        app.history.push(archived);
        app.snapshot
            .analysis_reports
            .push(section_report("standalone-b", "STANDALONE B"));
        app.open_analysis_section("archive-a".into(), AnalysisKind::Metadata)
            .unwrap();
        app.open_analysis_section("archive-a".into(), AnalysisKind::Metadata)
            .unwrap();
        app.open_analysis_section("standalone-b".into(), AnalysisKind::Structures)
            .unwrap();
        app.retain_analysis_windows(&[]);
        assert_eq!(
            app.analysis_windows.len(),
            2,
            "pending requests retain snapshots"
        );
        assert_eq!(
            app.take_analysis_sections().len(),
            2,
            "duplicate sections reuse a panel"
        );
        app.selected_analysis = Some("standalone-b".into());
        app.select_archive_run("archived".into());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                app.show_panel(
                    ui,
                    &Panel::AnalysisSection {
                        report_id: "archive-a".into(),
                        kind: AnalysisKind::Metadata,
                    },
                )
            });
        });
        assert!(texts(&output).iter().any(|(text, _)| text == "ARCHIVE A"));
        assert!(!texts(&output)
            .iter()
            .any(|(text, _)| text == "STANDALONE B"));
        app.retain_analysis_windows(&["standalone-b".into()]);
        assert!(!app.analysis_windows.contains_key("archive-a"));
        assert!(app.analysis_windows.contains_key("standalone-b"));
        assert!(
            app.submitted.is_empty(),
            "opening/closing sections never scans or cancels"
        );
    }

    #[test]
    fn section_cache_is_bounded_and_refreshes_matching_live_reports() {
        use antinomie_monitor_core::AnalysisKind;
        let mut app = app();
        for index in 0..9 {
            let id = format!("report-{index}");
            app.snapshot
                .analysis_reports
                .push(section_report(&id, "INITIAL"));
            let result = app.open_analysis_section(id, AnalysisKind::Metadata);
            assert_eq!(result.is_ok(), index < 8);
        }
        assert_eq!(app.analysis_windows.len(), 8);
        app.open_analysis_section("report-0".into(), AnalysisKind::Strings)
            .unwrap();
        app.snapshot.analysis_reports[0] = section_report("report-0", "UPDATED");
        app.refresh_analysis_windows();
        assert_eq!(
            app.analysis_windows["report-0"].source_path,
            "/fixture/UPDATED"
        );
        assert_eq!(
            app.analysis_windows["report-1"].source_path,
            "/fixture/INITIAL"
        );
        app.take_analysis_sections();
        app.retain_analysis_windows(&[]);
        assert!(app.analysis_windows.is_empty());
        app.open_analysis_section("report-8".into(), AnalysisKind::Metadata)
            .unwrap();
    }

    #[test]
    fn summary_is_compact_with_thousands_of_rows_and_section_renders_only_its_kind() {
        use antinomie_monitor_core::AnalysisKind;
        for font in [18.0, 24.0] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font);
            let report = section_report("summary", "METADATA MARKER");
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 600.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        assert!(crate::analysis::workspace(
                            ui,
                            Some(&report),
                            &mut crate::analysis::WorkspaceState::default(),
                            None,
                            None
                        )
                        .is_none());
                    });
                },
            );
            assert!(texts(&output)
                .iter()
                .any(|(text, _)| text == "Partial / 2048 rows"));
            assert!(!texts(&output)
                .iter()
                .any(|(text, _)| text.starts_with("Row ")));
            assert!(
                output.shapes.len() < 150,
                "summary size must not depend on evidence row count"
            );
            let output = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    crate::analysis::workspace_section(
                        ui,
                        Some(&report),
                        AnalysisKind::Metadata,
                        &mut crate::analysis::WorkspaceState::default(),
                        None,
                        None,
                    )
                });
            });
            assert!(texts(&output)
                .iter()
                .any(|(text, _)| text == "METADATA MARKER"));
            assert!(!texts(&output)
                .iter()
                .any(|(text, _)| text.starts_with("Row ")));
        }
    }

    #[test]
    fn summary_open_button_requests_only_the_chosen_section_without_backend_work() {
        let mut app = app();
        app.snapshot
            .analysis_reports
            .push(section_report("chosen", "CHOSEN"));
        app.selected_analysis = Some("chosen".into());
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let render = |app: &mut MonitorApp, events| {
            ctx.run(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default()
                        .show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
                },
            )
        };
        let mut output = render(&mut app, Vec::new());
        for _ in 0..3 {
            output = render(&mut app, Vec::new());
        }
        let target = texts(&output)
            .iter()
            .find(|(text, _)| text == egui_phosphor::regular::ARROW_SQUARE_OUT)
            .unwrap()
            .1
            .center();
        for pressed in [true, false] {
            render(
                &mut app,
                vec![
                    egui::Event::PointerMoved(target),
                    egui::Event::PointerButton {
                        pos: target,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
        }
        assert_eq!(
            app.take_analysis_sections(),
            [(
                "chosen".into(),
                antinomie_monitor_core::AnalysisKind::Metadata
            )]
        );
        assert!(app.submitted.is_empty());
    }

    #[test]
    #[ignore = "requires X11 native section previews; automatically exits after 15 seconds"]
    fn native_analysis_sections_fixture() {
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct QaApp {
            app: MonitorApp,
            deadline: Instant,
            updates: usize,
            held_updates: usize,
            releases: usize,
            reported: bool,
        }
        impl eframe::App for QaApp {
            fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
                self.updates += 1;
                ctx.input(|input| {
                    self.held_updates += usize::from(input.pointer.primary_down());
                    self.releases += input
                        .events
                        .iter()
                        .filter(|event| {
                            matches!(
                                event,
                                egui::Event::PointerButton {
                                    button: egui::PointerButton::Primary,
                                    pressed: false,
                                    ..
                                }
                            )
                        })
                        .count();
                });
                if Instant::now() >= self.deadline {
                    if !self.reported {
                        eprintln!(
                            "native section QA: root_updates={} held_updates={} root_primary_releases={}",
                            self.updates, self.held_updates, self.releases
                        );
                        self.reported = true;
                    }
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                eframe::App::update(&mut self.app, ctx, frame);
            }
        }
        let small = std::env::var_os("ANTINOMIE_ANALYSIS_QA_SMALL").is_some();
        let seconds = std::env::var("ANTINOMIE_ANALYSIS_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(15)
            .clamp(1, 120);
        eframe::run_native(
            "Antinomie Section Windows QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default().with_inner_size(if small {
                    [800.0, 600.0]
                } else {
                    [1280.0, 820.0]
                }),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                theme::install(&cc.egui_ctx);
                theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 18.0 });
                let mut app = app();
                app.settings.font_size = if small { 24.0 } else { 18.0 };
                app.snapshot
                    .analysis_reports
                    .push(section_report("qa-report-a", "REPORT A"));
                app.snapshot
                    .analysis_reports
                    .push(section_report("qa-report-b", "REPORT B"));
                app.selected_analysis = Some("qa-report-b".into());
                app.layout.focus(Panel::StaticAnalysis);
                app.open_analysis_section(
                    "qa-report-a".into(),
                    antinomie_monitor_core::AnalysisKind::Metadata,
                )
                .unwrap();
                app.open_analysis_section(
                    "qa-report-b".into(),
                    antinomie_monitor_core::AnalysisKind::Strings,
                )
                .unwrap();
                Ok(Box::new(QaApp {
                    app,
                    deadline: Instant::now() + Duration::from_secs(seconds),
                    updates: 0,
                    held_updates: 0,
                    releases: 0,
                    reported: false,
                }))
            }),
        )
        .unwrap();
    }

    /// A pcap of a DNS query (UDP 5353 → 53) and a TCP SYN (40000 → 80).
    fn test_pcap() -> Vec<u8> {
        fn frame(protocol: u8, transport: &[u8]) -> Vec<u8> {
            let mut frame = vec![
                0x52, 0x55, 10, 0, 2, 2, 0x52, 0x54, 0, 0x12, 0x34, 0x56, 8, 0,
            ];
            let total = (20 + transport.len()) as u16;
            frame.extend([0x45, 0]);
            frame.extend(total.to_be_bytes());
            frame.extend([0, 0, 0x40, 0, 64, protocol, 0, 0, 10, 0, 2, 15, 10, 0, 2, 3]);
            frame.extend(transport);
            frame
        }
        let mut dns = vec![0x14, 0xe9, 0, 53, 0, 37, 0, 0];
        dns.extend([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        dns.extend(b"\x07example\x03com\x00\x00\x01\x00\x01");
        let mut syn = vec![0x9c, 0x40, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02];
        syn.extend([0; 6]);
        let mut file = Vec::new();
        file.extend(0xa1b2c3d4u32.to_le_bytes());
        file.extend([2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        file.extend(65535u32.to_le_bytes());
        file.extend(1u32.to_le_bytes());
        for frame in [frame(17, &dns), frame(6, &syn)] {
            file.extend(1_800_000_000u32.to_le_bytes());
            file.extend(0u32.to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend(frame);
        }
        file
    }

    #[test]
    fn network_panel_lists_captures_toggles_capture_and_filters_by_clicked_values() {
        use antinomie_monitor_core::network::NetworkCapture;
        let root = std::env::temp_dir().join(format!("ant-ui-network-{}", std::process::id()));
        let dir = root.join("boots").join("b1").join("network");
        std::fs::create_dir_all(&dir).unwrap();
        let save = |capture: &NetworkCapture| {
            std::fs::write(&capture.file, test_pcap()).unwrap();
            let mut saved = capture.clone();
            saved.file = capture.file.file_name().unwrap().into();
            std::fs::write(
                capture.file.with_extension("json"),
                serde_json::to_vec(&saved).unwrap(),
            )
            .unwrap();
        };
        let earlier = NetworkCapture {
            stopped_ms: Some(1_800_000_006_000),
            packets: Some(2),
            bytes: Some(200),
            ..NetworkCapture::new(&root.join("boots/b1"), "b1", "earlier", 1_800_000_000_000)
        };
        save(&earlier);
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.vms[0].nat = true;
        app.snapshot
            .vm_locations
            .push(antinomie_monitor_core::VmLocations {
                vm_id: "vm".into(),
                disk_directory: root.clone(),
                recording_directory: root.clone(),
                recording_directories: vec![root.clone()],
            });
        app.focus_panel = Some(Panel::Network);
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1400.0, 900.0);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        for expected in [
            "Captures",
            "2027-01-15 08:00:00 UTC",
            "2027-01-15 08:00:00",
            "2 packets · 6 s · 200 B",
            "DNS",
            "TCP",
            "10.0.2.15",
            ":5353",
            "query A example.com",
        ] {
            assert!(
                shown.iter().any(|text| text == expected),
                "missing {expected:?} in {shown:?}"
            );
        }
        // The capture list's button starts a capture of the running NAT VM.
        let start = format!("{} Start capture", egui_phosphor::regular::RECORD);
        click_label(&mut app, &ctx, size, &start);
        assert!(matches!(
            app.submitted.last(),
            Some(Command::StartNetworkCapture)
        ));
        app.pending_network = None;
        // Clicking a value filters by it.
        click_label(&mut app, &ctx, size, "DNS");
        click_label(&mut app, &ctx, size, ":5353");
        let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert!(
            shown
                .iter()
                .any(|text| text == "Quick search port 5353: 1 of 2 loaded packets"),
            "{shown:?}"
        );
        assert!(!shown.iter().any(|text| text == "TCP"));
        click_label(&mut app, &ctx, size, "Clear filter");
        // The quick filters list values with their packet counts.
        click_label(&mut app, &ctx, size, "Addresses");
        click_label(&mut app, &ctx, size, "10.0.2.3 (2)");
        let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert!(
            shown
                .iter()
                .any(|text| text == "Quick search ip 10.0.2.3: 2 of 2 loaded packets"),
            "{shown:?}"
        );
        click_label(&mut app, &ctx, size, "Clear filter");
        // A running capture is listed first, opened, and stopped from the list.
        let live = NetworkCapture::new(&root.join("boots/b1"), "b1", "live", 1_800_000_100_000);
        save(&live);
        app.snapshot.network_capture = Some(live.clone());
        let stop = format!("{} Stop capture", egui_phosphor::regular::STOP);
        click_label(&mut app, &ctx, size, &stop);
        assert!(matches!(
            app.submitted.last(),
            Some(Command::StopNetworkCapture)
        ));
        let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
            .into_iter()
            .map(|(text, _)| text)
            .collect();
        assert!(
            shown.iter().any(|text| text
                .starts_with(&format!("{} Live capture", egui_phosphor::regular::RECORD))),
            "{shown:?}"
        );
        assert!(shown
            .iter()
            .any(|text| text == "Live capture of 2027-01-15 08:01:40 UTC"));
        // Without NAT the toggle stays off.
        app.pending_network = None;
        app.snapshot.network_capture = None;
        app.snapshot.vms[0].nat = false;
        assert!(!app.network_toggle_enabled());
        app.snapshot.vms[0].nat = true;
        assert!(app.network_toggle_enabled());
        app.toggle_network_capture();
        assert!(matches!(
            app.submitted.last(),
            Some(Command::StartNetworkCapture)
        ));
        // A stopped VM's capture panel must never start a capture of a
        // different VM that happens to be running.
        app.pending_network = None;
        app.selected = Some("other-vm".into());
        app.snapshot.vms.push(VmConfig {
            id: "other-vm".into(),
            nat: true,
            ..VmConfig::default()
        });
        app.snapshot
            .vm_locations
            .push(antinomie_monitor_core::VmLocations {
                vm_id: "other-vm".into(),
                disk_directory: root.clone(),
                recording_directory: root.clone(),
                recording_directories: vec![root.clone()],
            });
        app.submitted.clear();
        click_label(&mut app, &ctx, size, &start);
        assert!(app.submitted.is_empty());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn details_follow_the_network_tab_with_the_selected_packet_layers_and_bytes() {
        use antinomie_monitor_core::network::NetworkCapture;
        let root = std::env::temp_dir().join(format!("ant-ui-packet-{}", std::process::id()));
        let capture = NetworkCapture {
            stopped_ms: Some(1_800_000_006_000),
            packets: Some(2),
            bytes: Some(200),
            ..NetworkCapture::new(&root.join("boots/b1"), "b1", "one", 1_800_000_000_000)
        };
        std::fs::create_dir_all(capture.file.parent().unwrap()).unwrap();
        std::fs::write(&capture.file, test_pcap()).unwrap();
        let mut saved = capture.clone();
        saved.file = capture.file.file_name().unwrap().into();
        std::fs::write(capture.summary_path(), serde_json::to_vec(&saved).unwrap()).unwrap();
        let mut app = app();
        observer_fixture(&mut app);
        app.snapshot.vms[0].nat = true;
        app.snapshot
            .vm_locations
            .push(antinomie_monitor_core::VmLocations {
                vm_id: "vm".into(),
                disk_directory: root.clone(),
                recording_directory: root.clone(),
                recording_directories: vec![root.clone()],
            });
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let size = egui::vec2(1700.0, 1000.0);
        let shown = |app: &mut MonitorApp| -> Vec<String> {
            texts(&render(app, &ctx, size))
                .into_iter()
                .map(|(text, _)| text)
                .collect()
        };
        // The trace is the open tab: Details show the (empty) syscall.
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        assert!(shown(&mut app)
            .iter()
            .any(|text| text == "Select a syscall in the trace to decode it here"));
        // On the Network tab, Details follow it; selecting a packet shows its
        // layers and bytes.
        app.focus_panel = Some(Panel::Network);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let texts_now = shown(&mut app);
        assert!(
            texts_now
                .iter()
                .any(|text| text.starts_with("No packet selected")),
            "{texts_now:?}"
        );
        assert!(!texts_now
            .iter()
            .any(|text| text == "Select a syscall in the trace to decode it here"));
        click_label(&mut app, &ctx, size, "query A example.com");
        let texts_now = shown(&mut app);
        for expected in [
            "Ethernet II  Src 52:54:00:12:34:56, Dst 52:55:0a:00:02:02",
            "Internet Protocol Version 4  Src 10.0.2.15, Dst 10.0.2.3",
            "Source: 52:54:00:12:34:56",
        ] {
            assert!(
                texts_now.iter().any(|text| text == expected),
                "missing {expected:?} in {texts_now:?}"
            );
        }
        assert!(
            texts_now
                .iter()
                .any(|text| text.starts_with("0000  52 55 0a 00 02 02 52 54  00 12 34 56 08 00")),
            "{texts_now:?}"
        );
        // Choosing a field marks its bytes.
        click_label(&mut app, &ctx, size, "Source: 52:54:00:12:34:56");
        assert!(shown(&mut app)
            .iter()
            .any(|text| text == "Source: 6 bytes at 0x0006"));
        // Back on the trace tab, Details show the syscall again.
        app.focus_panel = Some(Panel::Trace);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let texts_now = shown(&mut app);
        assert!(texts_now
            .iter()
            .any(|text| text == "Select a syscall in the trace to decode it here"));
        assert!(!texts_now.iter().any(|text| text.starts_with("Ethernet II")));
        std::fs::remove_dir_all(root).unwrap();
    }
}

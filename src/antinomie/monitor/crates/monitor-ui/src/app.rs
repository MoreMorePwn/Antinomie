use crate::{
    archive::{Answer, ArchiveWorker, Request},
    build_wizard,
    folders::{FolderPicker, Kind as FolderKind, Target as FolderTarget},
    runs::RunTerminal,
    theme,
    trace::{self, Inspector, InvocationKey},
    workspace::{Panel, WorkspaceLayout},
};
use antinomie_monitor_core::{
    capture_processes::CaptureProcess, pair_events, syscall_groups::SyscallGroup, Backend,
    BackendOptions, BaseSummary, CaptureState, CaptureSummary, Command, DisplayResolution,
    ExecRequest, GuestCredentials, InvocationSummary, Notification, RevisionStatus, RunState,
    RunSummary, Snapshot, TerminalRecord, TransportSettings, VmAcceleration, VmConfig, VmCpuModel,
    VmLaunchOptions, VmState, WaitStatus, APP_REVISION, APP_VERSION,
};
#[path = "captures.rs"]
mod captures;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    path::PathBuf,
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
        }
    }
}

enum Confirm {
    Reset(String),
    Delete(String),
    DeleteBase(String),
    Upload {
        source: PathBuf,
        destination: String,
        executable: bool,
        vm_id: Option<String>,
    },
    Nat {
        vm: VmConfig,
        creating: bool,
    },
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
}

impl AnalysisView {
    fn bind(&mut self, report_id: Option<&str>) {
        if self.report_id.as_deref() != report_id {
            self.report_id = report_id.map(str::to_owned);
            self.state = crate::analysis::WorkspaceState::default();
            self.preview = None;
            self.pending = None;
            self.listing = None;
            self.listing_pending = None;
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
    /// Download base: also list bases for earlier Antinomie versions.
    show_older_bases: bool,
    build_wizard: build_wizard::BuildWizard,
    confirm: Option<Confirm>,
    name_action: Option<(String, bool, String)>,
    status: String,
    filter: String,
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
    /// Process tree of a selected capture that is not live (processes.json).
    archived_processes: Option<(String, Result<Vec<CaptureProcess>, String>)>,
    capture_history: Vec<CaptureSummary>,
    capture_tab: bool,
    process_picker: captures::ProcessPicker,
    pending_observer: Option<u64>,
    selected_analysis: Option<String>,
    analysis_windows: BTreeMap<String, antinomie_monitor_core::AnalysisReport>,
    analysis_directories: BTreeMap<String, PathBuf>,
    pending_analysis_sections: Vec<(String, antinomie_monitor_core::AnalysisKind)>,
    analysis_views: BTreeMap<String, AnalysisView>,
    analysis_generation: u64,
    archive_selected: bool,
    history_generation: u64,
    run_filter: RunFilter,
    terminals: BTreeMap<String, RunTerminal>,
    archive: Option<ArchiveWorker>,
    pending_archive: Option<Request>,
    history: Vec<RunSummary>,
    archive_generation: u64,
    archive_page: Vec<InvocationSummary>,
    archive_offset: u64,
    archive_next: Option<u64>,
    archive_previous: Vec<u64>,
    archive_pending: bool,
    archive_error: Option<String>,
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
            show_older_bases: false,
            build_wizard: build_wizard::BuildWizard::default(),
            confirm: None,
            name_action: None,
            status,
            filter: String::new(),
            trace_sort: None,
            selected_event: None,
            selected_run: None,
            selected_capture: None,
            selected_process: None,
            transport_open: false,
            network_view: Default::default(),
            archived_processes: None,
            capture_history: Vec::new(),
            capture_tab: false,
            process_picker: captures::ProcessPicker::default(),
            pending_observer: None,
            selected_analysis: None,
            analysis_windows: BTreeMap::new(),
            analysis_directories: BTreeMap::new(),
            pending_analysis_sections: Vec::new(),
            analysis_views: BTreeMap::new(),
            analysis_generation: 0,
            archive_selected: false,
            history_generation: 0,
            run_filter: RunFilter::All,
            terminals: BTreeMap::new(),
            archive: None,
            pending_archive: None,
            history: Vec::new(),
            archive_generation: 0,
            archive_page: Vec::new(),
            archive_offset: 0,
            archive_next: None,
            archive_previous: Vec::new(),
            archive_pending: false,
            archive_error: None,
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
        let launch = matches!(&command, Command::Execute(_));
        let observer = matches!(
            &command,
            Command::AttachProcess { .. } | Command::CaptureAll | Command::StopCapture { .. }
        );
        let process_list = matches!(&command, Command::ListProcesses { .. });
        let admission = if launch {
            self.launch_admission()
        } else {
            Ok(())
        };
        if let Err(error) = admission {
            self.status = error.clone();
            self.log("ERROR", error);
            return;
        }
        #[cfg(test)]
        if self.submitted.len() < 1024 {
            self.submitted.push(command.clone());
        }
        let mut failure = None;
        if let Some(backend) = &self.backend {
            match backend.send(command) {
                Ok(id) => {
                    if observer {
                        self.pending_observer = Some(id);
                    }
                    if process_list {
                        self.process_picker.pending = Some(id);
                    }
                    if launch {
                        self.pending_launch = Some(id);
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
            self.log("ERROR", error);
        }
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
                        if self.pending_observer == Some(id) {
                            self.pending_observer = None;
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
            return self.credentials.credentials().err();
        }
        None
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
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
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
                Request::Invocations { generation, .. }
                    if generation == self.archive_generation =>
                {
                    self.archive_pending = false;
                    self.archive_error = Some("Read superseded".into());
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
        self.pending_archive = None;
        self.reset_trace_selection();
        if self.offline_run().is_some() {
            self.request_page(0);
        }
    }

    fn reset_trace_selection(&mut self) {
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
        self.archive_previous.clear();
        self.archive_next = None;
        self.archive_offset = 0;
        self.archive_pending = false;
        self.archive_error = None;
    }

    fn request_page(&mut self, offset: u64) {
        let Some(directory) = self.trace_archive_directory() else {
            return;
        };
        self.archive_generation = self.archive_generation.wrapping_add(1);
        self.archive_pending = false;
        self.archive_error = None;
        self.selected_event = None;
        self.inspector.clear();
        let request = Request::Invocations {
            generation: self.archive_generation,
            directory,
            offset,
            capture: self.selected_capture.is_some(),
            pid: self
                .selected_process
                .filter(|_| self.selected_capture.is_some()),
        };
        self.queue_archive(request);
        self.archive_pending = true;
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
            ui.colored_label(theme::MUTED, "No VM selected");
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
        let height = (ui.available_height() * 0.58 - 30.0).max(50.0);
        let mut inspect = None;
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), height + 28.0),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                TableBuilder::new(ui)
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
                    .min_scrolled_height(0.0)
                    .header(28.0, |mut header| {
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
                                    egui::Label::new(&run.request.path)
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
                            if response.clicked() || response.double_clicked() {
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
        ui.separator();
        if let Some(run) = self
            .selected_run
            .as_deref()
            .and_then(|id| runs.iter().find(|run| run.id == id))
        {
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
                                ("Tree", execution_detail(run)),
                                ("Root exit", root_exit(run)),
                                ("Recording", run.directory.display().to_string()),
                            ] {
                                ui.label(label);
                                ui.add(egui::Label::new(value).selectable(true));
                                ui.end_row();
                            }
                        });
                });
        } else if runs.is_empty() {
            ui.colored_label(theme::MUTED, "No retained runs for this VM");
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
        self.focus_trace();
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
        let Some(id) = self.selected_capture.clone() else {
            return;
        };
        let processes = match self.snapshot.capture_processes.get(&id) {
            Some(live) => Ok(live.as_slice()),
            None => match &self.archived_processes {
                Some((loaded, result)) if *loaded == id => {
                    result.as_ref().map(Vec::as_slice).map_err(String::as_str)
                }
                _ => Ok(&[][..]),
            },
        };
        ui.separator();
        match processes {
            Err(error) => {
                ui.colored_label(theme::WARN, format!("Process tree unavailable: {error}"));
            }
            Ok([]) => {
                ui.colored_label(
                    theme::MUTED,
                    "No process tree (captures before Antinomie 0.3.0 keep one combined trace)",
                );
            }
            Ok(processes) => {
                let selection = captures::process_tree(
                    ui,
                    processes,
                    self.selected_process,
                    self.settings.font_size,
                );
                if let Some(selection) = selection {
                    self.select_process(selection);
                    self.focus_trace();
                }
            }
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
                result,
            } if generation == self.archive_generation
                && self.trace_archive_directory().is_some() =>
            {
                self.archive_pending = false;
                match result {
                    Ok(page) => {
                        self.archive_page = page.invocations;
                        self.archive_offset = offset;
                        self.archive_next = page.next_offset;
                        self.archive_error =
                            (!page.issues.is_empty()).then(|| page.issues.join("; "));
                    }
                    Err(error) => self.archive_error = Some(error),
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
            if !terminal.open || terminal.replay_pending {
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

    fn menus(&mut self, ctx: &egui::Context) {
        let stopped = self.snapshot.active_vm.is_none();
        let selected = self.selected.is_some() && stopped;
        egui::TopBottomPanel::top("menus")
            .exact_height(self.settings.font_size + 16.0)
            .frame(theme::frame(theme::PANEL))
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui
                            .add_enabled(stopped, egui::Button::new("New VM"))
                            .clicked()
                        {
                            self.new_image();
                            ui.close_menu();
                        }
                        ui.menu_button("Add base", |ui| {
                            if ui
                                .add_enabled(stopped, egui::Button::new("Import base…"))
                                .clicked()
                            {
                                self.import_open = true;
                                ui.close_menu();
                            }
                            if ui.button("Download base…").clicked() {
                                self.download_open = true;
                                if !self.snapshot.remote_refreshing {
                                    self.send(Command::RefreshRemoteBases);
                                }
                                ui.close_menu();
                            }
                            if ui.button("Build base…").clicked() {
                                self.build_open = true;
                                ui.close_menu();
                            }
                        });
                        ui.separator();
                        if ui.button("Exit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("VM", |ui| {
                        if ui
                            .add_enabled(
                                self.selected.is_some() && self.snapshot.active_vm != self.selected,
                                egui::Button::new("Configuration"),
                            )
                            .clicked()
                        {
                            self.configure_vm();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(selected, egui::Button::new("Reset disk to base"))
                            .clicked()
                        {
                            self.confirm = self.selected.clone().map(Confirm::Reset);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(selected, egui::Button::new("Delete VM and disk"))
                            .clicked()
                        {
                            self.confirm = self.selected.clone().map(Confirm::Delete);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Run", |ui| {
                        if ui
                            .add_enabled(selected, egui::Button::new("Start VM"))
                            .clicked()
                        {
                            self.new_run();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(!stopped, egui::Button::new("Stop"))
                            .clicked()
                        {
                            self.send(Command::Stop);
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(self.running(), egui::Button::new("Launch program"))
                            .clicked()
                        {
                            self.launch_open = true;
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.observer_start_enabled(),
                                egui::Button::new("Attach to process"),
                            )
                            .clicked()
                        {
                            self.open_process_picker();
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.observer_start_enabled(),
                                egui::Button::new("Capture All"),
                            )
                            .clicked()
                        {
                            self.send(Command::CaptureAll);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(
                                self.observer_supported()
                                    && self.pending_observer.is_none()
                                    && self.active_observer().is_some(),
                                egui::Button::new("Stop Capture"),
                            )
                            .clicked()
                        {
                            self.stop_observer();
                            ui.close_menu();
                        }
                        if self.running() && !self.observer_supported() {
                            ui.colored_label(
                                theme::MUTED,
                                "Capture unavailable: needs a base for Antinomie 0.2.0 or newer",
                            );
                        }
                        if ui
                            .add_enabled(self.running(), egui::Button::new("Upload file"))
                            .clicked()
                        {
                            self.upload_open = true;
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("View", |ui| {
                        for view in [
                            Panel::Trace,
                            Panel::Network,
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
                        if ui.button("Settings").clicked() {
                            self.settings_open = true;
                            ui.close_menu();
                        }
                        if ui.button("Analysis tools…").clicked() {
                            self.tools_open = true;
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui
                            .add_enabled(
                                self.running(),
                                egui::Button::new("Refresh recorder statistics"),
                            )
                            .clicked()
                        {
                            self.send(Command::RecorderStats);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Help", |ui| {
                        if ui.button("About Antinomie").clicked() {
                            self.about_open = true;
                            ui.close_menu();
                        }
                    });
                    if self.snapshot.bases.is_empty() && !self.snapshot.bases_checking {
                        ui.separator();
                        if ui
                            .add(egui::Button::new(
                                RichText::new("No base image — Add base").color(theme::WARN),
                            ))
                            .clicked()
                        {
                            self.download_open = true;
                            if !self.snapshot.remote_refreshing {
                                self.send(Command::RefreshRemoteBases);
                            }
                        }
                    }
                });
            });
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar")
            .exact_height(self.settings.font_size + 22.0)
            .frame(theme::frame(theme::PANEL))
            .show(ctx, |ui| {
                egui::ScrollArea::horizontal()
                    .id_salt("toolbar_controls")
                    .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
                    .show(ui, |ui| {
                        ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                            let stopped = self.snapshot.active_vm.is_none();
                            if icon(ui, egui_phosphor::regular::PLUS, "New VM", stopped) {
                                self.new_image();
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::SLIDERS_HORIZONTAL,
                                "VM configuration",
                                self.selected.is_some() && self.snapshot.active_vm != self.selected,
                            ) {
                                self.configure_vm();
                            }
                            ui.separator();
                            if icon(
                                ui,
                                egui_phosphor::regular::PLAY,
                                "Start selected VM",
                                self.selected.is_some() && stopped,
                            ) {
                                self.new_run();
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::STOP,
                                "Shut down the current VM",
                                !stopped,
                            ) {
                                self.send(Command::Stop);
                            }
                            ui.separator();
                            if icon(
                                ui,
                                egui_phosphor::regular::TERMINAL_WINDOW,
                                "Launch program",
                                self.running(),
                            ) {
                                self.launch_open = true;
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::UPLOAD_SIMPLE,
                                "Upload file",
                                self.running(),
                            ) {
                                self.upload_open = true;
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::PLUG,
                                "Attach to process",
                                self.observer_start_enabled(),
                            ) {
                                self.open_process_picker();
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::RECORD,
                                "Capture All",
                                self.observer_start_enabled(),
                            ) {
                                self.send(Command::CaptureAll);
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::PAUSE,
                                "Stop Capture (leave programs running)",
                                self.observer_supported()
                                    && self.pending_observer.is_none()
                                    && self.active_observer().is_some(),
                            ) {
                                self.stop_observer();
                            }
                            ui.separator();
                            if icon(
                                ui,
                                egui_phosphor::regular::GEAR,
                                "Recording and base settings",
                                true,
                            ) {
                                self.settings_open = true;
                            }
                            if ui.available_width() > 160.0 {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        let name = self
                                            .snapshot
                                            .vms
                                            .iter()
                                            .find(|vm| {
                                                Some(&vm.id) == self.snapshot.active_vm.as_ref()
                                            })
                                            .map(|vm| vm.name.as_str())
                                            .unwrap_or(if self.snapshot.capture_dir.is_some() {
                                                "Last recording"
                                            } else {
                                                "No active VM"
                                            });
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(name).color(theme::MUTED),
                                            )
                                            .truncate(),
                                        )
                                        .on_hover_text(name);
                                        ui.colored_label(
                                            if self.snapshot.state == VmState::Running {
                                                theme::GOOD
                                            } else {
                                                theme::MUTED
                                            },
                                            egui_phosphor::regular::CIRCLE,
                                        );
                                    },
                                );
                            }
                        });
                    });
            });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let mut selected_vm = None;
        let mut action = None;
        let mut base_action: Option<(String, String)> = None;
        let mut clicked_base: Option<String> = None;
        let mut open_downloads = false;
        egui::SidePanel::left("vms")
            .default_width(210.0)
            .min_width(190.0)
            .max_width(300.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(theme::PANEL)
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| {
                if section_header(
                    ui,
                    "Virtual machines",
                    "Virtual machines",
                    "New VM",
                    self.snapshot.active_vm.is_none(),
                    false,
                )
                .clicked()
                {
                    self.new_image();
                }
                let list_budget = ui.available_height();
                egui::ScrollArea::vertical()
                    .id_salt("vm_list")
                    .max_height((list_budget * 0.55).max(80.0))
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.snapshot.vms.is_empty() {
                            ui.label(RichText::new("No saved VMs").color(theme::MUTED));
                        }
                        for vm in &self.snapshot.vms {
                            let active = self.snapshot.active_vm.as_ref() == Some(&vm.id);
                            let label = format!(
                                "{}  {}",
                                if active {
                                    egui_phosphor::regular::PLAY
                                } else {
                                    egui_phosphor::regular::HARD_DRIVE
                                },
                                vm.name
                            );
                            let response = ui
                                .add_sized(
                                    [ui.available_width(), self.settings.font_size + 14.0],
                                    egui::Button::new(RichText::new(label))
                                        .frame(false)
                                        .selected(self.selected.as_ref() == Some(&vm.id))
                                        .truncate(),
                                )
                                .on_hover_text(format!(
                                    "{}\n{} CPU / {} MiB / {} GiB\nNetwork: {}",
                                    vm.name,
                                    vm.cpus,
                                    vm.ram_mib,
                                    vm.disk_gib,
                                    if vm.nat { "NAT" } else { "disconnected" }
                                ));
                            if response.clicked() {
                                selected_vm = Some(vm.id.clone());
                            }
                            response.context_menu(|ui| {
                                let stopped = self.snapshot.active_vm.as_ref() != Some(&vm.id)
                                    && !self.closing;
                                for (label, enabled) in [
                                    ("Rename", !self.closing),
                                    ("Open Directory", true),
                                    ("Delete", stopped),
                                    ("Duplicate", stopped),
                                    ("Settings", stopped),
                                ] {
                                    if ui.add_enabled(enabled, egui::Button::new(label)).clicked() {
                                        action = Some((vm.clone(), label));
                                        ui.close_menu();
                                    }
                                }
                            });
                        }
                    });
                ui.separator();
                let add_base = egui::Id::new("add_base_menu");
                let open = ui.memory(|memory| memory.is_popup_open(add_base));
                let header = section_header(
                    ui,
                    "Base images",
                    "Installed base images",
                    "Add base",
                    true,
                    open,
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
                            self.download_open = true;
                            if !self.snapshot.remote_refreshing {
                                self.send(Command::RefreshRemoteBases);
                            }
                        }
                        if ui.button("Build base…").clicked() {
                            self.build_open = true;
                        }
                    },
                );
                egui::ScrollArea::vertical()
                    .id_salt("base_list")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        if self.snapshot.bases_checking {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(
                                    RichText::new("Checking base images…").color(theme::MUTED),
                                )
                                .on_hover_text(
                                    "The first start after an update or import checks each base once",
                                );
                            });
                        } else if self.snapshot.bases.is_empty() {
                            ui.label(RichText::new("No base images").color(theme::MUTED));
                            if ui.button("Add base…").clicked() {
                                self.download_open = true;
                                if !self.snapshot.remote_refreshing {
                                    self.send(Command::RefreshRemoteBases);
                                }
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
                            let outdated = base_status != RevisionStatus::Current;
                            let name = versioned_label(
                                &base.label,
                                base.revision,
                                base.min_app_version.as_deref(),
                            );
                            let label = if outdated {
                                format!(
                                    "{}  {name}  {}",
                                    egui_phosphor::regular::HARD_DRIVE,
                                    egui_phosphor::regular::WARNING
                                )
                            } else {
                                format!("{}  {name}", egui_phosphor::regular::HARD_DRIVE)
                            };
                            // min_size keeps the text on the sidebar's left alignment;
                            // add_sized would centre it.
                            let response = ui
                                .add(
                                    egui::Button::new(RichText::new(label))
                                        .frame(false)
                                        .selected(
                                            self.selected_base.as_deref() == Some(base.id.as_str()),
                                        )
                                        .min_size(egui::vec2(
                                            ui.available_width(),
                                            self.settings.font_size + 14.0,
                                        ))
                                        .truncate(),
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
                            if outdated {
                                let hint = match base_status {
                                    RevisionStatus::NeedsNewerApp => "Needs a newer Antinomie",
                                    _ if newer_base(&self.snapshot, base).is_some() => {
                                        "Outdated · newer base available"
                                    }
                                    _ => "Outdated · built for an earlier Antinomie",
                                };
                                ui.horizontal(|ui| {
                                    ui.add_space(24.0);
                                    if ui
                                        .add(
                                            egui::Label::new(
                                                RichText::new(hint).small().color(theme::WARN),
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
                                if ui.button("New VM from this base").clicked() {
                                    base_action = Some((base.id.clone(), "New VM".to_string()));
                                    ui.close_menu();
                                }
                                if ui.button("Open Directory").clicked() {
                                    base_action =
                                        Some((base.id.clone(), "Open Directory".to_string()));
                                    ui.close_menu();
                                }
                                if ui
                                    .add_enabled(
                                        self.snapshot.active_vm.is_none(),
                                        egui::Button::new("Delete base"),
                                    )
                                    .clicked()
                                {
                                    base_action = Some((base.id.clone(), "Delete".to_string()));
                                    ui.close_menu();
                                }
                            });
                        }
                    });
            });
        if open_downloads {
            self.download_open = true;
            if !self.snapshot.remote_refreshing {
                self.send(Command::RefreshRemoteBases);
            }
        }
        if let Some(identity) = clicked_base {
            self.selected_base = Some(identity);
        }
        if let Some((identity, action)) = base_action {
            match action.as_str() {
                "New VM" => self.new_image_from(identity),
                "Open Directory" => {
                    if let Some(base) = self.snapshot.bases.iter().find(|base| base.id == identity)
                    {
                        match std::process::Command::new("xdg-open")
                            .arg(&base.directory)
                            .spawn()
                        {
                            Ok(mut child) => {
                                std::thread::spawn(move || {
                                    let _ = child.wait();
                                });
                            }
                            Err(error) => self.status = format!("Open Directory: {error}"),
                        }
                    }
                }
                "Delete" => self.confirm = Some(Confirm::DeleteBase(identity)),
                _ => {}
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
                "Rename" => self.name_action = Some((vm.id, false, vm.name)),
                "Duplicate" => self.name_action = Some((vm.id, true, format!("{} copy", vm.name))),
                "Delete" => self.confirm = Some(Confirm::Delete(vm.id)),
                "Settings" => {
                    self.draft_generation = self.draft_generation.wrapping_add(1);
                    self.draft = vm;
                    self.config_open = true;
                }
                "Open Directory" => {
                    if let Some(location) = self
                        .snapshot
                        .vm_locations
                        .iter()
                        .find(|location| location.vm_id == vm.id)
                    {
                        match std::process::Command::new("xdg-open")
                            .arg(&location.disk_directory)
                            .spawn()
                        {
                            Ok(mut child) => {
                                std::thread::spawn(move || {
                                    let _ = child.wait();
                                });
                            }
                            Err(error) => self.status = format!("Open Directory: {error}"),
                        }
                    } else {
                        self.status = "VM directory unavailable".into();
                    }
                }
                _ => {}
            }
        }
    }

    fn health(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("health")
            .frame(theme::frame(theme::RAISED))
            .show(ctx, |ui| {
                let health = &self.snapshot.health;
                ui.add_space(3.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("{:?}", self.snapshot.state));
                    if let Some(kernel) = &self.snapshot.guest_kernel {
                        let status = RevisionStatus::of(kernel.revision);
                        ui.colored_label(
                            if status == RevisionStatus::Current { theme::GOOD } else { theme::WARN },
                            format!("Kernel: {}", RevisionStatus::describe(kernel.revision, None)),
                        )
                        .on_hover_text(format!(
                            "Release: {}\nKernel: {}\nThis app: Antinomie {APP_VERSION}",
                            kernel.release.as_deref().unwrap_or("unknown"),
                            RevisionStatus::describe(kernel.revision, None),
                        ));
                    }
                    ui.separator();
                    ui.colored_label(if health.dropped == 0 { theme::GOOD } else { theme::WARN },
                        format!("Transport loss: {}", health.dropped))
                        .on_hover_text(format!(
                            "Records the guest could not hand over: {} of {}\nGuest buffer per vCPU: {}\nWhen buffers fill: {}",
                            health.dropped,
                            health.attempted,
                            if health.ring_size == 0 { "unknown".to_owned() } else { ring_label(health.ring_size / 1024) },
                            if health.send_wait_us == 0 { "drop".to_owned() } else { format!("wait up to {} ms", health.send_wait_us / 1000) },
                        ));
                    if health.transport_waits > 0 {
                        // Never-drop mode: how much the guest was slowed down.
                        ui.label(format!("Guest waited: {:.1} s", health.transport_wait_ns as f64 / 1e9))
                            .on_hover_text(format!(
                                "{} system calls waited for the host to make room",
                                health.transport_waits
                            ));
                    }
                    if health.write_backlog > 64 * 1024 * 1024 {
                        ui.colored_label(theme::WARN, format!("Disk backlog: {} MB", health.write_backlog / 1_000_000))
                            .on_hover_text("Recording data waiting for the disk; when the queue is full the transport waits");
                    }
                    ui.colored_label(if health.ui_dropped == 0 { theme::GOOD } else { theme::WARN },
                        format!("UI loss: {}", health.ui_dropped));
                    ui.colored_label(if health.storage_dropped_packets == 0 && health.persistence_error.is_none() { theme::GOOD } else { theme::WARN },
                        format!("Storage loss: {}", health.storage_dropped_packets));
                    let recording = format!("Saved {:.1} / {} GiB",
                        health.persisted_len as f64 / 1073741824.0, self.settings.quota_gib);
                    ui.add(egui::Label::new(recording).truncate()).on_hover_text(format!(
                        "Packets saved / received: {} / {}\nParser errors: {}\nReply stalls: {}\nTransport health: {:#x}\nRecording: {}",
                        health.persisted_packets, health.received_packets, health.parser_errors,
                        health.reply_stalls, health.transport_health,
                        self.snapshot.capture_dir.as_ref().map(|path| path.display().to_string()).unwrap_or_else(|| "none".into())));
                    if health.parser_errors > 0 {
                        ui.colored_label(theme::WARN, format!("Parser errors: {}", health.parser_errors));
                    }
                });
                if let Some(error) = &health.persistence_error {
                    ui.add(egui::Label::new(RichText::new(format!("Saving stopped: {error}")).color(theme::ERROR)).truncate())
                        .on_hover_text(error);
                }
                if let Some(error) = &self.snapshot.last_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).truncate())
                        .on_hover_text(error);
                }
                if self.closing {
                    ui.label("Waiting for guest shutdown and recording finalization...");
                } else if !self.status.is_empty() {
                    ui.add(egui::Label::new(&self.status).truncate()).on_hover_text(&self.status);
                }
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
            ui.label(RichText::new("No activity").color(theme::MUTED));
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
                        ui.label(RichText::new(text).color(theme::MUTED));
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
                                theme::ERROR
                            } else {
                                theme::MUTED
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
                        graphical,
                    ) {
                        self.tools_open = true;
                    }
                });
            ui.separator();
            if let Some(reason) = selection_error {
                ui.colored_label(theme::ERROR, reason);
            }
            ui.horizontal(|ui| {
                let run = ui.add_enabled(
                    !self.exec.path.trim().is_empty() && self.exec.analysis.validate().is_ok(),
                    egui::Button::new(format!("{} Run", egui_phosphor::regular::PLAY))
                        .fill(theme::PRIMARY),
                );
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
                #[cfg(test)]
                {
                    self.launch_action_rects = Some((run.rect, analyze.rect));
                }
            });
        });
    }

    fn upload_form(&mut self, ui: &mut egui::Ui) {
        ui.add_enabled_ui(self.running(), |ui| {
            egui::Grid::new("upload").num_columns(2).show(ui, |ui| {
                ui.label("Host file");
                ui.add(egui::TextEdit::singleline(&mut self.source).desired_width(290.0));
                ui.end_row();
                ui.label("Guest path");
                ui.add(egui::TextEdit::singleline(&mut self.destination).desired_width(290.0));
                ui.end_row();
            });
            ui.checkbox(&mut self.executable, "Executable");
            ui.checkbox(&mut self.overwrite, "Overwrite existing file");
            ui.separator();
            if ui
                .add_enabled(
                    !self.source.trim().is_empty() && !self.destination.trim().is_empty(),
                    egui::Button::new(format!("{} Upload", egui_phosphor::regular::UPLOAD_SIMPLE)),
                )
                .clicked()
            {
                if self.overwrite {
                    self.confirm = Some(Confirm::Upload {
                        source: crate::folders::user_path(&self.source),
                        destination: self.destination.clone(),
                        executable: self.executable,
                        vm_id: self.snapshot.active_vm.clone(),
                    });
                } else {
                    self.upload();
                }
            }
        });
    }

    fn upload(&mut self) {
        self.send(Command::Upload {
            source: crate::folders::user_path(&self.source),
            destination: self.destination.clone(),
            overwrite: self.overwrite,
            executable: self.executable,
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

    fn events(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.strong("Syscalls");
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
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter")
                    .desired_width(130.0),
            );
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
                    if let Some(offset) = self.archive_next {
                        self.archive_previous.push(self.archive_offset);
                        self.request_page(offset);
                    }
                }
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_CLOCKWISE,
                    "Reload archive page",
                    !self.archive_pending,
                ) {
                    self.request_page(self.archive_offset);
                }
                ui.label(if self.archive_pending {
                    "Reading archive..."
                } else {
                    "History"
                });
            }
        });
        if let Some(error) = &self.archive_error {
            ui.add(egui::Label::new(RichText::new(error).color(theme::WARN)).truncate())
                .on_hover_text(error);
        }
        let filter = self.filter.to_lowercase();
        let all = self.invocations();
        self.trace_categories(ui, &all);
        let hidden = self.settings.hidden_trace_categories.clone();
        let invocations: Vec<_> = all
            .into_iter()
            .filter(|invocation| {
                let Some(event) = trace::representative(invocation) else {
                    return false;
                };
                if SyscallGroup::of(&event.syscall_name)
                    .is_some_and(|group| hidden.contains(&group))
                {
                    return false;
                }
                filter.is_empty()
                    || format!(
                        "{} {} {} {}",
                        event.syscall_name,
                        event.tid,
                        event.task_cookie,
                        trace::info(invocation)
                    )
                    .to_lowercase()
                    .contains(&filter)
            })
            .collect();
        let mut invocations = invocations;
        if let Some((column, descending)) = self.trace_sort {
            sort_invocations(&mut invocations, column, descending);
        }
        let height = self.settings.font_size + 14.0;
        let table_height = (ui.available_height() - height).max(0.0);
        let compact = ui.available_width() < 900.0;
        let widths = if compact {
            [64.0, 72.0, 44.0, 38.0, 128.0, 68.0]
        } else {
            [100.0, 100.0, 64.0, 56.0, 190.0, 108.0]
        };
        egui::ScrollArea::horizontal()
            .id_salt("syscalls_horizontal")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_min_width(
                    (self.settings.font_size / 16.0 * 760.0).max(ui.available_width()),
                );
                TableBuilder::new(ui)
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
                    .header(height, |mut header| {
                        for column in TraceColumn::ALL {
                            header.col(|ui| {
                                let sorted =
                                    self.trace_sort.filter(|(sorted, _)| *sorted == column);
                                let label = match sorted {
                                    Some((_, false)) => format!(
                                        "{} {}",
                                        column.title(),
                                        egui_phosphor::regular::CARET_UP
                                    ),
                                    Some((_, true)) => format!(
                                        "{} {}",
                                        column.title(),
                                        egui_phosphor::regular::CARET_DOWN
                                    ),
                                    None => column.title().to_string(),
                                };
                                let response = ui
                                    .add(
                                        egui::Label::new(RichText::new(label).strong())
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::click()),
                                    )
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .on_hover_text(format!("Sort by {}", column.title()));
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
                            let invocation = &invocations[row.index()];
                            let event =
                                trace::representative(invocation).expect("filtered observation");
                            let key = trace::key(invocation);
                            row.set_selected(self.selected_event == Some(key));
                            let cpu = match (&invocation.entry, &invocation.exit) {
                                (Some(entry), Some(exit)) if entry.cpu != exit.cpu => {
                                    format!("{}>{}", entry.cpu, exit.cpu)
                                }
                                _ => event.cpu.to_string(),
                            };
                            let sequence = match (&invocation.entry, &invocation.exit) {
                                (Some(entry), Some(exit)) => {
                                    format!("{}/{}", entry.event_seq, exit.event_seq)
                                }
                                _ => event.event_seq.to_string(),
                            };
                            let group = SyscallGroup::of(&event.syscall_name);
                            let tint = group
                                .filter(|_| self.settings.trace_colors)
                                .and_then(theme::syscall_tint)
                                .filter(|_| self.selected_event != Some(key));
                            let failed = invocation
                                .exit
                                .as_ref()
                                .and_then(|event| event.result)
                                .is_some_and(|result| result < 0);
                            for (column, text) in [
                                format!("{:.6}", event.timestamp_ns as f64 / 1_000_000_000.0),
                                sequence,
                                event.tid.to_string(),
                                cpu,
                                format!("{} ({})", event.syscall_name, event.syscall_nr),
                                invocation
                                    .exit
                                    .as_ref()
                                    .and_then(|event| event.result)
                                    .map(|result| result.to_string())
                                    .unwrap_or_else(|| "missing Exit".into()),
                                trace::info(invocation),
                            ]
                            .into_iter()
                            .enumerate()
                            {
                                row.col(|ui| {
                                    // Paint the cell and half of each gap so a tinted
                                    // row reads as one band, as in Wireshark.
                                    let cell = ui.max_rect().expand2(egui::vec2(
                                        ui.spacing().item_spacing.x / 2.0,
                                        0.0,
                                    ));
                                    if let Some(tint) = tint {
                                        ui.painter().rect_filled(cell, 0.0, tint);
                                    }
                                    if failed && column == 0 {
                                        let mut bar = cell;
                                        bar.set_width(3.0);
                                        ui.painter().rect_filled(bar, 0.0, theme::ERROR);
                                    }
                                    let mut label = RichText::new(&text);
                                    if failed && column == 5 {
                                        label = label.color(theme::ERROR);
                                    }
                                    ui.add(
                                        egui::Label::new(label)
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::hover()),
                                    )
                                    .on_hover_text(match group {
                                        Some(group) if column == 4 => {
                                            format!("{text}\n{}", group.label())
                                        }
                                        _ => text.clone(),
                                    });
                                });
                            }
                            if row.response().clicked() {
                                self.selected_event = Some(key);
                                self.inspector.clear();
                            }
                        });
                    });
            });
    }

    /// Category filter above the trace: one button per syscall group (with
    /// its row count) shows or hides that group's rows, and "All" shows or
    /// hides every group. The choice is saved with the settings; row colors
    /// are switched in Settings.
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
        // One row that scrolls sideways, so the buttons never push the trace
        // table down in a narrow panel or at large text sizes.
        egui::ScrollArea::horizontal()
            .id_salt("trace_categories")
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let all_shown = hidden.is_empty();
                    let all = egui::Button::new(RichText::new("All").small().strong())
                        .fill(if all_shown {
                            theme::PRIMARY
                        } else {
                            theme::PANEL
                        })
                        .stroke(egui::Stroke::new(1.0_f32, theme::LINE));
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
                        let swatch = theme::syscall_tint(group).unwrap_or(theme::RAISED);
                        let text = RichText::new(format!(
                            "{} {}",
                            group.label(),
                            counts.get(&group).copied().unwrap_or(0)
                        ))
                        .small()
                        .color(if shown {
                            theme::TEXT
                        } else {
                            theme::MUTED
                        });
                        let button = egui::Button::new(text)
                            .fill(if shown { swatch } else { theme::PANEL })
                            .stroke(egui::Stroke::new(1.0_f32, swatch.gamma_multiply(1.6)));
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
                theme::MUTED,
                "All categories are hidden; click All to show them.",
            );
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
        if self.import_open {
            let mut open = true;
            let mut import = false;
            egui::Window::new("Import base")
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_width(680.0)
                .min_width(520.0)
                .show(ctx, |ui| {
                    ui.label(
                        "Folder of a built base (it contains bundle.json, kernel and base.qcow2)",
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.import_directory)
                            .desired_width(ui.available_width())
                            .hint_text("Bundle directory"),
                    );
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                self.folder_picker.available(),
                                egui::Button::new(egui_phosphor::regular::FOLDER_OPEN),
                            )
                            .on_hover_text("Choose bundle directory")
                            .clicked()
                        {
                            if let Err(error) = self.folder_picker.choose(FolderTarget {
                                generation: 0,
                                kind: FolderKind::BaseImport,
                            }) {
                                self.status = error;
                            }
                        }
                        import = ui
                            .add_enabled(
                                self.snapshot.active_vm.is_none()
                                    && !self.import_directory.trim().is_empty(),
                                egui::Button::new("Import"),
                            )
                            .clicked();
                    });
                });
            self.import_open = open;
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
        if self.about_open {
            let mut open = true;
            egui::Window::new("About Antinomie")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(format!("Antinomie {APP_VERSION}"))
                            .strong()
                            .size(18.0),
                    );
                    ui.label("Run programs in a QEMU VM and record every system call they make.");
                    ui.add_space(6.0);
                    egui::Grid::new("about")
                        .num_columns(2)
                        .spacing([16.0, 4.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Guest kernel").color(theme::MUTED));
                            ui.label("Linux 6.12.94 (Debian 6.12.94-1 source)");
                            ui.end_row();
                            ui.label(RichText::new("Bases").color(theme::MUTED));
                            ui.label(format!(
                                "{} or newer",
                                RevisionStatus::describe(Some(APP_REVISION), None)
                            ));
                            ui.end_row();
                        });
                });
            self.about_open = open;
        }
        if self.build_open {
            let mut open = true;
            let build = self.snapshot.build.clone();
            let mut action = None;
            egui::Window::new("Build base")
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
            egui::Window::new(if *duplicate { "Duplicate VM" } else { "Rename VM" }).collapsible(false).resizable(false).open(&mut open).show(ctx, |ui| {
                ui.add(egui::TextEdit::singleline(name).desired_width(320.0));
                if *duplicate { ui.label("Copies the current disk with a new VM identity. Run history remains with the source VM."); }
                save = ui.add_enabled(!name.trim().is_empty() && (!*duplicate || self.snapshot.active_vm.as_ref() != Some(vm_id)), egui::Button::new(if *duplicate { "Duplicate" } else { "Rename" })).clicked();
            });
            if save {
                if let Some((vm_id, duplicate, name)) = self.name_action.take() {
                    self.send(if duplicate {
                        Command::Duplicate { vm_id, name }
                    } else {
                        Command::Rename { vm_id, name }
                    });
                }
            } else if !open {
                self.name_action = None;
            }
        }
        if self.create_open || self.config_open {
            let creating = self.create_open;
            let mut open = true;
            let mut save = false;
            let mut reset = false;
            let mut delete = false;
            let mut nat = false;
            let mut credentials_required = false;
            let mut form_error = None;
            egui::Window::new(if creating {
                "New VM"
            } else {
                "VM configuration"
            })
            .id(egui::Id::new("vm_configuration"))
            .collapsible(false)
            .resizable(false)
            .default_width(460.0)
            .default_height(0.0)
            .max_width(500.0)
            .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
            .open(&mut open)
            .show(ctx, |ui| {
                scroll_dialog(ui, ctx, |ui| {
                    let editable = if creating {
                        self.snapshot.active_vm.is_none()
                    } else {
                        self.snapshot.active_vm.as_ref() != Some(&self.draft.id)
                            && self.snapshot.vms.iter().any(|vm| vm.id == self.draft.id)
                    };
                    let disk_default = if creating {
                        self.options.data_dir.clone()
                    } else {
                        self.snapshot.vm_locations.iter()
                            .find(|location| location.vm_id == self.draft.id)
                            .and_then(|location| location.disk_directory.parent())
                            .unwrap_or(&self.options.data_dir).to_path_buf()
                    };
                    ui.add_enabled_ui(editable, |ui| {
                        egui::Grid::new("vm_config")
                            .num_columns(2)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                let old_base = self.draft.base_identity.clone();
                                ui.label("Installed base");
                                base_selector(ui, &self.snapshot, &mut self.draft.base_identity, "vm_base");
                                ui.end_row();
                                if old_base != self.draft.base_identity {
                                    self.credentials.reset();
                                }
                                let base = self.snapshot.bases.iter().find(|base| Some(&base.id) == self.draft.base_identity.as_ref());
                                let min_ram = base.map_or(256, |base| base.min_ram_mib);
                                let min_disk = base.map_or(1, |base| base.min_disk_gib);
                                credentials_required = creating && base.and_then(|base| base.guest.as_ref()).is_some_and(|guest| guest.requires_credentials);
                                self.draft.ram_mib = self.draft.ram_mib.max(min_ram);
                                if creating { self.draft.disk_gib = self.draft.disk_gib.max(min_disk); }
                                ui.label("Name");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.draft.name)
                                        .desired_width(280.0),
                                );
                                ui.end_row();
                                ui.label("CPU count");
                                ui.add(egui::DragValue::new(&mut self.draft.cpus).range(1..=64));
                                ui.end_row();
                                ui.label("RAM (MiB)");
                                ui.add(
                                    egui::DragValue::new(&mut self.draft.ram_mib)
                                        .range(min_ram..=antinomie_monitor_core::storage::MAX_RAM_MIB),
                                );
                                ui.end_row();
                                ui.label("Disk (GiB)");
                                if creating {
                                    ui.add(
                                        egui::DragValue::new(&mut self.draft.disk_gib)
                                            .range(min_disk..=2048),
                                    );
                                } else {
                                    ui.label(self.draft.disk_gib.to_string());
                                }
                                ui.end_row();
                                launch_options(ui, &mut self.draft.launch);
                                ui.label("Disk parent");
                                ui.add_enabled_ui(creating, |ui| { directory_input(ui, &mut self.draft.disk_root, &disk_default, &mut self.folder_picker, FolderTarget { generation: self.draft_generation, kind: FolderKind::Disk }, &mut self.status); });
                                ui.end_row();
                                ui.label("Recording parent");
                                let recording_default = if creating { self.draft.disk_root.as_ref().unwrap_or(&disk_default) } else { &disk_default }.clone();
                                directory_input(ui, &mut self.draft.recording_root, &recording_default, &mut self.folder_picker, FolderTarget { generation: self.draft_generation, kind: FolderKind::Recording }, &mut self.status);
                                ui.end_row();
                                if credentials_required {
                                    ui.label("Username");
                                    ui.add(egui::TextEdit::singleline(&mut self.credentials.username).char_limit(32).desired_width(280.0));
                                    ui.end_row();
                                    ui.label("Password");
                                    password_input(ui, &mut self.credentials.password, "guest_password");
                                    ui.end_row();
                                    ui.label("Confirm password");
                                    password_input(ui, &mut self.credentials.confirmation, "guest_confirmation");
                                    ui.end_row();
                                }
                            });
                        if !creating {
                            if let Some(location) = self.snapshot.vm_locations.iter().find(|location| location.vm_id == self.draft.id) {
                                ui.add(egui::Label::new(format!("Disk: {}", location.disk_directory.display())).truncate()).on_hover_text(location.disk_directory.display().to_string());
                                ui.add(egui::Label::new(format!("Recordings: {}", location.recording_directory.display())).truncate()).on_hover_text(location.recording_directory.display().to_string());
                            }
                            ui.label("Recording parent changes apply to future recordings. Earlier recordings are retained.");
                        }
                        ui.horizontal(|ui| {
                            if ui.checkbox(&mut self.draft.nat, "NAT network").changed()
                                && self.draft.nat
                            {
                                self.draft.nat = false;
                                nat = true;
                            }
                            ui.add_space(12.0);
                            if ui
                                .button("Telemetry transport…")
                                .on_hover_text("Guest buffers, never-drop mode and the host event table")
                                .clicked()
                            {
                                self.transport_open = !self.transport_open;
                            }
                        });
                        if self.draft.nat {
                            ui.colored_label(
                                theme::WARN,
                                "NAT permits guest access to the host network and Internet.",
                            );
                        }
                        ui.separator();
                        if creating {
                            form_error = self.create_validation_error(credentials_required);
                        } else {
                            form_error = self.save_validation_error(&self.draft);
                        }
                        // Above the button, so it stays in view in a tall dialog.
                        if let Some(error) = &form_error {
                            ui.add(egui::Label::new(egui::RichText::new(error).color(theme::WARN)).wrap());
                        }
                        ui.horizontal(|ui| {
                            save = ui
                                .add_enabled(
                                    form_error.is_none(),
                                    egui::Button::new(if creating {
                                        "Create VM"
                                    } else {
                                        "Save configuration"
                                    })
                                    .fill(theme::PRIMARY),
                                )
                                .clicked();
                            if !creating {
                                reset = icon(
                                    ui,
                                    egui_phosphor::regular::ARROW_COUNTER_CLOCKWISE,
                                    "Reset disk to base",
                                    self.snapshot.active_vm.is_none(),
                                );
                                delete = icon(
                                    ui,
                                    egui_phosphor::regular::TRASH,
                                    "Delete VM and disk",
                                    self.snapshot.active_vm.is_none(),
                                );
                            }
                        });
                    });
                    if !editable {
                        form_error = if creating {
                            self.create_validation_error(credentials_required)
                        } else {
                            self.save_validation_error(&self.draft)
                        };
                        if let Some(error) = &form_error {
                            ui.add(egui::Label::new(egui::RichText::new(error).color(theme::WARN)).wrap());
                        }
                    }
                });
            });
            if self.transport_open && open {
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
                } else {
                    if let Err(error) = self.save_vm(self.draft.clone()) {
                        self.status = error;
                        return;
                    }
                }
                self.create_open = false;
                self.config_open = false;
            }
        }
        if self.launch_open {
            let mut open = true;
            egui::Window::new("Run Program")
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_width(1000.0)
                .default_height(540.0)
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
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(420.0)
                .default_height(0.0)
                .max_width(460.0)
                .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    scroll_dialog(ui, ctx, |ui| {
                        self.upload_form(ui);
                    });
                });
            self.upload_open &= open;
        }
        if self.settings_open {
            let mut open = true;
            let mut save = false;
            egui::Window::new("Recording and base settings")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(420.0)
                .default_height(0.0)
                .max_width(460.0)
                .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    scroll_dialog(ui, ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Text size");
                            if ui
                                .add(
                                    egui::Slider::new(&mut self.settings.font_size, 12.0..=24.0)
                                        .step_by(1.0),
                                )
                                .changed()
                            {
                                theme::text_size(ctx, self.settings.font_size);
                                for terminal in self.terminals.values_mut() {
                                    terminal.terminal.invalidate_resize();
                                }
                            }
                        });
                        ui.checkbox(
                            &mut self.settings.trace_colors,
                            "Color syscall trace rows by category",
                        )
                        .on_hover_text(
                            "Tint each syscall by its category, like Wireshark's coloring rules",
                        );
                        ui.separator();
                        ui.add_enabled_ui(self.snapshot.active_vm.is_none(), |ui| {
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
                            numeric(
                                ui,
                                "Recording quota (GiB)",
                                &mut self.settings.quota_gib,
                                1..=4096,
                            );
                            numeric(
                                ui,
                                "Shutdown timeout (seconds)",
                                &mut self.settings.timeout,
                                1..=120,
                            );
                            ui.separator();
                            save = ui.button("Save settings").clicked();
                        });
                        if let Some(path) = &self.snapshot.capture_dir {
                            ui.separator();
                            ui.add(
                                egui::Label::new(format!("Recording: {}", path.display()))
                                    .truncate(),
                            )
                            .on_hover_text(path.display().to_string());
                        }
                    });
                });
            self.settings_open = open;
            if save {
                self.update_options();
                self.settings_open = false;
            }
        }
        if let Some(confirm) = &self.confirm {
            let text = match confirm {
                Confirm::Reset(_) => {
                    "Reset this VM's disk to the base image? All VM disk changes will be lost."
                }
                Confirm::Delete(_) => {
                    "Delete this VM configuration and disk? Disk changes will be lost. Retained run recordings and terminal history are preserved."
                }
                Confirm::DeleteBase(_) => {
                    "Delete this base image? This cannot be undone. VMs that reference it must be deleted first."
                }
                Confirm::Upload { .. } => "Overwrite the chosen guest path with this host file?",
                Confirm::Nat { .. } => {
                    "Enable NAT? The guest can connect to the host network and Internet."
                }
            };
            let mut yes = false;
            let mut cancel = false;
            egui::Modal::new(egui::Id::new("confirm_action")).show(ctx, |ui| {
                ui.set_width(360.0);
                ui.strong("Confirm action");
                ui.separator();
                ui.label(text);
                ui.horizontal(|ui| {
                    let enabled = !self.closing
                        && match confirm {
                            Confirm::Reset(_) | Confirm::Delete(_) | Confirm::DeleteBase(_) => {
                                self.snapshot.active_vm.is_none()
                            }
                            Confirm::Upload { vm_id, .. } => {
                                vm_id.is_some()
                                    && self.snapshot.active_vm == *vm_id
                                    && self.snapshot.state == VmState::Running
                            }
                            Confirm::Nat { vm, creating } => {
                                if *creating {
                                    self.snapshot.active_vm.is_none()
                                } else {
                                    self.snapshot.active_vm.as_ref() != Some(&vm.id)
                                }
                            }
                        };
                    yes = ui
                        .add_enabled(enabled, egui::Button::new("Confirm"))
                        .clicked();
                    cancel = ui.button("Cancel").clicked();
                });
            });
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
                        Confirm::Upload {
                            source,
                            destination,
                            executable,
                            ..
                        } => self.send(Command::Upload {
                            source,
                            destination,
                            executable,
                            overwrite: true,
                        }),
                        Confirm::Nat { mut vm, creating } => {
                            vm.nat = true;
                            if self.draft.id == vm.id {
                                self.draft.nat = true;
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

    fn draw(&mut self, ctx: &egui::Context) {
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
        let enabled = self.observer_start_enabled();
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
                self.queue_archive(Request::Listing {
                    view_key: view_key.into(),
                    generation,
                    directory,
                    report_id,
                    kind,
                    start,
                    query,
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
                    ui.colored_label(theme::ERROR, error);
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
                                theme::MUTED,
                                format!(
                                    "{}: download cancelled; it resumes where it stopped",
                                    status.label
                                ),
                            );
                        }
                        Some(error) => {
                            ui.colored_label(theme::ERROR, format!("{}: {error}", status.label));
                        }
                        None => {
                            ui.colored_label(theme::GOOD, format!("{} installed", status.label));
                        }
                    }
                }
                ui.separator();
                if current.is_empty() && older.is_empty() && other.is_empty() {
                    ui.colored_label(theme::MUTED, "No bases listed yet: refresh the catalog.");
                }
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let rows = current
                            .iter()
                            .chain(other.iter())
                            .chain(older.iter().filter(|_| *show_older));
                        for (index, base) in rows.enumerate() {
                            if index == current.len() && !other.is_empty() {
                                ui.add_space(6.0);
                                ui.label(RichText::new("Other bases").strong().color(theme::MUTED));
                            }
                            if index == current.len() + other.len() && *show_older {
                                ui.add_space(6.0);
                                ui.label(RichText::new("Older bases").strong().color(theme::MUTED));
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

    pub(crate) fn show_panel(&mut self, ui: &mut egui::Ui, panel: &Panel) {
        ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
        match panel {
            Panel::Trace => self.events(ui),
            Panel::Network => {
                let vm = self.selected.clone();
                let live = self
                    .snapshot
                    .network_pcap
                    .clone()
                    .filter(|_| vm.is_some() && vm == self.snapshot.active_vm);
                let recordings = self
                    .snapshot
                    .vm_locations
                    .iter()
                    .find(|location| Some(&location.vm_id) == vm.as_ref())
                    .map(|location| location.recording_directory.clone());
                let nat = self
                    .snapshot
                    .vms
                    .iter()
                    .any(|config| Some(&config.id) == vm.as_ref() && config.nat);
                self.network_view.show(
                    ui,
                    live.as_deref(),
                    recordings.as_deref(),
                    nat,
                    self.settings.font_size,
                );
            }
            Panel::AnalysisSection { report_id, kind } => {
                let key = format!("section:{report_id}:{kind:?}");
                let report = self.analysis_windows.get(report_id);
                let view = self.analysis_views.entry(key.clone()).or_default();
                view.bind(report.map(|report| report.id.as_str()));
                let action = crate::analysis::workspace_section(
                    ui,
                    report,
                    *kind,
                    &mut view.state,
                    view.preview.as_ref(),
                    view.listing.as_ref(),
                );
                self.analysis_action(&key, action);
            }
            Panel::StaticAnalysis => {
                egui::ComboBox::from_id_salt("analysis-source")
                    .selected_text(self.selected_analysis.as_deref().unwrap_or("Selected run"))
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.selected_analysis, None, "Selected run");
                        for report in &self.snapshot.analysis_reports {
                            ui.selectable_value(
                                &mut self.selected_analysis,
                                Some(report.id.clone()),
                                format!("{} ({:?})", report.source_path, report.state),
                            );
                        }
                    });
                let shown = match self.selected_analysis.as_deref() {
                    Some(id) => Some(id),
                    None => self.selected_run.as_deref().and_then(|id| {
                        self.snapshot
                            .runs
                            .iter()
                            .chain(&self.history)
                            .find(|run| run.id == id)
                            .and_then(|run| run.analysis.as_ref())
                            .map(|report| report.id.as_str())
                    }),
                };
                crate::analysis::other_progress(
                    ui,
                    self.snapshot
                        .runs
                        .iter()
                        .chain(&self.history)
                        .filter_map(|run| run.analysis.as_ref())
                        .chain(&self.snapshot.analysis_reports),
                    shown,
                );
                if let Some(id) = self.selected_analysis.as_deref() {
                    let report = self
                        .snapshot
                        .analysis_reports
                        .iter()
                        .find(|report| report.id == id);
                    let view = self.analysis_views.entry("workspace".into()).or_default();
                    view.bind(report.map(|report| report.id.as_str()));
                    let action = crate::analysis::workspace(
                        ui,
                        report,
                        &mut view.state,
                        view.preview.as_ref(),
                        view.listing.as_ref(),
                    );
                    self.analysis_action("workspace", action);
                    return;
                }
                if let Some(id) = self.selected_run.as_deref() {
                    let live = self.snapshot.runs.iter().find(|run| run.id == id);
                    let run = if self.archive_selected {
                        self.history.iter().find(|run| run.id == id).or(live)
                    } else {
                        live.or_else(|| self.history.iter().find(|run| run.id == id))
                    };
                    let report = run.and_then(|run| run.analysis.as_ref());
                    let view = self.analysis_views.entry("workspace".into()).or_default();
                    view.bind(report.map(|report| report.id.as_str()));
                    let action = crate::analysis::workspace(
                        ui,
                        report,
                        &mut view.state,
                        view.preview.as_ref(),
                        view.listing.as_ref(),
                    );
                    self.analysis_action("workspace", action);
                } else {
                    ui.label("Select a run to view its static analysis report.");
                }
            }
            Panel::RunHistory => self.run_history(ui),
            Panel::Details => self.details(ui),
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
                            ui.colored_label(theme::WARN, error);
                        }
                    });
                    let interactive = live && terminal.interactive() && !self.closing;
                    let (data, resize) = if live {
                        terminal.terminal.show(ui, interactive)
                    } else {
                        egui::ScrollArea::both()
                            .show(ui, |ui| terminal.terminal.show_grid(ui, false, false))
                            .inner
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
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain();
        self.flush_archive();
        self.drain_archive();
        self.resync_terminals();
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
    egui::ComboBox::from_id_salt(salt)
        .selected_text(label)
        .width(260.0)
        .show_ui(ui, |ui| {
            for base in &snapshot.bases {
                ui.selectable_value(identity, Some(base.id.clone()), base_choice_label(base))
                    .on_hover_text(base.directory.display().to_string());
            }
        });
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
                        .color(theme::MUTED),
                );
            },
        );
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if installed.contains(&base.identity) {
                ui.colored_label(
                    theme::GOOD,
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
                .add_enabled(!busy, egui::Button::new("Download"))
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

fn selected_base<'a>(snapshot: &'a Snapshot, identity: Option<&str>) -> Option<&'a BaseSummary> {
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
    egui::Window::new("Telemetry transport")
        .id(egui::Id::new("vm_transport"))
        .open(open)
        .collapsible(false)
        .resizable(false)
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.add_enabled_ui(editable, |ui| {
                transport_options(ui, transport, cpus, tunable)
            });
            if !editable {
                ui.colored_label(theme::WARN, "Stop the VM to change these settings.");
            }
            ui.weak("Save the VM configuration to apply.");
        });
}

fn transport_options(
    ui: &mut egui::Ui,
    transport: &mut TransportSettings,
    cpus: u16,
    tunable: bool,
) {
    if !tunable {
        ui.colored_label(
            theme::WARN,
            "This base predates Antinomie 0.3.0: it always uses 256 KiB buffers \
             and drops telemetry when they are full. These settings apply to \
             newer bases.",
        );
    }
    egui::Grid::new("vm_transport_grid")
        .num_columns(2)
        .spacing([12.0, 6.0])
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
    ui.weak(
        "Never drop makes a guest system call wait while the host saves \
         telemetry, so heavy tracing runs slower but nothing is lost. The \
         event table holds calls still being assembled; finished calls \
         leave it first. Settings apply at the next VM start.",
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
            .add(egui::TextEdit::singleline(&mut text).desired_width(235.0))
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
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| terminal.terminal.show_grid(ui, false, false))
                .inner
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
                    .fill(theme::TERMINAL)
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
            Self::Time => "Time",
            Self::Sequence => "Sequence",
            Self::Tid => "TID",
            Self::Cpu => "CPU",
            Self::Syscall => "Syscall (number)",
            Self::Return => "Return",
            Self::Info => "Info",
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

/// A sidebar section title with a "+" action on its right and a separator
/// below. The "+" lights up while hovered, or while its menu is `open`.
fn section_header(
    ui: &mut egui::Ui,
    title: &str,
    title_tooltip: &str,
    action: &str,
    enabled: bool,
    open: bool,
) -> egui::Response {
    let size = ui.spacing().interact_size.y;
    let response = ui
        .horizontal(|ui| {
            let title_width = (ui.available_width() - size - ui.spacing().item_spacing.x).max(0.0);
            // Left-aligned, so every section title starts at the same edge.
            ui.allocate_ui_with_layout(
                egui::vec2(title_width, size),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_min_size(egui::vec2(title_width, size));
                    ui.add(egui::Label::new(RichText::new(title).strong()).truncate())
                        .on_hover_text(title_tooltip);
                },
            );
            let sense = if enabled {
                egui::Sense::click()
            } else {
                egui::Sense::hover()
            };
            let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), sense);
            let lit = enabled && (response.hovered() || open);
            if ui.is_rect_visible(rect) {
                if lit {
                    ui.painter().rect_filled(rect, 4.0, theme::PRIMARY);
                }
                let color = match (enabled, lit) {
                    (false, _) => theme::MUTED.gamma_multiply(0.5),
                    (true, true) => egui::Color32::WHITE,
                    (true, false) => theme::TEXT,
                };
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    egui_phosphor::regular::PLUS,
                    egui::FontId::proportional(ui.text_style_height(&egui::TextStyle::Body)),
                    color,
                );
            }
            if enabled {
                response.on_hover_text(action)
            } else {
                response.on_hover_text(format!("{action} (stop the running VM first)"))
            }
        })
        .inner;
    ui.separator();
    response
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

fn numeric<T: egui::emath::Numeric>(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut T,
    range: std::ops::RangeInclusive<T>,
) {
    ui.horizontal(|ui| {
        ui.label(label);
        ui.add(egui::DragValue::new(value).range(range));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::RunIn;

    fn app() -> MonitorApp {
        let exec = ExecRequest::default();
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
            show_older_bases: false,
            build_wizard: build_wizard::BuildWizard::default(),
            name_action: None,
            filter: String::new(),
            trace_sort: None,
            selected_event: None,
            selected_run: None,
            selected_capture: None,
            selected_process: None,
            transport_open: false,
            network_view: Default::default(),
            archived_processes: None,
            capture_history: Vec::new(),
            capture_tab: false,
            process_picker: captures::ProcessPicker::default(),
            pending_observer: None,
            selected_analysis: None,
            analysis_windows: BTreeMap::new(),
            analysis_directories: BTreeMap::new(),
            pending_analysis_sections: Vec::new(),
            analysis_views: BTreeMap::new(),
            analysis_generation: 0,
            archive_selected: false,
            history_generation: 0,
            run_filter: RunFilter::All,
            terminals: BTreeMap::new(),
            archive: None,
            pending_archive: None,
            history: Vec::new(),
            archive_generation: 0,
            archive_page: Vec::new(),
            archive_offset: 0,
            archive_next: None,
            archive_previous: Vec::new(),
            archive_pending: false,
            archive_error: None,
            inspector: Inspector::default(),
            data_windows: crate::data_view::DataWindows::default(),
            layout: WorkspaceLayout::default(),
            focus_panel: None,
            activity: VecDeque::new(),
            env: exec.env.join("\n"),
            exec,
            args: String::new(),
            source: String::new(),
            destination: "/tmp/program".into(),
            executable: false,
            overwrite: false,
            pending_launch: None,
            started: Instant::now(),
            smoke: None,
            closing: false,
            submitted: Vec::new(),
            launch_action_rects: None,
        }
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
                        texts.push((text.galley.text().to_owned(), rect));
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
        assert!(visible
            .iter()
            .any(|(text, _)| text == "current · Antinomie 0.3.0"));
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
        assert_eq!(base_choice_label(&base), "Debian · Antinomie 0.3.0");
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
            .filter(|(text, _)| text.contains("Linux 6.12.94 · Antinomie 0.3.0"))
            .map(|(_, rect)| *rect)
            .collect();
        let title = texts
            .iter()
            .find(|(text, _)| text == "Base images")
            .expect("base images title")
            .1;
        assert_eq!(rows.len(), 2);
        // Left-aligned with the section title, not centred in the sidebar.
        assert!(
            rows.iter().all(|row| row.left() < title.left() + 12.0),
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
                        rect.fill == theme::PRIMARY && rect.rect.contains(point)
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
            format!("TID {}", egui_phosphor::regular::CARET_UP)
        );
        click(&mut app);
        assert_eq!(app.trace_sort, Some((TraceColumn::Tid, true)));
        assert_eq!(
            header(&mut app).0,
            format!("TID {}", egui_phosphor::regular::CARET_DOWN)
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
            "Linux 6.12.94 · Antinomie 0.3.0 (legacy)"
        );
        app.snapshot.bases[1].fixed_display = true;
        assert_eq!(
            base_choice_label(&app.snapshot.bases[1]),
            "Linux 6.12.94 · Antinomie 0.3.0"
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
        let target = find(&output, "Return: -2").expect("return value shown");
        let (output, _) = click(&mut inspector, target, egui::PointerButton::Secondary);
        for (label, value) in [
            ("Signed decimal", "-2"),
            ("Hex", "0xfffffffffffffffe"),
            ("Decimal", "18446744073709551614"),
        ] {
            assert!(find(&output, label).is_some(), "{label} offered");
            assert!(find(&output, value).is_some(), "{value} previewed");
        }
        let hex = find(&output, "Hex").unwrap();
        let (output, copied) = click(&mut inspector, hex, egui::PointerButton::Primary);
        assert_eq!(copied, ["0xfffffffffffffffe"]);

        // A captured field: right-click offers its data window. The Exit
        // phase (shown second) holds the field.
        let argument = texts(&output)
            .into_iter()
            .filter(|(text, _)| text == "buf: 0x1000")
            .map(|(_, rect)| rect.center())
            .next_back()
            .expect("argument header");
        let (mut output, _) = click(&mut inspector, argument, egui::PointerButton::Primary);
        for _ in 0..20 {
            output = frame(&mut inspector, Vec::new());
        }
        let field = find(&output, "buf").expect("captured field node");
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
        assert!(trace::info(&rows[0]).contains("fd=3 requested=8 returned=4"));
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
            "1/2",
            "42",
            "0>3",
            "read (0)",
            "4",
            "fd=3 requested=8 returned=4",
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
            .find(|(label, _)| label == "Working directory")
            .expect("metadata visible below history rows");
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
                assert!(rect("Details").bottom() < rect("Transport loss: 3").top());
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
                assert_eq!(
                    ctx.style().text_styles[&egui::TextStyle::Monospace].size,
                    font
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
}

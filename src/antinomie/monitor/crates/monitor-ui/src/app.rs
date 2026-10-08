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
    pair_events, Backend, BackendOptions, BaseSummary, Command, DisplayResolution, ExecRequest,
    GuestCredentials, InvocationSummary, Notification, RevisionStatus, RunState, RunSummary,
    Snapshot, TerminalRecord, VmAcceleration, VmConfig, VmCpuModel, VmLaunchOptions, VmState,
    WaitStatus, APP_REVISION, APP_VERSION,
};
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
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            bundle: String::new(),
            quota_gib: 4,
            timeout: 10,
            font_size: 16.0,
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
    build_wizard: build_wizard::BuildWizard,
    confirm: Option<Confirm>,
    name_action: Option<(String, bool, String)>,
    status: String,
    filter: String,
    /// Trace table order: the clicked column and whether it is descending.
    trace_sort: Option<(TraceColumn, bool)>,
    selected_event: Option<InvocationKey>,
    selected_run: Option<String>,
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
        options.bundle_dir = PathBuf::from(&settings.bundle);
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
            build_wizard: build_wizard::BuildWizard::default(),
            confirm: None,
            name_action: None,
            status,
            filter: String::new(),
            trace_sort: None,
            selected_event: None,
            selected_run: None,
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
        let was_offline = self.offline_run().is_some();
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
                        self.snapshot = snapshot;
                    }
                    Some(Notification::CommandResult {
                        id,
                        success,
                        message,
                    }) => {
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
        if !was_offline && self.offline_run().is_some() {
            self.request_page(0);
        }
    }

    fn running(&self) -> bool {
        self.snapshot.state == VmState::Running && self.snapshot.active_vm == self.selected
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

    fn refresh_history(&mut self) {
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
            return;
        };
        match worker.try_request(request) {
            Ok(()) => {}
            Err(error) => match *error {
                std::sync::mpsc::TrySendError::Full(request) => {
                    self.pending_archive = Some(request)
                }
                std::sync::mpsc::TrySendError::Disconnected(_) => {
                    self.archive_pending = false;
                    self.inspector.pending = false;
                    self.archive_error = Some("Archive worker disconnected".into());
                }
            },
        }
    }

    fn select_run(&mut self, id: Option<String>) {
        self.archive_selected = false;
        self.selected_run = id;
        self.selected_event = None;
        self.inspector.clear();
        self.pending_archive = None;
        self.archive_generation = self.archive_generation.wrapping_add(1);
        self.archive_page.clear();
        self.archive_previous.clear();
        self.archive_next = None;
        self.archive_offset = 0;
        self.archive_pending = false;
        self.archive_error = None;
        if self.offline_run().is_some() {
            self.request_page(0);
        }
    }

    fn request_page(&mut self, offset: u64) {
        let Some(run) = self.offline_run() else {
            return;
        };
        let directory = run.directory.clone();
        self.archive_generation = self.archive_generation.wrapping_add(1);
        self.archive_pending = false;
        self.archive_error = None;
        self.selected_event = None;
        self.inspector.clear();
        let request = Request::Invocations {
            generation: self.archive_generation,
            directory,
            offset,
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
                .selectable_label(self.selected_run.is_none(), "All live traces")
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
                                    "Wait status: {:?}",
                                    run.execution
                                        .as_ref()
                                        .and_then(|status| status.root_wait_status)
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

    fn select_archive_run(&mut self, id: String) {
        self.select_run(Some(id));
        self.archive_selected = true;
        self.request_page(0);
        self.focus_trace();
    }

    fn handle_archive_answer(&mut self, answer: Answer) {
        match answer {
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
            } if generation == self.archive_generation && self.offline_run().is_some() => {
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
                    if self.snapshot.bases.is_empty() {
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
                    ui.separator();
                    if icon(
                        ui,
                        egui_phosphor::regular::GEAR,
                        "Recording and base settings",
                        true,
                    ) {
                        self.settings_open = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let name = self
                            .snapshot
                            .vms
                            .iter()
                            .find(|vm| Some(&vm.id) == self.snapshot.active_vm.as_ref())
                            .map(|vm| vm.name.as_str())
                            .unwrap_or(if self.snapshot.capture_dir.is_some() {
                                "Last recording"
                            } else {
                                "No active VM"
                            });
                        ui.add(
                            egui::Label::new(RichText::new(name).color(theme::MUTED)).truncate(),
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
                    });
                });
            });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let mut selected_vm = None;
        let mut action = None;
        let mut base_action: Option<(String, String)> = None;
        let mut clicked_base: Option<String> = None;
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
                        if self.snapshot.bases.is_empty() {
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
                            let label = if RevisionStatus::of_base(
                                base.revision,
                                base.min_app_version.as_deref(),
                            ) == RevisionStatus::Current
                            {
                                format!("{}  {}", egui_phosphor::regular::HARD_DRIVE, base.label)
                            } else {
                                format!(
                                    "{}  {}  {}",
                                    egui_phosphor::regular::HARD_DRIVE,
                                    base.label,
                                    egui_phosphor::regular::WARNING
                                )
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
                                     Patch {}\nRight-click for actions",
                                    base.label,
                                    base.directory.display(),
                                    base.size_bytes as f64 / 1073741824.0,
                                    dependents,
                                    describe_base(base)
                                ));
                            if response.clicked() || response.secondary_clicked() {
                                clicked_base = Some(base.id.clone());
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
                            "Release: {}\nPatch series: {}\nGuest contract revision: {}\nThis app: Antinomie {APP_VERSION} (revision {APP_REVISION})",
                            kernel.release.as_deref().unwrap_or("unknown"),
                            kernel.source.as_deref().unwrap_or("not recorded"),
                            kernel.revision.map_or("none".into(), |r| r.to_string()),
                        ));
                    }
                    ui.separator();
                    ui.colored_label(if health.dropped == 0 { theme::GOOD } else { theme::WARN },
                        format!("Transport loss: {}", health.dropped));
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
            egui::Grid::new("launch")
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    ui.label("Executable");
                    ui.add(egui::TextEdit::singleline(&mut self.exec.path).desired_width(290.0));
                    ui.end_row();
                    ui.label("Arguments");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.args)
                            .desired_rows(3)
                            .desired_width(290.0),
                    )
                    .on_hover_text("One argument per line");
                    ui.end_row();
                    ui.label("Working directory");
                    ui.add(egui::TextEdit::singleline(&mut self.exec.cwd).desired_width(290.0));
                    ui.end_row();
                    ui.label("Environment");
                    ui.add(
                        egui::TextEdit::multiline(&mut self.env)
                            .desired_rows(3)
                            .desired_width(290.0),
                    )
                    .on_hover_text("One NAME=value entry per line");
                    ui.end_row();
                    ui.label("Identity");
                    ui.horizontal(|ui| {
                        numeric(ui, "UID", &mut self.exec.uid, 0..=u32::MAX);
                        numeric(ui, "GID", &mut self.exec.gid, 0..=u32::MAX);
                    });
                    ui.end_row();
                });
            ui.separator();
            if ui
                .add_enabled(
                    !self.exec.path.trim().is_empty(),
                    egui::Button::new(format!("{} Launch", egui_phosphor::regular::PLAY))
                        .fill(theme::PRIMARY),
                )
                .clicked()
            {
                self.exec.args = self.args.lines().map(str::to_owned).collect();
                self.exec.env = self
                    .env
                    .lines()
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned)
                    .collect();
                self.send(Command::Execute(self.exec.clone()));
                if self.pending_launch.is_some() {
                    self.launch_open = false;
                }
            }
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
                        source: PathBuf::from(&self.source),
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
            source: PathBuf::from(&self.source),
            destination: self.destination.clone(),
            overwrite: self.overwrite,
            executable: self.executable,
        });
    }

    fn invocations(&self) -> Vec<InvocationSummary> {
        if self.offline_run().is_some() {
            return self.archive_page.clone();
        }
        if self.selected.is_some()
            && self.snapshot.active_vm.is_some()
            && self.selected != self.snapshot.active_vm
        {
            return Vec::new();
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
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter")
                    .desired_width(130.0),
            );
            if self.offline_run().is_some() {
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
        let invocations: Vec<_> = self
            .invocations()
            .into_iter()
            .filter(|invocation| {
                let Some(event) = trace::representative(invocation) else {
                    return false;
                };
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
                            for text in [
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
                            ] {
                                row.col(|ui| {
                                    ui.add(
                                        egui::Label::new(&text)
                                            .truncate()
                                            .selectable(false)
                                            .sense(egui::Sense::hover()),
                                    )
                                    .on_hover_text(&text);
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

    fn details(&mut self, ui: &mut egui::Ui) {
        let invocations = self.invocations();
        let invocation = invocations
            .iter()
            .find(|invocation| Some(trace::key(invocation)) == self.selected_event);
        let directory = self.invocation_directory(invocation);
        if let Some((field, offset, data_len)) =
            self.inspector.show(ui, invocation, directory.is_some())
        {
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
                    directory: PathBuf::from(&self.import_directory),
                });
                self.import_open = false;
            }
        }
        if self.download_open {
            let mut open = true;
            let remote = self.snapshot.remote_bases.clone();
            let installed: Vec<String> = self
                .snapshot
                .bases
                .iter()
                .map(|base| base.id.clone())
                .collect();
            let refreshing = self.snapshot.remote_refreshing;
            let remote_error = self.snapshot.remote_error.clone();
            let download = self.snapshot.download.clone();
            let mut request: Option<String> = None;
            let mut refresh = false;
            egui::Window::new("Download base")
                .open(&mut open)
                .collapsible(false)
                .resizable(true)
                .default_size([820.0, 540.0])
                .min_width(600.0)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        if ui.button("Refresh catalog").clicked() {
                            refresh = true;
                        }
                        if refreshing {
                            ui.spinner();
                            ui.label("Fetching catalog…");
                        }
                    });
                    if let Some(error) = &remote_error {
                        ui.colored_label(theme::ERROR, error);
                    }
                    if let Some(status) = &download {
                        let fraction = if status.total > 0 {
                            status.received as f32 / status.total as f32
                        } else {
                            0.0
                        };
                        ui.add(egui::ProgressBar::new(fraction).text(format!(
                            "{} — {} / {}",
                            status.label,
                            human_bytes(status.received),
                            human_bytes(status.total)
                        )));
                        if let Some(error) = &status.error {
                            ui.colored_label(theme::ERROR, error);
                        } else if status.finished {
                            ui.colored_label(theme::GOOD, format!("{} installed", status.label));
                        }
                    }
                    ui.separator();
                    if remote.is_empty() {
                        ui.colored_label(
                            theme::MUTED,
                            "No bases listed yet — refresh the catalog.",
                        );
                    }
                    let busy = download.as_ref().is_some_and(|status| !status.finished);
                    egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    for base in &remote {
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&base.label).strong());
                                let kind = if base.kind.is_empty() {
                                    "base"
                                } else {
                                    &base.kind
                                };
                                let short = &base.identity[..12.min(base.identity.len())];
                                ui.small(format!(
                                    "{} · {} · {} · {} · {}",
                                    base.kernel_version,
                                    RevisionStatus::describe(
                                        base.revision,
                                        base.min_app_version.as_deref()
                                    ),
                                    kind,
                                    human_bytes(base.total_size),
                                    short
                                ));
                            });
                            let newer = RevisionStatus::of_base(
                                base.revision,
                                base.min_app_version.as_deref(),
                            ) == RevisionStatus::NeedsNewerApp;
                            if installed.contains(&base.identity) {
                                ui.colored_label(theme::GOOD, "installed");
                            } else if ui
                                .add_enabled(!busy && !newer, egui::Button::new("Download"))
                                .on_disabled_hover_text(if newer {
                                    format!(
                                        "Built for a newer Antinomie (this is Antinomie {APP_VERSION})"
                                    )
                                } else {
                                    "Another download is in progress".to_string()
                                })
                                .clicked()
                            {
                                request = Some(base.identity.clone());
                            }
                        });
                    }
                    });
                });
            self.download_open = open;
            if refresh {
                self.send(Command::RefreshRemoteBases);
            }
            if let Some(identity) = request {
                self.send(Command::DownloadBase { identity });
            }
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
                            ui.label(RichText::new("Guest contract revision").color(theme::MUTED));
                            ui.label(APP_REVISION.to_string());
                            ui.end_row();
                            ui.label(RichText::new("Kernel patch series").color(theme::MUTED));
                            ui.label(antinomie_monitor_core::build::series_short());
                            ui.end_row();
                            ui.label(RichText::new("Guest kernel").color(theme::MUTED));
                            ui.label("Linux 6.12.94 (Debian 6.12.94-1 source)");
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
                        if ui.checkbox(&mut self.draft.nat, "NAT network").changed()
                            && self.draft.nat
                        {
                            self.draft.nat = false;
                            nat = true;
                        }
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
                    }
                    if let Some(error) = &form_error {
                        ui.add(egui::Label::new(egui::RichText::new(error).color(theme::WARN)).wrap());
                    }
                });
            });
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
            egui::Window::new("Launch program")
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .default_width(500.0)
                .default_height(0.0)
                .max_width(540.0)
                .max_height((ctx.screen_rect().height() - 90.0).max(200.0))
                .show(ctx, |ui| {
                    scroll_dialog(ui, ctx, |ui| {
                        self.launch_form(ui);
                    });
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

    pub(crate) fn panel_title(&self, panel: &Panel) -> String {
        match panel {
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
        self.options.bundle_dir = PathBuf::from(&self.settings.bundle);
        self.send(Command::UpdateOptions {
            bundle_dir: PathBuf::from(&self.settings.bundle),
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

fn base_choice_label(base: &BaseSummary) -> String {
    let label = if base.fixed_display {
        base.label.clone()
    } else {
        format!("{} (legacy)", base.label)
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
            *path = (!text.trim().is_empty()).then(|| PathBuf::from(&text));
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
            build_wizard: build_wizard::BuildWizard::default(),
            name_action: None,
            filter: String::new(),
            trace_sort: None,
            selected_event: None,
            selected_run: None,
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
        }
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
    fn base_labels_name_outdated_newer_and_unrecorded_revisions() {
        let mut base = base_summary_for_revision(Some(APP_REVISION));
        assert_eq!(base_choice_label(&base), "Debian");
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
            .filter(|(text, _)| text.ends_with("Linux 6.12.94"))
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
            "Linux 6.12.94 (legacy)"
        );
        app.snapshot.bases[1].fixed_display = true;
        assert_eq!(base_choice_label(&app.snapshot.bases[1]), "Linux 6.12.94");
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
}

use crate::{
    archive::{Answer, ArchiveWorker, Request},
    runs::RunTerminal,
    theme,
    trace::{self, Inspector, InvocationKey},
};
use antinomie_monitor_core::{
    pair_events, Backend, BackendOptions, Command, ExecRequest, InvocationSummary, Notification,
    RunState, RunSummary, Snapshot, TerminalRecord, VmConfig, VmState,
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
enum Workspace {
    Details,
    Activity,
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

pub struct MonitorApp {
    backend: Option<Backend>,
    snapshot: Snapshot,
    selected: Option<String>,
    settings: Settings,
    settings_open: bool,
    create_open: bool,
    config_open: bool,
    launch_open: bool,
    upload_open: bool,
    draft: VmConfig,
    confirm: Option<Confirm>,
    status: String,
    filter: String,
    selected_event: Option<InvocationKey>,
    selected_run: Option<String>,
    run_filter: RunFilter,
    terminals: BTreeMap<String, RunTerminal>,
    archive: Option<ArchiveWorker>,
    pending_archive: Option<Request>,
    data_root: PathBuf,
    history: Vec<RunSummary>,
    history_path: String,
    archive_generation: u64,
    archive_page: Vec<InvocationSummary>,
    archive_offset: u64,
    archive_next: Option<u64>,
    archive_previous: Vec<u64>,
    archive_pending: bool,
    archive_error: Option<String>,
    inspector: Inspector,
    tab: Workspace,
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
        let data_root = options.data_dir.clone();
        options.bundle_dir = PathBuf::from(&settings.bundle);
        options.capture_quota_size = u64::from(settings.quota_gib) * 1024 * 1024 * 1024;
        options.shutdown_timeout = Duration::from_secs(settings.timeout);
        let (backend, status) = match Backend::new(options) {
            Ok(backend) => (Some(backend), String::new()),
            Err(error) => (None, error),
        };
        let exec = ExecRequest::default();
        let env = exec.env.join("\n");
        let mut app = Self {
            backend,
            snapshot: Snapshot::default(),
            selected: None,
            settings,
            settings_open: false,
            create_open: false,
            config_open: false,
            launch_open: false,
            upload_open: false,
            draft: VmConfig::default(),
            confirm: None,
            status,
            filter: String::new(),
            selected_event: None,
            selected_run: None,
            run_filter: RunFilter::All,
            terminals: BTreeMap::new(),
            archive: None,
            pending_archive: None,
            data_root,
            history: Vec::new(),
            history_path: String::new(),
            archive_generation: 0,
            archive_page: Vec::new(),
            archive_offset: 0,
            archive_next: None,
            archive_previous: Vec::new(),
            archive_pending: false,
            archive_error: None,
            inspector: Inspector::default(),
            tab: Workspace::Details,
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
        };
        match ArchiveWorker::new() {
            Ok(worker) => {
                app.archive = Some(worker);
                app.refresh_history();
            }
            Err(error) => app.status = format!("Archive worker: {error}"),
        }
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
                            run.state != RunState::Finalized
                                && !self.terminals.contains_key(&run.id)
                        });
                        sync_runs(&mut self.terminals, &snapshot.runs);
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
                        sync_runs(&mut self.terminals, &[run]);
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
        if available_terminal_slots(&self.terminals) == 0 {
            return Err(terminal_capacity_message());
        }
        Ok(())
    }

    fn new_image(&mut self) {
        self.draft = VmConfig::default();
        self.draft.name = "New VM".into();
        self.create_open = true;
    }

    fn new_run(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.send(Command::Start { vm_id });
        }
    }

    fn configure_vm(&mut self) {
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
        (!self.snapshot.runs.iter().any(|live| &live.id == id) || run.state == RunState::Finalized)
            .then_some(run)
    }

    fn refresh_history(&mut self) {
        self.queue_archive(Request::List(self.data_root.clone()));
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
        let live = self
            .snapshot
            .runs
            .iter()
            .any(|live| live.id == run.id && live.state != RunState::Finalized);
        let reserved = usize::from(self.pending_launch.is_some());
        let consumes_slot = self
            .terminals
            .get(&run.id)
            .is_none_or(|terminal| !terminal.open && terminal.run.state == RunState::Finalized);
        if consumes_slot && available_terminal_slots(&self.terminals) <= reserved {
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
                .find(|(_, terminal)| !terminal.open && terminal.run.state == RunState::Finalized)
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

    fn run_list(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Programs");
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Refresh retained runs",
                true,
            ) {
                self.refresh_history();
            }
        });
        ui.horizontal_wrapped(|ui| {
            for (filter, label) in [
                (RunFilter::All, "All"),
                (RunFilter::Live, "Live"),
                (RunFilter::Past, "Past"),
            ] {
                ui.selectable_value(&mut self.run_filter, filter, label);
            }
        });
        if self.run_filter != RunFilter::Past
            && ui
                .selectable_label(self.selected_run.is_none(), "All live runs")
                .clicked()
        {
            self.select_run(None);
        }
        let mut runs = self.snapshot.runs.clone();
        runs.extend(
            self.history
                .iter()
                .filter(|run| !self.snapshot.runs.iter().any(|live| live.id == run.id))
                .cloned(),
        );
        runs.retain(|run| match self.run_filter {
            RunFilter::All => true,
            RunFilter::Live => self
                .snapshot
                .runs
                .iter()
                .any(|live| live.id == run.id && live.state != RunState::Finalized),
            RunFilter::Past => !self
                .snapshot
                .runs
                .iter()
                .any(|live| live.id == run.id && live.state != RunState::Finalized),
        });
        egui::ScrollArea::vertical()
            .id_salt("program_runs")
            .max_height((ui.available_height() - 92.0).max(40.0))
            .auto_shrink([false, true])
            .show(ui, |ui| {
                if runs.is_empty() {
                    ui.colored_label(theme::MUTED, "No runs");
                }
                for run in runs {
                    let live = self
                        .snapshot
                        .runs
                        .iter()
                        .any(|live| live.id == run.id && live.state != RunState::Finalized);
                    ui.push_id(&run.id, |ui| {
                        let label = format!("{} / {}", run.pid, run.request.path);
                        if ui
                            .add_sized(
                                [ui.available_width(), self.settings.font_size + 12.0],
                                egui::Button::new(label)
                                    .frame(false)
                                    .selected(self.selected_run.as_ref() == Some(&run.id))
                                    .truncate(),
                            )
                            .on_hover_text(format!(
                                "{}\nRun {}\nRoot task {}\n{:?}",
                                run.request.path, run.id, run.root_task_cookie, run.state
                            ))
                            .clicked()
                        {
                            self.select_run(Some(run.id.clone()));
                        }
                        ui.horizontal(|ui| {
                            if icon(
                                ui,
                                egui_phosphor::regular::TERMINAL_WINDOW,
                                "Reopen terminal",
                                true,
                            ) {
                                self.reopen(run.clone());
                            }
                            if icon(
                                ui,
                                egui_phosphor::regular::STOP,
                                "Stop this run and tracked descendants",
                                live && run.state != RunState::StopRequested && !self.closing,
                            ) {
                                self.send(Command::StopRun {
                                    run_id: run.id.clone(),
                                });
                            }
                            ui.add(
                                egui::Label::new(
                                    RichText::new(format!("{:?}", run.state))
                                        .small()
                                        .color(theme::MUTED),
                                )
                                .truncate(),
                            )
                            .on_hover_text(
                                if run.terminal_eof && live {
                                    "PTY closed; descendants may still run"
                                } else {
                                    ""
                                },
                            );
                        });
                        if let Some(error) = &run.recording_error {
                            ui.add(
                                egui::Label::new(RichText::new(error).small().color(theme::WARN))
                                    .truncate(),
                            )
                            .on_hover_text(error);
                        }
                    });
                }
            });
        ui.separator();
        ui.add(
            egui::TextEdit::singleline(&mut self.history_path)
                .hint_text("Archive directory")
                .desired_width(ui.available_width()),
        );
        if ui.button("Open archive").clicked() && !self.history_path.trim().is_empty() {
            let directory = PathBuf::from(self.history_path.trim());
            // A synthetic view identity keeps direct-path archives independent of the live VM.
            let id = format!("archive:{}", directory.display());
            if !self.history.iter().any(|run| run.id == id) {
                if self.history.len() >= 1024 {
                    self.history.remove(0);
                }
                self.history.push(RunSummary {
                    id: id.clone(),
                    vm_id: String::new(),
                    boot_id: String::new(),
                    session_id: 0,
                    root_task_cookie: 0,
                    pid: 0,
                    request: ExecRequest {
                        path: directory
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_else(|| "Archive".into()),
                        ..ExecRequest::default()
                    },
                    directory,
                    terminal_eof: true,
                    state: RunState::Finalized,
                    recording_error: None,
                });
            }
            self.select_run(Some(id));
        }
    }

    fn handle_archive_answer(&mut self, answer: Answer) {
        match answer {
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
                    && self
                        .snapshot
                        .runs
                        .iter()
                        .any(|run| run.id == terminal.run.id && run.state != RunState::Finalized)
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

    fn terminal_windows(&mut self, ctx: &egui::Context) {
        let mut commands = Vec::new();
        for (id, terminal) in &mut self.terminals {
            if !terminal.open {
                continue;
            }
            let live = self
                .snapshot
                .runs
                .iter()
                .any(|run| &run.id == id && run.state != RunState::Finalized);
            let interactive = live && terminal.interactive() && !self.closing;
            let state = if terminal.snapshot_error.is_some() {
                "resync failed"
            } else if terminal.dirty {
                "resync pending"
            } else if terminal
                .replay_error
                .as_ref()
                .is_some_and(|error| error.starts_with("Final terminal screen unavailable"))
            {
                "history, snapshot unavailable"
            } else if terminal.replay_error.is_some() {
                "history error"
            } else if terminal.replay_offset.is_some() || terminal.replay_pending {
                "loading history"
            } else if !live {
                "history, read only"
            } else if terminal.run.terminal_eof {
                "PTY closed"
            } else {
                "live"
            };
            let title = format!(
                "{} / PID {} / {} [{}]",
                terminal.run.request.path, terminal.run.pid, id, state
            );
            ctx.show_viewport_immediate(
                egui::ViewportId::from_hash_of(("program-terminal", id)),
                egui::ViewportBuilder::default()
                    .with_title(title)
                    .with_inner_size([820.0, 520.0])
                    .with_min_inner_size([320.0, 180.0]),
                |ctx, class| {
                    commands.extend(show_terminal_viewport(
                        ctx,
                        class,
                        terminal,
                        live,
                        interactive,
                    ));
                },
            );
        }
        for command in commands {
            self.send(command);
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
                        for (view, label) in [
                            (Workspace::Details, "Details"),
                            (Workspace::Activity, "Activity"),
                        ] {
                            if ui.button(label).clicked() {
                                self.tab = view;
                                ui.close_menu();
                            }
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
                ui.horizontal(|ui| {
                    let button_width =
                        ui.spacing().interact_size.y + ui.spacing().button_padding.x * 2.0;
                    let title_width =
                        (ui.available_width() - button_width - ui.spacing().item_spacing.x)
                            .max(0.0);
                    ui.add_sized(
                        [title_width, ui.spacing().interact_size.y],
                        egui::Label::new(RichText::new("Virtual machines").strong()).truncate(),
                    )
                    .on_hover_text("Virtual machines");
                    if icon(
                        ui,
                        egui_phosphor::regular::PLUS,
                        "New VM",
                        self.snapshot.active_vm.is_none(),
                    ) {
                        self.new_image();
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("vm_list")
                    .max_height((ui.available_height() * 0.27).max(60.0))
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
                            if ui
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
                                ))
                                .clicked()
                            {
                                self.selected = Some(vm.id.clone());
                            }
                        }
                    });
                ui.separator();
                self.run_list(ui);
            });
    }

    fn health(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("health")
            .frame(theme::frame(theme::RAISED))
            .show(ctx, |ui| {
                let health = &self.snapshot.health;
                ui.add_space(3.0);
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("{:?}", self.snapshot.state));
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

    fn bottom_panel(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("inspection")
            .default_height(260.0)
            .min_height(130.0)
            .max_height((ctx.screen_rect().height() * 0.6).max(130.0))
            .resizable(true)
            .frame(theme::frame(theme::BG))
            .show(ctx, |ui| {
                ui.set_min_height(ui.max_rect().height());
                ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
                ui.horizontal(|ui| {
                    for (target, label) in [
                        (Workspace::Details, "Details"),
                        (Workspace::Activity, "Activity"),
                    ] {
                        workspace_tab(ui, &mut self.tab, target, label, true);
                    }
                });
                ui.separator();
                match self.tab {
                    Workspace::Details => self.details(ui),
                    Workspace::Activity => self.activity(ui),
                }
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
                let Some(event) = invocation.entry.as_ref().or(invocation.exit.as_ref()) else {
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
                        for label in [
                            "Time",
                            "Sequence",
                            "TID",
                            "CPU",
                            "Syscall (number)",
                            "Return",
                            "Info",
                        ] {
                            header.col(|ui| {
                                ui.add(egui::Label::new(RichText::new(label).strong()).truncate())
                                    .on_hover_text(label);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(height, invocations.len(), |mut row| {
                            let invocation = &invocations[row.index()];
                            let event = invocation
                                .entry
                                .as_ref()
                                .or(invocation.exit.as_ref())
                                .expect("filtered phase");
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
        if self.create_open || self.config_open {
            let creating = self.create_open;
            let mut open = true;
            let mut save = false;
            let mut reset = false;
            let mut delete = false;
            let mut nat = false;
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
                    ui.add_enabled_ui(editable, |ui| {
                        egui::Grid::new("vm_config")
                            .num_columns(2)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
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
                                    egui::DragValue::new(&mut self.draft.ram_mib).range(256..=3072),
                                );
                                ui.end_row();
                                ui.label("Disk (GiB)");
                                if creating {
                                    ui.add(
                                        egui::DragValue::new(&mut self.draft.disk_gib)
                                            .range(1..=2048),
                                    );
                                } else {
                                    ui.label(self.draft.disk_gib.to_string());
                                }
                                ui.end_row();
                                if creating {
                                    ui.label("Base directory");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.settings.bundle)
                                            .desired_width(280.0),
                                    );
                                    ui.end_row();
                                }
                            });
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
                        ui.horizontal(|ui| {
                            save = ui
                                .add_enabled(
                                    !self.draft.name.trim().is_empty(),
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
                });
            });
            self.create_open = creating && open;
            self.config_open = !creating && open;
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
                    self.update_options();
                    self.send(Command::Create(self.draft.clone()));
                } else {
                    self.send(Command::Save(self.draft.clone()));
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
                            ui.label("Base artifact directory");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.settings.bundle)
                                    .desired_width(400.0),
                            );
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
                Confirm::Delete(_) => "Delete this VM and its disk? All VM disk data will be lost.",
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
                            Confirm::Reset(_) | Confirm::Delete(_) => {
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
                                self.send(Command::Save(vm));
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
        self.bottom_panel(ctx);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(ctx, |ui| {
                self.events(ui);
            });
        self.dialogs(ctx);
        self.terminal_windows(ctx);
    }

    fn update_options(&mut self) {
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
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(backend) = &mut self.backend {
            if let Err(error) = backend.shutdown() {
                eprintln!("shutdown failed: {error}");
            }
        }
    }
}

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

fn available_terminal_slots(terminals: &BTreeMap<String, RunTerminal>) -> usize {
    let reclaimable = terminals
        .values()
        .filter(|terminal| !terminal.open && terminal.run.state == RunState::Finalized)
        .count();
    TERMINAL_VIEW_LIMIT.saturating_sub(terminals.len().saturating_sub(reclaimable))
}

fn resolve_launch_result(pending: &mut Option<u64>, id: u64, success: bool) {
    // Success retains the reserved view until RunStarted or the snapshot supplies its run.
    if !success && *pending == Some(id) {
        *pending = None;
    }
}

fn sync_runs(terminals: &mut BTreeMap<String, RunTerminal>, runs: &[RunSummary]) {
    for run in runs {
        if let Some(terminal) = terminals.get_mut(&run.id) {
            terminal.run = run.clone();
            if run.state == RunState::Finalized && terminal.dirty {
                terminal.begin_replay();
            }
        } else if run.state != RunState::Finalized {
            if terminals.len() >= TERMINAL_VIEW_LIMIT {
                let reclaim = terminals
                    .iter()
                    .find(|(_, terminal)| {
                        !terminal.open && terminal.run.state == RunState::Finalized
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

fn workspace_tab(
    ui: &mut egui::Ui,
    view: &mut Workspace,
    target: Workspace,
    label: &str,
    enabled: bool,
) {
    let response = ui.add_enabled(
        enabled,
        egui::Button::new(label)
            .frame(false)
            .selected(*view == target)
            .min_size(egui::vec2(60.0, ui.spacing().interact_size.y)),
    );
    if *view == target {
        ui.painter().line_segment(
            [response.rect.left_top(), response.rect.right_top()],
            egui::Stroke::new(2.0_f32, theme::BLUE),
        );
    }
    if response.clicked() {
        *view = target;
    }
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
            settings: Settings::default(),
            settings_open: false,
            create_open: false,
            config_open: false,
            launch_open: false,
            upload_open: false,
            draft: VmConfig::default(),
            confirm: None,
            status: String::new(),
            filter: String::new(),
            selected_event: None,
            selected_run: None,
            run_filter: RunFilter::All,
            terminals: BTreeMap::new(),
            archive: None,
            pending_archive: None,
            data_root: PathBuf::new(),
            history: Vec::new(),
            history_path: String::new(),
            archive_generation: 0,
            archive_page: Vec::new(),
            archive_offset: 0,
            archive_next: None,
            archive_previous: Vec::new(),
            archive_pending: false,
            archive_error: None,
            inspector: Inspector::default(),
            tab: Workspace::Details,
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
        assert_eq!(available_terminal_slots(&app.terminals), 0);
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
        sync_runs(&mut app.terminals, &[launched]);
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
        sync_runs(&mut app.terminals, &[run("launched")]);
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
    fn finalized_dirty_run_and_reopen_replay_archive_with_fresh_generation() {
        let mut app = app();
        let mut finished = run("finished");
        app.snapshot.runs.push(finished.clone());
        app.reopen(finished.clone());
        app.terminals
            .get_mut("finished")
            .unwrap()
            .output(3, b"missing tail", false);
        finished.state = RunState::Finalized;
        sync_runs(&mut app.terminals, &[finished.clone()]);
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
    fn snapshot_recovers_missing_launch_notification_and_preserves_closed_views() {
        let mut app = app();
        let run = run("missed");
        sync_runs(&mut app.terminals, std::slice::from_ref(&run));
        assert!(app.terminals["missed"].open && app.terminals["missed"].dirty);
        let terminal = app.terminals.get_mut("missed").unwrap();
        terminal.output(1, b"kept", false);
        terminal.close_view();
        sync_runs(&mut app.terminals, &[run]);
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

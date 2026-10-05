use crate::{terminal::Terminal, theme};
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig, VmState,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    path::PathBuf,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    bundle: String,
    quota_gib: u32,
    timeout: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            bundle: String::new(),
            quota_gib: 4,
            timeout: 10,
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
    Terminal,
    Activity,
}

struct Activity {
    time: String,
    level: &'static str,
    message: String,
}

const ACTIVITY_LIMIT: usize = 256;

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
    selected_event: Option<(u64, u64, u64, u64)>,
    tab: Workspace,
    activity: VecDeque<Activity>,
    exec: ExecRequest,
    args: String,
    env: String,
    source: String,
    destination: String,
    executable: bool,
    overwrite: bool,
    terminal: Terminal,
    terminal_ready: bool,
    pending_launch: Option<u64>,
    last_poll: Instant,
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
            tab: Workspace::Details,
            activity: VecDeque::new(),
            exec,
            args: String::new(),
            env,
            source: String::new(),
            destination: "/tmp/program".into(),
            executable: false,
            overwrite: false,
            terminal: Terminal::default(),
            terminal_ready: false,
            pending_launch: None,
            last_poll: Instant::now(),
            started: Instant::now(),
            smoke,
            closing: false,
        };
        if !app.status.is_empty() {
            app.log("ERROR", app.status.clone());
        }
        app
    }

    fn send(&mut self, command: Command) {
        let mut failure = None;
        if let Some(backend) = &self.backend {
            let launch = matches!(&command, Command::Execute(_));
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
                        if snapshot.active_vm.is_some()
                            && snapshot.active_vm != self.snapshot.active_vm
                        {
                            self.terminal = Terminal::default();
                            self.terminal_ready = false;
                            self.pending_launch = None;
                        }
                        self.snapshot = snapshot;
                    }
                    Some(Notification::CommandResult {
                        id,
                        success,
                        message,
                    }) => {
                        if self.pending_launch == Some(id) {
                            self.pending_launch = None;
                            if success {
                                self.terminal_ready = true;
                                self.terminal.invalidate_resize();
                                self.tab = Workspace::Terminal;
                            }
                        }
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
                    Some(Notification::Terminal(bytes)) => self.terminal.process(&bytes),
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
    }

    fn running(&self) -> bool {
        self.snapshot.state == VmState::Running && self.snapshot.active_vm == self.selected
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

    fn menus(&mut self, ctx: &egui::Context) {
        let stopped = self.snapshot.active_vm.is_none();
        let selected = self.selected.is_some() && stopped;
        egui::TopBottomPanel::top("menus")
            .exact_height(32.0)
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
                        if ui
                            .add_enabled(
                                self.running() && self.terminal_ready,
                                egui::Button::new("Send SIGINT"),
                            )
                            .clicked()
                        {
                            self.send(Command::Signal { pid: 0, signal: 2 });
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("View", |ui| {
                        for (view, label) in [
                            (Workspace::Details, "Details"),
                            (Workspace::Terminal, "Terminal"),
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
            .exact_height(38.0)
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
                    if icon(
                        ui,
                        egui_phosphor::regular::HAND,
                        "Send SIGINT",
                        self.running() && self.terminal_ready,
                    ) {
                        self.send(Command::Signal { pid: 0, signal: 2 });
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
                    ui.strong("Virtual machines");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon(
                            ui,
                            egui_phosphor::regular::PLUS,
                            "New VM",
                            self.snapshot.active_vm.is_none(),
                        ) {
                            self.new_image();
                        }
                    });
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("vm_list")
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
                                    [ui.available_width(), 30.0],
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
            .default_height(230.0)
            .min_height(130.0)
            .max_height((ctx.screen_rect().height() * 0.65).max(130.0))
            .resizable(true)
            .frame(theme::frame(theme::BG))
            .show(ctx, |ui| {
                ui.set_min_height(ui.max_rect().height());
                ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
                ui.horizontal(|ui| {
                    for (target, label) in [
                        (Workspace::Details, "Details"),
                        (Workspace::Terminal, "Terminal"),
                        (Workspace::Activity, "Activity"),
                    ] {
                        workspace_tab(ui, &mut self.tab, target, label, true);
                    }
                    if self.tab == Workspace::Terminal {
                        ui.separator();
                        if icon(
                            ui,
                            egui_phosphor::regular::ARROW_CLOCKWISE,
                            "Read terminal output",
                            self.running() && self.terminal_ready,
                        ) {
                            self.send(Command::TerminalRead);
                        }
                        if icon(
                            ui,
                            egui_phosphor::regular::HAND,
                            "Send SIGINT",
                            self.running() && self.terminal_ready,
                        ) {
                            self.send(Command::Signal { pid: 0, signal: 2 });
                        }
                    }
                });
                ui.separator();
                match self.tab {
                    Workspace::Details => self.details(ui),
                    Workspace::Terminal => self.terminal_view(ui),
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

    fn terminal_view(&mut self, ui: &mut egui::Ui) {
        let enabled = self.running()
            && self.terminal_ready
            && !self.closing
            && !self.launch_open
            && !self.upload_open
            && !self.settings_open
            && !self.create_open
            && !self.config_open
            && self.confirm.is_none();
        if !enabled {
            ui.label(
                RichText::new(if self.snapshot.active_vm.is_some() && !self.running() {
                    "Select the active VM to use its terminal"
                } else if self.terminal_ready {
                    "Session stopped"
                } else {
                    "No launched program"
                })
                .color(theme::MUTED),
            );
        }
        let (bytes, resize) = self.terminal.show(ui, enabled);
        if !bytes.is_empty() {
            self.send(Command::TerminalInput(bytes));
        }
        if let Some((rows, cols)) = resize {
            if enabled {
                self.send(Command::TerminalResize { rows, cols });
            }
        }
    }

    fn upload(&mut self) {
        self.send(Command::Upload {
            source: PathBuf::from(&self.source),
            destination: self.destination.clone(),
            overwrite: self.overwrite,
            executable: self.executable,
        });
    }

    fn events(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Syscalls");
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .hint_text("Filter")
                    .desired_width(180.0),
            )
            .on_hover_text("Syscall, task, field or issue");
            ui.add(egui::Label::new(format!("{} events", self.snapshot.events.len())).truncate());
        });
        let filter = self.filter.to_lowercase();
        let indices: Vec<usize> = self
            .snapshot
            .events
            .iter()
            .enumerate()
            .filter(|(_, event)| {
                filter.is_empty()
                    || format!(
                        "{} {} {} {:?} {:?}",
                        event.syscall_name,
                        event.tid,
                        event.task_cookie,
                        event.issues,
                        event.fields.iter().map(|f| &f.key).collect::<Vec<_>>()
                    )
                    .to_lowercase()
                    .contains(&filter)
            })
            .map(|(index, _)| index)
            .collect();
        let table_height = (ui.available_height() - 30.0).max(0.0);
        ui.allocate_ui(
            egui::vec2(ui.available_width(), table_height + 30.0),
            |ui| {
                ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
                ui.style_mut().interaction.selectable_labels = false;
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .max_scroll_height(table_height)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false])
                    .column(Column::initial(84.0).at_least(76.0).clip(true))
                    .column(Column::initial(54.0).at_least(40.0).clip(true))
                    .column(Column::initial(110.0).at_least(70.0).clip(true))
                    .column(Column::initial(40.0).at_least(36.0).clip(true))
                    .column(Column::initial(86.0).at_least(60.0).clip(true))
                    .column(Column::remainder().clip(true))
                    .header(30.0, |mut header| {
                        for label in ["Sequence", "TID", "Syscall", "CPU", "Return", "Capture"] {
                            header.col(|ui| {
                                ui.strong(label);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(30.0, indices.len(), |mut row| {
                            let event = &self.snapshot.events[indices[row.index()]];
                            let key = (
                                event.stream_id,
                                event.task_cookie,
                                event.call_id,
                                event.event_seq,
                            );
                            row.set_selected(self.selected_event == Some(key));
                            row.col(|ui| {
                                if ui
                                    .add(
                                        egui::Button::new(event.event_seq.to_string())
                                            .frame(false)
                                            .selected(self.selected_event == Some(key))
                                            .truncate(),
                                    )
                                    .on_hover_text(event.event_seq.to_string())
                                    .clicked()
                                {
                                    self.selected_event = Some(key);
                                }
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(event.tid.to_string()).truncate())
                                    .on_hover_text(format!(
                                        "Task cookie {} / call {} / stream {}",
                                        event.task_cookie, event.call_id, event.stream_id
                                    ));
                            });
                            row.col(|ui| {
                                if ui
                                    .add(
                                        egui::Button::new(&event.syscall_name)
                                            .frame(false)
                                            .selected(self.selected_event == Some(key))
                                            .truncate(),
                                    )
                                    .on_hover_text(&event.syscall_name)
                                    .clicked()
                                {
                                    self.selected_event = Some(key);
                                }
                            });
                            row.col(|ui| {
                                ui.add(egui::Label::new(event.cpu.to_string()).truncate())
                                    .on_hover_text(event.cpu.to_string());
                            });
                            row.col(|ui| {
                                let value = event
                                    .result
                                    .map(|value| value.to_string())
                                    .unwrap_or_else(|| "-".into());
                                ui.add(egui::Label::new(&value).truncate())
                                    .on_hover_text(value);
                            });
                            row.col(|ui| {
                                let color = if event.complete && event.issues.is_empty() {
                                    theme::GOOD
                                } else {
                                    theme::WARN
                                };
                                let label = if event.complete && event.issues.is_empty() {
                                    "Complete".into()
                                } else {
                                    format!("Incomplete {}", event.issues.join(", "))
                                };
                                ui.add(
                                    egui::Label::new(RichText::new(&label).color(color)).truncate(),
                                )
                                .on_hover_text(label);
                            });
                            if row.response().clicked() {
                                self.selected_event = Some(key);
                            }
                        })
                    });
            },
        );
    }

    fn details(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::both().id_salt("detail").show(ui, |ui| {
            if let Some(event) = self.snapshot.events.iter().find(|event| {
                Some((
                    event.stream_id,
                    event.task_cookie,
                    event.call_id,
                    event.event_seq,
                )) == self.selected_event
            }) {
                ui.strong(format!(
                    "{}  /  task {}  /  call {}",
                    event.syscall_name, event.task_cookie, event.call_id
                ));
                ui.label(format!(
                    "Time {} ns  |  phase {}  |  stream {}",
                    event.timestamp_ns, event.phase, event.stream_id
                ));
                if let Some(result) = event.result {
                    ui.monospace(format!("Return: {result}"));
                }
                if let Some(args) = event.args {
                    ui.monospace(format!("args: {:x?}", args));
                }
                for field in &event.fields {
                    ui.separator();
                    ui.strong(format!("{}  ({})", field.key, field.layout));
                    ui.label(format!(
                        "Captured {} / {:?} bytes  |  status {:?}  |  error {}  |  {}",
                        field.captured_len,
                        field.logical_len,
                        field.status,
                        field.capture_error,
                        if field.complete {
                            "Complete"
                        } else {
                            "Incomplete"
                        }
                    ));
                    if let Some(path) = &field.raw_path {
                        ui.label(path.display().to_string());
                    }
                    for (line, bytes) in field.preview.chunks(16).enumerate() {
                        let hex = bytes
                            .iter()
                            .map(|byte| format!("{byte:02x} "))
                            .collect::<String>();
                        let text = bytes
                            .iter()
                            .map(|byte| {
                                if byte.is_ascii_graphic() || *byte == b' ' {
                                    char::from(*byte)
                                } else {
                                    '.'
                                }
                            })
                            .collect::<String>();
                        ui.monospace(format!("{:08x}  {:48}  {}", line * 16, hex, text));
                    }
                }
            } else {
                ui.label("No event selected");
            }
        });
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
        if self.snapshot.state == VmState::Running
            && self.last_poll.elapsed() >= Duration::from_millis(100)
        {
            if let Some(backend) = &self.backend {
                if let Err(error) = backend.send(Command::TerminalRead) {
                    self.status = error;
                }
            }
            self.last_poll = Instant::now();
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

fn icon(ui: &mut egui::Ui, icon: &str, tooltip: &str, enabled: bool) -> bool {
    ui.add_enabled(
        enabled,
        egui::Button::new(RichText::new(icon).size(16.0))
            .frame(false)
            .min_size(egui::vec2(28.0, 28.0)),
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
            .min_size(egui::vec2(60.0, 28.0)),
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
            tab: Workspace::Details,
            activity: VecDeque::new(),
            env: exec.env.join("\n"),
            exec,
            args: String::new(),
            source: String::new(),
            destination: "/tmp/program".into(),
            executable: false,
            overwrite: false,
            terminal: Terminal::default(),
            terminal_ready: false,
            pending_launch: None,
            last_poll: Instant::now(),
            started: Instant::now(),
            smoke: None,
            closing: false,
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
    fn monitor_and_losses_stay_visible_above_and_below_each_inspection_tab() {
        for size in [egui::vec2(800.0, 600.0), egui::vec2(1280.0, 820.0)] {
            for tab in [Workspace::Details, Workspace::Terminal, Workspace::Activity] {
                let ctx = egui::Context::default();
                theme::install(&ctx);
                let mut app = app();
                app.tab = tab;
                app.snapshot.health.dropped = 3;
                app.snapshot.health.persistence_error = Some("disk full".into());
                app.log("ERROR", "disk full".into());
                app.log("INFO", "statistics refreshed".into());
                let _ = render(&mut app, &ctx, size);
                let output = render(&mut app, &ctx, size);
                let texts = texts(&output);
                let rect = |label: &str| {
                    texts
                        .iter()
                        .find(|(text, _)| text == label)
                        .unwrap_or_else(|| panic!("missing visible {label}: {texts:?}"))
                        .1
                };
                assert!(rect("Capture").bottom() < rect("Details").top());
                assert!(rect("Details").bottom() < rect("Transport loss: 3").top());
                assert!(rect("Saving stopped: disk full").bottom() <= size.y);
                for label in [
                    "File",
                    "VM",
                    "Run",
                    "View",
                    "Tools",
                    "Virtual machines",
                    "Syscalls",
                    "Sequence",
                    "TID",
                    "Syscall",
                    "CPU",
                    "Return",
                    "Capture",
                    "Details",
                    "Terminal",
                    "Activity",
                ] {
                    assert!(
                        egui::Rect::from_min_size(egui::Pos2::ZERO, size)
                            .contains_rect(rect(label)),
                        "{label} outside viewport"
                    );
                }
                if tab == Workspace::Activity {
                    assert!(rect("Time").right() < rect("Level").left());
                    assert!(rect("Level").right() < rect("Message").left());
                    assert!(rect("ERROR").right() < rect("disk full").left());
                    assert!(rect("INFO").right() < rect("statistics refreshed").left());
                }
                assert!(!texts.iter().any(|(text, _)| [
                    "Processes",
                    "Rules",
                    "Build output",
                    "Library",
                    "Runs"
                ]
                .contains(&text.as_str())));
            }
        }
    }

    #[test]
    fn long_return_values_do_not_overlap_the_capture_column() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        app.snapshot
            .events
            .push(antinomie_monitor_core::EventSummary {
                stream_id: 1,
                task_cookie: 1,
                call_id: 1,
                event_seq: u64::MAX,
                phase: 2,
                syscall_nr: 9,
                syscall_name: "mmap".into(),
                tid: u32::MAX,
                cpu: 0,
                timestamp_ns: 1,
                args: None,
                result: Some(i64::MAX),
                complete: false,
                issues: vec!["capture content is incomplete".into()],
                fields: Vec::new(),
            });
        let _ = render(&mut app, &ctx, egui::vec2(800.0, 600.0));
        let output = render(&mut app, &ctx, egui::vec2(800.0, 600.0));
        let texts = texts(&output);
        let return_rect = texts
            .iter()
            .find(|(text, _)| text == &i64::MAX.to_string())
            .unwrap()
            .1;
        let capture_rect = texts.iter().find(|(text, _)| text == "Capture").unwrap().1;
        assert!(
            return_rect.right() < capture_rect.left(),
            "Return {return_rect:?}, Capture {capture_rect:?}"
        );
        let pos = egui::pos2(capture_rect.left() + 30.0, return_rect.center().y);
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
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(800.0, 600.0),
                    )),
                    events,
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert_eq!(app.selected_event, Some((1, 1, 1, u64::MAX)));
    }

    #[test]
    fn dialogs_show_all_fields_and_actions_with_fresh_or_restored_small_geometry() {
        for (kind, dialog, labels) in [
            (
                "create",
                "vm_configuration",
                vec![
                    "Name",
                    "CPU count",
                    "RAM (MiB)",
                    "Disk (GiB)",
                    "Base directory",
                    "NAT network",
                    "Create VM",
                ],
            ),
            (
                "config",
                "vm_configuration",
                vec![
                    "Name",
                    "CPU count",
                    "RAM (MiB)",
                    "Disk (GiB)",
                    "NAT network",
                    "Save configuration",
                ],
            ),
            (
                "launch",
                "Launch program",
                vec![
                    "Executable",
                    "Arguments",
                    "Working directory",
                    "Environment",
                    "UID",
                    "GID",
                    "Launch",
                ],
            ),
            (
                "upload",
                "Upload file",
                vec![
                    "Host file",
                    "Guest path",
                    "Executable",
                    "Overwrite existing file",
                    "Upload",
                ],
            ),
            (
                "settings",
                "Recording and base settings",
                vec![
                    "Base artifact directory",
                    "Recording quota (GiB)",
                    "Shutdown timeout (seconds)",
                    "Save settings",
                ],
            ),
        ] {
            for (restored, size) in [
                (false, egui::vec2(800.0, 600.0)),
                (true, egui::vec2(800.0, 600.0)),
                (false, egui::vec2(1280.0, 820.0)),
                (true, egui::vec2(1280.0, 820.0)),
            ] {
                let mut ctx = egui::Context::default();
                theme::install(&ctx);
                if restored {
                    let _ = ctx.run(
                        egui::RawInput {
                            screen_rect: Some(egui::Rect::from_min_size(
                                egui::Pos2::ZERO,
                                egui::vec2(800.0, 600.0),
                            )),
                            ..Default::default()
                        },
                        |ctx| {
                            egui::Window::new(dialog)
                                .id(egui::Id::new(dialog))
                                .fixed_size([420.0, 64.0])
                                .show(ctx, |ui| {
                                    ui.label("Previous geometry");
                                });
                        },
                    );
                    let memory = ctx.memory(Clone::clone);
                    ctx = egui::Context::default();
                    theme::install(&ctx);
                    ctx.memory_mut(|restored_memory| *restored_memory = memory);
                }
                let mut app = app();
                app.exec.uid = u32::MAX;
                app.exec.gid = u32::MAX;
                app.settings.quota_gib = 4096;
                app.settings.timeout = 120;
                match kind {
                    "create" => app.new_image(),
                    "config" => {
                        app.snapshot.vms.push(VmConfig {
                            id: "saved".into(),
                            ..Default::default()
                        });
                        app.selected = Some("saved".into());
                        app.configure_vm();
                    }
                    "launch" => app.launch_open = true,
                    "upload" => app.upload_open = true,
                    _ => app.settings_open = true,
                }
                app.draft.cpus = 64;
                app.draft.ram_mib = 3072;
                app.draft.disk_gib = 2048;
                for _ in 0..3 {
                    let _ = render(&mut app, &ctx, size);
                }
                let output = render(&mut app, &ctx, size);
                let rect = ctx
                    .memory(|memory| memory.area_rect(egui::Id::new(dialog)))
                    .unwrap();
                assert!(
                    rect.left() >= 0.0
                        && rect.top() >= 0.0
                        && rect.right() <= size.x
                        && rect.bottom() <= size.y,
                    "{kind}, restored={restored}: {rect:?}"
                );
                assert!(
                    rect.height() < 400.0,
                    "{kind} has surplus empty space: {rect:?}"
                );
                let visible = texts(&output);
                for label in &labels {
                    let (_, label_rect) = visible.iter().find(|(text, _)| text == label || text.ends_with(&format!(" {label}")))
                        .unwrap_or_else(|| panic!("{kind}, restored={restored}: missing visible {label}, visible={visible:?}"));
                    assert!(
                        rect.contains_rect(*label_rect),
                        "{kind}, restored={restored}: {label} outside dialog"
                    );
                }
                if kind == "launch" {
                    let identities: Vec<_> = visible
                        .iter()
                        .filter(|(text, _)| text == &u32::MAX.to_string())
                        .map(|(_, rect)| *rect)
                        .collect();
                    assert_eq!(identities.len(), 2, "UID and GID must both fit");
                    assert!(identities
                        .iter()
                        .all(|identity| rect.contains_rect(*identity)));
                    assert!(!identities[0].intersects(identities[1]));
                }
            }
        }
    }
}

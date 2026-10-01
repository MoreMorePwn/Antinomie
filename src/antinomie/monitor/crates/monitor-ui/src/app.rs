use crate::{terminal::Terminal, theme};
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig, VmState,
};
use eframe::egui::{self, Color32, RichText};
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
    Upload,
    Nat,
}

#[derive(Clone, Copy, PartialEq)]
enum Workspace {
    Images,
    Syscalls,
    Terminal,
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
    draft: VmConfig,
    confirm: Option<Confirm>,
    status: String,
    filter: String,
    selected_event: Option<(u64, u64, u64, u64)>,
    tab: Workspace,
    activity: VecDeque<Activity>,
    activity_visible: bool,
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
            draft: VmConfig::default(),
            confirm: None,
            status,
            filter: String::new(),
            selected_event: None,
            tab: Workspace::Images,
            activity: VecDeque::new(),
            activity_visible: true,
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
        self.draft.name = "New image".into();
        self.create_open = true;
    }

    fn new_run(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.tab = Workspace::Terminal;
            self.send(Command::Start { vm_id });
        }
    }

    fn menus(&mut self, ctx: &egui::Context) {
        let stopped = self.snapshot.active_vm.is_none();
        let selected = self.selected.is_some() && stopped;
        egui::TopBottomPanel::top("menus")
            .exact_height(28.0)
            .frame(theme::frame(theme::PANEL))
            .show(ctx, |ui| {
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui
                            .add_enabled(stopped, egui::Button::new("New image"))
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
                    ui.menu_button("Image", |ui| {
                        if ui
                            .add_enabled(selected, egui::Button::new("Reset disk to base"))
                            .clicked()
                        {
                            self.confirm = self.selected.clone().map(Confirm::Reset);
                            ui.close_menu();
                        }
                        if ui
                            .add_enabled(selected, egui::Button::new("Delete image and disk"))
                            .clicked()
                        {
                            self.confirm = self.selected.clone().map(Confirm::Delete);
                            ui.close_menu();
                        }
                    });
                    ui.menu_button("Run", |ui| {
                        if ui
                            .add_enabled(selected, egui::Button::new("New run"))
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
                    });
                    ui.menu_button("View", |ui| {
                        for (view, label) in [
                            (Workspace::Images, "Images"),
                            (Workspace::Syscalls, "Syscalls"),
                            (Workspace::Terminal, "Terminal"),
                        ] {
                            if ui
                                .add_enabled(
                                    view == Workspace::Images || self.selected.is_some(),
                                    egui::Button::new(label),
                                )
                                .clicked()
                            {
                                self.tab = view;
                                ui.close_menu();
                            }
                        }
                        ui.separator();
                        ui.checkbox(&mut self.activity_visible, "Activity");
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
            .exact_height(49.0)
            .frame(theme::frame(theme::PANEL))
            .show(ctx, |ui| {
                ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                    let stopped = self.snapshot.active_vm.is_none();
                    if tool(
                        ui,
                        egui_phosphor::regular::PLUS,
                        "New image",
                        "Create a persistent VM image",
                        stopped,
                        true,
                    ) {
                        self.new_image();
                    }
                    if tool(
                        ui,
                        egui_phosphor::regular::SLIDERS_HORIZONTAL,
                        "Settings",
                        "Selected image configuration",
                        self.selected.is_some() && self.snapshot.active_vm != self.selected,
                        false,
                    ) {
                        self.tab = Workspace::Images;
                    }
                    ui.separator();
                    if tool(
                        ui,
                        egui_phosphor::regular::PLAY,
                        "New run",
                        "Start selected image in QEMU",
                        self.selected.is_some() && stopped,
                        false,
                    ) {
                        self.new_run();
                    }
                    if tool(
                        ui,
                        egui_phosphor::regular::STOP,
                        "Stop",
                        "Shut down the current VM",
                        !stopped,
                        false,
                    ) {
                        self.send(Command::Stop);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(if stopped {
                                "No active session".into()
                            } else {
                                format!("{:?}", self.snapshot.state)
                            })
                            .color(theme::MUTED),
                        );
                        ui.colored_label(
                            if self.running() {
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
            .default_width(246.0)
            .min_width(190.0)
            .max_width(320.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(34, 36, 40))
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ctx, |ui| {
                ui.add_space(2.0);
                ui.strong("Library");
                ui.separator();
                if library_row(
                    ui,
                    egui_phosphor::regular::HARD_DRIVES,
                    "Images",
                    self.snapshot.vms.len(),
                    self.tab == Workspace::Images,
                ) {
                    self.tab = Workspace::Images;
                }
                if self.snapshot.vms.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new("       No images").color(theme::MUTED));
                }
                for vm in &self.snapshot.vms {
                    ui.indent(&vm.id, |ui| {
                        if ui
                            .selectable_label(self.selected.as_ref() == Some(&vm.id), &vm.name)
                            .clicked()
                        {
                            self.selected = Some(vm.id.clone());
                            self.tab = Workspace::Images;
                        }
                    });
                }
                ui.add_space(18.0);
                let run_count = usize::from(
                    self.snapshot.active_vm.is_some() || self.snapshot.capture_dir.is_some(),
                );
                if library_row(
                    ui,
                    egui_phosphor::regular::TERMINAL_WINDOW,
                    "Runs",
                    run_count,
                    self.tab != Workspace::Images,
                ) && run_count > 0
                {
                    self.tab = if self.snapshot.active_vm.is_some() {
                        Workspace::Terminal
                    } else {
                        Workspace::Syscalls
                    };
                }
                if run_count == 0 {
                    ui.label(RichText::new("       No runs").color(theme::MUTED));
                } else {
                    ui.indent("run", |ui| {
                        if ui
                            .selectable_label(
                                self.tab != Workspace::Images,
                                if self.snapshot.active_vm.is_some() {
                                    "Current session"
                                } else {
                                    "Last recording"
                                },
                            )
                            .clicked()
                        {
                            self.tab = if self.snapshot.active_vm.is_some() {
                                Workspace::Terminal
                            } else {
                                Workspace::Syscalls
                            };
                        }
                        if let Some(path) = &self.snapshot.capture_dir {
                            ui.label(
                                RichText::new(
                                    path.file_name().unwrap_or_default().to_string_lossy(),
                                )
                                .small()
                                .color(theme::MUTED),
                            )
                            .on_hover_text(path.display().to_string());
                        }
                    });
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(RichText::new("Local workspace").small().color(theme::MUTED));
                    ui.separator();
                });
            });
    }

    fn health(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("health")
            .frame(theme::frame(theme::RAISED))
            .show(ctx, |ui| {
                let health = &self.snapshot.health;
                ui.add_space(3.0);
                ui.style_mut()
                    .text_styles
                    .insert(egui::TextStyle::Body, egui::FontId::proportional(11.0));
                ui.horizontal_wrapped(|ui| {
                    ui.label(if self.closing {
                        "Closing"
                    } else if self.snapshot.state == VmState::Failed {
                        "Failed"
                    } else if self.snapshot.active_vm.is_none() {
                        "Idle"
                    } else if self.snapshot.state == VmState::Running {
                        "Connected"
                    } else if self.snapshot.state == VmState::Starting {
                        "Starting"
                    } else {
                        "Stopping"
                    });
                    ui.separator();
                    ui.label(format!("Images: {}", self.snapshot.vms.len()));
                    ui.label(format!("Events: {}", self.snapshot.events.len()));
                    let loss = health.dropped.saturating_add(health.ui_dropped);
                    ui.colored_label(
                        if loss == 0 { theme::GOOD } else { theme::WARN },
                        format!(
                            "Transport loss: {} / UI: {}",
                            health.dropped, health.ui_dropped
                        ),
                    );
                    ui.colored_label(
                        if health.storage_dropped_packets > 0 || health.persistence_error.is_some()
                        {
                            theme::WARN
                        } else {
                            theme::GOOD
                        },
                        format!("Storage loss: {}", health.storage_dropped_packets),
                    );
                    ui.label(format!("Parser: {}", health.parser_errors));
                    ui.label(format!(
                        "Disk: {:.1}/{} GiB",
                        health.persisted_len as f64 / 1073741824.0,
                        self.settings.quota_gib
                    ));
                    ui.label(format!(
                        "Packets {}/{}",
                        health.persisted_packets, health.received_packets
                    ))
                    .on_hover_text("Raw packets saved / received");
                    ui.label(if self.snapshot.state == VmState::Running {
                        "Guest: BusyBox / 6.12.94"
                    } else {
                        "Guest: disconnected"
                    })
                    .on_hover_text(format!(
                        "Replies stalled {} / transport {:#x}",
                        health.reply_stalls, health.transport_health
                    ));
                });
                if let Some(error) = &health.persistence_error {
                    ui.colored_label(theme::ERROR, format!("Saving stopped: {error}"));
                }
                if let Some(error) = &self.snapshot.last_error {
                    ui.add(egui::Label::new(RichText::new(error).color(theme::ERROR)).truncate())
                        .on_hover_text(error);
                }
                if self.closing {
                    ui.label("Waiting for guest shutdown and recording finalization...");
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

    fn activity(&mut self, ctx: &egui::Context) {
        if !self.activity_visible {
            return;
        }
        egui::TopBottomPanel::bottom("activity")
            .default_height(166.0)
            .min_height(64.0)
            .max_height(if ctx.screen_rect().height() < 680.0 {
                125.0
            } else {
                166.0
            })
            .resizable(true)
            .frame(theme::frame(theme::TERMINAL))
            .show(ctx, |ui| {
                ui.set_min_height(ui.max_rect().height());
                ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("Activity  {}", self.activity.len()))
                            .color(theme::TEXT),
                    );
                    ui.add_enabled(false, egui::Button::new("Build output").frame(false))
                        .on_hover_text("Image build tasks are not implemented");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon(ui, egui_phosphor::regular::X, "Hide activity", true) {
                            self.activity_visible = false;
                        }
                        ui.label(
                            RichText::new(if self.snapshot.active_vm.is_some() {
                                "Session active"
                            } else {
                                "No tasks running"
                            })
                            .small()
                            .color(theme::MUTED),
                        );
                    });
                });
                ui.separator();
                let log_height = (ui.available_height() - 24.0).max(0.0);
                let empty_center = ui.cursor().min
                    + egui::vec2(ui.available_width() * 0.5, 24.0 + log_height * 0.5);
                TableBuilder::new(ui)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .column(Column::exact(112.0))
                    .column(Column::exact(72.0))
                    .column(Column::remainder())
                    .min_scrolled_height(0.0)
                    .max_scroll_height(log_height)
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .header(22.0, |mut header| {
                        for text in ["Time", "Level", "Message"] {
                            header.col(|ui| {
                                ui.label(RichText::new(text).small().color(theme::MUTED));
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(22.0, self.activity.len(), |mut row| {
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
                if self.activity.is_empty() {
                    ui.painter().text(
                        empty_center,
                        egui::Align2::CENTER_CENTER,
                        "No activity to display.",
                        egui::FontId::proportional(12.0),
                        theme::MUTED,
                    );
                }
            });
    }

    fn images(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.strong("Image catalog");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{} images", self.snapshot.vms.len()))
                        .small()
                        .color(theme::MUTED),
                );
            });
        });
        ui.separator();
        if self.snapshot.vms.is_empty() {
            let height = ui.available_height();
            ui.add_space((height * 0.28).max(10.0));
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new(egui_phosphor::regular::HARD_DRIVE)
                        .size(44.0)
                        .color(Color32::from_rgb(120, 137, 158)),
                );
                ui.add_space(12.0);
                ui.heading("No images yet");
                ui.add_space(12.0);
                if tool(
                    ui,
                    egui_phosphor::regular::PLUS,
                    "New image",
                    "Create a persistent VM from base artifacts",
                    true,
                    true,
                ) {
                    self.new_image();
                }
            });
            return;
        }
        egui::ScrollArea::vertical()
            .id_salt("images")
            .show(ui, |ui| {
                for vm in &self.snapshot.vms {
                    ui.horizontal(|ui| {
                        if ui
                            .selectable_label(
                                self.selected.as_ref() == Some(&vm.id),
                                format!("{}  {}", egui_phosphor::regular::HARD_DRIVE, vm.name),
                            )
                            .clicked()
                        {
                            self.selected = Some(vm.id.clone());
                        }
                        ui.label(
                            RichText::new(format!(
                                "{} CPU  /  {} MiB  /  {} GiB",
                                vm.cpus, vm.ram_mib, vm.disk_gib
                            ))
                            .color(theme::MUTED),
                        );
                    });
                }
                ui.separator();
                if let Some(vm) = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| Some(&vm.id) == self.selected.as_ref())
                    .cloned()
                {
                    let mut edit = vm.clone();
                    ui.add_space(12.0);
                    ui.strong("Image configuration");
                    ui.add_space(8.0);
                    ui.add_enabled_ui(self.snapshot.active_vm.as_ref() != Some(&vm.id), |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Name");
                            ui.text_edit_singleline(&mut edit.name);
                        });
                        numeric(ui, "CPU count", &mut edit.cpus, 1..=64);
                        numeric(ui, "RAM (MiB)", &mut edit.ram_mib, 256..=3072);
                        ui.label(format!("Disk: {} GiB", edit.disk_gib));
                        if ui.checkbox(&mut edit.nat, "NAT network").changed() && edit.nat {
                            self.confirm = Some(Confirm::Nat);
                            edit.nat = false;
                            self.draft = edit.clone();
                        }
                        if edit != vm {
                            self.send(Command::Save(edit));
                        }
                        ui.add_space(8.0);
                        ui.horizontal(|ui| {
                            if tool(
                                ui,
                                egui_phosphor::regular::ARROW_COUNTER_CLOCKWISE,
                                "Reset disk",
                                "Reset overlay to base; requires confirmation",
                                true,
                                false,
                            ) {
                                self.confirm = Some(Confirm::Reset(vm.id.clone()));
                            }
                            if tool(
                                ui,
                                egui_phosphor::regular::TRASH,
                                "Delete",
                                "Delete image and overlay; requires confirmation",
                                true,
                                false,
                            ) {
                                self.confirm = Some(Confirm::Delete(vm.id.clone()));
                            }
                        });
                    });
                    ui.add_space(12.0);
                    ui.label(RichText::new("BusyBox  /  Linux 6.12.94").color(theme::MUTED));
                    ui.label(
                        RichText::new(if vm.nat {
                            "Network: NAT"
                        } else {
                            "Network: disconnected"
                        })
                        .color(theme::MUTED),
                    );
                }
            });
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
        let form_height = (ui.available_height() - 130.0).clamp(60.0, 300.0);
        egui::ScrollArea::vertical()
            .id_salt("control_forms")
            .max_height(form_height)
            .show(ui, |ui| {
                egui::CollapsingHeader::new("Launch configuration")
                    .id_salt(("launch_configuration", self.terminal_ready))
                    .default_open(!self.terminal_ready)
                    .show(ui, |ui| {
                        ui.add_enabled_ui(self.running(), |ui| {
                            egui::Grid::new("launch")
                                .num_columns(2)
                                .spacing([14.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label("Executable");
                                    ui.add(
                                        egui::TextEdit::singleline(&mut self.exec.path)
                                            .desired_width(f32::INFINITY),
                                    );
                                    ui.end_row();
                                    ui.label("Arguments");
                                    ui.add(
                                        egui::TextEdit::multiline(&mut self.args)
                                            .desired_rows(2)
                                            .desired_width(f32::INFINITY),
                                    )
                                    .on_hover_text("One argument per line");
                                    ui.end_row();
                                    ui.label("Working directory");
                                    ui.text_edit_singleline(&mut self.exec.cwd);
                                    ui.end_row();
                                    ui.label("Environment");
                                    ui.add(
                                        egui::TextEdit::multiline(&mut self.env)
                                            .desired_rows(2)
                                            .desired_width(f32::INFINITY),
                                    );
                                    ui.end_row();
                                    ui.label("Identity");
                                    ui.horizontal(|ui| {
                                        numeric(ui, "UID", &mut self.exec.uid, 0..=u32::MAX);
                                        numeric(ui, "GID", &mut self.exec.gid, 0..=u32::MAX);
                                    });
                                    ui.end_row();
                                });
                            ui.horizontal(|ui| {
                                if ui
                                    .button(format!("{} Launch", egui_phosphor::regular::PLAY))
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
                                }
                                if icon(
                                    ui,
                                    egui_phosphor::regular::STOP,
                                    "Send SIGINT to launched process",
                                    self.terminal_ready,
                                ) {
                                    self.send(Command::Signal { pid: 0, signal: 2 });
                                }
                            });
                        });
                    });
                egui::CollapsingHeader::new("File upload")
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.add_enabled_ui(self.running(), |ui| {
                            egui::Grid::new("upload").num_columns(2).show(ui, |ui| {
                                ui.label("Host file");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.source)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.end_row();
                                ui.label("Guest path");
                                ui.add(
                                    egui::TextEdit::singleline(&mut self.destination)
                                        .desired_width(f32::INFINITY),
                                );
                                ui.end_row();
                            });
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.executable, "Executable");
                                ui.checkbox(&mut self.overwrite, "Overwrite existing file");
                                if ui
                                    .button(format!(
                                        "{} Upload",
                                        egui_phosphor::regular::UPLOAD_SIMPLE
                                    ))
                                    .clicked()
                                {
                                    if self.overwrite {
                                        self.confirm = Some(Confirm::Upload);
                                    } else {
                                        self.upload();
                                    }
                                }
                            });
                        });
                    });
            });
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Terminal").strong());
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Read terminal output",
                self.running() && self.terminal_ready,
            ) {
                self.send(Command::TerminalRead);
            }
        });
        let (bytes, resize) = self
            .terminal
            .show(ui, self.running() && self.terminal_ready);
        if !bytes.is_empty() {
            self.send(Command::TerminalInput(bytes));
        }
        if let Some((rows, cols)) = resize {
            if self.running() && self.terminal_ready {
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
            ui.label("Filter");
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(280.0))
                .on_hover_text("Syscall, task, field or issue");
            ui.label(format!("{} events", self.snapshot.events.len()));
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
        let table_height = (ui.available_height() * 0.54).max(100.0);
        ui.allocate_ui(
            egui::vec2(ui.available_width(), table_height + 25.0),
            |ui| {
                ui.set_clip_rect(ui.clip_rect().intersect(ui.max_rect()));
                TableBuilder::new(ui)
                    .striped(true)
                    .resizable(true)
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .max_scroll_height(table_height)
                    .min_scrolled_height(0.0)
                    .auto_shrink([false, false])
                    .column(Column::initial(70.0))
                    .column(Column::initial(70.0))
                    .column(Column::initial(140.0))
                    .column(Column::initial(55.0))
                    .column(Column::initial(90.0))
                    .column(Column::remainder())
                    .header(25.0, |mut header| {
                        for label in ["Sequence", "TID", "Syscall", "CPU", "Return", "Capture"] {
                            header.col(|ui| {
                                ui.strong(label);
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(24.0, indices.len(), |mut row| {
                            let event = &self.snapshot.events[indices[row.index()]];
                            let key = (
                                event.stream_id,
                                event.task_cookie,
                                event.call_id,
                                event.event_seq,
                            );
                            row.col(|ui| {
                                if ui
                                    .selectable_label(
                                        self.selected_event == Some(key),
                                        event.event_seq.to_string(),
                                    )
                                    .clicked()
                                {
                                    self.selected_event = Some(key);
                                }
                            });
                            row.col(|ui| {
                                ui.label(event.tid.to_string()).on_hover_text(format!(
                                    "Task cookie {} / call {} / stream {}",
                                    event.task_cookie, event.call_id, event.stream_id
                                ));
                            });
                            row.col(|ui| {
                                if ui
                                    .selectable_label(
                                        self.selected_event == Some(key),
                                        &event.syscall_name,
                                    )
                                    .clicked()
                                {
                                    self.selected_event = Some(key);
                                }
                            });
                            row.col(|ui| {
                                ui.label(event.cpu.to_string());
                            });
                            row.col(|ui| {
                                ui.label(
                                    event
                                        .result
                                        .map(|value| value.to_string())
                                        .unwrap_or_else(|| "-".into()),
                                );
                            });
                            row.col(|ui| {
                                ui.colored_label(
                                    if event.complete && event.issues.is_empty() {
                                        theme::GOOD
                                    } else {
                                        theme::WARN
                                    },
                                    if event.complete && event.issues.is_empty() {
                                        "Complete".into()
                                    } else {
                                        format!("Incomplete {}", event.issues.join(", "))
                                    },
                                );
                            });
                        })
                    });
            },
        );
        ui.separator();
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
        if self.create_open {
            let mut open = true;
            let mut create = false;
            egui::Window::new("New image")
                .collapsible(false)
                .resizable(false)
                .open(&mut open)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Name");
                        ui.text_edit_singleline(&mut self.draft.name);
                    });
                    numeric(ui, "CPU count", &mut self.draft.cpus, 1..=64);
                    numeric(ui, "RAM (MiB)", &mut self.draft.ram_mib, 256..=3072);
                    numeric(ui, "Disk (GiB)", &mut self.draft.disk_gib, 1..=2048);
                    ui.horizontal(|ui| {
                        ui.label("Base artifact directory");
                        ui.text_edit_singleline(&mut self.settings.bundle);
                    });
                    ui.checkbox(&mut self.draft.nat, "NAT network");
                    if self.draft.nat {
                        ui.colored_label(
                            theme::WARN,
                            "NAT permits guest connections to the host network and Internet.",
                        );
                    }
                    create = ui
                        .add_enabled(
                            !self.draft.name.trim().is_empty() && self.snapshot.active_vm.is_none(),
                            egui::Button::new(format!(
                                "{} Create image",
                                egui_phosphor::regular::PLUS
                            ))
                            .fill(theme::PRIMARY),
                        )
                        .clicked();
                });
            self.create_open = open;
            if create {
                self.update_options();
                self.send(Command::Create(self.draft.clone()));
                self.create_open = false;
            }
        }
        if self.settings_open {
            let mut open = true;
            let mut save = false;
            egui::Window::new("Recording and base image")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.add_enabled_ui(self.snapshot.active_vm.is_none(), |ui| {
                        ui.label("Base artifact directory");
                        ui.text_edit_singleline(&mut self.settings.bundle);
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
                        save = ui.button("Save settings").clicked();
                    });
                    if let Some(path) = &self.snapshot.capture_dir {
                        ui.label(format!("Recording: {}", path.display()));
                    }
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
                Confirm::Upload => "Overwrite the chosen guest path with this host file?",
                Confirm::Nat => {
                    "Enable NAT? The guest can connect to the host network and Internet."
                }
            };
            let mut yes = false;
            let mut cancel = false;
            egui::Window::new("Confirm action")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(text);
                    ui.horizontal(|ui| {
                        yes = ui.button("Confirm").clicked();
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
                        Confirm::Upload => self.upload(),
                        Confirm::Nat => {
                            self.draft.nat = true;
                            self.send(Command::Save(self.draft.clone()));
                        }
                    }
                }
            }
            if cancel {
                self.confirm = None;
            }
        }
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
        if self.running() && self.last_poll.elapsed() >= Duration::from_millis(100) {
            if let Some(backend) = &self.backend {
                if let Err(error) = backend.send(Command::TerminalRead) {
                    self.status = error;
                }
            }
            self.last_poll = Instant::now();
        }
        self.menus(ctx);
        self.toolbar(ctx);
        self.health(ctx);
        self.activity(ctx);
        self.sidebar(ctx);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::same(12)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    workspace_tab(ui, &mut self.tab, Workspace::Images, "Images", true);
                    ui.add_enabled(false, egui::Button::new("Processes").frame(false))
                        .on_hover_text("Process view is not implemented");
                    workspace_tab(
                        ui,
                        &mut self.tab,
                        Workspace::Syscalls,
                        "Syscalls",
                        self.selected.is_some(),
                    );
                    ui.add_enabled(false, egui::Button::new("Rules").frame(false))
                        .on_hover_text("Rules are not implemented");
                    workspace_tab(
                        ui,
                        &mut self.tab,
                        Workspace::Terminal,
                        "Terminal",
                        self.selected.is_some(),
                    );
                });
                ui.separator();
                match self.tab {
                    Workspace::Images => self.images(ui),
                    Workspace::Syscalls => self.events(ui),
                    Workspace::Terminal => self.controls(ui),
                }
            });
        self.dialogs(ctx);
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
            .min_size(egui::vec2(26.0, 24.0)),
    )
    .on_hover_text(tooltip)
    .clicked()
}

fn tool(
    ui: &mut egui::Ui,
    icon: &str,
    label: &str,
    tooltip: &str,
    enabled: bool,
    primary: bool,
) -> bool {
    let mut button = egui::Button::new(format!("{icon}  {label}")).min_size(egui::vec2(0.0, 30.0));
    if primary {
        button = button
            .fill(theme::PRIMARY)
            .stroke(egui::Stroke::new(1.0_f32, Color32::from_rgb(83, 123, 166)));
    } else {
        button = button.frame(false);
    }
    ui.add_enabled(enabled, button)
        .on_hover_text(tooltip)
        .clicked()
}

fn library_row(ui: &mut egui::Ui, icon: &str, label: &str, count: usize, selected: bool) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 30.0), egui::Sense::click());
    if selected || response.hovered() {
        ui.painter().rect_filled(
            rect,
            0.0,
            if selected {
                Color32::from_rgb(45, 62, 82)
            } else {
                theme::RAISED
            },
        );
    }
    if selected {
        ui.painter().line_segment(
            [rect.left_top(), rect.left_bottom()],
            egui::Stroke::new(2.0_f32, theme::BLUE),
        );
    }
    ui.painter().text(
        rect.left_center() + egui::vec2(10.0, 0.0),
        egui::Align2::LEFT_CENTER,
        format!("{}  {icon}  {label}", egui_phosphor::regular::CARET_DOWN),
        egui::FontId::proportional(12.0),
        theme::TEXT,
    );
    ui.painter().text(
        rect.right_center() - egui::vec2(10.0, 0.0),
        egui::Align2::RIGHT_CENTER,
        count.to_string(),
        egui::FontId::monospace(11.0),
        theme::MUTED,
    );
    response.clicked()
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

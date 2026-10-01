use crate::terminal::Terminal;
use antinomie_monitor_core::{
    Backend, BackendOptions, Command, ExecRequest, Notification, Snapshot, VmConfig, VmState,
};
use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
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
    tab: u8,
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
        let mut fonts = egui::FontDefinitions::default();
        egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
        cc.egui_ctx.set_fonts(fonts);
        let mut style = (*cc.egui_ctx.style()).clone();
        style.visuals = egui::Visuals::light();
        style.visuals.panel_fill = Color32::from_rgb(242, 244, 246);
        style.visuals.selection.bg_fill = Color32::from_rgb(192, 220, 234);
        style.spacing.item_spacing = egui::vec2(8.0, 5.0);
        style.spacing.button_padding = egui::vec2(8.0, 5.0);
        cc.egui_ctx.set_style(style);
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
        Self {
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
            tab: 0,
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
        }
    }

    fn send(&mut self, command: Command) {
        if let Some(backend) = &self.backend {
            let launch = matches!(&command, Command::Execute(_));
            match backend.send(command) {
                Ok(id) => {
                    if launch {
                        self.pending_launch = Some(id);
                    }
                    self.status = "Request queued".into();
                }
                Err(error) => self.status = error,
            }
        }
    }

    fn drain(&mut self) {
        if let Some(backend) = &self.backend {
            for _ in 0..256 {
                match backend.try_recv() {
                    Some(Notification::Snapshot(snapshot)) => {
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
    }

    fn running(&self) -> bool {
        self.snapshot.state == VmState::Running && self.snapshot.active_vm == self.selected
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Antinomie").strong().size(18.0));
                ui.separator();
                if icon(
                    ui,
                    egui_phosphor::regular::PLUS,
                    "Create VM",
                    self.snapshot.active_vm.is_none(),
                ) {
                    self.draft = VmConfig::default();
                    self.create_open = true;
                }
                let selected = self.selected.clone();
                if icon(
                    ui,
                    egui_phosphor::regular::PLAY,
                    "Start VM",
                    selected.is_some() && self.snapshot.active_vm.is_none(),
                ) {
                    if let Some(vm_id) = selected.clone() {
                        self.send(Command::Start { vm_id });
                    }
                }
                if icon(
                    ui,
                    egui_phosphor::regular::STOP,
                    "Shut down VM",
                    self.snapshot.active_vm.is_some(),
                ) {
                    self.send(Command::Stop);
                }
                ui.separator();
                if icon(
                    ui,
                    egui_phosphor::regular::ARROW_COUNTER_CLOCKWISE,
                    "Reset disk to base image",
                    selected.is_some() && self.snapshot.active_vm.is_none(),
                ) {
                    if let Some(id) = selected.clone() {
                        self.confirm = Some(Confirm::Reset(id));
                    }
                }
                if icon(
                    ui,
                    egui_phosphor::regular::TRASH,
                    "Delete VM and its disk",
                    selected.is_some() && self.snapshot.active_vm.is_none(),
                ) {
                    if let Some(id) = selected {
                        self.confirm = Some(Confirm::Delete(id));
                    }
                }
                if icon(
                    ui,
                    egui_phosphor::regular::GEAR,
                    "Recording and base image settings",
                    true,
                ) {
                    self.settings_open = true;
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("{:?}", self.snapshot.state));
                });
            });
        });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("vms")
            .default_width(210.0)
            .min_width(160.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Virtual machines");
                ui.separator();
                if self.snapshot.vms.is_empty() {
                    ui.label("No virtual machines");
                    if ui.button("Create VM").clicked() {
                        self.create_open = true;
                    }
                }
                for vm in &self.snapshot.vms {
                    let active = self.snapshot.active_vm.as_ref() == Some(&vm.id);
                    if ui
                        .selectable_label(
                            self.selected.as_ref() == Some(&vm.id),
                            RichText::new(&vm.name).strong(),
                        )
                        .clicked()
                    {
                        self.selected = Some(vm.id.clone());
                    }
                    ui.small(format!(
                        "{} CPU  |  {} MiB  |  {} GiB",
                        vm.cpus, vm.ram_mib, vm.disk_gib
                    ));
                    ui.small(if active {
                        "Running"
                    } else if vm.nat {
                        "Stopped / NAT"
                    } else {
                        "Stopped / disconnected"
                    });
                    ui.separator();
                }
                if let Some(vm) = self
                    .snapshot
                    .vms
                    .iter()
                    .find(|vm| Some(&vm.id) == self.selected.as_ref())
                    .cloned()
                {
                    let mut edit = vm.clone();
                    ui.add_space(10.0);
                    ui.label(RichText::new("Configuration").strong());
                    ui.add_enabled_ui(self.snapshot.active_vm.as_ref() != Some(&vm.id), |ui| {
                        ui.text_edit_singleline(&mut edit.name);
                        numeric(ui, "CPU", &mut edit.cpus, 1..=64);
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
                    });
                }
            });
    }

    fn health(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("health").show(ctx, |ui| {
            let health = &self.snapshot.health;
            ui.horizontal_wrapped(|ui| {
                let loss = health.dropped.saturating_add(health.ui_dropped);
                ui.colored_label(
                    if loss == 0 {
                        Color32::from_rgb(30, 120, 75)
                    } else {
                        Color32::from_rgb(180, 65, 35)
                    },
                    format!(
                        "Transport loss {} / UI loss {}",
                        health.dropped, health.ui_dropped
                    ),
                );
                ui.colored_label(
                    if health.storage_dropped_packets > 0 || health.persistence_error.is_some() {
                        Color32::from_rgb(180, 65, 35)
                    } else {
                        Color32::from_rgb(30, 120, 75)
                    },
                    format!("Storage loss {}", health.storage_dropped_packets),
                );
                ui.label(format!("Parser {}", health.parser_errors));
                ui.label(format!(
                    "Capture {:.1} / {} GiB",
                    health.persisted_len as f64 / 1073741824.0,
                    self.settings.quota_gib
                ));
                ui.label(format!(
                    "Packets {}/{}",
                    health.persisted_packets, health.received_packets
                ))
                .on_hover_text("Raw packets saved / received");
                ui.label(format!("Replies stalled {}", health.reply_stalls));
                ui.label(format!("Transport {:#x}", health.transport_health));
            });
            if let Some(error) = &health.persistence_error {
                ui.colored_label(
                    Color32::from_rgb(180, 40, 40),
                    format!("Saving stopped: {error}"),
                );
            }
            if let Some(error) = &self.snapshot.last_error {
                ui.colored_label(Color32::from_rgb(180, 40, 40), error);
            }
            if !self.status.is_empty() {
                ui.label(&self.status);
            }
            if self.closing {
                ui.label("Waiting for guest shutdown and recording finalization...");
            }
        });
    }

    fn controls(&mut self, ui: &mut egui::Ui) {
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
                            .hint_text("One argument per line")
                            .desired_width(f32::INFINITY),
                    );
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
                    true,
                ) {
                    self.send(Command::Signal { pid: 0, signal: 2 });
                }
            });
            ui.separator();
            egui::Grid::new("upload").num_columns(2).show(ui, |ui| {
                ui.label("Host file");
                ui.add(egui::TextEdit::singleline(&mut self.source).desired_width(f32::INFINITY));
                ui.end_row();
                ui.label("Guest path");
                ui.add(
                    egui::TextEdit::singleline(&mut self.destination).desired_width(f32::INFINITY),
                );
                ui.end_row();
            });
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.executable, "Executable");
                ui.checkbox(&mut self.overwrite, "Overwrite existing file");
                if ui
                    .button(format!("{} Upload", egui_phosphor::regular::UPLOAD_SIMPLE))
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
        ui.separator();
        ui.horizontal(|ui| {
            ui.label(RichText::new("Terminal").strong());
            if icon(
                ui,
                egui_phosphor::regular::ARROW_CLOCKWISE,
                "Read terminal output",
                self.running(),
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
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(280.0)
                    .hint_text("Syscall, task, field or issue"),
            );
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
                                        Color32::from_rgb(30, 120, 75)
                                    } else {
                                        Color32::from_rgb(175, 95, 20)
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
            egui::Window::new("Create virtual machine")
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
                            Color32::from_rgb(180, 65, 35),
                            "NAT permits guest connections to the host network and Internet.",
                        );
                    }
                    create = ui
                        .add_enabled(
                            !self.draft.name.trim().is_empty() && self.snapshot.active_vm.is_none(),
                            egui::Button::new("Create VM"),
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
        self.toolbar(ctx);
        self.health(ctx);
        self.sidebar(ctx);
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.selected.is_none() {
                ui.heading("Virtual machines");
                return;
            }
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, 0, "Syscalls");
                ui.selectable_value(&mut self.tab, 1, "Launch and terminal");
            });
            ui.separator();
            if self.tab == 0 {
                self.events(ui);
            } else {
                self.controls(ui);
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
        egui::Button::new(RichText::new(icon).size(18.0)).min_size(egui::vec2(30.0, 28.0)),
    )
    .on_hover_text(tooltip)
    .clicked()
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

// SPDX-License-Identifier: MIT
//! VM configuration, launch and the VM settings dialog.
use super::*;

impl MonitorApp {
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

    pub(super) fn launch_admission(&self) -> Result<(), String> {
        if self.pending_launch.is_some() {
            return Err("A program launch is still pending".into());
        }
        if available_terminal_slots(&self.terminals, &self.snapshot) == 0 {
            return Err(terminal_capacity_message());
        }
        Ok(())
    }

    pub(super) fn new_image(&mut self) {
        self.draft_generation = self.draft_generation.wrapping_add(1);
        self.draft = VmConfig::default();
        self.draft.name = "New VM".into();
        self.draft.base_identity =
            preferred_new_base(&self.snapshot, &self.settings.bundle).map(|base| base.id.clone());
        self.credentials.reset();
        self.create_open = true;
    }

    /// Start a new VM pinned to a specific installed base.
    pub(super) fn new_image_from(&mut self, base_identity: String) {
        self.new_image();
        self.draft.base_identity = Some(base_identity);
    }

    pub(super) fn create_vm(&mut self) -> Result<(), String> {
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

    pub(super) fn create_validation_error(&self, requires_credentials: bool) -> Option<String> {
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

    pub(super) fn save_validation_error(&self, vm: &VmConfig) -> Option<String> {
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

    pub(super) fn fixed_display_error(&self, vm: &VmConfig) -> Option<String> {
        if vm.launch.resolution.dimensions().is_some()
            && !selected_base(&self.snapshot, vm.base_identity.as_deref())
                .is_some_and(|base| base.fixed_display)
        {
            return Some("This base does not support fixed resolutions. Select a refreshed base or choose Auto.".into());
        }
        None
    }

    pub(super) fn save_vm(&mut self, vm: VmConfig) -> Result<(), String> {
        if let Some(error) = self.save_validation_error(&vm) {
            return Err(error);
        }
        self.send(Command::Save(vm));
        Ok(())
    }

    pub(super) fn new_run(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            self.send(Command::Start { vm_id });
        }
    }

    pub(super) fn configure_vm(&mut self) {
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

    pub(super) fn run(&self, id: &str) -> Option<&RunSummary> {
        self.snapshot
            .runs
            .iter()
            .find(|run| run.id == id)
            .or_else(|| self.history.iter().find(|run| run.id == id))
    }

    /// The selected run, when it belongs to the selected VM.
    pub(super) fn selected_vm_run(&self) -> Option<&RunSummary> {
        let run = self.run(self.selected_run.as_ref()?)?;
        (Some(&run.vm_id) == self.selected.as_ref()).then_some(run)
    }

    pub(super) fn offline_run(&self) -> Option<&RunSummary> {
        let run = self.selected_vm_run()?;
        (self.archive_selected || !run_in_live_session(&self.snapshot, run)).then_some(run)
    }

    pub(super) fn capture(&self, id: &str) -> Option<&CaptureSummary> {
        self.snapshot
            .captures
            .iter()
            .chain(&self.capture_history)
            .find(|capture| capture.id == id)
    }

    pub(super) fn can_start_vm(&self) -> bool {
        self.selected.is_some() && self.snapshot.active_vm.is_none()
    }

    pub(super) fn can_stop_vm(&self) -> bool {
        self.snapshot.active_vm.is_some()
    }

    pub(super) fn can_configure_vm(&self) -> bool {
        self.selected.is_some() && self.snapshot.active_vm != self.selected
    }

    pub(super) fn can_stop_capture(&self) -> bool {
        self.observer_supported()
            && self.pending_observer.is_none()
            && self.active_observer().is_some()
    }

    pub(super) fn selected_vm(&self) -> Option<&VmConfig> {
        self.snapshot
            .vms
            .iter()
            .find(|vm| Some(&vm.id) == self.selected.as_ref())
    }

    /// Malware samples > Send and run…: the sample is in the guest; the Run
    /// program window opens with it as the program, to be run as any other
    /// (arguments, user, where it runs, analysis) once the user presses Run.
    pub(super) fn launch_sample(&mut self, run: ExecRequest) {
        self.exec.path = run.path;
        self.exec.uid = run.uid;
        self.exec.gid = run.gid;
        self.exec.cwd = run.cwd;
        self.args = run.args.join("\n");
        self.launch_open = true;
        self.status = "Sample sent: set how it runs, then press Run".into();
    }

    pub(super) fn open_snapshots(&mut self) {
        if let Some(vm) = self.selected_vm().cloned() {
            self.vm_snapshots.bind(&vm.id, &vm.name);
            if self.vm_snapshots.pending.is_none() {
                self.send(Command::RefreshVmSnapshots { vm_id: vm.id });
            }
        }
    }

    pub(super) fn open_vm_directory(&mut self, vm_id: &str) {
        match self
            .snapshot
            .vm_locations
            .iter()
            .find(|location| location.vm_id == vm_id)
        {
            Some(location) => open_directory(&location.disk_directory),
            None => self.status = "VM directory unavailable".into(),
        }
    }

    pub(super) fn launch_form(&mut self, ui: &mut egui::Ui) {
        // Cancel stays usable when the VM stops or a launch is pending; only
        // the form and its actions wait for a running VM.
        let ready = self.running() && self.pending_launch.is_none();
        {
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
            ui.add_enabled_ui(ready, |ui| {
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
            });
            ui.separator();
            if let Some(reason) = selection_error {
                ui.colored_label(theme::error(), reason);
            }
            ui.horizontal(|ui| {
                let run = ui
                    .add_enabled(
                        ready
                            && !self.exec.path.trim().is_empty()
                            && self.exec.analysis.validate().is_ok(),
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
                    ready
                        && self.exec.analysis.enabled
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
        }
    }

    /// New VM / VM configuration: the machine, display and emulation on the
    /// left; storage, the guest account and networking on the right (one
    /// column on a narrow screen). The buttons stay below the form.
    pub(super) fn vm_dialog(&mut self, ctx: &egui::Context) {
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
                            if !app.draft.nat && !app.draft.isolated_network {
                                ui.add(egui::Label::new(RichText::new("Disconnected: network capture is unavailable. Choose Isolated or NAT to capture packets.").color(theme::warn())).wrap());
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

/// A VM state as a word and its color.
pub(super) fn vm_state_word(state: &VmState) -> (&'static str, egui::Color32) {
    match state {
        VmState::Running => ("Running", theme::good()),
        VmState::Starting => ("Starting", theme::warn()),
        VmState::Stopping => ("Stopping", theme::warn()),
        VmState::Failed => ("Failed", theme::error()),
        VmState::Stopped => ("Stopped", theme::muted()),
    }
}

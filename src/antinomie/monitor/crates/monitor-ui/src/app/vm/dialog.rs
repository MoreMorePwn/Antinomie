// SPDX-License-Identifier: GPL-3.0-only
//! The New VM / VM configuration dialog and its option groups (moved out of `vm`).
use super::*;

impl MonitorApp {
    /// New VM / VM configuration: the machine, display and emulation on the
    /// left; storage, the guest account and networking on the right (one
    /// column on a narrow screen). The buttons stay below the form.
    pub(in crate::app) fn vm_dialog(&mut self, ctx: &egui::Context) {
        let creating = self.create_open;
        let mut open = true;
        let mut save = false;
        let mut cancel = false;
        let mut reset = false;
        let mut delete = false;
        let mut credentials_required = false;
        let label_width = form_label_width(ctx);
        let column = label_width + 340.0;
        let screen = crate::title_bar::content_rect(ctx);
        let wide = screen.width() - 60.0 >= column * 2.0 + 24.0;
        let width = if wide {
            column * 2.0 + 24.0
        } else {
            column.min(screen.width() - 60.0)
        };
        crate::widgets::window(if creating {
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
                        if wide {
                            crate::widgets::columns(ui, 2, |columns| {
                                self.vm_machine_column(
                                    &mut columns[0],
                                    creating,
                                    &mut credentials_required,
                                );
                                self.vm_storage_column(
                                    &mut columns[1],
                                    creating,
                                    credentials_required,
                                    &disk_default,
                                );
                            });
                        } else {
                            self.vm_machine_column(ui, creating, &mut credentials_required);
                            self.vm_storage_column(
                                ui,
                                creating,
                                credentials_required,
                                &disk_default,
                            );
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
                crate::activity::inline_only(ui, crate::activity::Level::Warn, error);
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
            self.vm_transport_window(ctx, creating);
        }
        if self.stealth_open && open && !cancel {
            self.vm_stealth_window(ctx, creating);
        }
        let open = open && !cancel;
        if !open {
            self.transport_open = false;
            self.stealth_open = false;
        }
        self.create_open = creating && open;
        self.config_open = !creating && open;
        if !open {
            self.credentials.reset();
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
                    self.report_error(error);
                    return;
                }
            } else if let Err(error) = self.save_vm(self.draft.clone()) {
                self.report_error(error);
                return;
            }
            self.create_open = false;
            self.config_open = false;
        }
    }

    /// The Machine section and the display and emulation options: the left column.
    fn vm_machine_column(
        &mut self,
        ui: &mut egui::Ui,
        creating: bool,
        credentials_required: &mut bool,
    ) {
        let app = self;
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
            ui.add(text_field(&mut app.draft.name).desired_width(crate::theme::edit_width(280.0)));
            ui.end_row();
            ui.label("CPU count");
            ui.add(egui::DragValue::new(&mut app.draft.cpus).range(1..=64))
                .on_hover_text("A real PC has 4 to 16 threads (checks flag 1)");
            ui.end_row();
            ui.label("RAM");
            ui.add(
                egui::DragValue::new(&mut app.draft.ram_mib)
                    .range(min_ram..=antinomie_monitor_core::storage::MAX_RAM_MIB)
                    .suffix(" MiB"),
            )
            .on_hover_text(format!(
                "At least {min_ram} MiB for this base; a real PC has 8 to 32 GiB \
                     (checks flag under 4 GiB)"
            ));
            ui.end_row();
            ui.label("Disk");
            if creating {
                ui.add(
                    egui::DragValue::new(&mut app.draft.disk_gib)
                        .range(min_disk..=2048)
                        .suffix(" GiB"),
                )
                .on_hover_text(format!(
                    "At least {min_disk} GiB for this base; a real PC has 256 GiB \
                         or more (checks flag under 60 GiB); a BusyBox base grows its \
                         filesystem on the first boot (256 GiB: about 400 MiB of image, \
                         two minutes)"
                ));
            } else {
                ui.label(RichText::new(format!("{} GiB", app.draft.disk_gib)).monospace())
                    .on_hover_text("Set when the VM was created");
            }
            ui.end_row();
        });
        vm_section(ui, "Display and emulation");
        form_grid("vm_display", ui).show(ui, |ui| {
            let kvm_problem = app.kvm_problem();
            let arch = base_arch(&app.snapshot, app.draft.base_identity.as_deref());
            launch_options(ui, &mut app.draft.launch, kvm_problem.as_deref(), arch);
            let fallbacks = app.draft_stealth_fallbacks();
            super::stealth::preset_row(
                ui,
                &mut app.draft.stealth,
                &mut app.stealth_open,
                &fallbacks,
                "Edit…",
            );
        });
        super::stealth::launch_advice(ui, &mut app.draft);
    }

    /// Storage, the guest account and networking: the right column.
    fn vm_storage_column(
        &mut self,
        ui: &mut egui::Ui,
        creating: bool,
        credentials_required: bool,
        disk_default: &std::path::PathBuf,
    ) {
        let app = self;
        vm_section(ui, "Storage");
        form_grid("vm_storage", ui).show(ui, |ui| {
            ui.label("Disk parent");
            ui.add_enabled_ui(creating, |ui| {
                directory_input(
                    ui,
                    &mut app.draft.disk_root,
                    disk_default,
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
                app.draft.disk_root.as_ref().unwrap_or(disk_default)
            } else {
                disk_default
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
                            egui::Label::new(RichText::new(path.display().to_string()).monospace())
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
            vm_section(ui, "Guest account");
            form_grid("vm_account", ui).show(ui, |ui| {
                ui.label("Username");
                ui.add(
                    text_field(&mut app.credentials.username)
                        .char_limit(32)
                        .desired_width(crate::theme::edit_width(280.0)),
                );
                ui.end_row();
                ui.label("Password");
                password_input(ui, &mut app.credentials.password, "guest_password");
                ui.end_row();
                ui.label("Confirm password");
                password_input(ui, &mut app.credentials.confirmation, "guest_confirmation");
                ui.end_row();
            });
        }
        vm_section(ui, "Network and telemetry");
        form_grid("vm_network", ui).show(ui, |ui| {
            ui.label("Network");
            const MODES: [&str; 4] = [
                "Disconnected",
                "Isolated",
                "NAT (Internet)",
                "Routed (route per run)",
            ];
            let mut mode = if app.draft.isolated_network {
                1
            } else if app.draft.routed {
                3
            } else if app.draft.nat {
                2
            } else {
                0
            };
            let previous = mode;
            egui::ComboBox::from_id_salt("network-mode")
                .selected_text(MODES[mode])
                .show_ui(ui, |ui| {
                    for (value, label) in MODES.iter().enumerate() {
                        ui.selectable_value(&mut mode, value, *label);
                    }
                });
            if mode != previous {
                app.draft.nat = mode == 2;
                app.draft.isolated_network = mode == 1;
                app.draft.routed = mode == 3;
            }
            ui.end_row();
            ui.label("Transport");
            if ui
                .button("Telemetry transport…")
                .on_hover_text("Guest buffers, never-drop mode and the host event table")
                .clicked()
            {
                app.transport_open = !app.transport_open;
            }
            ui.end_row();
        });
        if app.draft.isolated_network {
            ui.colored_label(theme::muted(), "Isolated: no host or Internet access.");
        }
        if app.draft.routed && !app.draft.isolated_network {
            ui.colored_label(
                theme::muted(),
                "Routed: each run picks a route (Tools > Settings > Network routes).",
            );
        }
        if !app.draft.has_network() {
            ui.colored_label(
                theme::muted(),
                "Disconnected: no network capture. Choose Isolated, Routed or NAT.",
            );
        }
        if app.draft.nat {
            ui.colored_label(
                theme::warn(),
                "NAT: the guest can reach the host network and Internet.",
            );
        }
        if let Some(note) = running_network_note(&app.snapshot, &app.draft) {
            ui.colored_label(note.1, note.0);
        }
    }

    /// The telemetry transport window of the dialog.
    fn vm_transport_window(&mut self, ctx: &egui::Context, creating: bool) {
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

    /// The stealth window of the dialog.
    fn vm_stealth_window(&mut self, ctx: &egui::Context, creating: bool) {
        let editable = creating || self.snapshot.active_vm.as_ref() != Some(&self.draft.id);
        // What the VM's base boots with; none chosen yet offers all.
        let base = selected_base(&self.snapshot, self.draft.base_identity.as_deref()).map_or(
            antinomie_monitor_core::stealth::BaseSupport::all(),
            |base| antinomie_monitor_core::stealth::BaseSupport::from_list(&base.stealth_support),
        );
        let selected = selected_base(&self.snapshot, self.draft.base_identity.as_deref());
        let current = selected.map(|base| base.id.clone());
        let arch = selected.map_or_else(Default::default, BaseSummary::arch);
        let mut fit = super::stealth::Fit::new(
            &self.draft.stealth,
            base,
            &self.snapshot.bases,
            current.as_deref(),
            arch,
            self.draft.launch.fast_emulation,
        );
        super::stealth::window(
            ctx,
            &mut self.stealth_open,
            &mut self.draft.stealth,
            &mut fit,
            &antinomie_monitor_core::stealth::resource_hints(
                self.draft.cpus,
                self.draft.ram_mib,
                self.draft.disk_gib,
            ),
            editable,
            creating,
        );
        if let Some(base) = fit.switch.take() {
            self.draft.base_identity = Some(base);
        }
    }
}

/// Extra room above a VM dialog section that follows another one.
const VM_SECTION_GAP: f32 = 12.0;

/// A section heading of the VM dialog, set apart from the fields above it.
fn vm_section(ui: &mut egui::Ui, title: &str) {
    if ui.min_rect().height() > 1.0 {
        ui.add_space(VM_SECTION_GAP);
    }
    dialog_section(ui, title);
}

fn launch_options(
    ui: &mut egui::Ui,
    launch: &mut VmLaunchOptions,
    kvm_problem: Option<&str>,
    arch: antinomie_monitor_core::GuestArch,
) {
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
    ui.label("VM screen");
    egui::ComboBox::from_id_salt("vm_screen")
        .selected_text(launch.screen.label())
        .width(260.0)
        .show_ui(ui, |ui| {
            for &screen in VmScreen::ALL {
                ui.selectable_value(&mut launch.screen, screen, screen.label());
            }
        })
        .response
        .on_hover_text("Applies at the next start of this VM, not to a running one. No screen runs the VM without any display.");
    ui.end_row();
    // Fullscreen and Fit to window are options of QEMU's own window.
    if launch.screen == VmScreen::QemuWindow {
        ui.label("Window");
        ui.horizontal(|ui| {
            ui.checkbox(&mut launch.fullscreen, "Fullscreen");
            ui.checkbox(&mut launch.fit_to_window, "Fit to window");
        });
        ui.end_row();
    }
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
    if let Some(problem) = kvm_problem
        && launch.acceleration != VmAcceleration::Tcg
    {
        ui.label("");
        ui.vertical(|ui| {
            let fallback = launch.acceleration == VmAcceleration::Default;
            ui.colored_label(
                theme::warn(),
                format!(
                    "KVM is not available on this host ({problem}). {} TCG is much slower (roughly 10 to 50 times).",
                    if fallback {
                        "This VM will start with TCG."
                    } else {
                        "This VM will not start with KVM."
                    }
                ),
            );
            if ui.button("Use TCG for this VM").clicked() {
                launch.acceleration = VmAcceleration::Tcg;
                // The host CPU model needs KVM.
                if launch.cpu_model == VmCpuModel::Host {
                    launch.cpu_model = VmCpuModel::Default;
                }
            }
        });
        ui.end_row();
    }
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
    if arch == antinomie_monitor_core::GuestArch::AARCH64 {
        ui.label("Emulation");
        ui.checkbox(&mut launch.fast_emulation, "Faster emulation (KPTI off)")
            .on_hover_text(
                "Boots the arm64 guest without kernel page-table isolation, which the \
                 emulated CPU runs slowly. A program can notice: a real machine of this CPU \
                 has it. Listed under Still visible in the VM's summary.",
            );
        ui.end_row();
    }
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
    crate::widgets::window("Telemetry transport")
        .id(egui::Id::new("vm_transport"))
        // Beside the top of the VM dialog, not over its buttons.
        .pivot(egui::Align2::CENTER_TOP)
        .default_pos(egui::pos2(ctx.content_rect().center().x, 60.0))
        .open(open)
        .collapsible(false)
        .resizable(false)
        .default_width(440.0)
        .show(ctx, |ui| {
            ui.add_enabled_ui(editable, |ui| {
                transport_options(ui, transport, cpus, tunable)
            });
            if !editable {
                crate::activity::info(ui, "Stop the VM to change these settings.");
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
        crate::activity::info(
            ui,
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
            ui.label("Capture All");
            ui.add_enabled(
                transport.lossless,
                egui::Checkbox::new(
                    &mut transport.capture_all_shed,
                    "Drop telemetry when the host falls behind",
                ),
            )
            .on_hover_text(
                "Under Capture All, drop telemetry while the host falls behind \
                 instead of slowing the guest. Keeps a desktop guest responsive; \
                 the recording loses events. Off: never drop also holds under \
                 Capture All, and the guest runs slower.",
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
             telemetry, so heavy tracing runs slower but nothing is lost, \
             Capture All included unless it may drop when the host falls \
             behind. The event table holds calls still being assembled; \
             finished calls leave it first. Settings apply at the next VM \
             start.",
        )
        .small()
        .color(theme::muted()),
    );
}

fn ring_label(kib: u32) -> String {
    crate::values::short_size(u64::from(kib) * 1024)
}

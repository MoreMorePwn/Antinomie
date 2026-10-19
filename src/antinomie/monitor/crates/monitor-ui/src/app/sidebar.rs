// SPDX-License-Identifier: MIT
//! Sidebar VM list, health and activity log.
use super::*;

impl MonitorApp {
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

    pub(super) fn sidebar(&mut self, ctx: &egui::Context) {
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
                        .max_height(if !self.settings.explorer_collapsed {
                            budget * 0.35
                        } else if self.settings.bases_collapsed {
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
                if !self.settings.bases_collapsed {
                egui::ScrollArea::vertical()
                    .id_salt("base_list")
                    .max_height(if self.settings.explorer_collapsed {
                        ui.available_height() - 40.0
                    } else {
                        ui.available_height() * 0.35
                    }.max(36.0))
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        if self.snapshot.bases_checking {
                            ui.horizontal(|ui| {
                                theme::spinner(ui);
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
                                    if crate::activity::warning(ui, format!("{}: {hint}", base.label))
                                        .interact(egui::Sense::click())
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
                }
                ui.add_space(6.0);
                self.explorer_sidebar(ui);
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
                        open_directory(&base.directory);
                    }
                }
                BaseAction::Delete => self.confirm = Some(Confirm::DeleteBase(identity)),
            }
        }
        if let Some(vm_id) = selected_vm {
            if self.selected.as_ref() != Some(&vm_id) {
                self.selected = Some(vm_id);
                self.clear_history();
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
    pub(super) fn health(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("health")
            .frame(theme::frame(theme::raised()))
            .show(ctx, |ui| {
                let dropped = self.snapshot.health.dropped;
                let attempted = self.snapshot.health.attempted;
                let ui_dropped = self.snapshot.health.ui_dropped;
                let guest_lost = self.snapshot.health.guest_note_lost;
                let storage_dropped = self.snapshot.health.storage_dropped_packets;
                let persisted = self.snapshot.health.persisted_len;
                let quota = self.settings.quota_gib;
                let shedding = self.snapshot.health.shedding;
                let persistence = self.snapshot.health.persistence_error.clone();
                // A backend error is news until a later status message
                // replaces the status text it arrived with.
                let last_error = self
                    .snapshot
                    .last_error
                    .clone()
                    .filter(|_| self.error_status_mark.as_ref() == Some(&self.status));
                let status = self.status.clone();
                let notice = self.status_notice.as_ref().filter(|(_, message)| message == &status).map(|(level, _)| *level);
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
                    ui.monospace(format!("CAP {saved:.1}/{quota} GiB"))
                        .on_hover_text(format!("Capture saved / quota: {saved:.1} / {quota} GiB"));
                    ui.add_space(16.0);
                    let storage_color = if persistence.is_some() {
                        theme::error()
                    } else {
                        loss(storage_dropped)
                    };
                    status_value_rtl(ui, "STL", &storage_dropped.to_string(), storage_color)
                        .on_hover_text(format!("STL — Storage loss\n{storage_dropped} packets could not be retained.{}",
                            persistence.as_ref().map_or(String::new(), |error| format!("\nSaving error: {error}"))));
                    ui.add_space(16.0);
                    status_value_rtl(ui, "UIL", &ui_dropped.to_string(), loss(ui_dropped))
                        .on_hover_text(format!("UIL — User interface loss\n{ui_dropped} preview records could not be delivered to the interface."));
                    ui.add_space(16.0);
                    status_value_rtl(ui, "TRL", &dropped.to_string(), loss(dropped))
                        .on_hover_text(format!("TRL — Transport loss\n{dropped} of {attempted} attempted records could not be handed over by the guest.\nGuest hash and credential records dropped by the tracer: {guest_lost}\nCapture All shedding: {}",
                            if shedding { "dropping events" } else { "off" }));
                    version.on_hover_text(format!("Antinomie {APP_VERSION}"));
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
                            if let Some(level) = notice { crate::activity::compact(ui, level, &status); }
                            else { status_line(ui, egui_phosphor::regular::INFO, &status, theme::info()); }
                        }
                    });
                });
                ui.add_space(3.0);
            });
    }

    pub(super) fn log(&mut self, level: &'static str, message: String) {
        if message == self.status && matches!(level, "WARN" | "ERROR") {
            self.status_notice = Some((
                if level == "ERROR" {
                    crate::activity::Level::Error
                } else {
                    crate::activity::Level::Warn
                },
                message.clone(),
            ));
        }
        self.activity.log(level, message);
    }

    pub(super) fn report_warning(&mut self, message: String) {
        self.status = message.clone();
        self.log("WARN", message);
    }

    pub(super) fn report_error(&mut self, message: String) {
        self.status = message.clone();
        self.log("ERROR", message);
    }

    pub(super) fn activity(&mut self, ui: &mut egui::Ui) {
        self.activity.ingest(ui.ctx());
        self.activity.show(ui);
    }
}

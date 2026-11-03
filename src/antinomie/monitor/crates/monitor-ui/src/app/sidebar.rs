// SPDX-License-Identifier: GPL-3.0-only
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
            None => machine.push(("No base".into(), theme::warn())),
        }
        let fallbacks = self.stealth_fallbacks_of(vm);
        machine.extend([
            (" · ".into(), theme::muted()),
            (vm.cpus.to_string(), number),
            (" CPU · ".into(), theme::muted()),
            (vm.ram_mib.to_string(), number),
            (" MiB".into(), theme::muted()),
        ]);
        let (_, machine_note) = vm.stealth.machine.for_ram(u64::from(vm.ram_mib) << 20);
        if machine_note.is_some() {
            machine.push((" · q35 fallback".into(), theme::warn()));
        }
        if vm.isolated_network {
            machine.push((" · Isolated network".into(), theme::good()));
        } else if vm.network() == antinomie_monitor_core::VmNetwork::Routed {
            machine.push((" · ".into(), theme::muted()));
            machine.push(("Routed".into(), theme::good()));
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
                details: if fallbacks.is_empty() {
                    vec![machine, last]
                } else {
                    // Its own line: the base's label can fill the first.
                    let badge = vec![(
                        format!("{} Profile fallback", egui_phosphor::regular::WARNING),
                        theme::warn(),
                    )];
                    vec![machine, badge, last]
                },
                selected: self.selected.as_ref() == Some(&vm.id),
            },
        );
        response.on_hover_ui(|ui| {
            ui.label(RichText::new(&vm.name).strong());
            match selected_base(&self.snapshot, vm.base_identity.as_deref()) {
                Some(base) => ui.label(format!("Base: {}", base.label)),
                None => ui.colored_label(
                    theme::warn(),
                    "Base unavailable: the base image this VM was made from is not installed",
                ),
            };
            ui.label(format!(
                "{} CPU / {} MiB RAM / {} GiB disk\nNetwork: {}",
                vm.cpus,
                vm.ram_mib,
                vm.disk_gib,
                match vm.network() {
                    antinomie_monitor_core::VmNetwork::Isolated => "isolated",
                    antinomie_monitor_core::VmNetwork::Routed => "routed (a route per run)",
                    antinomie_monitor_core::VmNetwork::Nat => "NAT",
                    antinomie_monitor_core::VmNetwork::Disconnected => "disconnected",
                }
            ));
            for fallback in &fallbacks {
                ui.colored_label(theme::warn(), fallback.summary.as_str());
            }
            if let Some(note) = machine_note {
                ui.colored_label(theme::warn(), note);
            }
            if let Some(last) = self.settings.last_runs.get(&vm.id) {
                ui.label(format!("Latest run: {}", last.program));
            }
            ui.weak("Right-click for actions");
        })
    }

    /// The VMs being created or copied that are not saved yet.
    fn pending_vm_rows(&self) -> Vec<&antinomie_monitor_core::VmWork> {
        self.snapshot
            .vm_work
            .iter()
            .filter(|work| !self.snapshot.vms.iter().any(|vm| vm.id == work.id))
            .collect()
    }

    /// A VM that is still being made: marked Creating with the step it is in.
    fn pending_vm_row(ui: &mut egui::Ui, work: &antinomie_monitor_core::VmWork) {
        let copy = work.copy_of.is_some();
        let word = if copy { "Copying…" } else { "Creating…" };
        let elapsed = crate::time_format::duration_ms(
            crate::time_format::now_ms().saturating_sub(work.started_ms),
        );
        let response = sidebar_row(
            ui,
            SidebarRow {
                mark: (egui_phosphor::regular::CIRCLE_NOTCH, theme::warn()),
                name: &work.name,
                state: Some((word, theme::warn())),
                details: vec![
                    vec![(work.step.clone(), theme::text())],
                    vec![(format!("{elapsed} so far; see Jobs"), theme::muted())],
                ],
                selected: false,
            },
        );
        response.on_hover_ui(|ui| {
            ui.label(RichText::new(&work.name).strong());
            ui.label(match &work.copy_of {
                Some(source) => format!("A copy of {source} is being made."),
                None => "This VM is being created.".to_owned(),
            });
            ui.label(format!("Step: {}", work.step));
            ui.weak(
                "It becomes a normal entry when it is done; the Jobs window shows the progress.",
            );
        });
        // The elapsed time moves while the row is on screen.
        ui.ctx().request_repaint_after(Duration::from_secs(1));
    }

    pub(super) fn sidebar(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        self.note_last_runs();
        let now = unix_seconds();
        let mut selected_vm = None;
        let mut action: Option<(VmConfig, VmAction)> = None;
        let mut new_vm = false;
        egui::Panel::left("vms")
            // Room for the VM details, but the trace keeps most of a small
            // screen.
            .default_size(
                (ctx.content_rect().width() * 0.2)
                    .clamp(200.0, 300.0)
                    // Section titles and VM rows are cut when the text is
                    // larger than the default: the width follows the text,
                    // but a screen narrower than 1100 px keeps the tab beside it
                    // wide (the debugger listing needs that room there).
                    .max(if ctx.content_rect().width() >= 1100.0 {
                        (ctx.global_style().text_styles[&egui::TextStyle::Body].size * 14.0)
                            .min(ctx.content_rect().width() * 0.22)
                    } else {
                        0.0
                    }),
            )
            .min_size(200.0)
            .max_size(380.0)
            .resizable(true)
            .frame(
                egui::Frame::new()
                    .fill(theme::panel())
                    .inner_margin(egui::Margin::same(8)),
            )
            .show(root, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                let stopped = self.snapshot.active_vm.is_none();
                if section_header(
                    ui,
                    SectionHeader {
                        title: "Virtual machines",
                        count: self.snapshot.vms.len() + self.pending_vm_rows().len(),
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
                        .max_height(
                            if self.settings.explorer_collapsed {
                                // Room for the Library rows below.
                                budget - ui.spacing().interact_size.y * 4.0 - 24.0
                            } else {
                                budget * 0.45
                            }
                            .max(80.0),
                        )
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            if self.snapshot.vms.is_empty() && self.pending_vm_rows().is_empty() {
                                ui.label(RichText::new("No saved VMs").color(theme::muted()));
                            }
                            for work in self.pending_vm_rows() {
                                Self::pending_vm_row(ui, work);
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
                                        (
                                            "Start VM",
                                            self.snapshot.active_vm.is_none() && !self.closing,
                                            VmAction::Start,
                                        ),
                                        ("Stop VM", active, VmAction::Stop),
                                        ("Configuration…", stopped, VmAction::Configure),
                                        ("Snapshots…", !self.closing, VmAction::Snapshots),
                                        ("Rename…", !self.closing, VmAction::Rename),
                                        ("Duplicate…", stopped, VmAction::Duplicate),
                                        ("Open directory", true, VmAction::OpenDirectory),
                                        (
                                            "Reset disk to base…",
                                            self.snapshot.active_vm.is_none(),
                                            VmAction::Reset,
                                        ),
                                        ("Delete VM and disk…", stopped, VmAction::Delete),
                                    ] {
                                        if matches!(choice, VmAction::Configure | VmAction::Reset) {
                                            ui.separator();
                                        }
                                        if ui
                                            .add_enabled(enabled, egui::Button::new(label))
                                            .clicked()
                                        {
                                            action = Some((vm.clone(), choice));
                                            ui.close();
                                        }
                                    }
                                });
                            }
                        });
                }
                ui.add_space(6.0);
                self.library_sidebar(ui);
                ui.add_space(6.0);
                self.explorer_sidebar(ui);
            });
        if new_vm {
            self.new_image();
        }
        if let Some(vm_id) = selected_vm {
            self.select_vm(vm_id);
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
    pub(super) fn health(&mut self, root: &mut egui::Ui) {
        let ctx = &root.ctx().clone();
        let mut open_jobs = false;
        let bar = egui::Panel::bottom("health")
            .frame(theme::frame(theme::raised()))
            .show(root, |ui| {
                let dropped = self.snapshot.health.dropped;
                let attempted = self.snapshot.health.attempted;
                let ui_dropped = self.snapshot.health.ui_dropped;
                let guest_lost = self.snapshot.health.guest_note_lost;
                let storage_dropped = self.snapshot.health.storage_dropped_packets;
                let persisted = self.snapshot.health.persisted_len;
                let quota = self.settings.quota_gib;
                let shedding = self.snapshot.health.shedding;
                let persistence = self.snapshot.health.persistence_error.clone();
                let status = self.status.clone();
                let is_notice = self.status_notice.as_ref().is_some_and(|(_, message)| message == &status);
                let closing = self.closing;
                let jobs = &self.jobs;
                // A slow start is waited for, not failed.
                let start_note = (self.snapshot.state == VmState::Starting)
                    .then(|| self.snapshot.start_note.clone())
                    .flatten()
                    .or_else(|| self.snapshot.launch_wait.as_ref().map(|wait| format!("{}…", wait.text)));
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
                    if jobs.chip(ui) {
                        open_jobs = true;
                        ui.add_space(16.0);
                    }
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
                        } else if closing {
                            crate::theme::spinner(ui);
                            let message = "Waiting for guest shutdown and recording finalization…";
                            ui.add(egui::Label::new(RichText::new(message).color(theme::neutral_accent())).truncate())
                                .on_hover_text(message);
                        } else if let Some(note) = &start_note {
                            crate::theme::spinner(ui);
                            ui.add(egui::Label::new(RichText::new(note).color(theme::warn())).truncate())
                                .on_hover_text(note);
                        } else if !status.is_empty() && !is_notice {
                            // A warning or an error is a toast, not a status line.
                            status_line(ui, egui_phosphor::regular::INFO, &status, theme::info());
                        }
                    });
                });
                ui.add_space(3.0);
            });
        if open_jobs {
            self.focus_panel = Some(Panel::Jobs);
        }
        // The toast stack sits above the bar.
        crate::toasts::set_floor(ctx, bar.response.rect.top());
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

    /// A normal state or a refused no-op: the status line and an Info row, no
    /// toast and no count in the Activity badge.
    pub(super) fn report_info(&mut self, message: String) {
        self.status = message.clone();
        self.log("INFO", message);
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

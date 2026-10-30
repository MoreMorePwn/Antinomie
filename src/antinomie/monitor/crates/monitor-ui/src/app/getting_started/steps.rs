// SPDX-License-Identifier: GPL-3.0-only
//! What each Getting started step shows. Every step reads live state and
//! sends the same commands as the window it stands in for.
use super::*;
use crate::{
    dependencies_window,
    rules_window::first_run::{Offer, ENGINES},
};
use antinomie_monitor_core::analysis_tools::ToolStatus;

impl MonitorApp {
    pub(super) fn getting_started_step(&mut self, ui: &mut egui::Ui, facts: &Facts) {
        match self.getting_started.step {
            Step::Base => self.step_base(ui),
            Step::Vm => self.step_vm(ui),
            Step::Dependencies => self.step_dependencies(ui),
            Step::Tools => self.step_tools(ui),
            Step::Rules => self.step_rules(ui),
            Step::Finish => self.step_finish(ui, facts),
        }
    }

    /// Fetch the base catalog once per opening, when curl is known to work.
    fn request_catalog(&mut self) {
        if self.getting_started.catalog_requested || self.dependencies.report().is_none() {
            return;
        }
        self.getting_started.catalog_requested = true;
        match self.dependencies.require_dependencies(&[Dependency::Curl]) {
            Ok(()) if !self.snapshot.remote_refreshing && !self.closing => {
                self.send(Command::RefreshRemoteBases);
            }
            Ok(()) => {}
            Err(error) => self.getting_started.base_error = Some(error),
        }
    }

    fn step_base(&mut self, ui: &mut egui::Ui) {
        ui.label("A base image is the guest Linux system with Antinomie's patched kernel.");
        for base in &self.snapshot.bases {
            ui.colored_label(
                theme::good(),
                format!(
                    "{} {} is installed",
                    egui_phosphor::regular::CHECK,
                    base.label
                ),
            );
        }
        if self.snapshot.bases_checking {
            theme::loading_weak(ui, "Looking for installed bases…");
        }
        self.request_catalog();
        theme::section(ui, "Available bases");
        let mut command = None;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.snapshot.remote_refreshing && !self.closing,
                    egui::Button::new("Refresh catalog"),
                )
                .clicked()
            {
                self.getting_started.catalog_requested = false;
                self.getting_started.base_error = None;
            }
            if self.snapshot.remote_refreshing {
                theme::loading(ui, "Fetching catalog…");
            }
        });
        if let Some(error) = &self.getting_started.base_error {
            crate::activity::error_toast(ui, error);
        }
        if let Some(error) = &self.snapshot.remote_error {
            crate::activity::error(ui, error);
        }
        let download = self.snapshot.download.clone();
        if let Some(next) = download_status(ui, download.as_ref()) {
            command = Some(next);
        }
        let installed: Vec<String> = self
            .snapshot
            .bases
            .iter()
            .map(|base| base.id.clone())
            .collect();
        let busy = download.as_ref().is_some_and(|status| !status.finished);
        let mut listed = 0;
        for base in self.snapshot.remote_bases.clone() {
            let status = RevisionStatus::of_base(base.revision, base.min_app_version.as_deref());
            // Bases for older versions stay in the Download base window.
            if matches!(status, RevisionStatus::Outdated | RevisionStatus::Legacy) {
                continue;
            }
            listed += 1;
            egui::Frame::group(ui.style())
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if let Some(next) = download_row(ui, &base, &installed, download.as_ref(), busy)
                    {
                        command = Some(next);
                    }
                    let (color, text) = if remote_is_current(&base) {
                        (
                            theme::good(),
                            format!(
                                "{} Built for Antinomie {APP_VERSION}",
                                egui_phosphor::regular::CHECK
                            ),
                        )
                    } else {
                        (
                            theme::warn(),
                            RevisionStatus::describe(
                                base.revision,
                                base.min_app_version.as_deref(),
                            ),
                        )
                    };
                    ui.label(RichText::new(text).small().color(color));
                });
        }
        if listed == 0 && !self.snapshot.remote_refreshing {
            ui.colored_label(theme::muted(), "No bases listed yet: refresh the catalog.");
        }
        if let Some(command) = command {
            self.send(command);
        }
    }

    fn step_vm(&mut self, ui: &mut egui::Ui) {
        ui.label("A VM runs the program you analyse.");
        for vm in &self.snapshot.vms {
            ui.colored_label(
                theme::good(),
                format!("{} {} is created", egui_phosphor::regular::CHECK, vm.name),
            );
        }
        if !self.snapshot.vms.is_empty() {
            ui.weak("More VMs: File › New VM…");
            return;
        }
        if self.snapshot.bases.is_empty() {
            crate::activity::warning(ui, "Install a base image first.");
            if ui.button("Go to Base image").clicked() {
                self.getting_started.step = Step::Base;
            }
            return;
        }
        let mut draft = self
            .getting_started
            .draft
            .take()
            .unwrap_or_else(|| self.fresh_draft());
        if !self
            .snapshot
            .bases
            .iter()
            .any(|base| Some(&base.id) == draft.base_identity.as_ref())
        {
            draft.base_identity = selected_base(&self.snapshot, None).map(|base| base.id.clone());
        }
        let base = self
            .snapshot
            .bases
            .iter()
            .find(|base| Some(&base.id) == draft.base_identity.as_ref());
        let (min_ram, min_disk) =
            base.map_or((256, 1), |base| (base.min_ram_mib, base.min_disk_gib));
        let credentials_required = base
            .and_then(|base| base.guest.as_ref())
            .is_some_and(|guest| guest.requires_credentials);
        draft.ram_mib = draft
            .ram_mib
            .clamp(min_ram, antinomie_monitor_core::storage::MAX_RAM_MIB);
        draft.disk_gib = draft.disk_gib.max(min_disk);
        let old_base = draft.base_identity.clone();
        form_grid("getting_started_vm", ui).show(ui, |ui| {
            ui.label("Installed base");
            base_selector(
                ui,
                &self.snapshot,
                &mut draft.base_identity,
                "getting_started_base",
            );
            ui.end_row();
            ui.label("Name");
            ui.add(text_field(&mut draft.name).desired_width(280.0));
            ui.end_row();
            ui.label("CPU count");
            ui.add(egui::DragValue::new(&mut draft.cpus).range(1..=64));
            ui.end_row();
            ui.label("RAM");
            ui.add(
                egui::DragValue::new(&mut draft.ram_mib)
                    .range(min_ram..=antinomie_monitor_core::storage::MAX_RAM_MIB)
                    .suffix(" MiB"),
            )
            .on_hover_text(format!("At least {min_ram} MiB for this base"));
            ui.end_row();
            ui.label("Disk");
            ui.add(
                egui::DragValue::new(&mut draft.disk_gib)
                    .range(min_disk..=2048)
                    .suffix(" GiB"),
            )
            .on_hover_text(format!("At least {min_disk} GiB for this base"));
            ui.end_row();
            ui.label("Device profile");
            let mut stealth =
                draft.stealth.preset != antinomie_monitor_core::stealth::StealthPreset::Transparent;
            if ui
                .checkbox(&mut stealth, "Look like a real desktop PC")
                .changed()
            {
                draft.stealth = if stealth {
                    self.fresh_draft().stealth
                } else {
                    Default::default()
                };
            }
            ui.end_row();
            if credentials_required {
                ui.label("Guest username");
                ui.add(
                    text_field(&mut self.credentials.username)
                        .char_limit(32)
                        .desired_width(280.0),
                );
                ui.end_row();
                ui.label("Password");
                password_input(
                    ui,
                    &mut self.credentials.password,
                    "getting_started_password",
                );
                ui.end_row();
                ui.label("Confirm password");
                password_input(
                    ui,
                    &mut self.credentials.confirmation,
                    "getting_started_confirmation",
                );
                ui.end_row();
            }
        });
        if old_base != draft.base_identity {
            self.credentials.reset();
        }
        if let Some(error) = &self.getting_started.vm_error {
            crate::activity::error_toast(ui, error);
        }
        let pending = self.getting_started.vm_pending.is_some();
        if pending {
            theme::loading(ui, "Creating the VM…");
        }
        let create = ui
            .add_enabled(!pending && !self.closing, primary_button("Create VM"))
            .on_hover_text("Uses the New VM checks; File › New VM… has every option")
            .clicked();
        self.getting_started.draft = Some(draft);
        if create {
            self.create_first_vm();
        }
    }

    /// Create the wizard's VM through the New VM dialog's own path.
    fn create_first_vm(&mut self) {
        let before = self.snapshot.vms.len();
        let Some(draft) = self.getting_started.draft.take() else {
            return;
        };
        let previous = std::mem::replace(&mut self.draft, draft);
        let result = self.create_vm();
        self.getting_started.draft = Some(std::mem::replace(&mut self.draft, previous));
        match result {
            Ok(()) => {
                self.getting_started.vm_error = None;
                self.getting_started.vm_pending = Some((Instant::now(), before));
            }
            Err(error) => self.getting_started.vm_error = Some(error),
        }
    }

    fn step_dependencies(&mut self, ui: &mut egui::Ui) {
        ui.label("Antinomie needs these programs on this computer.")
            .on_hover_text(
                "Nothing is installed for you: copy the command and run it in a terminal.",
            );
        if self.dependencies.checking() {
            theme::loading(ui, "Checking this system…");
        }
        let mut again = false;
        if let Some(report) = self.dependencies.report() {
            for check in &report.checks {
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(check.name).strong().color(theme::heading()));
                    let (color, state) = dependencies_window::state_of(check);
                    let state = match (&check.problem, check.optional) {
                        (None, _) => "Found",
                        (Some(_), true) => state,
                        (Some(problem), false)
                            if problem.contains("missing") || problem.contains("not installed") =>
                        {
                            "Missing"
                        }
                        (Some(_), false) => "Needs attention",
                    };
                    ui.colored_label(color, state);
                    ui.weak(check.purpose);
                });
                if let Some(problem) = &check.problem {
                    ui.weak(problem);
                }
            }
            dependencies_window::install_section(ui, report);
        }
        ui.separator();
        ui.horizontal(|ui| {
            again = ui
                .add_enabled(
                    !self.dependencies.checking(),
                    egui::Button::new("Check again"),
                )
                .clicked();
            if ui.button("Open App dependencies").clicked() {
                self.dependencies.open = true;
            }
        });
        if again {
            self.dependencies.recheck_quietly(&self.options);
        }
    }

    fn step_tools(&mut self, ui: &mut egui::Ui) {
        ui.label("Tools used by static analysis.").on_hover_text("A missing one is downloaded from its upstream release (SHA-256 checked) into Antinomie's data folder.");
        let tools: Vec<ToolStatus> = self
            .snapshot
            .analysis_tools
            .iter()
            .filter(|tool| {
                !crate::app::debugger::is_console_tool(&tool.id)
                    && !antinomie_monitor_core::analysis_tools::is_route_tool(&tool.id)
            })
            .cloned()
            .collect();
        let install = self.snapshot.tool_install.clone();
        let queued = !self.getting_started.tool_queue.is_empty()
            || self.getting_started.tool_inflight.is_some();
        let running = install.as_ref().is_some_and(|install| !install.finished);
        let missing: Vec<String> = tools
            .iter()
            .filter(|tool| !tool.available())
            .map(|tool| tool.id.clone())
            .collect();
        if tools.is_empty() {
            theme::loading_weak(ui, "Listing analysis tools…");
        }
        let mut command = None;
        for tool in &tools {
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&tool.name).strong().color(theme::heading()));
                match (&tool.system, &tool.installed) {
                    (Some(_), _) => ui.colored_label(theme::good(), "On this system"),
                    (None, Some(version)) => {
                        ui.colored_label(theme::good(), format!("Installed ({version})"))
                    }
                    (None, None) => ui.colored_label(theme::warn(), "Not installed"),
                };
                ui.weak(&tool.purpose);
                let this = install.as_ref().filter(|install| install.id == tool.id);
                if this.is_some_and(|install| !install.finished) {
                    theme::loading(ui, "Installing…");
                } else if !tool.available()
                    && ui
                        .add_enabled(
                            !running && !queued && !self.closing,
                            egui::Button::new(format!("Install · {}", human_bytes(tool.size))),
                        )
                        .clicked()
                {
                    command = Some(Command::InstallTool {
                        id: tool.id.clone(),
                    });
                }
            });
            if let Some(install) = install.as_ref().filter(|install| install.id == tool.id) {
                if let Some(error) = install.error.as_ref().filter(|_| install.finished) {
                    crate::activity::error_toast(ui, error);
                } else if !install.finished {
                    let fraction = if install.total > 0 {
                        install.received as f32 / install.total as f32
                    } else {
                        0.0
                    };
                    ui.add(
                        egui::ProgressBar::new(fraction.clamp(0.0, 1.0))
                            .text(install.stage.clone()),
                    );
                }
            }
        }
        if let Some(error) = &self.getting_started.tool_error {
            crate::activity::error_toast(ui, error);
        }
        ui.separator();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !missing.is_empty() && !running && !queued && !self.closing,
                    primary_button("Install all missing"),
                )
                .clicked()
            {
                self.getting_started.tool_error = None;
                self.getting_started.tool_queue = missing.iter().cloned().collect();
            }
            if (queued || running) && ui.button("Cancel").clicked() {
                self.getting_started.tool_queue.clear();
                self.getting_started.tool_inflight = None;
                command = Some(Command::CancelToolInstall);
            }
            if missing.is_empty() && !tools.is_empty() {
                ui.colored_label(theme::good(), "All analysis tools are available.");
            }
        });
        if let Some(command) = command {
            self.send(command);
        }
    }

    fn step_rules(&mut self, ui: &mut egui::Ui) {
        ui.label("Rules tell the scans what to look for: YARA for files, an IDS for network captures, Sigma for behaviour.");
        let data_dir = self.options.data_dir.clone();
        let busy = self.rules_ui.is_busy();
        if !self.settings.outbound_catalog {
            ui.label(RichText::new("Downloads are off.").color(theme::muted()));
            if ui.button("Allow downloads").clicked() {
                self.settings.outbound_catalog = true;
            }
        }
        ui.add(
            egui::Label::new(
                RichText::new(self.rules_ui.consent_line())
                    .small()
                    .color(theme::muted()),
            )
            .wrap(),
        );
        let outbound = self.settings.outbound_catalog;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(outbound && !busy, egui::Button::new("Check the catalog"))
                .clicked()
            {
                self.getting_started.rules_chosen = None;
                self.rules_ui.check_catalog(&data_dir, outbound);
            }
            if ui.button("Open Detection rules").clicked() {
                self.open_library(crate::workspace::LibraryPage::Rules);
            }
        });
        let offers = self.rules_ui.offers();
        if self.getting_started.rules_chosen.is_none() && !offers.is_empty() {
            // Every pack without license terms to read first, not yet installed.
            self.getting_started.rules_chosen = Some(
                offers
                    .iter()
                    .filter(|offer| !offer.installed && offer.notices.is_empty())
                    .map(|offer| offer.id.clone())
                    .collect(),
            );
        }
        let mut chosen = self
            .getting_started
            .rules_chosen
            .clone()
            .unwrap_or_default();
        // One tab per engine, with whether it has rules yet.
        let ready = self.rules_ui.engines_with_packs();
        let mut engine = ENGINES[self.getting_started.rules_engine.min(ENGINES.len() - 1)].0;
        let items = ENGINES.map(|(id, label)| {
            let (glyph, tone) = if ready.contains(id) {
                (egui_phosphor::regular::CHECK_CIRCLE, Tone::Good)
            } else {
                (egui_phosphor::regular::CIRCLE, Tone::Neutral)
            };
            (id, TabItem::new(label).icon(glyph, tone))
        });
        if tabs(ui, items, &mut engine) {
            self.getting_started.rules_engine = ENGINES
                .iter()
                .position(|(id, _)| *id == engine)
                .unwrap_or(0);
        }
        let group: Vec<&Offer> = offers
            .iter()
            .filter(|offer| offer.engine == engine)
            .collect();
        if group.is_empty() {
            ui.weak(if offers.is_empty() {
                "No catalog yet: allow downloads and check the catalog to see the packs."
            } else {
                "The catalog has no pack for this engine."
            });
        }
        for offer in group {
            ui.horizontal_wrapped(|ui| {
                let mut on = chosen.contains(&offer.id) || offer.installed;
                if ui
                    .add_enabled(
                        !offer.installed && !busy,
                        egui::Checkbox::new(&mut on, &offer.name),
                    )
                    .changed()
                {
                    if on {
                        chosen.insert(offer.id.clone());
                    } else {
                        chosen.remove(&offer.id);
                    }
                }
                if offer.installed {
                    crate::widgets::chip(ui, "Installed", Tone::Good);
                }
                ui.weak(format!(
                    "about {} rules · {} · {} · from {}",
                    offer.rules,
                    human_bytes(offer.size),
                    offer.license,
                    offer.hosts
                ));
            });
            for notice in &offer.notices {
                crate::activity::warning(ui, notice);
            }
        }
        let queued = !self.getting_started.rule_queue.is_empty();
        self.getting_started.rules_chosen = Some(chosen.clone());
        let (status, is_error, progress) = self.rules_ui.status_text();
        let (status, progress) = (status.to_owned(), progress);
        ui.horizontal(|ui| {
            let wanted: Vec<String> = offers
                .iter()
                .filter(|offer| !offer.installed && chosen.contains(&offer.id))
                .map(|offer| offer.id.clone())
                .collect();
            if ui
                .add_enabled(
                    outbound && !busy && !queued && !wanted.is_empty(),
                    primary_button("Download selected"),
                )
                .clicked()
            {
                self.getting_started.rule_queue = wanted.into();
            }
            if (busy || queued) && ui.button("Cancel").clicked() {
                self.getting_started.rule_queue.clear();
                self.rules_ui.cancel_job();
            }
        });
        if let Some(progress) = progress {
            theme::loading(
                ui,
                if progress.is_empty() {
                    "Working…"
                } else {
                    progress.as_str()
                },
            );
        }
        if is_error {
            crate::activity::error_toast(ui, status);
        } else if !status.is_empty() {
            ui.weak(status);
        }
    }

    fn step_finish(&mut self, ui: &mut egui::Ui, facts: &Facts) {
        ui.label("Nothing here is required.");
        ui.add_space(4.0);
        for step in Step::ALL.into_iter().filter(|step| *step != Step::Finish) {
            let status = walkthrough::status(step, facts, &self.settings.getting_started);
            let (glyph, color) = match status {
                Status::Done => (egui_phosphor::regular::CHECK_CIRCLE, theme::good()),
                Status::Skipped => (egui_phosphor::regular::MINUS_CIRCLE, theme::muted()),
                Status::Pending => (egui_phosphor::regular::WARNING, theme::warn()),
            };
            ui.horizontal(|ui| {
                ui.colored_label(color, format!("{glyph} {}", step.title()));
                ui.colored_label(color, status.word());
                if status != Status::Done && ui.small_button("Open").clicked() {
                    self.getting_started.step = step;
                }
            });
        }
        ui.add_space(6.0);
        ui.hyperlink_to("Your first run (documentation)", walkthrough::DOCS_URL);
    }
}

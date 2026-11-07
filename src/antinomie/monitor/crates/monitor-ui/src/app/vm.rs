// SPDX-License-Identifier: GPL-3.0-only
//! VM configuration, launch and the VM settings dialog.
use super::*;

mod dialog;

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

    /// The settings a new VM starts with, shared by New VM and Getting started.
    pub(super) fn fresh_draft(&self) -> VmConfig {
        VmConfig {
            name: "New VM".into(),
            // New VMs look like an ordinary PC; saved ones keep what they had.
            stealth: antinomie_monitor_core::stealth::StealthProfile::realistic(
                antinomie_monitor_core::stealth::StealthPreset::RealisticDesktop,
                &antinomie_monitor_core::stealth::host_cpu_vendor(),
            ),
            base_identity: preferred_new_base(&self.snapshot, &self.settings.bundle)
                .map(|base| base.id.clone()),
            ..VmConfig::default()
        }
    }

    pub(super) fn new_image(&mut self) {
        self.draft_generation = self.draft_generation.wrapping_add(1);
        self.draft = self.fresh_draft();
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
        if let Err(error) = self.draft.stealth.validate() {
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
            .or_else(|| vm.stealth.validate().err())
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

    /// Why this host cannot use KVM, once the dependency check has finished.
    pub(super) fn kvm_problem(&self) -> Option<String> {
        self.dependencies
            .report()?
            .checks
            .iter()
            .find(|check| {
                check.dependency == antinomie_monitor_core::dependencies::Dependency::Kvm
            })?
            .problem
            .clone()
    }

    /// The Use TCG buttons of the dependencies window.
    pub(super) fn apply_tcg_choice(&mut self, everywhere: bool, for_vm: bool) {
        if everywhere {
            self.settings.start.kvm_fallback = true;
            self.update_options();
            self.report_info(
                "Use TCG when KVM is unavailable is on; VMs set to KVM run with TCG, much slower"
                    .into(),
            );
        }
        if for_vm
            && let Some(mut vm) = self
                .snapshot
                .vms
                .iter()
                .find(|vm| Some(&vm.id) == self.selected.as_ref())
                .cloned()
        {
            vm.launch.acceleration = VmAcceleration::Tcg;
            if vm.launch.cpu_model == VmCpuModel::Host {
                vm.launch.cpu_model = VmCpuModel::Default;
            }
            let name = vm.name.clone();
            match self.save_vm(vm) {
                Ok(()) => self.report_info(format!(
                    "{name} now uses TCG acceleration; software emulation is much slower"
                )),
                Err(error) => self.report_warning(error),
            }
        }
    }

    pub(super) fn new_run(&mut self) {
        if let Some(vm_id) = self.selected.clone() {
            if self.confirm.is_none() && self.warns_without_snapshot(&vm_id) {
                self.confirm = Some(Confirm::StartWithoutSnapshot(vm_id));
                return;
            }
            self.send(Command::Start { vm_id });
        }
    }

    /// The VM's snapshots are listed and none is left, and the warning is on.
    /// A VM whose list has not arrived yet starts without the question.
    fn warns_without_snapshot(&self, vm_id: &str) -> bool {
        self.settings.warn_no_snapshot
            && self
                .snapshot
                .vm_snapshot_trees
                .get(vm_id)
                .is_some_and(|tree| tree.nodes.iter().all(|node| node.deleted))
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
        // A run whose tree ended and whose terminal closed is read from its
        // archive: the backend drops its live events once it is complete.
        (self.archive_selected
            || !run_in_live_session(&self.snapshot, run)
            || run_recording_complete(run))
        .then_some(run)
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

    /// Before the Summary draws: list the selected VM's snapshots (again when
    /// the VM starts or stops, which changes what is allowed) and tell the
    /// Snapshots box what the manager is doing.
    pub(super) fn prepare_summary_snapshots(&mut self, ctx: &egui::Context) {
        use crate::snapshots::summary_box::{BoxState, STATE};
        let Some(vm_id) = self.selected_vm().map(|vm| vm.id.clone()) else {
            return;
        };
        let key = (
            vm_id.clone(),
            self.snapshot.active_vm.as_deref() == Some(vm_id.as_str()),
        );
        if self.summary_snapshots_asked.as_ref() != Some(&key)
            && self.vm_snapshots.pending.is_none()
            && !self.closing
        {
            self.summary_snapshots_asked = Some(key);
            self.send(Command::RefreshVmSnapshots {
                vm_id: vm_id.clone(),
            });
        }
        let ours = self.vm_snapshots.vm_id.as_deref() == Some(vm_id.as_str());
        let state = BoxState {
            busy: self.vm_snapshots.pending.is_some() && ours,
            result: self.vm_snapshots.result.clone().filter(|_| ours),
        };
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(STATE), state));
    }

    /// After the Summary drew: what its Snapshots box asked for.
    pub(super) fn answer_summary_snapshots(&mut self, ctx: &egui::Context) {
        use crate::snapshots::summary_box::{Action, ACTION};
        let Some(action) = ctx.data_mut(|data| data.remove_temp::<Action>(egui::Id::new(ACTION)))
        else {
            return;
        };
        let Some(vm) = self.selected_vm().cloned() else {
            return;
        };
        if matches!(action, Action::Open) {
            self.open_snapshots();
            return;
        }
        let Some(tree) = self.snapshot.vm_snapshot_trees.get(&vm.id).cloned() else {
            return;
        };
        match action {
            Action::Take => self.vm_snapshots.ask_create_for(&vm.id, &vm.name, &tree),
            Action::Restore { id, boot_from_disk } => {
                self.vm_snapshots
                    .ask_restore_for(&vm.id, &vm.name, &tree, &id, boot_from_disk)
            }
            Action::Open => {}
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
            None => self.report_error("VM directory unavailable".into()),
        }
    }

    /// What the Run form offers for the running VM's network.
    fn route_choice(&self) -> crate::route_ui::RouteChoice {
        let vm = self
            .snapshot
            .vms
            .iter()
            .find(|vm| Some(&vm.id) == self.snapshot.active_vm.as_ref());
        let network = vm.map_or(antinomie_monitor_core::VmNetwork::Disconnected, |vm| {
            vm.network()
        });
        let mut choice = crate::route_ui::RouteChoice::new(network, &self.routes.config);
        // Only a Routed VM has the simulated metadata service.
        choice.cloud = vm
            .filter(|_| network == antinomie_monitor_core::VmNetwork::Routed)
            .and_then(|vm| vm.stealth.cloud_provider())
            .map(|provider| provider.label);
        choice
    }

    pub(super) fn launch_form(&mut self, ui: &mut egui::Ui) {
        // Cancel stays usable when the VM stops or a launch is pending; only
        // the form and its actions wait for a running VM.
        let ready = self.running() && self.pending_launch.is_none();
        let uploading = self.launch_source == crate::analysis::LaunchSource::Upload;
        let selection_error = self.exec.analysis.validate().err();
        let graphical = self.selected_vm_graphical();
        let core_on_exit = self
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 15));
        let debug_on_start = self
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 17));
        // The footer: its rule and buttons, and the line of an error above.
        let footer = ui.spacing().interact_size.y
            + 24.0
            + if selection_error.is_some() {
                ui.text_style_height(&egui::TextStyle::Body) + 10.0
            } else {
                0.0
            };
        let chooser_note = if self.folder_picker.checking() {
            Some("Checking file chooser…")
        } else if !self.folder_picker.installed() {
            Some("File selection requires Zenity; you can type a file path.")
        } else {
            None
        };
        let mut choose = false;
        let route = self.route_choice();
        ui.add_enabled_ui(ready, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("run-setup")
                .max_height((ui.available_height() - footer).max(80.0))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // The time limit is one value, here and in Settings.
                    self.exec.analysis.time_limit_minutes =
                        self.settings.analysis_time_limit_minutes;
                    self.exec.analysis.limits = self.settings.analysis_limits;
                    let outcome = crate::analysis::launch_fields(
                        ui,
                        &mut self.exec,
                        &mut self.args,
                        &mut self.env,
                        &self.snapshot.analysis_tools,
                        crate::analysis::LaunchCapabilities {
                            graphical,
                            core_on_exit,
                            debug_on_start,
                            core_limits: self.snapshot.guest_core_limits,
                            core_default_mib: self.settings.core_budget_mib,
                            route,
                            guest_arch: self
                                .snapshot
                                .guest_kernel
                                .as_ref()
                                .map(|kernel| kernel.arch)
                                .unwrap_or_default(),
                        },
                        crate::analysis::ProgramSource {
                            choice: &mut self.launch_source,
                            upload: crate::analysis::UploadFields {
                                host_file: &mut self.source,
                                destination: &mut self.destination,
                                overwrite: &mut self.overwrite,
                                can_choose: self.folder_picker.available()
                                    && self.pending_upload.is_none(),
                                chooser_note,
                                busy: self.pending_upload.is_some(),
                            },
                        },
                    );
                    self.settings.analysis_time_limit_minutes =
                        self.exec.analysis.time_limit_minutes;
                    if outcome.install {
                        self.open_library(crate::workspace::LibraryPage::Tools);
                    }
                    if outcome.open_vm_settings {
                        self.configure_vm();
                    }
                    if outcome.source.host_file_edited {
                        self.upload_browser.selected = None;
                    }
                    choose = outcome.source.choose_file;
                    if let Some(size) = ui.data_mut(|data| {
                        data.remove_temp::<u32>(crate::analysis::remembered_budget_id())
                    }) {
                        self.settings.core_budget_mib = size >> 20;
                    }
                });
        });
        if choose {
            self.upload_browser.invalidate();
            if let Err(error) = self.folder_picker.choose(FolderTarget {
                generation: self.upload_browser.generation,
                kind: FolderKind::UploadFile,
            }) {
                self.report_error(format!("Host file: {error}"));
            }
        }
        if let Some(reason) = selection_error {
            crate::activity::inline_only(ui, crate::activity::Level::Warn, reason);
        }
        let valid = self.exec.analysis.validate().is_ok();
        let program_ready = if uploading {
            !self.source.trim().is_empty() && !self.destination.trim().is_empty()
        } else {
            !self.exec.path.trim().is_empty()
        };
        let mut run_rects = None;
        let mut start = false;
        let mut analyze_clicked = false;
        let mut cancel = false;
        let vm_name = self.selected_vm().map(|vm| vm.name.clone());
        crate::widgets::footer_split(
            ui,
            |ui| {
                let room = (ui.available_width() - 330.0).max(60.0);
                ui.scope(|ui| {
                    ui.set_max_width(room);
                    if self.pending_upload.is_some() {
                        theme::loading_weak(ui, "Uploading…");
                    } else if ready {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "{} {} is running",
                                    egui_phosphor::regular::CHECK_CIRCLE,
                                    vm_name.as_deref().unwrap_or("The VM")
                                ))
                                .small()
                                .color(theme::good()),
                            )
                            .truncate(),
                        );
                    } else {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "{} Start the VM to run a program",
                                    egui_phosphor::regular::INFO
                                ))
                                .small()
                                .color(theme::neutral_accent()),
                            )
                            .truncate(),
                        );
                    }
                });
            },
            |ui| {
                // Right to left: the main action lands rightmost.
                let run = if uploading {
                    ui.add_enabled(
                        ready && program_ready && valid && self.pending_upload.is_none(),
                        primary_button(&format!("{} Upload", egui_phosphor::regular::UPLOAD_SIMPLE)),
                    )
                    .on_hover_text(
                        "Upload as executable. The program is then set to its guest path in this window, ready to Run.",
                    )
                    .on_disabled_hover_text("Choose the host file and the guest path")
                } else {
                    ui.add_enabled(
                        ready && program_ready && valid,
                        primary_button(&format!("{} Run", egui_phosphor::regular::PLAY)),
                    )
                    .on_disabled_hover_text("Enter the executable to run")
                };
                start = run.clicked();
                let analyze = ui
                    .add_enabled(
                        ready && !uploading && self.exec.analysis.enabled && program_ready && valid,
                        egui::Button::new("Analyze only"),
                    )
                    .on_hover_text("Acquire the file and run static analysis without launching it")
                    .on_disabled_hover_text(if uploading {
                        "Upload the file first"
                    } else {
                        "Needs Static analysis and an executable"
                    });
                analyze_clicked = analyze.clicked();
                cancel = ui.button("Cancel").clicked();
                run_rects = Some((run.rect, analyze.rect));
            },
        );
        if start {
            if uploading {
                self.request_upload(true);
            } else {
                match crate::analysis::snapshot(&self.exec, &self.args, &self.env, graphical) {
                    Ok(mut request) => {
                        request.analysis.time_limit_minutes =
                            self.settings.analysis_time_limit_minutes;
                        request.analysis.limits = self.settings.analysis_limits;
                        request.host_copy = self.uploaded_host_file(&request.path);
                        self.send(Command::Execute(request))
                    }
                    Err(reason) => self.report_error(reason),
                }
                if self.pending_launch.is_some() {
                    self.launch_open = false;
                }
            }
        }
        if analyze_clicked {
            self.send(Command::AnalyzeOnly {
                path: self.exec.path.clone(),
                uid: self.exec.uid,
                gid: self.exec.gid,
                analysis: antinomie_monitor_core::AnalysisSelection {
                    time_limit_minutes: self.settings.analysis_time_limit_minutes,
                    limits: self.settings.analysis_limits,
                    ..self.exec.analysis.clone()
                },
            });
            self.focus_panel = Some(Panel::StaticAnalysis);
        }
        if cancel {
            self.launch_open = false;
        }
        #[cfg(test)]
        {
            self.launch_action_rects = run_rects;
        }
        let _ = run_rects;
    }
}

/// A VM state as a word and its color.
pub(super) fn vm_state_word(state: &VmState) -> (&'static str, egui::Color32) {
    match state {
        VmState::Running => ("Running", theme::good()),
        VmState::Starting => ("Starting", theme::neutral_accent()),
        VmState::Stopping => ("Stopping", theme::neutral_accent()),
        VmState::Failed => ("Failed", theme::error()),
        VmState::Stopped => ("Stopped", theme::muted()),
    }
}

/// What the Network row says about a running VM, which keeps the network it
/// started with: a changed choice needs a restart, an unchanged one says how
/// to change it. Nothing for a VM that is not running.
fn running_network_note(
    snapshot: &Snapshot,
    draft: &VmConfig,
) -> Option<(&'static str, egui::Color32)> {
    if snapshot.active_vm.as_ref() != Some(&draft.id) {
        return None;
    }
    let running = snapshot.vms.iter().find(|vm| vm.id == draft.id)?.network();
    Some(if running == draft.network() {
        (
            "The VM is running: stop it to change its network.",
            theme::muted(),
        )
    } else {
        ("Restart the VM to apply the new network.", theme::warn())
    })
}

#[cfg(test)]
mod running_network_tests {
    use super::*;

    #[test]
    fn a_running_vm_says_restart_for_a_changed_network_and_a_stopped_one_says_nothing() {
        let mut snapshot = Snapshot::default();
        let vm = VmConfig {
            id: "vm-1".into(),
            ..VmConfig::default()
        };
        snapshot.vms.push(vm.clone());
        let mut draft = vm.clone();
        assert!(
            running_network_note(&snapshot, &draft).is_none(),
            "not running"
        );
        snapshot.active_vm = Some("vm-1".into());
        let same = running_network_note(&snapshot, &draft).unwrap();
        assert!(
            same.0.contains("stop it to change its network"),
            "{}",
            same.0
        );
        draft.routed = true;
        draft.nat = false;
        draft.isolated_network = false;
        assert_eq!(
            running_network_note(&snapshot, &draft).unwrap().0,
            "Restart the VM to apply the new network."
        );
    }
}

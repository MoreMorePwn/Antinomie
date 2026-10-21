//! Startup runtime checks and Tools > App dependencies; package changes stay
//! with the user, and a recheck updates which feature actions are available.
use crate::theme;
use antinomie_monitor_core::{
    dependencies::{self, Dependency, Report},
    BackendOptions, Command, Snapshot,
};
use eframe::egui;
use std::{
    sync::mpsc::{self, Receiver, TryRecvError},
    thread::{self, JoinHandle},
};

type Worker = (Receiver<Report>, JoinHandle<()>);

/// The window's egui ID (Escape closes it).
pub(crate) const WINDOW_ID: &str = "app_dependencies";

#[derive(Default)]
pub(crate) struct DependenciesWindow {
    wake: Option<egui::Context>,
    pub open: bool,
    report: Option<Report>,
    worker: Option<Worker>,
    error: Option<String>,
    /// The running check was asked for by another window (Getting started):
    /// its result must not open this one.
    quiet: bool,
}

impl DependenciesWindow {
    pub fn start(options: &BackendOptions, ctx: &egui::Context) -> Self {
        let mut window = Self {
            wake: Some(ctx.clone()),
            open: false,
            report: None,
            worker: None,
            error: None,
            quiet: false,
        };
        window.recheck(options);
        window
    }

    /// The latest completed check, if one has finished.
    pub(crate) fn report(&self) -> Option<&Report> {
        self.report.as_ref()
    }

    pub(crate) fn checking(&self) -> bool {
        self.worker.is_some()
    }

    /// Check again for another window; the result does not open this one.
    pub(crate) fn recheck_quietly(&mut self, options: &BackendOptions) {
        if self.worker.is_none() {
            self.recheck(options);
            self.quiet = true;
        }
    }

    pub(crate) fn recheck(&mut self, options: &BackendOptions) {
        if self.worker.is_some() {
            return;
        }
        self.report = None;
        self.error = None;
        self.quiet = false;
        let options = options.clone();
        let wake = self.wake.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        match thread::Builder::new()
            .name("antinomie-dependencies".into())
            .spawn(move || {
                // The receiver can close normally when the app exits.
                let _ = sender.send(dependencies::check(&options));
                if let Some(ctx) = wake {
                    ctx.request_repaint_of(eframe::egui::ViewportId::ROOT);
                }
            }) {
            Ok(thread) => self.worker = Some((receiver, thread)),
            Err(error) => {
                self.error = Some(format!("Could not start dependency checks: {error}"));
                self.open = true;
            }
        }
    }

    pub fn poll(&mut self) {
        let Some((receiver, _)) = &self.worker else {
            return;
        };
        match receiver.try_recv() {
            Ok(report) => {
                self.open |= report.has_missing() && !self.quiet;
                self.report = Some(report);
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.error = Some("Dependency check stopped; select Check again to retry".into());
                self.open |= !self.quiet;
            }
        }
        if let Some((_, thread)) = self.worker.take() {
            if thread.join().is_err() {
                self.error = Some("Dependency check failed; select Check again to retry".into());
                self.open |= !self.quiet;
            }
        }
    }

    /// Check only dependencies used by this action. Closing, recording viewing,
    /// terminal input and cancellation continue while startup checks run.
    pub fn require(
        &self,
        command: &Command,
        options: &BackendOptions,
        snapshot: &Snapshot,
    ) -> Result<(), String> {
        let required = requirements(command, options, snapshot);
        if required.is_empty() {
            return Ok(());
        }
        self.require_dependencies(&required)
    }

    pub fn require_dependencies(&self, required: &[Dependency]) -> Result<(), String> {
        self.report
            .as_ref()
            .ok_or("Checking app dependencies; open Tools > App dependencies")?
            .require(required)
    }

    pub fn show(&mut self, ctx: &egui::Context, options: &BackendOptions) -> bool {
        if !self.open {
            return false;
        }
        let mut recheck = false;
        crate::widgets::window("App dependencies")
            .id(egui::Id::new(WINDOW_ID))
            .open(&mut self.open)
            .collapsible(false)
            .default_width(640.0)
            .show(ctx, |ui| {
                ui.label("Missing requirements block the actions listed below. You can still open saved recordings.");
                if self.worker.is_some() {
                    crate::theme::loading(ui, "Checking this system…");
                }
                if let Some(error) = &self.error {
                    crate::activity::error_toast(ui, error);
                }
                if let Some(report) = &self.report {
                    egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                        // Put repairs first so their commands stay visible even
                        // on a small desktop or with enlarged application text;
                        // optional tools follow the required ones.
                        let rank = |check: &dependencies::Check| match (&check.problem, check.optional) {
                            (Some(_), false) => 0,
                            (Some(_), true) => 1,
                            (None, _) => 2,
                        };
                        let mut ordered: Vec<_> = report.checks.iter().collect();
                        ordered.sort_by_key(|check| rank(check));
                        for check in ordered {
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(check.name).strong().color(theme::heading()));
                                let (color, state) = state_of(check);
                                ui.colored_label(color, state);
                            });
                            ui.weak(check.purpose);
                            if let Some(problem) = &check.problem {
                                ui.label(problem);
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(check.hint);
                                    if let Some(command) = check.hint.strip_prefix("On Debian/Ubuntu: ") {
                                        if ui.small_button("Copy command").clicked() {
                                            ui.ctx().copy_text(command.to_owned());
                                        }
                                    }
                                });
                            }
                        }
                    });
                }
                if let Some(report) = &self.report {
                    install_section(ui, report);
                }
                ui.separator();
                recheck = ui.add_enabled(self.worker.is_none(), egui::Button::new(egui::RichText::new("Check again").color(theme::palette().primary_text)).fill(theme::primary())).clicked();
                ui.weak("Install with your system's package manager, then check again. Build tools and optional analysis tools are checked in their own dialogs.");
            });
        if recheck {
            self.recheck(options);
        }
        recheck
    }
}

/// Whether a check passed, and how to say so: required tools are
/// "Unavailable" when missing, optional ones "Optional, not installed", and an installed
/// tool that is too old "Wrong version".
pub(crate) fn state_of(check: &dependencies::Check) -> (egui::Color32, &'static str) {
    if check.wrong_version {
        return (theme::warn(), "Wrong version");
    }
    match (&check.problem, check.optional) {
        (Some(_), false) => (theme::warn(), "Unavailable"),
        (Some(_), true) => (theme::muted(), "Optional, not installed"),
        (None, _) => (theme::good(), "Ready"),
    }
}

/// One copyable command for everything missing, for this system's package
/// manager, plus the kvm-group step when `/dev/kvm` needs it.
pub(crate) fn install_section(ui: &mut egui::Ui, report: &Report) {
    use dependencies::KvmAdvice;
    let plan = report.install_plan();
    ui.separator();
    theme::section(ui, "Install everything missing");
    if let Some(command) = &plan.command {
        match plan.manager {
            Some(manager) => ui.weak(format!("Detected {} from /etc/os-release.", manager.name())),
            None => ui.weak("This distribution's package manager is not recognised; install the packages named above, then run the group step."),
        };
        ui.horizontal_wrapped(|ui| {
            ui.add(egui::Label::new(egui::RichText::new(command).monospace()).selectable(true));
        });
        if ui.button("Copy").clicked() {
            ui.ctx().copy_text(command.clone());
        }
        if plan.kvm_group {
            ui.weak("Sign out and in again after the group step so that it applies.");
        }
    } else {
        ui.colored_label(theme::good(), "Nothing to install.");
    }
    match report.kvm {
        KvmAdvice::SignInAgain => {
            ui.colored_label(
                theme::warn(),
                "You are in the kvm group; sign out and in again to use KVM.",
            );
        }
        KvmAdvice::NoDevice => {
            ui.colored_label(theme::warn(), "There is no /dev/kvm: turn on hardware virtualization in the firmware, or choose TCG in VM settings.");
        }
        _ => {}
    }
    if !plan.unmapped.is_empty() {
        ui.weak(format!("No package is known for: {:?}", plan.unmapped));
    }
}

impl Drop for DependenciesWindow {
    fn drop(&mut self) {
        // One bounded capability probe may still be finishing during app exit.
        if let Some((_, worker)) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("dependency check worker failed during shutdown");
            }
        }
    }
}

fn requirements(
    command: &Command,
    options: &BackendOptions,
    snapshot: &Snapshot,
) -> Vec<Dependency> {
    use Dependency::*;
    match command {
        Command::Start { vm_id } | Command::RestoreVmSnapshot { vm_id, .. } => {
            let launch = snapshot
                .vms
                .iter()
                .find(|vm| &vm.id == vm_id)
                .map(|vm| vm.launch.clone())
                .unwrap_or_default();
            let mut required = dependencies::vm_requirements(options, &launch);
            if matches!(command, Command::RestoreVmSnapshot { .. }) {
                required.push(QemuImg);
            }
            required
        }
        Command::Create(_) | Command::Reset { .. } | Command::CreateVmSnapshot { .. } => {
            vec![QemuImg]
        }
        Command::CreateWithCredentials { .. } => vec![QemuImg, DebianAccount],
        Command::RefreshRemoteBases
        | Command::DownloadBase { .. }
        | Command::InstallTool { .. } => vec![Curl],
        Command::AnalyzeOnly { .. } | Command::AnalyzeHostFile { .. } => vec![Bubblewrap],
        Command::MeasureDisk { .. }
        | Command::OpenDiskReference { .. }
        | Command::SaveDiskPartition { .. } => vec![QemuImg],
        Command::OpenCurrentDisk { .. }
        | Command::DumpDisk { .. }
        | Command::ImportQcow2Disk { .. }
        | Command::KeepCurrentDiskAsDump { .. } => vec![QemuImg, Bubblewrap, Prlimit],
        Command::Execute(request) if request.analysis.enabled => vec![Bubblewrap],
        _ => Vec::new(),
    }
}

#[cfg(test)]
impl DependenciesWindow {
    pub(crate) fn missing_for_test(dependency: Dependency) -> Self {
        let mut window = Self::ready_for_test();
        for check in &mut window.report.as_mut().unwrap().checks {
            if check.dependency == dependency {
                check.problem = Some("missing test dependency".into());
            }
        }
        window
    }

    pub(crate) fn with_report_for_test(report: Report) -> Self {
        let mut window = Self::ready_for_test();
        window.report = Some(report);
        window
    }

    pub(crate) fn ready_for_test() -> Self {
        use Dependency::*;
        Self {
            report: Some(Report {
                checks: [
                    Qemu,
                    QemuImg,
                    Gtk,
                    Kvm,
                    Curl,
                    DebianAccount,
                    Bubblewrap,
                    Prlimit,
                ]
                .into_iter()
                .map(|dependency| dependencies::Check {
                    dependency,
                    name: "test tool",
                    purpose: "test",
                    problem: None,
                    hint: "test fix",
                    optional: false,
                    wrong_version: false,
                })
                .collect(),
                ..Report::default()
            }),
            open: false,
            worker: None,
            error: None,
            wake: None,
            quiet: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::VmConfig;

    #[test]
    fn missing_gtk_blocks_start_but_not_recordings_or_close() {
        let mut window = DependenciesWindow::ready_for_test();
        let report = window.report.as_mut().unwrap();
        let gtk = report
            .checks
            .iter_mut()
            .find(|check| check.dependency == Dependency::Gtk)
            .unwrap();
        gtk.problem = Some("GTK missing".into());
        let options = BackendOptions::default();
        let snapshot = Snapshot::default();
        assert!(window
            .require(
                &Command::Start {
                    vm_id: "test".into()
                },
                &options,
                &snapshot
            )
            .is_err());
        window
            .require(&Command::Close, &options, &snapshot)
            .unwrap();
        window
            .require(&Command::Create(VmConfig::default()), &options, &snapshot)
            .unwrap();
    }

    #[test]
    fn snapshot_creation_and_restore_require_disk_tools_but_listing_does_not() {
        let window = DependenciesWindow::missing_for_test(Dependency::QemuImg);
        let options = BackendOptions::default();
        let snapshot = Snapshot::default();
        let create = Command::CreateVmSnapshot {
            vm_id: "vm".into(),
            request: antinomie_monitor_core::SnapshotRequest {
                name: "Checkpoint".into(),
                description: String::new(),
                mode: antinomie_monitor_core::VmSnapshotMode::Disk,
            },
        };
        let restore = Command::RestoreVmSnapshot {
            vm_id: "vm".into(),
            snapshot_id: "point".into(),
            boot_from_disk: true,
            save_current: None,
            confirmed: true,
        };
        assert!(window.require(&create, &options, &snapshot).is_err());
        assert!(window.require(&restore, &options, &snapshot).is_err());
        assert!(window
            .require(
                &Command::RefreshVmSnapshots { vm_id: "vm".into() },
                &options,
                &snapshot
            )
            .is_ok());
        assert!(window
            .require(&Command::ReconnectTransport, &options, &snapshot)
            .is_ok());
    }

    #[test]
    fn pending_checks_allow_shutdown_and_reject_dependent_actions() {
        let window = DependenciesWindow::default();
        let options = BackendOptions::default();
        let snapshot = Snapshot::default();
        window
            .require(&Command::Close, &options, &snapshot)
            .unwrap();
        assert!(window
            .require(&Command::RefreshRemoteBases, &options, &snapshot)
            .is_err());
    }

    #[test]
    fn worker_result_opens_window_when_a_requirement_is_missing() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            sender
                .send(Report {
                    checks: vec![dependencies::Check {
                        dependency: Dependency::Gtk,
                        name: "QEMU GTK display",
                        purpose: "Open VM windows",
                        problem: Some("missing".into()),
                        hint: "sudo apt install qemu-system-gui",
                        optional: false,
                        wrong_version: false,
                    }],
                    ..Report::default()
                })
                .unwrap();
        });
        let mut window = DependenciesWindow {
            wake: None,
            worker: Some((receiver, worker)),
            open: false,
            report: None,
            error: None,
            quiet: false,
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while window.worker.is_some() {
            assert!(std::time::Instant::now() < deadline);
            window.poll();
            thread::yield_now();
        }
        assert!(window.open && window.report.as_ref().unwrap().has_missing());
    }
}

#[cfg(test)]
mod wrong_version_tests {
    use super::*;

    #[test]
    fn an_installed_tool_that_is_too_old_reads_as_wrong_version() {
        let mut window = DependenciesWindow::ready_for_test();
        let check = &mut window.report.as_mut().unwrap().checks[0];
        assert_eq!(state_of(check).1, "Ready");
        check.problem = Some("QEMU 5.2 is older than 6.0".into());
        assert_eq!(state_of(check).1, "Unavailable");
        check.wrong_version = true;
        assert_eq!(state_of(check).1, "Wrong version");
    }
}

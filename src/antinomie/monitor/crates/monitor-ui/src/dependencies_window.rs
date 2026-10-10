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
    pub open: bool,
    report: Option<Report>,
    worker: Option<Worker>,
    error: Option<String>,
}

impl DependenciesWindow {
    pub fn start(options: &BackendOptions) -> Self {
        let mut window = Self::default();
        window.recheck(options);
        window
    }

    fn recheck(&mut self, options: &BackendOptions) {
        if self.worker.is_some() {
            return;
        }
        self.report = None;
        self.error = None;
        let options = options.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        match thread::Builder::new()
            .name("antinomie-dependencies".into())
            .spawn(move || {
                // The receiver can close normally when the app exits.
                let _ = sender.send(dependencies::check(&options));
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
                self.open |= report.has_missing();
                self.report = Some(report);
            }
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                self.error = Some("Dependency check stopped; select Check again to retry".into());
                self.open = true;
            }
        }
        if let Some((_, thread)) = self.worker.take() {
            if thread.join().is_err() {
                self.error = Some("Dependency check failed; select Check again to retry".into());
                self.open = true;
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

    pub fn show(&mut self, ctx: &egui::Context, options: &BackendOptions) {
        if !self.open {
            return;
        }
        let mut recheck = false;
        egui::Window::new("App dependencies")
            .id(egui::Id::new(WINDOW_ID))
            .open(&mut self.open)
            .collapsible(false)
            .default_width(640.0)
            .show(ctx, |ui| {
                ui.label("Missing requirements block the actions listed below. You can still open saved recordings.");
                if self.worker.is_some() {
                    ui.horizontal(|ui| { ui.spinner(); ui.label("Checking this system…"); });
                }
                if let Some(error) = &self.error {
                    ui.colored_label(theme::error(), error);
                }
                if let Some(report) = &self.report {
                    egui::ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                        // Put repairs first so their commands stay visible even
                        // on a small desktop or with enlarged application text.
                        for check in report.checks.iter().filter(|check| check.problem.is_some())
                            .chain(report.checks.iter().filter(|check| check.problem.is_none())) {
                            ui.separator();
                            ui.horizontal_wrapped(|ui| {
                                ui.label(egui::RichText::new(check.name).strong().color(theme::heading()));
                                ui.colored_label(if check.problem.is_some() { theme::warn() } else { theme::good() },
                                    if check.problem.is_some() { "Unavailable" } else { "Ready" });
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
                ui.separator();
                recheck = ui.add_enabled(self.worker.is_none(), egui::Button::new(egui::RichText::new("Check again").color(theme::palette().primary_text)).fill(theme::primary())).clicked();
                ui.weak("Package commands are for Debian/Ubuntu. Install with your system's package manager, then check again. Build tools and optional analysis tools are checked in their own dialogs.");
            });
        if recheck {
            self.recheck(options);
        }
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
        Command::Start { vm_id } => {
            let launch = snapshot
                .vms
                .iter()
                .find(|vm| &vm.id == vm_id)
                .map(|vm| vm.launch.clone())
                .unwrap_or_default();
            dependencies::vm_requirements(options, &launch)
        }
        Command::Create(_) | Command::Reset { .. } => vec![QemuImg],
        Command::CreateWithCredentials { .. } => vec![QemuImg, DebianAccount],
        Command::RefreshRemoteBases
        | Command::DownloadBase { .. }
        | Command::InstallTool { .. } => vec![Curl],
        Command::AnalyzeOnly { .. } => vec![Bubblewrap],
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

    pub(crate) fn ready_for_test() -> Self {
        use Dependency::*;
        Self {
            report: Some(Report {
                checks: [Qemu, QemuImg, Gtk, Kvm, Curl, DebianAccount, Bubblewrap]
                    .into_iter()
                    .map(|dependency| dependencies::Check {
                        dependency,
                        name: "test tool",
                        purpose: "test",
                        problem: None,
                        hint: "test fix",
                    })
                    .collect(),
            }),
            open: false,
            worker: None,
            error: None,
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
                    }],
                })
                .unwrap();
        });
        let mut window = DependenciesWindow {
            worker: Some((receiver, worker)),
            open: false,
            report: None,
            error: None,
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

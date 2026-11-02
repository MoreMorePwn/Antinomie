// SPDX-License-Identifier: GPL-3.0-only
//! Native tour of a host without KVM, driving the real backend: creates a VM
//! from a saved configuration with Default acceleration, starts it, and takes
//! screenshots of the Warning, the slow-boot note and the Settings that tune
//! it. Needs an X11 display (DISPLAY) and QEMU; exits by itself.
//!
//! ANTINOMIE_QA_DATA = throwaway data folder holding bases/<identity>,
//! ANTINOMIE_QA_VM_JSON = a saved VM config.json, ANTINOMIE_QA_SHOTS = folder
//! for the PNGs, ANTINOMIE_QA_THEME = dark | light, ANTINOMIE_QA_SIZE = 1280x820,
//! ANTINOMIE_QA_PREFIX = file name prefix.
use super::*;
use crate::theme::Theme;

#[test]
#[ignore = "requires X11 native rendering, QEMU and a throwaway data folder"]
fn native_tcg_tour() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Phase {
        Settle,
        Created,
        Deps,
        Settings,
        Dialog,
        Starting,
        Note,
        Running,
        Stopping,
    }
    struct Tour {
        app: MonitorApp,
        phase: Phase,
        next: Instant,
        vm: VmConfig,
        shots: PathBuf,
        prefix: String,
        started: Instant,
    }
    impl Tour {
        fn shot(&self, name: &str) {
            let file = self.shots.join(format!("{}-{name}.png", self.prefix));
            let status = std::process::Command::new("import")
                .args(["-window", "root"])
                .arg(&file)
                .status();
            println!("shot {} {:?}", file.display(), status);
        }
    }
    impl eframe::App for Tour {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            eframe::App::update(&mut self.app, ctx, frame);
            ctx.request_repaint_after(Duration::from_millis(100));
            if self.started.elapsed() > Duration::from_secs(900) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if Instant::now() < self.next {
                return;
            }
            let after = |seconds: f32| Instant::now() + Duration::from_secs_f32(seconds);
            match self.phase {
                Phase::Settle => {
                    if self.app.dependencies.checking() || self.app.dependencies.report().is_none()
                    {
                        self.next = after(0.5);
                        return;
                    }
                    self.app.send(Command::Create(self.vm.clone()));
                    self.phase = Phase::Created;
                    self.next = after(2.0);
                }
                Phase::Created => {
                    let Some(vm) = self.app.snapshot.vms.last().cloned() else {
                        self.next = after(0.5);
                        return;
                    };
                    self.app.selected = Some(vm.id);
                    self.app.dependencies.open = true;
                    self.phase = Phase::Deps;
                    self.next = after(2.0);
                }
                Phase::Deps => {
                    self.shot("1-dependencies-warning");
                    self.app.dependencies.open = false;
                    self.app.settings_open = true;
                    self.app.settings_page = super::super::settings_window::SettingsPage::Advanced;
                    self.phase = Phase::Settings;
                    self.next = after(2.0);
                }
                Phase::Settings => {
                    self.shot("2-settings-advanced");
                    self.app.settings_open = false;
                    self.app.configure_vm();
                    self.app.config_open = true;
                    self.phase = Phase::Dialog;
                    self.next = after(2.0);
                }
                Phase::Dialog => {
                    self.shot("3-vm-dialog-acceleration");
                    self.app.config_open = false;
                    if let Some(id) = self.app.selected.clone() {
                        self.app.send(Command::Start { vm_id: id });
                    }
                    self.phase = Phase::Starting;
                    self.next = after(6.0);
                }
                Phase::Starting => {
                    if self.app.snapshot.state == VmState::Starting
                        && self.app.snapshot.start_note.is_some()
                    {
                        self.phase = Phase::Note;
                        self.next = after(1.0);
                    } else if self.app.snapshot.state == VmState::Running {
                        self.phase = Phase::Note;
                    } else {
                        self.next = after(0.5);
                    }
                }
                Phase::Note => {
                    self.shot("4-starting-slow-tcg-boot");
                    self.phase = Phase::Running;
                    self.next = after(0.5);
                }
                Phase::Running => match self.app.snapshot.state {
                    VmState::Running => {
                        // Let the toast show with its countdown.
                        std::thread::sleep(Duration::from_millis(700));
                        self.shot("5-running-with-tcg-warning-toast");
                        println!("accelerator {:?}", self.app.snapshot.accelerator);
                        self.app.send(Command::Stop);
                        self.phase = Phase::Stopping;
                        self.next = after(1.0);
                    }
                    VmState::Failed | VmState::Stopped => {
                        println!("start failed: {:?}", self.app.snapshot.last_error);
                        self.shot("5-failed");
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    _ => self.next = after(0.5),
                },
                Phase::Stopping => {
                    if self.app.snapshot.state == VmState::Stopped {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    } else {
                        self.next = after(0.5);
                    }
                }
            }
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let data = PathBuf::from(var("ANTINOMIE_QA_DATA"));
    let mut vm: VmConfig =
        serde_json::from_str(&std::fs::read_to_string(var("ANTINOMIE_QA_VM_JSON")).unwrap())
            .unwrap();
    vm.id = String::new();
    vm.name = "TCG demo".into();
    vm.launch.acceleration = VmAcceleration::Default;
    let base = vm.base_identity.clone().unwrap();
    let shots = PathBuf::from(var("ANTINOMIE_QA_SHOTS"));
    let prefix = var("ANTINOMIE_QA_PREFIX");
    eframe::run_native(
        "Antinomie TCG QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            let options = BackendOptions {
                data_dir: data.clone(),
                bundle_dir: data.join("bases").join(base),
                ..BackendOptions::default()
            };
            let mut app = MonitorApp::new(cc, options, None, false);
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            Ok(Box::new(Tour {
                app,
                phase: Phase::Settle,
                next: Instant::now() + Duration::from_secs(2),
                vm,
                shots,
                prefix,
                started: Instant::now(),
            }))
        }),
    )
    .expect("native tcg tour");
}

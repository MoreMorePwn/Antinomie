// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for a VM that asks for SATA on a base without it, for
//! screenshots in each theme. Needs an X11 display; exits by itself.
//!
//! ANTINOMIE_QA_SCENE = window (the Stealth window beside the VM dialog) |
//! summary (the VM's Summary header and the sidebar badge),
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x900,
//! ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::theme::Theme;
use antinomie_monitor_core::stealth::{DiskBus, Firmware, NatNetwork};

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_stealth_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        "blue" => Theme::Blue,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 900.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    let scene = var("ANTINOMIE_QA_SCENE");
    eframe::run_native(
        "Antinomie Stealth QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = app();
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            let mut old = test_base("old", true);
            old.label = "Linux 6.12.94 (built before 0.7.0)".into();
            let mut new = test_base("new", true);
            new.label = "BusyBox 0.7.0".into();
            new.stealth_support = ["uefi", "sata", "nvme", "dhcp"].map(String::from).into();
            app.snapshot.bases = vec![old, new];
            let mut vm = VmConfig {
                id: "vm".into(),
                name: "Analysis VM".into(),
                base_identity: Some("old".into()),
                ..VmConfig::default()
            };
            vm.stealth.disk_bus = DiskBus::Sata;
            vm.stealth.firmware = Firmware::Bios;
            vm.stealth.smt = false;
            vm.stealth.nat = NatNetwork::default();
            app.snapshot.vms.push(vm.clone());
            app.selected = Some("vm".into());
            if scene == "window" {
                app.draft = vm;
                app.config_open = true;
                app.stealth_open = true;
            } else {
                workspace(&mut app).focus(Panel::Summary);
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native stealth fixture");
}

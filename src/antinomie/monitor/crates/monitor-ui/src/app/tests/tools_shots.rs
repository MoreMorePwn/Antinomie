// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for the Tools menu windows: base images, analysis tools,
//! API keys, app dependencies and the update check. Needs an X11 display;
//! exits by itself.
//!
//! ANTINOMIE_QA_SCENE = bases | tools | keys | deps | updates | updates_off | routes,
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1500x1050,
//! ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::theme::Theme;
use antinomie_monitor_core::{
    analysis_tools::{ToolInstall, ToolStatus},
    update_check::{Release, UpdateStatus},
};

fn tool(id: &str, name: &str, version: &str, size: u64, installed: Option<&str>) -> ToolStatus {
    ToolStatus {
        id: id.into(),
        name: name.into(),
        purpose: "A tool the fixture shows".into(),
        version: version.into(),
        size,
        system: None,
        installed: installed.map(str::to_owned),
        installed_path: installed
            .map(|_| format!("/home/analyst/.local/share/antinomie/tools/{id}/{id}")),
    }
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_tools_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                self.app.snapshot.active_vm = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let scene = var("ANTINOMIE_QA_SCENE");
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        "blue" => Theme::Blue,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1500.0, 1050.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse().unwrap_or(25);
    eframe::run_native(
        "Antinomie tools fixture",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = super::ui_polish_shots::history_fixture();
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            let mut tools = vec![
                tool("capa", "capa", "9.0.0", 15_000_000, Some("9.0.0")),
                tool("floss", "FLOSS", "3.1.1", 40_000_000, None),
                tool(
                    "tor",
                    "Tor",
                    "0.4.9.14 (Expert Bundle 15.0.26)",
                    32_448_097,
                    None,
                ),
                tool("wireproxy", "wireproxy", "1.1.3", 4_123_755, Some("1.1.3")),
            ];
            tools[1].system = Some("/usr/local/bin/floss".into());
            app.snapshot.analysis_tools = tools;
            match scene.as_str() {
                "bases" => {
                    let rows = [
                        ("Debian 13 (trixie)", 4.2, "debian-13"),
                        ("BusyBox 1.37", 0.1, "busybox"),
                        ("Linux 6.12.94 with a long base name", 2.6, "linux"),
                    ];
                    app.snapshot.bases = rows
                        .iter()
                        .map(|(label, gib, id)| {
                            let mut base = test_base(id, true);
                            base.label = (*label).into();
                            base.size_bytes = (gib * 1073741824.0) as u64;
                            base
                        })
                        .collect();
                    app.snapshot.bases[2].revision = Some(1);
                    app.open_library(crate::workspace::LibraryPage::BaseImages);
                }
                "tools" => app.open_library(crate::workspace::LibraryPage::Tools),
                "keys" => app.api_keys.open = true,
                "deps" => {
                    app.dependencies.open = true;
                    app.snapshot.tool_install = Some(ToolInstall {
                        id: "tor".into(),
                        name: "Tor".into(),
                        stage: "download".into(),
                        received: 10 << 20,
                        total: 30 << 20,
                        finished: false,
                        error: None,
                    });
                }
                "routes" => app.open_routes_settings(),
                "updates" | "updates_off" => {
                    let release = Release {
                        tag: "v0.8.1".into(),
                        version: "0.8.1".into(),
                        url: "https://github.com/MoreMorePwn/Antinomie/releases/tag/v0.8.1".into(),
                    };
                    app.settings.outbound_catalog = scene == "updates";
                    app.updates = if scene == "updates" {
                        crate::update_window::UpdateWindow::with_answer_for_test(Ok(
                            UpdateStatus::Newer(release),
                        ))
                    } else {
                        let mut window = crate::update_window::UpdateWindow::default();
                        window.open = true;
                        window
                    };
                }
                _ => {}
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native tools fixture");
}

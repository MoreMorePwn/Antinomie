// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for the Settings, Snapshots and Run program windows, for
//! screenshots in each theme and size. Needs an X11 display; exits by itself.
//!
//! ANTINOMIE_QA_DIALOG = settings | snapshots | run
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
//! ANTINOMIE_QA_PAGE = settings page name (or `upload` for run), ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::app::settings_window::SettingsPage;
use crate::theme::Theme;

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_dialog_fixture() {
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
    let which = var("ANTINOMIE_QA_DIALOG");
    let theme_choice = match var("ANTINOMIE_QA_THEME").as_str() {
        "light" => Theme::Light,
        "blue" => Theme::Blue,
        _ => Theme::Dark,
    };
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    let page_name = var("ANTINOMIE_QA_PAGE");
    let page = SettingsPage::ALL
        .into_iter()
        .find(|page| page.label().eq_ignore_ascii_case(&page_name))
        .unwrap_or_default();
    eframe::run_native(
        "Antinomie Dialog QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([width, height]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = analysis_setup_fixture();
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            app.launch_open = false;
            app.snapshot.guest_kernel = Some(antinomie_monitor_core::GuestKernel {
                revision: Some(17),
                ..Default::default()
            });
            match which.as_str() {
                "settings" => {
                    app.settings_open = true;
                    app.settings_page = page;
                }
                "snapshots" => {
                    app.snapshot
                        .vm_snapshot_trees
                        .insert("vm".into(), crate::snapshots::tests::fixture());
                    app.vm_snapshots.bind("vm", "Analysis QA");
                    app.vm_snapshots.selected = Some("sample".into());
                }
                _ => {
                    app.launch_open = true;
                    app.args = String::new();
                    if page_name == "upload" {
                        app.launch_source = crate::analysis::LaunchSource::Upload;
                        app.source = "/home/analyst/samples/dropper.elf".into();
                        app.destination = "/tmp/dropper.elf".into();
                    }
                }
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native dialog fixture");
}

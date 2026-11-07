// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for Stop run: the toolbar with a run whose root exited and
//! whose child lives on, and the confirmation. Needs an X11 display; exits by
//! itself.
//!
//! ANTINOMIE_QA_SCENE = toolbar | confirm
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
//! ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::theme::Theme;

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_stop_run_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn ui(&mut self, root: &mut egui::Ui, frame: &mut eframe::Frame) {
            let ctx = &root.ctx().clone();
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::ui(&mut self.app, root, frame);
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
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(25);
    eframe::run_native(
        "Antinomie Stop run QA",
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
            let mut app = app();
            observer_fixture(&mut app);
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            // The root exited 0 and one child lives on.
            app.snapshot.runs = vec![super::run_kill::orphaned("orphan", 1)];
            if scene == "confirm" {
                app.request_kill(None);
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native stop run fixture");
}

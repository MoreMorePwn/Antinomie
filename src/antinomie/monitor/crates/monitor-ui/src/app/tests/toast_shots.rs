// SPDX-License-Identifier: MIT
//! Native fixture for the toast stack and the Activity tab's counts, for
//! screenshots in each theme and size. Needs an X11 display; exits by itself.
//!
//! ANTINOMIE_QA_SCENE = stack | dialog (the Settings window open under the stack)
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
//! ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::activity::Level;
use crate::theme::Theme;
use crate::toasts::{self, Action};

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_toast_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        seeded: bool,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if !self.seeded {
                self.seeded = true;
                seed(ctx);
                self.app.focus_panel = Some(crate::workspace::Panel::Activity);
            }
            // A screenshot needs the stack to stay.
            toasts::keep_alive(ctx);
            eframe::App::update(&mut self.app, ctx, frame);
            ctx.request_repaint_after(Duration::from_millis(200));
        }
    }
    fn seed(ctx: &egui::Context) {
        toasts::push(
            ctx,
            Level::Info,
            "Starting debian-13-lab",
            "QEMU/KVM · 4 vCPU · 4096 MiB · isolated network",
            Some(Action::open_activity()),
        );
        for _ in 0..2 {
            toasts::push(
                ctx,
                Level::Warn,
                "Rule trigger fired",
                "'core on first outbound connect' matched connect() in PID 1312",
                Some(Action::open_activity()),
            );
        }
        for _ in 0..3 {
            toasts::push(
                ctx,
                Level::Error,
                "Sigma input failed",
                "audit.log: pySigma backend returned exit 2. Details are in Activity.",
                Some(Action::open_activity()),
            );
        }
        toasts::push(
            ctx,
            Level::Error,
            "Saving the run failed",
            "No space left on device while writing telemetry.raw (a very long path follows: /var/lib/antinomie/runs/7c1e9a2f/telemetry.raw)",
            None,
        );
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
        "Antinomie Toast QA",
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
            if scene == "dialog" {
                app.settings_open = true;
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
                seeded: false,
            }))
        }),
    )
    .expect("native toast fixture");
}

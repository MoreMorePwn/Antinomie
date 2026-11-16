// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for the window splitting screenshots: one window split off
//! the main tab group, side by side or stacked. Needs an X11 display; exits
//! by itself.
//!
//! ANTINOMIE_QA_SPLIT_PANEL = memory | network | trace | triage | static |
//! core | disks | history | summary | samples | rules (the window split off),
//! ANTINOMIE_QA_SPLIT = right | below, ANTINOMIE_QA_FRACTION = the main
//! group's share (0.5), ANTINOMIE_QA_SIZE = 1280x820, ANTINOMIE_QA_SECONDS = 20.
use super::*;
use crate::workspace::{LibraryPage, Panel};

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_split_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn ui(&mut self, root: &mut egui::Ui, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                self.app.snapshot.active_vm = None;
                root.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::ui(&mut self.app, root, frame);
            root.ctx().request_repaint_after(Duration::from_millis(200));
        }
    }
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let panel = match var("ANTINOMIE_QA_SPLIT_PANEL").as_str() {
        "network" => Panel::Network,
        "trace" => Panel::Trace,
        "triage" => Panel::Triage,
        "static" => Panel::StaticAnalysis,
        "core" => Panel::CoreDump,
        "disks" => Panel::Disks,
        "history" => Panel::RunHistory,
        "summary" => Panel::Summary,
        "samples" => Panel::Library(LibraryPage::Samples),
        "rules" => Panel::Library(LibraryPage::Rules),
        _ => Panel::Memory,
    };
    let split = if var("ANTINOMIE_QA_SPLIT") == "below" {
        egui_dock::Split::Below
    } else {
        egui_dock::Split::Right
    };
    let fraction = var("ANTINOMIE_QA_FRACTION").parse::<f32>().unwrap_or(0.5);
    let (width, height) = var("ANTINOMIE_QA_SIZE")
        .split_once('x')
        .and_then(|(w, h)| Some((w.parse::<f32>().ok()?, h.parse::<f32>().ok()?)))
        .unwrap_or((1280.0, 820.0));
    let seconds = var("ANTINOMIE_QA_SECONDS").parse::<u64>().unwrap_or(20);
    eframe::run_native(
        "Antinomie split QA",
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
            let mut app = super::ui_polish_shots::history_fixture();
            // Run History is the other part, so the main group shows it.
            let other = if panel == Panel::RunHistory {
                Panel::Summary
            } else {
                Panel::RunHistory
            };
            let layout = workspace(&mut app);
            layout.split_beside_history(&panel, split, fraction);
            layout.focus(other);
            layout.focus(panel);
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native split fixture");
}

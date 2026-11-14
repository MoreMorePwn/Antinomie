// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for screenshots of the timed-screenshots UI (ANT-T0487):
//! the Run program form's Screen section and Library > Screenshots with a made-up
//! run series. Needs an X11 display; exits by itself.
//!
//! ANTINOMIE_QA_SCENE = run | library, ANTINOMIE_QA_THEME = dark | light | blue,
//! ANTINOMIE_QA_SIZE = 1280x820, ANTINOMIE_QA_SECONDS = 25,
//! ANTINOMIE_QA_DATA = a throwaway folder for the pictures.
use super::*;
use crate::{app::tests::analysis_setup_fixture, theme::Theme};
use std::time::{Duration, Instant};

/// A made-up 640 x 360 desktop at `t` seconds: a window that fills up, and a
/// red note that appears after 40 s.
fn picture(t: u64) -> Vec<u8> {
    let (w, h) = (640usize, 360usize);
    let mut rgba = vec![255u8; w * h * 4];
    let mut paint = |x0: usize, y0: usize, x1: usize, y1: usize, rgb: [u8; 3]| {
        for y in y0..y1.min(h) {
            for x in x0..x1.min(w) {
                rgba[(y * w + x) * 4..][..3].copy_from_slice(&rgb);
            }
        }
    };
    paint(0, 0, w, h, [24, 36, 64]);
    paint(0, h - 28, w, h, [40, 44, 52]);
    paint(40, 40, 400, 260, [236, 236, 236]);
    paint(40, 40, 400, 62, [90, 100, 120]);
    for line in 0..((t / 10).min(8) as usize) {
        paint(
            56,
            80 + line * 20,
            56 + 120 + line * 24,
            90 + line * 20,
            [60, 60, 60],
        );
    }
    if t >= 40 {
        paint(260, 110, 600, 330, [180, 20, 20]);
        paint(276, 130, 584, 150, [255, 255, 255]);
        paint(276, 170, 520, 180, [255, 220, 220]);
        paint(276, 196, 540, 206, [255, 220, 220]);
    }
    antinomie_monitor_core::vnc::encode_png(w, h, &rgba).unwrap()
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_timed_screenshots_fixture() {
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
    let data = PathBuf::from(var("ANTINOMIE_QA_DATA"));
    assert!(data.is_absolute(), "ANTINOMIE_QA_DATA must be a folder");
    crate::app::tests::exit_after(seconds);
    eframe::run_native(
        "Antinomie Timed Screenshots QA",
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
            if scene == "library" {
                app.launch_open = false;
                let folder = data.join("screenshots");
                std::fs::create_dir_all(&folder).unwrap();
                let started = 1_792_000_000_000u64;
                let label = "timed screenshots of run dropper.sh (2026-11-13 14:02:11)".to_owned();
                for step in 0..12u64 {
                    let rel = step * 5_000 + 1_400;
                    let path = folder.join(antinomie_monitor_core::timed_shots::file_name(rel));
                    std::fs::write(&path, picture(rel / 1000)).unwrap();
                    app.screenshots_page.shots.push(Shot {
                        path,
                        vm_id: "vm".into(),
                        vm_name: "Analysis QA".into(),
                        ms: started + rel,
                        run: Some(label.clone()),
                        rel_ms: Some(rel),
                    });
                }
                app.screenshots_page.shots.reverse();
                app.screenshots_page.loaded = true;
                app.open_library(crate::workspace::LibraryPage::Screenshots);
            } else {
                app.snapshot.vm_screen = Some(PathBuf::from("/nonexistent/vnc.sock"));
                app.exec.screenshot_every_s = Some(10);
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
            }))
        }),
    )
    .expect("native timed screenshots fixture");
}

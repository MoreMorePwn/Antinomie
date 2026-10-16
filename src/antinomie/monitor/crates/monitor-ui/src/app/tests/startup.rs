// SPDX-License-Identifier: MIT
//! Start-up checks and the frame-time probe.
use super::*;

#[test]
fn missing_startup_dependency_blocks_a_command_before_submission() {
    let mut app = app();
    app.dependencies = crate::dependencies_window::DependenciesWindow::missing_for_test(
        antinomie_monitor_core::dependencies::Dependency::Gtk,
    );
    app.send(Command::Start {
        vm_id: "test".into(),
    });
    assert!(app.submitted.is_empty());
    assert!(app.dependencies.open);
    assert!(app.status.contains("missing test dependency"));
    app.send(Command::Close);
    assert!(matches!(app.submitted.last(), Some(Command::Close)));
}
#[test]
#[ignore = "isolated native idle/performance probe; requires X11 and ANTINOMIE_PERF_QA_DIR"]
fn native_ui_performance_probe() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct Probe {
        app: MonitorApp,
        started: Instant,
        warmed: bool,
        finished: bool,
        previous_cadence: bool,
        directory: PathBuf,
    }
    impl eframe::App for Probe {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if !self.warmed && self.started.elapsed() >= Duration::from_secs(1) {
                self.app.performance.reset_for_probe();
                self.warmed = true;
            }
            eframe::App::update(&mut self.app, ctx, frame);
            if self.previous_cadence {
                ctx.request_repaint_after(Duration::from_millis(50));
            }
            ctx.request_repaint_after(
                Duration::from_secs(4).saturating_sub(self.started.elapsed()),
            );
            if self.started.elapsed() >= Duration::from_secs(4) && !self.finished {
                self.finished = true;
                std::fs::write(
                    self.directory.join("report.json"),
                    serde_json::to_vec_pretty(&self.app.performance.probe_report()).unwrap(),
                )
                .unwrap();
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }
    let directory =
        PathBuf::from(std::env::var_os("ANTINOMIE_PERF_QA_DIR").expect("probe output directory"));
    std::fs::create_dir_all(&directory).unwrap();
    let previous_cadence = std::env::var_os("ANTINOMIE_PERF_QA_POLLING").is_some();
    let diagnostic = std::env::var_os("ANTINOMIE_PERF_QA_DIAGNOSTIC").is_some();
    let options = BackendOptions {
        data_dir: directory.join("data"),
        bundle_dir: directory.join("no-bundle"),
        ..Default::default()
    };
    let storage = directory.join("ui.ron");
    eframe::run_native(
        "Antinomie UI Performance QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1280.0, 820.0]),
            persistence_path: Some(storage),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            let mut app = MonitorApp::new(cc, options, None, false);
            app.performance.open = diagnostic;
            Ok(Box::new(Probe {
                app,
                started: Instant::now(),
                warmed: false,
                finished: false,
                previous_cadence,
                directory,
            }))
        }),
    )
    .expect("native UI performance probe");
}

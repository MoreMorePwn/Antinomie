// SPDX-License-Identifier: GPL-3.0-only
//! Native fixture for the Run History and Static Analysis polish screenshots.
//! Needs an X11 display; exits by itself.
//!
//! ANTINOMIE_QA_SCENE = history | static | details
//! ANTINOMIE_QA_THEME = dark | light | blue, ANTINOMIE_QA_SIZE = 1280x820,
//! ANTINOMIE_QA_SECONDS = 25.
use super::*;
use crate::theme::Theme;
use antinomie_monitor_core::{capture_processes::CaptureProcess, AnalysisKind, RunState};

fn process(pid: u32, parent: u32, name: &str, calls: u64) -> CaptureProcess {
    CaptureProcess {
        pid,
        parent_pid: parent,
        name: name.into(),
        exe: Some(format!("/usr/bin/{name}")),
        at_start: false,
        first_ns: 1_000_000_000,
        last_ns: 2_000_000_000,
        calls,
        packets: 0,
        exited: true,
        exit_code: Some(0),
    }
}

/// Three finished runs of the same VM; the first has a static report with
/// one unavailable check and one that produced nothing.
pub(super) fn history_fixture() -> MonitorApp {
    let mut app = analysis_setup_fixture();
    app.launch_open = false;
    app.snapshot.state = VmState::Running;
    let mut runs = Vec::new();
    for (index, path) in ["/tmp/dropper", "/usr/bin/curl", "/opt/miner/xmrig"]
        .into_iter()
        .enumerate()
    {
        let mut run = run(&format!("run-{}", index + 1));
        run.state = RunState::Finished;
        run.started_ms = Some(1_760_000_000_000 + index as u64 * 90_000);
        run.request.path = path.into();
        run.request.args = vec!["-o".into(), "pool.example:3333".into()];
        run.request.analysis.enabled = index == 0;
        run.request.analysis.checks = vec![
            AnalysisKind::Metadata,
            AnalysisKind::Structures,
            AnalysisKind::Strings,
            AnalysisKind::Rules,
        ];
        run.request.capture_network = true;
        run.request.core_dump_on_exit = index == 0;
        run.request.core_max_size = Some(256 << 20);
        if index == 0 {
            run.analysis = Some(section_report("report-1", "dropper"));
        }
        runs.push(run);
    }
    app.history = runs;
    app.selected_run = Some("run-1".into());
    app.archive_selected = true;
    app.run_tree = Some((
        "run-1".into(),
        Ok((
            vec![
                process(42, 1, "dropper", 120),
                process(43, 42, "sh", 80),
                process(44, 43, "curl", 40),
                process(45, 42, "chmod", 6),
            ],
            Vec::new(),
        )),
    ));
    app
}

#[test]
#[ignore = "requires X11 native rendering; exits after the given seconds"]
fn native_ui_polish_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        scene: String,
        seeded: bool,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            if !self.seeded {
                self.seeded = true;
                self.app.focus_panel = Some(if self.scene == "static" {
                    crate::workspace::Panel::StaticAnalysis
                } else {
                    crate::workspace::Panel::RunHistory
                });
            }
            if self.scene == "details" {
                // The run's Details alone, tall enough to show all of it.
                egui::CentralPanel::default().show(ctx, |ui| self.app.history_detail(ui));
            } else {
                eframe::App::update(&mut self.app, ctx, frame);
            }
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
        "Antinomie UI polish QA",
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
            let mut app = history_fixture();
            app.settings.set_theme(theme_choice);
            theme::apply_theme(&cc.egui_ctx, theme_choice);
            if scene == "static" {
                app.selected_analysis = Some("report-1".into());
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
                scene,
                seeded: false,
            }))
        }),
    )
    .expect("native ui polish fixture");
}

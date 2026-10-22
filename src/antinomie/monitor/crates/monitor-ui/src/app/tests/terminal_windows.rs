// SPDX-License-Identifier: GPL-3.0-only
//! Native terminal window geometry.
use super::*;

#[test]
#[ignore = "requires decorated X11; automatically checks terminal geometry and exits"]
fn native_terminal_geometry_regression() {
    use std::sync::{Arc, Mutex};
    use winit::platform::x11::EventLoopBuilderExtX11;
    #[derive(Default)]
    struct Evidence {
        samples: Vec<(f32, egui::Pos2, egui::Vec2)>,
        raw_geometry: Vec<(f32, egui::Rect, egui::Rect)>,
        decorated: bool,
        retained: bool,
        reopened: bool,
    }
    struct QaApp {
        app: MonitorApp,
        started: Instant,
        evidence: Arc<Mutex<Evidence>>,
        moved: bool,
        closed: bool,
        reopened: bool,
        settled_after: Option<f32>,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            let elapsed = self.started.elapsed().as_secs_f32();
            let viewport = egui::ViewportId::from_hash_of(("workspace", 1usize));
            if elapsed >= 8.0 {
                self.app.snapshot.active_vm = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
            if elapsed >= 0.5 && (!self.closed || self.reopened) {
                if let Some((outer, inner)) = ctx.input_for(viewport, |input| {
                    Some((input.viewport().outer_rect?, input.viewport().inner_rect?))
                }) {
                    let mut evidence = self.evidence.lock().expect("geometry evidence");
                    evidence.raw_geometry.push((elapsed, outer, inner));
                    if inner.min.y - outer.min.y >= 10.0 {
                        evidence.decorated = true;
                        self.settled_after.get_or_insert(elapsed + 0.7);
                    }
                    if self.settled_after.is_some_and(|after| elapsed >= after) {
                        evidence.samples.push((elapsed, outer.min, inner.size()));
                    }
                }
            }
            if elapsed >= 3.0 && !self.moved {
                self.moved = true;
                ctx.send_viewport_cmd_to(
                    viewport,
                    egui::ViewportCommand::OuterPosition(egui::pos2(140.0, 100.0)),
                );
                ctx.send_viewport_cmd_to(
                    viewport,
                    egui::ViewportCommand::InnerSize(egui::vec2(740.0, 460.0)),
                );
            }
            if elapsed >= 5.0 && !self.closed {
                self.closed = true;
                self.settled_after = None;
                self.app.close_terminal_view("geometry-terminal");
            }
            if elapsed >= 5.5 && !self.reopened {
                self.reopened = true;
                let terminal = self
                    .app
                    .terminals
                    .get_mut("geometry-terminal")
                    .expect("retained terminal");
                terminal.open = true;
                let mut evidence = self.evidence.lock().expect("geometry evidence");
                evidence.retained = terminal
                    .terminal
                    .contents()
                    .contains("GEOMETRY BUFFER RETAINED");
                evidence.reopened = true;
            }
            ctx.request_repaint_after(Duration::from_millis(10));
        }
    }
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let result = evidence.clone();
    eframe::run_native(
        "Antinomie Terminal Geometry QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 720.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = app();
            let run = run("geometry-terminal");
            app.snapshot.runs.push(run.clone());
            let mut terminal = RunTerminal::new(run);
            terminal.output(1, b"GEOMETRY BUFFER RETAINED\r\n", false);
            app.terminals.insert("geometry-terminal".into(), terminal);
            Ok(Box::new(QaApp {
                app,
                started: Instant::now(),
                evidence,
                moved: false,
                closed: false,
                reopened: false,
                settled_after: None,
            }))
        }),
    )
    .expect("native geometry fixture");
    let evidence = result.lock().expect("geometry evidence");
    eprintln!(
        "Decorated: {}; samples: {}; buffer retained: {}; reopened: {}",
        evidence.decorated,
        evidence.samples.len(),
        evidence.retained,
        evidence.reopened
    );
    assert!(
        evidence.decorated,
        "fixture requires a decorating X11 window manager"
    );
    eprintln!(
        "Raw geometry (time, outer rect, inner rect): {:?}",
        evidence.raw_geometry
    );
    for (start, end) in [(1.2, 2.8), (3.8, 4.9), (6.2, 7.8)] {
        let samples: Vec<_> = evidence
            .samples
            .iter()
            .filter(|(time, _, _)| *time >= start && *time <= end)
            .collect();
        assert!(
            samples.len() >= 10,
            "insufficient geometry samples: {}",
            samples.len()
        );
        let (_, origin, size) = samples[0];
        let max_drift = samples
            .iter()
            .map(|(_, next, _)| next.distance(*origin))
            .fold(0.0_f32, f32::max);
        let max_resize = samples
            .iter()
            .map(|(_, _, next)| (*next - *size).length())
            .fold(0.0_f32, f32::max);
        eprintln!(
            "Phase {start}..{end}: {} samples; outer origin {origin:?}; inner size {size:?}; max drift {max_drift}; max resize {max_resize}",
            samples.len()
        );
        assert!(
            max_drift <= 2.0,
            "terminal outer origin drifted {max_drift} points"
        );
        assert!(
            max_resize <= 2.0,
            "terminal inner size drifted {max_resize} points"
        );
        if start == 3.8 {
            assert!(
                origin.distance(egui::pos2(140.0, 100.0)) <= 2.0,
                "move target was not applied: {origin:?}"
            );
            assert!(
                (*size - egui::vec2(740.0, 460.0)).length() <= 2.0,
                "resize target was not applied: {size:?}"
            );
        }
        if start == 6.2 {
            assert!(
                (*size - egui::vec2(820.0, 520.0)).length() <= 2.0,
                "reopened viewport did not expose fresh default geometry: {size:?}"
            );
            assert!(
                origin.x >= 0.0
                    && origin.y >= 0.0
                    && origin.x + size.x <= 1600.0
                    && origin.y + size.y <= 1000.0,
                "reopened window is not on screen: {origin:?}/{size:?}"
            );
        }
    }
    assert!(evidence.retained && evidence.reopened);
}

#[test]
#[ignore = "requires decorated X11; maximizes a terminal window and exits"]
fn native_terminal_window_maximizes_and_grows_its_grid() {
    use std::sync::{Arc, Mutex};
    use winit::platform::x11::EventLoopBuilderExtX11;
    #[derive(Default)]
    struct Evidence {
        before: Option<(egui::Vec2, (u16, u16))>,
        after: Option<(egui::Vec2, (u16, u16), bool)>,
    }
    struct QaApp {
        app: MonitorApp,
        started: Instant,
        evidence: Arc<Mutex<Evidence>>,
        maximized: bool,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            let elapsed = self.started.elapsed().as_secs_f32();
            let viewport = egui::ViewportId::from_hash_of(("workspace", 1usize));
            if elapsed >= 5.0 {
                self.app.snapshot.active_vm = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
            let inner = ctx.input_for(viewport, |input| input.viewport().inner_rect);
            let maximized = ctx.input_for(viewport, |input| input.viewport().maximized);
            let grid = self.app.terminals["maximize"].terminal.size();
            let mut evidence = self.evidence.lock().expect("maximize evidence");
            if elapsed >= 1.5 && !self.maximized {
                self.maximized = true;
                evidence.before = inner.map(|inner| (inner.size(), grid));
                // The same request the window manager's maximize button makes.
                ctx.send_viewport_cmd_to(viewport, egui::ViewportCommand::Maximized(true));
            }
            if elapsed >= 4.0 {
                evidence.after = inner.map(|inner| (inner.size(), grid, maximized == Some(true)));
            }
            ctx.request_repaint_after(Duration::from_millis(10));
        }
    }
    let evidence = Arc::new(Mutex::new(Evidence::default()));
    let result = evidence.clone();
    eframe::run_native(
        "Antinomie Terminal Maximize QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([1024.0, 720.0]),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = app();
            app.snapshot.state = VmState::Running;
            app.snapshot.active_vm = Some("vm".into());
            let run = run("maximize");
            app.snapshot.runs.push(run.clone());
            app.terminals
                .insert("maximize".into(), RunTerminal::new(run));
            Ok(Box::new(QaApp {
                app,
                started: Instant::now(),
                evidence,
                maximized: false,
            }))
        }),
    )
    .expect("native maximize fixture");
    let evidence = result.lock().expect("maximize evidence");
    let (size, grid) = evidence.before.expect("terminal window before maximizing");
    let (maximized_size, maximized_grid, maximized) =
        evidence.after.expect("terminal window after maximizing");
    eprintln!("Before: {size:?} {grid:?}; after: {maximized_size:?} {maximized_grid:?}");
    assert!(
        maximized,
        "window manager did not maximize the terminal window"
    );
    assert!(maximized_size.x > size.x + 100.0 && maximized_size.y > size.y + 100.0);
    assert!(maximized_grid.0 > grid.0 && maximized_grid.1 > grid.1);
}

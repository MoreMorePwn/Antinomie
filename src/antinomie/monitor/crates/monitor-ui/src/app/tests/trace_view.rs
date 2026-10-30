// SPDX-License-Identifier: GPL-3.0-only
//! Terminal focus, trace selection and trace categories.
use super::*;

#[test]
fn terminal_close_flushes_queued_enter_before_hiding_and_stops_at_focus_loss() {
    fn enter() -> egui::Event {
        egui::Event::Key {
            key: egui::Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }
    }
    for (focused, events, expected) in [
        (
            true,
            vec![egui::Event::Text("echo queued".into()), enter()],
            b"echo queued\r".to_vec(),
        ),
        (
            false,
            vec![
                egui::Event::Text("echo queued".into()),
                enter(),
                egui::Event::WindowFocused(false),
                egui::Event::Text("late".into()),
                enter(),
            ],
            b"echo queued\r".to_vec(),
        ),
        (
            false,
            vec![
                egui::Event::WindowFocused(false),
                egui::Event::Text("late".into()),
                enter(),
            ],
            vec![],
        ),
    ] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut terminal = RunTerminal::new(run("fast-close"));
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(820.0, 520.0));
        let render = |terminal: &mut RunTerminal, input: egui::RawInput| {
            let mut commands = Vec::new();
            let output = ctx.run(input, |ctx| {
                commands = show_terminal_viewport(
                    ctx,
                    egui::ViewportClass::Immediate,
                    terminal,
                    true,
                    true,
                );
            });
            (commands, output)
        };
        for _ in 0..2 {
            let _ = render(
                &mut terminal,
                egui::RawInput {
                    screen_rect: Some(screen),
                    ..Default::default()
                },
            );
        }
        let pos = egui::pos2(20.0, 20.0);
        for pressed in [true, false] {
            let _ = render(
                &mut terminal,
                egui::RawInput {
                    screen_rect: Some(screen),
                    events: vec![
                        egui::Event::PointerMoved(pos),
                        egui::Event::PointerButton {
                            pos,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
            );
        }
        assert!(ctx.memory(|memory| memory.focused().is_some()));
        let mut input = egui::RawInput {
            screen_rect: Some(screen),
            focused,
            events,
            ..Default::default()
        };
        input
            .viewports
            .get_mut(&egui::ViewportId::ROOT)
            .unwrap()
            .events
            .push(egui::ViewportEvent::Close);
        let (commands, output) = render(&mut terminal, input);
        let mut received = Vec::new();
        for command in commands {
            match command {
                Command::TerminalInput { run_id, data } => {
                    assert_eq!(run_id, "fast-close");
                    received.extend(data);
                }
                Command::TerminalResize { run_id, .. } => assert_eq!(run_id, "fast-close"),
                other => {
                    panic!("closing presentation must not send a lifecycle command: {other:?}")
                }
            }
        }
        assert_eq!(received, expected);
        assert!(!terminal.open);
        assert_eq!(terminal.run.state, RunState::Running);
        assert!(output.viewport_output[&egui::ViewportId::ROOT]
            .commands
            .iter()
            .any(|command| matches!(command, egui::ViewportCommand::CancelClose)));
    }
}

#[test]
fn clicking_trace_cell_text_selects_its_invocation() {
    for label in [
        "0.000001",
        "1\u{2192}2",
        "42",
        "0\u{2192}3",
        "read (0)",
        "4",
        "fd=3 buf=0x1000 count=8",
    ] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut app = app();
        app.snapshot.events = vec![event(1, 0), event(2, 3)];
        let size = egui::vec2(1280.0, 820.0);
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let text = texts(&output)
            .into_iter()
            .find(|(text, _)| text == label)
            .unwrap_or_else(|| panic!("missing trace cell {label}"));
        let pos = text.1.center();
        for events in [
            vec![egui::Event::PointerMoved(pos)],
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        ] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events,
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert_eq!(
            app.selected_event,
            Some((1, 3, 2)),
            "click on {label} must select its row"
        );
    }
}

/// Clicks the saved run's row `clicks` times and returns the app.
fn click_history_row(clicks: usize) -> MonitorApp {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.selected = Some("vm".into());
    let mut saved = run("saved");
    saved.state = RunState::Finished;
    saved.request.path = "/usr/bin/history-row".into();
    app.history = vec![saved];
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(900.0, 500.0));
    let draw = |app: &mut MonitorApp, events: Vec<egui::Event>, time: f64| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(screen),
                events,
                time: Some(time),
                ..Default::default()
            },
            |ctx| {
                egui::TopBottomPanel::bottom("history-details")
                    .exact_height(180.0)
                    .show(ctx, |ui| app.history_detail(ui));
                egui::CentralPanel::default().show(ctx, |ui| app.run_history(ui));
            },
        )
    };
    for index in 0..3 {
        let _ = draw(&mut app, vec![], f64::from(index) * 0.01);
    }
    let output = draw(&mut app, vec![], 0.03);
    let pos = texts(&output)
        .into_iter()
        .find(|(label, _)| label == "/usr/bin/history-row")
        .expect("history row text")
        .1
        .center();
    let mut time = 0.04;
    for _ in 0..clicks {
        for pressed in [true, false] {
            let _ = draw(
                &mut app,
                vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                time,
            );
            time += 0.05;
        }
    }
    app
}

#[test]
fn single_click_in_run_history_selects_the_run_without_opening_triage() {
    let app = click_history_row(1);
    assert_eq!(app.selected_run.as_deref(), Some("saved"));
    assert_ne!(app.focus_panel, Some(Panel::Triage));
}

#[test]
fn double_click_in_run_history_selects_the_run_and_opens_triage() {
    let app = click_history_row(2);
    assert_eq!(app.selected_run.as_deref(), Some("saved"));
    assert_eq!(app.focus_panel, Some(Panel::Triage));
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { .. })
    ));
}

#[test]
fn run_history_details_show_the_process_tree_then_the_enabled_analysis_only() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.selected = Some("vm".into());
    let mut saved = run("saved");
    saved.state = RunState::Finished;
    saved.request.capture_network = true;
    saved.request.memory_dump_on_exit = true;
    saved.request.analysis.enabled = true;
    saved.request.analysis.checks = vec![antinomie_monitor_core::AnalysisKind::Capabilities];
    app.history = vec![saved];
    app.select_run(Some("saved".into()));
    app.run_tree = Some(("saved".into(), Ok((Vec::new(), Vec::new()))));
    let mut time = 0.0;
    let mut draw = |app: &mut MonitorApp, events: Vec<egui::Event>| {
        time += 0.05;
        texts(&ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 1000.0),
                )),
                events,
                time: Some(time),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.history_detail(ui));
            },
        ))
    };
    let shown = draw(&mut app, Vec::new());
    let top = |needle: &str| {
        shown
            .iter()
            .find(|(label, _)| label.contains(needle))
            .unwrap_or_else(|| panic!("{needle} missing from {shown:?}"))
            .1
            .top()
    };
    assert!(top("Recorded process tree") < top("Analysis enabled"));
    // The static analysis is a branch with its checks below it.
    assert!(top("Analysis enabled") < top("Static analysis"));
    assert!(
        top("Static analysis") < top(antinomie_monitor_core::AnalysisKind::Capabilities.label())
    );
    top("Memory dump on exit");
    top("Network capture");
    assert!(!shown.iter().any(|(label, _)| label.contains("Core dump")));
    // The Launch fold comes last and starts closed.
    assert!(top("Network capture") < top("Launch"));
    assert!(!shown.iter().any(|(label, _)| label == "Executable"));
    for removed in [
        "Launch details",
        "Open static analysis",
        "Network segment",
        "Open memory dump",
        "Process core",
    ] {
        assert!(
            !shown.iter().any(|(label, _)| label.contains(removed)),
            "{removed} should not be in the run details"
        );
    }
    let header = top_center(&shown, "Launch");
    draw(&mut app, vec![egui::Event::PointerMoved(header)]);
    for pressed in [true, false] {
        draw(
            &mut app,
            vec![egui::Event::PointerButton {
                pos: header,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: egui::Modifiers::NONE,
            }],
        );
    }
    // The opened fold is below the taller tree: scroll the Details to it.
    draw(
        &mut app,
        vec![
            egui::Event::PointerMoved(egui::pos2(450.0, 10.0)),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -3000.0),
                modifiers: egui::Modifiers::NONE,
            },
        ],
    );
    let mut opened = Vec::new();
    for _ in 0..20 {
        opened = draw(&mut app, Vec::new());
    }
    for label in [
        "Executable",
        "Arguments",
        "Working directory",
        "Environment",
        "UID / GID",
        "Boot",
        "Session",
        "Recording",
    ] {
        assert!(
            opened.iter().any(|(text, _)| text == label),
            "{label} missing from the opened Launch fold: {opened:?}"
        );
    }
}

fn top_center(shown: &[(String, egui::Rect)], label: &str) -> egui::Pos2 {
    shown
        .iter()
        .find(|(text, _)| text == label)
        .unwrap_or_else(|| panic!("{label} missing from {shown:?}"))
        .1
        .center()
}

#[test]
fn trace_categories_hide_and_show_their_rows() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.snapshot.events = vec![event(1, 0), event(2, 0)];
    let size = egui::vec2(1280.0, 820.0);
    let row_visible = |app: &mut MonitorApp| {
        for _ in 0..2 {
            let _ = render(app, &ctx, size);
        }
        texts(&render(app, &ctx, size))
            .iter()
            .any(|(text, _)| text == "read (0)")
    };
    assert!(row_visible(&mut app));
    app.settings.hidden_trace_categories = vec![SyscallGroup::File];
    assert!(!row_visible(&mut app));
    app.settings.hidden_trace_categories = vec![SyscallGroup::Network];
    assert!(row_visible(&mut app));
    let labels: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    assert!(labels.contains(&"All".to_string()));
    assert!(
        labels.contains(&"File & filesystem 1".to_string()),
        "{labels:?}"
    );
}

#[test]
fn stopped_vm_trace_offers_its_recent_runs_and_captures() {
    let size = egui::vec2(1280.0, 820.0);
    let fixture = || {
        let mut app = app();
        app.selected = Some("vm".into());
        let mut saved = run("saved");
        saved.state = RunState::Finished;
        saved.request.path = "/usr/bin/recent-run".into();
        app.history = vec![saved];
        app.capture_history = vec![observer("cap", CaptureState::Finalized)];
        // Stale events of an ended session are not a live trace.
        app.snapshot.events = vec![event(1, 0), event(2, 0)];
        app.snapshot.vms = vec![VmConfig {
            id: "vm".into(),
            ..VmConfig::default()
        }];
        app
    };
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = fixture();
    assert!(app.no_live_trace());
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    for label in [
        "No live trace",
        "Recent runs",
        "/usr/bin/recent-run",
        "Recent captures",
        "All guest programs",
    ] {
        assert!(shown.iter().any(|text| text == label), "{label}: {shown:?}");
    }
    assert!(!shown.iter().any(|text| text == "read (0)"));
    // Run History lists runs; the panel asked for the captures too.
    assert!(matches!(
        app.pending_archive,
        Some(Request::ListCaptures { ref vm_id, .. }) if vm_id == "vm"
    ));

    click_label(&mut app, &ctx, size, "/usr/bin/recent-run");
    assert_eq!(app.selected_run.as_deref(), Some("saved"));
    assert!(app.archive_selected);
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { capture: false, .. })
    ));
    assert!(!app.no_live_trace());

    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = fixture();
    click_label(&mut app, &ctx, size, "All guest programs");
    assert_eq!(app.selected_capture.as_deref(), Some("cap"));
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { capture: true, .. })
    ));

    // A running VM shows its live trace instead.
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = fixture();
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    assert!(!app.no_live_trace());
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    assert!(texts(&render(&mut app, &ctx, size))
        .iter()
        .any(|(text, _)| text == "read (0)"));
}

#[test]
fn category_chips_wrap_to_two_lines_inside_the_panel() {
    for (size, font) in [
        (egui::vec2(1280.0, 820.0), 16.0),
        (egui::vec2(800.0, 600.0), 16.0),
        (egui::vec2(800.0, 600.0), 24.0),
    ] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, font);
        let mut app = app();
        app.settings.font_size = font;
        app.snapshot.events = vec![event(1, 0), event(2, 0)];
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let texts = texts(&render(&mut app, &ctx, size));
        let chips: Vec<_> = texts
            .iter()
            .filter(|(text, _)| {
                text == "All"
                    || SyscallGroup::ALL.iter().any(|group| {
                        text.strip_prefix(group.label())
                            .and_then(|count| count.strip_prefix(' '))
                            .is_some_and(|count| count.parse::<usize>().is_ok())
                    })
            })
            .map(|(_, rect)| *rect)
            .collect();
        let mut lines: Vec<f32> = Vec::new();
        for chip in &chips {
            if !lines
                .iter()
                .any(|line| (line - chip.center().y).abs() < 8.0)
            {
                lines.push(chip.center().y);
            }
            assert!(chip.right() <= size.x, "chip overflows at {size:?}/{font}");
        }
        assert!(lines.len() <= 2, "chip lines {lines:?} at {size:?}/{font}");
        if size.x > 1000.0 {
            // Wide enough for every chip within the two lines.
            assert_eq!(chips.len(), SyscallGroup::ALL.len() + 1);
            assert_eq!(lines.len(), 2);
        }
        let header = texts
            .iter()
            .find(|(text, _)| text == "Record")
            .expect("table header stays in view")
            .1;
        assert!(chips.iter().all(|chip| chip.bottom() < header.top()));
    }
}

#[test]
fn native_layout_keeps_controls_and_trace_panels_separate_at_all_text_sizes() {
    for size in [egui::vec2(800.0, 600.0), egui::vec2(1280.0, 820.0)] {
        for font in [12.0, 16.0, 24.0] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font);
            let mut app = app();
            app.settings.font_size = font;
            app.snapshot.events = vec![event(1, 0), event(2, 3)];
            app.snapshot.health.dropped = 3;
            for _ in 0..3 {
                let _ = render(&mut app, &ctx, size);
            }
            let output = render(&mut app, &ctx, size);
            let texts = texts(&output);
            let rect = |label: &str| {
                texts
                    .iter()
                    .find(|(text, _)| text == label)
                    .unwrap_or_else(|| panic!("missing {label} at {size:?}/{font}: {texts:?}"))
                    .1
            };
            assert!(rect("Syscalls").bottom() < rect("Details").top());
            assert!(rect("Details").bottom() < rect("TRL").top());
            // The status bar value sits beside its name, colored as a loss.
            let label = rect("TRL");
            let loss = texts
                .iter()
                .find(|(text, value)| {
                    text == "3" && (value.center().y - label.center().y).abs() < 4.0
                })
                .expect("transport loss value")
                .1;
            assert!(label.right() < loss.left());
            assert!(
                texts.iter().any(
                    |(text, version)| text == &format!("Antinomie {APP_VERSION}")
                        && version.top() >= label.top() - 4.0
                        && version.right() > size.x - 48.0
                ),
                "loss meters must sit on the right edge"
            );
            assert!(rect("File").bottom() < rect("Syscalls").top());
            let title = rect("Virtual machines");
            let add = texts
                .iter()
                .find(|(text, rect)| {
                    text == egui_phosphor::regular::PLUS
                        && rect.top() < title.bottom()
                        && rect.bottom() > title.top()
                })
                .expect("sidebar Add control must remain visible")
                .1;
            assert!(
                title.right() <= add.left(),
                "sidebar title {title:?} overlaps Add {add:?} at {font}"
            );
            assert!(rect("Return").right() <= rect("Info").left());
            assert!(!texts.iter().any(|(text, _)| text == "Terminal"));
            // DejaVu Sans Mono runs wider; data text is one point smaller.
            assert_eq!(
                ctx.style().text_styles[&egui::TextStyle::Monospace].size,
                font - 1.0
            );
        }
    }
}

// SPDX-License-Identifier: MIT
//! Analysis section windows.
use super::*;

#[test]
fn section_windows_keep_report_identity_and_prune_only_unreferenced_reports() {
    use antinomie_monitor_core::AnalysisKind;
    let mut app = app();
    let mut archived = run("archived");
    archived.analysis = Some(section_report("archive-a", "ARCHIVE A"));
    app.history.push(archived);
    app.snapshot
        .analysis_reports
        .push(section_report("standalone-b", "STANDALONE B"));
    app.open_analysis_section("archive-a".into(), AnalysisKind::Metadata)
        .unwrap();
    app.open_analysis_section("archive-a".into(), AnalysisKind::Metadata)
        .unwrap();
    app.open_analysis_section("standalone-b".into(), AnalysisKind::Structures)
        .unwrap();
    app.retain_analysis_windows(&[]);
    assert_eq!(
        app.analysis_windows.len(),
        2,
        "pending requests retain snapshots"
    );
    assert_eq!(
        app.take_analysis_sections().len(),
        2,
        "duplicate sections reuse a panel"
    );
    app.selected_analysis = Some("standalone-b".into());
    app.select_archive_run("archived".into());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let output = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            app.show_panel(
                ui,
                &Panel::AnalysisSection {
                    report_id: "archive-a".into(),
                    kind: AnalysisKind::Metadata,
                },
            )
        });
    });
    assert!(texts(&output).iter().any(|(text, _)| text == "ARCHIVE A"));
    assert!(!texts(&output)
        .iter()
        .any(|(text, _)| text == "STANDALONE B"));
    app.retain_analysis_windows(&["standalone-b".into()]);
    assert!(!app.analysis_windows.contains_key("archive-a"));
    assert!(app.analysis_windows.contains_key("standalone-b"));
    assert!(
        app.submitted.is_empty(),
        "opening/closing sections never scans or cancels"
    );
}

#[test]
fn section_cache_is_bounded_and_refreshes_matching_live_reports() {
    use antinomie_monitor_core::AnalysisKind;
    let mut app = app();
    for index in 0..9 {
        let id = format!("report-{index}");
        app.snapshot
            .analysis_reports
            .push(section_report(&id, "INITIAL"));
        let result = app.open_analysis_section(id, AnalysisKind::Metadata);
        assert_eq!(result.is_ok(), index < 8);
    }
    assert_eq!(app.analysis_windows.len(), 8);
    app.open_analysis_section("report-0".into(), AnalysisKind::Strings)
        .unwrap();
    app.snapshot.analysis_reports[0] = section_report("report-0", "UPDATED");
    app.refresh_analysis_windows();
    assert_eq!(
        app.analysis_windows["report-0"].source_path,
        "/fixture/UPDATED"
    );
    assert_eq!(
        app.analysis_windows["report-1"].source_path,
        "/fixture/INITIAL"
    );
    app.take_analysis_sections();
    app.retain_analysis_windows(&[]);
    assert!(app.analysis_windows.is_empty());
    app.open_analysis_section("report-8".into(), AnalysisKind::Metadata)
        .unwrap();
}

#[test]
fn summary_is_compact_with_thousands_of_rows_and_section_renders_only_its_kind() {
    use antinomie_monitor_core::AnalysisKind;
    for font in [18.0, 24.0] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, font);
        let report = section_report("summary", "METADATA MARKER");
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(800.0, 600.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    assert!(crate::analysis::workspace(
                        ui,
                        Some(&report),
                        &mut crate::analysis::WorkspaceState::default(),
                        None,
                        None
                    )
                    .is_none());
                });
            },
        );
        assert!(texts(&output)
            .iter()
            .any(|(text, _)| text == "Partial / 2048 rows"));
        assert!(!texts(&output)
            .iter()
            .any(|(text, _)| text.starts_with("Row ")));
        assert!(
            output.shapes.len() < 150,
            "summary size must not depend on evidence row count"
        );
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                crate::analysis::workspace_section(
                    ui,
                    Some(&report),
                    AnalysisKind::Metadata,
                    &mut crate::analysis::WorkspaceState::default(),
                    None,
                    None,
                )
            });
        });
        assert!(texts(&output)
            .iter()
            .any(|(text, _)| text == "METADATA MARKER"));
        assert!(!texts(&output)
            .iter()
            .any(|(text, _)| text.starts_with("Row ")));
    }
}

#[test]
fn summary_open_button_requests_only_the_chosen_section_without_backend_work() {
    let mut app = app();
    app.snapshot
        .analysis_reports
        .push(section_report("chosen", "CHOSEN"));
    app.selected_analysis = Some("chosen".into());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let render = |app: &mut MonitorApp, events| {
        ctx.run(
            egui::RawInput {
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
            },
        )
    };
    let mut output = render(&mut app, Vec::new());
    for _ in 0..3 {
        output = render(&mut app, Vec::new());
    }
    let target = texts(&output)
        .iter()
        .find(|(text, _)| text == egui_phosphor::regular::ARROW_SQUARE_OUT)
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        render(
            &mut app,
            vec![
                egui::Event::PointerMoved(target),
                egui::Event::PointerButton {
                    pos: target,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
    }
    assert_eq!(
        app.take_analysis_sections(),
        [(
            "chosen".into(),
            antinomie_monitor_core::AnalysisKind::Metadata
        )]
    );
    assert!(app.submitted.is_empty());
}

#[test]
#[ignore = "requires X11 native section previews; automatically exits after 15 seconds"]
fn native_analysis_sections_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
        updates: usize,
        held_updates: usize,
        releases: usize,
        reported: bool,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            self.updates += 1;
            ctx.input(|input| {
                self.held_updates += usize::from(input.pointer.primary_down());
                self.releases += input
                    .events
                    .iter()
                    .filter(|event| {
                        matches!(
                            event,
                            egui::Event::PointerButton {
                                button: egui::PointerButton::Primary,
                                pressed: false,
                                ..
                            }
                        )
                    })
                    .count();
            });
            if Instant::now() >= self.deadline {
                if !self.reported {
                    eprintln!(
                        "native section QA: root_updates={} held_updates={} root_primary_releases={}",
                        self.updates, self.held_updates, self.releases
                    );
                    self.reported = true;
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
        }
    }
    let small = std::env::var_os("ANTINOMIE_ANALYSIS_QA_SMALL").is_some();
    let seconds = std::env::var("ANTINOMIE_ANALYSIS_QA_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(15)
        .clamp(1, 120);
    eframe::run_native(
        "Antinomie Section Windows QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size(if small {
                [800.0, 600.0]
            } else {
                [1280.0, 820.0]
            }),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11().with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            theme::text_size(&cc.egui_ctx, if small { 24.0 } else { 18.0 });
            let mut app = app();
            app.settings.font_size = if small { 24.0 } else { 18.0 };
            app.snapshot
                .analysis_reports
                .push(section_report("qa-report-a", "REPORT A"));
            app.snapshot
                .analysis_reports
                .push(section_report("qa-report-b", "REPORT B"));
            app.selected_analysis = Some("qa-report-b".into());
            app.layout.focus(Panel::StaticAnalysis);
            app.open_analysis_section(
                "qa-report-a".into(),
                antinomie_monitor_core::AnalysisKind::Metadata,
            )
            .unwrap();
            app.open_analysis_section(
                "qa-report-b".into(),
                antinomie_monitor_core::AnalysisKind::Strings,
            )
            .unwrap();
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(seconds),
                updates: 0,
                held_updates: 0,
                releases: 0,
                reported: false,
            }))
        }),
    )
    .unwrap();
}

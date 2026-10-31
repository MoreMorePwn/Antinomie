// SPDX-License-Identifier: GPL-3.0-only
//! Run setup and static analysis windows.
use super::*;

#[test]
fn run_setup_title_can_move_and_reopen_without_resetting_position() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 900.0);
    let mut app = analysis_setup_fixture();
    for _ in 0..4 {
        render(&mut app, &ctx, size);
    }
    let before = egui::AreaState::load(&ctx, Dialog::Launch.window_id())
        .unwrap()
        .rect();
    let output = render(&mut app, &ctx, size);
    let start = texts(&output)
        .iter()
        .find(|(text, _)| text == "Run program")
        .unwrap()
        .1
        .center();
    let end = start + egui::vec2(32.0, -12.0);
    for events in [
        vec![egui::Event::PointerMoved(start)],
        vec![egui::Event::PointerButton {
            pos: start,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        }],
        vec![egui::Event::PointerMoved(end)],
        vec![egui::Event::PointerButton {
            pos: end,
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
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let moved = egui::AreaState::load(&ctx, Dialog::Launch.window_id())
        .unwrap()
        .rect();
    assert!(
        moved.min.x > before.min.x + 12.0 && moved.min.y < before.min.y - 4.0,
        "title drag must move the dialog: {before:?} -> {moved:?}"
    );
    app.launch_open = false;
    render(&mut app, &ctx, size);
    app.launch_open = true;
    render(&mut app, &ctx, size);
    let reopened = egui::AreaState::load(&ctx, Dialog::Launch.window_id())
        .unwrap()
        .rect();
    assert!(
        (reopened.min - moved.min).length() < 1.0,
        "reopen retains the moved position"
    );
    let (run, analyze) = app.launch_action_rects.unwrap();
    assert!(run.bottom() < size.y && analyze.bottom() < size.y);
}

#[test]
fn run_setup_keeps_final_actions_visible_and_dispatches_a_selection_snapshot() {
    for (size, font) in [
        (egui::vec2(1280.0, 820.0), 18.0),
        (egui::vec2(1280.0, 820.0), 24.0),
        (egui::vec2(800.0, 600.0), 24.0),
    ] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, font);
        let mut app = analysis_setup_fixture();
        app.settings.font_size = font;
        for _ in 0..3 {
            let _ = render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let visible = texts(&output);
        let action = |suffix: &str| {
            visible
                .iter()
                .find(|(text, _)| text.ends_with(suffix))
                .unwrap_or_else(|| panic!("missing {suffix} at {size:?}/{font}: {visible:?}"))
                .1
        };
        let run_rect = action(" Run");
        assert!(run_rect.bottom() < size.y);
        let _ = action("Analyze Only");
        let (run_rect, analyze_rect) = app.launch_action_rects.unwrap();
        assert!((analyze_rect.center().y - run_rect.center().y).abs() < 1.0);
        assert!(
            analyze_rect.right() < run_rect.left(),
            "the main action is rightmost"
        );
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events: vec![
                        egui::Event::PointerMoved(run_rect.center()),
                        egui::Event::PointerButton {
                            pos: run_rect.center(),
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        assert!(app.submitted.iter().any(|command| matches!(command, Command::Execute(request) if request.analysis.enabled && request.analysis.checks.len() == 2)), "Run action did not submit at {size:?}/{font}");
        app.exec.analysis.checks.clear();
        assert!(app.submitted.iter().any(|command| matches!(command, Command::Execute(request) if request.analysis.checks.len() == 2)));
    }
}

#[test]
fn run_in_is_offered_for_graphical_bases_remembered_and_sent_with_the_launch() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = analysis_setup_fixture();
    app.exec.analysis.enabled = false;
    app.exec.run_in = RunIn::GuestDesktop;
    let click_run = |app: &mut MonitorApp| {
        for _ in 0..3 {
            let _ = render(app, &ctx, size);
        }
        let output = render(app, &ctx, size);
        let visible = texts(&output);
        let offered = visible.iter().any(|(text, _)| text == "Run in");
        let run = app.launch_action_rects.unwrap().0.center();
        for pressed in [true, false] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    events: vec![
                        egui::Event::PointerMoved(run),
                        egui::Event::PointerButton {
                            pos: run,
                            button: egui::PointerButton::Primary,
                            pressed,
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                    ..Default::default()
                },
                |ctx| app.draw(ctx),
            );
        }
        let sent = app
            .submitted
            .iter()
            .rev()
            .find_map(|command| match command {
                Command::Execute(request) => Some(request.run_in),
                _ => None,
            });
        (offered, sent)
    };
    // A base without a desktop hides the choice and runs in the app.
    assert_eq!(click_run(&mut app), (false, Some(RunIn::AppTerminal)));
    assert_eq!(app.exec.run_in, RunIn::GuestDesktop);

    let mut app = analysis_setup_fixture();
    app.exec.analysis.enabled = false;
    app.exec.run_in = RunIn::GuestDesktopTerminal;
    app.snapshot
        .bases
        .push(antinomie_monitor_core::BaseSummary {
            id: "gnome".into(),
            label: "Debian 13 (GNOME)".into(),
            directory: "/bases/gnome".into(),
            min_ram_mib: 4096,
            min_disk_gib: 16,
            fixed_display: true,
            size_bytes: 0,
            revision: Some(APP_REVISION),
            min_app_version: None,
            built_with: None,
            stealth_support: Vec::new(),
            guest: Some(antinomie_monitor_core::GuestProfile {
                id: "debian-gnome".into(),
                label: "Debian 13 (GNOME)".into(),
                min_ram_mib: 4096,
                min_disk_gib: 16,
                requires_credentials: true,
                graphical: true,
            }),
        });
    app.snapshot.vms[0].base_identity = Some("gnome".into());
    assert_eq!(
        click_run(&mut app),
        (true, Some(RunIn::GuestDesktopTerminal))
    );
    // The dialog keeps the choice for the next launch.
    assert_eq!(app.exec.run_in, RunIn::GuestDesktopTerminal);
}

#[test]
fn static_analysis_uses_selected_archive_report_without_submitting_work() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    let mut live = run("same-run");
    let report = |id: &str| antinomie_monitor_core::AnalysisReport {
        id: id.into(),
        state: antinomie_monitor_core::AnalysisState::Unavailable,
        source_path: "/sample".into(),
        specimen_sha256: None,
        specimen_len: None,
        reason: Some("Acquisition unavailable in fixture".into()),
        sections: Vec::new(),
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    };
    live.analysis = Some(report("live-report"));
    app.snapshot.runs.push(live.clone());
    live.analysis = Some(report("archive-report"));
    app.history.push(live);
    app.selected_run = Some("same-run".into());
    app.archive_selected = true;
    let output = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
    });
    let visible = texts(&output);
    assert!(visible
        .iter()
        .any(|(text, _)| text.contains("archive-report")));
    assert!(!visible.iter().any(|(text, _)| text.contains("live-report")));
    assert!(app.submitted.is_empty());
}

#[test]
fn specimen_answers_require_the_current_pane_report_and_selection_ticket() {
    let mut app = app();
    let view = app.analysis_views.entry("workspace".into()).or_default();
    view.bind(Some("selected-report"));
    view.pending = Some((7, 16, 4));
    let answer = |view_key: &str, generation, report_id: &str| Answer::Specimen {
        view_key: view_key.into(),
        generation,
        report_id: report_id.into(),
        offset: 16,
        data_len: 4,
        result: Ok(antinomie_monitor_core::AnalysisSpecimenPage {
            report_id: report_id.into(),
            offset: 16,
            total_len: 64,
            data: b"data".to_vec(),
        }),
    };
    app.handle_archive_answer(answer("workspace", 6, "selected-report"));
    app.handle_archive_answer(answer("workspace", 7, "different-report"));
    app.handle_archive_answer(answer("closed-pane", 7, "selected-report"));
    assert!(app.analysis_views["workspace"].preview.is_none());
    assert_eq!(app.analysis_views["workspace"].pending, Some((7, 16, 4)));
    app.handle_archive_answer(answer("workspace", 7, "selected-report"));
    assert_eq!(
        app.analysis_views["workspace"]
            .preview
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .data,
        b"data"
    );
    assert!(app.analysis_views["workspace"].pending.is_none());
    app.analysis_views
        .get_mut("workspace")
        .unwrap()
        .bind(Some("new-report"));
    app.handle_archive_answer(answer("workspace", 7, "selected-report"));
    assert!(app.analysis_views["workspace"].preview.is_none());
}

#[test]
fn specimen_requests_use_retained_directories_and_supersession_clears_pending() {
    let mut app = app();
    let mut saved = run("saved-run");
    saved.analysis = Some(section_report("saved-report", "SAVED"));
    saved.directory = "/saved/run".into();
    app.history.push(saved);
    app.analysis_views
        .entry("workspace".into())
        .or_default()
        .bind(Some("saved-report"));
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::ReadSpecimen {
            report_id: "saved-report".into(),
            offset: 0,
            data_len: 4,
        }),
    );
    assert!(
        matches!(app.pending_archive, Some(Request::Specimen { ref directory, ref report_id, .. })
        if directory == &PathBuf::from("/saved/run/analysis") && report_id == "saved-report")
    );
    app.queue_archive(Request::ListVm {
        options: app.options.clone(),
        vm_id: "vm".into(),
        generation: 1,
        carried: Vec::new(),
    });
    assert!(app.analysis_views["workspace"].pending.is_none());
    assert!(app.analysis_views["workspace"]
        .preview
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap_err()
        .contains("superseded"));
    assert!(app.submitted.is_empty());
}

#[test]
fn closed_analysis_panes_release_their_state_and_late_answers() {
    let mut app = app();
    app.analysis_views
        .entry("workspace".into())
        .or_default()
        .bind(Some("main"));
    let section = app
        .analysis_views
        .entry("section:closed:Strings".into())
        .or_default();
    section.bind(Some("closed"));
    section.pending = Some((2, 0, 1));
    app.retain_analysis_windows(&[]);
    assert_eq!(app.analysis_views.len(), 1);
    app.handle_archive_answer(Answer::Specimen {
        view_key: "section:closed:Strings".into(),
        generation: 2,
        report_id: "closed".into(),
        offset: 0,
        data_len: 1,
        result: Err("late error".into()),
    });
    assert_eq!(app.analysis_views.len(), 1);
}

#[test]
fn detached_analysis_retains_its_directory_after_vm_history_changes() {
    let mut app = app();
    let mut saved = run("saved-run");
    saved.directory = "/saved/run".into();
    saved.analysis = Some(section_report("saved-report", "SAVED"));
    app.history.push(saved);
    app.open_analysis_section(
        "saved-report".into(),
        antinomie_monitor_core::AnalysisKind::Strings,
    )
    .unwrap();
    app.take_analysis_sections();
    app.history.clear();
    assert_eq!(
        app.analysis_directory("saved-report"),
        Some(PathBuf::from("/saved/run/analysis"))
    );
    app.retain_analysis_windows(&[]);
    assert!(app.analysis_directory("saved-report").is_none());
}

#[test]
fn missing_specimen_reader_is_an_explicit_error_not_a_stuck_request() {
    let mut app = app();
    let mut saved = run("saved-run");
    saved.analysis = Some(section_report("saved-report", "SAVED"));
    app.history.push(saved);
    app.analysis_views
        .entry("workspace".into())
        .or_default()
        .bind(Some("saved-report"));
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::ReadSpecimen {
            report_id: "saved-report".into(),
            offset: 0,
            data_len: 1,
        }),
    );
    app.flush_archive();
    assert!(app.analysis_views["workspace"].pending.is_none());
    assert!(app.analysis_views["workspace"]
        .preview
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap_err()
        .contains("unavailable"));
}

#[test]
fn analyze_only_and_cancel_do_not_launch_or_stop_a_program() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = analysis_setup_fixture();
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let output = render(&mut app, &ctx, size);
    let target = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "Analyze Only")
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![
                    egui::Event::PointerMoved(target),
                    egui::Event::PointerButton {
                        pos: target,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| app.draw(ctx),
        );
    }
    assert!(app.submitted.iter().any(|command| matches!(command, Command::AnalyzeOnly { analysis, path, .. } if analysis.enabled && path == "/usr/bin/sample")));
    assert!(app.pending_launch.is_none() && app.terminals.is_empty());
    app.launch_open = false;
    app.snapshot
        .analysis_reports
        .push(antinomie_monitor_core::AnalysisReport {
            id: "standalone-job".into(),
            state: antinomie_monitor_core::AnalysisState::Running,
            source_path: "/sample".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: Vec::new(),
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
            limits: None,
        });
    app.selected_analysis = Some("standalone-job".into());
    let output = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
    });
    let target = texts(&output)
        .into_iter()
        .find(|(text, _)| text == egui_phosphor::regular::X)
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                events: vec![
                    egui::Event::PointerMoved(target),
                    egui::Event::PointerButton {
                        pos: target,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default()
                    .show(ctx, |ui| app.show_panel(ui, &Panel::StaticAnalysis));
            },
        );
    }
    assert!(app.submitted.iter().any(|command| matches!(command, Command::CancelAnalysis { analysis_id } if analysis_id == "standalone-job")));
    assert!(!app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::Execute(_) | Command::StopRun { .. })));
    assert!(app.pending_launch.is_none() && app.terminals.is_empty());
}

#[test]
#[ignore = "requires X11 native rendering; exits after 20 seconds"]
fn native_analysis_setup_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                self.app.snapshot.active_vm = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            eframe::App::update(&mut self.app, ctx, frame);
        }
    }
    let small = std::env::var_os("ANTINOMIE_ANALYSIS_QA_SMALL").is_some();
    let size = if small {
        [800.0, 600.0]
    } else {
        [1280.0, 820.0]
    };
    eframe::run_native(
        "Antinomie Run Setup QA",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size(size),
            persist_window: false,
            event_loop_builder: Some(Box::new(|builder| {
                builder.with_x11();
                builder.with_any_thread(true);
            })),
            ..Default::default()
        },
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            let mut app = analysis_setup_fixture();
            app.settings.font_size = if small { 24.0 } else { 18.0 };
            theme::text_size(&cc.egui_ctx, app.settings.font_size);
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(20),
            }))
        }),
    )
    .unwrap();
}

#[test]
fn an_unpacked_layers_analysis_is_found_in_its_packed_files_folder_and_can_be_shown() {
    let mut app = app();
    let mut saved = run("packed-run");
    saved.directory = "/saved/run".into();
    saved.analysis = Some(section_report("packed-report", "PACKED"));
    app.history.push(saved);
    app.snapshot
        .analysis_reports
        .push(antinomie_monitor_core::AnalysisReport {
            id: "packed-report-L2".into(),
            state: antinomie_monitor_core::AnalysisState::Queued,
            source_path: "/sample".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: Vec::new(),
            layer: Some(antinomie_monitor_core::AnalysisLayer {
                parent_id: "packed-report".into(),
                index: 2,
                method: "UPX".into(),
                parent_sha256: "0".repeat(64),
            }),
            specimen_source: None,
            time_limit_seconds: None,
            limits: None,
        });
    assert_eq!(
        app.analysis_directory("packed-report-L2"),
        Some(PathBuf::from("/saved/run/analysis/layers/2"))
    );
    // Showing it makes it the report the panel follows; an unknown one is refused.
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::ShowReport {
            report_id: "packed-report-L2".into(),
        }),
    );
    assert_eq!(app.selected_analysis.as_deref(), Some("packed-report-L2"));
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::ShowReport {
            report_id: "gone".into(),
        }),
    );
    assert_eq!(app.selected_analysis.as_deref(), Some("packed-report-L2"));
}

#[test]
fn running_a_missing_check_asks_the_backend_to_add_it_to_the_runs_analysis() {
    let mut app = app();
    let mut saved = run("packed-run");
    saved.directory = "/saved/run".into();
    saved.analysis = Some(section_report("packed-report", "PACKED"));
    app.history.push(saved);
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::RunCheck {
            report_id: "packed-report".into(),
            kind: antinomie_monitor_core::AnalysisKind::Floss,
        }),
    );
    assert!(matches!(
        app.submitted.last(),
        Some(Command::AnalyzeMore { directory, run_id, checks, time_limit_seconds: None, .. })
            if directory == &PathBuf::from("/saved/run/analysis")
                && run_id.as_deref() == Some("packed-run")
                && checks == &[antinomie_monitor_core::AnalysisKind::Floss]
    ));
    // The time limit of Settings goes with a check run later, and "2× time"
    // asks for the doubled limit whatever Settings say.
    app.settings.analysis_time_limit_minutes = 6;
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::RunCheck {
            report_id: "packed-report".into(),
            kind: antinomie_monitor_core::AnalysisKind::Floss,
        }),
    );
    assert!(matches!(
        app.submitted.last(),
        Some(Command::AnalyzeMore {
            time_limit_seconds: Some(360),
            ..
        })
    ));
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::RunCheckLonger {
            report_id: "packed-report".into(),
            kind: antinomie_monitor_core::AnalysisKind::Floss,
            seconds: 960,
        }),
    );
    assert!(matches!(
        app.submitted.last(),
        Some(Command::AnalyzeMore { time_limit_seconds: Some(960), checks, .. })
            if checks == &[antinomie_monitor_core::AnalysisKind::Floss]
    ));
    app.settings.analysis_time_limit_minutes = 0;
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::OpenAnalysisSettings),
    );
    assert!(app.settings_open);
    assert_eq!(
        app.settings_page,
        crate::app::settings_window::SettingsPage::AnalysisTools
    );
    // A report with no retained folder cannot be added to.
    let sent = app.submitted.len();
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::RunCheck {
            report_id: "unknown".into(),
            kind: antinomie_monitor_core::AnalysisKind::Floss,
        }),
    );
    assert_eq!(app.submitted.len(), sent);
}

#[test]
fn a_limit_warning_opens_settings_at_its_field_and_the_fields_edit_the_limits() {
    use antinomie_monitor_core::{LimitSetting, LIMIT_FIELDS};
    let mut app = app();
    app.analysis_action(
        "workspace",
        Some(crate::analysis::ReportAction::OpenAnalysisLimit(
            LimitSetting::FlossFile,
        )),
    );
    assert!(app.settings_open);
    assert_eq!(app.settings_focus, Some(LimitSetting::FlossFile));
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(900.0, 1400.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.analysis_limit_fields(ui));
        },
    );
    // The focus is spent, and every setting has its label.
    assert_eq!(app.settings_focus, None);
    let shown = crate::app::tests::texts(&output);
    for field in &LIMIT_FIELDS {
        assert!(
            shown.iter().any(|(text, _)| text == field.label),
            "{} missing",
            field.label
        );
    }
    app.settings.analysis_limits.set(LimitSetting::Rows, 4096);
    assert_eq!(app.settings.analysis_limits.rows, 4096);
}

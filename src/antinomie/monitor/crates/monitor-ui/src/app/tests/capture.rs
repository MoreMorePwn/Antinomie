// SPDX-License-Identifier: MIT
//! Run selection, observers, process and core pickers.
use super::*;

#[test]
fn triage_packets_stay_with_the_live_vm_only() {
    let mut live = app();
    live.network_view
        .open(Some(PathBuf::from("/tmp/live.pcap")));
    assert!(!live.triage_hides_packets());

    live.snapshot.state = VmState::Running;
    live.snapshot.active_vm = Some("vm".into());
    live.snapshot.runs.push(run("live"));
    live.selected_run = Some("live".into());
    assert!(!live.triage_hides_packets());

    let mut past = run("old");
    past.state = RunState::Finished;
    live.history.push(past);
    live.selected_run = Some("old".into());
    assert!(live.triage_hides_packets());

    let mut captured = app();
    captured
        .snapshot
        .captures
        .push(observer("cap", CaptureState::Active));
    captured.selected_capture = Some("cap".into());
    captured
        .network_view
        .open(Some(PathBuf::from("/tmp/live.pcap")));
    assert!(captured.triage_hides_packets());
    assert_eq!(
        captured.network_view.loaded_path(),
        Some(std::path::Path::new("/tmp/live.pcap"))
    );
}

#[test]
fn selecting_another_run_cancels_queued_tree_and_stale_answer() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs.extend([run("old"), run("new")]);
    app.run_tree_pending = Some("old".into());
    app.pending_archive = Some(Request::ProcessTree {
        run_id: "old".into(),
        directory: PathBuf::new(),
        root_pid: 42,
        path: "/bin/a".into(),
    });
    app.select_run(Some("new".into()));
    assert!(app.run_tree_pending.is_none());
    assert!(app.run_tree.is_none());
    app.handle_archive_answer(Answer::ProcessTree {
        run_id: "old".into(),
        result: Ok((Vec::new(), Vec::new())),
    });
    assert!(app.run_tree.is_none());
}

#[test]
fn triage_selector_has_only_selected_vm_runs_in_newest_first_order() {
    let mut app = app();
    observer_fixture(&mut app);
    let mut first = run("first");
    first.started_ms = Some(10);
    let mut latest = run("latest");
    latest.started_ms = Some(20);
    let mut wrong_vm = run("other");
    wrong_vm.vm_id = "different".into();
    let mut legacy = run("legacy");
    legacy.root_task_cookie = 0;
    app.history = vec![first.clone(), latest.clone(), wrong_vm, legacy];
    app.snapshot.runs = vec![latest];
    let shown = app.triage_runs();
    assert_eq!(
        shown.iter().map(|run| run.id.as_str()).collect::<Vec<_>>(),
        ["latest", "first"]
    );
}

#[test]
fn triage_jump_reloads_exact_archive_evidence_without_changing_category_preferences() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs.push(run("one"));
    app.select_run(Some("one".into()));
    app.settings.hidden_trace_categories = vec![SyscallGroup::File];
    app.jump_triage_call((1, 7, 12));
    assert_eq!(app.settings.hidden_trace_categories, [SyscallGroup::File]);
    assert_eq!(app.selected_event, Some((1, 7, 12)));
    assert_eq!(app.trace_evidence, Some((1, 7, 12)));
    assert_eq!(app.focus_panel, Some(Panel::Trace));
    match app.pending_archive.as_ref().unwrap() {
        Request::Invocations {
            query,
            hidden_categories,
            offset,
            ..
        } => {
            assert_eq!(
                query,
                "stream.id == 1 && process.cookie == 7 && call.id == 12"
            );
            assert!(hidden_categories.is_empty());
            assert_eq!(*offset, 0);
        }
        _ => panic!("exact retained invocation request expected"),
    }
    app.filter.clear();
    app.commit_trace_filter();
    assert!(app.trace_evidence.is_none());
}

#[test]
fn packet_evidence_opens_the_selected_run_capture_instead_of_the_previous_capture() {
    let mut app = app();
    observer_fixture(&mut app);
    let directory = std::env::temp_dir().join(format!(
        "ant-run-packet-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let pcap = directory.join("run.pcap");
    std::fs::write(&pcap, [0xd4, 0xc3, 0xb2, 0xa1]).unwrap();
    let mut selected = run("one");
    selected.directory = directory.clone();
    std::fs::write(
        directory.join("artifacts.json"),
        serde_json::to_vec(&antinomie_monitor_core::RunArtifacts {
            run_id: selected.id.clone(),
            vm_id: selected.vm_id.clone(),
            boot_id: selected.boot_id.clone(),
            network_captures: vec![pcap.clone()],
            ..Default::default()
        })
        .unwrap(),
    )
    .unwrap();
    let manual = directory.join("manual.pcap");
    std::fs::write(&manual, [0xd4, 0xc3, 0xb2, 0xa1]).unwrap();
    app.snapshot.network_capture = Some(antinomie_monitor_core::network::NetworkCapture {
        boot_id: selected.boot_id.clone(),
        file: manual,
        ..Default::default()
    });
    app.snapshot.runs.push(selected);
    app.select_run(Some("one".into()));
    app.network_view.open(Some(directory.join("other.pcap")));
    app.jump_triage_packet(520).unwrap();
    assert_eq!(app.network_view.loaded_path(), Some(pcap.as_path()));
    assert_eq!(app.focus_panel, Some(Panel::Network));
    app.selected_capture = Some("all".into());
    assert!(app.jump_triage_packet(1).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn run_descendant_filter_applies_to_live_and_saved_trace_requests() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs.push(run("tree"));
    app.select_run(Some("tree".into()));
    let mut child = event(1, 0);
    child.pid = 99;
    child.tid = 99;
    child.task_cookie = 99;
    app.snapshot.events = vec![event(1, 0), child];
    app.select_process(captures::ProcessSelection::Process(99));
    assert_eq!(app.invocations().len(), 1);
    assert_eq!(app.invocations()[0].entry.as_ref().unwrap().pid, 99);
    app.archive_selected = true;
    app.request_page(0);
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { pid: Some(99), .. })
    ));
}

#[test]
fn capture_selection_has_independent_events_archive_and_no_terminal() {
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.runs.push(run("launched"));
    app.snapshot.events.push(event(1, 0));
    app.selected_analysis = Some("static-report".into());
    app.analysis_views.insert(
        "workspace".into(),
        AnalysisView {
            report_id: Some("static-report".into()),
            ..Default::default()
        },
    );
    let mut observed = event(1, 2);
    observed.call_id = 77;
    app.snapshot
        .captures
        .push(observer("observation", CaptureState::Stopped));
    app.snapshot
        .capture_events
        .insert("observation".into(), vec![observed]);
    app.select_capture("observation".into(), false);
    assert_eq!(app.invocations()[0].call_id, 77);
    assert_eq!(
        app.invocation_directory(app.invocations().first()),
        Some("/capture/observation".into())
    );
    assert_eq!(app.snapshot.events.len(), 1);
    assert!(app.selected_run.is_none());
    assert!(app.terminals.is_empty());
    assert_eq!(app.selected_analysis.as_deref(), Some("static-report"));
    assert_eq!(
        app.analysis_views["workspace"].report_id.as_deref(),
        Some("static-report")
    );
    app.select_capture("observation".into(), true);
    assert!(
        matches!(&app.pending_archive, Some(Request::Invocations { directory, capture: true, .. }) if directory == &PathBuf::from("/capture/observation"))
    );
    let generation = app.archive_generation;
    app.select_run(Some("launched".into()));
    app.handle_archive_answer(Answer::Invocations {
        generation,
        offset: 0,
        total: None,
        source_total: None,
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: pair_events(&[event(1, 9)]),
            next_offset: None,
            issues: Vec::new(),
        }),
    });
    assert!(app.selected_capture.is_none());
    assert_eq!(app.invocations()[0].entry.as_ref().unwrap().cpu, 0);
    assert!(app.terminals.is_empty());
}

#[test]
fn older_observation_uses_archive_when_live_preview_is_absent() {
    let mut app = app();
    observer_fixture(&mut app);
    app.capture_history
        .push(observer("past", CaptureState::Finalized));
    app.select_capture("past".into(), false);
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { capture: true, .. })
    ));
    let generation = app.archive_generation;
    app.handle_archive_answer(Answer::Invocations {
        generation,
        offset: 0,
        total: None,
        source_total: None,
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: pair_events(&[event(1, 4)]),
            next_offset: Some(64),
            issues: vec!["Pending tails".into()],
        }),
    });
    assert_eq!(app.invocations()[0].entry.as_ref().unwrap().cpu, 4);
    assert_eq!(app.archive_next, Some(64));
    assert_eq!(app.archive_error.as_deref(), Some("Pending tails"));
    app.history_generation = 2;
    app.handle_archive_answer(Answer::ListCaptures {
        vm_id: "other".into(),
        generation: 2,
        result: Ok(Vec::new()),
    });
    assert_eq!(app.capture_history.len(), 1);
}

#[test]
fn stop_capture_never_submits_program_or_vm_termination() {
    let mut app = app();
    observer_fixture(&mut app);
    assert!(app.observer_start_enabled());
    app.snapshot
        .captures
        .push(observer("active", CaptureState::Active));
    assert!(!app.observer_start_enabled());
    app.stop_observer();
    assert_eq!(app.submitted.len(), 1);
    assert!(
        matches!(&app.submitted[0], Command::StopCapture { capture_id } if capture_id == "active")
    );
    app.pending_observer = Some(9);
    app.stop_observer();
    assert_eq!(app.submitted.len(), 1);
    for revision in [None, Some(10)] {
        app.pending_observer = None;
        app.snapshot.guest_kernel.as_mut().unwrap().revision = revision;
        assert!(!app.observer_supported());
        app.stop_observer();
    }
    assert_eq!(app.submitted.len(), 1);
}

#[test]
fn unknown_quiet_capture_start_remains_stoppable_without_a_cookie() {
    let mut app = app();
    observer_fixture(&mut app);
    let mut capture = observer("unacknowledged", CaptureState::Unknown);
    capture.capture_cookie = 0;
    app.snapshot.captures.push(capture);
    assert!(!app.observer_start_enabled());
    app.stop_observer();
    assert!(
        matches!(&app.submitted[..], [Command::StopCapture { capture_id }] if capture_id == "unacknowledged")
    );
    assert!(app.terminals.is_empty());
}

#[test]
fn process_picker_preserves_task_identity_and_rejects_reused_pid_and_boot() {
    let mut app = app();
    observer_fixture(&mut app);
    let identity = antinomie_monitor_core::GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 55,
        tgid: 42,
        start_boot_ns: 100,
    };
    app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
        boot_id: "boot".into(),
        after_pid: 0,
        next_pid: 42,
        processes: vec![antinomie_monitor_core::GuestProcess {
            identity: identity.clone(),
            parent_tgid: 1,
            uid: 1000,
            gid: 1000,
            thread_count: 3,
            command: "guest-target".into(),
        }],
    });
    app.open_process_picker();
    assert!(matches!(
        app.submitted.last(),
        Some(Command::ListProcesses { after_pid: 0 })
    ));
    app.process_picker.selected = Some(identity.clone());
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(800.0, 600.0);
    render(&mut app, &ctx, size);
    assert_eq!(app.process_picker.selected.as_ref(), Some(&identity));
    app.snapshot.process_page.as_mut().unwrap().processes[0]
        .identity
        .task_cookie = 56;
    render(&mut app, &ctx, size);
    assert!(app.process_picker.selected.is_none());
    app.process_picker.selected = Some(identity);
    app.snapshot.boot_id = Some("new-boot".into());
    render(&mut app, &ctx, size);
    assert!(app.process_picker.selected.is_none());
    assert!(app
        .submitted
        .iter()
        .all(|command| matches!(command, Command::ListProcesses { .. })));
}

#[test]
fn capture_process_and_history_layout_remain_visible_with_large_fonts() {
    for size in [egui::vec2(800.0, 600.0), egui::vec2(1280.0, 820.0)] {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        theme::text_size(&ctx, 24.0);
        let mut app = app();
        observer_fixture(&mut app);
        app.settings.font_size = 24.0;
        app.process_picker.open = true;
        let identity = antinomie_monitor_core::GuestProcessIdentity {
            boot_id: "boot".into(),
            task_cookie: 55,
            tgid: 42,
            start_boot_ns: 100,
        };
        app.process_picker.selected = Some(identity.clone());
        app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
            boot_id: "boot".into(),
            processes: (1..=64)
                .map(|index| antinomie_monitor_core::GuestProcess {
                    identity: antinomie_monitor_core::GuestProcessIdentity {
                        task_cookie: if index == 1 { 55 } else { index },
                        ..identity.clone()
                    },
                    parent_tgid: 1,
                    uid: 1000,
                    gid: 1000,
                    thread_count: 3,
                    command: format!("guest-process-{index}"),
                })
                .collect(),
            ..Default::default()
        });
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        let visible = texts(&output);
        assert!(
            visible
                .iter()
                .any(|(text, _)| text == &format!("{} Attach", egui_phosphor::regular::PLUG)),
            "selected64rowpickeractionsclipped: {visible:?}"
        );
        for label in [
            "Attach to process",
            "PID",
            "Name",
            "UID",
            "Threads",
            "Cancel",
        ] {
            assert!(
                visible.iter().any(|(text, _)| text == label),
                "missing or clipped {label} at {size:?}: {visible:?}"
            );
        }
        app.process_picker.open = false;
        app.capture_tab = true;
        app.snapshot
            .captures
            .push(observer("active", CaptureState::Active));
        app.layout.focus(Panel::RunHistory);
        for _ in 0..3 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert!(texts(&output).iter().any(|(text, _)| text == "Captures"));
    }
}

#[test]
fn history_tabs_switch_back_from_captures_with_empty_and_populated_lists() {
    for populated in [false, true] {
        for (size, font_size) in [
            (egui::vec2(1280.0, 820.0), 16.0),
            (egui::vec2(800.0, 600.0), 24.0),
        ] {
            let ctx = egui::Context::default();
            theme::install(&ctx);
            theme::text_size(&ctx, font_size);
            let mut app = app();
            observer_fixture(&mut app);
            app.settings.font_size = font_size;
            if populated {
                app.snapshot.runs.push(run("live-run"));
                app.snapshot
                    .captures
                    .push(observer("active", CaptureState::Active));
            }
            app.layout.focus(Panel::RunHistory);
            for _ in 0..3 {
                click_label(&mut app, &ctx, size, "Captures");
                assert!(app.capture_tab, "Captures must open at {size:?}");
                click_label(&mut app, &ctx, size, "Runs");
                assert!(
                    !app.capture_tab,
                    "Runs must reopen at {size:?}, populated={populated}"
                );
            }
        }
    }
}

#[test]
fn core_picker_captures_the_complete_identity_and_requires_supported_selected_vm() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    observer_fixture(&mut app);
    app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(15);
    app.open_core_picker();
    assert!(!app.process_picker.open);
    assert!(app
        .manual_core_unavailable()
        .unwrap()
        .contains("revision 16"));
    app.snapshot.guest_kernel.as_mut().unwrap().revision = Some(16);
    let identity = antinomie_monitor_core::GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 55,
        tgid: 42,
        start_boot_ns: 100,
    };
    app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
        boot_id: "boot".into(),
        after_pid: 0,
        next_pid: 42,
        processes: vec![antinomie_monitor_core::GuestProcess {
            identity: identity.clone(),
            parent_tgid: 1,
            uid: 1000,
            gid: 1000,
            thread_count: 3,
            command: "core-target".into(),
        }],
    });
    app.open_core_picker();
    assert!(matches!(
        app.submitted.last(),
        Some(Command::ListProcesses { after_pid: 0 })
    ));
    let size = egui::vec2(1000.0, 800.0);
    click_label(&mut app, &ctx, size, "core-target");
    assert_eq!(app.process_picker.selected.as_ref(), Some(&identity));
    // The foreground picker and background panel share the same action
    // name. Click the foreground button rather than the toolbar/panel.
    let output = render(&mut app, &ctx, size);
    let label = format!("{} Dump core", egui_phosphor::regular::FILE);
    let position = texts(&output)
        .iter()
        .rfind(|(text, _)| text == &label)
        .unwrap()
        .1
        .center();
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events: vec![
                    egui::Event::PointerMoved(position),
                    egui::Event::PointerButton {
                        pos: position,
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
    assert!(
        matches!(app.submitted.last(), Some(Command::DumpProcessCore { request })
        if request.target == identity && request.vm_id == "vm" && request.max_size == 64 * 1024 * 1024
            && request.timeout_ms == 5000 && request.source_run_id.is_none())
    );
    assert!(!app.process_picker.open);
    assert!(!app
        .submitted
        .iter()
        .any(|command| matches!(command, Command::AttachProcess { .. })));
    app.selected = Some("other-vm".into());
    assert!(app.manual_core_unavailable().is_some());
    app.open_core_picker();
    assert!(!app.process_picker.open);
}

#[test]
fn process_picker_click_attaches_the_complete_identity_and_filters() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    observer_fixture(&mut app);
    let identity = antinomie_monitor_core::GuestProcessIdentity {
        boot_id: "boot".into(),
        task_cookie: 55,
        tgid: 42,
        start_boot_ns: 100,
    };
    app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
        boot_id: "boot".into(),
        after_pid: 0,
        next_pid: 42,
        processes: vec![antinomie_monitor_core::GuestProcess {
            identity: identity.clone(),
            parent_tgid: 1,
            uid: 1000,
            gid: 1000,
            thread_count: 3,
            command: "guest-target".into(),
        }],
    });
    app.open_process_picker();
    let size = egui::vec2(800.0, 600.0);
    click_label(&mut app, &ctx, size, "guest-target");
    assert_eq!(app.process_picker.selected.as_ref(), Some(&identity));
    click_label(
        &mut app,
        &ctx,
        size,
        &format!("{} Attach", egui_phosphor::regular::PLUG),
    );
    assert!(
        matches!(app.submitted.last(), Some(Command::AttachProcess { identity: selected }) if selected == &identity)
    );
    assert!(!app.process_picker.open);
    assert!(app.terminals.is_empty());
    // The backend lists every page at once; the picker filters by name or PID.
    app.open_process_picker();
    for (filter, shown) in [("target", true), ("4", true), ("sshd", false)] {
        app.process_picker.filter = filter.into();
        for _ in 0..2 {
            render(&mut app, &ctx, size);
        }
        let output = render(&mut app, &ctx, size);
        assert_eq!(
            texts(&output)
                .iter()
                .any(|(text, _)| text == "guest-target"),
            shown,
            "{filter}"
        );
    }
}

#[test]
#[ignore = "requires X11 capture controls preview; automatically exits after 12 seconds"]
fn native_capture_controls_fixture() {
    use winit::platform::x11::EventLoopBuilderExtX11;
    struct QaApp {
        app: MonitorApp,
        deadline: Instant,
    }
    impl eframe::App for QaApp {
        fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
            if Instant::now() >= self.deadline {
                eprintln!("native capture QA commands: {:?}", self.app.submitted);
                assert!(self.app.terminals.is_empty());
                assert!(self.app.submitted.iter().all(|command| matches!(
                    command,
                    Command::ListProcesses { .. }
                        | Command::AttachProcess { .. }
                        | Command::CaptureAll
                        | Command::StopCapture { .. }
                )));
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            eframe::App::update(&mut self.app, ctx, frame);
        }
    }
    let small = std::env::var_os("ANTINOMIE_CAPTURE_QA_SMALL").is_some();
    let picker = std::env::var_os("ANTINOMIE_CAPTURE_QA_PICKER").is_some();
    eframe::run_native(
        "Antinomie Capture QA",
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
            observer_fixture(&mut app);
            app.settings.font_size = if small { 24.0 } else { 18.0 };
            app.snapshot
                .captures
                .push(observer("previous-observation", CaptureState::Stopped));
            app.snapshot.capture_events.insert(
                "previous-observation".into(),
                vec![event(1, 0), event(2, 1)],
            );
            app.capture_tab = true;
            app.layout.focus(Panel::RunHistory);
            if picker {
                app.snapshot.process_page = Some(antinomie_monitor_core::GuestProcessPage {
                    boot_id: "boot".into(),
                    after_pid: 0,
                    next_pid: 64,
                    processes: (1..=64)
                        .map(|pid| antinomie_monitor_core::GuestProcess {
                            identity: antinomie_monitor_core::GuestProcessIdentity {
                                boot_id: "boot".into(),
                                task_cookie: u64::from(pid),
                                tgid: pid,
                                start_boot_ns: u64::from(pid) * 100,
                            },
                            parent_tgid: 1,
                            uid: 1000,
                            gid: 1000,
                            thread_count: 2,
                            command: format!("guest-process-{pid}"),
                        })
                        .collect(),
                });
                app.open_process_picker();
            }
            Ok(Box::new(QaApp {
                app,
                deadline: Instant::now() + Duration::from_secs(12),
            }))
        }),
    )
    .unwrap();
}

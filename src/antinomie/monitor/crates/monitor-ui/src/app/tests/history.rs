// SPDX-License-Identifier: GPL-3.0-only
//! Run history, details and saved trace selection.
use super::*;

#[test]
fn history_answers_from_another_vm_cannot_replace_selected_vm() {
    let mut app = app();
    app.selected = Some("selected".into());
    let mut current = run("current");
    current.vm_id = "selected".into();
    app.history = vec![current];
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "other".into(),
        generation: app.history_generation,
        result: Ok(vec![run("stale")]),
        checked: Vec::new(),
        retained: Vec::new(),
    });
    assert_eq!(app.history[0].id, "current");
    app.refresh_history();
    assert!(
        matches!(&app.pending_archive, Some(Request::ListVm { vm_id, .. }) if vm_id == "selected")
    );
    let old_generation = app.history_generation;
    app.refresh_history();
    app.handle_archive_answer(Answer::ListVm {
        vm_id: "selected".into(),
        generation: old_generation,
        result: Ok(vec![run("outdated-roots")]),
        checked: Vec::new(),
        retained: Vec::new(),
    });
    assert_eq!(app.history[0].id, "current");
}

#[test]
fn selected_vm_hides_another_vms_live_trace_and_finished_runs_are_past() {
    let mut app = app();
    app.selected = Some("other-vm".into());
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.events = vec![event(1, 0)];
    app.snapshot.runs = vec![run("current")];
    assert!(app.invocations().is_empty());
    app.selected = Some("vm".into());
    assert_eq!(app.invocations().len(), 1);
    assert!(app.live_history_run(&app.snapshot.runs[0]));
    app.snapshot.runs[0].state = RunState::Finished;
    assert!(!app.live_history_run(&app.snapshot.runs[0]));
}

#[test]
fn async_only_row_keeps_missing_phases_and_renders_observation_loss() {
    let mut observed = event(3, 2);
    observed.args = None;
    observed.result = Some(-61);
    observed.fields = vec![antinomie_monitor_core::FieldSummary {
        arg: None,
        object_id: 1,
        key: "async.stage".into(),
        layout: "u64".into(),
        logical_len: Some(8),
        captured_len: 8,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: 6u64.to_le_bytes().to_vec(),
        raw_path: None,
        ranges: vec![(0, 8)],
        recapture: None,
        encoding: None,
    }];
    let mut row = InvocationSummary {
        stream_id: observed.stream_id,
        task_cookie: observed.task_cookie,
        call_id: observed.call_id,
        entry: None,
        exit: None,
        async_events: vec![observed.clone()],
        async_saved: 1,
        task_exit: None,
        kernel_notes: Vec::new(),
    };
    assert_eq!(trace::representative(&row).unwrap().tid, 42);
    assert!(
        trace::info(&row).contains("missing Entry; missing Exit; Async: Observation unavailable")
    );
    assert!(!trace::info(&row).contains("Canceled"));
    row.async_events[0].fields[0].preview = 99u64.to_le_bytes().to_vec();
    assert!(trace::info(&row).contains("Unknown stage 99"));
    row.async_events[0] = observed;
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut inspector = trace::Inspector::default();
    let output = ctx.run(egui::RawInput::default(), |ctx| {
        egui::CentralPanel::default().show(ctx, |ui| {
            inspector.show(ui, Some(&row), false);
        });
    });
    assert!(texts(&output).iter().any(|(label, _)| label == "Async (1)"));
    assert!(row.entry.is_none() && row.exit.is_none());
    inspector.selection = Some(trace::Selection::AsyncCaptured {
        event_seq: 3,
        object_id: 1,
    });
    assert_eq!(inspector.field(&row).unwrap().key, "async.stage");
}

#[test]
fn a_call_the_task_ended_in_shows_how_it_ended_and_empty_reads_say_why() {
    let render = |row: &InvocationSummary| {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut inspector = trace::Inspector::default();
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(2400.0, 1500.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    inspector.show(ui, Some(row), false);
                });
            },
        );
        // Every drawn text, clipped or not: a long note runs past the tree's edge.
        fn all(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().trim().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| all(shape, out)),
                _ => {}
            }
        }
        let mut shown = Vec::new();
        for clipped in &output.shapes {
            all(&clipped.shape, &mut shown);
        }
        shown
    };
    let mut entry = event(1, 0);
    entry.syscall_nr = 231;
    entry.syscall_name = "exit_group".into();
    entry.args = Some([1, 0, 0, 0, 0, 0]);
    let mut ended = entry.clone();
    ended.phase = 3;
    ended.event_seq = 9;
    ended.fields = vec![antinomie_monitor_core::FieldSummary {
        arg: None,
        object_id: 1,
        key: "lifecycle.task_exit".into(),
        layout: String::new(),
        logical_len: Some(8),
        captured_len: 8,
        status: Some(0),
        capture_error: 0,
        complete: true,
        // exit_group(1): the kernel keeps the wait status 1 << 8.
        preview: 0x100u64.to_le_bytes().to_vec(),
        raw_path: None,
        ranges: vec![(0, 8)],
        recapture: None,
        encoding: None,
    }];
    let mut row = InvocationSummary {
        stream_id: 1,
        task_cookie: 3,
        call_id: 2,
        entry: Some(entry),
        exit: None,
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: Some(ended),
        kernel_notes: Vec::new(),
    };
    let cells = trace::cells(&row);
    assert_eq!(cells[1].0[0].0, "1\u{2192}9");
    assert_eq!(cells[5].0[0].0, "exit 1");
    assert!(!trace::info(&row).contains("missing Exit"));
    let shown = render(&row);
    assert!(shown.iter().any(|text| text == "Task ended"), "{shown:?}");
    assert!(shown.iter().any(|text| text == "exit 1"));
    assert!(!shown.iter().any(|text| text == "missing Exit"));
    // Without the kernel's record the Exit is reported missing as before.
    row.task_exit = None;
    assert_eq!(trace::cells(&row)[5].0[0].0, "missing Exit");

    // read() at end of file returns 0 and captures no buffer.
    let mut exit = event(2, 0);
    exit.result = Some(0);
    let read = InvocationSummary {
        stream_id: 1,
        task_cookie: 3,
        call_id: 2,
        entry: Some(event(1, 0)),
        exit: Some(exit),
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
        kernel_notes: Vec::new(),
    };
    let shown = render(&read);
    assert!(
        shown
            .iter()
            .any(|text| text == "nothing to capture: the call returned 0 bytes"),
        "{shown:?}"
    );
}

#[test]
fn details_values_copy_in_many_forms_and_captured_fields_open_data_windows() {
    let mut exit = event(2, 0);
    exit.result = Some(-2);
    exit.fields = vec![antinomie_monitor_core::FieldSummary {
        arg: None,
        object_id: 5,
        key: "buf".into(),
        layout: String::new(),
        logical_len: Some(8),
        captured_len: 4,
        status: Some(1),
        capture_error: -14,
        complete: false,
        preview: b"abcd".to_vec(),
        raw_path: None,
        ranges: vec![(0, 4)],
        recapture: None,
        encoding: None,
    }];
    let row = InvocationSummary {
        stream_id: 1,
        task_cookie: 3,
        call_id: 2,
        entry: Some(event(1, 0)),
        exit: Some(exit),
        async_events: Vec::new(),
        async_saved: 0,
        task_exit: None,
        kernel_notes: Vec::new(),
    };
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut inspector = trace::Inspector::default();
    let frame = |inspector: &mut trace::Inspector, events: Vec<egui::Event>| {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 900.0),
                )),
                events,
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    inspector.show(ui, Some(&row), false);
                });
            },
        )
    };
    let click = |inspector: &mut trace::Inspector, pos: egui::Pos2, button| {
        let mut copied = Vec::new();
        for events in [
            vec![egui::Event::PointerMoved(pos)],
            vec![egui::Event::PointerButton {
                pos,
                button,
                pressed: true,
                modifiers: egui::Modifiers::NONE,
            }],
            vec![egui::Event::PointerButton {
                pos,
                button,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
            Vec::new(),
        ] {
            let output = frame(inspector, events);
            for command in output.platform_output.commands {
                if let egui::OutputCommand::CopyText(text) = command {
                    copied.push(text);
                }
            }
        }
        (frame(inspector, Vec::new()), copied)
    };
    let find = |output: &egui::FullOutput, label: &str| {
        texts(output)
            .into_iter()
            .find(|(text, _)| text == label)
            .map(|(_, rect)| rect.center())
    };
    let (output, _) = click(
        &mut inspector,
        egui::pos2(-10.0, -10.0),
        egui::PointerButton::Primary,
    );
    // The return value reads by meaning: the error name, its number in
    // the copy menu.
    assert!(find(&output, "ENOENT").is_some(), "error shown by name");
    let target = find(&output, "Return").expect("return value shown");
    let (output, _) = click(&mut inspector, target, egui::PointerButton::Secondary);
    for (label, value) in [
        ("Signed decimal", "-2"),
        ("Hex", "0xfffffffffffffffe"),
        ("Decimal", "18446744073709551614"),
    ] {
        assert!(find(&output, label).is_some(), "{label} offered");
        assert!(find(&output, value).is_some(), "{value} previewed");
    }
    // The menu is drawn last, over the numeric view's own "Hex" row.
    let hex = texts(&output)
        .into_iter()
        .filter(|(text, _)| text == "Hex")
        .map(|(_, rect)| rect.center())
        .next_back()
        .unwrap();
    let (output, copied) = click(&mut inspector, hex, egui::PointerButton::Primary);
    assert_eq!(copied, ["0xfffffffffffffffe"]);

    // A captured field: right-click offers its data window. The
    // argument row shows the pointer; the Exit data sits under it.
    assert!(find(&output, "0x1000").is_some(), "pointer argument in hex");
    let argument = find(&output, "buf").expect("argument row");
    let (mut output, _) = click(&mut inspector, argument, egui::PointerButton::Primary);
    for _ in 0..20 {
        output = frame(&mut inspector, Vec::new());
    }
    assert!(matches!(
        inspector.selection,
        Some(trace::Selection::Argument { index: 1, .. })
    ));
    let mut rows: Vec<_> = texts(&output)
        .into_iter()
        .filter(|(text, rect)| text == "buf" && rect.left() < 600.0)
        .map(|(_, rect)| rect)
        .collect();
    rows.sort_by(|a, b| a.top().total_cmp(&b.top()));
    assert_eq!(rows.len(), 2, "argument row and its captured field");
    assert!(
        rows[1].left() > rows[0].left(),
        "field indented under argument"
    );
    let field = rows[1].center();
    let (output, _) = click(&mut inspector, field, egui::PointerButton::Secondary);
    let open = find(
        &output,
        &format!("{} Open data…", egui_phosphor::regular::ARROW_SQUARE_OUT),
    )
    .expect("Open data offered");
    click(&mut inspector, open, egui::PointerButton::Primary);
    assert_eq!(inspector.open_data.len(), 1);
    assert_eq!(inspector.open_data[0].field.object_id, 5);
    assert_eq!(inspector.open_data[0].title, "buf / read call 2");

    // The selected field names its partial capture instead of "x bytes captured".
    inspector.selection = Some(trace::Selection::Captured {
        phase: 2,
        object_id: 5,
    });
    let output = frame(&mut inspector, Vec::new());
    let shown = texts(&output);
    assert!(shown
        .iter()
        .any(|(text, _)| text == "Captured bytes (4 of 8 bytes, copy fault)"));
    assert!(!shown
        .iter()
        .any(|(text, _)| text.contains("bytes captured;")));
}

#[test]
fn saved_trace_selection_never_replaces_live_collector_or_terminal() {
    let mut app = app();
    app.selected = Some("vm".into());
    let live = run("live");
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.runs = vec![live.clone()];
    app.snapshot.events = vec![event(1, 0)];
    sync_runs(&mut app.terminals, &app.snapshot);
    app.select_archive_run("live".into());
    assert!(app.offline_run().is_some());
    assert!(matches!(
        &app.pending_archive,
        Some(Request::Invocations { .. })
    ));
    assert_eq!(app.snapshot.events.len(), 1);
    assert_eq!(app.snapshot.runs[0].state, RunState::Running);
    assert!(app.terminals["live"].open && app.terminals["live"].interactive());
}

#[test]
fn root_exit_is_independent_of_full_tree_completion_and_legacy_state() {
    let mut run = run("descendants");
    run.execution = Some(antinomie_monitor_core::RunExecution {
        generation: 2,
        live_task_count: 3,
        pending_async_count: 1,
        flags: 1,
        root_wait_status: Some(7 << 8),
        root_exit: Some(WaitStatus::Exited { code: 7 }),
        async_loss_count: 0,
        total_task_count: 4,
    });
    assert_eq!(run_status(&run), "Running");
    assert_eq!(root_exit(&run), "Exit 7");
    assert!(execution_detail(&run).contains("3 live tasks; 1 pending async"));
    assert!(!execution_detail(&run).contains("SIGKILL"));
    // A Stop that the guest had to finish with SIGKILL says so.
    let escalated = {
        let mut run = run.clone();
        let execution = run.execution.as_mut().unwrap();
        execution.flags |= 32;
        execution.root_exit = Some(WaitStatus::Signaled {
            signal: 9,
            core_dumped: false,
        });
        run
    };
    assert_eq!(root_exit(&escalated), "Signal 9");
    assert!(execution_detail(&escalated).contains("Stop needed SIGKILL after the grace period"));
    run.execution = None;
    run.state = RunState::Finalized;
    assert_eq!(root_exit(&run), "Unknown");
    assert_eq!(run_status(&run), "Recording ended");
}

#[test]
fn finalized_dirty_run_and_reopen_replay_archive_with_fresh_generation() {
    let mut app = app();
    let mut finished = run("finished");
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.runs.push(finished.clone());
    app.reopen(finished.clone());
    app.terminals
        .get_mut("finished")
        .unwrap()
        .output(3, b"missing tail", false);
    finished.state = RunState::Finalized;
    app.snapshot.active_vm = None;
    app.snapshot.state = VmState::Stopped;
    app.snapshot.runs = vec![finished.clone()];
    sync_runs(&mut app.terminals, &app.snapshot);
    let terminal = &app.terminals["finished"];
    assert!(!terminal.dirty);
    assert_eq!(terminal.replay_offset, Some(0));
    let old_generation = terminal.generation;
    app.snapshot.runs[0] = finished.clone();
    app.terminals.get_mut("finished").unwrap().close_view();
    app.reopen(finished);
    assert_ne!(app.terminals["finished"].generation, old_generation);
    app.handle_archive_answer(Answer::Terminal {
        run_id: "finished".into(),
        generation: old_generation,
        result: Ok(crate::archive::TerminalReplay {
            page: antinomie_monitor_core::TerminalPage {
                records: vec![TerminalRecord::Output(b"stale".to_vec())],
                next_offset: None,
            },
            screen_warning: None,
        }),
    });
    assert!(!app.terminals["finished"]
        .terminal
        .contents()
        .contains("stale"));
    assert_eq!(app.terminals["finished"].replay_offset, Some(0));
}

#[test]
fn past_boot_finished_and_stopped_terminals_reclaim_closed_slots() {
    for state in [RunState::Finished, RunState::Stopped] {
        let mut app = app();
        for index in 0..TERMINAL_VIEW_LIMIT {
            let mut past = run(&format!("past-{index}"));
            past.state = state.clone();
            past.boot_id = "previous-boot".into();
            app.terminals
                .insert(past.id.clone(), RunTerminal::new(past));
        }
        let closed = app.terminals["past-0"].run.clone();
        app.terminals.get_mut(&closed.id).unwrap().close_view();
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs = vec![run("new-launch")];
        assert_eq!(available_terminal_slots(&app.terminals, &app.snapshot), 1);
        assert!(app.launch_admission().is_ok());
        app.pending_launch = Some(77);
        app.reopen(closed.clone());
        assert!(!app.terminals[&closed.id].open);
        sync_runs(&mut app.terminals, &app.snapshot);
        assert!(!app.terminals.contains_key(&closed.id));
        assert!(app.terminals["new-launch"].open);
        assert_eq!(app.terminals.len(), TERMINAL_VIEW_LIMIT);
    }
}

#[test]
fn ended_boot_finished_and_stopped_runs_reopen_from_archive() {
    for state in [RunState::Finished, RunState::Stopped] {
        let mut app = app();
        app.selected = Some("vm".into());
        let mut past = run("past");
        past.state = state;
        app.snapshot.runs = vec![past.clone()];
        let mut terminal = RunTerminal::new(past.clone());
        terminal.terminal.process(b"outdated screen");
        terminal.dirty = true;
        terminal.close_view();
        app.terminals.insert(past.id.clone(), terminal);
        sync_runs(&mut app.terminals, &app.snapshot);
        let previous_generation = app.terminals["past"].generation;
        app.reopen(past);
        let terminal = &app.terminals["past"];
        assert!(terminal.open && !terminal.dirty);
        assert_eq!(terminal.replay_offset, Some(0));
        assert!(terminal.generation > previous_generation);
        assert!(!terminal.terminal.contents().contains("outdated screen"));
        app.select_run(Some("past".into()));
        assert!(app.offline_run().is_some());
        assert!(matches!(
            app.pending_archive,
            Some(Request::Invocations { .. })
        ));
    }
}

#[test]
fn current_boot_finished_and_stopped_terminals_preserve_live_session_state() {
    for state in [RunState::Finished, RunState::Stopped] {
        let mut app = app();
        let mut current = run("current");
        current.state = state;
        app.snapshot.active_vm = Some("vm".into());
        app.snapshot.state = VmState::Running;
        app.snapshot.runs = vec![current.clone()];
        app.reopen(current.clone());
        app.terminals
            .get_mut("current")
            .unwrap()
            .terminal
            .process(b"retained current screen");
        app.terminals.get_mut("current").unwrap().close_view();
        for index in 1..TERMINAL_VIEW_LIMIT {
            let past = run(&format!("open-history-{index}"));
            app.terminals
                .insert(past.id.clone(), RunTerminal::new(past));
        }
        assert_eq!(available_terminal_slots(&app.terminals, &app.snapshot), 0);
        assert!(app.launch_admission().is_err());
        let generation = app.terminals["current"].generation;
        app.pending_launch = Some(77);
        app.reopen(current);
        sync_runs(&mut app.terminals, &app.snapshot);
        let terminal = &app.terminals["current"];
        assert!(terminal.open && terminal.dirty);
        assert_eq!(terminal.generation, generation);
        assert!(terminal.replay_offset.is_none());
        assert!(terminal
            .terminal
            .contents()
            .contains("retained current screen"));
        app.select_run(Some("current".into()));
        assert!(app.offline_run().is_none());
    }
}

#[test]
fn live_terminal_ownership_requires_matching_vm_boot_and_attached_session() {
    let current = run("current");
    let mut snapshot = Snapshot {
        active_vm: Some("vm".into()),
        state: VmState::Running,
        runs: vec![current.clone()],
        ..Snapshot::default()
    };
    assert!(run_in_live_session(&snapshot, &current));
    let mut past = current.clone();
    past.boot_id = "previous-boot".into();
    assert!(!run_in_live_session(&snapshot, &past));
    past = current.clone();
    past.vm_id = "other-vm".into();
    assert!(!run_in_live_session(&snapshot, &past));
    snapshot.state = VmState::Starting;
    assert!(!run_in_live_session(&snapshot, &current));
    snapshot.state = VmState::Stopping;
    assert!(run_in_live_session(&snapshot, &current));
    snapshot.active_vm = None;
    assert!(!run_in_live_session(&snapshot, &current));
}

#[test]
fn snapshot_recovers_missing_launch_notification_and_preserves_closed_views() {
    let mut app = app();
    let run = run("missed");
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.runs = vec![run];
    sync_runs(&mut app.terminals, &app.snapshot);
    assert!(app.terminals["missed"].open && app.terminals["missed"].dirty);
    let terminal = app.terminals.get_mut("missed").unwrap();
    terminal.output(1, b"kept", false);
    terminal.close_view();
    sync_runs(&mut app.terminals, &app.snapshot);
    assert!(!app.terminals["missed"].open);
    assert_eq!(app.terminals["missed"].terminal.contents(), "kept");
    assert_eq!(app.terminals.len(), 1);
}

#[test]
fn stale_archive_and_capture_answers_cannot_replace_new_selection() {
    let mut app = app();
    let mut old = run("past");
    old.state = RunState::Finalized;
    app.history.push(old);
    app.select_run(Some("past".into()));
    let generation = app.archive_generation;
    app.archive_page = pair_events(&[event(1, 0)]);
    app.handle_archive_answer(Answer::Invocations {
        generation: generation.wrapping_sub(1),
        offset: 99,
        total: None,
        source_total: None,
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: pair_events(&[event(2, 3)]),
            next_offset: None,
            issues: vec![],
        }),
    });
    assert!(app.archive_page[0].entry.is_some());
    assert_eq!(app.archive_offset, 0);
    app.inspector.clear();
    let old_generation = app.inspector.generation;
    app.inspector.clear();
    app.handle_archive_answer(Answer::Captured {
        generation: old_generation,
        offset: 8,
        result: Ok(vec![1, 2, 3]),
    });
    assert!(app.inspector.data.is_empty());
    app.select_run(None);
    app.handle_archive_answer(Answer::Invocations {
        generation,
        offset: 99,
        total: None,
        source_total: None,
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: pair_events(&[event(2, 3)]),
            next_offset: None,
            issues: vec![],
        }),
    });
    assert!(app.archive_page.is_empty());
}

#[test]
fn paired_selection_uses_task_call_stream_despite_cpu_migration() {
    let mut app = app();
    app.snapshot.events = vec![event(1, 0), event(2, 3)];
    let rows = app.invocations();
    assert_eq!(rows.len(), 1);
    assert_eq!(trace::key(&rows[0]), (1, 3, 2));
    assert_eq!(rows[0].exit.as_ref().unwrap().cpu, 3);
    assert!(trace::info(&rows[0]).contains("fd=3 buf=0x1000 count=8"));
    app.selected_event = Some((1, 3, 2));
    assert_eq!(
        app.invocations()
            .iter()
            .filter(|row| Some(trace::key(row)) == app.selected_event)
            .count(),
        1
    );
}

#[test]
fn history_selection_keeps_live_snapshot_and_stale_answers_are_ignored() {
    let mut app = app();
    app.selected = Some("vm".into());
    app.snapshot.active_vm = Some("vm".into());
    app.snapshot.state = VmState::Running;
    app.snapshot.events = vec![event(1, 0)];
    app.snapshot.runs.push(run("live"));
    let mut old = run("past");
    old.state = RunState::Finalized;
    app.history.push(old);
    app.select_run(Some("past".into()));
    app.archive_page = pair_events(&[event(2, 1)]);
    assert!(app.invocations()[0].entry.is_none());
    assert_eq!(app.snapshot.events.len(), 1);
    let generation = app.archive_generation;
    app.select_run(Some("live".into()));
    assert_ne!(generation, app.archive_generation);
    assert!(app.invocations()[0].entry.is_some());
    assert!(app.snapshot.events[0].result.is_none());
}

#[test]
fn all_live_windows_keep_independent_run_identity_when_one_closes() {
    let mut app = app();
    app.snapshot.runs = vec![run("one"), run("two")];
    app.reopen(run("one"));
    app.reopen(run("two"));
    app.terminals.get_mut("one").unwrap().close_view();
    assert!(!app.terminals["one"].open);
    assert!(app.terminals["two"].open);
    assert_eq!(app.snapshot.runs[0].state, RunState::Running);
    app.reopen(run("one"));
    assert!(app.terminals["one"].open);
}

#[test]
fn the_run_list_keeps_the_analysis_report_without_copying_its_rows() {
    let mut analyzed = run("analyzed");
    analyzed.state = RunState::Finalized;
    analyzed.request.path = "/bin/analyzed".into();
    analyzed.analysis = Some(section_report("analyzed", "sample"));
    let copy = listed(&analyzed);
    assert!(copy
        .analysis
        .as_ref()
        .is_some_and(|report| report.sections.is_empty() && report.id == "analyzed"));
    assert_eq!(copy.id, analyzed.id);
    assert_eq!(copy.request.path, analyzed.request.path);
    assert_eq!(analyzed.analysis.as_ref().unwrap().sections.len(), 3);
    assert!(listed(&run("plain")).analysis.is_none());

    let mut app = app();
    observer_fixture(&mut app);
    app.history = vec![analyzed.clone()];
    app.focus_panel = Some(Panel::RunHistory);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1400.0, 900.0);
    for _ in 0..3 {
        render(&mut app, &ctx, size);
    }
    let shown: Vec<_> = texts(&render(&mut app, &ctx, size))
        .into_iter()
        .map(|(text, _)| text)
        .collect();
    // The executable is followed by the run's short id, never by a mark.
    assert!(shown.iter().any(|text| text == "[analyzed]"), "{shown:?}");
    assert!(
        shown.iter().all(|text| !text.contains("[static analysis]")),
        "{shown:?}"
    );
    assert_eq!(
        app.history[0].analysis, analyzed.analysis,
        "drawing leaves the retained run whole"
    );
}

#[test]
fn a_check_that_timed_out_is_a_warning_in_the_tree_not_a_missing_check() {
    use antinomie_monitor_core::{AnalysisKind, AnalysisSectionState};
    let mut run = run("r1");
    run.request.analysis.enabled = true;
    run.request.analysis.checks = vec![AnalysisKind::Metadata, AnalysisKind::Strings];
    let mut report = section_report("r1", "sample");
    // The fixture's Strings check ran out of time.
    report.sections[2].state = AnalysisSectionState::Timeout;
    run.analysis = Some(report);
    let tree = super::super::history::feature_tree(&run, None);
    let strings = tree
        .iter()
        .find(|feature| feature.text.contains("Strings"))
        .expect("the Strings check");
    assert!(strings.timed_out && !strings.available);
    let metadata = tree
        .iter()
        .find(|feature| feature.text.contains("Metadata") || feature.text.contains("metadata"))
        .expect("the Metadata check");
    assert!(!metadata.timed_out && metadata.available);
}

#[test]
fn enabled_analysis_is_a_tree_with_unavailable_checks_greyed() {
    use antinomie_monitor_core::AnalysisKind;
    let mut run = run("r1");
    run.request.analysis.enabled = true;
    run.request.analysis.checks = vec![
        AnalysisKind::Metadata,
        AnalysisKind::Structures,
        AnalysisKind::Rules,
    ];
    run.request.capture_network = true;
    // Without a report nothing is known to be missing.
    let tree = super::super::history::feature_tree(&run, None);
    assert_eq!(tree.len(), 5);
    assert!(tree.iter().all(|feature| feature.available));
    assert_eq!(
        tree.iter().map(|feature| feature.depth).collect::<Vec<_>>(),
        [0, 1, 1, 1, 0]
    );
    // Structures is unavailable in the fixture's report and Rules has no section.
    run.analysis = Some(super::section_report("rep", "m"));
    let tree = super::super::history::feature_tree(&run, None);
    let available = |name: &str| {
        tree.iter()
            .find(|feature| feature.text == name)
            .unwrap_or_else(|| panic!("{name}"))
            .available
    };
    assert!(available(AnalysisKind::Metadata.label()));
    assert!(!available(AnalysisKind::Structures.label()));
    assert!(!available(AnalysisKind::Rules.label()));
    assert!(available("Network capture"));
}

#[test]
fn run_history_table_follows_the_pane_width() {
    let mut app = super::ui_polish_shots::history_fixture();
    app.focus_panel = Some(Panel::RunHistory);
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let header_x = |app: &mut MonitorApp, width: f32| {
        let mut x = 0.0;
        for _ in 0..4 {
            let output = render(app, &ctx, egui::vec2(width, 800.0));
            x = texts(&output)
                .into_iter()
                .find(|(text, _)| text == "Arguments")
                .map_or(x, |(_, rect)| rect.min.x);
        }
        x
    };
    let narrow = header_x(&mut app, 1100.0);
    let wide = header_x(&mut app, 1700.0);
    assert!(
        wide > narrow + 400.0,
        "the Executable column takes the extra width: {narrow} -> {wide}"
    );
}

#[test]
fn a_click_in_the_run_tree_filters_the_trace_to_that_process() {
    let mut app = super::ui_polish_shots::history_fixture();
    let ctx = egui::Context::default();
    crate::theme::install(&ctx);
    let mut at = None;
    for _ in 0..4 {
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 900.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.history_detail(ui));
            },
        );
        at = texts(&output)
            .into_iter()
            .find(|(text, _)| text == "sh")
            .map(|(_, rect)| rect.center());
    }
    let at = at.expect("the tree lists sh");
    for pressed in [true, false] {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(900.0, 900.0),
                )),
                events: vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.history_detail(ui));
            },
        );
    }
    assert_eq!(app.filter, "process.pid == 43");
    assert_eq!(app.applied_filter, "process.pid == 43");
    assert!(app.focus_panel == Some(Panel::Trace));
}

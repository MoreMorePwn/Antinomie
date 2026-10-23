// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn page_size_defaults_round_trips_large_sizes_and_all_sentinels() {
    let old: Settings = serde_json::from_str("{}").unwrap();
    assert_eq!(old.trace_page_size, 100);
    for (saved, expected) in [
        (-1, 0),
        (0, 0),
        (1, 1),
        (37, 37),
        (256, 256),
        (999, 999),
        (100_000, 100_000),
    ] {
        let settings: Settings = serde_json::from_value(serde_json::json!({
            "trace_page_size": saved
        }))
        .unwrap();
        assert_eq!(settings.trace_page_size, expected);
        let restored: Settings =
            serde_json::from_str(&serde_json::to_string(&settings).unwrap()).unwrap();
        assert_eq!(restored.trace_page_size, expected);
    }
}

#[test]
fn direct_page_four_thousand_preserves_filter_and_uses_matching_rank() {
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    app.filter = "syscall.num == 9 && args.fd < 3".into();
    app.applied_filter.clone_from(&app.filter);
    app.archive_total = Some(500_000);
    app.jump_trace_page(3999);
    assert_eq!(app.trace_paging.page, 3999);
    assert!(
        matches!(&app.pending_archive, Some(Request::InvocationRange {
        offset: 0, skip: 399900, limit: 100, query, ..
    }) if query == &app.filter)
    );
    assert!(app.archive_previous.is_empty());
}

#[test]
fn all_and_large_pages_request_only_bounded_windows_and_reuse_cursors() {
    for size in [0, 5000, 1_000_000] {
        let mut app = app();
        app.selected = Some("vm".into());
        let mut past = run("past");
        past.state = RunState::Finalized;
        app.history.push(past);
        app.select_run(Some("past".into()));
        app.set_trace_page_size(size);
        assert!(matches!(
            app.pending_archive,
            Some(Request::InvocationRange {
                skip: 0,
                limit: 256,
                ..
            })
        ));
        app.trace_paging.remember(256, 9000);
        app.request_trace_window(300);
        assert!(matches!(
            app.pending_archive,
            Some(Request::InvocationRange {
                offset: 9000,
                skip: 44,
                limit: 256,
                ..
            })
        ));
        app.request_page(0);
        assert!(matches!(
            app.pending_archive,
            Some(Request::InvocationRange {
                offset: 0,
                skip: 0,
                limit: 256,
                ..
            })
        ));
    }
}

#[test]
fn all_mode_renders_a_million_row_extent_without_loading_a_million_calls() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    app.set_trace_page_size(0);
    let events: Vec<_> = (0..256)
        .map(|id| {
            let mut e = event(1, 0);
            e.call_id = id;
            e
        })
        .collect();
    app.handle_archive_answer(Answer::Invocations {
        generation: app.archive_generation,
        offset: 0,
        total: Some(1_000_000),
        source_total: Some(1_000_000),
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: pair_events(&events),
            next_offset: Some(9000),
            issues: Vec::new(),
        }),
    });
    app.pending_archive = None;
    let size = egui::vec2(1400.0, 900.0);
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let started = Instant::now();
    let output = render(&mut app, &ctx, size);
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(app.archive_page.len(), 256);
    assert_eq!(app.trace_page_count(), 1);
    assert!(texts(&output)
        .iter()
        .any(|(text, _)| text.contains("All 1000000 matching")));
    let position = texts(&output)
        .into_iter()
        .find(|(text, _)| text == "read (0)")
        .expect("a trace row is visible")
        .1
        .center();
    draw_input(
        &mut app,
        &ctx,
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
            events: vec![
                egui::Event::PointerMoved(position),
                egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(0.0, -20_000.0),
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            ..Default::default()
        },
    );
    for _ in 0..5 {
        let _ = render(&mut app, &ctx, size);
    }
    // Prefetch can start before row 256, and a remembered raw cursor can
    // reduce `skip` to zero. Assert the requested matching rank instead.
    assert!(
        app.trace_paging
            .pending_start
            .is_some_and(|start| start > 0),
        "no scrolled window requested: rank {:?}, pending {}, error {:?}",
        app.trace_paging.pending_start,
        app.archive_pending,
        app.archive_error
    );
    assert!(matches!(
        app.pending_archive,
        Some(Request::InvocationRange { limit: 256, .. })
    ));
    // Opening another recording must not inherit the old virtual scroll
    // position and immediately seek past that recording's beginning.
    let mut second = run("second");
    second.state = RunState::Finalized;
    second.directory = PathBuf::from("/second-recording");
    app.history.push(second);
    app.select_run(Some("second".into()));
    app.handle_archive_answer(Answer::Invocations {
        generation: app.archive_generation,
        offset: 0,
        total: Some(1_000_000),
        source_total: Some(1_000_000),
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: pair_events(&events),
            next_offset: Some(9000),
            issues: Vec::new(),
        }),
    });
    app.pending_archive = None;
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    assert!(app.trace_paging.pending_start.is_none());
    assert_eq!(app.trace_paging.window_start, 0);
}

#[test]
fn resizing_cancels_old_reads_resets_cursors_and_keeps_the_filtered_identity() {
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    app.filter = "syscall.num == 0".into();
    app.commit_trace_filter();
    let rows = pair_events(&[event(1, 0)]);
    let selected = trace::key(&rows[0]);
    app.archive_page.clone_from(&rows);
    app.selected_event = Some(selected);
    app.archive_previous = vec![0, 500];
    app.archive_next = Some(900);
    let old_generation = app.archive_generation;
    let old_cancel = Arc::clone(app.archive_read_cancel.as_ref().unwrap());
    app.set_trace_page_size(37);
    assert!(old_cancel.load(Ordering::Relaxed));
    assert!(app.archive_previous.is_empty());
    assert!(app.archive_next.is_none());
    assert_eq!(app.archive_offset, 0);
    assert!(matches!(&app.pending_archive,
        Some(Request::Invocations { offset: 0, limit: 37, query, .. })
        if query == "syscall.num == 0"));
    let answer = |generation, rows| Answer::Invocations {
        generation,
        offset: 0,
        total: Some(1),
        source_total: Some(350),
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: rows,
            next_offset: None,
            issues: Vec::new(),
        }),
    };
    app.handle_archive_answer(answer(old_generation, Vec::new()));
    assert!(app.archive_pending);
    assert_eq!(app.selected_event, Some(selected));
    app.handle_archive_answer(answer(app.archive_generation, rows));
    assert!(!app.archive_pending);
    assert_eq!(app.selected_event, Some(selected));
    app.request_page(0);
    assert!(matches!(
        app.pending_archive,
        Some(Request::Invocations { limit: 37, .. })
    ));
    app.handle_archive_answer(answer(app.archive_generation, Vec::new()));
    assert!(app.selected_event.is_none());
}

#[test]
fn archive_toolbar_uses_selected_size_in_page_counts() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut app = app();
    app.selected = Some("vm".into());
    let mut past = run("past");
    past.state = RunState::Finalized;
    app.history.push(past);
    app.select_run(Some("past".into()));
    app.set_trace_page_size(37);
    app.handle_archive_answer(Answer::Invocations {
        generation: app.archive_generation,
        offset: 0,
        total: Some(75),
        source_total: Some(350),
        result: Ok(antinomie_monitor_core::InvocationPage {
            invocations: Vec::new(),
            next_offset: None,
            issues: Vec::new(),
        }),
    });
    let size = egui::vec2(800.0, 600.0);
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let labels = texts(&render(&mut app, &ctx, size));
    assert!(labels.iter().any(|(text, _)| text == "Calls/page"));
    assert!(labels
        .iter()
        .any(|(text, _)| text == "Page 1 of 3 · 37 calls/page · 75 matching / 350 saved calls"));
}

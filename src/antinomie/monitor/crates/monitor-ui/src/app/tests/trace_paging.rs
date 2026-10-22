// SPDX-License-Identifier: GPL-3.0-only
use super::*;

#[test]
fn page_size_defaults_round_trips_and_clamps_restored_settings() {
    let old: Settings = serde_json::from_str("{}").unwrap();
    assert_eq!(old.trace_page_size, 100);
    for (saved, expected) in [(0, 1), (1, 1), (37, 37), (256, 256), (999, 256)] {
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

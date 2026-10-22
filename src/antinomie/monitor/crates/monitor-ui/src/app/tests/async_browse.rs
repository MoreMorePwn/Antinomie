// SPDX-License-Identifier: GPL-3.0-only
//! A call row that previews its async observations says so and browses the rest.
use super::*;
use antinomie_monitor_core::{AsyncPage, FieldSummary};
use std::sync::atomic::Ordering;

fn observation(call: u64, event_seq: u64) -> antinomie_monitor_core::EventSummary {
    let mut observed = event(3, 1);
    observed.call_id = call;
    observed.event_seq = event_seq;
    observed.args = None;
    observed.fields = vec![FieldSummary {
        arg: None,
        object_id: 1,
        key: "async.stage".into(),
        layout: "u64".into(),
        logical_len: Some(8),
        captured_len: 8,
        status: Some(0),
        capture_error: 0,
        complete: true,
        preview: 4u64.to_le_bytes().to_vec(),
        raw_path: None,
        ranges: vec![(0, 8)],
        recapture: None,
    }];
    observed
}

/// A call whose first 256 of `saved` observations are previewed.
fn dense_row(saved: u64) -> InvocationSummary {
    let mut events = vec![event(1, 1)];
    events.extend((0..256).map(|seq| observation(2, 100 + seq)));
    let mut row = pair_events(&events).remove(0);
    row.async_saved = saved;
    row
}

fn render(
    ctx: &egui::Context,
    inspector: &mut trace::Inspector,
    row: &InvocationSummary,
    events: Vec<egui::Event>,
) -> Vec<String> {
    let output = ctx.run(
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
                inspector.show(ui, Some(row), true);
            });
        },
    );
    texts(&output).into_iter().map(|(text, _)| text).collect()
}

/// Open the closed "Async" section by clicking its header.
fn open_async(ctx: &egui::Context, inspector: &mut trace::Inspector, row: &InvocationSummary) {
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 900.0),
            )),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                inspector.show(ui, Some(row), true);
            });
        },
    );
    let header = texts(&output)
        .into_iter()
        .find(|(text, _)| text.starts_with("Async ("))
        .expect("async header")
        .1;
    let at = header.center();
    let click = |pressed| egui::Event::PointerButton {
        pos: at,
        button: egui::PointerButton::Primary,
        pressed,
        modifiers: egui::Modifiers::NONE,
    };
    for events in [
        vec![egui::Event::PointerMoved(at)],
        vec![click(true)],
        vec![click(false)],
    ] {
        render(ctx, inspector, row, events);
    }
}

#[test]
fn a_partial_preview_names_what_it_leaves_out() {
    let row = dense_row(2600);
    assert_eq!((row.async_events.len(), row.async_omitted()), (256, 2344));
    assert!(trace::info(&row).contains("256 of 2,600 async observations shown"));
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut inspector = trace::Inspector::default();
    let shown = render(&ctx, &mut inspector, &row, Vec::new());
    assert!(shown
        .iter()
        .any(|text| text == "Async (256 of 2,600 saved)"));
    open_async(&ctx, &mut inspector, &row);
    let shown = render(&ctx, &mut inspector, &row, Vec::new());
    assert!(
        shown
            .iter()
            .any(|text| text == "2,344 more saved observations not shown"),
        "{shown:?}"
    );
    assert!(shown
        .iter()
        .any(|text| text == "Browse all saved observations"));
    // A complete preview has neither the note nor the button.
    let whole = dense_row(256);
    assert!(!trace::info(&whole).contains("async observations shown"));
    let mut inspector = trace::Inspector::default();
    let shown = render(&ctx, &mut inspector, &whole, Vec::new());
    assert!(shown.iter().any(|text| text == "Async (256)"));
}

#[test]
fn browsing_reads_pages_off_the_interface_thread_and_drops_stale_answers() {
    let row = dense_row(2600);
    let call = trace::key(&row);
    let mut inspector = trace::Inspector::default();
    inspector.begin_async(call);
    let wanted = inspector.take_async_read().expect("a page is wanted");
    assert_eq!((wanted.call, wanted.from), (call, 0));
    assert!(inspector.take_async_read().is_none());
    let page = |first: u64, next| AsyncPage {
        events: (0..256).map(|seq| observation(2, first + seq)).collect(),
        next_event_seq: next,
        total: 2600,
        issues: Vec::new(),
    };
    // An answer to a superseded read changes nothing.
    inspector.async_answer(
        wanted.generation.wrapping_sub(1),
        call,
        Ok(page(7000, None)),
    );
    assert!(inspector.find_async(&row, 7000).is_none());
    inspector.async_answer(wanted.generation, call, Ok(page(356, Some(612))));
    // Browsed events are found beside the preview, and fields of those the
    // preview lacks can be selected.
    assert!(inspector.find_async(&row, 100).is_some());
    assert!(inspector.find_async(&row, 400).is_some());
    inspector.selection = Some(trace::Selection::AsyncCaptured {
        event_seq: 400,
        object_id: 1,
    });
    assert!(inspector.field(&row).is_none());
    assert_eq!(
        inspector
            .browsed_field(&row)
            .map(|field| field.key)
            .as_deref(),
        Some("async.stage")
    );
    let ctx = egui::Context::default();
    theme::install(&ctx);
    open_async(&ctx, &mut inspector, &row);
    let shown = render(&ctx, &mut inspector, &row, Vec::new());
    assert!(
        shown
            .iter()
            .any(|text| text == "Async (1–256 of 2,600 saved)"),
        "{shown:?}"
    );
    assert!(shown.iter().any(|text| text == "Next page"));
    assert!(shown.iter().any(|text| text == "Back to preview"));
    // Leaving ends the read and the next answer is dropped.
    inspector.end_async();
    assert!(wanted.cancel.load(Ordering::Relaxed));
    inspector.async_answer(wanted.generation, call, Ok(page(356, None)));
    assert!(inspector.find_async(&row, 400).is_none());
    // A different call is not browsed with the first one's pages.
    inspector.begin_async(call);
    let other = InvocationSummary {
        call_id: 99,
        ..row.clone()
    };
    render(&ctx, &mut inspector, &other, Vec::new());
    assert!(inspector.take_async_read().is_none());
    assert!(inspector.find_async(&other, 400).is_none());
}

#[test]
fn failed_and_superseded_reads_are_reported_not_left_waiting() {
    let mut app = app();
    let row = dense_row(300);
    let call = trace::key(&row);
    app.inspector.begin_async(call);
    let wanted = app.inspector.take_async_read().unwrap();
    let cancel = Arc::clone(&wanted.cancel);
    let request = |wanted: &trace::async_browse::AsyncRead| Request::AsyncObservations {
        generation: wanted.generation,
        directory: PathBuf::from("/unused"),
        capture: false,
        call: wanted.call,
        from: wanted.from,
        cancel: Arc::clone(&wanted.cancel),
    };
    app.queue_archive(request(&wanted));
    // A newer request replaces the queued one, which is cancelled.
    app.inspector.begin_async(call);
    let newer = app.inspector.take_async_read().unwrap();
    app.queue_archive(request(&newer));
    assert!(cancel.load(Ordering::Relaxed));
    assert!(matches!(
        &app.pending_archive,
        Some(Request::AsyncObservations { generation, .. }) if *generation == newer.generation
    ));
    // The worker's error answer is shown on the browser.
    app.handle_archive_answer(Answer::AsyncObservations {
        generation: newer.generation,
        call,
        result: Err("raw archive was replaced".into()),
    });
    assert_eq!(
        app.inspector.async_error().as_deref(),
        Some("raw archive was replaced")
    );
    // Selecting something else ends the read.
    app.reset_trace_selection();
    assert!(newer.cancel.load(Ordering::Relaxed));
    assert!(app.inspector.async_error().is_none());
}

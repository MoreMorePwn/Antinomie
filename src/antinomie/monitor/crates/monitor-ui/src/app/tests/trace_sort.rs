// SPDX-License-Identifier: MIT
//! Trace column sorting.
use super::*;

#[test]
fn trace_columns_sort_both_ways_with_stable_ties() {
    let call = |call_id: u64, tid: u32, time: u64, result: Option<i64>| {
        let mut entry = event(1, 0);
        entry.call_id = call_id;
        entry.tid = tid;
        entry.timestamp_ns = time;
        entry.event_seq = call_id * 2;
        let mut exit = entry.clone();
        exit.phase = 2;
        exit.event_seq += 1;
        exit.result = result;
        vec![entry, exit]
    };
    let events: Vec<_> = [
        call(1, 30, 300, Some(5)),
        call(2, 10, 100, Some(-2)),
        call(3, 20, 200, Some(5)),
    ]
    .concat();
    let order = |column, descending| {
        let mut invocations = antinomie_monitor_core::pair_events(&events);
        sort_invocations(&mut invocations, column, descending);
        invocations.iter().map(|i| i.call_id).collect::<Vec<_>>()
    };
    assert_eq!(order(TraceColumn::Time, false), [2, 3, 1]);
    assert_eq!(order(TraceColumn::Time, true), [1, 3, 2]);
    assert_eq!(order(TraceColumn::Tid, false), [2, 3, 1]);
    assert_eq!(order(TraceColumn::Tid, true), [1, 3, 2]);
    // Equal returns keep time order in both directions.
    assert_eq!(order(TraceColumn::Return, false), [2, 3, 1]);
    assert_eq!(order(TraceColumn::Return, true), [3, 1, 2]);
}

#[test]
fn clicking_a_trace_header_sorts_and_shows_the_direction() {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let size = egui::vec2(1280.0, 820.0);
    let mut app = app();
    app.snapshot.events = vec![event(1, 0), event(2, 3)];
    for _ in 0..3 {
        let _ = render(&mut app, &ctx, size);
    }
    let header = |app: &mut MonitorApp| {
        texts(&render(app, &ctx, size))
            .into_iter()
            .find(|(text, _)| text.starts_with("TID"))
            .expect("TID header")
    };
    let (text, rect) = header(&mut app);
    assert_eq!(text, "TID");
    let click = |app: &mut MonitorApp| {
        let pos = rect.center();
        for events in [
            vec![egui::Event::PointerMoved(pos)],
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            }],
            vec![egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
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
    };
    click(&mut app);
    assert_eq!(app.trace_sort, Some((TraceColumn::Tid, false)));
    assert_eq!(
        header(&mut app).0,
        format!("TID{}", egui_phosphor::regular::CARET_UP)
    );
    click(&mut app);
    assert_eq!(app.trace_sort, Some((TraceColumn::Tid, true)));
    assert_eq!(
        header(&mut app).0,
        format!("TID{}", egui_phosphor::regular::CARET_DOWN)
    );
}

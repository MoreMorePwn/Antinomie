// SPDX-License-Identifier: GPL-3.0-only
//! Equal spacing of the time axis, and the overview ruler under it: the map
//! between time and slots, the toggle and where it is remembered, ticks and
//! breaks, phases and the curve on the same axis, and the ruler's hit-testing
//! and dragging.
#![allow(clippy::field_reassign_with_default)]
use super::axis::{Axis, Slots, BREAK_RATIO};
use super::index::{Builder, GraphIndex, Record};
use super::input::{self, Action, Hit, Layout};
use super::lanes::Lanes;
use super::paint::{self, Colors};
use super::ruler::{self, Spot};
use super::tests::{marker_pos, node, record, scene, Harness, SIZE, WIDGET_HEIGHT};
use super::view::{self, Drag, Ruler, State};
use super::widget::{self, Config};
use super::*;
use crate::theme::Theme;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{Event, Key, Modifiers, PointerButton, Pos2, Rect};

const S: u64 = 1_000_000_000;

fn events() -> Harness {
    let mut harness = Harness::new();
    harness.spacing = Spacing::Events;
    harness
}

/// Findings at 1 s, 2 s, then a burst of `burst` in the next millisecond, then one a minute later.
fn bursty(burst: u64) -> GraphIndex {
    let nodes = vec![node(0, 7, 1, "/bin/x", 0, 90 * S)];
    let mut builder = Builder::new(Lanes::from_processes(&nodes)).without_rows();
    builder.push_record(record(S, 1, Tier::Low, Category::Discovery));
    builder.push_record(record(2 * S, 1, Tier::Low, Category::Discovery));
    for n in 0..burst {
        builder.push_record(record(
            3 * S + n * 1_000_000 / burst.max(1),
            1,
            if n % 7 == 0 { Tier::High } else { Tier::Medium },
            Category::Execution,
        ));
    }
    builder.push_record(record(63 * S, 1, Tier::High, Category::Command));
    builder.finish()
}

// ----- the map -----

#[test]
fn every_moment_is_one_slot_and_time_between_two_is_linear() {
    let slots = Slots::new(vec![10, 20, 40, 1_000_000]);
    let axis = Axis::new(Spacing::Events, &slots);
    for (at, ns) in [10.0, 20.0, 40.0, 1_000_000.0].into_iter().enumerate() {
        assert_eq!(axis.to_u(ns), at as f64);
        assert_eq!(axis.to_ns(at as f64), ns);
    }
    assert_eq!(axis.to_u(15.0), 0.5);
    assert_eq!(axis.to_u(30.0), 1.5);
    assert_eq!(axis.to_ns(1.5), 30.0);
    // Round trip at arbitrary points, and the map only goes up.
    let mut last = f64::MIN;
    for ns in (0..1_200_000).step_by(997) {
        let u = axis.to_u(ns as f64);
        assert!(u >= last);
        last = u;
        if (10..=1_000_000).contains(&ns) {
            assert!((axis.to_ns(u) - ns as f64).abs() < 1e-6, "{ns}");
        }
    }
    // Before the first and after the last it goes on at the typical slot width.
    assert!(axis.to_u(0.0) < 0.0 && axis.to_u(2_000_000.0) > 3.0);
    assert_eq!(axis.to_ns(axis.to_u(5.0)), 5.0);
    // The Time spacing is the identity.
    let plain = Axis::new(Spacing::Time, &slots);
    assert_eq!((plain.to_u(123.0), plain.to_ns(456.0)), (123.0, 456.0));
    // With no findings Events falls back to the plain scale.
    let none = Axis::new(Spacing::Events, &Slots::default());
    assert_eq!(none.to_u(9.0), 9.0);
}

#[test]
fn a_window_moves_between_spacings_and_back() {
    let index = bursty(40);
    let events = Axis::new(Spacing::Events, &index.slots);
    let time = Axis::new(Spacing::Time, &index.slots);
    let window_ns = (2.5 * S as f64, 3.0005 * S as f64);
    let in_events = events.convert_from(Spacing::Time, window_ns);
    assert!(
        in_events.0 > 1.0 && in_events.1 < 43.0 && in_events.1 > in_events.0,
        "{in_events:?}"
    );
    let back = time.convert_from(Spacing::Events, in_events);
    assert!((back.0 - window_ns.0).abs() < 1.0 && (back.1 - window_ns.1).abs() < 1.0);
    assert_eq!(events.convert_from(Spacing::Events, in_events), in_events);
}

#[test]
fn a_gap_many_times_the_usual_one_is_a_break() {
    let index = bursty(20);
    let breaks = &index.slots.breaks;
    // Between 2 s and the burst, and between the burst and 63 s.
    assert!(breaks.len() >= 2, "{breaks:?}");
    let last = breaks.last().unwrap();
    assert!(last.1 as f64 >= index.slots.unit * BREAK_RATIO);
    assert!(last.1 > 50 * S);
    // An even run has none.
    let times: Vec<u64> = (1..=50).map(|n| n * S).collect();
    assert!(Slots::new(times).breaks.is_empty());
    // And no more than a few dozen are kept: the widest.
    let mut times = Vec::new();
    let mut at = 0u64;
    for n in 0..400u64 {
        at += if n % 2 == 0 { 1 } else { 1_000 + n };
        times.push(at);
    }
    assert!(Slots::new(times).breaks.len() <= super::axis::MAX_BREAKS);
    assert_eq!(paint::gap_text(2_500_000_000), "2.5 s");
    assert_eq!(paint::gap_text(90 * S), "1.5 min");
    assert_eq!(paint::gap_text(40_000), "40 µs");
}

// ----- the widget in Events spacing -----

#[test]
fn findings_sit_in_equal_slots_in_events_spacing_and_by_time_in_time_spacing() {
    let index = bursty(40);
    let n = index.records.len();
    let mut state = State::default();
    state.units = Spacing::Events;
    let layout = Layout::new(
        Rect::from_min_size(Pos2::new(8.0, 8.0), egui::vec2(1084.0, WIDGET_HEIGHT)),
        &state,
        &index,
    );
    let xs: Vec<f32> = index
        .records
        .iter()
        .map(|r| layout.frame.x_rec(r))
        .collect();
    let step = xs[1] - xs[0];
    assert!(step > 5.0);
    for pair in xs.windows(2) {
        assert!(((pair[1] - pair[0]) - step).abs() < 0.01, "{pair:?}");
    }
    // The whole run is in view: the first and last findings are inside the plot.
    assert!(xs[0] > layout.frame.plot.left() && xs[n - 1] < layout.frame.plot.right());
    // In Time spacing the burst of 40 is a sliver and the first two are far from it.
    let time = Layout::new(
        Rect::from_min_size(Pos2::new(8.0, 8.0), egui::vec2(1084.0, WIDGET_HEIGHT)),
        &State::default(),
        &index,
    );
    let burst = time.frame.x_rec(&index.records[41]) - time.frame.x_rec(&index.records[2]);
    assert!(burst < 2.0, "{burst}");
}

#[test]
fn a_marker_is_hit_at_its_slot_in_events_spacing() {
    let index = scene();
    let mut harness = events();
    harness.frame(&index, vec![]);
    let layout = harness.layout(&index);
    assert_eq!(layout.frame.map.spacing, Spacing::Events);
    for at in 0..index.records.len() {
        let pos = marker_pos(&layout, &index, at);
        assert!(
            matches!(
                input::hit_test(&layout, &index, 10.0, pos),
                Some(Hit::Marker { record, .. }) if record == at
            ),
            "record {at}"
        );
    }
    // A click on one selects it, as in Time spacing.
    let pos = marker_pos(&layout, &index, 3);
    assert_eq!(
        harness.click(&index, pos),
        [Action::Select {
            record: 3,
            focus: true
        }]
    );
}

#[test]
fn the_spacing_chips_and_t_ask_for_the_other_spacing_and_the_window_follows() {
    let index = bursty(40);
    let mut harness = Harness::new();
    harness.frame(&index, vec![]);
    // A zoom in Time spacing...
    let zoomed = (2.9 * S as f64, 3.002 * S as f64);
    harness.state.window = Some(zoomed);
    let layout = harness.layout(&index);
    // ...the Events chip is clicked: the widget asks for it.
    let chip = layout.spacing[0].center();
    assert_eq!(
        harness.click(&index, chip),
        [Action::Spacing(Spacing::Events)]
    );
    let time_chip = layout.spacing[1].center();
    assert_eq!(
        harness.click(&index, time_chip),
        [Action::Spacing(Spacing::Time)]
    );
    // Told to use Events, it re-expresses the window in slots, over the same stretch.
    harness.spacing = Spacing::Events;
    harness.frame(&index, vec![]);
    assert_eq!(harness.state.units, Spacing::Events);
    let slots = harness.state.window.unwrap();
    assert!(slots.0 > 1.0 && slots.1 < 43.0, "{slots:?}");
    let axis = Axis::new(Spacing::Events, &index.slots);
    assert!((axis.to_ns(slots.0) - zoomed.0).abs() < 1.0);
    // And back.
    harness.spacing = Spacing::Time;
    harness.frame(&index, vec![]);
    let window = harness.state.window.unwrap();
    assert!((window.0 - zoomed.0).abs() < 1.0 && (window.1 - zoomed.1).abs() < 1.0);
    // T asks for the other one.
    harness.state.window = None;
    harness.focus_on(&index, 0);
    assert_eq!(
        harness.key(&index, Key::T),
        [Action::Spacing(Spacing::Events)]
    );
    harness.spacing = Spacing::Events;
    harness.frame(&index, vec![]);
    assert_eq!(
        harness.key(&index, Key::T),
        [Action::Spacing(Spacing::Time)]
    );
}

#[test]
fn zoom_pan_and_the_keyboard_work_in_slots() {
    let index = bursty(40);
    let mut harness = events();
    harness.focus_on(&index, 10);
    let layout = harness.layout(&index);
    let range = layout.range;
    let wide = layout.frame.t1 - layout.frame.t0;
    harness.key(&index, Key::Plus);
    let window = harness.state.window.expect("zoomed in");
    assert!((window.1 - window.0) < wide * 0.6);
    let at = f64::from(index.records[10].slot);
    assert!(
        window.0 <= at && at <= window.1,
        "the selection stays in view"
    );
    // Zooming in never goes below a slot and a half.
    for _ in 0..12 {
        harness.key(&index, Key::Plus);
    }
    let tight = harness.state.window.unwrap();
    assert!((tight.1 - tight.0 - 1.5).abs() < 1e-6, "{tight:?}");
    // Panning stays inside the run.
    harness.state.window = Some(view::panned(tight, -1e9, range));
    assert!(harness.state.window.unwrap().0 >= range.0 - 1e-9);
    // F fits the findings, R the whole run: in Events they are the same.
    harness.key(&index, Key::F);
    assert_eq!(harness.state.window, None);
    harness.key(&index, Key::R);
    assert_eq!(harness.state.window, Some(range));
    // → steps one finding, whatever the gap in time.
    harness.state.window = None;
    harness.key(&index, Key::End);
    assert_eq!(harness.state.selected, Some(index.records.len() - 1));
    harness.key(&index, Key::ArrowLeft);
    assert_eq!(harness.state.selected, Some(index.records.len() - 2));
}

#[test]
fn the_ticks_are_real_times_at_slot_boundaries_and_the_curve_and_phases_follow() {
    let index = bursty(200);
    let mut state = State::default();
    state.units = Spacing::Events;
    let layout = Layout::new(
        Rect::from_min_size(Pos2::new(8.0, 8.0), egui::vec2(1084.0, WIDGET_HEIGHT)),
        &state,
        &index,
    );
    let ticks = paint::tick_marks(&layout.frame);
    assert!(ticks.len() >= 3, "{ticks:?}");
    let times = &index.slots.times;
    for (x, ns) in &ticks {
        assert!(
            times.iter().any(|time| *time as f64 == *ns),
            "{ns} is a slot's time"
        );
        assert!(*x >= layout.frame.plot.left() && *x <= layout.frame.plot.right());
    }
    // Equal slots, so the ticks are evenly spread though the times are not.
    let gaps: Vec<f32> = ticks.windows(2).map(|pair| pair[1].0 - pair[0].0).collect();
    assert!(
        gaps.iter().all(|gap| (gap - gaps[0]).abs() < 0.5),
        "{gaps:?}"
    );
    let spans: Vec<f64> = ticks.windows(2).map(|pair| pair[1].1 - pair[0].1).collect();
    assert!(spans.iter().any(|gap| *gap > 1e9) && spans.iter().any(|gap| *gap < 1e6));
    // The curve counts the findings of the window into columns of the same axis.
    let ctx = egui::Context::default();
    let series = paint::series(&layout.frame, &index, None).expect("a series");
    let counted: u32 = series
        .bins
        .iter()
        .map(|bin| bin.tiers.iter().sum::<u32>())
        .sum();
    assert_eq!(counted as usize, index.records.len());
    let busy = series
        .bins
        .iter()
        .filter(|bin| bin.tiers.iter().sum::<u32>() > 0)
        .count();
    // 204 findings over about 360 columns: the burst of 200 is not squeezed into one.
    assert!(busy > 100, "{busy} columns have findings");
    drop(ctx);
    // A phase sits where its findings are, on the same axis.
    let span = index.phases.first().expect("a phase");
    let geometry = index.geometry();
    let start = layout.frame.x(geometry.start(0, span.first as usize));
    let slot_of_start = layout
        .frame
        .map
        .to_u(geometry.start(0, span.first as usize));
    assert!((layout.frame.x_u(slot_of_start) - start).abs() < 1e-3);
}

// ----- the overview ruler -----

fn ruler_rect() -> Rect {
    Rect::from_min_size(Pos2::new(100.0, 400.0), egui::vec2(800.0, 30.0))
}

#[test]
fn the_ruler_tells_the_edges_the_window_and_the_empty_part_apart() {
    let (rect, range, window) = (ruler_rect(), (0.0, 100.0), (20.0, 40.0));
    // 20..40 of 100 over 800 px is x 260..420.
    assert_eq!(ruler::x_of(rect, range, 20.0), 260.0);
    assert_eq!(ruler::spot(rect, range, window, 260.0), Spot::LeftEdge);
    assert_eq!(ruler::spot(rect, range, window, 263.0), Spot::LeftEdge);
    assert_eq!(ruler::spot(rect, range, window, 420.0), Spot::RightEdge);
    assert_eq!(ruler::spot(rect, range, window, 340.0), Spot::Window);
    assert_eq!(ruler::spot(rect, range, window, 150.0), Spot::Empty);
    assert_eq!(ruler::spot(rect, range, window, 700.0), Spot::Empty);
    // A window too narrow for two edges is all window.
    assert_eq!(ruler::spot(rect, range, (50.0, 50.5), 500.0), Spot::Window);
    assert_eq!(ruler::u_of(rect, range, 100.0), 0.0);
    assert_eq!(ruler::u_of(rect, range, 500.0), 50.0);
    assert_eq!(
        ruler::u_of(rect, range, 5000.0),
        100.0,
        "clamped to the run"
    );
}

#[test]
fn dragging_the_ruler_moves_resizes_and_selects() {
    let (rect, range, window) = (ruler_rect(), (0.0, 100.0), (20.0, 40.0));
    let mut state = State::default();
    // Take hold inside and move: the width stays and the run's ends hold.
    state.drag = Some(Drag::Ruler(ruler::begin(rect, range, window, 340.0)));
    let moved = ruler::drag(&mut state, rect, range, window, 540.0, 1.0).unwrap();
    assert!((moved.1 - moved.0 - 20.0).abs() < 1e-9);
    assert!((moved.0 - 45.0).abs() < 1e-9, "{moved:?}");
    let edge = ruler::drag(&mut state, rect, range, window, 5000.0, 1.0).unwrap();
    assert_eq!(edge, (80.0, 100.0));
    // The left edge pulled left widens it; pulled past the right edge it keeps the minimum.
    state.drag = Some(Drag::Ruler(ruler::begin(rect, range, window, 260.0)));
    let widened = ruler::drag(&mut state, rect, range, window, 180.0, 1.0).unwrap();
    assert!(
        (widened.0 - 10.0).abs() < 1e-4 && widened.1 == 40.0,
        "{widened:?}"
    );
    let crossed = ruler::drag(&mut state, rect, range, window, 700.0, 1.5).unwrap();
    assert_eq!(crossed, (38.5, 40.0));
    // The right edge likewise.
    state.drag = Some(Drag::Ruler(ruler::begin(rect, range, window, 420.0)));
    let widened = ruler::drag(&mut state, rect, range, window, 580.0, 1.0).unwrap();
    assert!(
        (widened.1 - 60.0).abs() < 1e-4 && widened.0 == 20.0,
        "{widened:?}"
    );
    assert_eq!(
        ruler::drag(&mut state, rect, range, window, 0.0, 1.5),
        Some((20.0, 21.5))
    );
    // On an empty part a drag selects: it changes nothing until it ends.
    state.drag = Some(Drag::Ruler(ruler::begin(rect, range, window, 500.0)));
    assert!(ruler::drag(&mut state, rect, range, window, 700.0, 1.0).is_none());
    let Some(Drag::Ruler(Ruler::Select { start, now })) = state.drag else {
        panic!("selecting");
    };
    assert_eq!((start, now), (50.0, 75.0));
    assert_eq!(
        ruler::selected(rect, range, window, (start, now), 1.0),
        (50.0, 75.0)
    );
    // Dragged backwards it is the same stretch.
    assert_eq!(
        ruler::selected(rect, range, window, (75.0, 50.0), 1.0),
        (50.0, 75.0)
    );
    // A click without a drag centres the window there.
    let centred = ruler::selected(rect, range, window, (60.0, 60.2), 1.0);
    assert!((centred.0 - 50.0).abs() < 1e-9 && (centred.1 - 70.0).abs() < 1e-9);
}

#[test]
fn the_ruler_shows_every_finding_and_is_made_again_only_when_something_changes() {
    let index = bursty(300);
    let events = Axis::new(Spacing::Events, &index.slots);
    let marks = ruler::Marks::build(&index, &events, events.run(index.run_extent()), 600);
    let total: u32 = marks.columns.iter().map(|column| column.0).sum();
    assert_eq!(
        total as usize,
        index.records.len(),
        "every finding is on it"
    );
    // Equal slots: the burst of 300 takes most of the ruler, as it does the graph.
    let filled = marks.columns.iter().filter(|column| column.0 > 0).count();
    assert!(filled > 300, "{filled} of 600 columns");
    // The worst tier of a column is kept.
    assert!(marks
        .columns
        .iter()
        .any(|column| column.1 == Tier::High.index() as u8));
    // The same run by time puts the burst in a sliver.
    let time = Axis::new(Spacing::Time, &index.slots);
    let by_time = ruler::Marks::build(&index, &time, time.run(index.run_extent()), 600);
    let filled_time = by_time.columns.iter().filter(|column| column.0 > 0).count();
    assert!(filled_time < 20, "{filled_time}");
    assert!(marks.is_for(&index, &events, 600));
    assert!(!marks.is_for(&index, &events, 601));
    assert!(!marks.is_for(&index, &time, 600));
    assert!(
        !marks.is_for(&bursty(300), &events, 600),
        "another index is another set of marks"
    );
}

#[test]
fn the_ruler_drags_the_graph_in_both_spacings_through_real_events() {
    for spacing in [Spacing::Events, Spacing::Time] {
        let index = bursty(60);
        let mut harness = Harness::new();
        harness.spacing = spacing;
        harness.frame(&index, vec![]);
        let layout = harness.layout(&index);
        let rect = layout.frame.ruler;
        let range = layout.range;
        // Zoom in first, so the window is a part of the ruler.
        let width = range.1 - range.0;
        let window = (range.0 + width * 0.3, range.0 + width * 0.5);
        harness.state.window = Some(window);
        harness.frame(&index, vec![]);
        let inside = Pos2::new(
            ruler::x_of(rect, range, (window.0 + window.1) / 2.0),
            rect.center().y,
        );
        // Drag the window to the right.
        harness.press(&index, inside, true);
        harness.frame(
            &index,
            vec![Event::PointerMoved(inside + egui::vec2(40.0, 0.0))],
        );
        harness.frame(
            &index,
            vec![Event::PointerMoved(inside + egui::vec2(120.0, 0.0))],
        );
        harness.press(&index, inside + egui::vec2(120.0, 0.0), false);
        let moved = harness.state.window.unwrap();
        assert!(
            (moved.1 - moved.0 - (window.1 - window.0)).abs() < 1e-6,
            "{spacing:?}: it only moved"
        );
        assert!(
            moved.0 > window.0 + width * 0.1,
            "{spacing:?}: panned right {moved:?}"
        );
        assert!(harness.state.drag.is_none());
        // Drag its right edge out: zoomed out.
        harness.time += 2.0;
        let (left, right) = (moved.0, moved.1);
        let edge = Pos2::new(ruler::x_of(rect, range, right), rect.center().y);
        harness.press(&index, edge, true);
        harness.frame(
            &index,
            vec![Event::PointerMoved(edge + egui::vec2(30.0, 0.0))],
        );
        harness.frame(
            &index,
            vec![Event::PointerMoved(edge + egui::vec2(90.0, 0.0))],
        );
        harness.press(&index, edge + egui::vec2(90.0, 0.0), false);
        let wider = harness.state.window.unwrap();
        assert!(
            (wider.0 - left).abs() < 1e-6 && wider.1 > right,
            "{spacing:?}: {wider:?}"
        );
        // Select a new range on the empty left part.
        harness.time += 2.0;
        let (from, to) = (
            Pos2::new(
                ruler::x_of(rect, range, range.0 + width * 0.05),
                rect.center().y,
            ),
            Pos2::new(
                ruler::x_of(rect, range, range.0 + width * 0.15),
                rect.center().y,
            ),
        );
        harness.press(&index, from, true);
        harness.frame(
            &index,
            vec![Event::PointerMoved(from + egui::vec2(20.0, 0.0))],
        );
        harness.frame(&index, vec![Event::PointerMoved(to)]);
        harness.press(&index, to, false);
        let chosen = harness.state.window.unwrap();
        assert!(
            (chosen.0 - (range.0 + width * 0.05)).abs() < width * 0.01
                && (chosen.1 - (range.0 + width * 0.15)).abs() < width * 0.01,
            "{spacing:?}: {chosen:?}"
        );
        // A double-click anywhere on it shows the whole run.
        harness.time += 2.0;
        for pressed in [true, false, true, false] {
            harness.press(&index, from, pressed);
        }
        assert_eq!(harness.state.window, Some(range), "{spacing:?}");
    }
}

#[test]
fn the_ruler_shows_the_brush_and_follows_the_filter() {
    let index = bursty(40);
    let mut harness = events();
    harness.frame(&index, vec![]);
    let layout = harness.layout(&index);
    let selection = Colors::of(Theme::Dark.palette()).selection;
    let painted = |harness: &mut Harness| -> bool {
        let mut found = false;
        let output = harness.ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, SIZE)),
                time: Some(harness.time + 0.5),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let config = Config {
                        index: &index,
                        colors: Colors::of(Theme::Dark.palette()),
                        clock: None,
                        height: WIDGET_HEIGHT,
                        spacing: Spacing::Events,
                    };
                    widget::show(ui, &mut harness.state, &config);
                });
            },
        );
        fn walk(shape: &egui::Shape, ruler: Rect, selection: egui::Color32, found: &mut bool) {
            match shape {
                egui::Shape::Rect(rect)
                    if rect.fill == selection && ruler.intersects(rect.rect) =>
                {
                    *found = true
                }
                egui::Shape::Vec(shapes) => shapes
                    .iter()
                    .for_each(|shape| walk(shape, ruler, selection, found)),
                _ => {}
            }
        }
        output
            .shapes
            .iter()
            .for_each(|clipped| walk(&clipped.shape, layout.frame.ruler, selection, &mut found));
        found
    };
    assert!(!painted(&mut harness), "no brush, none on the ruler");
    // The graph's brush (what the filter holds) is on the ruler, in the same spacing.
    harness.state.brush = Some((3 * S, 3 * S + 500_000));
    assert!(painted(&mut harness));
    harness.state.brush = None;
    assert!(!painted(&mut harness), "cleared with the filter");
}

// ----- the budget -----

#[test]
fn a_graph_in_events_spacing_with_120k_findings_paints_within_the_budget_and_idles() {
    use std::time::Duration;
    let index = super::bench::synthetic(120_000, 2_000);
    let ctx = egui::Context::default();
    theme::install(&ctx);
    let mut state = State::default();
    let frame = |state: &mut State| {
        let mut delay = Duration::MAX;
        let took = super::bench::timed(|| {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 800.0))),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        let config = Config {
                            index: &index,
                            colors: Colors::of(Theme::Dark.palette()),
                            clock: None,
                            height: 760.0,
                            spacing: Spacing::Events,
                        };
                        widget::show(ui, state, &config);
                    });
                },
            );
            let meshes = ctx.tessellate(output.shapes, output.pixels_per_point);
            std::hint::black_box(meshes.len());
            delay = output
                .viewport_output
                .values()
                .map(|viewport| viewport.repaint_delay)
                .min()
                .unwrap_or(Duration::MAX);
        });
        (took, delay)
    };
    frame(&mut state);
    let slots = index.slots.times.len() as f64;
    let mut slowest = Duration::ZERO;
    // Whole run, a tenth, a thousandth: the ruler and the markers are drawn each time.
    for window in [
        None,
        Some((slots * 0.4, slots * 0.5)),
        Some((slots * 0.4, slots * 0.401)),
    ] {
        state.window = window;
        // The fastest of many frames, in this thread's CPU time: other tests
        // or programs using the cores only ever make a frame slower, so this
        // is what the paint costs.
        let best = (0..80)
            .map(|_| frame(&mut state).0)
            .min()
            .unwrap_or_default();
        eprintln!("graph paint, events spacing, 120k findings, {window:?}: {best:?}");
        slowest = slowest.max(best);
    }
    if !cfg!(debug_assertions) {
        assert!(
            slowest <= Duration::from_millis(4),
            "the slowest view took {slowest:?}; the budget is 4 ms"
        );
    }
    // Settled, nothing asks for a repaint.
    for _ in 0..4 {
        frame(&mut state);
    }
    assert!(
        frame(&mut state).1 >= Duration::from_secs(1),
        "an idle graph asked to repaint"
    );
    let _ = (
        Record {
            slot: 0,
            ..record(1, 0, Tier::Low, Category::Discovery)
        },
        PointerButton::Primary,
        Modifiers::NONE,
    );
}

#[test]
fn the_choice_of_spacing_reaches_the_view_the_settings_and_every_graph() {
    use super::sync_tests::{recording, view_with};
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = egui::Context::default();
    assert_eq!(
        view.graph_spacing,
        Spacing::Events,
        "equal slots by default"
    );
    assert_eq!(view.take_graph_spacing(), None);
    // The settings give the view its spacing.
    view.set_graph_spacing(Spacing::Time);
    assert_eq!(view.graph_spacing, Spacing::Time);
    // The chip or the key asks for another: the view uses it and hands it to the settings once.
    view.apply_graph_actions(&ctx, vec![Action::Spacing(Spacing::Events)]);
    assert_eq!(view.graph_spacing, Spacing::Events);
    assert_eq!(view.take_graph_spacing(), Some(Spacing::Events));
    assert_eq!(view.take_graph_spacing(), None);
}

// SPDX-License-Identifier: GPL-3.0-only
//! The graph window and the roomier layout: one window per run that opens,
//! closes and remembers its size; the window and the table staying in step;
//! lanes that scale to the space and a pane that scrolls instead of squeezing.
use super::filter::Parts;
use super::index::Builder;
use super::input::{Action, Layout};
use super::paint::Colors;
use super::sync_tests::{draw, recording, request, scan_with, view_with};
use super::tests::{node, record, scene, scene_nodes};
use super::view::{self, Metrics, State, LANE_MAX, LANE_MIN};
use super::window::window_id;
use super::*;
use crate::app::tests::texts;
use crate::theme::Theme;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{Pos2, Rect};

fn identified(view: &mut TriageView, run: &str) {
    view.scan_request.identity = Some(("vm".into(), "boot".into(), run.into()));
}

fn pass(
    ctx: &egui::Context,
    view: &mut TriageView,
    viewport: Option<egui::ViewportInfo>,
) -> egui::FullOutput {
    let mut raw = egui::RawInput {
        screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1400.0, 900.0))),
        ..Default::default()
    };
    if let Some(info) = viewport {
        raw.viewports.insert(window_id("run-a"), info);
    }
    ctx.run(raw, |ctx| view.show_finding_windows(ctx))
}

fn context() -> egui::Context {
    let ctx = egui::Context::default();
    theme::install(&ctx);
    ctx
}

#[test]
fn the_window_opens_once_per_run_draws_every_frame_and_closes() {
    let spool = recording();
    let mut view = view_with(&spool);
    identified(&mut view, "run-a");
    let ctx = context();
    pass(&ctx, &mut view, None);
    assert_eq!(view.graph_window.drawn, 0, "closed until asked for");
    view.open_graph_window(&ctx);
    // Asking again while it is open is the same window, not another.
    view.open_graph_window(&ctx);
    view.open_graph_window(&ctx);
    assert!(view.graph_window.open);
    for frame in 1..=3 {
        pass(&ctx, &mut view, None);
        assert_eq!(
            view.graph_window.drawn, frame,
            "one viewport, drawn once a frame"
        );
    }
    view.graph_window.close();
    pass(&ctx, &mut view, None);
    assert_eq!(view.graph_window.drawn, 3);
    // It can be opened again.
    view.open_graph_window(&ctx);
    pass(&ctx, &mut view, None);
    assert_eq!(view.graph_window.drawn, 4);
}

#[test]
fn the_window_belongs_to_its_run_and_closes_when_another_is_selected() {
    let spool = recording();
    let mut view = view_with(&spool);
    identified(&mut view, "run-a");
    let ctx = context();
    view.open_graph_window(&ctx);
    pass(&ctx, &mut view, None);
    assert!(view.graph_window.open);
    identified(&mut view, "run-b");
    pass(&ctx, &mut view, None);
    assert!(
        !view.graph_window.open,
        "another run's window is not this run's"
    );
    // Its viewport is named by the run, so two runs never share one.
    assert_ne!(window_id("run-a"), window_id("run-b"));
    assert_eq!(window_id("run-a"), window_id("run-a"));
    // Without a run there is nothing to open.
    let mut empty = TriageView::default();
    empty.open_graph_window(&ctx);
    assert!(!empty.graph_window.open);
}

#[test]
fn the_window_remembers_its_size_for_the_run_and_for_the_next_one() {
    let spool = recording();
    let mut view = view_with(&spool);
    identified(&mut view, "run-a");
    let ctx = context();
    view.open_graph_window(&ctx);
    // Embedded in the main window it has no size of its own to report.
    pass(&ctx, &mut view, None);
    assert_eq!(view.take_graph_window_size(), None);
    assert_eq!(view.graph_window.opened_at(), window::DEFAULT_SIZE);
    // The app hands the saved size to a view that has not opened one yet.
    let mut fresh = view_with(&spool);
    identified(&mut fresh, "run-a");
    fresh.set_graph_window_size([1000.0, 640.0]);
    fresh.open_graph_window(&ctx);
    assert_eq!(fresh.graph_window.opened_at(), [1000.0, 640.0]);
    // A size below the minimum is ignored.
    fresh.set_graph_window_size([100.0, 100.0]);
    fresh.graph_window.close();
    fresh.open_graph_window(&ctx);
    assert_eq!(fresh.graph_window.opened_at(), [1000.0, 640.0]);
}

#[test]
fn the_window_follows_the_tables_selection_and_filter() {
    let spool = recording();
    let mut view = view_with(&spool);
    identified(&mut view, "run-a");
    let ctx = context();
    view.open_graph_window(&ctx);
    pass(&ctx, &mut view, None);
    let keys: Vec<_> = view
        .scan
        .as_ref()
        .unwrap()
        .graph
        .index
        .rows
        .iter()
        .map(|row| row.key)
        .collect();
    assert!(keys.len() >= 2);
    // A row picked in the table is the window's selection...
    view.selected_call_id = Some(keys[1]);
    pass(&ctx, &mut view, None);
    let at = view
        .graph_window
        .state
        .selected
        .expect("a record is selected");
    assert_eq!(
        view.scan.as_ref().unwrap().graph.index.rows[at].key,
        keys[1]
    );
    // ...and the embedded graph's state is separate from the window's.
    assert_eq!(view.graph.selected, None);
    // A brushed filter is the window's brush.
    let brushed = Parts {
        brush: Some((5, 50)),
        ..Parts::default()
    }
    .render();
    // The filter bar takes an outside change from here, as a click on a lane does.
    ctx.data_mut(|data| data.insert_temp(egui::Id::new(("triage-filter-draft", 0usize)), brushed));
    pass(&ctx, &mut view, None);
    assert_eq!(view.graph_window.state.brush, Some((5, 50)));
    // What the window selects is the table's selection and Details.
    view.apply_graph_actions(
        &ctx,
        vec![Action::Select {
            record: 0,
            focus: false,
        }],
    );
    assert_eq!(view.selected_call_id, Some(keys[0]));
    assert_eq!(view.table_focus, Some(keys[0]));
    // The window shows the same filter bar as the table: the same draft.
    let out = pass(&ctx, &mut view, None);
    assert!(texts(&out)
        .iter()
        .any(|(text, _)| text == "Details beside the graph"));
    assert_eq!(
        view.filter_drafts[0],
        Parts {
            brush: Some((5, 50)),
            ..Parts::default()
        }
        .render()
    );
}

#[test]
fn a_click_beside_details_does_not_bring_the_details_panel_forward() {
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = context();
    for (round, (beside, expected)) in [(true, false), (false, true)].into_iter().enumerate() {
        ctx.data_mut(|data| data.remove::<bool>(egui::Id::new("triage-details-focus")));
        let mut state = State::default();
        let origin = std::cell::Cell::new(Pos2::ZERO);
        let frame = |view: &mut TriageView,
                     state: &mut State,
                     events: Vec<egui::Event>,
                     time: f64| {
            ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1200.0, 800.0))),
                    events,
                    time: Some(time),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        origin.set(ui.available_rect_before_wrap().min);
                        let width = ui.available_width();
                        let _ = width;
                        view.draw_graph(ui, state, beside, 600.0);
                    });
                },
            )
        };
        frame(&mut view, &mut state, vec![], 10.0 * round as f64);
        let scan = view.scan.as_ref().unwrap();
        let rect = Rect::from_min_size(origin.get(), egui::vec2(1200.0 - 16.0, 600.0));
        let layout = Layout::new(rect, &state, &scan.graph.index);
        let record = &scan.graph.index.records[0];
        let at = Pos2::new(
            layout.frame.x(record.first_ns as f64),
            layout.row_center(layout.row_of(record.lane).unwrap()),
        );
        for (n, pressed) in [true, false].into_iter().enumerate() {
            frame(
                &mut view,
                &mut state,
                vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::PointerButton {
                        pos: at,
                        button: egui::PointerButton::Primary,
                        pressed,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
                10.0 * (round + 1) as f64 + n as f64 * 0.03,
            );
        }
        assert!(
            view.selected_call_id.is_some(),
            "the click selected a finding"
        );
        let focused = ctx
            .data(|data| data.get_temp::<bool>(egui::Id::new("triage-details-focus")))
            .unwrap_or(false);
        assert_eq!(focused, expected, "details beside: {beside}");
        view.selected_call_id = None;
    }
}

// ----- the roomier layout -----

fn rect(width: f32, height: f32) -> Rect {
    Rect::from_min_size(Pos2::new(8.0, 8.0), egui::vec2(width, height))
}

#[test]
fn a_few_lanes_grow_to_fill_the_room_and_many_lanes_keep_a_readable_row() {
    let few = Metrics::roomy(rect(1200.0, 640.0), 6, 4);
    assert!(
        few.lane_h > 40.0 && few.lane_h <= LANE_MAX,
        "{}",
        few.lane_h
    );
    let one = Metrics::roomy(rect(1200.0, 640.0), 6, 1);
    assert_eq!(
        one.lane_h, LANE_MAX,
        "a single lane is as tall as a lane gets"
    );
    assert!(
        one.curve_h > 64.0,
        "what the lanes cannot use goes to the curve"
    );
    let many = Metrics::roomy(rect(1200.0, 640.0), 6, 400);
    assert_eq!(many.lane_h, LANE_MIN);
    assert_eq!(many.curve_h, 64.0);
    assert!(many.glyph() < few.glyph(), "markers grow with their row");
    // The rows of a middling run use the area without overflowing it.
    let fits = Metrics::roomy(rect(1200.0, 700.0), 4, 12);
    let used = 12.0 * fits.lane_h;
    let area =
        700.0 - (fits.phase_h + fits.curve_h + fits.heat_h * 4.0 + fits.axis_h + 4.0 * view::GAP);
    assert!(used <= area + 1.0 && used >= area * 0.7, "{used} of {area}");
    // The label column scales with the width, within bounds.
    assert_eq!(Metrics::roomy(rect(600.0, 640.0), 0, 3).label_w, 190.0);
    assert_eq!(Metrics::roomy(rect(2400.0, 640.0), 0, 3).label_w, 260.0);
}

#[test]
fn the_layout_of_a_small_run_fills_the_widget_and_a_big_one_scrolls() {
    let index = scene();
    let layout = Layout::new(rect(1100.0, 640.0), &State::default(), &index);
    let lanes = layout.rows.lanes.len() as f32;
    assert!(
        layout.frame.m.lane_h > LANE_MIN,
        "four lanes in 640 px are not thin"
    );
    assert!(lanes * layout.frame.m.lane_h <= layout.frame.lanes.height() + 0.5);
    assert!(
        layout.frame.heat.height() >= layout.frame.m.heat_h * layout.categories.len() as f32 - 0.5
    );
    // Rows are where the metrics say they are: a hit on a row's middle is that row.
    for row in 0..layout.rows.lanes.len() {
        let middle = layout.row_center(row);
        assert_eq!(
            layout
                .frame
                .row_at(middle, layout.scroll, layout.rows.lanes.len()),
            Some(row)
        );
    }
    let mut nodes = scene_nodes();
    for n in 0..300u32 {
        nodes.push(node(
            1,
            5000 + n,
            5000 + u64::from(n),
            &format!("/bin/t{n}"),
            1_000_000_000,
            2_000_000_000,
        ));
    }
    let mut builder = Builder::new(Lanes::from_processes(&nodes)).without_rows();
    builder.push_record(record(1_500_000_000, 6, Tier::High, Category::Execution));
    let big = builder.finish();
    let layout = Layout::new(rect(1100.0, 640.0), &State::default(), &big);
    assert_eq!(layout.frame.m.lane_h, LANE_MIN);
    assert!(layout.rows.lanes.len() as f32 * LANE_MIN > layout.frame.lanes.height());
}

#[test]
fn every_label_fits_in_its_column_at_the_roomy_sizes() {
    let ctx = context();
    ctx.set_pixels_per_point(1.0);
    let index = scene();
    let mut state = State::default();
    let output = ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 800.0))),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let config = widget::Config {
                    index: &index,
                    colors: Colors::of(Theme::Dark.palette()),
                    clock: None,
                    height: 720.0,
                };
                widget::show(ui, &mut state, &config);
            });
        },
    );
    let shown = texts(&output);
    let labels_right = 8.0 + Metrics::roomy(rect(1264.0, 720.0), 5, 4).label_w;
    for name in [
        "phases",
        "severity",
        "dropper 1201",
        "sh 1202",
        "curl 1203",
        ".x 1204",
        "Execution",
        "Persistence",
        "Evasion",
        "Injection",
        "C2",
    ] {
        // "C2" is also a phase, drawn in the plot; one of them is in the column.
        assert!(
            shown
                .iter()
                .any(|(text, rect)| text == name && rect.right() <= labels_right),
            "{name} is not drawn inside the label column: {shown:?}"
        );
    }
}

#[test]
fn a_pane_shorter_than_the_graph_needs_scrolls_it_and_keeps_every_band() {
    let spool = recording();
    let mut view = view_with(&spool);
    let ctx = context();
    for height in [900.0f32, 340.0] {
        draw_at(&ctx, &mut view, height, 0.0);
        let out = draw_at(&ctx, &mut view, height, 0.05);
        let shown = texts(&out);
        let has = |text: &str| shown.iter().any(|(shown, _)| shown.contains(text));
        assert!(has("Open in window"), "{height}: the pop-out button");
        assert!(
            has("phases") && has("severity"),
            "{height}: the bands are drawn, not squeezed out"
        );
    }
}

fn draw_at(ctx: &egui::Context, view: &mut TriageView, height: f32, time: f64) -> egui::FullOutput {
    let input = TriageInput {
        vm_id: Some("vm"),
        boot_id: Some("boot"),
        run_id: Some("run"),
        ..TriageInput::empty()
    };
    ctx.run(
        egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, height))),
            time: Some(time),
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                view.show(ui, input);
            });
        },
    )
}

#[test]
fn the_pop_out_button_and_the_strip_icon_open_the_window() {
    let spool = recording();
    let mut view = view_with(&spool);
    identified(&mut view, "run");
    let ctx = context();
    let _ = (scan_with, request, draw);
    draw_at(&ctx, &mut view, 900.0, 0.0);
    let out = draw_at(&ctx, &mut view, 900.0, 0.05);
    let button = texts(&out)
        .into_iter()
        .find(|(text, _)| text.ends_with("Open in window"))
        .expect("the button")
        .1;
    let at = button.center();
    for (n, pressed) in [true, false].into_iter().enumerate() {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 900.0))),
                time: Some(1.0 + n as f64 * 0.03),
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
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.show(
                        ui,
                        TriageInput {
                            vm_id: Some("vm"),
                            boot_id: Some("boot"),
                            run_id: Some("run"),
                            ..TriageInput::empty()
                        },
                    );
                });
            },
        );
    }
    assert!(
        view.graph_window.open,
        "the Graph tab's button opened the window"
    );
    view.graph_window.close();
    // The strip's icon on the Summary does the same.
    view.section = Section::Summary;
    view.process = ProcessTab::Tree;
    view.strip.open = Some(true);
    draw_at(&ctx, &mut view, 900.0, 3.0);
    let out = draw_at(&ctx, &mut view, 900.0, 3.05);
    let icon = texts(&out)
        .into_iter()
        .find(|(text, _)| text == egui_phosphor::regular::ARROW_SQUARE_OUT)
        .expect("the strip's pop-out icon")
        .1;
    let at = icon.center();
    for (n, pressed) in [true, false].into_iter().enumerate() {
        let _ = ctx.run(
            egui::RawInput {
                screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1280.0, 900.0))),
                time: Some(4.0 + n as f64 * 0.03),
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
                egui::CentralPanel::default().show(ctx, |ui| {
                    view.show(
                        ui,
                        TriageInput {
                            vm_id: Some("vm"),
                            boot_id: Some("boot"),
                            run_id: Some("run"),
                            ..TriageInput::empty()
                        },
                    );
                });
            },
        );
    }
    assert!(view.graph_window.open, "the strip's icon opened the window");
    assert!(
        view.section == Section::Summary,
        "and left the Summary where it was"
    );
}

#[test]
fn a_burst_at_the_end_of_a_long_run_opens_fitted_to_the_burst_and_run_shows_it_all() {
    // A minute-long process whose findings all fall in the last 6 ms.
    let nodes = vec![node(0, 119, 1, "/tmp/ant-malware", 0, 60_000_000_000)];
    let mut builder = Builder::new(Lanes::from_processes(&nodes)).without_rows();
    for n in 0..6u64 {
        builder.push_record(record(
            59_990_000_000 + n * 1_000_000,
            1,
            Tier::High,
            Category::Execution,
        ));
    }
    let index = builder.finish();
    assert_eq!(index.extent(), (59_990_000_000, 59_995_000_000));
    assert_eq!(index.run_extent(), (0, 60_000_000_000));
    let layout = Layout::new(rect(1100.0, 640.0), &State::default(), &index);
    // The burst fills the plot: its first and last findings are well apart on screen.
    let first = layout.frame.x(index.records[0].first_ns as f64);
    let last = layout.frame.x(index.records[5].first_ns as f64);
    assert!(
        last - first > layout.frame.plot.width() * 0.6,
        "{first} {last}"
    );
    // The buckets cover the burst, not the minute, so they are fine enough to tell it apart.
    assert!(index.geometry().width(0) < 5_000_000.0);
    // Run shows the whole minute, and the findings are a sliver at its end.
    let state = State {
        window: Some(view::fitted(index.run_extent())),
        ..State::default()
    };
    let whole = Layout::new(rect(1100.0, 640.0), &state, &index);
    assert!(
        whole.frame.x(index.records[5].first_ns as f64)
            - whole.frame.x(index.records[0].first_ns as f64)
            < 5.0
    );
    assert!(whole.frame.t0 < 0.0 + 1.0e9 && whole.frame.t1 > 60.0e9);
}

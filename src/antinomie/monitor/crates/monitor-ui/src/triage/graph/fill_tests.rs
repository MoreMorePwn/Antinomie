// SPDX-License-Identifier: GPL-3.0-only
//! A run with few findings still fills the graph: the plot takes the whole
//! width it is given and the first and last finding sit near its two edges in
//! the default view, in the tab, in the pop-out and in the Summary strip.
use super::axis::{slot_pad, Axis, Spacing};
use super::index::{Builder, GraphIndex};
use super::input::Layout;
use super::sync_tests::{draw, recording, view_with};
use super::tests::{record, scene_nodes};
use super::*;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{Pos2, Rect};

const S: u64 = 1_000_000_000;

/// `findings` findings over `lanes` lanes, unevenly spaced in time: a burst,
/// then a long wait, so a true-time axis would bunch them.
fn few(findings: usize, lanes: u32) -> GraphIndex {
    let mut builder = Builder::new(Lanes::from_processes(&scene_nodes())).without_rows();
    let mut at = S;
    for n in 0..findings {
        let tier = [Tier::High, Tier::Medium, Tier::Low][n % 3];
        builder.push_record(record(at, 1 + n as u32 % lanes, tier, Category::Execution));
        at += if n % 3 == 2 { 40 * S } else { S / 10 };
    }
    builder.finish()
}

/// Where the first and the last finding are, as a share of the plot's width.
fn edge_shares(layout: &Layout, index: &GraphIndex) -> (f32, f32) {
    let frame = &layout.frame;
    let share = |x: f32| (x - frame.plot.left()) / frame.plot.width();
    let first = index.records.first().unwrap();
    let last = index.records.last().unwrap();
    (share(frame.x_rec(first)), share(frame.x_rec(last)))
}

fn assert_spread(layout: &Layout, index: &GraphIndex, what: &str) {
    let (first, last) = edge_shares(layout, index);
    if index.records.len() == 1 {
        assert!(
            (first - 0.5).abs() < 0.01,
            "{what}: a lone finding is centred"
        );
        return;
    }
    assert!(
        (0.0..=0.12).contains(&first) && (0.88..=1.0).contains(&last),
        "{what}: the findings run from {first:.3} to {last:.3} of the plot"
    );
}

#[test]
fn the_default_window_leaves_little_room_beside_a_few_slots() {
    assert_eq!(slot_pad(1.0), 0.5);
    for slots in 2..=12 {
        let pad = slot_pad(slots as f64);
        let share = pad / (slots as f64 - 1.0 + 2.0 * pad);
        assert!(
            share <= 1.0 / 6.0 + 1e-9,
            "{slots} slots leave {share:.3} each side"
        );
    }
    // A long run keeps its two per cent.
    assert_eq!(slot_pad(1000.0), 20.0);
    let index = few(3, 3);
    let (from, to) = Axis::new(Spacing::Events, &index.slots).all(index.extent());
    assert_eq!((from, to), (-0.25, 2.25));
}

#[test]
fn the_graph_tab_fills_its_width_with_few_findings() {
    let spool = recording();
    for (findings, lanes) in [(1, 1), (3, 2), (8, 3)] {
        let mut view = view_with(&spool);
        let index = few(findings, lanes);
        view.scan.as_mut().unwrap().graph.index = index;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        draw(&ctx, &mut view, 0.0);
        draw(&ctx, &mut view, 0.1);
        let rect = view.graph.drawn_in.expect("the graph was drawn");
        // The test pane is 1280 points wide, less the panel's margins.
        assert!(
            rect.width() >= 1280.0 - 40.0,
            "{findings} findings: the graph is {} wide",
            rect.width()
        );
        let index = &view.scan.as_ref().unwrap().graph.index;
        let layout = Layout::new(rect, &view.graph, index);
        assert!(
            layout.frame.plot.width() >= rect.width() - 270.0,
            "the label column leaves the rest to the plot"
        );
        assert_spread(&layout, index, &format!("tab, {findings} findings"));
    }
}

#[test]
fn the_graph_window_fills_its_width_with_few_findings() {
    let spool = recording();
    for (findings, lanes, details) in [(1, 1, false), (3, 2, false), (8, 3, false), (3, 2, true)] {
        let mut view = view_with(&spool);
        view.scan_request.identity = Some(("vm".into(), "boot".into(), "run-a".into()));
        view.scan.as_mut().unwrap().graph.index = few(findings, lanes);
        view.graph_window.details = details;
        let ctx = egui::Context::default();
        theme::install(&ctx);
        view.open_graph_window(&ctx);
        for time in [0.0, 0.1] {
            let _ = ctx.run(
                egui::RawInput {
                    screen_rect: Some(Rect::from_min_size(Pos2::ZERO, egui::vec2(1400.0, 900.0))),
                    time: Some(time),
                    ..Default::default()
                },
                |ctx| view.show_finding_windows(ctx),
            );
        }
        let rect = view.graph_window.state.drawn_in.expect("the window drew");
        // The window is as wide as its content area; Details take their share.
        let wanted = if details {
            window::DEFAULT_SIZE[0] - view.graph_window.details_width - 60.0
        } else {
            window::DEFAULT_SIZE[0] - 40.0
        };
        assert!(
            rect.width() >= wanted,
            "{findings} findings: {}",
            rect.width()
        );
        let index = &view.scan.as_ref().unwrap().graph.index;
        let layout = Layout::new(rect, &view.graph_window.state, index);
        assert_spread(&layout, index, &format!("window, {findings} findings"));
    }
}

#[test]
fn the_summary_strip_spreads_a_few_findings_over_its_whole_width() {
    // Three findings, a quiet wait, then INFO activity much later: the strip
    // spans all of it, and in true time the findings would be a sliver.
    let mut builder = Builder::overview();
    for (n, ns) in [S, S + S / 10, S + S / 5, 600 * S].into_iter().enumerate() {
        let tier = if n < 3 { Tier::High } else { Tier::Info };
        builder.push_record(record(ns, 0, tier, Category::Command));
    }
    let overview = builder.finish();
    let rect = Rect::from_min_size(Pos2::ZERO, egui::vec2(1200.0, 160.0));
    let events = super::strip::frame(rect, &overview, 1, Spacing::Events);
    let layout_share = |frame: &super::view::Frame, at: usize| {
        (frame.x_rec(&overview.records[at]) - frame.plot.left()) / frame.plot.width()
    };
    assert!(
        layout_share(&events, 0) <= 0.12,
        "the first sits at the left"
    );
    assert!(
        layout_share(&events, 3) >= 0.88,
        "the last sits at the right"
    );
    assert!(
        events.plot.width() >= 1200.0 - 200.0,
        "the plot takes the width"
    );
    // The equal slots: the three findings are a third of the plot, not a sliver.
    assert!(layout_share(&events, 2) - layout_share(&events, 0) > 0.3);
    // True time is still there to choose.
    let time = super::strip::frame(rect, &overview, 1, Spacing::Time);
    assert!(layout_share(&time, 2) - layout_share(&time, 0) < 0.05);
}

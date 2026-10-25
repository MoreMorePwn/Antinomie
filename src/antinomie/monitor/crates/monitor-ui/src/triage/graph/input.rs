// SPDX-License-Identifier: GPL-3.0-only
//! What a point on the graph means, and where the keyboard moves the selection.
//! Everything here is plain arithmetic over the index, so it is tested without
//! a window.
use super::axis::{Axis, Spacing};
use super::index::GraphIndex;
use super::lanes::Rows;
use super::view::{Frame, Metrics, State};
use super::*;
use crate::triage::rules::{Category, Tier};
use eframe::egui::{Pos2, Rect};

/// How far from a marker, in pixels, a point still reaches it.
pub(super) const REACH: f32 = 7.0;

/// What the graph asks the Triage view to do.
#[derive(Clone, Debug, PartialEq)]
pub(in crate::triage) enum Action {
    /// Show the record in Details. `focus` is a click, which brings Details forward.
    Select {
        record: usize,
        focus: bool,
    },
    /// Open the first evidence of the record.
    Open(usize),
    /// Keep only findings in this time range (ns).
    Brush(u64, u64),
    ClearBrush,
    /// Keep only findings of these processes.
    Lane {
        cookies: Vec<u64>,
    },
    Tier(Tier),
    Category(Category),
    /// The spacing chip or `T` chose this spacing.
    Spacing(Spacing),
}

/// What is under a point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hit {
    /// A marker: the best record there, and how many records the point reaches.
    Marker {
        record: usize,
        near: usize,
    },
    /// The ▾/▸ of a lane's name.
    Chevron {
        row: usize,
    },
    LaneName {
        row: usize,
    },
    Phase {
        span: usize,
    },
    Axis,
    Fit,
    /// The whole run, not just the findings.
    Run,
    /// A chip that chooses the spacing.
    Spacing(Spacing),
    /// The overview ruler.
    Ruler,
}

/// The frame of one draw and what is on its rows.
pub(super) struct Layout {
    pub frame: Frame,
    pub rows: Rows,
    pub scroll: f32,
    /// The categories that have a heat row, in [`Category::ALL`] order.
    pub categories: Vec<usize>,
    pub fit: Rect,
    /// The chip that shows the whole run, left of Fit.
    pub run: Rect,
    /// The Events and Time chips, left of Run.
    pub spacing: [Rect; 2],
    /// Where the whole run lies on the axis: the ruler spans it, and pan and
    /// zoom stay inside it.
    pub range: (f64, f64),
}

impl Layout {
    pub(super) fn new(whole: Rect, state: &State, index: &GraphIndex) -> Self {
        let categories: Vec<usize> = (0..13)
            .filter(|bit| index.categories & (1 << bit) != 0)
            .collect();
        let axis = Axis::new(state.units, &index.slots);
        let window = state.window.unwrap_or_else(|| axis.all(index.extent()));
        let range = axis.run(index.run_extent());
        let rows = Rows::build(&index.lanes, &state.collapsed, index.lane0_used);
        let metrics = Metrics::roomy(whole, categories.len(), rows.lanes.len());
        let frame = Frame::new(whole, window, categories.len(), metrics, axis);
        let content = rows.lanes.len() as f32 * frame.m.lane_h;
        let scroll = state
            .scroll
            .clamp(0.0, (content - frame.lanes.height()).max(0.0));
        let fit = Rect::from_min_size(
            Pos2::new(whole.right() - 40.0, frame.axis.top() + 3.0),
            eframe::egui::vec2(36.0, frame.axis.height() - 6.0),
        );
        let run = fit.translate(eframe::egui::vec2(-44.0, 0.0));
        let chip = |right: f32, width: f32| {
            Rect::from_min_size(
                Pos2::new(right - width, fit.top()),
                eframe::egui::vec2(width, fit.height()),
            )
        };
        let time = chip(run.left() - 8.0, 44.0);
        let events = chip(time.left() - 2.0, 58.0);
        Self {
            frame,
            rows,
            scroll,
            categories,
            fit,
            run,
            spacing: [events, time],
            range,
        }
    }

    /// The row a lane is drawn on, if it has one.
    pub(super) fn row_of(&self, lane: u32) -> Option<usize> {
        self.rows
            .row_of
            .get(lane as usize)
            .copied()
            .filter(|row| *row != u32::MAX)
            .map(|row| row as usize)
    }

    pub(super) fn row_center(&self, row: usize) -> f32 {
        self.frame.row_top(row, self.scroll) + self.frame.m.lane_h / 2.0
    }

    /// Whether a row is in the lane area now.
    pub(super) fn row_in_view(&self, row: usize) -> bool {
        let top = self.frame.row_top(row, self.scroll);
        top + self.frame.m.lane_h > self.frame.lanes.top() && top < self.frame.lanes.bottom()
    }
}

/// What is at `pos`.
pub(super) fn hit_test(
    layout: &Layout,
    index: &GraphIndex,
    depth_px: f32,
    pos: Pos2,
) -> Option<Hit> {
    let frame = &layout.frame;
    if layout.fit.contains(pos) {
        return Some(Hit::Fit);
    }
    if layout.run.contains(pos) {
        return Some(Hit::Run);
    }
    if layout.spacing[0].contains(pos) {
        return Some(Hit::Spacing(Spacing::Events));
    }
    if layout.spacing[1].contains(pos) {
        return Some(Hit::Spacing(Spacing::Time));
    }
    if frame.ruler.contains(pos) {
        return Some(Hit::Ruler);
    }
    if frame.axis.contains(pos) {
        return Some(Hit::Axis);
    }
    if frame.phases.contains(pos) {
        let geometry = index.geometry?;
        let ns = frame.ns(pos.x);
        return index
            .phases
            .iter()
            .position(|span| {
                geometry.start(0, span.first as usize) <= ns
                    && ns <= geometry.start(0, span.last as usize + 1)
            })
            .map(|span| Hit::Phase { span });
    }
    if frame.labels.contains(pos) || frame.lanes.contains(pos) {
        let row = frame.row_at(pos.y, layout.scroll, layout.rows.lanes.len())?;
        if frame.labels.contains(pos) {
            let lane = &index.lanes.list[layout.rows.lanes[row] as usize];
            let chevron =
                frame.labels.left() + 4.0 + f32::from(lane.depth.saturating_sub(1)) * depth_px;
            let has_children = lane.subtree_end as usize > layout.rows.lanes[row] as usize + 1;
            return Some(
                if has_children && (chevron..chevron + 14.0).contains(&pos.x) {
                    Hit::Chevron { row }
                } else {
                    Hit::LaneName { row }
                },
            );
        }
        return marker_at(layout, index, row, pos.x);
    }
    None
}

/// The record on `row` nearest to `x`, the worst of those within reach.
fn marker_at(layout: &Layout, index: &GraphIndex, row: usize, x: f32) -> Option<Hit> {
    let frame = &layout.frame;
    let window = index.window(frame.ns(x - REACH), frame.ns(x + REACH));
    let mut best: Option<(u8, f32, usize)> = None;
    let mut near = 0;
    for at in window {
        let record = &index.records[at];
        if layout.row_of(record.lane) != Some(row) {
            continue;
        }
        near += 1;
        let key = (record.tier, (frame.x(record.first_ns as f64) - x).abs());
        if best
            .is_none_or(|(tier, distance, _)| key.0 < tier || (key.0 == tier && key.1 < distance))
        {
            best = Some((key.0, key.1, at));
        }
    }
    best.map(|(_, _, record)| Hit::Marker { record, near })
}

/// What a marker's tooltip says, ready to lay out: the tier it is coloured by,
/// a heading, the finding's title, labelled facts and a closing hint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Tip {
    /// The tier the chip is coloured by.
    pub tier: Tier,
    /// `HIGH · Command & control`.
    pub heading: String,
    /// The rule's name; empty when only the packed record is known.
    pub title: String,
    /// What the finding did, in a sentence.
    pub summary: String,
    /// Label and value, in display order.
    pub facts: Vec<(&'static str, String)>,
    /// How many findings share the point, when more than one.
    pub crowd: Option<String>,
}

/// A marker's tooltip: rule, tier, category, process, time, count, outcome.
pub(super) fn tooltip(
    index: &GraphIndex,
    record: usize,
    near: usize,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Tip {
    let mut tip = Tip {
        tier: Tier::Info,
        heading: String::new(),
        title: String::new(),
        summary: String::new(),
        facts: Vec::new(),
        crowd: None,
    };
    let mut facts: Vec<(&'static str, String)> = Vec::new();
    if let Some(row) = index.rows.get(record) {
        let cell = |column: usize| row.cells.get(column).map(|cell| cell.text.clone());
        let tier = cell(rules::COL_TIER).unwrap_or_default();
        tip.tier = Tier::from_tag(&tier.to_lowercase()).unwrap_or(Tier::Info);
        tip.heading = format!("{} · {}", tier.to_uppercase(), cell(2).unwrap_or_default());
        tip.title = cell(0).unwrap_or_default();
        tip.summary = cell(rules::COL_SUMMARY).unwrap_or_default();
        facts.push(("Process", cell(rules::COL_PROCESS).unwrap_or_default()));
        facts.push(("Count", cell(5).unwrap_or_default()));
        facts.push(("Outcome", cell(11).unwrap_or_default()));
    } else if let Some(record) = index.records.get(record) {
        tip.tier = Tier::ALL[usize::from(record.tier).min(3)];
        tip.heading = format!(
            "{} · {}",
            tip.tier.tag().to_uppercase(),
            Category::ALL[usize::from(record.category).min(12)].label()
        );
        facts.push(("Count", record.count.to_string()));
    }
    if let Some(record) = index.records.get(record) {
        // Without a host anchor the guest time has no wall clock to show.
        let time = crate::time_format::guest_ns(clock, Some(record.first_ns));
        let when = if clock.is_some() && time != "Unavailable" {
            time
        } else {
            format!(
                "{:.3} s into the run",
                record.first_ns.saturating_sub(index.run_extent().0) as f64 / 1e9
            )
        };
        facts.insert(0, ("When", when));
    }
    tip.facts = facts
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .collect();
    if near > 1 {
        tip.crowd = Some(format!(
            "{near} findings under the pointer; the worst is shown"
        ));
    }
    tip
}

/// The previous (`-1`) or next (`1`) record in time, from `from`; with no
/// selection the first at or after the window start, or the last before its end.
pub(super) fn step_time(
    index: &GraphIndex,
    from: Option<usize>,
    direction: i32,
    window: (f64, f64),
) -> Option<usize> {
    if index.records.is_empty() {
        return None;
    }
    let last = index.records.len() - 1;
    match (from, direction.signum()) {
        (Some(at), 1) => Some((at + 1).min(last)),
        (Some(at), _) => Some(at.saturating_sub(1)),
        (None, 1) => Some(index.window(window.0, window.1).start.min(last)),
        (None, _) => Some(
            index
                .window(window.0, window.1)
                .end
                .saturating_sub(1)
                .min(last),
        ),
    }
}

/// The record in the nearest row above (`-1`) or below (`1`) that holds one,
/// the one closest in time to `from`.
pub(super) fn step_lane(
    index: &GraphIndex,
    layout: &Layout,
    from: usize,
    direction: i32,
) -> Option<usize> {
    let record = index.records.get(from)?;
    let row = layout.row_of(record.lane)? as i64;
    let direction = i64::from(direction.signum());
    let mut best: Option<((i64, usize), usize)> = None;
    for (at, other) in index.records.iter().enumerate() {
        let Some(other_row) = layout.row_of(other.lane) else {
            continue;
        };
        let away = (other_row as i64 - row) * direction;
        if away <= 0 {
            continue;
        }
        let key = (away, at.abs_diff(from));
        if best.is_none_or(|(known, _)| key < known) {
            best = Some((key, at));
        }
    }
    best.map(|(_, at)| at)
}

/// The window moved, if it must be, so `ns` is inside it.
pub(super) fn including(window: (f64, f64), ns: f64, bounds: (f64, f64)) -> (f64, f64) {
    let span = window.1 - window.0;
    if ns < window.0 {
        view::panned(window, ns - window.0 - span * 0.1, bounds)
    } else if ns > window.1 {
        view::panned(window, ns - window.1 + span * 0.1, bounds)
    } else {
        window
    }
}

/// The scroll that puts `row` in view.
pub(super) fn scroll_to(row: usize, scroll: f32, area: f32, lane_h: f32) -> f32 {
    let top = row as f32 * lane_h;
    if top < scroll {
        top
    } else if top + lane_h > scroll + area {
        top + lane_h - area
    } else {
        scroll
    }
}

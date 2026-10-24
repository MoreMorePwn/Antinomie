// SPDX-License-Identifier: GPL-3.0-only
//! What the graph remembers between frames, and the arithmetic of its window:
//! where a time falls on the screen, and how zoom and pan move the window.
use super::axis::{Axis, Spacing};
use eframe::egui::{Pos2, Rect};

pub(super) const GAP: f32 = 3.0;
/// The overview ruler's height.
pub(super) const RULER_H: f32 = 30.0;
/// The thinnest and the thickest a lane row is drawn.
pub(super) const LANE_MIN: f32 = 24.0;
pub(super) const LANE_MAX: f32 = 84.0;
/// The graph never asks for less height than this; a shorter pane scrolls.
pub(in crate::triage) const MIN_HEIGHT: f32 = 420.0;
/// A bucket is drawn at the level where it is at least this wide.
pub(super) const MIN_BUCKET_PX: f64 = 3.0;
/// Individual findings are drawn when the window holds fewer than this.
pub(super) const INDIVIDUAL_BELOW: usize = 5_000;
/// The shortest window: one microsecond.
pub(super) const MIN_SPAN_NS: f64 = 1_000.0;

/// How tall each part is. The embedded and the windowed graph size their lanes
/// and bands to the room they are given; the Summary strip is compact.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Metrics {
    /// Width of the lane-name column.
    pub label_w: f32,
    pub phase_h: f32,
    pub curve_h: f32,
    /// One category row of the heat strip.
    pub heat_h: f32,
    pub axis_h: f32,
    /// The overview ruler under the axis; none in the Summary strip.
    pub ruler_h: f32,
    pub lane_h: f32,
}

impl Metrics {
    /// The Summary strip: no lanes, small bands.
    pub(super) fn compact() -> Self {
        Self {
            label_w: 168.0,
            phase_h: 18.0,
            curve_h: 46.0,
            heat_h: 11.0,
            axis_h: 24.0,
            ruler_h: 0.0,
            lane_h: 20.0,
        }
    }

    /// The height of the strip's bands and axis.
    pub(super) fn strip_height(heat_rows: usize) -> f32 {
        let m = Self::compact();
        m.phase_h + GAP + m.curve_h + GAP + m.heat_h * heat_rows as f32 + GAP + m.axis_h
    }

    /// Sizes for `lanes` rows in `whole`: lanes grow up to [`LANE_MAX`] to fill
    /// the room, and a run with few lanes gives what is left to the curve.
    pub(super) fn roomy(whole: Rect, heat_rows: usize, lanes: usize) -> Self {
        let heat_h = if heat_rows > 8 { 12.0 } else { 14.0 };
        let (phase_h, axis_h, curve_base) = (22.0, 26.0, 64.0);
        let ruler_h = RULER_H;
        let heat = if heat_rows > 0 {
            heat_h * heat_rows as f32 + GAP
        } else {
            0.0
        };
        let fixed = phase_h + GAP + curve_base + GAP + heat + GAP + axis_h + ruler_h + 2.0 * GAP;
        let area = (whole.height() - fixed).max(0.0);
        let rows = lanes.max(1) as f32;
        let lane_h = (area / rows).clamp(LANE_MIN, LANE_MAX);
        let spare = (area - rows * lane_h).max(0.0);
        Self {
            label_w: (whole.width() * 0.16).clamp(190.0, 260.0),
            phase_h,
            curve_h: curve_base + spare.min(120.0),
            heat_h,
            axis_h,
            ruler_h,
            lane_h,
        }
    }

    /// The radius of a marker in a row this tall.
    pub(super) fn glyph(&self) -> f32 {
        (self.lane_h * 0.24).clamp(5.0, 9.0)
    }
}

/// A drag in progress.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Drag {
    /// Moving the window; `last_x` is where the pointer was.
    Pan,
    /// Brushing a time range on the axis, from `start` to `now`, in ns.
    Brush { start: f64, now: f64 },
    /// Dragging in the overview ruler, in the axis's units.
    Ruler(Ruler),
}

/// What a drag in the overview ruler does.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Ruler {
    /// Moving the window; `grab` is how far into it the pointer took hold.
    Move { grab: f64, width: f64 },
    /// Pulling the window's left or right edge.
    Edge { left: bool },
    /// Selecting a new range, from `start` to `now`.
    Select { start: f64, now: f64 },
}

/// What the graph keeps between frames.
pub(in crate::triage) struct State {
    /// The visible stretch in the units of `units`: ns for Time spacing and
    /// slot numbers for Events. `None` fits the findings.
    pub window: Option<(f64, f64)>,
    /// The spacing `window` is in; it is converted when the spacing changes.
    pub units: Spacing,
    /// Pixels the lane list is scrolled by.
    pub scroll: f32,
    /// Lanes folded into their own row, by `(cookie, pid)`.
    pub collapsed: std::collections::BTreeSet<(u64, u32)>,
    /// The record selected in the graph.
    pub selected: Option<usize>,
    /// The time range brushed, which the filter holds.
    pub brush: Option<(u64, u64)>,
    pub(super) drag: Option<Drag>,
    /// The overview ruler's marks, kept until the index, width or spacing changes.
    pub(super) ruler: Option<super::ruler::Marks>,
    /// Where the widget was drawn last, for tests.
    #[cfg(test)]
    pub(super) drawn_in: Option<Rect>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            window: None,
            // The widget converts to the spacing it is told on its first frame.
            units: Spacing::Time,
            scroll: 0.0,
            collapsed: Default::default(),
            selected: None,
            brush: None,
            drag: None,
            ruler: None,
            #[cfg(test)]
            drawn_in: None,
        }
    }
}

impl State {
    pub(in crate::triage) fn fit(&mut self) {
        self.window = None;
    }
}

/// The areas of the widget for one frame, and the window they show.
#[derive(Clone, Debug)]
pub(super) struct Frame {
    pub whole: Rect,
    pub labels: Rect,
    /// The part of every band that maps to time.
    pub plot: Rect,
    pub phases: Rect,
    pub curve: Rect,
    pub heat: Rect,
    pub lanes: Rect,
    pub axis: Rect,
    /// The overview ruler, under the axis.
    pub ruler: Rect,
    /// The window on the axis, in its units.
    pub t0: f64,
    pub t1: f64,
    pub map: Axis,
    pub m: Metrics,
}

impl Frame {
    pub(super) fn new(
        whole: Rect,
        window: (f64, f64),
        heat_rows: usize,
        m: Metrics,
        map: Axis,
    ) -> Self {
        let plot_left = whole.left() + m.label_w;
        let mut y = whole.top();
        let band = |y: &mut f32, height: f32| {
            let rect = Rect::from_min_max(
                Pos2::new(plot_left, *y),
                Pos2::new(whole.right(), (*y + height).min(whole.bottom())),
            );
            *y += height + GAP;
            rect
        };
        let phases = band(&mut y, m.phase_h);
        let curve = band(&mut y, m.curve_h);
        let heat = band(&mut y, m.heat_h * heat_rows as f32);
        let ruler_top = (whole.bottom() - m.ruler_h).max(y);
        let ruler_gap = if m.ruler_h > 0.0 { GAP } else { 0.0 };
        let axis_top = (ruler_top - ruler_gap - m.axis_h).max(y);
        let lanes = Rect::from_min_max(
            Pos2::new(plot_left, y),
            Pos2::new(whole.right(), (axis_top - GAP).max(y)),
        );
        let axis = Rect::from_min_max(
            Pos2::new(plot_left, axis_top),
            Pos2::new(whole.right(), (axis_top + m.axis_h).min(whole.bottom())),
        );
        let ruler = Rect::from_min_max(
            Pos2::new(plot_left, ruler_top.max(axis.bottom())),
            Pos2::new(whole.right(), whole.bottom().max(ruler_top)),
        );
        let labels = Rect::from_min_max(
            whole.min,
            Pos2::new(plot_left - GAP, whole.bottom().max(whole.top())),
        );
        Self {
            whole,
            labels,
            plot: Rect::from_min_max(Pos2::new(plot_left, whole.top()), whole.max),
            phases,
            curve,
            heat,
            lanes,
            axis,
            ruler,
            t0: window.0,
            t1: window.1.max(window.0 + 1e-6),
            map,
            m,
        }
    }

    /// Axis units to a pixel row of the plot: one pixel's worth of the window.
    pub(super) fn u_per_px(&self) -> f64 {
        (self.t1 - self.t0) / f64::from(self.plot.width().max(1.0))
    }

    /// The x of a place on the axis.
    pub(super) fn x_u(&self, u: f64) -> f32 {
        self.plot.left() + ((u - self.t0) / (self.t1 - self.t0)) as f32 * self.plot.width()
    }

    /// The place on the axis at `x`.
    pub(super) fn u_at(&self, x: f32) -> f64 {
        self.t0
            + f64::from((x - self.plot.left()) / self.plot.width().max(1.0)) * (self.t1 - self.t0)
    }

    /// The x of a finding: its slot in Events spacing, its time otherwise.
    pub(super) fn x_rec(&self, record: &super::index::Record) -> f32 {
        if self.map.spacing == Spacing::Events && !self.map.slots.times.is_empty() {
            self.x_u(f64::from(record.slot))
        } else {
            self.x(record.first_ns as f64)
        }
    }

    /// The x of a time.
    pub(super) fn x(&self, ns: f64) -> f32 {
        self.x_u(self.map.to_u(ns))
    }

    /// The time at `x`.
    pub(super) fn ns(&self, x: f32) -> f64 {
        self.map.to_ns(self.u_at(x))
    }

    /// The times at the window's two edges.
    pub(super) fn ns_range(&self) -> (f64, f64) {
        (self.map.to_ns(self.t0), self.map.to_ns(self.t1))
    }

    /// How many ns one pixel is, on average, over the window: what the pyramid
    /// level is chosen by, and the axis ticks in Time spacing.
    pub(super) fn ns_per_px(&self) -> f64 {
        let (from, to) = self.ns_range();
        (to - from) / f64::from(self.plot.width().max(1.0))
    }

    /// The rows whose band touches the lane area at `scroll`.
    pub(super) fn visible_rows(&self, scroll: f32, rows: usize) -> std::ops::Range<usize> {
        let first = (scroll / self.m.lane_h).floor().max(0.0) as usize;
        let last = ((scroll + self.lanes.height()) / self.m.lane_h).ceil() as usize;
        first.min(rows)..last.min(rows)
    }

    pub(super) fn row_top(&self, row: usize, scroll: f32) -> f32 {
        self.lanes.top() + row as f32 * self.m.lane_h - scroll
    }

    /// The row under `y` in the lane area.
    pub(super) fn row_at(&self, y: f32, scroll: f32, rows: usize) -> Option<usize> {
        if y < self.lanes.top() || y >= self.lanes.bottom() {
            return None;
        }
        let row = ((y - self.lanes.top() + scroll) / self.m.lane_h).floor();
        (row >= 0.0 && (row as usize) < rows).then_some(row as usize)
    }
}

/// The window that shows the whole run, with a little room at both ends.
pub(super) fn fitted(extent: (u64, u64)) -> (f64, f64) {
    let (lo, hi) = (extent.0 as f64, extent.1 as f64);
    let margin = ((hi - lo) * 0.01).max(MIN_SPAN_NS / 2.0);
    (lo - margin, hi + margin)
}

/// The window a graph opens at: the findings with some room, however short
/// their stretch of a long run is (a burst of a few milliseconds at the end of
/// a minute is shown as the burst).
pub(super) fn fitted_findings(findings: (u64, u64)) -> (f64, f64) {
    let (lo, hi) = (findings.0 as f64, findings.1 as f64);
    // A single finding has no stretch: half a millisecond either side.
    let pad = ((hi - lo) * 0.06).max(500_000.0);
    (lo - pad, hi + pad)
}

/// `window` zoomed by `factor` around `anchor`, kept inside `bounds`.
#[cfg(test)]
pub(super) fn zoomed(
    window: (f64, f64),
    anchor: f64,
    factor: f64,
    bounds: (f64, f64),
) -> (f64, f64) {
    zoomed_min(window, anchor, factor, bounds, MIN_SPAN_NS)
}

/// [`zoomed`] with the shortest window given, in the axis's units.
pub(super) fn zoomed_min(
    window: (f64, f64),
    anchor: f64,
    factor: f64,
    bounds: (f64, f64),
    min_span: f64,
) -> (f64, f64) {
    let span = window.1 - window.0;
    let widest = bounds.1 - bounds.0;
    let wanted = (span / factor.max(1e-6)).clamp(min_span.min(widest), widest);
    let share = ((anchor - window.0) / span).clamp(0.0, 1.0);
    let start = anchor - share * wanted;
    placed((start, start + wanted), bounds)
}

/// `window` moved by `delta` ns, kept inside `bounds`.
pub(super) fn panned(window: (f64, f64), delta: f64, bounds: (f64, f64)) -> (f64, f64) {
    placed((window.0 + delta, window.1 + delta), bounds)
}

/// Shift a window so it lies inside `bounds` without changing its width.
pub(super) fn placed(window: (f64, f64), bounds: (f64, f64)) -> (f64, f64) {
    let width = window.1 - window.0;
    let start = window.0.clamp(bounds.0, (bounds.1 - width).max(bounds.0));
    (start, start + width)
}

/// How far a window may go: the run, a little beyond at both ends.
#[cfg(test)]
pub(super) fn bounds(extent: (u64, u64)) -> (f64, f64) {
    fitted(extent)
}

/// A step between axis ticks of 1, 2 or 5 times a power of ten that leaves at
/// least `min_px` between ticks.
pub(super) fn tick_step(ns_per_px: f64, min_px: f64) -> f64 {
    let wanted = (ns_per_px * min_px).max(1.0);
    let magnitude = 10f64.powf(wanted.log10().floor());
    [1.0, 2.0, 5.0, 10.0]
        .into_iter()
        .map(|base| base * magnitude)
        .find(|step| *step >= wanted)
        .unwrap_or(10.0 * magnitude)
}

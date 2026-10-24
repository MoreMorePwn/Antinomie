// SPDX-License-Identifier: GPL-3.0-only
//! What the graph remembers between frames, and the arithmetic of its window:
//! where a time falls on the screen, and how zoom and pan move the window.
use eframe::egui::{Pos2, Rect};

/// Width of the lane-name column.
pub(super) const LABEL_W: f32 = 168.0;
pub(super) const PHASE_H: f32 = 18.0;
pub(super) const CURVE_H: f32 = 46.0;
pub(super) const HEAT_ROW_H: f32 = 11.0;
pub(super) const AXIS_H: f32 = 24.0;
pub(super) const LANE_H: f32 = 20.0;
pub(super) const GAP: f32 = 3.0;
/// A bucket is drawn at the level where it is at least this wide.
pub(super) const MIN_BUCKET_PX: f64 = 3.0;
/// Individual findings are drawn when the window holds fewer than this.
pub(super) const INDIVIDUAL_BELOW: usize = 5_000;
/// The shortest window: one microsecond.
pub(super) const MIN_SPAN_NS: f64 = 1_000.0;

/// A drag in progress.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Drag {
    /// Moving the window; `last_x` is where the pointer was.
    Pan,
    /// Brushing a time range on the axis, from `start` to `now`, in ns.
    Brush { start: f64, now: f64 },
}

/// What the graph keeps between frames.
#[derive(Default)]
pub(in crate::triage) struct State {
    /// The visible time, ns. `None` fits the whole run.
    pub window: Option<(f64, f64)>,
    /// Pixels the lane list is scrolled by.
    pub scroll: f32,
    /// Lanes folded into their own row, by `(cookie, pid)`.
    pub collapsed: std::collections::BTreeSet<(u64, u32)>,
    /// The record selected in the graph.
    pub selected: Option<usize>,
    /// The time range brushed, which the filter holds.
    pub brush: Option<(u64, u64)>,
    pub(super) drag: Option<Drag>,
}

impl State {
    pub(in crate::triage) fn fit(&mut self) {
        self.window = None;
    }
}

/// The areas of the widget for one frame, and the window they show.
#[derive(Clone, Copy, Debug)]
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
    pub t0: f64,
    pub t1: f64,
}

impl Frame {
    pub(super) fn new(whole: Rect, window: (f64, f64), heat_rows: usize) -> Self {
        let plot_left = whole.left() + LABEL_W;
        let mut y = whole.top();
        let band = |y: &mut f32, height: f32| {
            let rect = Rect::from_min_max(
                Pos2::new(plot_left, *y),
                Pos2::new(whole.right(), (*y + height).min(whole.bottom())),
            );
            *y += height + GAP;
            rect
        };
        let phases = band(&mut y, PHASE_H);
        let curve = band(&mut y, CURVE_H);
        let heat = band(&mut y, HEAT_ROW_H * heat_rows as f32);
        let axis_top = (whole.bottom() - AXIS_H).max(y);
        let lanes = Rect::from_min_max(
            Pos2::new(plot_left, y),
            Pos2::new(whole.right(), (axis_top - GAP).max(y)),
        );
        let axis = Rect::from_min_max(
            Pos2::new(plot_left, axis_top),
            Pos2::new(whole.right(), whole.bottom().max(axis_top)),
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
            t0: window.0,
            t1: window.1.max(window.0 + 1.0),
        }
    }

    pub(super) fn ns_per_px(&self) -> f64 {
        (self.t1 - self.t0) / f64::from(self.plot.width().max(1.0))
    }

    pub(super) fn x(&self, ns: f64) -> f32 {
        self.plot.left() + ((ns - self.t0) / (self.t1 - self.t0)) as f32 * self.plot.width()
    }

    pub(super) fn ns(&self, x: f32) -> f64 {
        self.t0
            + f64::from((x - self.plot.left()) / self.plot.width().max(1.0)) * (self.t1 - self.t0)
    }

    /// The rows whose band touches the lane area at `scroll`.
    pub(super) fn visible_rows(&self, scroll: f32, rows: usize) -> std::ops::Range<usize> {
        let first = (scroll / LANE_H).floor().max(0.0) as usize;
        let last = ((scroll + self.lanes.height()) / LANE_H).ceil() as usize;
        first.min(rows)..last.min(rows)
    }

    pub(super) fn row_top(&self, row: usize, scroll: f32) -> f32 {
        self.lanes.top() + row as f32 * LANE_H - scroll
    }

    /// The row under `y` in the lane area.
    pub(super) fn row_at(&self, y: f32, scroll: f32, rows: usize) -> Option<usize> {
        if y < self.lanes.top() || y >= self.lanes.bottom() {
            return None;
        }
        let row = ((y - self.lanes.top() + scroll) / LANE_H).floor();
        (row >= 0.0 && (row as usize) < rows).then_some(row as usize)
    }
}

/// The window that shows the whole run, with a little room at both ends.
pub(super) fn fitted(extent: (u64, u64)) -> (f64, f64) {
    let (lo, hi) = (extent.0 as f64, extent.1 as f64);
    let margin = ((hi - lo) * 0.01).max(MIN_SPAN_NS / 2.0);
    (lo - margin, hi + margin)
}

/// `window` zoomed by `factor` around `anchor`, kept inside `bounds`.
pub(super) fn zoomed(
    window: (f64, f64),
    anchor: f64,
    factor: f64,
    bounds: (f64, f64),
) -> (f64, f64) {
    let span = window.1 - window.0;
    let widest = bounds.1 - bounds.0;
    let wanted = (span / factor.max(1e-6)).clamp(MIN_SPAN_NS.min(widest), widest);
    let share = ((anchor - window.0) / span).clamp(0.0, 1.0);
    let start = anchor - share * wanted;
    placed((start, start + wanted), bounds)
}

/// `window` moved by `delta` ns, kept inside `bounds`.
pub(super) fn panned(window: (f64, f64), delta: f64, bounds: (f64, f64)) -> (f64, f64) {
    placed((window.0 + delta, window.1 + delta), bounds)
}

/// Shift a window so it lies inside `bounds` without changing its width.
fn placed(window: (f64, f64), bounds: (f64, f64)) -> (f64, f64) {
    let width = window.1 - window.0;
    let start = window.0.clamp(bounds.0, (bounds.1 - width).max(bounds.0));
    (start, start + width)
}

/// How far a window may go: the run, a little beyond at both ends.
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

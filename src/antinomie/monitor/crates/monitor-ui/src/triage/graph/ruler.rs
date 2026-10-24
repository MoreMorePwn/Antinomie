// SPDX-License-Identifier: GPL-3.0-only
//! The overview ruler: a thin strip under the time axis that shows every
//! finding of the run, squeezed into its width, and the stretch the graph
//! shows now as a window on it. Drag the window to pan, drag its edges to
//! zoom, drag across an empty part to choose a new stretch, double-click to
//! see the whole run again.
use super::axis::Axis;
use super::index::GraphIndex;
use super::paint::Colors;
use super::view::{self, Ruler, State};
use eframe::egui::{Painter, Pos2, Rect, Shape, Stroke};

/// How close to an edge of the window, in pixels, still takes the edge.
pub(super) const GRAB: f32 = 5.0;
/// A drag shorter than this many pixels is a click.
pub(super) const CLICK_PX: f32 = 3.0;

/// What is under a point of the ruler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Spot {
    LeftEdge,
    RightEdge,
    /// Inside the window.
    Window,
    /// Outside it: a new stretch starts here.
    Empty,
}

/// The ruler's marks: for each pixel column, how many findings fall in it and
/// the worst tier among them.
#[derive(Clone, Debug)]
pub(in crate::triage) struct Marks {
    key: (u64, u32, bool),
    pub columns: Vec<(u32, u8)>,
    pub most: u32,
}

impl Marks {
    /// The marks of `index` over `range` (in axis units) in `width` columns.
    pub(super) fn build(index: &GraphIndex, axis: &Axis, range: (f64, f64), width: usize) -> Self {
        let width = width.max(1);
        let mut columns = vec![(0u32, super::index::NO_TIER); width];
        let span = (range.1 - range.0).max(1e-9);
        for record in &index.records {
            let u = if axis.spacing == super::axis::Spacing::Events {
                f64::from(record.slot)
            } else {
                record.first_ns as f64
            };
            let at = (((u - range.0) / span) * width as f64).floor();
            let column = &mut columns[(at.max(0.0) as usize).min(width - 1)];
            column.0 += 1;
            column.1 = column.1.min(record.tier);
        }
        let most = columns.iter().map(|column| column.0).max().unwrap_or(0);
        Self {
            key: Self::key(index, axis, width),
            columns,
            most,
        }
    }

    fn key(index: &GraphIndex, axis: &Axis, width: usize) -> (u64, u32, bool) {
        (
            index.id,
            width as u32,
            axis.spacing == super::axis::Spacing::Events,
        )
    }

    /// Whether these marks are of `index` at this width and spacing.
    pub(super) fn is_for(&self, index: &GraphIndex, axis: &Axis, width: usize) -> bool {
        self.key == Self::key(index, axis, width.max(1))
    }
}

/// The x of a place on the axis, on the ruler.
pub(super) fn x_of(rect: Rect, range: (f64, f64), u: f64) -> f32 {
    rect.left() + (((u - range.0) / (range.1 - range.0).max(1e-9)) as f32) * rect.width()
}

/// The place on the axis at `x`, on the ruler, kept inside the run.
pub(super) fn u_of(rect: Rect, range: (f64, f64), x: f32) -> f64 {
    let share = f64::from(((x - rect.left()) / rect.width().max(1.0)).clamp(0.0, 1.0));
    range.0 + share * (range.1 - range.0)
}

/// What is at `x` given the window on the ruler.
pub(super) fn spot(rect: Rect, range: (f64, f64), window: (f64, f64), x: f32) -> Spot {
    let (left, right) = (x_of(rect, range, window.0), x_of(rect, range, window.1));
    // A window too narrow to have two edges takes the nearer one.
    let narrow = right - left < GRAB * 2.0;
    if !narrow && (x - left).abs() <= GRAB {
        Spot::LeftEdge
    } else if !narrow && (x - right).abs() <= GRAB {
        Spot::RightEdge
    } else if (left - GRAB..=right + GRAB).contains(&x) {
        Spot::Window
    } else {
        Spot::Empty
    }
}

/// Start a drag at `x`.
pub(super) fn begin(rect: Rect, range: (f64, f64), window: (f64, f64), x: f32) -> Ruler {
    let at = u_of(rect, range, x);
    match spot(rect, range, window, x) {
        Spot::LeftEdge => Ruler::Edge { left: true },
        Spot::RightEdge => Ruler::Edge { left: false },
        Spot::Window => Ruler::Move {
            grab: at - window.0,
            width: window.1 - window.0,
        },
        Spot::Empty => Ruler::Select { start: at, now: at },
    }
}

/// The window a drag at `x` asks for, and whether it is settled (a selection
/// only takes effect when it ends). `None` leaves the window as it is.
pub(super) fn drag(
    state: &mut State,
    rect: Rect,
    range: (f64, f64),
    window: (f64, f64),
    x: f32,
    min_span: f64,
) -> Option<(f64, f64)> {
    let at = u_of(rect, range, x);
    let Some(view::Drag::Ruler(mode)) = state.drag else {
        return None;
    };
    match mode {
        Ruler::Move { grab, width } => Some(view::placed((at - grab, at - grab + width), range)),
        Ruler::Edge { left: true } => Some((at.min(window.1 - min_span), window.1)),
        Ruler::Edge { left: false } => Some((window.0, at.max(window.0 + min_span))),
        Ruler::Select { start, .. } => {
            state.drag = Some(view::Drag::Ruler(Ruler::Select { start, now: at }));
            None
        }
    }
}

/// The window a finished selection chooses: the stretch dragged over, or the
/// current width centred where it was clicked.
pub(super) fn selected(
    rect: Rect,
    range: (f64, f64),
    window: (f64, f64),
    (start, now): (f64, f64),
    min_span: f64,
) -> (f64, f64) {
    let per_px = (range.1 - range.0) / f64::from(rect.width().max(1.0));
    if (now - start).abs() / per_px.max(1e-12) < f64::from(CLICK_PX) {
        let width = window.1 - window.0;
        return view::placed((start - width / 2.0, start + width / 2.0), range);
    }
    let (from, to) = (start.min(now), start.max(now));
    (from, to.max(from + min_span))
}

/// Draw the ruler: the marks, the brush, the window on it.
pub(super) struct Drawing<'a> {
    pub rect: Rect,
    pub range: (f64, f64),
    pub window: (f64, f64),
    pub marks: Option<&'a Marks>,
    /// The filter's brush, in axis units.
    pub brush: Option<(f64, f64)>,
    /// A range being selected, in axis units.
    pub selecting: Option<(f64, f64)>,
}

pub(super) fn paint(painter: &Painter, drawing: Drawing<'_>, colors: &Colors) {
    let Drawing {
        rect,
        range,
        window,
        marks,
        brush,
        selecting,
    } = drawing;
    painter.rect_filled(rect, 2.0, colors.bg);
    let painter = painter.with_clip_rect(rect);
    if let Some(marks) = marks.filter(|marks| marks.most > 0) {
        let scale = (1.0 + marks.most as f32).ln();
        let width = rect.width() / marks.columns.len() as f32;
        let mut shapes = Vec::new();
        for (at, (count, top)) in marks.columns.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let height =
                ((1.0 + *count as f32).ln() / scale).clamp(0.12, 1.0) * (rect.height() - 6.0);
            let x = rect.left() + at as f32 * width;
            shapes.push(Shape::rect_filled(
                Rect::from_min_max(
                    Pos2::new(x, rect.bottom() - 2.0 - height),
                    Pos2::new(x + width.max(1.0), rect.bottom() - 2.0),
                ),
                0.0,
                colors.tier[usize::from(*top).min(3)],
            ));
        }
        painter.extend(shapes);
    }
    if let Some((from, to)) = brush {
        let (a, b) = (x_of(rect, range, from), x_of(rect, range, to));
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(a.min(b), rect.top()),
                Pos2::new(a.max(b).max(a.min(b) + 2.0), rect.top() + 4.0),
            ),
            0.0,
            colors.selection,
        );
    }
    if let Some((from, to)) = selecting {
        let (a, b) = (x_of(rect, range, from), x_of(rect, range, to));
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(a.min(b), rect.top()),
                Pos2::new(a.max(b), rect.bottom()),
            ),
            0.0,
            colors.accent.gamma_multiply(0.25),
        );
    }
    let (left, right) = (
        x_of(rect, range, window.0).clamp(rect.left(), rect.right()),
        x_of(rect, range, window.1).clamp(rect.left(), rect.right()),
    );
    let view = Rect::from_min_max(
        Pos2::new(left, rect.top()),
        Pos2::new(right.max(left + 3.0), rect.bottom()),
    );
    painter.rect_filled(view, 2.0, colors.accent.gamma_multiply(0.16));
    painter.rect_stroke(
        view,
        2.0,
        Stroke::new(1.5_f32, colors.accent),
        eframe::egui::StrokeKind::Inside,
    );
    // A grip at each edge.
    for x in [view.left() + 1.5, view.right() - 1.5] {
        let middle = rect.center().y;
        painter.line_segment(
            [Pos2::new(x, middle - 5.0), Pos2::new(x, middle + 5.0)],
            Stroke::new(2.0_f32, colors.accent),
        );
    }
}

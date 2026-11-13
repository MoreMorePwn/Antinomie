// SPDX-License-Identifier: GPL-3.0-only
//! Drawing the Call rate graph and reading the pointer on it (design 2.4).
//!
//! The graph is custom painted. Lines differ in colour, dash pattern and end
//! marker, so colour is never the only signal; hatched bands carry a text
//! label. A line is thinned to one point per pixel column (the largest count
//! in the column) when the view holds more intervals than pixels, so a frame
//! costs the same for 65,536 bins as for a few hundred.
use super::hierarchy::Click;
use super::rate::{click_of, Band, Inputs, Plot, PlotLine, State};
use super::{time_text, TimeBase};
use crate::theme;
use antinomie_monitor_core::api::HostClockAnchor;
use antinomie_triage::statistics::rate::Peak;
use eframe::egui::{self, Color32, Pos2, Rect, Stroke};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Marker {
    Circle,
    Square,
    Triangle,
    Diamond,
}

/// How line `i` is drawn: colour, dash pattern and end marker.
#[derive(Clone, Copy)]
pub(super) struct Style {
    pub glyph: &'static str,
    color: fn() -> Color32,
    pub dash: Option<(f32, f32)>,
    pub marker: Marker,
}

impl Style {
    pub(super) fn color(&self) -> Color32 {
        (self.color)()
    }
}

pub(super) fn style(index: usize) -> Style {
    match index % 4 {
        0 => Style {
            glyph: "●",
            color: theme::blue,
            dash: None,
            marker: Marker::Circle,
        },
        1 => Style {
            glyph: "■",
            color: theme::orange,
            dash: Some((7.0, 4.0)),
            marker: Marker::Square,
        },
        2 => Style {
            glyph: "▲",
            color: theme::good,
            dash: Some((2.0, 3.0)),
            marker: Marker::Triangle,
        },
        _ => Style {
            glyph: "◆",
            color: theme::info,
            dash: Some((12.0, 3.0)),
            marker: Marker::Diamond,
        },
    }
}

/// Most points one line is drawn with.
const MAX_POINTS: usize = 640;
const LEFT: f32 = 60.0;
const BOTTOM: f32 = 22.0;
const TOP: f32 = 10.0;
const RIGHT: f32 = 10.0;

/// The plot area and what it shows.
#[derive(Clone, Copy, Debug)]
pub(super) struct Geometry {
    pub rect: Rect,
    pub v0: f64,
    pub v1: f64,
    pub ymax: f64,
}

impl Geometry {
    pub(super) fn x_of(&self, ns: f64) -> f32 {
        self.rect.left() + ((ns - self.v0) / (self.v1 - self.v0)) as f32 * self.rect.width()
    }

    pub(super) fn t_of(&self, x: f32) -> f64 {
        self.v0 + f64::from((x - self.rect.left()) / self.rect.width()) * (self.v1 - self.v0)
    }

    pub(super) fn y_of(&self, n: f64) -> f32 {
        self.rect.bottom() - (n / self.ymax) as f32 * self.rect.height()
    }
}

/// The interval indices that touch `v0..v1`.
fn visible(plot: &Plot, v0: f64, v1: f64) -> std::ops::Range<usize> {
    let w = plot.width_ns as f64;
    let first = ((v0 - plot.start_ns as f64) / w).floor().max(0.0) as usize;
    let last = (((v1 - plot.start_ns as f64) / w).ceil().max(0.0) as usize).min(plot.intervals);
    first.min(last)..last
}

/// A top for the y axis: 1, 2 or 5 times a power of ten.
pub(super) fn nice_max(value: f64) -> f64 {
    if value <= 1.0 {
        return 1.0;
    }
    let power = 10_f64.powf(value.log10().floor());
    let scaled = value / power;
    let step = if scaled <= 1.0 {
        1.0
    } else if scaled <= 2.0 {
        2.0
    } else if scaled <= 5.0 {
        5.0
    } else {
        10.0
    };
    step * power
}

/// The points of one line: one per interval, or per pixel column (the largest
/// count in it) when intervals are narrower than a pixel.
pub(super) fn points(line: &PlotLine, plot: &Plot, g: &Geometry) -> Vec<Pos2> {
    let range = visible(plot, g.v0, g.v1);
    if line.counts.is_empty() || range.is_empty() {
        return Vec::new();
    }
    let w = plot.width_ns as f64;
    let centre = |i: usize| plot.start_ns as f64 + (i as f64 + 0.5) * w;
    let per_pixel = f64::from(g.rect.width()) * w / (g.v1 - g.v0);
    if per_pixel >= 1.0 && range.len() <= MAX_POINTS * 2 {
        return range
            .map(|i| Pos2::new(g.x_of(centre(i)), g.y_of(line.counts[i] as f64)))
            .collect();
    }
    // At most MAX_POINTS columns: a wider graph groups pixels, which keeps the
    // tessellation of four zigzagging lines within the frame budget.
    let group = (g.rect.width() / MAX_POINTS as f32).ceil().max(1.0);
    let columns = (g.rect.width() / group).ceil() as usize + 1;
    let mut best = vec![0_u64; columns];
    let mut seen = vec![false; columns];
    for i in range {
        let column =
            (((g.x_of(centre(i)) - g.rect.left()).max(0.0) / group) as usize).min(columns - 1);
        seen[column] = true;
        best[column] = best[column].max(line.counts[i]);
    }
    (0..columns)
        .filter(|c| seen[*c])
        .map(|c| {
            Pos2::new(
                g.rect.left() + (c as f32 + 0.5) * group,
                g.y_of(best[c] as f64),
            )
        })
        .collect()
}

fn marker(painter: &egui::Painter, at: Pos2, kind: Marker, color: Color32) {
    let r = 4.0;
    match kind {
        Marker::Circle => {
            painter.circle_filled(at, r, color);
        }
        Marker::Square => {
            painter.rect_filled(
                Rect::from_center_size(at, egui::vec2(2.0 * r, 2.0 * r)),
                0.0,
                color,
            );
        }
        Marker::Triangle => {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    at + egui::vec2(0.0, -r - 1.0),
                    at + egui::vec2(r + 1.0, r),
                    at + egui::vec2(-r - 1.0, r),
                ],
                color,
                Stroke::NONE,
            ));
        }
        Marker::Diamond => {
            painter.add(egui::Shape::convex_polygon(
                vec![
                    at + egui::vec2(0.0, -r - 1.0),
                    at + egui::vec2(r + 1.0, 0.0),
                    at + egui::vec2(0.0, r + 1.0),
                    at + egui::vec2(-r - 1.0, 0.0),
                ],
                color,
                Stroke::NONE,
            ));
        }
    }
}

/// Steps for the time axis, in ns.
const TICKS: [u64; 22] = [
    1_000_000,
    2_000_000,
    5_000_000,
    10_000_000,
    20_000_000,
    50_000_000,
    100_000_000,
    200_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
    10_000_000_000,
    30_000_000_000,
    60_000_000_000,
    120_000_000_000,
    300_000_000_000,
    600_000_000_000,
    1_800_000_000_000,
    3_600_000_000_000,
    7_200_000_000_000,
    21_600_000_000_000,
];

fn hatch(painter: &egui::Painter, band: Rect, color: Color32) {
    if band.width() < 12.0 {
        // Too narrow for stripes: a stronger tint, and the label is in the tooltip.
        painter.rect_filled(band, 0.0, color.gamma_multiply(0.45));
        return;
    }
    painter.rect_filled(band, 0.0, color.gamma_multiply(0.18));
    let stroke = Stroke::new(1.0, color.gamma_multiply(0.7));
    let painter = painter.with_clip_rect(band);
    let mut x = band.left() - band.height();
    while x < band.right() {
        painter.line_segment(
            [
                Pos2::new(x, band.bottom()),
                Pos2::new(x + band.height(), band.top()),
            ],
            stroke,
        );
        x += 7.0;
    }
}

/// A dashed line. Up to a few hundred points the dashes follow the path's length;
/// a thinned line (one point per pixel column, zigzagging) is dashed by columns
/// instead, so a frame draws a hundred pieces and not a hundred thousand.
fn dashed(painter: &egui::Painter, pts: &[Pos2], stroke: Stroke, dash: f32, gap: f32) {
    const FEW: usize = 400;
    if pts.len() <= FEW {
        painter.extend(egui::Shape::dashed_line(pts, stroke, dash, gap));
        return;
    }
    let mean_step = (pts[pts.len() - 1].x - pts[0].x) / (pts.len() - 1) as f32;
    let step = mean_step.max(0.1);
    let on = ((dash / step).round() as usize).max(2);
    let period = on + ((gap / step).round() as usize).max(1);
    let mut start = 0;
    while start + 1 < pts.len() {
        let end = (start + on).min(pts.len());
        painter.add(egui::Shape::line(pts[start..end].to_vec(), stroke));
        start += period;
    }
}

/// Everything the painter needs beside the plot.
pub(super) struct Marks<'a> {
    pub bands: &'a [Band],
    pub reduced_ns: Option<u64>,
    pub peak: Option<&'a Peak>,
    pub base: TimeBase,
    pub first_ns: Option<u64>,
    pub anchor: Option<HostClockAnchor>,
}

/// Paint the graph into `rect`; returns where things landed.
pub(super) fn paint(
    painter: &egui::Painter,
    rect: Rect,
    plot: &Plot,
    view: (f64, f64),
    marks: &Marks<'_>,
) -> Geometry {
    let mut g = Geometry {
        rect,
        v0: view.0,
        v1: view.1.max(view.0 + 1.0),
        ymax: 1.0,
    };
    let range = visible(plot, g.v0, g.v1);
    let top = plot
        .lines
        .iter()
        .flat_map(|line| {
            line.counts
                .get(range.clone())
                .unwrap_or(&[])
                .iter()
                .copied()
        })
        .max()
        .unwrap_or(0);
    g.ymax = nice_max(top as f64);
    painter.rect_filled(rect, 2.0, theme::panel());
    let font = egui::FontId::proportional(11.0);
    for step in 0..=4 {
        let n = g.ymax * f64::from(step) / 4.0;
        let y = g.y_of(n);
        painter.hline(rect.x_range(), y, Stroke::new(1.0, theme::line_soft()));
        painter.text(
            Pos2::new(rect.left() - 6.0, y),
            egui::Align2::RIGHT_CENTER,
            super::int(n as u64),
            font.clone(),
            theme::muted(),
        );
    }
    let span = g.v1 - g.v0;
    let step = TICKS
        .iter()
        .copied()
        .find(|t| span / *t as f64 <= 7.0)
        .unwrap_or(TICKS[TICKS.len() - 1]);
    let origin = marks.first_ns.unwrap_or(0);
    let mut t =
        origin + ((g.v0.max(origin as f64) - origin as f64) / step as f64).ceil() as u64 * step;
    let mut guard = 0;
    while (t as f64) <= g.v1 && guard < 32 {
        let x = g.x_of(t as f64);
        painter.vline(x, rect.y_range(), Stroke::new(1.0, theme::line_soft()));
        painter.text(
            Pos2::new(x, rect.bottom() + 3.0),
            egui::Align2::CENTER_TOP,
            time_text(marks.base, t, marks.first_ns, marks.anchor),
            font.clone(),
            theme::muted(),
        );
        t += step;
        guard += 1;
    }
    let clipped = painter.with_clip_rect(rect.expand(1.0));
    for band in marks.bands {
        let (x0, x1) = (g.x_of(band.start_ns as f64), g.x_of(band.end_ns as f64));
        if x1 < rect.left() || x0 > rect.right() {
            continue;
        }
        let area = Rect::from_x_y_ranges(
            x0.max(rect.left())..=x1.min(rect.right()).max(x0.max(rect.left()) + 1.0),
            rect.y_range(),
        );
        hatch(
            &clipped,
            area,
            if band.full_ring {
                theme::error()
            } else {
                theme::warn()
            },
        );
        let label = match (band.full_ring, area.width()) {
            (_, w) if w < 70.0 => None,
            (true, w) if w < 130.0 => Some("ring full"),
            (true, _) => Some("ring full here"),
            (false, w) if w < 150.0 => Some("no telemetry"),
            (false, _) => Some("no telemetry read here"),
        };
        if let Some(label) = label {
            clipped.text(
                area.left_top() + egui::vec2(4.0, 2.0),
                egui::Align2::LEFT_TOP,
                label,
                font.clone(),
                theme::text(),
            );
        }
    }
    if let Some(ns) = marks.reduced_ns {
        let x = g.x_of(ns as f64);
        if x >= rect.left() && x <= rect.right() {
            clipped.add(egui::Shape::dashed_line(
                &[Pos2::new(x, rect.top()), Pos2::new(x, rect.bottom())],
                Stroke::new(1.5, theme::warn()),
                5.0,
                3.0,
            ));
            clipped.text(
                Pos2::new(x + 4.0, rect.bottom() - 4.0),
                egui::Align2::LEFT_BOTTOM,
                "reduced recording from here",
                font.clone(),
                theme::warn(),
            );
        }
    }
    if let Some(peak) = marks.peak {
        let x = g.x_of((peak.start_ns + peak.span_ns / 2) as f64);
        if x >= rect.left() && x <= rect.right() {
            clipped.vline(x, rect.y_range(), Stroke::new(1.0, theme::muted()));
            clipped.text(
                Pos2::new(x + 3.0, rect.top() + 2.0),
                egui::Align2::LEFT_TOP,
                "peak",
                font.clone(),
                theme::muted(),
            );
        }
    }
    for (i, line) in plot.lines.iter().enumerate() {
        let style = style(i);
        let pts = points(line, plot, &g);
        if pts.is_empty() {
            continue;
        }
        let stroke = Stroke::new(1.8, style.color());
        match style.dash {
            None if pts.len() > 1 => {
                clipped.add(egui::Shape::line(pts.clone(), stroke));
            }
            Some((dash, gap)) if pts.len() > 1 => dashed(&clipped, &pts, stroke, dash, gap),
            _ => {}
        }
        if let Some(last) = pts.last() {
            marker(&clipped, *last, style.marker, style.color());
        }
    }
    painter.rect_stroke(
        rect,
        2.0,
        Stroke::new(1.0, theme::line()),
        egui::StrokeKind::Inside,
    );
    g
}

/// What the tooltip over interval `index` says.
pub(super) fn hover_lines(
    plot: &Plot,
    bands: &[Band],
    input: &Inputs<'_>,
    index: usize,
) -> Vec<String> {
    let (from, to) = (plot.interval_start(index), plot.interval_start(index + 1));
    let mut lines = vec![format!(
        "{} for {}",
        time_text(input.base, from, input.stats.first_ns, input.anchor),
        super::duration_ns(plot.width_ns)
    )];
    for (i, line) in plot.lines.iter().enumerate() {
        let count = line
            .counts
            .get(index)
            .map_or_else(|| "…".to_owned(), |n| super::int(*n));
        lines.push(format!("{} {}: {count}", style(i).glyph, line.kind.label()));
    }
    for band in bands.iter().filter(|b| b.start_ns < to && b.end_ns >= from) {
        lines.push(band.label.clone());
    }
    lines
}

/// Draw the graph, zoom and pan it, and answer a click.
pub(super) fn graph(
    ui: &mut egui::Ui,
    state: &mut State,
    plot: &Plot,
    bands: &[Band],
    input: &Inputs<'_>,
) -> Option<Click> {
    let size = egui::vec2(
        ui.available_width(),
        (ui.available_height() - 8.0).clamp(150.0, 640.0),
    );
    let (response, painter) = ui.allocate_painter(size, egui::Sense::click_and_drag());
    let rect = Rect::from_min_max(
        response.rect.min + egui::vec2(LEFT, TOP),
        response.rect.max - egui::vec2(RIGHT, BOTTOM),
    );
    let full = (plot.start_ns as f64, plot.end_ns() as f64);
    let mut view = state.view.unwrap_or(full);
    let min_span = (plot.width_ns as f64 * 4.0).min(full.1 - full.0);
    let pointer = response.hover_pos().filter(|p| rect.contains(*p));
    let geometry = Geometry {
        rect,
        v0: view.0,
        v1: view.1,
        ymax: 1.0,
    };
    if response.hovered() {
        let (zoom, scroll) = ui.input(|i| (i.zoom_delta(), i.smooth_scroll_delta.x));
        if zoom != 1.0 {
            let anchor = pointer.map_or((view.0 + view.1) / 2.0, |p| geometry.t_of(p.x));
            view = (
                anchor - (anchor - view.0) / f64::from(zoom),
                anchor + (view.1 - anchor) / f64::from(zoom),
            );
        }
        if scroll != 0.0 {
            let dt = -f64::from(scroll) * (view.1 - view.0) / f64::from(rect.width());
            view = (view.0 + dt, view.1 + dt);
        }
    }
    if response.dragged() {
        let dt = -f64::from(response.drag_delta().x) * (view.1 - view.0) / f64::from(rect.width());
        view = (view.0 + dt, view.1 + dt);
    }
    if response.has_focus() {
        let keys = ui.input(|i| {
            (
                i.key_pressed(egui::Key::ArrowLeft),
                i.key_pressed(egui::Key::ArrowRight),
                i.key_pressed(egui::Key::Plus) || i.key_pressed(egui::Key::Equals),
                i.key_pressed(egui::Key::Minus),
                i.key_pressed(egui::Key::Home),
            )
        });
        let span = view.1 - view.0;
        match keys {
            (true, ..) => view = (view.0 - span / 10.0, view.1 - span / 10.0),
            (_, true, ..) => view = (view.0 + span / 10.0, view.1 + span / 10.0),
            (_, _, true, ..) => view = (view.0 + span / 4.0, view.1 - span / 4.0),
            (_, _, _, true, _) => view = (view.0 - span / 2.0, view.1 + span / 2.0),
            (.., true) => view = full,
            _ => {}
        }
    }
    if response.double_clicked() {
        view = full;
    }
    state.view = clamp_view(view, full, min_span);
    let shown = state.view.unwrap_or(full);
    let g = paint(
        &painter,
        rect,
        plot,
        shown,
        &Marks {
            bands,
            reduced_ns: input.stats.quality.reduced.as_ref().map(|r| r.at_guest_ns),
            peak: input.stats.peak_per_s.as_ref(),
            base: input.base,
            first_ns: input.stats.first_ns,
            anchor: input.anchor,
        },
    );
    state.shape = Some(g);
    let index = pointer.and_then(|p| plot.index_of(g.t_of(p.x)));
    if let (Some(p), Some(index)) = (pointer, index) {
        painter.vline(p.x, rect.y_range(), Stroke::new(1.0, theme::muted()));
        response.clone().on_hover_ui_at_pointer(|ui| {
            for line in hover_lines(plot, bands, input, index) {
                ui.label(line);
            }
            ui.colored_label(
                theme::muted(),
                "Click to open this line's calls of this interval in the Syscall Trace.",
            );
        });
    }
    if response.clicked() {
        response.request_focus();
        if let (Some(p), Some(index)) = (pointer, index) {
            return nearest(plot, &g, p, index)
                .map(|line| click_of(plot, &plot.lines[line].kind, index));
        }
    }
    None
}

/// The line whose point in interval `index` is nearest the pointer, among those with calls there.
pub(super) fn nearest(plot: &Plot, g: &Geometry, pointer: Pos2, index: usize) -> Option<usize> {
    plot.lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| {
            let n = *line.counts.get(index)?;
            (n > 0).then(|| (i, (g.y_of(n as f64) - pointer.y).abs()))
        })
        .min_by(|a, b| a.1.total_cmp(&b.1))
        .map(|(i, _)| i)
}

/// `None` when the view is the whole run; otherwise the view kept inside it
/// and no narrower than `min_span`.
pub(super) fn clamp_view(view: (f64, f64), full: (f64, f64), min_span: f64) -> Option<(f64, f64)> {
    let whole = full.1 - full.0;
    let span = (view.1 - view.0).clamp(min_span.min(whole), whole);
    if span >= whole * 0.999 {
        return None;
    }
    let centre = (view.0 + view.1) / 2.0;
    let mut v0 = centre - span / 2.0;
    if v0 < full.0 {
        v0 = full.0;
    }
    if v0 + span > full.1 {
        v0 = full.1 - span;
    }
    Some((v0, v0 + span))
}

// SPDX-License-Identifier: GPL-3.0-only
//! Colors and shapes of the graph: the glyph of each category, the phase band,
//! the severity curve, the category heat strip and the time axis.
use super::index::GraphIndex;
use super::phases::Phase;
use super::view::{Frame, HEAT_ROW_H, MIN_BUCKET_PX};
use super::*;
use crate::theme::Palette;
use eframe::egui::{Align2, Color32, FontId, Painter, Pos2, Rect, Shape, Stroke, Vec2};

/// Every color the graph draws with, read from one palette.
#[derive(Clone, Copy, Debug)]
pub(in crate::triage) struct Colors {
    pub bg: Color32,
    pub panel: Color32,
    pub line: Color32,
    pub text: Color32,
    pub muted: Color32,
    pub stripe: Color32,
    pub accent: Color32,
    pub selection: Color32,
    /// HIGH, MEDIUM, LOW and INFO.
    pub tier: [Color32; 4],
    pub injection: Color32,
}

impl Colors {
    pub(in crate::triage) fn of(palette: &Palette) -> Self {
        Self {
            bg: palette.bg,
            panel: palette.panel,
            line: palette.line,
            text: palette.text,
            muted: palette.muted,
            stripe: palette.stripe,
            accent: palette.accent,
            selection: palette.selection,
            tier: [palette.error, palette.warn, palette.info, palette.muted],
            injection: palette.error,
        }
    }

    pub(in crate::triage) fn current() -> Self {
        Self::of(theme::palette())
    }

    /// The color of a lane row: the table's stripe on every second one.
    pub(in crate::triage) fn lane(&self, row: usize) -> Color32 {
        if row % 2 == 1 {
            blend(self.bg, self.stripe)
        } else {
            self.bg
        }
    }
}

/// `over` laid on `under`.
pub(in crate::triage) fn blend(under: Color32, over: Color32) -> Color32 {
    let alpha = f32::from(over.a()) / 255.0;
    let mix = |below: u8, above: u8| {
        // `over` is premultiplied, as egui keeps colors.
        (f32::from(above) + f32::from(below) * (1.0 - alpha))
            .round()
            .clamp(0.0, 255.0) as u8
    };
    Color32::from_rgb(
        mix(under.r(), over.r()),
        mix(under.g(), over.g()),
        mix(under.b(), over.b()),
    )
}

#[cfg(test)]
fn linear(channel: u8) -> f64 {
    let value = f64::from(channel) / 255.0;
    if value <= 0.04045 {
        value / 12.92
    } else {
        ((value + 0.055) / 1.055).powf(2.4)
    }
}

/// WCAG contrast ratio of two opaque colors.
#[cfg(test)]
pub(in crate::triage) fn contrast(a: Color32, b: Color32) -> f64 {
    let luminance =
        |c: Color32| 0.2126 * linear(c.r()) + 0.7152 * linear(c.g()) + 0.0722 * linear(c.b());
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// The shape of a category's marker, by [`Category::index`] in `Category::ALL`:
/// Execution ●, Persistence ■, Privilege ▲, Evasion ◆, Credential ⬟,
/// Discovery ○, Injection ✚, C2 ★, Rootkit ⬢, Impact ✖, Collection ▼,
/// Lateral ⇄, Exfiltration ⬆.
pub(in crate::triage) fn glyph(
    shapes: &mut Vec<Shape>,
    category: u8,
    center: Pos2,
    r: f32,
    color: Color32,
    hollow: bool,
) {
    let line = Stroke::new(if r < 4.0 { 1.2_f32 } else { 1.6_f32 }, color);
    let polygon = |points: Vec<Pos2>| {
        if hollow {
            Shape::closed_line(points, line)
        } else {
            Shape::convex_polygon(points, color, Stroke::NONE)
        }
    };
    let ring = |sides: usize, turn: f32| {
        (0..sides)
            .map(|i| {
                let angle = turn + std::f32::consts::TAU * i as f32 / sides as f32;
                center + Vec2::new(angle.cos(), angle.sin()) * r
            })
            .collect::<Vec<_>>()
    };
    let up = -std::f32::consts::FRAC_PI_2;
    let shape = match category {
        0 if hollow => Shape::circle_stroke(center, r, line),
        0 => Shape::circle_filled(center, r, color),
        1 => {
            let rect = Rect::from_center_size(center, Vec2::splat(r * 1.7));
            if hollow {
                Shape::rect_stroke(rect, 0.0, line, eframe::egui::StrokeKind::Inside)
            } else {
                Shape::rect_filled(rect, 0.0, color)
            }
        }
        2 => polygon(ring(3, up)),
        3 => polygon(ring(4, up)),
        4 => polygon(ring(5, up)),
        5 => Shape::circle_stroke(center, r, Stroke::new(line.width * 1.2, color)),
        6 => {
            let arm = r * 1.1;
            let width = Stroke::new(line.width * 1.4, color);
            shapes.push(Shape::line_segment(
                [center - Vec2::X * arm, center + Vec2::X * arm],
                width,
            ));
            Shape::line_segment([center - Vec2::Y * arm, center + Vec2::Y * arm], width)
        }
        7 => star(center, r * 1.25, color, hollow, line),
        8 => polygon(ring(6, 0.0)),
        9 => {
            let arm = r * 0.9;
            let width = Stroke::new(line.width * 1.4, color);
            shapes.push(Shape::line_segment(
                [center + Vec2::new(-arm, -arm), center + Vec2::new(arm, arm)],
                width,
            ));
            Shape::line_segment(
                [center + Vec2::new(-arm, arm), center + Vec2::new(arm, -arm)],
                width,
            )
        }
        10 => polygon(ring(3, -up)),
        11 => {
            for shift in [-r * 0.55, r * 0.55] {
                let tip = center + Vec2::new(shift + r * 0.4, 0.0);
                shapes.push(Shape::line(
                    vec![
                        tip + Vec2::new(-r * 0.7, -r),
                        tip,
                        tip + Vec2::new(-r * 0.7, r),
                    ],
                    line,
                ));
            }
            return;
        }
        _ => {
            shapes.push(Shape::line_segment(
                [
                    center + Vec2::new(0.0, r),
                    center + Vec2::new(0.0, -r * 0.3),
                ],
                Stroke::new(line.width * 1.4, color),
            ));
            polygon(vec![
                center + Vec2::new(0.0, -r),
                center + Vec2::new(-r * 0.9, -r * 0.1),
                center + Vec2::new(r * 0.9, -r * 0.1),
            ])
        }
    };
    shapes.push(shape);
}

fn star(center: Pos2, r: f32, color: Color32, hollow: bool, line: Stroke) -> Shape {
    let points: Vec<Pos2> = (0..10)
        .map(|i| {
            let angle = -std::f32::consts::FRAC_PI_2 + std::f32::consts::TAU * i as f32 / 10.0;
            let radius = if i % 2 == 0 { r } else { r * 0.45 };
            center + Vec2::new(angle.cos(), angle.sin()) * radius
        })
        .collect();
    if hollow {
        return Shape::closed_line(points, line);
    }
    // A star is not convex: fill it as a fan around its center.
    let mut mesh = eframe::egui::epaint::Mesh::default();
    mesh.colored_vertex(center, color);
    for point in &points {
        mesh.colored_vertex(*point, color);
    }
    for i in 0..10u32 {
        mesh.add_triangle(0, 1 + i, 1 + (i + 1) % 10);
    }
    Shape::mesh(mesh)
}

pub(in crate::triage) fn label(
    painter: &Painter,
    pos: Pos2,
    align: Align2,
    text: &str,
    size: f32,
    color: Color32,
) {
    painter.text(pos, align, text, FontId::proportional(size), color);
}

/// The phase band, with each span's label when it fits.
pub(super) fn phase_band(painter: &Painter, frame: &Frame, index: &GraphIndex, colors: &Colors) {
    painter.rect_filled(frame.phases, 2.0, colors.bg);
    let Some(geometry) = index.geometry else {
        return;
    };
    let painter = painter.with_clip_rect(frame.phases);
    for span in &index.phases {
        let from = frame.x(geometry.start(0, span.first as usize));
        let to = frame.x(geometry.start(0, span.last as usize + 1));
        if to < frame.phases.left() || from > frame.phases.right() {
            continue;
        }
        let rect = Rect::from_min_max(
            Pos2::new(from.max(frame.phases.left()), frame.phases.top()),
            Pos2::new(to.min(frame.phases.right()), frame.phases.bottom()),
        );
        let tint = phase_color(span.phase, colors);
        painter.rect_filled(
            rect.shrink2(Vec2::new(0.0, 1.0)),
            2.0,
            tint.gamma_multiply(0.35),
        );
        painter.rect_stroke(
            rect.shrink2(Vec2::new(0.0, 1.0)),
            2.0,
            Stroke::new(1.0_f32, tint.gamma_multiply(0.8)),
            eframe::egui::StrokeKind::Inside,
        );
        let font = FontId::proportional(11.0);
        let text = painter.layout_no_wrap(span.phase.label().to_owned(), font, colors.text);
        // The label only when it fits inside the span.
        if text.size().x + 6.0 <= rect.width() {
            painter.galley(rect.center() - text.size() / 2.0, text, colors.text);
        }
    }
}

/// A phase's color, from the tier colors and the accent so the band reads in every theme.
pub(super) fn phase_color(phase: Phase, colors: &Colors) -> Color32 {
    match phase {
        Phase::Recon => colors.muted,
        Phase::Download => colors.accent,
        Phase::Persistence => colors.tier[2],
        Phase::Escalation | Phase::Hide => colors.tier[1],
        Phase::C2 | Phase::Impact => colors.tier[0],
        Phase::Spread => colors.accent,
    }
}

/// How the level for the visible window is chosen, and its buckets in view.
pub(super) fn visible_buckets(index: &GraphIndex, frame: &Frame) -> (usize, u32, u32) {
    let level = index.level_for(frame.ns_per_px(), MIN_BUCKET_PX);
    let geometry = index.geometry();
    let width = geometry.width(level);
    let low = (((frame.t0 - geometry.origin as f64) / width)
        .floor()
        .max(0.0)) as u32;
    let high = (((frame.t1 - geometry.origin as f64) / width)
        .ceil()
        .max(0.0)) as u32;
    (level, low, high)
}

/// The severity curve: a stacked area per tier, height the sum of weights per
/// bucket, scaled to the largest bucket in view. Returns that largest weight.
pub(super) fn severity_curve(
    painter: &Painter,
    frame: &Frame,
    index: &GraphIndex,
    colors: &Colors,
) -> u32 {
    painter.rect_filled(frame.curve, 2.0, colors.bg);
    let Some(geometry) = index.geometry else {
        return 0;
    };
    let (level, low, high) = visible_buckets(index, frame);
    let Some(bins) = index.bins.get(level) else {
        return 0;
    };
    let range = (low as usize).min(bins.len())..(high as usize + 1).min(bins.len());
    let tallest = bins[range.clone()]
        .iter()
        .map(|bin| bin.weight())
        .max()
        .unwrap_or(0);
    if tallest == 0 {
        return 0;
    }
    let painter = painter.with_clip_rect(frame.curve);
    let scale = (frame.curve.height() - 3.0) / tallest as f32;
    let width = geometry.width(level);
    let mut shapes = Vec::with_capacity(range.len() * 3);
    for at in range {
        let bin = &bins[at];
        if bin.weight() == 0 {
            continue;
        }
        let from = frame.x(geometry.origin as f64 + at as f64 * width);
        let to = frame
            .x(geometry.origin as f64 + (at + 1) as f64 * width)
            .max(from + 1.0);
        let mut base = frame.curve.bottom() - 1.0;
        // HIGH at the bottom, then MEDIUM, then LOW: the tier that matters sits on the floor.
        for tier in 0..3 {
            let height = bin.weight_of(tier) as f32 * scale;
            if height <= 0.0 {
                continue;
            }
            let rect = Rect::from_min_max(Pos2::new(from, base - height), Pos2::new(to, base));
            shapes.push(Shape::rect_filled(
                rect,
                0.0,
                colors.tier[tier].gamma_multiply(0.6),
            ));
            base -= height;
        }
    }
    painter.extend(shapes);
    tallest
}

/// The heat strip: one row per category present, one cell per bucket, alpha
/// the log of the count and hue the worst tier in the cell.
pub(super) fn heat_strip(
    painter: &Painter,
    frame: &Frame,
    index: &GraphIndex,
    colors: &Colors,
    categories: &[usize],
) {
    let Some(geometry) = index.geometry else {
        return;
    };
    let (level, low, high) = visible_buckets(index, frame);
    let Some(bins) = index.bins.get(level) else {
        return;
    };
    let range = (low as usize).min(bins.len())..(high as usize + 1).min(bins.len());
    let tallest = bins[range.clone()]
        .iter()
        .flat_map(|bin| bin.cats.iter().copied())
        .max()
        .unwrap_or(0)
        .max(1);
    let scale = (1.0 + tallest as f32).ln();
    let painter = painter.with_clip_rect(frame.heat);
    let width = geometry.width(level);
    let mut shapes = Vec::new();
    for (row, category) in categories.iter().enumerate() {
        let top = frame.heat.top() + row as f32 * HEAT_ROW_H;
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(frame.heat.left(), top + 1.0),
                Pos2::new(frame.heat.right(), top + HEAT_ROW_H - 1.0),
            ),
            1.0,
            colors.bg,
        );
        for at in range.clone() {
            let count = bins[at].cats[*category];
            if count == 0 {
                continue;
            }
            let from = frame.x(geometry.origin as f64 + at as f64 * width);
            let to = frame
                .x(geometry.origin as f64 + (at + 1) as f64 * width)
                .max(from + 1.0);
            let tier = usize::from(bins[at].top[*category]).min(3);
            let alpha = ((1.0 + count as f32).ln() / scale).clamp(0.2, 1.0);
            shapes.push(Shape::rect_filled(
                Rect::from_min_max(
                    Pos2::new(from, top + 1.0),
                    Pos2::new(to, top + HEAT_ROW_H - 1.0),
                ),
                0.0,
                colors.tier[tier].gamma_multiply(alpha),
            ));
        }
    }
    painter.extend(shapes);
}

/// The time axis: ticks at round times, labelled in host time when the run
/// has an anchor and in seconds from the start otherwise.
pub(super) fn axis(
    painter: &Painter,
    frame: &Frame,
    origin: u64,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    colors: &Colors,
    right: f32,
) {
    let mut clip = frame.axis;
    clip.max.x = clip.max.x.min(right);
    let painter = painter.with_clip_rect(clip);
    painter.line_segment(
        [frame.axis.left_top(), frame.axis.right_top()],
        Stroke::new(1.0_f32, colors.line),
    );
    let step = view::tick_step(frame.ns_per_px(), 110.0);
    let mut tick = (frame.t0 / step).ceil() * step;
    let mut drawn = 0;
    while tick <= frame.t1 && drawn < 64 {
        let x = frame.x(tick);
        painter.line_segment(
            [
                Pos2::new(x, frame.axis.top()),
                Pos2::new(x, frame.axis.top() + 5.0),
            ],
            Stroke::new(1.0_f32, colors.muted),
        );
        painter.text(
            Pos2::new(x + 3.0, frame.axis.top() + 6.0),
            Align2::LEFT_TOP,
            axis_label(tick as u64, step, origin, clock),
            FontId::proportional(11.0),
            colors.muted,
        );
        tick += step;
        drawn += 1;
    }
}

/// The text of one tick.
pub(in crate::triage) fn axis_label(
    ns: u64,
    step: f64,
    origin: u64,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> String {
    match clock.and_then(|clock| clock.host_us(ns)) {
        Some(us) => crate::time_format::axis_time(us, step < 1e9),
        None => {
            let seconds = ns.saturating_sub(origin) as f64 / 1e9;
            if step >= 1e9 {
                format!("+{seconds:.0} s")
            } else if step >= 1e6 {
                format!("+{seconds:.3} s")
            } else {
                format!("+{:.0} µs", seconds * 1e6)
            }
        }
    }
}

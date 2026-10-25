// SPDX-License-Identifier: GPL-3.0-only
//! Colors and shapes of the graph: the icon of each category, the phase band,
//! the severity curve, the category heat strip and the time axis.
use super::index::GraphIndex;
use super::phases::Phase;
use super::view::{Frame, MIN_BUCKET_PX};
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

/// The Phosphor icon of each category, by [`Category::index`] in
/// `Category::ALL`: Execution play, Persistence anchor, Privilege arrow up,
/// Evasion eye-slash, Credential key, Discovery magnifier, Injection syringe,
/// C2 broadcast, Rootkit skull, Impact fire, Collection tray, Lateral arrows,
/// Exfiltration upload.
const ICONS: [&str; 13] = [
    egui_phosphor::regular::PLAY,
    egui_phosphor::regular::ANCHOR,
    egui_phosphor::regular::ARROW_FAT_UP,
    egui_phosphor::regular::EYE_SLASH,
    egui_phosphor::regular::KEY,
    egui_phosphor::regular::MAGNIFYING_GLASS,
    egui_phosphor::regular::SYRINGE,
    egui_phosphor::regular::BROADCAST,
    egui_phosphor::regular::SKULL,
    egui_phosphor::regular::FIRE,
    egui_phosphor::regular::TRAY_ARROW_DOWN,
    egui_phosphor::regular::ARROWS_LEFT_RIGHT,
    egui_phosphor::regular::UPLOAD_SIMPLE,
];

pub(in crate::triage) fn icon(category: u8) -> &'static str {
    ICONS[usize::from(category).min(ICONS.len() - 1)]
}

/// An icon colour that reads on a disc filled with `fill`.
pub(in crate::triage) fn ink(fill: Color32) -> Color32 {
    let luminance =
        0.299 * f32::from(fill.r()) + 0.587 * f32::from(fill.g()) + 0.114 * f32::from(fill.b());
    if luminance > 150.0 {
        Color32::from_rgb(18, 20, 26)
    } else {
        Color32::WHITE
    }
}

/// A finding's marker: its category's icon on a disc of the tier's colour;
/// a hollow disc in the tier's colour when only packets showed it.
pub(in crate::triage) fn marker(
    painter: &Painter,
    shapes: &mut Vec<Shape>,
    category: u8,
    center: Pos2,
    r: f32,
    color: Color32,
    hollow: bool,
) {
    let radius = r * 1.15;
    let icon_color = if hollow {
        shapes.push(Shape::circle_stroke(
            center,
            radius,
            Stroke::new(1.5_f32, color),
        ));
        color
    } else {
        shapes.push(Shape::circle_filled(center, radius, color));
        ink(color)
    };
    let galley = painter.layout_no_wrap(
        icon(category).to_owned(),
        FontId::proportional(radius * 1.35),
        icon_color,
    );
    let at = center - galley.size() / 2.0;
    shapes.push(Shape::galley(at, galley, icon_color));
}

/// A plain tier dot: what a dense or zoomed-out view draws instead of icons.
pub(in crate::triage) fn dot(shapes: &mut Vec<Shape>, center: Pos2, r: f32, color: Color32) {
    shapes.push(Shape::circle_filled(center, r, color));
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
        let font = FontId::proportional(11.0 * frame.m.text);
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
    let (ns0, ns1) = frame.ns_range();
    let low = (((ns0 - geometry.origin as f64) / width).floor().max(0.0)) as u32;
    let high = (((ns1 - geometry.origin as f64) / width).ceil().max(0.0)) as u32;
    (level, low, high)
}

/// What the severity curve and the heat strip draw: bins across the window and
/// the x of each one's left edge.
pub(super) struct Series<'a> {
    pub bins: std::borrow::Cow<'a, [super::index::Bin]>,
    pub range: std::ops::Range<usize>,
    pub edge: Box<dyn Fn(usize) -> f32 + 'a>,
}

/// The bins of the window. In Time spacing they are the pyramid's; in Events
/// spacing the buckets would be uneven on screen, so the findings of the window
/// are counted into columns of a few pixels.
pub(super) fn series<'a>(
    frame: &'a Frame,
    index: &'a GraphIndex,
    pass: Option<&'a EventPass>,
) -> Option<Series<'a>> {
    let geometry = index.geometry?;
    if let Some(pass) = pass {
        let step = frame.plot.width() / pass.columns as f32;
        let left = frame.plot.left();
        return Some(Series {
            bins: std::borrow::Cow::Borrowed(pass.bins.as_slice()),
            range: 0..pass.columns,
            edge: Box::new(move |at| left + at as f32 * step),
        });
    }
    if frame.map.spacing == super::axis::Spacing::Events && !frame.map.slots.times.is_empty() {
        let columns = (frame.plot.width() / MIN_BUCKET_PX as f32).ceil().max(1.0) as usize;
        let mut bins = vec![super::index::Bin::default(); columns];
        let (ns0, ns1) = frame.ns_range();
        for record in &index.records[index.window(ns0, ns1)] {
            let share = (f64::from(record.slot) - frame.t0) / (frame.t1 - frame.t0);
            let column = (share * columns as f64).floor();
            if (0.0..columns as f64).contains(&column) {
                bins[column as usize].add(record);
            }
        }
        let step = frame.plot.width() / columns as f32;
        let left = frame.plot.left();
        return Some(Series {
            bins: std::borrow::Cow::Owned(bins),
            range: 0..columns,
            edge: Box::new(move |at| left + at as f32 * step),
        });
    }
    let (level, low, high) = visible_buckets(index, frame);
    let bins = index.bins.get(level)?;
    let range = (low as usize).min(bins.len())..(high as usize + 1).min(bins.len());
    let width = geometry.width(level);
    Some(Series {
        bins: std::borrow::Cow::Borrowed(bins.as_slice()),
        range,
        edge: Box::new(move |at| frame.x(geometry.origin as f64 + at as f64 * width)),
    })
}

/// One pass over the findings of the window in Events spacing, shared by the
/// severity curve, the heat strip and the markers: each finding is put into a
/// column of a few pixels, in the bins of the curve and, on a visible row, in
/// that row's cell.
pub(super) struct EventPass {
    pub columns: usize,
    pub bins: Vec<super::index::Bin>,
    /// One per visible row and column, row after row, from `first_row`.
    pub cells: Vec<Option<super::index::Cell>>,
    pub first_row: usize,
}

/// The pass for `layout`, or `None` when the spacing is Time (the pyramid does
/// that) or the window holds few findings (they are drawn one by one).
pub(super) fn event_pass(
    layout: &super::input::Layout,
    index: &GraphIndex,
    rows: std::ops::Range<usize>,
) -> Option<EventPass> {
    let frame = &layout.frame;
    if frame.map.spacing != super::axis::Spacing::Events || frame.map.slots.times.is_empty() {
        return None;
    }
    let columns = (frame.plot.width() / MIN_BUCKET_PX as f32).ceil().max(1.0) as usize;
    let mut bins = vec![super::index::Bin::default(); columns];
    let mut cells: Vec<Option<super::index::Cell>> = vec![None; rows.len() * columns];
    let (ns0, ns1) = frame.ns_range();
    let scale = columns as f64 / (frame.t1 - frame.t0);
    let window = index.window(ns0, ns1);
    let begins = window.start;
    for (at, record) in index.records[window].iter().enumerate() {
        let column = ((f64::from(record.slot) - frame.t0) * scale).floor();
        if !(0.0..columns as f64).contains(&column) {
            continue;
        }
        let column = column as usize;
        bins[column].add(record);
        let Some(row) = layout.row_of(record.lane).filter(|row| rows.contains(row)) else {
            continue;
        };
        match &mut cells[(row - rows.start) * columns + column] {
            Some(cell) => cell.add(record),
            none => {
                *none = Some(super::index::Cell::of(record, begins + at, column as u32));
            }
        }
    }
    Some(EventPass {
        columns,
        bins,
        cells,
        first_row: rows.start,
    })
}

/// The severity curve: a stacked area per tier, height the sum of weights per
/// bucket, scaled to the largest bucket in view. Returns that largest weight.
pub(super) fn severity_curve(
    painter: &Painter,
    frame: &Frame,
    index: &GraphIndex,
    colors: &Colors,
    pass: Option<&EventPass>,
) -> u32 {
    painter.rect_filled(frame.curve, 2.0, colors.bg);
    let Some(Series { bins, range, edge }) = series(frame, index, pass) else {
        return 0;
    };
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
    let mut shapes = Vec::with_capacity(range.len() * 3);
    for at in range {
        let bin = &bins[at];
        if bin.weight() == 0 {
            continue;
        }
        let from = edge(at);
        let to = edge(at + 1).max(from + 1.0);
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
    pass: Option<&EventPass>,
) {
    let Some(Series { bins, range, edge }) = series(frame, index, pass) else {
        return;
    };
    let tallest = bins[range.clone()]
        .iter()
        .flat_map(|bin| bin.cats.iter().copied())
        .max()
        .unwrap_or(0)
        .max(1);
    let scale = (1.0 + tallest as f32).ln();
    let painter = painter.with_clip_rect(frame.heat);
    let mut shapes = Vec::new();
    for (row, category) in categories.iter().enumerate() {
        let top = frame.heat.top() + row as f32 * frame.m.heat_h;
        painter.rect_filled(
            Rect::from_min_max(
                Pos2::new(frame.heat.left(), top + 1.0),
                Pos2::new(frame.heat.right(), top + frame.m.heat_h - 1.0),
            ),
            1.0,
            colors.bg,
        );
        for at in range.clone() {
            let count = bins[at].cats[*category];
            if count == 0 {
                continue;
            }
            let from = edge(at);
            let to = edge(at + 1).max(from + 1.0);
            let tier = usize::from(bins[at].top[*category]).min(3);
            let alpha = ((1.0 + count as f32).ln() / scale).clamp(0.2, 1.0);
            shapes.push(Shape::rect_filled(
                Rect::from_min_max(
                    Pos2::new(from, top + 1.0),
                    Pos2::new(to, top + frame.m.heat_h - 1.0),
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
    let ticks = tick_marks(frame);
    let step_ns = ticks
        .windows(2)
        .map(|pair| pair[1].1 - pair[0].1)
        .fold(f64::MAX, f64::min);
    // One tick alone says nothing of its spacing: label it to the millisecond.
    let step_ns = if step_ns == f64::MAX { 1e6 } else { step_ns };
    for (x, ns) in ticks {
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
            axis_label(ns.max(0.0) as u64, step_ns, origin, clock),
            FontId::proportional(11.0 * frame.m.text),
            colors.muted,
        );
    }
}

/// The ticks of the axis: the x and the time of each. In Time spacing they are
/// at round times; in Events spacing at slot boundaries, so each label is the
/// real time of a slot, and the labels are further apart where findings are
/// scarce in time.
pub(super) fn tick_marks(frame: &Frame) -> Vec<(f32, f64)> {
    let mut ticks = Vec::new();
    if frame.map.spacing == super::axis::Spacing::Events && !frame.map.slots.times.is_empty() {
        let times = &frame.map.slots.times;
        let step = view::tick_step(frame.u_per_px(), 110.0 * f64::from(frame.m.text.max(1.0)))
            .max(1.0)
            .round();
        let mut at = (frame.t0 / step).ceil() * step;
        while at <= frame.t1 && ticks.len() < 64 {
            if at >= 0.0 && (at as usize) < times.len() {
                ticks.push((frame.x_u(at), times[at as usize] as f64));
            }
            at += step;
        }
        return ticks;
    }
    let step = view::tick_step(frame.ns_per_px(), 110.0 * f64::from(frame.m.text.max(1.0)));
    let mut tick = (frame.t0 / step).ceil() * step;
    while tick <= frame.t1 && ticks.len() < 64 {
        ticks.push((frame.x(tick), tick));
        tick += step;
    }
    ticks
}

/// How long a gap in time is, in words.
pub(in crate::triage) fn gap_text(ns: u64) -> String {
    let ns = ns as f64;
    if ns < 1e3 {
        format!("{ns:.0} ns")
    } else if ns < 1e6 {
        format!("{:.0} µs", ns / 1e3)
    } else if ns < 1e9 {
        format!("{:.0} ms", ns / 1e6)
    } else if ns < 60e9 {
        format!("{:.1} s", ns / 1e9)
    } else if ns < 3600e9 {
        format!("{:.1} min", ns / 60e9)
    } else {
        format!("{:.1} h", ns / 3600e9)
    }
}

/// The breaks of Events spacing: where a long stretch of time with nothing in
/// it was squeezed into one slot's width, a slanted pair of strokes on the axis,
/// the length of the gap and a faint line up the plot.
pub(super) fn breaks(painter: &Painter, frame: &Frame, colors: &Colors, right: f32) {
    if frame.map.spacing != super::axis::Spacing::Events {
        return;
    }
    let colour = colors.tier[1];
    for (slot, gap) in frame.map.slots.breaks.iter() {
        let x = frame.x_u(f64::from(*slot) + 0.5);
        if x < frame.plot.left() + 2.0 || x > frame.plot.right() - 2.0 {
            continue;
        }
        painter.line_segment(
            [
                Pos2::new(x, frame.phases.top()),
                Pos2::new(x, frame.axis.top()),
            ],
            Stroke::new(1.0_f32, colour.gamma_multiply(0.22)),
        );
        let middle = frame.axis.top();
        for shift in [-2.0, 2.0] {
            painter.line_segment(
                [
                    Pos2::new(x + shift - 3.0, middle + 6.0),
                    Pos2::new(x + shift + 3.0, middle - 6.0),
                ],
                Stroke::new(1.6_f32, colour),
            );
        }
        if x < right - 50.0 {
            painter.text(
                Pos2::new(x + 7.0, middle - 9.0),
                Align2::LEFT_CENTER,
                gap_text(*gap),
                FontId::proportional(10.0 * frame.m.text),
                colour,
            );
        }
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
        Some(us) => crate::time_format::axis_time(us, step),
        None => {
            let seconds = ns.saturating_sub(origin) as f64 / 1e9;
            if step >= 1e9 {
                format!("+{seconds:.0} s")
            } else if step >= 1e6 {
                format!("+{seconds:.3} s")
            } else if step >= 1e3 {
                format!("+{:.0} µs", seconds * 1e6)
            } else {
                format!("+{} ns", ns.saturating_sub(origin))
            }
        }
    }
}

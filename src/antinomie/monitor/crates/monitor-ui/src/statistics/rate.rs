// SPDX-License-Identifier: GPL-3.0-only
//! The Call rate tab (design 2.4): calls per interval over the run, up to four
//! lines, with the recording's own holes drawn on the graph. This file holds
//! the model (what is drawn, built by pure functions so the tests can read it)
//! and the tab around the graph; `rate_paint.rs` draws and handles the pointer.
use super::hierarchy::Click;
use super::navigate::and;
use super::rate_lines::{LineKind, Lines};
use super::worker::{Phase, Where};
use super::{time_text, TimeBase};
use antinomie_monitor_core::api::HostClockAnchor;
use antinomie_triage::statistics::export::{Cell, Table};
use antinomie_triage::statistics::rate::{Peak, Rate, FIRST_WIDTH_NS};
use antinomie_triage::statistics::RunStatistics;
use eframe::egui;

/// The intervals the menu offers, shortest first.
pub(super) const INTERVALS: [(&str, u64); 15] = [
    ("1 ms", 1_000_000),
    ("2 ms", 2_000_000),
    ("5 ms", 5_000_000),
    ("10 ms", 10_000_000),
    ("20 ms", 20_000_000),
    ("50 ms", 50_000_000),
    ("100 ms", 100_000_000),
    ("200 ms", 200_000_000),
    ("500 ms", 500_000_000),
    ("1 s", 1_000_000_000),
    ("2 s", 2_000_000_000),
    ("5 s", 5_000_000_000),
    ("10 s", 10_000_000_000),
    ("30 s", 30_000_000_000),
    ("1 min", 60_000_000_000),
];
/// Auto aims at about this many intervals across the run.
const AUTO_BUCKETS: u64 = 400;

/// What the person chose; kept while the window lives.
#[derive(Default)]
pub(super) struct State {
    pub lines: Lines,
    /// `None` is Auto.
    pub interval: Option<u64>,
    /// Show the numbers instead of the graph.
    pub table: bool,
    /// Zoom: the guest time range on view, `None` for the whole run.
    pub view: Option<(f64, f64)>,
    /// Where the graph was drawn last frame (the tests click on it).
    pub shape: Option<super::rate_paint::Geometry>,
}

/// How a custom line stands, for its legend chip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum LineProgress {
    Ready,
    /// Waiting for the main read to end.
    Waiting,
    /// Reading; the share is known once the walk counts the calls.
    Reading(Option<u64>),
    Stopped,
    Failed(String),
}

impl LineProgress {
    /// From the extra walk's phase.
    pub(super) fn of(phase: &Phase, main_running: bool, have_result: bool) -> Self {
        match phase {
            Phase::Running(Where::Reading { read, total }) => {
                Self::Reading(Some(if *total == 0 { 0 } else { read * 100 / total }))
            }
            Phase::Running(_) => Self::Reading(None),
            Phase::Stopped => Self::Stopped,
            Phase::Failed(error) => Self::Failed(error.clone()),
            Phase::Done => Self::Ready,
            Phase::Idle if main_running || !have_result => Self::Waiting,
            Phase::Idle => Self::Ready,
        }
    }
}

/// One line of the plot.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct PlotLine {
    pub kind: LineKind,
    /// Calls per interval; empty while a custom line has no result yet.
    pub counts: Vec<u64>,
    pub progress: LineProgress,
}

/// All lines on one timeline of equal intervals.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Plot {
    /// Guest time at the start of interval 0.
    pub start_ns: u64,
    pub width_ns: u64,
    pub intervals: usize,
    pub lines: Vec<PlotLine>,
}

impl Plot {
    pub(super) fn end_ns(&self) -> u64 {
        self.start_ns + self.intervals as u64 * self.width_ns
    }

    pub(super) fn interval_start(&self, index: usize) -> u64 {
        self.start_ns + index as u64 * self.width_ns
    }

    /// The interval a guest time falls in.
    pub(super) fn index_of(&self, ns: f64) -> Option<usize> {
        if ns < self.start_ns as f64 {
            return None;
        }
        let index = ((ns - self.start_ns as f64) / self.width_ns as f64) as usize;
        (index < self.intervals).then_some(index)
    }
}

fn ceil_to(value: u64, unit: u64) -> u64 {
    value.div_ceil(unit.max(1)) * unit.max(1)
}

/// The interval actually used: the choice (or Auto's), rounded up to a whole
/// number of the engine's bins so that no bin is split and every interval's
/// count is exact.
pub(super) fn interval_width(choice: Option<u64>, native_ns: u64, span_ns: u64) -> u64 {
    let wanted = choice.unwrap_or_else(|| {
        let raw = span_ns / AUTO_BUCKETS;
        INTERVALS
            .iter()
            .map(|(_, ns)| *ns)
            .find(|ns| *ns >= raw)
            .unwrap_or(INTERVALS[INTERVALS.len() - 1].1)
    });
    ceil_to(wanted.max(native_ns), native_ns)
}

/// Build the plot from the main result's bins and, for custom lines, the
/// extra walk's. Two grids sit on whole multiples of 1 ms times a power of
/// two, so an interval that is a multiple of the coarser one holds whole bins
/// of both.
pub(super) fn plot(
    lines: &[LineKind],
    base: &Rate,
    custom: Option<&Rate>,
    progress: &LineProgress,
    choice: Option<u64>,
) -> Plot {
    let grid = |rate: &Rate| {
        if rate.series.iter().all(|s| s.bins.is_empty()) {
            None
        } else {
            Some(rate.bin_ns.max(FIRST_WIDTH_NS))
        }
    };
    let uses_custom = lines.iter().any(|line| line.custom().is_some());
    let source = |line: &LineKind| -> Option<&Rate> {
        let rate = if line.custom().is_some() {
            custom
        } else {
            Some(base)
        }?;
        rate.series
            .iter()
            .any(|s| s.name == line.series())
            .then_some(rate)
    };
    let mut native = grid(base).unwrap_or(FIRST_WIDTH_NS);
    if let (true, Some(custom_native)) = (uses_custom, custom.and_then(grid)) {
        native = native.max(custom_native);
    }
    let used: Vec<(&LineKind, Option<&Rate>)> = lines.iter().map(|l| (l, source(l))).collect();
    let spans = used.iter().filter_map(|(_, rate)| {
        let rate = (*rate)?;
        let len = rate.series.first().map_or(0, |s| s.bins.len()) as u64;
        (len > 0).then_some((rate.start_ns, rate.start_ns + len * rate.bin_ns))
    });
    let (low, high) = spans.fold((u64::MAX, 0), |(lo, hi), (a, b)| (lo.min(a), hi.max(b)));
    if low == u64::MAX {
        return Plot {
            start_ns: 0,
            width_ns: native,
            intervals: 0,
            lines: used
                .iter()
                .map(|(line, _)| PlotLine {
                    kind: (*line).clone(),
                    counts: Vec::new(),
                    progress: pending(line, progress),
                })
                .collect(),
        };
    }
    let width = interval_width(choice, native, high - low);
    let start = low / width * width;
    let intervals = (high - start).div_ceil(width) as usize;
    let lines = used
        .iter()
        .map(|(line, rate)| {
            let mut counts = Vec::new();
            if let Some(rate) = rate {
                counts = vec![0_u64; intervals];
                if let Some(series) = rate.series.iter().find(|s| s.name == line.series()) {
                    for (i, &n) in series.bins.iter().enumerate() {
                        if n > 0 {
                            let at = rate.start_ns + i as u64 * rate.bin_ns;
                            counts[((at - start) / width) as usize] += u64::from(n);
                        }
                    }
                }
            }
            PlotLine {
                kind: (*line).clone(),
                counts,
                progress: pending(line, progress),
            }
        })
        .collect();
    Plot {
        start_ns: start,
        width_ns: width,
        intervals,
        lines,
    }
}

fn pending(line: &LineKind, progress: &LineProgress) -> LineProgress {
    if line.custom().is_some() {
        progress.clone()
    } else {
        LineProgress::Ready
    }
}

/// A stretch the recording itself is missing or doubtful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Band {
    pub start_ns: u64,
    pub end_ns: u64,
    pub label: String,
    pub full_ring: bool,
}

/// Host read gaps and full-ring spells inside the run's span (the figures are
/// the whole boot's), clipped to it.
pub(super) fn bands(stats: &RunStatistics) -> Vec<Band> {
    let (Some(first), Some(last), Some(gaps)) =
        (stats.first_ns, stats.last_ns, &stats.quality.read_gaps)
    else {
        return Vec::new();
    };
    let clip = |start: u64, len: u64| {
        let end = start.saturating_add(len);
        (end > first && start <= last).then(|| (start.max(first), end.min(last)))
    };
    let mut out = Vec::new();
    for gap in &gaps.gaps {
        if let Some((start_ns, end_ns)) = clip(gap.guest_ns, gap.len_ns) {
            out.push(Band {
                start_ns,
                end_ns,
                label: format!(
                    "no telemetry read here · host read gap, {}",
                    super::duration_ns(gap.len_ns)
                ),
                full_ring: false,
            });
        }
    }
    for spell in &gaps.full_spells {
        if let Some((start_ns, end_ns)) = clip(spell.guest_ns, spell.len_ns) {
            out.push(Band {
                start_ns,
                end_ns,
                label: format!(
                    "ring full here · calls may be missing, {}",
                    super::duration_ns(spell.len_ns)
                ),
                full_ring: true,
            });
        }
    }
    out.sort_by_key(|band| band.start_ns);
    out
}

/// The Trace clause for the calls of `line` in interval `index`.
pub(super) fn click_of(plot: &Plot, line: &LineKind, index: usize) -> Click {
    let (from, to) = (plot.interval_start(index), plot.interval_start(index + 1));
    let range = format!("event.time_ns >= {from} && event.time_ns < {to}");
    Click {
        clause: and(&line.clause(), &range),
        group: line.group(),
    }
}

/// The busiest stretch in words.
pub(super) fn peak_text(
    peak: &Peak,
    base: TimeBase,
    first: Option<u64>,
    anchor: Option<HostClockAnchor>,
) -> String {
    let per_s = peak.calls as f64 * 1e9 / peak.span_ns.max(1) as f64;
    let span = if peak.span_ns > 1_100_000_000 {
        format!(" (the busiest {})", super::duration_ns(peak.span_ns))
    } else {
        String::new()
    };
    format!(
        "Peak {} calls/s at {}{span}",
        super::int(per_s.round() as u64),
        time_text(base, peak.start_ns, first, anchor)
    )
}

/// The plot as one table for Copy and Export: raw numbers in base units.
pub(super) fn table(plot: &Plot, bands: &[Band]) -> Table {
    let mut columns = vec!["start_ns".to_owned(), "interval_ns".to_owned()];
    columns.extend(
        plot.lines
            .iter()
            .map(|l| format!("calls_{}", l.kind.label())),
    );
    columns.push("recording".to_owned());
    let rows = (0..plot.intervals)
        .map(|i| {
            let (from, to) = (plot.interval_start(i), plot.interval_start(i + 1));
            let mut row = vec![Cell::Num(from), Cell::Num(plot.width_ns)];
            row.extend(plot.lines.iter().map(|l| match l.counts.get(i) {
                Some(n) => Cell::Num(*n),
                None => Cell::Empty,
            }));
            row.push(
                bands
                    .iter()
                    .find(|b| b.start_ns < to && b.end_ns >= from)
                    .map_or(Cell::Empty, |b| Cell::Text(b.label.clone())),
            );
            row
        })
        .collect();
    Table {
        name: "rate",
        columns,
        rows,
    }
}

/// What the tab needs to draw.
pub(super) struct Inputs<'a> {
    pub stats: &'a RunStatistics,
    pub custom: Option<&'a RunStatistics>,
    pub progress: LineProgress,
    pub base: TimeBase,
    pub anchor: Option<HostClockAnchor>,
    pub partial: bool,
}

/// What the tab asks of the window.
#[derive(Default)]
pub(super) struct Out {
    pub click: Option<Click>,
    /// The Stop button of a custom line was pressed.
    pub stop_custom: bool,
}

impl Inputs<'_> {
    pub(super) fn plot(&self, state: &State) -> Plot {
        plot(
            &state.lines.list,
            &self.stats.rate,
            self.custom.map(|c| &c.rate),
            &self.progress,
            state.interval,
        )
    }
}

/// Draw the tab.
pub(super) fn show(ui: &mut egui::Ui, state: &mut State, input: &Inputs<'_>) -> Out {
    let mut out = Out::default();
    let groups: Vec<String> = input
        .stats
        .hierarchy
        .iter()
        .map(|g| g.group.clone())
        .collect();
    ui.horizontal_wrapped(|ui| {
        ui.label("Lines");
        legend(ui, state, input, &mut out);
        state.lines.edit(ui, &groups);
    });
    if let Some(message) = &state.lines.message {
        crate::activity::inline_only(ui, crate::activity::Level::Warn, message);
    }
    let plot = input.plot(state);
    ui.horizontal(|ui| {
        interval_menu(ui, state, &plot);
        ui.checkbox(&mut state.table, "Table")
            .on_hover_text("The same numbers as rows, one per interval");
        if let Some(peak) = &input.stats.peak_per_s {
            ui.colored_label(
                crate::theme::muted(),
                peak_text(peak, input.base, input.stats.first_ns, input.anchor),
            );
        }
    });
    let bands = bands(input.stats);
    if input.partial {
        ui.colored_label(
            crate::theme::warn(),
            "Partial: the read is still going; the lines cover the calls read so far.",
        );
    }
    if plot.intervals == 0 {
        crate::theme::empty_state(ui, "No calls in the view.");
        return out;
    }
    if !bands.is_empty() {
        ui.colored_label(
            crate::theme::muted(),
            format!(
                "{} {} drawn as hatched bands: a quiet stretch inside one is not an idle program.",
                bands.len(),
                if bands.len() == 1 {
                    "stretch"
                } else {
                    "stretches"
                }
            ),
        );
    }
    if state.table {
        table_view(ui, &plot, &bands, input);
    } else {
        out.click = super::rate_paint::graph(ui, state, &plot, &bands, input);
    }
    out
}

fn interval_menu(ui: &mut egui::Ui, state: &mut State, plot: &Plot) {
    let text = match state.interval {
        None => format!("Auto ({})", super::duration_ns(plot.width_ns)),
        Some(_) => super::duration_ns(plot.width_ns),
    };
    egui::ComboBox::from_id_salt("statistics-rate-interval")
        .selected_text(format!("Interval: {text}"))
        .show_ui(ui, |ui| {
            ui.selectable_value(&mut state.interval, None, "Auto");
            for (label, ns) in INTERVALS {
                ui.selectable_value(&mut state.interval, Some(ns), label);
            }
        })
        .response
        .on_hover_text(
            "Calls are counted in the recording's own bins; an interval is rounded up to a whole number of them.",
        );
}

fn legend(ui: &mut egui::Ui, state: &mut State, input: &Inputs<'_>, out: &mut Out) {
    let mut remove = None;
    for (i, line) in state.lines.list.iter().enumerate() {
        let style = super::rate_paint::style(i);
        let mut text = format!("{} {}", style.glyph, line.label());
        let progress = if line.custom().is_some() {
            Some(&input.progress)
        } else {
            None
        };
        match progress {
            Some(LineProgress::Reading(Some(percent))) => {
                text.push_str(&format!(" · reading {percent} %"))
            }
            Some(LineProgress::Reading(None)) => text.push_str(" · reading"),
            Some(LineProgress::Waiting) => text.push_str(" · waiting for the main read"),
            Some(LineProgress::Stopped) => text.push_str(" · stopped, partial"),
            Some(LineProgress::Failed(_)) => text.push_str(" · failed"),
            Some(LineProgress::Ready) => text.push_str(" · custom"),
            None => {}
        }
        let tooltip = match progress {
            Some(LineProgress::Failed(error)) => error.clone(),
            Some(_) => "A custom line reads the recording once more with this filter added to the window's.".into(),
            None => "Counted in the main read; no extra walk.".to_owned(),
        };
        ui.colored_label(style.color(), text).on_hover_text(tooltip);
        if matches!(progress, Some(LineProgress::Reading(_)))
            && ui
                .small_button("Stop")
                .on_hover_text("Stop reading this line")
                .clicked()
        {
            out.stop_custom = true;
        }
        if state.lines.list.len() > 1
            && ui
                .small_button(egui_phosphor::regular::X)
                .on_hover_text("Remove this line")
                .clicked()
        {
            remove = Some(i);
        }
    }
    if let Some(i) = remove {
        state.lines.remove(i);
    }
}

fn table_view(ui: &mut egui::Ui, plot: &Plot, bands: &[Band], input: &Inputs<'_>) {
    use crate::widgets::fit_table::{Col, FitBuilder};
    let height = crate::theme::row_height(ui.text_style_height(&egui::TextStyle::Body) + 2.0);
    let mut table = FitBuilder::new(ui)
        .id_salt("statistics-rate-table")
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Col::fixed(170.0));
    for _ in &plot.lines {
        table = table.column(Col::fixed(120.0));
    }
    table
        .column(Col::rest(160.0))
        .min_scrolled_height(0.0)
        .auto_shrink([false, false])
        .header(26.0, |mut header| {
            header.col(|ui| crate::widgets::fit_table::head(ui, "Interval start"));
            for line in &plot.lines {
                header.col(|ui| {
                    crate::widgets::fit_table::head_aligned(
                        ui,
                        &line.kind.label(),
                        egui::Align::Max,
                    );
                });
            }
            header.col(|ui| crate::widgets::fit_table::head(ui, "Recording"));
        })
        .body(|body| {
            body.rows(height, plot.intervals, |mut row| {
                let i = row.index();
                let (from, to) = (plot.interval_start(i), plot.interval_start(i + 1));
                row.col(|ui| {
                    ui.label(time_text(
                        input.base,
                        from,
                        input.stats.first_ns,
                        input.anchor,
                    ));
                });
                for line in &plot.lines {
                    row.col(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if let Some(n) = line.counts.get(i) {
                                ui.monospace(super::int(*n));
                            }
                        });
                    });
                }
                row.col(|ui| {
                    if let Some(band) = bands.iter().find(|b| b.start_ns < to && b.end_ns >= from) {
                        ui.colored_label(crate::theme::warn(), &band.label);
                    }
                });
            });
        });
}

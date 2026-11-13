// SPDX-License-Identifier: GPL-3.0-only
//! The Latency tab (design 2.5): how long calls took, from the entry record to
//! the exit record on the guest clock. Labelled with the accelerator the run
//! was measured under, with the guest-send-wait warning, ordinary calls apart
//! from calls that wait by design, the distribution of the selected call and
//! the slowest calls, each a link to that exact call.
use super::hierarchy::Click;
use super::navigate::{self, and};
use super::properties::Tone;
use super::{duration_ns, int, time_text, Pick, TimeBase};
use crate::theme;
use antinomie_monitor_core::api::HostClockAnchor;
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use antinomie_triage::statistics::blocking::BlockClass;
use antinomie_triage::statistics::export::{self, Table};
use antinomie_triage::statistics::latency::{LatencyRow, SlowCall};
use antinomie_triage::statistics::RunStatistics;
use eframe::egui;

const CALLS: &str = "statistics-latency-calls";
const WAITS: &str = "statistics-latency-waits";

/// Which table Copy and Export take.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Part {
    #[default]
    Calls,
    Blocking,
    Slowest,
    Waits,
}

impl Part {
    pub(super) const ALL: [Self; 4] = [Self::Calls, Self::Blocking, Self::Slowest, Self::Waits];

    pub(super) fn label(self) -> &'static str {
        match self {
            Self::Calls => "Calls",
            Self::Blocking => "Calls that wait by design",
            Self::Slowest => "Slowest ordinary calls",
            Self::Waits => "Longest waits",
        }
    }
}

#[derive(Default)]
pub(super) struct State {
    /// The row whose distribution is drawn: call name and class.
    pub selected: Option<(String, BlockClass)>,
    /// The distribution as numbers.
    pub table: bool,
    pub part: Part,
}

/// The banner over the tables: what the figures were measured under, in words.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Banner {
    pub text: String,
    pub tone: Tone,
}

/// From the run's recorded accelerator (design 2.5).
pub(super) fn banner(accelerator: Option<&str>) -> Banner {
    let accelerator = accelerator.map(str::trim).filter(|a| !a.is_empty());
    let lower = accelerator.map(str::to_lowercase);
    match (accelerator, lower.as_deref()) {
        // "tcg (KVM unavailable)" is TCG: look for it first.
        (Some(_), Some(a)) if a.contains("tcg") => Banner {
            text: "Measured under TCG (software emulation): much slower than real hardware; compare only with other TCG runs.".into(),
            tone: Tone::Warn,
        },
        (Some(_), Some(a)) if a.contains("kvm") => Banner {
            text: "Measured under KVM (hardware virtualization).".into(),
            tone: Tone::Plain,
        },
        (Some(other), _) => Banner {
            text: format!("Measured under {other}. Compare only with runs measured under the same accelerator."),
            tone: Tone::Warn,
        },
        (None, _) => Banner {
            text: "Accelerator not recorded: compare with care.".into(),
            tone: Tone::Warn,
        },
    }
}

const INCLUDES: &str = "A call's time is its exit record's guest time minus its entry record's: the wait in the kernel, \
plus the recorder's own work at entry and exit, plus, in never-drop mode, any wait of the guest for room in the telemetry ring.";

/// The warning for a boot whose guest sends waited, or `None`.
pub(super) fn send_wait_warning(stats: &RunStatistics) -> Option<String> {
    let waits = stats.quality.guest_send_waits.filter(|w| w.count > 0)?;
    Some(format!(
        "This boot's guest sends waited for the host {} times ({} in all): some of the times below include such a wait.",
        int(waits.count),
        duration_ns(waits.total_ns)
    ))
}

/// The accelerator the run was measured under: the manifest's, else the guest facts'.
pub(super) fn accelerator<'a>(
    stats: &'a RunStatistics,
    facts: &'a super::Facts,
) -> Option<&'a str> {
    stats.quality.accelerator.as_deref().or_else(|| {
        facts
            .guest
            .iter()
            .find(|(label, _)| label == "Accelerator")
            .map(|(_, value)| value.as_str())
            .filter(|value| *value != "not recorded")
    })
}

/// Rows of one table: calls that wait by design, or the others.
pub(super) fn rows(
    stats: &RunStatistics,
    waits: bool,
    sort: Option<(usize, bool)>,
) -> Vec<&LatencyRow> {
    let mut rows: Vec<&LatencyRow> = stats
        .latency
        .iter()
        .filter(|row| (row.class == BlockClass::Waits) == waits)
        .collect();
    let (column, descending) = sort.unwrap_or((7, true));
    rows.sort_by(|a, b| {
        let order = match column {
            0 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            1 => a.timed.cmp(&b.timed),
            2 => a.min_ns.cmp(&b.min_ns),
            3 => a.median_ns.cmp(&b.median_ns),
            4 => a.p95_ns.cmp(&b.p95_ns),
            5 => a.p99_ns.cmp(&b.p99_ns),
            6 => a.max_ns.cmp(&b.max_ns),
            8 => a.mean_ns.cmp(&b.mean_ns),
            _ => a.total_ns.cmp(&b.total_ns),
        };
        let order = order.then_with(|| a.name.cmp(&b.name));
        if descending {
            order.reverse()
        } else {
            order
        }
    });
    rows
}

/// `syscall.name == read`.
pub(super) fn row_click(row: &LatencyRow) -> Click {
    Click {
        clause: navigate::call_clause(&row.name),
        group: SyscallGroup::of(&row.name),
    }
}

/// "Slowest 1 % in Trace": the call's calls at or above its 99th percentile.
pub(super) fn slowest_percent_click(row: &LatencyRow) -> Click {
    Click {
        clause: and(
            &navigate::call_clause(&row.name),
            &format!("syscall.duration_ns >= {}", row.p99_ns),
        ),
        group: SyscallGroup::of(&row.name),
    }
}

/// The table Copy and Export take.
pub(super) fn table(stats: &RunStatistics, part: Part) -> Table {
    match part {
        Part::Calls => export::latency_table(stats, false),
        Part::Blocking => export::latency_table(stats, true),
        Part::Slowest => export::slowest_table(stats, false),
        Part::Waits => export::slowest_table(stats, true),
    }
}

/// "may block" next to a call whose time depends on what it reads or writes.
fn class_mark(class: BlockClass) -> &'static str {
    match class {
        BlockClass::MayBlock => " may block",
        _ => "",
    }
}

/// Log-scale histogram bars: `(x from 0 to 1, height from 0 to 1)` for each bucket.
pub(super) fn bars(histogram: &[(u64, u64)], min_ns: u64, max_ns: u64) -> Vec<(f32, f32)> {
    let low = (min_ns.max(1) as f64).log2();
    let high = (max_ns.max(2) as f64).log2().max(low + 1.0);
    let top = histogram.iter().map(|(_, n)| *n).max().unwrap_or(1).max(1) as f32;
    histogram
        .iter()
        .map(|(bound, n)| {
            let x = (((*bound).max(1) as f64).log2() - low) / (high - low);
            (x.clamp(0.0, 1.0) as f32, *n as f32 / top)
        })
        .collect()
}

/// What the tab needs.
pub(super) struct Inputs<'a> {
    pub stats: &'a RunStatistics,
    pub facts: &'a super::Facts,
    pub base: TimeBase,
    pub anchor: Option<HostClockAnchor>,
}

fn note(ui: &mut egui::Ui, text: &str, tone: Tone) {
    let (icon, color) = match tone {
        Tone::Plain => (egui_phosphor::regular::INFO, theme::muted()),
        Tone::Warn => (egui_phosphor::regular::WARNING, theme::warn()),
        Tone::Bad => (egui_phosphor::regular::WARNING_OCTAGON, theme::error()),
    };
    ui.add(egui::Label::new(egui::RichText::new(format!("{icon} {text}")).color(color)).wrap());
}

/// Draw the tab; returns what was clicked.
pub(super) fn show(ui: &mut egui::Ui, state: &mut State, input: &Inputs<'_>) -> Option<Pick> {
    let stats = input.stats;
    let mut pick = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let banner = banner(accelerator(stats, input.facts));
            note(ui, &format!("{} {INCLUDES}", banner.text), banner.tone);
            if let Some(warning) = send_wait_warning(stats) {
                note(ui, &warning, Tone::Warn);
            }
            ui.horizontal(|ui| {
                ui.label("Copy and Export take:");
                egui::ComboBox::from_id_salt("statistics-latency-part")
                    .selected_text(state.part.label())
                    .show_ui(ui, |ui| {
                        for part in Part::ALL {
                            ui.selectable_value(&mut state.part, part, part.label());
                        }
                    });
            });
            if stats.latency.is_empty() {
                theme::empty_state(ui, "No call in the view has both an entry and an exit.");
                return;
            }
            theme::section(ui, "Calls");
            if let Some(found) = latency_table(ui, state, input, false) {
                pick = Some(found);
            }
            if stats
                .latency
                .iter()
                .any(|row| row.class == BlockClass::Waits)
            {
                theme::section(ui, "Calls that wait by design");
                ui.colored_label(
                    theme::muted(),
                    "Shown apart so a sleep or a poll does not hide the slow ordinary calls.",
                );
                if let Some(found) = latency_table(ui, state, input, true) {
                    pick = Some(found);
                }
            }
            histogram(ui, state, stats);
            slowest(
                ui,
                input,
                "Slowest ordinary calls",
                &stats.slowest,
                "statistics-slowest",
                &mut pick,
            );
            slowest(
                ui,
                input,
                "Longest waits",
                &stats.longest_waits,
                "statistics-waits",
                &mut pick,
            );
            if stats.not_timed > 0 {
                ui.colored_label(
                    theme::muted(),
                    format!(
                        "{} calls have no entry or no exit and are not timed.",
                        int(stats.not_timed)
                    ),
                );
            }
        });
    pick
}

fn latency_table(
    ui: &mut egui::Ui,
    state: &mut State,
    input: &Inputs<'_>,
    waits: bool,
) -> Option<Pick> {
    use crate::widgets::fit_table::{Col, FitBuilder};
    let id = if waits { WAITS } else { CALLS };
    let sort = crate::triage::sort_current(ui.ctx(), id).map(|spec| (spec.column, spec.descending));
    let rows = rows(input.stats, waits, sort);
    if rows.is_empty() {
        return None;
    }
    const TITLES: [&str; 9] = [
        "Call",
        "Timed",
        "Min",
        "Median ≈",
        "p95 ≈",
        "p99 ≈",
        "Max",
        "Total",
        "Mean",
    ];
    let height = theme::row_height(ui.text_style_height(&egui::TextStyle::Body) + 2.0);
    let mut pick = None;
    let mut select = None;
    FitBuilder::new(ui)
        .id_salt(id)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Col::fixed(28.0))
        .column(Col::rest(150.0))
        .column(Col::fixed(72.0))
        .column(Col::fixed(80.0))
        .column(Col::fixed(80.0))
        .column(Col::fixed(80.0))
        .column(Col::fixed(80.0))
        .column(Col::fixed(80.0))
        .column(Col::fixed(80.0))
        .column(Col::fixed(80.0))
        .max_scroll_height(250.0)
        .min_scrolled_height(0.0)
        .auto_shrink([false, true])
        .header(26.0, |mut header| {
            header.col(|_| {});
            for (column, title) in TITLES.iter().enumerate() {
                header.col(|ui| {
                    if column == 0 {
                        crate::table_sort::header(ui, id, column, title);
                    } else {
                        crate::table_sort::header_aligned(ui, id, column, title, egui::Align::Max);
                    }
                });
            }
        })
        .body(|body| {
            body.rows(height, rows.len(), |mut table_row| {
                let row = rows[table_row.index()];
                let key = (row.name.clone(), row.class);
                let chosen = state.selected.as_ref() == Some(&key);
                table_row.col(|ui| {
                    if ui
                        .selectable_label(chosen, egui_phosphor::regular::CHART_BAR)
                        .on_hover_text("Draw this call's distribution below")
                        .clicked()
                    {
                        select = Some(key.clone());
                    }
                });
                table_row.col(|ui| {
                    let text = format!("{}{}", row.name, class_mark(row.class));
                    let response = ui
                        .add(
                            egui::Label::new(egui::RichText::new(text).monospace().color(theme::blue()))
                                .selectable(false)
                                .sense(egui::Sense::click()),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text(match row.class {
                            BlockClass::MayBlock => "May block: how long it takes depends on what it reads or writes. Click to open these calls; right-click for more.",
                            BlockClass::Waits => "Waits by design. Click to open these calls; right-click for more.",
                            BlockClass::Ordinary => "Click to open these calls in the Syscall Trace; right-click for more.",
                        });
                    if response.clicked() {
                        pick = Some(Pick::Count(row_click(row)));
                    }
                    response.context_menu(|ui| {
                        if ui.button("Open these calls").clicked() {
                            pick = Some(Pick::Count(row_click(row)));
                            ui.close();
                        }
                        if ui
                            .button("Slowest 1 % in Trace")
                            .on_hover_text("Only this call's calls at or above its 99th percentile (≈)")
                            .clicked()
                        {
                            pick = Some(Pick::Count(slowest_percent_click(row)));
                            ui.close();
                        }
                    });
                });
                let cells = [
                    (int(row.timed), ""),
                    (duration_ns(row.min_ns), ""),
                    (duration_ns(row.median_ns), "≈ within about 6 %"),
                    (duration_ns(row.p95_ns), "≈ within about 6 %"),
                    (duration_ns(row.p99_ns), "≈ within about 6 %"),
                    (duration_ns(row.max_ns), ""),
                    (duration_ns(row.total_ns), ""),
                    (duration_ns(row.mean_ns), ""),
                ];
                for (text, hint) in cells {
                    table_row.col(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let label = ui.monospace(text);
                            if !hint.is_empty() {
                                label.on_hover_text(hint);
                            }
                        });
                    });
                }
            });
        });
    if let Some(key) = select {
        state.selected = Some(key);
    }
    pick
}

/// The row whose distribution is drawn: the selected one, else the busiest.
pub(super) fn chosen<'a>(stats: &'a RunStatistics, state: &State) -> Option<&'a LatencyRow> {
    state
        .selected
        .as_ref()
        .and_then(|(name, class)| {
            stats
                .latency
                .iter()
                .find(|row| &row.name == name && row.class == *class)
        })
        .or_else(|| stats.latency.iter().max_by_key(|row| row.timed))
}

fn histogram(ui: &mut egui::Ui, state: &mut State, stats: &RunStatistics) {
    let Some(row) = chosen(stats, state) else {
        return;
    };
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        ui.label(theme::section_title(
            ui,
            format!(
                "{}: how long the {} timed calls took",
                row.name,
                int(row.timed)
            ),
        ));
        ui.checkbox(&mut state.table, "Table")
            .on_hover_text("The same numbers as rows");
    });
    if state.table {
        egui::Grid::new("statistics-latency-hist")
            .striped(true)
            .show(ui, |ui| {
                ui.strong("Up to");
                ui.strong("Calls");
                ui.end_row();
                for (bound, n) in &row.histogram {
                    ui.monospace(duration_ns(*bound));
                    ui.monospace(int(*n));
                    ui.end_row();
                }
            });
        return;
    }
    let size = egui::vec2(ui.available_width().min(760.0), 120.0);
    let (response, painter) = ui.allocate_painter(size, egui::Sense::hover());
    let rect = response.rect.shrink2(egui::vec2(8.0, 4.0));
    let plot = egui::Rect::from_min_max(rect.min, rect.max - egui::vec2(0.0, 16.0));
    painter.rect_filled(plot, 2.0, theme::panel());
    let font = egui::FontId::proportional(11.0);
    let step = (plot.width() / 128.0).max(2.0);
    for (x, h) in bars(&row.histogram, row.min_ns, row.max_ns) {
        let at = plot.left() + x * (plot.width() - step);
        let top = plot.bottom() - h.max(0.02) * plot.height();
        painter.rect_filled(
            egui::Rect::from_min_max(egui::pos2(at, top), egui::pos2(at + step, plot.bottom())),
            0.0,
            theme::blue(),
        );
    }
    painter.text(
        plot.left_bottom() + egui::vec2(0.0, 2.0),
        egui::Align2::LEFT_TOP,
        duration_ns(row.min_ns),
        font.clone(),
        theme::muted(),
    );
    painter.text(
        plot.right_bottom() + egui::vec2(0.0, 2.0),
        egui::Align2::RIGHT_TOP,
        duration_ns(row.max_ns),
        font.clone(),
        theme::muted(),
    );
    painter.text(
        egui::pos2(plot.center().x, plot.bottom() + 2.0),
        egui::Align2::CENTER_TOP,
        "log scale",
        font,
        theme::muted(),
    );
}

fn slowest(
    ui: &mut egui::Ui,
    input: &Inputs<'_>,
    title: &str,
    calls: &[SlowCall],
    id: &str,
    pick: &mut Option<Pick>,
) {
    if calls.is_empty() {
        return;
    }
    use crate::widgets::fit_table::{Col, FitBuilder};
    ui.add_space(6.0);
    theme::section(ui, &format!("{title}  ({} of 20)", calls.len()));
    let height = theme::row_height(ui.text_style_height(&egui::TextStyle::Body) + 2.0);
    FitBuilder::new(ui)
        .id_salt(id)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Col::rest(170.0))
        .column(Col::fixed(96.0))
        .column(Col::fixed(70.0))
        .column(Col::fixed(70.0))
        .column(Col::fixed(190.0))
        .vscroll(false)
        .header(26.0, |mut header| {
            header.col(|ui| crate::widgets::fit_table::head(ui, "Call"));
            header.col(|ui| crate::widgets::fit_table::head_aligned(ui, "Took", egui::Align::Max));
            header.col(|ui| crate::widgets::fit_table::head_aligned(ui, "pid", egui::Align::Max));
            header.col(|ui| crate::widgets::fit_table::head_aligned(ui, "tid", egui::Align::Max));
            header.col(|ui| crate::widgets::fit_table::head(ui, "Started"));
        })
        .body(|body| {
            body.rows(height, calls.len(), |mut row| {
                let call = &calls[row.index()];
                row.col(|ui| {
                    let class =
                        antinomie_triage::statistics::blocking::classify(&call.name, 0, None);
                    let text = format!("{}{}", call.name, class_mark(class));
                    let response = ui
                        .add(
                            egui::Label::new(
                                egui::RichText::new(text).monospace().color(theme::blue()),
                            )
                            .selectable(false)
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .on_hover_text("Open exactly this call in the Syscall Trace");
                    if response.clicked() {
                        *pick = Some(Pick::Call(call.key));
                    }
                });
                row.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.monospace(duration_ns(call.duration_ns));
                    });
                });
                row.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.monospace(if call.pid == 0 {
                            "-".to_owned()
                        } else {
                            call.pid.to_string()
                        });
                    });
                });
                row.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.monospace(call.tid.to_string());
                    });
                });
                row.col(|ui| {
                    ui.label(time_text(
                        input.base,
                        call.start_ns,
                        input.stats.first_ns,
                        input.anchor,
                    ));
                });
            });
        });
}

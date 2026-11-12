// SPDX-License-Identifier: GPL-3.0-only
//! The Hierarchy tab (design 2.3): group, call, result, with counts and shares.
//! "Failed only" and "By error" are cuts of the same counts (no new walk). The
//! rows are built by [`rows`], a pure function, and drawn by [`show`].
use super::navigate::{self, and};
use crate::tree_lines::Prefix;
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use antinomie_triage::statistics::aggregate::{CallRow, GroupRow, ResultKey};
use antinomie_triage::statistics::{views, RunStatistics};
use eframe::egui;
use std::collections::HashSet;

/// What the person chose; kept while the window lives.
#[derive(Default)]
pub(super) struct State {
    pub failed_only: bool,
    pub by_error: bool,
    /// Rows whose open state differs from the default (groups and results open, calls closed).
    pub toggled: HashSet<String>,
}

/// One line of the table.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Row {
    pub depth: usize,
    pub prefix: Prefix,
    /// Identity for the open state.
    pub key: String,
    pub label: String,
    pub expandable: bool,
    pub open: bool,
    pub calls: u64,
    /// Shares in percent.
    pub of_view: f64,
    pub of_parent: Option<f64>,
    pub failed: u64,
    /// Calls the reduced recording did not save, for call and group rows.
    pub not_saved: Option<u64>,
    /// The Trace filter clause for the count, without the window's filter.
    pub clause: Option<String>,
    /// The same, restricted to failed calls (the Failed column).
    pub failed_clause: Option<String>,
    /// The group whose hidden state must be asked about before opening.
    pub group: Option<SyscallGroup>,
    pub is_error: bool,
    pub no_result: bool,
}

fn share(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

struct Builder<'a> {
    rows: Vec<Row>,
    total: u64,
    state: &'a State,
    dropped: Option<&'a std::collections::BTreeMap<String, u64>>,
    sort: Option<(usize, bool)>,
}

impl Builder<'_> {
    fn open(&self, key: &str, default: bool) -> bool {
        default != self.state.toggled.contains(key)
    }

    fn order<T>(&self, items: &mut [T], value: impl Fn(&T) -> (u64, u64, &str)) {
        let Some((column, descending)) = self.sort else {
            return;
        };
        items.sort_by(|a, b| {
            let (a, b) = (value(a), value(b));
            let order = match column {
                0 => a.2.to_lowercase().cmp(&b.2.to_lowercase()),
                4 => a.1.cmp(&b.1),
                _ => a.0.cmp(&b.0),
            };
            if descending {
                order.reverse()
            } else {
                order
            }
        });
    }

    fn calls(&mut self, group: &GroupRow, group_prefix: &Prefix) {
        let mut calls: Vec<&CallRow> = group.calls_by_name.iter().collect();
        self.order(&mut calls, |c| (c.calls, c.failed, c.name.as_str()));
        let last = calls.len().saturating_sub(1);
        for (i, call) in calls.into_iter().enumerate() {
            let prefix = group_prefix.child(i == last);
            let key = format!("{}/{}", group.group, call.name);
            let open = self.open(&key, false);
            let call_clause = navigate::call_clause(&call.name);
            let syscall_group = group.syscall_group();
            self.rows.push(Row {
                depth: 1,
                prefix: prefix.clone(),
                key: key.clone(),
                label: call.name.clone(),
                expandable: !call.results.is_empty(),
                open,
                calls: call.calls,
                of_view: share(call.calls, self.total),
                of_parent: Some(share(call.calls, group.calls)),
                failed: call.failed,
                not_saved: self.dropped.and_then(|d| d.get(&call.name).copied()),
                clause: Some(call_clause.clone()),
                failed_clause: Some(and(&call_clause, navigate::FAILED)),
                group: syscall_group,
                is_error: false,
                no_result: false,
            });
            if !open {
                continue;
            }
            let mut results: Vec<&(ResultKey, u64)> = call.results.iter().collect();
            self.order(&mut results, |r| {
                (r.1, if r.0.is_error() { r.1 } else { 0 }, "")
            });
            let extra = call.other_results > 0;
            let last_result = results.len().saturating_sub(1);
            for (j, (result, n)) in results.into_iter().map(|r| (&r.0, r.1)).enumerate() {
                let clause = and(&call_clause, &navigate::result_part(*result));
                self.rows.push(Row {
                    depth: 2,
                    prefix: prefix.child(j == last_result && !extra),
                    key: format!("{key}/{}", result.label()),
                    label: result.label(),
                    expandable: false,
                    open: false,
                    calls: n,
                    of_view: share(n, self.total),
                    of_parent: Some(share(n, call.calls)),
                    failed: if result.is_error() { n } else { 0 },
                    not_saved: None,
                    clause: Some(clause),
                    failed_clause: None,
                    group: syscall_group,
                    is_error: result.is_error(),
                    no_result: *result == ResultKey::NoResult,
                });
            }
            if extra {
                self.rows.push(Row {
                    depth: 2,
                    prefix: prefix.child(true),
                    key: format!("{key}/other"),
                    label: "other results".into(),
                    expandable: false,
                    open: false,
                    calls: call.other_results,
                    of_view: share(call.other_results, self.total),
                    of_parent: Some(share(call.other_results, call.calls)),
                    failed: 0,
                    not_saved: None,
                    clause: None,
                    failed_clause: None,
                    group: None,
                    is_error: false,
                    no_result: false,
                });
            }
        }
    }
}

/// The table's rows for `stats` under the person's choices. `sort` is the
/// header click, `(column, descending)`; siblings are sorted, the tree stays.
pub(super) fn rows(stats: &RunStatistics, state: &State, sort: Option<(usize, bool)>) -> Vec<Row> {
    let cut;
    let hierarchy: &[GroupRow] = if state.failed_only {
        cut = views::failed_only(&stats.hierarchy);
        &cut
    } else {
        &stats.hierarchy
    };
    let dropped = stats
        .quality
        .reduced
        .as_ref()
        .map(|reduced| &reduced.dropped_calls);
    if state.by_error {
        return by_error(hierarchy, state, sort);
    }
    let total: u64 = hierarchy.iter().map(|g| g.calls).sum();
    let mut builder = Builder {
        rows: Vec::new(),
        total,
        state,
        dropped,
        sort,
    };
    let mut groups: Vec<&GroupRow> = hierarchy.iter().collect();
    builder.order(&mut groups, |g| (g.calls, g.failed, g.group.as_str()));
    for group in groups {
        let key = group.group.clone();
        let open = builder.open(&key, true);
        let clause = navigate::group_clause(&group.group);
        let not_saved = dropped.map(|d| {
            group
                .calls_by_name
                .iter()
                .filter_map(|c| d.get(&c.name))
                .sum::<u64>()
        });
        builder.rows.push(Row {
            depth: 0,
            prefix: Prefix::default(),
            key,
            label: group.group.clone(),
            expandable: !group.calls_by_name.is_empty(),
            open,
            calls: group.calls,
            of_view: share(group.calls, total),
            of_parent: None,
            failed: group.failed,
            not_saved: not_saved.filter(|n| *n > 0),
            failed_clause: Some(and(&clause, navigate::FAILED)),
            clause: Some(clause),
            group: group.syscall_group(),
            is_error: false,
            no_result: false,
        });
        if open {
            builder.calls(group, &Prefix::default());
        }
    }
    builder.rows
}

/// Result first, then the calls that returned it.
fn by_error(hierarchy: &[GroupRow], state: &State, sort: Option<(usize, bool)>) -> Vec<Row> {
    let pivot = views::by_error(hierarchy, state.failed_only);
    let total = pivot.total();
    let builder = Builder {
        rows: Vec::new(),
        total,
        state,
        dropped: None,
        sort,
    };
    let mut results: Vec<&views::ResultRow> = pivot.rows.iter().collect();
    builder.order(&mut results, |r| {
        (r.calls, if r.result.is_error() { r.calls } else { 0 }, "")
    });
    let mut rows = Vec::new();
    for result in results {
        let label = result.result.label();
        let key = format!("result/{label}");
        let open = builder.open(&key, true);
        let part = navigate::result_part(result.result);
        rows.push(Row {
            depth: 0,
            prefix: Prefix::default(),
            key: key.clone(),
            label,
            expandable: !result.by_call.is_empty(),
            open,
            calls: result.calls,
            of_view: share(result.calls, total),
            of_parent: None,
            failed: if result.result.is_error() {
                result.calls
            } else {
                0
            },
            not_saved: None,
            clause: Some(part.clone()),
            failed_clause: None,
            group: None,
            is_error: result.result.is_error(),
            no_result: result.result == ResultKey::NoResult,
        });
        if !open {
            continue;
        }
        let last = result.by_call.len().saturating_sub(1);
        for (i, (name, n)) in result.by_call.iter().enumerate() {
            rows.push(Row {
                depth: 1,
                prefix: Prefix::default().child(i == last),
                key: format!("{key}/{name}"),
                label: name.clone(),
                expandable: false,
                open: false,
                calls: *n,
                of_view: share(*n, total),
                of_parent: Some(share(*n, result.calls)),
                failed: if result.result.is_error() { *n } else { 0 },
                not_saved: None,
                clause: Some(and(&navigate::call_clause(name), &part)),
                failed_clause: None,
                group: SyscallGroup::of(name),
                is_error: result.result.is_error(),
                no_result: result.result == ResultKey::NoResult,
            });
        }
    }
    if !pivot.other_errors.is_empty() {
        let n: u64 = pivot.other_errors.iter().map(|(_, n)| n).sum();
        rows.push(Row {
            depth: 0,
            prefix: Prefix::default(),
            key: "result/other".into(),
            label: "other errors".into(),
            expandable: false,
            open: false,
            calls: n,
            of_view: share(n, total),
            of_parent: None,
            failed: n,
            not_saved: None,
            clause: None,
            failed_clause: None,
            group: None,
            is_error: true,
            no_result: false,
        });
    }
    rows
}

/// A click on a count: the filter clause and the group to ask about.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Click {
    pub clause: String,
    pub group: Option<SyscallGroup>,
}

const TABLE: &str = "statistics-hierarchy";
const COLUMNS: [&str; 5] = ["Name", "Calls", "% of view", "% of parent", "Failed"];

/// Draw the switches and the table; returns the count that was clicked.
pub(super) fn show(
    ui: &mut egui::Ui,
    stats: &RunStatistics,
    state: &mut State,
    partial: bool,
) -> Option<Click> {
    ui.horizontal(|ui| {
        ui.checkbox(&mut state.failed_only, "Failed only").on_hover_text(
            "Keep only calls that returned an error number. Percentages are then of the failed calls. \
             Harmless errors such as EAGAIN and EINPROGRESS count too.",
        );
        ui.checkbox(&mut state.by_error, "By error")
            .on_hover_text("Result first, then the calls that returned it: ENOENT, then openat, newfstatat.");
    });
    let sort =
        crate::triage::sort_current(ui.ctx(), TABLE).map(|spec| (spec.column, spec.descending));
    let rows = rows(stats, state, sort);
    if rows.is_empty() {
        crate::theme::empty_state(
            ui,
            if state.failed_only {
                "No call returned an error."
            } else {
                "No calls in the view."
            },
        );
        return None;
    }
    let saved = stats.quality.reduced.is_some();
    let font = crate::theme::mono(ui.text_style_height(&egui::TextStyle::Body));
    let char_width = crate::tree_lines::char_width(ui, &font);
    let height = crate::theme::row_height(ui.text_style_height(&egui::TextStyle::Body) + 2.0);
    let mut click = None;
    let mut toggle = None;
    use crate::widgets::fit_table::{Col, FitBuilder};
    let mut table = FitBuilder::new(ui)
        .id_salt("statistics-hierarchy-table")
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Col::rest(220.0))
        .column(Col::fixed(96.0))
        .column(Col::fixed(84.0))
        .column(Col::fixed(96.0))
        .column(Col::fixed(120.0));
    if saved {
        table = table.column(Col::fixed(110.0));
    }
    table
        .column(Col::fixed(130.0))
        .min_scrolled_height(0.0)
        .auto_shrink([false, false])
        .header(26.0, |mut header| {
            for (column, title) in COLUMNS.iter().enumerate() {
                header.col(|ui| {
                    if column == 0 {
                        crate::table_sort::header(ui, TABLE, column, title);
                    } else {
                        crate::table_sort::header_aligned(ui, TABLE, column, title, egui::Align::Max);
                    }
                });
            }
            if saved {
                header.col(|ui| crate::widgets::fit_table::head_aligned(ui, "Not saved", egui::Align::Max));
            }
            header.col(|ui| crate::widgets::fit_table::head(ui, "Share of view"));
        })
        .body(|body| {
            body.rows(height, rows.len(), |mut table_row| {
                let row = &rows[table_row.index()];
                table_row.col(|ui| {
                    crate::tree_lines::row(ui, &row.prefix, char_width, |ui| {
                        name_cell(ui, row, stats, &mut click, &mut toggle);
                    });
                });
                table_row.col(|ui| {
                    number_cell(ui, row.calls, row.clause.as_deref(), row, &mut click, "Calls");
                });
                table_row.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(percent(row.of_view));
                    });
                });
                table_row.col(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(row.of_parent.map_or_else(String::new, percent));
                    });
                });
                table_row.col(|ui| failed_cell(ui, row, &mut click));
                if saved {
                    table_row.col(|ui| {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if let Some(n) = row.not_saved {
                                ui.colored_label(crate::theme::warn(), format!("+{} not saved", super::int(n)))
                                    .on_hover_text(
                                        "Calls the reduced recording did not keep; the saved counts stay exact.",
                                    );
                            }
                        });
                    });
                }
                table_row.col(|ui| bar_cell(ui, row, partial));
            });
        });
    if let Some(key) = toggle {
        if !state.toggled.remove(&key) {
            state.toggled.insert(key);
        }
    }
    click
}

fn percent(value: f64) -> String {
    if value > 0.0 && value < 0.1 {
        "<0.1 %".into()
    } else {
        format!("{value:.1} %")
    }
}

/// A number that opens its calls: pointing hand, underline on hover, Enter when focused.
fn link_number(ui: &mut egui::Ui, text: &str, enabled: bool, hint: &str) -> bool {
    let response = ui.add(
        egui::Label::new(egui::RichText::new(text).monospace().color(if enabled {
            crate::theme::blue()
        } else {
            crate::theme::text()
        }))
        .selectable(false)
        .sense(if enabled {
            egui::Sense::click()
        } else {
            egui::Sense::hover()
        }),
    );
    if !enabled {
        return false;
    }
    let response = response.on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.hovered() || response.has_focus() {
        let rect = response.rect;
        ui.painter().hline(
            rect.x_range(),
            rect.bottom(),
            egui::Stroke::new(1.0_f32, crate::theme::blue()),
        );
    }
    response.on_hover_text(hint).clicked()
}

fn name_cell(
    ui: &mut egui::Ui,
    row: &Row,
    stats: &RunStatistics,
    click: &mut Option<Click>,
    toggle: &mut Option<String>,
) {
    if row.expandable {
        let icon = if row.open {
            egui_phosphor::regular::CARET_DOWN
        } else {
            egui_phosphor::regular::CARET_RIGHT
        };
        let caret = ui
            .add(
                egui::Label::new(egui::RichText::new(icon).color(crate::theme::muted()))
                    .selectable(false)
                    .sense(egui::Sense::click()),
            )
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if caret.clicked() {
            *toggle = Some(row.key.clone());
        }
    }
    let color = if row.is_error {
        crate::theme::error()
    } else if row.no_result {
        crate::theme::warn()
    } else {
        crate::theme::text()
    };
    let text = egui::RichText::new(&row.label).color(color);
    let response = ui.add(
        egui::Label::new(if row.depth == 0 { text.strong() } else { text })
            .truncate()
            .selectable(false)
            .sense(egui::Sense::click()),
    );
    let hint = if row.no_result {
        format!(
            "Calls with no result recorded. Of the {} in this view, {} ended their task (exit, exit_group, a fatal signal); \
             the others were still running at the end or lost their exit. Click to open them in the Syscall Trace.",
            super::int(stats.no_result),
            super::int(stats.ended_task)
        )
    } else {
        format!(
            "{}\nClick to open these calls in the Syscall Trace; click the caret to fold.",
            row.label
        )
    };
    let response = response.on_hover_text(hint);
    if response.double_clicked() && row.expandable {
        *toggle = Some(row.key.clone());
    } else if response.clicked() {
        if let Some(clause) = &row.clause {
            *click = Some(Click {
                clause: clause.clone(),
                group: row.group,
            });
        }
    }
}

fn number_cell(
    ui: &mut egui::Ui,
    value: u64,
    clause: Option<&str>,
    row: &Row,
    click: &mut Option<Click>,
    what: &str,
) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let hint = format!(
            "{what}: {} calls. Click to open them in the Syscall Trace.",
            super::int(value)
        );
        if link_number(ui, &super::int(value), clause.is_some(), &hint) {
            if let Some(clause) = clause {
                *click = Some(Click {
                    clause: clause.to_owned(),
                    group: row.group,
                });
            }
        }
    });
}

fn failed_cell(ui: &mut egui::Ui, row: &Row, click: &mut Option<Click>) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        if row.failed == 0 {
            ui.colored_label(crate::theme::muted(), "–");
            return;
        }
        let share = share(row.failed, row.calls);
        let text = format!(
            "{} {}  ({share:.0} %)",
            egui_phosphor::regular::WARNING,
            super::int(row.failed)
        );
        let hint = "Calls that returned an error number (the exit's result, else the entry's). \
                    Includes harmless errors such as EAGAIN and EINPROGRESS. Click to open them.";
        let clause = row.failed_clause.as_deref().or(row.clause.as_deref());
        let response = ui
            .add(
                egui::Label::new(
                    egui::RichText::new(text)
                        .monospace()
                        .color(crate::theme::error()),
                )
                .selectable(false)
                .sense(if clause.is_some() {
                    egui::Sense::click()
                } else {
                    egui::Sense::hover()
                }),
            )
            .on_hover_text(hint);
        if response.clicked() {
            if let Some(clause) = clause {
                *click = Some(Click {
                    clause: clause.to_owned(),
                    group: row.group,
                });
            }
        }
    });
}

fn bar_cell(ui: &mut egui::Ui, row: &Row, partial: bool) {
    let width = ui.available_width();
    let (rect, _) = ui.allocate_exact_size(
        egui::vec2(width, ui.available_height().max(10.0)),
        egui::Sense::hover(),
    );
    let track = egui::Rect::from_min_size(
        egui::pos2(rect.left(), rect.center().y - 3.0),
        egui::vec2((width - 46.0).max(10.0), 6.0),
    );
    let painter = ui.painter();
    painter.rect_filled(track, 2.0, crate::theme::line_soft());
    let fill = egui::Rect::from_min_size(
        track.min,
        egui::vec2(
            track.width() * (row.of_view / 100.0).clamp(0.0, 1.0) as f32,
            track.height(),
        ),
    );
    let color = if partial {
        crate::theme::muted()
    } else {
        crate::theme::blue()
    };
    painter.rect_filled(fill, 2.0, color);
    painter.text(
        egui::pos2(track.right() + 4.0, rect.center().y),
        egui::Align2::LEFT_CENTER,
        format!("{:.0}", row.of_view),
        egui::TextStyle::Small.resolve(ui.style()),
        crate::theme::muted(),
    );
}

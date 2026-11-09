// SPDX-License-Identifier: GPL-3.0-only
//! Bounded evidence tables and the jump from a row to its evidence.
use super::*;

use crate::widgets::fit_table;
pub(super) use antinomie_triage::table::*;

/// The process a Source cell names, from its row's values: `(pid, task cookie)`.
fn source_process(values: &[(&str, RowValue)]) -> Option<(u32, u64)> {
    let pid = files::number(values, "network.source_pid")?;
    let cookie = files::number(values, "network.source_cookie")?;
    (pid != 0 && cookie != 0).then_some((pid as u32, cookie))
}

/// An outcome cell "failed (EACCES)" gets the errno number on hover.
fn hover_errno(response: egui::Response, text: &str) {
    if let Some(hover) = crate::values::outcome_hover(text) {
        response.on_hover_text(hover);
    }
}

/// The pills of a cell, before its text.
fn cell_badges(ui: &mut egui::Ui, cell: &Cell) {
    for badge in &cell.badges {
        crate::widgets::chip(ui, badge.text.clone(), badge.tone.into()).on_hover_text(&badge.hover);
    }
}

/// The least height a table's body keeps. A section whose filters and notes
/// fill the pane leaves less than this under them; the page scrolls (see
/// `TriageView::show`) instead of squeezing the table out of reach.
pub(super) const MIN_TABLE_HEIGHT: f32 = 160.0;

pub(super) fn column_widths<'a>(
    ui: &egui::Ui,
    headers: &[&str],
    rows: impl Iterator<Item = &'a [Cell]> + Clone,
) -> Vec<f32> {
    headers
        .iter()
        .enumerate()
        .map(|(index, header)| {
            let (minimum, maximum) = match *header {
                "Endpoint" | "Endpoints" => (360.0_f32, 900.0_f32),
                "Path" | "URI" | "Hostname" | "Transferred / content" | "Argv" => (250.0, 650.0),
                "Time" | "First seen" | "Last seen" => (230.0, 500.0),
                "Behaviour" => (170.0, 260.0),
                "Source" => (200.0, 420.0),
                "Target" => (220.0, 560.0),
                "ATT&CK" => (150.0, 300.0),
                "When" => (150.0, 320.0),
                "Host" => (160.0, 400.0),
                "Summary" => (360.0, 800.0),
                "Observation" => (260.0, 340.0),
                _ => (100.0, 320.0),
            };
            let heading = ui.fonts_mut(|fonts| {
                fonts
                    .layout_no_wrap(
                        (*header).to_owned(),
                        egui::TextStyle::Body.resolve(ui.style()),
                        theme::text(),
                    )
                    .size()
                    .x
            }) + 24.0;
            let content = rows
                .clone()
                .take(128)
                .filter_map(|row| row.get(index))
                .max_by_key(|cell| cell.text.chars().count())
                .map_or(0.0, |cell| {
                    let font = if cell.mono {
                        egui::TextStyle::Monospace.resolve(ui.style())
                    } else {
                        egui::TextStyle::Body.resolve(ui.style())
                    };
                    ui.fonts_mut(|fonts| {
                        fonts
                            .layout_no_wrap(
                                cell.text.chars().take(256).collect(),
                                font,
                                cell.color(),
                            )
                            .size()
                            .x
                    }) + 24.0
                        + cell
                            .badges
                            .iter()
                            .map(|badge| 12.0 + 6.0 * badge.text.chars().count() as f32)
                            .sum::<f32>()
                });
            content.max(minimum).max(heading).min(maximum.max(heading))
        })
        .collect()
}

pub(super) fn table(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<Cell>]) {
    table_with(ui, id, headers, rows, None);
}

/// A table whose first column is a tree: `branches` holds the prefix of each
/// row, in the order of `rows`. A sorted table is flat and leaves them out.
pub(super) fn table_with(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Vec<Cell>],
    branches: Option<&[crate::tree_lines::Prefix]>,
) {
    table_rows_with(ui, id, headers, rows, branches);
    details::refresh(ui.ctx(), id, headers, rows);
}

/// What a row's menu offers for a note: a process is noted by its pid, a row
/// of call evidence by the event sequence its record has in the Syscall
/// Trace; other rows (packets, files without a call) have no reference yet.
fn row_extras(
    run: Option<&query::NoteRun>,
    table: &str,
    first: &str,
    values: &[(&str, RowValue)],
) -> query::RowMenuExtras {
    use antinomie_monitor_core::samples::{trace_target, NoteRef, RefKind};
    let Some(run) = run else {
        return query::RowMenuExtras::default();
    };
    let short: String = first.chars().take(48).collect();
    let packet = values.iter().any(|(key, _)| *key == "capture.path");
    let reference = if table == "triage-process" {
        files::number(values, "process.pid").map(|pid| {
            NoteRef::new(
                RefKind::Process,
                format!("{}/{}/{pid}", run.vm_id, run.run_id),
                format!("{short} {pid} · run {}", run.run_id),
            )
        })
    } else {
        files::number(values, "event.id")
            .filter(|_| !packet)
            .map(|seq| {
                NoteRef::new(
                    RefKind::Trace,
                    trace_target(&run.vm_id, &run.run_id, seq),
                    format!("Run {} · {short} · record {seq}", run.run_id),
                )
            })
    };
    run.extras(reference)
}

pub(super) fn request_evidence_jump(ctx: &egui::Context, values: &[(&str, RowValue)]) {
    // A finding found in packets carries a frame and no call.
    let packet = values.iter().any(|(key, _)| *key == "capture.path");
    if let Some(key) = files::number(values, "stream.id")
        .filter(|_| !packet)
        .zip(files::number(values, "process.cookie"))
        .zip(files::number(values, "event.id"))
    {
        let ((stream, task), call) = key;
        ctx.data_mut(|data| {
            data.insert_temp(egui::Id::new("triage-call-jump"), (stream, task, call))
        });
    } else if let Some(frame) = files::number(values, "frame.number") {
        ctx.data_mut(|data| data.insert_temp(egui::Id::new("triage-packet-jump"), frame));
        if let Some(path) = values.iter().find_map(|(key, value)| match (*key, value) {
            ("capture.path", RowValue::Text(path)) => Some(std::path::PathBuf::from(path)),
            _ => None,
        }) {
            ctx.data_mut(|data| data.insert_temp(egui::Id::new("triage-packet-capture"), path));
        }
    } else if let Some(path) = values.iter().find_map(|(key, value)| match (*key, value) {
        ("evidence.path", RowValue::Text(path)) => Some(std::path::PathBuf::from(path)),
        _ => None,
    }) {
        use antinomie_monitor_core::analysis::detection::Evidence;
        let report_id = values.iter().find_map(|(key, value)| match (*key, value) {
            ("evidence.report", RowValue::Text(id)) => Some(id.clone()),
            _ => None,
        });
        let evidence = Evidence::Bytes {
            path,
            offset: files::number(values, "evidence.offset"),
            address: files::number(values, "evidence.address"),
            report_id,
            block: values.iter().find_map(|(key, value)| match (*key, value) {
                ("evidence.block", RowValue::Text(value)) => serde_json::from_str(value).ok(),
                _ => None,
            }),
            input: values.iter().find_map(|(key, value)| match (*key, value) {
                ("evidence.input", RowValue::Text(value)) => {
                    serde_json::from_value(serde_json::Value::String(value.clone())).ok()
                }
                _ => None,
            }),
        };
        ctx.data_mut(|data| {
            data.insert_temp(egui::Id::new("triage-byte-jump"), evidence);
            data.insert_temp(egui::Id::new("triage-details-focus"), true);
        });
    }
}

/// The bar at a row's left edge: the selection, else a flagged file path.
fn mark_of(selected: bool, first: &Cell) -> fit_table::Mark {
    use fit_table::Mark;
    if selected {
        Mark::Selected
    } else if file_category::row_flagged(&first.values) {
        Mark::Flagged
    } else {
        Mark::None
    }
}

pub(super) fn table_rows(ui: &mut egui::Ui, id: &str, headers: &[&str], rows: &[Vec<Cell>]) {
    table_rows_with(ui, id, headers, rows, None);
}

fn table_rows_with(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Vec<Cell>],
    branches: Option<&[crate::tree_lines::Prefix]>,
) {
    use fit_table::{Col, FitBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return;
    }
    let mut widths = column_widths(ui, headers, rows.iter().map(Vec::as_slice));
    let order = sorting::order(ui.ctx(), id, headers, rows.iter().map(Vec::as_slice));
    // Sorted rows lose their tree: shown flat.
    let branches = branches.filter(|_| order.is_none());
    let branch_font = egui::TextStyle::Monospace.resolve(ui.style());
    let branch_char = crate::tree_lines::char_width(ui, &branch_font);
    if let (Some(branches), Some(first)) = (branches, widths.first_mut()) {
        let deepest = branches.iter().map(|prefix| prefix.width(branch_char));
        *first += deepest.fold(0.0, f32::max).min(branch_char * 64.0);
    }
    let font = ui.text_style_height(&egui::TextStyle::Body).max(14.0);
    let row_height = fit_table::row_height(font);
    let selected_id = egui::Id::new(("triage-selected-row", id));
    let selected = ui.ctx().data(|data| data.get_temp::<String>(selected_id));
    let filter_id = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("triage-filter-target", id))));
    let max_height = ui.available_height().max(MIN_TABLE_HEIGHT);
    // The columns are planned for the width this table really has (see
    // `fit_table`): the text column takes the spare width, the others keep
    // their content width while it fits and give way, cut with an ellipsis,
    // when it does not.
    let remainder = if id == "triage-bpf" {
        1
    } else {
        headers.len() - 1
    };
    let cols: Vec<Col> = widths
        .iter()
        .enumerate()
        .map(|(index, width)| {
            if index == remainder {
                Col::rest(
                    width
                        .min(if id == "triage-bpf" { 260.0 } else { 140.0 })
                        .max(80.0),
                )
            } else if matches!(headers[index], "Time" | "Endpoint" | "Endpoints") {
                Col::fixed(*width).min(120.0).resizable(true)
            } else {
                Col::flex(*width).min(64.0).resizable(true)
            }
        })
        .collect();
    let mut builder = FitBuilder::new(ui)
        .id_salt(("triage-062", id))
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .vscroll(true)
        .max_scroll_height(max_height)
        .min_scrolled_height(0.0)
        .sense(egui::Sense::click());
    for col in cols {
        builder = builder.column(col);
    }
    builder
        .header(fit_table::header_height(font), |mut header| {
            for (column, title) in headers.iter().enumerate() {
                header.col(|ui| {
                    fit_table::aligned(ui, fit_table::numeric_align(numeric_column(title)), |ui| {
                        sorting::header(ui, id, column, title)
                    });
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let cells = &rows[order
                    .as_ref()
                    .map_or(row.index(), |order| order[row.index()])];
                let key = evidence_key(cells);
                let row_selected = selected.as_ref() == Some(&key);
                row.set_selected(row_selected);
                let branch = branches.map(|branches| &branches[row.index()]);
                for (column, cell) in cells.iter().enumerate() {
                    row.col(|ui| {
                        if column == 0 {
                            fit_table::row_mark(ui, mark_of(row_selected, cell));
                        }
                        let indent = branch.filter(|_| column == 0).map(|branch| {
                            let reach = ui.spacing().item_spacing.y * 0.5;
                            let lines = ui.max_rect().expand2(egui::vec2(0.0, reach));
                            branch.paint(ui.painter(), lines, branch_char);
                            branch.width(branch_char)
                        });
                        // A Source that names a process opens it in Details.
                        let source_link = (id == "triage-endpoints" && headers[column] == "Source")
                            .then(|| source_process(&cells[0].values))
                            .flatten();
                        let mut text = RichText::new(display_cell(&cell.text)).color(
                            if source_link.is_some() {
                                ui.visuals().hyperlink_color
                            } else {
                                cell.color()
                            },
                        );
                        if cell.mono {
                            text = text.monospace();
                        }
                        let label = egui::Label::new(text).truncate().selectable(false).sense(
                            if source_link.is_some() {
                                egui::Sense::click()
                            } else {
                                egui::Sense::hover()
                            },
                        );
                        // A process cell may carry a note of its own (the full
                        // path, why a command line is flagged, a time).
                        let note = (id == "triage-process")
                            .then(|| process_tree::cell_hover(column, cell, &cells[0]))
                            .flatten();
                        let hover = |response: egui::Response| {
                            let response = match source_link {
                                Some((pid, cookie)) => {
                                    let response =
                                        response.on_hover_cursor(egui::CursorIcon::PointingHand);
                                    if response.clicked() {
                                        response.ctx.data_mut(|data| {
                                            data.insert_temp(
                                                egui::Id::new(finding_cells::OPEN_PROCESS),
                                                (pid, cookie),
                                            )
                                        });
                                    }
                                    response
                                }
                                None => response,
                            };
                            match (&note, &cell.note) {
                                (Some(note), _) | (None, Some(note)) => {
                                    let note = if source_link.is_some() {
                                        format!("{note}\n\nClick to open this process in Details.")
                                    } else {
                                        note.clone()
                                    };
                                    response.on_hover_text(note);
                                }
                                (None, None) => hover_errno(response, &cell.text),
                            }
                        };
                        let draw = |ui: &mut egui::Ui| match indent {
                            Some(width) => {
                                let mut rect = ui.max_rect();
                                rect.min.x += width;
                                ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                                    cell_badges(ui, cell);
                                    hover(ui.add(label));
                                });
                            }
                            None => {
                                cell_badges(ui, cell);
                                hover(ui.add(label));
                            }
                        };
                        // The count of findings is a chip in the Findings column,
                        // in the colour of the worst tier among them; it lists them.
                        let suspect = (id == "triage-process" && headers[column] == "Findings")
                            .then(|| files::number(&cells[0].values, "process.suspicious"))
                            .flatten();
                        if let Some(count) = suspect {
                            if count > 0 {
                                let tone = cells[0]
                                    .values
                                    .iter()
                                    .find_map(|(key, value)| match value {
                                        RowValue::Text(tag) if *key == "process.worst_tier" => {
                                            rules::Tier::from_tag(tag)
                                        }
                                        _ => None,
                                    })
                                    .map_or(crate::widgets::Tone::Neutral, |tier| {
                                        tier.tone().into()
                                    });
                                let chip = crate::widgets::chip(ui, count.to_string(), tone);
                                let chip = ui.interact(
                                    chip.rect,
                                    chip.id.with("list-findings"),
                                    egui::Sense::click(),
                                );
                                if chip
                                    .on_hover_text("Findings in this process. Click to list them.")
                                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                                    .clicked()
                                {
                                    if let Some(pid) =
                                        files::number(&cells[0].values, "process.pid")
                                    {
                                        ui.ctx().data_mut(|data| {
                                            data.insert_temp(
                                                egui::Id::new(process_details::PROCESS_SCOPE),
                                                pid,
                                            )
                                        });
                                    }
                                }
                            }
                        } else {
                            fit_table::aligned_cell(
                                ui,
                                fit_table::numeric_align(numeric_column(headers[column])),
                                draw,
                            );
                        }
                    });
                }
                if row.response().clicked() {
                    details::select(&row.response().ctx, id, headers, cells);
                    details::clicked(&row.response().ctx, id);
                    row.response()
                        .ctx
                        .data_mut(|data| data.insert_temp(selected_id, key));
                }
                if row.response().double_clicked() {
                    request_evidence_jump(
                        &row.response().ctx,
                        cells
                            .first()
                            .map(|cell| cell.values.as_slice())
                            .unwrap_or_default(),
                    );
                }
                let values = cells
                    .first()
                    .map(|cell| cell.values.as_slice())
                    .unwrap_or_default();
                let extras = row_extras(
                    query::NoteRun::get(&row.response().ctx).as_ref(),
                    id,
                    cells.first().map_or("", |cell| cell.text.as_str()),
                    values,
                );
                row.response().context_menu(|ui| {
                    file_activity::reconstruct_menu(ui, id, values);
                    file_shown::copy_hash_menu(ui, values);
                    match filter_id {
                        Some(filter_id) => {
                            query::table_row_menu_with(ui, filter_id, values, extras)
                        }
                        None => query::row_menu_plain(
                            ui,
                            egui::Id::new((id, "row-menu")),
                            values,
                            extras,
                        ),
                    }
                });
            });
        });
}

/// Suspicious-activity rows. A click returns that invocation's `call_id`.
pub(super) fn finding_table(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Finding],
    selected: Option<trace::InvocationKey>,
    scroll_to: Option<trace::InvocationKey>,
) -> Option<trace::InvocationKey> {
    let clicked = finding_table_rows(ui, id, headers, rows, selected, scroll_to);
    details::refresh_findings(ui.ctx(), id, headers, rows);
    clicked
}

/// Columns whose cells are numbers (ids, frames, counts): their header and
/// cells sit at the right edge, as in the other tables of the app.
fn numeric_column(header: &str) -> bool {
    matches!(
        header,
        "TID"
            | "Frame"
            | "Response frame"
            | "Occurrences"
            | "Diff count"
            | "Offset"
            | "Length"
            | "Requests"
            | "Rcode"
            | "Evidence"
            | "Calls"
    )
}

/// The stored columns of a table in the order they are laid out. The
/// Suspicious activity table lays out only [`rules::SHOWN`]; its other columns
/// stay in the row, where the filters, sorts, exports and Details read them.
pub(super) fn display_order(id: &str, count: usize) -> Vec<usize> {
    if id == "triage-findings" && count == rules::HEADERS.len() {
        return rules::SHOWN.to_vec();
    }
    (0..count).collect()
}

fn finding_table_rows(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Finding],
    selected: Option<trace::InvocationKey>,
    scroll_to: Option<trace::InvocationKey>,
) -> Option<trace::InvocationKey> {
    use fit_table::{Col, FitBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return None;
    }
    let mut widths = column_widths(ui, headers, rows.iter().map(|row| row.cells.as_slice()));
    // The columns as they are laid out: Time leads the Suspicious activity table.
    let shown = display_order(id, headers.len());
    widths = shown.iter().map(|&column| widths[column]).collect();
    let order = sorting::order(
        ui.ctx(),
        id,
        headers,
        rows.iter().map(|row| row.cells.as_slice()),
    );
    let mut clicked = None;
    let filter_id = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("triage-filter-target", id))));
    let font = ui.text_style_height(&egui::TextStyle::Body).max(14.0);
    let row_height = fit_table::row_height(font);
    let max_height = ui.available_height().max(MIN_TABLE_HEIGHT);
    let last = shown.len() - 1;
    let cols: Vec<Col> = widths
        .iter()
        .enumerate()
        .map(|(index, width)| {
            if index == last {
                Col::rest(width.clamp(80.0, 140.0))
            } else {
                Col::flex(*width).min(64.0).resizable(true)
            }
        })
        .collect();
    let mut builder = FitBuilder::new(ui)
        .id_salt(("triage-062", id))
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .vscroll(true)
        .max_scroll_height(max_height)
        .min_scrolled_height(0.0)
        .sense(egui::Sense::click());
    for col in cols {
        builder = builder.column(col);
    }
    // A row picked in the graph: scroll the table to where it sits now.
    if let Some(shown) = scroll_to.and_then(|key| {
        (0..rows.len()).find(|at| rows[order.as_ref().map_or(*at, |order| order[*at])].key == key)
    }) {
        builder = builder.scroll_to_row(shown, Some(egui::Align::Center));
    }
    builder
        .header(fit_table::header_height(font), |mut header| {
            // A header sorts by the stored column it shows, so the sort the
            // query asks for needs no translation.
            for &column in &shown {
                let title = headers[column];
                header.col(|ui| {
                    fit_table::aligned(ui, fit_table::numeric_align(numeric_column(title)), |ui| {
                        sorting::header(ui, id, column, title)
                    });
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let finding = &rows[order
                    .as_ref()
                    .map_or(row.index(), |order| order[row.index()])];
                row.set_selected(selected == Some(finding.key));
                for &column in &shown {
                    let Some(cell) = finding.cells.get(column) else {
                        row.col(|_| {});
                        continue;
                    };
                    row.col(|ui| {
                        let align = fit_table::numeric_align(numeric_column(
                            headers.get(column).copied().unwrap_or_default(),
                        ));
                        fit_table::aligned_cell(ui, align, |ui| {
                            finding_cells::draw(ui, column, finding, cell)
                        });
                    });
                }
                if row.response().clicked() {
                    clicked = Some(finding.key);
                    let mut cells = finding.cells.clone();
                    if let Some(first) = cells.first_mut() {
                        first.values.clone_from(&finding.values);
                    }
                    details::select(&row.response().ctx, id, headers, &cells);
                    details::clicked(&row.response().ctx, id);
                }
                if row.response().double_clicked() {
                    request_evidence_jump(&row.response().ctx, &finding.values);
                }
                let extras = row_extras(
                    query::NoteRun::get(&row.response().ctx).as_ref(),
                    id,
                    finding.cells.first().map_or("", |cell| cell.text.as_str()),
                    &finding.values,
                );
                row.response().context_menu(|ui| match filter_id {
                    Some(filter_id) => {
                        query::table_row_menu_with(ui, filter_id, &finding.values, extras)
                    }
                    None => query::row_menu_plain(
                        ui,
                        egui::Id::new((id, "row-menu")),
                        &finding.values,
                        extras,
                    ),
                });
            });
        });
    clicked
}

#[cfg(test)]
mod display_tests {
    use super::*;

    #[test]
    fn the_suspicious_activity_table_lays_out_its_eight_columns_and_no_other_table_does() {
        let count = rules::HEADERS.len();
        let shown: Vec<&str> = display_order("triage-findings", count)
            .into_iter()
            .map(|column| rules::HEADERS[column])
            .collect();
        assert_eq!(
            shown,
            [
                "Tier",
                "Behaviour",
                "Target",
                "Process",
                "ATT&CK",
                "Count",
                "Result",
                "When"
            ]
        );
        // Other tables, and a findings table of another width, keep theirs.
        assert_eq!(display_order("triage-opened", 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(display_order("triage-findings", 3), vec![0, 1, 2]);
    }
}

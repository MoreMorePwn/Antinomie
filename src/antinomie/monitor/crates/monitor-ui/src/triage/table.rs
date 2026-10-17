// SPDX-License-Identifier: MIT
//! Bounded evidence tables and the jump from a row to its evidence.
use super::*;

pub(super) fn cell(text: impl Into<String>, color: egui::Color32, mono: bool) -> Cell {
    Cell {
        text: text.into(),
        color,
        mono,
        values: Vec::new(),
    }
}

/// Characters a table cell shows. A cut cell's hover text is its shown text,
/// so this also bounds the hover box; Details keeps the whole value.
const CELL_TEXT_MAX: usize = 240;

/// Keep the unresolved directory reason in Details while shortening table text.
pub(super) fn display_text(text: &str) -> String {
    text.replace("(relative, cwd not recorded)", "(relative)")
        .replace("(relative, dirfd not recorded)", "(relative)")
}

fn display_cell(text: &str) -> String {
    bounded_cell(&display_text(text))
}

fn bounded_cell(text: &str) -> String {
    match text.char_indices().nth(CELL_TEXT_MAX) {
        Some((end, _)) => format!("{}… (full value in Details)", &text[..end]),
        None => text.to_owned(),
    }
}

#[cfg(test)]
pub(super) fn push_limited(limited: &mut LimitedRows, row: Vec<Cell>) -> bool {
    limited.rows.push(row);
    true
}

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
                "Host" => (160.0, 400.0),
                "Summary" => (360.0, 800.0),
                _ => (100.0, 320.0),
            };
            let heading = ui.fonts(|fonts| {
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
                    ui.fonts(|fonts| {
                        fonts
                            .layout_no_wrap(cell.text.chars().take(256).collect(), font, cell.color)
                            .size()
                            .x
                    }) + 24.0
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
    egui::ScrollArea::horizontal()
        .id_salt((id, "columns"))
        .auto_shrink([false, true])
        .show(ui, |ui| table_rows_with(ui, id, headers, rows, branches));
    details::refresh(ui.ctx(), id, headers, rows);
}

pub(super) fn evidence_key(row: &[Cell]) -> String {
    let identity = evidence_values_key(
        row.first()
            .map(|cell| cell.values.as_slice())
            .unwrap_or_default(),
    );
    if identity.is_empty() {
        row.iter()
            .map(|cell| cell.text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        identity
    }
}

pub(super) fn evidence_values_key(values: &[(&str, RowValue)]) -> String {
    values
        .iter()
        .filter(|(name, _)| {
            matches!(
                *name,
                "event.id"
                    | "stream.id"
                    | "frame.number"
                    | "dns.name"
                    | "http.uri"
                    | "process.cookie"
                    | "finding.rule"
                    | "finding.engine"
                    | "capture.path"
            )
        })
        .map(|(name, value)| format!("{name}:{value:?}"))
        .collect::<Vec<_>>()
        .join("/")
}

pub(super) fn request_evidence_jump(ctx: &egui::Context, values: &[(&str, RowValue)]) {
    if let Some(key) = files::number(values, "stream.id")
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
        };
        ctx.data_mut(|data| {
            data.insert_temp(egui::Id::new("triage-byte-jump"), evidence);
            data.insert_temp(egui::Id::new("triage-details-focus"), true);
        });
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
    use egui_extras::{Column, TableBuilder};
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
    ui.set_width(
        (widths.iter().sum::<f32>()
            + ui.spacing().item_spacing.x * headers.len().saturating_sub(1) as f32
            + 16.0)
            .max(ui.available_width()),
    );
    let row_height = ui.text_style_height(&egui::TextStyle::Body).max(14.0) + 8.0;
    let selected_id = egui::Id::new(("triage-selected-row", id));
    let selected = ui.ctx().data(|data| data.get_temp::<String>(selected_id));
    let filter_id = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("triage-filter-target", id))));
    let max_height = ui.available_height().max(60.0);
    let mut builder = TableBuilder::new(ui)
        .id_salt(("triage-062", id))
        .striped(true)
        .resizable(true)
        .vscroll(true)
        .max_scroll_height(max_height)
        .min_scrolled_height(0.0)
        .sense(egui::Sense::click());
    for (index, width) in widths.into_iter().enumerate() {
        let minimum = if matches!(headers[index], "Time" | "Endpoint" | "Endpoints") {
            width
        } else {
            64.0
        };
        builder = if index + 1 == headers.len() {
            builder.column(Column::remainder().at_least(width))
        } else {
            builder.column(Column::initial(width).at_least(minimum).resizable(true))
        };
    }
    builder
        .header(row_height, |mut header| {
            for (column, title) in headers.iter().enumerate() {
                header.col(|ui| {
                    sorting::header(ui, id, column, title);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let cells = &rows[order
                    .as_ref()
                    .map_or(row.index(), |order| order[row.index()])];
                let key = evidence_key(cells);
                row.set_selected(selected.as_ref() == Some(&key));
                let branch = branches.map(|branches| &branches[row.index()]);
                for (column, cell) in cells.iter().enumerate() {
                    row.col(|ui| {
                        let indent = branch.filter(|_| column == 0).map(|branch| {
                            let reach = ui.spacing().item_spacing.y * 0.5;
                            let lines = ui.max_rect().expand2(egui::vec2(0.0, reach));
                            branch.paint(ui.painter(), lines, branch_char);
                            branch.width(branch_char)
                        });
                        let mut text = RichText::new(display_cell(&cell.text)).color(cell.color);
                        if cell.mono {
                            text = text.monospace();
                        }
                        let label = egui::Label::new(text)
                            .truncate()
                            .selectable(false)
                            .sense(egui::Sense::hover());
                        match indent {
                            Some(width) => {
                                let mut rect = ui.max_rect();
                                rect.min.x += width;
                                ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
                                    ui.add(label);
                                });
                            }
                            None => {
                                ui.add(label);
                            }
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
                if let Some(filter_id) = filter_id {
                    row.response().context_menu(|ui| {
                        query::table_row_menu(
                            ui,
                            filter_id,
                            cells
                                .first()
                                .map(|cell| cell.values.as_slice())
                                .unwrap_or_default(),
                        );
                    });
                }
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
) -> Option<trace::InvocationKey> {
    let clicked = egui::ScrollArea::horizontal()
        .id_salt((id, "columns"))
        .auto_shrink([false, true])
        .show(ui, |ui| finding_table_rows(ui, id, headers, rows, selected))
        .inner;
    details::refresh_findings(ui.ctx(), id, headers, rows);
    clicked
}

fn finding_table_rows(
    ui: &mut egui::Ui,
    id: &str,
    headers: &[&str],
    rows: &[Finding],
    selected: Option<trace::InvocationKey>,
) -> Option<trace::InvocationKey> {
    use egui_extras::{Column, TableBuilder};
    if rows.is_empty() {
        ui.colored_label(theme::muted(), "Nothing recorded for this view.");
        return None;
    }
    let widths = column_widths(ui, headers, rows.iter().map(|row| row.cells.as_slice()));
    let order = sorting::order(
        ui.ctx(),
        id,
        headers,
        rows.iter().map(|row| row.cells.as_slice()),
    );
    ui.set_width(
        (widths.iter().sum::<f32>()
            + ui.spacing().item_spacing.x * headers.len().saturating_sub(1) as f32
            + 16.0)
            .max(ui.available_width()),
    );
    let mut clicked = None;
    let filter_id = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new(("triage-filter-target", id))));
    let row_height = ui.text_style_height(&egui::TextStyle::Body).max(14.0) + 8.0;
    let max_height = ui.available_height().max(60.0);
    let mut builder = TableBuilder::new(ui)
        .id_salt(("triage-062", id))
        .striped(true)
        .resizable(true)
        .vscroll(true)
        .max_scroll_height(max_height)
        .min_scrolled_height(0.0)
        .sense(egui::Sense::click());
    for (index, width) in widths.into_iter().enumerate() {
        builder = if index + 1 == headers.len() {
            builder.column(Column::remainder().at_least(width))
        } else {
            builder.column(Column::initial(width).at_least(64.0).resizable(true))
        };
    }
    builder
        .header(row_height, |mut header| {
            for (column, title) in headers.iter().enumerate() {
                header.col(|ui| {
                    sorting::header(ui, id, column, title);
                });
            }
        })
        .body(|body| {
            body.rows(row_height, rows.len(), |mut row| {
                let finding = &rows[order
                    .as_ref()
                    .map_or(row.index(), |order| order[row.index()])];
                row.set_selected(selected == Some(finding.key));
                for cell in &finding.cells {
                    row.col(|ui| {
                        let mut text = RichText::new(bounded_cell(&cell.text)).color(cell.color);
                        if cell.mono {
                            text = text.monospace();
                        }
                        ui.add(
                            egui::Label::new(text)
                                .truncate()
                                .selectable(false)
                                .sense(egui::Sense::hover()),
                        );
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
                if let Some(filter_id) = filter_id {
                    row.response()
                        .context_menu(|ui| query::table_row_menu(ui, filter_id, &finding.values));
                }
            });
        });
    clicked
}

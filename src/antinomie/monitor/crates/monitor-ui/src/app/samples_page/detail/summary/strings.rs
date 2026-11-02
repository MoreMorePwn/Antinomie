// SPDX-License-Identifier: GPL-3.0-only
//! The Summary tab's Interesting strings and Regex matches tables.
use super::*;

/// Rows the Interesting strings and Regex matches tables show before they
/// scroll inside their own area.
const VISIBLE_ROWS: usize = 10;

/// Interesting strings (the 100 longest) and Regex matches below them.
pub(super) fn strings(
    ui: &mut egui::Ui,
    data: &Data,
    scanned: &Scanned,
    go: &mut Option<Go>,
    font: f32,
) {
    let reference = data.report.as_ref();
    parts::section(
        ui,
        "Interesting strings",
        match scanned {
            Scanned::Done(strings) => Some(strings.longest.len()),
            _ => None,
        },
        |ui| match (scanned, reference) {
            (Scanned::None, _) | (_, None) => parts::muted_line(ui, "Not analysed."),
            (Scanned::Reading, _) => {
                theme::loading_weak(ui, "Reading the strings…");
            }
            (Scanned::Failed(error), _) => {
                ui.colored_label(theme::error(), error);
            }
            (Scanned::Done(strings), Some(reference)) => {
                let rows: Vec<&StringRow> = strings.longest.iter().collect();
                string_table(
                    ui,
                    "sample_summary_strings",
                    &rows,
                    &["Length", "String", "Offset"],
                    font,
                    |row| {
                        vec![
                            row.length.to_string(),
                            row.shown.clone(),
                            row.found_in.clone(),
                        ]
                    },
                    "No strings.",
                );
                let total = strings_total(&reference.report);
                if parts::open_all(
                    ui,
                    &format!("Open Strings ({})", crate::values::thousands(total)),
                ) {
                    *go = Some(Go::Report(AnalysisKind::Strings));
                }
            }
        },
    );
    // The scan is of the report's strings: no report, no matches section.
    let (Scanned::Done(strings), Some(_)) = (scanned, reference) else {
        return;
    };
    parts::section(ui, "Regex matches", Some(strings.total as usize), |ui| {
        let filter_id = egui::Id::new("sample_summary_regex_category");
        let mut chosen: Option<Category> = ui.data(|d| d.get_temp(filter_id)).flatten();
        ui.horizontal_wrapped(|ui| {
            let all = widgets::toggle_chip(
                ui,
                "All",
                chosen.is_none(),
                Some(strings.matches.len() as u64),
            );
            if all.clicked() {
                chosen = None;
            }
            for category in Category::ALL {
                let count = strings
                    .matches
                    .iter()
                    .filter(|row| row.category == category)
                    .count();
                if count == 0 {
                    continue;
                }
                if widgets::toggle_chip(
                    ui,
                    category.label(),
                    chosen == Some(category),
                    Some(count as u64),
                )
                .clicked()
                {
                    chosen = Some(category);
                }
            }
        });
        ui.data_mut(|d| d.insert_temp(filter_id, chosen));
        let rows: Vec<&StringRow> = strings
            .matches
            .iter()
            .filter(|row| chosen.is_none_or(|category| row.category == category))
            .collect();
        string_table(
            ui,
            "sample_summary_regex",
            &rows,
            &["Category", "Type", "Match", "Found in", "Seen"],
            font,
            |row| {
                vec![
                    row.category.label().to_owned(),
                    row.kind.clone(),
                    row.shown.clone(),
                    row.found_in.clone(),
                    row.seen.to_string(),
                ]
            },
            "No regex matches.",
        );
        if parts::open_all(
            ui,
            &format!(
                "Open Regex matches ({})",
                crate::values::thousands(strings.total)
            ),
        ) {
            *go = Some(Go::Report(AnalysisKind::Regex));
        }
    });
}

/// How many strings the report's Strings tab lists.
fn strings_total(report: &antinomie_monitor_core::AnalysisReport) -> u64 {
    report
        .sections
        .iter()
        .find(|section| section.kind == AnalysisKind::Strings)
        .map_or(0, counted)
}

pub(super) fn counted(section: &AnalysisSection) -> u64 {
    section
        .listing
        .as_ref()
        .map_or(section.entries.len() as u64, |listing| listing.rows)
}

/// Rows of text cells in a table that scrolls inside its own area (about ten
/// rows show); one line each with the full text in the tooltip.
fn string_table(
    ui: &mut egui::Ui,
    id: &str,
    rows: &[&StringRow],
    titles: &[&str],
    font: f32,
    cells: impl Fn(&antinomie_monitor_core::samples::StringRow) -> Vec<String>,
    empty: &str,
) {
    if rows.is_empty() {
        parts::muted_line(ui, empty);
        return;
    }
    let shown = rows;
    let wide = if titles.len() == 3 { 1 } else { 2 };
    // Text columns are as wide as their longest name (header and shown rows),
    // so "Linux behaviour" and "Persistence path" are not cut; the string
    // column takes what is left.
    let body = egui::TextStyle::Body.resolve(ui.style());
    let ui_ref: &egui::Ui = ui;
    let fitted = |index: usize| -> f32 {
        parts::fitted(
            ui_ref,
            &body,
            std::iter::once(titles[index].to_owned())
                .chain(shown.iter().map(|row| cells(row).swap_remove(index))),
        )
    };
    let widths: Vec<f32> = (0..titles.len())
        .map(|index| {
            if index == wide {
                0.0
            } else if matches!(titles[index], "Seen" | "Length") {
                60.0
            } else if titles[index] == "Found in" || titles[index] == "Offset" {
                // Mono text: "Strings · 0x0019", whole.
                parts::fitted_up_to(
                    ui_ref,
                    &egui::TextStyle::Monospace.resolve(ui_ref.style()),
                    std::iter::once(titles[index].to_owned())
                        .chain(shown.iter().map(|row| cells(row).swap_remove(index))),
                    320.0,
                )
            } else {
                fitted(index)
            }
        })
        .collect();
    // The string column keeps at least this much; fit_table shrinks the
    // other columns (text cut, whole on hover) before the table would pass
    // the window.
    let keep = 160.0;
    parts::on_surface(ui, |ui| {
        let mut builder = parts::mini_table(ui, id);
        for (index, _) in titles.iter().enumerate() {
            builder = builder.column(if index == wide {
                crate::widgets::fit_table::Col::rest(80.0)
                    .at_least(keep)
                    .clip(true)
            } else {
                crate::widgets::fit_table::Col::flex(widths[index])
                    .at_least(48.0)
                    .clip(true)
            });
        }
        // Like the Samples list: the columns can be dragged.
        let row_height = table::list_row_height(font);
        builder
            .resizable(true)
            .vscroll(true)
            .max_scroll_height(row_height * VISIBLE_ROWS as f32)
            .min_scrolled_height(row_height * shown.len().min(VISIBLE_ROWS) as f32)
            .header(table::header_height(font), |mut header| {
                for title in titles {
                    header.col(|ui| {
                        table::head_aligned(
                            ui,
                            title,
                            table::numeric_align(matches!(*title, "Seen" | "Length")),
                        )
                    });
                }
            })
            .body(|body| {
                body.rows(table::list_row_height(font), shown.len(), |mut row| {
                    let values = cells(shown[row.index()]);
                    for (index, value) in values.iter().enumerate() {
                        row.col(|ui| {
                            let kind = if index == wide {
                                table::Cell::Mono
                            } else if matches!(titles[index], "Seen" | "Length") {
                                table::Cell::Number
                            } else if titles[index] == "Found in" || titles[index] == "Offset" {
                                table::Cell::Mono
                            } else {
                                table::Cell::Text
                            };
                            let shown = table::cell_rich(
                                ui,
                                kind,
                                RichText::new(value).color(if index == wide {
                                    theme::text()
                                } else {
                                    theme::muted()
                                }),
                            );
                            shown.on_hover_text(value);
                        });
                    }
                });
            });
    });
}

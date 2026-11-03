// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's "Files written": one row for each file the sample's runs
//! wrote, rewrote, deleted or renamed, from the runs' Triage digests. A run
//! Triage has not read yet has no list, and the section says so. The
//! recording keeps the bytes; Export bytes opens the file's reconstruction in
//! Triage, where they are saved. A deleted file is exported as it was just
//! before the delete, checked against the guest's hash taken then.
use super::{parts, *};
use crate::widgets::fit_table;
use antinomie_monitor_core::run_digest::WrittenFile;

/// The width the three buttons of a row need on one line.
const ACTIONS_WIDTH: f32 = 650.0;
/// Rows shown before "Show more".
const PAGE: usize = 100;

/// What a click in the table asks for.
pub(in crate::app::samples_page) enum Act {
    /// Open the file in the run's Per-file history.
    History(usize, String),
    /// Open the file's reconstruction, where its bytes are saved.
    Export(usize, String),
    /// Open the run in Triage so it reads its files.
    GoToRun(usize),
}

struct Row<'a> {
    number: usize,
    file: &'a WrittenFile,
}

fn short_hash(hash: &str) -> String {
    if hash.is_empty() {
        "–".into()
    } else {
        hash.chars().take(12).collect()
    }
}

/// Draw the section; returns what was clicked.
pub(in crate::app::samples_page) fn section(
    ui: &mut egui::Ui,
    data: &Data,
    font: f32,
) -> Option<Act> {
    let mut act = None;
    let rows: Vec<Row> = data
        .runs
        .iter()
        .filter(|entry| entry.folder)
        .flat_map(|entry| {
            entry
                .digest
                .as_ref()
                .and_then(|digest| digest.files.as_deref())
                .unwrap_or_default()
                .iter()
                .map(move |file| Row {
                    number: entry.number,
                    file,
                })
        })
        .collect();
    let unread = data
        .runs
        .iter()
        .filter(|entry| {
            entry.folder
                && entry
                    .digest
                    .as_ref()
                    .is_none_or(|digest| digest.files.is_none())
        })
        .count();
    if rows.is_empty() && unread == 0 {
        return None;
    }
    parts::section(ui, "Files written", Some(rows.len()), |ui| {
        if unread > 0 {
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{unread} run{} not read by Triage yet, so their files are not listed.",
                        if unread == 1 { " is" } else { "s are" }
                    ))
                    .color(theme::muted()),
                );
                if let Some(entry) = data.runs.iter().find(|entry| {
                    entry.folder
                        && entry
                            .digest
                            .as_ref()
                            .is_none_or(|digest| digest.files.is_none())
                }) {
                    if parts::more_inline(
                        ui,
                        &format!("Open {} in Triage ›", parts::run_name(entry.number)),
                    )
                    .on_hover_text("Triage reads the run's files and keeps the list")
                    .clicked()
                    {
                        act = Some(Act::GoToRun(entry.number));
                    }
                }
            });
        }
        if rows.is_empty() {
            return;
        }
        let filter_id = egui::Id::new("sample_files_written_filter");
        let limit_id = egui::Id::new("sample_files_written_limit");
        let mut filter = ui
            .ctx()
            .data(|d| d.get_temp::<String>(filter_id))
            .unwrap_or_default();
        let limit = ui
            .ctx()
            .data(|d| d.get_temp::<usize>(limit_id))
            .unwrap_or(PAGE);
        ui.horizontal(|ui| {
            ui.label(RichText::new("Filter").color(theme::muted()));
            ui.add(
                egui::TextEdit::singleline(&mut filter)
                    .hint_text(theme::hint_text("path or state"))
                    .desired_width(220.0),
            );
        });
        let needle = filter.trim().to_lowercase();
        let shown: Vec<&Row> = rows
            .iter()
            .filter(|row| {
                needle.is_empty()
                    || row.file.path.to_lowercase().contains(&needle)
                    || row.file.state.to_lowercase().contains(&needle)
            })
            .collect();
        ui.ctx().data_mut(|d| d.insert_temp(filter_id, filter));
        let page: &[&Row] = &shown[..shown.len().min(limit)];
        ui.add_space(4.0);
        let mono = egui::TextStyle::Monospace.resolve(ui.style());
        let hash = parts::fitted(ui, &mono, ["SHA-256".to_owned(), "000000000000".to_owned()]);
        let body = egui::TextStyle::Body.resolve(ui.style());
        let state = parts::fitted_up_to(
            ui,
            &body,
            std::iter::once("State".to_owned())
                .chain(page.iter().map(|row| row.file.state.clone())),
            220.0,
        );
        let size = parts::fitted(
            ui,
            &body,
            std::iter::once("Size".to_owned()).chain(page.iter().map(|row| {
                row.file.size.map_or(
                    "–".to_owned(),
                    antinomie_monitor_core::byte_size::short_size,
                )
            })),
        );
        // The three buttons need about this much; a narrower table keeps one
        // Actions button that opens them.
        let room = ui.available_width() - ui.spacing().item_spacing.x * 6.0;
        let roomy = room - (160.0 + 70.0 + state + size + hash) >= ACTIONS_WIDTH;
        let actions = if roomy { ACTIONS_WIDTH } else { 90.0 };
        parts::on_surface(ui, |ui| {
            parts::click_table(ui, "sample_summary_files_written")
                .column(crate::widgets::fit_table::Col::rest(160.0).clip(true))
                .column(crate::widgets::fit_table::Col::fixed(70.0))
                .column(crate::widgets::fit_table::Col::fixed(state).clip(true))
                .column(crate::widgets::fit_table::Col::fixed(size))
                .column(crate::widgets::fit_table::Col::fixed(hash))
                .column(crate::widgets::fit_table::Col::fixed(actions))
                .header(fit_table::header_height(font), |mut header| {
                    for title in ["File", "Run", "State", "Size", "SHA-256", ""] {
                        header.col(|ui| fit_table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(fit_table::row_height(font) + 6.0, page.len(), |mut row| {
                        let item = page[row.index()];
                        let file = item.file;
                        row.col(|ui| {
                            fit_table::cell(ui, fit_table::Cell::Mono, &file.path)
                                .on_hover_text(&file.path);
                        });
                        row.col(|ui| {
                            ui.label(parts::run_name(item.number));
                        });
                        row.col(|ui| {
                            ui.add(egui::Label::new(&file.state).truncate())
                                .on_hover_text(&file.state);
                        });
                        row.col(|ui| {
                            ui.label(
                                file.size
                                    .map_or("–".to_owned(), antinomie_monitor_core::byte_size::short_size),
                            );
                        });
                        row.col(|ui| {
                            fit_table::cell(ui, fit_table::Cell::Mono, &short_hash(&file.sha256))
                                .on_hover_text(if file.sha256.is_empty() {
                                    if file.hash_note.is_empty() {
                                        "The guest took no hash of this file"
                                    } else {
                                        file.hash_note.as_str()
                                    }
                                } else {
                                    file.sha256.as_str()
                                });
                        });
                        row.col(|ui| {
                            let buttons = |ui: &mut egui::Ui| {
                                if ui
                                    .add(egui::Button::new("Open in Per-file history").small())
                                    .on_hover_text("Show this file's history in the run's Triage")
                                    .clicked()
                                {
                                    act = Some(Act::History(item.number, file.path.clone()));
                                    ui.close_menu();
                                }
                                let deleted = file.state == "deleted";
                                if ui
                                    .add(
                                        egui::Button::new(if deleted {
                                            "Export bytes (as before deletion)"
                                        } else {
                                            "Export bytes"
                                        })
                                        .small(),
                                    )
                                    .on_hover_text(if deleted {
                                        "Open the file's reconstruction in Triage: its bytes are rebuilt \
                                         from the recorded writes as of the last moment before the \
                                         delete, checked against the guest's hash taken then, and saved"
                                    } else {
                                        "Open the file's reconstruction in Triage, where its bytes are saved"
                                    })
                                    .clicked()
                                {
                                    act = Some(Act::Export(item.number, file.path.clone()));
                                    ui.close_menu();
                                }
                                if ui
                                    .add_enabled(
                                        !file.sha256.is_empty(),
                                        egui::Button::new("Copy SHA-256").small(),
                                    )
                                    .on_disabled_hover_text("The guest took no hash of this file")
                                    .clicked()
                                {
                                    ui.ctx().copy_text(file.sha256.clone());
                                    ui.close_menu();
                                }
                            };
                            if roomy {
                                ui.horizontal(buttons);
                            } else {
                                ui.menu_button("Actions", buttons);
                            }
                        });
                    });
                });
        });
        if shown.len() > page.len() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("{} of {} files", page.len(), shown.len()))
                        .color(theme::muted()),
                );
                if parts::more_inline(ui, "Show more ›").clicked() {
                    ui.ctx()
                        .data_mut(|d| d.insert_temp(limit_id, limit + PAGE * 4));
                }
            });
        } else if shown.is_empty() {
            parts::muted_line(ui, "No file matches the filter.");
        }
    });
    act
}

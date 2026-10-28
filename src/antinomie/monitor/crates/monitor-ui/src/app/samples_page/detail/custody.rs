// SPDX-License-Identifier: GPL-3.0-only
//! The Custody log tab: the sample's hash chain with its verify banner, a
//! check mark per entry and the head hash to copy. The log is tamper-evident,
//! not tamper-proof; the banner says so.
use super::{parts, *};
use crate::{app::samples_page::custody_parts, widgets::table};
use egui_extras::{Column, TableBuilder};

/// What the tab asks of the window.
pub(super) enum Outcome {
    None,
    /// Read the log again and recheck it.
    Verify,
}

pub(super) fn show(ui: &mut egui::Ui, data: &Data, font: f32, verifying: bool) -> Outcome {
    let verify = custody_parts::banner(ui, &data.chain, verifying);
    ui.add_space(4.0);
    if data.events.is_empty() {
        theme::empty_state(ui, "No events recorded for this sample.");
        return if verify {
            Outcome::Verify
        } else {
            Outcome::None
        };
    }
    let height = ui.available_height().max(80.0);
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let time = parts::fitted(
        ui,
        &mono,
        data.events.iter().map(|event| parts::second(event.at_ms)),
    );
    table::begin(ui);
    TableBuilder::new(ui)
        .id_salt("sample_custody")
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(44.0))
        .column(Column::exact(time))
        .column(Column::exact(130.0))
        .column(Column::exact(80.0))
        .column(Column::remainder().at_least(160.0).clip(true))
        .column(Column::exact(86.0))
        .max_scroll_height(height)
        .min_scrolled_height(0.0)
        .header(table::header_height(font), |mut header| {
            for title in ["#", "Time", "Event", "By", "Detail", "Check"] {
                header.col(|ui| table::head(ui, title));
            }
        })
        .body(|body| {
            body.rows(table::row_height(font), data.events.len(), |mut row| {
                let index = row.index();
                let event = &data.events[index];
                let state = data.chain.state_of(event.seq);
                row.col(|ui| {
                    table::cell(ui, table::Cell::Number, &event.seq.to_string());
                });
                row.col(|ui| {
                    table::cell(ui, table::Cell::Mono, &parts::second(event.at_ms));
                });
                row.col(|ui| {
                    table::cell_rich(
                        ui,
                        table::Cell::Text,
                        RichText::new(event.event.label()).strong(),
                    );
                });
                row.col(|ui| {
                    table::cell(ui, table::Cell::Text, &event.by);
                });
                row.col(|ui| {
                    let mut detail = event.event.detail();
                    if event.before_chain {
                        detail.push_str(" (recorded before the custody log)");
                    }
                    table::cell(ui, table::Cell::Text, &detail).on_hover_text(&detail);
                });
                row.col(|ui| {
                    custody_parts::check_mark(ui, state, &event.prev, &event.hash);
                });
            });
        });
    if verify {
        Outcome::Verify
    } else {
        Outcome::None
    }
}

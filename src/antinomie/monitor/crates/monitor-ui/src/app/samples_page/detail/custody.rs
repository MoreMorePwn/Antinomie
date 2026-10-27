// SPDX-License-Identifier: GPL-3.0-only
//! The Custody log tab: what happened to the sample, as plain rows. The hash
//! chain, the verify banner and the signed export come with the custody log
//! card; until then there is no check column.
use super::{parts, *};
use crate::widgets::table;
use egui_extras::{Column, TableBuilder};

pub(super) fn show(ui: &mut egui::Ui, data: &Data, font: f32) {
    if data.events.is_empty() {
        theme::empty_state(ui, "No events recorded for this sample.");
        return;
    }
    let height = ui.available_height().max(80.0);
    table::begin(ui);
    TableBuilder::new(ui)
        .id_salt("sample_custody")
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(44.0))
        .column(Column::exact(160.0))
        .column(Column::exact(130.0))
        .column(Column::exact(80.0))
        .column(Column::remainder().at_least(160.0).clip(true))
        .max_scroll_height(height)
        .min_scrolled_height(0.0)
        .header(table::header_height(font), |mut header| {
            for title in ["#", "Time", "Event", "By", "Detail"] {
                header.col(|ui| table::head(ui, title));
            }
        })
        .body(|body| {
            body.rows(table::row_height(font), data.events.len(), |mut row| {
                let index = row.index();
                let event = &data.events[index];
                row.col(|ui| {
                    table::cell(ui, table::Cell::Number, &(index + 1).to_string());
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
                    let detail = event.event.detail();
                    table::cell(ui, table::Cell::Text, &detail).on_hover_text(&detail);
                });
            });
        });
}

// SPDX-License-Identifier: GPL-3.0-only
//! Facts about one thing, said the same way in every window: the name of the
//! fact in muted text, its value beside it in normal text (the "x: y" of a
//! window, without the colon), and a section title with its subtitle.
use crate::theme;
use eframe::egui::{self, RichText};

/// A section title with a muted subtitle under it that says what the section
/// shows. An empty subtitle draws only the title.
pub fn titled(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(theme::section_title(ui, title));
    if !subtitle.is_empty() {
        ui.add(egui::Label::new(RichText::new(subtitle).small().color(theme::muted())).wrap());
    }
    ui.add_space(4.0);
}

/// One fact per row in two columns: the name (muted), then the value (wrapped
/// when it is long). `id` keeps the grids of one window apart.
pub fn facts(ui: &mut egui::Ui, id: &str, rows: &[(&str, String)]) {
    egui::Grid::new(id)
        .num_columns(2)
        .spacing([16.0, 4.0])
        .show(ui, |ui| {
            for (name, value) in rows {
                ui.label(RichText::new(*name).color(theme::muted()));
                ui.add(egui::Label::new(RichText::new(value).color(theme::text())).wrap());
                ui.end_row();
            }
        });
}

/// One fact on a line of its own, for a place with no room for a grid: the
/// name in muted text and the value after it.
pub fn fact_line(ui: &mut egui::Ui, name: &str, value: &str) -> egui::Response {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(name).color(theme::muted()));
        ui.label(RichText::new(value).color(theme::text()));
    })
    .response
}

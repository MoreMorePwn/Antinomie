// SPDX-License-Identifier: GPL-3.0-only
//! The mockup's card: a bordered panel with a heading, for grouping facts on
//! a page (Identity, Categories, register groups).
use crate::theme;
use eframe::egui::{self, RichText, Stroke};

/// A card titled `title` that fills the width it is given. `header` adds
/// widgets at the right of the title line (a link, a button).
pub fn card<R>(
    ui: &mut egui::Ui,
    title: &str,
    header: impl FnOnce(&mut egui::Ui),
    body: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let palette = theme::palette();
    egui::Frame::new()
        .fill(palette.panel)
        .stroke(Stroke::new(1.0_f32, palette.line_soft))
        .corner_radius(6)
        .inner_margin(10)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::Sides::new().show(
                ui,
                |ui| {
                    ui.label(theme::section_title(ui, title));
                },
                header,
            );
            ui.add_space(4.0);
            body(ui)
        })
        .inner
}

/// A link in the accent color that navigates to another view: a frameless
/// button, so it clicks like one and is not part of text selection.
pub fn link(ui: &mut egui::Ui, text: impl Into<String>) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(text).color(theme::palette().accent)).frame(false))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
}

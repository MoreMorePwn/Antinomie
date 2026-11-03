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

/// The link back to a list from the page of one of its items ("‹ All
/// samples"): an ordinary link, in the accent color like every other one.
pub fn back_link(ui: &mut egui::Ui, text: impl Into<String>) -> egui::Response {
    link(ui, text)
}

/// Detail text that sits under a table or list (a pack's source and license,
/// a dataset's terms, a tool's path): clear of the table's edge above and of
/// the window's edge at both sides, and filling the width so its lines wrap.
pub fn detail_block<R>(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    ui.add_space(8.0);
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(10, 4))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            body(ui)
        })
        .inner
}

/// The body of a menu (or submenu) whose items come from data: a list of
/// recent filters, every field of a packet, the checkpoints of a disk. It
/// grows to the items, but never past most of the screen: a longer list
/// scrolls inside the menu, and a long item is cut at a readable width.
pub fn bounded_menu<R>(ui: &mut egui::Ui, body: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let screen = ui.ctx().content_rect();
    ui.set_max_width((screen.width() * 0.6).clamp(240.0, 480.0));
    egui::ScrollArea::vertical()
        .max_height((screen.height() * 0.7).max(160.0))
        .auto_shrink([true, true])
        .show(ui, body)
        .inner
}

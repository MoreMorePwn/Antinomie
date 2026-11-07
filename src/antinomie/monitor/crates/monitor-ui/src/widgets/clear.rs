// SPDX-License-Identifier: GPL-3.0-only
//! The clear button of every filter and search box: a small cross inside the
//! box's right edge, shown only while the box holds text. Esc in the focused
//! box clears it as well.
use crate::theme;
use eframe::egui;

/// The room the cross takes at the box's right edge.
const ROOM: i8 = 24;
/// The cross's own size.
const SIZE: f32 = 18.0;

/// `base` with room at the right for the cross, so typed text never runs
/// under it. Give it to the box with `.margin(..)`.
pub fn clear_margin(base: egui::Margin) -> egui::Margin {
    egui::Margin {
        right: base.right.saturating_add(ROOM),
        ..base
    }
}

/// Draws the cross over `response`'s right edge while `text` is not empty and
/// clears `text` on a click on it or on Esc in the box. Returns whether the
/// text was cleared (the box then has the focus again).
pub fn clear_button(ui: &mut egui::Ui, response: &egui::Response, text: &mut String) -> bool {
    if text.is_empty() {
        return false;
    }
    // egui drops the focus on Esc, so the box has just lost it that frame.
    let escape = (response.has_focus() || response.lost_focus())
        && ui.input(|input| input.key_pressed(egui::Key::Escape));
    let rect = egui::Rect::from_center_size(
        egui::pos2(
            response.rect.right() - ROOM as f32 / 2.0 - 2.0,
            response.rect.center().y,
        ),
        egui::vec2(SIZE, SIZE),
    );
    let cross = ui
        .interact(rect, response.id.with("clear"), egui::Sense::click())
        .on_hover_text("Clear")
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    let color = if cross.hovered() {
        theme::palette().text
    } else {
        theme::palette().muted
    };
    if cross.hovered() {
        ui.painter().rect_filled(rect, 4.0, theme::palette().hover);
    }
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        egui_phosphor::regular::X,
        egui::TextStyle::Body.resolve(ui.style()),
        color,
    );
    if escape || cross.clicked() {
        text.clear();
        ui.memory_mut(|memory| memory.request_focus(response.id));
        ui.ctx().request_repaint();
        return true;
    }
    false
}

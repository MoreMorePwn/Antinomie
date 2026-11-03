// SPDX-License-Identifier: GPL-3.0-only
//! The mouse wheel as the device sent it this frame.
//!
//! egui 0.36 smooths wheel steps over several frames and, while Ctrl is held,
//! turns them into a zoom instead of a scroll delta. A wheel that steps a
//! counter (the terminal's lines, Ctrl+wheel's text size, the lineage zoom)
//! needs the step once, on the frame it arrived: the sum of the frame's wheel
//! events, converted to points the way egui's `raw_scroll_delta` did.

use eframe::egui;

/// The points the wheel moved this frame: the content moves with the sign.
pub(crate) fn raw_delta(ui: &egui::Ui) -> egui::Vec2 {
    let line = ui.options(|options| options.input_options.line_scroll_speed);
    let page = ui.content_rect().height();
    ui.input(|input| {
        input
            .raw
            .events
            .iter()
            .filter_map(|event| match event {
                egui::Event::MouseWheel { unit, delta, .. } => Some(match unit {
                    egui::MouseWheelUnit::Point => *delta,
                    egui::MouseWheelUnit::Line => line * *delta,
                    egui::MouseWheelUnit::Page => page * *delta,
                }),
                _ => None,
            })
            .fold(egui::Vec2::ZERO, |sum, delta| sum + delta)
    })
}

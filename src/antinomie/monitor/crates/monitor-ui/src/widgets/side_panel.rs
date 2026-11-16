// SPDX-License-Identifier: GPL-3.0-only
//! The body of a resizable side panel (a dump list, a function list, a
//! details column), held to the size the panel has.
//!
//! An `egui::Panel` stores the size its content took as its size for the
//! next frame. Content one point wider than the panel (a full-width button
//! with an icon beside it, a long name in a row that does not wrap) then
//! widens the panel by that point every frame until it reaches its maximum:
//! the panel "grows by itself". [`side_panel_body`] draws the content in a
//! child of exactly the panel's size and reports that size to the panel, so
//! only a drag of its edge (or the window) changes it. Content wider than
//! the panel is cut at the panel's edge instead.
use eframe::egui;

/// Run `add` in the panel body `ui` without letting its content resize the
/// panel. Call it as the whole body of `egui::Panel::show`.
pub fn side_panel_body<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let rect = ui.available_rect_before_wrap();
    let mut body = ui.new_child(
        egui::UiBuilder::new()
            .id_salt("side-panel-body")
            .max_rect(rect)
            .layout(*ui.layout()),
    );
    let inner = add(&mut body);
    // The panel takes this rect, not what the content reached.
    ui.expand_to_include_rect(rect);
    inner
}

/// `egui::Panel::show` with its body held by [`side_panel_body`]: call
/// `.show_held(ui, ...)` in place of `.show(ui, ...)`.
pub trait HeldPanel {
    fn show_held<R>(
        self,
        ui: &mut egui::Ui,
        add: impl FnOnce(&mut egui::Ui) -> R,
    ) -> egui::InnerResponse<R>;
}

impl HeldPanel for egui::Panel {
    fn show_held<R>(
        self,
        ui: &mut egui::Ui,
        add: impl FnOnce(&mut egui::Ui) -> R,
    ) -> egui::InnerResponse<R> {
        self.show(ui, |ui| side_panel_body(ui, add))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The width a left panel has after `frames` frames of `content`.
    fn width_after(frames: usize, held: bool, content: impl Fn(&mut egui::Ui)) -> f32 {
        let ctx = egui::Context::default();
        let mut width = 0.0;
        for _ in 0..frames {
            let _ = ctx.run_ui(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 700.0),
                    )),
                    ..Default::default()
                },
                |root| {
                    let panel = egui::Panel::left("held-panel")
                        .resizable(true)
                        .default_size(240.0)
                        .size_range(180.0..=480.0);
                    let response = if held {
                        panel.show_held(root, |ui| content(ui))
                    } else {
                        panel.show(root, |ui| content(ui))
                    };
                    width = response.response.rect.width();
                },
            );
        }
        width
    }

    /// A full-width button with an icon after it: one icon wider than the
    /// panel, the content of the Memory dump list before its fix.
    fn too_wide(ui: &mut egui::Ui) {
        let full = egui::vec2(ui.available_width(), 0.0);
        ui.horizontal(|ui| {
            ui.add(egui::Button::new("Dump memory").min_size(full));
            ui.label("?");
        });
    }

    #[test]
    fn content_wider_than_the_panel_grows_a_plain_panel_to_its_maximum() {
        // The behaviour this module exists for: without it the panel creeps.
        assert!(width_after(60, false, too_wide) > 400.0);
    }

    #[test]
    fn a_held_panel_keeps_its_width_whatever_its_content() {
        let first = width_after(1, true, too_wide);
        let later = width_after(60, true, too_wide);
        assert!((first - 240.0).abs() < 1.0, "{first}");
        assert!((later - first).abs() < 0.5, "{first} -> {later}");
        // Narrow content does not shrink it either.
        let narrow = width_after(60, true, |ui| {
            ui.label("x");
        });
        assert!((narrow - 240.0).abs() < 1.0, "{narrow}");
    }
}

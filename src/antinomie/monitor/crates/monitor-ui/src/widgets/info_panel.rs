// SPDX-License-Identifier: GPL-3.0-only
//! The panel a run-based window shows while it has nothing to show: what the
//! window is for and how to fill it. Every such window uses this one layout.
use crate::theme;
use eframe::egui::{self, RichText};

/// Text of an [`info_panel`].
pub struct InfoPanel<'a> {
    /// A phosphor icon, shown large and muted.
    pub icon: &'a str,
    /// What is missing, one line (for example "Select a run to view its triage").
    pub title: &'a str,
    /// What the window shows, one or two sentences.
    pub about: &'a str,
    /// The heading of the numbered steps.
    pub steps_title: &'a str,
    /// The numbered steps, short sentences.
    pub steps: &'a [&'a str],
}

/// Widest the text and the steps card grow, so a wide window keeps a readable line.
const WIDTH: f32 = 560.0;

/// Icon, title, description and a card with the numbered steps, centred on
/// both axes of the room the pane has. The height of the content is the one
/// the last frame measured (the first frame guesses), so a pane that was
/// resized settles in a frame.
pub fn info_panel(ui: &mut egui::Ui, panel: &InfoPanel<'_>) {
    // Inside a scroll area the room is unbounded: the visible part is the pane.
    let room = ui.available_rect_before_wrap().intersect(ui.clip_rect());
    let width = room.width().min(WIDTH);
    let key = ui.id().with("info-panel-height");
    let known: f32 = ui.ctx().data(|data| data.get_temp(key)).unwrap_or(220.0);
    let top = ((room.height() - known) * 0.5).max(16.0);
    let rect = egui::Rect::from_min_size(
        egui::pos2(room.center().x - width * 0.5, room.top() + top),
        egui::vec2(width, 0.0),
    );
    let used = ui
        .scope_builder(
            egui::UiBuilder::new()
                .max_rect(rect)
                .layout(egui::Layout::top_down(egui::Align::Center)),
            |ui| {
                ui.set_width(width);
                ui.label(RichText::new(panel.icon).size(32.0).color(theme::muted()));
                ui.label(theme::section_title(ui, panel.title));
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(RichText::new(panel.about).color(theme::muted()))
                        .halign(egui::Align::Center)
                        .wrap(),
                );
                ui.add_space(10.0);
                egui::Frame::new()
                    .fill(theme::raised())
                    .stroke(egui::Stroke::new(1.0_f32, theme::line()))
                    .corner_radius(6)
                    .inner_margin(egui::Margin::same(12))
                    .show(ui, |ui| {
                        ui.set_width(width - 24.0);
                        ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                            theme::section(ui, panel.steps_title);
                            for (index, text) in panel.steps.iter().enumerate() {
                                ui.horizontal_wrapped(|ui| {
                                    ui.label(
                                        RichText::new((index + 1).to_string())
                                            .monospace()
                                            .color(theme::value(theme::ValueKind::Number)),
                                    );
                                    ui.label(*text);
                                });
                            }
                        });
                    });
            },
        )
        .response
        .rect;
    if (used.height() - known).abs() > 0.5 {
        ui.ctx()
            .data_mut(|data| data.insert_temp(key, used.height()));
        ui.ctx().request_repaint();
    }
}

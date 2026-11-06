// SPDX-License-Identifier: GPL-3.0-only
//! The small pieces the Summary's boxes are made of: a clickable item whose
//! parts have their own colours, a figure (a strong number and a muted word)
//! and the inset box that holds the rows past the first few.
use crate::theme;
use eframe::egui::{self, RichText};

/// One piece of an item, with the role that gives it its colour.
pub(super) enum Part<'a> {
    /// The thing itself (address, domain, URL, path): normal text, monospace.
    Value(&'a str),
    /// Secondary information (country, organization, type, hash): muted.
    Note(&'a str),
    /// A name in the normal text colour and the text font (a process).
    Name(&'a str),
}

/// A clickable item. It does not look like a link; hovering it underlines
/// its parts and shows the pointing hand. True when it was clicked.
pub(super) fn item(ui: &mut egui::Ui, parts: &[Part<'_>], hint: &str) -> bool {
    let out = ui.scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
        let hot = ui.response().hovered();
        ui.spacing_mut().item_spacing.x = 6.0;
        for part in parts {
            let text = match part {
                Part::Value(text) => RichText::new(*text).monospace().color(theme::text()),
                Part::Note(text) => RichText::new(*text).color(theme::muted()),
                Part::Name(text) => RichText::new(*text).color(theme::text()),
            };
            ui.add(egui::Label::new(if hot { text.underline() } else { text }).selectable(false));
        }
    });
    let response = out
        .response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hint);
    response.clicked()
}

/// One label made of sections that are numbers (strong, normal text colour)
/// or words (muted), so that it wraps as a unit.
fn counted_job(ui: &egui::Ui, sections: &[(String, bool)], underline: bool) -> egui::WidgetText {
    let mut job = egui::text::LayoutJob::default();
    for (text, number) in sections {
        let rich = if *number {
            RichText::new(text).strong().color(theme::text())
        } else {
            RichText::new(text).color(theme::muted())
        };
        let rich = if underline { rich.underline() } else { rich };
        rich.append_to(
            &mut job,
            ui.style(),
            egui::FontSelection::Default,
            egui::Align::Center,
        );
    }
    job.into()
}

/// Counts and words as a clickable item (hover underlines it). True when clicked.
pub(super) fn counted_item(ui: &mut egui::Ui, sections: &[(String, bool)], hint: &str) -> bool {
    let out = ui.scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
        let hot = ui.response().hovered();
        let text = counted_job(ui, sections, hot);
        ui.add(egui::Label::new(text).selectable(false));
    });
    out.response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hint)
        .clicked()
}

/// The figures of a one-line row: "3 created \u{b7} 1 executed" or
/// "Execution 2", numbers strong in the text colour and words muted.
/// Each is `(number, word, number first)`.
pub(super) fn figures(ui: &mut egui::Ui, figures: &[(String, &str, bool)]) {
    let mut sections: Vec<(String, bool)> = Vec::new();
    for (at, (number, word, number_first)) in figures.iter().enumerate() {
        if at > 0 {
            sections.push((" \u{b7} ".to_owned(), false));
        }
        if *number_first {
            sections.push((number.clone(), true));
            sections.push((format!(" {word}"), false));
        } else {
            sections.push((format!("{word} "), false));
            sections.push((number.clone(), true));
        }
    }
    let text = counted_job(ui, &sections, false);
    ui.add(egui::Label::new(text).selectable(false));
}

/// The fill of the inset box: the box's own, a little darker.
pub(super) fn inset_fill() -> egui::Color32 {
    let darker = if theme::is_light() { 0.05 } else { 0.35 };
    theme::bg().lerp_to_gamma(egui::Color32::BLACK, darker)
}

/// A small framed box of `height` that scrolls inside, with its scroll bar
/// always drawn at its right edge so it shows there is more.
pub(super) fn inset<R>(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    height: f32,
    body: impl FnOnce(&mut egui::Ui) -> R,
) {
    egui::Frame::new()
        .fill(inset_fill())
        .stroke(egui::Stroke::new(1.0, theme::line_soft()))
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
            egui::ScrollArea::vertical()
                .id_salt(id)
                .max_height(height)
                .auto_shrink([false, true])
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .show(ui, body);
        });
}

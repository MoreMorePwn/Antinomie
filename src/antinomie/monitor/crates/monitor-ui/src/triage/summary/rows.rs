// SPDX-License-Identifier: GPL-3.0-only
//! The small pieces the Summary's boxes are made of: a clickable item whose
//! parts have their own colours, a figure (a strong number and a muted word)
//! and the scrolling list that replaces the first few rows.
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

/// A list that shows its first rows and, once `open`, turns into one scroll
/// area with every row, as tall as the first rows were (measured while the
/// list is shut, `fallback` before that), with its scroll bar always drawn
/// at the right edge. `row` draws row `at` of `total`; `shown` rows show
/// while the list is shut.
pub(super) fn scroll_list(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    open: bool,
    fallback: f32,
    (shown, total): (usize, usize),
    mut row: impl FnMut(&mut egui::Ui, usize),
) {
    let key = ui.id().with(("summary-list-height", &id));
    if !open {
        let height = ui
            .scope(|ui| (0..shown.min(total)).for_each(|at| row(ui, at)))
            .response
            .rect
            .height();
        ui.data_mut(|data| data.insert_temp(key, height));
        return;
    }
    let height = ui
        .data(|data| data.get_temp::<f32>(key))
        .filter(|height| *height > 0.0)
        .unwrap_or(fallback);
    ui.scope(|ui| {
        ui.spacing_mut().scroll = egui::style::ScrollStyle::solid();
        egui::ScrollArea::vertical()
            .id_salt(id)
            .max_height(height)
            .min_scrolled_height(height)
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .show(ui, |ui| (0..total).for_each(|at| row(ui, at)));
    });
}

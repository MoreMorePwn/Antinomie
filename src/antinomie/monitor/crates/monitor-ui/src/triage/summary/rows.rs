// SPDX-License-Identifier: GPL-3.0-only
//! The small pieces the Summary's boxes are made of: a clickable item whose
//! parts have their own colours, a figure (a strong number and a muted word)
//! and the scrolling list that replaces the first few rows.
use crate::scroll_contain::ScrollContained as _;
use crate::theme;
use eframe::egui::{self, RichText};

/// One piece of an item, with the role that gives it its colour.
pub(super) enum Part<'a> {
    /// The thing itself (address, domain, URL, path): normal text, monospace.
    Value(&'a str),
    /// Secondary information (country, organization, type, hash): muted.
    Note(&'a str),
}

/// The width a part takes on one line, unwrapped.
fn width_of(ui: &egui::Ui, text: egui::WidgetText) -> f32 {
    text.into_galley(
        ui,
        Some(egui::TextWrapMode::Extend),
        f32::INFINITY,
        egui::TextStyle::Body,
    )
    .size()
    .x
}

/// A clickable item. It does not look like a link; hovering it underlines
/// its parts and shows the pointing hand. A value too long for the row is cut
/// with an ellipsis to the room the notes after it leave (the row never grows
/// past its box: a long URL or path used to push the whole Summary off the
/// window), and its full text is in the tooltip. True when it was clicked.
pub(super) fn item(ui: &mut egui::Ui, parts: &[Part<'_>], hint: &str) -> bool {
    let cut = std::cell::Cell::new(None);
    let out = ui.scope_builder(egui::UiBuilder::new().sense(egui::Sense::click()), |ui| {
        let hot = ui.response().hovered();
        ui.spacing_mut().item_spacing.x = 6.0;
        let gap = ui.spacing().item_spacing.x;
        let rich = |part: &Part<'_>| match part {
            Part::Value(text) => RichText::new(*text).monospace().color(theme::text()),
            Part::Note(text) => RichText::new(*text).color(theme::muted()),
        };
        // What the notes need, so the values share the rest.
        let notes: f32 = parts
            .iter()
            .filter(|part| matches!(part, Part::Note(_)))
            .map(|part| width_of(ui, rich(part).into()) + gap)
            .sum();
        let values = parts
            .iter()
            .filter(|part| matches!(part, Part::Value(_)))
            .count()
            .max(1) as f32;
        let room = ((ui.available_width() - notes) / values - gap * (values - 1.0)).max(60.0);
        for part in parts {
            let text = rich(part);
            let text = if hot { text.underline() } else { text };
            match part {
                Part::Value(full) => {
                    if width_of(ui, rich(part).into()) > room {
                        cut.set(Some((*full).to_owned()));
                    }
                    ui.scope(|ui| {
                        ui.set_max_width(room);
                        ui.add(egui::Label::new(text).truncate().selectable(false));
                    });
                }
                Part::Note(_) => {
                    ui.add(egui::Label::new(text).selectable(false));
                }
            }
        }
    });
    let hint = match cut.take() {
        Some(full) => format!("{full}\n{hint}"),
        None => hint.to_owned(),
    };
    let response = out
        .response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hint);
    response.clicked()
}

/// One label made of sections that are numbers (strong, normal text colour)
/// or words (muted), so that it wraps as a unit.
fn counted_job(
    ui: &egui::Ui,
    sections: &[(String, bool)],
    underline: bool,
    number_color: egui::Color32,
) -> egui::WidgetText {
    let mut job = egui::text::LayoutJob::default();
    for (text, number) in sections {
        let rich = if *number {
            RichText::new(text).strong().color(number_color)
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
        let text = counted_job(ui, sections, hot, theme::text());
        ui.add(egui::Label::new(text).selectable(false));
    });
    out.response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .on_hover_text(hint)
        .clicked()
}

/// The figures of a one-line row: "3 created \u{b7} 1 executed" or
/// "Execution 2", numbers strong in `color` and words muted.
/// Each is `(number, word, number first)`.
pub(super) fn figures(ui: &mut egui::Ui, figures: &[(String, &str, bool)], color: egui::Color32) {
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
    let text = counted_job(ui, &sections, false, color);
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
        ui.spacing_mut().scroll = theme::solid_scroll();
        egui::ScrollArea::vertical()
            .id_salt(id)
            .max_height(height)
            .min_scrolled_height(height)
            .auto_shrink([false, false])
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .show_contained(ui, |ui| (0..total).for_each(|at| row(ui, at)));
    });
}

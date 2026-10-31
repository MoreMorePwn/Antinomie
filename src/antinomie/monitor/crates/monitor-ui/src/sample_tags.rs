// SPDX-License-Identifier: GPL-3.0-only
//! How a sample's tags are drawn. The shapes carry the meaning, so nothing
//! explains them: a verdict is an outlined pill with a coloured dot, a
//! malware category a filled orange pill, a technique a purple box with its
//! ID in monospace, a custom tag a dashed outline in its own colour with a
//! `#` before the name. The colour is in the shape (fill, outline, dot); the
//! text is the theme's own text colour, so it reads in every theme.
use crate::theme;
use antinomie_monitor_core::samples::{Tag, TagKind};
use eframe::egui::{self, Color32, RichText, Stroke};

/// The colour of a verdict tag value.
pub(crate) fn verdict_color(value: &str) -> Color32 {
    let palette = theme::palette();
    match value {
        "malicious" => palette.error,
        "suspicious" => palette.warn,
        "benign" => palette.good,
        _ => palette.muted,
    }
}

/// A custom tag's colour from the nine-colour palette (anything else is grey).
pub(crate) fn palette_color(name: &str) -> Color32 {
    let palette = theme::palette();
    match name {
        "red" => palette.error,
        "orange" => palette.string,
        "yellow" => palette.name,
        "green" => palette.good,
        "cyan" => palette.info,
        "blue" => palette.flag,
        "purple" => palette.pointer,
        "pink" => palette.tree[3],
        _ => palette.muted,
    }
}

/// `color` as a translucent wash for a filled chip.
fn wash(color: Color32) -> Color32 {
    let [r, g, b, _] = color.to_array();
    Color32::from_rgba_unmultiplied(r, g, b, 44)
}

/// The ID and name of a technique tag: `T1053.003 Scheduled Task/Job: Cron`.
fn technique_parts(value: &str) -> (&str, &str) {
    value.split_once(' ').unwrap_or((value, ""))
}

/// The width a tag takes: its text, the chip's margins and the gap inside.
fn width_of(ui: &egui::Ui, tag: &Tag) -> f32 {
    let text = |text: &str, font: egui::FontId| {
        ui.painter()
            .layout_no_wrap(text.to_owned(), font, Color32::PLACEHOLDER)
            .size()
            .x
    };
    let small = egui::TextStyle::Small.resolve(ui.style());
    let mono = egui::FontId::monospace(small.size);
    16.0 + 8.0
        + match tag.kind {
            TagKind::Technique => {
                let (id, name) = technique_parts(&tag.value);
                text(id, mono) + text(name, small)
            }
            TagKind::Custom => text(&format!("#{}", tag.value), small),
            _ => text(&tag.value, small) + 12.0,
        }
}

/// Draw one tag. In a wrapping row a tag that does not fit what is left of
/// the line starts the next one, whole.
pub(crate) fn tag(ui: &mut egui::Ui, tag: &Tag) -> egui::Response {
    let layout = *ui.layout();
    if layout.is_horizontal()
        && layout.main_wrap()
        && ui.cursor().min.x > ui.min_rect().left() + 1.0
        && width_of(ui, tag) > ui.available_width()
    {
        ui.end_row();
    }
    let palette = theme::palette();
    // A chip is never wrapped inside: it moves to the next line whole.
    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
    let frame = egui::Frame::new().inner_margin(egui::Margin::symmetric(8, 0));
    match tag.kind {
        TagKind::Verdict => {
            let color = verdict_color(&tag.value);
            frame
                .stroke(Stroke::new(1.0_f32, color))
                .corner_radius(11)
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("●").small().color(color));
                        ui.label(RichText::new(&tag.value).small().color(color));
                    });
                })
                .response
        }
        TagKind::Category => {
            frame
                .fill(wash(palette.string))
                .stroke(Stroke::new(1.0_f32, palette.string))
                .corner_radius(11)
                .show(ui, |ui| {
                    ui.label(RichText::new(&tag.value).small().color(theme::text()));
                })
                .response
        }
        TagKind::Technique => {
            let (id, name) = technique_parts(&tag.value);
            // A name longer than the line is cut (the tooltip has it all).
            let fits = width_of(ui, tag) <= ui.available_width();
            let room = ui.available_width() - 16.0 - 8.0;
            frame
                .fill(wash(palette.pointer))
                .stroke(Stroke::new(1.0_f32, palette.pointer))
                .corner_radius(4)
                .show(ui, |ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.horizontal(|ui| {
                        if !fits {
                            ui.set_max_width(room.max(60.0));
                        }
                        ui.label(
                            RichText::new(id)
                                .small()
                                .strong()
                                .monospace()
                                .color(theme::text()),
                        );
                        if !name.is_empty() {
                            let text = RichText::new(name).small().color(theme::text());
                            if fits {
                                ui.label(text);
                            } else {
                                ui.add(egui::Label::new(text).truncate());
                            }
                        }
                    });
                })
                .response
                .on_hover_text(&tag.value)
        }
        TagKind::Custom => {
            let color = palette_color(&tag.color);
            let shown = frame
                .corner_radius(11)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!("#{}", tag.value))
                            .small()
                            .color(theme::text()),
                    );
                })
                .response;
            let rect = shown.rect.shrink(0.5);
            let outline = [
                rect.left_top(),
                rect.right_top(),
                rect.right_bottom(),
                rect.left_bottom(),
                rect.left_top(),
            ];
            ui.painter().extend(egui::Shape::dashed_line(
                &outline,
                Stroke::new(1.0_f32, color),
                3.0,
                2.0,
            ));
            shown
        }
    }
}

/// The tags the list shows: verdicts and categories, with the techniques and
/// custom tags folded into a `+N` chip whose tooltip names them.
pub(crate) fn short(ui: &mut egui::Ui, tags: &[Tag]) {
    ui.spacing_mut().item_spacing.x = 4.0;
    let (shown, hidden): (Vec<&Tag>, Vec<&Tag>) = tags
        .iter()
        .partition(|tag| matches!(tag.kind, TagKind::Verdict | TagKind::Category));
    for item in shown {
        tag(ui, item);
    }
    if !hidden.is_empty() {
        let names: Vec<String> = hidden.iter().map(|tag| tag.value.clone()).collect();
        crate::widgets::chip(
            ui,
            format!("+{}", hidden.len()),
            crate::widgets::Tone::Neutral,
        )
        .on_hover_text(names.join("\n"));
    }
}

/// A tag as one line of plain text, for search and tooltips.
pub(crate) fn text(tag: &Tag) -> String {
    match tag.kind {
        TagKind::Custom => format!("#{}", tag.value),
        _ => tag.value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::samples::TAG_COLORS;

    #[test]
    fn every_palette_colour_has_a_distinct_theme_colour_except_unknown_names() {
        for name in TAG_COLORS {
            assert_eq!(palette_color(name), palette_color(name));
        }
        assert_eq!(palette_color("mauve"), palette_color("grey"));
        assert_ne!(palette_color("red"), palette_color("green"));
        assert_eq!(
            technique_parts("T1053.003 Scheduled Task/Job: Cron"),
            ("T1053.003", "Scheduled Task/Job: Cron")
        );
        assert_eq!(technique_parts("T1053"), ("T1053", ""));
        assert_eq!(text(&Tag::new(TagKind::Custom, "x")), "#x");
    }
}

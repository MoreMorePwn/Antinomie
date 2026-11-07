// SPDX-License-Identifier: GPL-3.0-only
//! How a sample's tags are drawn. The shapes carry the meaning, so nothing
//! explains them: a verdict is an outlined pill with a coloured dot, a
//! malware category a filled orange pill, a technique a box in its ATT&CK
//! tactic's colour (see `widgets::attack`) with its ID in monospace, a custom
//! tag a dashed outline in its own colour with a `#` before the name. The colour is in the shape (fill, outline, dot); the
//! text is the theme's own text colour, so it reads in every theme.
use crate::theme;
use crate::widgets::attack;
use antinomie_monitor_core::mitre::Tactic;
use antinomie_monitor_core::samples::{Tag, TagKind};
use eframe::egui::{self, Color32, Stroke};

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

/// The text of a tag as one pill line: a verdict's dot, a technique's ID in
/// monospace, a custom tag's `#`. The text is the theme's own colour.
fn tag_job(
    ui: &egui::Ui,
    tag: &Tag,
    context: Option<Tactic>,
) -> (egui::text::LayoutJob, Vec<Color32>) {
    use crate::widgets::tone::{pill_font, pill_text};
    let small = pill_font(ui);
    let mut job = egui::text::LayoutJob::default();
    match tag.kind {
        TagKind::Verdict => {
            let color = verdict_color(&tag.value);
            pill_text(&mut job, &tag.value, small, color);
            return (job, vec![color]);
        }
        TagKind::Category => pill_text(&mut job, &tag.value, small, theme::text()),
        TagKind::Technique => {
            let (id, name) = technique_parts(&tag.value);
            let tactics = attack::badge_tactics(id, context);
            return (
                attack::technique_job(ui, id, name, &tactics),
                attack::technique_dots(&tactics),
            );
        }
        TagKind::Custom => pill_text(&mut job, &format!("#{}", tag.value), small, theme::text()),
    }
    (job, Vec::new())
}

/// Draw one tag. In a wrapping row a tag that does not fit what is left of
/// the line starts the next one, whole; one wider than a whole line is cut
/// with "…" and its tooltip has all of it.
pub(crate) fn tag(ui: &mut egui::Ui, tag: &Tag) -> egui::Response {
    tag_in(ui, tag, None)
}

/// [`tag`] for a technique drawn in the row of the tactic `context`.
pub(crate) fn tag_in(ui: &mut egui::Ui, tag: &Tag, context: Option<Tactic>) -> egui::Response {
    use crate::widgets::tone::{pill_dots, PillLook};
    let palette = theme::palette();
    let (job, dots) = tag_job(ui, tag, context);
    let pill =
        |ui: &mut egui::Ui, look: PillLook, job, min: f32| pill_dots(ui, look, &dots, job, min);
    let look = |fill: Color32, stroke: Stroke, corner: u8| PillLook {
        fill,
        stroke,
        corner,
        pad: 8.0,
    };
    match tag.kind {
        TagKind::Verdict => {
            let color = verdict_color(&tag.value);
            pill(
                ui,
                look(Color32::TRANSPARENT, Stroke::new(1.0_f32, color), 11),
                job,
                0.0,
            )
        }
        TagKind::Category => pill(
            ui,
            look(
                wash(palette.string),
                Stroke::new(1.0_f32, palette.string),
                11,
            ),
            job,
            0.0,
        ),
        TagKind::Technique => {
            let (id, _) = technique_parts(&tag.value);
            let tactics = attack::badge_tactics(id, context);
            pill(ui, attack::technique_look(&tactics), job, 0.0).on_hover_text(format!(
                "{}\n{}",
                tag.value,
                attack::tactic_names(&tactics)
            ))
        }
        TagKind::Custom => {
            let color = palette_color(&tag.color);
            let shown = pill(ui, look(Color32::TRANSPARENT, Stroke::NONE, 11), job, 0.0);
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

/// The width a tag drawn with [`tag_in`] takes on one line, for a caller that
/// keeps a tag and something beside it together.
pub(crate) fn width_of_in(ui: &egui::Ui, tag: &Tag, context: Option<Tactic>) -> f32 {
    let (mut job, dots) = tag_job(ui, tag, context);
    job.wrap.max_width = f32::INFINITY;
    let lead =
        crate::widgets::tone::dots_width(crate::widgets::tone::pill_font(ui).size, dots.len());
    ui.fonts_mut(|fonts| fonts.layout_job(job)).size().x + lead + 16.0
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

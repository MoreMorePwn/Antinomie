// SPDX-License-Identifier: GPL-3.0-only
//! The tag picker: one panel, four groups (verdict, malware category, ATT&CK
//! technique, custom), shared by Add file and Edit tags. The groups are told
//! apart by their shapes (see `sample_tags`), so the picker carries no rule
//! text. A technique is searched by ID or name; a custom tag takes a colour
//! from a palette of nine theme colours, and the preview chip shows it as it
//! will look.
use crate::{sample_tags, theme};
use antinomie_monitor_core::{
    mitre,
    samples::{Tag, TagKind, CATEGORIES, TAG_COLORS, VERDICTS},
};
use eframe::egui::{self, RichText, Stroke};
use std::collections::BTreeSet;

/// Techniques listed for one search.
const SEARCH_LIMIT: usize = 8;

#[derive(Default)]
pub(crate) struct TagPicker {
    pub(crate) picked: BTreeSet<Tag>,
    technique_query: String,
    custom_name: String,
    custom_color: usize,
}

impl TagPicker {
    pub(crate) fn with(tags: &[Tag]) -> Self {
        Self {
            picked: tags.iter().cloned().collect(),
            ..Self::default()
        }
    }

    pub(crate) fn tags(&self) -> Vec<Tag> {
        self.picked.iter().cloned().collect()
    }

    /// A tag that can be toggled: drawn in its own shape, ringed when picked.
    fn toggle(&mut self, ui: &mut egui::Ui, tag: Tag) {
        let on = self.picked.contains(&tag);
        let shown = sample_tags::tag(ui, &tag);
        let response = ui
            .interact(shown.rect, shown.id.with("pick"), egui::Sense::click())
            .on_hover_cursor(egui::CursorIcon::PointingHand);
        if on {
            ui.painter().rect_stroke(
                shown.rect.expand(2.0),
                8.0,
                Stroke::new(1.5_f32, theme::palette().accent),
                egui::StrokeKind::Outside,
            );
        }
        if response.clicked() {
            if on {
                self.picked.remove(&tag);
            } else {
                self.picked.insert(tag);
            }
        }
    }

    fn heading(ui: &mut egui::Ui, title: &str) {
        ui.label(RichText::new(title).color(theme::muted()).small());
    }

    /// Draw the picker. `suggested` are techniques Triage mapped; they are
    /// offered and never added on their own. `known_custom` are the custom
    /// tags other samples already carry, with their colours.
    pub(crate) fn show(&mut self, ui: &mut egui::Ui, suggested: &[String], known_custom: &[Tag]) {
        Self::heading(ui, "Verdict");
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
            for verdict in VERDICTS {
                self.toggle(ui, Tag::new(TagKind::Verdict, verdict));
            }
        });
        ui.add_space(4.0);
        Self::heading(ui, "Malware category");
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
            for category in CATEGORIES {
                self.toggle(ui, Tag::new(TagKind::Category, category));
            }
        });
        ui.add_space(4.0);
        Self::heading(ui, "ATT&CK technique");
        ui.add(
            egui::TextEdit::singleline(&mut self.technique_query)
                .hint_text(theme::hint_text(
                    "Search by ID or name, for example T1053 or cron",
                ))
                .desired_width(ui.available_width()),
        );
        let found = mitre::search(&self.technique_query, SEARCH_LIMIT);
        let picked_techniques: Vec<Tag> = self
            .picked
            .iter()
            .filter(|tag| tag.kind == TagKind::Technique)
            .cloned()
            .collect();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
            for tag in picked_techniques {
                self.toggle(ui, tag);
            }
            for label in found {
                self.toggle(ui, Tag::new(TagKind::Technique, label));
            }
        });
        if !suggested.is_empty() {
            Self::heading(ui, "From Triage");
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
                for label in suggested {
                    self.toggle(ui, Tag::new(TagKind::Technique, label.clone()));
                }
            });
        }
        ui.add_space(4.0);
        Self::heading(ui, "Custom");
        let picked_custom: Vec<Tag> = self
            .picked
            .iter()
            .filter(|tag| tag.kind == TagKind::Custom)
            .cloned()
            .collect();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
            for tag in picked_custom {
                self.toggle(ui, tag);
            }
            for tag in known_custom {
                if !self.picked.contains(tag) {
                    self.toggle(ui, tag.clone());
                }
            }
        });
        let mut add = false;
        ui.horizontal(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.custom_name)
                    .hint_text(theme::hint_text("New tag name"))
                    .desired_width(160.0),
            );
            for (index, name) in TAG_COLORS.iter().enumerate() {
                let color = sample_tags::palette_color(name);
                let (rect, response) =
                    ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::click());
                ui.painter().circle_filled(rect.center(), 6.0, color);
                if index == self.custom_color {
                    ui.painter().circle_stroke(
                        rect.center(),
                        8.0,
                        Stroke::new(1.5_f32, theme::palette().text),
                    );
                }
                if response.on_hover_text(*name).clicked() {
                    self.custom_color = index;
                }
            }
            let name = self.custom_name.trim().to_owned();
            let valid = !name.is_empty() && name.len() <= 64;
            if valid {
                sample_tags::tag(ui, &self.custom_tag(&name));
            }
            add = ui.add_enabled(valid, egui::Button::new("Add")).clicked()
                || (valid && edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
        });
        if add {
            let tag = self.custom_tag(self.custom_name.trim());
            self.picked.insert(tag);
            self.custom_name.clear();
        }
    }

    fn custom_tag(&self, name: &str) -> Tag {
        Tag {
            kind: TagKind::Custom,
            value: name.to_owned(),
            color: TAG_COLORS[self.custom_color.min(TAG_COLORS.len() - 1)].to_owned(),
        }
    }
}

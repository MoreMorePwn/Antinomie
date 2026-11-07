// SPDX-License-Identifier: GPL-3.0-only
//! The right pane of a rules window: the selected rule's name, its metadata
//! as a two-column grid, and its source text on a code background.
use super::page::severity_tone;
use crate::{theme, widgets, widgets::Tone};
use antinomie_monitor_core::ruleset::IndexedRule;
use eframe::egui::{self, RichText};

/// The vertical gap between two metadata rows.
pub(super) const ROW_GAP: f32 = 10.0;
/// The gap between a label and its value.
pub(super) const COLUMN_GAP: f32 = 18.0;

/// The metadata rows above the severity and the state, label first, empty
/// values left out.
pub(super) fn head_rows(rule: &IndexedRule) -> Vec<(&'static str, String)> {
    let mut rows = vec![
        ("ID", rule.id.clone()),
        ("File", rule.file.clone()),
        ("Author", rule.author.clone()),
        ("License", rule.license.clone()),
    ];
    rows.retain(|(_, value)| !value.is_empty());
    rows
}

/// The metadata rows below them. The severity and the state are drawn as
/// chips by [`show`], and the references as links.
pub(super) fn tail_rows(rule: &IndexedRule, engine: &str) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    // An IDS rule's "description" is its own text, which the source block shows.
    if engine != "ids" {
        rows.push(("Description", rule.condition.clone()));
    }
    rows.extend([
        ("Tags", rule.tags.join(", ")),
        ("Evidence", rule.evidence.join(", ")),
        ("Source", rule.source_url.clone()),
        ("Uses rules", rule.depends_on.join(", ")),
        (
            "Compatibility",
            if rule.compatible {
                "compatible".into()
            } else {
                rule.reason.clone()
            },
        ),
    ]);
    rows.retain(|(_, value)| !value.is_empty());
    rows
}

/// What the pane asks for in a frame.
#[derive(Default)]
pub(super) struct Asked {
    /// "Remove from group" was clicked.
    pub remove: bool,
}

/// A value as text that wraps even inside a word: a long reference or hash
/// has no space to break at, and must not widen the window.
fn wrapped(ui: &egui::Ui, text: &str, color: egui::Color32) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::simple_singleline(
        text.to_owned(),
        egui::TextStyle::Body.resolve(ui.style()),
        color,
    );
    job.wrap = egui::text::TextWrapping {
        break_anywhere: true,
        max_rows: usize::MAX,
        ..Default::default()
    };
    job
}

/// One value cell: a link when it is a web address, wrapped text otherwise.
fn value(ui: &mut egui::Ui, text: &str) {
    if text.starts_with("http://") || text.starts_with("https://") {
        ui.add(egui::Hyperlink::from_label_and_url(
            wrapped(ui, text, theme::palette().accent),
            text,
        ));
    } else {
        ui.add(egui::Label::new(wrapped(ui, text, theme::text())).wrap());
    }
}

fn label(ui: &mut egui::Ui, text: &str) {
    ui.add(egui::Label::new(theme::bold(ui, text).color(theme::muted())).selectable(false));
}

/// Draws the pane. `text` is the rule's source: `None` while it is read.
pub(super) fn show(
    ui: &mut egui::Ui,
    rule: &IndexedRule,
    engine: &str,
    in_group: bool,
    state: &str,
    text: Option<&Result<String, String>>,
) -> Asked {
    let mut asked = Asked::default();
    egui::ScrollArea::vertical()
        .id_salt("rule-detail")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(egui::Label::new(theme::section_title(ui, &rule.name)).wrap());
            ui.add_space(ROW_GAP);
            egui::Grid::new("rule-meta")
                .num_columns(2)
                .spacing([COLUMN_GAP, ROW_GAP])
                .show(ui, |ui| {
                    for (name, text) in head_rows(rule) {
                        label(ui, name);
                        value(ui, &text);
                        ui.end_row();
                    }
                    if !rule.severity.is_empty() {
                        label(ui, "Severity");
                        widgets::chip(ui, &rule.severity, severity_tone(&rule.severity));
                        ui.end_row();
                    }
                    label(ui, "State");
                    ui.horizontal(|ui| {
                        let tone = match state {
                            "enabled" => Tone::Good,
                            "incompatible" => Tone::Warn,
                            _ => Tone::Neutral,
                        };
                        widgets::chip(ui, state, tone);
                        if rule.helper {
                            widgets::chip(ui, "helper", Tone::Neutral);
                        }
                    });
                    ui.end_row();
                    for (name, text) in tail_rows(rule, engine) {
                        label(ui, name);
                        value(ui, &text);
                        ui.end_row();
                    }
                    if !rule.references.is_empty() {
                        label(ui, "References");
                        ui.vertical(|ui| {
                            for reference in &rule.references {
                                value(ui, reference);
                            }
                        });
                        ui.end_row();
                    }
                });
            if in_group {
                ui.add_space(ROW_GAP);
                if ui.button("Remove from group").clicked() {
                    asked.remove = true;
                }
            }
            ui.add_space(ROW_GAP);
            theme::section(ui, "Source text");
            ui.add_space(4.0);
            match text {
                Some(Ok(text)) => {
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(text.clone());
                    }
                    code_block(ui, text);
                }
                Some(Err(error)) => {
                    crate::activity::error(ui, format!("The rule text could not be read: {error}"));
                }
                None => {
                    theme::loading(ui, "Reading the rule…");
                }
            }
        });
    asked
}

/// The rule's source on the theme's code background, with padding, so it
/// reads as a block.
pub(super) fn code_block(ui: &mut egui::Ui, text: &str) {
    egui::Frame::new()
        .fill(ui.visuals().code_bg_color)
        .corner_radius(4)
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            // Long lines scroll sideways inside the box; they never widen
            // the pane or the window.
            egui::ScrollArea::horizontal()
                .id_salt("rule-code")
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(text).monospace().color(theme::text()))
                            .wrap_mode(egui::TextWrapMode::Extend)
                            .selectable(true),
                    );
                });
        });
}

// SPDX-License-Identifier: GPL-3.0-only
//! The floating details window of one installed rule: its metadata and its
//! source text on a code background. One window per rule; a click on the
//! same rule again brings it to the front.
use super::{page::severity_tone, Model};
use crate::{theme, widgets, widgets::Tone};
use antinomie_monitor_core::ruleset::{self, IndexedRule};
use eframe::egui::{self, RichText};
use std::{
    cell::Cell,
    path::Path,
    sync::mpsc::{self, Receiver},
};

pub(super) struct RuleWindow {
    /// The rule set and the rule it was opened for.
    pub key: (String, String),
    pub rule: IndexedRule,
    /// The custom group it was opened from; empty for an installed pack.
    pub group: String,
    /// `None` while the source text is read.
    pub text: Option<Result<String, String>>,
    pub rx: Option<Receiver<Result<String, String>>>,
    pub raise: Cell<bool>,
}

impl RuleWindow {
    pub fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        let done = match rx.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err("The rule could not be read".into()),
        };
        self.rx = None;
        self.text = Some(done);
    }

    fn id(&self) -> egui::Id {
        egui::Id::new(("rule-details-window", &self.key))
    }
}

impl Model {
    /// Draws every open rule window; a closed one is dropped.
    pub(super) fn show_rule_windows(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let mut removal = None;
        let windows = std::mem::take(&mut self.rule_windows);
        let mut kept = Vec::new();
        for window in windows {
            let mut open = true;
            let state = self.state_of(&window.rule);
            let area = crate::title_bar::content_rect(ctx);
            crate::widgets::window(format!("Rule · {}", window.rule.name))
                .id(window.id())
                .open(&mut open)
                .default_size([
                    (area.width() * 0.5).clamp(480.0, 760.0),
                    (area.height() * 0.8).max(360.0),
                ])
                .resizable(true)
                .show(ctx, |ui| {
                    if body(ui, &window, state) {
                        removal = Some((window.group.clone(), window.rule.id.clone()));
                    }
                });
            if window.raise.replace(false) {
                ctx.move_to_top(egui::LayerId::new(egui::Order::Middle, window.id()));
            }
            if open {
                kept.push(window);
            }
        }
        // Windows opened while these were drawn are kept too.
        kept.append(&mut self.rule_windows);
        self.rule_windows = kept;
        if let Some((group, removed)) = removal {
            self.remove_from_group(data_dir, group, removed);
        }
    }

    fn remove_from_group(&mut self, data_dir: &Path, id: String, removed: String) {
        let dir = data_dir.to_path_buf();
        self.spawn(move |_| {
            let revision = ruleset::revise_group(&dir, &id, None, std::slice::from_ref(&removed))?;
            let registry = ruleset::load_registry(&dir)?;
            Ok(super::Done::Registry(
                registry,
                format!("Removed a rule from {id} as revision {revision}."),
            ))
        });
        self.rows_key.clear();
    }
}

/// The window's contents. Returns true when "Remove from group" was clicked.
fn body(ui: &mut egui::Ui, window: &RuleWindow, state: &str) -> bool {
    let rule = &window.rule;
    let mut remove = false;
    egui::ScrollArea::vertical()
        .id_salt(("rule-detail", &window.key))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(RichText::new(&rule.name).strong().color(theme::heading())).wrap(),
            );
            ui.horizontal_wrapped(|ui| {
                if !rule.severity.is_empty() {
                    widgets::chip(ui, &rule.severity, severity_tone(&rule.severity));
                }
                widgets::chip(
                    ui,
                    state,
                    match state {
                        "enabled" => Tone::Good,
                        "incompatible" => Tone::Warn,
                        _ => Tone::Neutral,
                    },
                );
                if rule.helper {
                    widgets::chip(ui, "helper", Tone::Neutral);
                }
            });
            let tags = rule.tags.join(", ");
            let evidence = rule.evidence.join(", ");
            let references = rule.references.join(", ");
            let depends = rule.depends_on.join(", ");
            for (label, value) in [
                ("Id", rule.id.as_str()),
                ("File", rule.file.as_str()),
                ("License", rule.license.as_str()),
                ("Source", rule.source_url.as_str()),
                ("Description", rule.condition.as_str()),
                ("Tags", tags.as_str()),
                ("Evidence", evidence.as_str()),
                ("References", references.as_str()),
                ("Uses rules", depends.as_str()),
                (
                    "Compatibility",
                    if rule.compatible {
                        "compatible"
                    } else {
                        rule.reason.as_str()
                    },
                ),
            ] {
                if !value.is_empty() {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("{label}: {value}")).color(theme::text()),
                        )
                        .wrap(),
                    );
                }
            }
            if !window.group.is_empty() && ui.button("Remove from group").clicked() {
                remove = true;
            }
            theme::section(ui, "Source text");
            match &window.text {
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
    remove
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
            ui.add(
                egui::Label::new(RichText::new(text).monospace().color(theme::text()))
                    .selectable(true),
            );
        });
}

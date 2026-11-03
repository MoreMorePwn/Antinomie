// SPDX-License-Identifier: GPL-3.0-only
//! The Strings regex tab of the Detection rules page: the patterns the regex
//! regex matches of Static analysis (Regex matches) and Core dumps use. Built-in patterns
//! can be switched off; patterns of your own can be added and removed. The
//! choices are kept in the rules folder and read by the next scan.
use super::{theme, Model};
use crate::widgets::fit_table::{self, Cell};
use crate::widgets::fit_table::{Col, FitBuilder};
use antinomie_monitor_core::strings_regex::{
    builtin_patterns, Category, Config, CustomPattern, Origin, RuleSet, Scan, CUSTOM_MAX_COUNT,
    PATTERN_MAX_LEN,
};
use eframe::egui::{self, RichText};
use std::path::Path;

pub(super) struct RegexState {
    loaded: bool,
    config: Config,
    error: Option<String>,
    name: String,
    category: Category,
    pattern: String,
    sample: String,
}

impl Default for RegexState {
    fn default() -> Self {
        Self {
            loaded: false,
            config: Config::default(),
            error: None,
            name: String::new(),
            category: Category::Custom,
            pattern: String::new(),
            sample: String::new(),
        }
    }
}

impl RegexState {
    /// "12 custom" for the tab's badge.
    pub(super) fn badge(&self) -> String {
        self.config.custom.len().to_string()
    }

    fn load(&mut self, data_dir: &Path) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        match Config::load(data_dir) {
            Ok(config) => self.config = config,
            Err(error) => {
                self.error = Some(format!("The saved patterns could not be read: {error}"))
            }
        }
    }

    /// Save `changed`, and keep it only when it saved.
    fn apply(&mut self, data_dir: &Path, changed: Config) {
        match changed.save(data_dir) {
            Ok(()) => {
                self.config = changed;
                self.error = None;
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn add(&mut self, data_dir: &Path) {
        let mut id = String::new();
        for character in self.name.to_lowercase().chars() {
            if character.is_ascii_alphanumeric() {
                id.push(character);
            } else if !id.ends_with('-') && !id.is_empty() {
                id.push('-');
            }
        }
        let id = format!("custom.{}", id.trim_end_matches('-'));
        let mut unique = id.clone();
        let mut number = 2;
        while self
            .config
            .custom
            .iter()
            .any(|pattern| pattern.id == unique)
        {
            unique = format!("{id}-{number}");
            number += 1;
        }
        let mut changed = self.config.clone();
        changed.custom.push(CustomPattern {
            id: unique,
            name: self.name.trim().to_owned(),
            category: self.category,
            pattern: self.pattern.clone(),
            enabled: true,
        });
        let before = self.config.custom.len();
        self.apply(data_dir, changed);
        if self.config.custom.len() > before {
            self.name.clear();
            self.pattern.clear();
        }
    }
}

/// The name field's width, in points.
const NAME_WIDTH: f32 = 240.0;
/// The least room, Add included, the expression is given on the name's row;
/// with less it moves to its own row.
const MIN_PATTERN_ROOM: f32 = 220.0;
/// What the empty name field says.
const NAME_HINT: &str = "Name, e.g. Campaign marker";

impl Model {
    pub(super) fn regex_tab(&mut self, ui: &mut egui::Ui, data_dir: &Path) {
        self.regex.load(data_dir);
        if let Some(error) = &self.regex.error {
            crate::activity::error(ui, error);
        }
        ui.add_space(4.0);
        theme::section(ui, "Add patterns");
        self.custom_patterns(ui, data_dir);
        ui.add_space(4.0);
        theme::section(ui, "Built-in patterns");
        self.builtin_table(ui, data_dir);
    }

    fn custom_patterns(&mut self, ui: &mut egui::Ui, data_dir: &Path) {
        let mut remove = None;
        let mut toggle = None;
        for (index, pattern) in self.regex.config.custom.iter().enumerate() {
            ui.horizontal(|ui| {
                let mut enabled = pattern.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    toggle = Some((index, enabled));
                }
                ui.label(RichText::new(pattern.category.label()).color(theme::muted()));
                ui.label(RichText::new(&pattern.name).strong());
                ui.label(RichText::new(&pattern.pattern).monospace());
                if ui.small_button("Remove").clicked() {
                    remove = Some(index);
                }
            });
        }
        if let Some((index, enabled)) = toggle {
            let mut changed = self.regex.config.clone();
            changed.custom[index].enabled = enabled;
            self.regex.apply(data_dir, changed);
        }
        if let Some(index) = remove {
            let mut changed = self.regex.config.clone();
            changed.custom.remove(index);
            self.regex.apply(data_dir, changed);
        }
        let full = self.regex.config.custom.len() >= CUSTOM_MAX_COUNT;
        // One row when the window is wide enough: the name, its category, the
        // expression (which takes what Add leaves) and Add. Below that the
        // expression and Add drop to a row of their own, so nothing is pushed
        // out of the window at any text size.
        let ready = !full && !self.regex.name.trim().is_empty() && !self.regex.pattern.is_empty();
        let mut add = false;
        let mut expression = |ui: &mut egui::Ui, pattern: &mut String| {
            // Add is laid out first, at the width its own text needs; the
            // expression field then fills what is left.
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                add = ui
                    .add_enabled(ready, egui::Button::new("Add"))
                    .on_hover_text("Rust regex syntax, matched against every string")
                    .clicked();
                ui.add(
                    egui::TextEdit::singleline(pattern)
                        .hint_text(theme::hint_text(
                            "Regular expression, such as evil[0-9]+\\.example\\.com",
                        ))
                        .char_limit(PATTERN_MAX_LEN)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ui.available_width()),
                );
            });
        };
        let mut second_row = false;
        ui.horizontal(|ui| {
            // Room for the whole hint at any text size.
            let hint_width = ui.fonts_mut(|fonts| {
                fonts
                    .layout_no_wrap(
                        NAME_HINT.to_owned(),
                        egui::TextStyle::Body.resolve(ui.style()),
                        egui::Color32::PLACEHOLDER,
                    )
                    .size()
                    .x
            });
            let name_width =
                NAME_WIDTH.max(hint_width + 2.0 * f32::from(theme::TEXT_EDIT_MARGIN.left));
            ui.add(
                egui::TextEdit::singleline(&mut self.regex.name)
                    .hint_text(theme::hint_text(NAME_HINT))
                    .char_limit(80)
                    .desired_width(crate::theme::plain_edit_width(
                        name_width.min((ui.available_width() - 120.0).max(120.0)),
                    )),
            );
            egui::ComboBox::from_id_salt("regex-new-category")
                .selected_text(self.regex.category.label())
                .show_ui(ui, |ui| {
                    for category in Category::ALL {
                        ui.selectable_value(&mut self.regex.category, category, category.label());
                    }
                });
            if ui.available_width() >= MIN_PATTERN_ROOM {
                expression(ui, &mut self.regex.pattern);
            } else {
                second_row = true;
            }
        });
        if second_row {
            ui.horizontal(|ui| expression(ui, &mut self.regex.pattern));
        }
        if add {
            self.regex.add(data_dir);
        }
        ui.horizontal(|ui| {
            ui.label("Try on");
            ui.add(
                egui::TextEdit::singleline(&mut self.regex.sample)
                    .hint_text(theme::hint_text("Paste a string to see what matches"))
                    .desired_width(ui.available_width()),
            );
        });
        if !self.regex.sample.is_empty() {
            let rules = RuleSet::build(&self.regex.config);
            let mut scan = Scan::default();
            rules.scan_text(&self.regex.sample, &Origin::default(), &mut scan);
            if scan.matches.is_empty() {
                ui.weak("No pattern matches this string.");
            }
            for found in scan.matches.iter().take(20) {
                ui.label(format!(
                    "{} · {} · {}",
                    found.category.label(),
                    found.kind,
                    found.text
                ));
            }
        }
    }

    fn builtin_table(&mut self, ui: &mut egui::Ui, data_dir: &Path) {
        let patterns = builtin_patterns();
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let mut toggle = None;
        let height = ui.available_height().max(160.0);
        FitBuilder::new(ui)
            .id_salt("regex_builtin")
            .max_scroll_height(height)
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Col::fixed(28.0))
            .column(Col::flex(120.0).at_least(60.0).clip(true))
            .column(Col::flex(170.0).at_least(80.0).clip(true))
            .column(Col::rest(80.0).at_least(120.0).clip(true))
            .header(fit_table::header_height(font), |mut header| {
                for title in ["On", "Category", "Type", "Pattern"] {
                    header.col(|ui| fit_table::head(ui, title));
                }
            })
            .body(|body| {
                body.rows(fit_table::row_height(font), patterns.len(), |mut row| {
                    let (id, category, name, regex) = patterns[row.index()];
                    let mut enabled = self.regex.config.is_enabled(id);
                    row.col(|ui| {
                        if ui.checkbox(&mut enabled, "").on_hover_text(id).changed() {
                            toggle = Some((id, enabled));
                        }
                    });
                    row.col(|ui| {
                        fit_table::cell(ui, Cell::Text, category.label());
                    });
                    row.col(|ui| {
                        fit_table::cell(ui, Cell::Text, name);
                    });
                    row.col(|ui| {
                        fit_table::cell(ui, Cell::Mono, regex).on_hover_text(regex);
                    });
                });
            });
        if let Some((id, enabled)) = toggle {
            let mut changed = self.regex.config.clone();
            changed.set_enabled(id, enabled);
            self.regex.apply(data_dir, changed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_a_pattern_derives_a_unique_id_and_refuses_a_bad_regex() {
        let dir = std::env::temp_dir().join(format!("ant-regex-tab-{}", std::process::id()));
        let mut state = RegexState::default();
        state.load(&dir);
        state.name = "Campaign marker!".into();
        state.pattern = "op-[a-z]+".into();
        state.add(&dir);
        state.name = "Campaign marker!".into();
        state.pattern = "op2-[a-z]+".into();
        state.add(&dir);
        let ids: Vec<_> = state.config.custom.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["custom.campaign-marker", "custom.campaign-marker-2"]);
        assert!(state.name.is_empty() && state.error.is_none());
        state.name = "Broken".into();
        state.pattern = "(open".into();
        state.add(&dir);
        assert_eq!(state.config.custom.len(), 2);
        assert!(state.error.as_deref().unwrap().contains("custom.broken"));
        // What was saved is what a later scan reads.
        assert_eq!(Config::load(&dir).unwrap().custom.len(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}

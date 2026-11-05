// SPDX-License-Identifier: GPL-3.0-only
//! Settings > Keyboard: one row per action with its shortcut. A click on the
//! key records the next press, a taken key asks before it moves, and each row
//! has a clear and a reset to the default. What is changed is saved in
//! Settings (`shortcuts`); `bindings` holds the rules.
use super::bindings;
use super::*;
use eframe::egui::{Event, Key, KeyboardShortcut};

impl MonitorApp {
    /// Take the next key press as the shortcut of the row being recorded.
    /// Escape alone cancels; a press that cannot be a shortcut says why and
    /// the recording goes on.
    fn record_shortcut(&mut self, ctx: &egui::Context) {
        let Some(action) = self.shortcut_ui.recording.clone() else {
            return;
        };
        let press = ctx.input_mut(|input| {
            let found = input.events.iter().find_map(|event| match event {
                Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } => Some((*key, *modifiers)),
                _ => None,
            });
            if found.is_some() {
                // Nothing else sees the key, and no letter is typed.
                input
                    .events
                    .retain(|event| !matches!(event, Event::Key { .. } | Event::Text(_)));
            }
            found
        });
        let Some((key, modifiers)) = press else {
            return;
        };
        self.shortcut_ui.notice = None;
        if key == Key::Escape && modifiers.is_none() {
            self.shortcut_ui.recording = None;
            return;
        }
        match bindings::from_press(modifiers, key) {
            Err(reason) => self.shortcut_ui.notice = Some((action, reason)),
            Ok(shortcut) => {
                self.shortcut_ui.recording = None;
                self.choose_shortcut(&action, shortcut);
            }
        }
    }

    /// Give `action` the shortcut, or ask when another action has it.
    pub(super) fn choose_shortcut(&mut self, action: &Action, shortcut: KeyboardShortcut) {
        match self.shortcut_owner(action, &shortcut) {
            Some(owner) => {
                self.shortcut_ui.conflict = Some((action.clone(), shortcut, owner));
            }
            None => self.set_shortcut(action, Some(shortcut)),
        }
    }

    /// The actions by menu, in the order of the menus.
    fn shortcut_groups(&self, words: &str) -> Vec<(&'static str, Vec<Action>)> {
        let words = words.trim().to_lowercase();
        let mut groups: Vec<(&'static str, Vec<Action>)> = Vec::new();
        for action in Action::bindable() {
            if !words.is_empty() {
                let keys = self
                    .shortcut_of(&action)
                    .map(|shortcut| bindings::to_text(&shortcut))
                    .unwrap_or_default();
                let text = format!("{} {} {}", action.label(self), action.group(), keys);
                if !text.to_lowercase().contains(&words) {
                    continue;
                }
            }
            let group = action.group();
            match groups.iter_mut().find(|(name, _)| *name == group) {
                Some((_, actions)) => actions.push(action),
                None => groups.push((group, vec![action])),
            }
        }
        groups
    }

    pub(super) fn keyboard_page(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.record_shortcut(ctx);
        ui.add(egui::Label::new("Click a key, then press the new one. Esc cancels.").wrap())
            .on_hover_text(
                "Click a key, then press the new one. Esc cancels. A shortcut needs Ctrl or Alt, \
                 so it never types a letter, and waits while a text field or the terminal has the \
                 keyboard. Ctrl+1 to Ctrl+9 always show the first nine tabs.",
            );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.add(
                widgets::text_field(&mut self.shortcut_ui.filter)
                    .hint_text(theme::placeholder(ui, "Find an action or a key"))
                    .desired_width(theme::edit_width(220.0)),
            );
            let any = !self.settings.shortcuts.is_empty();
            if ui
                .add_enabled(any, egui::Button::new("Reset all"))
                .on_hover_text("Every shortcut back to its default")
                .clicked()
            {
                self.settings.shortcuts.clear();
                self.shortcut_ui.conflict = None;
                self.shortcut_ui.notice = None;
            }
        });
        if let Some((action, reason)) = self.shortcut_ui.notice.clone() {
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{}: {reason}", action.label(self))).color(theme::warn()),
                )
                .wrap(),
            );
        }
        if let Some((action, shortcut, owner)) = self.shortcut_ui.conflict.clone() {
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "{} is already {}.",
                        bindings::to_text(&shortcut),
                        owner.label(self)
                    ))
                    .color(theme::warn()),
                )
                .wrap(),
            );
            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(format!("Move it to {}", action.label(self)))
                    .on_hover_text("The other action is left without a shortcut")
                    .clicked()
                {
                    self.set_shortcut(&owner, None);
                    self.set_shortcut(&action, Some(shortcut));
                    self.shortcut_ui.conflict = None;
                }
                if ui.button("Keep it where it is").clicked() {
                    self.shortcut_ui.conflict = None;
                }
            });
        }
        ui.add_space(6.0);
        let groups = self.shortcut_groups(&self.shortcut_ui.filter.clone());
        if groups.is_empty() {
            ui.weak("No action matches.");
        }
        let recording = self.shortcut_ui.recording.clone();
        let mut start = None;
        let mut set = Vec::new();
        // One row: the action, its key, Clear and Reset. The widths follow the
        // text size and the room, so a row never reaches past the page.
        let size = egui::TextStyle::Body.resolve(ui.style()).size;
        let spacing = ui.spacing().item_spacing.x;
        let key_width = size * 9.5;
        let button_width = size * 3.6 + 16.0;
        let label_width =
            (ui.available_width() - key_width - 2.0 * button_width - 3.0 * spacing).max(size * 8.0);
        for (group, actions) in &groups {
            ui.add_space(8.0);
            theme::section(ui, group);
            ui.add_space(4.0);
            for action in actions {
                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(label_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            ui.set_width(label_width);
                            ui.add(egui::Label::new(action.label(self)).wrap());
                        },
                    );
                    let current = self.shortcut_of(action);
                    let text = if recording.as_ref() == Some(action) {
                        "Press the keys…".to_owned()
                    } else {
                        current
                            .as_ref()
                            .map_or_else(|| "None".to_owned(), bindings::to_text)
                    };
                    let key = ui
                        .add(
                            egui::Button::new(RichText::new(text).monospace().color(theme::text()))
                                .min_size(egui::vec2(key_width, 0.0)),
                        )
                        .on_hover_text("Click, then press the new shortcut");
                    if key.clicked() {
                        start = Some(action.clone());
                    }
                    if ui
                        .add_enabled(
                            current.is_some(),
                            egui::Button::new("Clear").min_size(egui::vec2(button_width, 0.0)),
                        )
                        .on_hover_text("No shortcut for this action")
                        .clicked()
                    {
                        set.push((action.clone(), None));
                    }
                    let default = action.default_shortcut();
                    let tip = match &default {
                        Some(default) => {
                            format!("Back to the default, {}", bindings::to_text(default))
                        }
                        None => "Back to the default: no shortcut".to_owned(),
                    };
                    if ui
                        .add_enabled(
                            self.shortcut_changed(action),
                            egui::Button::new("Reset").min_size(egui::vec2(button_width, 0.0)),
                        )
                        .on_hover_text(tip)
                        .clicked()
                    {
                        set.push((action.clone(), default));
                    }
                });
            }
        }
        if let Some(action) = start {
            self.shortcut_ui.notice = None;
            self.shortcut_ui.conflict = None;
            self.shortcut_ui.recording = Some(action);
        }
        for (action, shortcut) in set {
            match shortcut {
                Some(shortcut) => self.choose_shortcut(&action, shortcut),
                None => self.set_shortcut(&action, None),
            }
        }
        if self.shortcut_ui.recording.is_some() {
            ctx.request_repaint();
        }
    }
}

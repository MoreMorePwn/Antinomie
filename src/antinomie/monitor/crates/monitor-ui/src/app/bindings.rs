// SPDX-License-Identifier: GPL-3.0-only
//! Editable keyboard shortcuts. `keys.rs` holds the defaults; what the person
//! changed is saved in Settings as one text per action (`Settings::shortcuts`,
//! "Ctrl+Shift+A", or "" for an action left without a key) and read here.
//! Every action of the menus and the palette, and every view, has its own
//! entry, so Settings > Keyboard lists them one by one.
use super::*;
use eframe::egui::{Key, KeyboardShortcut, Modifiers};

/// One shortcut as `(ctrl or command, alt, shift, key)`: Ctrl and Command are
/// the same key on Linux, and two actions on it would collide.
pub(super) type Chord = (bool, bool, bool, Key);

pub(super) fn chord(shortcut: &KeyboardShortcut) -> Chord {
    let modifiers = shortcut.modifiers;
    (
        modifiers.command || modifiers.ctrl,
        modifiers.alt,
        modifiers.shift,
        shortcut.logical_key,
    )
}

/// The text a shortcut is saved as, and shown as in Settings: "Ctrl+Shift+A".
pub(super) fn to_text(shortcut: &KeyboardShortcut) -> String {
    let (ctrl, alt, shift, key) = chord(shortcut);
    let mut text = String::new();
    for (on, name) in [(ctrl, "Ctrl+"), (alt, "Alt+"), (shift, "Shift+")] {
        if on {
            text.push_str(name);
        }
    }
    text.push_str(key.name());
    text
}

/// A shortcut from its saved text; `None` for text that is not one.
pub(super) fn from_text(text: &str) -> Option<KeyboardShortcut> {
    let mut rest = text.trim();
    let mut modifiers = Modifiers::NONE;
    loop {
        if let Some(tail) = rest.strip_prefix("Ctrl+") {
            modifiers = modifiers.plus(Modifiers::COMMAND);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("Alt+") {
            modifiers = modifiers.plus(Modifiers::ALT);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("Shift+") {
            modifiers = modifiers.plus(Modifiers::SHIFT);
            rest = tail;
        } else {
            break;
        }
    }
    Some(KeyboardShortcut::new(modifiers, Key::from_name(rest)?))
}

/// Why a key press cannot be a shortcut, or the shortcut it makes.
pub(super) fn from_press(modifiers: Modifiers, key: Key) -> Result<KeyboardShortcut, String> {
    let ctrl = modifiers.command || modifiers.ctrl;
    let function = matches!(
        key,
        Key::F1
            | Key::F2
            | Key::F3
            | Key::F4
            | Key::F5
            | Key::F6
            | Key::F7
            | Key::F8
            | Key::F9
            | Key::F10
            | Key::F11
            | Key::F12
    );
    if !ctrl && !modifiers.alt && !function {
        return Err("Hold Ctrl or Alt with the key, so it never types a letter.".into());
    }
    let mut made = Modifiers::NONE;
    if ctrl {
        made = made.plus(Modifiers::COMMAND);
    }
    if modifiers.alt {
        made = made.plus(Modifiers::ALT);
    }
    if modifiers.shift {
        made = made.plus(Modifiers::SHIFT);
    }
    let shortcut = KeyboardShortcut::new(made, key);
    if let Some(reason) = reserved(&shortcut) {
        return Err(reason);
    }
    Ok(shortcut)
}

/// What a shortcut cannot be taken for, as a sentence; `None` when it is free.
pub(super) fn reserved(shortcut: &KeyboardShortcut) -> Option<String> {
    let (ctrl, alt, shift, key) = chord(shortcut);
    if ctrl && !alt && !shift {
        if keys::TAB_KEYS.contains(&key) {
            return Some(format!(
                "{} to {} show the first nine tabs.",
                to_text(&KeyboardShortcut::new(
                    Modifiers::COMMAND,
                    keys::TAB_KEYS[0]
                )),
                to_text(&KeyboardShortcut::new(
                    Modifiers::COMMAND,
                    keys::TAB_KEYS[8]
                ))
            ));
        }
        if matches!(key, Key::C | Key::X | Key::V | Key::A | Key::Z | Key::Y) {
            return Some("Copy, cut, paste, select all and undo keep their keys.".into());
        }
    }
    None
}

impl Action {
    /// The key this action's shortcut is saved under: its name, which a
    /// release must not change.
    pub(super) fn binding_id(&self) -> String {
        format!("{self:?}")
    }

    /// Every action that can have a shortcut, one entry each: the menus' and
    /// the palette's, the views, and the pages and windows the palette opens.
    pub(super) fn bindable() -> Vec<Self> {
        let mut actions: Vec<Self> = Self::PALETTE.to_vec();
        actions.extend(
            Panel::MAIN
                .into_iter()
                .chain([
                    Panel::Details,
                    Panel::Activity,
                    Panel::Jobs,
                    Panel::VmScreen,
                ])
                .map(Self::Go),
        );
        actions.extend(Self::palette_pages());
        actions
    }
}

impl MonitorApp {
    /// The shortcut of `action`: the one chosen in Settings, else its default.
    pub(super) fn shortcut_of(&self, action: &Action) -> Option<KeyboardShortcut> {
        match self.settings.shortcuts.get(&action.binding_id()) {
            Some(text) if text.is_empty() => None,
            Some(text) => from_text(text).or_else(|| action.default_shortcut()),
            None => action.default_shortcut(),
        }
    }

    /// Choose `shortcut` for `action` (`None` leaves it without one); a choice
    /// equal to the default is not kept, so a later default shows up.
    pub(super) fn set_shortcut(&mut self, action: &Action, shortcut: Option<KeyboardShortcut>) {
        let id = action.binding_id();
        let default = action.default_shortcut();
        if shortcut.as_ref().map(chord) == default.as_ref().map(chord) {
            self.settings.shortcuts.remove(&id);
        } else {
            self.settings
                .shortcuts
                .insert(id, shortcut.as_ref().map(to_text).unwrap_or_default());
        }
    }

    /// Whether the person changed the shortcut of `action`.
    pub(super) fn shortcut_changed(&self, action: &Action) -> bool {
        self.settings.shortcuts.contains_key(&action.binding_id())
    }

    /// The other action that already has `shortcut`, if any.
    pub(super) fn shortcut_owner(
        &self,
        action: &Action,
        shortcut: &KeyboardShortcut,
    ) -> Option<Action> {
        let wanted = chord(shortcut);
        Action::bindable()
            .into_iter()
            .filter(|other| other != action)
            .find(|other| self.shortcut_of(other).as_ref().map(chord) == Some(wanted))
    }

    /// Every action that has a shortcut now, the ones with more modifiers
    /// first: a press of Shift+F5 must reach its action before F5 would.
    pub(super) fn bound_actions(&self) -> Vec<(Action, KeyboardShortcut)> {
        let mut bound: Vec<(Action, KeyboardShortcut)> = Action::bindable()
            .into_iter()
            .filter_map(|action| self.shortcut_of(&action).map(|shortcut| (action, shortcut)))
            .collect();
        bound.sort_by_key(|(_, shortcut)| {
            let (ctrl, alt, shift, _) = chord(shortcut);
            std::cmp::Reverse(u8::from(ctrl) + u8::from(alt) + u8::from(shift))
        });
        bound
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shortcut_round_trips_through_its_text() {
        for text in [
            "Ctrl+Shift+A",
            "Alt+J",
            "Ctrl+Comma",
            "Shift+F5",
            "Ctrl+Alt+Shift+Z",
        ] {
            let shortcut = from_text(text).unwrap_or_else(|| panic!("{text}"));
            assert_eq!(to_text(&shortcut), text);
        }
        assert!(from_text("Ctrl+").is_none());
        assert!(from_text("Hyper+A").is_none());
    }

    #[test]
    fn a_press_needs_ctrl_or_alt_and_may_not_take_reserved_keys() {
        assert!(from_press(Modifiers::NONE, Key::A).is_err());
        assert!(from_press(Modifiers::SHIFT, Key::A).is_err());
        assert!(from_press(Modifiers::COMMAND, Key::Num3).is_err());
        assert!(from_press(Modifiers::COMMAND, Key::C).is_err());
        assert!(from_press(Modifiers::NONE, Key::F9).is_ok());
        let made = from_press(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::M).unwrap();
        assert_eq!(to_text(&made), "Ctrl+Shift+M");
    }

    #[test]
    fn every_action_has_its_own_stable_id() {
        let ids: Vec<String> = Action::bindable().iter().map(Action::binding_id).collect();
        let mut unique = ids.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(ids.len(), unique.len(), "{ids:?}");
        for id in ["NewVm", "ToggleBottomPane", "Go(Activity)", "Go(Details)"] {
            assert!(ids.iter().any(|known| known == id), "{id}: {ids:?}");
        }
    }

    #[test]
    fn the_defaults_do_not_collide_and_need_no_function_or_arrow_key() {
        let mut seen = std::collections::BTreeMap::new();
        for action in Action::bindable() {
            let Some(shortcut) = action.default_shortcut() else {
                continue;
            };
            assert!(reserved(&shortcut).is_none(), "{action:?}");
            let (_, _, _, key) = chord(&shortcut);
            assert!(
                !matches!(
                    key,
                    Key::F1
                        | Key::F2
                        | Key::F3
                        | Key::F4
                        | Key::F5
                        | Key::F6
                        | Key::F7
                        | Key::F8
                        | Key::F9
                        | Key::F10
                        | Key::F11
                        | Key::F12
                        | Key::Backtick
                        | Key::Home
                        | Key::End
                        | Key::PageUp
                        | Key::PageDown
                        | Key::ArrowUp
                        | Key::ArrowDown
                        | Key::ArrowLeft
                        | Key::ArrowRight
                ),
                "{action:?} needs a key a 60% keyboard lacks"
            );
            if let Some(other) = seen.insert(chord(&shortcut), action.clone()) {
                panic!("{other:?} and {action:?} share {shortcut:?}");
            }
        }
    }
}

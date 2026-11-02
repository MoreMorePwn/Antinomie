// SPDX-License-Identifier: GPL-3.0-only
//! The application's keyboard shortcuts. Each is one `KeyboardShortcut`, shown
//! in the menus, the tooltips, the palette and the Keyboard shortcuts window,
//! and consumed in [`super::MonitorApp::shortcuts`].
use eframe::egui::{Key, KeyboardShortcut, Modifiers};

pub const NEW_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::N);
pub const START_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::NONE, Key::F5);
pub const STOP_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::SHIFT, Key::F5);
pub const RUN_PROGRAM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::R);
pub const UPLOAD: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::U);
pub const ATTACH_DEBUGGER: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::D);
pub const PALETTE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::K);
pub const TYPE_CLIPBOARD: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::Y);
pub const SETTINGS: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Comma);
pub const QUIT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::Q);

/// Ctrl+1 to Ctrl+9: the first nine tabs of the work area, left to right.
pub const TAB_KEYS: [Key; 9] = [
    Key::Num1,
    Key::Num2,
    Key::Num3,
    Key::Num4,
    Key::Num5,
    Key::Num6,
    Key::Num7,
    Key::Num8,
    Key::Num9,
];

/// The text of the shortcut that lists the shortcuts (typed as Shift+/).
pub const SHORTCUT_LIST: &str = "?";

/// The shortcut that opens the tab at `position` (0 for the first).
pub fn tab_shortcut(position: usize) -> Option<KeyboardShortcut> {
    TAB_KEYS
        .get(position)
        .map(|key| KeyboardShortcut::new(Modifiers::COMMAND, *key))
}

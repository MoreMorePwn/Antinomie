// SPDX-License-Identifier: GPL-3.0-only
//! The application's default keyboard shortcuts. Each is one
//! `KeyboardShortcut`; Settings > Keyboard can change them (see `bindings`),
//! and the menus, the tooltips, the palette and the Keyboard shortcuts window
//! show what is in force. They are consumed in
//! [`super::MonitorApp::shortcuts`].
//!
//! Every default is a Ctrl (or Ctrl+Shift) chord on a letter, the comma or a
//! digit: a 60% keyboard has these without a Fn layer. No default uses an F-key,
//! an arrow, Home, End, PgUp, PgDn, the numpad or the backtick, which a 60%
//! board puts behind Fn (F5 and Shift+F5 for Start and Stop VM, and Ctrl+`
//! for folding the bottom pane, were of that kind).
use eframe::egui::{Key, KeyboardShortcut, Modifiers};

pub const NEW_VM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::N);
pub const START_VM: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::S);
pub const STOP_VM: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::X);
pub const RUN_PROGRAM: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::R);
pub const UPLOAD: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::U);
pub const ATTACH_DEBUGGER: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::D);
pub const PALETTE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::K);
/// Show the Activity tab (Ctrl+Shift+A) and the Jobs tab (Ctrl+Shift+J): they
/// sit in the lower bar, which Ctrl+1 to Ctrl+9 do not reach. Ctrl+J folds or
/// opens the whole bar.
pub const SHOW_ACTIVITY: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::A);
pub const SHOW_JOBS: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::J);
pub const TYPE_CLIPBOARD: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::CTRL.plus(Modifiers::SHIFT), Key::Y);
/// Fold the sidebar to its icon rail, or open it again.
pub const TOGGLE_SIDEBAR: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::B);
/// Fold the Details, Activity and Jobs pane to its tab strip, or open it again.
pub const TOGGLE_BOTTOM_PANE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, Key::J);
/// Show the Details tab (Ctrl+Shift+D).
pub const SHOW_DETAILS: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::D);
/// Open the Statistics window (Ctrl+Shift+T).
pub const STATISTICS: KeyboardShortcut =
    KeyboardShortcut::new(Modifiers::COMMAND.plus(Modifiers::SHIFT), Key::T);
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

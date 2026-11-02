// SPDX-License-Identifier: GPL-3.0-only
//! Who owns the keyboard. A global shortcut must not steal a key from a text
//! field or the terminal: egui has no "a text field is focused" query, and
//! `wants_keyboard_input` is true for any focused widget (a button reached with
//! Tab too), so the answer is built here from what is known about the widget
//! that has the focus.
use eframe::egui;

/// The terminal pane that has the focus, as of its last frame.
fn terminal_key() -> egui::Id {
    egui::Id::new("antinomie-terminal-focus")
}

/// A terminal pane calls this each frame it has the focus: its keys, Ctrl+letters
/// included, belong to the guest.
pub(crate) fn mark_terminal(ctx: &egui::Context, id: egui::Id) {
    ctx.data_mut(|data| data.insert_temp(terminal_key(), id));
}

/// A text field (egui keeps edit state per field) or a terminal has the focus.
/// A focused button, table or graph does not count: they take few keys, and
/// those without Ctrl.
pub(crate) fn typing(ctx: &egui::Context) -> bool {
    let Some(id) = ctx.memory(|memory| memory.focused()) else {
        return false;
    };
    egui::text_edit::TextEditState::load(ctx, id).is_some()
        || ctx.data(|data| data.get_temp::<egui::Id>(terminal_key())) == Some(id)
}

/// `?` was typed (Shift+/ on most layouts) with no Ctrl or Alt. The events
/// are taken so that nothing else sees the key.
pub(crate) fn question_mark_pressed(ctx: &egui::Context) -> bool {
    ctx.input_mut(|input| {
        if input.modifiers.ctrl || input.modifiers.alt || input.modifiers.command {
            return false;
        }
        let is_question = |event: &egui::Event| match event {
            egui::Event::Text(text) => text == "?",
            egui::Event::Key {
                key,
                pressed: true,
                modifiers,
                ..
            } => {
                *key == egui::Key::Questionmark
                    || (*key == egui::Key::Slash && modifiers.shift && !modifiers.ctrl)
            }
            _ => false,
        };
        let found = input.events.iter().any(is_question);
        if found {
            input.events.retain(|event| !is_question(event));
        }
        found
    })
}

// SPDX-License-Identifier: GPL-3.0-only
//! The Keyboard shortcuts window (`?` or Help > Keyboard shortcuts): every
//! shortcut by area, and the rule for who owns the keyboard.
use super::*;

/// The command palette and the shortcut list.
#[derive(Default)]
pub(super) struct ShortcutUi {
    pub(super) palette: palette::Palette,
    pub(super) list_open: bool,
}

impl ShortcutUi {
    /// Open the palette with an empty query.
    pub(super) fn open_palette(&mut self) {
        self.palette = palette::Palette::default();
        self.palette.open = true;
    }
}

/// The rule the window states first.
pub(super) const OWNERSHIP_RULE: &str = "Shortcuts never take a key from a text field or the \
terminal: while one has the keyboard, typing goes to it, and every key below that is global waits. \
Click away (or press Esc in a dialog) to use them again. Ctrl+K in particular stays with the \
field or the terminal (it deletes to the end of the line); use the Search button in the menu \
bar or Help > Command palette there.";

/// Shortcuts that belong to one area of the window and not to the application,
/// as `(area, keys, what it does)`. The global ones come from `Action`.
pub(super) const AREA_SHORTCUTS: &[(&str, &str, &str)] = &[
    (
        "Windows and dialogs",
        "Esc",
        "Close the window on top (not while a field has the keyboard)",
    ),
    (
        "Windows and dialogs",
        "Ctrl+D",
        "In the Attach debugger list: attach the debugger to the selected process",
    ),
    (
        "Windows and dialogs",
        "Enter",
        "Confirm Rename and Duplicate; accept a one-line field",
    ),
    (
        "Command palette",
        "↑ ↓ PgUp PgDn",
        "Move through the matches",
    ),
    (
        "Command palette",
        "Enter",
        "Run the highlighted entry; a greyed one shows why it cannot",
    ),
    ("Command palette", "Esc, Ctrl+K", "Close the palette"),
    ("Tabs", "Esc", "Cancel dragging a tab"),
    (
        "Run history and Captures",
        "↑ ↓ Home End",
        "Move the selection when the table has the focus",
    ),
    ("Triage graph", "← →", "Previous or next finding in time"),
    ("Triage graph", "↑ ↓", "Move between lanes"),
    ("Triage graph", "Enter", "Open the selected finding"),
    (
        "Triage graph",
        "F, R",
        "Fit the view; reset the time window",
    ),
    (
        "Triage graph",
        "+ -",
        "Zoom in and out around the selection",
    ),
    ("Triage graph", "Space", "Fold or unfold the selected lane"),
    (
        "Triage graph",
        "H M L I",
        "Show or hide the High, Medium, Low and Info tiers",
    ),
    (
        "Triage graph",
        "1 to 9, 0",
        "Toggle the first ten category chips",
    ),
    (
        "Triage graph",
        "T, Home, End",
        "Change the spacing; first and last finding",
    ),
    ("Triage graph", "Esc", "Clear the brush"),
    (
        "File activity",
        "← →",
        "Previous and next version of the file under the pointer",
    ),
    ("Lineage graph", "← → ↑ ↓", "Pan"),
    ("Lineage graph", "+ - 0", "Zoom in, zoom out, fit"),
    ("Syscall filter", "Ctrl+Space", "Open the completions"),
    (
        "Syscall filter",
        "↑ ↓ Enter Tab Esc",
        "Choose, accept (Enter or Tab) and dismiss a completion",
    ),
    (
        "Sample pickers",
        "↑ ↓ Enter Esc",
        "Choose, accept and go back",
    ),
    (
        "Terminal",
        "Shift+PgUp PgDn Home End",
        "Scroll the terminal's history",
    ),
    (
        "Terminal",
        "Ctrl+Shift+C, Ctrl+Shift+V",
        "Copy the selection; paste",
    ),
    (
        "Terminal",
        "Ctrl+C",
        "Copy the selection, or interrupt the program when nothing is selected",
    ),
    (
        "Terminal",
        "Every other key",
        "Goes to the program in the guest, Ctrl+letters included",
    ),
];

/// One line of the window.
pub(super) struct Row {
    pub(super) area: String,
    pub(super) keys: String,
    pub(super) what: String,
}

impl MonitorApp {
    /// Every shortcut by area: the application's (from the actions), the
    /// tabs' Ctrl+digits, then the areas' own keys.
    pub(super) fn shortcut_rows(&self, ctx: &egui::Context) -> Vec<Row> {
        let mut rows = Vec::new();
        let mut add = |area: &str, keys: String, what: &str| {
            rows.push(Row {
                area: area.into(),
                keys,
                what: what.into(),
            });
        };
        for action in Action::PALETTE {
            let Some(keys) = self.shortcut_text(ctx, &action) else {
                continue;
            };
            let what = match &action {
                Action::Palette => {
                    "Command palette: find any action, tab, VM, run or sample".into()
                }
                Action::Shortcuts => "This list".into(),
                other => format!("{} ({})", other.label(self), other.group()),
            };
            add("Application", keys, &what);
        }
        add(
            "Workspace tabs",
            format!(
                "{} to {}",
                ctx.format_shortcut(&keys::tab_shortcut(0).expect("first tab key")),
                ctx.format_shortcut(&keys::tab_shortcut(8).expect("ninth tab key"))
            ),
            "Show the 1st to 9th tab of the work area, left to right",
        );
        for panel in [Panel::Activity, Panel::Jobs] {
            let action = Action::Go(panel.clone());
            if let Some(keys) = action
                .shortcut()
                .map(|shortcut| ctx.format_shortcut(&shortcut))
            {
                add(
                    "Workspace tabs",
                    keys,
                    &format!("Show the {} tab (lower bar)", panel.title()),
                );
            }
        }
        for (area, keys, what) in AREA_SHORTCUTS {
            add(area, (*keys).into(), what);
        }
        rows
    }

    /// The Keyboard shortcuts window; Esc closes it unless a field has the keyboard.
    pub(super) fn shortcut_window(&mut self, ctx: &egui::Context) {
        if !self.shortcut_ui.list_open {
            return;
        }
        if !crate::typing::typing(ctx)
            && ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::Escape))
        {
            self.shortcut_ui.list_open = false;
            return;
        }
        let rows = self.shortcut_rows(ctx);
        let mut open = true;
        egui::Window::new("Keyboard shortcuts")
            .id(egui::Id::new("keyboard_shortcuts"))
            .open(&mut open)
            .order(egui::Order::Foreground)
            .collapsible(false)
            .default_size(egui::vec2(640.0, 520.0))
            .show(ctx, |ui| {
                ui.label(OWNERSHIP_RULE);
                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .id_salt("keyboard_shortcuts_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let mut area = "";
                        for row in &rows {
                            if row.area != area {
                                area = &row.area;
                                ui.add_space(6.0);
                                ui.label(theme::bold(ui, area).color(theme::heading()));
                                ui.separator();
                            }
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [190.0, 0.0],
                                    egui::Label::new(
                                        egui::RichText::new(&row.keys)
                                            .monospace()
                                            .color(theme::text()),
                                    )
                                    .wrap(),
                                );
                                ui.label(&row.what);
                            });
                        }
                    });
            });
        if !open {
            self.shortcut_ui.list_open = false;
        }
    }
}

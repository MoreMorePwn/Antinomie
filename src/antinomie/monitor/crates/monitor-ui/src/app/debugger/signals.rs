// SPDX-License-Identifier: MIT
//! The signal handling table (gdb's `handle`): what the panel does when the
//! program is about to receive each signal, and the latest signals seen.
use super::*;
use antinomie_monitor_core::debug::{
    signal_policy::{default_action, signal_name, SignalNote, SignalTable},
    view::Controller,
};

/// Signals the table lists: the standard ones.
const LISTED_MAX: u8 = 31;
/// Log lines shown, newest last.
const LOG_SHOWN_COUNT: usize = 8;

/// One log line in words.
pub(super) fn note_text(note: &SignalNote) -> String {
    let name = signal_name(note.number);
    if note.stopped {
        format!("{name} stopped thread {}", note.tid)
    } else if note.passed {
        format!("{name} to thread {} passed", note.tid)
    } else {
        format!("{name} to thread {} not passed", note.tid)
    }
}

/// The table, with `table` as the values shown; an edit is one request.
pub(super) fn rows(
    ui: &mut egui::Ui,
    table: &SignalTable,
    enabled: bool,
    actions: &mut Vec<PanelAction>,
) {
    egui::Grid::new("debugger-signals")
        .num_columns(5)
        .spacing([10.0, 2.0])
        .show(ui, |ui| {
            for head in ["Signal", "Stop", "Print", "Pass", ""] {
                ui.label(RichText::new(head).color(theme::muted()));
            }
            ui.end_row();
            for number in 1..=LISTED_MAX {
                let current = table.action(number);
                let changed = current != default_action(number);
                let name = RichText::new(format!("{} ({number})", signal_name(number))).monospace();
                ui.label(if changed {
                    name.color(theme::warn())
                } else {
                    name
                });
                let mut next = current;
                let mut touched = false;
                for (value, field) in [
                    (&mut next.stop, "stop"),
                    (&mut next.print, "print"),
                    (&mut next.pass, "pass"),
                ] {
                    touched |= ui
                        .add_enabled(enabled, egui::Checkbox::without_text(value))
                        .on_hover_text(field)
                        .changed();
                }
                ui.label(if changed {
                    RichText::new("changed").color(theme::warn())
                } else {
                    RichText::new("")
                });
                ui.end_row();
                if touched {
                    actions.push(PanelAction::Debug(DebugAction::SetSignalPolicy {
                        signal: number,
                        action: next,
                    }));
                }
            }
        });
}

/// The collapsible Signals section of the left column.
pub(super) fn section(ui: &mut egui::Ui, view: &DebugView, actions: &mut Vec<PanelAction>) {
    if !view.signal_log.is_empty() {
        let skip = view.signal_log.len().saturating_sub(LOG_SHOWN_COUNT);
        theme::section(ui, "Recent signals");
        for note in view.signal_log.iter().skip(skip) {
            ui.label(RichText::new(note_text(note)).monospace());
        }
    }
    let gdb = view.controller == Controller::Gdb;
    egui::CollapsingHeader::new("Signals")
        .id_salt("debugger-signals-section")
        .default_open(false)
        .show(ui, |ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "What this panel does when the program gets a signal. A gdb client \
                         keeps gdb's own handle table.",
                    )
                    .color(theme::muted()),
                )
                .wrap(),
            );
            let enabled = !gdb;
            if ui
                .add_enabled(
                    enabled && !view.signals.is_default(),
                    egui::Button::new("Reset to defaults"),
                )
                .on_hover_text("Back to gdb's defaults")
                .clicked()
            {
                actions.push(PanelAction::Debug(DebugAction::SetSignalTable(
                    SignalTable::default(),
                )));
            }
            rows(ui, &view.signals, enabled, actions);
        });
}

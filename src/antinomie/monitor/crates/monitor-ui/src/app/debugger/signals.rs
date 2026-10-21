// SPDX-License-Identifier: MIT
//! The signal handling table (gdb's `handle`): what the panel does when the
//! program is about to receive each signal, and the latest signals seen.
use super::*;
use crate::{table_sort, widgets::table as widgets_table};
use antinomie_monitor_core::debug::{
    signal_policy::{default_action, signal_name, SignalNote, SignalTable},
    view::Controller,
};

use egui_extras::{Column, TableBuilder};

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
    const TABLE: &str = "debugger-signals";
    let numbers: Vec<u8> = (1..=LISTED_MAX).collect();
    let order = table_sort::order(ui.ctx(), TABLE, numbers.len(), |column, a, b| {
        let (a, b) = (numbers[a], numbers[b]);
        let (x, y) = (table.action(a), table.action(b));
        match column {
            0 => signal_name(a).cmp(&signal_name(b)),
            1 => x.stop.cmp(&y.stop),
            2 => x.print.cmp(&y.print),
            3 => x.pass.cmp(&y.pass),
            _ => (x != default_action(a)).cmp(&(y != default_action(b))),
        }
    });
    let row_height = widgets_table::row_height(egui::TextStyle::Body.resolve(ui.style()).size);
    widgets_table::begin(ui);
    TableBuilder::new(ui)
        .id_salt(TABLE)
        .striped(true)
        .column(Column::auto().at_least(110.0))
        .column(Column::auto().at_least(44.0))
        .column(Column::auto().at_least(44.0))
        .column(Column::auto().at_least(44.0))
        .column(Column::remainder().at_least(60.0))
        .vscroll(false)
        .header(row_height + 4.0, |mut header| {
            for (column, title) in ["Signal", "Stop", "Print", "Pass", "Changed"]
                .into_iter()
                .enumerate()
            {
                header.col(|ui| table_sort::header(ui, TABLE, column, title));
            }
        })
        .body(|body| {
            body.rows(row_height, order.len(), |mut row| {
                let number = numbers[order[row.index()]];
                let current = table.action(number);
                let changed = current != default_action(number);
                let mut next = current;
                let mut touched = false;
                row.col(|ui| {
                    let name =
                        RichText::new(format!("{} ({number})", signal_name(number))).monospace();
                    ui.label(if changed {
                        name.color(theme::warn())
                    } else {
                        name
                    });
                });
                for (value, field) in [
                    (&mut next.stop, "stop"),
                    (&mut next.print, "print"),
                    (&mut next.pass, "pass"),
                ] {
                    row.col(|ui| {
                        touched |= ui
                            .add_enabled(enabled, egui::Checkbox::without_text(value))
                            .on_hover_text(field)
                            .changed();
                    });
                }
                row.col(|ui| {
                    if changed {
                        ui.label(RichText::new("changed").color(theme::warn()));
                    }
                });
                if touched {
                    actions.push(PanelAction::Debug(DebugAction::SetSignalPolicy {
                        signal: number,
                        action: next,
                    }));
                }
            });
        });
}

/// The Signals pane: a reset button, the recent signals (folded) and the table.
pub(super) fn pane(ui: &mut egui::Ui, view: &DebugView, actions: &mut Vec<PanelAction>) {
    let gdb = view.controller == Controller::Gdb;
    let enabled = !gdb;
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                enabled && !view.signals.is_default(),
                egui::Button::new("Reset to defaults").small(),
            )
            .on_hover_text("Back to gdb's defaults")
            .clicked()
        {
            actions.push(PanelAction::Debug(DebugAction::SetSignalTable(
                SignalTable::default(),
            )));
        }
        ui.label(RichText::new("handle table").small().color(theme::muted()))
            .on_hover_text(
                "What this panel does when the program gets a signal. A gdb client keeps \
                 gdb's own handle table.",
            );
    });
    if !view.signal_log.is_empty() {
        let skip = view.signal_log.len().saturating_sub(LOG_SHOWN_COUNT);
        egui::CollapsingHeader::new(format!("Recent signals · {}", view.signal_log.len()))
            .id_salt("debugger-signal-log")
            .default_open(false)
            .show(ui, |ui| {
                for note in view.signal_log.iter().skip(skip) {
                    ui.label(RichText::new(note_text(note)).monospace());
                }
            });
    }
    rows(ui, &view.signals, enabled, actions);
}

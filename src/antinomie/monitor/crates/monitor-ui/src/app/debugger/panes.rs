// SPDX-License-Identifier: MIT
//! The panes under the listing: threads, processes, breakpoints, memory,
//! stack, signals and the gdb console. They are folded until the user opens
//! them from the strip, each independently, and the tab remembers which are
//! open. Open panes share the width of the area below the strip.
use super::*;
use crate::widgets::{self, Tone};
use antinomie_monitor_core::debug::view::Controller;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Pane {
    Threads,
    Processes,
    Breakpoints,
    Memory,
    Stack,
    Signals,
    Console,
}

impl Pane {
    pub const ALL: [Self; 7] = [
        Self::Threads,
        Self::Processes,
        Self::Breakpoints,
        Self::Memory,
        Self::Stack,
        Self::Signals,
        Self::Console,
    ];

    /// The name saved with the settings.
    pub fn key(self) -> &'static str {
        match self {
            Self::Threads => "threads",
            Self::Processes => "processes",
            Self::Breakpoints => "breakpoints",
            Self::Memory => "memory",
            Self::Stack => "stack",
            Self::Signals => "signals",
            Self::Console => "console",
        }
    }

    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|pane| pane.key() == key)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Threads => "Threads",
            Self::Processes => "Processes",
            Self::Breakpoints => "Breakpoints",
            Self::Memory => "Memory",
            Self::Stack => "Stack",
            Self::Signals => "Signals",
            Self::Console => "Console",
        }
    }

    fn tip(self) -> &'static str {
        match self {
            Self::Threads => "The threads of the stopped process",
            Self::Processes => "The program and the children of its forks; what to do at a fork",
            Self::Breakpoints => "Software breakpoints of the process",
            Self::Memory => "Read a range of the process's memory",
            Self::Stack => "The words at the stack pointer",
            Self::Signals => "What happens when the program is about to get a signal",
            Self::Console => "Host gdb attached to this session, with GEF or pwndbg",
        }
    }

    /// A share of the width the open panes divide: the console needs room.
    fn weight(self) -> f32 {
        match self {
            Self::Console => 2.5,
            Self::Signals | Self::Breakpoints | Self::Processes => 1.3,
            _ => 1.0,
        }
    }

    /// The width below which the pane's content would not fit.
    fn min_width(self) -> f32 {
        match self {
            Self::Threads => 300.0,
            Self::Processes => 420.0,
            Self::Breakpoints => 340.0,
            Self::Memory | Self::Stack => 260.0,
            Self::Signals => 400.0,
            Self::Console => 480.0,
        }
    }
}

/// The count shown on a pane's tab, when it has one.
fn count(pane: Pane, view: Option<&DebugView>) -> Option<usize> {
    let view = view?;
    match pane {
        Pane::Threads => Some(view.threads.len()),
        Pane::Processes => Some(view.inferiors.len()).filter(|count| *count > 1),
        Pane::Breakpoints => Some(view.breakpoints.len()),
        Pane::Signals => Some(view.signals.changes().count()).filter(|count| *count > 0),
        _ => None,
    }
}

/// The strip: one tab per pane, lit while the pane is open; a click folds or
/// opens it. Returns the pane clicked.
pub(super) fn strip(
    ui: &mut egui::Ui,
    prefs: &DebuggerPrefs,
    view: Option<&DebugView>,
    console_running: bool,
) -> Option<Pane> {
    let mut clicked = None;
    widgets::tab_row(ui, |ui| {
        for pane in Pane::ALL {
            let mut item = widgets::TabItem::new(pane.label()).tooltip(if prefs.pane_open(pane) {
                format!("{} (click to fold)", pane.tip())
            } else {
                pane.tip().to_owned()
            });
            if let Some(count) = count(pane, view) {
                item = item.badge(count.to_string(), Tone::Neutral);
            } else if pane == Pane::Console && console_running {
                item = item.badge("live", Tone::Live);
            }
            if widgets::tab(ui, prefs.pane_open(pane), &item).clicked() {
                clicked = Some(pane);
            }
        }
    });
    clicked
}

/// The open panes in strip order.
pub(super) fn open(prefs: &DebuggerPrefs) -> Vec<Pane> {
    Pane::ALL
        .into_iter()
        .filter(|pane| prefs.pane_open(*pane))
        .collect()
}

/// The chip that says who drives the process, when it is not the tab.
pub(crate) fn driving_chip(view: Option<&DebugView>) -> Option<&'static str> {
    view.filter(|view| view.controller == Controller::Gdb)
        .map(|_| "gdb is driving; panel is read-only")
}

/// The open panes side by side, sharing the width by weight but none
/// narrower than its content needs; when they do not all fit, the row scrolls
/// sideways.
pub(super) fn show(
    ui: &mut egui::Ui,
    panes: &[Pane],
    mut pane_ui: impl FnMut(&mut egui::Ui, Pane),
) {
    use egui_extras::{Size, StripBuilder};
    let gaps = ui.spacing().item_spacing.x * panes.len().saturating_sub(1) as f32;
    let available = ui.available_width();
    let weights: f32 = panes.iter().map(|pane| pane.weight()).sum();
    let widths: Vec<f32> = panes
        .iter()
        .map(|pane| ((available - gaps) * pane.weight() / weights.max(1.0)).max(pane.min_width()))
        .collect();
    let total = widths.iter().sum::<f32>() + gaps;
    let mut row = |ui: &mut egui::Ui| {
        let mut builder = StripBuilder::new(ui);
        for width in &widths {
            builder = builder.size(Size::exact(*width));
        }
        builder.horizontal(|mut strip| {
            for pane in panes {
                strip.cell(|ui| cell(ui, *pane, &mut pane_ui));
            }
        });
    };
    if total > available + 0.5 {
        egui::ScrollArea::horizontal()
            .id_salt("debugger-panes-row")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                let height = ui.available_height();
                ui.allocate_ui(egui::vec2(total, height), row);
            });
    } else {
        row(ui);
    }
}

/// One pane: its title and body.
fn cell(ui: &mut egui::Ui, pane: Pane, pane_ui: &mut impl FnMut(&mut egui::Ui, Pane)) {
    // A margin on the left, so the first glyphs are not cut by the cell's edge.
    egui::Frame::new()
        .inner_margin(egui::Margin {
            left: 4,
            right: 4,
            ..Default::default()
        })
        .show(ui, |ui| {
            ui.push_id(pane.key(), |ui| {
                // The console fits itself to the space and heads itself.
                if pane == Pane::Console {
                    pane_ui(ui, pane);
                    return;
                }
                ui.label(
                    RichText::new(pane.label())
                        .small()
                        .strong()
                        .color(theme::heading()),
                );
                // The rest scroll when they are taller than the area.
                // Hex rows are wide; tables take the width given.
                let scroll = match pane {
                    Pane::Memory | Pane::Stack => egui::ScrollArea::both(),
                    _ => egui::ScrollArea::vertical(),
                };
                scroll
                    .id_salt(("debugger-pane", pane.key()))
                    .auto_shrink([false, false])
                    .show(ui, |ui| pane_ui(ui, pane));
            });
        });
}

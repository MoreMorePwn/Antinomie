// SPDX-License-Identifier: GPL-3.0-only
//! The Threads and Breakpoints panes: sortable tables of the stopped process's
//! threads and its breakpoints.
use super::*;
use crate::{
    table_sort,
    widgets::table::{self, Cell, Mark},
};
use antinomie_monitor_core::debug::{
    signal_policy::signal_name,
    view::{BreakpointKind, DebugThread, ViewCaps, WatchAccess},
};
use egui_extras::{Column, TableBuilder};

/// Height of the panes' table rows.
fn row_height(ui: &egui::Ui) -> f32 {
    table::row_height(egui::TextStyle::Body.resolve(ui.style()).size)
}

/// One thread's state in words: running, stopped, or stopped with the signal
/// it has yet to receive.
pub(crate) fn thread_state(thread: &DebugThread) -> String {
    if !thread.stopped {
        "running".into()
    } else if thread.signal != 0 {
        let number = u8::try_from(thread.signal).unwrap_or(0);
        format!("stopped {}", signal_name(number))
    } else {
        "stopped".into()
    }
}

pub(super) fn threads(
    ui: &mut egui::Ui,
    panel: &DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    let stopped = view.run.stopped_sequence().is_some();
    let editable = view.app_controls() && stopped && !panel.waiting(view);
    if view.threads.is_empty() {
        if view.loading {
            theme::loading_weak(ui, "Reading threads…");
        } else {
            ui.weak("No threads listed");
        }
        return;
    }
    const TABLE: &str = "debugger-threads";
    let order = table_sort::order(ui.ctx(), TABLE, view.threads.len(), |column, a, b| {
        let (a, b) = (&view.threads[a], &view.threads[b]);
        match column {
            0 => a.tid.cmp(&b.tid),
            1 => thread_state(a).cmp(&thread_state(b)),
            _ => a.pc.cmp(&b.pc),
        }
    });
    let row_height = row_height(ui);
    table::begin(ui);
    TableBuilder::new(ui)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .id_salt(TABLE)
        .striped(true)
        .sense(egui::Sense::click())
        .column(Column::auto().at_least(76.0))
        .column(Column::auto().at_least(100.0))
        .column(Column::remainder().at_least(90.0))
        .vscroll(false)
        .header(row_height + 4.0, |mut header| {
            for (column, title) in ["Thread", "State", "PC"].into_iter().enumerate() {
                header.col(|ui| table_sort::header(ui, TABLE, column, title));
            }
        })
        .body(|body| {
            body.rows(row_height, order.len(), |mut row| {
                let thread = &view.threads[order[row.index()]];
                let selected = view.selected_tid == Some(thread.tid);
                row.set_selected(selected);
                row.col(|ui| {
                    table::row_mark(ui, if selected { Mark::Selected } else { Mark::None });
                    table::cell_click(ui, Cell::Mono, &thread.tid.to_string());
                });
                row.col(|ui| {
                    let text = RichText::new(thread_state(thread));
                    table::cell_rich(
                        ui,
                        Cell::Text,
                        if thread.stopped {
                            text
                        } else {
                            text.color(theme::muted())
                        },
                    );
                });
                row.col(|ui| {
                    table::cell_rich(
                        ui,
                        Cell::Mono,
                        RichText::new(format!("{:#x}", thread.pc))
                            .color(theme::value(theme::ValueKind::Pointer)),
                    );
                });
                if row.response().clicked() && editable && !selected {
                    actions.push(PanelAction::Debug(DebugAction::SelectThread {
                        tid: thread.tid,
                    }));
                }
            });
        });
}

/// The kinds of breakpoint the panel can add, with their names and what each
/// needs from the guest's debug engine.
const KINDS: [(&str, BreakpointKind); 5] = [
    ("Software", BreakpointKind::Software),
    ("Hardware", BreakpointKind::Hardware),
    ("Watch write", BreakpointKind::Watch(WatchAccess::Write)),
    ("Watch read", BreakpointKind::Watch(WatchAccess::Read)),
    ("Watch access", BreakpointKind::Watch(WatchAccess::Access)),
];

/// Whether the guest's engine offers `kind`, and why not when it does not.
fn kind_offered(caps: ViewCaps, kind: BreakpointKind) -> Result<(), &'static str> {
    match kind {
        BreakpointKind::Software if !caps.software_breakpoints => {
            Err("This guest has no software breakpoints")
        }
        BreakpointKind::Hardware if caps.hardware_breakpoints == 0 => {
            Err("This guest has no hardware breakpoint registers")
        }
        BreakpointKind::Watch(_) if caps.hardware_watchpoints == 0 => {
            Err("This guest has no watchpoint registers")
        }
        _ => Ok(()),
    }
}

pub(super) fn breakpoints(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    let stopped = view.run.stopped_sequence().is_some();
    let editable = view.app_controls() && stopped && !panel.waiting(view);
    panel.breakpoint_kind = panel.breakpoint_kind.min(KINDS.len() - 1);
    let kind = KINDS[panel.breakpoint_kind].1;
    let offered = kind_offered(view.caps, kind);
    ui.horizontal(|ui| {
        let response = ui.add_enabled(
            editable,
            egui::TextEdit::singleline(&mut panel.breakpoint_input)
                .desired_width((ui.available_width() - 70.0).clamp(60.0, 240.0))
                .hint_text(theme::hint_text("address e.g. 0x401136")),
        );
        let entered =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        let add = ui
            .add_enabled(editable && offered.is_ok(), egui::Button::new("Add"))
            .on_disabled_hover_text(match offered {
                Err(why) => why,
                Ok(()) => "Stop the process to change breakpoints",
            })
            .clicked();
        if (add || entered) && editable && offered.is_ok() {
            match state::parse_address(&panel.breakpoint_input) {
                Ok(addr) => {
                    panel.input_error = None;
                    panel.breakpoint_input.clear();
                    actions.push(PanelAction::Debug(DebugAction::AddBreakpoint {
                        addr,
                        kind,
                    }));
                }
                Err(problem) => panel.input_error = Some(problem),
            }
        }
    });
    ui.horizontal(|ui| {
        ui.weak("Add as");
        ui.add_enabled_ui(editable, |ui| {
            egui::ComboBox::from_id_salt("debugger-breakpoint-kind")
                .selected_text(KINDS[panel.breakpoint_kind].0)
                .show_ui(ui, |ui| {
                    for (index, (label, kind)) in KINDS.iter().enumerate() {
                        let offered = kind_offered(view.caps, *kind);
                        let item = ui
                            .add_enabled_ui(offered.is_ok(), |ui| {
                                ui.selectable_value(&mut panel.breakpoint_kind, index, *label)
                            })
                            .inner;
                        if let Err(why) = offered {
                            item.on_disabled_hover_text(why);
                        }
                    }
                })
                .response
                .on_hover_text(
                    "Software patches the code. Hardware and watchpoints use the CPU's debug \
                     registers (a few slots); a watch covers 8 bytes from the address, and a \
                     read watch also stops on writes, as the registers have no read-only mode.",
                );
        });
    });
    if view.breakpoints.is_empty() {
        ui.weak("No breakpoints");
        return;
    }
    const TABLE: &str = "debugger-breakpoints";
    let here = view
        .registers
        .as_ref()
        .and_then(|registers| registers.get("rip"));
    let order = table_sort::order(ui.ctx(), TABLE, view.breakpoints.len(), |column, a, b| {
        let (a, b) = (&view.breakpoints[a], &view.breakpoints[b]);
        match column {
            0 => a.enabled.cmp(&b.enabled),
            1 => a.addr.cmp(&b.addr),
            2 => a.kind.label().cmp(b.kind.label()),
            _ => (here == Some(a.addr)).cmp(&(here == Some(b.addr))),
        }
    });
    let row_height = row_height(ui);
    table::begin(ui);
    TableBuilder::new(ui)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .id_salt(TABLE)
        .striped(true)
        .column(Column::auto().at_least(40.0))
        .column(Column::auto().at_least(110.0))
        .column(Column::auto().at_least(50.0))
        .column(Column::auto().at_least(50.0))
        .column(Column::remainder().at_least(24.0))
        .vscroll(false)
        .header(row_height + 4.0, |mut header| {
            for (column, title) in ["On", "Address", "Kind", "At PC"].into_iter().enumerate() {
                header.col(|ui| table_sort::header(ui, TABLE, column, title));
            }
            header.col(|ui| table::head(ui, ""));
        })
        .body(|body| {
            body.rows(row_height, order.len(), |mut row| {
                let entry = &view.breakpoints[order[row.index()]];
                row.col(|ui| {
                    let mut enabled = entry.enabled;
                    if ui
                        .add_enabled(editable, egui::Checkbox::without_text(&mut enabled))
                        .on_hover_text("Enable or disable")
                        .changed()
                    {
                        actions.push(PanelAction::Debug(DebugAction::SetBreakpointEnabled {
                            addr: entry.addr,
                            enabled,
                        }));
                    }
                });
                row.col(|ui| {
                    table::cell_rich(
                        ui,
                        Cell::Mono,
                        RichText::new(format!("{:#x}", entry.addr)).color(if entry.enabled {
                            theme::value(theme::ValueKind::Pointer)
                        } else {
                            theme::muted()
                        }),
                    );
                });
                row.col(|ui| {
                    table::cell_rich(
                        ui,
                        Cell::Text,
                        RichText::new(entry.kind.label()).color(theme::muted()),
                    );
                });
                row.col(|ui| {
                    if here == Some(entry.addr) {
                        ui.label(RichText::new("here").color(theme::error()));
                    }
                });
                row.col(|ui| {
                    if icon(
                        ui,
                        egui_phosphor::regular::TRASH,
                        "Remove breakpoint",
                        editable,
                    ) {
                        actions.push(PanelAction::Debug(DebugAction::RemoveBreakpoint {
                            addr: entry.addr,
                        }));
                    }
                });
            });
        });
}

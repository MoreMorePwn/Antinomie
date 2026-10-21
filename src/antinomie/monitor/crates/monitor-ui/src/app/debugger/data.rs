// SPDX-License-Identifier: MIT
//! Registers with decoded flags beside the listing, and the Stack and Memory
//! panes: the bounded stack window and a memory range of the user's choosing,
//! shown with the shared hex rows.
use super::*;
use crate::hex_view::{self, Cell};
use antinomie_monitor_core::debug::{
    view::{decode_rflags, MemoryWindow, WindowKind, MAX_READ_SIZE},
    RegKind,
};

/// Bytes the memory pane asks for.
const MEMORY_READ_SIZE: usize = 256;

/// The registers next to the listing.
pub(super) fn registers_column(ui: &mut egui::Ui, view: &DebugView) {
    egui::ScrollArea::both()
        .id_salt("debugger-registers-scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            theme::section(ui, "Registers");
            registers(ui, view);
        });
}

/// The Stack pane.
pub(super) fn stack_pane(ui: &mut egui::Ui, view: &DebugView) {
    egui::ScrollArea::both()
        .id_salt("debugger-stack-scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            window_rows(ui, view, WindowKind::Stack, Some("rsp"))
        });
}

/// The Memory pane.
pub(super) fn memory_pane(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    memory(ui, panel, view, actions);
}

fn registers(ui: &mut egui::Ui, view: &DebugView) {
    let Some(registers) = view
        .registers
        .as_ref()
        .filter(|registers| view.run.stopped_sequence() == Some(registers.sequence))
    else {
        if view.run.stopped_sequence().is_some() {
            theme::loading_weak(ui, "Reading registers…");
        } else {
            ui.weak("Registers are shown while the process is stopped.");
        }
        return;
    };
    egui::Grid::new("debugger-registers")
        .num_columns(2)
        .spacing([10.0, 2.0])
        .show(ui, |ui| {
            for entry in &registers.entries {
                let name_color = match entry.name {
                    "rip" => theme::error(),
                    "rsp" | "rbp" => theme::warn(),
                    _ => theme::value(theme::ValueKind::Name),
                };
                ui.label(RichText::new(entry.name).monospace().color(name_color));
                let text = match entry.kind {
                    RegKind::Segment => format!("{:#06x}", entry.value),
                    RegKind::Flags => format!("{:#010x}", entry.value),
                    _ => format!("{:#018x}", entry.value),
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(text).monospace().color(theme::value(
                        if entry.kind == RegKind::Flags {
                            theme::ValueKind::Flags
                        } else {
                            theme::ValueKind::Pointer
                        },
                    )));
                    if entry.kind == RegKind::Flags {
                        ui.label(
                            RichText::new(format!("[{}]", decode_rflags(entry.value).join(" ")))
                                .monospace()
                                .color(theme::value(theme::ValueKind::Flags)),
                        );
                    }
                });
                ui.end_row();
            }
        });
}

/// Hex rows of one window. `marker` names the register whose address gets an
/// arrow when it is the row's start.
fn window_rows(ui: &mut egui::Ui, view: &DebugView, kind: WindowKind, marker: Option<&str>) {
    if view.run.stopped_sequence().is_none() {
        ui.weak("Shown while the process is stopped.");
        return;
    }
    let Some(window) = view.window(kind) else {
        theme::loading_weak(ui, "Reading memory…");
        return;
    };
    rows(
        ui,
        window,
        marker.and_then(|name| view.registers.as_ref()?.get(name)),
    );
}

fn rows(ui: &mut egui::Ui, window: &MemoryWindow, arrow: Option<u64>) {
    if let Some(problem) = &window.error {
        crate::activity::warning(ui, format!("{:#x}: {problem}", window.address));
        return;
    }
    // At most a few dozen rows (the stack window and the memory range are both
    // small), so they are laid out directly inside the column's own scroll area.
    for row in 0..window.requested_size.div_ceil(16) {
        let start = window.address + row as u64 * 16;
        let text = hex_view::row_text(start, |at| {
            let offset = (at - window.address) as usize;
            if offset >= window.requested_size {
                Cell::Outside
            } else {
                window
                    .bytes
                    .get(offset)
                    .map_or(Cell::Unavailable, |byte| Cell::Byte(*byte))
            }
        });
        let marker = if arrow == Some(start) { "→" } else { " " };
        hex_view::paint_row(ui, format!("{marker} {text}"));
    }
}

fn memory(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    let editable =
        view.app_controls() && view.run.stopped_sequence().is_some() && !panel.waiting(view);
    ui.horizontal(|ui| {
        let response = ui.add_enabled(
            editable,
            egui::TextEdit::singleline(&mut panel.memory_input)
                .desired_width((ui.available_width() - 70.0).clamp(60.0, 260.0))
                .hint_text(theme::hint_text("address e.g. 0x7ffd0000")),
        );
        let entered =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        let read = ui
            .add_enabled(editable, egui::Button::new("Read"))
            .on_hover_text(format!(
                "Read {MEMORY_READ_SIZE} bytes (at most {MAX_READ_SIZE})"
            ))
            .clicked();
        if (read || entered) && editable {
            match state::parse_address(&panel.memory_input) {
                Ok(addr) => {
                    panel.input_error = None;
                    actions.push(PanelAction::Debug(DebugAction::ReadMemory {
                        addr,
                        size: MEMORY_READ_SIZE,
                    }));
                }
                Err(problem) => panel.input_error = Some(problem),
            }
        }
    });
    if let Some(window) = view.window(WindowKind::Memory) {
        rows(ui, window, None);
    } else if view.memory.is_some() && view.loading {
        theme::loading_weak(ui, "Reading memory…");
    }
}

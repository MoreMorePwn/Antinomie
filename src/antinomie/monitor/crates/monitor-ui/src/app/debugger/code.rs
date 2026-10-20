// SPDX-License-Identifier: MIT
//! The middle column: disassembly around the instruction pointer, decoded by the
//! same iced-x86 formatter as the static listing from a bounded window of the
//! stopped process's memory. Clicking the gutter toggles a breakpoint.
use super::*;
use antinomie_monitor_core::debug::view::{BreakpointKind, WindowKind};

pub(super) fn show(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    theme::section(ui, "Disassembly");
    let editable = view.app_controls() && !panel.waiting(view);
    let stopped = view.run.stopped_sequence().is_some();
    if !stopped {
        ui.weak(if view.app_controls() {
            "Stop the process to read its code."
        } else {
            "Read-only while gdb controls the process."
        });
        return;
    }
    let window = view.window(WindowKind::Code);
    let Some(window) = window else {
        theme::loading_weak(ui, "Reading code…");
        return;
    };
    if let Some(problem) = &window.error {
        crate::activity::warning(ui, format!("Code at {:#x}: {problem}", window.address));
        return;
    }
    let pc = view
        .registers
        .as_ref()
        .and_then(|registers| registers.get("rip"));
    let lines = panel.disassembly(view).to_vec();
    if lines.is_empty() {
        ui.weak("No readable code at the instruction pointer.");
        return;
    }
    ui.weak("Instructions before the current one are a best guess (x86 lengths vary).");
    egui::ScrollArea::both()
        .id_salt(("debugger-code", window.sequence, window.address))
        .show(ui, |ui| {
            for line in &lines {
                let current = pc == Some(line.address);
                let breakpoint = view
                    .breakpoints
                    .iter()
                    .find(|entry| entry.addr == line.address);
                ui.horizontal(|ui| {
                    let gutter = match breakpoint {
                        Some(entry) if entry.enabled => "●",
                        Some(_) => "○",
                        None => "·",
                    };
                    let response = ui
                        .add(
                            egui::Label::new(
                                RichText::new(gutter).monospace().color(theme::error()),
                            )
                            .sense(egui::Sense::click()),
                        )
                        .on_hover_text("Toggle a breakpoint here");
                    if response.clicked() && editable {
                        actions.push(PanelAction::Debug(match breakpoint {
                            Some(_) => DebugAction::RemoveBreakpoint { addr: line.address },
                            None => DebugAction::AddBreakpoint {
                                addr: line.address,
                                kind: BreakpointKind::Software,
                            },
                        }));
                    }
                    let arrow = if current { "▶" } else { " " };
                    ui.label(RichText::new(arrow).monospace().color(theme::error()));
                    ui.label(
                        RichText::new(format!("{:#x}", line.address))
                            .monospace()
                            .color(theme::value(theme::ValueKind::Pointer)),
                    );
                    let shown: Vec<String> = line
                        .bytes
                        .iter()
                        .take(8)
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    ui.label(
                        RichText::new(format!("{:<24}", shown.join(" ")))
                            .monospace()
                            .color(theme::muted()),
                    );
                    let text = RichText::new(&line.text).monospace();
                    ui.label(if current { text.strong() } else { text });
                });
            }
        });
}

// SPDX-License-Identifier: GPL-3.0-only
//! The listing: disassembly around the instruction pointer, decoded by the
//! same iced-x86 formatter as the static listing from a bounded window of the
//! stopped process's memory, and painted with the shared listing's
//! instruction colors. Clicking the gutter toggles a breakpoint. The shared
//! function sidebar is not used: the debug engine reads memory windows, with
//! no symbols, function bounds or load bias to name functions by.
use super::*;
use antinomie_monitor_core::debug::view::{BreakpointKind, WindowKind};

/// Code bytes shown before an instruction's text; the rest is "…".
const BYTES_SHOWN: usize = 6;

pub(super) fn show(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    ui.horizontal(|ui| {
        theme::section(ui, crate::code_listing::View::Disassembly.label()).on_hover_text(
            "Instructions before the current one are a best guess (x86 lengths vary).",
        );
        if let Some(pc) = view
            .registers
            .as_ref()
            .and_then(|registers| registers.get("rip"))
        {
            ui.label(
                RichText::new(format!("rip {pc:#x}"))
                    .monospace()
                    .color(theme::value(theme::ValueKind::Pointer)),
            );
        }
    });
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
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    egui::ScrollArea::both()
        .id_salt(("debugger-code", window.sequence, window.address))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for line in &lines {
                let current = pc == Some(line.address);
                let breakpoint = view
                    .breakpoints
                    .iter()
                    .find(|entry| entry.addr == line.address);
                let background = ui.painter().add(egui::Shape::Noop);
                let row = ui.horizontal(|ui| {
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
                        .take(BYTES_SHOWN)
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    let more = if line.bytes.len() > BYTES_SHOWN {
                        "…"
                    } else {
                        ""
                    };
                    ui.label(
                        RichText::new(format!("{:<18}", format!("{}{more}", shown.join(" "))))
                            .monospace()
                            .color(theme::muted()),
                    );
                    let (mnemonic, operands) = line
                        .text
                        .split_once(char::is_whitespace)
                        .unwrap_or((&line.text, ""));
                    ui.label(crate::code_listing::instruction(
                        mnemonic,
                        operands.trim_start(),
                        &font,
                    ));
                });
                if current {
                    let mut rect = row.response.rect;
                    rect.max.x = rect.max.x.max(ui.max_rect().max.x);
                    ui.painter().set(
                        background,
                        egui::Shape::rect_filled(rect, 2.0, theme::palette().selection),
                    );
                }
            }
        });
}

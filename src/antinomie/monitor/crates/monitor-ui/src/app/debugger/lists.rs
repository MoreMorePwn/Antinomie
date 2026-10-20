// SPDX-License-Identifier: MIT
//! The left column: the threads of the stopped process and the breakpoint list.
use super::*;
use antinomie_monitor_core::debug::signal_policy::signal_name;
use antinomie_monitor_core::debug::view::BreakpointKind;

pub(super) fn show(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    actions: &mut Vec<PanelAction>,
) {
    let stopped = view.run.stopped_sequence().is_some();
    let editable = view.app_controls() && stopped && !panel.waiting(view);
    egui::ScrollArea::vertical()
        .id_salt("debugger-left")
        .show(ui, |ui| {
            processes::section(ui, view, actions);
            ui.add_space(8.0);
            theme::section(ui, "Threads");
            if view.threads.is_empty() {
                if view.loading {
                    theme::loading_weak(ui, "Reading threads…");
                } else {
                    ui.weak("No threads listed");
                }
            }
            for thread in &view.threads {
                let selected = view.selected_tid == Some(thread.tid);
                let text = RichText::new(thread_text(thread, selected)).monospace();
                let text = if thread.stopped {
                    text
                } else {
                    text.color(theme::muted())
                };
                let response = ui.selectable_label(selected, text);
                if response.clicked() && editable && !selected {
                    actions.push(PanelAction::Debug(DebugAction::SelectThread {
                        tid: thread.tid,
                    }));
                }
            }
            ui.add_space(8.0);
            theme::section(ui, "Breakpoints");
            breakpoints(ui, panel, view, editable, actions);
            ui.add_space(8.0);
            signals::section(ui, view, actions);
        });
}

/// One thread row: id, running or stopped (with the signal it has yet to
/// receive) and the instruction pointer.
pub(crate) fn thread_text(
    thread: &antinomie_monitor_core::debug::view::DebugThread,
    selected: bool,
) -> String {
    let state = if !thread.stopped {
        "running".to_string()
    } else if thread.signal != 0 {
        let number = u8::try_from(thread.signal).unwrap_or(0);
        format!("stopped {}", signal_name(number))
    } else {
        "stopped".to_string()
    };
    format!(
        "{}{}  {}  {:#x}",
        if selected { ">" } else { " " },
        thread.tid,
        state,
        thread.pc
    )
}

fn breakpoints(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    view: &DebugView,
    editable: bool,
    actions: &mut Vec<PanelAction>,
) {
    ui.horizontal(|ui| {
        let response = ui.add_enabled(
            editable,
            egui::TextEdit::singleline(&mut panel.breakpoint_input)
                .desired_width((ui.available_width() - 50.0).max(60.0))
                .hint_text(theme::hint_text("address e.g. 0x401136")),
        );
        let entered =
            response.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
        let add = ui
            .add_enabled(editable, egui::Button::new("Add"))
            .on_disabled_hover_text("Stop the process to change breakpoints")
            .clicked();
        if (add || entered) && editable {
            match state::parse_address(&panel.breakpoint_input) {
                Ok(addr) => {
                    panel.input_error = None;
                    panel.breakpoint_input.clear();
                    actions.push(PanelAction::Debug(DebugAction::AddBreakpoint {
                        addr,
                        kind: BreakpointKind::Software,
                    }));
                }
                Err(problem) => panel.input_error = Some(problem),
            }
        }
    });
    if view.breakpoints.is_empty() {
        ui.weak("No breakpoints");
    }
    let here = view
        .registers
        .as_ref()
        .and_then(|registers| registers.get("rip"));
    for entry in &view.breakpoints {
        ui.horizontal(|ui| {
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
            let color = if entry.enabled {
                theme::value(theme::ValueKind::Pointer)
            } else {
                theme::muted()
            };
            ui.label(
                RichText::new(format!("{:#x}", entry.addr))
                    .monospace()
                    .color(color),
            );
            ui.label(RichText::new(entry.kind.label()).color(theme::muted()));
            if here == Some(entry.addr) {
                ui.label(RichText::new("here").color(theme::error()));
            }
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
    }
}

// SPDX-License-Identifier: MIT
//! Attach the debugger to a running guest process and show how to reach it.
//! The engine is in the guest kernel and the RSP server on the host; this
//! window starts and ends the session, shows how to reach it from gdb, and is
//! the minimal in-app debugger: run control, threads, breakpoints, disassembly
//! around the instruction pointer, registers, stack and memory.
use super::*;
use antinomie_monitor_core::{
    debug::view::{DebugAction, DebugView},
    DebugSessionInfo,
};

mod code;
mod data;
mod header;
mod lists;
mod state;

pub(crate) use state::DebuggerPanel;

/// Something the panel asks of the app once the window has been drawn.
pub(super) enum PanelAction {
    Detach { kill: bool },
    Debug(DebugAction),
}

impl MonitorApp {
    /// Why the debugger cannot be attached now, if it cannot.
    pub(super) fn debugger_unavailable(&self) -> Option<&'static str> {
        if !self.running() || self.closing || self.selected.is_none() {
            Some("Start the selected VM to debug a process.")
        } else if self.snapshot.memory_dump.is_some() {
            Some("Wait for the VM RAM dump to finish; the guest is paused.")
        } else if !self
            .snapshot
            .guest_kernel
            .as_ref()
            .is_some_and(|kernel| kernel.revision.is_some_and(|revision| revision >= 17))
        {
            Some("The debugger needs a guest base with revision 17 or newer.")
        } else if self.snapshot.debug.is_some() {
            Some("A debugger is already attached; detach it first.")
        } else {
            None
        }
    }

    pub(super) fn open_debug_picker(&mut self) {
        if self.debugger_unavailable().is_some() {
            return;
        }
        self.process_picker.purpose = captures::ProcessPurpose::Debug;
        self.process_picker.open = true;
        self.process_picker.reset();
        self.send(Command::ListProcesses { after_pid: 0 });
    }

    /// The attached session: the debugger panel and its connection details.
    pub(super) fn debugger_window(&mut self, ctx: &egui::Context) {
        let Some(info) = self.snapshot.debug.clone() else {
            self.debugger.track_session(None);
            return;
        };
        self.debugger.track_session(Some(u64::from(info.tcp_port)));
        let view = self.debug_view();
        if let Some(view) = &view {
            self.debugger.prune(view);
        }
        let mut actions = Vec::new();
        let panel = &mut self.debugger;
        egui::Window::new(format!("Debugger / PID {}", info.target.tgid))
            .id(egui::Id::new("debugger_session"))
            .collapsible(true)
            .resizable(true)
            .default_size([1450.0, 780.0])
            .show(ctx, |ui| {
                show(ui, panel, &info, view.as_deref(), &mut actions);
            });
        for action in actions {
            match action {
                PanelAction::Detach { kill } => self.send(Command::DebugDetach { kill }),
                PanelAction::Debug(action) => {
                    if let Some(view) = &view {
                        self.debug_action(view, action);
                    }
                }
            }
        }
    }
}

/// The whole panel: header, then three columns (threads and breakpoints,
/// disassembly, registers and memory).
fn show(
    ui: &mut egui::Ui,
    panel: &mut DebuggerPanel,
    info: &DebugSessionInfo,
    view: Option<&DebugView>,
    actions: &mut Vec<PanelAction>,
) {
    header::show(ui, panel, info, view, actions);
    if let Some(ended) = &info.ended {
        crate::activity::warning(ui, format!("Session ended: {ended}"));
    }
    let Some(view) = view else {
        theme::loading_weak(ui, "Connecting to the debug engine…");
        return;
    };
    if let Some(notice) = &view.notice {
        crate::activity::warning(ui, notice);
    }
    if let Some(problem) = panel.input_error.clone() {
        crate::activity::warning(ui, problem);
    }
    ui.separator();
    use egui_extras::{Size, StripBuilder};
    StripBuilder::new(ui)
        .size(Size::relative(0.16).at_least(260.0))
        .size(Size::remainder().at_least(380.0))
        .size(Size::relative(0.5).at_least(560.0))
        .horizontal(|mut strip| {
            strip.cell(|ui| lists::show(ui, panel, view, actions));
            strip.cell(|ui| code::show(ui, panel, view, actions));
            strip.cell(|ui| data::show(ui, panel, view, actions));
        });
}

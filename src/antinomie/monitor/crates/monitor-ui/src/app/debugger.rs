// SPDX-License-Identifier: MIT
//! Attach the debugger to a running guest process and show how to reach it.
//! The engine is in the guest kernel and the RSP server on the host; this
//! window only starts and ends the session and offers the connection commands.
use super::*;

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

    /// The attached session: its endpoints, ready to copy, and the detach controls.
    pub(super) fn debugger_window(&mut self, ctx: &egui::Context) {
        let Some(info) = self.snapshot.debug.clone() else {
            return;
        };
        let mut action = None;
        egui::Window::new(format!("Debugger / PID {}", info.target.tgid))
            .id(egui::Id::new("debugger_session"))
            .collapsible(true)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("State").color(theme::muted()));
                    ui.label(&info.target_state);
                    ui.label(RichText::new("Client").color(theme::muted()));
                    ui.label(if info.client_connected {
                        "connected"
                    } else {
                        "waiting"
                    });
                    ui.label(RichText::new("Architecture").color(theme::muted()));
                    ui.label(&info.architecture);
                });
                if let Some(ended) = &info.ended {
                    crate::activity::warning(ui, format!("Session ended: {ended}"));
                }
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        "The process keeps running until a debugger connects, then it stops. \
                         A debugger that disconnects leaves it running. Connections are local \
                         to this computer.",
                    )
                    .wrap(),
                );
                ui.add_space(4.0);
                for (label, command) in [
                    ("gdb (TCP, 127.0.0.1)", &info.gdb_command),
                    ("gdb (Unix socket, needs socat)", &info.gdb_unix_command),
                ] {
                    ui.label(RichText::new(label).color(theme::muted()));
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::Label::new(RichText::new(command).monospace()).selectable(true),
                        );
                        if icon(ui, egui_phosphor::regular::COPY, "Copy command", true) {
                            ui.ctx().copy_text(command.clone());
                        }
                    });
                }
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Detach").clicked() {
                        action = Some(false);
                    }
                    if ui
                        .button("Detach and kill process")
                        .on_hover_text("Ends the process with SIGKILL")
                        .clicked()
                    {
                        action = Some(true);
                    }
                });
            });
        if let Some(kill) = action {
            self.send(Command::DebugDetach { kill });
        }
    }
}

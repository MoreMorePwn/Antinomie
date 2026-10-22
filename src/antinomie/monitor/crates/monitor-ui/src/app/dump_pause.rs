// SPDX-License-Identifier: GPL-3.0-only
//! The VM is paused while QEMU writes the RAM dump: say so, with progress,
//! and keep guest commands from being sent (the backend refuses them).
use super::*;

impl MonitorApp {
    /// "Writing RAM dump 41% - VM paused" while the dump is being written.
    pub(super) fn dump_pause_notice(&self) -> Option<String> {
        self.snapshot
            .memory_dump
            .as_ref()
            .map(|dump| dump.status_text())
    }

    /// Holds back `command` while the guest is paused. Returns true when it
    /// was held back: nothing is sent and no failure is reported.
    pub(super) fn held_for_memory_dump(&mut self, command: &Command) -> bool {
        let Some(notice) = self.dump_pause_notice() else {
            return false;
        };
        if !command.needs_running_guest() {
            return false;
        }
        match command {
            // Sent by the terminal view on its own: the pane size is sent
            // again once the dump is done, because the terminal forgets it.
            Command::TerminalResize { run_id, .. } => {
                if let Some(terminal) = self.terminals.get_mut(run_id) {
                    terminal.terminal.invalidate_resize();
                }
            }
            // Polling of the debugger panels: dropped quietly.
            Command::DebugUi(_) => {}
            _ => self.status = notice,
        }
        true
    }

    /// A banner under the toolbar for as long as the guest is paused.
    pub(super) fn dump_pause_banner(&self, ctx: &egui::Context) {
        let Some(dump) = &self.snapshot.memory_dump else {
            return;
        };
        let fraction = if dump.total == 0 {
            0.0
        } else {
            (dump.completed as f32 / dump.total as f32).clamp(0.0, 1.0)
        };
        let text = dump.status_text();
        egui::TopBottomPanel::top("memory-dump-banner")
            .frame(theme::frame(theme::raised()))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.colored_label(theme::warn(), text);
                    ui.add(
                        egui::ProgressBar::new(fraction)
                            .desired_width(200.0)
                            .animate(true),
                    );
                    ui.weak("Program, terminal and capture actions resume when it is done.");
                });
            });
    }
}

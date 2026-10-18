// SPDX-License-Identifier: MIT
//! Read through the native integration; bind every typing intent to one boot.
use super::*;
use antinomie_monitor_core::clipboard::Text;

pub(super) struct Intent {
    vm_id: String,
    boot_id: String,
    started: Instant,
}

impl Intent {
    pub fn current(&self, snapshot: &Snapshot) -> bool {
        snapshot.state == VmState::Running
            && snapshot.active_vm.as_ref() == Some(&self.vm_id)
            && snapshot.boot_id.as_ref() == Some(&self.boot_id)
            && self.started.elapsed() < Duration::from_secs(180)
    }
}

impl MonitorApp {
    pub(super) fn clipboard_enabled(&self) -> bool {
        self.running()
            && !self.closing
            && self.snapshot.boot_id.is_some()
            && self.snapshot.memory_dump.is_none()
            && self.vm_snapshots.pending.is_none()
            && self.clipboard_request.is_none()
    }

    pub(super) fn request_clipboard(&mut self, ctx: &egui::Context) {
        if !self.clipboard_enabled() || self.confirm.is_some() {
            return;
        }
        if let (Some(vm_id), Some(boot_id)) = (&self.snapshot.active_vm, &self.snapshot.boot_id) {
            self.clipboard_request = Some(Intent {
                vm_id: vm_id.clone(),
                boot_id: boot_id.clone(),
                started: Instant::now(),
            });
            // Use the native host clipboard, including the platform's Wayland support.
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
            ctx.request_repaint_after(Duration::from_secs(5));
        }
    }

    pub(super) fn receive_clipboard(&mut self, ctx: &egui::Context) {
        let Some(intent) = self.clipboard_request.as_ref() else {
            return;
        };
        let paste = ctx.input_mut(|input| {
            let index = input
                .events
                .iter()
                .position(|event| matches!(event, egui::Event::Paste(_)))?;
            match input.events.remove(index) {
                egui::Event::Paste(text) => Some(text),
                _ => None,
            }
        });
        if let Some(paste) = paste {
            let intent = self
                .clipboard_request
                .take()
                .expect("pending clipboard request");
            if self.confirm.is_some() || self.closing {
                self.report_warning(
                    "Clipboard typing cancelled while another confirmation or shutdown is active"
                        .into(),
                );
                return;
            }
            if !intent.current(&self.snapshot) || self.selected.as_ref() != Some(&intent.vm_id) {
                self.report_warning(
                    "Clipboard target changed; request clipboard typing again".into(),
                );
                return;
            }
            match Text::prepare(&paste) {
                Err(error) => self.report_warning(error),
                Ok(text) => {
                    if text.skipped_count > 0 {
                        self.report_warning(format!(
                            "Clipboard: skipped {} unsupported characters (US keyboard layout)",
                            text.skipped_count
                        ));
                    }
                    if text.needs_confirmation() {
                        self.confirm = Some(Confirm::Clipboard { intent, text });
                    } else {
                        self.submit_clipboard(intent, text);
                    }
                }
            }
        } else if intent.started.elapsed() >= Duration::from_secs(5) {
            self.clipboard_request = None;
            self.report_warning(
                "Host clipboard text was unavailable; copy text and try again".into(),
            );
        }
    }

    pub(super) fn submit_clipboard(&mut self, intent: Intent, text: Text) {
        if !intent.current(&self.snapshot)
            || self.selected.as_ref() != Some(&intent.vm_id)
            || self.closing
            || self.snapshot.memory_dump.is_some()
            || self.vm_snapshots.pending.is_some()
        {
            self.report_warning("Clipboard target changed; request clipboard typing again".into());
            return;
        }
        self.send(Command::TypeClipboard {
            vm_id: intent.vm_id,
            boot_id: intent.boot_id,
            text: text.text,
        });
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The VM screen tab's ties to the app: whether there is a screen to show,
//! whether the user closed the tab, and the tab itself.
use super::*;

impl MonitorApp {
    /// The VNC socket of the VM that runs (or starts) with its screen in the
    /// app, if one does.
    pub(crate) fn vm_screen_socket(&self) -> Option<PathBuf> {
        if self.snapshot.active_vm.is_none()
            || matches!(self.snapshot.state, VmState::Stopped | VmState::Failed)
        {
            return None;
        }
        self.snapshot.vm_screen.clone()
    }

    /// The user closed the tab, so a new boot does not open it again.
    pub(crate) fn vm_screen_closed(&self) -> bool {
        self.settings.vm_screen_closed
    }

    pub(crate) fn set_vm_screen_closed(&mut self, closed: bool) {
        self.settings.vm_screen_closed = closed;
    }

    /// View > VM screen (or the palette) asked for the tab; true once.
    pub(crate) fn take_vm_screen_request(&mut self) -> bool {
        std::mem::take(&mut self.vm_screen_request)
    }

    /// Why the VM screen cannot be shown now.
    pub(super) fn vm_screen_unavailable(&self) -> Option<String> {
        if self.vm_screen_socket().is_some() {
            return None;
        }
        Some(if self.snapshot.active_vm.is_some() {
            "This VM shows its screen in a QEMU window; change VM screen in its settings.".into()
        } else {
            "Start a VM first.".into()
        })
    }

    pub(super) fn vm_screen_tab(&mut self, ui: &mut egui::Ui) {
        let shots = self
            .snapshot
            .active_vm
            .as_ref()
            .and_then(|id| self.snapshot.vm_locations.iter().find(|l| &l.vm_id == id))
            .map(|locations| locations.recording_directory.clone());
        let can_type = self.clipboard_enabled();
        if let Some(crate::vm_screen::Request::TypeClipboard) =
            self.vm_screen.show(ui, shots.as_deref(), can_type)
        {
            self.run_action(ui.ctx(), Action::TypeClipboard);
        }
    }
}

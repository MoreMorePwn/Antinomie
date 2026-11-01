// SPDX-License-Identifier: GPL-3.0-only
//! Opening what a note's chip names on the surfaces of a VM: a packet or a
//! capture in Network, a dump in Memory or Disks, a core in Core dumps, and a
//! row of a static analysis report in its section. The chip selects the VM,
//! brings the panel to the front and leaves the target with the panel's view,
//! which selects it as soon as its list holds it.
use super::detail::Data;
use super::*;
use crate::workspace::Panel;
use antinomie_monitor_core::samples::{NoteRef, RefKind};
use std::sync::Arc;

impl MonitorApp {
    /// Open a packet, capture, dump or core reference in the VM's panel.
    pub(in crate::app) fn open_note_surface(&mut self, reference: &NoteRef) {
        let Some(vm_id) = reference.vm_id().map(str::to_owned) else {
            return;
        };
        if !self.snapshot.vms.iter().any(|vm| vm.id == vm_id) {
            self.samples_page.notice = Some((
                format!(
                    "The VM of this {} is no longer listed.",
                    reference.kind.label().to_lowercase()
                ),
                true,
            ));
            return;
        }
        if self.selected.as_ref() != Some(&vm_id) {
            self.selected = Some(vm_id);
            self.clear_history();
            self.select_run(None);
            self.refresh_history();
        }
        let item = reference.item().unwrap_or_default().to_owned();
        let panel = match reference.kind {
            RefKind::Packet => {
                self.network_view.ask_note_target(item, reference.frame());
                Panel::Network
            }
            RefKind::Capture => {
                self.network_view.ask_note_target(item, None);
                Panel::Network
            }
            RefKind::MemoryDump => {
                self.memory_view.ask_note_target(item);
                Panel::Memory
            }
            RefKind::DiskDump => {
                self.disk_view.ask_note_target(item);
                Panel::Disks
            }
            RefKind::ProcessCore => {
                self.core_view.ask_note_target(item);
                Panel::CoreDump
            }
            _ => return,
        };
        self.focus_panel = Some(panel);
    }

    /// Open a static analysis row reference: the report's section, filtered
    /// to the row.
    pub(super) fn open_static_row(&mut self, data: &Arc<Data>, reference: &NoteRef) {
        let Some((report_id, section, key)) = reference.static_row() else {
            return;
        };
        let Some(kind) = crate::analysis::kind_of_name(section) else {
            return;
        };
        let Some(kept) = data
            .report
            .as_ref()
            .filter(|kept| kept.report.id == report_id)
        else {
            self.samples_page.notice = Some((
                "The static analysis report of this row is no longer kept with the sample.".into(),
                true,
            ));
            return;
        };
        if let Some(query) = crate::analysis::key_query(key) {
            self.pending_static_row = Some((report_id.to_owned(), kind, query));
        }
        self.open_sample_report(&kept.report, kept.directory.clone(), kind);
    }
}

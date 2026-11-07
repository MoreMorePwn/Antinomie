// SPDX-License-Identifier: GPL-3.0-only
//! The Details of a changed file: its operations as a table.
use super::*;
use antinomie_monitor_core::kernel_notes::HashKind;
use antinomie_triage::files::retention;

pub(super) trait ChangeView {
    fn show(&self, ui: &mut egui::Ui, clock: Option<antinomie_monitor_core::HostClockAnchor>);
}

impl ChangeView for files::Change {
    fn show(&self, ui: &mut egui::Ui, clock: Option<antinomie_monitor_core::HostClockAnchor>) {
        egui::ScrollArea::vertical().id_salt(("file-change-details", self.key)).max_height(ui.available_height().max(40.0)).show(ui, |ui| {
        ui.separator();
        ui.label(
            RichText::new(format!("Original → final: {}", self.path))
                .strong()
                .color(theme::text()),
        );
        if self.deleted {
            crate::activity::info(ui,
                "File was deleted or unlinked; open descriptors may still refer to its contents.",
            );
        }
        if self.original_size.is_none() {
            ui.weak("Original size/contents were not fully captured.");
        }
        if self.final_size.is_none() {
            ui.weak("Final size/contents were not fully captured.");
        }
        for gap in &self.gap_notes() {
            gap_note(ui, gap);
        }
        if let Some(hash) = &self.hash {
            let moment = match hash.kind {
                HashKind::Delete => "just before it was deleted",
                _ => "when its last writer closed it",
            };
            match (hash.sha256_hex(), hash.skipped()) {
                (Some(hex), None) => {
                    ui.label(RichText::new(format!("SHA-256 (guest, {moment})")).strong().color(theme::text()));
                    ui.monospace(hex);
                    if hash.cached {
                        ui.weak("Served from the guest's digest of the same unchanged file.");
                    }
                }
                (Some(hex), Some(why)) => {
                    ui.label(RichText::new(format!("SHA-256 (guest, {moment})")).strong().color(theme::text()));
                    ui.monospace(hex);
                    crate::activity::warning(ui, format!("Not a hash of the file as it was: {why}."));
                }
                (None, why) => {
                    ui.weak(format!("The guest did not hash the file {moment}: {}.", why.unwrap_or_else(|| "no digest".into())));
                }
            }
        }
            let mut shown = 0;
            for (offset, before, after) in files::bytes::merged(&self.original, &self.final_data) {
                if before == after { continue; }
                if shown == 512 { ui.weak("Byte preview limited to 512 differences; original syscall evidence retains captured data."); break; }
                let before = files::view::byte_label(before, self.original_size, offset);
                let after = files::view::byte_label(after, self.final_size, offset);
                ui.monospace(format!("{offset:08x}  {before} → {after}"))
                    .on_hover_text("?? = unavailable; ∅ = outside a known file extent.");
                shown += 1;
            }
            if shown == 0 { ui.weak("No differing byte pairs available in captured ranges."); }
            ui.label(theme::section_title(ui, "Operation timeline"));
            let rows: Vec<_> = self.operations.iter().map(|op| {
                // A reconnect marker has no call of its own.
                let marker = op.call == 0;
                let mut row = vec![
                    cell(if marker { "—".to_owned() } else { crate::time_format::guest_ns(clock, Some(op.time)) }, tone::text(), true),
                    cell(
                        &op.name,
                        if marker { Tone::Accent } else { tone::text() },
                        false,
                    ),
                    cell(&op.process, tone::text(), true),
                    cell(&op.result, tone::text(), false),
                    cell(if marker { "—".to_owned() } else { format!("call {}", op.call) }, tone::text(), true),
                ];
                row[0].values = vec![("event.id", RowValue::Number(i128::from(op.call))), ("stream.id", RowValue::Number(i128::from(op.key.0))), ("process.cookie", RowValue::Number(i128::from(op.key.1)))]; row
            }).collect();
            egui::ScrollArea::horizontal().id_salt("file-operation-timeline-columns").auto_shrink([false,true]).show(ui,|ui| {
                table_rows(ui, "file-operation-timeline", &["Time", "Operation", "Process", "Result", "Evidence"], &rows);
            });
        });
    }
}


/// One thing said about a file's rebuild. A limit leads to its setting, and a
/// note about a call's bytes to that call's syscall evidence.
pub fn gap_note(ui: &mut egui::Ui, note: &retention::GapNote) {
    ui.horizontal_wrapped(|ui| {
        crate::activity::warning(ui, &note.text);
    });
    ui.horizontal(|ui| {
        if note.limit
            && ui
                .small_button("Open this limit in Settings")
                .on_hover_text("Settings > Analysis limits > Rebuilt file bytes")
                .clicked()
        {
            ui.ctx()
                .data_mut(|data| data.insert_temp(egui::Id::new(OPEN_REBUILD_LIMIT), true));
        }
        if let Some((stream, cookie, call)) = note.evidence {
            if ui
                .small_button("Show the syscall evidence")
                .on_hover_text("Open the call in Trace")
                .clicked()
            {
                ui.ctx().data_mut(|data| {
                    data.insert_temp(egui::Id::new("triage-call-jump"), (stream, cookie, call))
                });
            }
        }
    });
}

/// Set when a note asked for the setting that raises a rebuild limit.
pub const OPEN_REBUILD_LIMIT: &str = "triage-open-rebuild-limit";
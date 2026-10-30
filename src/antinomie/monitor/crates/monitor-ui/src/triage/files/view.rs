// SPDX-License-Identifier: GPL-3.0-only
//! How a changed file is shown: its row in the Changed tab and its Details.
use super::*;

/// Differing runs kept for the File activity window, and octets in each.
const RUNS_KEPT: usize = 32;
const RUN_OCTETS: usize = 32;

impl Change {
    /// What the run saw of the file's bytes, for the File activity window:
    /// the octets that differ between the first and the last it knew, in runs.
    pub fn contents(&self) -> file_activity::Contents {
        let offsets: BTreeSet<u64> = self
            .original
            .keys()
            .chain(self.final_data.keys())
            .copied()
            .filter(|offset| self.byte_diff(*offset))
            .collect();
        let mut runs: Vec<file_activity::ByteRun> = Vec::new();
        for offset in offsets {
            let (before, after) = (
                self.original.get(&offset).copied(),
                self.final_data.get(&offset).copied(),
            );
            let continues = runs.last().is_some_and(|run| {
                run.offset + run.after.len() as u64 == offset && run.after.len() < RUN_OCTETS
            });
            if continues {
                if let Some(run) = runs.last_mut() {
                    run.before.push(before);
                    run.after.push(after);
                }
            } else if runs.len() < RUNS_KEPT {
                runs.push(file_activity::ByteRun {
                    offset,
                    before: vec![before],
                    after: vec![after],
                });
            } else {
                break;
            }
        }
        file_activity::Contents {
            original_size: self.original_size,
            final_size: self.final_size,
            differing: self.diff_count(),
            runs,
            gaps: self.gaps.iter().copied().collect(),
            hash: self.hash.clone(),
        }
    }

    pub fn row(&self, clock: Option<antinomie_monitor_core::HostClockAnchor>) -> Vec<Cell> {
        let mut row = vec![
            cell(
                crate::time_format::guest_ns(clock, Some(self.first_ns)),
                theme::text(),
                true,
            ),
            cell(&self.path, theme::text(), true),
            cell(
                process_identity(self.pid, self.tid, self.process_image.as_deref()),
                theme::text(),
                true,
            ),
            cell(self.lifecycle_text(), theme::text(), false),
            cell(
                self.count_label(),
                if self.gaps.is_empty() {
                    theme::text()
                } else {
                    theme::warn()
                },
                false,
            ),
            file_category::location_cell(&self.locations),
            cell(format!("call {}", self.call), theme::text(), true),
        ];
        row[0].values = vec![
            (
                "process.exe",
                self.process_image
                    .as_ref()
                    .map_or(RowValue::Missing, |image| RowValue::Text(image.clone())),
            ),
            ("file.standard_io", RowValue::Bool(self.standard_io)),
            (
                "file.path",
                if self.path_known {
                    RowValue::Text(self.path.clone())
                } else {
                    RowValue::Missing
                },
            ),
            (
                "file.diff_count",
                RowValue::Number(self.diff_count() as i128),
            ),
            (
                "file.complete",
                RowValue::Bool(
                    self.gaps.is_empty()
                        && self.original_size.is_some()
                        && self.final_size.is_some(),
                ),
            ),
            (
                "file.count",
                RowValue::Number(self.operations.len() as i128),
            ),
            ("event.id", RowValue::Number(i128::from(self.call))),
            ("stream.id", RowValue::Number(i128::from(self.key.0))),
            ("process.cookie", RowValue::Number(i128::from(self.key.1))),
            ("event.time_ns", RowValue::Number(i128::from(self.first_ns))),
            ("process.pid", RowValue::Number(i128::from(self.pid))),
            ("process.tid", RowValue::Number(i128::from(self.tid))),
            (
                "file.operation",
                RowValue::List(self.operations.iter().map(|op| op.name.clone()).collect()),
            ),
            ("file.lifecycle", RowValue::Text(self.lifecycle_text())),
            (
                "file.sha256",
                self.hash
                    .as_ref()
                    .and_then(FileHash::sha256_hex)
                    .map_or(RowValue::Missing, RowValue::Text),
            ),
            (
                "file.inode",
                self.identity.map_or(RowValue::Missing, |key| {
                    RowValue::Text(format!("{}:{}", key.dev, key.ino))
                }),
            ),
            (
                "file.names",
                RowValue::List(
                    std::iter::once(&self.path)
                        .chain(self.names.iter())
                        .cloned()
                        .collect(),
                ),
            ),
            (
                "file.category",
                RowValue::List(
                    self.categories
                        .iter()
                        .map(|name| (*name).to_owned())
                        .collect(),
                ),
            ),
            (
                "file.failed_attempts",
                RowValue::Number(i128::from(self.failed)),
            ),
            (
                "file.result",
                RowValue::Text(if self.changes { "succeeded" } else { "failed" }.into()),
            ),
            (
                "file.access_by",
                self.access.map_or(RowValue::Missing, |access| {
                    RowValue::Text(access.tag().into())
                }),
            ),
            (
                "file.location",
                RowValue::List(self.locations.iter().map(|l| l.tag().to_owned()).collect()),
            ),
        ];
        row
    }
    pub fn show(&self, ui: &mut egui::Ui, clock: Option<antinomie_monitor_core::HostClockAnchor>) {
        egui::ScrollArea::vertical().id_salt(("file-change-details", self.key)).max_height(ui.available_height().max(40.0)).show(ui, |ui| {
        ui.separator();
        ui.label(
            RichText::new(format!("Original → final: {}", self.path))
                .strong()
                .color(theme::text()),
        );
        if self.deleted {
            crate::activity::warning(ui,
                "File was deleted or unlinked; open descriptors may still refer to its contents.",
            );
        }
        if self.original_size.is_none() {
            ui.weak("Original size/contents were not fully captured.");
        }
        if self.final_size.is_none() {
            ui.weak("Final size/contents were not fully captured.");
        }
        for gap in &self.gaps {
            crate::activity::warning(ui, *gap);
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
            let offsets = self.original.keys().chain(self.final_data.keys()).copied().collect::<BTreeSet<_>>();
            let mut shown = 0;
            for offset in &offsets {
                if self.original.get(offset) == self.final_data.get(offset) { continue; }
                if shown == 512 { ui.weak("Byte preview limited to 512 differences; original syscall evidence retains captured data."); break; }
                let before = byte_label(self.original.get(offset), self.original_size, *offset);
                let after = byte_label(self.final_data.get(offset), self.final_size, *offset);
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
                    cell(if marker { "—".to_owned() } else { crate::time_format::guest_ns(clock, Some(op.time)) }, theme::text(), true),
                    cell(&op.name, if marker { theme::warn() } else { theme::text() }, false),
                    cell(&op.process, theme::text(), true),
                    cell(&op.result, theme::text(), false),
                    cell(if marker { "—".to_owned() } else { format!("call {}", op.call) }, theme::text(), true),
                ];
                row[0].values = vec![("event.id", RowValue::Number(i128::from(op.call))), ("stream.id", RowValue::Number(i128::from(op.key.0))), ("process.cookie", RowValue::Number(i128::from(op.key.1)))]; row
            }).collect();
            egui::ScrollArea::horizontal().id_salt("file-operation-timeline-columns").auto_shrink([false,true]).show(ui,|ui| {
                table_rows(ui, "file-operation-timeline", &["Time", "Operation", "Process (PID / TID)", "Result", "Evidence"], &rows);
            });
        });
    }
}

fn byte_label(byte: Option<&u8>, size: Option<u64>, offset: u64) -> String {
    byte.map(|b| format!("{b:02x}")).unwrap_or_else(|| {
        if size.is_some_and(|size| offset >= size) {
            "∅"
        } else {
            "??"
        }
        .into()
    })
}

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
        let mut runs: Vec<file_activity::ByteRun> = Vec::new();
        let differing = bytes::merged(&self.original, &self.final_data)
            .filter(|(offset, before, after)| self.byte_diff(*offset, *before, *after));
        for (offset, before, after) in differing {
            let (before, after) = (before.copied(), after.copied());
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
            gaps: self.gap_notes(),
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
                process_cells::task_label(self.pid, self.tid, self.process_image.as_deref()),
                theme::text(),
                true,
            ),
            cell(self.lifecycle_text(), theme::text(), false),
            cell(
                self.count_label(),
                if !self.has_gaps() {
                    theme::text()
                } else {
                    theme::warn()
                },
                false,
            ),
            file_category::location_cell(&self.locations),
            cell(format!("call {}", self.call), theme::text(), true),
            cell(
                file_type::of(&self.head(), &self.path),
                theme::text(),
                false,
            ),
            cell(
                self.hash
                    .as_ref()
                    .and_then(FileHash::sha256_hex)
                    .unwrap_or_default(),
                theme::text(),
                true,
            ),
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
                    !self.has_gaps() && self.original_size.is_some() && self.final_size.is_some(),
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
            for (offset, before, after) in bytes::merged(&self.original, &self.final_data) {
                if before == after { continue; }
                if shown == 512 { ui.weak("Byte preview limited to 512 differences; original syscall evidence retains captured data."); break; }
                let before = byte_label(before, self.original_size, offset);
                let after = byte_label(after, self.final_size, offset);
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
                    cell(
                        &op.name,
                        if marker { theme::neutral_accent() } else { theme::text() },
                        false,
                    ),
                    cell(&op.process, theme::text(), true),
                    cell(&op.result, theme::text(), false),
                    cell(if marker { "—".to_owned() } else { format!("call {}", op.call) }, theme::text(), true),
                ];
                row[0].values = vec![("event.id", RowValue::Number(i128::from(op.call))), ("stream.id", RowValue::Number(i128::from(op.key.0))), ("process.cookie", RowValue::Number(i128::from(op.key.1)))]; row
            }).collect();
            egui::ScrollArea::horizontal().id_salt("file-operation-timeline-columns").auto_shrink([false,true]).show(ui,|ui| {
                table_rows(ui, "file-operation-timeline", &["Time", "Operation", "Process", "Result", "Evidence"], &rows);
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

/// One thing said about a file's rebuild. A limit leads to its setting, and a
/// note about a call's bytes to that call's syscall evidence.
pub(in crate::triage) fn gap_note(ui: &mut egui::Ui, note: &retention::GapNote) {
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
pub(in crate::triage) const OPEN_REBUILD_LIMIT: &str = "triage-open-rebuild-limit";

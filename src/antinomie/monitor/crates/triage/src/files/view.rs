// SPDX-License-Identifier: GPL-3.0-only
//! How a changed file is shown: its row in the Changed tab and its Details.
use super::*;

/// Differing runs kept for the File activity window, and octets in each.
pub const RUNS_KEPT: usize = 32;
pub const RUN_OCTETS: usize = 32;

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
                tone::text(),
                true,
            ),
            cell(&self.path, tone::text(), true),
            cell(
                process_cells::task_label(self.pid, self.tid, self.process_image.as_deref()),
                tone::text(),
                true,
            ),
            cell(self.lifecycle_text(), tone::text(), false),
            cell(
                self.count_label(),
                if !self.has_gaps() {
                    tone::text()
                } else {
                    tone::warn()
                },
                false,
            ),
            file_category::location_cell(&self.locations),
            cell(format!("call {}", self.call), tone::text(), true),
            cell(file_type::of(&self.head(), &self.path), tone::text(), false),
            cell(
                self.hash
                    .as_ref()
                    .and_then(FileHash::sha256_hex)
                    .unwrap_or_default(),
                tone::text(),
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
}

pub fn byte_label(byte: Option<&u8>, size: Option<u64>, offset: u64) -> String {
    byte.map(|b| format!("{b:02x}")).unwrap_or_else(|| {
        if size.is_some_and(|size| offset >= size) {
            "∅"
        } else {
            "??"
        }
        .into()
    })
}

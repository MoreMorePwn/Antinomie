// SPDX-License-Identifier: MIT
//! Bounded, evidence-based file reads and original-to-final change reconstruction.
//! Unknown bytes are never zero-filled. Paths are observed names, not inode identities.
use super::file_category::{self, Access, Category, Hit};
use super::file_content::{capture as captured_data, CapturedPayload};
use super::file_location::{self, Location};
use super::*;
use std::collections::{BTreeMap, BTreeSet};

const READ_NAMES: &[&str] = &["read", "pread64", "readv", "preadv", "preadv2"];
const TRACKED_FILES: usize = 8192;
const TRACKED_OCTETS: usize = 128 * 1024;
const TOTAL_OCTETS: usize = 4 * 1024 * 1024;
const TIMELINE_ROWS: usize = 1024;
const TOTAL_OPERATIONS: usize = 32768;

#[derive(Clone)]
pub(super) struct Operation {
    time: u64,
    call: u64,
    key: trace::InvocationKey,
    name: String,
    process: String,
    result: String,
}

#[derive(Clone, Default)]
pub(super) struct Change {
    pub path: String,
    path_known: bool,
    standard_io: bool,
    process_image: Option<String>,
    pub call: u64,
    key: trace::InvocationKey,
    known_diff_count: Option<usize>,
    first_ns: u64,
    pid: u32,
    tid: u32,
    original: BTreeMap<u64, u8>,
    final_data: BTreeMap<u64, u8>,
    original_size: Option<u64>,
    final_size: Option<u64>,
    modified: bool,
    changes: bool,
    deleted: bool,
    gaps: BTreeSet<&'static str>,
    operations: Vec<Operation>,
    /// What happened to the file, in order; a repeat is counted, not listed again.
    lifecycle: Vec<(String, u32)>,
    lifecycle_cut: bool,
    categories: BTreeSet<&'static str>,
    /// Change attempts the kernel refused. They are not changes.
    failed: u32,
    /// Last mode a successful chmod set, to tell a new `+x` from a repeat.
    mode: Option<u64>,
    locations: Vec<Location>,
    access: Option<Access>,
}

/// Distinct lifecycle steps kept per file.
const LIFECYCLE_STEPS: usize = 64;

impl Change {
    fn diff_count(&self) -> usize {
        if let Some(count) = self.known_diff_count {
            return count;
        }
        self.original
            .keys()
            .chain(self.final_data.keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|offset| self.byte_diff(*offset))
            .count()
    }
    fn byte_diff(&self, offset: u64) -> bool {
        let before = self.original.get(&offset);
        let after = self.final_data.get(&offset);
        match (before, after) {
            (Some(a), Some(b)) => a != b,
            (None, Some(_)) => self.original_size.is_some_and(|size| offset >= size),
            (Some(_), None) => self.final_size.is_some_and(|size| offset >= size),
            _ => false,
        }
    }
    /// Whether the file has a change the kernel accepted, or one with no exit.
    pub fn real(&self) -> bool {
        self.changes
    }
    fn step(&mut self, label: String) {
        if let Some((last, count)) = self.lifecycle.last_mut() {
            if *last == label {
                *count += 1;
                return;
            }
        }
        if self.lifecycle.len() < LIFECYCLE_STEPS {
            self.lifecycle.push((label, 1));
        } else {
            self.lifecycle_cut = true;
        }
    }
    /// "created → written 3× → chmod +x → executed → deleted"
    pub fn lifecycle_text(&self) -> String {
        let mut text = self
            .lifecycle
            .iter()
            .map(|(label, count)| {
                if *count > 1 {
                    format!("{label} {count}×")
                } else {
                    label.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(" → ");
        if self.lifecycle_cut {
            text.push_str(" → …");
        }
        if text.is_empty() {
            text = if self.changes {
                "changed".into()
            } else {
                "no change".into()
            };
        }
        if self.failed > 0 {
            text.push_str(&format!(
                " · {} failed attempt{} not counted",
                self.failed,
                if self.failed == 1 { "" } else { "s" }
            ));
        }
        text
    }
    fn count_label(&self) -> String {
        let count = self.diff_count();
        if self.original_size.is_some() && self.final_size.is_some() && self.gaps.is_empty() {
            count.to_string()
        } else {
            format!("{count} known; gaps")
        }
    }
    pub fn evidence_key(&self) -> String {
        evidence_key(&self.row(None))
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
            let offsets = self.original.keys().chain(self.final_data.keys()).copied().collect::<BTreeSet<_>>();
            let mut shown = 0;
            for offset in &offsets {
                if self.original.get(offset) == self.final_data.get(offset) { continue; }
                if shown == 512 { ui.weak("Byte preview limited to 512 differences; original syscall evidence retains captured data."); break; }
                let before = byte_label(self.original.get(offset), self.original_size, *offset);
                let after = byte_label(self.final_data.get(offset), self.final_size, *offset);
                ui.monospace(format!("{offset:08x}  {before} → {after}"));
                shown += 1;
            }
            if shown == 0 { ui.weak("No differing byte pairs available in captured ranges."); }
            ui.weak("?? = unavailable; ∅ = outside a known file extent.");
            ui.label(RichText::new("Operation timeline").strong().color(theme::heading()));
            let rows: Vec<_> = self.operations.iter().map(|op| {
                let mut row = vec![
                    cell(crate::time_format::guest_ns(clock, Some(op.time)), theme::text(), true),
                    cell(&op.name, theme::text(), false),
                    cell(&op.process, theme::text(), true),
                    cell(&op.result, theme::text(), false),
                    cell(format!("call {}", op.call), theme::text(), true),
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

#[derive(Default)]
pub(super) struct FileIndex {
    changes: BTreeMap<String, Change>,
    /// Descriptor owner, fd -> shared open-file description; dup shares offsets.
    descriptors: BTreeMap<(u64, u32, u64), u64>,
    descriptions: BTreeMap<u64, (Option<u64>, bool)>,
    next_description: u64,
    retained_octets: usize,
    operation_count: usize,
    pub omitted_files: u64,
}

impl FileIndex {
    #[cfg(test)]
    pub fn observe(
        &mut self,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
        directory: Option<&Path>,
    ) -> Option<Vec<Cell>> {
        let hits = file_category::classify(files, call, event);
        self.observe_with(files, call, event, directory, &hits)
    }

    /// `hits` is the call's classification, made before the call was tracked.
    pub fn observe_with(
        &mut self,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
        directory: Option<&Path>,
        hits: &[Hit],
    ) -> Option<Vec<Cell>> {
        let name = event.syscall_name.as_str();
        let args = call_args(call);
        let ret = call.exit.as_ref().and_then(|event| event.result);
        let success = ret.is_some_and(|ret| ret >= 0);
        let owner = table_owner(files, call.task_cookie, event.tid);
        let fd = fd_argument(call, event);
        let descriptor = fd.map(|fd| (owner.0, owner.1, fd));
        if let Some(key) = descriptor {
            if !files.opened.contains_key(&key) {
                self.descriptors.remove(&key);
            }
        }
        if OPEN_NAMES.contains(&name)
            && success
            && self.descriptions.len() < 65536
            && self.descriptors.len() < 65536
        {
            let id = self.next_description;
            self.next_description = self.next_description.saturating_add(1);
            self.descriptions.insert(
                id,
                (
                    Some(0),
                    open_flags(call, event).is_some_and(|flags| flags & 0x400 != 0),
                ),
            );
            self.descriptors
                .insert((owner.0, owner.1, ret.unwrap_or(0) as u64), id);
        }
        if success && matches!(name, "dup" | "dup2" | "dup3" | "fcntl") {
            let duplicate = name != "fcntl" || args.is_some_and(|args| matches!(args[1], 0 | 1030));
            if duplicate {
                if let Some(source) = args
                    .and_then(|args| self.descriptors.get(&(owner.0, owner.1, args[0])))
                    .copied()
                {
                    if self.descriptors.len() < 65536 {
                        self.descriptors
                            .insert((owner.0, owner.1, ret.unwrap_or(0) as u64), source);
                    }
                }
            }
        }
        if success && matches!(event.syscall_nr, CLONE | CLONE3 | FORK | VFORK) {
            if let Some(child) = ret
                .and_then(|ret| u32::try_from(ret).ok())
                .filter(|pid| *pid != 0)
            {
                let inherited: Vec<_> = files
                    .opened
                    .keys()
                    .filter(|(_, tid, _)| *tid == child)
                    .filter_map(|key| {
                        self.descriptors
                            .get(&(owner.0, owner.1, key.2))
                            .map(|id| (*key, *id))
                    })
                    .collect();
                for (key, description) in inherited
                    .into_iter()
                    .take(65536usize.saturating_sub(self.descriptors.len()))
                {
                    self.descriptors.insert(key, description);
                }
            }
        }
        let description = descriptor
            .and_then(|key| self.descriptors.get(&key))
            .copied();
        if name == "lseek" && (success || ret.is_none()) {
            if let Some((offset, _)) = description.and_then(|id| self.descriptions.get_mut(&id)) {
                *offset = ret.and_then(|ret| u64::try_from(ret).ok());
            }
        }
        if name == "fcntl" && success && args.is_some_and(|args| args[1] == 4) {
            if let Some((_, append)) = description.and_then(|id| self.descriptions.get_mut(&id)) {
                *append = args.is_some_and(|args| args[2] & 0x400 != 0);
            }
        }
        if name == "close" && success {
            if let Some(key) = descriptor {
                self.descriptors.remove(&key);
            }
        }
        let reading = READ_NAMES.contains(&name);
        let writing = matches!(
            name,
            "write" | "pwrite64" | "writev" | "pwritev" | "pwritev2"
        );
        let failed = file_category::outcome(call).failed();
        let created = hits.iter().any(|hit| hit.category == Category::Created);
        let changed = change_operation(call, event) || created;
        // An exec or an executable mapping is part of a file's story, but
        // does not make a file worth listing by itself.
        let lifecycle_only = !reading
            && !changed
            && !failed
            && hits
                .iter()
                .any(|hit| matches!(hit.category, Category::Executed | Category::Mapped));
        if !reading && !changed && !lifecycle_only {
            return None;
        }
        let observed = displayed_path(call, event, files);
        let path_known = observed != "—";
        // The map key stays unique per task and descriptor. The visible label does not.
        let group = if path_known {
            observed.clone()
        } else {
            format!(
                "\u{0}{}:{}",
                call.task_cookie,
                fd.map(|fd| fd.to_string()).unwrap_or_else(|| "?".into())
            )
        };
        let path = if path_known {
            observed
        } else {
            unavailable_descriptor(fd)
        };
        let mut explicit = matches!(
            name,
            "pread64" | "pwrite64" | "preadv" | "pwritev" | "preadv2" | "pwritev2"
        );
        // The pinned native x86-64 ABI uses the full 64-bit pos_l (arg3).
        // pos_h contributes only on a 32-bit ABI, which this collector does not decode.
        let uses_position =
            matches!(name, "preadv2" | "pwritev2") && args.is_some_and(|args| args[3] == u64::MAX);
        if uses_position {
            explicit = false;
        }
        let mut offset = if explicit {
            args.and_then(|args| (args[3] <= i64::MAX as u64).then_some(args[3]))
        } else {
            description
                .and_then(|id| self.descriptions.get(&id))
                .and_then(|(offset, _)| *offset)
        };
        let append = description
            .and_then(|id| self.descriptions.get(&id))
            .is_some_and(|(_, append)| *append)
            || (name == "pwritev2" && args.is_some_and(|args| args[5] & 0x10 != 0));
        if writing && append {
            offset = None;
            if let Some((position, _)) = description.and_then(|id| self.descriptions.get_mut(&id)) {
                *position = None;
            }
        }
        let size = ret.and_then(|ret| u64::try_from(ret).ok()).unwrap_or(0);
        if (reading || writing)
            && !explicit
            && (ret.is_none() || (description.is_none() && size > 0))
        {
            // Untracked inherited descriptors may share known open-file offsets.
            for (position, _) in self.descriptions.values_mut() {
                *position = None;
            }
            offset = None;
        }
        let bytes = if success && (reading || writing) {
            captured_data(call, reading, directory, size)
        } else {
            CapturedPayload::default()
        };
        // One Read files row; `content` is None when the kernel moved the
        // bytes itself and none were captured.
        let read_cells = |path: &str,
                          path_known: bool,
                          fd: Option<u64>,
                          content: Option<&CapturedPayload>| {
            let read_locations = if path_known {
                file_location::classify(path, &file_category::own_images(files))
            } else {
                Vec::new()
            };
            let read_access = if path_known {
                Access::ByDescriptor
            } else {
                Access::Inherited
            };
            let mut row = vec![
                cell(event.timestamp_ns.to_string(), theme::text(), true),
                cell(path, theme::text(), true),
                cell(
                    process_identity(event.pid, event.tid, process_image(files, event)),
                    theme::text(),
                    true,
                ),
                cell(
                    match (success, content) {
                        (true, Some(bytes)) => format!(
                            "{size} B: {}{}",
                            bytes.preview(),
                            if bytes.len() as u64 != size {
                                " … [capture gap]"
                            } else {
                                ""
                            }
                        ),
                        (true, None) => format!("{size} B: kernel transfer; bytes not captured"),
                        (false, _) => "Unavailable".into(),
                    },
                    theme::text(),
                    true,
                ),
                cell(result_label(ret), theme::text(), false),
                file_category::location_cell(&read_locations),
                cell(read_access.label(), theme::text(), false),
                cell(format!("call {}", call.call_id), theme::text(), true),
            ];
            row[0].values = vec![
                (
                    "process.exe",
                    process_image(files, event)
                        .map_or(RowValue::Missing, |image| RowValue::Text(image.into())),
                ),
                (
                    "file.fd",
                    fd.map_or(RowValue::Missing, |fd| RowValue::Number(i128::from(fd))),
                ),
                (
                    "file.path",
                    if path_known {
                        RowValue::Text(path.to_owned())
                    } else {
                        RowValue::Missing
                    },
                ),
                ("event.id", RowValue::Number(i128::from(call.call_id))),
                ("stream.id", RowValue::Number(i128::from(call.stream_id))),
                (
                    "process.cookie",
                    RowValue::Number(i128::from(call.task_cookie)),
                ),
                (
                    "event.time_ns",
                    RowValue::Number(i128::from(event.timestamp_ns)),
                ),
                ("process.pid", RowValue::Number(i128::from(event.pid))),
                ("process.tid", RowValue::Number(i128::from(event.tid))),
                ("file.operation", RowValue::Text(name.into())),
                (
                    "file.success",
                    ret.map_or(RowValue::Missing, |ret| RowValue::Bool(ret >= 0)),
                ),
                (
                    "file.read_size",
                    if success {
                        RowValue::Number(i128::from(size))
                    } else {
                        RowValue::Missing
                    },
                ),
                (
                    "file.content",
                    match content {
                        Some(bytes) if success && (bytes.len() > 0 || size == 0) => {
                            RowValue::Text(bytes.preview())
                        }
                        _ => RowValue::Missing,
                    },
                ),
                (
                    "syscall.ret",
                    ret.map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
                ),
                (
                    "file.category",
                    RowValue::List(vec![Category::Read.label().to_owned()]),
                ),
            ];
            row[0].values.extend(file_category::cross_values(
                file_category::outcome(call),
                read_access,
                &read_locations,
            ));
            row
        };
        let read_row = if reading {
            Some(read_cells(&path, path_known, fd, Some(&bytes)))
        } else {
            // The source of a kernel-side copy was read too.
            transfer_source(name, args).map(|source| {
                let owner = table_owner(files, call.task_cookie, event.tid);
                match files.opened.get(&(owner.0, owner.1, source)) {
                    Some(path) => read_cells(path, true, Some(source), None),
                    None => read_cells(
                        &unavailable_descriptor(Some(source)),
                        false,
                        Some(source),
                        None,
                    ),
                }
            })
        };
        if lifecycle_only && !self.changes.contains_key(&group) {
            return read_row;
        }
        if !self.changes.contains_key(&group) && self.changes.len() >= TRACKED_FILES {
            self.omitted_files += 1;
            return read_row;
        }
        let change = self.changes.entry(group).or_insert_with(|| Change {
            path: path.clone(),
            path_known,
            standard_io: true,
            process_image: process_image(files, event).map(str::to_owned),
            call: call.call_id,
            key: trace::key(call),
            first_ns: event.timestamp_ns,
            pid: event.pid,
            tid: event.tid,
            locations: file_category::locations(files, call, event),
            access: Some(file_category::access(files, call, event)),
            ..Change::default()
        });
        // Hide a group only when every observed operation uses fd 0/1/2.
        // A metadata/namespace operation or another descriptor keeps it visible.
        change.standard_io &= file_fd(call, event)
            .parse::<u64>()
            .ok()
            .and_then(crate::values::standard_fd_name)
            .is_some();
        if !path_known {
            change.gaps.insert(
                "File path unavailable; these operations cannot be assigned to a named file.",
            );
        }
        if change.operations.len() < TIMELINE_ROWS && self.operation_count < TOTAL_OPERATIONS {
            change.operations.push(Operation {
                time: event.timestamp_ns,
                call: call.call_id,
                key: trace::key(call),
                name: name.into(),
                process: process_identity(event.pid, event.tid, process_image(files, event)),
                result: result_label(ret),
            });
            self.operation_count += 1;
        } else {
            change.gaps.insert("Operation timeline retention limit reached; use syscall evidence for remaining operations.");
        }
        if changed && !failed && !change.changes {
            change.call = call.call_id;
            change.key = trace::key(call);
            change.first_ns = event.timestamp_ns;
            change.pid = event.pid;
            change.tid = event.tid;
        }
        change.changes |= changed && !failed;
        if changed && failed {
            change.failed = change.failed.saturating_add(1);
        } else if changed && !success {
            change
                .gaps
                .insert("A change attempt has no recorded exit; see the operation timeline.");
        }
        if !failed {
            let created = hits.iter().any(|hit| hit.category == Category::Created);
            for hit in hits {
                if hit.category == Category::Truncated && created {
                    continue;
                }
                if let Some(label) =
                    file_category::step_label(files, call, event, *hit, &mut change.mode)
                {
                    change.categories.insert(hit.category.label());
                    change.step(label);
                }
            }
        }
        if writing && ret.is_none() {
            change.modified = true;
            change.final_data.clear();
            change
                .gaps
                .insert("Write exit unavailable; final bytes and descriptor position are unknown.");
        }
        if success && (reading || writing) {
            if let Some(offset) = offset {
                if writing {
                    change
                        .final_data
                        .retain(|at, _| *at < offset || *at >= offset.saturating_add(size));
                    change.modified = true;
                    change.final_size = change.final_size.and_then(|size_before| {
                        offset.checked_add(size).map(|end| size_before.max(end))
                    });
                }
                let was_modified = change.modified;
                for (relative, byte) in bytes.iter() {
                    let Some(at) = offset.checked_add(relative) else {
                        break;
                    };
                    if change.final_data.len() >= TRACKED_OCTETS
                        || self.retained_octets >= TOTAL_OCTETS
                    {
                        change.gaps.insert("Byte reconstruction retention limit reached; more captured data may exist in syscall evidence.");
                        break;
                    }
                    if !was_modified && !change.original.contains_key(&at) {
                        change.original.insert(at, byte);
                        self.retained_octets += 1;
                    }
                    if change.final_data.insert(at, byte).is_none() {
                        self.retained_octets += 1;
                    }
                }
            } else if size > 0 {
                change.gaps.insert("File offset unavailable (inherited/shared descriptor, append or missing seek); transferred bytes cannot be placed safely.");
                if writing {
                    change.final_data.clear();
                    change.modified = true;
                }
            }
            if bytes.len() as u64 != size {
                change.gaps.insert("Transferred content contains capture gaps or exceeds the bounded byte preview.");
            }
            if !explicit {
                if let Some((position, _)) =
                    description.and_then(|id| self.descriptions.get_mut(&id))
                {
                    *position = position.and_then(|offset| offset.checked_add(size));
                }
            }
            if reading && size == 0 {
                // EOF proves an upper bound, not that an arbitrary seek position equals size.
                if offset == Some(change.final_data.len() as u64) {
                    change.final_size = offset;
                    if !change.modified {
                        change.original_size = offset;
                    }
                }
            }
        } else if success && changed {
            match name {
                "truncate" | "ftruncate" => {
                    let size = args.map(|args| args[1]);
                    if let Some(size) = size {
                        change.final_data.retain(|offset, _| *offset < size);
                        change.final_size = Some(size);
                    }
                    change.modified = true;
                    change.gaps.insert("Truncate observed; uncaptured original bytes and implicit zero extension are unavailable.");
                }
                "unlink" | "unlinkat" | "rmdir" => {
                    change.deleted = true;
                    change.gaps.insert(
                        "Unlink observed; link count and final inode lifetime are unavailable.",
                    );
                }
                "msync" => {
                    change.modified = true;
                    change.final_data.clear();
                    change.gaps.insert("Shared writable mapping observed; actual mapped writes and final bytes are unavailable.");
                }
                "rename" | "renameat" | "renameat2" | "link" | "linkat" | "symlink"
                | "symlinkat" => {
                    change.gaps.insert("Namespace change observed; overwritten destination, inode identity and aliases are not fully captured.");
                }
                "ioctl" => {
                    change.modified = true;
                    change.final_data.clear();
                    change
                        .gaps
                        .insert("Reflink clone observed; the cloned bytes are unavailable.");
                }
                "sendfile" | "copy_file_range" | "splice" => {
                    change.modified = true;
                    change.final_data.clear();
                    change.gaps.insert(
                        "Kernel-mediated transfer observed; payload and/or offset are unavailable.",
                    );
                }
                "fallocate" => {
                    change.modified = true;
                    change.final_data.clear();
                    change.gaps.insert("Allocation, hole punching or extent change observed; final bytes are unavailable.");
                }
                _ => {}
            }
        }
        if OPEN_NAMES.contains(&name)
            && success
            && open_flags(call, event).is_some_and(|flags| flags & 0x200 != 0)
        {
            change.final_data.clear();
            change.final_size = Some(0);
            change.modified = true;
        }
        if OPEN_NAMES.contains(&name)
            && success
            && open_flags(call, event).is_some_and(|flags| flags & 0xc0 == 0xc0)
        {
            // O_CREAT|O_EXCL success establishes a new empty regular-file namespace entry.
            change.original_size = Some(0);
            change.final_size = Some(0);
        }
        read_row
    }
    pub fn finish(self) -> Vec<Change> {
        self.changes
            .into_values()
            .filter(|change| change.changes || change.failed > 0)
            .map(|mut change| {
                change.known_diff_count = Some(change.diff_count());
                change
            })
            .collect()
    }
}

/// The descriptor a sendfile, copy_file_range or splice reads from.
pub(super) fn transfer_source(name: &str, args: Option<[u64; 6]>) -> Option<u64> {
    let args = args?;
    match name {
        "sendfile" => Some(args[1]),
        "copy_file_range" | "splice" => Some(args[0]),
        // FICLONERANGE names its source inside a structure that is not decoded.
        "ioctl" if args[1] == FICLONE => Some(args[2]),
        _ => None,
    }
}

fn unavailable_descriptor(fd: Option<u64>) -> String {
    fd.and_then(crate::values::standard_fd_name)
        .map(str::to_owned)
        .or_else(|| fd.map(|fd| format!("fd {fd}")))
        .unwrap_or_else(|| "fd unavailable".into())
}

pub(super) fn result_label(ret: Option<i64>) -> String {
    match ret {
        Some(ret) if ret >= 0 => format!("Success ({ret})"),
        Some(ret) => format!("Failed ({ret})"),
        None => "Exit unavailable".into(),
    }
}

pub(super) fn change_operation(call: &InvocationSummary, event: &EventSummary) -> bool {
    let name = event.syscall_name.as_str();
    // mmap records a mapping, not a write. msync is the observed write-back.
    CHANGE_NAMES.contains(&name)
        || (OPEN_NAMES.contains(&name)
            && open_flags(call, event).is_some_and(|flags| flags & 0x200 != 0))
        || reflink(name, call_args(call))
}

/// ioctl FICLONE and FICLONERANGE: the destination descriptor's contents are
/// replaced by a shared extent of the source, without a write.
pub(super) const FICLONE: u64 = 0x4004_9409;
pub(super) const FICLONERANGE: u64 = 0x4020_940d;

pub(super) fn reflink(name: &str, args: Option<[u64; 6]>) -> bool {
    name == "ioctl" && args.is_some_and(|args| matches!(args[1], FICLONE | FICLONERANGE))
}

pub(super) fn number(values: &[(&str, RowValue)], key: &str) -> Option<u64> {
    number_signed(values, key).and_then(|number| u64::try_from(number).ok())
}
fn number_signed(values: &[(&str, RowValue)], key: &str) -> Option<i128> {
    values.iter().find_map(|(name, value)| {
        if *name == key {
            if let RowValue::Number(value) = value {
                Some(*value)
            } else {
                None
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triage::tests::{call, captured, path_call};

    fn operation(
        id: u64,
        nr: u64,
        name: &str,
        ret: i64,
        args: [u64; 6],
        data: &[u8],
    ) -> InvocationSummary {
        let mut call = call(1, nr, name, ret);
        call.call_id = id;
        call.entry.as_mut().unwrap().call_id = id;
        call.entry.as_mut().unwrap().args = Some(args);
        call.exit.as_mut().unwrap().call_id = id;
        let event = if READ_NAMES.contains(&name) {
            call.exit.as_mut().unwrap()
        } else {
            call.entry.as_mut().unwrap()
        };
        if !data.is_empty() {
            event.fields.push(captured("arg1.data", "", data));
        }
        call
    }

    fn open(flags: u64) -> InvocationSummary {
        let mut call = path_call(1, 2, "open", 3, "/tmp/file");
        call.entry.as_mut().unwrap().args = Some([0, flags, 0, 0, 0, 0]);
        call
    }

    fn build(calls: &[InvocationSummary]) -> (FileIndex, Vec<Vec<Cell>>) {
        let mut index = FileIndex::default();
        let mut files = FdState::default();
        let mut reads = Vec::new();
        let cookies = task_cookies(calls);
        for call in calls {
            let event = trace::representative(call).unwrap();
            remember_cwd(&mut files, call, event);
            remember_open(&mut files, call, event);
            apply_dup(&mut files, call, event);
            forget_closed(&mut files, call, event);
            inherit_open_fds(&mut files, call, event, &cookies);
            if let Some(row) = index.observe(&files, call, event, None) {
                reads.push(row);
            }
        }
        (index, reads)
    }

    #[test]
    fn a_reflink_clone_changes_its_destination_and_reads_its_source() {
        let calls = [
            open(2),
            operation(2, 16, "ioctl", 0, [3, FICLONE, 5, 0, 0, 0], b""),
            operation(3, 16, "ioctl", 0, [3, 0x5401, 0, 0, 0, 0], b""),
        ];
        let (index, reads) = build(&calls);
        assert_eq!(reads.len(), 1, "only the clone reads a source");
        assert_eq!(reads[0][1].text, "fd 5");
        let changes = index.finish();
        let change = changes
            .iter()
            .find(|change| change.path == "/tmp/file")
            .unwrap();
        assert!(change
            .gaps
            .iter()
            .any(|gap| gap.starts_with("Reflink clone observed")));
    }

    #[test]
    fn a_kernel_copy_reads_its_source_without_inventing_content() {
        let calls = [
            open(0),
            operation(2, 40, "sendfile", 5, [4, 3, 0, 5, 0, 0], b""),
            operation(3, 326, "copy_file_range", 7, [3, 0, 4, 0, 7, 0], b""),
            operation(4, 275, "splice", -22, [9, 0, 4, 0, 7, 0], b""),
        ];
        let (_, reads) = build(&calls);
        assert_eq!(reads.len(), 3);
        for (row, size) in reads[..2].iter().zip(["5 B", "7 B"]) {
            assert_eq!(row[1].text, "/tmp/file");
            assert_eq!(
                row[3].text,
                format!("{size}: kernel transfer; bytes not captured")
            );
            assert!(
                row[0]
                    .values
                    .iter()
                    .any(|(name, value)| *name == "file.content"
                        && matches!(value, RowValue::Missing))
            );
        }
        assert_eq!(reads[2][1].text, "fd 9");
        assert_eq!(reads[2][3].text, "Unavailable");
    }

    #[test]
    fn read_then_pwrite_reconstructs_original_to_final_and_keeps_timeline() {
        let calls = [
            open(2),
            operation(2, 0, "read", 5, [3, 0, 5, 0, 0, 0], b"ABCDE"),
            operation(3, 0, "read", 0, [3, 0, 5, 0, 0, 0], b""),
            operation(4, 18, "pwrite64", 2, [3, 0, 2, 1, 0, 0], b"zz"),
        ];
        let (index, reads) = build(&calls);
        let changes = index.finish();
        assert_eq!(reads.len(), 2);
        assert_eq!(reads[0][1].text, "/tmp/file");
        assert!(reads[0][3].text.contains("ABCDE"));
        assert_eq!(changes.len(), 1);
        let change = &changes[0];
        assert_eq!(change.call, 4);
        assert_eq!(change.diff_count(), 2);
        assert_eq!(change.original.get(&1), Some(&b'B'));
        assert_eq!(change.final_data.get(&1), Some(&b'z'));
        assert_eq!(change.original_size, Some(5));
        assert_eq!(change.final_size, Some(5));
        assert_eq!(change.operations.len(), 3);
        assert_eq!(change.count_label(), "2");
    }

    #[test]
    fn partial_write_never_turns_uncaptured_tail_into_zero_or_preserves_old_tail() {
        let calls = [
            open(2),
            operation(2, 0, "read", 4, [3, 0, 4, 0, 0, 0], b"AAAA"),
            operation(3, 18, "pwrite64", 3, [3, 0, 3, 0, 0, 0], b"B"),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        let change = &changes[0];
        assert_eq!(change.diff_count(), 1);
        assert_eq!(change.final_data.get(&1), None);
        assert_eq!(change.final_data.get(&3), Some(&b'A'));
        assert!(change.count_label().contains("gaps"));
    }

    #[test]
    fn uncaptured_read_path_and_content_remain_missing_filter_values() {
        let (_, reads) = build(&[operation(2, 0, "read", 2, [3, 0, 2, 0, 0, 0], b"")]);
        for field in ["file.path", "file.content"] {
            assert!(reads[0][0]
                .values
                .iter()
                .any(|(name, value)| *name == field && matches!(value, RowValue::Missing)));
        }
    }

    #[test]
    fn failed_read_has_no_content_and_does_not_advance_descriptor() {
        let (index, reads) = build(&[
            open(2),
            operation(2, 0, "read", -9, [3, 0, 4, 0, 0, 0], b"BAD"),
            operation(3, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"X"),
        ]);
        assert_eq!(reads[0][3].text, "Unavailable");
        assert!(reads[0][4].text.starts_with("Failed"));
        assert_eq!(index.finish()[0].final_data.get(&0), Some(&b'X'));
    }

    #[test]
    fn dup_shares_offset_and_pread_does_not_move_it() {
        let calls = [
            open(2),
            operation(2, 0, "read", 2, [3, 0, 2, 0, 0, 0], b"AB"),
            operation(3, 32, "dup", 4, [3, 0, 0, 0, 0, 0], b""),
            operation(4, 17, "pread64", 1, [4, 0, 1, 0, 0, 0], b"A"),
            operation(5, 1, "write", 1, [4, 0, 1, 0, 0, 0], b"C"),
        ];
        let (index, _) = build(&calls);
        assert_eq!(index.finish()[0].final_data.get(&2), Some(&b'C'));
    }

    #[test]
    fn truncate_counts_known_removed_bytes_and_labels_missing_original_extent() {
        let (index, _) = build(&[
            open(2),
            operation(2, 0, "read", 4, [3, 0, 4, 0, 0, 0], b"ABCD"),
            operation(3, 77, "ftruncate", 0, [3, 2, 0, 0, 0, 0], b""),
        ]);
        let changes = index.finish();
        assert_eq!(changes[0].diff_count(), 2);
        assert_eq!(changes[0].final_size, Some(2));
        assert!(!changes[0].gaps.is_empty());
    }

    #[test]
    fn shared_mapping_without_writeback_is_not_a_file_change() {
        let calls = [
            open(2),
            operation(2, 9, "mmap", 4096, [0, 4096, 2, MAP_PRIVATE, 3, 0], b""),
            operation(3, 9, "mmap", 8192, [0, 4096, 2, 1, 3, 0], b""),
            operation(4, 26, "msync", 0, [8192, 4096, 4, 0, 0, 0], b""),
            operation(5, 91, "fchmod", 0, [3, 0o600, 0, 0, 0, 0], b""),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        assert_eq!(changes.len(), 2);
        let file = changes
            .iter()
            .find(|change| change.path == "/tmp/file")
            .unwrap();
        assert_eq!(file.operations.len(), 1);
        assert_eq!(file.operations[0].name, "fchmod");
        assert_eq!(file.operations[0].process, "Unknown (1 / 1)");
        assert!(file.gaps.iter().all(|gap| !gap.contains("mapped writes")));
        let synced = changes
            .iter()
            .find(|change| change.operations.iter().any(|op| op.name == "msync"))
            .unwrap();
        assert_eq!(synced.path, "fd unavailable");
        assert!(synced.gaps.iter().any(|gap| gap.contains("mapped writes")));
    }

    #[test]
    fn unknown_descriptor_uses_a_short_label_and_stays_missing() {
        let (_, reads) = build(&[operation(2, 0, "read", 2, [1, 0, 2, 0, 0, 0], b"hi")]);
        assert_eq!(reads[0][1].text, "stdout");
        assert!(reads[0][0]
            .values
            .iter()
            .any(|(name, value)| { *name == "file.path" && matches!(value, RowValue::Missing) }));
    }

    #[test]
    fn readv_uses_only_vector_payloads_and_clips_to_successful_result() {
        let mut read = operation(2, 19, "readv", 3, [3, 0, 2, 0, 0, 0], b"");
        read.exit.as_mut().unwrap().fields = vec![
            captured("arg1.iov", "iovec[]", &[0; 32]),
            captured("arg1.iov[0].data", "", b"AB"),
            captured("arg1.iov[1].data", "", b"CD"),
        ];
        let (_, rows) = build(&[open(2), read]);
        assert!(rows[0][3].text.contains("3 B: ABC"));
        assert!(!rows[0][3].text.contains("ABCD"));
    }

    #[test]
    fn exclusive_create_proves_empty_original_and_append_marks_unknown_offset() {
        let (index, _) = build(&[
            open(0xc2),
            operation(2, 1, "write", 3, [3, 0, 3, 0, 0, 0], b"abc"),
        ]);
        let change = &index.finish()[0];
        assert_eq!(change.original_size, Some(0));
        assert_eq!(change.final_size, Some(3));
        assert_eq!(change.diff_count(), 3);
        let (index, _) = build(&[
            open(0x402),
            operation(2, 1, "write", 3, [3, 0, 3, 0, 0, 0], b"abc"),
        ]);
        let changes = index.finish();
        assert!(changes[0].final_data.is_empty());
        assert!(!changes[0].gaps.is_empty());
    }

    #[test]
    fn fork_inherits_shared_open_file_position() {
        let mut child = operation(4, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"C");
        child.task_cookie = 2;
        child.entry.as_mut().unwrap().task_cookie = 2;
        child.entry.as_mut().unwrap().tid = 2;
        child.entry.as_mut().unwrap().pid = 2;
        child.exit.as_mut().unwrap().task_cookie = 2;
        child.exit.as_mut().unwrap().tid = 2;
        child.exit.as_mut().unwrap().pid = 2;
        let (index, _) = build(&[
            open(2),
            operation(2, 0, "read", 2, [3, 0, 2, 0, 0, 0], b"AB"),
            operation(3, FORK, "fork", 2, [0; 6], b""),
            child,
            operation(5, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"D"),
        ]);
        let changes = index.finish();
        assert_eq!(changes[0].final_data.get(&2), Some(&b'C'));
        assert_eq!(changes[0].final_data.get(&3), Some(&b'D'));
    }

    #[test]
    fn missing_write_exit_invalidates_old_final_bytes_and_future_offsets() {
        let mut unknown = operation(3, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"X");
        unknown.exit = None;
        let (index, _) = build(&[
            open(2),
            operation(2, 0, "read", 2, [3, 0, 2, 0, 0, 0], b"AB"),
            unknown,
            operation(4, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"C"),
        ]);
        let changes = index.finish();
        assert!(changes[0].final_data.is_empty());
        assert!(changes[0]
            .gaps
            .iter()
            .any(|gap| gap.contains("Write exit unavailable")));
    }

    #[test]
    fn nonprefix_capture_ranges_preserve_offsets_and_read_preview_holes() {
        let mut read = operation(2, 0, "read", 4, [3, 0, 4, 0, 0, 0], b"A?CD");
        read.exit.as_mut().unwrap().fields[0].ranges = vec![(0, 1), (2, 2)];
        let mut write = operation(3, 18, "pwrite64", 4, [3, 0, 4, 0, 0, 0], b"Z?XD");
        write.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 1), (2, 2)];
        let (index, reads) = build(&[open(2), read, write]);
        let changes = index.finish();
        assert!(reads[0][3].text.contains("A??CD"));
        assert_eq!(changes[0].diff_count(), 2);
        assert_eq!(changes[0].original.get(&1), None);
        assert_eq!(changes[0].final_data.get(&1), None);
        assert_eq!(changes[0].final_data.get(&2), Some(&b'X'));
    }

    #[test]
    fn native_vectored_offset_retains_all_64_bits_and_missing_iov_does_not_shift_data() {
        let mut write = operation(2, 296, "pwritev", 1, [3, 0, 1, 1u64 << 40, 0, 0], b"");
        write
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.iov[0].data", "", b"X"));
        let (index, _) = build(&[open(2), write]);
        assert_eq!(index.finish()[0].final_data.get(&(1u64 << 40)), Some(&b'X'));
        let mut read = operation(2, 19, "readv", 3, [3, 0, 2, 0, 0, 0], b"");
        read.exit
            .as_mut()
            .unwrap()
            .fields
            .push(captured("arg1.iov[1].data", "", b"XYZ"));
        let (_, rows) = build(&[open(2), read]);
        assert!(rows[0][3].text.contains("??????"));
        assert!(!rows[0][3].text.contains("XYZ"));
    }
}

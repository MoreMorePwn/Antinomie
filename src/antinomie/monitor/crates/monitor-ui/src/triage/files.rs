// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, evidence-based file reads and original-to-final change reconstruction.
//! Unknown bytes are never zero-filled. A path is a name: where the guest
//! recorded the identity of a file (device and inode) one file is followed
//! across its names, and where it did not, two names are two files.
use super::file_category::{self, Access, Category, Hit};
use super::file_content::{self, capture as captured_data, CapturedPayload};
use super::file_location::{self, Location};
use super::*;
use antinomie_monitor_core::kernel_notes::{FileHash, FileId, FileIdKind, FileKey, HashKind};
use std::collections::{BTreeMap, BTreeSet};

mod copies;
mod ioc;
mod order;
mod view;

pub(super) use ioc::IocFile;

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
    /// The file the guest identified, once a call named it.
    identity: Option<FileKey>,
    /// Other names the same file was seen under (renames, hard links), in order.
    names: Vec<String>,
    /// Hard links the inode had after the last call that reported them.
    links: Option<u32>,
    /// The guest's latest hash of the file: taken after its last writer closed
    /// it, or just before it was deleted.
    hash: Option<FileHash>,
    /// Recording segment of the file's latest operation; a later one after a
    /// transport reconnect puts the boundary in its story.
    segment: usize,
    /// Recent numbered writes, `(start, end, write order)` (files/order.rs).
    applied: Vec<(u64, u64, u64)>,
}

const PATH_GAP: &str =
    "File path unavailable; these operations cannot be assigned to a named file.";

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
    /// Record what the guest said about the file this change describes: its
    /// identity, how many links it has left and a new name for it.
    fn note_identity(&mut self, id: FileId, name: Option<&str>) {
        self.identity.get_or_insert(id.key);
        if !matches!(id.kind, FileIdKind::Issue | FileIdKind::Exec) {
            self.links = Some(id.nlink);
        }
        if let (false, Some(name)) = (self.path_known, name) {
            self.path = name.to_owned();
            self.path_known = true;
            self.gaps.remove(PATH_GAP);
        }
    }
    /// The guest hashed the file: it says what the file held then, or why it
    /// has no digest.
    fn record_hash(&mut self, hash: FileHash) {
        let moment = match hash.kind {
            HashKind::Delete => "hashed before delete",
            _ => "closed after write",
        };
        let what = match (hash.sha256_hex(), hash.skipped()) {
            (Some(hex), None) => format!("SHA-256 {}…", &hex[..12]),
            (_, Some(why)) => format!("no hash: {why}"),
            (None, None) => "no hash".to_owned(),
        };
        self.step(format!("{moment} · {what}"));
        self.hash = Some(hash);
    }
    /// A transport reconnect lies between this file's last operation and the
    /// next: the recording continues in another segment.
    fn cross_segment(&mut self, segment: usize, operation_count: &mut usize) {
        if segment <= self.segment {
            return;
        }
        self.segment = segment;
        self.step("reconnected".into());
        if self.operations.len() < TIMELINE_ROWS && *operation_count < TOTAL_OPERATIONS {
            self.operations.push(Operation {
                time: 0,
                call: 0,
                key: (0, 0, 0),
                name: format!("transport reconnected · recording segment {}", segment + 1),
                process: String::new(),
                result: String::new(),
            });
            *operation_count += 1;
        }
    }
    /// A name the file was reached by that no rename or link of the run gave it.
    fn alias(&mut self, name: String) {
        if name != self.path && !self.names.contains(&name) && self.names.len() < 16 {
            self.step(format!("also seen as {name}"));
            self.names.push(name);
        }
    }
    /// A name the file was given by a rename or a hard link.
    fn add_name(&mut self, name: &str) {
        if name != self.path
            && !self.names.iter().any(|known| known == name)
            && self.names.len() < 16
        {
            self.names.push(name.to_owned());
        }
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
}

#[derive(Default)]
pub(super) struct FileIndex {
    changes: BTreeMap<String, Change>,
    /// Descriptor owner, fd -> shared open-file description; dup shares offsets.
    descriptors: BTreeMap<(u64, u32, u64), u64>,
    descriptions: BTreeMap<u64, (Option<u64>, bool)>,
    next_description: u64,
    /// Identified file → the group of its changes, whatever name it came by.
    by_identity: BTreeMap<FileKey, String>,
    /// Open-file description → the group of the identified file it was opened
    /// on, so a write through a descriptor reaches the file whatever name the
    /// descriptor was opened by.
    description_group: BTreeMap<u64, String>,
    /// Group → the identified file it holds, to tell a name that a new file
    /// took over from the file that held it.
    group_identity: BTreeMap<String, FileKey>,
    /// Names the file of a group was reached by, not yet put in its entry.
    aliases: BTreeMap<String, Vec<String>>,
    next_split: u64,
    retained_octets: usize,
    operation_count: usize,
    pub omitted_files: u64,
    /// Recording segment being read (0 for the first).
    segment: usize,
    /// What each call did to each file the run touched, for the File activity
    /// window.
    activity: file_activity::Builder,
    /// Directory and object names shared by the extents of a field.
    interned: file_content::Interned,
}

impl FileIndex {
    /// The caps on the write content kept per file and per run.
    pub fn set_write_limits(&mut self, limits: antinomie_monitor_core::file_writes::Limits) {
        self.activity.set_limits(limits);
    }

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

    /// The calls that follow come from recording segment `segment` (counted
    /// from 0), after a transport reconnect.
    pub fn begin_segment(&mut self, segment: usize) {
        self.segment = segment;
        self.activity.set_segment(segment);
    }

    /// The hashes the guest took of files of this run: at the last close of a
    /// written file (carried by the closing task's last call, with the file's
    /// identity) and just before a delete (carried by the unlink).
    pub fn observe_hashes(
        &mut self,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
    ) {
        for hash in kernel_records::write_hashes(call) {
            let Some(file) = hash.file else { continue };
            self.activity.hash(
                Some(file.key),
                None,
                event.timestamp_ns,
                "closed after write",
                &hash,
            );
            if let Some(change) = self
                .by_identity
                .get(&file.key)
                .and_then(|group| self.changes.get_mut(group))
            {
                change.record_hash(hash);
            }
        }
        let Some(hash) = kernel_records::file_hash(call, HashKind::Delete) else {
            return;
        };
        self.activity.hash(
            kernel_records::file_id(call).map(|id| id.key),
            Some(&displayed_path(call, event, files)),
            event.timestamp_ns,
            "before delete",
            &hash,
        );
        let group = kernel_records::file_id(call)
            .and_then(|id| self.by_identity.get(&id.key).cloned())
            .unwrap_or_else(|| displayed_path(call, event, files));
        if let Some(change) = self.changes.get_mut(&group) {
            change.record_hash(hash);
        }
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
        let mut opened_description = None;
        if OPEN_NAMES.contains(&name)
            && success
            && !async_files::direct_descriptor(call)
            && self.descriptions.len() < 65536
            && self.descriptors.len() < 65536
        {
            let id = self.next_description;
            opened_description = Some(id);
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
            // An open that changes nothing still says which file a descriptor
            // leads to, whatever name it was opened by.
            if let (Some(opened), Some(id)) = (opened_description, kernel_records::file_id(call)) {
                let named = displayed_path(call, event, files);
                if named != "—" {
                    let mut alias = None;
                    let group = self.route(id.key, named.clone(), Some(&named), &mut alias);
                    self.remember_alias(&group, alias);
                    self.bind_description(opened, group);
                }
            }
            self.note_activity(files, call, event, hits, fd, None);
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
        // The same file may arrive by another name, or by no name at all (a
        // descriptor of a registered table, one opened before the capture):
        // the guest's file identity joins it to the file it already knows.
        let identity = kernel_records::file_id(call);
        let mut alias = None;
        // A rename or link acts on the file by its old name and names it anew;
        // without an identity the pair of names is all there is to key on.
        let (group, path, path_known) = match identity.and_then(|_| {
            sigma_events::paths(files, call, event)
                .into_iter()
                .find(|used| used.role == sigma_events::Role::Old)
        }) {
            Some(old) => (old.name.clone(), old.name, true),
            None => (group, path, path_known),
        };
        let group = match identity {
            Some(id) => self.route(
                id.key,
                group,
                path_known.then_some(path.as_str()),
                &mut alias,
            ),
            // An operation on a descriptor goes where its description was opened.
            None => description
                .and_then(|id| self.description_group.get(&id))
                .cloned()
                .unwrap_or(group),
        };
        self.remember_alias(&group, alias.take());
        if let (Some(description), Some(_)) = (opened_description, identity) {
            self.bind_description(description, group.clone());
        }
        let (path, path_known) = match self.changes.get(&group) {
            Some(known) if !path_known && known.path_known => (known.path.clone(), true),
            _ => (path, path_known),
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
        // The guest's record of the position (revision 18) is exact where the
        // inference above is not: a shared descriptor, an append.
        let kernel_position = kernel_records::file_position(call).filter(|_| reading || writing);
        if let Some(position) = kernel_position {
            offset = Some(position.offset);
        }
        let copy = kernel_records::file_copy(call).filter(|_| success && changed);
        let copied = copy
            .filter(|copy| copy.data_len > 0)
            .map(|copy| captured_data(call, true, directory, copy.data_len))
            .unwrap_or_default();
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
                cell(
                    match async_files::via(call) {
                        Some(system) => format!("{} ({system})", read_access.label()),
                        None => read_access.label().to_owned(),
                    },
                    theme::text(),
                    false,
                ),
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
                    "file.via",
                    RowValue::Text(async_files::via(call).unwrap_or("syscall").into()),
                ),
                (
                    "file.inode",
                    kernel_records::file_id(call).map_or(RowValue::Missing, |id| {
                        RowValue::Text(format!("{}:{}", id.key.dev, id.key.ino))
                    }),
                ),
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
        let known_size = self
            .changes
            .get(&group)
            .and_then(|change| change.final_size);
        let transfer = match copy {
            Some(copy) => {
                let stretches = file_content::copy_stretches(
                    call,
                    directory,
                    copy.data_len,
                    &mut self.interned,
                );
                copies::copy_transfer(&copy, &copied, known_size, stretches)
            }
            None => (success && (reading || writing)).then(|| file_activity::Transfer {
                write: writing,
                offset,
                len: size,
                stretches: if writing {
                    file_content::write_stretches(call, directory, size, &mut self.interned)
                } else {
                    Vec::new()
                },
                content: bytes.head(file_activity::CONTENT_HEAD),
                gap: bytes.len() as u64 != size,
                extends: offset
                    .zip(known_size)
                    .is_some_and(|(offset, known)| offset.saturating_add(size) > known),
                order: kernel_position.and_then(|position| position.order),
            }),
        };
        self.note_activity(files, call, event, hits, fd, transfer);
        if lifecycle_only && !self.changes.contains_key(&group) {
            return read_row;
        }
        if !self.changes.contains_key(&group) && self.changes.len() >= TRACKED_FILES {
            self.omitted_files += 1;
            return read_row;
        }
        let known_identity = self.group_identity.get(&group).copied();
        // A file reached first by another name keeps the name of its group.
        let own_name = group
            .split('\u{0}')
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_owned);
        let aliases = self.aliases.remove(&group);
        let segment = self.segment;
        let change = self.changes.entry(group).or_insert_with(|| Change {
            segment,
            path: own_name.clone().unwrap_or_else(|| path.clone()),
            path_known: path_known || own_name.is_some(),
            identity: known_identity,
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
        change.cross_segment(segment, &mut self.operation_count);
        if let Some(id) = identity {
            change.note_identity(id, path_known.then_some(path.as_str()));
        }
        for alias in aliases.into_iter().flatten() {
            change.alias(alias);
        }
        // Hide a group only when every observed operation uses fd 0/1/2.
        // A metadata/namespace operation or another descriptor keeps it visible.
        change.standard_io &= file_fd(call, event)
            .parse::<u64>()
            .ok()
            .and_then(crate::values::standard_fd_name)
            .is_some();
        if !path_known {
            change.gaps.insert(PATH_GAP);
        }
        if change.operations.len() < TIMELINE_ROWS && self.operation_count < TOTAL_OPERATIONS {
            change.operations.push(Operation {
                time: event.timestamp_ns,
                call: call.call_id,
                key: trace::key(call),
                name: file_events::operation_label(call, event),
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
                let newer = change.newer(kernel_position, offset, size);
                if writing {
                    change
                        .final_data
                        .retain(|at, _| !order::replaced(&newer, offset, size, *at));
                    change.modified = true;
                    change.final_size = change.final_size.and_then(|size_before| {
                        offset.checked_add(size).map(|end| size_before.max(end))
                    });
                }
                let was_modified = change.modified;
                for (relative, byte) in order::outside(&newer, offset, bytes.iter()) {
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
                change.note_applied(kernel_position, offset, size);
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
                    *position = match kernel_position {
                        Some(known) => known.offset.checked_add(known.len),
                        None => position.and_then(|offset| offset.checked_add(size)),
                    };
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
        } else if let Some(copy) = copy {
            change.kernel_copy(&copy, &copied, &mut self.retained_octets);
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
                "unlink" | "unlinkat" | "rmdir" => match identity {
                    // Another name keeps the file alive: only a name was removed.
                    Some(id) if id.nlink > 0 && !id.directory => {}
                    Some(_) => change.deleted = true,
                    None => {
                        change.deleted = true;
                        change.gaps.insert(
                            "Unlink observed; link count and final inode lifetime are unavailable.",
                        );
                    }
                },
                "msync" => {
                    change.modified = true;
                    change.final_data.clear();
                    change.gaps.insert("Shared writable mapping observed; actual mapped writes and final bytes are unavailable.");
                }
                "rename" | "renameat" | "renameat2" | "link" | "linkat" if identity.is_some() => {
                    let new = sigma_events::paths(files, call, event)
                        .into_iter()
                        .find(|used| used.role == sigma_events::Role::New);
                    if let Some(new) = new {
                        change.add_name(&new.name);
                    }
                    if name.starts_with("rename") {
                        change.gaps.insert(
                            "Rename observed; a destination file it overwrote is not captured.",
                        );
                    }
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
    /// The group of the changes to the file `key`. A name already seen for the
    /// same file joins it. A name that now holds another file starts its own
    /// group and the file it held keeps its history under a private key.
    fn route(
        &mut self,
        key: FileKey,
        group: String,
        name: Option<&str>,
        alias: &mut Option<String>,
    ) -> String {
        if let Some(known) = self.by_identity.get(&key).cloned() {
            if known != group {
                *alias = name.map(str::to_owned);
            }
            return known;
        }
        let replaced = self
            .group_identity
            .get(&group)
            .copied()
            .filter(|old| *old != key);
        if let Some(old) = replaced {
            let private = format!("{group}\u{0}#{}", self.next_split);
            self.next_split += 1;
            if let Some(change) = self.changes.remove(&group) {
                self.changes.insert(private.clone(), change);
            }
            self.group_identity.remove(&group);
            self.group_identity.insert(private.clone(), old);
            self.by_identity.insert(old, private.clone());
            for known in self.description_group.values_mut() {
                if *known == group {
                    known.clone_from(&private);
                }
            }
        }
        if self.by_identity.len() < 65536 {
            self.by_identity.insert(key, group.clone());
            self.group_identity.insert(group.clone(), key);
        }
        group
    }
    /// Tell the File activity index about a call on a file.
    fn note_activity(
        &mut self,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
        hits: &[Hit],
        fd: Option<u64>,
        transfer: Option<file_activity::Transfer>,
    ) {
        if hits.is_empty() && transfer.is_none() {
            return;
        }
        let observed = displayed_path(call, event, files);
        let (mut path, mut path_known, mut new_name) = (observed.clone(), observed != "—", None);
        // A rename or link acts on the file by its old name and names it anew.
        if hits
            .iter()
            .any(|hit| matches!(hit.category, Category::Renamed | Category::Linked))
        {
            for used in sigma_events::paths(files, call, event) {
                match used.role {
                    sigma_events::Role::Old => (path, path_known) = (used.name, true),
                    sigma_events::Role::New => new_name = Some(used.name),
                    sigma_events::Role::Subject => {}
                }
            }
        }
        self.activity.record(file_activity::Record {
            path: &path,
            path_known,
            cookie: call.task_cookie,
            fd,
            identity: kernel_records::file_id(call),
            call,
            event,
            image: process_image(files, event),
            hits,
            transfer,
            new_name,
        });
    }
    fn remember_alias(&mut self, group: &str, alias: Option<String>) {
        if let Some(alias) = alias {
            let names = self.aliases.entry(group.to_owned()).or_default();
            if names.len() < 16 && !names.contains(&alias) {
                names.push(alias);
            }
        }
    }
    fn bind_description(&mut self, description: u64, group: String) {
        if self.description_group.len() < 65536 {
            self.description_group.insert(description, group);
        }
    }
    #[cfg(test)]
    pub fn finish(self) -> Vec<Change> {
        self.finish_all().0
    }

    /// The changed files, and the activity of every file the run touched with
    /// what the changes know of each one's contents.
    pub fn finish_all(self) -> (Vec<Change>, file_activity::Activity) {
        let by_path: BTreeMap<&str, &Change> = self
            .changes
            .values()
            .map(|change| (change.path.as_str(), change))
            .collect();
        let by_identity: BTreeMap<FileKey, &Change> = self
            .changes
            .values()
            .filter_map(|change| change.identity.map(|key| (key, change)))
            .collect();
        let activity = self.activity.finish(|file| {
            file.identity
                .and_then(|key| by_identity.get(&key))
                .or_else(|| by_path.get(file.path.as_str()))
                .map(|change| change.contents())
        });
        let changes = self
            .changes
            .into_values()
            .filter(|change| change.changes || change.failed > 0)
            .map(|mut change| {
                change.known_diff_count = Some(change.diff_count());
                change
            })
            .collect();
        (changes, activity)
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
    use std::path::PathBuf;

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

    /// A call with the guest's identity record of the file it acted on.
    fn identified(
        mut call: InvocationSummary,
        kind: u8,
        nlink: u32,
        inode: u64,
    ) -> InvocationSummary {
        let mut bytes = vec![0u8; 32];
        bytes[0] = kind;
        bytes[1] = 2;
        bytes[4..8].copy_from_slice(&nlink.to_le_bytes());
        bytes[8..16].copy_from_slice(&1u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&inode.to_le_bytes());
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0o100644u32.to_le_bytes());
        let mut note = call.exit.clone().unwrap();
        note.phase = 3;
        note.fields = vec![captured("lifecycle.file_id", "antinomie.fileid/1", &bytes)];
        call.kernel_notes.push(note);
        call
    }

    fn named(
        id: u64,
        nr: u64,
        name: &str,
        ret: i64,
        args: [u64; 6],
        paths: &[&str],
    ) -> InvocationSummary {
        let mut call = operation(id, nr, name, ret, args, b"");
        for (index, path) in paths.iter().enumerate() {
            let mut bytes = path.as_bytes().to_vec();
            bytes.push(0);
            let key = match (name, index) {
                ("rename" | "link", 0) => "arg0.oldname",
                ("rename" | "link", _) => "arg1.newname",
                _ => "arg0.pathname",
            };
            call.entry
                .as_mut()
                .unwrap()
                .fields
                .push(captured(key, "", &bytes));
        }
        call
    }

    fn create(id: u64, path: &str, inode: u64, nlink: u32) -> InvocationSummary {
        let mut call = named(id, 2, "open", 3, [0, 0x42, 0, 0, 0, 0], &[path]);
        call.entry.as_mut().unwrap().args = Some([0, 0x42, 0, 0, 0, 0]);
        identified(call, 1, nlink, inode)
    }

    fn reopen(id: u64, path: &str, inode: u64, nlink: u32) -> InvocationSummary {
        let call = named(id, 2, "open", 4, [0, 0x2, 0, 0, 0, 0], &[path]);
        identified(call, 1, nlink, inode)
    }

    #[test]
    fn a_name_the_run_never_saw_made_is_joined_to_its_file_by_identity() {
        let calls = [
            create(1, "/tmp/x", 100, 2),
            operation(2, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"x"),
            // Another name of the same inode, linked before the capture.
            reopen(3, "/tmp/y", 100, 2),
            operation(4, 1, "write", 1, [4, 0, 1, 0, 0, 0], b"y"),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].names, ["/tmp/y"]);
        assert!(changes[0].lifecycle_text().contains("also seen as /tmp/y"));
        assert!(
            changes[0].gaps.is_empty() || changes[0].gaps.iter().all(|gap| !gap.contains("path"))
        );
    }

    #[test]
    fn a_renamed_and_hard_linked_file_stays_one_entry_with_all_its_names() {
        let calls = [
            create(1, "/tmp/a", 100, 1),
            operation(2, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"x"),
            identified(
                named(3, 82, "rename", 0, [0; 6], &["/tmp/a", "/tmp/b"]),
                2,
                1,
                100,
            ),
            identified(
                named(4, 86, "link", 0, [0; 6], &["/tmp/b", "/tmp/c"]),
                3,
                2,
                100,
            ),
            // The other name opened: the same file.
            reopen(5, "/tmp/c", 100, 2),
            identified(named(6, 87, "unlink", 0, [0; 6], &["/tmp/b"]), 4, 1, 100),
            identified(named(7, 87, "unlink", 0, [0; 6], &["/tmp/c"]), 4, 0, 100),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        assert_eq!(changes.len(), 1, "one file, not one per name");
        let file = &changes[0];
        assert_eq!(file.path, "/tmp/a");
        assert_eq!(file.names, ["/tmp/b", "/tmp/c"]);
        let story = file.lifecycle_text();
        for step in [
            "renamed → /tmp/b",
            "hard-linked → /tmp/c",
            "name removed (1 link remains)",
            "deleted",
        ] {
            assert!(story.contains(step), "{step:?} missing from {story}");
        }
        // The file was alive until its last name went.
        assert!(file.deleted);
        assert!(file.gaps.iter().all(|gap| !gap.contains("link count")));
    }

    #[test]
    fn a_name_that_a_new_file_takes_over_is_a_second_entry() {
        let calls = [
            create(1, "/tmp/a", 100, 1),
            operation(2, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"x"),
            identified(named(3, 87, "unlink", 0, [0; 6], &["/tmp/a"]), 4, 0, 100),
            create(4, "/tmp/a", 200, 1),
            operation(5, 1, "write", 2, [3, 0, 2, 0, 0, 0], b"yy"),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        assert_eq!(
            changes.len(),
            2,
            "{:?}",
            changes
                .iter()
                .map(Change::lifecycle_text)
                .collect::<Vec<_>>()
        );
        assert!(changes.iter().all(|change| change.path == "/tmp/a"));
        let (old, new): (Vec<_>, Vec<_>) = changes.iter().partition(|change| change.deleted);
        assert_eq!((old.len(), new.len()), (1, 1));
        assert!(!new[0].lifecycle_text().contains("deleted"));
    }

    #[test]
    fn without_identity_two_names_are_two_files_and_the_gap_says_why() {
        let calls = [
            named(1, 2, "open", 3, [0, 0x42, 0, 0, 0, 0], &["/tmp/a"]),
            operation(2, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"x"),
            named(3, 82, "rename", 0, [0; 6], &["/tmp/a", "/tmp/b"]),
            named(4, 2, "open", 4, [0, 0x42, 0, 0, 0, 0], &["/tmp/b"]),
            operation(5, 1, "write", 1, [4, 0, 1, 0, 0, 0], b"y"),
            named(6, 87, "unlink", 0, [0; 6], &["/tmp/b"]),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        assert!(changes.len() >= 2);
        assert!(changes.iter().all(|change| change.names.is_empty()));
        assert!(changes
            .iter()
            .flat_map(|change| change.gaps.iter())
            .any(|gap| gap.contains("link count")));
    }

    #[test]
    fn a_descriptor_with_no_name_is_tied_to_its_file_by_identity() {
        // A request on a registered descriptor: no path, only the identity.
        let calls = [
            create(1, "/tmp/a", 100, 1),
            identified(
                operation(2, 1, "write", 2, [u64::MAX, 0, 2, 0, 0, 0], b"hi"),
                5,
                1,
                100,
            ),
        ];
        let (index, _) = build(&calls);
        let changes = index.finish();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].path, "/tmp/a");
        assert!(changes[0]
            .gaps
            .iter()
            .all(|gap| !gap.contains("path unavailable")));
    }

    /// The guest's hash of inode `inode` at its last close (`antinomie.hash/2`).
    fn with_write_hash(mut call: InvocationSummary, inode: u64, status: u8) -> InvocationSummary {
        let mut bytes = vec![0u8; 112];
        bytes[0] = 3;
        bytes[1] = status;
        bytes[2] = u8::from(status == 0);
        bytes[8..16].copy_from_slice(&5u64.to_le_bytes());
        bytes[24..32].copy_from_slice(&(16u64 << 20).to_le_bytes());
        if status == 0 {
            bytes[32..64].fill(0xcd);
        }
        bytes[80..88].copy_from_slice(&1u64.to_le_bytes());
        bytes[88..96].copy_from_slice(&inode.to_le_bytes());
        bytes[96..100].copy_from_slice(&1u32.to_le_bytes());
        let mut note = call.exit.clone().unwrap();
        note.phase = 3;
        note.fields = vec![captured("lifecycle.file_hash", "antinomie.hash/2", &bytes)];
        call.kernel_notes.push(note);
        call
    }

    fn index_with_hashes(calls: &[InvocationSummary], segments: &[usize]) -> FileIndex {
        let mut index = FileIndex::default();
        let mut files = FdState::default();
        let cookies = task_cookies(calls);
        for (position, call) in calls.iter().enumerate() {
            index.begin_segment(segments.get(position).copied().unwrap_or(0));
            let event = trace::representative(call).unwrap();
            remember_cwd(&mut files, call, event);
            remember_open(&mut files, call, event);
            apply_dup(&mut files, call, event);
            forget_closed(&mut files, call, event);
            inherit_open_fds(&mut files, call, event, &cookies);
            index.observe(&files, call, event, None);
            index.observe_hashes(&files, call, event);
        }
        index
    }

    #[test]
    fn a_written_file_shows_the_hash_of_its_last_close() {
        let calls = [
            create(2, "/tmp/out", 40, 1),
            operation(3, 1, "write", 5, [3, 0, 5, 0, 0, 0], b"hello"),
            // Carried by the task's last call, which names no file.
            with_write_hash(operation(4, 231, "exit_group", 0, [0; 6], b""), 40, 0),
        ];
        let changes = index_with_hashes(&calls, &[]).finish();
        let change = changes
            .iter()
            .find(|change| change.path == "/tmp/out")
            .unwrap();
        let text = change.lifecycle_text();
        assert!(
            text.ends_with("closed after write · SHA-256 cdcdcdcdcdcd…"),
            "{text}"
        );
        let row = change.row(None);
        let value = row[0]
            .values
            .iter()
            .find(|(name, _)| *name == "file.sha256")
            .map(|(_, value)| value.clone());
        assert!(matches!(value, Some(RowValue::Text(hex)) if hex == "cd".repeat(32)));
        // A refused hash says why instead.
        let refused = [
            create(2, "/tmp/big", 41, 1),
            operation(3, 1, "write", 5, [3, 0, 5, 0, 0, 0], b"hello"),
            with_write_hash(operation(4, 3, "close", 0, [3, 0, 0, 0, 0, 0], b""), 41, 1),
        ];
        let changes = index_with_hashes(&refused, &[]).finish();
        assert!(changes[0].lifecycle_text().contains("no hash: file is"));
    }

    #[test]
    fn a_reconnect_between_two_operations_of_a_file_is_marked() {
        let calls = [
            create(2, "/tmp/long", 50, 1),
            operation(3, 1, "write", 5, [3, 0, 5, 0, 0, 0], b"hello"),
            operation(4, 1, "write", 5, [3, 0, 5, 0, 0, 0], b"again"),
        ];
        let changes = index_with_hashes(&calls, &[0, 0, 1]).finish();
        let change = &changes[0];
        assert!(
            change.lifecycle_text().contains("reconnected"),
            "{}",
            change.lifecycle_text()
        );
        let marker = change
            .operations
            .iter()
            .position(|op| {
                op.name
                    .contains("transport reconnected · recording segment 2")
            })
            .unwrap();
        assert_eq!(marker, 2, "between the write before and the write after");
        // A file whose story is all in one segment has none.
        let changes = index_with_hashes(&calls, &[1, 1, 1]).finish();
        assert!(!changes[0].lifecycle_text().contains("reconnected"));
    }

    use super::file_activity::{Activity, FileActivity, Kind};

    fn activity_of(calls: &[InvocationSummary]) -> Activity {
        build(calls).0.finish_all().1
    }

    fn file<'a>(activity: &'a Activity, path: &str) -> &'a FileActivity {
        activity
            .files
            .iter()
            .find(|file| file.path == path)
            .unwrap_or_else(|| {
                panic!(
                    "{path} not in {:?}",
                    activity.files.iter().map(|f| &f.path).collect::<Vec<_>>()
                )
            })
    }

    fn kinds(file: &FileActivity) -> Vec<Kind> {
        file.events.iter().map(|event| event.kind).collect()
    }

    #[test]
    fn the_activity_lists_every_file_touched_and_tells_each_ones_story_in_order() {
        let calls = [
            // Only looked at: opened and read, never changed.
            named(1, 2, "open", 3, [0, 0, 0, 0, 0, 0], &["/etc/hosts"]),
            operation(2, 0, "read", 4, [3, 0, 4, 0, 0, 0], b"host"),
            // Made, written, renamed, linked and removed.
            create(3, "/tmp/a", 100, 1),
            operation(4, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"x"),
            identified(
                named(5, 82, "rename", 0, [0; 6], &["/tmp/a", "/tmp/b"]),
                2,
                1,
                100,
            ),
            identified(named(6, 87, "unlink", 0, [0; 6], &["/tmp/b"]), 4, 0, 100),
            // Only its attributes were asked for.
            named(7, 4, "stat", 0, [0; 6], &["/tmp/probed"]),
        ];
        let activity = activity_of(&calls);
        assert_eq!(
            activity
                .files
                .iter()
                .map(|f| f.path.as_str())
                .collect::<Vec<_>>(),
            ["/etc/hosts", "/tmp/a", "/tmp/probed"],
            "every touched file, in order of the first call"
        );
        let hosts = file(&activity, "/etc/hosts");
        assert_eq!(kinds(hosts), [Kind::Open, Kind::Read]);
        assert!(!hosts.changed() && !hosts.created && !hosts.deleted);
        let a = file(&activity, "/tmp/a");
        assert_eq!(
            kinds(a),
            [Kind::Create, Kind::Write, Kind::Rename, Kind::Delete]
        );
        assert_eq!(a.names, ["/tmp/b"], "the new name belongs to the same file");
        assert!(a.created && a.deleted && a.changed());
        assert_eq!(a.events[2].other_path.as_deref(), Some("/tmp/b"));
        assert_eq!(a.events[3].note, "last name removed");
        assert_eq!(a.summary(), "create → write → rename → delete");
        assert_eq!(kinds(file(&activity, "/tmp/probed")), [Kind::Probe]);
        // One process made every call.
        assert_eq!(activity.processes.len(), 1);
    }

    #[test]
    fn a_name_removed_while_another_link_remains_is_not_a_deletion() {
        let calls = [
            create(1, "/tmp/a", 100, 2),
            identified(named(2, 87, "unlink", 0, [0; 6], &["/tmp/a"]), 4, 1, 100),
        ];
        let activity = activity_of(&calls);
        let a = file(&activity, "/tmp/a");
        assert!(!a.deleted);
        assert_eq!(a.events[1].note, "1 link remains");
    }

    #[test]
    fn a_name_a_new_file_takes_over_is_a_second_entry_in_the_activity() {
        let calls = [
            create(1, "/tmp/a", 100, 1),
            identified(named(2, 87, "unlink", 0, [0; 6], &["/tmp/a"]), 4, 0, 100),
            create(3, "/tmp/a", 200, 1),
        ];
        let activity = activity_of(&calls);
        assert_eq!(activity.files.len(), 2);
        assert!(activity.files[0].deleted);
        assert!(!activity.files[1].deleted && activity.files[1].created);
    }

    #[test]
    fn a_rename_without_identity_moves_the_name_to_the_file_for_later_calls() {
        let calls = [
            named(1, 2, "open", 3, [0, 0x42, 0, 0, 0, 0], &["/tmp/a"]),
            named(2, 82, "rename", 0, [0; 6], &["/tmp/a", "/tmp/b"]),
            // A call by the new name reaches the renamed file.
            named(3, 87, "unlink", 0, [0; 6], &["/tmp/b"]),
        ];
        let activity = activity_of(&calls);
        assert_eq!(activity.files.len(), 1, "{:?}", activity.files);
        assert_eq!(
            kinds(&activity.files[0]),
            [Kind::Create, Kind::Rename, Kind::Delete]
        );
    }

    #[test]
    fn writes_keep_their_offset_length_and_captured_bytes_and_say_when_they_extend_the_file() {
        let calls = [
            open(2),
            operation(2, 0, "read", 5, [3, 0, 5, 0, 0, 0], b"ABCDE"),
            operation(3, 0, "read", 0, [3, 0, 5, 0, 0, 0], b""),
            // Overwrites two bytes of what the run read.
            operation(4, 18, "pwrite64", 2, [3, 0, 2, 1, 0, 0], b"zz"),
            // Writes at the descriptor's position, past the end.
            operation(5, 1, "write", 3, [3, 0, 3, 0, 0, 0], b"xyz"),
            // The kernel captured none of these bytes.
            operation(6, 1, "write", 4, [3, 0, 4, 0, 0, 0], b""),
        ];
        let activity = activity_of(&calls);
        let file = file(&activity, "/tmp/file");
        let writes: Vec<_> = file
            .events
            .iter()
            .filter(|event| event.kind == Kind::Write)
            .collect();
        assert_eq!(writes.len(), 3);
        assert_eq!(
            (
                writes[0].offset,
                writes[0].len,
                writes[0].content.as_slice()
            ),
            (Some(1), Some(2), &b"zz"[..])
        );
        assert!(!writes[0].extends, "inside the file as far as it was read");
        assert_eq!(
            (
                writes[1].offset,
                writes[1].len,
                writes[1].content.as_slice()
            ),
            (Some(5), Some(3), &b"xyz"[..])
        );
        assert!(writes[1].extends);
        assert_eq!((writes[2].offset, writes[2].len), (Some(8), Some(4)));
        assert!(writes[2].content.is_empty(), "never invented");
        let read = &file.events[1];
        assert_eq!(
            (read.kind, read.offset, read.len, read.content.as_slice()),
            (Kind::Read, Some(0), Some(5), &b"ABCDE"[..])
        );
        // What the run changed, from what it read and what it wrote.
        let runs = &file.contents.runs;
        assert_eq!(runs[0].offset, 1);
        assert_eq!(runs[0].before, [Some(b'B'), Some(b'C')]);
        assert_eq!(runs[0].after, [Some(b'z'), Some(b'z')]);
        assert_eq!(runs[1].offset, 5, "added past the known end");
        assert_eq!(runs[1].before, [None, None, None]);
        assert_eq!(file.contents.original_size, Some(5));
    }

    #[test]
    fn an_append_or_a_shared_descriptor_has_a_length_and_no_offset() {
        let calls = [
            open(0x401),
            operation(2, 1, "write", 2, [3, 0, 2, 0, 0, 0], b"ab"),
        ];
        let activity = activity_of(&calls);
        let write = &file(&activity, "/tmp/file").events[1];
        assert_eq!(
            (write.kind, write.offset, write.len),
            (Kind::Write, None, Some(2))
        );
        assert_eq!(write.content, b"ab");
    }

    #[test]
    fn a_refused_call_is_listed_and_a_file_with_only_refusals_is_marked() {
        let calls = [
            named(1, 2, "open", -2, [0; 6], &["/tmp/missing"]),
            open(0),
            operation(3, 0, "read", -9, [3, 0, 4, 0, 0, 0], b""),
        ];
        let activity = activity_of(&calls);
        let missing = file(&activity, "/tmp/missing");
        assert!(missing.failed_only);
        assert_eq!(missing.events[0].success, Some(false));
        assert!(missing.events[0].result.starts_with("Failed"));
        let seen = file(&activity, "/tmp/file");
        assert!(!seen.failed_only, "the open worked");
        assert_eq!(seen.events[1].success, Some(false));
        assert!(!seen.changed());
    }

    #[test]
    fn a_files_calls_and_the_files_are_bounded_and_the_rest_counted() {
        let mut calls = vec![open(2)];
        for id in 0..600u64 {
            calls.push(operation(id + 2, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"x"));
        }
        let activity = activity_of(&calls);
        let file = file(&activity, "/tmp/file");
        assert_eq!(file.events.len(), 512);
        assert_eq!(file.omitted, 601 - 512);
        assert_eq!(activity.omitted_events, file.omitted);
    }

    #[test]
    fn the_guests_hashes_join_the_files_history_in_order() {
        let calls = [
            create(1, "/tmp/h", 50, 1),
            with_write_hash(
                operation(2, 1, "write", 5, [3, 0, 5, 0, 0, 0], b"hello"),
                50,
                0,
            ),
            // The guest could not hash the file the second time.
            with_write_hash(
                operation(3, 1, "write", 5, [3, 0, 5, 0, 0, 0], b"again"),
                50,
                1,
            ),
        ];
        let activity = index_with_hashes(&calls, &[]).finish_all().1;
        let hashes = &file(&activity, "/tmp/h").hashes;
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0].moment, "closed after write");
        assert_eq!(hashes[0].sha256.as_deref(), Some("cd".repeat(32).as_str()));
        assert!(hashes[1].sha256.is_none() && hashes[1].skipped.is_some());
        assert!(file(&activity, "/tmp/h")
            .events
            .iter()
            .all(|e| e.via.is_none()));
    }

    /// A write whose payload sits in a recording's object store: the field
    /// names a file under `objects/` and the range says how much of it exists.
    fn stored_write(
        id: u64,
        offset: u64,
        size: u64,
        object: &str,
        ranges: Vec<(u64, u64)>,
    ) -> InvocationSummary {
        let mut call = operation(
            id,
            18,
            "pwrite64",
            size as i64,
            [3, 0, size, offset, 0, 0],
            b"",
        );
        let mut field = captured("arg1.data", "", b"");
        field.raw_path = Some(PathBuf::from(format!("objects/{object}")));
        field.logical_len = Some(size);
        field.ranges = ranges;
        call.entry.as_mut().unwrap().fields.push(field);
        call
    }

    fn scratch(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("ant-write-content-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("objects")).unwrap();
        root
    }

    fn activity_in(
        calls: &[InvocationSummary],
        directory: &Path,
        limits: antinomie_monitor_core::file_writes::Limits,
    ) -> Activity {
        let mut index = FileIndex::default();
        index.set_write_limits(limits);
        let mut files = FdState::default();
        let cookies = task_cookies(calls);
        for call in calls {
            let event = trace::representative(call).unwrap();
            remember_cwd(&mut files, call, event);
            remember_open(&mut files, call, event);
            apply_dup(&mut files, call, event);
            forget_closed(&mut files, call, event);
            inherit_open_fds(&mut files, call, event, &cookies);
            index.observe(&files, call, event, Some(directory));
        }
        index.finish_all().1
    }

    #[test]
    fn a_file_written_in_many_small_blocks_comes_back_byte_for_byte_beyond_the_event_bound() {
        let root = scratch("blocks");
        let mut expected: Vec<u8> = Vec::new();
        let mut calls = vec![open(0x41)];
        // 700 blocks of 4 bytes: more writes than the 512 events a file lists.
        for index in 0..700u64 {
            let block: Vec<u8> = (0..4).map(|n| (index * 7 + n) as u8).collect();
            std::fs::write(root.join(format!("objects/b{index}.raw")), &block).unwrap();
            expected.extend(&block);
            calls.push(stored_write(
                index + 2,
                index * 4,
                4,
                &format!("b{index}.raw"),
                vec![(0, 4)],
            ));
        }
        let activity = activity_in(&calls, &root, Default::default());
        let file = file(&activity, "/tmp/file");
        assert_eq!(
            file.events.iter().filter(|e| e.kind == Kind::Write).count(),
            511
        );
        assert_eq!(file.writes.read(0, 2800).unwrap(), expected);
        assert_eq!(file.writes.tally.kept, 2800);
        assert_eq!(activity.written.kept, 2800);
        assert_eq!(activity.written.skipped(), 0);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn past_the_cap_the_first_writes_are_kept_and_the_rest_is_shown_as_not_captured() {
        let root = scratch("cap");
        let mut calls = vec![open(0x41)];
        for index in 0..4u64 {
            std::fs::write(
                root.join(format!("objects/c{index}.raw")),
                [b'a' + index as u8; 10],
            )
            .unwrap();
            calls.push(stored_write(
                index + 2,
                index * 10,
                10,
                &format!("c{index}.raw"),
                vec![(0, 10)],
            ));
        }
        let limits = antinomie_monitor_core::file_writes::Limits {
            per_file: 25,
            per_run: 1 << 30,
        };
        let activity = activity_in(&calls, &root, limits);
        let file = file(&activity, "/tmp/file");
        let kept = file.writes.read(0, 25).unwrap();
        assert_eq!(&kept[..10], [b'a'; 10]);
        assert_eq!(&kept[20..], [b'c'; 5]);
        assert_eq!(
            file.writes.read(0, 26),
            Err(antinomie_monitor_core::file_writes::ReadError::NotCaptured(
                25
            ))
        );
        assert_eq!((activity.written.kept, activity.written.file_cap), (25, 15));
        assert_eq!(activity.limits, limits);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn bytes_the_kernel_did_not_capture_stay_gaps_in_the_written_content() {
        let root = scratch("gap");
        std::fs::write(root.join("objects/g.raw"), b"\0\0abc").unwrap();
        // 10 bytes written; the object holds bytes 2..5 only.
        let calls = [open(0x41), stored_write(2, 100, 10, "g.raw", vec![(2, 3)])];
        let activity = activity_in(&calls, &root, Default::default());
        let file = file(&activity, "/tmp/file");
        assert_eq!(file.writes.read(102, 3).unwrap(), b"abc");
        assert!(file.writes.read(100, 10).is_err());
        assert_eq!(activity.written.not_recorded, 7);
        assert!(file.events.iter().any(|e| e.content_gap));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_recording_without_object_files_keeps_the_inline_preview() {
        let calls = [
            open(0x41),
            operation(2, 18, "pwrite64", 3, [3, 0, 3, 8, 0, 0], b"xyz"),
        ];
        let activity = activity_of(&calls);
        let file = file(&activity, "/tmp/file");
        assert_eq!(file.writes.read(8, 3).unwrap(), b"xyz");
    }

    fn position(offset: u64, len: u64) -> antinomie_monitor_core::api::FieldSummary {
        ordered_position(offset, len, 0)
    }

    fn ordered_position(
        offset: u64,
        len: u64,
        order: u64,
    ) -> antinomie_monitor_core::api::FieldSummary {
        let bytes = [offset.to_le_bytes(), len.to_le_bytes(), order.to_le_bytes()].concat();
        captured("file.position", "antinomie.filepos/1", &bytes)
    }

    /// A file.copy record into /tmp/file (fd 3, ino 30) at `offset`.
    fn copy_record(
        kind: u8,
        flags: u8,
        len: u64,
        offset: u64,
        source_mode: u32,
        size: u64,
        data: u32,
    ) -> antinomie_monitor_core::api::FieldSummary {
        let mut bytes = vec![kind, flags, 0, 0, 0, 0, 0, 0];
        bytes.extend(len.to_le_bytes());
        bytes.extend(0u64.to_le_bytes());
        bytes.extend(offset.to_le_bytes());
        for (ino, mode) in [(20u64, source_mode), (30, 0o100644)] {
            bytes.extend(0xfe00u64.to_le_bytes());
            bytes.extend(ino.to_le_bytes());
            bytes.extend(0u32.to_le_bytes());
            bytes.extend(mode.to_le_bytes());
        }
        bytes.extend(size.to_le_bytes());
        bytes.extend(data.to_le_bytes());
        bytes.extend([0; 4]);
        bytes.extend(0u64.to_le_bytes());
        captured("file.copy", "antinomie.filecopy/1", &bytes)
    }

    #[test]
    fn racing_writes_are_replayed_in_the_order_the_file_system_applied_them() {
        // Applied as 1, 2, 3 under the inode lock; write 2's exit came last.
        let write = |id: u64, data: &[u8], offset: u64, order: u64| {
            let len = data.len() as u64;
            let mut call = operation(
                id,
                18,
                "pwrite64",
                len as i64,
                [3, 0, len, offset, 0, 0],
                data,
            );
            call.exit
                .as_mut()
                .unwrap()
                .fields
                .push(ordered_position(offset, len, order));
            call
        };
        let calls = [
            open(2),
            write(2, b"AAAA", 0, 1),
            write(3, b"CCCC", 0, 3),
            write(4, b"BBBB", 2, 2),
        ];
        let (index, _) = build(&calls);
        let change = &index.finish()[0];
        let bytes: Vec<u8> = (0..6)
            .filter_map(|at| change.final_data.get(&at).copied())
            .collect();
        assert_eq!(bytes, b"CCCCBB", "trace order would give CCBBBB");
        let activity = activity_of(&calls);
        assert_eq!(
            file(&activity, "/tmp/file").writes.read(0, 6).unwrap(),
            b"CCCCBB"
        );
    }

    #[test]
    fn the_position_the_guest_recorded_places_an_append_and_a_shared_descriptor() {
        // O_APPEND: the host alone cannot know where the bytes landed.
        let mut append = operation(2, 1, "write", 2, [3, 0, 2, 0, 0, 0], b"ab");
        append.exit.as_mut().unwrap().fields.push(position(7, 2));
        // The next write through the same descriptor follows the real position.
        let next = operation(3, 1, "write", 1, [3, 0, 1, 0, 0, 0], b"c");
        let activity = activity_of(&[open(0x401), append, next]);
        let file = file(&activity, "/tmp/file");
        assert_eq!(
            (file.events[1].offset, file.events[1].len),
            (Some(7), Some(2))
        );
        assert_eq!(file.writes.read(7, 2).unwrap(), b"ab");
        assert_eq!(
            activity.written.offset_unknown, 1,
            "no record: an append stays unplaced"
        );
    }

    #[test]
    fn a_copy_from_a_socket_puts_the_carried_bytes_at_the_recorded_offset() {
        let mut sendfile = operation(2, 40, "sendfile", 3, [3, 5, 0, 3, 0, 0], b"");
        let exit = sendfile.exit.as_mut().unwrap();
        exit.fields
            .push(copy_record(1, 2 | 4, 3, 4, 0o140777, 7, 3));
        exit.fields.push(captured("file.copy.data", "", b"xyz"));
        let activity = activity_of(&[open(0x1), sendfile]);
        let file = file(&activity, "/tmp/file");
        let event = file.events.iter().find(|e| e.kind == Kind::Write).unwrap();
        assert_eq!((event.offset, event.len), (Some(4), Some(3)));
        assert_eq!(event.content, b"xyz");
        assert_eq!(file.writes.read(4, 3).unwrap(), b"xyz");
    }

    #[test]
    fn a_copy_from_another_file_changes_only_its_range_and_says_where_the_bytes_came_from() {
        let mut write = operation(2, 18, "pwrite64", 8, [3, 0, 8, 0, 0, 0], b"abcdefgh");
        write.exit.as_mut().unwrap().fields.push(position(0, 8));
        let mut copy = operation(3, 326, "copy_file_range", 2, [5, 0, 3, 0, 2, 0], b"");
        copy.exit
            .as_mut()
            .unwrap()
            .fields
            .push(copy_record(3, 1 | 2, 2, 2, 0o100644, 8, 0));
        let (index, _) = build(&[open(0x2), write, copy]);
        let change = index.changes.get("/tmp/file").unwrap();
        let known: Vec<u64> = change.final_data.keys().copied().collect();
        assert_eq!(known, [0, 1, 4, 5, 6, 7]);
        assert_eq!(change.final_size, Some(8));
        assert!(change
            .gaps
            .iter()
            .any(|gap| gap.starts_with("In-kernel copy from another file")));
        assert!(!change
            .gaps
            .iter()
            .any(|gap| gap.starts_with("Kernel-mediated transfer")));
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The steps of observing one call: the descriptor tables, the read row and the file's change.
use super::*;
use antinomie_monitor_core::kernel_notes::{FileCopy, FilePosition};

/// What one call is, as the descriptor tables read it.
#[derive(Clone, Copy)]
pub(super) struct CallFacts<'a> {
    pub(super) name: &'a str,
    pub(super) args: Option<[u64; 6]>,
    pub(super) ret: Option<i64>,
    pub(super) success: bool,
    pub(super) owner: (u64, u32),
    pub(super) descriptor: Option<(u64, u32, u64)>,
}

/// What the Read row of a call is built from.
#[derive(Clone, Copy)]
pub(super) struct ReadRow<'a> {
    pub(super) files: &'a FdState,
    pub(super) call: &'a InvocationSummary,
    pub(super) event: &'a EventSummary,
    pub(super) name: &'a str,
    pub(super) ret: Option<i64>,
    pub(super) success: bool,
    pub(super) size: u64,
}

/// What a call did to its file, once its name and offset are settled.
pub(super) struct Observed<'a> {
    pub(super) files: &'a FdState,
    pub(super) call: &'a InvocationSummary,
    pub(super) event: &'a EventSummary,
    pub(super) hits: &'a [Hit],
    pub(super) name: &'a str,
    pub(super) args: Option<[u64; 6]>,
    pub(super) ret: Option<i64>,
    pub(super) success: bool,
    pub(super) reading: bool,
    pub(super) writing: bool,
    pub(super) failed: bool,
    pub(super) changed: bool,
    pub(super) identity: Option<FileId>,
    pub(super) description: Option<u64>,
    pub(super) offset: Option<u64>,
    pub(super) size: u64,
    pub(super) bytes: &'a CapturedPayload,
    pub(super) copied: &'a CapturedPayload,
    pub(super) explicit: bool,
    pub(super) kernel_position: Option<FilePosition>,
    pub(super) copy: Option<FileCopy>,
    pub(super) path_known: bool,
}

impl FileIndex {
    /// The descriptor tables after this call: the open file description it
    /// created and the one its descriptor leads to.
    pub(super) fn track_descriptors(
        &mut self,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
        facts: &CallFacts<'_>,
    ) -> (Option<u64>, Option<u64>) {
        let CallFacts {
            name,
            args,
            ret,
            success,
            owner,
            descriptor,
        } = *facts;
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
        if success
            && matches!(
                event.syscall_name.as_str(),
                "clone" | "clone3" | "fork" | "vfork"
            )
        {
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
        (opened_description, description)
    }

    /// Fold the call into the file's change: its names, operations, data and gaps.
    pub(super) fn apply_change(&mut self, observed: &Observed<'_>, group: String, path: String) {
        let Observed {
            files,
            call,
            event,
            hits,
            name,
            args,
            ret,
            success,
            reading,
            writing,
            failed,
            changed,
            identity,
            description,
            offset,
            size,
            bytes,
            copied,
            explicit,
            kernel_position,
            copy,
            path_known,
        } = *observed;
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
        let stored_before = change.stored();
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
                process: process_cells::task_label(
                    event.pid,
                    event.tid,
                    process_image(files, event),
                ),
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
                    change.final_data.remove_replaced(&newer, offset, size);
                    change.modified = true;
                    change.final_size = change.final_size.and_then(|size_before| {
                        offset.checked_add(size).map(|end| size_before.max(end))
                    });
                }
                let was_modified = change.modified;
                let mut budget = retention::Budget {
                    used: &mut self.retained_octets,
                    retention: self.retention,
                    call: trace::key(call),
                };
                change.store(
                    offset,
                    order::outside(&newer, offset, bytes.iter()),
                    !was_modified,
                    &mut budget,
                );
                change.note_applied(kernel_position, offset, size);
            } else if size > 0 {
                change.gaps.insert("File offset unavailable (inherited/shared descriptor, append or missing seek); transferred bytes cannot be placed safely.");
                if writing {
                    change.final_data.clear();
                    change.modified = true;
                }
            }
            if bytes.len() as u64 != size {
                change.note_short_capture(trace::key(call), size, bytes.len() as u64);
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
            let mut budget = retention::Budget {
                used: &mut self.retained_octets,
                retention: self.retention,
                call: trace::key(call),
            };
            change.kernel_copy(&copy, copied, &mut budget);
        } else if success && changed {
            match name {
                "truncate" | "ftruncate" => {
                    let size = args.map(|args| args[1]);
                    if let Some(size) = size {
                        change.final_data.truncate(size);
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
        self.retained_octets =
            (self.retained_octets + change.stored()).saturating_sub(stored_before);
    }
}

/// One Read files row; `content` is None when the kernel moved the
/// bytes itself and none were captured.
pub(super) fn read_cells(
    context: &ReadRow<'_>,
    path: &str,
    path_known: bool,
    fd: Option<u64>,
    content: Option<&CapturedPayload>,
) -> Vec<Cell> {
    let ReadRow {
        files,
        call,
        event,
        name,
        ret,
        success,
        size,
    } = *context;
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
            process_cells::task_label(event.pid, event.tid, process_image(files, event)),
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
}

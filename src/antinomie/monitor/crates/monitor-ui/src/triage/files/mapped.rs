// SPDX-License-Identifier: GPL-3.0-only
//! Pages a run wrote through a shared mapping of a file (contract revision 18,
//! `lifecycle.file_mapped`). A store into a mapping is no call; the guest
//! copies the pages when a call writes them back (msync, fsync) or drops them
//! dirty (munmap, exec, exit), so the file's bytes are known as they were at
//! that moment, never each store in between. The records name the file by
//! its identity and come with the call the guest attached them to.
use super::*;
use antinomie_monitor_core::kernel_notes::{FileMapped, MappedCause};

const MAPPED_GAP: &str = "Written through a shared mapping: each page is known as it was when written back or unmapped; the stores in between are not seen.";
const UNCOPIED_GAP: &str = "Pages written through a shared mapping that the guest did not copy (its per-call budget, or memory): their bytes are unknown.";
const UNLISTED_GAP: &str = "A call wrote more pages through mappings than the guest lists: where the others were and what they held is unknown.";

/// An msync whose pages a revision-18 guest named, with their bytes: the
/// records place them (the call itself names no file).
pub(super) fn synced_named_pages(call: &InvocationSummary, name: &str) -> bool {
    name == "msync" && !kernel_records::file_mapped(call, true).is_empty()
}

impl FileIndex {
    /// The pages written through mappings that `call`'s task wrote back or
    /// dropped dirty: those the guest published before the call's exit
    /// (`before_exit`, applied before the call's own change, which the copies
    /// precede), or after it (the address space dropped at the task's exit).
    pub fn observe_mapped(
        &mut self,
        files: &FdState,
        call: &InvocationSummary,
        event: &EventSummary,
        directory: Option<&Path>,
        before_exit: bool,
    ) {
        for (record, data) in kernel_records::file_mapped(call, before_exit) {
            let copied = data
                .map(|field| file_content::field_capture(field, directory, record.carried))
                .unwrap_or_default();
            let stretches = data
                .map(|field| {
                    file_content::field_stretches(
                        field,
                        directory,
                        record.carried,
                        &mut self.interned,
                    )
                })
                .unwrap_or_default();
            let group = self.mapped_group(&record);
            let named = group
                .split('\u{0}')
                .next()
                .filter(|name| !name.is_empty())
                .map(str::to_owned);
            self.activity.mapped(file_activity::Mapped {
                record: &record,
                path: named.as_deref(),
                call,
                event,
                image: process_image(files, event),
                stretches,
                content: copied.head(file_activity::CONTENT_HEAD),
            });
            if !self.changes.contains_key(&group) && self.changes.len() >= TRACKED_FILES {
                self.omitted_files += 1;
                continue;
            }
            let segment = self.segment;
            let change = self.changes.entry(group).or_insert_with(|| Change {
                segment,
                path: named
                    .clone()
                    .unwrap_or_else(|| format!("inode {}:{}", record.file.dev, record.file.ino)),
                path_known: named.is_some(),
                identity: Some(record.file),
                process_image: process_image(files, event).map(str::to_owned),
                call: call.call_id,
                key: trace::key(call),
                first_ns: record.time_ns,
                pid: event.pid,
                tid: event.tid,
                ..Change::default()
            });
            change.cross_segment(segment, &mut self.operation_count);
            change.apply_mapped(&record, &copied, &mut self.retained_octets);
            if !change.changes {
                change.call = call.call_id;
                change.key = trace::key(call);
                change.first_ns = record.time_ns;
                change.pid = event.pid;
                change.tid = event.tid;
            }
            change.changes = true;
            if change.operations.len() < TIMELINE_ROWS && self.operation_count < TOTAL_OPERATIONS {
                change.operations.push(Operation {
                    time: record.time_ns,
                    call: call.call_id,
                    key: trace::key(call),
                    name: format!("{} · mapping", file_events::operation_label(call, event)),
                    process: process_identity(event.pid, event.tid, process_image(files, event)),
                    result: format!("{} B at 0x{:x}", record.len, record.offset),
                });
                self.operation_count += 1;
            }
        }
    }

    /// The group of the file `record` names: the one its identity already
    /// leads to, or a new one for a file no call named.
    fn mapped_group(&mut self, record: &FileMapped) -> String {
        if let Some(known) = self.by_identity.get(&record.file) {
            return known.clone();
        }
        let key = record.file;
        let group = format!("\u{0}id:{}:{}:{}", key.dev, key.ino, key.generation);
        let mut alias = None;
        self.route(key, group, None, &mut alias)
    }
}

impl Change {
    /// Lay the copied pages of `record` over what is known of the file. A
    /// write the file system applied after the copy (a higher write order)
    /// keeps its bytes.
    fn apply_mapped(
        &mut self,
        record: &FileMapped,
        copied: &CapturedPayload,
        retained: &mut usize,
    ) {
        let (offset, len) = (record.offset, record.len);
        let end = offset.saturating_add(len);
        self.modified = true;
        if !self.path_known {
            self.gaps.insert(PATH_GAP);
        }
        self.categories.insert(Category::Written.label());
        self.categories.insert(Category::Mapped.label());
        self.step(
            match record.cause {
                MappedCause::Writeback => "written back through a mapping",
                MappedCause::Unmap | MappedCause::Unknown(_) => "written through a mapping",
            }
            .into(),
        );
        let newer = self.newer_than(record.order, offset, end);
        self.final_data
            .retain(|at, _| !super::order::replaced(&newer, offset, len, *at));
        self.place(
            offset,
            super::order::outside(&newer, offset, copied.iter()),
            retained,
        );
        self.note_order(record.order, offset, end);
        self.final_size = Some(record.size);
        self.final_data.retain(|at, _| *at < record.size);
        self.gaps.insert(MAPPED_GAP);
        if record.carried < len {
            self.gaps.insert(UNCOPIED_GAP);
        } else if (copied.len() as u64) < len {
            self.gaps.insert(
                "Transferred content contains capture gaps or exceeds the bounded byte preview.",
            );
        }
        if record.unlisted > 0 || record.lost > 0 {
            self.gaps.insert(UNLISTED_GAP);
        }
    }
}

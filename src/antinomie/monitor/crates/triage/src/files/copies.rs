// SPDX-License-Identifier: GPL-3.0-only
//! What the guest recorded of an in-kernel copy or an allocation into a file
//! (contract revision 18, `file.copy`): the exact range the call changed, the
//! file's size after it, and the bytes themselves when they came from a pipe. Without the record the whole file's known bytes are dropped,
//! because neither the range nor the content is known.
use super::*;
use antinomie_monitor_core::file_writes::Captured;
use antinomie_monitor_core::kernel_notes::{CopyKind, FileCopy};

pub const COPY_GAP: &str = "In-kernel copy from another file: the range it changed is known, its bytes come from that file and are not rebuilt here.";
pub const CUT_GAP: &str =
    "In-kernel copy from a pipe: the guest carried only part of the bytes it moved.";
pub const SHIFT_GAP: &str =
    "Range collapsed or inserted (fallocate): the bytes after it moved and are not rebuilt.";

impl Change {
    /// Apply `copy` to this file, its destination. `data` is what the guest
    /// carried (from the destination offset on). A destination without a
    /// position (a pipe, a socket) is not a file this index rebuilds.
    pub fn kernel_copy(
        &mut self,
        copy: &FileCopy,
        data: &CapturedPayload,
        budget: &mut super::retention::Budget<'_>,
    ) {
        let Some(offset) = copy.destination.offset else {
            return;
        };
        let end = offset.saturating_add(copy.len);
        match copy.kind {
            CopyKind::Fallocate
                if copy.mode & (FileCopy::COLLAPSE_RANGE | FileCopy::INSERT_RANGE) != 0 =>
            {
                self.modified = true;
                self.final_data.truncate(offset);
                self.gaps.insert(SHIFT_GAP);
            }
            CopyKind::Fallocate
                if copy.mode & (FileCopy::PUNCH_HOLE | FileCopy::ZERO_RANGE) != 0 =>
            {
                self.modified = true;
                self.final_data.remove_range(offset, end);
                // The range reads back as zeros, up to the end of the file.
                let size = copy.destination_size.unwrap_or(end);
                let zeros = (0..end.min(size).saturating_sub(offset)).map(|at| (at, 0u8));
                self.store(offset, zeros, false, budget);
            }
            // A plain allocation adds zeros past the end and changes nothing else.
            CopyKind::Fallocate => {}
            _ => {
                self.modified = true;
                // Bytes a racing write the file system applied later holds.
                let newer = self.newer_than(copy.order, offset, end);
                self.final_data.remove_replaced(&newer, offset, copy.len);
                self.store(
                    offset,
                    super::order::outside(&newer, offset, data.iter()),
                    false,
                    budget,
                );
                self.note_order(copy.order, offset, end);
                if (data.len() as u64) < copy.len {
                    let from_file = copy.source.is_some_and(|source| source.regular());
                    self.gaps.insert(if from_file { COPY_GAP } else { CUT_GAP });
                }
            }
        }
        if let Some(size) = copy.destination_size {
            self.final_data.truncate(size);
            self.final_size = Some(size);
        }
    }
}

/// The File activity entry of a copy into a file with positions: where it
/// wrote, how much, and the first bytes when the guest carried them.
pub fn copy_transfer(
    copy: &FileCopy,
    data: &CapturedPayload,
    known_size: Option<u64>,
    stretches: Vec<Captured>,
) -> Option<file_activity::Transfer> {
    let offset = copy.destination.offset?;
    (copy.kind != CopyKind::Fallocate).then(|| file_activity::Transfer {
        stream: false,
        write: true,
        offset: Some(offset),
        len: copy.len,
        stretches,
        content: data.head(file_activity::CONTENT_HEAD),
        gap: (data.len() as u64) < copy.len,
        extends: known_size.is_some_and(|known| offset.saturating_add(copy.len) > known),
        order: copy.order,
    })
}

/// Bookkeeping of the names and descriptors that lead to a file.
impl FileIndex {
    /// The kernel revision of the run's base, when the run recorded it.
    pub fn set_kernel_revision(&mut self, revision: Option<u32>) {
        self.kernel_revision = revision;
        self.activity.set_kernel_revision(revision);
    }

    /// From revision 18 the guest records the position of every read and
    /// write on a regular file or block device. A successful transfer (not a
    /// copy) whose exit came whole without one had no position to record: it
    /// went to a terminal, pipe or socket. `kernel_revision` is the base's.
    pub fn is_stream(&self, call: &InvocationSummary, position: bool) -> bool {
        !position
            && call.exit.as_ref().is_some_and(|exit| exit.complete)
            && self.kernel_revision.is_some_and(|revision| revision >= 18)
    }

    pub fn remember_alias(&mut self, group: &str, alias: Option<String>) {
        if let Some(alias) = alias {
            let names = self.aliases.entry(group.to_owned()).or_default();
            if names.len() < 16 && !names.contains(&alias) {
                names.push(alias);
            }
        }
    }

    pub fn bind_description(&mut self, description: u64, group: String) {
        if self.description_group.len() < 65536 {
            self.description_group.insert(description, group);
        }
    }
}

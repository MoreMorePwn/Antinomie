// SPDX-License-Identifier: GPL-3.0-only
//! What the guest recorded of an in-kernel copy or an allocation into a file
//! (contract revision 18, `file.copy`): the exact range the call changed, the
//! file's size after it, and the bytes themselves when they came from a pipe. Without the record the whole file's known bytes are dropped,
//! because neither the range nor the content is known.
use super::*;
use antinomie_monitor_core::file_writes::Captured;
use antinomie_monitor_core::kernel_notes::{CopyKind, FileCopy};

const COPY_GAP: &str = "In-kernel copy from another file: the range it changed is known, its bytes come from that file and are not rebuilt here.";
const CUT_GAP: &str =
    "In-kernel copy from a pipe: the guest carried only part of the bytes it moved.";
const SHIFT_GAP: &str =
    "Range collapsed or inserted (fallocate): the bytes after it moved and are not rebuilt.";

impl Change {
    /// Apply `copy` to this file, its destination. `data` is what the guest
    /// carried (from the destination offset on). A destination without a
    /// position (a pipe, a socket) is not a file this index rebuilds.
    pub(super) fn kernel_copy(
        &mut self,
        copy: &FileCopy,
        data: &CapturedPayload,
        retained: &mut usize,
    ) {
        let Some(offset) = copy.destination.offset else {
            return;
        };
        let end = offset.saturating_add(copy.len);
        let in_range = |at: &u64| *at >= offset && *at < end;
        match copy.kind {
            CopyKind::Fallocate
                if copy.mode & (FileCopy::COLLAPSE_RANGE | FileCopy::INSERT_RANGE) != 0 =>
            {
                self.modified = true;
                self.final_data.retain(|at, _| *at < offset);
                self.gaps.insert(SHIFT_GAP);
            }
            CopyKind::Fallocate
                if copy.mode & (FileCopy::PUNCH_HOLE | FileCopy::ZERO_RANGE) != 0 =>
            {
                self.modified = true;
                self.final_data.retain(|at, _| !in_range(at));
                // The range reads back as zeros, up to the end of the file.
                let size = copy.destination_size.unwrap_or(end);
                let zeros = (0..end.min(size).saturating_sub(offset)).map(|at| (at, 0u8));
                self.place(offset, zeros, retained);
            }
            // A plain allocation adds zeros past the end and changes nothing else.
            CopyKind::Fallocate => {}
            _ => {
                self.modified = true;
                // Bytes a racing write the file system applied later holds.
                let newer = self.newer_than(copy.order, offset, end);
                self.final_data
                    .retain(|at, _| !super::order::replaced(&newer, offset, copy.len, *at));
                self.place(
                    offset,
                    super::order::outside(&newer, offset, data.iter()),
                    retained,
                );
                self.note_order(copy.order, offset, end);
                if (data.len() as u64) < copy.len {
                    let from_file = copy.source.is_some_and(|source| source.regular());
                    self.gaps.insert(if from_file { COPY_GAP } else { CUT_GAP });
                }
            }
        }
        if let Some(size) = copy.destination_size {
            self.final_data.retain(|at, _| *at < size);
            self.final_size = Some(size);
        }
    }

    /// Put `bytes` (relative offset, value) at `offset`, within the retention
    /// limits.
    pub(super) fn place(
        &mut self,
        offset: u64,
        bytes: impl Iterator<Item = (u64, u8)>,
        retained: &mut usize,
    ) {
        for (relative, byte) in bytes {
            let Some(at) = offset.checked_add(relative) else {
                break;
            };
            if self.final_data.len() >= TRACKED_OCTETS || *retained >= TOTAL_OCTETS {
                self.gaps.insert("Byte reconstruction retention limit reached; more captured data may exist in syscall evidence.");
                break;
            }
            if self.final_data.insert(at, byte).is_none() {
                *retained += 1;
            }
        }
    }
}

/// The File activity entry of a copy into a file with positions: where it
/// wrote, how much, and the first bytes when the guest carried them.
pub(super) fn copy_transfer(
    copy: &FileCopy,
    data: &CapturedPayload,
    known_size: Option<u64>,
    stretches: Vec<Captured>,
) -> Option<file_activity::Transfer> {
    let offset = copy.destination.offset?;
    (copy.kind != CopyKind::Fallocate).then(|| file_activity::Transfer {
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
    pub(super) fn remember_alias(&mut self, group: &str, alias: Option<String>) {
        if let Some(alias) = alias {
            let names = self.aliases.entry(group.to_owned()).or_default();
            if names.len() < 16 && !names.contains(&alias) {
                names.push(alias);
            }
        }
    }
    pub(super) fn bind_description(&mut self, description: u64, group: String) {
        if self.description_group.len() < 65536 {
            self.description_group.insert(description, group);
        }
    }
}

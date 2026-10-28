// SPDX-License-Identifier: GPL-3.0-only
//! Writes that raced on one file, in the order the file system applied them.
//!
//! The host reads calls in the order their exits were recorded, which is not
//! the order two writers got the file's inode lock in. A revision-18 guest
//! numbers each write while the lock is held (the write order of
//! `file.position` and `file.copy`); a write that arrives after one with a
//! higher number keeps out of the bytes that later write already holds.
use super::Change;
use antinomie_monitor_core::kernel_notes::FilePosition;

/// Numbered writes remembered per file. Writes race only while they are in
/// flight together, so a short window is enough.
const APPLIED_KEPT: usize = 64;

impl Change {
    /// The parts of the `len` bytes at `from` that writes applied after the
    /// one at `position` hold (none for a read, which has no order).
    pub(super) fn newer(
        &self,
        position: Option<FilePosition>,
        from: u64,
        len: u64,
    ) -> Vec<(u64, u64)> {
        self.newer_than(
            position.and_then(|p| p.order),
            from,
            from.saturating_add(len),
        )
    }

    /// The parts of `[from, to)` that writes applied after `order` hold.
    pub(super) fn newer_than(&self, order: Option<u64>, from: u64, to: u64) -> Vec<(u64, u64)> {
        let Some(order) = order else {
            return Vec::new();
        };
        self.applied
            .iter()
            .filter(|(start, end, later)| *later > order && *start < to && *end > from)
            .map(|(start, end, _)| (*start, *end))
            .collect()
    }

    /// Remember the write at `position` of `len` bytes at `from`, when numbered.
    pub(super) fn note_applied(&mut self, position: Option<FilePosition>, from: u64, len: u64) {
        let order = position.and_then(|p| p.order);
        self.note_order(order, from, from.saturating_add(len));
    }

    /// Remember a numbered write of `[from, to)`.
    pub(super) fn note_order(&mut self, order: Option<u64>, from: u64, to: u64) {
        let Some(order) = order else {
            return;
        };
        if self.applied.len() >= APPLIED_KEPT {
            self.applied.remove(0);
        }
        self.applied.push((from, to, order));
    }
}

/// Whether `at` lies in one of `ranges`.
pub(super) fn covered(ranges: &[(u64, u64)], at: u64) -> bool {
    ranges.iter().any(|(start, end)| at >= *start && at < *end)
}

/// Whether a write of `len` bytes at `offset` replaced the byte at `at`: in
/// its range and not held by a write applied after it.
pub(super) fn replaced(newer: &[(u64, u64)], offset: u64, len: u64, at: u64) -> bool {
    at >= offset && at < offset.saturating_add(len) && !covered(newer, at)
}

/// The bytes of a transfer at `offset` (relative offset, value) that no write
/// applied after it holds.
pub(super) fn outside<'a>(
    newer: &'a [(u64, u64)],
    offset: u64,
    bytes: impl Iterator<Item = (u64, u8)> + 'a,
) -> impl Iterator<Item = (u64, u8)> + 'a {
    bytes.filter(move |(relative, _)| !covered(newer, offset.saturating_add(*relative)))
}

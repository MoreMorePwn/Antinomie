// SPDX-License-Identifier: GPL-3.0-only
//! What a call that is not a read or write did to a file's size or bytes, for
//! the File Reconstruction window: a resize, a range of zeros, a range that
//! changed to bytes the run did not see, a shared mapping.
use super::file_activity::Shape;
use antinomie_monitor_core::kernel_notes::{CopyKind, FileCopy};

/// The O_TRUNC bit of `open` flags.
const O_TRUNC: u64 = 0x200;
/// `mmap` protection and flag bits.
const PROT_WRITE: u64 = 0x2;
const MAP_TYPE: u64 = 0x3;
const MAP_PRIVATE: u64 = 0x2;
const MAP_ANONYMOUS: u64 = 0x20;

/// The effect of call `name` that succeeded (`success`) and changed the file
/// (`changed`). `copy` is the guest's record of an in-kernel copy or
/// allocation; `flags` are an open's flags. A transfer the guest placed is
/// not described here: its bytes are the file's writes.
pub(super) fn of(
    name: &str,
    args: Option<[u64; 6]>,
    copy: &Option<FileCopy>,
    flags: Option<u64>,
    success: bool,
    changed: bool,
) -> Option<Shape> {
    if !success {
        return None;
    }
    if crate::triage::file_events::OPEN_NAMES.contains(&name)
        && flags.is_some_and(|flags| flags & O_TRUNC != 0)
    {
        return Some(Shape::Resize(0));
    }
    // A shared writable mapping of the file: its range may change with no
    // further call. What a revision-18 guest saw written through it at
    // writeback or unmap comes as writes of its own (files/mapped.rs).
    if name == "mmap" {
        return args
            .filter(|args| {
                args[2] & PROT_WRITE != 0
                    && args[3] & MAP_TYPE != 0
                    && args[3] & MAP_TYPE != MAP_PRIVATE
                    && args[3] & MAP_ANONYMOUS == 0
            })
            .map(|args| Shape::Mapping {
                offset: args[5],
                len: args[1],
            });
    }
    if !changed {
        return None;
    }
    let everything = Shape::Changed {
        offset: 0,
        len: u64::MAX,
    };
    if let Some(copy) = copy.as_ref() {
        let offset = copy.destination.offset?;
        let end = offset.saturating_add(copy.len);
        return match copy.kind {
            CopyKind::Fallocate
                if copy.mode & (FileCopy::COLLAPSE_RANGE | FileCopy::INSERT_RANGE) != 0 =>
            {
                Some(Shape::Changed {
                    offset,
                    len: u64::MAX,
                })
            }
            CopyKind::Fallocate
                if copy.mode & (FileCopy::PUNCH_HOLE | FileCopy::ZERO_RANGE) != 0 =>
            {
                // The range reads back as zeros, up to the end of the file.
                let stop = end.min(copy.destination_size.unwrap_or(end));
                Some(Shape::Zero {
                    offset,
                    len: stop.saturating_sub(offset),
                })
            }
            // A plain allocation changes no byte; a placed copy is a write.
            _ => None,
        };
    }
    match name {
        "truncate" | "ftruncate" => args.map(|args| Shape::Resize(args[1])),
        "msync" => Some(Shape::Mapping {
            offset: 0,
            len: u64::MAX,
        }),
        "ioctl" | "sendfile" | "copy_file_range" | "splice" | "fallocate" => Some(everything),
        _ => None,
    }
}

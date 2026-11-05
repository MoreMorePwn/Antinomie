// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The AIO structures (`iocb`, `io_event`, `__aio_sigset`), the pointer
//! arrays AIO passes (`io_submit`'s `iocbpp`), and the bitmaps of CPUs and
//! NUMA nodes. The AIO structures are fixed-size with 64-bit members on every
//! ABI; `__aio_sigset` and pointers are as wide as the program's.
use super::spec::{self, Item, Show, Table, u16f, u32f, u64f};
use super::{Decoded, Shape, pointer};
use crate::syscalls::Abi;

const IOCB_CMD: Table = &[
    ("IOCB_CMD_PREAD", 0),
    ("IOCB_CMD_PWRITE", 1),
    ("IOCB_CMD_FSYNC", 2),
    ("IOCB_CMD_FDSYNC", 3),
    ("IOCB_CMD_POLL", 5),
    ("IOCB_CMD_NOOP", 6),
    ("IOCB_CMD_PREADV", 7),
    ("IOCB_CMD_PWRITEV", 8),
];

const RWF: Table = &[
    ("RWF_HIPRI", 0x1),
    ("RWF_DSYNC", 0x2),
    ("RWF_SYNC", 0x4),
    ("RWF_NOWAIT", 0x8),
    ("RWF_APPEND", 0x10),
];

const IOCB_FLAGS: Table = &[("IOCB_FLAG_RESFD", 0x1), ("IOCB_FLAG_IOPRIO", 0x2)];

/// `struct iocb`, 64 bytes.
const IOCB: &[Item] = &[
    u64f("aio_data", 0, Show::Hex),
    u32f("aio_key", 8, Show::Dec),
    u32f("aio_rw_flags", 12, Show::Flags(RWF)),
    u16f("aio_lio_opcode", 16, Show::Enum(IOCB_CMD)),
    spec::i16f("aio_reqprio", 18, Show::Dec),
    u32f("aio_fildes", 20, Show::Fd),
    u64f("aio_buf", 24, Show::Ptr),
    u64f("aio_nbytes", 32, Show::Dec),
    spec::i64f("aio_offset", 40, Show::Dec),
    u32f("aio_flags", 56, Show::Flags(IOCB_FLAGS)),
    u32f("aio_resfd", 60, Show::Fd),
];

/// `struct io_event`, 32 bytes.
const IO_EVENT: &[Item] = &[
    u64f("data", 0, Show::Hex),
    u64f("obj", 8, Show::Ptr),
    spec::i64f("res", 16, Show::Dec),
    spec::i64f("res2", 24, Show::Dec),
];

const SIGSET_64: &[Item] = &[
    u64f("sigmask", 0, Show::Ptr),
    u64f("sigsetsize", 8, Show::Dec),
];
const SIGSET_32: &[Item] = &[
    u32f("sigmask", 0, Show::Ptr),
    u32f("sigsetsize", 4, Show::Dec),
];

pub(super) fn iocb(data: &[u8]) -> Option<Decoded> {
    spec::structure(IOCB, data)
}

pub(super) fn io_event(data: &[u8]) -> Option<Decoded> {
    spec::structure(IO_EVENT, data)
}

pub(super) fn io_events(data: &[u8]) -> Option<Decoded> {
    spec::records(IO_EVENT, 32, data, super::ARRAY_LINE_RECORDS)
}

/// `getevents`' and `pgetevents`' `{sigmask, sigsetsize}`, 16 bytes or, for a
/// 32-bit program, 8.
pub(super) fn aio_sigset(abi: Abi, data: &[u8]) -> Option<Decoded> {
    let items = if super::layout::is_compat(abi) {
        SIGSET_32
    } else {
        SIGSET_64
    };
    spec::structure(items, data)
}

/// Pointers as wide as the program's, `[0x7ffd1000, NULL]`.
pub(super) fn pointers(abi: Abi, data: &[u8], array: bool) -> Option<Decoded> {
    let width = if super::layout::is_compat(abi) { 4 } else { 8 };
    let mut decoded = Decoded::new(Shape::List);
    for chunk in data.chunks(width).take(super::ARRAY_LINE_RECORDS) {
        let Some(value) = spec::word(chunk, 0, width) else {
            decoded.more = true;
            break;
        };
        decoded.push("", pointer(value));
    }
    decoded.more |= data.len().div_ceil(width) > super::ARRAY_LINE_RECORDS;
    if decoded.members.is_empty() {
        return None;
    }
    if array {
        return Some(decoded);
    }
    let text = decoded.members.remove(0).1;
    Some(Decoded::value(text))
}

/// A bitmap of CPUs or nodes as a list, `0-3,6`; `none` for an empty one. The
/// bytes are the kernel's `unsigned long` words, whose bit order is the
/// byte order on every little-endian guest.
pub(super) fn bit_list(data: &[u8]) -> Decoded {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for (index, byte) in data.iter().enumerate() {
        for bit in 0..8 {
            if byte >> bit & 1 == 0 {
                continue;
            }
            let number = index * 8 + bit;
            match ranges.last_mut() {
                Some((_, end)) if *end + 1 == number => *end = number,
                _ => ranges.push((number, number)),
            }
        }
    }
    let text: Vec<String> = ranges
        .iter()
        .map(|(from, to)| {
            if from == to {
                from.to_string()
            } else {
                format!("{from}-{to}")
            }
        })
        .collect();
    Decoded::value(if text.is_empty() {
        "none".to_owned()
    } else {
        text.join(",")
    })
}

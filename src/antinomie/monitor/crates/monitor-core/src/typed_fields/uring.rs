// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! io_uring's shared structures: the submission queue entry, the rings, the
//! probe reply, the extended `enter` argument and the registered buffer
//! ring. All are fixed-size with 64-bit members on every ABI. The opcode and
//! flag names are the 6.12 UAPI's.
use super::spec::{self, Item, Show, Table, u8f, u16f, u32f, u64f};
use super::{Decoded, Node};

const OPCODES: &[&str] = &[
    "NOP",
    "READV",
    "WRITEV",
    "FSYNC",
    "READ_FIXED",
    "WRITE_FIXED",
    "POLL_ADD",
    "POLL_REMOVE",
    "SYNC_FILE_RANGE",
    "SENDMSG",
    "RECVMSG",
    "TIMEOUT",
    "TIMEOUT_REMOVE",
    "ACCEPT",
    "ASYNC_CANCEL",
    "LINK_TIMEOUT",
    "CONNECT",
    "FALLOCATE",
    "OPENAT",
    "CLOSE",
    "FILES_UPDATE",
    "STATX",
    "READ",
    "WRITE",
    "FADVISE",
    "MADVISE",
    "SEND",
    "RECV",
    "OPENAT2",
    "EPOLL_CTL",
    "SPLICE",
    "PROVIDE_BUFFERS",
    "REMOVE_BUFFERS",
    "TEE",
    "SHUTDOWN",
    "RENAMEAT",
    "UNLINKAT",
    "MKDIRAT",
    "SYMLINKAT",
    "LINKAT",
    "MSG_RING",
    "FSETXATTR",
    "SETXATTR",
    "FGETXATTR",
    "GETXATTR",
    "SOCKET",
    "URING_CMD",
    "SEND_ZC",
    "SENDMSG_ZC",
    "READ_MULTISHOT",
    "WAITID",
    "FUTEX_WAIT",
    "FUTEX_WAKE",
    "FUTEX_WAITV",
    "FIXED_FD_INSTALL",
    "FTRUNCATE",
    "BIND",
    "LISTEN",
];

/// `IORING_OP_*` by number.
pub(super) fn opcode_name(opcode: u64) -> String {
    usize::try_from(opcode)
        .ok()
        .and_then(|index| OPCODES.get(index))
        .map_or_else(|| opcode.to_string(), |name| format!("IORING_OP_{name}"))
}

const SQE_FLAGS: Table = &[
    ("IOSQE_FIXED_FILE", 0x01),
    ("IOSQE_IO_DRAIN", 0x02),
    ("IOSQE_IO_LINK", 0x04),
    ("IOSQE_IO_HARDLINK", 0x08),
    ("IOSQE_ASYNC", 0x10),
    ("IOSQE_BUFFER_SELECT", 0x20),
    ("IOSQE_CQE_SKIP_SUCCESS", 0x40),
];

const CQE_FLAGS: Table = &[
    ("IORING_CQE_F_BUFFER", 0x1),
    ("IORING_CQE_F_MORE", 0x2),
    ("IORING_CQE_F_SOCK_NONEMPTY", 0x4),
    ("IORING_CQE_F_NOTIF", 0x8),
];

const SQ_FLAGS: Table = &[
    ("IORING_SQ_NEED_WAKEUP", 0x1),
    ("IORING_SQ_CQ_OVERFLOW", 0x2),
    ("IORING_SQ_TASKRUN", 0x4),
];

const CQ_FLAGS: Table = &[("IORING_CQ_EVENTFD_DISABLED", 0x1)];

/// `struct io_uring_sqe`, 64 bytes. `addr2`, `addr` and `op_flags` mean what
/// the opcode says; they read as numbers.
const SQE: &[Item] = &[
    u8f("opcode", 0, Show::Custom(opcode_text)),
    u8f("flags", 1, Show::Flags(SQE_FLAGS)),
    u16f("ioprio", 2, Show::Dec),
    spec::i32f("fd", 4, Show::Fd),
    u64f("off", 8, Show::Hex),
    u64f("addr", 16, Show::Ptr),
    u32f("len", 24, Show::Dec),
    u32f("op_flags", 28, Show::Hex),
    u64f("user_data", 32, Show::Hex),
    u16f("buf_index", 40, Show::Dec),
    u16f("personality", 42, Show::Dec),
    u32f("splice_fd_in", 44, Show::Dec),
    u64f("addr3", 48, Show::Hex),
];

fn opcode_text(value: u64) -> String {
    opcode_name(value)
}

/// `struct io_uring_cqe`, 16 bytes.
const CQE: &[Item] = &[
    u64f("user_data", 0, Show::Hex),
    spec::i32f("res", 8, Show::Dec),
    u32f("flags", 12, Show::Flags(CQE_FLAGS)),
];

/// `struct io_rings`: the kernel-shared header, each ring index on its own
/// cache line.
const RINGS: &[Item] = &[
    Item::Group(
        "sq",
        &[u32f("head", 0, Show::Dec), u32f("tail", 64, Show::Dec)],
    ),
    Item::Group(
        "cq",
        &[u32f("head", 128, Show::Dec), u32f("tail", 192, Show::Dec)],
    ),
    u32f("sq_ring_mask", 256, Show::Hex),
    u32f("cq_ring_mask", 260, Show::Hex),
    u32f("sq_ring_entries", 264, Show::Dec),
    u32f("cq_ring_entries", 268, Show::Dec),
    u32f("sq_dropped", 272, Show::Dec),
    u32f("sq_flags", 276, Show::Flags(SQ_FLAGS)),
    u32f("cq_flags", 280, Show::Flags(CQ_FLAGS)),
    u32f("cq_overflow", 284, Show::Dec),
];

/// Where the first completion entry lies in `io_rings`.
const CQES: usize = 320;

const GETEVENTS_ARG: &[Item] = &[
    u64f("sigmask", 0, Show::Ptr),
    u32f("sigmask_sz", 8, Show::Dec),
    u32f("min_wait_usec", 12, Show::Dec),
    u64f("ts", 16, Show::Ptr),
];

const BUF: &[Item] = &[
    u64f("addr", 0, Show::Ptr),
    u32f("len", 8, Show::Dec),
    u16f("bid", 12, Show::Dec),
];

pub(super) fn sqe(data: &[u8]) -> Option<Decoded> {
    spec::structure(SQE, data)
}

pub(super) fn sqes(data: &[u8]) -> Option<Decoded> {
    spec::records(SQE, 64, data, super::ARRAY_LINE_RECORDS)
}

pub(super) fn getevents_arg(data: &[u8]) -> Option<Decoded> {
    spec::structure(GETEVENTS_ARG, data)
}

pub(super) fn buffers(data: &[u8]) -> Option<Decoded> {
    spec::records(BUF, 16, data, super::ARRAY_LINE_RECORDS)
}

/// The rings header and, when the capture reaches them, the completion
/// entries that follow it.
pub(super) fn rings(data: &[u8]) -> Option<Decoded> {
    let mut cut = false;
    let mut tree = spec::nodes(RINGS, data, &mut cut);
    if tree.is_empty() {
        return None;
    }
    if let Some(entries) = data.get(CQES..).filter(|bytes| !bytes.is_empty()) {
        let list = spec::records(CQE, 16, entries, super::ARRAY_LINE_RECORDS)?;
        let children = list.nodes();
        tree.push(Node {
            name: "cqes".into(),
            text: list.full_line(),
            children,
        });
    }
    Some(spec::from_nodes(tree, cut))
}

/// `struct io_uring_probe`: the last opcode, and the opcodes the kernel
/// supports from the `ops` entries the capture holds (8 bytes each after a
/// 16-byte header).
pub(super) fn probe(data: &[u8]) -> Option<Decoded> {
    let last = u64::from(*data.first()?);
    let count = usize::from(*data.get(1)?);
    let mut decoded = Decoded::new(super::Shape::Struct);
    decoded.push("last_op", opcode_name(last));
    decoded.push("ops_len", count.to_string());
    let mut supported = Vec::new();
    let entries = data.get(16..).unwrap_or(&[]);
    for entry in entries.chunks(8).take(count) {
        if entry.len() < 8 {
            decoded.more = true;
            break;
        }
        if spec::word(entry, 2, 2)? & 1 == 1 {
            supported.push(opcode_name(u64::from(entry[0])));
        }
    }
    if entries.len() < count * 8 {
        decoded.more = true;
    }
    if !entries.is_empty() {
        decoded.push("supported", format!("[{}]", supported.join(", ")));
    }
    Some(decoded)
}

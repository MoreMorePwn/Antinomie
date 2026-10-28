// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Identity, capability, directory, handle, ring, message, netfilter and LDT
//! layouts. Offsets are the 64-bit Linux 6.12.94 UAPI's: `linux/capability.h`,
//! `linux/dirent.h` (`linux_dirent64`; `linux_dirent` is fs/readdir.c's),
//! `linux/fcntl.h` (`file_handle`), `linux/io_uring.h`, `linux/msg.h`,
//! `linux/netfilter_ipv4/ip_tables.h`, `linux/netfilter/x_tables.h`, and x86's
//! `asm/ldt.h` (`user_desc`) and `asm/desc_defs.h` (`desc_struct`).
use super::{
    Call, Decoded, Shape, c_string, flags, i32_at, i64_at, named, pointer, quoted, u8_at, u16_at,
    u32_at, u64_at,
};

const CAPABILITIES: &[&str] = &[
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// A capability set by name: every capability 6.12.94 knows reads `all`, a
/// set holding most of them `all but CAP_SYS_BOOT`.
fn capability_set(set: u64) -> String {
    let known = (1u64 << CAPABILITIES.len()) - 1;
    let names = |bits: u64| -> Vec<String> {
        CAPABILITIES
            .iter()
            .enumerate()
            .filter(|(bit, _)| bits & (1 << bit) != 0)
            .map(|(_, name)| (*name).to_owned())
            .collect()
    };
    let mut parts = Vec::new();
    if set & known == known {
        parts.push("all".to_owned());
    } else if (set & known).count_ones() * 2 > CAPABILITIES.len() as u32 {
        parts.push(format!("all but {}", names(!set & known).join("|")));
    } else {
        parts.extend(names(set));
    }
    if set & !known != 0 {
        parts.push(format!("{:#x}", set & !known));
    }
    if parts.is_empty() {
        "0".into()
    } else {
        parts.join("|")
    }
}

/// `struct __user_cap_data_struct[]`: one 12-byte element per 32 capabilities
/// (two for versions 2 and 3, one for version 1), shown as three sets.
pub(super) fn capabilities(data: &[u8]) -> Option<Decoded> {
    let mut sets = [0u64; 3];
    let mut any = false;
    for (index, element) in data.as_chunks::<12>().0.iter().take(2).enumerate() {
        for (set, at) in sets.iter_mut().zip([0, 4, 8]) {
            *set |= u64::from(u32_at(element, at)?) << (32 * index);
        }
        any = true;
    }
    if !any {
        return None;
    }
    let mut decoded = Decoded::new(Shape::Struct);
    for (name, set) in ["effective", "permitted", "inheritable"].iter().zip(sets) {
        decoded.push(name, capability_set(set));
    }
    decoded.more = !data.len().is_multiple_of(12) || data.len() > 24;
    Some(decoded)
}

const CAPABILITY_VERSIONS: &[(&str, u64)] = &[
    ("_LINUX_CAPABILITY_VERSION_1", 0x1998_0330),
    ("_LINUX_CAPABILITY_VERSION_2", 0x2007_1026),
    ("_LINUX_CAPABILITY_VERSION_3", 0x2008_0522),
];

/// capget/capset's header, captured as its members: the version (and the
/// version the kernel wrote back) by name, the pid as a number.
pub(super) fn capability_header(call: &Call<'_>, key: &str, data: &[u8]) -> Option<Decoded> {
    if !matches!(call.name, "capget" | "capset") {
        return None;
    }
    match key {
        "arg0.version" | "arg0.required_version" => {
            let version = u64::from(u32_at(data, 0)?);
            let name = named(version, CAPABILITY_VERSIONS);
            Some(Decoded::value(if name == version.to_string() {
                format!("{version:#x}")
            } else {
                name
            }))
        }
        "arg0.pid" => Some(Decoded::value(i32_at(data, 0)?.to_string())),
        _ => None,
    }
}

/// A `uid_t` or `gid_t` the call wrote.
pub(super) fn id(data: &[u8]) -> Option<Decoded> {
    Some(Decoded::value(u32_at(data, 0)?.to_string()))
}

/// An array of `gid_t` (or F_GETOWNER_UIDS's `uid_t[2]`).
pub(super) fn ids(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::List);
    for element in data.chunks(4) {
        match u32_at(element, 0) {
            Some(id) => decoded.push("", id.to_string()),
            None => decoded.more = true,
        }
    }
    Some(decoded)
}

const DIRENT_TYPES: &[(&str, u64)] = &[
    ("DT_UNKNOWN", 0),
    ("DT_FIFO", 1),
    ("DT_CHR", 2),
    ("DT_DIR", 4),
    ("DT_BLK", 6),
    ("DT_REG", 8),
    ("DT_LNK", 10),
    ("DT_SOCK", 12),
    ("DT_WHT", 14),
];

/// getdents' records, each `d_reclen` bytes long. `linux_dirent`: `d_ino` at 0,
/// `d_off` at 8, `d_reclen` at 16, the name at 18 and the type in the record's
/// last byte; `linux_dirent64`: the type at 18 and the name at 19. A record
/// that does not fit the bytes present ends the list as `more`.
pub(super) fn dirents(data: &[u8], wide: bool) -> Option<Decoded> {
    let name_at = if wide { 19 } else { 18 };
    let mut decoded = Decoded::new(Shape::List);
    let mut at = 0usize;
    while at < data.len() {
        let record = &data[at..];
        let Some(length) = u16_at(record, 16).map(usize::from) else {
            decoded.more = true;
            break;
        };
        // A record holds at least its header and a name's NUL.
        if length < name_at + 1 || length > record.len() {
            decoded.more = true;
            break;
        }
        let record = &record[..length];
        let kind = if wide {
            u8_at(record, 18)?
        } else {
            u8_at(record, length - 1)?
        };
        let name_end = if wide { length } else { length - 1 };
        let mut entry = Decoded::new(Shape::Struct);
        entry.push("d_ino", u64_at(record, 0)?.to_string());
        entry.push("d_off", i64_at(record, 8)?.to_string());
        entry.push("d_reclen", length.to_string());
        entry.push("d_type", named(u64::from(kind), DIRENT_TYPES));
        entry.push("d_name", c_string(&record[name_at..name_end]));
        decoded.push("", entry.full_line());
        at += length;
    }
    Some(decoded)
}

const HANDLE_TYPES: &[(&str, u64)] = &[
    ("FILEID_ROOT", 0),
    ("FILEID_INO32_GEN", 1),
    ("FILEID_INO32_GEN_PARENT", 2),
    ("FILEID_BTRFS_WITHOUT_PARENT", 0x4d),
    ("FILEID_BTRFS_WITH_PARENT", 0x4e),
    ("FILEID_BTRFS_WITH_PARENT_ROOT", 0x4f),
    ("FILEID_UDF_WITHOUT_PARENT", 0x51),
    ("FILEID_UDF_WITH_PARENT", 0x52),
    ("FILEID_NILFS_WITHOUT_PARENT", 0x61),
    ("FILEID_NILFS_WITH_PARENT", 0x62),
    ("FILEID_FAT_WITHOUT_PARENT", 0x71),
    ("FILEID_FAT_WITH_PARENT", 0x72),
    ("FILEID_INO64_GEN", 0x81),
    ("FILEID_INO64_GEN_PARENT", 0x82),
    ("FILEID_LUSTRE", 0x97),
    ("FILEID_BCACHEFS_WITHOUT_PARENT", 0xb1),
    ("FILEID_BCACHEFS_WITH_PARENT", 0xb2),
    ("FILEID_KERNFS", 0xfe),
    ("FILEID_INVALID", 0xff),
];

/// `struct file_handle`'s header: the size of the opaque handle that follows
/// and the file system's handle type. The handle bytes are a separate field.
pub(super) fn file_handle(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("handle_bytes", u32_at(data, 0)?.to_string());
    let kind = i32_at(data, 4)?;
    decoded.push(
        "handle_type",
        u64::try_from(kind).map_or_else(|_| kind.to_string(), |kind| named(kind, HANDLE_TYPES)),
    );
    Some(decoded)
}

const SETUP_FLAGS: &[(&str, u64)] = &[
    ("IORING_SETUP_IOPOLL", 1 << 0),
    ("IORING_SETUP_SQPOLL", 1 << 1),
    ("IORING_SETUP_SQ_AFF", 1 << 2),
    ("IORING_SETUP_CQSIZE", 1 << 3),
    ("IORING_SETUP_CLAMP", 1 << 4),
    ("IORING_SETUP_ATTACH_WQ", 1 << 5),
    ("IORING_SETUP_R_DISABLED", 1 << 6),
    ("IORING_SETUP_SUBMIT_ALL", 1 << 7),
    ("IORING_SETUP_COOP_TASKRUN", 1 << 8),
    ("IORING_SETUP_TASKRUN_FLAG", 1 << 9),
    ("IORING_SETUP_SQE128", 1 << 10),
    ("IORING_SETUP_CQE32", 1 << 11),
    ("IORING_SETUP_SINGLE_ISSUER", 1 << 12),
    ("IORING_SETUP_DEFER_TASKRUN", 1 << 13),
    ("IORING_SETUP_NO_MMAP", 1 << 14),
    ("IORING_SETUP_REGISTERED_FD_ONLY", 1 << 15),
    ("IORING_SETUP_NO_SQARRAY", 1 << 16),
];
const FEATURES: &[(&str, u64)] = &[
    ("IORING_FEAT_SINGLE_MMAP", 1 << 0),
    ("IORING_FEAT_NODROP", 1 << 1),
    ("IORING_FEAT_SUBMIT_STABLE", 1 << 2),
    ("IORING_FEAT_RW_CUR_POS", 1 << 3),
    ("IORING_FEAT_CUR_PERSONALITY", 1 << 4),
    ("IORING_FEAT_FAST_POLL", 1 << 5),
    ("IORING_FEAT_POLL_32BITS", 1 << 6),
    ("IORING_FEAT_SQPOLL_NONFIXED", 1 << 7),
    ("IORING_FEAT_EXT_ARG", 1 << 8),
    ("IORING_FEAT_NATIVE_WORKERS", 1 << 9),
    ("IORING_FEAT_RSRC_TAGS", 1 << 10),
    ("IORING_FEAT_CQE_SKIP", 1 << 11),
    ("IORING_FEAT_LINKED_FILE", 1 << 12),
    ("IORING_FEAT_REG_REG_RING", 1 << 13),
    ("IORING_FEAT_RECVSEND_BUNDLE", 1 << 14),
    ("IORING_FEAT_MIN_TIMEOUT", 1 << 15),
];

/// `{head=0, tail=64, ...}` of one ring's offsets (40 bytes at `at`; the
/// reserved word is left out).
fn ring_offsets(data: &[u8], at: usize, names: [&str; 7]) -> Option<String> {
    let mut decoded = Decoded::new(Shape::Struct);
    for (index, name) in names.iter().enumerate() {
        decoded.push(name, u32_at(data, at + 4 * index)?.to_string());
    }
    decoded.push("user_addr", pointer(u64_at(data, at + 32)?));
    Some(decoded.full_line())
}

/// `struct io_uring_params` (120 bytes): what the program asked for, and on
/// return what the kernel set up (entries, features, ring offsets).
pub(super) fn io_uring_params(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("sq_entries", u32_at(data, 0)?.to_string());
    decoded.push("cq_entries", u32_at(data, 4)?.to_string());
    decoded.push("flags", flags(u64::from(u32_at(data, 8)?), SETUP_FLAGS));
    decoded.push("sq_thread_cpu", u32_at(data, 12)?.to_string());
    decoded.push("sq_thread_idle", u32_at(data, 16)?.to_string());
    decoded.push("features", flags(u64::from(u32_at(data, 20)?), FEATURES));
    decoded.push("wq_fd", i32_at(data, 24)?.to_string());
    let sq = ring_offsets(
        data,
        40,
        [
            "head",
            "tail",
            "ring_mask",
            "ring_entries",
            "flags",
            "dropped",
            "array",
        ],
    );
    let cq = ring_offsets(
        data,
        80,
        [
            "head",
            "tail",
            "ring_mask",
            "ring_entries",
            "overflow",
            "cqes",
            "flags",
        ],
    );
    match (sq, cq) {
        (Some(sq), Some(cq)) => {
            decoded.push("sq_off", sq);
            decoded.push("cq_off", cq);
        }
        _ => decoded.more = true,
    }
    Some(decoded)
}

/// How much of a message's text is shown on the line.
const MTEXT_SHOWN: usize = 64;

/// `struct msgbuf`: the message type, then its text (every byte, quoted).
pub(super) fn msgbuf(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("mtype", i64_at(data, 0)?.to_string());
    let text = &data[8..];
    decoded.push("mtext", quoted(&text[..text.len().min(MTEXT_SHOWN)]));
    decoded.more = text.len() > MTEXT_SHOWN;
    Some(decoded)
}

const HOOKS: &[(&str, u64)] = &[
    ("PREROUTING", 1 << 0),
    ("INPUT", 1 << 1),
    ("FORWARD", 1 << 2),
    ("OUTPUT", 1 << 3),
    ("POSTROUTING", 1 << 4),
];

fn words(data: &[u8], at: usize, count: usize) -> Option<String> {
    let mut decoded = Decoded::new(Shape::List);
    for index in 0..count {
        decoded.push("", u32_at(data, at + 4 * index)?.to_string());
    }
    Some(decoded.full_line())
}

/// `struct ipt_replace` (and `ip6t_replace`, the same header): the table, its
/// hooks, the size of the rule blob that follows and where each hook's
/// chain starts. The rules themselves are not decoded.
pub(super) fn ipt_replace(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("name", c_string(data.get(..32)?));
    decoded.push("valid_hooks", flags(u64::from(u32_at(data, 32)?), HOOKS));
    decoded.push("num_entries", u32_at(data, 36)?.to_string());
    decoded.push("size", u32_at(data, 40)?.to_string());
    let _ = (|| -> Option<()> {
        decoded.push("hook_entry", words(data, 44, 5)?);
        decoded.push("underflow", words(data, 64, 5)?);
        decoded.push("num_counters", u32_at(data, 84)?.to_string());
        decoded.push("counters", pointer(u64_at(data, 88)?));
        Some(())
    })();
    decoded.more = data.len() > 96;
    Some(decoded)
}

/// `struct xt_counters_info`: the table and how many counters follow.
pub(super) fn counters_info(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("name", c_string(data.get(..32)?));
    decoded.push("num_counters", u32_at(data, 32)?.to_string());
    decoded.more = data.len() > 40;
    Some(decoded)
}

/// x86's `struct user_desc` (16 bytes): an LDT or TLS entry as modify_ldt
/// writes it, the flags in the bit fields of the last word.
pub(super) fn user_desc(data: &[u8]) -> Option<Decoded> {
    let bits = u32_at(data, 12)?;
    let bit = |shift: u32, width: u32| ((bits >> shift) & ((1 << width) - 1)).to_string();
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("entry_number", u32_at(data, 0)?.to_string());
    decoded.push("base_addr", format!("{:#x}", u32_at(data, 4)?));
    decoded.push("limit", format!("{:#x}", u32_at(data, 8)?));
    for (name, shift, width) in [
        ("seg_32bit", 0, 1),
        ("contents", 1, 2),
        ("read_exec_only", 3, 1),
        ("limit_in_pages", 4, 1),
        ("seg_not_present", 5, 1),
        ("useable", 6, 1),
        ("lm", 7, 1),
    ] {
        decoded.push(name, bit(shift, width));
    }
    Some(decoded)
}

/// One 8-byte x86 segment descriptor as modify_ldt reads it: base, limit and
/// the access bits; an all-zero (unused) entry reads `empty`.
pub(super) fn descriptor(data: &[u8]) -> Option<Decoded> {
    let raw = u64_at(data, 0)?;
    if raw == 0 {
        return Some(Decoded::value("empty"));
    }
    let limit = u32::from(u16_at(data, 0)?) | (u32::from(u8_at(data, 6)? & 0xf) << 16);
    let base = u32::from(u16_at(data, 2)?)
        | (u32::from(u8_at(data, 4)?) << 16)
        | (u32::from(u8_at(data, 7)?) << 24);
    let access = u8_at(data, 5)?;
    let high = u8_at(data, 6)? >> 4;
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("base", format!("{base:#x}"));
    decoded.push("limit", format!("{limit:#x}"));
    decoded.push("type", (access & 0xf).to_string());
    decoded.push("s", ((access >> 4) & 1).to_string());
    decoded.push("dpl", ((access >> 5) & 3).to_string());
    decoded.push("p", (access >> 7).to_string());
    decoded.push("avl", (high & 1).to_string());
    decoded.push("l", ((high >> 1) & 1).to_string());
    decoded.push("d", ((high >> 2) & 1).to_string());
    decoded.push("g", (high >> 3).to_string());
    Some(decoded)
}

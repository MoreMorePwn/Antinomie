// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Record decoders of the arrays that were only bytes before: `pollfd`,
//! `sembuf`, control messages, `futex_waitv`, `kexec_segment`, the BPF
//! instruction and BTF record arrays, and plain integer arrays; plus the
//! summaries of the older record arrays. Offsets are the 64-bit Linux 6.12.94
//! UAPI's (`poll.h`, `sem.h`, `socket.h`, `futex.h`, `kexec.h`, `bpf.h`).
use super::{Ctx, hex, len16, table::Length};
use crate::typed_fields::{
    Decoded, Shape, ebpf_asm, flags, i32_at, named, pointer, u8_at, u16_at, u32_at, u64_at,
};

// Summaries ---------------------------------------------------------------

/// The first members of a struct: `a=1 b=2 c=3`; a value as is.
pub(super) fn first_members(decoded: &Decoded) -> String {
    match decoded.shape {
        Shape::Struct => decoded
            .members
            .iter()
            .take(3)
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" "),
        _ => decoded.full_line(),
    }
}

pub(super) fn value_summary(decoded: &Decoded) -> String {
    member(decoded, "value").unwrap_or_else(|| decoded.full_line())
}

fn member(decoded: &Decoded, name: &str) -> Option<String> {
    decoded
        .members
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.clone())
}

fn text(decoded: &Decoded, name: &str) -> String {
    member(decoded, name).unwrap_or_default()
}

/// A directory entry: its name and its type.
pub(super) fn dirent_summary(decoded: &Decoded) -> String {
    format!("{} {}", text(decoded, "d_name"), text(decoded, "d_type"))
}

pub(super) fn descriptor_summary(decoded: &Decoded) -> String {
    match decoded.shape {
        Shape::Struct => format!(
            "base={} limit={}",
            text(decoded, "base"),
            text(decoded, "limit")
        ),
        _ => decoded.full_line(),
    }
}

pub(super) fn asm_summary(decoded: &Decoded) -> String {
    text(decoded, "asm")
}

// Directory entries -------------------------------------------------------

/// `d_reclen` at 16 gives a record's size; a record holds at least its header
/// and a name's NUL (`name_at` is where the name starts).
fn dirent_size(bytes: &[u8], name_at: usize) -> Length {
    let Some(size) = len16(bytes, 16) else {
        return Length::Short;
    };
    if size < name_at + 1 {
        return Length::Bad("d_reclen is smaller than a record's header");
    }
    Length::Bytes(size)
}

pub(super) fn dirent64_length(bytes: &[u8]) -> Length {
    dirent_size(bytes, 19)
}

pub(super) fn dirent_length(bytes: &[u8]) -> Length {
    dirent_size(bytes, 18)
}

// poll and semaphores -----------------------------------------------------

const POLL_EVENTS: &[(&str, u64)] = &[
    ("POLLIN", 0x1),
    ("POLLPRI", 0x2),
    ("POLLOUT", 0x4),
    ("POLLERR", 0x8),
    ("POLLHUP", 0x10),
    ("POLLNVAL", 0x20),
    ("POLLRDNORM", 0x40),
    ("POLLRDBAND", 0x80),
    ("POLLWRNORM", 0x100),
    ("POLLWRBAND", 0x200),
    ("POLLMSG", 0x400),
    ("POLLREMOVE", 0x1000),
    ("POLLRDHUP", 0x2000),
];

/// `struct pollfd`: `fd` at 0, `events` at 4, `revents` at 6.
pub(super) fn pollfd(bytes: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("fd", i32_at(bytes, 0)?.to_string());
    decoded.push("events", flags(u64::from(u16_at(bytes, 4)?), POLL_EVENTS));
    decoded.push("revents", flags(u64::from(u16_at(bytes, 6)?), POLL_EVENTS));
    Some(decoded)
}

/// Descriptor and what happened to it; before the call returns only what it
/// waits for.
pub(super) fn pollfd_summary(decoded: &Decoded) -> String {
    let (fd, revents) = (text(decoded, "fd"), text(decoded, "revents"));
    if revents == "0" {
        format!("fd {fd} waits for {}", text(decoded, "events"))
    } else {
        format!("fd {fd} revents {revents}")
    }
}

const SEM_FLAGS: &[(&str, u64)] = &[("IPC_NOWAIT", 0x800), ("SEM_UNDO", 0x1000)];

/// `struct sembuf`: `sem_num` at 0, `sem_op` at 2, `sem_flg` at 4.
pub(super) fn sembuf(bytes: &[u8]) -> Option<Decoded> {
    let operation = i16::from_le_bytes([u8_at(bytes, 2)?, u8_at(bytes, 3)?]);
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("sem_num", u16_at(bytes, 0)?.to_string());
    decoded.push("sem_op", operation.to_string());
    decoded.push("sem_flg", flags(u64::from(u16_at(bytes, 4)?), SEM_FLAGS));
    Some(decoded)
}

pub(super) fn sembuf_summary(decoded: &Decoded) -> String {
    let op = text(decoded, "sem_op");
    let meaning = match op.parse::<i32>() {
        Ok(0) => "wait for zero".to_owned(),
        Ok(n) if n > 0 => format!("add {n}"),
        Ok(n) => format!("take {}", -n),
        Err(_) => op,
    };
    let flags = text(decoded, "sem_flg");
    let flags = if flags == "0" {
        String::new()
    } else {
        format!(" {flags}")
    };
    format!("semaphore {}: {meaning}{flags}", text(decoded, "sem_num"))
}

// Control messages --------------------------------------------------------

/// `struct cmsghdr`: `cmsg_len` (8 bytes, header included), `cmsg_level` and
/// `cmsg_type` (4 each); the next header starts at the length rounded up to 8.
/// The last message may end before its padding.
pub(super) fn cmsg_length(bytes: &[u8]) -> Length {
    let Some(length) = u64_at(bytes, 0) else {
        return Length::Short;
    };
    if bytes.len() < 16 {
        return Length::Short;
    }
    let Ok(length) = usize::try_from(length) else {
        return Length::Bad("cmsg_len does not fit in memory");
    };
    if length < 16 {
        return Length::Bad("cmsg_len is smaller than the 16-byte header");
    }
    let padded = length.checked_add(7).map(|padded| padded & !7);
    Length::Bytes(match padded {
        Some(padded) if padded <= bytes.len() => padded,
        _ => length,
    })
}

const CMSG_LEVELS: &[(&str, u64)] = &[
    ("SOL_IP", 0),
    ("SOL_SOCKET", 1),
    ("SOL_TCP", 6),
    ("SOL_UDP", 17),
    ("SOL_IPV6", 41),
    ("SOL_RAW", 255),
    ("SOL_PACKET", 263),
    ("SOL_ALG", 279),
    ("SOL_TLS", 282),
];

fn cmsg_type(level: i32, kind: i32) -> String {
    let names: &[(&str, u64)] = match level {
        1 => &[
            ("SCM_RIGHTS", 1),
            ("SCM_CREDENTIALS", 2),
            ("SCM_SECURITY", 3),
            ("SCM_PIDFD", 4),
            ("SCM_TIMESTAMP", 29),
            ("SCM_TIMESTAMPNS", 35),
            ("SCM_TIMESTAMPING", 37),
        ],
        0 => &[
            ("IP_TOS", 1),
            ("IP_TTL", 2),
            ("IP_RETOPTS", 7),
            ("IP_PKTINFO", 8),
            ("IP_RECVERR", 11),
            ("IP_ORIGDSTADDR", 20),
        ],
        41 => &[
            ("IPV6_RECVERR", 25),
            ("IPV6_PKTINFO", 50),
            ("IPV6_HOPLIMIT", 52),
            ("IPV6_TCLASS", 67),
        ],
        _ => &[],
    };
    u64::try_from(kind).map_or_else(|_| kind.to_string(), |kind| named(kind, names))
}

/// One control message: header, then its data by level and type. Passed file
/// descriptors (`SCM_RIGHTS`) and peer credentials (`SCM_CREDENTIALS`) are
/// shown by meaning; any other data stays bytes.
pub(super) fn cmsg(bytes: &[u8]) -> Option<Decoded> {
    let length = usize::try_from(u64_at(bytes, 0)?).ok()?;
    let (level, kind) = (i32_at(bytes, 8)?, i32_at(bytes, 12)?);
    let data = bytes.get(16..length.min(bytes.len()))?;
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("cmsg_len", length.to_string());
    decoded.push(
        "cmsg_level",
        u64::try_from(level).map_or_else(|_| level.to_string(), |l| named(l, CMSG_LEVELS)),
    );
    decoded.push("cmsg_type", cmsg_type(level, kind));
    match (level, kind) {
        (1, 1) => {
            let (fds, rest) = data.as_chunks::<4>();
            let list: Vec<String> = fds
                .iter()
                .map(|fd| i32::from_le_bytes(*fd).to_string())
                .collect();
            decoded.push("fds", format!("[{}]", list.join(", ")));
            if !rest.is_empty() {
                decoded.push("trailing", hex(rest));
            }
        }
        (1, 2) if data.len() >= 12 => {
            decoded.push("pid", i32_at(data, 0)?.to_string());
            decoded.push("uid", u32_at(data, 4)?.to_string());
            decoded.push("gid", u32_at(data, 8)?.to_string());
            if data.len() > 12 {
                decoded.push("trailing", hex(&data[12..]));
            }
        }
        (1, 4) if data.len() >= 4 => decoded.push("pidfd", i32_at(data, 0)?.to_string()),
        _ => decoded.push("data", format!("{} bytes: {}", data.len(), hex(data))),
    }
    Some(decoded)
}

pub(super) fn cmsg_summary(decoded: &Decoded) -> String {
    let kind = text(decoded, "cmsg_type");
    match (member(decoded, "fds"), member(decoded, "pid")) {
        (Some(fds), _) => format!("{kind} fds {fds}"),
        (None, Some(pid)) => format!(
            "{kind} pid {pid} uid {} gid {}",
            text(decoded, "uid"),
            text(decoded, "gid")
        ),
        _ => format!("{} {kind}", text(decoded, "cmsg_level")),
    }
}

// futex_waitv, kexec ------------------------------------------------------

const FUTEX_SIZES: &[(&str, u64)] = &[
    ("FUTEX2_SIZE_U8", 0),
    ("FUTEX2_SIZE_U16", 1),
    ("FUTEX2_SIZE_U32", 2),
    ("FUTEX2_SIZE_U64", 3),
];
const FUTEX_FLAGS: &[(&str, u64)] = &[("FUTEX2_NUMA", 0x4), ("FUTEX2_PRIVATE", 0x80)];

/// `struct futex_waitv`: `val` at 0, `uaddr` at 8, `flags` at 16, a reserved
/// word at 20.
pub(super) fn futex_waitv(bytes: &[u8]) -> Option<Decoded> {
    let word = u32_at(bytes, 16)?;
    let mut shown = named(u64::from(word & 3), FUTEX_SIZES);
    let rest = u64::from(word & !3);
    if rest != 0 {
        shown = format!("{shown}|{}", flags(rest, FUTEX_FLAGS));
    }
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("uaddr", pointer(u64_at(bytes, 8)?));
    decoded.push("val", u64_at(bytes, 0)?.to_string());
    decoded.push("flags", shown);
    Some(decoded)
}

pub(super) fn futex_summary(decoded: &Decoded) -> String {
    format!(
        "{} == {} ({})",
        text(decoded, "uaddr"),
        text(decoded, "val"),
        text(decoded, "flags")
    )
}

/// `struct kexec_segment`: `buf` at 0, `bufsz` at 8, `mem` at 16, `memsz` at 24.
pub(super) fn kexec_segment(bytes: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("buf", pointer(u64_at(bytes, 0)?));
    decoded.push("bufsz", u64_at(bytes, 8)?.to_string());
    decoded.push("mem", format!("{:#x}", u64_at(bytes, 16)?));
    decoded.push("memsz", u64_at(bytes, 24)?.to_string());
    Some(decoded)
}

pub(super) fn kexec_summary(decoded: &Decoded) -> String {
    format!(
        "{} bytes to {} ({} bytes of memory)",
        text(decoded, "bufsz"),
        text(decoded, "mem"),
        text(decoded, "memsz")
    )
}

// BPF ---------------------------------------------------------------------

/// `struct bpf_insn`: `code` at 0, `dst_reg` (low nibble) and `src_reg` of
/// byte 1, `off` at 2, `imm` at 4. `BPF_LD | BPF_DW | BPF_IMM` takes two
/// slots; the second holds the high half of the 64-bit immediate.
pub(super) fn bpf_insn(ctx: &Ctx<'_>, bytes: &[u8]) -> Option<Decoded> {
    let op = u8_at(bytes, 0)?;
    let regs = u8_at(bytes, 1)?;
    let (dst, src) = (regs & 0xf, regs >> 4);
    let off = i16::from_le_bytes([u8_at(bytes, 2)?, u8_at(bytes, 3)?]);
    let imm = i32_at(bytes, 4)?;
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("index", ctx.index.to_string());
    decoded.push("code", format!("{op:#04x}"));
    decoded.push("dst", format!("r{dst}"));
    decoded.push("src", format!("r{src}"));
    decoded.push("off", off.to_string());
    decoded.push("imm", imm.to_string());
    let asm = if is_second_slot(ctx) {
        format!("(upper half of the lddw immediate: {:#x})", imm as u32)
    } else if op == 0x18 {
        match ctx.data.get(ctx.at + 8..ctx.at + 16) {
            Some(high) if high[..4] == [0; 4] => {
                let low = u64::from(imm as u32);
                let high = u64::from(u32::from_le_bytes(high[4..8].try_into().ok()?));
                let kind = match src {
                    0 => "",
                    1 => " (map fd)",
                    2 => " (map value)",
                    3 => " (BTF id)",
                    4 => " (map index)",
                    5 => " (map index value)",
                    6 => " (kernel function)",
                    _ => " (pseudo source)",
                };
                format!("lddw r{dst}, {:#x}{kind}", (high << 32) | low)
            }
            Some(_) => format!("lddw r{dst}, (malformed second slot)"),
            None => format!("lddw r{dst}, (second slot not captured)"),
        }
    } else {
        ebpf_asm::mnemonic(op, dst, src, off, imm, ctx.index, ctx.total)
    };
    decoded.push("asm", asm);
    Some(decoded)
}

/// Slot `index` is the second half of an lddw when an odd run of `0x18`
/// opcodes ends right before it (looking back at most 64 slots).
fn is_second_slot(ctx: &Ctx<'_>) -> bool {
    let mut run = 0usize;
    let mut at = ctx.at;
    while run < 64 && at >= 8 && ctx.data.get(at - 8) == Some(&0x18) {
        run += 1;
        at -= 8;
    }
    run % 2 == 1
}

/// `struct bpf_func_info`: `insn_off` at 0, `type_id` at 4.
pub(super) fn bpf_func_info(bytes: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("insn_off", u32_at(bytes, 0)?.to_string());
    decoded.push("type_id", u32_at(bytes, 4)?.to_string());
    Some(decoded)
}

/// `struct bpf_line_info`: `insn_off`, `file_name_off`, `line_off` and
/// `line_col` (line in the upper 22 bits, column in the lower 10).
pub(super) fn bpf_line_info(bytes: &[u8]) -> Option<Decoded> {
    let line_col = u32_at(bytes, 12)?;
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("insn_off", u32_at(bytes, 0)?.to_string());
    decoded.push("file_name_off", u32_at(bytes, 4)?.to_string());
    decoded.push("line_off", u32_at(bytes, 8)?.to_string());
    decoded.push("line", (line_col >> 10).to_string());
    decoded.push("col", (line_col & 0x3ff).to_string());
    Some(decoded)
}

pub(super) fn line_info_summary(decoded: &Decoded) -> String {
    format!(
        "insn {} line {} col {}",
        text(decoded, "insn_off"),
        text(decoded, "line"),
        text(decoded, "col")
    )
}

const CORE_KINDS: &[(&str, u64)] = &[
    ("FIELD_BYTE_OFFSET", 0),
    ("FIELD_BYTE_SIZE", 1),
    ("FIELD_EXISTS", 2),
    ("FIELD_SIGNED", 3),
    ("FIELD_LSHIFT_U64", 4),
    ("FIELD_RSHIFT_U64", 5),
    ("TYPE_ID_LOCAL", 6),
    ("TYPE_ID_TARGET", 7),
    ("TYPE_EXISTS", 8),
    ("TYPE_SIZE", 9),
    ("ENUMVAL_EXISTS", 10),
    ("ENUMVAL_VALUE", 11),
    ("TYPE_MATCHES", 12),
];

/// `struct bpf_core_relo`: `insn_off`, `type_id`, `access_str_off`, `kind`.
pub(super) fn bpf_core_relo(bytes: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("insn_off", u32_at(bytes, 0)?.to_string());
    decoded.push("type_id", u32_at(bytes, 4)?.to_string());
    decoded.push("access_str_off", u32_at(bytes, 8)?.to_string());
    decoded.push("kind", named(u64::from(u32_at(bytes, 12)?), CORE_KINDS));
    Some(decoded)
}

/// One `__u32` or `__u64` of an integer array, in decimal and hex.
pub(super) fn number(bytes: &[u8], width: usize) -> Option<Decoded> {
    let value = if width == 4 {
        u64::from(u32_at(bytes, 0)?)
    } else {
        u64_at(bytes, 0)?
    };
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("value", value.to_string());
    decoded.push("hex", format!("{value:#x}"));
    Some(decoded)
}

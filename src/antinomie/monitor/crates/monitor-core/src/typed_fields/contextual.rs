// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Decoders that need the call's meaning, not only the field's layout: a
//! socket option's value by its level and name, wait4's status, select's
//! descriptor sets by their `nfds`, the descriptor pairs of pipe and
//! socketpair, ptrace's words, and the small structures a socket option
//! carries that the inventory has no member list for (`ucred`, `ip_mreq`).
//! Compat (32-bit) fields are read here too, by their own layout names and
//! word sizes (`u32[]` descriptor sets); the call's name is the ABI table's,
//! so the compat spellings (`waitpid`, `_newselect`) are listed beside the
//! native ones.
use super::{Call, Decoded, Shape, i32_at, named, signals, u32_at, u64_at};
use crate::FieldSummary;

mod sockopt;

pub use sockopt::PROTOCOLS;

/// The register argument the field was captured for.
fn argument(field: &FieldSummary) -> Option<usize> {
    super::argument_of(field)
}

pub(super) fn decode(
    call: Option<&Call<'_>>,
    field: &FieldSummary,
    layout: &str,
    data: &[u8],
) -> Option<Decoded> {
    let abi = super::layout::abi_of_layout(&field.layout)?;
    let call = call?;
    let arg = argument(field)?;
    match (call.name, arg, layout) {
        ("setsockopt" | "getsockopt", 3, _) => sockopt::value(abi, call, layout, data),
        ("wait4" | "waitpid", 1, "wait_status" | "int") => wait_status(data),
        (
            "select" | "_newselect" | "pselect6" | "pselect6_time64",
            1..=3,
            "unsigned_long[]" | "u32[]",
        ) => {
            // The word is the program's `unsigned long`: 4 bytes on a 32-bit ABI.
            let word = super::layout::stride(abi, layout).unwrap_or(8);
            descriptor_set(call, data, word)
        }
        ("sched_setaffinity" | "sched_getaffinity", 2, "unsigned_long[]" | "u32[]")
        | ("mbind", 3, "unsigned_long[]" | "u32[]")
        | ("set_mempolicy" | "get_mempolicy", 1, "unsigned_long[]" | "u32[]")
        | ("migrate_pages", 2..=3, "unsigned_long[]" | "u32[]") => Some(super::aio::bit_list(data)),
        ("ptrace", 3, "") if field.key.ends_with("iovec.data") => {
            let length = field
                .logical_len
                .map_or(data.len(), |len| usize::try_from(len).unwrap_or(usize::MAX));
            super::regset::decode(call, length, data)
        }
        ("pipe" | "pipe2", 0, "int[2]") => pair(data, "read", "write"),
        ("socketpair", 3, "int[2]") => pair(data, "fd0", "fd1"),
        ("ptrace", 3, "u64") | ("arch_prctl", 1, "u64") => word(data),
        _ => None,
    }
}

/// A 64-bit word the program reads back as an address or a value: hex.
fn word(data: &[u8]) -> Option<Decoded> {
    Some(Decoded::value(format!("{:#x}", u64_at(data, 0)?)))
}

/// Two descriptors as a structure of their roles.
fn pair(data: &[u8], first: &str, second: &str) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push(first, i32_at(data, 0)?.to_string());
    decoded.push(second, i32_at(data, 4)?.to_string());
    Some(decoded)
}

const PTRACE_EVENTS: &[(&str, u64)] = &[
    ("PTRACE_EVENT_FORK", 1),
    ("PTRACE_EVENT_VFORK", 2),
    ("PTRACE_EVENT_CLONE", 3),
    ("PTRACE_EVENT_EXEC", 4),
    ("PTRACE_EVENT_VFORK_DONE", 5),
    ("PTRACE_EVENT_EXIT", 6),
    ("PTRACE_EVENT_SECCOMP", 7),
    ("PTRACE_EVENT_STOP", 128),
];

/// A wait status as what happened: `exited 0`, `killed by SIGSEGV (core
/// dumped)`, `stopped by SIGSTOP`, `continued`.
pub(super) fn wait_status_text(status: u32) -> String {
    if status == 0xffff {
        return "continued".into();
    }
    let signal = status & 0x7f;
    match signal {
        0 => format!("exited {}", (status >> 8) & 0xff),
        0x7f => {
            let stop = (status >> 8) & 0xff;
            let event = status >> 16;
            let by = if stop == 0x85 {
                "SIGTRAP|0x80".to_owned()
            } else {
                signals::signal_name(u64::from(stop))
            };
            if event == 0 {
                format!("stopped by {by}")
            } else {
                format!(
                    "stopped by {by} ({})",
                    named(u64::from(event), PTRACE_EVENTS)
                )
            }
        }
        _ => format!(
            "killed by {}{}",
            signals::signal_name(u64::from(signal)),
            if status & 0x80 != 0 {
                " (core dumped)"
            } else {
                ""
            }
        ),
    }
}

fn wait_status(data: &[u8]) -> Option<Decoded> {
    Some(Decoded::value(wait_status_text(u32_at(data, 0)?)))
}

/// select's `fd_set` of `word`-byte words (8 for a 64-bit program, 4 for a
/// 32-bit one): the descriptors below `nfds` whose bit is set, as `fd N`.
fn descriptor_set(call: &Call<'_>, data: &[u8], word: usize) -> Option<Decoded> {
    let limit = call.args.map_or(usize::MAX, |args| {
        usize::try_from(args[0] as u32).unwrap_or(usize::MAX)
    });
    let mut decoded = Decoded::new(Shape::List);
    let width = word * 8;
    for (index, chunk) in data.chunks(word).enumerate() {
        if chunk.len() < word {
            decoded.more = true;
            break;
        }
        let bits = super::spec::word(chunk, 0, word)?;
        for bit in 0..width {
            let fd = index * width + bit;
            if fd >= limit {
                return Some(decoded);
            }
            if bits >> bit & 1 == 1 {
                decoded.push("", format!("fd {fd}"));
            }
        }
    }
    Some(decoded)
}

/// An IPv4 address, `10.0.0.1`.
pub(super) fn ipv4(data: &[u8], at: usize) -> Option<String> {
    let bytes = data.get(at..at + 4)?;
    Some(format!(
        "{}.{}.{}.{}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

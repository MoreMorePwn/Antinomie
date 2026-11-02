// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Classic BPF (`struct sock_filter`) as text: `code` (u16) at 0, `jt` at 2,
//! `jf` at 3, `k` (u32) at 4, written the way `tcpdump -d` writes them
//! (`ldh [12]`, `jeq #0x800 jt 2 jf 5`, `ret #262144`). A filter passed to
//! `seccomp`/`prctl` reads a `seccomp_data`, so its loads are named by field
//! and returns by action; one passed to a socket option reads a packet.
use super::{Ctx, hex};
use crate::typed_fields::{Decoded, Shape, named, u8_at, u16_at, u32_at};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    Seccomp,
    Packet,
    Unknown,
}

fn input(call: &str) -> Input {
    match call {
        "seccomp" | "prctl" => Input::Seccomp,
        "setsockopt" | "getsockopt" => Input::Packet,
        _ => Input::Unknown,
    }
}

const ACTIONS: &[(&str, u64)] = &[
    ("SECCOMP_RET_KILL_PROCESS", 0x8000_0000),
    ("SECCOMP_RET_KILL_THREAD", 0),
    ("SECCOMP_RET_TRAP", 0x0003_0000),
    ("SECCOMP_RET_ERRNO", 0x0005_0000),
    ("SECCOMP_RET_USER_NOTIF", 0x7fc0_0000),
    ("SECCOMP_RET_TRACE", 0x7ff0_0000),
    ("SECCOMP_RET_LOG", 0x7ffc_0000),
    ("SECCOMP_RET_ALLOW", 0x7fff_0000),
];

/// `struct seccomp_data`: `nr` at 0, `arch` at 4, `instruction_pointer` at 8,
/// `args[6]` from 16.
fn seccomp_field(k: u32) -> Option<String> {
    Some(match k {
        0 => "seccomp_data.nr".to_owned(),
        4 => "seccomp_data.arch".to_owned(),
        8 => "seccomp_data.instruction_pointer (low)".to_owned(),
        12 => "seccomp_data.instruction_pointer (high)".to_owned(),
        16..=60 => {
            let at = k - 16;
            format!(
                "seccomp_data.args[{}] ({})",
                at / 8,
                if at.is_multiple_of(8) { "low" } else { "high" }
            )
        }
        _ => return None,
    })
}

fn action(k: u32) -> String {
    let name = named(u64::from(k & 0xffff_0000), ACTIONS);
    if name.chars().all(|c| c.is_ascii_digit()) {
        return format!("unknown action {k:#x}");
    }
    match k & 0xffff {
        0 => name,
        data => format!("{name}, data {data}"),
    }
}

pub(super) fn decode(ctx: &Ctx<'_>, bytes: &[u8]) -> Option<Decoded> {
    let code = u16_at(bytes, 0)?;
    let (jt, jf) = (u8_at(bytes, 2)?, u8_at(bytes, 3)?);
    let k = u32_at(bytes, 4)?;
    let input = input(ctx.call);
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("index", ctx.index.to_string());
    decoded.push("code", format!("{code:#06x}"));
    decoded.push("jt", jt.to_string());
    decoded.push("jf", jf.to_string());
    decoded.push("k", format!("{k:#x}"));
    decoded.push("asm", assemble(ctx, code, jt, jf, k, input));
    Some(decoded)
}

fn assemble(ctx: &Ctx<'_>, code: u16, jt: u8, jf: u8, k: u32, input: Input) -> String {
    let size = match code & 0x18 {
        0x00 => "",
        0x08 => "h",
        0x10 => "b",
        _ => "?",
    };
    let target = |offset: u32| {
        let at = ctx.index as u64 + 1 + u64::from(offset);
        if at < ctx.total as u64 {
            at.to_string()
        } else {
            "outside".to_owned()
        }
    };
    match code & 7 {
        0 | 1 => {
            let register = if code & 7 == 0 { "ld" } else { "ldx" };
            match code & 0xe0 {
                0x00 => format!("{register} #{k:#x}"),
                0x20 => {
                    let note = (input == Input::Seccomp && size.is_empty())
                        .then(|| seccomp_field(k))
                        .flatten()
                        .map_or_else(String::new, |name| format!(" ; {name}"));
                    format!("{register}{size} [{k}]{note}")
                }
                0x40 => format!("{register}{size} [x+{k}]"),
                0x60 => format!("{register} M[{k}]"),
                0x80 => format!("{register} #len"),
                0xa0 => format!("ldx 4*([{k}]&0xf)"),
                _ => format!("unknown code {code:#06x}"),
            }
        }
        2 => format!("st M[{k}]"),
        3 => format!("stx M[{k}]"),
        4 => {
            let op = match code & 0xf0 {
                0x00 => "add",
                0x10 => "sub",
                0x20 => "mul",
                0x30 => "div",
                0x40 => "or",
                0x50 => "and",
                0x60 => "lsh",
                0x70 => "rsh",
                0x80 => return "neg".into(),
                0x90 => "mod",
                0xa0 => "xor",
                _ => return format!("unknown code {code:#06x}"),
            };
            if code & 8 == 0 {
                format!("{op} #{k:#x}")
            } else {
                format!("{op} x")
            }
        }
        5 => {
            if code & 0xf0 == 0 {
                return format!("jmp {}", target(k));
            }
            let op = match code & 0xf0 {
                0x10 => "jeq",
                0x20 => "jgt",
                0x30 => "jge",
                0x40 => "jset",
                _ => return format!("unknown code {code:#06x}"),
            };
            let operand = if code & 8 == 0 {
                format!("#{k:#x}")
            } else {
                "x".to_owned()
            };
            let note = (code & 8 == 0)
                .then(|| compare_note(ctx, k, input))
                .flatten()
                .map_or_else(String::new, |note| format!(" ; {note}"));
            format!(
                "{op} {operand} jt {} jf {}{note}",
                target(u32::from(jt)),
                target(u32::from(jf))
            )
        }
        6 => match code & 0x18 {
            0x10 => "ret a".into(),
            0x08 => "ret x".into(),
            _ if input == Input::Seccomp => format!("ret #{k:#x} ; {}", action(k)),
            _ => format!("ret #{k:#x}"),
        },
        _ => match code & 0xf8 {
            0x00 => "tax".into(),
            0x80 => "txa".into(),
            _ => format!("unknown code {code:#06x}"),
        },
    }
}

/// What a compare with `k` means when the load right before it was a seccomp
/// field: a syscall name for `nr`, an architecture for `arch`.
fn compare_note(ctx: &Ctx<'_>, k: u32, input: Input) -> Option<String> {
    if input != Input::Seccomp || ctx.at < 8 {
        return None;
    }
    let before = ctx.data.get(ctx.at - 8..ctx.at)?;
    if u16_at(before, 0)? != 0x20 {
        return None;
    }
    match u32_at(before, 4)? {
        0 => crate::syscalls::known_name(u64::from(k)).map(str::to_owned),
        4 => Some(match k {
            0xc000_003e => "AUDIT_ARCH_X86_64".to_owned(),
            0xc000_00b7 => "AUDIT_ARCH_AARCH64".to_owned(),
            0x4000_0003 => "AUDIT_ARCH_I386".to_owned(),
            _ => format!("architecture {}", hex(&k.to_le_bytes())),
        }),
        _ => None,
    }
}

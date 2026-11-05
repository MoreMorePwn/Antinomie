// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The register sets `PTRACE_GETREGSET` and `PTRACE_SETREGSET` pass: the
//! iovec's data has no layout name, so the set is told by the note type the
//! call passes (`addr`) and the length of the set, which also says which
//! architecture it belongs to (an aarch64 `user_pt_regs` is 272 bytes, an
//! x86-64 `user_regs_struct` 216, an AArch32 task's 72, an i386 task's 68).
//! Only the first 256 captured bytes are decoded: on aarch64 the program
//! counter and the processor state, which end the set, lie past them.
use super::spec::{self, Item, Show, u32f, u64f};
use super::{Call, Decoded, Node, flags, frames, named};
use crate::syscalls::Abi;

const PTRACE_GETREGSET: u64 = 0x4204;
const PTRACE_SETREGSET: u64 = 0x4205;

const PSTATE: &[(&str, u64)] = &[
    ("N", 1 << 31),
    ("Z", 1 << 30),
    ("C", 1 << 29),
    ("V", 1 << 28),
    ("TCO", 1 << 25),
    ("DIT", 1 << 24),
    ("UAO", 1 << 23),
    ("PAN", 1 << 22),
    ("SS", 1 << 21),
    ("IL", 1 << 20),
    ("SSBS", 1 << 12),
    ("D", 1 << 9),
    ("A", 1 << 8),
    ("I", 1 << 7),
    ("F", 1 << 6),
];

const CPSR: &[(&str, u64)] = &[
    ("N", 1 << 31),
    ("Z", 1 << 30),
    ("C", 1 << 29),
    ("V", 1 << 28),
    ("Q", 1 << 27),
    ("J", 1 << 24),
    ("E", 1 << 9),
    ("A", 1 << 8),
    ("I", 1 << 7),
    ("F", 1 << 6),
    ("T", 1 << 5),
];

const EL_MODES: &[(&str, u64)] = &[
    ("EL0t", 0x0),
    ("EL1t", 0x4),
    ("EL1h", 0x5),
    ("EL2t", 0x8),
    ("EL2h", 0x9),
];

const ARM_MODES: &[(&str, u64)] = &[
    ("USR", 0x10),
    ("FIQ", 0x11),
    ("IRQ", 0x12),
    ("SVC", 0x13),
    ("ABT", 0x17),
    ("HYP", 0x1a),
    ("UND", 0x1b),
    ("SYS", 0x1f),
];

fn with_flags(mode: String, value: u64, table: &[(&str, u64)]) -> String {
    let mask = table.iter().fold(0, |mask, (_, bit)| mask | bit);
    match flags(value & mask, table).as_str() {
        "0" => mode,
        set => format!("{mode} {set}"),
    }
}

/// An AArch32 `cpsr`: `USR N|C|T` (T is Thumb state).
pub(super) fn cpsr_text(value: u64) -> String {
    let mode = named(value & 0x1f, ARM_MODES);
    with_flags(mode, value, CPSR)
}

/// An aarch64 `pstate`: `EL0t N|C`; with bit 4 set the task runs AArch32 and
/// the value is a `cpsr`.
pub(super) fn pstate_text(value: u64) -> String {
    if value & 0x10 != 0 {
        return cpsr_text(value);
    }
    with_flags(named(value & 0xf, EL_MODES), value, PSTATE)
}

fn x_registers(count: usize, data: &[u8]) -> Vec<Node> {
    (0..count)
        .filter_map(|n| {
            let value = spec::word(data, 8 * n, 8)?;
            Some(Node::leaf(format!("x{n}"), format!("{value:#x}")))
        })
        .collect()
}

/// aarch64 `struct user_pt_regs`: x0-x30, sp, pc, pstate.
fn aarch64_regs(data: &[u8]) -> Option<Decoded> {
    let mut cut = data.len() < 272;
    let regs = x_registers(31, data);
    if regs.is_empty() {
        return None;
    }
    let mut tree = Vec::new();
    tree.push(Node {
        name: "regs".into(),
        text: spec::struct_line(&regs),
        children: regs,
    });
    let tail = [
        u64f("sp", 248, Show::Hex),
        u64f("pc", 256, Show::Hex),
        u64f("pstate", 264, Show::Custom(pstate_text)),
    ];
    tree.extend(spec::nodes(&tail, data, &mut cut));
    Some(spec::from_nodes(tree, cut))
}

/// An AArch32 task's `NT_PRSTATUS`: r0-r12, sp, lr, pc, cpsr, orig_r0.
fn arm_regs(data: &[u8]) -> Option<Decoded> {
    const NAMES: [&str; 13] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
    ];
    let mut cut = data.len() < 72;
    let mut regs = Vec::new();
    for (n, name) in NAMES.iter().enumerate() {
        if let Some(value) = spec::word(data, 4 * n, 4) {
            regs.push(Node::leaf(*name, format!("{value:#x}")));
        }
    }
    if regs.is_empty() {
        return None;
    }
    let mut tree = vec![Node {
        name: "regs".into(),
        text: spec::struct_line(&regs),
        children: regs,
    }];
    let tail = [
        u32f("sp", 52, Show::Hex),
        u32f("lr", 56, Show::Hex),
        u32f("pc", 60, Show::Hex),
        u32f("cpsr", 64, Show::Custom(cpsr_text)),
        u32f("orig_r0", 68, Show::Hex),
    ];
    tree.extend(spec::nodes(&tail, data, &mut cut));
    Some(spec::from_nodes(tree, cut))
}

/// An i386 task's `struct user_regs_struct`, 17 words.
fn i386_regs(data: &[u8]) -> Option<Decoded> {
    let items: Vec<Item> = [
        "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds", "es", "fs", "gs", "orig_eax", "eip",
        "cs", "eflags", "esp", "ss",
    ]
    .iter()
    .enumerate()
    .map(|(n, name)| {
        let show = if *name == "eflags" {
            Show::Custom(eflags_text)
        } else {
            Show::Hex
        };
        u32f(name, 4 * n, show)
    })
    .collect();
    spec::structure(&items, data)
}

fn eflags_text(value: u64) -> String {
    flags(value & !0x2, super::layout::names::EFLAGS)
}

/// aarch64 `struct user_fpsimd_state`: v0-v31, fpsr, fpcr.
fn fpsimd(data: &[u8]) -> Option<Decoded> {
    let mut cut = data.len() < 520;
    let held = (data.len() / 16).min(32);
    if held == 0 {
        return None;
    }
    let used = (0..held)
        .filter(|n| data[16 * n..16 * n + 16].iter().any(|byte| *byte != 0))
        .count();
    let text = if held < 32 {
        format!("{used} of the first {held}")
    } else {
        used.to_string()
    };
    let mut tree = vec![Node::leaf("v_registers_in_use", text)];
    let tail = [u32f("fpsr", 512, Show::Hex), u32f("fpcr", 516, Show::Hex)];
    tree.extend(spec::nodes(&tail, data, &mut cut));
    Some(spec::from_nodes(tree, cut))
}

/// An AArch32 task's `NT_ARM_VFP`: d0-d31 and fpscr.
fn vfp(data: &[u8]) -> Option<Decoded> {
    let mut cut = data.len() < 260;
    let held = (data.len() / 8).min(32);
    if held == 0 {
        return None;
    }
    let used = (0..held)
        .filter(|n| data[8 * n..8 * n + 8].iter().any(|byte| *byte != 0))
        .count();
    let text = if held < 32 {
        format!("{used} of the first {held}")
    } else {
        used.to_string()
    };
    let mut tree = vec![Node::leaf("d_registers_in_use", text)];
    tree.extend(spec::nodes(
        &[u32f("fpscr", 256, Show::Hex)],
        data,
        &mut cut,
    ));
    Some(spec::from_nodes(tree, cut))
}

/// The register set a `PTRACE_GETREGSET` or `PTRACE_SETREGSET` call carries,
/// of `length` bytes. None for a call that is not one, or a set this does
/// not know by its note type and length.
pub(super) fn decode(call: &Call<'_>, length: usize, data: &[u8]) -> Option<Decoded> {
    let args = call.args?;
    if args[0] != PTRACE_GETREGSET && args[0] != PTRACE_SETREGSET {
        return None;
    }
    let note = args[2] & 0xffff_ffff;
    let mut decoded = match (note, length) {
        (1, 272) => aarch64_regs(data)?,
        (1, 216) => {
            super::layout::decode(Abi::X86_64, "user_regs_struct", Some(call), Some(3), data)?
        }
        (1, 72) => arm_regs(data)?,
        (1, 68) => i386_regs(data)?,
        (2, 528) => fpsimd(data)?,
        (2 | 0x202, 512..) => frames::fxregs(data)?,
        (0x400, 260) => vfp(data)?,
        (0x401, 4 | 8) => {
            let width = length;
            Decoded::value(format!("tpidr {:#x}", spec::word(data, 0, width)?))
        }
        _ => return None,
    };
    decoded.more |= length > data.len();
    Some(decoded)
}

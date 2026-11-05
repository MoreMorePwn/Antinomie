// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The frames the kernel reads from the user stack on `rt_sigreturn` and
//! `uretprobe`: the signal frame (`context.rt_sigframe`) of x86-64 and
//! aarch64, the x87/SSE save area (`context.fpstate`), the extended state
//! after it (`context.fpstate.xstate`) and the three registers the uretprobe
//! trampoline pushed. The registers a handler returns to are shown by name;
//! the floating-point and vector state as a summary of which components
//! hold anything, never every byte. Only the first 256 bytes of a field are
//! kept, so a frame's tail (the signal mask, `siginfo`) is usually not here.
use super::layout::names::EFLAGS;
use super::spec::{self, Item, Show, Table, i32f, u16f, u32f, u64f};
use super::{Decoded, Node, flags, signals};
use crate::syscalls::Abi;

fn eflags_text(value: u64) -> String {
    flags(value & !0x2, EFLAGS)
}

const FP_XSTATE_MAGIC1: u64 = 0x4650_5853;

const XFEATURES: Table = &[
    ("X87", 1 << 0),
    ("SSE", 1 << 1),
    ("YMM", 1 << 2),
    ("BNDREGS", 1 << 3),
    ("BNDCSR", 1 << 4),
    ("OPMASK", 1 << 5),
    ("ZMM_Hi256", 1 << 6),
    ("Hi16_ZMM", 1 << 7),
    ("PT", 1 << 8),
    ("PKRU", 1 << 9),
    ("PASID", 1 << 10),
    ("CET_USER", 1 << 11),
    ("CET_KERNEL", 1 << 12),
    ("UINTR", 1 << 14),
    ("LBR", 1 << 15),
    ("XTILE_CFG", 1 << 17),
    ("XTILE_DATA", 1 << 18),
];

/// `struct sigcontext` of x86-64, from offset 48 of the frame.
const X86_CONTEXT: &[Item] = &[
    u64f("r8", 48, Show::Hex),
    u64f("r9", 56, Show::Hex),
    u64f("r10", 64, Show::Hex),
    u64f("r11", 72, Show::Hex),
    u64f("r12", 80, Show::Hex),
    u64f("r13", 88, Show::Hex),
    u64f("r14", 96, Show::Hex),
    u64f("r15", 104, Show::Hex),
    u64f("rdi", 112, Show::Hex),
    u64f("rsi", 120, Show::Hex),
    u64f("rbp", 128, Show::Hex),
    u64f("rbx", 136, Show::Hex),
    u64f("rdx", 144, Show::Hex),
    u64f("rax", 152, Show::Hex),
    u64f("rcx", 160, Show::Hex),
    u64f("rsp", 168, Show::Hex),
    u64f("rip", 176, Show::Hex),
    u64f("eflags", 184, Show::Custom(eflags_text)),
    u16f("cs", 192, Show::Hex),
    u16f("gs", 194, Show::Hex),
    u16f("fs", 196, Show::Hex),
    u16f("ss", 198, Show::Hex),
    u64f("err", 200, Show::Hex),
    u64f("trapno", 208, Show::Dec),
    u64f("oldmask", 216, Show::Hex),
    u64f("cr2", 224, Show::Hex),
    u64f("fpstate", 232, Show::Ptr),
];

fn stack(at: usize) -> [Item<'static>; 3] {
    [
        u64f("ss_sp", at, Show::Ptr),
        i32f("ss_flags", at + 8, Show::Dec),
        u64f("ss_size", at + 16, Show::Dec),
    ]
}

/// The x86-64 frame: `{pretcode, ucontext{uc_flags, uc_link, uc_stack,
/// uc_mcontext, uc_sigmask}, info}`.
fn x86_frame(data: &[u8]) -> Option<Decoded> {
    let mut cut = false;
    let mut tree = spec::nodes(&[u64f("pretcode", 0, Show::Ptr)], data, &mut cut);
    let stack = stack(24);
    let uc = [
        u64f("uc_flags", 8, Show::Hex),
        u64f("uc_link", 16, Show::Ptr),
        Item::Group("uc_stack", &stack),
        Item::Group("uc_mcontext", X86_CONTEXT),
        u64f("uc_sigmask", 304, Show::SigSet),
    ];
    tree.extend(spec::nodes(&[Item::Group("uc", &uc)], data, &mut cut));
    // The siginfo follows the 312-byte head; a short capture stops before it.
    match data.get(312..440).and_then(signals::siginfo) {
        Some(info) => tree.push(Node {
            name: "info".into(),
            text: info.full_line(),
            children: info.nodes(),
        }),
        None => cut = true,
    }
    if tree.is_empty() {
        return None;
    }
    Some(spec::from_nodes(tree, cut))
}

/// The aarch64 frame: `{info, ucontext{uc_flags, uc_link, uc_stack,
/// uc_sigmask, uc_mcontext{fault_address, regs, sp, pc, pstate}}}.
fn aarch64_frame(data: &[u8]) -> Option<Decoded> {
    let mut cut = false;
    let mut tree = Vec::new();
    match data.get(..128).and_then(signals::siginfo) {
        Some(info) => tree.push(Node {
            name: "info".into(),
            text: info.full_line(),
            children: info.nodes(),
        }),
        None => cut = true,
    }
    let stack = stack(144);
    let head = [
        u64f("uc_flags", 128, Show::Hex),
        u64f("uc_link", 136, Show::Ptr),
        Item::Group("uc_stack", &stack),
        u64f("uc_sigmask", 168, Show::SigSet),
    ];
    let mut uc = spec::nodes(&head, data, &mut cut);
    let mut context = spec::nodes(&[u64f("fault_address", 304, Show::Hex)], data, &mut cut);
    // x0-x30 sit between the fault address and sp.
    let regs: Vec<Node> = (0..31)
        .filter_map(|n| {
            let value = spec::word(data, 312 + 8 * n, 8)?;
            Some(Node::leaf(format!("x{n}"), format!("{value:#x}")))
        })
        .collect();
    if !regs.is_empty() {
        context.push(Node {
            name: "regs".into(),
            text: spec::struct_line(&regs),
            children: regs,
        });
    }
    let tail = [
        u64f("sp", 560, Show::Hex),
        u64f("pc", 568, Show::Hex),
        u64f("pstate", 576, Show::Custom(super::regset::pstate_text)),
    ];
    context.extend(spec::nodes(&tail, data, &mut cut));
    if !context.is_empty() {
        uc.push(Node {
            name: "uc_mcontext".into(),
            text: spec::struct_line(&context),
            children: context,
        });
    }
    if !uc.is_empty() {
        tree.push(Node {
            name: "uc".into(),
            text: spec::struct_line(&uc),
            children: uc,
        });
    }
    if tree.is_empty() {
        return None;
    }
    Some(spec::from_nodes(tree, cut))
}

pub(super) fn rt_sigframe(abi: Abi, data: &[u8]) -> Option<Decoded> {
    match abi {
        Abi::Aarch64 => aarch64_frame(data),
        _ => x86_frame(data),
    }
}

/// How many of the 16-byte registers from `at` in `data` hold a non-zero
/// byte, among those the capture has whole.
fn live_registers(data: &[u8], at: usize, count: usize) -> usize {
    (0..count)
        .filter_map(|n| data.get(at + 16 * n..at + 16 * n + 16))
        .filter(|register| register.iter().any(|byte| *byte != 0))
        .count()
}

/// `struct fxregs_state`: the x87 and SSE control words and which registers
/// are in use, plus the software-reserved extension record at 464.
pub(super) fn fxregs(data: &[u8]) -> Option<Decoded> {
    let mut cut = false;
    let items = [
        u16f("cwd", 0, Show::Hex),
        u16f("swd", 2, Show::Hex),
        u16f("twd", 4, Show::Hex),
        u16f("fop", 6, Show::Hex),
        u64f("rip", 8, Show::Hex),
        u64f("rdp", 16, Show::Hex),
        u32f("mxcsr", 24, Show::Hex),
        u32f("mxcsr_mask", 28, Show::Hex),
    ];
    let mut tree = spec::nodes(&items, data, &mut cut);
    if tree.is_empty() {
        return None;
    }
    if data.len() >= 160 {
        let used = live_registers(data, 32, 8);
        tree.push(Node::leaf("st_registers_in_use", used.to_string()));
    }
    if data.len() >= 176 {
        let held = ((data.len() - 160) / 16).min(16);
        let used = live_registers(data, 160, 16);
        let of = if held < 16 {
            format!("{used} of the first {held}")
        } else {
            used.to_string()
        };
        tree.push(Node::leaf("xmm_registers_in_use", of));
    }
    let extension = [
        u32f("magic1", 464, Show::Custom(magic_text)),
        u32f("extended_size", 468, Show::Dec),
        u64f("xfeatures", 472, Show::Flags(XFEATURES)),
        u32f("xstate_size", 480, Show::Dec),
    ];
    let extra = spec::nodes(&[Item::Group("sw_reserved", &extension)], data, &mut cut);
    tree.extend(extra);
    Some(spec::from_nodes(tree, cut))
}

fn magic_text(value: u64) -> String {
    if value == FP_XSTATE_MAGIC1 {
        "FP_XSTATE_MAGIC1".into()
    } else {
        format!("{value:#x}")
    }
}

/// The extended state after the legacy 512 bytes of an `xsave` area: the
/// header's feature masks and the 256-bit upper halves in use.
pub(super) fn xstate(data: &[u8]) -> Option<Decoded> {
    let mut cut = false;
    let items = [
        u64f("xfeatures", 0, Show::Flags(XFEATURES)),
        u64f("xcomp_bv", 8, Show::Hex),
    ];
    let mut tree = spec::nodes(&items, data, &mut cut);
    if tree.is_empty() {
        return None;
    }
    let features = spec::word(data, 0, 8).unwrap_or(0);
    // The standard format puts the upper halves of ymm0-15 at 576 of the area,
    // 64 bytes into this field.
    if features & 0b100 != 0 {
        if data.len() > 64 {
            let held = ((data.len() - 64) / 16).min(16);
            let used = live_registers(data, 64, 16);
            let text = if held < 16 {
                format!("{used} of the first {held}")
            } else {
                used.to_string()
            };
            tree.push(Node::leaf("ymm_hi128_in_use", text));
        } else {
            cut = true;
        }
    }
    tree.push(Node::leaf("bytes", data.len().to_string()));
    Some(spec::from_nodes(tree, cut))
}

/// The registers the uretprobe trampoline saved.
pub(super) fn uretprobe(data: &[u8]) -> Option<Decoded> {
    spec::structure(
        &[
            u64f("r11", 0, Show::Hex),
            u64f("rcx", 8, Show::Hex),
            u64f("rax", 16, Show::Hex),
        ],
        data,
    )
}

// SPDX-License-Identifier: GPL-3.0-only
//! The 32-bit ARM (AArch32) target description, for AArch32 programs of arm64
//! guests (guest contract revision 21, `DEBUG_CAPS` bit `AARCH32`).
//!
//! The guest keeps `arch` EM_AARCH64 and serves a compat task its
//! `user_aarch32_ptrace_view` regsets: `NT_PRSTATUS` is 18 words (r0-r12, sp,
//! lr, pc, cpsr, orig_r0), `NT_ARM_VFP` 260 bytes (d0..d31 as u64, then fpscr)
//! and `NT_ARM_TLS` 4 bytes (TPIDRURO). The register image follows GDB's
//! arm-linux feature order: `org.gnu.gdb.arm.core`, the VFP feature and a TLS
//! register. CPSR bit 5 (T) says Thumb: the debugger plants a 2-byte
//! breakpoint at Thumb code and a 4-byte one at ARM code.
use super::regs::{FeatureSpec, RegKind, RegSource, RegSpec, TargetDescription};
use std::sync::OnceLock;

pub const NT_PRSTATUS: u32 = 1;
pub const NT_ARM_VFP: u32 = 0x400;
pub const NT_ARM_TLS: u32 = 0x401;

/// `NT_PRSTATUS` of an AArch32 task: r0-r15, cpsr, orig_r0.
pub const PRSTATUS_SIZE: usize = 72;
pub const VFP_SIZE: usize = 260;
/// CPSR bit 5: Thumb state.
pub const CPSR_THUMB: u32 = 1 << 5;
/// Break patterns' lengths (guest contract): A32 and Thumb (T16) breakpoint.
pub const ARM_BREAKPOINT_LEN: u32 = 4;
pub const THUMB_BREAKPOINT_LEN: u32 = 2;

const CORE: &str = "org.gnu.gdb.arm.core";
const VFP: &str = "org.gnu.gdb.arm.vfp";
const TLS: &str = "org.gnu.gdb.arm.tls";

const CORE_TYPES: &str = r#"    <flags id="cpsr_flags" size="4">
      <field name="M" start="0" end="4"/>
      <field name="T" start="5" end="5"/>
      <field name="F" start="6" end="6"/>
      <field name="I" start="7" end="7"/>
      <field name="A" start="8" end="8"/>
      <field name="E" start="9" end="9"/>
      <field name="GE" start="16" end="19"/>
      <field name="J" start="24" end="24"/>
      <field name="Q" start="27" end="27"/>
      <field name="V" start="28" end="28"/>
      <field name="C" start="29" end="29"/>
      <field name="Z" start="30" end="30"/>
      <field name="N" start="31" end="31"/>
    </flags>
"#;

const R: [&str; 13] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
];
const D: [&str; 32] = [
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9", "d10", "d11", "d12", "d13", "d14",
    "d15", "d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27",
    "d28", "d29", "d30", "d31",
];

fn slice(nt_type: u32, offset: usize, len: usize) -> RegSource {
    RegSource::Slice {
        nt_type,
        offset,
        len,
    }
}

fn core_reg(name: &'static str, gdb_type: &'static str, kind: RegKind, word: usize) -> RegSpec {
    RegSpec {
        name,
        bits: 32,
        feature: CORE,
        gdb_type,
        group: Some("general"),
        kind,
        source: slice(NT_PRSTATUS, 4 * word, 4),
    }
}

fn build() -> TargetDescription {
    let mut regs = Vec::new();
    for (index, name) in R.iter().enumerate() {
        // r11 is the frame pointer in ARM state.
        let (gdb_type, kind) = match index {
            11 => ("data_ptr", RegKind::DataPointer),
            _ => ("uint32", RegKind::General),
        };
        regs.push(core_reg(name, gdb_type, kind, index));
    }
    regs.push(core_reg("sp", "data_ptr", RegKind::DataPointer, 13));
    regs.push(core_reg("lr", "code_ptr", RegKind::General, 14));
    regs.push(core_reg("pc", "code_ptr", RegKind::CodePointer, 15));
    regs.push(core_reg("cpsr", "cpsr_flags", RegKind::Flags, 16));
    for (index, name) in D.iter().enumerate() {
        regs.push(RegSpec {
            name,
            bits: 64,
            feature: VFP,
            gdb_type: "ieee_double",
            group: Some("float"),
            kind: RegKind::Float,
            source: slice(NT_ARM_VFP, 8 * index, 8),
        });
    }
    regs.push(RegSpec {
        name: "fpscr",
        bits: 32,
        feature: VFP,
        gdb_type: "int",
        group: Some("float"),
        kind: RegKind::FloatControl,
        source: slice(NT_ARM_VFP, 256, 4),
    });
    regs.push(RegSpec {
        name: "tpidruro",
        bits: 32,
        feature: TLS,
        gdb_type: "data_ptr",
        group: Some("system"),
        kind: RegKind::System,
        source: slice(NT_ARM_TLS, 0, 4),
    });
    TargetDescription {
        architecture: "arm",
        osabi: Some("GNU/Linux"),
        features: vec![
            FeatureSpec {
                name: CORE,
                types: CORE_TYPES,
            },
            FeatureSpec {
                name: VFP,
                types: "",
            },
            FeatureSpec {
                name: TLS,
                types: "",
            },
        ],
        regs,
        regsets: vec![NT_PRSTATUS, NT_ARM_VFP, NT_ARM_TLS],
    }
}

pub fn description() -> &'static TargetDescription {
    static DESCRIPTION: OnceLock<TargetDescription> = OnceLock::new();
    DESCRIPTION.get_or_init(build)
}

/// The software breakpoint length for a gdb `Z0` kind on an ARM target: 4 is an
/// ARM-state breakpoint, 2 and 3 Thumb (a 32-bit Thumb-2 instruction takes the
/// 2-byte trap at its first halfword). Anything else is not an ARM kind.
pub fn breakpoint_len_for_kind(kind: u64) -> Option<u32> {
    match kind {
        4 => Some(ARM_BREAKPOINT_LEN),
        2 | 3 => Some(THUMB_BREAKPOINT_LEN),
        _ => None,
    }
}

/// Whether an `NT_PRSTATUS` blob is the AArch32 one (the guest gives a compat
/// task 72 bytes, a native one 272).
pub fn is_compat_prstatus(blob: &[u8]) -> bool {
    blob.len() == PRSTATUS_SIZE
}

/// The instruction set a stopped thread executes in, from its `NT_PRSTATUS`.
pub fn thumb_state(prstatus: &[u8]) -> Option<bool> {
    let word = prstatus.get(64..68)?;
    Some(u32::from_le_bytes(word.try_into().ok()?) & CPSR_THUMB != 0)
}

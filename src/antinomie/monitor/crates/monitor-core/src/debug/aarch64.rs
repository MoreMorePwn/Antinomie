// SPDX-License-Identifier: GPL-3.0-only
//! The AArch64 target description.
//!
//! The register image follows GDB's aarch64-linux feature order, which this
//! file also publishes as the target description: core (x0..x30, sp, pc,
//! cpsr), fpu (v0..v31, fpsr, fpcr) and tls (tpidr). The kernel supplies
//! `NT_PRSTATUS` (`struct user_pt_regs`: 31 registers, sp, pc, pstate),
//! `NT_PRFPREG` (`struct user_fpsimd_state`: 32 128-bit registers, fpsr,
//! fpcr) and `NT_ARM_TLS` (tpidr_el0).
use super::regs::{FeatureSpec, RegKind, RegSource, RegSpec, TargetDescription};
use std::sync::OnceLock;

pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRFPREG: u32 = 2;
pub const NT_ARM_TLS: u32 = 0x401;

pub const USER_PT_REGS_SIZE: usize = 272;
pub const FPSIMD_SIZE: usize = 528;

const CORE: &str = "org.gnu.gdb.aarch64.core";
const FPU: &str = "org.gnu.gdb.aarch64.fpu";
const TLS: &str = "org.gnu.gdb.aarch64.tls";

const CORE_TYPES: &str = r#"    <flags id="cpsr_flags" size="4">
      <field name="SP" start="0" end="0"/>
      <field name="EL" start="2" end="3"/>
      <field name="nRW" start="4" end="4"/>
      <field name="F" start="6" end="6"/>
      <field name="I" start="7" end="7"/>
      <field name="A" start="8" end="8"/>
      <field name="D" start="9" end="9"/>
      <field name="SSBS" start="12" end="12"/>
      <field name="IL" start="20" end="20"/>
      <field name="SS" start="21" end="21"/>
      <field name="PAN" start="22" end="22"/>
      <field name="UAO" start="23" end="23"/>
      <field name="V" start="28" end="28"/>
      <field name="C" start="29" end="29"/>
      <field name="Z" start="30" end="30"/>
      <field name="N" start="31" end="31"/>
    </flags>
"#;
const FPU_TYPES: &str = r#"    <vector id="v2d" type="ieee_double" count="2"/>
    <vector id="v2u" type="uint64" count="2"/>
    <vector id="v2i" type="int64" count="2"/>
    <vector id="v4f" type="ieee_single" count="4"/>
    <vector id="v4u" type="uint32" count="4"/>
    <vector id="v4i" type="int32" count="4"/>
    <vector id="v8u" type="uint16" count="8"/>
    <vector id="v8i" type="int16" count="8"/>
    <vector id="v16u" type="uint8" count="16"/>
    <vector id="v16i" type="int8" count="16"/>
    <vector id="v1u" type="uint128" count="1"/>
    <vector id="v1i" type="int128" count="1"/>
    <union id="vnd">
      <field name="f" type="v2d"/>
      <field name="u" type="v2u"/>
      <field name="s" type="v2i"/>
    </union>
    <union id="vns">
      <field name="f" type="v4f"/>
      <field name="u" type="v4u"/>
      <field name="s" type="v4i"/>
    </union>
    <union id="vnh">
      <field name="u" type="v8u"/>
      <field name="s" type="v8i"/>
    </union>
    <union id="vnb">
      <field name="u" type="v16u"/>
      <field name="s" type="v16i"/>
    </union>
    <union id="vnq">
      <field name="u" type="v1u"/>
      <field name="s" type="v1i"/>
    </union>
    <union id="aarch64v">
      <field name="d" type="vnd"/>
      <field name="s" type="vns"/>
      <field name="h" type="vnh"/>
      <field name="b" type="vnb"/>
      <field name="q" type="vnq"/>
    </union>
"#;

const X: [&str; 31] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30",
];
const V: [&str; 32] = [
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10", "v11", "v12", "v13", "v14",
    "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23", "v24", "v25", "v26", "v27",
    "v28", "v29", "v30", "v31",
];

fn slice(nt_type: u32, offset: usize, len: usize) -> RegSource {
    RegSource::Slice {
        nt_type,
        offset,
        len,
    }
}

fn core_reg(
    name: &'static str,
    bits: usize,
    gdb_type: &'static str,
    kind: RegKind,
    offset: usize,
) -> RegSpec {
    RegSpec {
        name,
        bits,
        feature: CORE,
        gdb_type,
        group: Some("general"),
        kind,
        source: slice(NT_PRSTATUS, offset, bits / 8),
    }
}

fn build() -> TargetDescription {
    let mut regs = Vec::new();
    for (index, name) in X.iter().enumerate() {
        // x29 is the frame pointer, x30 the link register.
        let (gdb_type, kind) = match index {
            29 => ("data_ptr", RegKind::DataPointer),
            30 => ("code_ptr", RegKind::General),
            _ => ("uint64", RegKind::General),
        };
        regs.push(core_reg(name, 64, gdb_type, kind, 8 * index));
    }
    regs.push(core_reg("sp", 64, "data_ptr", RegKind::DataPointer, 248));
    regs.push(core_reg("pc", 64, "code_ptr", RegKind::CodePointer, 256));
    regs.push(core_reg("cpsr", 32, "cpsr_flags", RegKind::Flags, 264));
    for (index, name) in V.iter().enumerate() {
        regs.push(RegSpec {
            name,
            bits: 128,
            feature: FPU,
            gdb_type: "aarch64v",
            group: Some("vector"),
            kind: RegKind::Vector,
            source: slice(NT_PRFPREG, 16 * index, 16),
        });
    }
    for (name, offset) in [("fpsr", 512), ("fpcr", 516)] {
        regs.push(RegSpec {
            name,
            bits: 32,
            feature: FPU,
            gdb_type: "int",
            group: Some("float"),
            kind: RegKind::VectorControl,
            source: slice(NT_PRFPREG, offset, 4),
        });
    }
    regs.push(RegSpec {
        name: "tpidr",
        bits: 64,
        feature: TLS,
        gdb_type: "data_ptr",
        group: Some("system"),
        kind: RegKind::System,
        source: slice(NT_ARM_TLS, 0, 8),
    });
    TargetDescription {
        architecture: "aarch64",
        osabi: Some("GNU/Linux"),
        features: vec![
            FeatureSpec {
                name: CORE,
                types: CORE_TYPES,
            },
            FeatureSpec {
                name: FPU,
                types: FPU_TYPES,
            },
            FeatureSpec {
                name: TLS,
                types: "",
            },
        ],
        regs,
        regsets: vec![NT_PRSTATUS, NT_PRFPREG, NT_ARM_TLS],
    }
}

pub fn description() -> &'static TargetDescription {
    static DESCRIPTION: OnceLock<TargetDescription> = OnceLock::new();
    DESCRIPTION.get_or_init(build)
}

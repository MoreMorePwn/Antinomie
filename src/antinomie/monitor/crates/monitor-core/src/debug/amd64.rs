// SPDX-License-Identifier: MIT
//! x86-64 target description and the gdbstub `Arch` built from it.
//!
//! The register image follows GDB's amd64-linux feature order, which this file
//! also publishes as the target description, so the two cannot disagree:
//! core (rax..gs, st0..st7, fctrl..fop), sse (xmm0..xmm15, mxcsr), linux
//! (orig_rax) and segments (fs_base, gs_base). The kernel supplies
//! `NT_PRSTATUS` (`struct user_regs_struct`) and `NT_PRFPREG` (the 512-byte
//! FXSAVE image).
use super::regs::{FeatureSpec, RegKind, RegSource, RegSpec, RegisterFile, TargetDescription};
use gdbstub::arch::{Arch, BreakpointKind, RegId, Registers};
use std::{num::NonZeroUsize, sync::OnceLock};

pub const NT_PRSTATUS: u32 = 1;
pub const NT_PRFPREG: u32 = 2;
pub const NT_X86_XSTATE: u32 = 0x202;

/// Offsets inside `struct user_regs_struct`.
const GENERAL: [(&str, usize); 27] = [
    ("r15", 0),
    ("r14", 8),
    ("r13", 16),
    ("r12", 24),
    ("rbp", 32),
    ("rbx", 40),
    ("r11", 48),
    ("r10", 56),
    ("r9", 64),
    ("r8", 72),
    ("rax", 80),
    ("rcx", 88),
    ("rdx", 96),
    ("rsi", 104),
    ("rdi", 112),
    ("orig_rax", 120),
    ("rip", 128),
    ("cs", 136),
    ("eflags", 144),
    ("rsp", 152),
    ("ss", 160),
    ("fs_base", 168),
    ("gs_base", 176),
    ("ds", 184),
    ("es", 192),
    ("fs", 200),
    ("gs", 208),
];
pub const USER_REGS_SIZE: usize = 216;
pub const FXSAVE_SIZE: usize = 512;

fn general(name: &str) -> usize {
    GENERAL
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, offset)| *offset)
        .expect("known x86-64 register")
}

const CORE: &str = "org.gnu.gdb.i386.core";
const SSE: &str = "org.gnu.gdb.i386.sse";
const LINUX: &str = "org.gnu.gdb.i386.linux";
const SEGMENTS: &str = "org.gnu.gdb.i386.segments";

const CORE_TYPES: &str = r#"    <flags id="i386_eflags" size="4">
      <field name="CF" start="0" end="0"/>
      <field name="" start="1" end="1"/>
      <field name="PF" start="2" end="2"/>
      <field name="AF" start="4" end="4"/>
      <field name="ZF" start="6" end="6"/>
      <field name="SF" start="7" end="7"/>
      <field name="TF" start="8" end="8"/>
      <field name="IF" start="9" end="9"/>
      <field name="DF" start="10" end="10"/>
      <field name="OF" start="11" end="11"/>
      <field name="NT" start="14" end="14"/>
      <field name="RF" start="16" end="16"/>
      <field name="VM" start="17" end="17"/>
      <field name="AC" start="18" end="18"/>
      <field name="VIF" start="19" end="19"/>
      <field name="VIP" start="20" end="20"/>
      <field name="ID" start="21" end="21"/>
    </flags>
"#;
const SSE_TYPES: &str = r#"    <vector id="v4f" type="ieee_single" count="4"/>
    <vector id="v2d" type="ieee_double" count="2"/>
    <vector id="v16i8" type="int8" count="16"/>
    <vector id="v8i16" type="int16" count="8"/>
    <vector id="v4i32" type="int32" count="4"/>
    <vector id="v2i64" type="int64" count="2"/>
    <union id="vec128">
      <field name="v4_float" type="v4f"/>
      <field name="v2_double" type="v2d"/>
      <field name="v16_int8" type="v16i8"/>
      <field name="v8_int16" type="v8i16"/>
      <field name="v4_int32" type="v4i32"/>
      <field name="v2_int64" type="v2i64"/>
      <field name="uint128" type="uint128"/>
    </union>
    <flags id="i386_mxcsr" size="4">
      <field name="IE" start="0" end="0"/>
      <field name="DE" start="1" end="1"/>
      <field name="ZE" start="2" end="2"/>
      <field name="OE" start="3" end="3"/>
      <field name="UE" start="4" end="4"/>
      <field name="PE" start="5" end="5"/>
      <field name="DAZ" start="6" end="6"/>
      <field name="IM" start="7" end="7"/>
      <field name="DM" start="8" end="8"/>
      <field name="ZM" start="9" end="9"/>
      <field name="OM" start="10" end="10"/>
      <field name="UM" start="11" end="11"/>
      <field name="PM" start="12" end="12"/>
      <field name="FZ" start="15" end="15"/>
    </flags>
"#;

// ---- x87 tag word -------------------------------------------------------

/// Tag of one x87 register from its 80-bit image: 0 valid, 1 zero, 2 special.
fn x87_tag(register: &[u8]) -> u16 {
    let exponent = u16::from_le_bytes([register[8], register[9]]) & 0x7fff;
    let mantissa = u64::from_le_bytes(register[..8].try_into().expect("eight bytes"));
    if exponent == 0x7fff {
        2
    } else if exponent == 0 {
        if mantissa == 0 { 1 } else { 2 }
    } else if mantissa >> 63 == 1 {
        0
    } else {
        2
    }
}
/// The full x87 tag word GDB shows, from the kernel's abridged FXSAVE tag.
pub fn full_tag_word(fxsave: &[u8]) -> u16 {
    if fxsave.len() < FXSAVE_SIZE {
        return 0xffff;
    }
    let abridged = fxsave[4];
    let top = usize::from((u16::from_le_bytes([fxsave[2], fxsave[3]]) >> 11) & 7);
    let mut word = 0u16;
    for physical in 0..8usize {
        let tag = if abridged & (1 << physical) == 0 {
            3
        } else {
            let slot = (physical + 8 - top) % 8;
            x87_tag(&fxsave[32 + 16 * slot..32 + 16 * slot + 10])
        };
        word |= tag << (2 * physical);
    }
    word
}
fn read_tag(file: &RegisterFile) -> Vec<u8> {
    let word = file.get(NT_PRFPREG).map_or(0xffff, full_tag_word);
    word.to_le_bytes().to_vec()
}
fn write_tag(file: &mut RegisterFile, bytes: &[u8]) -> bool {
    let Some(blob) = file.get_mut(NT_PRFPREG) else {
        return true;
    };
    if blob.len() < FXSAVE_SIZE || bytes.len() < 2 {
        return false;
    }
    let word = u16::from_le_bytes([bytes[0], bytes[1]]);
    // Leave the abridged tag alone when the full word already matches it, so a
    // register write that did not touch the tag never rewrites the blob.
    if full_tag_word(blob) == word {
        return true;
    }
    let mut abridged = 0u8;
    for physical in 0..8 {
        if (word >> (2 * physical)) & 3 != 3 {
            abridged |= 1 << physical;
        }
    }
    blob[4] = abridged;
    true
}

fn general_reg(name: &'static str, bits: usize, gdb_type: &'static str, kind: RegKind) -> RegSpec {
    RegSpec {
        name,
        bits,
        feature: CORE,
        gdb_type,
        group: None,
        kind,
        source: RegSource::Slice {
            nt_type: NT_PRSTATUS,
            offset: general(name),
            len: bits / 8,
        },
    }
}
fn fp_source(offset: usize, len: usize) -> RegSource {
    RegSource::Slice {
        nt_type: NT_PRFPREG,
        offset,
        len,
    }
}
fn float_reg(
    name: &'static str,
    bits: usize,
    gdb_type: &'static str,
    source: RegSource,
) -> RegSpec {
    RegSpec {
        name,
        bits,
        feature: CORE,
        gdb_type,
        group: Some("float"),
        kind: RegKind::Float,
        source,
    }
}

fn build() -> TargetDescription {
    const ST: [&str; 8] = ["st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7"];
    const XMM: [&str; 16] = [
        "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10",
        "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
    ];
    let mut regs = Vec::new();
    for name in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi"] {
        regs.push(general_reg(name, 64, "int64", RegKind::General));
    }
    for name in ["rbp", "rsp"] {
        regs.push(general_reg(name, 64, "data_ptr", RegKind::DataPointer));
    }
    for name in ["r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"] {
        regs.push(general_reg(name, 64, "int64", RegKind::General));
    }
    regs.push(general_reg("rip", 64, "code_ptr", RegKind::CodePointer));
    regs.push(general_reg("eflags", 32, "i386_eflags", RegKind::Flags));
    for name in ["cs", "ss", "ds", "es", "fs", "gs"] {
        regs.push(general_reg(name, 32, "int32", RegKind::Segment));
    }
    for (index, name) in ST.iter().enumerate() {
        regs.push(float_reg(
            name,
            80,
            "i387_ext",
            fp_source(32 + 16 * index, 10),
        ));
    }
    let control = |name, offset, len| RegSpec {
        kind: RegKind::FloatControl,
        ..float_reg(name, 32, "int", fp_source(offset, len))
    };
    regs.push(control("fctrl", 0, 2));
    regs.push(control("fstat", 2, 2));
    regs.push(RegSpec {
        name: "ftag",
        bits: 32,
        feature: CORE,
        gdb_type: "int",
        group: Some("float"),
        kind: RegKind::FloatControl,
        source: RegSource::Derived {
            read: read_tag,
            write: write_tag,
        },
    });
    regs.push(control("fiseg", 12, 4));
    regs.push(control("fioff", 8, 4));
    regs.push(control("foseg", 20, 4));
    regs.push(control("fooff", 16, 4));
    regs.push(control("fop", 6, 2));
    let vector = |name, bits, gdb_type, offset, len, kind| RegSpec {
        feature: SSE,
        group: Some("vector"),
        kind,
        ..float_reg(name, bits, gdb_type, fp_source(offset, len))
    };
    for (index, name) in XMM.iter().enumerate() {
        regs.push(vector(
            name,
            128,
            "vec128",
            160 + 16 * index,
            16,
            RegKind::Vector,
        ));
    }
    regs.push(vector(
        "mxcsr",
        32,
        "i386_mxcsr",
        24,
        4,
        RegKind::VectorControl,
    ));
    regs.push(RegSpec {
        name: "orig_rax",
        bits: 64,
        feature: LINUX,
        gdb_type: "int",
        group: Some("system"),
        kind: RegKind::System,
        source: RegSource::Slice {
            nt_type: NT_PRSTATUS,
            offset: general("orig_rax"),
            len: 8,
        },
    });
    for name in ["fs_base", "gs_base"] {
        regs.push(RegSpec {
            name,
            bits: 64,
            feature: SEGMENTS,
            gdb_type: "int",
            group: None,
            kind: RegKind::System,
            source: RegSource::Slice {
                nt_type: NT_PRSTATUS,
                offset: general(name),
                len: 8,
            },
        });
    }
    TargetDescription {
        architecture: "i386:x86-64",
        osabi: Some("GNU/Linux"),
        features: vec![
            FeatureSpec {
                name: CORE,
                types: CORE_TYPES,
            },
            FeatureSpec {
                name: SSE,
                types: SSE_TYPES,
            },
            FeatureSpec {
                name: LINUX,
                types: "",
            },
            FeatureSpec {
                name: SEGMENTS,
                types: "",
            },
        ],
        regs,
        regsets: vec![NT_PRSTATUS, NT_PRFPREG],
    }
}

pub fn description() -> &'static TargetDescription {
    static DESCRIPTION: OnceLock<TargetDescription> = OnceLock::new();
    DESCRIPTION.get_or_init(build)
}

fn xml() -> &'static str {
    static XML: OnceLock<String> = OnceLock::new();
    XML.get_or_init(|| description().xml())
}

// ---- gdbstub glue ---------------------------------------------------------

/// The full register image in GDB order, as one byte string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Amd64Registers {
    pub image: Vec<u8>,
}
impl Default for Amd64Registers {
    fn default() -> Self {
        Self {
            image: vec![0; description().image_len()],
        }
    }
}
impl Registers for Amd64Registers {
    type ProgramCounter = u64;
    fn pc(&self) -> u64 {
        let (offset, _) = description().find("rip").expect("rip is described");
        u64::from_le_bytes(
            self.image[offset..offset + 8]
                .try_into()
                .expect("eight bytes"),
        )
    }
    fn gdb_serialize(&self, mut write_byte: impl FnMut(Option<u8>)) {
        for byte in &self.image {
            write_byte(Some(*byte));
        }
    }
    fn gdb_deserialize(&mut self, bytes: &[u8]) -> Result<(), ()> {
        if bytes.len() != description().image_len() {
            return Err(());
        }
        self.image.copy_from_slice(bytes);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Amd64RegId(pub usize);
impl RegId for Amd64RegId {
    fn from_raw_id(id: usize) -> Option<(Self, Option<NonZeroUsize>)> {
        let reg = description().regs.get(id)?;
        Some((Self(id), NonZeroUsize::new(reg.bytes())))
    }
    fn to_raw_id(&self) -> Option<usize> {
        Some(self.0)
    }
}

/// Software breakpoints are `kind` bytes long (1 on x86-64).
#[derive(Debug)]
pub struct BreakpointLen(pub usize);
impl BreakpointKind for BreakpointLen {
    fn from_usize(kind: usize) -> Option<Self> {
        Some(Self(kind))
    }
}

pub enum Amd64 {}
impl Arch for Amd64 {
    type Usize = u64;
    type Registers = Amd64Registers;
    type BreakpointKind = BreakpointLen;
    type RegId = Amd64RegId;
    fn target_description_xml() -> Option<&'static str> {
        Some(xml())
    }
}

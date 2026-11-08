// SPDX-License-Identifier: GPL-3.0-only
//! Bounded, file-backed Linux x86-64, aarch64 and 32-bit ARM process-core inspection.
//! Physical QEMU dumps are deliberately rejected: their CPU notes are not process threads.
//!
//! The 32-bit ARM cores are the ELF32 cores arm64 guests write for AArch32 programs
//! (`fs/compat_binfmt_elf.c`): ELFCLASS32, EM_ARM, `compat_elf_prstatus` (r0-r15, cpsr,
//! orig_r0), `NT_ARM_VFP`, a compat siginfo and 32-bit `NT_FILE` and auxv.
use crate::analysis::{ArmMode, decode_span_arm};
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use object::{Object, ObjectSegment, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const NOTE_LIMIT: u64 = 16 * 1024 * 1024;
const ITEM_LIMIT: usize = 16_384;
pub const READ_LIMIT: usize = 256 * 1024;
const REG_NAMES: [&str; 27] = [
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "rflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];
/// ELF machines of the process cores this reader opens.
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_ARM: u16 = 40;
/// CPSR bit 5: the program counter is in Thumb state.
pub const CPSR_THUMB: u64 = 1 << 5;
/// `compat_elf_prstatus`'s `pr_reg`: r0-r12, sp, lr, pc, cpsr and orig_r0.
const ARM_REG_NAMES: [&str; 18] = [
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr",
    "pc", "cpsr", "orig_r0",
];
/// `NT_ARM_VFP`: d0-d31 then fpscr.
const ARM_VFP_SIZE: usize = 260;
const NT_ARM_VFP: u32 = 0x400;
/// aarch64's `user_pt_regs`, its `elf_gregset_t`.
const AARCH64_REG_NAMES: [&str; 34] = [
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "sp", "pc", "pstate",
];
fn x86_64_machine() -> u16 {
    EM_X86_64
}

/// Whether the first bytes of a core are an ET_CORE the guest of ELF machine
/// `machine` writes: its own 64-bit little-endian one, or on an arm64 guest the
/// ELF32 EM_ARM core of an AArch32 task (revision 21).
pub fn guest_core_header(data: &[u8], machine: u32) -> bool {
    if data.len() < 20 || data[16..18] != 4u16.to_le_bytes() {
        return false;
    }
    let found = u32::from(u16::from_le_bytes([data[18], data[19]]));
    (&data[..7] == b"\x7fELF\x02\x01\x01" && found == machine)
        || (&data[..7] == b"\x7fELF\x01\x01\x01"
            && found == u32::from(EM_ARM)
            && machine == u32::from(EM_AARCH64))
}

#[derive(Debug)]
pub struct CoreError(String);
impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl std::error::Error for CoreError {}
impl From<std::io::Error> for CoreError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}
impl From<serde_json::Error> for CoreError {
    fn from(error: serde_json::Error) -> Self {
        Self(error.to_string())
    }
}
type Result<T> = std::result::Result<T, CoreError>;
fn invalid(message: impl Into<String>) -> CoreError {
    CoreError(message.into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreThread {
    pub tid: u32,
    pub parent_pid: u32,
    pub signal: u16,
    pub registers: Vec<(String, u64)>,
}
impl CoreThread {
    pub fn register(&self, name: &str) -> Option<u64> {
        self.registers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| *value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreMapping {
    pub start: u64,
    pub memory_size: u64,
    pub file_offset: u64,
    /// Extent declared captured by PT_LOAD, distinct from omitted virtual pages.
    pub captured_size: u64,
    pub available_size: u64,
    pub flags: u32,
}
impl CoreMapping {
    pub fn end(&self) -> u64 {
        self.start.saturating_add(self.memory_size)
    }
    pub fn permissions(&self) -> String {
        format!(
            "{}{}{}",
            if self.flags & 4 != 0 { "r" } else { "-" },
            if self.flags & 2 != 0 { "w" } else { "-" },
            if self.flags & 1 != 0 { "x" } else { "-" }
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MappedFile {
    pub start: u64,
    pub end: u64,
    pub file_offset: u64,
    pub path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreDump {
    pub source: PathBuf,
    pub source_size: u64,
    pub threads: Vec<CoreThread>,
    pub mappings: Vec<CoreMapping>,
    pub files: Vec<MappedFile>,
    pub auxv: Vec<(u64, u64)>,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
    /// ELF machine (`EM_X86_64`, `EM_AARCH64`, `EM_ARM`); records saved before 0.9.0
    /// are x86-64.
    #[serde(default = "x86_64_machine")]
    pub machine: u16,
}
fn number<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    data.get(
        offset
            ..offset
                .checked_add(N)
                .ok_or_else(|| invalid("note offset overflow"))?,
    )
    .ok_or_else(|| invalid("truncated ELF metadata"))?
    .try_into()
    .map_err(|_| invalid("invalid field length"))
}
fn u16_at(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(number(data, offset)?))
}
fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(number(data, offset)?))
}
fn i32_at(data: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_le_bytes(number(data, offset)?))
}
fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(number(data, offset)?))
}
fn aligned(value: usize) -> Result<usize> {
    value
        .checked_add(3)
        .map(|n| n & !3)
        .ok_or_else(|| invalid("note alignment overflow"))
}
fn read_at(file: &mut File, offset: u64, size: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut data = vec![0; size];
    file.read_exact(&mut data)?;
    Ok(data)
}

impl CoreDump {
    /// Inspect headers and bounded notes only; never load all process memory.
    ///
    /// | Argument / result | Meaning |
    /// |---|---|
    /// | `path` | Existing little-endian Linux ET_CORE file: ELF64 x86-64 or aarch64, or ELF32 ARM |
    /// | result | File-backed mappings and recovered process-thread metadata |
    ///
    /// # Errors
    /// Rejects other ABIs, QEMU notes, invalid extents and excessive metadata.
    /// Truncated memory and trailing notes remain inspectable with warnings.
    pub fn open(path: &Path) -> Result<Self> {
        let source = fs::canonicalize(path)?;
        if !fs::metadata(&source)?.is_file() {
            return Err(invalid("core source must be a regular file"));
        }
        let mut file = File::open(&source)?;
        let source_size = file.metadata()?.len();
        let header = read_at(&mut file, 0, 64)?;
        let machine = u16_at(&header, 18)?;
        let class32 = header[4] == 1;
        if &header[..4] != b"\x7fELF"
            || !(header[4] == 2 && matches!(machine, EM_X86_64 | EM_AARCH64)
                || class32 && machine == EM_ARM)
            || header[5] != 1
            || header[6] != 1
            || u16_at(&header, 16)? != 4
        {
            return Err(invalid(
                "requires a Linux x86-64 or aarch64 little-endian ELF64 process core, or a 32-bit ARM ELF32 one",
            ));
        }
        let (ph_offset, ph_size, ph_count, ph_min) = if class32 {
            (
                u64::from(u32_at(&header, 28)?),
                u16_at(&header, 42)?,
                usize::from(u16_at(&header, 44)?),
                32,
            )
        } else {
            (
                u64_at(&header, 32)?,
                u16_at(&header, 54)?,
                usize::from(u16_at(&header, 56)?),
                56,
            )
        };
        if ph_size < ph_min || ph_count == 0 || ph_count > ITEM_LIMIT {
            return Err(invalid(
                "unsupported or excessive program-header count (extended numbering unsupported)",
            ));
        }
        let ph_end = ph_offset
            .checked_add(u64::from(ph_size) * ph_count as u64)
            .ok_or_else(|| invalid("program-header overflow"))?;
        if ph_end > source_size {
            return Err(invalid("truncated program-header table"));
        }
        let mut core = Self {
            source,
            source_size,
            threads: Vec::new(),
            mappings: Vec::new(),
            files: Vec::new(),
            auxv: Vec::new(),
            notes: Vec::new(),
            warnings: Vec::new(),
            machine,
        };
        let mut note_size = 0u64;
        for index in 0..ph_count {
            let ph = read_at(
                &mut file,
                ph_offset + index as u64 * u64::from(ph_size),
                usize::from(ph_min),
            )?;
            let kind = u32_at(&ph, 0)?;
            // Elf32_Phdr: type, offset, vaddr, paddr, filesz, memsz, flags;
            // Elf64_Phdr: type, flags, offset, vaddr, paddr, filesz, memsz.
            let (offset, start, size, memory_size, flags) = if class32 {
                (
                    u64::from(u32_at(&ph, 4)?),
                    u64::from(u32_at(&ph, 8)?),
                    u64::from(u32_at(&ph, 16)?),
                    u64::from(u32_at(&ph, 20)?),
                    u32_at(&ph, 24)?,
                )
            } else {
                (
                    u64_at(&ph, 8)?,
                    u64_at(&ph, 16)?,
                    u64_at(&ph, 32)?,
                    u64_at(&ph, 40)?,
                    u32_at(&ph, 4)?,
                )
            };
            offset
                .checked_add(size)
                .ok_or_else(|| invalid("segment file extent overflow"))?;
            if kind == 1 {
                start
                    .checked_add(memory_size)
                    .ok_or_else(|| invalid("segment virtual extent overflow"))?;
                if size > memory_size {
                    return Err(invalid("PT_LOAD file size exceeds virtual extent"));
                }
                let available_size = size.min(source_size.saturating_sub(offset));
                if available_size != size {
                    core.warnings.push(format!("truncated memory segment at 0x{start:x}: {available_size}/{size} octets available"));
                }
                if memory_size > 0 {
                    core.mappings.push(CoreMapping {
                        start,
                        memory_size,
                        file_offset: offset,
                        captured_size: size,
                        available_size,
                        flags,
                    });
                }
            } else if kind == 4 {
                note_size = note_size
                    .checked_add(size)
                    .ok_or_else(|| invalid("note size overflow"))?;
                if note_size > NOTE_LIMIT {
                    return Err(invalid("ELF notes exceed 16 MiB inspection budget"));
                }
                let available = size.min(source_size.saturating_sub(offset));
                if available != size {
                    core.warnings.push("truncated PT_NOTE segment".into());
                }
                let data = read_at(
                    &mut file,
                    offset,
                    usize::try_from(available).map_err(|_| invalid("note length overflow"))?,
                )?;
                core.parse_notes(&data)?;
            }
        }
        if core.threads.is_empty() {
            return Err(invalid(
                "no Linux CORE/NT_PRSTATUS process-thread registers; physical VM dumps belong in Memory",
            ));
        }
        core.mappings.sort_by_key(|mapping| mapping.start);
        if core
            .mappings
            .windows(2)
            .any(|pair| pair[0].end() > pair[1].start)
        {
            return Err(invalid("overlapping virtual PT_LOAD mappings"));
        }
        Ok(core)
    }

    fn parse_notes(&mut self, data: &[u8]) -> Result<()> {
        let mut cursor = 0usize;
        while cursor < data.len() {
            if self.notes.len() >= ITEM_LIMIT {
                return Err(invalid("excessive ELF note count"));
            }
            if data.len() - cursor < 12 {
                self.warnings.push("truncated final note header".into());
                break;
            }
            let name_size = usize::try_from(u32_at(data, cursor)?)
                .map_err(|_| invalid("note length overflow"))?;
            let desc_size = usize::try_from(u32_at(data, cursor + 4)?)
                .map_err(|_| invalid("note length overflow"))?;
            let kind = u32_at(data, cursor + 8)?;
            let name_offset = cursor + 12;
            let desc_offset = name_offset
                .checked_add(aligned(name_size)?)
                .ok_or_else(|| invalid("note offset overflow"))?;
            let end = desc_offset
                .checked_add(desc_size)
                .ok_or_else(|| invalid("note offset overflow"))?;
            let next = desc_offset
                .checked_add(aligned(desc_size)?)
                .ok_or_else(|| invalid("note offset overflow"))?;
            if end > data.len() {
                self.warnings.push("truncated final note contents".into());
                break;
            }
            let name = data
                .get(name_offset..name_offset + name_size)
                .ok_or_else(|| invalid("truncated note owner"))?;
            let owner = String::from_utf8_lossy(name)
                .trim_end_matches('\0')
                .to_owned();
            if owner == "QEMU" {
                return Err(invalid(
                    "QEMU physical dump notes are not Linux process cores",
                ));
            }
            self.notes
                .push(format!("{owner}: type 0x{kind:x}, {desc_size} octets"));
            let desc = &data[desc_offset..end];
            if owner == "LINUX" && kind == NT_ARM_VFP && self.machine == EM_ARM {
                self.parse_vfp(desc)?;
            }
            if owner == "CORE" {
                let arm = self.machine == EM_ARM;
                match kind {
                    // elf_prstatus: the registers at 112, then pr_fpvalid and padding
                    // (336 octets on x86-64, 392 on aarch64); compat_elf_prstatus
                    // (148 octets): pid at 24, ppid at 28, the registers at 72.
                    1 if arm && desc.len() >= 72 + ARM_REG_NAMES.len() * 4 => {
                        let mut registers = Vec::with_capacity(ARM_REG_NAMES.len());
                        for (index, name) in ARM_REG_NAMES.iter().enumerate() {
                            registers
                                .push(((*name).into(), u64::from(u32_at(desc, 72 + index * 4)?)));
                        }
                        self.threads.push(CoreThread {
                            tid: u32_at(desc, 24)?,
                            parent_pid: u32_at(desc, 28)?,
                            signal: u16_at(desc, 12)?,
                            registers,
                        });
                    }
                    1 if !arm && desc.len() >= 112 + self.register_names().len() * 8 + 8 => {
                        let names = self.register_names();
                        let mut registers = Vec::with_capacity(names.len());
                        for (index, name) in names.iter().enumerate() {
                            registers.push(((*name).into(), u64_at(desc, 112 + index * 8)?));
                        }
                        self.threads.push(CoreThread {
                            tid: u32_at(desc, 32)?,
                            parent_pid: u32_at(desc, 36)?,
                            signal: u16_at(desc, 12)?,
                            registers,
                        });
                    }
                    1 => self
                        .warnings
                        .push("truncated NT_PRSTATUS; thread registers omitted".into()),
                    6 => {
                        let pair = if arm { 8 } else { 16 };
                        for entry in desc.chunks_exact(pair) {
                            let (key, value) = if arm {
                                (u64::from(u32_at(entry, 0)?), u64::from(u32_at(entry, 4)?))
                            } else {
                                (u64_at(entry, 0)?, u64_at(entry, 8)?)
                            };
                            if key == 0 {
                                break;
                            }
                            if self.auxv.len() >= ITEM_LIMIT {
                                return Err(invalid("excessive auxv entries"));
                            }
                            self.auxv.push((key, value));
                        }
                        if !desc.len().is_multiple_of(pair) {
                            self.warnings.push("truncated AUXV pair".into());
                        }
                    }
                    0x4649_4c45 => self.parse_files(desc)?,
                    0x5349_4749 if desc.len() >= 12 => {
                        let signal = i32_at(desc, 0)?;
                        let code = i32_at(desc, 8)?;
                        self.notes.push(format!(
                            "signal info: signo={signal} errno={} code={code}",
                            i32_at(desc, 4)?
                        ));
                        // A 64-bit Linux siginfo's union starts at offset 16, a compat
                        // (32-bit) one's at 12. Only interpret si_addr for a known
                        // signal-specific code.
                        let union = if arm { 12 } else { 16 };
                        if matches!(signal, 4 | 5 | 7 | 8 | 11)
                            && code > 0
                            && code < 128
                            && desc.len() >= union + if arm { 4 } else { 8 }
                        {
                            self.notes.push(if arm {
                                format!("fault address: 0x{:08x}", u32_at(desc, union)?)
                            } else {
                                format!("fault address: 0x{:016x}", u64_at(desc, union)?)
                            });
                        } else if matches!(code, 0 | -1 | -6) && desc.len() >= union + 8 {
                            self.notes.push(format!(
                                "signal sender PID={} UID={}",
                                i32_at(desc, union)?,
                                u32_at(desc, union + 4)?
                            ));
                        }
                    }
                    // compat_elf_prpsinfo (124 octets): pr_fname at 28, pr_psargs at 44.
                    3 if arm && desc.len() >= 124 => self.notes.push(format!(
                        "process: {}; arguments: {}",
                        note_text(&desc[28..44]),
                        note_text(&desc[44..124])
                    )),
                    3 if !arm && desc.len() >= 136 => self.notes.push(format!(
                        "process: {}; arguments: {}",
                        note_text(&desc[40..56]),
                        note_text(&desc[56..136])
                    )),
                    _ => {}
                }
            }
            cursor = next;
        }
        Ok(())
    }
    /// `NT_ARM_VFP` of the thread the last `NT_PRSTATUS` started: d0-d31 and fpscr.
    fn parse_vfp(&mut self, desc: &[u8]) -> Result<()> {
        if desc.len() < ARM_VFP_SIZE {
            self.warnings.push("truncated NT_ARM_VFP".into());
            return Ok(());
        }
        let Some(thread) = self.threads.last_mut() else {
            return Ok(());
        };
        for index in 0..32 {
            thread
                .registers
                .push((format!("d{index}"), u64_at(desc, index * 8)?));
        }
        thread
            .registers
            .push(("fpscr".into(), u64::from(u32_at(desc, 256)?)));
        Ok(())
    }
    fn parse_files(&mut self, desc: &[u8]) -> Result<()> {
        // 32-bit cores: u32 count, u32 page size, u32 start/end/page-offset triples.
        let word = if self.machine == EM_ARM { 4 } else { 8 };
        let read = |offset: usize| -> Result<u64> {
            if word == 4 {
                Ok(u64::from(u32_at(desc, offset)?))
            } else {
                u64_at(desc, offset)
            }
        };
        let count = usize::try_from(read(0)?).map_err(|_| invalid("NT_FILE count overflow"))?;
        let page_size = read(word)?;
        if count > ITEM_LIMIT
            || self.files.len().saturating_add(count) > ITEM_LIMIT
            || page_size == 0
        {
            return Err(invalid("invalid NT_FILE count/page size"));
        }
        let path_offset = (2 * word)
            .checked_add(
                count
                    .checked_mul(3 * word)
                    .ok_or_else(|| invalid("NT_FILE overflow"))?,
            )
            .ok_or_else(|| invalid("NT_FILE overflow"))?;
        if count > 0 && desc.last() != Some(&0) {
            return Err(invalid("unterminated NT_FILE pathname"));
        }
        let mut names = desc
            .get(path_offset..)
            .ok_or_else(|| invalid("truncated NT_FILE table"))?
            .split(|byte| *byte == 0);
        for index in 0..count {
            let offset = 2 * word + index * 3 * word;
            let start = read(offset)?;
            let end = read(offset + word)?;
            if end < start {
                return Err(invalid("reversed NT_FILE extent"));
            }
            let file_offset = read(offset + 2 * word)?
                .checked_mul(page_size)
                .ok_or_else(|| invalid("NT_FILE file offset overflow"))?;
            let path = names
                .next()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| invalid("missing NT_FILE pathname"))?;
            self.files.push(MappedFile {
                start,
                end,
                file_offset,
                path: String::from_utf8_lossy(path).into_owned(),
            });
        }
        Ok(())
    }
    /// Read at most READ_LIMIT octets from virtual memory. `None` preserves
    /// uncaptured/unmapped/truncated bytes; zero-filled bytes are actual data.
    pub fn read_virtual(&self, address: u64, size: usize) -> Result<Vec<Option<u8>>> {
        if size > READ_LIMIT {
            return Err(invalid("virtual preview exceeds 256 KiB"));
        }
        let end = address
            .checked_add(size as u64)
            .ok_or_else(|| invalid("virtual read overflow"))?;
        let mut result = vec![None; size];
        let mut file = File::open(&self.source)?;
        let current_size = file.metadata()?.len();
        for mapping in &self.mappings {
            let available = mapping
                .available_size
                .min(current_size.saturating_sub(mapping.file_offset));
            let read_start = address.max(mapping.start);
            if available > mapping.memory_size {
                return Err(invalid("invalid stored mapping extent"));
            }
            let mapping_end = mapping
                .start
                .checked_add(available)
                .ok_or_else(|| invalid("stored mapping overflow"))?;
            let read_end = end.min(mapping_end);
            if read_start >= read_end {
                continue;
            }
            let read_len = usize::try_from(read_end - read_start)
                .map_err(|_| invalid("preview length overflow"))?;
            let input_offset = mapping
                .file_offset
                .checked_add(read_start - mapping.start)
                .ok_or_else(|| invalid("stored file offset overflow"))?;
            let data = read_at(&mut file, input_offset, read_len)?;
            let output_offset = usize::try_from(read_start - address)
                .map_err(|_| invalid("preview offset overflow"))?;
            for (slot, byte) in result[output_offset..output_offset + read_len]
                .iter_mut()
                .zip(data)
            {
                *slot = Some(byte);
            }
        }
        Ok(result)
    }
    /// The names of a thread's registers in the core's `NT_PRSTATUS`.
    fn register_names(&self) -> &'static [&'static str] {
        if self.machine == EM_ARM {
            &ARM_REG_NAMES
        } else if self.machine == EM_AARCH64 {
            &AARCH64_REG_NAMES
        } else {
            &REG_NAMES
        }
    }
    /// Decode only a user-selected virtual span, stopping at the first gap.
    pub fn disassemble(&self, address: u64, size: usize) -> Result<String> {
        if self.machine == EM_ARM {
            return self.disassemble_arm(address, size);
        }
        if self.machine != EM_X86_64 {
            return Err(invalid(
                "this core view disassembles x86-64 and 32-bit ARM process memory only; aarch64 code is shown as bytes",
            ));
        }
        let data = self.read_virtual(address, size.min(64 * 1024))?;
        let available: Vec<u8> = data.iter().map_while(|byte| *byte).collect();
        if available.is_empty() {
            return Err(invalid("no captured memory at selected code address"));
        }
        let mut decoder = Decoder::with_ip(64, &available, address, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut text = format!(
            "x86-64 process memory at 0x{address:x}; linear decoding, not verified function boundaries\n"
        );
        while decoder.can_decode() {
            let instruction = decoder.decode();
            let mut line = String::new();
            formatter.format(&instruction, &mut line);
            text.push_str(&format!("{:016x}  {line}\n", instruction.ip()));
        }
        if available.len() < data.len() {
            text.push_str("[stopped at missing memory]\n");
        }
        Ok(text)
    }
}
impl CoreDump {
    /// The instruction set the code at `address` is in, and the address without
    /// the Thumb marker: an odd address (a Thumb symbol or branch target) is
    /// Thumb; a thread's own program counter follows its CPSR T bit; any other
    /// address is ARM.
    pub fn arm_mode_at(&self, address: u64) -> (ArmMode, u64) {
        if address & 1 != 0 {
            return (ArmMode::Thumb, address & !1);
        }
        let thumb = self.threads.iter().any(|thread| {
            thread.register("pc") == Some(address)
                && thread
                    .register("cpsr")
                    .is_some_and(|cpsr| cpsr & CPSR_THUMB != 0)
        });
        (if thumb { ArmMode::Thumb } else { ArmMode::Arm }, address)
    }
    fn disassemble_arm(&self, address: u64, size: usize) -> Result<String> {
        let (mode, address) = self.arm_mode_at(address);
        let data = self.read_virtual(address, size.min(64 * 1024))?;
        let available: Vec<u8> = data.iter().map_while(|byte| *byte).collect();
        if available.is_empty() {
            return Err(invalid("no captured memory at selected code address"));
        }
        let mut text = format!(
            "32-bit ARM process memory at 0x{address:x} ({} mode); linear decoding, not verified function boundaries\n",
            mode.label()
        );
        for row in decode_span_arm(address, &available, mode) {
            text.push_str(&format!("{:016x}  {}\n", row.address, row.text));
        }
        if available.len() < data.len() {
            text.push_str("[stopped at missing memory]\n");
        }
        Ok(text)
    }
}
fn note_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreRecord {
    pub dir: PathBuf,
    pub label: String,
    pub tags: String,
    pub core: CoreDump,
    /// Where it came from: its run, origin and process. None in a record
    /// saved before the field; it reads as unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::provenance::Provenance>,
}
impl CoreRecord {
    /// Save a reference and metadata under the chosen recording root. The
    /// original potentially huge core remains in place and must be retained.
    pub fn import(source: &Path, recording_root: &Path) -> Result<Self> {
        let core = CoreDump::open(source)?;
        let parent = recording_root.join("core-dumps");
        fs::create_dir_all(&parent)?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| invalid(error.to_string()))?
            .as_nanos();
        let dir = parent.join(format!("core-{stamp}-{}", std::process::id()));
        fs::create_dir(&dir)?;
        let label = core
            .source
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let record = Self {
            dir,
            label,
            tags: String::new(),
            core,
            provenance: Some(crate::provenance::Provenance::imported(
                "",
                u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_millis()),
                )
                .unwrap_or(0),
            )),
        };
        record.save()?;
        Ok(record)
    }
    pub fn save(&self) -> Result<()> {
        let temporary = self.dir.join("metadata.json.tmp");
        let mut file = File::create(&temporary)?;
        serde_json::to_writer_pretty(&mut file, self)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        fs::rename(temporary, self.dir.join("metadata.json"))?;
        Ok(())
    }
}
/// List metadata only, with bounded directory and JSON budgets; no core reads.
#[cfg(test)]
mod coverage_tests {
    use super::coverage_text;

    #[test]
    fn a_partial_core_says_which_part_is_missing() {
        // Contexts all there, pages missing.
        let text = coverage_text(3, 3, 100 * 4096, 60 * 4096);
        assert!(
            text.contains("all 3 thread contexts were captured"),
            "{text}"
        );
        assert!(text.contains("40 of 100 mapped pages"), "{text}");
        // Contexts lost, pages all there.
        let text = coverage_text(2, 5, 8 * 4096, 8 * 4096);
        assert!(
            text.contains("2 of 5 thread contexts were captured (3 lost)"),
            "{text}"
        );
        assert!(text.contains("every mapped page has its bytes"), "{text}");
        let one = coverage_text(1, 1, 4096, 0);
        assert!(one.contains("all 1 thread context was captured"), "{one}");
    }
}

/// Which part of a core is missing, in words, for a core the guest called
/// incomplete for coverage: the thread contexts against the `expected_threads`
/// the guest counted, and the mapped pages the file holds no bytes for. `None`
/// when the file cannot be read as a process core.
pub fn coverage_detail(path: &Path, expected_threads: u32) -> Option<String> {
    let core = CoreDump::open(path).ok()?;
    let threads = u32::try_from(core.threads.len()).unwrap_or(u32::MAX);
    let mapped: u64 = core.mappings.iter().map(|m| m.memory_size).sum();
    let stored: u64 = core.mappings.iter().map(|m| m.captured_size).sum();
    Some(coverage_text(threads, expected_threads, mapped, stored))
}

/// The wording of [`coverage_detail`].
pub fn coverage_text(threads: u32, expected_threads: u32, mapped: u64, stored: u64) -> String {
    const PAGE: u64 = 4096;
    let contexts = if expected_threads > threads {
        format!(
            "{threads} of {expected_threads} thread contexts were captured ({} lost)",
            expected_threads - threads
        )
    } else {
        format!(
            "all {threads} thread context{} captured",
            if threads == 1 { " was" } else { "s were" }
        )
    };
    let missing = mapped.saturating_sub(stored);
    let pages = if missing == 0 {
        "every mapped page has its bytes".to_owned()
    } else {
        format!(
            "{} of {} mapped pages ({} of {}) have no bytes: not resident when read (the guest reads resident pages only), or left out by the kernel's core filter",
            missing.div_ceil(PAGE),
            mapped.div_ceil(PAGE),
            crate::byte_size::short_size(missing),
            crate::byte_size::short_size(mapped),
        )
    };
    format!("Partial: {contexts}; {pages}.")
}

pub fn list_records(roots: &[PathBuf]) -> Result<Vec<CoreRecord>> {
    let mut records = Vec::new();
    let mut total_size = 0u64;
    for root in roots {
        let parent = root.join("core-dumps");
        let entries = match fs::read_dir(&parent) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries.take(4096) {
            let path = entry?.path().join("metadata.json");
            if !path.is_file() {
                continue;
            }
            let file = File::open(&path)?;
            let metadata_size = file.metadata()?.len();
            if metadata_size > NOTE_LIMIT {
                return Err(invalid("core metadata exceeds 16 MiB"));
            }
            total_size = total_size
                .checked_add(metadata_size)
                .ok_or_else(|| invalid("metadata size overflow"))?;
            if total_size > 32 * 1024 * 1024 {
                return Err(invalid(
                    "core index exceeds 32 MiB; select fewer recording folders",
                ));
            }
            let mut record: CoreRecord = serde_json::from_reader(file.take(NOTE_LIMIT + 1))?;
            record.dir = path
                .parent()
                .ok_or_else(|| invalid("metadata has no parent directory"))?
                .to_owned();
            records.push(record);
            if records.len() >= 4096 {
                return Ok(records);
            }
        }
    }
    records.sort_by(|a, b| b.dir.cmp(&a.dir));
    Ok(records)
}

#[derive(Clone, Debug)]
pub struct CoreFunction {
    /// Start address; for a Thumb function the Thumb marker (the symbol's low
    /// bit) is in `thumb`, not here.
    pub address: u64,
    /// A 32-bit ARM function in Thumb state (its symbol's low bit was set).
    pub thumb: bool,
    pub size: u64,
    pub name: String,
}
/// Recover function names from a user-supplied ELF binary and the selected
/// NT_FILE mapping. The binary is not executed; identity is not assumed.
pub fn binary_functions(path: &Path, mapping: &MappedFile) -> Result<Vec<CoreFunction>> {
    let file = File::open(path)?;
    if file.metadata()?.len() > 128 * 1024 * 1024 {
        return Err(invalid("symbol binary exceeds 128 MiB inspection budget"));
    }
    let mut data = Vec::new();
    file.take(128 * 1024 * 1024 + 1).read_to_end(&mut data)?;
    if data.len() > 128 * 1024 * 1024 {
        return Err(invalid("symbol binary grew beyond inspection budget"));
    }
    let object =
        object::File::parse(data.as_slice()).map_err(|error| invalid(error.to_string()))?;
    if !matches!(
        object.architecture(),
        object::Architecture::X86_64 | object::Architecture::Arm
    ) || object.format() != object::BinaryFormat::Elf
    {
        return Err(invalid("symbol binary must be an x86-64 or 32-bit ARM ELF"));
    }
    let arm = object.architecture() == object::Architecture::Arm;
    let segment = object
        .segments()
        .find(|segment| {
            let (offset, size) = segment.file_range();
            mapping.file_offset >= (offset & !4095)
                && mapping.file_offset < offset.saturating_add(size)
        })
        .ok_or_else(|| invalid("selected NT_FILE offset does not match a binary LOAD segment"))?;
    let (segment_offset, _) = segment.file_range();
    let bias = i128::from(mapping.start)
        - i128::from(mapping.file_offset)
        - (i128::from(segment.address()) - i128::from(segment_offset));
    let mut result = Vec::new();
    for symbol in object.symbols().chain(object.dynamic_symbols()) {
        if symbol.kind() != SymbolKind::Text || symbol.is_undefined() {
            continue;
        }
        if result.len() >= 100_000 {
            return Err(invalid("symbol table exceeds 100,000 function budget"));
        }
        // An ARM function symbol's low bit marks Thumb code.
        let thumb = arm && symbol.address() & 1 != 0;
        let raw = if thumb {
            symbol.address() & !1
        } else {
            symbol.address()
        };
        if let (Ok(name), Ok(address)) = (symbol.name(), u64::try_from(i128::from(raw) + bias))
            && !name.is_empty()
        {
            result.push(CoreFunction {
                address,
                thumb,
                size: symbol.size(),
                name: name.into(),
            });
        }
    }
    result.sort_by_key(|function| function.address);
    result.dedup_by(|a, b| a.address == b.address && a.name == b.name);
    Ok(result)
}

#[cfg(test)]
mod arm_tests;
#[cfg(test)]
mod tests {
    use super::*;
    fn put16(data: &mut [u8], at: usize, value: u16) {
        data[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(data: &mut [u8], at: usize, value: u64) {
        data[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut data = vec![0u8; 0x1004];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut data, 16, 4);
        put16(&mut data, 18, 62);
        put64(&mut data, 32, 64);
        put16(&mut data, 54, 56);
        put16(&mut data, 56, 2);
        put32(&mut data, 64, 4);
        put64(&mut data, 72, 0x200);
        put64(&mut data, 96, 712);
        put32(&mut data, 120, 1);
        put32(&mut data, 124, 5);
        put64(&mut data, 128, 0x1000);
        put64(&mut data, 136, 0x400000);
        put64(&mut data, 152, 8);
        put64(&mut data, 160, 0x1000);
        for (index, tid) in [40, 41].into_iter().enumerate() {
            let at = 0x200 + index * 356;
            put32(&mut data, at, 5);
            put32(&mut data, at + 4, 336);
            put32(&mut data, at + 8, 1);
            data[at + 12..at + 17].copy_from_slice(b"CORE\0");
            let desc = at + 20;
            put16(&mut data, desc + 12, 11);
            put32(&mut data, desc + 32, tid);
            put64(&mut data, desc + 112 + 16 * 8, 0x400000 + u64::from(tid));
            put64(&mut data, desc + 112 + 19 * 8, 0x7fff0000);
        }
        data[0x1000..].copy_from_slice(&[0x90, 0xc3, 0, 0x41]);
        data
    }
    fn with_core(test: impl FnOnce(&Path)) {
        let path = std::env::temp_dir().join(format!(
            "antinomie-core-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, fixture()).unwrap();
        test(&path);
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn threads_and_missing_memory_are_distinct() {
        with_core(|path| {
            let core = CoreDump::open(path).unwrap();
            assert_eq!(core.threads.len(), 2);
            assert_eq!(core.threads[1].tid, 41);
            assert_eq!(core.threads[0].register("rip"), Some(0x400028));
            assert_eq!(core.mappings[0].available_size, 4);
            assert!(!core.warnings.is_empty());
            assert_eq!(
                core.read_virtual(0x400000, 8).unwrap(),
                vec![
                    Some(0x90),
                    Some(0xc3),
                    Some(0),
                    Some(0x41),
                    None,
                    None,
                    None,
                    None
                ]
            );
            assert!(
                core.disassemble(0x400000, 8)
                    .unwrap()
                    .contains("stopped at missing memory")
            );
            assert!(core.read_virtual(u64::MAX, 2).is_err());
            assert!(core.read_virtual(0, READ_LIMIT + 1).is_err());
        });
    }
    #[test]
    fn aarch64_cores_name_their_registers_and_x86_sized_status_is_short() {
        let core_of = |desc_size: u32| {
            let mut data = fixture();
            put16(&mut data, 18, EM_AARCH64);
            data[0x200..0x200 + 712].fill(0);
            put64(&mut data, 96, 20 + u64::from(desc_size));
            put32(&mut data, 0x200, 5);
            put32(&mut data, 0x204, desc_size);
            put32(&mut data, 0x208, 1);
            data[0x20c..0x211].copy_from_slice(b"CORE\0");
            let desc = 0x200 + 20;
            put32(&mut data, desc + 32, 77);
            put64(&mut data, desc + 112 + 31 * 8, 0xffff_f000);
            put64(&mut data, desc + 112 + 32 * 8, 0x400004);
            let path = std::env::temp_dir().join(format!(
                "antinomie-core-a64-{desc_size}-{}",
                std::process::id()
            ));
            fs::write(&path, data).unwrap();
            let core = CoreDump::open(&path);
            fs::remove_file(path).unwrap();
            core
        };
        let core = core_of(392).unwrap();
        assert_eq!(core.machine, EM_AARCH64);
        assert_eq!(core.threads.len(), 1);
        assert_eq!(core.threads[0].tid, 77);
        assert_eq!(core.threads[0].registers.len(), 34);
        assert_eq!(core.threads[0].register("pc"), Some(0x400004));
        assert_eq!(core.threads[0].register("sp"), Some(0xffff_f000));
        assert_eq!(core.threads[0].register("rip"), None);
        assert!(core.disassemble(0x400000, 4).is_err());
        // An x86-64-sized status holds no aarch64 thread: no registers at all.
        assert!(core_of(336).is_err());
        with_core(|path| assert_eq!(CoreDump::open(path).unwrap().machine, EM_X86_64));
    }
    #[test]
    fn truncated_headers_and_qemu_are_rejected() {
        with_core(|path| {
            let mut data = fixture();
            data[0x20c..0x211].copy_from_slice(b"QEMU\0");
            fs::write(path, &data).unwrap();
            assert!(
                CoreDump::open(path)
                    .unwrap_err()
                    .to_string()
                    .contains("QEMU")
            );
            fs::write(path, &data[..90]).unwrap();
            assert!(CoreDump::open(path).is_err());
        });
    }
    #[test]
    fn malicious_segment_and_notes_are_bounded() {
        with_core(|path| {
            let mut data = fixture();
            put64(&mut data, 136, u64::MAX - 1);
            fs::write(path, &data).unwrap();
            assert!(CoreDump::open(path).is_err());
            data = fixture();
            put64(&mut data, 96, NOTE_LIMIT + 1);
            fs::write(path, &data).unwrap();
            assert!(CoreDump::open(path).is_err());
            data = fixture();
            put32(&mut data, 0x204, u32::MAX);
            fs::write(path, &data).unwrap();
            assert!(CoreDump::open(path).is_err());
        });
    }
    #[test]
    fn mapped_files_use_page_scaled_offsets_and_validate_counts() {
        with_core(|path| {
            let mut core = CoreDump::open(path).unwrap();
            let mut desc = vec![0; 40];
            put64(&mut desc, 0, 1);
            put64(&mut desc, 8, 4096);
            put64(&mut desc, 16, 0x400000);
            put64(&mut desc, 24, 0x401000);
            put64(&mut desc, 32, 2);
            desc.extend_from_slice(b"/usr/bin/sample\0");
            core.parse_files(&desc).unwrap();
            assert_eq!(core.files[0].file_offset, 8192);
            assert_eq!(core.files[0].path, "/usr/bin/sample");
            put64(&mut desc, 0, u64::MAX);
            assert!(core.parse_files(&desc).is_err());
        });
    }
    #[test]
    fn imports_reopen_without_copying_core_and_shrunk_source_stays_partial() {
        with_core(|path| {
            let root = path.with_extension("recording");
            let record = CoreRecord::import(path, &root).unwrap();
            assert_eq!(record.core.source, fs::canonicalize(path).unwrap());
            assert!(!record.dir.join("core.elf").exists());
            let listed = list_records(std::slice::from_ref(&root)).unwrap();
            assert_eq!(listed.len(), 1);
            assert_eq!(listed[0].core.threads[1].tid, 41);
            fs::write(path, &fixture()[..0x1002]).unwrap();
            assert_eq!(
                record.core.read_virtual(0x400000, 4).unwrap(),
                vec![Some(0x90), Some(0xc3), None, None]
            );
            fs::remove_dir_all(root).unwrap();
        });
    }
    #[test]
    fn cross_mapping_reads_preserve_gaps_and_overlapping_elf_is_rejected() {
        with_core(|path| {
            let mut core = CoreDump::open(path).unwrap();
            core.mappings[0].memory_size = 4;
            core.mappings.push(CoreMapping {
                start: 0x400008,
                memory_size: 4,
                file_offset: 0x1002,
                captured_size: 2,
                available_size: 2,
                flags: 4,
            });
            assert_eq!(
                core.read_virtual(0x400002, 8).unwrap(),
                vec![
                    Some(0),
                    Some(0x41),
                    None,
                    None,
                    None,
                    None,
                    Some(0),
                    Some(0x41)
                ]
            );
            let mut data = fixture();
            put16(&mut data, 56, 3);
            put32(&mut data, 176, 1);
            put64(&mut data, 192, 0x400002);
            put64(&mut data, 216, 4);
            fs::write(path, data).unwrap();
            assert!(
                CoreDump::open(path)
                    .unwrap_err()
                    .to_string()
                    .contains("overlapping")
            );
        });
    }
}

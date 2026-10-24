// SPDX-License-Identifier: GPL-3.0-only
//! What a dump file is, before MemNixFS reads it: a whole-guest physical
//! memory image, or something that only looks like one. A process core is an
//! ELF core too, but it holds one process's virtual memory, not the guest's
//! physical memory, and must never be handed to a physical-memory analyser.
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

/// Segments and notes read from an ELF core, at most.
const SEGMENT_MAX_COUNT: usize = 4096;
const NOTE_MAX_SIZE: u64 = 1024 * 1024;
const NOTES_TOTAL_MAX_SIZE: u64 = 4 * 1024 * 1024;

/// A dump format MemNixFS reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DumpFormat {
    /// Microsoft AVML (framed Snappy).
    Avml,
    /// Linux Memory Extractor.
    Lime,
    /// ELF core with physical addresses: QEMU `dump-guest-memory` or a
    /// kdump vmcore.
    ElfCore {
        /// PT_LOAD segments with data.
        ranges: usize,
        /// Written by QEMU (a `QEMU` note holds the CPU state).
        qemu: bool,
        /// Carries VMCOREINFO (kdump/vmcore, or QEMU with the vmcoreinfo device).
        vmcoreinfo: bool,
    },
    /// No known header: a flat physical image (`dd`, padded).
    Raw,
}

impl DumpFormat {
    /// The format as the run record and the messages name it.
    pub fn label(&self) -> String {
        match self {
            DumpFormat::Avml => "AVML".into(),
            DumpFormat::Lime => "LiME".into(),
            DumpFormat::ElfCore {
                ranges,
                qemu,
                vmcoreinfo,
            } => format!(
                "ELF64 core of guest physical memory ({}{} PT_LOAD ranges{})",
                if *qemu { "QEMU, " } else { "" },
                ranges,
                if *vmcoreinfo { ", VMCOREINFO" } else { "" }
            ),
            DumpFormat::Raw => "raw physical image (no header)".into(),
        }
    }
}

fn le16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}
fn le32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap_or([0; 4]))
}
fn le64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]))
}

/// Names of the notes in one PT_NOTE segment (ELF notes: a 12-byte header,
/// then the name and the data, each padded to four bytes).
fn note_names(bytes: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    let mut at = 0usize;
    while at + 12 <= bytes.len() {
        let name_len = le32(bytes, at) as usize;
        let data_len = le32(bytes, at + 4) as usize;
        let name_end = at + 12 + name_len;
        let next = (name_end + 3) / 4 * 4 + (data_len + 3) / 4 * 4;
        if name_end > bytes.len() || next > bytes.len() || next <= at {
            break;
        }
        let name = &bytes[at + 12..name_end];
        names.push(
            String::from_utf8_lossy(name.strip_suffix(&[0]).unwrap_or(name)).into_owned(),
        );
        at = next;
    }
    names
}

/// Classify the dump file at `path`. Errors say why MemNixFS cannot be used.
pub fn classify(path: &Path) -> Result<DumpFormat, String> {
    let mut file = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut header = [0u8; 64];
    let read = file
        .read(&mut header)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if read == 0 {
        return Err("the dump file is empty".into());
    }
    let header = &header[..read];
    match header.get(..4) {
        Some(b"AVML") => return Ok(DumpFormat::Avml),
        Some(b"EMiL") => return Ok(DumpFormat::Lime),
        Some(b"PAGE") => {
            return Err("this is a Windows crash dump; MemNixFS reads Linux memory only".into());
        }
        Some(b"hibr" | b"HIBR" | b"wake" | b"WAKE") => {
            return Err("this is a Windows hibernation file; MemNixFS reads Linux memory only".into());
        }
        Some(b"\x7fELF") => {}
        _ => return Ok(DumpFormat::Raw),
    }
    if read < 64 {
        return Err("the ELF header is truncated".into());
    }
    if header[4] != 2 || header[5] != 1 {
        return Err("only little-endian ELF64 cores are read".into());
    }
    if le16(header, 16) != 4 {
        return Err(
            "this ELF file is a program or library, not a core; MemNixFS needs a guest \
             physical-memory dump"
                .into(),
        );
    }
    if le16(header, 18) != 62 {
        return Err("only x86-64 guest memory is read".into());
    }
    let (phoff, phentsize, phnum) = (le64(header, 32), le16(header, 54), le16(header, 56));
    if phentsize != 56 || phnum == 0 || usize::from(phnum) > SEGMENT_MAX_COUNT {
        return Err("the ELF core has no usable program headers".into());
    }
    let mut table = vec![0u8; usize::from(phnum) * 56];
    file.seek(SeekFrom::Start(phoff))
        .and_then(|_| file.read_exact(&mut table))
        .map_err(|e| format!("the ELF program headers cannot be read: {e}"))?;
    let (mut ranges, mut physical, mut notes_size) = (0usize, false, 0u64);
    let (mut qemu, mut vmcoreinfo) = (false, false);
    for entry in table.chunks_exact(56) {
        let (kind, offset, paddr, filesz) =
            (le32(entry, 0), le64(entry, 8), le64(entry, 24), le64(entry, 32));
        match kind {
            1 if filesz > 0 => {
                ranges += 1;
                physical |= paddr != 0;
            }
            4 if filesz <= NOTE_MAX_SIZE && notes_size + filesz <= NOTES_TOTAL_MAX_SIZE => {
                notes_size += filesz;
                let mut bytes = vec![0u8; filesz as usize];
                if file
                    .seek(SeekFrom::Start(offset))
                    .and_then(|_| file.read_exact(&mut bytes))
                    .is_ok()
                {
                    for name in note_names(&bytes) {
                        qemu |= name == "QEMU";
                        vmcoreinfo |= name == "VMCOREINFO";
                    }
                }
            }
            _ => {}
        }
    }
    if ranges == 0 {
        return Err("the ELF core has no memory segments".into());
    }
    // QEMU's and kdump's cores carry physical addresses (and say so in their
    // notes). A process core has only virtual addresses: every segment has a
    // zero physical address.
    if !qemu && !vmcoreinfo && !physical {
        return Err(
            "this ELF core is a process core (its segments have no physical addresses): it \
             holds one process's memory, not the guest's, so MemNixFS cannot analyse it"
                .into(),
        );
    }
    Ok(DumpFormat::ElfCore {
        ranges,
        qemu,
        vmcoreinfo,
    })
}

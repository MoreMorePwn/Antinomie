// SPDX-License-Identifier: MIT
//! Segments for Structures: every ELF program header, or the segments
//! other object formats declare.
use object::{Object, ObjectSegment};

/// A program header or load command, recorded under Structures with the
/// label "Segment" and the shape of a section.
pub(super) struct Segment {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_range: Option<(u64, u64)>,
    pub raw_flags: String,
    pub flags: Vec<String>,
}

/// Every ELF program header (the object crate's segments are PT_LOAD only),
/// or the segments other formats declare.
pub(super) fn segments(file: &object::File) -> Vec<Segment> {
    match file {
        object::File::Elf32(elf) => elf_segments(elf),
        object::File::Elf64(elf) => elf_segments(elf),
        _ => file
            .segments()
            .map(|segment| {
                let permissions = segment.permissions();
                Segment {
                    name: segment
                        .name()
                        .ok()
                        .flatten()
                        .unwrap_or("<unnamed>")
                        .to_owned(),
                    address: segment.address(),
                    size: segment.size(),
                    file_range: Some(segment.file_range()),
                    raw_flags: format!("{:?}", segment.flags()),
                    flags: [
                        (permissions.readable(), "R"),
                        (permissions.writable(), "W"),
                        (permissions.executable(), "X"),
                    ]
                    .into_iter()
                    .filter(|(set, _)| *set)
                    .map(|(_, name)| name.to_owned())
                    .collect(),
                }
            })
            .collect(),
    }
}

fn elf_segments<Elf: object::read::elf::FileHeader<Endian = object::Endianness>>(
    elf: &object::read::elf::ElfFile<'_, Elf>,
) -> Vec<Segment> {
    use object::read::elf::ProgramHeader;
    let endian = elf.endian();
    elf.elf_program_headers()
        .iter()
        .map(|header| {
            let kind = header.p_type(endian);
            let flags = header.p_flags(endian);
            Segment {
                name: program_type(kind.0),
                address: header.p_vaddr(endian).into(),
                size: header.p_memsz(endian).into(),
                file_range: Some((
                    header.p_offset(endian).into(),
                    header.p_filesz(endian).into(),
                )),
                raw_flags: format!("0x{:x}", flags.0),
                flags: [
                    (object::elf::PF_R, "R"),
                    (object::elf::PF_W, "W"),
                    (object::elf::PF_X, "X"),
                ]
                .into_iter()
                .filter(|(flag, _)| flags.0 & flag.0 != 0)
                .map(|(_, name)| name.to_owned())
                .collect(),
            }
        })
        .collect()
}

/// The name of an ELF `p_type`, without its `PT_` prefix.
fn program_type(value: u32) -> String {
    match value {
        0 => "NULL",
        1 => "LOAD",
        2 => "DYNAMIC",
        3 => "INTERP",
        4 => "NOTE",
        5 => "SHLIB",
        6 => "PHDR",
        7 => "TLS",
        0x6474_e550 => "GNU_EH_FRAME",
        0x6474_e551 => "GNU_STACK",
        0x6474_e552 => "GNU_RELRO",
        0x6474_e553 => "GNU_PROPERTY",
        0x6474_e554 => "GNU_SFRAME",
        _ => return format!("0x{value:x}"),
    }
    .to_owned()
}

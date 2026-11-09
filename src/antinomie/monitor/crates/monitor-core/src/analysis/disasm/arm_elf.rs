// SPDX-License-Identifier: GPL-3.0-only
//! AArch64 and 32-bit ARM programs in the Disassembly check, decoded with the
//! linked Capstone (the same decoders as the debugger's code pane) into the
//! rows the x86 path writes. The host's objdump is not used: on an x86 PC it
//! cannot decode ARM.
//!
//! For ARM32 the instruction set of a range comes from the ELF mapping
//! symbols (`$a` ARM, `$t` Thumb, `$d` data) when the file keeps them; a
//! stripped file is read in Thumb when the entry point has its low bit set,
//! else in ARM.
use super::super::disasm_aarch64::decode_window_aarch64;
use super::super::disasm_arm::{ArmMode, decode_span_arm};
use super::super::listing::ListingWriter;
use super::super::*;
use super::{DecodedInstruction, Functions, unavailable};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind};
use std::path::Path;

/// Bytes decoded per Capstone call.
const CHUNK: usize = 1 << 20;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Region {
    Code(ArmMode),
    Data,
}

/// `$a`, `$t` and `$d` mapping symbols, by address.
fn mapping(file: &object::File) -> Vec<(u64, Region)> {
    let mut marks: Vec<(u64, Region)> = file
        .symbols()
        .filter_map(|symbol| {
            let region = match symbol.name().ok()?.split('.').next()? {
                "$a" => Region::Code(ArmMode::Arm),
                "$t" => Region::Code(ArmMode::Thumb),
                "$d" => Region::Data,
                _ => return None,
            };
            Some((symbol.address(), region))
        })
        .collect();
    marks.sort_by_key(|(address, _)| *address);
    marks
}

/// The code of one executable section, cut into runs of one instruction set.
fn runs(start: u64, end: u64, marks: &[(u64, Region)], default: Region) -> Vec<(u64, u64, Region)> {
    let mut runs = Vec::new();
    let mut at = start;
    let mut current = marks
        .iter()
        .rev()
        .find(|(address, _)| *address <= start)
        .map_or(default, |(_, region)| *region);
    for (address, region) in marks.iter().filter(|(a, _)| *a > start && *a < end) {
        if *address > at {
            runs.push((at, *address, current));
            at = *address;
        }
        current = *region;
    }
    if end > at {
        runs.push((at, end, current));
    }
    runs
}

fn data_rows(address: u64, bytes: &[u8]) -> Vec<DecodedInstruction> {
    bytes
        .chunks(4)
        .enumerate()
        .map(|(index, word)| {
            let text = match <[u8; 4]>::try_from(word) {
                Ok(word) => format!(".word {:#010x}", u32::from_le_bytes(word)),
                Err(_) => format!(".byte {:#04x}", word[0]),
            };
            DecodedInstruction {
                address: address + index as u64 * 4,
                bytes: word.to_vec(),
                text,
            }
        })
        .collect()
}

fn decode(aarch64: bool, region: Region, address: u64, bytes: &[u8]) -> Vec<DecodedInstruction> {
    match region {
        Region::Data => data_rows(address, bytes),
        Region::Code(_) if aarch64 => {
            decode_window_aarch64(address, bytes, address, 0, bytes.len() / 4)
        }
        Region::Code(mode) => decode_span_arm(address, bytes, mode),
    }
}

pub(super) fn disassemble(
    section: &mut AnalysisSection,
    file: &object::File,
    listings: &Path,
    aarch64: bool,
) {
    let isa = if aarch64 { "AArch64" } else { "ARM and Thumb" };
    if file.endianness() != object::Endianness::Little {
        return unavailable(
            section,
            format!("Big-endian {isa} code is not decoded; only little-endian programs are"),
        );
    }
    super::super::progress::tool_started("capstone", &[]);
    let (major, minor) = capstone::Capstone::lib_version();
    let version = format!("capstone {major}.{minor}");
    // Function names: the Thumb bit of a symbol address is not part of it.
    let mut named = Functions::new();
    for (address, (name, size)) in super::functions(file) {
        named
            .entry(if aarch64 { address } else { address & !1 })
            .or_insert((name, size));
    }
    let symbols = named.len();
    let marks = if aarch64 { Vec::new() } else { mapping(file) };
    let default = if !aarch64 && file.entry() & 1 == 1 {
        Region::Code(ArmMode::Thumb)
    } else {
        Region::Code(ArmMode::Arm)
    };
    let mut writer = match ListingWriter::create(
        listings,
        AnalysisKind::Disassembly,
        super::super::limits::listing_bytes(),
    ) {
        Ok(writer) => writer,
        Err(error) => {
            return unavailable(
                section,
                format!("The disassembly listing could not be written: {error}"),
            );
        }
    };
    let (mut instructions, mut sections, mut undecoded) = (0u64, 0u64, 0u64);
    let mut full = false;
    'sections: for code in file.sections() {
        if code.kind() != SectionKind::Text {
            continue;
        }
        let (Ok(bytes), Some((file_offset, _))) = (code.data(), code.file_range()) else {
            continue;
        };
        sections += 1;
        let base = code.address();
        let end = base.saturating_add(bytes.len() as u64);
        for (run_start, run_end, region) in runs(base, end, &marks, default) {
            let mut position = run_start;
            while position < run_end {
                let from = (position - base) as usize;
                let to = (run_end - base) as usize;
                let last = to - from <= CHUNK;
                let slice = &bytes[from..if last { to } else { from + CHUNK }];
                let mut rows = decode(aarch64, region, position, slice);
                if !last && rows.len() > 1 {
                    // The last row may have been cut by the chunk's end.
                    rows.pop();
                }
                let Some(next) = rows.last().map(|row| row.address + row.bytes.len() as u64) else {
                    break;
                };
                for row in rows {
                    let address = row.address;
                    if let Some((name, size)) = named.get(&address)
                        && !writer.push(
                            name.clone(),
                            if *size > 0 {
                                format!("{name} · {}", crate::byte_size::file_size(*size))
                            } else {
                                name.clone()
                            },
                            Some(AnalysisLocation {
                                kind: AnalysisAddressKind::ObjectAddress,
                                value: address,
                                file_range: None,
                            }),
                            AnalysisData::Function {
                                name: name.clone(),
                                address,
                                size: *size,
                            },
                        )
                    {
                        full = true;
                        break 'sections;
                    }
                    if row.text.starts_with('.') {
                        undecoded += 1;
                    }
                    let (mnemonic, operands) = row
                        .text
                        .split_once(char::is_whitespace)
                        .unwrap_or((row.text.as_str(), ""));
                    let function = super::containing(&named, address).map(str::to_owned);
                    let hex = row
                        .bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ");
                    if !writer.push(
                        function.clone().unwrap_or_default(),
                        row.text.clone(),
                        Some(AnalysisLocation {
                            kind: AnalysisAddressKind::ObjectAddress,
                            value: address,
                            file_range: Some(AnalysisRange {
                                offset: file_offset + (address - base),
                                len: row.bytes.len() as u64,
                            }),
                        }),
                        AnalysisData::Instruction {
                            address,
                            bytes: hex,
                            mnemonic: mnemonic.into(),
                            operands: operands.into(),
                            function,
                            label: None,
                            targets: Vec::new(),
                            xrefs: Vec::new(),
                        },
                    ) {
                        full = true;
                        break 'sections;
                    }
                    instructions += 1;
                }
                if next <= position {
                    break;
                }
                position = next;
            }
        }
    }
    match writer.finish(full) {
        Ok(listing) => {
            section.state = AnalysisSectionState::Complete;
            section.summary = format!(
                "{instructions} {isa} instructions in {sections} executable sections (Capstone); {symbols} function symbols; addresses are object addresses{}",
                if undecoded > 0 {
                    format!("; {undecoded} words or halfwords shown as data")
                } else {
                    String::new()
                },
            );
            if listing.truncated {
                section.state = AnalysisSectionState::Partial;
                super::super::limits::add_for(
                    section,
                    AnalysisLimitKind::Size,
                    LimitSetting::Listing,
                    format!(
                        "The listing reached its {} limit after {} instructions; later code is not listed.",
                        crate::byte_size::short_size(super::super::limits::listing_bytes()),
                        super::super::detection::group_digits(instructions)
                    ),
                );
            }
            section.listing = Some(listing);
            section.tools.push(version);
        }
        Err(error) => unavailable(section, error),
    }
}

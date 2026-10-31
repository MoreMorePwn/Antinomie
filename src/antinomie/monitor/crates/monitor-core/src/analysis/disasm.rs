// SPDX-License-Identifier: GPL-3.0-only
//! Built-in disassembly: x86 and x86-64 decoded with iced-x86, other
//! architectures through objdump; every instruction is one listing row.
use super::listing::ListingWriter;
use super::*;
use iced_x86::{
    Decoder, DecoderOptions, Formatter, Instruction, IntelFormatter, SymbolResolver, SymbolResult,
};
use object::{Object, ObjectSection, ObjectSymbol, SectionKind, SymbolKind};
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub(super) const ICED_VERSION: &str = "iced-x86 1.21";

/// Function symbols by start address: name and declared size.
type Functions = BTreeMap<u64, (String, u64)>;

struct Names(Arc<Functions>);

impl SymbolResolver for Names {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        self.0
            .get(&address)
            .map(|(name, _)| SymbolResult::with_string(address, name.clone()))
    }
}

fn functions(file: &object::File) -> Functions {
    let mut functions = Functions::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.kind() == SymbolKind::Text
            && !symbol.is_undefined()
            && symbol.address() != 0
            && let Ok(name) = symbol.name()
            && !name.is_empty()
        {
            functions
                .entry(symbol.address())
                .or_insert_with(|| (name.to_owned(), symbol.size()));
        }
    }
    let entry = file.entry();
    if entry != 0 {
        functions
            .entry(entry)
            .or_insert_with(|| ("entry".into(), 0));
    }
    functions
}

/// The function containing `address`: a sized symbol covers its size, an
/// unsized one (a call target) runs until the next function.
fn containing(functions: &Functions, address: u64) -> Option<&str> {
    let (start, (name, size)) = functions.range(..=address).next_back()?;
    let end = if *size > 0 {
        start.saturating_add(*size)
    } else {
        functions
            .range(start + 1..)
            .next()
            .map_or(u64::MAX, |(next, _)| *next)
    };
    (address < end).then_some(name.as_str())
}

/// Name every direct call target inside executable code `sub_<address>`,
/// so stripped programs still read as functions.
fn call_targets(file: &object::File, bitness: u32, functions: &mut Functions) {
    let ranges: Vec<(u64, u64)> = file
        .sections()
        .filter(|s| s.kind() == SectionKind::Text)
        .map(|s| (s.address(), s.address() + s.size()))
        .collect();
    for code in file.sections().filter(|s| s.kind() == SectionKind::Text) {
        let Ok(bytes) = code.data() else { continue };
        let mut decoder = Decoder::with_ip(bitness, bytes, code.address(), DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_call_near() {
                let target = instruction.near_branch_target();
                if ranges
                    .iter()
                    .any(|(start, end)| (*start..*end).contains(&target))
                {
                    functions
                        .entry(target)
                        .or_insert_with(|| (format!("sub_{target:x}"), 0));
                }
            }
        }
    }
}

/// The listing's text style, shared with the debugger's live disassembly.
fn configure(formatter: &mut IntelFormatter) {
    formatter.options_mut().set_first_operand_char_index(0);
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(false);
}

/// One instruction decoded from raw bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
}

/// Decode x86-64 code around `focus` from `bytes` that start at `address`:
/// up to `before` instructions ahead of `focus` and `after` from it on (counting
/// it). Going backwards is a guess, since x86 instructions vary in length: the
/// decode starts at the earliest byte from which linear decoding lands exactly
/// on `focus`, or at `focus` itself when none does. The same formatter as the
/// static listing, so the text matches it.
pub fn decode_window(
    address: u64,
    bytes: &[u8],
    focus: u64,
    before: usize,
    after: usize,
) -> Vec<DecodedInstruction> {
    let Some(focus_offset) = focus
        .checked_sub(address)
        .and_then(|offset| usize::try_from(offset).ok())
        .filter(|offset| *offset < bytes.len())
    else {
        return Vec::new();
    };
    let lands_on_focus = |start: usize| {
        let mut decoder = Decoder::with_ip(
            64,
            &bytes[start..focus_offset],
            address + start as u64,
            DecoderOptions::NONE,
        );
        let mut instruction = Instruction::default();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                return false;
            }
        }
        decoder.position() == focus_offset - start
    };
    let start = (0..focus_offset)
        .find(|start| lands_on_focus(*start))
        .unwrap_or(focus_offset);
    let mut formatter = IntelFormatter::new();
    configure(&mut formatter);
    formatter.options_mut().set_branch_leading_zeros(false);
    let mut decoder = Decoder::with_ip(
        64,
        &bytes[start..],
        address + start as u64,
        DecoderOptions::NONE,
    );
    let mut instruction = Instruction::default();
    let mut lines = Vec::new();
    let mut seen_focus = 0usize;
    while decoder.can_decode() && seen_focus < after {
        decoder.decode_out(&mut instruction);
        let offset = (instruction.ip() - address) as usize;
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        if instruction.is_invalid() {
            text = "(bad)".into();
        }
        lines.push(DecodedInstruction {
            address: instruction.ip(),
            bytes: bytes[offset..offset + instruction.len()].to_vec(),
            text,
        });
        if instruction.ip() >= focus {
            seen_focus += 1;
        }
    }
    let first = lines
        .iter()
        .position(|line| line.address >= focus)
        .unwrap_or(0)
        .saturating_sub(before);
    lines.split_off(first)
}

pub(super) fn disassemble(section: &mut AnalysisSection, specimen: &[u8], listings: &Path) {
    let Ok(file) = object::File::parse(specimen) else {
        unavailable(
            section,
            "The file is not an ELF, PE or Mach-O file the parser can read, so there is nothing to disassemble",
        );
        return;
    };
    let bitness = match file.architecture() {
        object::Architecture::X86_64 => 64,
        object::Architecture::I386 => 32,
        object::Architecture::X86_64_X32 => 64,
        _ => return objdump(section, listings),
    };
    super::progress::tool_started("iced-x86", &[]);
    let mut named = functions(&file);
    let symbols = named.len();
    call_targets(&file, bitness, &mut named);
    let discovered = named.len() - symbols;
    let functions = Arc::new(named);
    let mut writer = match ListingWriter::create(
        listings,
        AnalysisKind::Disassembly,
        super::limits::listing_bytes(),
    ) {
        Ok(writer) => writer,
        Err(error) => {
            return unavailable(
                section,
                format!("The disassembly listing could not be written: {error}"),
            );
        }
    };
    let mut formatter =
        IntelFormatter::with_options(Some(Box::new(Names(functions.clone()))), None);
    configure(&mut formatter);
    let (mut instructions, mut sections, mut invalid) = (0u64, 0u64, 0u64);
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
        let mut decoder = Decoder::with_ip(bitness, bytes, base, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut text = String::new();
        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            let address = instruction.ip();
            if let Some((name, size)) = functions.get(&address)
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
            let offset = (address - base) as usize;
            let raw = &bytes[offset..offset + instruction.len()];
            let (mnemonic, operands) = if instruction.is_invalid() {
                invalid += 1;
                ("(bad)".to_string(), String::new())
            } else {
                text.clear();
                formatter.format_mnemonic(&instruction, &mut text);
                let mnemonic = text.clone();
                text.clear();
                formatter.format_all_operands(&instruction, &mut text);
                (mnemonic, text.clone())
            };
            let function = containing(&functions, address).map(str::to_owned);
            let hex = raw
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let value = if operands.is_empty() {
                mnemonic.clone()
            } else {
                format!("{mnemonic} {operands}")
            };
            if !writer.push(
                function.clone().unwrap_or_default(),
                value,
                Some(AnalysisLocation {
                    kind: AnalysisAddressKind::ObjectAddress,
                    value: address,
                    file_range: Some(AnalysisRange {
                        offset: file_offset + offset as u64,
                        len: raw.len() as u64,
                    }),
                }),
                AnalysisData::Instruction {
                    address,
                    bytes: hex,
                    mnemonic,
                    operands,
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
    }
    match writer.finish(full) {
        Ok(listing) => {
            section.state = AnalysisSectionState::Complete;
            section.summary = format!(
                "{instructions} instructions in {sections} executable sections; {symbols} function symbols and {discovered} call targets named sub_<address>; addresses are object addresses{}",
                if invalid > 0 {
                    format!("; {invalid} undecodable byte runs shown as (bad)")
                } else {
                    String::new()
                },
            );
            if listing.truncated {
                section.state = AnalysisSectionState::Partial;
                super::limits::add_for(
                    section,
                    AnalysisLimitKind::Size,
                    LimitSetting::Listing,
                    format!(
                        "The listing reached its {} limit after {} instructions; later code is not listed.",
                        crate::byte_size::short_size(super::limits::listing_bytes()),
                        super::detection::group_digits(instructions)
                    ),
                );
            }
            section.listing = Some(listing);
            section.tools.push(ICED_VERSION.into());
        }
        Err(error) => unavailable(section, error),
    }
}

/// Other architectures: objdump's text, parsed into the same rows.
fn objdump(section: &mut AnalysisSection, listings: &Path) {
    let (version, output, end) = match super::worker::tool(
        "/usr/bin/objdump",
        &[
            "--disassemble",
            "--wide",
            "--no-show-raw-insn",
            "/input/specimen",
        ],
    ) {
        Ok(result) => result,
        Err(error) => {
            return unavailable(
                section,
                format!(
                    "no built-in decoder for this architecture and objdump is unavailable: {error}"
                ),
            );
        }
    };
    let mut writer = match ListingWriter::create(
        listings,
        AnalysisKind::Disassembly,
        super::limits::listing_bytes(),
    ) {
        Ok(writer) => writer,
        Err(error) => {
            return unavailable(
                section,
                format!("The disassembly listing could not be written: {error}"),
            );
        }
    };
    let mut function: Option<String> = None;
    let mut full = false;
    let mut instructions = 0u64;
    for line in output.lines() {
        // "0000000000401000 <_start>:" opens a function.
        if let Some((address, rest)) = line.split_once(' ')
            && let Some(name) = rest.strip_prefix('<').and_then(|r| r.strip_suffix(">:"))
            && let Ok(address) = u64::from_str_radix(address, 16)
        {
            function = Some(name.to_owned());
            full |= !writer.push(
                name,
                name,
                Some(AnalysisLocation {
                    kind: AnalysisAddressKind::ObjectAddress,
                    value: address,
                    file_range: None,
                }),
                AnalysisData::Function {
                    name: name.into(),
                    address,
                    size: 0,
                },
            );
            continue;
        }
        // "  401000:\tmov    %rsp,%rbp"
        let Some((address, text)) = line.trim_start().split_once(":\t") else {
            continue;
        };
        let Ok(address) = u64::from_str_radix(address, 16) else {
            continue;
        };
        let text = text.trim();
        let (mnemonic, operands) = text.split_once(char::is_whitespace).unwrap_or((text, ""));
        full |= !writer.push(
            function.clone().unwrap_or_default(),
            text,
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::ObjectAddress,
                value: address,
                file_range: None,
            }),
            AnalysisData::Instruction {
                address,
                bytes: String::new(),
                mnemonic: mnemonic.into(),
                operands: operands.trim().into(),
                function: function.clone(),
                label: None,
                targets: Vec::new(),
                xrefs: Vec::new(),
            },
        );
        if full {
            break;
        }
        instructions += 1;
    }
    match writer.finish(full || end != super::worker::ToolEnd::Finished) {
        Ok(listing) => {
            section.state = AnalysisSectionState::Complete;
            section.summary = format!(
                "{instructions} instructions from objdump (no built-in decoder for this architecture); addresses are object addresses"
            );
            if listing.truncated && full {
                section.state = AnalysisSectionState::Partial;
                super::limits::add_for(
                    section,
                    AnalysisLimitKind::Size,
                    LimitSetting::Listing,
                    format!(
                        "The listing reached its {} limit after {} instructions; later code is not listed.",
                        crate::byte_size::short_size(super::limits::listing_bytes()),
                        super::detection::group_digits(instructions)
                    ),
                );
            }
            section.listing = Some(listing);
            section.tools.push(version);
            super::worker::cut_tool_short(section, "objdump", end);
        }
        Err(error) => unavailable(section, error),
    }
}

fn unavailable(section: &mut AnalysisSection, reason: impl Into<String>) {
    section.state = AnalysisSectionState::Unavailable;
    section.summary = reason.into();
}

#[cfg(test)]
mod window_tests {
    use super::*;

    // push rbp; mov rbp, rsp; sub rsp, 0x20; call +0; xor eax, eax; ret
    const CODE: &[u8] = &[
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0xe8, 0, 0, 0, 0, 0x31, 0xc0, 0xc3,
    ];

    #[test]
    fn the_window_starts_before_the_focus_and_matches_the_listing_style() {
        let lines = decode_window(0x401000, CODE, 0x401008, 2, 3);
        let text: Vec<_> = lines
            .iter()
            .map(|line| (line.address, line.text.as_str()))
            .collect();
        assert_eq!(
            text,
            [
                (0x401001, "mov rbp, rsp"),
                (0x401004, "sub rsp, 0x20"),
                (0x401008, "call 0x40100d"),
                (0x40100d, "xor eax, eax"),
                (0x40100f, "ret"),
            ]
        );
        assert_eq!(lines[2].bytes, [0xe8, 0, 0, 0, 0]);
    }

    #[test]
    fn a_focus_outside_the_bytes_decodes_nothing() {
        assert!(decode_window(0x1000, CODE, 0x900, 2, 3).is_empty());
        assert!(decode_window(0x1000, CODE, 0x2000, 2, 3).is_empty());
        assert!(decode_window(0x1000, &[], 0x1000, 2, 3).is_empty());
    }

    #[test]
    fn a_focus_that_no_earlier_start_reaches_decodes_from_the_focus() {
        // 0xe8 needs four more bytes, so nothing before the focus can end on it.
        let lines = decode_window(0x1000, &[0xe8, 0x90, 0x90, 0x90, 0x90, 0x90], 0x1001, 3, 2);
        assert_eq!(lines.first().map(|line| line.address), Some(0x1001));
        assert_eq!(lines.len(), 2);
    }
}

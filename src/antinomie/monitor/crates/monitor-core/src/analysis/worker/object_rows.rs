// SPDX-License-Identifier: GPL-3.0-only
//! The checks that read the specimen as an object file: hashes, entropy,
//! headers, sections, symbols, imports, exports and hardening flags.
use super::*;

/// Hashes, size and the object header of the specimen.
pub(super) fn metadata_rows(section: &mut AnalysisSection, specimen: &[u8]) {
    entry(
        section,
        "MD5",
        format!("{:x}", md5::Md5::digest(specimen)),
        None,
    );
    entry(
        section,
        "SHA-1",
        format!("{:x}", sha1::Sha1::digest(specimen)),
        None,
    );
    entry(
        section,
        "SHA-256",
        format!("{:x}", Sha256::digest(specimen)),
        None,
    );
    entry(
        section,
        "File size",
        crate::byte_size::file_size(specimen.len() as u64),
        None,
    );
    match object::File::parse(specimen) {
        Ok(file) => {
            for (label, value) in [
                ("Format", format!("{:?}", file.format())),
                ("Architecture", format!("{:?}", file.architecture())),
                ("Object kind", format!("{:?}", file.kind())),
                (
                    "Class",
                    format!("{}-bit", if file.is_64() { 64 } else { 32 }),
                ),
                ("Endianness", format!("{:?}", file.endianness())),
            ] {
                structured_entry(
                    section,
                    label,
                    value,
                    None,
                    AnalysisData::Field {
                        group: "Object header".into(),
                    },
                );
            }
        }
        Err(_) => entry(
            section,
            "Object",
            "not an ELF, PE or Mach-O file the parser can read; only the hashes and size apply",
            None,
        ),
    }
    // What the file's own headers say about running it: a cut-off download, a
    // library that is no program. Identity shows these above its rows.
    for note in super::super::elf_facts::file_notes(specimen) {
        structured_entry(
            section,
            super::super::elf_facts::NOTE_LABEL,
            note,
            None,
            AnalysisData::Field {
                group: "Notes".into(),
            },
        );
    }
}

/// Whole-file entropy and up to 64 measured regions.
pub(super) fn entropy_rows(section: &mut AnalysisSection, specimen: &[u8]) {
    entropy_entry(section, "Whole file", specimen, 0);
    let region_size = specimen.len().div_ceil(64).max(4096);
    for (index, region) in specimen.chunks(region_size).take(64).enumerate() {
        entropy_entry(
            section,
            "Measured region",
            region,
            (index * region_size) as u64,
        );
    }
    section.summary =
        "whole-file and up to 64 measured regions; entropy is not a packing verdict".into();
}

/// Headers or hardening flags, once the specimen parses as an object file.
pub(super) fn rows(section: &mut AnalysisSection, specimen: &[u8]) {
    match object::File::parse(specimen) {
        Ok(file) => {
            if section.kind == AnalysisKind::Structures {
                structure_rows(section, &file, specimen);
            } else {
                hardening_rows(section, &file);
            }
        }
        Err(error) => unavailable(
            section,
            format!(
                "The file is not an executable format Antinomie can read ({error}), so there are no {} to show.",
                if section.kind == AnalysisKind::Structures {
                    "headers, sections or symbols"
                } else {
                    "hardening flags"
                }
            ),
        ),
    }
}

/// The entry point, then every table the object file holds.
fn structure_rows(section: &mut AnalysisSection, file: &object::File<'_>, specimen: &[u8]) {
    structured_entry(
        section,
        "Entry point (declared address)",
        format!("0x{:x}", file.entry()),
        Some(AnalysisLocation {
            kind: AnalysisAddressKind::ObjectAddress,
            value: file.entry(),
            file_range: None,
        }),
        AnalysisData::Field {
            group: "Object header".into(),
        },
    );
    needed_rows(section, specimen);
    section_rows(section, file, specimen);
    segment_rows(section, file, specimen);
    symbol_rows(section, file, specimen);
    import_rows(section, file);
    export_rows(section, file);
}

/// One row per library an ELF's dynamic section needs, so a program that
/// stops at "cannot open shared object file" shows what it was missing.
fn needed_rows(section: &mut AnalysisSection, specimen: &[u8]) {
    let Some(elf) = super::super::elf_facts::parse(specimen) else {
        return;
    };
    for library in elf.dynamic(specimen).needed {
        structured_entry(
            section,
            "Needed library",
            library,
            None,
            AnalysisData::Field {
                group: "Needed libraries".into(),
            },
        );
    }
}

/// One row per object section.
fn section_rows(section: &mut AnalysisSection, file: &object::File<'_>, specimen: &[u8]) {
    for s in file.sections() {
        let file_range = checked_range(s.file_range(), specimen.len() as u64);
        if s.file_range().is_some() && file_range.is_none() {
            section.state = AnalysisSectionState::Partial;
            super::super::limits::add(
                section,
                AnalysisLimitKind::Input,
                format!(
                    "Section {} points past the end of the file; its bytes are not shown.",
                    s.name().unwrap_or("<invalid name>")
                ),
                None,
            );
        }
        let (raw_flags, flags) = section_flags(s.flags());
        structured_entry(
            section,
            "Section",
            format!(
                "{}; size {}; flags {:?}",
                s.name().unwrap_or("<invalid name>"),
                s.size(),
                s.flags()
            ),
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::ObjectAddress,
                value: s.address(),
                file_range,
            }),
            AnalysisData::Section {
                name: s.name().unwrap_or("<invalid name>").into(),
                address: s.address(),
                virtual_size: s.size(),
                file_size: file_range.map(|r| r.len),
                raw_flags,
                flags,
            },
        );
    }
}

/// One row per segment or load command.
fn segment_rows(section: &mut AnalysisSection, file: &object::File<'_>, specimen: &[u8]) {
    for segment in super::super::segments::segments(file) {
        let file_range = checked_range(segment.file_range, specimen.len() as u64);
        if segment.file_range.is_some() && file_range.is_none() {
            section.state = AnalysisSectionState::Partial;
            super::super::limits::add(
                section,
                AnalysisLimitKind::Input,
                format!(
                    "Segment {} points past the end of the file; its bytes are not shown.",
                    segment.name
                ),
                None,
            );
        }
        structured_entry(
            section,
            "Segment",
            format!(
                "{}; size {}; {}",
                segment.name,
                segment.size,
                segment.flags.join(" ")
            ),
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::ObjectAddress,
                value: segment.address,
                file_range,
            }),
            AnalysisData::Section {
                name: segment.name,
                address: segment.address,
                virtual_size: segment.size,
                file_size: file_range.map(|r| r.len),
                raw_flags: segment.raw_flags,
                flags: segment.flags,
            },
        );
    }
}

/// Static and dynamic symbols.
fn symbol_rows(section: &mut AnalysisSection, file: &object::File<'_>, specimen: &[u8]) {
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if let Ok(name) = symbol.name()
            && !name.is_empty()
        {
            let address = (!symbol.is_undefined()
                && symbol.section_index().is_some()
                && !matches!(
                    symbol.kind(),
                    object::SymbolKind::Tls | object::SymbolKind::File
                ))
            .then_some(symbol.address());
            let file_range = address.and_then(|address| {
                symbol
                    .section_index()
                    .and_then(|index| file.section_by_index(index).ok())
                    .and_then(|section| {
                        symbol_range(&section, address, symbol.size(), specimen.len() as u64)
                    })
            });
            structured_entry(
                section,
                if symbol.is_undefined() {
                    "Undefined symbol"
                } else {
                    "Symbol"
                },
                name,
                address.map(|value| AnalysisLocation {
                    kind: AnalysisAddressKind::ObjectAddress,
                    value,
                    file_range,
                }),
                AnalysisData::Symbol {
                    name: name.into(),
                    kind: format!("{:?}", symbol.kind()),
                    scope: format!("{:?}", symbol.scope()),
                    undefined: symbol.is_undefined(),
                    address,
                    size: symbol.size(),
                },
            );
        }
    }
}

/// The import table.
fn import_rows(section: &mut AnalysisSection, file: &object::File<'_>) {
    match file.imports() {
        Ok(imports) => {
            for import in imports {
                match import {
                    Ok(import) => {
                        let (name, ordinal) = name_parts(import.name());
                        let library = (!import.library().is_empty())
                            .then(|| String::from_utf8_lossy(import.library()).into_owned());
                        structured_entry(
                            section,
                            "Import",
                            format!(
                                "{}!{}",
                                library.as_deref().unwrap_or(""),
                                object_name(import.name())
                            ),
                            None,
                            AnalysisData::Import {
                                name,
                                library,
                                ordinal,
                            },
                        );
                    }
                    Err(error) => {
                        section.state = AnalysisSectionState::Partial;
                        super::super::limits::add(
                            section,
                            AnalysisLimitKind::Input,
                            format!("Part of the import table cannot be read: {error}."),
                            None,
                        );
                        entry(section, "Import parse error", error.to_string(), None);
                    }
                }
            }
        }
        Err(error) => {
            section.state = AnalysisSectionState::Partial;
            super::super::limits::add(
                section,
                AnalysisLimitKind::Input,
                format!("The import table cannot be read: {error}."),
                None,
            );
            entry(section, "Imports parse error", error.to_string(), None);
        }
    }
}

/// The export table.
fn export_rows(section: &mut AnalysisSection, file: &object::File<'_>) {
    match file.exports() {
        Ok(exports) => {
            for export in exports {
                match export {
                    Ok(export) => {
                        let (name, ordinal) = name_parts(export.name());
                        let address = match export.target() {
                            object::ExportTarget::Address { address, .. } => Some(address),
                            _ => None,
                        };
                        structured_entry(
                            section,
                            "Export",
                            object_name(export.name()),
                            address.map(|value| AnalysisLocation {
                                kind: AnalysisAddressKind::ObjectAddress,
                                value,
                                file_range: None,
                            }),
                            AnalysisData::Export {
                                name,
                                ordinal,
                                address,
                            },
                        );
                    }
                    Err(error) => {
                        section.state = AnalysisSectionState::Partial;
                        super::super::limits::add(
                            section,
                            AnalysisLimitKind::Input,
                            format!("Part of the export table cannot be read: {error}."),
                            None,
                        );
                        entry(section, "Export parse error", error.to_string(), None);
                    }
                }
            }
        }
        Err(error) => {
            section.state = AnalysisSectionState::Partial;
            super::super::limits::add(
                section,
                AnalysisLimitKind::Input,
                format!("The export table cannot be read: {error}."),
                None,
            );
            entry(section, "Exports parse error", error.to_string(), None);
        }
    }
}

/// Hardening flags the object file declares, by format.
fn hardening_rows(section: &mut AnalysisSection, file: &object::File<'_>) {
    entry(
        section,
        "Object kind",
        format!(
            "{:?}; a dynamic kind alone is not proof of PIE",
            file.kind()
        ),
        None,
    );
    let canary = file
        .symbols()
        .chain(file.dynamic_symbols())
        .any(|s| s.name().is_ok_and(|n| n.contains("stack_chk")));
    entry(
        section,
        "Stack protector symbol",
        if canary {
            "observed"
        } else {
            "not observed; absence does not prove no protection"
        },
        None,
    );
    match file.format() {
        object::BinaryFormat::Elf => {
            section.summary =
                "ELF hardening metadata from readelf; symbol presence is only an indicator".into();
            match tool(
                "/usr/bin/readelf",
                &[
                    "--wide",
                    "--program-headers",
                    "--dynamic",
                    "/input/specimen",
                ],
            ) {
                Ok((version, output, end)) => {
                    section.tools.push(version);
                    for line in output.lines().filter(|l| {
                        l.contains("GNU_STACK")
                            || l.contains("GNU_RELRO")
                            || l.contains("BIND_NOW")
                            || l.contains("FLAGS")
                    }) {
                        entry(section, "ELF hardening metadata", line, None);
                    }
                    cut_tool_short(section, "readelf", end);
                }
                Err(error) => unavailable(section, error),
            }
        }
        object::BinaryFormat::Pe => {
            use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
            let flags = match file {
                object::File::Pe32(pe) => {
                    Some(pe.nt_headers().optional_header().dll_characteristics())
                }
                object::File::Pe64(pe) => {
                    Some(pe.nt_headers().optional_header().dll_characteristics())
                }
                _ => None,
            };
            if let Some(flags) = flags {
                for (label, mask) in [
                    (
                        "ASLR dynamic base",
                        object::pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
                    ),
                    (
                        "NX compatible",
                        object::pe::IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
                    ),
                    (
                        "Control flow guard",
                        object::pe::IMAGE_DLLCHARACTERISTICS_GUARD_CF,
                    ),
                    (
                        "High entropy VA",
                        object::pe::IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
                    ),
                ] {
                    entry(
                        section,
                        label,
                        if flags.contains(mask) {
                            "declared"
                        } else {
                            "not declared"
                        },
                        None,
                    );
                }
                section.summary =
                    "PE declared optional-header flags; runtime enforcement not observed".into();
            } else {
                unavailable(
                    section,
                    "This PE file has no optional header, so there are no hardening flags to read",
                );
            }
        }
        object::BinaryFormat::MachO => {
            if let object::FileFlags::MachO { flags } = file.flags() {
                entry(
                    section,
                    "PIE",
                    if flags.contains(object::macho::MH_PIE) {
                        "declared"
                    } else {
                        "not declared"
                    },
                    None,
                );
                entry(
                    section,
                    "Executable stack",
                    if flags.contains(object::macho::MH_ALLOW_STACK_EXECUTION) {
                        "allowed by header"
                    } else {
                        "not requested by header"
                    },
                    None,
                );
                section.summary =
                    "Mach-O declared header flags; runtime enforcement not observed".into();
            } else {
                unavailable(section, "This Mach-O file has no header flags to read");
            }
        }
        _ => unavailable(
            section,
            "Hardening flags are only read from ELF, PE and Mach-O files",
        ),
    }
}

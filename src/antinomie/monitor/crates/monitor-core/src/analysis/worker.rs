// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use object::{Object, ObjectSection, ObjectSymbol};
use sha2::{Digest, Sha256};
use std::{cell::Cell, fs, io::Write, path::Path};

pub(crate) const REPORT_MAX_SIZE: usize = 128 * 1024;
const ENTRY_MAX_COUNT: usize = 2048;
const VALUE_MAX_SIZE: usize = 4096;
const TOOL_OUTPUT_MAX_SIZE: usize = 1024 * 1024;
thread_local! {
    /// Set when `entry` dropped a row at the report's row bound; the section's
    /// full listing is then marked truncated. Cleared when a section starts.
    static ROWS_DROPPED: Cell<bool> = const { Cell::new(false) };
}
/// Wall-clock budget of a decompiler run (analysis plus export).
pub(super) const DECOMPILER_SECONDS: u64 = 840;

/// Dispatch the monitor's private, sandbox-only analysis entry point before CLI parsing.
/// Returns None for ordinary invocations, or the worker process exit code.
pub fn worker_main_if_requested() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args
        .get(1)
        .is_none_or(|a| a != "--antinomie-analysis-worker")
    {
        return None;
    }
    let result = worker_main();
    if let Err(error) = &result {
        eprintln!("analysis worker: {error}");
    }
    Some(if result.is_ok() { 0 } else { 1 })
}

fn worker_main() -> Result<(), String> {
    use rustix::process::{Resource, Rlimit, setrlimit};
    if std::env::var_os("ANTINOMIE_ISOLATED_WORKER").as_deref() != Some(std::ffi::OsStr::new("1"))
        || !Path::new("/input/specimen").is_file()
    {
        return Err("private worker requires the analysis sandbox".into());
    }
    let request = fs::read("/input/request.json").map_err(|e| e.to_string())?;
    if request.len() > REPORT_MAX_SIZE {
        return Err("oversized worker request".into());
    }
    let mut report: AnalysisReport = serde_json::from_slice(&request).map_err(|e| e.to_string())?;
    let has = |kind| {
        report
            .sections
            .iter()
            .any(|s: &AnalysisSection| s.kind == kind)
    };
    // A decompiler runs a JVM with many threads, a large address space
    // reservation, hundreds of open jars and a project database in /tmp.
    let (cpu, address_space, file_size, files) = if has(AnalysisKind::Decompilation) {
        (6 * DECOMPILER_SECONDS, None, Some(512 * 1024 * 1024), 8192)
    } else if has(AnalysisKind::Capabilities) {
        (
            600,
            Some(8 * 1024 * 1024 * 1024),
            Some(super::listing::LISTING_MAX_SIZE),
            1024,
        )
    } else {
        (
            300,
            Some(4 * 1024 * 1024 * 1024),
            Some(super::listing::LISTING_MAX_SIZE),
            256,
        )
    };
    for (resource, size) in [
        (Resource::Cpu, Some(cpu)),
        (Resource::As, address_space),
        (Resource::Fsize, file_size),
        (Resource::Nofile, Some(files)),
        (Resource::Core, Some(0)),
    ] {
        setrlimit(
            resource,
            Rlimit {
                current: size,
                maximum: size,
            },
        )
        .map_err(|e| e.to_string())?;
    }
    let specimen = fs::read("/input/specimen").map_err(|e| e.to_string())?;
    if specimen.len() > crate::control::SPECIMEN_MAX_SIZE as usize {
        return Err("oversized specimen".into());
    }
    report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
    report.specimen_len = Some(specimen.len() as u64);
    for index in super::progress::execution_order(&report) {
        let _stage = super::progress::Stage::begin(Path::new("/output/progress"), &report, index);
        super::progress::publish(Path::new("/output"), &report, Some(index));
        analyze_section(
            &mut report.sections[index],
            &specimen,
            Path::new("/output/listings"),
        );
    }
    super::progress::publish(Path::new("/output"), &report, None);
    report.state = if report
        .sections
        .iter()
        .all(|s| s.state == AnalysisSectionState::Complete)
    {
        AnalysisState::Complete
    } else {
        AnalysisState::Partial
    };
    let encoded = bounded_report(&mut report)?;
    super::validation::validate_report(&report)?;
    fs::File::create("/output/report.json")
        .and_then(|mut f| f.write_all(&encoded).and_then(|_| f.sync_all()))
        .map_err(|e| e.to_string())
}
pub(super) fn bounded_report(report: &mut AnalysisReport) -> Result<Vec<u8>, String> {
    let mut encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    // Rows of a category with a full listing are only a preview: shorten
    // those first, without calling anything partial.
    while encoded.len() > REPORT_MAX_SIZE {
        let Some(section) = report
            .sections
            .iter_mut()
            .filter(|s| s.listing.is_some() && s.entries.len() > 16)
            .max_by_key(|s| s.entries.len())
        else {
            break;
        };
        section.entries.truncate(section.entries.len() / 2);
        encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    }
    if encoded.len() > REPORT_MAX_SIZE {
        report.state = AnalysisState::Partial;
        report.reason = Some("normalized report truncated to 128 KiB live-snapshot limit".into());
        while encoded.len() > REPORT_MAX_SIZE {
            let section = report
                .sections
                .iter_mut()
                .filter(|s| !s.entries.is_empty())
                .max_by_key(|s| s.entries.len())
                .ok_or("report metadata alone exceeds normalized bound")?;
            section.entries.truncate(section.entries.len() / 2);
            section.state = AnalysisSectionState::Partial;
            encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
        }
    }
    Ok(encoded)
}

fn entry(
    section: &mut AnalysisSection,
    label: impl Into<String>,
    value: impl Into<String>,
    offset: Option<u64>,
) {
    if section.entries.len() >= ENTRY_MAX_COUNT {
        section.state = AnalysisSectionState::Partial;
        ROWS_DROPPED.set(true);
        return;
    }
    let mut value = value.into();
    let mut label = label.into();
    for text in [&mut label, &mut value] {
        if text.len() > VALUE_MAX_SIZE {
            let mut end = VALUE_MAX_SIZE;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
            section.state = AnalysisSectionState::Partial;
        }
    }
    section.entries.push(AnalysisEntry {
        label,
        value,
        offset,
        record: None,
    });
    let id = section.entries.len() as u64;
    if let Some(row) = section.entries.last_mut()
        && (section.kind != AnalysisKind::Disassembly || row.label != "Disassembly")
    {
        let data = if section.kind == AnalysisKind::Hardening {
            AnalysisData::Property {
                scope: "Static file metadata".into(),
                observed: row.value.clone(),
                evidence: row.label.clone(),
            }
        } else {
            AnalysisData::Field {
                group: section.kind.label().into(),
            }
        };
        row.record = Some(AnalysisRecord {
            revision: 1,
            id,
            location: None,
            data,
        });
    }
}
pub(super) fn structured_entry(
    section: &mut AnalysisSection,
    label: impl Into<String>,
    value: impl Into<String>,
    location: Option<AnalysisLocation>,
    mut data: AnalysisData,
) {
    let before = section.entries.len();
    entry(
        section,
        label,
        value,
        location
            .as_ref()
            .and_then(|l| l.file_range.map(|r| r.offset)),
    );
    if section.entries.len() == before {
        return;
    }
    if bound_data(&mut data) {
        section.state = AnalysisSectionState::Partial;
    }
    if let Some(row) = section.entries.last_mut() {
        if let AnalysisData::String { retained_len, .. } = &mut data {
            *retained_len = row.value.len() as u64;
        }
        row.record = Some(AnalysisRecord {
            revision: 1,
            id: before as u64 + 1,
            location,
            data,
        });
    }
}
pub(super) fn clip(text: &mut String) -> bool {
    if text.len() <= VALUE_MAX_SIZE {
        return false;
    }
    let mut end = VALUE_MAX_SIZE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}
pub(super) fn bound_data(data: &mut AnalysisData) -> bool {
    let mut truncated = false;
    let mut bound = |text: &mut String| {
        truncated |= clip(text);
    };
    match data {
        AnalysisData::Field { group } => bound(group),
        AnalysisData::Section {
            name,
            raw_flags,
            flags,
            ..
        } => {
            bound(name);
            bound(raw_flags);
            for flag in flags.iter_mut() {
                bound(flag);
            }
            if flags.len() > 64 {
                flags.truncate(64);
                truncated = true;
            }
        }
        AnalysisData::Symbol {
            name, kind, scope, ..
        } => {
            bound(name);
            bound(kind);
            bound(scope);
        }
        AnalysisData::Import { name, library, .. } => {
            if let Some(name) = name {
                bound(name);
            }
            if let Some(library) = library {
                bound(library);
            }
        }
        AnalysisData::Export { name, .. } => {
            if let Some(name) = name {
                bound(name);
            }
        }
        AnalysisData::String { encoding, .. } => bound(encoding),
        AnalysisData::Entropy { .. } => {}
        AnalysisData::Signature { description, .. } => bound(description),
        AnalysisData::Property {
            scope,
            observed,
            evidence,
        } => {
            bound(scope);
            bound(observed);
            bound(evidence);
        }
        AnalysisData::Instruction {
            bytes,
            mnemonic,
            operands,
            function,
            ..
        } => {
            bound(bytes);
            bound(mnemonic);
            bound(operands);
            if let Some(function) = function {
                bound(function);
            }
        }
        AnalysisData::Function { name, .. } => bound(name),
        AnalysisData::SourceLine { function, .. } => bound(function),
        AnalysisData::RuleMatch {
            rule,
            namespace,
            tags,
            ruleset,
        } => {
            bound(rule);
            bound(namespace);
            bound(ruleset);
            truncated |= bound_list(tags);
        }
        AnalysisData::Capability {
            name,
            namespace,
            attack,
            mbc,
        } => {
            bound(name);
            bound(namespace);
            truncated |= bound_list(attack);
            truncated |= bound_list(mbc);
        }
        AnalysisData::Identification {
            category,
            name,
            version,
        } => {
            bound(category);
            bound(name);
            if let Some(version) = version {
                bound(version);
            }
        }
    }
    truncated
}
/// Keep at most 64 list items of bounded text.
fn bound_list(items: &mut Vec<String>) -> bool {
    let mut truncated = items.len() > 64;
    items.truncate(64);
    for item in items.iter_mut() {
        truncated |= clip(item);
    }
    truncated
}
fn unavailable(section: &mut AnalysisSection, reason: impl Into<String>) {
    section.state = AnalysisSectionState::Unavailable;
    section.summary = reason.into();
}
/// The built-in triage engine, named once per category instead of as a row.
const TRIAGE_ENGINE: &str = "Antinomie byte triage 2 (object 0.40)";

fn analyze_section(section: &mut AnalysisSection, specimen: &[u8], listings: &Path) {
    ROWS_DROPPED.set(false);
    section.state = AnalysisSectionState::Complete;
    section.summary = "completed bounded static byte analysis".into();
    if matches!(
        section.kind,
        AnalysisKind::Metadata
            | AnalysisKind::Structures
            | AnalysisKind::Strings
            | AnalysisKind::Entropy
            | AnalysisKind::Hardening
    ) {
        section.tools.push(TRIAGE_ENGINE.into());
    }
    match section.kind {
        AnalysisKind::Metadata => {
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
                    "unknown or malformed format; generic byte triage available",
                    None,
                ),
            }
        }
        AnalysisKind::Entropy => {
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
        AnalysisKind::Strings => strings(section, specimen, listings),
        AnalysisKind::Structures | AnalysisKind::Hardening => match object::File::parse(specimen) {
            Ok(file) => {
                if section.kind == AnalysisKind::Structures {
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
                    for s in file.sections() {
                        let file_range = checked_range(s.file_range(), specimen.len() as u64);
                        if s.file_range().is_some() && file_range.is_none() {
                            section.state = AnalysisSectionState::Partial;
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
                    for segment in super::segments::segments(&file) {
                        let file_range = checked_range(segment.file_range, specimen.len() as u64);
                        if segment.file_range.is_some() && file_range.is_none() {
                            section.state = AnalysisSectionState::Partial;
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
                                        symbol_range(
                                            &section,
                                            address,
                                            symbol.size(),
                                            specimen.len() as u64,
                                        )
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
                    match file.imports() {
                        Ok(imports) => {
                            for import in imports {
                                match import {
                                    Ok(import) => {
                                        let (name, ordinal) = name_parts(import.name());
                                        let library = (!import.library().is_empty()).then(|| {
                                            String::from_utf8_lossy(import.library()).into_owned()
                                        });
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
                                        entry(
                                            section,
                                            "Import parse error",
                                            error.to_string(),
                                            None,
                                        );
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            section.state = AnalysisSectionState::Partial;
                            entry(section, "Imports parse error", error.to_string(), None);
                        }
                    }
                    match file.exports() {
                        Ok(exports) => {
                            for export in exports {
                                match export {
                                    Ok(export) => {
                                        let (name, ordinal) = name_parts(export.name());
                                        let address = match export.target() {
                                            object::ExportTarget::Address { address, .. } => {
                                                Some(address)
                                            }
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
                                        entry(
                                            section,
                                            "Export parse error",
                                            error.to_string(),
                                            None,
                                        );
                                    }
                                }
                            }
                        }
                        Err(error) => {
                            section.state = AnalysisSectionState::Partial;
                            entry(section, "Exports parse error", error.to_string(), None);
                        }
                    }
                } else {
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
                            section.summary="ELF hardening metadata from readelf; symbol presence is only an indicator".into();
                            match tool(
                                "/usr/bin/readelf",
                                &[
                                    "--wide",
                                    "--program-headers",
                                    "--dynamic",
                                    "/input/specimen",
                                ],
                            ) {
                                Ok((version, output, truncated)) => {
                                    section.tools.push(version);
                                    for line in output.lines().filter(|l| {
                                        l.contains("GNU_STACK")
                                            || l.contains("GNU_RELRO")
                                            || l.contains("BIND_NOW")
                                            || l.contains("FLAGS")
                                    }) {
                                        entry(section, "ELF hardening metadata", line, None);
                                    }
                                    if truncated {
                                        section.state = AnalysisSectionState::Partial;
                                    }
                                }
                                Err(error) => unavailable(section, error),
                            }
                        }
                        object::BinaryFormat::Pe => {
                            use object::read::pe::{ImageNtHeaders, ImageOptionalHeader};
                            let flags = match &file {
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
                                section.summary="PE declared optional-header flags; runtime enforcement not observed".into();
                            } else {
                                unavailable(section, "PE optional-header flags unavailable");
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
                                section.summary="Mach-O declared header flags; runtime enforcement not observed".into();
                            } else {
                                unavailable(section, "Mach-O header flags unavailable");
                            }
                        }
                        _ => unavailable(
                            section,
                            "hardening adapter unsupported for this object format",
                        ),
                    }
                }
            }
            Err(error) => unavailable(
                section,
                format!("structures unsupported for unknown or malformed format: {error}"),
            ),
        },
        AnalysisKind::Disassembly => super::disasm::disassemble(section, specimen, listings),
        AnalysisKind::Identification => super::ident::identify(section, specimen),
        AnalysisKind::Rules => super::rules::scan(section, specimen),
        AnalysisKind::Capabilities => super::capa::capabilities(section),
        AnalysisKind::Embedded => super::binwalk::embedded(section, specimen.len() as u64),
        AnalysisKind::Decompilation => super::decompile::decompile(section, specimen, listings),
    }
    // Headers, sections, segments, symbols, imports and exports of an
    // ordinary binary outgrow the report; the report keeps a preview.
    if section.kind == AnalysisKind::Structures {
        keep_listing(section, listings);
    }
    if section.state == AnalysisSectionState::Partial {
        section.summary.push_str("; partial/bounded evidence");
    }
}

/// Write a category's structured rows to its full listing beside the report.
fn keep_listing(section: &mut AnalysisSection, listings: &Path) {
    let Ok(mut writer) = super::listing::ListingWriter::create(
        listings,
        section.kind,
        super::listing::LISTING_MAX_SIZE,
    ) else {
        return;
    };
    let mut full = false;
    for entry in &section.entries {
        let Some(record) = &entry.record else {
            continue;
        };
        if !writer.push(
            entry.label.clone(),
            entry.value.clone(),
            record.location.clone(),
            record.data.clone(),
        ) {
            full = true;
            break;
        }
    }
    if let Ok(listing) = writer.finish(full || ROWS_DROPPED.get()) {
        if listing.truncated {
            section.state = AnalysisSectionState::Partial;
        }
        section.listing = Some(listing);
    }
}

pub(super) fn tool(path: &str, arguments: &[&str]) -> Result<(String, String, bool), String> {
    if !Path::new(path).is_file() {
        return Err(format!("local tool unavailable: {path}"));
    }
    let run = super::tools::run(
        path,
        arguments,
        &[],
        std::time::Duration::from_secs(120),
        TOOL_OUTPUT_MAX_SIZE,
    )?;
    if !run.success && !run.truncated {
        return Err(format!(
            "local tool failed: {path}{}",
            if run.timed_out { " (timed out)" } else { "" }
        ));
    }
    Ok((
        super::tools::version(path, &["--version"]),
        run.stdout,
        run.truncated || run.timed_out,
    ))
}
fn object_name(name: object::NameOrOrdinal<&[u8]>) -> String {
    match name {
        object::NameOrOrdinal::Name(value) => String::from_utf8_lossy(value).into_owned(),
        object::NameOrOrdinal::Ordinal(value) => format!("ordinal {value}"),
    }
}
fn name_parts(name: object::NameOrOrdinal<&[u8]>) -> (Option<String>, Option<u64>) {
    match name {
        object::NameOrOrdinal::Name(name) => {
            (Some(String::from_utf8_lossy(name).into_owned()), None)
        }
        object::NameOrOrdinal::Ordinal(ordinal) => (None, Some(u64::from(ordinal))),
    }
}
fn checked_range(range: Option<(u64, u64)>, total_len: u64) -> Option<AnalysisRange> {
    range.and_then(|(offset, len)| {
        offset
            .checked_add(len)
            .filter(|&end| end <= total_len)
            .map(|_| AnalysisRange { offset, len })
    })
}
fn symbol_range<'data, S: ObjectSection<'data>>(
    section: &S,
    address: u64,
    size: u64,
    total_len: u64,
) -> Option<AnalysisRange> {
    if section.compressed_file_range().ok()?.format != object::CompressionFormat::None {
        return None;
    }
    let (section_offset, section_len) = section.file_range()?;
    let relative = address.checked_sub(section.address())?;
    if relative.checked_add(size)? > section_len {
        return None;
    }
    checked_range(
        Some((section_offset.checked_add(relative)?, size)),
        total_len,
    )
}
/// Strings kept in the report itself; the listing holds all of them.
const REPORT_STRINGS: usize = 256;

/// Printable ASCII (four or more octets) and UTF-16LE strings, in file order.
pub(crate) fn find_strings(specimen: &[u8]) -> Vec<(usize, usize, &'static str, String)> {
    let mut found = Vec::new();
    let mut start = 0;
    for index in 0..=specimen.len() {
        if index < specimen.len() && (specimen[index].is_ascii_graphic() || specimen[index] == b' ')
        {
            continue;
        }
        if index - start >= 4 {
            let retained = &specimen[start..index.min(start + VALUE_MAX_SIZE)];
            found.push((
                start,
                index - start,
                "ASCII",
                String::from_utf8_lossy(retained).into_owned(),
            ));
        }
        start = index + 1;
    }
    // UTF-16LE: printable ASCII code units, each followed by a zero octet.
    let mut index = 0;
    while index + 1 < specimen.len() {
        let begin = index;
        let mut text = String::new();
        while index + 1 < specimen.len()
            && specimen[index + 1] == 0
            && (specimen[index].is_ascii_graphic() || specimen[index] == b' ')
        {
            if text.len() < VALUE_MAX_SIZE {
                text.push(specimen[index] as char);
            }
            index += 2;
        }
        if index - begin >= 8 {
            found.push((begin, index - begin, "UTF-16LE", text));
        } else {
            index = begin + 1;
        }
    }
    found.sort_by_key(|(offset, ..)| *offset);
    found
}

fn strings(section: &mut AnalysisSection, specimen: &[u8], listings: &Path) {
    let found = find_strings(specimen);
    let mut writer = super::listing::ListingWriter::create(
        listings,
        AnalysisKind::Strings,
        super::listing::LISTING_MAX_SIZE,
    )
    .ok();
    let mut full = false;
    for (index, (offset, len, encoding, text)) in found.iter().enumerate() {
        let range = AnalysisRange {
            offset: *offset as u64,
            len: *len as u64,
        };
        let location = || {
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: range.offset,
                file_range: Some(range),
            })
        };
        let data = || AnalysisData::String {
            encoding: (*encoding).into(),
            byte_len: range.len,
            retained_len: text.len() as u64,
        };
        if index < REPORT_STRINGS {
            structured_entry(section, *encoding, text.clone(), location(), data());
        }
        if let Some(writer) = writer.as_mut()
            && !full
            && !writer.push(*encoding, text.clone(), location(), data())
        {
            full = true;
        }
    }
    // A string longer than the row bound keeps only its start.
    section.state = if found.iter().any(|(_, len, encoding, text)| {
        let units = if *encoding == "ASCII" { *len } else { len / 2 };
        text.len() < units
    }) {
        AnalysisSectionState::Partial
    } else {
        AnalysisSectionState::Complete
    };
    if let Some(listing) = writer.and_then(|w| w.finish(full).ok()) {
        if listing.truncated {
            section.state = AnalysisSectionState::Partial;
        }
        section.listing = Some(listing);
    } else if found.len() > REPORT_STRINGS {
        section.state = AnalysisSectionState::Partial;
    }
    section.summary = format!(
        "{} strings (printable ASCII of four or more bytes, UTF-16LE of four or more characters); offsets are file offsets",
        found.len()
    );
}

fn entropy_entry(section: &mut AnalysisSection, label: &str, specimen: &[u8], offset: u64) {
    let mut counts = [0u64; 256];
    for &byte in specimen {
        counts[byte as usize] += 1;
    }
    let entropy: f64 = counts
        .iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = n as f64 / specimen.len() as f64;
            -p * p.log2()
        })
        .sum();
    let range = AnalysisRange {
        offset,
        len: specimen.len() as u64,
    };
    structured_entry(
        section,
        label,
        format!("{entropy:.6}"),
        Some(AnalysisLocation {
            kind: AnalysisAddressKind::FileOffset,
            value: offset,
            file_range: Some(range),
        }),
        AnalysisData::Entropy {
            range,
            milli_bits: (entropy * 1000.0).round().clamp(0.0, 8000.0) as u32,
        },
    );
}
fn section_flags(flags: object::SectionFlags) -> (String, Vec<String>) {
    let (raw, masks): (u64, Vec<(u64, &str)>) = match flags {
        object::SectionFlags::Elf { sh_flags, .. } => (
            sh_flags.0,
            vec![
                (object::elf::SHF_WRITE.0, "WRITE"),
                (object::elf::SHF_ALLOC.0, "ALLOC"),
                (object::elf::SHF_EXECINSTR.0, "EXECINSTR"),
                (object::elf::SHF_MERGE.0, "MERGE"),
                (object::elf::SHF_STRINGS.0, "STRINGS"),
                (object::elf::SHF_INFO_LINK.0, "INFO_LINK"),
                (object::elf::SHF_LINK_ORDER.0, "LINK_ORDER"),
                (object::elf::SHF_GROUP.0, "GROUP"),
                (object::elf::SHF_TLS.0, "TLS"),
                (object::elf::SHF_COMPRESSED.0, "COMPRESSED"),
                (object::elf::SHF_EXCLUDE.0, "EXCLUDE"),
            ],
        ),
        object::SectionFlags::Coff { characteristics } => (
            u64::from(characteristics.0),
            vec![
                (u64::from(object::pe::IMAGE_SCN_CNT_CODE.0), "CODE"),
                (
                    u64::from(object::pe::IMAGE_SCN_CNT_INITIALIZED_DATA.0),
                    "INITIALIZED_DATA",
                ),
                (
                    u64::from(object::pe::IMAGE_SCN_CNT_UNINITIALIZED_DATA.0),
                    "UNINITIALIZED_DATA",
                ),
                (u64::from(object::pe::IMAGE_SCN_MEM_EXECUTE.0), "EXECUTE"),
                (u64::from(object::pe::IMAGE_SCN_MEM_READ.0), "READ"),
                (u64::from(object::pe::IMAGE_SCN_MEM_WRITE.0), "WRITE"),
                (
                    u64::from(object::pe::IMAGE_SCN_MEM_DISCARDABLE.0),
                    "DISCARDABLE",
                ),
                (u64::from(object::pe::IMAGE_SCN_MEM_SHARED.0), "SHARED"),
                (
                    u64::from(object::pe::IMAGE_SCN_MEM_NOT_CACHED.0),
                    "NOT_CACHED",
                ),
                (
                    u64::from(object::pe::IMAGE_SCN_MEM_NOT_PAGED.0),
                    "NOT_PAGED",
                ),
            ],
        ),
        object::SectionFlags::MachO { flags, .. } => (
            u64::from(flags.0),
            vec![
                (
                    u64::from(object::macho::S_ATTR_PURE_INSTRUCTIONS.0),
                    "PURE_INSTRUCTIONS",
                ),
                (
                    u64::from(object::macho::S_ATTR_SOME_INSTRUCTIONS.0),
                    "SOME_INSTRUCTIONS",
                ),
                (u64::from(object::macho::S_ATTR_DEBUG.0), "DEBUG"),
            ],
        ),
        _ => return (format!("{flags:?}"), Vec::new()),
    };
    let decoded = masks
        .into_iter()
        .filter(|(mask, _)| raw & mask == *mask)
        .map(|(_, name)| name.into())
        .collect();
    (format!("0x{raw:x}"), decoded)
}
#[cfg(test)]
mod tests {
    use super::*;
    /// A fresh directory for the listings a test analysis writes.
    fn listings() -> std::path::PathBuf {
        let directory =
            std::env::temp_dir().join(format!("ant-listings-{}", crate::storage::unique_id()));
        fs::create_dir_all(&directory).unwrap();
        directory
    }
    #[test]
    fn compressed_elf_section_keeps_storage_range_without_fake_symbol_byte_mapping() {
        let names = b"\0.debug_info\0.shstrtab\0";
        let mut specimen = vec![0u8; 288 + names.len()];
        specimen[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        specimen[16..18].copy_from_slice(&1u16.to_le_bytes());
        specimen[18..20].copy_from_slice(&62u16.to_le_bytes());
        specimen[20..24].copy_from_slice(&1u32.to_le_bytes());
        specimen[40..48].copy_from_slice(&64u64.to_le_bytes());
        specimen[52..54].copy_from_slice(&64u16.to_le_bytes());
        specimen[58..60].copy_from_slice(&64u16.to_le_bytes());
        specimen[60..62].copy_from_slice(&3u16.to_le_bytes());
        specimen[62..64].copy_from_slice(&2u16.to_le_bytes());
        let section = &mut specimen[128..192];
        section[0..4].copy_from_slice(&1u32.to_le_bytes());
        section[4..8].copy_from_slice(&1u32.to_le_bytes());
        section[8..16].copy_from_slice(&object::elf::SHF_COMPRESSED.0.to_le_bytes());
        section[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        section[24..32].copy_from_slice(&256u64.to_le_bytes());
        section[32..40].copy_from_slice(&32u64.to_le_bytes());
        section[48..56].copy_from_slice(&1u64.to_le_bytes());
        let section = &mut specimen[192..256];
        section[0..4].copy_from_slice(&13u32.to_le_bytes());
        section[4..8].copy_from_slice(&3u32.to_le_bytes());
        section[24..32].copy_from_slice(&288u64.to_le_bytes());
        section[32..40].copy_from_slice(&(names.len() as u64).to_le_bytes());
        section[48..56].copy_from_slice(&1u64.to_le_bytes());
        specimen[256..260].copy_from_slice(&1u32.to_le_bytes());
        specimen[264..272].copy_from_slice(&64u64.to_le_bytes());
        specimen[272..280].copy_from_slice(&8u64.to_le_bytes());
        specimen[288..].copy_from_slice(names);
        let file = object::File::parse(specimen.as_slice()).unwrap();
        let section = file.section_by_name(".debug_info").unwrap();
        assert_eq!(section.file_range(), Some((256, 32)));
        assert_eq!(
            section.compressed_file_range().unwrap().format,
            object::CompressionFormat::Zlib
        );
        assert!(symbol_range(&section, 0x1001, 2, specimen.len() as u64).is_none());
        let mut structures = super::tests::section(AnalysisKind::Structures);
        analyze_section(&mut structures, &specimen, &listings());
        assert!(structures.entries.iter().any(|row|matches!(&row.record.as_ref().unwrap().data,AnalysisData::Section {flags,..} if flags.iter().any(|flag|flag=="COMPRESSED"))));
    }
    #[test]
    fn actual_elf_rows_have_decoded_sections_symbols_strings_and_measured_regions() {
        let specimen = fs::read("/usr/bin/true").unwrap();
        let mut structures = section(AnalysisKind::Structures);
        analyze_section(&mut structures, &specimen, &listings());
        assert!(structures.entries.iter().any(|entry|matches!(&entry.record.as_ref().unwrap().data,AnalysisData::Section {name,flags,..} if name==".text"&&flags.iter().any(|flag|flag=="EXECINSTR"))));
        assert!(structures.entries.iter().any(|entry|matches!(&entry.record.as_ref().unwrap().data,AnalysisData::Section {name,file_size,..} if name==".bss"&&file_size.is_none())&&entry.record.as_ref().unwrap().location.as_ref().unwrap().file_range.is_none()));
        assert!(structures.entries.iter().any(|entry| matches!(
            &entry.record.as_ref().unwrap().data,
            AnalysisData::Import { .. }
        )));
        for kind in [
            AnalysisKind::Metadata,
            AnalysisKind::Structures,
            AnalysisKind::Strings,
            AnalysisKind::Entropy,
        ] {
            let mut result = section(kind);
            analyze_section(&mut result, &specimen, &listings());
            let mut report = crate::analysis::jobs::new_report(
                "/usr/bin/true",
                &AnalysisSelection {
                    enabled: true,
                    checks: vec![kind],
                },
            );
            report.specimen_len = Some(specimen.len() as u64);
            report.sections = vec![result];
            bounded_report(&mut report).unwrap();
            crate::analysis::validation::validate_report(&report).unwrap();
            if kind == AnalysisKind::Entropy {
                let entropy: Vec<_> = report.sections[0]
                    .entries
                    .iter()
                    .filter_map(|entry| entry.record.as_ref())
                    .filter(|record| matches!(record.data, AnalysisData::Entropy { .. }))
                    .collect();
                assert!(!entropy.is_empty());
                assert!(entropy.len() <= 65);
            }
        }
    }
    #[test]
    fn string_lengths_entropy_bounds_and_record_ids_survive_report_truncation() {
        let specimen = vec![b'a'; 5000];
        let mut strings = section(AnalysisKind::Strings);
        analyze_section(&mut strings, &specimen, &listings());
        let row = &strings.entries[0];
        assert_eq!(row.value.len(), 4096);
        assert!(matches!(
            row.record.as_ref().unwrap().data,
            AnalysisData::String {
                byte_len: 5000,
                retained_len: 4096,
                ..
            }
        ));
        assert_eq!(strings.state, AnalysisSectionState::Partial);
        let mut entropy = section(AnalysisKind::Entropy);
        let specimen: Vec<_> = (0..=255u8).cycle().take(65536).collect();
        analyze_section(&mut entropy, &specimen, &listings());
        assert!(matches!(
            entropy.entries[1].record.as_ref().unwrap().data,
            AnalysisData::Entropy {
                milli_bits: 8000,
                ..
            }
        ));
        let mut report = crate::analysis::jobs::new_report(
            "/tmp/sample",
            &AnalysisSelection {
                enabled: true,
                checks: vec![AnalysisKind::Metadata],
            },
        );
        for _ in 0..200 {
            entry(&mut report.sections[0], "row", "x".repeat(4096), None);
        }
        let encoded = bounded_report(&mut report).unwrap();
        assert!(encoded.len() <= REPORT_MAX_SIZE);
        assert_eq!(report.state, AnalysisState::Partial);
        for (index, row) in report.sections[0].entries.iter().enumerate() {
            assert_eq!(row.record.as_ref().unwrap().id, index as u64 + 1);
        }
        let mut malformed = report.clone();
        malformed.sections.clear();
        malformed.source_path = "x".repeat(REPORT_MAX_SIZE + 1);
        assert!(bounded_report(&mut malformed).is_err());
    }
    fn section(kind: AnalysisKind) -> AnalysisSection {
        AnalysisSection {
            kind,
            state: AnalysisSectionState::Pending,
            summary: String::new(),
            tools: Vec::new(),
            listing: None,
            entries: Vec::new(),
        }
    }
    #[test]
    fn unknown_format_keeps_generic_evidence_and_never_claims_rule_verdict() {
        let specimen = b"hello unknown specimen\0";
        for kind in [
            AnalysisKind::Metadata,
            AnalysisKind::Strings,
            AnalysisKind::Entropy,
        ] {
            let mut result = section(kind);
            analyze_section(&mut result, specimen, &listings());
            assert_eq!(result.state, AnalysisSectionState::Complete);
            assert!(!result.entries.is_empty());
        }
        // Use an isolated, explicitly selected test rule. Host tests do not
        // have the worker sandbox's /input/rules mount or a default ruleset.
        let directory = std::env::temp_dir().join(format!(
            "ant-analysis-unknown-rules-{}",
            crate::storage::unique_id()
        ));
        fs::create_dir(&directory).unwrap();
        fs::write(
            directory.join("test-only.yar"),
            "rule TestOnlyUnknownBytes { strings: $a = \"test-only-marker\" condition: $a }",
        )
        .unwrap();
        let mut rules = section(AnalysisKind::Rules);
        super::super::rules::scan_at(&mut rules, specimen, &directory);
        assert_eq!(rules.state, AnalysisSectionState::Complete);
        assert!(rules.entries.is_empty());
        super::super::rules::scan_at(&mut rules, b"test-only-marker", &directory);
        assert_eq!(rules.state, AnalysisSectionState::Complete);
        assert_eq!(rules.entries.len(), 1);
        fs::remove_dir_all(&directory).unwrap();
        let mut missing = section(AnalysisKind::Rules);
        super::super::rules::scan_at(&mut missing, specimen, &directory);
        assert_eq!(missing.state, AnalysisSectionState::Unavailable);
        assert_eq!(missing.summary, "No rules enabled");
        assert!(missing.entries.is_empty());
        for kind in [
            AnalysisKind::Structures,
            AnalysisKind::Hardening,
            AnalysisKind::Decompilation,
        ] {
            let mut result = section(kind);
            analyze_section(&mut result, specimen, &listings());
            assert_eq!(result.state, AnalysisSectionState::Unavailable);
        }
        for specimen in [b"\x7fELF".as_slice(), b"MZ", b"\xcf\xfa\xed\xfe", b""] {
            let mut result = section(AnalysisKind::Structures);
            analyze_section(&mut result, specimen, &listings());
            assert_eq!(result.state, AnalysisSectionState::Unavailable);
        }
    }
    #[test]
    fn metadata_shows_the_file_size_as_bytes_with_a_unit() {
        for (len, text) in [(5, "5 bytes"), (4096, "4096 bytes (4.0 KB)")] {
            let mut result = section(AnalysisKind::Metadata);
            analyze_section(&mut result, &vec![0u8; len], &listings());
            let size = result
                .entries
                .iter()
                .find(|entry| entry.label == "File size")
                .unwrap();
            assert_eq!(size.value, text);
            assert!(
                result
                    .entries
                    .iter()
                    .all(|entry| !entry.label.contains("octet"))
            );
        }
    }
    #[test]
    fn entry_bound_preserves_utf8_and_reports_truncation() {
        let mut result = section(AnalysisKind::Strings);
        result.state = AnalysisSectionState::Complete;
        entry(&mut result, "long", "a\u{1f600}".repeat(2000), Some(3));
        assert_eq!(result.state, AnalysisSectionState::Partial);
        assert!(result.entries[0].value.len() <= 4096);
        for _ in 0..3000 {
            entry(&mut result, "row", "text", None);
        }
        assert_eq!(result.entries.len(), 2048);
    }
    fn structures_rows(count: usize) -> AnalysisSection {
        ROWS_DROPPED.set(false);
        let mut result = section(AnalysisKind::Structures);
        result.state = AnalysisSectionState::Complete;
        for index in 0..count {
            structured_entry(
                &mut result,
                format!("row {index}"),
                "value",
                None,
                AnalysisData::Field {
                    group: "Headers".into(),
                },
            );
        }
        result
    }
    #[test]
    fn listing_is_truncated_when_the_row_bound_dropped_rows() {
        let mut result = structures_rows(ENTRY_MAX_COUNT + 5);
        assert_eq!(result.entries.len(), ENTRY_MAX_COUNT);
        keep_listing(&mut result, &listings());
        let listing = result.listing.unwrap();
        assert_eq!(listing.rows, ENTRY_MAX_COUNT as u64);
        assert!(listing.truncated);
        assert_eq!(result.state, AnalysisSectionState::Partial);
    }
    #[test]
    fn listing_is_complete_when_every_row_fits() {
        let mut result = structures_rows(ENTRY_MAX_COUNT);
        keep_listing(&mut result, &listings());
        let listing = result.listing.unwrap();
        assert_eq!(listing.rows, ENTRY_MAX_COUNT as u64);
        assert!(!listing.truncated);
        assert_eq!(result.state, AnalysisSectionState::Complete);
        // A later section on the same thread does not inherit the flag.
        structures_rows(ENTRY_MAX_COUNT + 1);
        let specimen = fs::read("/usr/bin/true").unwrap();
        let mut real = section(AnalysisKind::Structures);
        analyze_section(&mut real, &specimen, &listings());
        assert!(!real.listing.unwrap().truncated);
    }
}

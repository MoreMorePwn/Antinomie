// SPDX-License-Identifier: GPL-3.0-only
use super::bounds::{VALUE_MAX_SIZE, bound_data, clip};
use super::listing::ListingWriter;
use super::*;
use object::{Object, ObjectSection, ObjectSymbol};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs,
    io::Write,
    path::Path,
    time::Duration,
};

pub(crate) const REPORT_MAX_SIZE: usize = 128 * 1024;
/// Rows of a category the report itself keeps; a category with a listing holds
/// all of its rows there and the report only previews the first ones.
pub(super) const ENTRY_MAX_COUNT: usize = 2048;
pub(super) const TOOL_OUTPUT_MAX_SIZE: usize = 1024 * 1024;
thread_local! {
    /// Rows the section was given, kept or not. A row's id is its number here.
    static ROWS_SEEN: Cell<u64> = const { Cell::new(0) };
    /// Rows left out of the report with no listing to hold them.
    static ROWS_DROPPED: Cell<u64> = const { Cell::new(0) };
    /// Rows with a text cut to `VALUE_MAX_SIZE`.
    static VALUES_CUT: Cell<u64> = const { Cell::new(0) };
    /// The listing every row of the section is also written to as it is made.
    static LISTING: RefCell<Option<RowSink>> = const { RefCell::new(None) };
}
/// A section's full listing while its rows are made.
struct RowSink {
    writer: ListingWriter,
    full: bool,
}
/// Wall-clock budget of a decompiler run (analysis plus export).
pub(super) const DECOMPILER_SECONDS: u64 = 840;
/// The decompiler's budget for this run.
pub(super) fn decompiler_seconds() -> u64 {
    super::limits::seconds(DECOMPILER_SECONDS)
}

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
    // Checks a finished analysis already has are not run again.
    let has = |kind| {
        report
            .sections
            .iter()
            .any(|s: &AnalysisSection| s.kind == kind && s.state == AnalysisSectionState::Pending)
    };
    // A decompiler runs a JVM with many threads, a large address space
    // reservation, hundreds of open jars and a project database in /tmp.
    super::limits::set_time_limit(report.time_limit_seconds);
    let (cpu, address_space, file_size, files) = if has(AnalysisKind::Decompilation) {
        (6 * DECOMPILER_SECONDS, None, Some(512 * 1024 * 1024), 8192)
    } else if has(AnalysisKind::Capabilities) || has(AnalysisKind::Floss) {
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
    // A longer time limit than the tools' own needs the CPU budget to follow.
    let cpu = cpu.max(
        report.time_limit_seconds.unwrap_or(0)
            * if has(AnalysisKind::Decompilation) {
                6
            } else {
                2
            },
    );
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
    for index in super::progress::pending_order(&report) {
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
    push_row(section, label.into(), value.into(), offset, None);
}
pub(super) fn structured_entry(
    section: &mut AnalysisSection,
    label: impl Into<String>,
    value: impl Into<String>,
    location: Option<AnalysisLocation>,
    data: AnalysisData,
) {
    let offset = location
        .as_ref()
        .and_then(|l| l.file_range.map(|r| r.offset));
    push_row(
        section,
        label.into(),
        value.into(),
        offset,
        Some((location, data)),
    );
}
/// Make one row. It goes to the section's full listing when there is one, and
/// to the report while the report's preview has room.
fn push_row(
    section: &mut AnalysisSection,
    mut label: String,
    mut value: String,
    offset: Option<u64>,
    typed: Option<(Option<AnalysisLocation>, AnalysisData)>,
) {
    let id = ROWS_SEEN.get() + 1;
    ROWS_SEEN.set(id);
    let mut cut = clip(&mut label);
    cut |= clip(&mut value);
    let (location, mut data) = typed.unwrap_or_else(|| {
        let data = if section.kind == AnalysisKind::Hardening {
            AnalysisData::Property {
                scope: "Static file metadata".into(),
                observed: value.clone(),
                evidence: label.clone(),
            }
        } else {
            AnalysisData::Field {
                group: section.kind.label().into(),
            }
        };
        (None, data)
    });
    cut |= bound_data(&mut data);
    if let AnalysisData::String { retained_len, .. } = &mut data {
        *retained_len = value.len() as u64;
    }
    if cut {
        VALUES_CUT.set(VALUES_CUT.get() + 1);
        section.state = AnalysisSectionState::Partial;
    }
    let listed = LISTING.with(|sink| {
        let mut sink = sink.borrow_mut();
        let Some(sink) = sink.as_mut() else {
            return false;
        };
        if !sink.full {
            sink.full =
                !sink
                    .writer
                    .push(label.clone(), value.clone(), location.clone(), data.clone());
        }
        true
    });
    if section.entries.len() >= ENTRY_MAX_COUNT {
        if !listed {
            section.state = AnalysisSectionState::Partial;
            ROWS_DROPPED.set(ROWS_DROPPED.get() + 1);
        }
        return;
    }
    section.entries.push(AnalysisEntry {
        label,
        value,
        offset,
        record: Some(AnalysisRecord {
            revision: 1,
            id,
            location,
            data,
        }),
    });
}
fn unavailable(section: &mut AnalysisSection, reason: impl Into<String>) {
    section.state = AnalysisSectionState::Unavailable;
    section.summary = reason.into();
}
/// The built-in analysis (byte triage, revision 2) with the version of the
/// object-file parser it reads formats with, named once per category instead
/// of as a row. Reports from before the rename call it "Antinomie byte triage 2".
const TRIAGE_ENGINE: &str = "Built-in analysis (object 0.40)";

/// Forget what the previous section counted.
fn begin_section() {
    ROWS_SEEN.set(0);
    ROWS_DROPPED.set(0);
    VALUES_CUT.set(0);
    LISTING.with(|sink| sink.borrow_mut().take());
}

/// What a category with no summary of its own found.
fn default_summary(kind: AnalysisKind) -> &'static str {
    match kind {
        AnalysisKind::Metadata => "File hashes, size and object header.",
        AnalysisKind::Structures => {
            "Entry point, sections, segments, symbols, imports and exports."
        }
        _ => "",
    }
}

/// The counts the section's rows were made with, said as the bounds they hit.
fn note_row_limits(section: &mut AnalysisSection) {
    use super::limits::add;
    let dropped = ROWS_DROPPED.get();
    if dropped > 0 {
        add(
            section,
            AnalysisLimitKind::Rows,
            format!(
                "The report keeps the first {} rows; {} more were left out.",
                super::detection::group_digits(ENTRY_MAX_COUNT as u64),
                super::detection::group_digits(dropped)
            ),
            None,
        );
    }
    let cut = VALUES_CUT.get();
    if cut > 0 {
        add(
            section,
            AnalysisLimitKind::Text,
            format!(
                "{} {} longer than {} bytes; only the start is kept.",
                super::detection::group_digits(cut),
                if cut == 1 { "value was" } else { "values were" },
                super::detection::group_digits(VALUE_MAX_SIZE as u64)
            ),
            None,
        );
    }
}

fn analyze_section(section: &mut AnalysisSection, specimen: &[u8], listings: &Path) {
    begin_section();
    section.state = AnalysisSectionState::Complete;
    section.summary = default_summary(section.kind).into();
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
    if section.kind == AnalysisKind::Structures {
        begin_listing(section.kind, listings);
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
                    "not an ELF, PE or Mach-O file the parser can read; only the hashes and size apply",
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
        AnalysisKind::Strings => super::strings::strings(section, specimen, listings),
        // The patterns are those of the Rule manager as they are when the
        // matches are read, so none are fixed in the report: this check says
        // the run asked for them, and the Regex matches tab lists them.
        AnalysisKind::Regex => {
            section.summary =
                "regex patterns are matched over the strings when the Regex matches tab opens"
                    .into();
        }
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
                            super::limits::add(
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
                    for segment in super::segments::segments(&file) {
                        let file_range = checked_range(segment.file_range, specimen.len() as u64);
                        if segment.file_range.is_some() && file_range.is_none() {
                            section.state = AnalysisSectionState::Partial;
                            super::limits::add(
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
                                        super::limits::add(
                                            section,
                                            AnalysisLimitKind::Input,
                                            format!(
                                                "Part of the import table cannot be read: {error}."
                                            ),
                                            None,
                                        );
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
                            super::limits::add(
                                section,
                                AnalysisLimitKind::Input,
                                format!("The import table cannot be read: {error}."),
                                None,
                            );
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
                                        super::limits::add(
                                            section,
                                            AnalysisLimitKind::Input,
                                            format!(
                                                "Part of the export table cannot be read: {error}."
                                            ),
                                            None,
                                        );
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
                            super::limits::add(
                                section,
                                AnalysisLimitKind::Input,
                                format!("The export table cannot be read: {error}."),
                                None,
                            );
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
                                section.summary="Mach-O declared header flags; runtime enforcement not observed".into();
                            } else {
                                unavailable(
                                    section,
                                    "This Mach-O file has no header flags to read",
                                );
                            }
                        }
                        _ => unavailable(
                            section,
                            "Hardening flags are only read from ELF, PE and Mach-O files",
                        ),
                    }
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
        },
        AnalysisKind::Disassembly => super::disasm::disassemble(section, specimen, listings),
        AnalysisKind::Identification => super::ident::identify(section, specimen),
        AnalysisKind::Rules => super::rules::scan(section, specimen),
        AnalysisKind::Capabilities => super::capa::capabilities(section),
        AnalysisKind::Embedded => super::binwalk::embedded(section, specimen.len() as u64),
        AnalysisKind::Floss => super::floss::strings(section, specimen.len() as u64, listings),
        AnalysisKind::Unpacking => {
            let artifacts = listings.parent().unwrap_or(listings).join("artifacts");
            super::unpack::unpack(section, specimen, &artifacts)
        }
        AnalysisKind::Decompilation => super::decompile::decompile(section, specimen, listings),
    }
    // Headers, sections, segments, symbols, imports and exports of an
    // ordinary binary outgrow the report; the report keeps a preview and the
    // listing every row.
    if section.kind == AnalysisKind::Structures {
        finish_listing(section);
    }
    note_row_limits(section);
    if section.state == AnalysisSectionState::Partial && section.limits.is_empty() {
        super::limits::add(
            section,
            AnalysisLimitKind::Input,
            "Some of the file could not be read as the format describes it.",
            None,
        );
    }
}

/// Start writing the section's rows to its listing as they are made.
fn begin_listing(kind: AnalysisKind, listings: &Path) {
    let writer = ListingWriter::create(listings, kind, super::listing::LISTING_MAX_SIZE);
    LISTING.with(|sink| {
        *sink.borrow_mut() = writer.ok().map(|writer| RowSink {
            writer,
            full: false,
        });
    });
}

/// Close the listing [`begin_listing`] started and say what the report holds
/// of it.
fn finish_listing(section: &mut AnalysisSection) {
    let Some(sink) = LISTING.with(|sink| sink.borrow_mut().take()) else {
        // No listing could be made: the report's preview is all there is.
        return;
    };
    let Ok(listing) = sink.writer.finish(sink.full) else {
        return;
    };
    let rows = listing.rows;
    if listing.truncated {
        section.state = AnalysisSectionState::Partial;
        super::limits::add(
            section,
            AnalysisLimitKind::Size,
            format!(
                "The listing reached its {} limit after {} rows; the rest of the rows are not listed.",
                crate::byte_size::short_size(super::listing::LISTING_MAX_SIZE),
                super::detection::group_digits(rows)
            ),
            None,
        );
    }
    if section.state != AnalysisSectionState::Unavailable {
        let kept = section.entries.len() as u64;
        let what = "entry point, sections, segments, symbols, imports and exports";
        section.summary = if rows > kept {
            format!(
                "{} rows of {what}. The report shows the first {}; the full list is in the listing.",
                super::detection::group_digits(rows),
                super::detection::group_digits(kept)
            )
        } else {
            format!("{} rows of {what}.", super::detection::group_digits(rows))
        };
    }
    section.listing = Some(listing);
}

/// What ended a local tool before its output was whole.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum ToolEnd {
    Finished,
    /// It printed more than the analysis reads.
    Output,
    /// It was stopped after this many seconds.
    Time(u64),
}

/// Say on `section` that `tool` was cut short, when it was.
pub(super) fn cut_tool_short(section: &mut AnalysisSection, tool: &str, end: ToolEnd) {
    match end {
        ToolEnd::Finished => {}
        ToolEnd::Output => {
            section.state = AnalysisSectionState::Partial;
            super::limits::add(
                section,
                AnalysisLimitKind::Size,
                format!(
                    "{tool} printed more than {} of output; the rest was ignored.",
                    crate::byte_size::short_size(TOOL_OUTPUT_MAX_SIZE as u64)
                ),
                None,
            );
        }
        ToolEnd::Time(seconds) => super::limits::time_out(
            section,
            tool,
            seconds,
            format!("{tool} was stopped before it finished; what it had printed by then is shown."),
        ),
    }
}

pub(super) fn tool(path: &str, arguments: &[&str]) -> Result<(String, String, ToolEnd), String> {
    if !Path::new(path).is_file() {
        return Err(format!("local tool unavailable: {path}"));
    }
    let limit = Duration::from_secs(super::limits::seconds(120));
    let run = super::tools::run_with(path, arguments, &[], limit, TOOL_OUTPUT_MAX_SIZE, true)?;
    if !run.success && !run.truncated && !run.timed_out {
        return Err(run
            .failure_text(path, limit)
            .unwrap_or_else(|| format!("{path} failed")));
    }
    let end = if run.timed_out {
        ToolEnd::Time(limit.as_secs())
    } else if run.truncated {
        ToolEnd::Output
    } else {
        ToolEnd::Finished
    };
    Ok((super::tools::version(path, &["--version"]), run.stdout, end))
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
                    time_limit_minutes: 0,
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
                time_limit_minutes: 0,
            },
        );
        // Row ids count per analysed section, as analyze_section starts them.
        ROWS_SEEN.set(0);
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
            limits: Vec::new(),
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
        assert!(missing.summary.starts_with("No rules are turned on"));
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
        begin_section();
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
    fn structures_rows(count: usize, with_listing: bool) -> AnalysisSection {
        begin_section();
        let mut result = section(AnalysisKind::Structures);
        result.state = AnalysisSectionState::Complete;
        if with_listing {
            begin_listing(AnalysisKind::Structures, &listings());
        }
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
    fn the_listing_holds_every_row_while_the_report_keeps_a_preview() {
        let mut result = structures_rows(ENTRY_MAX_COUNT + 5, true);
        assert_eq!(result.entries.len(), ENTRY_MAX_COUNT);
        finish_listing(&mut result);
        note_row_limits(&mut result);
        let listing = result.listing.unwrap();
        assert_eq!(listing.rows, ENTRY_MAX_COUNT as u64 + 5);
        assert!(!listing.truncated);
        assert_eq!(result.state, AnalysisSectionState::Complete);
        assert!(result.limits.is_empty());
        assert!(
            result.summary.contains("2,053 rows") && result.summary.contains("first 2,048"),
            "{}",
            result.summary
        );
    }
    #[test]
    fn a_large_binary_lists_completely_beside_a_bounded_report() {
        let mut result = structures_rows(40_000, true);
        finish_listing(&mut result);
        assert_eq!(result.listing.as_ref().unwrap().rows, 40_000);
        assert_eq!(result.entries.len(), ENTRY_MAX_COUNT);
        let mut report = AnalysisReport {
            id: "x".into(),
            state: AnalysisState::Complete,
            source_path: "/x".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: vec![result],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
        };
        let encoded = bounded_report(&mut report).unwrap();
        assert!(encoded.len() <= REPORT_MAX_SIZE);
        assert_eq!(report.state, AnalysisState::Complete);
        assert_eq!(report.sections[0].listing.as_ref().unwrap().rows, 40_000);
    }
    #[test]
    fn rows_over_the_preview_without_a_listing_are_counted_and_said() {
        let mut result = structures_rows(ENTRY_MAX_COUNT + 5, false);
        note_row_limits(&mut result);
        assert_eq!(result.entries.len(), ENTRY_MAX_COUNT);
        assert_eq!(result.state, AnalysisSectionState::Partial);
        assert_eq!(result.limits.len(), 1);
        assert_eq!(result.limits[0].kind, AnalysisLimitKind::Rows);
        assert!(result.limits[0].text.contains("first 2,048 rows; 5 more"));
    }
    #[test]
    fn a_row_that_fits_the_preview_leaves_no_note() {
        let mut result = structures_rows(ENTRY_MAX_COUNT, true);
        finish_listing(&mut result);
        note_row_limits(&mut result);
        assert!(!result.listing.unwrap().truncated);
        assert_eq!(result.state, AnalysisSectionState::Complete);
        assert!(result.limits.is_empty());
        let specimen = fs::read("/usr/bin/true").unwrap();
        let mut real = section(AnalysisKind::Structures);
        analyze_section(&mut real, &specimen, &listings());
        assert!(!real.listing.unwrap().truncated);
    }
    /// Measurement on a real large ELF:
    /// `ANTINOMIE_STRUCTURES_FILE=/path cargo test --release -p antinomie-monitor-core
    /// measure_structures_of_a_large_file -- --ignored --nocapture`.
    #[test]
    #[ignore = "measures the file named by ANTINOMIE_STRUCTURES_FILE"]
    fn measure_structures_of_a_large_file() {
        let path = std::env::var("ANTINOMIE_STRUCTURES_FILE").expect("ANTINOMIE_STRUCTURES_FILE");
        let specimen = fs::read(&path).unwrap();
        let mut result = section(AnalysisKind::Structures);
        let started = std::time::Instant::now();
        analyze_section(&mut result, &specimen, &listings());
        let listing = result.listing.as_ref().expect("a listing");
        eprintln!(
            "{path}: {} bytes, {} rows, listing {} bytes (truncated {}), report preview {} rows, \
             {:?}, state {:?}, limits {:?}",
            specimen.len(),
            listing.rows,
            listing.bytes,
            listing.truncated,
            result.entries.len(),
            started.elapsed(),
            result.state,
            result.limits
        );
        assert!(!listing.truncated);
    }
    #[test]
    fn a_cut_value_says_how_many_were_cut() {
        begin_section();
        let mut result = section(AnalysisKind::Strings);
        entry(&mut result, "long", "x".repeat(VALUE_MAX_SIZE + 1), None);
        note_row_limits(&mut result);
        assert_eq!(result.state, AnalysisSectionState::Partial);
        assert_eq!(result.limits[0].kind, AnalysisLimitKind::Text);
        assert!(
            result.limits[0]
                .text
                .starts_with("1 value was longer than 4,096 bytes")
        );
    }
}

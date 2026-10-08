// SPDX-License-Identifier: MIT
use super::*;
use object::{Object, ObjectSection, ObjectSymbol};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Command, Stdio},
};

pub(crate) const REPORT_MAX_SIZE: usize = 128 * 1024;
const ENTRY_MAX_COUNT: usize = 2048;
const VALUE_MAX_SIZE: usize = 4096;
const TOOL_OUTPUT_MAX_SIZE: usize = 1024 * 1024;

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
    for (resource, size) in [
        (Resource::Cpu, 120),
        (Resource::As, 1024 * 1024 * 1024),
        (Resource::Fsize, REPORT_MAX_SIZE as u64),
        (Resource::Nofile, 64),
        (Resource::Core, 0),
    ] {
        setrlimit(
            resource,
            Rlimit {
                current: Some(size),
                maximum: Some(size),
            },
        )
        .map_err(|e| e.to_string())?;
    }
    let request = fs::read("/input/request.json").map_err(|e| e.to_string())?;
    if request.len() > REPORT_MAX_SIZE {
        return Err("oversized worker request".into());
    }
    let mut report: AnalysisReport = serde_json::from_slice(&request).map_err(|e| e.to_string())?;
    let specimen = fs::read("/input/specimen").map_err(|e| e.to_string())?;
    if specimen.len() > crate::control::SPECIMEN_MAX_SIZE as usize {
        return Err("oversized specimen".into());
    }
    report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
    report.specimen_len = Some(specimen.len() as u64);
    for section in &mut report.sections {
        analyze_section(section, &specimen);
    }
    report.state = if report
        .sections
        .iter()
        .all(|s| s.state == AnalysisSectionState::Complete)
    {
        AnalysisState::Complete
    } else {
        AnalysisState::Partial
    };
    let mut encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
    if encoded.len() > REPORT_MAX_SIZE {
        report.state = AnalysisState::Partial;
        report.reason = Some("normalized report truncated to 128 KiB live-snapshot limit".into());
        while encoded.len() > REPORT_MAX_SIZE {
            if let Some(section) = report.sections.iter_mut().max_by_key(|s| s.entries.len()) {
                section.entries.truncate(section.entries.len() / 2);
                section.state = AnalysisSectionState::Partial;
            }
            encoded = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
        }
    }
    fs::File::create("/output/report.json")
        .and_then(|mut f| f.write_all(&encoded).and_then(|_| f.sync_all()))
        .map_err(|e| e.to_string())
}

fn entry(
    section: &mut AnalysisSection,
    label: impl Into<String>,
    value: impl Into<String>,
    offset: Option<u64>,
) {
    if section.entries.len() >= ENTRY_MAX_COUNT {
        section.state = AnalysisSectionState::Partial;
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
    });
}
fn unavailable(section: &mut AnalysisSection, reason: impl Into<String>) {
    section.state = AnalysisSectionState::Unavailable;
    section.summary = reason.into();
}
fn analyze_section(section: &mut AnalysisSection, specimen: &[u8]) {
    section.state = AnalysisSectionState::Complete;
    section.summary = "completed bounded static byte analysis".into();
    entry(
        section,
        "Engine",
        "Antinomie built-in byte triage v1; object 0.40 read parser",
        None,
    );
    match section.kind {
        AnalysisKind::Metadata => {
            entry(
                section,
                "SHA-256",
                format!("{:x}", Sha256::digest(specimen)),
                None,
            );
            entry(section, "Length (octets)", specimen.len().to_string(), None);
            match object::File::parse(specimen) {
                Ok(file) => entry(
                    section,
                    "Object",
                    format!(
                        "{:?}; {:?}; {:?}; {}-bit; {:?}",
                        file.format(),
                        file.architecture(),
                        file.kind(),
                        if file.is_64() { 64 } else { 32 },
                        file.endianness()
                    ),
                    None,
                ),
                Err(_) => entry(
                    section,
                    "Object",
                    "unknown or malformed format; generic byte triage available",
                    None,
                ),
            }
        }
        AnalysisKind::Entropy => {
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
            entry(
                section,
                "Shannon entropy (bits/octet)",
                format!("{entropy:.6}"),
                None,
            );
            section.summary = "whole-file entropy is an indicator, not a packing verdict".into();
        }
        AnalysisKind::Strings => {
            let mut start = 0;
            for index in 0..=specimen.len() {
                if index < specimen.len()
                    && (specimen[index].is_ascii_graphic() || specimen[index] == b' ')
                {
                    continue;
                }
                if index - start >= 4 {
                    entry(
                        section,
                        "ASCII",
                        String::from_utf8_lossy(&specimen[start..index]).into_owned(),
                        Some(start as u64),
                    );
                }
                start = index + 1;
                if section.entries.len() >= ENTRY_MAX_COUNT {
                    section.state = AnalysisSectionState::Partial;
                    break;
                }
            }
            section.summary =
                "printable ASCII strings, minimum four octets; offsets are file offsets".into();
        }
        AnalysisKind::Structures | AnalysisKind::Hardening => match object::File::parse(specimen) {
            Ok(file) => {
                if section.kind == AnalysisKind::Structures {
                    entry(
                        section,
                        "Entry point (declared address)",
                        format!("0x{:x}", file.entry()),
                        None,
                    );
                    for s in file.sections() {
                        entry(
                            section,
                            "Section",
                            format!(
                                "{}; size {}; flags {:?}",
                                s.name().unwrap_or("<invalid name>"),
                                s.size(),
                                s.flags()
                            ),
                            s.file_range().map(|r| r.0),
                        );
                    }
                    for symbol in file.symbols().chain(file.dynamic_symbols()) {
                        if let Ok(name) = symbol.name() {
                            if !name.is_empty() {
                                entry(
                                    section,
                                    if symbol.is_undefined() {
                                        "Undefined symbol"
                                    } else {
                                        "Symbol"
                                    },
                                    name,
                                    None,
                                );
                            }
                        }
                    }
                    match file.imports() {
                        Ok(imports) => {
                            for import in imports {
                                match import {
                                    Ok(import) => entry(
                                        section,
                                        "Import",
                                        format!(
                                            "{}!{}",
                                            String::from_utf8_lossy(import.library()),
                                            object_name(import.name())
                                        ),
                                        None,
                                    ),
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
                                        entry(section, "Export", object_name(export.name()), None)
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
                                    entry(section, "readelf version", version, None);
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
        AnalysisKind::Disassembly => {
            if object::File::parse(specimen).is_err() {
                unavailable(
                    section,
                    "disassembly unsupported for unknown/malformed format",
                );
                return;
            }
            match tool(
                "/usr/bin/objdump",
                &["--disassemble", "--wide", "/input/specimen"],
            ) {
                Ok((version, output, truncated)) => {
                    entry(section, "objdump version", version, None);
                    for line in output.lines() {
                        entry(section, "Disassembly", line, None);
                    }
                    if truncated {
                        section.state = AnalysisSectionState::Partial;
                    }
                    section.summary="objdump declared sections; printed addresses are object addresses, not observed runtime addresses".into();
                }
                Err(error) => unavailable(section, error),
            }
        }
        AnalysisKind::Identification => match tool(
            "/usr/bin/file",
            &["--brief", "--no-sandbox", "/input/specimen"],
        ) {
            Ok((version, output, truncated)) => {
                entry(section, "file version", version, None);
                entry(section, "File identification", output, None);
                section.state = AnalysisSectionState::Partial;
                section.summary="file magic identification only; compiler/packer signature adapter and local rules unavailable".into();
                if truncated {
                    section.summary.push_str("; output truncated");
                }
            }
            Err(error) => unavailable(section, error),
        },
        AnalysisKind::Rules => unavailable(
            section,
            "reviewed local rule adapter/rule set unavailable; no rule verdict",
        ),
        AnalysisKind::Capabilities => unavailable(
            section,
            "reviewed local capability adapter/rule set unavailable; no capability verdict",
        ),
        AnalysisKind::Decompilation => unavailable(
            section,
            "reviewed decompiler adapter unavailable; installed suites are not automatically invoked",
        ),
    }
    if section.state == AnalysisSectionState::Partial {
        section.summary.push_str("; partial/bounded evidence");
    }
}

fn tool(path: &str, arguments: &[&str]) -> Result<(String, String, bool), String> {
    if !Path::new(path).is_file() {
        return Err(format!("local tool unavailable: {path}"));
    }
    let version = bounded_command(path, &["--version"])?;
    let result = bounded_command(path, arguments)?;
    Ok((
        version
            .0
            .lines()
            .next()
            .unwrap_or("version unavailable")
            .to_string(),
        result.0,
        result.1,
    ))
}
fn object_name(name: object::NameOrOrdinal<&[u8]>) -> String {
    match name {
        object::NameOrOrdinal::Name(value) => String::from_utf8_lossy(value).into_owned(),
        object::NameOrOrdinal::Ordinal(value) => format!("ordinal {value}"),
    }
}
fn bounded_command(path: &str, arguments: &[&str]) -> Result<(String, bool), String> {
    let mut child = Command::new(path)
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("HOME", "/nonexistent")
        .current_dir("/output")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("tool spawn: {e}"))?;
    let mut output = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or("tool stdout unavailable")?
        .take((TOOL_OUTPUT_MAX_SIZE + 1) as u64)
        .read_to_end(&mut output);
    if let Err(error) = read {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("tool read: {error}"));
    }
    let truncated = output.len() > TOOL_OUTPUT_MAX_SIZE;
    if truncated {
        child.kill().map_err(|e| format!("tool kill: {e}"))?;
        output.truncate(TOOL_OUTPUT_MAX_SIZE);
    }
    let status = child.wait().map_err(|e| format!("tool reap: {e}"))?;
    if !status.success() && !truncated {
        return Err(format!("local tool failed: {path}: {status}"));
    }
    Ok((String::from_utf8_lossy(&output).into_owned(), truncated))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn section(kind: AnalysisKind) -> AnalysisSection {
        AnalysisSection {
            kind,
            state: AnalysisSectionState::Pending,
            summary: String::new(),
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
            analyze_section(&mut result, specimen);
            assert_eq!(result.state, AnalysisSectionState::Complete);
            assert!(result.entries.len() > 1);
        }
        for kind in [
            AnalysisKind::Structures,
            AnalysisKind::Hardening,
            AnalysisKind::Rules,
            AnalysisKind::Capabilities,
            AnalysisKind::Decompilation,
        ] {
            let mut result = section(kind);
            analyze_section(&mut result, specimen);
            assert_eq!(result.state, AnalysisSectionState::Unavailable);
        }
        for specimen in [b"\x7fELF".as_slice(), b"MZ", b"\xcf\xfa\xed\xfe", b""] {
            let mut result = section(AnalysisKind::Structures);
            analyze_section(&mut result, specimen);
            assert_eq!(result.state, AnalysisSectionState::Unavailable);
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
}

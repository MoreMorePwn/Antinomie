// SPDX-License-Identifier: MIT
//! Compiler, language, linker, runtime and packer identification from
//! built-in signatures, plus `file` magic and Detect It Easy when installed.
use super::tools;
use super::*;
use object::{Object, ObjectSection};
use std::time::Duration;

pub(super) const SIGNATURES: &str = "Antinomie identification signatures 1";
const DIE: &[&str] = &["/usr/bin/diec", "/usr/local/bin/diec", "/opt/die/diec"];

/// Find `needle` and return the printable run around it (for versions).
fn printable_around(data: &[u8], needle: &[u8], max: usize) -> Option<(usize, String)> {
    let at = data.windows(needle.len()).position(|w| w == needle)?;
    let end = data[at..]
        .iter()
        .take(max)
        .position(|b| !(b.is_ascii_graphic() || *b == b' '))
        .map_or((at + max).min(data.len()), |len| at + len);
    Some((at, String::from_utf8_lossy(&data[at..end]).into_owned()))
}

struct Finding {
    category: &'static str,
    name: String,
    version: Option<String>,
    evidence: String,
    offset: Option<(u64, u64)>,
}

fn found(
    findings: &mut Vec<Finding>,
    category: &'static str,
    name: impl Into<String>,
    version: Option<String>,
    evidence: impl Into<String>,
    offset: Option<(u64, u64)>,
) {
    let name = name.into();
    if findings
        .iter()
        .any(|f| f.category == category && f.name == name)
    {
        return;
    }
    findings.push(Finding {
        category,
        name,
        version,
        evidence: evidence.into(),
        offset,
    });
}

fn signatures(specimen: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let file = object::File::parse(specimen).ok();
    // Compiler and linker banners in ELF .comment.
    if let Some(file) = &file
        && let Some(comment) = file.section_by_name(".comment")
        && let Ok(data) = comment.data()
    {
        for banner in data.split(|b| *b == 0).filter(|b| !b.is_empty()) {
            let text = String::from_utf8_lossy(banner).trim().to_owned();
            let version = text
                .split_whitespace()
                .rev()
                .find(|word| word.chars().next().is_some_and(|c| c.is_ascii_digit()))
                .map(str::to_owned);
            let (category, name) = if text.starts_with("GCC:") {
                ("compiler", "GCC")
            } else if text.contains("clang version") {
                ("compiler", "Clang")
            } else if text.starts_with("rustc version") {
                ("compiler", "rustc")
            } else if text.starts_with("Linker:") || text.contains("LLD") {
                (
                    "linker",
                    if text.contains("LLD") {
                        "LLD"
                    } else {
                        "linker"
                    },
                )
            } else if text.contains("GNU ld") || text.contains("GNU gold") {
                ("linker", "GNU binutils")
            } else {
                ("compiler", "other toolchain banner")
            };
            found(
                &mut findings,
                category,
                name,
                version,
                format!(".comment: {text}"),
                None,
            );
        }
    }
    // Go: build info and runtime version.
    if let Some((at, text)) = printable_around(specimen, b"\xff Go buildinf:", 14) {
        found(
            &mut findings,
            "language",
            "Go",
            None,
            format!("Go build info marker ({text})"),
            Some((at as u64, 14)),
        );
    }
    if let Some((at, text)) = printable_around(specimen, b"go1.", 16) {
        let version = text
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
            .next()
            .map(str::to_owned);
        if version.as_deref().is_some_and(|v| v.len() > 4) {
            found(
                &mut findings,
                "language",
                "Go",
                version.clone(),
                format!("runtime version string {}", version.unwrap_or_default()),
                Some((at as u64, text.len() as u64)),
            );
        }
    }
    // Rust: standard library paths from the compiler's source tree.
    if let Some((at, text)) = printable_around(specimen, b"/rustc/", 80) {
        found(
            &mut findings,
            "language",
            "Rust",
            None,
            format!("standard library path {text}"),
            Some((at as u64, text.len() as u64)),
        );
    } else if let Some((at, _)) = printable_around(specimen, b"rust_panic", 10) {
        found(
            &mut findings,
            "language",
            "Rust",
            None,
            "rust_panic symbol text",
            Some((at as u64, 10)),
        );
    }
    // C runtimes.
    if let Some((at, text)) = printable_around(specimen, b"GLIBC_2.", 16) {
        found(
            &mut findings,
            "runtime",
            "glibc",
            None,
            format!("symbol version {text}"),
            Some((at as u64, text.len() as u64)),
        );
    }
    if printable_around(specimen, b"musl libc", 9).is_some()
        || printable_around(specimen, b"ld-musl-", 8).is_some()
    {
        found(
            &mut findings,
            "runtime",
            "musl",
            None,
            "musl loader or banner text",
            None,
        );
    }
    if let Some(file) = &file
        && file.format() == object::BinaryFormat::Elf
    {
        let interpreter = file
            .section_by_name(".interp")
            .and_then(|s| s.data().ok())
            .map(|d| String::from_utf8_lossy(d).trim_end_matches('\0').to_owned());
        match interpreter {
            Some(interp) => found(
                &mut findings,
                "linking",
                "dynamically linked",
                None,
                format!("interpreter {interp}"),
                None,
            ),
            None => found(
                &mut findings,
                "linking",
                "statically linked",
                None,
                "no program interpreter",
                None,
            ),
        }
    }
    // PE toolchains, runtimes and installers.
    if let Some(file) = &file
        && file.format() == object::BinaryFormat::Pe
    {
        if let Some((at, _)) = printable_around(specimen, b"Rich", 4)
            && at < 0x400
        {
            found(
                &mut findings,
                "compiler",
                "Microsoft Visual C++",
                None,
                "Rich header (MSVC linker product records)",
                Some((at as u64, 4)),
            );
        }
        if file.section_by_name(".text").is_some()
            && (printable_around(specimen, b"mscoree.dll", 11).is_some()
                || printable_around(specimen, b"_CorExeMain", 11).is_some())
        {
            found(
                &mut findings,
                "language",
                ".NET",
                None,
                "CLR entry import (mscoree.dll, _CorExeMain)",
                None,
            );
        }
        for (needle, category, name) in [
            (&b"Mingw-w64 runtime failure"[..], "compiler", "MinGW-w64"),
            (b"Embarcadero Delphi", "compiler", "Delphi"),
            (b"Borland", "compiler", "Borland"),
            (b"Nullsoft Install System", "installer", "NSIS"),
            (b"Inno Setup", "installer", "Inno Setup"),
            (b"PyInstaller", "packer", "PyInstaller"),
            (b"_MEIPASS", "packer", "PyInstaller"),
            (b"AU3!EA06", "packer", "AutoIt"),
        ] {
            if let Some((at, text)) = printable_around(specimen, needle, 64) {
                found(
                    &mut findings,
                    category,
                    name,
                    None,
                    text,
                    Some((at as u64, needle.len() as u64)),
                );
            }
        }
    }
    // Packers.
    if let Some((at, text)) =
        printable_around(specimen, b"$Info: This file is packed with the UPX", 80)
    {
        found(
            &mut findings,
            "packer",
            "UPX",
            None,
            text,
            Some((at as u64, 40)),
        );
    } else if let Some((at, _)) = printable_around(specimen, b"UPX!", 4) {
        found(
            &mut findings,
            "packer",
            "UPX",
            None,
            "UPX! marker",
            Some((at as u64, 4)),
        );
    }
    if let Some(file) = &file {
        for section in file.sections() {
            let name = section.name().unwrap_or("");
            let packer = match name {
                ".MPRESS1" | ".MPRESS2" => Some("MPRESS"),
                ".aspack" | ".adata" => Some("ASPack"),
                ".themida" | ".winlice" => Some("Themida / WinLicense"),
                ".vmp0" | ".vmp1" | ".vmp2" => Some("VMProtect"),
                ".petite" => Some("Petite"),
                ".nsp0" | ".nsp1" => Some("NsPack"),
                _ => None,
            };
            if let Some(packer) = packer {
                found(
                    &mut findings,
                    "packer",
                    packer,
                    None,
                    format!("section {name}"),
                    None,
                );
            }
        }
    }
    findings
}

pub(super) fn identify(section: &mut AnalysisSection, specimen: &[u8]) {
    let findings = signatures(specimen);
    section.tools.push(SIGNATURES.into());
    for finding in &findings {
        super::worker::structured_entry(
            section,
            format!("{}: {}", finding.category, finding.name),
            finding.evidence.clone(),
            finding.offset.map(|(offset, len)| AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: offset,
                file_range: Some(AnalysisRange { offset, len }),
            }),
            AnalysisData::Identification {
                category: finding.category.into(),
                name: finding.name.clone(),
                version: finding.version.clone(),
            },
        );
    }
    let mut sources = vec!["built-in signatures"];
    if let Some(file) = tools::find(&["/usr/bin/file"])
        && let Ok(run) = tools::run(
            file,
            &["--brief", "--no-sandbox", "/input/specimen"],
            &[],
            Duration::from_secs(30),
            4096,
        )
        && run.success
    {
        super::worker::structured_entry(
            section,
            "format: file magic",
            run.stdout.trim(),
            None,
            AnalysisData::Identification {
                category: "format".into(),
                name: "file magic".into(),
                version: None,
            },
        );
        section.tools.push(tools::version(file, &["--version"]));
        sources.push("file magic");
    }
    let die = tools::find(DIE);
    if let Some(die) = die
        && let Ok(run) = tools::run(
            die,
            &["--json", "/input/specimen"],
            &[("HOME", "/tmp")],
            Duration::from_secs(120),
            1024 * 1024,
        )
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&run.stdout)
    {
        let values = json
            .pointer("/detects/0/values")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for value in values {
            let category = value
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("detected")
                .to_lowercase();
            let name = value
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if name.is_empty() {
                continue;
            }
            let version = value
                .get("version")
                .and_then(|v| v.as_str())
                .filter(|v| !v.is_empty())
                .map(str::to_owned);
            let text = value
                .get("string")
                .and_then(|v| v.as_str())
                .unwrap_or(&name)
                .to_owned();
            super::worker::structured_entry(
                section,
                format!("{category}: {name}"),
                format!("Detect It Easy: {text}"),
                None,
                AnalysisData::Identification {
                    category,
                    name,
                    version,
                },
            );
        }
        section.tools.push(tools::version(die, &["--version"]));
        sources.push("Detect It Easy");
    }
    section.state = AnalysisSectionState::Complete;
    section.summary = format!(
        "{} identifications from {}{}",
        section.entries.len(),
        sources.join(", "),
        if die.is_none() {
            "; install Detect It Easy (diec) for its signature database"
        } else {
            ""
        }
    );
}

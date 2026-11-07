// SPDX-License-Identifier: GPL-3.0-only
//! Compiler, language, linker, runtime and packer identification from
//! built-in signatures, plus `file` magic and Detect It Easy when installed.
use super::tools;
use super::*;
use object::{Object, ObjectSection};
use std::time::Duration;

pub(super) const SIGNATURES: &str = "Antinomie identification signatures 1";
const DIE_MANAGED: &str = "/opt/antinomie-tools/die/diec.sh";

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

/// Whether the file shows the Go toolchain's own structures.
fn go_evidence(specimen: &[u8], file: Option<&object::File>) -> bool {
    if let Some(file) = file
        && file.sections().any(|section| {
            matches!(
                section.name().unwrap_or(""),
                ".go.buildinfo" | ".gopclntab" | ".note.go.buildid" | ".typelink" | ".itablink"
            )
        })
    {
        return true;
    }
    // Stripped of sections: the marker sits 16-byte aligned in the data, and
    // the runtime's symbol text is in the file.
    let aligned = specimen
        .windows(14)
        .enumerate()
        .any(|(at, w)| at % 16 == 0 && w == b"\xff Go buildinf:");
    aligned
        && (printable_around(specimen, b"runtime.main", 12).is_some()
            || printable_around(specimen, b"runtime.goexit", 14).is_some())
}

/// What the file's own structure says about "Go", for a tool that claims it.
pub(super) fn go_supported(specimen: &[u8]) -> bool {
    let file = object::File::parse(specimen).ok();
    go_evidence(specimen, file.as_ref())
}

/// How `file`'s magic describes the linking: Some(true) dynamic, Some(false)
/// static.
fn magic_linking(magic: &str) -> Option<bool> {
    if magic.contains("statically linked") || magic.contains("static-pie") {
        Some(false)
    } else if magic.contains("dynamically linked") {
        Some(true)
    } else {
        None
    }
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
    if let Some(existing) = findings
        .iter_mut()
        .find(|f| f.category == category && f.name == name)
    {
        // A second sighting can still add the version the first lacked.
        if existing.version.is_none() {
            existing.version = version;
        }
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
    // Go: build info and runtime version. The marker is a short string that
    // other programs carry as data (a scanner, a string table), so it counts
    // only where the Go linker puts it: in a Go section, or 16-byte aligned
    // beside the runtime's own symbols.
    let go = go_evidence(specimen, file.as_ref());
    if go && let Some((at, text)) = printable_around(specimen, b"\xff Go buildinf:", 14) {
        found(
            &mut findings,
            "language",
            "Go",
            None,
            format!("Go build info marker ({text})"),
            Some((at as u64, 14)),
        );
    }
    if go && let Some((at, text)) = printable_around(specimen, b"go1.", 16) {
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
    // The loader's view (program headers), not the section table: a stripped
    // or packed file may have no `.interp` section yet still name one.
    if let Some(elf) = super::elf_facts::parse(specimen) {
        use super::elf_facts::Linking;
        match elf.linking(specimen) {
            Linking::Interpreter(interp) => found(
                &mut findings,
                "linking",
                "dynamically linked",
                None,
                format!("interpreter {interp} (program header)"),
                None,
            ),
            Linking::DynamicWithoutInterpreter => found(
                &mut findings,
                "linking",
                "statically linked",
                None,
                "dynamic segment but no program interpreter (static PIE)",
                None,
            ),
            Linking::Static => found(
                &mut findings,
                "linking",
                "statically linked",
                None,
                "no program interpreter and no dynamic segment",
                None,
            ),
        }
        let cut = elf.truncation();
        if !cut.is_empty() {
            found(
                &mut findings,
                "format",
                "truncated ELF",
                None,
                cut.join("; "),
                None,
            );
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
    } else if let Some(sign) = super::unpack::upx_marker(specimen) {
        found(
            &mut findings,
            "packer",
            "UPX",
            None,
            sign,
            printable_around(specimen, b"UPX!", 4).map(|(at, _)| (at as u64, 4)),
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
    // The tool that was stopped, and the seconds it had.
    let mut out_of_time: Option<(&str, u64)> = None;
    if let Some(file) = tools::find(&["/usr/bin/file"]) {
        let limit = Duration::from_secs(super::limits::seconds(30));
        if let Ok(run) = tools::run(
            file,
            &["--brief", "--no-sandbox", "/input/specimen"],
            &[],
            limit,
            4096,
        ) {
            if run.timed_out {
                out_of_time = Some(("file", limit.as_secs()));
            } else if run.success {
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
                let ours = findings
                    .iter()
                    .find(|f| f.category == "linking" && !f.evidence.contains("static PIE"))
                    .map(|f| f.name == "dynamically linked");
                if let (Some(ours), Some(theirs)) = (ours, magic_linking(&run.stdout))
                    && ours != theirs
                {
                    let word = |dynamic: bool| if dynamic { "dynamically" } else { "statically" };
                    super::worker::structured_entry(
                        section,
                        "linking: signatures and file magic disagree",
                        format!(
                            "the program headers say {} linked ({}), file magic says {} linked; neither is hidden here, the file may have been edited",
                            word(ours),
                            findings
                                .iter()
                                .find(|f| f.category == "linking")
                                .map_or("", |f| f.evidence.as_str()),
                            word(theirs)
                        ),
                        None,
                        AnalysisData::Identification {
                            category: "linking".into(),
                            name: "disagreement".into(),
                            version: None,
                        },
                    );
                }
            }
        }
    }
    let die = tools::find_tool("die", crate::analysis_tools::DIE_SYSTEM, DIE_MANAGED);
    let die_limit = Duration::from_secs(super::limits::seconds_for(
        super::limits::TimedTool::Identify,
    ));
    let die_run = die.and_then(|die| {
        tools::run_with(
            die,
            &["--json", "/input/specimen"],
            &[("HOME", "/tmp")],
            die_limit,
            1024 * 1024,
            true,
        )
        .ok()
    });
    if die_run.as_ref().is_some_and(|run| run.timed_out) {
        out_of_time = Some(("Detect It Easy", die_limit.as_secs()));
    }
    let mut die_failure = None;
    if let Some(die) = die
        && let Some(run) = die_run.as_ref().filter(|run| !run.timed_out)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&run.stdout).inspect_err(|_| {
            die_failure = run.failure_text("Detect It Easy", die_limit);
            eprintln!(
                "Detect It Easy output did not parse ({} octets, success {}): {}",
                run.stdout.len(),
                run.success,
                run.stdout.chars().take(300).collect::<String>()
            )
        })
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
            // DIE matches Go on short byte patterns that C programs can
            // contain; say so when the file has none of Go's structures.
            let disputed = name.eq_ignore_ascii_case("go") && !go_supported(specimen);
            super::worker::structured_entry(
                section,
                format!("{category}: {name}"),
                format!(
                    "Detect It Easy: {text}{}",
                    if disputed {
                        "; DISPUTED: the file has no Go section, build info marker or runtime symbols, so this is probably a false match"
                    } else {
                        ""
                    }
                ),
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
        "{} identifications from {}{}{}",
        section.entries.len(),
        sources.join(", "),
        if die.is_none() {
            "; install Detect It Easy from Tools > Analysis tools for its signature database"
        } else {
            ""
        },
        die_failure.map_or(String::new(), |failure| format!("; {failure}"))
    );
    if let Some((tool, seconds)) = out_of_time {
        let summary = format!(
            "{}; {tool} was stopped, so its findings are missing",
            section.summary
        );
        super::limits::time_out(section, tool, seconds, summary);
    }
}

#[cfg(test)]
mod tests {
    use super::super::elf_facts::fixtures::elf64;
    use super::*;

    fn names(findings: &[Finding]) -> Vec<String> {
        findings
            .iter()
            .map(|f| format!("{}: {}", f.category, f.name))
            .collect()
    }

    #[test]
    fn a_go_marker_in_data_does_not_make_a_c_program_go() {
        let mut file = elf64(0x800, 0x800, 0x100, false);
        // The marker and a version string sit at an odd offset, as in a
        // scanner's string table; there is no Go section or runtime symbol.
        file[0x305..0x305 + 14].copy_from_slice(b"\xff Go buildinf:");
        file[0x400..0x408].copy_from_slice(b"go1.24.1");
        let found = names(&signatures(&file));
        assert!(!found.contains(&"language: Go".to_owned()), "{found:?}");
    }

    #[test]
    fn go_needs_its_linker_structures() {
        let mut file = elf64(0x800, 0x800, 0x100, false);
        file[0x300..0x300 + 14].copy_from_slice(b"\xff Go buildinf:");
        file[0x500..0x50c].copy_from_slice(b"runtime.main");
        file[0x600..0x608].copy_from_slice(b"go1.24.1");
        let found = signatures(&file);
        let go: Vec<_> = found.iter().filter(|f| f.name == "Go").collect();
        assert!(
            !go.is_empty(),
            "aligned marker beside runtime symbols is Go"
        );
        assert!(go.iter().any(|f| f.version.as_deref() == Some("go1.24.1")));
    }

    #[test]
    fn linking_follows_the_program_headers_when_sections_are_gone() {
        let dynamic = elf64(0x400, 0x400, 0x100, true);
        let found = signatures(&dynamic);
        let linking: Vec<_> = found.iter().filter(|f| f.category == "linking").collect();
        assert_eq!(linking.len(), 1);
        assert_eq!(linking[0].name, "dynamically linked");
        assert!(linking[0].evidence.contains("ld-linux-x86-64"));
        let fixed = signatures(&elf64(0x400, 0x400, 0x100, false));
        assert!(fixed.iter().any(|f| f.name == "statically linked"));
    }

    #[test]
    fn a_truncated_elf_is_named_in_identification() {
        let cut = elf64(0x300, 0x400, 0x350, false);
        let found = signatures(&cut);
        let truncated = found.iter().find(|f| f.name == "truncated ELF").unwrap();
        assert!(truncated.evidence.contains("entry point"));
        assert!(
            !signatures(&elf64(0x400, 0x400, 0x100, false))
                .iter()
                .any(|f| f.name == "truncated ELF")
        );
    }

    #[test]
    fn magic_text_is_read_for_its_linking() {
        assert_eq!(
            magic_linking("ELF 64-bit, statically linked, stripped"),
            Some(false)
        );
        assert_eq!(magic_linking("ELF 64-bit, static-pie linked"), Some(false));
        assert_eq!(
            magic_linking("ELF 32-bit, dynamically linked, interpreter /lib/ld.so"),
            Some(true)
        );
        assert_eq!(magic_linking("data"), None);
    }
}

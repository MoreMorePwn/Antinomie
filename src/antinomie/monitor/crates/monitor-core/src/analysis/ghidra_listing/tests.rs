// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/ghidra-listing")
        .join(name)
}

/// Ghidra's headless launcher on this machine, when there is one.
fn headless() -> Option<PathBuf> {
    std::env::var_os("ANTINOMIE_GHIDRA_HEADLESS")
        .map(PathBuf::from)
        .into_iter()
        .chain(
            crate::analysis_tools::GHIDRA_SYSTEM
                .iter()
                .chain(&["/opt/ghidra/support/analyzeHeadless"])
                .map(PathBuf::from),
        )
        .find(|path| path.is_file())
}

/// Ghidra 12 wants JDK 25; the distribution's own JDK directory when the
/// environment names none.
fn java_home() -> Option<(&'static str, std::ffi::OsString)> {
    const JDK: &str = "/usr/lib/jvm/java-25-openjdk-amd64";
    (std::env::var_os("JAVA_HOME").is_none() && Path::new(JDK).is_dir())
        .then(|| ("JAVA_HOME", JDK.into()))
}

fn scratch(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ant-ghidra-listing-{label}-{}",
        crate::storage::unique_id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

/// Run the real post-script on a fixture and parse its export.
fn export(headless: &Path, name: &str) -> (PathBuf, Vec<u8>, AnalysisListing, ListingSummary) {
    export_file(headless, &fixture(name))
}

fn export_file(
    headless: &Path,
    path: &Path,
) -> (PathBuf, Vec<u8>, AnalysisListing, ListingSummary) {
    export_mode(headless, path, false)
}

/// `listing_only` runs the post-script the way a Disassembly-only run does.
fn export_mode(
    headless: &Path,
    path: &Path,
    listing_only: bool,
) -> (PathBuf, Vec<u8>, AnalysisListing, ListingSummary) {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let work = scratch(&name);
    let specimen = std::fs::read(path).unwrap();
    std::fs::write(
        work.join("AntinomieExport.java"),
        super::super::decompile::ghidra_script(),
    )
    .unwrap();
    for directory in ["project", "home", "listings"] {
        std::fs::create_dir(work.join(directory)).unwrap();
    }
    let export = work.join("disassembly.txt");
    let run = Command::new(headless)
        .arg(work.join("project"))
        .arg("antinomie")
        .arg("-import")
        .arg(path)
        .arg("-scriptPath")
        .arg(&work)
        .args(["-postScript", "AntinomieExport.java"])
        .arg(work.join("decompiled.txt"))
        .arg("60")
        .arg(&export)
        .arg(export_max_size().to_string())
        .args(listing_only.then_some("listing"))
        .args(["-analysisTimeoutPerFile", "120", "-deleteProject"])
        .env("HOME", work.join("home"))
        .envs(java_home())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        run.status.success() && export.is_file(),
        "Ghidra failed on {name}:\n{}",
        String::from_utf8_lossy(&run.stdout)
            .lines()
            .rev()
            .take(30)
            .collect::<Vec<_>>()
            .join("\n")
    );
    let object_base = super::super::decompile::object_base(&specimen);
    let (listing, summary) =
        write_listing(&work.join("listings"), &export, &specimen, object_base).unwrap();
    (work, specimen, listing, summary)
}

fn rows(work: &Path) -> Vec<AnalysisEntry> {
    let text = std::fs::read(
        work.join("listings")
            .join(super::super::listing::GHIDRA_DISASSEMBLY_FILE),
    )
    .unwrap();
    text.split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect()
}

fn data(entry: &AnalysisEntry) -> &AnalysisData {
    &entry.record.as_ref().unwrap().data
}

fn function_address(rows: &[AnalysisEntry], wanted: &str) -> u64 {
    rows.iter()
        .find_map(|entry| match data(entry) {
            AnalysisData::Function { name, address, .. } if name == wanted => Some(*address),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no function {wanted}"))
}

/// Every architecture: the language, the functions of the program, the file
/// bytes under every row, a call with its target and the matching xref.
fn check(headless: &Path, name: &str, language: &str, endian: &str, bits: u32) {
    let (work, specimen, listing, summary) = export(headless, name);
    assert!(
        summary.language.starts_with(language),
        "{name}: {}",
        summary.language
    );
    assert_eq!(summary.endian, endian, "{name}");
    assert_eq!(summary.pointer_bits, bits, "{name}");
    assert!(!listing.truncated, "{name}: {}", summary.note);
    assert!(
        summary.instructions >= 20,
        "{name}: {}",
        summary.instructions
    );
    let rows = rows(&work);
    assert_eq!(rows.len() as u64, listing.rows);
    let entry = object::File::parse(&*specimen).unwrap().entry();
    assert_eq!(function_address(&rows, "_start"), entry, "{name} entry");
    let pick = function_address(&rows, "pick");
    let sum = function_address(&rows, "sum_squares");
    let mut previous = 0;
    let mut calls_pick = None;
    let mut pick_callers = Vec::new();
    for row in &rows {
        let record = row.record.as_ref().unwrap();
        let AnalysisData::Instruction {
            address,
            bytes,
            function,
            targets,
            xrefs,
            mnemonic,
            ..
        } = &record.data
        else {
            continue;
        };
        assert!(*address > previous, "{name}: addresses ascend");
        previous = *address;
        assert!(!mnemonic.is_empty(), "{name}");
        // The listing's bytes are the file's bytes at the row's file range.
        let range = record
            .location
            .as_ref()
            .unwrap()
            .file_range
            .expect("file range");
        let hex: String = specimen[range.offset as usize..(range.offset + range.len) as usize]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert_eq!(&hex, bytes, "{name} at {address:x}");
        if function.as_deref() == Some("_start")
            && targets
                .iter()
                .any(|t| t.address == pick && t.kind == AnalysisReferenceKind::Call)
        {
            calls_pick = Some(*address);
        }
        if *address == pick {
            pick_callers = xrefs.clone();
        }
    }
    let caller = calls_pick.unwrap_or_else(|| panic!("{name}: _start calls pick"));
    assert!(
        pick_callers
            .iter()
            .any(|x| x.address == caller && x.kind == AnalysisReferenceKind::Call),
        "{name}: pick lists its caller {caller:x} in {pick_callers:?}"
    );
    assert!(sum != pick);
    let _ = std::fs::remove_dir_all(work);
}

macro_rules! architecture {
    ($test:ident, $file:literal, $language:literal, $endian:literal, $bits:literal) => {
        #[test]
        fn $test() {
            let Some(headless) = headless() else {
                eprintln!("skipped: Ghidra is not installed");
                return;
            };
            check(&headless, $file, $language, $endian, $bits);
        }
    };
}

architecture!(x86_64_listing, "x86_64.elf", "x86:LE:64", "little", 64);
architecture!(i386_listing, "i386.elf", "x86:LE:32", "little", 32);
architecture!(arm_listing, "arm.elf", "ARM:LE:32", "little", 32);
architecture!(
    aarch64_listing,
    "aarch64.elf",
    "AARCH64:LE:64",
    "little",
    64
);
architecture!(mips_listing, "mips.elf", "MIPS:BE:32", "big", 32);
architecture!(riscv64_listing, "riscv64.elf", "RISCV:LE:64", "little", 64);

fn sample(lines: &[&str]) -> (PathBuf, AnalysisListing, ListingSummary) {
    let work = scratch("sample");
    std::fs::create_dir(work.join("listings")).unwrap();
    let export = work.join("export.txt");
    std::fs::write(&export, lines.join("\n") + "\n").unwrap();
    let (listing, summary) =
        write_listing(&work.join("listings"), &export, b"not an object", 0).unwrap();
    (work, listing, summary)
}

#[test]
fn rows_follow_the_export_and_a_rebased_image_maps_back() {
    let (work, listing, summary) = sample(&[
        "@@ANTINOMIE-ARCH\tx86:LE:64:default\tx86\tlittle\t64\tgcc",
        "@@ANTINOMIE-BASE\t1048576",
        "F\t101000\t6\tmain",
        "I\t101000\t5589e5\tPUSH\tRBP\tmain\t\t101010:j\t",
        "I\t101001\t90\tNOP\t\tmain\tentry_label\t101020:c,zzz\t",
        "garbage line",
        "I\t101002\t\tnotenough",
    ]);
    assert_eq!((summary.functions, summary.instructions), (1, 2));
    assert_eq!(summary.language, "x86:LE:64:default");
    assert!(!listing.truncated && summary.note.is_empty());
    let rows = rows(&work);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].value, "main");
    let AnalysisData::Instruction {
        address,
        bytes,
        targets,
        label,
        ..
    } = data(&rows[1])
    else {
        panic!()
    };
    // Image base 0x100000, object base 0: the object's address is 0x1000.
    assert_eq!((*address, bytes.as_str()), (0x1000, "55 89 e5"));
    assert_eq!(
        targets,
        &[AnalysisReference {
            address: 0x1010,
            kind: AnalysisReferenceKind::Jump
        }]
    );
    assert_eq!(label, &None);
    let AnalysisData::Instruction { label, targets, .. } = data(&rows[2]) else {
        panic!()
    };
    assert_eq!(label.as_deref(), Some("entry_label"));
    assert_eq!(targets.len(), 1, "a malformed reference is dropped");
    assert_eq!(rows[2].value, "NOP");
    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_stopped_export_keeps_its_rows_and_says_why() {
    let (work, listing, summary) = sample(&["I\t1000\t90\tNOP\t\t\t\t\t", "@@ANTINOMIE-TIMEOUT"]);
    assert!(listing.truncated);
    assert!(summary.note.contains("time"), "{}", summary.note);
    assert_eq!(listing.rows, 1);
    let (work2, listing, summary) =
        sample(&["I\t1000\t90\tNOP\t\t\t\t\t", "@@ANTINOMIE-LISTING-SIZE"]);
    assert!(listing.truncated && summary.note.contains("size"));
    let _ = std::fs::remove_dir_all(work);
    let _ = std::fs::remove_dir_all(work2);
}

#[test]
fn an_overlong_line_and_invalid_text_are_skipped() {
    let long = format!("I\t1000\t90\tNOP\t{}\t\t\t\t", "x".repeat(40_000));
    let (work, listing, summary) = sample(&[&long, "I\t1001\t90\tRET\t\t\t\t\t"]);
    assert_eq!((listing.rows, summary.instructions), (1, 1));
    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn the_listing_stops_at_its_size_bound() {
    let work = scratch("bound");
    let export = work.join("export.txt");
    let mut text = String::new();
    for index in 0..200 {
        text.push_str(&format!("I\t{:x}\t90\tNOP\t\t\t\t\t\n", 0x1000 + index));
    }
    std::fs::write(&export, text).unwrap();
    // A bound far under the listing maximum cuts the stream and marks it.
    let (listing, summary) = write_listing_with(&work, &export, b"x", 0, 2048).unwrap();
    assert!(listing.truncated && listing.bytes <= 2048, "{listing:?}");
    assert!(
        summary.instructions < 200 && summary.note.contains("limit"),
        "{}",
        summary.note
    );
    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_report_reads_the_ghidra_listing_page_by_page_and_adoption_validates_it() {
    let Some(headless) = headless() else {
        eprintln!("skipped: Ghidra is not installed");
        return;
    };
    let (work, specimen, listing, summary) = export(&headless, "x86_64.elf");
    // The worker's output directory, then the host's retained one.
    let host = scratch("host");
    std::fs::create_dir_all(host.join("output")).unwrap();
    std::fs::rename(work.join("listings"), host.join("output/listings")).unwrap();
    let mut section = AnalysisSection::new(AnalysisKind::Decompilation);
    section.state = AnalysisSectionState::Complete;
    section.disassembly = Some(AnalysisDisassembly {
        listing: listing.clone(),
        tool: "Ghidra test".into(),
        language: summary.language.clone(),
        endian: summary.endian.clone(),
        pointer_bits: summary.pointer_bits,
        functions: summary.functions,
        instructions: summary.instructions,
        note: String::new(),
    });
    let mut report = AnalysisReport {
        id: "ghidra".into(),
        state: AnalysisState::Complete,
        source_path: "/fixture".into(),
        specimen_sha256: None,
        specimen_len: Some(specimen.len() as u64),
        reason: None,
        sections: vec![section],
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    };
    super::super::jobs::adopt_listings(&host, &mut report, &[]);
    assert!(
        report.sections[0].disassembly.is_some(),
        "{}",
        report.sections[0].summary
    );
    std::fs::write(
        host.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let page = read_ghidra_disassembly_page(&host, "ghidra", 0, 5, "", |_| true).unwrap();
    assert_eq!(
        (page.kind, page.rows.len() as u64, page.total),
        (AnalysisKind::Disassembly, 5, listing.rows)
    );
    let found = read_ghidra_disassembly_page(&host, "ghidra", 0, 50, "call", |entry| {
        entry.value.to_lowercase().contains("call")
    })
    .unwrap();
    assert!(
        found.total > 0
            && found
                .rows
                .iter()
                .all(|(_, row)| row.value.to_lowercase().contains("call"))
    );
    assert!(read_ghidra_disassembly_page(&host, "other", 0, 5, "", |_| true).is_err());
    // A damaged file is refused when it is read.
    let path = host
        .join("listings")
        .join(super::super::listing::GHIDRA_DISASSEMBLY_FILE);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] = b'!';
    std::fs::write(&path, bytes).unwrap();
    assert!(read_ghidra_disassembly_page(&host, "ghidra", 0, 5, "", |_| true).is_err());
    let _ = std::fs::remove_dir_all(work);
    let _ = std::fs::remove_dir_all(host);
}

/// `ANTINOMIE_LISTING_PROGRAM=<benign ELF>`: export a larger real program and
/// say how long it took and how big the listing is.
#[test]
fn a_real_program_from_the_environment_exports_within_the_bounds() {
    let (Some(headless), Some(program)) =
        (headless(), std::env::var_os("ANTINOMIE_LISTING_PROGRAM"))
    else {
        return;
    };
    let started = std::time::Instant::now();
    let (work, _, listing, summary) = export_file(&headless, Path::new(&program));
    eprintln!(
        "listing of {}: {:?} in {:?}; {summary:?}",
        Path::new(&program).display(),
        listing,
        started.elapsed()
    );
    assert!(listing.bytes <= super::super::limits::ghidra_listing_bytes());
    let _ = std::fs::remove_dir_all(work);
}

fn disassembly_of(bytes: u64) -> AnalysisDisassembly {
    AnalysisDisassembly {
        listing: AnalysisListing {
            rows: 1,
            bytes,
            truncated: false,
        },
        tool: "Ghidra test".into(),
        language: String::new(),
        endian: String::new(),
        pointer_bits: 64,
        functions: 0,
        instructions: 0,
        note: String::new(),
    }
}

fn report_with(sections: Vec<AnalysisSection>) -> AnalysisReport {
    AnalysisReport {
        id: "budget".into(),
        state: AnalysisState::Complete,
        source_path: "/fixture".into(),
        specimen_sha256: None,
        specimen_len: None,
        reason: None,
        sections,
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    }
}

fn limit_settings(section: &AnalysisSection) -> Vec<Option<super::super::limits::LimitSetting>> {
    section.limits.iter().map(|limit| limit.setting).collect()
}

/// Ghidra's disassembly listing is adopted under its own size setting, and a
/// listing over it is dropped with a reason that names the setting.
#[test]
fn the_disassembly_is_adopted_under_the_ghidra_listing_size_setting() {
    use super::super::limits::{AnalysisLimits, LimitSetting};
    let mut section = AnalysisSection::new(AnalysisKind::Decompilation);
    section.state = AnalysisSectionState::Complete;
    section.disassembly = Some(disassembly_of(200 << 20));
    let mut report = report_with(vec![section]);
    let host = std::env::temp_dir().join(format!("ant-adopt-budget-{}", std::process::id()));
    std::fs::create_dir_all(&host).unwrap();
    let mut raised = report.clone();
    let mut limits = AnalysisLimits::default();
    limits.set(LimitSetting::GhidraListing, 512);
    raised.limits = limits.for_report();
    super::super::jobs::adopt_listings(&host, &mut report, &[]);
    super::super::jobs::adopt_listings(&host, &mut raised, &[]);
    let section = &report.sections[0];
    assert_eq!(section.state, AnalysisSectionState::Partial);
    assert!(section.disassembly.is_none());
    assert_eq!(limit_settings(section), [Some(LimitSetting::GhidraListing)]);
    assert!(
        section.limits[0]
            .text
            .contains("Ghidra disassembly size limit"),
        "{}",
        section.limits[0].text
    );
    // Raised, the size is no longer what refuses it (the file is missing).
    assert!(
        raised.sections[0]
            .limits
            .iter()
            .all(|limit| limit.setting.is_none()),
        "{:?}",
        raised.sections[0].limits
    );
    let _ = std::fs::remove_dir_all(host);
}

/// The combined listing bound stays for the other listings and says so.
#[test]
fn a_listing_over_the_combined_bound_is_dropped_with_a_reason_and_its_setting() {
    use super::super::limits::LimitSetting;
    let listed = |kind, bytes| {
        let mut section = AnalysisSection::new(kind);
        section.state = AnalysisSectionState::Complete;
        section.listing = Some(AnalysisListing {
            rows: 1,
            bytes,
            truncated: false,
        });
        section
    };
    let mut report = report_with(vec![
        listed(AnalysisKind::Strings, 100 << 20),
        listed(AnalysisKind::Disassembly, 100 << 20),
    ]);
    let host = std::env::temp_dir().join(format!("ant-adopt-combined-{}", std::process::id()));
    std::fs::create_dir_all(&host).unwrap();
    super::super::jobs::adopt_listings(&host, &mut report, &[]);
    let second = &report.sections[1];
    assert_eq!(second.state, AnalysisSectionState::Partial);
    assert!(second.listing.is_none());
    assert_eq!(second.limits.len(), 1);
    assert_eq!(second.limits[0].setting, Some(LimitSetting::Listing));
    assert_eq!(
        second.limits[0].text,
        "Full listing not kept: the listings of this report exceeded their combined size limit."
    );
    let _ = std::fs::remove_dir_all(host);
}

/// A statically linked program of about 1,400 functions and 190,000
/// instructions: its built-in and Ghidra disassembly listings, the decompiled
/// source and the strings together pass the combined 128 MiB, and every one is
/// kept whole at the default settings because Ghidra's has a budget of its own.
#[test]
fn a_large_static_program_keeps_every_listing_at_the_default_limits() {
    use super::super::listing::{ListingWriter, file_name};
    let host = scratch("static-host");
    let listings = host.join("output/listings");
    std::fs::create_dir_all(&listings).unwrap();
    // Ghidra's export of 190,000 instructions, 1,400 functions, with references.
    let export = host.join("export.txt");
    let mut text = String::from("@@ANTINOMIE-ARCH\tx86:LE:64:default\tx86\tlittle\t64\tgcc\n");
    text.push_str("@@ANTINOMIE-BASE\t4194304\n");
    let address = |index: u64| 0x401000 + index * 4;
    for index in 0..190_000u64 {
        if index % 136 == 0 {
            text.push_str(&format!(
                "F\t{:x}\t544\tFUN_{:08x}\n",
                address(index),
                address(index)
            ));
        }
        text.push_str(&format!(
            "I\t{:x}\t488b45f8\tMOV\tRAX,qword ptr [RBP + -0x8]\tFUN_{:08x}\t\t{:x}:j\t{:x}:c,{:x}:j\n",
            address(index),
            address(index - index % 136),
            address(index + 1),
            address(index.saturating_sub(7)),
            address(index.saturating_sub(9)),
        ));
    }
    std::fs::write(&export, text).unwrap();
    let (ghidra, summary) = write_listing(&listings, &export, b"x", 0).unwrap();
    assert!(!ghidra.truncated && summary.note.is_empty(), "{ghidra:?}");
    assert_eq!(summary.instructions, 190_000);
    assert!(
        ghidra.bytes > 64 << 20,
        "the listing must pass the combined single bound"
    );
    // The built-in listing of the same code, the decompilation and the strings.
    let rows = |kind, count: u64, make: &dyn Fn(u64) -> (String, AnalysisData)| {
        let mut writer = ListingWriter::create(&listings, kind, 64 << 20).unwrap();
        for index in 0..count {
            let (value, data) = make(index);
            assert!(writer.push("row", value, None, data));
        }
        let listing = writer.finish(false).unwrap();
        assert!(!listing.truncated, "{kind:?} {listing:?}");
        listing
    };
    let instruction = |index: u64| {
        (
            "MOV RAX, [RBP-8]".to_string(),
            AnalysisData::Instruction {
                address: address(index),
                bytes: "48 8b 45 f8".into(),
                mnemonic: "mov".into(),
                operands: "rax, qword ptr [rbp-8]".into(),
                function: Some(format!("sub_{:x}", address(index))),
                label: None,
                targets: Vec::new(),
                xrefs: Vec::new(),
            },
        )
    };
    let built_in = rows(AnalysisKind::Disassembly, 150_000, &instruction);
    let source = rows(AnalysisKind::Decompilation, 40_000, &|line| {
        (
            format!("  local_{line} = param_1 + {line};"),
            AnalysisData::SourceLine {
                function: "FUN_00401000".into(),
                address: None,
                line: line as u32 + 1,
            },
        )
    });
    let strings = rows(AnalysisKind::Strings, 60_000, &|index| {
        (
            format!("string number {index} of the program"),
            AnalysisData::String {
                encoding: "ASCII".into(),
                byte_len: 64,
                retained_len: 32,
            },
        )
    });
    let others = built_in.bytes + source.bytes + strings.bytes;
    assert!(
        others + ghidra.bytes > super::super::limits::AnalysisLimits::default().listings_total(),
        "the sample must pass the old combined bound"
    );
    let mut decompilation = AnalysisSection::new(AnalysisKind::Decompilation);
    decompilation.state = AnalysisSectionState::Complete;
    decompilation.listing = Some(source);
    decompilation.disassembly = Some(AnalysisDisassembly {
        listing: ghidra,
        tool: "Ghidra test".into(),
        language: summary.language,
        endian: summary.endian,
        pointer_bits: summary.pointer_bits,
        functions: summary.functions,
        instructions: summary.instructions,
        note: String::new(),
    });
    let mut disassembly = AnalysisSection::new(AnalysisKind::Disassembly);
    disassembly.state = AnalysisSectionState::Complete;
    disassembly.listing = Some(built_in);
    let mut strings_section = AnalysisSection::new(AnalysisKind::Strings);
    strings_section.state = AnalysisSectionState::Complete;
    strings_section.listing = Some(strings);
    let mut report = report_with(vec![strings_section, disassembly, decompilation]);
    super::super::jobs::adopt_listings(&host, &mut report, &[]);
    for section in &report.sections {
        assert_eq!(
            section.state,
            AnalysisSectionState::Complete,
            "{:?}",
            section.limits
        );
        assert!(section.limits.is_empty(), "{:?}", section.limits);
        assert!(section.listing.is_some());
    }
    assert!(report.sections[2].disassembly.is_some());
    for name in [
        super::super::listing::GHIDRA_DISASSEMBLY_FILE,
        file_name(AnalysisKind::Disassembly),
        file_name(AnalysisKind::Decompilation),
        file_name(AnalysisKind::Strings),
    ] {
        assert!(host.join("listings").join(name).is_file(), "{name}");
    }
    // The old default would have refused it: with the Ghidra listing counted
    // in the combined bound, one of them does not fit.
    let _ = std::fs::remove_dir_all(host);
}

/// `ANTINOMIE_STATIC_PROGRAM=<statically linked benign ELF>` with Ghidra
/// installed: the real export of a large static program is kept whole.
#[test]
fn a_real_static_program_from_the_environment_is_listed_whole_at_the_defaults() {
    let (Some(headless), Some(program)) =
        (headless(), std::env::var_os("ANTINOMIE_STATIC_PROGRAM"))
    else {
        return;
    };
    let (work, _, listing, summary) = export_file(&headless, Path::new(&program));
    eprintln!("static program: {listing:?} {summary:?}");
    assert!(!listing.truncated && summary.note.is_empty(), "{summary:?}");
    assert!(summary.functions > 1000, "{summary:?}");
    let _ = std::fs::remove_dir_all(work);
}

fn report_of(
    kinds: &[AnalysisKind],
    limits: Option<super::super::limits::AnalysisLimits>,
) -> AnalysisReport {
    let sections = kinds
        .iter()
        .map(|kind| AnalysisSection::new(*kind))
        .collect();
    AnalysisReport {
        id: "plan".into(),
        state: AnalysisState::Queued,
        source_path: "/fixture".into(),
        specimen_sha256: None,
        specimen_len: None,
        reason: None,
        sections,
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits,
    }
}

/// Acceptance: a Disassembly-only run starts Ghidra in listing-only mode, with
/// Decompilation it stays the one run, and the setting turns it off.
#[test]
fn a_disassembly_only_run_plans_ghidra_unless_decompilation_or_the_setting_say_otherwise() {
    use super::super::decompile::listing_only;
    use super::super::limits::AnalysisLimits;
    let only = report_of(&[AnalysisKind::Metadata, AnalysisKind::Disassembly], None);
    assert_eq!(listing_only(&only), Some(1));
    // Decompilation selected: its single Ghidra run exports the listing too.
    let both = report_of(
        &[AnalysisKind::Disassembly, AnalysisKind::Decompilation],
        None,
    );
    assert_eq!(listing_only(&both), None);
    // The setting off keeps the built-in rows only.
    let off = AnalysisLimits {
        ghidra_disassembly: false,
        ..AnalysisLimits::default()
    };
    let mut report = report_of(&[AnalysisKind::Disassembly], off.for_report());
    assert!(
        report
            .limits
            .is_some_and(|limits| !limits.ghidra_disassembly)
    );
    assert_eq!(listing_only(&report), None);
    // A finished Disassembly check is not run again.
    report.limits = None;
    report.sections[0].state = AnalysisSectionState::Complete;
    assert_eq!(listing_only(&report), None);
    // A report saved before the setting existed has it on.
    let old: AnalysisLimits = serde_json::from_str(r#"{"rows":4096}"#).unwrap();
    assert!(old.ghidra_disassembly && old.rows == 4096);
    // The run's time goes to Ghidra's whole analysis, not 90 seconds.
    assert!(
        super::super::progress::worker_deadline(&only)
            > std::time::Duration::from_secs(super::super::worker::DECOMPILER_SECONDS)
    );
}

/// Acceptance: Ghidra's listing-only run exports the ARM fixture (no built-in
/// disassembler needed) and writes no decompilation; the report that carries
/// it on the Disassembly section pages it like a decompilation run's.
#[test]
fn a_listing_only_run_lists_the_arm_fixture_and_writes_no_decompilation() {
    let Some(headless) = headless() else {
        eprintln!("skipped: Ghidra is not installed");
        return;
    };
    let (work, specimen, listing, summary) = export_mode(&headless, &fixture("arm.elf"), true);
    assert!(
        !work.join("decompiled.txt").exists(),
        "listing-only mode skips the decompile loop"
    );
    assert!(
        summary.language.starts_with("ARM:LE:32"),
        "{}",
        summary.language
    );
    assert!(summary.instructions >= 20 && summary.functions > 0);
    let host = scratch("only-host");
    std::fs::create_dir_all(host.join("output")).unwrap();
    std::fs::rename(work.join("listings"), host.join("output/listings")).unwrap();
    let mut section = AnalysisSection::new(AnalysisKind::Disassembly);
    section.state = AnalysisSectionState::Complete;
    section.disassembly = Some(AnalysisDisassembly {
        listing: listing.clone(),
        tool: "Ghidra test".into(),
        language: summary.language.clone(),
        endian: summary.endian.clone(),
        pointer_bits: summary.pointer_bits,
        functions: summary.functions,
        instructions: summary.instructions,
        note: String::new(),
    });
    let mut report = report_of(&[], None);
    report.id = "only".into();
    report.specimen_len = Some(specimen.len() as u64);
    report.sections = vec![section];
    super::super::jobs::adopt_listings(&host, &mut report, &[]);
    assert!(report.ghidra_disassembly().is_some());
    assert!(
        !report
            .sections
            .iter()
            .any(|s| s.kind == AnalysisKind::Decompilation)
    );
    std::fs::write(
        host.join("report.json"),
        serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let page = read_ghidra_disassembly_page(&host, "only", 0, 6, "", |_| true).unwrap();
    assert_eq!((page.rows.len() as u64, page.total), (6, listing.rows));
    let _ = std::fs::remove_dir_all(work);
    let _ = std::fs::remove_dir_all(host);
}

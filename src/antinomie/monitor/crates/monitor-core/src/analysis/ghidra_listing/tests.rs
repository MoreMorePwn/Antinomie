// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::analysis::listing::LISTING_MAX_SIZE;
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
        .arg(EXPORT_MAX_SIZE.to_string())
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
    assert!(listing.bytes <= LISTING_MAX_SIZE);
    let _ = std::fs::remove_dir_all(work);
}

/// The combined listing budget the Ghidra disassembly is adopted under follows
/// the report's size-limit settings.
#[test]
fn the_disassembly_is_adopted_under_the_listing_size_setting() {
    let mut section = AnalysisSection::new(AnalysisKind::Decompilation);
    section.state = AnalysisSectionState::Complete;
    section.disassembly = Some(AnalysisDisassembly {
        listing: AnalysisListing {
            rows: 1,
            bytes: 200 << 20,
            truncated: false,
        },
        tool: "Ghidra test".into(),
        language: String::new(),
        endian: String::new(),
        pointer_bits: 64,
        functions: 0,
        instructions: 0,
        note: String::new(),
    });
    let mut report = AnalysisReport {
        id: "budget".into(),
        state: AnalysisState::Complete,
        source_path: "/fixture".into(),
        specimen_sha256: None,
        specimen_len: None,
        reason: None,
        sections: vec![section],
        layer: None,
        specimen_source: None,
        time_limit_seconds: None,
        limits: None,
    };
    let host = std::env::temp_dir().join(format!("ant-adopt-budget-{}", std::process::id()));
    std::fs::create_dir_all(&host).unwrap();
    let mut raised = report.clone();
    let mut limits = super::super::limits::AnalysisLimits::default();
    limits.set(super::super::limits::LimitSetting::Listing, 512);
    raised.limits = limits.for_report();
    super::super::jobs::adopt_listings(&host, &mut report, &[]);
    super::super::jobs::adopt_listings(&host, &mut raised, &[]);
    let note = |r: &AnalysisReport| r.sections[0].summary.clone();
    assert!(
        note(&report).contains("combined bound"),
        "{}",
        note(&report)
    );
    assert!(
        !note(&raised).contains("combined bound"),
        "{}",
        note(&raised)
    );
    let _ = std::fs::remove_dir_all(host);
}

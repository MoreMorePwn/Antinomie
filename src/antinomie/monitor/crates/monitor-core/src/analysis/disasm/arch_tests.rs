// SPDX-License-Identifier: GPL-3.0-only
//! The Disassembly check on tiny benign ELF fixtures (sources and build
//! scripts beside them): x86 output is pinned, ARM output comes from Capstone.
use super::super::jobs::new_report;
use super::*;

const AARCH64: &[u8] = include_bytes!("../../../tests/fixtures/arm-disasm/aarch64.elf");
const ARM32: &[u8] = include_bytes!("../../../tests/fixtures/arm-disasm/arm32.elf");
const ARM32_STRIPPED: &[u8] =
    include_bytes!("../../../tests/fixtures/arm-disasm/arm32-stripped.elf");
const X86_64: &[u8] = include_bytes!("../../../tests/fixtures/x86-disasm/x86_64.elf");
const I386: &[u8] = include_bytes!("../../../tests/fixtures/x86-disasm/i386.elf");

/// The check's section and its listing rows as `address text` lines, with
/// function rows as `<name>`.
fn run(specimen: &[u8]) -> (AnalysisSection, Vec<String>) {
    let directory = std::env::temp_dir().join(format!(
        "antinomie-disasm-{}-{}",
        std::process::id(),
        specimen.len()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    let mut report = new_report(
        "/tmp/sample",
        &AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Disassembly],
            time_limit_minutes: 0,
            limits: Default::default(),
        },
    );
    let mut section = report.sections.remove(0);
    disassemble(&mut section, specimen, &directory);
    let rows = std::fs::read_to_string(directory.join("disassembly.jsonl"))
        .map(|text| {
            text.lines()
                .map(|line| serde_json::from_str::<AnalysisEntry>(line).unwrap())
                .map(|entry| match entry.record.map(|record| record.data) {
                    Some(AnalysisData::Function { name, .. }) => format!("<{name}>"),
                    Some(AnalysisData::Instruction { address, .. }) => {
                        format!("{address:x} {}", entry.value)
                    }
                    _ => entry.value,
                })
                .collect()
        })
        .unwrap_or_default();
    let _ = std::fs::remove_dir_all(&directory);
    (section, rows)
}

#[test]
fn x86_64_output_is_unchanged() {
    let (section, rows) = run(X86_64);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert_eq!(section.tools, [ICED_VERSION]);
    assert_eq!(rows, EXPECTED_X86_64);
}

#[test]
fn ia32_output_is_unchanged() {
    let (section, rows) = run(I386);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert_eq!(section.tools, [ICED_VERSION]);
    assert_eq!(rows, EXPECTED_I386);
}

#[test]
fn aarch64_is_decoded_by_capstone() {
    let (section, rows) = run(AARCH64);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert!(
        section.tools[0].starts_with("capstone "),
        "{:?}",
        section.tools
    );
    assert!(section.listing.is_some());
    assert_eq!(rows, EXPECTED_AARCH64);
}

#[test]
fn arm32_decodes_arm_and_thumb_by_mapping_symbols() {
    let (section, rows) = run(ARM32);
    assert_eq!(
        section.state,
        AnalysisSectionState::Complete,
        "{}",
        section.summary
    );
    assert!(
        section.summary.contains("ARM and Thumb"),
        "{}",
        section.summary
    );
    assert_eq!(rows, EXPECTED_ARM32, "{}", section.summary);
}

#[test]
fn a_stripped_arm32_file_still_lists_rows() {
    let (section, rows) = run(ARM32_STRIPPED);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    // No symbols: the entry point names the first function, and the code is
    // read as ARM (the entry's low bit is clear).
    assert_eq!(rows[0], "<entry>");
    assert_eq!(rows[1], "10054 mov r1, r0");
}

#[test]
fn one_unavailable_check_does_not_make_the_run_partial() {
    let mut report = new_report(
        "/tmp/sample",
        &AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Strings, AnalysisKind::Disassembly],
            time_limit_minutes: 0,
            limits: Default::default(),
        },
    );
    report.sections[0].state = AnalysisSectionState::Complete;
    report.sections[1].state = AnalysisSectionState::Unavailable;
    assert!(report.sections_settled());
    // A check that stopped short still does.
    report.sections[0].state = AnalysisSectionState::Partial;
    assert!(!report.sections_settled());
    // Nothing finished at all is not a settled run.
    report.sections[0].state = AnalysisSectionState::Unavailable;
    assert!(!report.sections_settled());
}

const EXPECTED_X86_64: &[&str] = &[
    "<entry>",
    "400078 push rbp",
    "400079 mov rbp, rsp",
    "40007c call sub_40008a",
    "400081 xor edi, edi",
    "400083 mov eax, 0x3c",
    "400088 syscall",
    "<sub_40008a>",
    "40008a ret",
];
const EXPECTED_I386: &[&str] = &[
    "<entry>",
    "8048054 push ebp",
    "8048055 mov ebp, esp",
    "8048057 call sub_8048065",
    "804805c xor ebx, ebx",
    "804805e mov eax, 1",
    "8048063 int 0x80",
    "<sub_8048065>",
    "8048065 ret",
];
const EXPECTED_AARCH64: &[&str] = &[
    "<_start>",
    "400078 mov x1, x0",
    "40007c add x0, x1, x1, lsl #1",
    "400080 bl #0x400084",
    "<done>",
    "400084 mov x8, #0x5d",
    "400088 mov x0, #0",
    "40008c svc #0",
    "400090 ret",
];
const EXPECTED_ARM32: &[&str] = &[
    "<_start>",
    "10054 mov r1, r0",
    "10058 add r0, r1, r1, lsl #1",
    "1005c blx #0x10068",
    "10060 mov r7, #1",
    "10064 svc #0",
    "<thumbed>",
    "10068 movs r2, #7",
    "1006a adds r0, r0, r2",
    "1006c bx lr",
    "1006e nop",
];

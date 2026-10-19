// SPDX-License-Identifier: MIT
use super::super::*;

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path =
            std::env::temp_dir().join(format!("ant-physical-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&path).unwrap();
        Self(path)
    }
    fn dump(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("memory.elf");
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn elf() -> Vec<u8> {
    let mut bytes = vec![0; 521];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&4u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
    // A QEMU CPU note, which must never be scanned as RAM or process registers.
    segment(&mut bytes, 0, 4, 256, 0, 0, 24, 24);
    bytes[256..260].copy_from_slice(&5u32.to_le_bytes());
    bytes[260..264].copy_from_slice(&4u32.to_le_bytes());
    bytes[268..273].copy_from_slice(b"QEMU\0");
    bytes[276..280].copy_from_slice(b"NOTE");
    segment(&mut bytes, 1, 1, 512, 0x100000, 0x400000, 9, 16);
    // A second physical range has no retained bytes; it is not zero-filled.
    segment(&mut bytes, 2, 1, 521, 0x200000, 0x800000, 0, 32);
    bytes[512..].copy_from_slice(b"xxxneedle");
    bytes
}

#[allow(clippy::too_many_arguments)]
fn segment(
    bytes: &mut [u8],
    index: usize,
    kind: u32,
    offset: u64,
    virtual_address: u64,
    physical_address: u64,
    captured: u64,
    memory: u64,
) {
    let start = 64 + index * 56;
    bytes[start..start + 4].copy_from_slice(&kind.to_le_bytes());
    for (field, value) in [
        (8, offset),
        (16, virtual_address),
        (24, physical_address),
        (32, captured),
        (40, memory),
    ] {
        bytes[start + field..start + field + 8].copy_from_slice(&value.to_le_bytes());
    }
}

#[test]
fn physical_ram_matches_without_scanning_notes_or_inventing_virtual_addresses() {
    let fixture = Fixture::new();
    let path = fixture.dump(&elf());
    assert!(
        crate::core_dump::CoreDump::open(&path)
            .unwrap_err()
            .to_string()
            .contains("QEMU physical")
    );
    assert_eq!(memory_blocks(&path, false), 1);
    assert_eq!(memory_blocks(&path, true), 0);
    let rules = yara_x::compile("rule ram_only { strings: $a = \"needle\" condition: $a } rule note_only { strings: $a = \"NOTE\" condition: $a }").unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    let mut report = Report::empty(
        Engine::Yara,
        Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        },
    );
    let mut budget = super::super::super::RuleTextBudget::new();
    let mut total = 0;
    let mut progress = super::super::super::runner::ProgressWriter::new(&fixture.0);
    let mut pass = MemoryPass {
        sources: &[],
        budget: &mut budget,
        total: &mut total,
        deadline: Instant::now() + Duration::from_secs(10),
        progress: &mut progress,
        block_index: 0,
        block_total: 1,
        gaps: 0,
    };
    let result = scan_core(&mut scanner, &path, false, &mut report, &mut pass);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(pass.gaps, 2);
    assert_eq!(pass.block_index, 1);
    assert_eq!(*pass.total, 9);
    let input = inputs::memory_input(
        InputKind::MemoryDump,
        &path,
        &result,
        pass.block_index,
        pass.gaps,
    );
    // The engine finished what was captured; the gaps are a note, not a failure.
    assert_eq!(input.outcome, InputOutcome::Succeeded);
    assert!(input.reason.contains("missing from the dump"));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].title, "ram_only");
    assert!(matches!(
        report.findings[0].evidence[0],
        Evidence::Bytes {
            offset: Some(515),
            address: None,
            ..
        }
    ));
}

#[test]
fn truncated_ram_is_available_only_to_the_end_of_the_file() {
    let fixture = Fixture::new();
    let mut bytes = elf();
    bytes.truncate(516);
    let path = fixture.dump(&bytes);
    let mappings = super::mappings(&mut fs::File::open(path).unwrap()).unwrap();
    assert_eq!(mappings[0].start, 0x400000);
    assert_eq!(mappings[0].available_size, 4);
    assert_eq!(mappings[0].captured_size, 9);
}

#[test]
fn physical_metadata_rejects_overflow_overlaps_and_excessive_tables() {
    let fixture = Fixture::new();
    for case in 0..7 {
        let mut bytes = elf();
        match case {
            0 => bytes.truncate(100),
            1 => segment(&mut bytes, 1, 1, u64::MAX, 0, 4096, 9, 16),
            2 => segment(&mut bytes, 1, 1, 512, 0, u64::MAX, 9, 16),
            3 => segment(&mut bytes, 1, 1, 512, 0, 4096, 17, 16),
            4 => segment(&mut bytes, 2, 1, 521, 0, 0x400001, 0, 32),
            5 => bytes[56..58].copy_from_slice(&u16::MAX.to_le_bytes()),
            6 => {
                bytes[64..68].fill(0);
                bytes[120..124].fill(0);
                bytes[176..180].fill(0);
            }
            _ => unreachable!(),
        }
        let path = fixture.dump(&bytes);
        assert!(
            super::mappings(&mut fs::File::open(path).unwrap()).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn physical_scan_obeys_existing_shared_input_budget() {
    let fixture = Fixture::new();
    let path = fixture.dump(&elf());
    let rules = yara_x::compile("rule fixture { condition: true }").unwrap();
    let mut scanner = yara_x::Scanner::new(&rules);
    let mut report = Report::empty(
        Engine::Yara,
        Identity {
            vm_id: "v".into(),
            boot_id: "b".into(),
            run_id: "r".into(),
            root_cookie: 1,
        },
    );
    let mut budget = super::super::super::RuleTextBudget::new();
    let mut progress = super::super::super::runner::ProgressWriter::new(&fixture.0);
    let mut total = TOTAL_SIZE;
    let mut pass = MemoryPass {
        sources: &[],
        budget: &mut budget,
        total: &mut total,
        deadline: Instant::now() + Duration::from_secs(10),
        progress: &mut progress,
        block_index: 0,
        block_total: 1,
        gaps: 0,
    };
    assert!(
        scan_core(&mut scanner, &path, false, &mut report, &mut pass)
            .unwrap_err()
            .contains("budget")
    );
    assert_eq!(pass.block_index, 0);
    assert!(report.findings.is_empty());
}

#[test]
fn upstream_kobalos_rule_matches_ram_in_the_complete_scan_pipeline() {
    let fixture = Fixture::new();
    let mut bytes = elf();
    bytes.resize(528, 0);
    segment(&mut bytes, 1, 1, 512, 0, 0x400000, 16, 16);
    bytes[176..180].fill(0);
    bytes[512..].copy_from_slice(&[
        0xAE, 0x0E, 0x05, 0x09, 0x0F, 0x3A, 0xC2, 0xB5, 0x0B, 0x1B, 0xC6, 0xE9, 0x1D, 0x2F, 0xE3,
        0xCE,
    ]);
    let memory = fixture.0.join("ram");
    crate::storage::private_dir(&memory).unwrap();
    fs::write(memory.join("memory.elf"), bytes).unwrap();
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/assets/rules/yara-forge-core.yar"
    ));
    let rule = crate::ruleset::yara_rule_source(source, "ESET_Kobalos").unwrap();
    let rules = fixture.0.join("upstream.yar");
    fs::write(&rules, &rule).unwrap();
    crate::storage::atomic_json(&fixture.0.join("artifacts.json"), &serde_json::json!({"run_id":"r","vm_id":"v","boot_id":"b","network_captures":[],"network_state":"complete","memory_dump":memory,"memory_state":"complete","core_dump":null,"core_state":"complete","issues":[]})).unwrap();
    let staged = Staged {
        request: super::super::super::runner::Request {
            engine: Engine::Yara,
            identity: Identity {
                vm_id: "v".into(),
                boot_id: "b".into(),
                run_id: "r".into(),
                root_cookie: 1,
            },
            directory: fixture.0.clone(),
            settings: Settings {
                scan_memory: true,
                ..Settings::default()
            },
            source_digest: None,
            frozen: None,
        },
        yara_sources: vec![super::super::super::runner::RuleFile {
            path: rules,
            name: "upstream.yar".into(),
            sha256: crate::storage::sha256_hex(rule.as_bytes()),
        }],
        sigma_sources: vec![],
        ids_sources: vec![],
        captures: vec![],
        journal: None,
        warnings: vec![],
        selection: String::new(),
        no_rules: false,
        include_dir: None,
        skipped_inputs: vec![],
        unstaged: vec![],
    };
    let report = scan(&staged, &fixture.0).unwrap();
    assert_eq!(report.findings.len(), 1, "{report:?}");
    assert_eq!(report.findings[0].title, "ESET_Kobalos");
    let inputs = report.inputs.unwrap();
    assert!(
        inputs
            .iter()
            .any(|input| input.kind == InputKind::MemoryDump
                && input.outcome == InputOutcome::Succeeded),
        "{inputs:?}"
    );
    assert!(
        inputs
            .iter()
            .any(|input| input.kind == InputKind::Executable
                && input.outcome == InputOutcome::Skipped)
    );
}

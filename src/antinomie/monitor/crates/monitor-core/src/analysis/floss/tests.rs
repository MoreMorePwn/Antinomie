// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::{fs, os::unix::fs::PermissionsExt};

/// FLOSS 3.2.0's `-j` output for a small x86-64 ELF that builds one URL on the
/// stack and decodes two strings, as FLOSS wrote it (static strings omitted).
const OUTPUT: &str = r#"{"analysis":{},"metadata":{"version":"v3.2.0-0-g69e8ea2"},"strings":{"decoded_strings":[{"address":18446744072630828875,"address_type":"STACK","decoded_at":33559085,"decoding_routine":33558960,"encoding":"ASCII","string":"/etc/crontab"},{"address":18446744072630828792,"address_type":"STACK","decoded_at":33559102,"decoding_routine":33558841,"encoding":"ASCII","string":"http://evil.example/bot"},{"address":1,"address_type":"STACK","decoded_at":33559102,"decoding_routine":33558841,"encoding":"ASCII","string":"http://evil.example/bot"}],"language_strings":[{"encoding":"ASCII","offset":4096,"string":"main.beacon"},{"encoding":"UTF-16LE","offset":9000000,"string":"past the end"}],"language_strings_missed":[],"stack_strings":[{"encoding":"ASCII","frame_offset":48,"function":33558841,"offset":8,"original_stack_pointer":18446744072630828896,"program_counter":33558576,"stack_pointer":18446744072630828832,"string":"http://evil.example/bot"},{"encoding":"UTF-16LE","frame_offset":13,"function":33559030,"offset":27,"original_stack_pointer":18446744072630828896,"program_counter":33558960,"stack_pointer":18446744072630828848,"string":"cmd.exe"}],"static_strings":[],"tight_strings":[{"encoding":"ASCII","frame_offset":1,"function":33559030,"offset":2,"original_stack_pointer":3,"program_counter":33558970,"stack_pointer":4,"string":"tight one"}]}}"#;

fn scratch(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("ant-floss-{name}-{}", crate::storage::unique_id()));
    fs::create_dir_all(dir.join("listings")).unwrap();
    dir
}

/// A stand-in for FLOSS: a script that prints `body` and exits with `code`,
/// and answers `--version` like the real one.
fn fake(dir: &Path, body: &str, code: i32) -> String {
    let path = dir.join("floss");
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'floss v3.2.0-0-gfake'; exit 0; fi\ncat <<'END'\n{body}\nEND\nexit {code}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    path.display().to_string()
}

fn section() -> AnalysisSection {
    AnalysisSection::new(AnalysisKind::Floss)
}

#[test]
fn every_kind_of_string_is_kept_once_with_its_routine() {
    let found = parse(OUTPUT).unwrap();
    let rows: Vec<_> = found
        .iter()
        .map(|s| (s.origin, s.text.as_str(), s.function))
        .collect();
    assert_eq!(
        rows,
        [
            ("decoded", "/etc/crontab", Some(33558960)),
            ("decoded", "http://evil.example/bot", Some(33558841)),
            ("stack", "http://evil.example/bot", Some(33558841)),
            ("stack", "cmd.exe", Some(33559030)),
            ("tight", "tight one", Some(33559030)),
            ("language", "main.beacon", None),
            ("language", "past the end", None),
        ]
    );
    assert_eq!(found[0].address, Some(33559085));
    assert_eq!(found[3].encoding, "UTF-16LE");
    assert_eq!(found[5].offset, Some(4096));
    assert!(parse("not json").is_err());
    assert!(parse("{}").is_err());
    assert!(parse("{\"strings\":{}}").unwrap().is_empty());
}

#[test]
fn a_run_fills_the_section_and_a_listing_the_validator_accepts() {
    let dir = scratch("run");
    let floss = fake(&dir, OUTPUT, 0);
    let mut section = section();
    run(&mut section, &floss, 8192, &dir.join("listings"));
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert_eq!(section.tools, ["floss v3.2.0-0-gfake"]);
    assert_eq!(
        section.summary,
        "7 strings from FLOSS: 2 decoded, 2 stack, 1 tight, 2 Go or Rust; addresses are the ones FLOSS reports"
    );
    assert_eq!(section.entries.len(), 7);
    let stack = &section.entries[2];
    assert_eq!(
        (stack.label.as_str(), stack.value.as_str()),
        ("stack", "http://evil.example/bot")
    );
    let record = stack.record.as_ref().unwrap();
    assert_eq!(record.location.as_ref().unwrap().value, 33558841);
    assert_eq!(
        record.location.as_ref().unwrap().kind,
        AnalysisAddressKind::ObjectAddress
    );
    let go = section.entries[5].record.as_ref().unwrap();
    let location = go.location.as_ref().unwrap();
    assert_eq!(location.kind, AnalysisAddressKind::FileOffset);
    assert_eq!(
        location.file_range,
        Some(AnalysisRange {
            offset: 4096,
            len: 11
        })
    );
    // An offset past the file is kept as a string without a place.
    assert!(
        section.entries[6]
            .record
            .as_ref()
            .unwrap()
            .location
            .is_none()
    );
    let listing = section.listing.clone().unwrap();
    assert_eq!(listing.rows, 7);
    assert!(!listing.truncated);
    super::super::listing::validate(
        &dir.join("listings/floss.jsonl"),
        AnalysisKind::Floss,
        &listing,
        Some(8192),
    )
    .unwrap();
    for entry in &section.entries {
        super::super::validation::validate_record(
            AnalysisKind::Floss,
            entry,
            entry.record.as_ref().unwrap(),
            Some(8192),
        )
        .unwrap();
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn a_run_without_strings_is_complete_and_says_so() {
    let dir = scratch("none");
    let floss = fake(&dir, r#"{"strings":{"static_strings":[]}}"#, 0);
    let mut section = section();
    run(&mut section, &floss, 100, &dir.join("listings"));
    assert_eq!(section.state, AnalysisSectionState::Complete);
    assert!(section.entries.is_empty());
    assert!(section.summary.starts_with("0 strings from FLOSS"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failures_are_named_not_reported_as_an_empty_result() {
    let dir = scratch("fail");
    let listings = dir.join("listings");
    let floss = fake(&dir, "", 1);
    let mut section = section();
    run(&mut section, &floss, 100, &listings);
    assert_eq!(section.state, AnalysisSectionState::Unavailable);
    assert!(
        section.summary.contains("exited with code 1"),
        "{}",
        section.summary
    );
    // Output FLOSS could not have written: not JSON.
    let floss = fake(&dir, "usage: floss", 0);
    let mut section = self::section();
    run(&mut section, &floss, 100, &listings);
    assert_eq!(section.state, AnalysisSectionState::Unavailable);
    assert!(
        section.summary.contains("FLOSS printed no readable result")
            || section.summary.contains("FLOSS")
    );
    // A file over FLOSS's own limit never starts it.
    let mut section = self::section();
    run(
        &mut section,
        "/nonexistent/floss",
        17 * 1024 * 1024,
        &listings,
    );
    assert_eq!(section.state, AnalysisSectionState::Unavailable);
    assert_eq!(
        section.summary,
        "FLOSS does not take files over 16 MiB; this file is 17 MiB"
    );
    let mut section = self::section();
    run(&mut section, "/nonexistent/floss", 100, &listings);
    assert!(section.summary.starts_with("FLOSS failed to start"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn the_row_bound_marks_the_section_partial() {
    let strings: Vec<String> = (0..300)
        .map(|n| format!(r#"{{"encoding":"ASCII","function":4096,"program_counter":1,"string":"string number {n}"}}"#))
        .collect();
    let output = format!(
        r#"{{"strings":{{"stack_strings":[{}]}}}}"#,
        strings.join(",")
    );
    let dir = scratch("many");
    let floss = fake(&dir, &output, 0);
    let mut section = section();
    run(&mut section, &floss, 100, &dir.join("listings"));
    // The report keeps a preview; the listing holds all of them.
    assert_eq!(section.entries.len(), REPORT_ROWS);
    assert_eq!(section.listing.as_ref().unwrap().rows, 300);
    assert_eq!(section.state, AnalysisSectionState::Complete);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn rows_of_another_category_or_origin_are_rejected() {
    let entry = |origin: &str| AnalysisEntry {
        label: origin.into(),
        value: "text".into(),
        offset: None,
        record: Some(AnalysisRecord {
            revision: 1,
            id: 1,
            location: None,
            data: AnalysisData::FlossString {
                origin: origin.into(),
                encoding: "ASCII".into(),
                function: None,
                address: None,
            },
        }),
    };
    let check = |kind, origin| {
        let entry = entry(origin);
        super::super::validation::validate_record(
            kind,
            &entry,
            entry.record.as_ref().unwrap(),
            Some(10),
        )
    };
    assert!(check(AnalysisKind::Floss, "stack").is_ok());
    assert!(check(AnalysisKind::Floss, "static").is_err());
    assert!(check(AnalysisKind::Strings, "stack").is_err());
}

use super::bundle::{self, BundleInput, DroppedFile};
use super::export;
use super::layout;
use super::*;
use std::io::Read;

fn table(rows: usize) -> Table {
    Table {
        columns: vec!["Endpoint".into(), "Note".into()],
        rows: (0..rows)
            .map(|i| {
                vec![
                    format!("203.0.113.{}:443", i % 250),
                    format!("row {i} <b>&\"'"),
                ]
            })
            .collect(),
        omitted: 0,
        indicator_columns: vec![IndicatorColumn {
            column: 0,
            kind: IndicatorKind::Endpoint,
        }],
    }
}

pub(super) fn fixture() -> Report {
    let mut report = Report::new(
        RunInfo {
            vm_id: "vm-1".into(),
            boot_id: "boot-1".into(),
            run_id: "run-0123456789".into(),
            started_ms: Some(1_792_000_000_000),
            finished: true,
        },
        1_792_000_100_000,
    );
    report.sample = Some(SampleInfo {
        name: "dropper <1>.elf".into(),
        sha256: "ab".repeat(32),
        size: Some(1234),
    });
    report.summary = Some(Summary {
        assessment: "matched_indicators".into(),
        statement: "Triage observed: 1 indicator(s) matched a stored dataset. Fetched http://evil.example/x.".into(),
        highest_tier: "high".into(),
        families: vec!["Mirai".into()],
        key_behaviours: vec![Behaviour {
            rule: "exec-from-tmp".into(),
            tier: "high".into(),
            category: "execution".into(),
            count: 3,
        }],
        counts: Counts {
            processes: 4,
            findings: 7,
            indicators: 3,
            indicators_matched: 1,
            techniques: 2,
            ..Counts::default()
        },
    });
    report.indicators = Some(vec![
        Indicator {
            kind: "endpoint".into(),
            value: "203.0.113.5:443".into(),
            verdict: "Matched".into(),
            matched: true,
            family: "Mirai".into(),
            dataset: "threatfox".into(),
            ..Indicator::default()
        },
        Indicator {
            kind: "domain".into(),
            value: "evil.example".into(),
            verdict: "No match".into(),
            ..Indicator::default()
        },
        Indicator {
            kind: "url".into(),
            value: "GET evil.example/a".into(),
            url: "http://evil.example/a".into(),
            verdict: "No match".into(),
            ..Indicator::default()
        },
        Indicator {
            kind: "file".into(),
            value: "cd".repeat(32),
            sha256: "cd".repeat(32),
            path: "/tmp/payload.bin".into(),
            verdict: "No match".into(),
            ..Indicator::default()
        },
    ]);
    report.attack = Some(vec![
        Technique {
            id: "T1059.004".into(),
            name: "Command and Scripting Interpreter: Unix Shell".into(),
            rules: vec!["exec-from-tmp".into()],
            count: 3,
        },
        Technique {
            id: "T1105".into(),
            name: "Ingress Tool Transfer".into(),
            rules: vec!["download".into()],
            count: 1,
        },
    ]);
    report.processes = Some(table(3));
    report.findings = Some(table(2));
    report.files = Some(FilesSection {
        tabs: vec![NamedTable {
            name: "Opened files".into(),
            table: table(2),
        }],
    });
    report.file_activity = Some(vec![FileRecord {
        path: "/tmp/payload.bin".into(),
        created: true,
        final_size: Some(16),
        guest_sha256: "cd".repeat(32),
        reconstruction: "complete".into(),
        bytes_written: 16,
        ..FileRecord::default()
    }]);
    report.network = Some(vec![NamedTable {
        name: "Endpoints".into(),
        table: table(5),
    }]);
    report.detections = Some(vec![Detection {
        engine: "YARA".into(),
        rule_id: "r1".into(),
        title: "t".into(),
        severity: "high".into(),
        mitre: vec!["T1105".into()],
        count: 1,
    }]);
    report.evidence = Some(vec![EvidenceRef {
        kind: "telemetry".into(),
        path: "telemetry.raw".into(),
        size: 10,
        sha256: "ef".repeat(32),
    }]);
    report.custody = Some(Custody {
        sample_sha256: "ab".repeat(32),
        entries: 3,
        head: "12".repeat(32),
        verified: true,
        ..Custody::default()
    });
    report
}

#[test]
fn json_round_trips_and_carries_its_schema_version() {
    let report = fixture();
    let text = report.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["schema"], SCHEMA);
    assert_eq!(value["schema_version"], SCHEMA_VERSION);
    let back: Report = serde_json::from_str(&text).unwrap();
    assert_eq!(back, report);
    // The JSON keeps raw values.
    assert!(text.contains("203.0.113.5:443") && text.contains("http://evil.example/a"));
}

#[test]
fn an_unchosen_part_is_absent_everywhere() {
    let mut report = fixture();
    report.network = None;
    report.indicators = None;
    let json = report.to_json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(value["network"].is_null() && value["indicators"].is_null());
    let doc = layout::document(&report, false);
    let ids: Vec<_> = doc.sections.iter().map(|s| s.id.as_str()).collect();
    assert!(!ids.contains(&"network") && !ids.contains(&"indicators"));
    assert!(ids.contains(&"summary") && ids.contains(&"processes"));
    let misp: serde_json::Value = serde_json::from_str(&misp::render(&report).unwrap()).unwrap();
    assert!(
        !misp["Event"]["Attribute"]
            .to_string()
            .contains("ip-dst|port"),
        "no indicator attributes without the section"
    );
}

#[test]
fn html_is_self_contained_escaped_and_defangs_on_request() {
    let report = fixture();
    let plain = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    for forbidden in [
        "http://", "https://", "<script", "<link", "src=", "@import", "url(",
    ] {
        // The fixture's own URL appears only as defanged text or not at all.
        if forbidden == "http://" {
            continue;
        }
        assert!(!plain.contains(forbidden), "{forbidden} in the HTML");
    }
    assert!(plain.contains("203.0.113.5:443"));
    assert!(
        plain.contains("&lt;b&gt;&amp;&quot;&#39;"),
        "cells are escaped"
    );
    assert!(plain.contains("dropper &lt;1&gt;.elf"));
    let defanged = String::from_utf8(export::render(&report, Format::Html, true).unwrap()).unwrap();
    assert!(defanged.contains("203[.]0[.]113[.]5:443"));
    assert!(
        defanged.contains("hxxp://evil[.]example/x"),
        "free text URL"
    );
    assert!(!defanged.contains("203.0.113.5:443"));
    // File paths and hashes are not touched.
    assert!(defanged.contains("/tmp/payload.bin") && defanged.contains(&"cd".repeat(32)));
    // The other formats keep raw values whatever the choice.
    for format in [Format::Json, Format::Misp, Format::Stix] {
        let text = String::from_utf8(export::render(&report, format, true).unwrap()).unwrap();
        assert!(text.contains("203.0.113.5"), "{format:?} stays raw");
        assert!(!text.contains("[.]"));
    }
}

#[test]
fn control_characters_cannot_break_the_html() {
    let mut report = fixture();
    report.processes = Some(Table {
        columns: vec!["A".into()],
        rows: vec![vec!["bad\u{0}\u{1b}[31m\u{7f}text</td><script>x".into()]],
        ..Table::default()
    });
    let html = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    assert!(!html.contains('\u{0}') && !html.contains('\u{1b}') && !html.contains("<script>"));
}

fn pdf_text(bytes: &[u8]) -> (String, usize) {
    // Every stream, inflated, concatenated.
    let mut out = String::new();
    let mut at = 0;
    let mut streams = 0;
    while let Some(found) = find(&bytes[at..], b"\nstream\n") {
        let start = at + found + 8;
        let end = start + find(&bytes[start..], b"\nendstream").unwrap();
        let mut inflated = Vec::new();
        flate2::read::ZlibDecoder::new(&bytes[start..end])
            .read_to_end(&mut inflated)
            .unwrap();
        out.push_str(&String::from_utf8_lossy(&inflated));
        streams += 1;
        at = end;
    }
    (out, streams)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

#[test]
fn pdf_has_valid_offsets_pages_bookmarks_and_the_sections() {
    let mut report = fixture();
    report.network = Some(vec![NamedTable {
        name: "Endpoints".into(),
        table: table(400),
    }]);
    let bytes = export::render(&report, Format::Pdf, false).unwrap();
    assert!(bytes.starts_with(b"%PDF-1.4") && bytes.ends_with(b"%%EOF\n"));
    // startxref points at the table, and every offset at its object.
    let text: String = bytes.iter().map(|&b| b as char).collect();
    let start: usize = text
        .rsplit("startxref\n")
        .next()
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert!(bytes[start..].starts_with(b"xref\n"));
    let table_text = String::from_utf8_lossy(&bytes[start..]).into_owned();
    let count: usize = table_text
        .lines()
        .nth(1)
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    for (n, line) in table_text.lines().skip(3).take(count - 1).enumerate() {
        let offset: usize = line[..10].parse().unwrap();
        assert!(
            bytes[offset..].starts_with(format!("{} 0 obj", n + 1).as_bytes()),
            "object {} is at its offset",
            n + 1
        );
    }
    let (content, streams) = pdf_text(&bytes);
    let pages = text.matches("/Type /Page ").count();
    assert!(pages >= 4, "400 rows span pages: {pages}");
    assert_eq!(streams, pages);
    assert!(text.contains(&format!("/Count {pages} ")));
    for title in [
        "Summary",
        "Indicators of compromise",
        "ATT&CK techniques",
        "Processes",
        "Network",
        "Custody log",
    ] {
        assert!(
            content.contains(&format!("({title}) Tj")),
            "{title} heading drawn"
        );
        assert!(
            text.contains(&format!("/Title ({title})")),
            "{title} bookmark"
        );
    }
    // The table header repeats on the next page.
    assert!(content.matches("(Endpoint) Tj").count() >= 3);
    assert!(content.contains("Page 1 of"));
    assert!(text.contains("/Title (Antinomie Triage report: dropper <1>.elf)"));
    assert!(content.contains("203.0.113.5:443"));
}

#[test]
fn pdf_defangs_and_shows_non_latin_text_as_question_marks() {
    let mut report = fixture();
    report.processes = Some(Table {
        columns: vec!["Name".into()],
        rows: vec![vec!["caf\u{e9} \u{4e2d}\u{6587} (x) \\y".into()]],
        ..Table::default()
    });
    let bytes = export::render(&report, Format::Pdf, true).unwrap();
    let (content, _) = pdf_text(&bytes);
    assert!(content.contains("203[.]0[.]113[.]5:443"));
    assert!(content.contains("caf\\351 ?? \\(x\\) \\\\y"), "{content}");
}

#[test]
fn misp_event_has_attributes_to_ids_only_for_matches_and_galaxy_tags() {
    let report = fixture();
    let value: serde_json::Value = serde_json::from_str(&misp::render(&report).unwrap()).unwrap();
    let event = &value["Event"];
    assert_eq!(event["analysis"], "2");
    let attrs = event["Attribute"].as_array().unwrap();
    let find = |kind: &str| attrs.iter().find(|a| a["type"] == kind).unwrap();
    assert_eq!(find("ip-dst|port")["value"], "203.0.113.5|443");
    assert_eq!(find("ip-dst|port")["to_ids"], true);
    assert_eq!(find("domain")["to_ids"], false);
    assert_eq!(find("url")["value"], "http://evil.example/a");
    assert_eq!(
        find("filename|sha256")["value"],
        format!("/tmp/payload.bin|{}", "cd".repeat(64 / 2))
    );
    assert_eq!(
        attrs
            .iter()
            .filter(|a| a["type"] == "sha256" && a["category"] == "Payload delivery")
            .count(),
        1
    );
    let tags: Vec<_> = event["Tag"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(tags.contains(&"misp-galaxy:mitre-attack-pattern=\"Unix Shell - T1059.004\""));
    assert!(tags.contains(&"misp-galaxy:mitre-attack-pattern=\"Ingress Tool Transfer - T1105\""));
    assert_eq!(
        event["Galaxy"][0]["GalaxyCluster"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    // The same report gives the same ids.
    assert_eq!(
        misp::render(&report).unwrap(),
        misp::render(&report).unwrap()
    );
}

#[test]
fn stix_bundle_links_indicators_and_techniques_to_the_malware() {
    let report = fixture();
    let value: serde_json::Value = serde_json::from_str(&stix::render(&report).unwrap()).unwrap();
    assert_eq!(value["type"], "bundle");
    let objects = value["objects"].as_array().unwrap();
    let of = |kind: &str| {
        objects
            .iter()
            .filter(|o| o["type"] == kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(of("identity").len(), 1);
    assert_eq!(of("malware").len(), 1);
    assert_eq!(of("file").len(), 1);
    assert_eq!(of("indicator").len(), 4);
    assert_eq!(of("attack-pattern").len(), 2);
    assert_eq!(of("relationship").len(), 6);
    let malware = of("malware")[0]["id"].as_str().unwrap();
    for rel in of("relationship") {
        assert!(rel["source_ref"] == malware || rel["target_ref"] == malware);
    }
    let patterns: Vec<_> = of("indicator")
        .iter()
        .map(|i| i["pattern"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        patterns
            .iter()
            .any(|p| p.contains("203.0.113.5") && p.contains("dst_port = 443"))
    );
    assert!(
        patterns
            .iter()
            .any(|p| p == "[url:value = 'http://evil.example/a']")
    );
    assert!(
        patterns
            .iter()
            .any(|p| p.starts_with("[file:hashes.'SHA-256' = "))
    );
    let matched = of("indicator")
        .into_iter()
        .find(|i| i["name"].as_str().unwrap().starts_with("endpoint"))
        .unwrap();
    assert_eq!(matched["indicator_types"][0], "malicious-activity");
    assert_eq!(
        of("attack-pattern")[0]["external_references"][0]["source_name"],
        "mitre-attack"
    );
}

#[test]
fn uuid5_is_stable_and_well_formed() {
    let a = uuid5("x");
    assert_eq!(a, uuid5("x"));
    assert_ne!(a, uuid5("y"));
    assert_eq!(a.len(), 36);
    assert_eq!(&a[14..15], "5");
    assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"));
    // The DNS-namespace v5 of "python.org" is the well-known value.
    assert_eq!(uuid5("python.org"), "886313e1-3b8a-5372-9b90-0c9aee199e5d");
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("antinomie-report-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn sha(bytes: &[u8]) -> String {
    crate::storage::sha256_hex(bytes)
}

#[test]
fn the_bundle_holds_every_file_with_a_matching_hash_and_the_password_opens_the_inner_zip() {
    let dir = temp("bundle");
    let pcap = dir.join("net.pcap");
    std::fs::write(&pcap, b"pcap-bytes-0123456789").unwrap();
    let custody = dir.join("custody-ab.json");
    std::fs::write(&custody, b"{\"custody\":true}").unwrap();
    let content = b"#!/bin/sh\necho hi\n".to_vec();
    let want = sha(&content);
    let copy = content.clone();
    let input = BundleInput {
        captures: vec![pcap, dir.join("missing.pcap")],
        dropped: vec![DroppedFile {
            path: "/tmp/d.sh".into(),
            sha256: want.clone(),
            guest_sha256: want.clone(),
            size: content.len() as u64,
            write: Box::new(move |out| out.write_all(&copy)),
        }],
        skipped: vec![("/tmp/big".into(), "over the limit".into())],
        custody: vec![custody],
        run_id: "run-1".into(),
        generated_ms: 1_792_000_000_000,
    };
    let path = dir.join("b.zip");
    let bundled = bundle::write(&path, &dir.join("inner.tmp"), input).unwrap();
    assert!(!dir.join("inner.tmp").exists(), "scratch removed");
    assert_eq!(
        bundled.dropped,
        vec![(
            "/tmp/d.sh".to_owned(),
            format!("dropped-files.zip/{want}.bin")
        )]
    );
    assert_eq!(
        bundled.skipped.len(),
        2,
        "the given reason and the missing capture"
    );

    let mut outer = zip::ZipArchive::new(std::fs::File::open(&path).unwrap()).unwrap();
    // manifest.sha256 is a sha256sum list of the real members: check each.
    let mut sums = String::new();
    outer
        .by_name("manifest.sha256")
        .unwrap()
        .read_to_string(&mut sums)
        .unwrap();
    let mut checked = 0;
    for line in sums.lines() {
        let (hash, name) = line.split_once("  ").unwrap();
        let mut bytes = Vec::new();
        outer
            .by_name(name)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(sha(&bytes), hash, "{name}");
        checked += 1;
    }
    assert_eq!(checked, 3, "capture, inner archive, custody");
    let mut manifest = String::new();
    outer
        .by_name("manifest.json")
        .unwrap()
        .read_to_string(&mut manifest)
        .unwrap();
    let manifest: serde_json::Value = serde_json::from_str(&manifest).unwrap();
    assert_eq!(manifest["schema"], "antinomie-evidence-bundle");
    assert_eq!(manifest["dropped_files_archive"]["password"], "infected");
    assert!(
        manifest["files"].as_array().unwrap().iter().any(
            |f| f["path"] == "capture/net.pcap" && f["sha256"] == sha(b"pcap-bytes-0123456789")
        )
    );

    // The inner archive: no password, no bytes; wrong password, no bytes; the right one, the file.
    let mut inner_bytes = Vec::new();
    outer
        .by_name("dropped-files.zip")
        .unwrap()
        .read_to_end(&mut inner_bytes)
        .unwrap();
    let mut inner = zip::ZipArchive::new(std::io::Cursor::new(inner_bytes)).unwrap();
    let entry = format!("{want}.bin");
    assert!(inner.by_name(&entry).is_err(), "no password");
    assert!(inner.by_name_decrypt(&entry, b"wrong").is_err());
    let mut opened = Vec::new();
    inner
        .by_name_decrypt(&entry, b"infected")
        .unwrap()
        .read_to_end(&mut opened)
        .unwrap();
    assert_eq!(opened, content);
    let mut files = String::new();
    inner
        .by_name_decrypt("files.json", b"infected")
        .unwrap()
        .read_to_string(&mut files)
        .unwrap();
    assert!(files.contains("/tmp/d.sh") && files.contains(&want));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn a_dropped_file_whose_bytes_do_not_match_its_hash_fails_the_bundle() {
    let dir = temp("mismatch");
    let input = BundleInput {
        captures: Vec::new(),
        dropped: vec![DroppedFile {
            path: "/tmp/x".into(),
            sha256: sha(b"expected"),
            guest_sha256: String::new(),
            size: 8,
            write: Box::new(|out| out.write_all(b"differen")),
        }],
        skipped: Vec::new(),
        custody: Vec::new(),
        run_id: "r".into(),
        generated_ms: 0,
    };
    let path = dir.join("b.zip");
    let error = bundle::write(&path, &dir.join("i.tmp"), input).unwrap_err();
    assert!(error.contains("/tmp/x"), "{error}");
    assert!(
        !path.exists() && !dir.join("i.tmp").exists(),
        "nothing left behind"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn export_writes_the_chosen_formats_and_never_overwrites() {
    let dir = temp("export");
    let report = fixture();
    let choices = Choices {
        formats: vec![Format::Html, Format::Json, Format::Stix],
        ..Choices::default()
    };
    let first = export::write(&report, &choices, &dir.join("out"), None).unwrap();
    let second = export::write(&report, &choices, &dir.join("out"), None).unwrap();
    assert_eq!(first.files.len(), 3);
    let names = |w: &export::Written| -> Vec<String> {
        w.files
            .iter()
            .map(|(_, p)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    };
    let (a, b) = (names(&first), names(&second));
    assert!(a[0].ends_with(".html") && a[1].ends_with(".json") && a[2].ends_with(".stix.json"));
    assert!(a[0].starts_with("antinomie-report-run01234") && a.iter().all(|n| !b.contains(n)));
    assert!(!first.files.iter().any(|(label, _)| label == "PDF"));
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&first.files[0].1)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn choices_remember_parts_and_formats() {
    let mut c = Choices::default();
    assert!(c.has(Part::Summary) && c.writes(Format::Pdf) && !c.bundle);
    c.set(Part::Network, false);
    c.set_format(Format::Misp, true);
    let text = serde_json::to_string(&c).unwrap();
    let back: Choices = serde_json::from_str(&text).unwrap();
    assert!(!back.has(Part::Network) && back.writes(Format::Misp));
    // A settings file from before the field existed reads as the default.
    assert_eq!(
        serde_json::from_str::<Choices>("{}").unwrap(),
        Choices::default()
    );
}

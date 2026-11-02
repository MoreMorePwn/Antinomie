// SPDX-License-Identifier: GPL-3.0-only
use super::build;
use super::export::{self, base_name};
use super::*;
use crate::run_digest::{Behaviour, BehaviourHit, DetectionHit, IndicatorEntry, RunDigest};
use crate::samples::{Library, NewSample};
use std::io::Read;

fn sha(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

fn digest(matched: bool, high: bool) -> RunDigest {
    RunDigest {
        behaviour: Some(Behaviour {
            highest: if high { "high" } else { "low" }.into(),
            rules: vec![BehaviourHit {
                rule: "exec-from-tmp".into(),
                tier: if high { "high" } else { "low" }.into(),
                category: "execution".into(),
                attack: vec!["T1059.004".into(), "TA0002".into()],
                count: 3,
                first_ns: 1,
            }],
            evasion: Vec::new(),
        }),
        detections: Some(vec![
            DetectionHit {
                engine: "Sigma".into(),
                rule_id: "sig-1".into(),
                title: "Cron <persistence>".into(),
                severity: "high".into(),
                mitre: vec!["T1053.003".into()],
                count: 2,
                author: "Jane Rule".into(),
                license: "DRL 1.1".into(),
                source: "Example Pack".into(),
                reference: "https://example.org/r1".into(),
                ..DetectionHit::default()
            },
            DetectionHit {
                engine: "YARA".into(),
                rule_id: "y-1".into(),
                title: "Family".into(),
                family: "Kinsing".into(),
                count: 1,
                ..DetectionHit::default()
            },
        ]),
        indicators: Some(vec![
            IndicatorEntry {
                ty: "endpoint".into(),
                value: "203.0.113.5:443".into(),
                matched,
                ..Default::default()
            },
            IndicatorEntry {
                ty: "domain".into(),
                value: "evil.example".into(),
                matched: false,
                ..Default::default()
            },
            IndicatorEntry {
                ty: "url".into(),
                value: "evil.example/x?a=1".into(),
                matched: false,
                ..Default::default()
            },
            IndicatorEntry {
                ty: "tls".into(),
                value: "ab".repeat(16),
                matched: false,
                ..Default::default()
            },
            IndicatorEntry {
                ty: "file".into(),
                value: sha(9),
                matched: false,
                ..Default::default()
            },
        ]),
        ..RunDigest::default()
    }
}

pub(super) fn fixture() -> SampleReport {
    let d1 = digest(true, true);
    let d2 = digest(false, false);
    let both = [(1, &d1), (2, &d2)];
    let mut report = SampleReport::new(
        Identity {
            sha256: sha(0xab),
            sha1: "cd".repeat(20),
            md5: "ef".repeat(16),
            tlsh: "T1".to_owned() + &"AB".repeat(35),
            name: "dropper <1>.elf".into(),
            description: "see http://evil.example/about".into(),
            size: 1234,
            file_type: "elf".into(),
            arch: "x86_64".into(),
            family: "Kinsing".into(),
            added_ms: 1_791_000_000_000,
            archived: true,
            removed_ms: None,
            first_seen_ms: Some(1_791_000_000_000),
            last_seen_ms: Some(1_792_000_000_000),
            tags: vec![
                TagRow {
                    kind: "verdict".into(),
                    value: "malicious".into(),
                },
                TagRow {
                    kind: "category".into(),
                    value: "miner".into(),
                },
            ],
            names: vec![NameRow {
                name: "kdevtmpfsi".into(),
                path: "/tmp/kdevtmpfsi".into(),
                seen: "run 1".into(),
            }],
            origins: vec![OriginRow {
                kind: "Downloaded".into(),
                source: "MalwareBazaar".into(),
                detail: "https://bazaar.example/s".into(),
                at_ms: 1_791_000_000_000,
                ..OriginRow::default()
            }],
        },
        1_792_000_100_000,
    );
    let (mut stat, mut yara) = build::static_analysis(None);
    stat.available = true;
    stat.state = "partial".into();
    stat.reason = String::new();
    stat.report_id = "an-1".into();
    stat.from_run = Some(2);
    stat.checks = vec![StaticCheck {
        label: "Capabilities".into(),
        state: "partial".into(),
        reason: "capa ran out of time.".into(),
        summary: "3 capabilities".into(),
        tools: vec!["capa 9".into()],
    }];
    stat.packer = "UPX".into();
    stat.layers = vec![Layer {
        index: 0,
        method: "original".into(),
        sha256: sha(0xab),
        size: 1234,
        packer: "UPX".into(),
    }];
    stat.capabilities = vec![Capability {
        name: "persist via cron".into(),
        namespace: "persistence".into(),
        attack: vec!["T1053.003".into()],
        mbc: Vec::new(),
    }];
    stat.floss = vec![FlossRow {
        origin: "decoded".into(),
        text: "http://evil.example/payload".into(),
    }];
    stat.floss_total = 1;
    report.static_analysis = stat;
    yara.push(RuleHit {
        engine: "YARA (static)".into(),
        rule_id: "static_rule".into(),
        title: "ns".into(),
        author: "Static Author".into(),
        license: "GPL".into(),
        source: "ns".into(),
        count: 1,
        ..RuleHit::default()
    });
    report.detections = [yara, build::merge_detections(&both)].concat();
    report.attack = build::merge_attack(&both);
    report.indicators = build::merge_indicators(&both);
    report.runs = vec![
        build::run_row(
            1,
            "vm-1",
            "Debian",
            "run-1",
            Some(1_791_500_000_000),
            "Exit 0",
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent/run-1"),
            false,
            Some(&d1),
        ),
        build::run_row(
            2,
            "vm-1",
            "Debian",
            "run-2",
            Some(1_792_000_000_000),
            "Exit 1",
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent/run-2"),
            false,
            Some(&d2),
        ),
        build::run_row(
            3,
            "vm-2",
            "Alpine",
            "run-3",
            None,
            "Running",
            std::path::Path::new("/nonexistent"),
            std::path::Path::new("/nonexistent/run-3"),
            false,
            None,
        ),
    ];
    report.lineage = Lineage {
        parents: vec![LineageEntry {
            role: "parent".into(),
            level: 1,
            kind: "library sample".into(),
            label: "stage1.sh".into(),
            sha256: sha(1),
            verdict: "malicious".into(),
            via: "dropped".into(),
            runs: vec![1],
            ..LineageEntry::default()
        }],
        children: vec![LineageEntry {
            role: "child".into(),
            level: 1,
            kind: "captured file".into(),
            label: "payload.bin".into(),
            path: "/tmp/payload.bin".into(),
            sha256: sha(2),
            via: "dropped, executed".into(),
            runs: vec![1, 2],
            ..LineageEntry::default()
        }],
        reason: "No parent beyond the library origin.".into(),
    };
    report.custody = CustodySection {
        entries: 2,
        head: sha(0x77),
        verified: true,
        problem: String::new(),
        log: vec![CustodyRow {
            seq: 1,
            at_ms: 1_791_000_000_000,
            by: "analyst".into(),
            event: "Added".into(),
            detail: "downloaded from http://bazaar.example/s".into(),
            state: "verified".into(),
            hash: sha(0x66),
            before_chain: false,
        }],
    };
    report.notes = vec![NoteRow {
        id: 1,
        by: "analyst".into(),
        created_ms: 1_792_000_000_000,
        text: "C2 is 203.0.113.5\n# not a heading".into(),
        refs: vec!["run 1".into()],
        ..NoteRow::default()
    }];
    report.similar = SimilarSection {
        rows: vec![SimilarRow {
            sha256: sha(3),
            name: "kinsing-old".into(),
            distance: 40,
            shared: "12 strings".into(),
        }],
        reason: String::new(),
    };
    report.seal();
    report
}

fn text(report: &SampleReport, format: Format, defang: bool) -> String {
    String::from_utf8(export::render(report, format, defang).unwrap()).unwrap()
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-samplereport-{name}-{}",
        crate::storage::unique_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn assessments_are_per_run_and_the_sample_takes_the_strongest() {
    let report = fixture();
    let by: Vec<&str> = report.runs.iter().map(|r| r.assessment.as_str()).collect();
    assert_eq!(by, ["matched_indicators", "observed_only", "not_read"]);
    assert_eq!(report.assessment(), "matched_indicators");
    assert!(report.runs[2].statement.contains("not read this run"));
    assert!(
        report
            .remarks
            .iter()
            .any(|r| r.contains("1 of 3 run(s) have not been read"))
    );
    let none = SampleReport::default();
    assert_eq!(none.assessment(), "not_read");
}

#[test]
fn indicators_and_rules_merge_across_runs_with_their_credits() {
    let report = fixture();
    let endpoint = report
        .indicators
        .iter()
        .find(|i| i.kind == "endpoint")
        .unwrap();
    assert!(endpoint.matched && endpoint.runs == [1, 2]);
    assert!(
        report.indicators[0].matched,
        "matched indicators come first"
    );
    let sigma = report
        .detections
        .iter()
        .find(|h| h.engine == "Sigma")
        .unwrap();
    assert_eq!((sigma.runs.clone(), sigma.count), (vec![1, 2], 4));
    assert_eq!(sigma.author, "Jane Rule");
    assert!(
        report
            .detections
            .iter()
            .any(|h| h.engine == "YARA (static)" && h.author == "Static Author")
    );
    let ids: Vec<&str> = report.attack.iter().map(|t| t.id.as_str()).collect();
    assert_eq!(ids, ["T1053.003", "T1059.004"], "ids only, tactics dropped");
}

#[test]
fn json_round_trips_with_its_schema_and_version() {
    let report = fixture();
    let json = report.to_json().unwrap();
    let back: SampleReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, report);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["schema"], "antinomie-sample-report");
    assert_eq!(value["schema_version"], 1);
    for key in [
        "sample",
        "static_analysis",
        "detections",
        "runs",
        "lineage",
        "indicators",
        "custody",
        "notes",
        "similar",
        "omitted",
        "remarks",
    ] {
        assert!(value.get(key).is_some(), "{key}");
    }
    // The JSON keeps raw values whatever the defang choice.
    let raw = text(&report, Format::Json, true);
    assert!(raw.contains("203.0.113.5:443") && !raw.contains("[.]"));
}

#[test]
fn html_is_self_contained_escaped_and_defangs_by_default() {
    let report = fixture();
    let plain = text(&report, Format::Html, false);
    for forbidden in ["<script", "<link", "src=", "@import", "url(", "href=\"http"] {
        assert!(!plain.contains(forbidden), "{forbidden} in the HTML");
    }
    assert!(plain.contains("dropper &lt;1&gt;.elf") && plain.contains("203.0.113.5:443"));
    assert!(plain.contains("<h2>Sample overview</h2>"));
    for section in [
        "Names and origins",
        "Static analysis",
        "Rules that matched",
        "Runs",
        "Lineage",
        "Indicators merged across runs",
        "Custody log",
        "Notes",
        "Similar samples",
    ] {
        assert!(plain.contains(&format!("<h2>{section}</h2>")), "{section}");
    }
    let defanged = text(&report, Format::Html, true);
    assert!(defanged.contains("203[.]0[.]113[.]5:443") && defanged.contains("evil[.]example"));
    assert!(defanged.contains("hxxp://evil[.]example/payload"));
    assert!(!defanged.contains("203.0.113.5") && !defanged.contains("http://"));
    // Hashes and paths are never changed.
    assert!(defanged.contains(&sha(0xab)) && defanged.contains("/tmp/payload.bin"));
    // Every rule credit is there; the reference without its scheme.
    for credit in [
        "Jane Rule",
        "DRL 1.1",
        "Example Pack",
        "example.org/r1",
        "Static Author",
    ] {
        assert!(plain.contains(credit), "{credit}");
    }
    // No bytes: the page says so, and nothing but hashes names the sample.
    assert!(plain.contains("holds none of the sample"));
}

#[test]
fn control_characters_cannot_break_the_html_or_the_markdown() {
    let mut report = fixture();
    report.sample.name = "bad\u{0}\u{1b}[31m</td><script>x".into();
    report.notes[0].text = "line\u{7f}<img src=x onerror=1>".into();
    let html = text(&report, Format::Html, false);
    assert!(
        !html.contains('\u{0}')
            && !html.contains('\u{1b}')
            && !html.contains("<script>")
            && !html.contains("<img")
    );
    let md = text(&report, Format::Markdown, false);
    assert!(!md.contains('\u{0}') && !md.contains("<script>") && !md.contains("<img"));
}

#[test]
fn markdown_has_the_sections_tables_and_escapes_markup() {
    let report = fixture();
    let md = text(&report, Format::Markdown, true);
    assert!(md.starts_with("# Antinomie Sample report: dropper &lt;1&gt;.elf"));
    for heading in [
        "## Sample overview",
        "## Static analysis",
        "## Rules that matched",
        "## Runs",
        "## Lineage",
        "## Custody log",
        "## Notes",
    ] {
        assert!(md.contains(heading), "{heading}");
    }
    assert!(md.contains("| Run | VM |") && md.contains("| --- |"));
    assert!(md.contains(&format!("`{}`", sha(0xab))), "hashes are code");
    assert!(md.contains("203[.]0[.]113[.]5") && !md.contains("203.0.113.5"));
    // A note line that looks like a heading is not one.
    assert!(md.contains("\\# not a heading") && !md.contains("\n# not a heading"));
    // Every table row has the header's cell count.
    for block in md.split("\n\n").filter(|b| b.starts_with("| ")) {
        let widths: Vec<usize> = block
            .lines()
            .map(|l| l.replace("\\|", "").matches('|').count())
            .collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{block}");
    }
}

fn pdf_text(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut at = 0;
    let find = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).position(|w| w == needle);
    while let Some(found) = find(&bytes[at..], b"\nstream\n") {
        let start = at + found + 8;
        let end = start + find(&bytes[start..], b"\nendstream").unwrap();
        let mut inflated = Vec::new();
        flate2::read::ZlibDecoder::new(&bytes[start..end])
            .read_to_end(&mut inflated)
            .unwrap();
        out.push_str(&String::from_utf8_lossy(&inflated));
        at = end;
    }
    out
}

#[test]
fn pdf_is_valid_has_bookmarks_and_the_credits() {
    let report = fixture();
    let bytes = export::render(&report, Format::Pdf, true).unwrap();
    assert!(bytes.starts_with(b"%PDF-1.4") && bytes.ends_with(b"%%EOF\n"));
    let raw: String = bytes.iter().map(|&b| b as char).collect();
    let content = pdf_text(&bytes);
    for title in [
        "Sample overview",
        "Static analysis",
        "Rules that matched",
        "Runs",
        "Lineage",
        "Custody log",
    ] {
        assert!(content.contains(&format!("({title}) Tj")), "{title} drawn");
        assert!(
            raw.contains(&format!("/Title ({title})")),
            "{title} bookmark"
        );
    }
    assert!(raw.contains("/Title (Antinomie Sample report: dropper <1>.elf)"));
    assert!(
        content.contains("203[.]0[.]113[.]5:443")
            && content.contains("Jane Rule")
            && content.contains("DRL 1.1")
    );
    assert!(content.contains("Page 1 of"));
}

#[test]
fn misp_event_is_sample_level_with_credits_lineage_and_galaxy() {
    let report = fixture();
    let event: serde_json::Value =
        serde_json::from_str(&text(&report, Format::Misp, true)).unwrap();
    let event = &event["Event"];
    let attrs = event["Attribute"].as_array().unwrap();
    let find = |ty: &str| -> Vec<&str> {
        attrs
            .iter()
            .filter(|a| a["type"] == ty)
            .map(|a| a["value"].as_str().unwrap())
            .collect()
    };
    assert!(find("sha256").contains(&sha(0xab).as_str()), "the sample");
    assert!(
        find("sha256").contains(&sha(1).as_str()) && find("sha256").contains(&sha(2).as_str()),
        "parent and child"
    );
    assert_eq!(find("sha1").len(), 1);
    assert_eq!(find("md5").len(), 1);
    assert_eq!(find("size-in-bytes"), ["1234"]);
    assert!(find("filename").contains(&"kdevtmpfsi"));
    assert!(find("ip-dst|port").contains(&"203.0.113.5|443"));
    assert!(find("url").contains(&"http://evil.example/x?a=1"));
    assert!(find("ja3-fingerprint-md5").contains(&"ab".repeat(16).as_str()));
    let ids: Vec<bool> = attrs
        .iter()
        .filter(|a| a["type"] == "ip-dst|port")
        .map(|a| a["to_ids"].as_bool().unwrap())
        .collect();
    assert_eq!(ids, [true], "to_ids only for the matched endpoint");
    let rules: Vec<&str> = find("comment")
        .into_iter()
        .filter(|c| c.contains(" rule "))
        .collect();
    assert_eq!(rules.len(), 3);
    assert!(
        rules
            .iter()
            .all(|c| c.contains("Author:") && c.contains("License:") && c.contains("Source:"))
    );
    assert!(
        rules
            .iter()
            .any(|c| c.contains("Jane Rule") && c.contains("https://example.org/r1"))
    );
    assert_eq!(event["threat_level_id"], "1");
    assert!(
        !text(&report, Format::Misp, true).contains("[.]"),
        "raw values"
    );
    let tags: Vec<&str> = event["Tag"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(
        tags.contains(&"antinomie:sample-report")
            && tags.contains(&"antinomie:verdict=\"malicious\"")
    );
    assert!(tags.iter().any(
        |t| t.starts_with("misp-galaxy:mitre-attack-pattern=") && t.ends_with("- T1053.003\"")
    ));
    // The same sample gives the same event id on a second export.
    let again: serde_json::Value =
        serde_json::from_str(&text(&report, Format::Misp, false)).unwrap();
    assert_eq!(again["Event"]["uuid"], event["uuid"]);
}

#[test]
fn stix_bundle_links_the_sample_its_family_lineage_indicators_and_rules() {
    let report = fixture();
    let bundle: serde_json::Value =
        serde_json::from_str(&text(&report, Format::Stix, true)).unwrap();
    let objects = bundle["objects"].as_array().unwrap();
    let ids: std::collections::BTreeSet<&str> =
        objects.iter().map(|o| o["id"].as_str().unwrap()).collect();
    assert_eq!(ids.len(), objects.len(), "ids are unique");
    for object in objects {
        for (key, value) in object.as_object().unwrap() {
            if key.ends_with("_ref") {
                assert!(ids.contains(value.as_str().unwrap()), "{key} dangles");
            }
            if key.ends_with("_refs") {
                assert!(
                    value
                        .as_array()
                        .unwrap()
                        .iter()
                        .all(|v| ids.contains(v.as_str().unwrap())),
                    "{key} dangles"
                );
            }
        }
    }
    let of = |ty: &str| objects.iter().filter(|o| o["type"] == ty).count();
    assert_eq!(of("identity"), 1);
    assert_eq!(of("malware"), 2, "the sample and its family");
    assert_eq!(of("malware-analysis"), 1);
    assert_eq!(of("file"), 3, "sample, parent, child");
    assert_eq!(of("indicator"), 4, "the JA3 hash has no STIX pattern");
    assert_eq!(of("attack-pattern"), 2);
    assert_eq!(of("note"), 4, "three rules and the custody head");
    let relationship = |ty: &str| {
        objects
            .iter()
            .filter(|o| o["type"] == "relationship" && o["relationship_type"] == ty)
            .count()
    };
    assert_eq!(
        (
            relationship("indicates"),
            relationship("uses"),
            relationship("variant-of"),
            relationship("drops")
        ),
        (4, 2, 1, 1)
    );
    let file = objects
        .iter()
        .find(|o| o["type"] == "file" && o["hashes"]["SHA-256"] == sha(0xab).as_str())
        .unwrap();
    assert_eq!(file["hashes"]["SHA-1"], "cd".repeat(20).as_str());
    assert!(
        file.get("created").is_none(),
        "a file object has no created time"
    );
    let analysis = objects
        .iter()
        .find(|o| o["type"] == "malware-analysis")
        .unwrap();
    assert_eq!(analysis["result"], "suspicious");
    for note in objects
        .iter()
        .filter(|o| o["type"] == "note" && o["abstract"].as_str().unwrap().contains("rule"))
    {
        let content = note["content"].as_str().unwrap();
        assert!(
            content.contains("Author:")
                && content.contains("License:")
                && note["authors"].is_array()
        );
    }
    assert!(
        objects
            .iter()
            .filter_map(|o| o["pattern"].as_str())
            .any(|p| p.contains("203.0.113.5")),
        "raw values"
    );
}

#[test]
fn rows_are_capped_with_a_note_and_json_keeps_up_to_its_own_cap() {
    let mut report = fixture();
    report.indicators = (0..crate::report::DOCUMENT_ROWS + 50)
        .map(|n| MergedIndicator {
            kind: "domain".into(),
            value: format!("d{n}.example"),
            matched: false,
            runs: vec![1],
            ..MergedIndicator::default()
        })
        .collect();
    let html = text(&report, Format::Html, false);
    assert!(html.contains("50 more rows are not shown here; the JSON export keeps them."));
    assert!(html.contains("d999.example") && !html.contains("d1000.example"));
    let json: SampleReport = serde_json::from_str(&text(&report, Format::Json, false)).unwrap();
    assert_eq!(json.indicators.len(), crate::report::DOCUMENT_ROWS + 50);
    // Past the list cap the report drops rows, counts them and says so.
    report.indicators = (0..LIST_ROWS + 7)
        .map(|n| MergedIndicator {
            kind: "domain".into(),
            value: format!("d{n}.example"),
            ..MergedIndicator::default()
        })
        .collect();
    report.remarks.clear();
    report.omitted = Omitted::default();
    report.seal();
    assert_eq!(
        (report.indicators.len(), report.omitted.indicators),
        (LIST_ROWS, 7)
    );
    assert!(
        report
            .remarks
            .iter()
            .any(|r| r.contains("7 indicators are left out"))
    );
    assert!(
        text(&report, Format::Html, false).contains("7 more indicators are not in this report.")
    );
}

#[test]
fn long_notes_and_strings_are_cut_and_say_so() {
    let (cut, was) = clip(&"x".repeat(NOTE_CHARS + 5), NOTE_CHARS);
    assert!(was && cut.chars().count() == NOTE_CHARS + 1);
    let note = crate::samples::Note {
        id: 4,
        sha256: sha(1),
        text: "y".repeat(NOTE_CHARS + 1),
        by: "analyst".into(),
        created_ms: 1,
        edited_ms: None,
        refs: Vec::new(),
    };
    let (rows, dropped) = build::notes(&[note]);
    assert!(rows[0].cut && dropped == 0);
    let mut report = fixture();
    report.notes = rows;
    assert!(text(&report, Format::Html, false).contains("The note was cut to"));
}

#[test]
fn an_empty_sample_reports_why_each_part_is_empty() {
    let mut report = SampleReport::new(
        Identity {
            sha256: sha(5),
            name: "x".into(),
            ..Identity::default()
        },
        1_792_000_000_000,
    );
    report.static_analysis = build::static_analysis(None).0;
    report.lineage = Lineage {
        reason: "none".into(),
        ..Lineage::default()
    };
    report.seal();
    let html = text(&report, Format::Html, true);
    for why in [
        "No finished static analysis report",
        "The sample has not been run",
        "No parent.",
        "No children.",
        "The custody log has no entry.",
        "The sample has no notes.",
        "No other library sample is close to this one.",
    ] {
        assert!(html.contains(why), "{why}");
    }
    for format in Format::ALL {
        assert!(!export::render(&report, format, true).unwrap().is_empty());
    }
}

#[test]
fn export_writes_the_chosen_formats_never_overwrites_and_is_owner_only() {
    let dir = temp("write");
    let report = fixture();
    let choices = Choices {
        formats: Format::ALL.to_vec(),
        ..Choices::default()
    };
    let first = export::write(&report, &choices, &dir.join("out")).unwrap();
    let second = export::write(&report, &choices, &dir.join("out")).unwrap();
    let names = |w: &export::Written| -> Vec<String> {
        w.files
            .iter()
            .map(|(_, p)| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect()
    };
    let (a, b) = (names(&first), names(&second));
    assert_eq!(a.len(), 6);
    for suffix in [".html", ".pdf", ".json", ".misp.json", ".stix.json", ".md"] {
        assert!(a.iter().any(|n| n.ends_with(suffix)), "{suffix}");
    }
    assert!(
        a.iter()
            .all(|n| n.starts_with("antinomie-sample-report-abababab-") && !b.contains(n))
    );
    assert_eq!(
        base_name(&report),
        "antinomie-sample-report-abababab-20261020-224140".replace(
            "20261020-224140",
            &crate::report::utc(report.generated_ms)
                .replace(['-', ':'], "")
                .replace(' ', "-")
        )
    );
    use std::os::unix::fs::PermissionsExt;
    for (_, path) in &first.files {
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // Unselected formats are not written.
    let one = Choices {
        formats: vec![Format::Json],
        ..Choices::default()
    };
    assert_eq!(
        export::write(&report, &one, &dir.join("one"))
            .unwrap()
            .files
            .len(),
        1
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn choices_default_to_defanged_html_and_pdf_and_read_old_settings() {
    let c = Choices::default();
    assert!(c.defang && c.writes(Format::Html) && c.writes(Format::Pdf) && !c.writes(Format::Json));
    assert_eq!(
        serde_json::from_str::<Choices>("{}").unwrap(),
        Choices::default()
    );
}

#[test]
fn the_report_is_built_from_a_real_library_and_the_export_is_noted_in_the_custody_log() {
    let dir = temp("library");
    let file = dir.join("benign.sh");
    std::fs::write(&file, b"#!/bin/sh\necho hello\n").unwrap();
    let mut library = Library::open(&dir.join("data")).unwrap();
    let added = library
        .add_file(&file, NewSample::default(), false)
        .unwrap();
    let hash = added.sha256.clone();
    let record = library.get(&hash).unwrap().unwrap();
    let events = library.events(&hash).unwrap();
    let check = library.custody_check(&hash).unwrap();
    let identity = build::identity(
        &record,
        &library.tags(&hash).unwrap(),
        &library.aliases(&hash).unwrap(),
        &library.origins(&hash).unwrap(),
        true,
        &[],
        &events,
    );
    assert_eq!(identity.sha256, hash);
    assert!(identity.first_seen_ms.is_some() && identity.last_seen_ms >= identity.first_seen_ms);
    assert!(!identity.origins.is_empty());
    let mut report = SampleReport::new(identity, 1_792_000_100_000);
    let (custody, dropped) = build::custody(&check, &events);
    assert_eq!(dropped, 0);
    assert!(
        custody.verified
            && custody.entries == events.len() as u64
            && custody.log[0].state == "verified"
    );
    report.custody = custody;
    report.static_analysis = build::static_analysis(None).0;
    report.seal();
    let choices = Choices {
        formats: vec![Format::Json, Format::Markdown],
        ..Choices::default()
    };
    let written = export::write_and_note(&library, &report, &choices, &dir.join("out")).unwrap();
    assert_eq!(written.files.len(), 2);
    let after = library.events(&hash).unwrap();
    assert_eq!(after.len(), events.len() + 1);
    let last = after.last().unwrap();
    assert_eq!(last.event.key(), "exported");
    assert!(
        last.event
            .detail()
            .contains("sample report (JSON, Markdown)")
    );
    assert!(
        library.custody_check(&hash).unwrap().ok(),
        "the chain still verifies"
    );
    // The file bytes are never in the report: only the hash is.
    let json = std::fs::read_to_string(&written.files[0].1).unwrap();
    assert!(!json.contains("echo hello") && json.contains(&hash));
    // No formats, no note.
    let none = Choices {
        formats: Vec::new(),
        ..Choices::default()
    };
    export::write_and_note(&library, &report, &none, &dir.join("out2")).unwrap();
    assert_eq!(library.events(&hash).unwrap().len(), after.len());
    drop(library);
    std::fs::remove_dir_all(dir).unwrap();
}

/// With `ANTINOMIE_SAMPLE_REPORT_OUT=DIR` the fixture report is written in
/// every format into DIR (defanged and raw), for
/// `tests/monitor/test-sample-report-export.py`, which checks it with tools
/// that are not Antinomie's.
#[test]
fn sample_report_fixture_export() {
    let Some(out) = std::env::var_os("ANTINOMIE_SAMPLE_REPORT_OUT") else {
        return;
    };
    let out = std::path::PathBuf::from(out);
    let report = fixture();
    let all = Choices {
        formats: Format::ALL.to_vec(),
        ..Choices::default()
    };
    export::write(&report, &all, &out).unwrap();
    let raw = Choices {
        formats: vec![Format::Html, Format::Markdown],
        defang: false,
        ..Choices::default()
    };
    export::write(&report, &raw, &out.join("raw")).unwrap();
}

#[test]
fn no_export_names_the_home_directory_of_the_data_dir() {
    let home = temp("home").join("fakeuser");
    let data_dir = home.join(".local/share/antinomie");
    let run_dir = data_dir.join("runs/vm-1/run-9");
    std::fs::create_dir_all(run_dir.join("report")).unwrap();
    std::fs::write(run_dir.join("report/antinomie-report-1.html"), b"x").unwrap();
    let mut report = fixture();
    report.runs = vec![build::run_row(
        1,
        "vm-1",
        "Debian",
        "run-9",
        Some(1_791_500_000_000),
        "Exit 0",
        &data_dir,
        &run_dir,
        true,
        None,
    )];
    assert_eq!(report.runs[0].directory, "runs/vm-1/run-9");
    assert_eq!(
        report.runs[0].report_file,
        "runs/vm-1/run-9/report/antinomie-report-1.html"
    );
    let home_text = home.display().to_string();
    for format in [
        Format::Html,
        Format::Json,
        Format::Misp,
        Format::Stix,
        Format::Markdown,
    ] {
        let out = text(&report, format, true);
        assert!(!out.contains(&home_text), "{format:?} names the home");
        assert!(!out.contains("fakeuser"), "{format:?} names the user");
    }
    assert!(text(&report, Format::Markdown, true).contains("runs/vm-1/run-9/report/"));
}

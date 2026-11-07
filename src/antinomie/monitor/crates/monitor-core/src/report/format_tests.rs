// SPDX-License-Identifier: GPL-3.0-only
//! What the exchange formats and the documents may and may not carry: unique
//! STIX ids with their required properties, MISP structure, none of the
//! sandbox's own addresses as indicators, and no host path or copied read
//! content in any format. Synthetic reports only.
use super::tests::fixture;
use super::*;
use serde_json::Value;
use std::collections::BTreeSet;

fn endpoint(value: &str, stand_in: &str) -> Indicator {
    Indicator {
        kind: "endpoint".into(),
        value: value.into(),
        verdict: "No match".into(),
        stand_in: stand_in.into(),
        not_shared: shared::not_shared_reason("endpoint", value, &[], ""),
        ..Indicator::default()
    }
}

fn file(path: &str, sha: &str, roles: &str) -> Indicator {
    let roles_list: Vec<String> = roles.split(", ").map(str::to_owned).collect();
    Indicator {
        kind: "file".into(),
        value: sha.into(),
        path: path.into(),
        sha256: sha.into(),
        count: roles.into(),
        verdict: "No match".into(),
        not_shared: shared::not_shared_reason("file", sha, &roles_list, ""),
        ..Indicator::default()
    }
}

/// The fixture plus the indicators a real run has: the resolver, the Tor
/// stand-ins, a Debian program the run started, and one dropped hash under
/// many paths.
fn noisy() -> Report {
    let mut report = fixture();
    let sha = "cd".repeat(32);
    let ls = "ee".repeat(32);
    report.indicators = Some(vec![
        endpoint("192.168.1.10:53", ""),
        endpoint("198.18.0.1:20", "mircd.xiao.my.id"),
        endpoint("203.0.113.9:4444", ""),
        Indicator {
            kind: "domain".into(),
            value: "mircd.xiao.my.id".into(),
            verdict: "No match".into(),
            ..Indicator::default()
        },
        file("/tmp/file0001", &sha, "created, written at close"),
        file("/tmp/file0002", &sha, "created, written at close"),
        file("/bin/ls", &ls, "executed"),
    ]);
    report
}

fn json(text: &str) -> Value {
    serde_json::from_str(text).expect("valid JSON")
}

#[test]
fn a_stix_bundle_has_unique_ids_and_the_required_properties() {
    let text = stix::render(&noisy()).unwrap();
    let bundle = json(&text);
    assert_eq!(bundle["type"], "bundle");
    assert!(bundle["id"].as_str().unwrap().starts_with("bundle--"));
    let objects = bundle["objects"].as_array().unwrap();
    let ids: Vec<&str> = objects.iter().map(|o| o["id"].as_str().unwrap()).collect();
    let unique: BTreeSet<&str> = ids.iter().copied().collect();
    assert_eq!(ids.len(), unique.len(), "two objects share an id: {ids:?}");
    for object in objects {
        let kind = object["type"].as_str().unwrap();
        assert!(
            object["id"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{kind}--"))
        );
        if kind != "file" {
            for key in ["spec_version", "created", "modified"] {
                assert!(object.get(key).is_some(), "{kind} lacks {key}");
            }
        }
        match kind {
            "indicator" => {
                for key in ["pattern", "pattern_type", "valid_from", "indicator_types"] {
                    assert!(object.get(key).is_some(), "indicator lacks {key}");
                }
            }
            "relationship" => {
                for key in ["relationship_type", "source_ref", "target_ref"] {
                    let target = object[key].as_str().unwrap();
                    assert!(
                        ids.contains(&target) || key == "relationship_type",
                        "{key} dangles"
                    );
                }
            }
            "malware" => {
                assert!(object["name"].is_string() && object["is_family"].is_boolean());
            }
            "report" => {
                let refs = object["object_refs"].as_array().unwrap();
                assert!(!refs.is_empty());
                for target in refs {
                    assert!(
                        ids.contains(&target.as_str().unwrap()),
                        "report ref dangles"
                    );
                }
            }
            _ => {}
        }
    }
}

#[test]
fn the_sandboxs_own_addresses_and_base_programs_are_not_exchange_indicators() {
    let report = noisy();
    let stix_text = stix::render(&report).unwrap();
    let misp_text = misp::render(&report).unwrap();
    for text in [&stix_text, &misp_text] {
        assert!(!text.contains("192.168.1.10"), "the guest's resolver");
        assert!(!text.contains("198.18.0.1"), "a Tor stand-in address");
        assert!(
            !text.contains("/bin/ls") && !text.contains(&"ee".repeat(32)),
            "a Debian program"
        );
        assert!(text.contains("203.0.113.9"), "a real address stays");
        assert!(
            text.contains("mircd.xiao.my.id"),
            "the name the stand-in stands for stays"
        );
    }
    // One indicator for the hash that sits under two paths, naming both.
    let bundle = json(&stix_text);
    let hashes: Vec<&Value> = bundle["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["type"] == "indicator" && o["pattern"].as_str().unwrap().contains("SHA-256"))
        .collect();
    assert_eq!(hashes.len(), 1);
    let description = hashes[0]["description"].as_str().unwrap();
    assert!(description.contains("/tmp/file0001") && description.contains("/tmp/file0002"));
}

#[test]
fn the_documents_show_a_stand_in_with_its_name_and_the_json_keeps_everything() {
    let report = noisy();
    let html = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    assert!(html.contains("198.18.0.1:20 \u{2192} mircd.xiao.my.id (Tor stand-in)"));
    assert!(html.contains("at 2 paths"), "one row for one hash");
    let doc = json(&report.to_json().unwrap());
    let all = doc["indicators"].as_array().unwrap();
    assert_eq!(all.len(), 7, "the JSON keeps every indicator");
    assert_eq!(all[1]["stand_in"], "mircd.xiao.my.id");
}

#[test]
fn a_misp_event_has_its_structure_and_the_sample_is_a_file_object() {
    let mut report = noisy();
    report.summary.as_mut().unwrap().families = vec!["Tsunami".into()];
    let event = json(&misp::render(&report).unwrap())["Event"].clone();
    for key in [
        "uuid",
        "info",
        "date",
        "timestamp",
        "threat_level_id",
        "analysis",
        "Orgc",
        "Attribute",
        "Tag",
    ] {
        assert!(event.get(key).is_some(), "Event lacks {key}");
    }
    let attributes = event["Attribute"].as_array().unwrap();
    let uuids: BTreeSet<&str> = attributes
        .iter()
        .map(|a| a["uuid"].as_str().unwrap())
        .collect();
    assert_eq!(uuids.len(), attributes.len(), "attribute uuids are unique");
    for attribute in attributes {
        for key in ["type", "category", "value", "to_ids", "timestamp"] {
            assert!(attribute.get(key).is_some(), "attribute lacks {key}");
        }
    }
    let object = &event["Object"][0];
    assert_eq!(object["name"], "file");
    assert!(
        object["Attribute"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["object_relation"] == "sha256" && a["to_ids"] == true)
    );
    assert!(
        event["Tag"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "antinomie:family=\"Tsunami\"")
    );
}

#[test]
fn a_run_with_no_sample_publishes_no_sample_hash() {
    let mut report = noisy();
    report.sample = None;
    report.run.command = "/bin/sh -c 'ls'".into();
    for text in [
        stix::render(&report).unwrap(),
        misp::render(&report).unwrap(),
    ] {
        assert!(!text.contains(&"ab".repeat(32)));
    }
    let stix = json(&stix::render(&report).unwrap());
    assert!(
        !stix["objects"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["type"] == "malware")
    );
    let html = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    assert!(html.contains("none recorded") && html.contains("/bin/sh -c"));
}

#[test]
fn a_family_the_rules_name_is_the_stix_malware_and_a_misp_tag() {
    let mut report = fixture();
    report.summary.as_mut().unwrap().families = vec!["BPFDoor".into()];
    let bundle = json(&stix::render(&report).unwrap());
    let malware = bundle["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["type"] == "malware")
        .unwrap();
    assert_eq!(malware["name"], "BPFDoor");
    assert_eq!(malware["is_family"], true);
    assert!(malware["sample_refs"].as_array().unwrap().len() == 1);
}

#[test]
fn the_run_state_and_the_environment_reach_the_documents_and_the_json() {
    let mut report = fixture();
    report.run.state = "Stopped by you at 6 min 25 s \u{b7} root exited 0".into();
    report.run.exit = "exit 0".into();
    report.run.stopped_by_user = true;
    report.run.duration_ms = Some(385_000);
    report.run.ended_ms = Some(1_792_000_386_000);
    report.run.environment = vec![
        Fact::new("Base image", "Debian 13 (Minimal) rev 20"),
        Fact::new("Kernel", "6.12.94"),
    ];
    let html = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    assert!(html.contains("Stopped by you at 6 min 25 s"));
    assert!(html.contains("Debian 13 (Minimal) rev 20") && html.contains("6 min 25 s"));
    assert!(!html.contains(">finished<"));
    let doc = json(&report.to_json().unwrap());
    assert_eq!(doc["run"]["stopped_by_user"], true);
    assert_eq!(doc["run"]["exit"], "exit 0");
    assert_eq!(doc["run"]["environment"][0]["name"], "Base image");
}

#[test]
fn big_numbers_have_separators_and_times_one_notation() {
    assert_eq!(layout::thousands(167_040), "167,040");
    assert_eq!(layout::thousands(12), "12");
    assert_eq!(layout::thousands(1_000), "1,000");
    let shown = layout::shown_iso("2026-11-07T10:40:42.662Z");
    assert!(
        shown.starts_with("2026-11-07 ") && shown.contains("(UTC"),
        "{shown}"
    );
    assert_eq!(layout::shown_iso("created, deleted"), "created, deleted");
}

#[test]
fn the_pdf_prints_an_arrow_and_names_its_kind_and_language() {
    let mut report = fixture();
    report.notes.push("created \u{2192} deleted".into());
    let pdf = export::render(&report, Format::Pdf, false).unwrap();
    let text = String::from_utf8_lossy(&pdf);
    assert!(text.contains("/Lang (en)") && text.contains("/Creator (Antinomie Triage report)"));
    assert!(text.contains("/Subject") && text.contains("/Keywords"));
}

#[test]
fn a_narrow_column_keeps_its_word_whole_beside_a_column_of_long_hashes() {
    use super::layout::{Block, DocTable, Document, Section};
    use super::pdf_layout::{Op, lay_out};
    let hash = "ab".repeat(100);
    let rows: Vec<Vec<String>> = (0..3)
        .map(|n| {
            vec![
                format!("row {n}"),
                "complete".into(),
                "reconstruction".into(),
                hash.clone(),
                hash.clone(),
            ]
        })
        .collect();
    let document = Document {
        title: "t".into(),
        subtitle: "s".into(),
        defanged: false,
        sections: vec![Section {
            id: "a".into(),
            title: "A".into(),
            blocks: vec![Block::Table(DocTable {
                columns: ["Name", "State", "Reconstruction", "Hash one", "Hash two"]
                    .map(String::from)
                    .to_vec(),
                rows,
            })],
        }],
        meta: Default::default(),
    };
    let laid = lay_out(&document);
    let words: Vec<String> = laid
        .pages
        .iter()
        .flat_map(|page| &page.ops)
        .filter_map(|op| match op {
            Op::Text { text, .. } => Some(text.clone()),
            _ => None,
        })
        .collect();
    assert!(
        words.iter().any(|w| w == "complete"),
        "State is not cut: {words:?}"
    );
    assert!(words.iter().any(|w| w == "reconstruction"));
}

#[test]
fn the_html_tables_have_captions_scopes_and_do_not_cut_short_words() {
    let report = noisy();
    let html = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    assert!(html.contains("<th scope=\"col\">") && html.contains("<th scope=\"row\">"));
    assert!(html.contains("<caption>Indicators of compromise</caption>"));
    assert!(html.contains("<nav aria-label=\"Sections\">") && html.contains("tabindex=\"0\""));
    assert!(html.contains("<td class=\"nw\">endpoint</td>"));
    assert!(html.contains("td.mono,td.long{overflow-wrap:anywhere}"));
    // Still self-contained: no script, no link out.
    assert!(!html.contains("<script") && !html.contains("href=\"http"));
}

#[test]
fn the_summary_counts_findings_by_tier_and_lists_the_key_findings() {
    let mut report = fixture();
    {
        let summary = report.summary.as_mut().unwrap();
        summary.tiers = TierCounts {
            high: 0,
            medium: 2,
            low: 1,
            info: 0,
        };
        summary.key_findings = vec!["MEDIUM Waiting for chosen packets: BPF on raw socket".into()];
        summary.key_behaviours[0].count = 167_040;
    }
    let html = String::from_utf8(export::render(&report, Format::Html, false).unwrap()).unwrap();
    assert!(html.contains("0 HIGH, 2 MEDIUM, 1 LOW, 0 INFO"));
    assert!(html.contains("<li>MEDIUM Waiting for chosen packets: BPF on raw socket</li>"));
    assert!(html.contains("167,040"));
    assert!(html.contains("<span class=\"tier high\">HIGH</span>"));
}

#[test]
fn the_geolocation_credit_closes_the_document_and_evidence_lists_recordings() {
    let mut report = fixture();
    report
        .notes
        .push("Network: IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0.".into());
    report.evidence = Some(vec![
        EvidenceRef {
            kind: "telemetry".into(),
            path: "telemetry.raw".into(),
            size: 229_072_586,
            sha256: String::new(),
        },
        EvidenceRef {
            kind: "other".into(),
            path: "terminal.journal".into(),
            size: 23,
            sha256: "ab".repeat(32),
        },
    ]);
    let document = layout::document(&report, false);
    let titles: Vec<&str> = document.sections.iter().map(|s| s.title.as_str()).collect();
    assert_eq!(titles.last(), Some(&"Notes"), "{titles:?}");
    let overview = &document.sections[0];
    assert!(!format!("{:?}", overview.blocks).contains("DB-IP"));
    let evidence = document
        .sections
        .iter()
        .find(|s| s.id == "evidence")
        .unwrap();
    let text = format!("{:?}", evidence.blocks);
    assert!(
        text.contains("218.5 MiB") && !text.contains("terminal.journal"),
        "{text}"
    );
}

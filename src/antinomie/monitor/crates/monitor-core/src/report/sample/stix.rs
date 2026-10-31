// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The STIX 2.1 export of a sample: an identity, the sample as a `file` and a
//! `malware` (with the family as a second `malware` it is a variant of), one
//! `malware-analysis`, its parents and children as `file` objects, an
//! `indicator` per indicator merged across its runs, an `attack-pattern` per
//! technique, a `note` per matching rule that names the rule's author,
//! licence and source, and a note with the custody head. Raw values. Ids are
//! version-5 UUIDs of the content, so a second export has the same ids.
use super::super::iso;
use super::super::stix::{id_of, object, pattern, pattern_seed, relationship};
use super::{LineageEntry, SampleReport, as_indicator};
use serde_json::{Value, json};

fn credit(value: &str) -> String {
    if value.is_empty() { "unknown" } else { value }.to_owned()
}

fn is_hash(text: &str, len: usize) -> bool {
    text.len() == len && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// STIX malware types for the library's categories.
fn malware_types(report: &SampleReport) -> Vec<&'static str> {
    let mut out = Vec::new();
    for tag in report.sample.tags.iter().filter(|t| t.kind == "category") {
        let ty = match tag.value.as_str() {
            "miner" => "resource-exploitation",
            "botnet" => "bot",
            "backdoor" => "backdoor",
            "rootkit" => "rootkit",
            "ransomware" => "ransomware",
            "dropper" | "loader" => "dropper",
            "infostealer" => "spyware",
            "worm" => "worm",
            _ => continue,
        };
        if !out.contains(&ty) {
            out.push(ty);
        }
    }
    out
}

fn file_object(node: &LineageEntry) -> Value {
    let mut file = json!({
        "type": "file",
        "hashes": {"SHA-256": node.sha256},
    });
    if !node.label.is_empty() && node.kind != "command" {
        file["name"] = json!(node.label);
    }
    file["id"] = json!(format!("file--{}", super::super::uuid5(&format!("stix:file:{}", node.sha256))));
    file
}

/// The STIX 2.1 bundle of `report`.
pub fn render(report: &SampleReport) -> Result<String, String> {
    let at = iso(report.generated_ms);
    let sample = &report.sample;
    let sha = &sample.sha256;
    let mut objects: Vec<Value> = Vec::new();
    let identity = object(
        "identity",
        "antinomie",
        &at,
        json!({"name": "Antinomie", "identity_class": "system", "description": report.app}),
    );
    let identity_id = id_of(&identity);
    objects.push(identity);

    let mut hashes = json!({});
    for (key, value, len) in [
        ("SHA-256", &sample.sha256, 64),
        ("SHA-1", &sample.sha1, 40),
        ("MD5", &sample.md5, 32),
    ] {
        if is_hash(value, len) {
            hashes[key] = json!(value);
        }
    }
    if !sample.tlsh.is_empty() {
        hashes["TLSH"] = json!(sample.tlsh);
    }
    let mut file = json!({"type": "file", "hashes": hashes, "size": sample.size});
    if !sample.name.is_empty() {
        file["name"] = json!(sample.name);
    }
    file["id"] = json!(format!("file--{}", super::super::uuid5(&format!("stix:file:{sha}"))));
    let file_id = id_of(&file);
    objects.push(file);

    let mut fields = json!({
        "name": if sample.name.is_empty() { sha } else { &sample.name },
        "is_family": false,
        "sample_refs": [file_id],
        "created_by_ref": identity_id,
    });
    let types = malware_types(report);
    if !types.is_empty() {
        fields["malware_types"] = json!(types);
    }
    if !sample.description.is_empty() {
        fields["description"] = json!(sample.description);
    }
    let malware = object("malware", sha, &at, fields);
    let malware_id = id_of(&malware);
    objects.push(malware);
    if !sample.family.is_empty() {
        let family = object(
            "malware",
            &format!("family:{}", sample.family),
            &at,
            json!({"name": sample.family, "is_family": true, "created_by_ref": identity_id}),
        );
        objects.push(relationship("variant-of", &malware_id, &id_of(&family), &at));
        objects.push(family);
    }

    let result = match report.assessment() {
        "matched_indicators" | "suspicious_behaviour" => "suspicious",
        _ => "unknown",
    };
    let mut analysis = json!({
        "product": "antinomie",
        "version": crate::api::APP_VERSION,
        "result": result,
        "analysis_engine_version": crate::api::APP_VERSION,
        "sample_ref": file_id,
        "created_by_ref": identity_id,
    });
    if let Some(first) = report.runs.iter().filter_map(|run| run.started_ms).min() {
        analysis["analysis_started"] = json!(iso(first));
    }
    objects.push(object("malware-analysis", sha, &at, analysis));

    for (nodes, kind) in [
        (&report.lineage.children, "drops"),
        (&report.lineage.parents, "related-to"),
    ] {
        for node in nodes.iter().filter(|n| is_hash(&n.sha256, 64)) {
            let object_file = file_object(node);
            let mut rel = relationship(kind, &malware_id, &id_of(&object_file), &at);
            let how = if kind == "drops" {
                format!("child of the sample ({})", node.via)
            } else {
                format!("parent of the sample ({})", node.via)
            };
            rel["description"] = json!(how);
            if !objects.iter().any(|o| o["id"] == object_file["id"]) {
                objects.push(object_file);
            }
            objects.push(rel);
        }
    }

    for item in &report.indicators {
        let indicator = as_indicator(item);
        let Some(pattern) = pattern(&indicator) else {
            continue;
        };
        let mut fields = json!({
            "name": format!("{} {}", indicator.kind, indicator.value),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": at,
            "indicator_types": if item.matched { json!(["malicious-activity"]) } else { json!(["anomalous-activity"]) },
            "created_by_ref": identity_id,
            "description": format!("Observed in run {} of the sample; dataset verdict: {}",
                item.runs.iter().map(usize::to_string).collect::<Vec<_>>().join(", "), indicator.verdict),
        });
        if item.runs.is_empty() {
            fields["description"] = json!(format!("Observed in the sample's runs; dataset verdict: {}", indicator.verdict));
        }
        let made = object("indicator", &format!("{sha}:{}", pattern_seed(&indicator)), &at, fields);
        objects.push(relationship("indicates", &id_of(&made), &malware_id, &at));
        objects.push(made);
    }

    for technique in &report.attack {
        let fields = json!({
            "name": if technique.name.is_empty() { &technique.id } else { &technique.name },
            "created_by_ref": identity_id,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": technique.id,
                "url": format!("https://attack.mitre.org/techniques/{}/", technique.id.replace('.', "/")),
            }],
        });
        let made = object("attack-pattern", &technique.id, &at, fields);
        objects.push(relationship("uses", &malware_id, &id_of(&made), &at));
        objects.push(made);
    }

    for hit in &report.detections {
        let mut fields = json!({
            "abstract": format!("{} rule {} matched", hit.engine, hit.rule_id),
            "content": format!(
                "{} rule {} ({}) matched {} time(s){}. Author: {}. License: {}. Source: {}.",
                hit.engine,
                hit.rule_id,
                hit.title,
                hit.count,
                if hit.runs.is_empty() {
                    " in the static scan".to_owned()
                } else {
                    format!(" in run {}", hit.runs.iter().map(usize::to_string).collect::<Vec<_>>().join(", "))
                },
                credit(&hit.author),
                credit(&hit.license),
                credit(&hit.source),
            ),
            "authors": [credit(&hit.author)],
            "object_refs": [malware_id],
            "created_by_ref": identity_id,
        });
        if !hit.reference.is_empty() {
            fields["external_references"] = json!([{
                "source_name": if hit.source.is_empty() { "rule" } else { hit.source.as_str() },
                "url": hit.reference,
            }]);
        }
        objects.push(object(
            "note",
            &format!("{sha}:{}:{}", hit.engine, hit.rule_id),
            &at,
            fields,
        ));
    }

    objects.push(object(
        "note",
        &format!("{sha}:custody"),
        &at,
        json!({
            "abstract": "Custody log head",
            "content": format!(
                "Custody log of the sample: {} entries, head {}, chain {} when exported. Tamper-evident, not tamper-proof.",
                report.custody.entries,
                report.custody.head,
                if report.custody.verified { "verified" } else { "NOT verified" }
            ),
            "authors": ["Antinomie"],
            "object_refs": [malware_id],
            "created_by_ref": identity_id,
        }),
    ));

    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", super::super::uuid5(&format!("stix:bundle:sample:{sha}:{}", report.generated_ms))),
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

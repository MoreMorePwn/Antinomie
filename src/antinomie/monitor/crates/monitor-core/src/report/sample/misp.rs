// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The MISP export of a sample: one event with the sample's hashes and names,
//! its parents and children by hash, the indicators merged across its runs
//! (`to_ids` only for those a dataset matched), the rules that matched with
//! their author, licence and source, the family, and a galaxy cluster per
//! ATT&CK technique. Raw values, never defanged, never sample bytes.
use super::super::misp::{attribute, attributes, cluster_value};
use super::super::{iso, utc, uuid5};
use super::{SampleReport, as_indicator};
use serde_json::{Value, json};

fn credit(value: &str) -> &str {
    if value.is_empty() { "unknown" } else { value }
}

fn is_hash(text: &str, len: usize) -> bool {
    text.len() == len && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// The MISP event of `report`.
pub fn render(report: &SampleReport) -> Result<String, String> {
    let at = report.generated_ms;
    let sample = &report.sample;
    let seed = format!("sample:{}", sample.sha256);
    let mut attrs: Vec<Value> = Vec::new();
    let mut add = |kind: &str, category: &str, value: &str, ids: bool, note: &str| {
        attrs.push(attribute(kind, category, value, ids, note, &seed, at));
    };
    // The sample's hashes are for blocking only when something says it is
    // malware: a dataset matched, a rule named a family, a run was suspicious.
    let strong = matches!(
        report.assessment(),
        "matched_indicators" | "suspicious_behaviour"
    ) || !sample.family.is_empty()
        || !sample.family_candidates.is_empty();
    for (kind, value, len) in [
        ("sha256", &sample.sha256, 64),
        ("sha1", &sample.sha1, 40),
        ("md5", &sample.md5, 32),
    ] {
        if is_hash(value, len) {
            add(kind, "Payload delivery", value, strong, "the sample");
        }
    }
    if !sample.tlsh.is_empty() {
        add(
            "tlsh",
            "Payload delivery",
            &sample.tlsh,
            false,
            "the sample's fuzzy hash",
        );
    }
    let mut names = vec![sample.name.clone()];
    names.extend(sample.names.iter().map(|alias| alias.name.clone()));
    names.retain(|name| !name.is_empty());
    names.sort();
    names.dedup();
    for name in &names {
        add(
            "filename",
            "Payload delivery",
            name,
            false,
            "a name the sample went by",
        );
    }
    add(
        "size-in-bytes",
        "Other",
        &sample.size.to_string(),
        false,
        "the sample's size",
    );
    if !sample.family.is_empty() {
        add(
            "comment",
            "Other",
            &format!("Family named by the library: {}", sample.family),
            false,
            "",
        );
    }
    for node in &report.lineage.parents {
        if is_hash(&node.sha256, 64) {
            add(
                "sha256",
                "Payload delivery",
                &node.sha256,
                false,
                &format!("parent of the sample ({}: {})", node.kind, node.via),
            );
        }
    }
    for node in &report.lineage.children {
        if is_hash(&node.sha256, 64) {
            add(
                "sha256",
                "Artifacts dropped",
                &node.sha256,
                false,
                &format!("child of the sample ({}: {})", node.kind, node.via),
            );
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for item in report
        .indicators
        .iter()
        .map(as_indicator)
        .filter(|i| i.shared())
    {
        for attr in attributes(&item, &seed, at) {
            if seen.insert((attr["type"].to_string(), attr["value"].to_string())) {
                attrs.push(attr);
            }
        }
    }
    for hit in &report.detections {
        attrs.push(attribute(
            "comment",
            "Other",
            &format!(
                "{} rule {} ({}) matched {} time(s){}. Author: {}. License: {}. Source: {}{}",
                hit.engine,
                crate::report::layout::plain_rule(&hit.rule_id),
                crate::report::layout::plain_rule(&hit.title),
                hit.count,
                if hit.runs.is_empty() {
                    String::new()
                } else {
                    format!(
                        " in run {}",
                        hit.runs
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
                credit(&hit.author),
                credit(&hit.license),
                credit(&hit.source),
                if hit.reference.is_empty() {
                    String::new()
                } else {
                    format!(". Reference: {}", hit.reference)
                },
            ),
            false,
            "a detection rule that matched; the rule's author and licence travel with it",
            &seed,
            at,
        ));
    }
    for run in &report.runs {
        attrs.push(attribute(
            "comment",
            "Other",
            &format!(
                "Run {}: {} ({}), exit {}, {} rule(s), {} indicator(s)",
                run.number,
                run.assessment,
                if run.highest_tier.is_empty() {
                    "tier unknown"
                } else {
                    &run.highest_tier
                },
                run.exit,
                run.rules,
                run.indicators
            ),
            false,
            "an observation from a recorded run, not a verdict",
            &seed,
            at,
        ));
    }
    attrs.push(attribute(
        "comment",
        "Other",
        &format!(
            "Custody log: {} entries, head {}, {}",
            report.custody.entries,
            report.custody.head,
            if report.custody.verified {
                "chain verified"
            } else {
                "chain NOT verified"
            }
        ),
        false,
        "",
        &seed,
        at,
    ));
    attrs.push(attribute(
        "comment",
        "Other",
        &format!(
            "Written by {} at {}. Observations from recorded runs, not a verdict.",
            report.app,
            iso(at)
        ),
        false,
        "",
        &seed,
        at,
    ));
    let assessment = report.assessment();
    let mut tags = vec![
        json!({"name": "antinomie:sample-report", "colour": "#0b5cad"}),
        json!({"name": format!("antinomie:assessment=\"{assessment}\""), "colour": "#6b4e00"}),
    ];
    for tag in sample
        .tags
        .iter()
        .filter(|t| t.kind == "verdict" || t.kind == "category")
    {
        tags.push(json!({
            "name": format!("antinomie:{}=\"{}\"", tag.kind, tag.value.replace('"', "")),
            "colour": "#5c6670",
        }));
    }
    let mut named: Vec<&str> = std::iter::once(sample.family.as_str())
        .chain(sample.family_candidates.iter().map(|c| c.name.as_str()))
        .filter(|name| !name.is_empty())
        .collect();
    named.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
    for family in named {
        tags.push(json!({
            "name": format!("antinomie:family=\"{}\"", family.replace('"', "")),
            "colour": "#7a1f5c",
        }));
    }
    let mut cluster = Vec::new();
    for technique in &report.attack {
        let value = cluster_value(technique);
        let tag = format!("misp-galaxy:mitre-attack-pattern=\"{value}\"");
        tags.push(json!({"name": tag, "colour": "#0088cc"}));
        cluster.push(json!({
            "uuid": uuid5(&format!("misp-cluster:{}", technique.id)),
            "type": "mitre-attack-pattern",
            "value": value,
            "tag_name": tag,
            "description": technique.name,
            "meta": {"external_id": [technique.id.clone()], "source": ["MITRE"]},
        }));
    }
    let mut event = json!({
        "uuid": uuid5(&format!("misp-event:{seed}")),
        "info": format!("Antinomie sample: {}", if sample.name.is_empty() { &sample.sha256 } else { &sample.name }),
        "date": &utc(at)[..10],
        "timestamp": (at / 1000).to_string(),
        "publish_timestamp": "0",
        "threat_level_id": match assessment {
            "matched_indicators" => "1",
            "suspicious_behaviour" => "2",
            _ => "4",
        },
        "analysis": "2",
        "distribution": "0",
        "published": false,
        "Orgc": {"uuid": uuid5("misp-org:antinomie"), "name": "Antinomie"},
        "Attribute": attrs,
        "Tag": tags,
    });
    if !cluster.is_empty() {
        event["Galaxy"] = json!([{
            "uuid": uuid5("misp-galaxy:mitre-attack-pattern"),
            "name": "Attack Pattern",
            "type": "mitre-attack-pattern",
            "namespace": "mitre-attack",
            "description": "ATT&CK techniques the sample's rules cite",
            "GalaxyCluster": cluster,
        }]);
    }
    serde_json::to_string_pretty(&json!({"Event": event})).map_err(|e| e.to_string())
}

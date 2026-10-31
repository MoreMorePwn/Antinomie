// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The STIX 2.1 export: a bundle with an identity, the sample (`file` and
//! `malware`), a `malware-analysis` of the run, an `indicator` per indicator,
//! an `attack-pattern` per ATT&CK technique, and the relationships between
//! them. Raw, not defanged, values. Ids are version-5 UUIDs of the object's
//! content, so a second export of the same run has the same ids.
use super::misp::split_endpoint;
use super::{Indicator, Report, iso, uuid5};
use serde_json::{Value, json};

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'"))
}

/// The STIX pattern of an indicator, when it has a form STIX can match.
fn pattern(indicator: &Indicator) -> Option<String> {
    match indicator.kind.as_str() {
        "endpoint" => {
            let (ip, port) = split_endpoint(&indicator.value)?;
            let ty = if ip.contains(':') {
                "ipv6-addr"
            } else {
                "ipv4-addr"
            };
            Some(format!(
                "[network-traffic:dst_ref.type = '{ty}' AND network-traffic:dst_ref.value = {} AND \
                 network-traffic:dst_port = {port}]",
                quote(&ip)
            ))
        }
        "domain" => Some(format!("[domain-name:value = {}]", quote(&indicator.value))),
        "url" => {
            (!indicator.url.is_empty()).then(|| format!("[url:value = {}]", quote(&indicator.url)))
        }
        "tls" => {
            let mut parts = Vec::new();
            if !indicator.sni.is_empty() {
                parts.push(format!("domain-name:value = {}", quote(&indicator.sni)));
            }
            if !indicator.cert_sha1.is_empty() {
                parts.push(format!(
                    "x509-certificate:hashes.'SHA-1' = {}",
                    quote(&indicator.cert_sha1)
                ));
            }
            (!parts.is_empty()).then(|| format!("[{}]", parts.join(" OR ")))
        }
        "file" => {
            let hash = if indicator.sha256.is_empty() {
                indicator.value.as_str()
            } else {
                indicator.sha256.as_str()
            };
            (hash.len() == 64).then(|| format!("[file:hashes.'SHA-256' = {}]", quote(hash)))
        }
        _ => None,
    }
}

fn object(kind: &str, seed: &str, at: &str, mut fields: Value) -> Value {
    let map = fields.as_object_mut().expect("an object");
    map.insert("type".into(), json!(kind));
    map.insert("spec_version".into(), json!("2.1"));
    map.insert(
        "id".into(),
        json!(format!("{kind}--{}", uuid5(&format!("stix:{kind}:{seed}")))),
    );
    map.insert("created".into(), json!(at));
    map.insert("modified".into(), json!(at));
    fields
}

fn id_of(value: &Value) -> String {
    value["id"].as_str().unwrap_or_default().to_owned()
}

fn relationship(kind: &str, from: &str, to: &str, at: &str) -> Value {
    object(
        "relationship",
        &format!("{kind}:{from}:{to}"),
        at,
        json!({"relationship_type": kind, "source_ref": from, "target_ref": to}),
    )
}

/// The STIX 2.1 bundle of `report`.
pub fn render(report: &Report) -> Result<String, String> {
    let at = iso(report.generated_ms);
    let run = &report.run.run_id;
    let mut objects: Vec<Value> = Vec::new();
    let identity = object(
        "identity",
        "antinomie",
        &at,
        json!({"name": "Antinomie", "identity_class": "system", "description": report.app}),
    );
    let identity_id = id_of(&identity);
    objects.push(identity);

    let mut malware_id = None;
    let mut sample_ref = None;
    if let Some(sample) = report.sample.as_ref().filter(|s| s.sha256.len() == 64) {
        let mut fields = json!({"hashes": {"SHA-256": sample.sha256}});
        if !sample.name.is_empty() {
            fields["name"] = json!(sample.name);
        }
        if let Some(size) = sample.size {
            fields["size"] = json!(size);
        }
        // A file object has no created or modified time and no spec version.
        let mut file = fields;
        file["type"] = json!("file");
        file["id"] = json!(format!(
            "file--{}",
            uuid5(&format!("stix:file:{}", sample.sha256))
        ));
        let file_id = id_of(&file);
        objects.push(file);
        let mut fields = json!({
            "is_family": false,
            "sample_refs": [file_id],
            "created_by_ref": identity_id,
        });
        fields["name"] = json!(if sample.name.is_empty() {
            &sample.sha256
        } else {
            &sample.name
        });
        let malware = object("malware", &sample.sha256, &at, fields);
        malware_id = Some(id_of(&malware));
        sample_ref = Some(file_id);
        objects.push(malware);
    }

    let assessment = report
        .summary
        .as_ref()
        .map_or("", |summary| summary.assessment.as_str());
    if let Some(sample_ref) = &sample_ref {
        let result = match assessment {
            "matched_indicators" | "suspicious_behaviour" => "suspicious",
            _ => "unknown",
        };
        objects.push(object(
            "malware-analysis",
            &format!("{run}:{sample_ref}"),
            &at,
            json!({
                "product": "antinomie",
                "version": crate::api::APP_VERSION,
                "result": result,
                "analysis_engine_version": crate::api::APP_VERSION,
                "sample_ref": sample_ref,
                "created_by_ref": identity_id,
            }),
        ));
    }

    for indicator in report.indicators.iter().flatten() {
        let Some(pattern) = pattern(indicator) else {
            continue;
        };
        let kinds = if indicator.matched {
            json!(["malicious-activity"])
        } else {
            json!(["anomalous-activity"])
        };
        let mut fields = json!({
            "name": format!("{} {}", indicator.kind, indicator.value),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": at,
            "indicator_types": kinds,
            "created_by_ref": identity_id,
            "description": format!("Observed in run {run}; dataset verdict: {}", indicator.verdict),
        });
        if let Some(confidence) = indicator.confidence {
            fields["confidence"] = json!(confidence);
        }
        let item = object(
            "indicator",
            &format!("{run}:{}", pattern_seed(indicator)),
            &at,
            fields,
        );
        if let Some(malware) = &malware_id {
            objects.push(relationship("indicates", &id_of(&item), malware, &at));
        }
        objects.push(item);
    }

    for technique in report.attack.iter().flatten() {
        let mut fields = json!({
            "name": if technique.name.is_empty() { &technique.id } else { &technique.name },
            "created_by_ref": identity_id,
            "external_references": [{
                "source_name": "mitre-attack",
                "external_id": technique.id,
                "url": format!("https://attack.mitre.org/techniques/{}/", technique.id.replace('.', "/")),
            }],
            "kill_chain_phases": [],
        });
        fields
            .as_object_mut()
            .expect("object")
            .remove("kill_chain_phases");
        let pattern = object("attack-pattern", &technique.id, &at, fields);
        if let Some(malware) = &malware_id {
            objects.push(relationship("uses", malware, &id_of(&pattern), &at));
        }
        objects.push(pattern);
    }

    // One note per matching rule, so its author and licence stay with the match.
    for hit in report.detections.iter().flatten() {
        let credit = |value: &str| if value.is_empty() { "unknown" } else { value }.to_owned();
        let mut fields = json!({
            "abstract": format!("{} rule {} matched", hit.engine, hit.rule_id),
            "content": format!(
                "{} rule {} ({}) matched {} time(s) in run {run}. Author: {}. License: {}. Source: {}.",
                hit.engine,
                hit.rule_id,
                hit.title,
                hit.count,
                credit(&hit.author),
                credit(&hit.license),
                credit(&hit.source),
            ),
            "authors": [credit(&hit.author)],
            "object_refs": [malware_id.clone().unwrap_or_else(|| identity_id.clone())],
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
            &format!("{run}:{}:{}", hit.engine, hit.rule_id),
            &at,
            fields,
        ));
    }

    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid5(&format!("stix:bundle:{run}:{}", report.generated_ms))),
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

fn pattern_seed(indicator: &Indicator) -> String {
    pattern(indicator).unwrap_or_default()
}

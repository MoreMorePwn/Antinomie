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
pub(in crate::report) fn pattern(indicator: &Indicator) -> Option<String> {
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

/// The `created` time of an object every export shares (the identity, the
/// sample's malware, an ATT&CK technique, what ties them): STIX 2.1 (3.6)
/// keeps `created` for every version of an id, and these ids are made from
/// content, so a later export, or the export of another run of the sample,
/// carries the same id (BH-21). Each export is a new version: its
/// `modified` is the export's time.
pub(in crate::report) const SHARED_CREATED: &str = "2026-01-01T00:00:00.000Z";

/// An SDO or SRO of the bundle. Its `created` is [`SHARED_CREATED`]; its
/// `modified` is `at`, the export's time.
pub(in crate::report) fn object(kind: &str, seed: &str, at: &str, fields: Value) -> Value {
    object_since(kind, seed, SHARED_CREATED, at, fields)
}

/// [`object`] created at `created`, a time that does not change from export
/// to export (a run's objects: the run's start). `modified` is `at`, or
/// `created` when that is later.
pub(in crate::report) fn object_since(
    kind: &str,
    seed: &str,
    created: &str,
    at: &str,
    mut fields: Value,
) -> Value {
    let map = fields.as_object_mut().expect("an object");
    map.insert("type".into(), json!(kind));
    map.insert("spec_version".into(), json!("2.1"));
    map.insert(
        "id".into(),
        json!(format!("{kind}--{}", uuid5(&format!("stix:{kind}:{seed}")))),
    );
    // Both are `iso` times of one form, so text order is time order.
    let modified = if at < created { created } else { at };
    map.insert("created".into(), json!(created));
    map.insert("modified".into(), json!(modified));
    fields
}

pub(in crate::report) fn id_of(value: &Value) -> String {
    value["id"].as_str().unwrap_or_default().to_owned()
}

pub(in crate::report) fn relationship(kind: &str, from: &str, to: &str, at: &str) -> Value {
    relationship_since(kind, from, to, SHARED_CREATED, at)
}

/// [`relationship`] created at `created` ([`object_since`]).
pub(in crate::report) fn relationship_since(
    kind: &str,
    from: &str,
    to: &str,
    created: &str,
    at: &str,
) -> Value {
    object_since(
        "relationship",
        &format!("{kind}:{from}:{to}"),
        created,
        at,
        json!({"relationship_type": kind, "source_ref": from, "target_ref": to}),
    )
}

/// The STIX 2.1 bundle of `report`.
pub fn render(report: &Report) -> Result<String, String> {
    let at = iso(report.generated_ms);
    let run = &report.run.run_id;
    // The run's own objects (its analysis, indicators, notes and report) are
    // created when it started, so every export of the run gives them the
    // same `created`.
    let since = report
        .run
        .started_ms
        .map_or_else(|| SHARED_CREATED.to_owned(), iso);
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
        if report.not_started() {
            // Nothing ran: the sample is a file and a note says why; there is
            // no malware analysis and nothing it was seen doing.
            objects.push(object_since(
                "note",
                &format!("{run}:not-started"),
                &since,
                &at,
                json!({
                    "abstract": format!("Run {run} did not start"),
                    "content": format!("Run {run} did not start, so nothing was observed. {}", report.run.state),
                    "object_refs": [file_id],
                    "created_by_ref": identity_id,
                }),
            ));
            let bundle = json!({
                "type": "bundle",
                "id": format!("bundle--{}", uuid5(&format!("stix:bundle:{run}:{}", report.generated_ms))),
                "objects": objects,
            });
            return serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string());
        }
        // The family the rules name, when they name one, is the malware
        // object; the sample is its file. Otherwise the sample is the malware.
        let family = report
            .summary
            .as_ref()
            .and_then(|summary| summary.families.first())
            .cloned();
        let mut fields = json!({
            "is_family": family.is_some(),
            "malware_types": ["unknown"],
            "sample_refs": [file_id],
            "created_by_ref": identity_id,
        });
        fields["name"] = json!(family.clone().unwrap_or_else(|| {
            if sample.name.is_empty() {
                sample.sha256.clone()
            } else {
                sample.name.clone()
            }
        }));
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
        objects.push(object_since(
            "malware-analysis",
            &format!("{run}:{sample_ref}"),
            &since,
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

    // One indicator per pattern: several indicators can give the same one (a
    // hash under many paths, a name seen as DNS and as SNI), and a bundle with
    // two objects of one id is invalid. Their places go in the description.
    let mut by_pattern: Vec<(String, Vec<&Indicator>)> = Vec::new();
    for indicator in report.indicators.iter().flatten().filter(|i| i.shared()) {
        let Some(pattern) = pattern(indicator) else {
            continue;
        };
        match by_pattern.iter_mut().find(|(known, _)| *known == pattern) {
            Some((_, group)) => group.push(indicator),
            None => by_pattern.push((pattern, vec![indicator])),
        }
    }
    for (pattern, group) in by_pattern {
        let first = group[0];
        let kinds = if group.iter().any(|i| i.matched) {
            json!(["malicious-activity"])
        } else {
            json!(["anomalous-activity"])
        };
        let mut paths: Vec<&str> = group
            .iter()
            .map(|i| i.path.as_str())
            .filter(|path| !path.is_empty())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        let verdict = first.verdict.trim();
        let mut description = format!("Observed in run {run}");
        if !paths.is_empty() {
            let shown: Vec<&str> = paths.iter().take(10).copied().collect();
            description.push_str(&format!(
                " at {} path(s): {}{}",
                paths.len(),
                shown.join(", "),
                if paths.len() > shown.len() {
                    ", ..."
                } else {
                    ""
                }
            ));
        }
        if !verdict.is_empty() && !verdict.to_ascii_lowercase().starts_with("not checked") {
            description.push_str(&format!("; dataset verdict: {verdict}"));
        }
        let mut fields = json!({
            "name": format!("{} {}", first.kind, first.value),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": at,
            "indicator_types": kinds,
            "created_by_ref": identity_id,
            "description": description,
        });
        if let Some(confidence) = first.confidence {
            fields["confidence"] = json!(confidence);
        }
        let item = object_since(
            "indicator",
            &format!("{run}:{pattern}"),
            &since,
            &at,
            fields,
        );
        if let Some(malware) = &malware_id {
            objects.push(relationship_since(
                "indicates",
                &id_of(&item),
                malware,
                &since,
                &at,
            ));
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
            "abstract": format!(
                "{} rule {} matched",
                hit.engine,
                super::layout::plain_rule(&hit.rule_id)
            ),
            "content": format!(
                "{} rule {} ({}) matched {} time(s) in run {run}. Author: {}. License: {}. Source: {}.",
                hit.engine,
                super::layout::plain_rule(&hit.rule_id),
                super::layout::plain_rule(&hit.title),
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
        objects.push(object_since(
            "note",
            &format!("{run}:{}:{}", hit.engine, hit.rule_id),
            &since,
            &at,
            fields,
        ));
    }

    // A report ties the bundle together for importers that list reports.
    if let Some(malware) = &malware_id {
        let refs: Vec<String> = objects
            .iter()
            .filter(|o| !matches!(o["type"].as_str(), Some("identity" | "relationship")))
            .map(id_of)
            .collect();
        objects.push(object_since(
            "report",
            &format!("{run}:{malware}"),
            &since,
            &at,
            json!({
                "name": format!("Antinomie triage of run {run}"),
                "published": at,
                "report_types": ["malware"],
                "object_refs": refs,
                "created_by_ref": identity_id,
            }),
        ));
    }
    // The safety net: never two objects of one id.
    let mut seen = std::collections::BTreeSet::new();
    objects.retain(|object| seen.insert(id_of(object)));
    let bundle = json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid5(&format!("stix:bundle:{run}:{}", report.generated_ms))),
        "objects": objects,
    });
    serde_json::to_string_pretty(&bundle).map_err(|e| e.to_string())
}

pub(in crate::report) fn pattern_seed(indicator: &Indicator) -> String {
    pattern(indicator).unwrap_or_default()
}

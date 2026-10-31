// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The MISP export: one event in MISP's core JSON format with the run's
//! indicators as attributes (`to_ids` only for those a dataset matched) and
//! each ATT&CK technique as a `mitre-attack-pattern` galaxy tag and cluster.
//! Raw, not defanged, values. The galaxy cluster uuids are derived from the
//! technique id (MISP matches clusters by their tag name when its own galaxy
//! is loaded).
use super::{Indicator, Report, Technique, iso, uuid5};
use serde_json::{Value, json};

/// A `host:port` or `[v6]:port` endpoint split into address and port.
pub(super) fn split_endpoint(text: &str) -> Option<(String, u16)> {
    let (host, port) = text.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>().ok()?;
    Some((host.to_owned(), port))
}

fn attribute(
    kind: &str,
    category: &str,
    value: &str,
    to_ids: bool,
    comment: &str,
    seed: &str,
    at: u64,
) -> Value {
    json!({
        "uuid": uuid5(&format!("misp-attribute:{seed}:{kind}:{value}")),
        "type": kind,
        "category": category,
        "value": value,
        "to_ids": to_ids,
        "distribution": "0",
        "comment": comment,
        "timestamp": (at / 1000).to_string(),
    })
}

fn comment(indicator: &Indicator) -> String {
    let mut parts = vec![format!("verdict: {}", indicator.verdict)];
    if !indicator.dataset.is_empty() {
        parts.push(format!("dataset: {}", indicator.dataset));
    }
    if !indicator.family.is_empty() {
        parts.push(format!("family: {}", indicator.family));
    }
    if !indicator.process.is_empty() {
        parts.push(format!("process: {}", indicator.process));
    }
    if !indicator.sources.is_empty() {
        parts.push(format!("seen in: {}", indicator.sources));
    }
    parts.join("; ")
}

fn attributes(indicator: &Indicator, seed: &str, at: u64) -> Vec<Value> {
    let note = comment(indicator);
    let ids = indicator.matched;
    let mut out = Vec::new();
    match indicator.kind.as_str() {
        "endpoint" => {
            if let Some((ip, port)) = split_endpoint(&indicator.value) {
                out.push(attribute(
                    "ip-dst|port",
                    "Network activity",
                    &format!("{ip}|{port}"),
                    ids,
                    &note,
                    seed,
                    at,
                ));
            }
        }
        "domain" => out.push(attribute(
            "domain",
            "Network activity",
            &indicator.value,
            ids,
            &note,
            seed,
            at,
        )),
        "url" => {
            if !indicator.url.is_empty() {
                out.push(attribute(
                    "url",
                    "Network activity",
                    &indicator.url,
                    ids,
                    &note,
                    seed,
                    at,
                ));
            }
        }
        "tls" => {
            if !indicator.sni.is_empty() {
                out.push(attribute(
                    "hostname",
                    "Network activity",
                    &indicator.sni,
                    ids,
                    &note,
                    seed,
                    at,
                ));
            }
            if !indicator.ja3.is_empty() {
                out.push(attribute(
                    "ja3-fingerprint-md5",
                    "Network activity",
                    &indicator.ja3,
                    ids,
                    &note,
                    seed,
                    at,
                ));
            }
            if !indicator.cert_sha1.is_empty() {
                out.push(attribute(
                    "x509-fingerprint-sha1",
                    "Network activity",
                    &indicator.cert_sha1,
                    ids,
                    &note,
                    seed,
                    at,
                ));
            }
        }
        "file" => {
            let hash = if indicator.sha256.is_empty() {
                indicator.value.as_str()
            } else {
                indicator.sha256.as_str()
            };
            if hash.len() == 64 {
                if indicator.path.is_empty() {
                    out.push(attribute(
                        "sha256",
                        "Artifacts dropped",
                        hash,
                        ids,
                        &note,
                        seed,
                        at,
                    ));
                } else {
                    out.push(attribute(
                        "filename|sha256",
                        "Artifacts dropped",
                        &format!("{}|{hash}", indicator.path),
                        ids,
                        &note,
                        seed,
                        at,
                    ));
                }
            }
        }
        _ => {}
    }
    out
}

/// The name part of ATT&CK's `Parent: Sub` form: MISP names a sub-technique
/// by its own name.
fn cluster_value(technique: &Technique) -> String {
    let name = technique
        .name
        .rsplit_once(": ")
        .map_or(technique.name.as_str(), |(_, sub)| sub);
    if name.is_empty() {
        technique.id.clone()
    } else {
        format!("{name} - {}", technique.id)
    }
}

/// The MISP event of `report`.
pub fn render(report: &Report) -> Result<String, String> {
    let at = report.generated_ms;
    let seed = format!(
        "{}:{}",
        report.run.run_id,
        report.sample.as_ref().map_or("", |s| s.sha256.as_str())
    );
    let name = report
        .sample
        .as_ref()
        .map(|s| s.name.as_str())
        .filter(|n| !n.is_empty())
        .unwrap_or(&report.run.run_id);
    let assessment = report
        .summary
        .as_ref()
        .map_or("", |summary| summary.assessment.as_str());
    let mut attrs = Vec::new();
    if let Some(sample) = &report.sample
        && sample.sha256.len() == 64
    {
        attrs.push(attribute(
            "sha256",
            "Payload delivery",
            &sample.sha256,
            true,
            "the sample the run executed",
            &seed,
            at,
        ));
        if !sample.name.is_empty() {
            attrs.push(attribute(
                "filename",
                "Payload delivery",
                &sample.name,
                false,
                "the sample's file name",
                &seed,
                at,
            ));
        }
    }
    let mut dropped_seen = std::collections::BTreeSet::new();
    for indicator in report.indicators.iter().flatten() {
        for attr in attributes(indicator, &seed, at) {
            // One attribute per value, even when two indicators give it.
            if dropped_seen.insert((attr["type"].to_string(), attr["value"].to_string())) {
                attrs.push(attr);
            }
        }
    }
    for hit in report.detections.iter().flatten() {
        attrs.push(attribute(
            "comment",
            "Other",
            &format!(
                "{} rule {} ({}) matched {} time(s). Author: {}. License: {}. Source: {}{}",
                hit.engine,
                hit.rule_id,
                hit.title,
                hit.count,
                if hit.author.is_empty() {
                    "unknown"
                } else {
                    &hit.author
                },
                if hit.license.is_empty() {
                    "unknown"
                } else {
                    &hit.license
                },
                if hit.source.is_empty() {
                    "unknown"
                } else {
                    &hit.source
                },
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
    attrs.push(attribute(
        "comment",
        "Other",
        &format!(
            "Written by {} at {}. Observations from a recorded run, not a verdict.",
            report.app,
            iso(at)
        ),
        false,
        "",
        &seed,
        at,
    ));
    let mut tags = vec![json!({"name": "antinomie:triage-report", "colour": "#0b5cad"})];
    if !assessment.is_empty() {
        tags.push(
            json!({"name": format!("antinomie:assessment=\"{assessment}\""), "colour": "#6b4e00"}),
        );
    }
    let mut cluster = Vec::new();
    for technique in report.attack.iter().flatten() {
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
        "info": format!("Antinomie triage: {name}"),
        "date": &super::utc(at)[..10],
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
            "description": "ATT&CK techniques the run's rules cite",
            "GalaxyCluster": cluster,
        }]);
    }
    serde_json::to_string_pretty(&json!({"Event": event})).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_split_into_address_and_port() {
        assert_eq!(
            split_endpoint("203.0.113.5:443"),
            Some(("203.0.113.5".into(), 443))
        );
        assert_eq!(
            split_endpoint("[2001:db8::1]:8080"),
            Some(("2001:db8::1".into(), 8080))
        );
        assert_eq!(split_endpoint("example.com:80"), None);
    }
}

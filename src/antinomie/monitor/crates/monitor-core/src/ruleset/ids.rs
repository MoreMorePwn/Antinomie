// SPDX-License-Identifier: MIT
//! Suricata rule parsing for the rule index.
use super::*;

pub(super) const IDS_DATASET_REASON: &str = "requires an external dataset";
pub(super) const IDS_TLS_REASON: &str =
    "requires a TLS fingerprint keyword that is not part of the bundled Suricata configuration";

pub(super) fn parse_ids(text: &str) -> Vec<IndexedRule> {
    ids_blocks(text)
        .into_iter()
        .map(|(sid, body)| {
            let (compatible, reason) = ids_support(&body);
            IndexedRule {
                id: sid.clone(),
                name: ids_msg(&body).unwrap_or_else(|| format!("sid {sid}")),
                file: String::new(),
                helper: false,
                tags: Vec::new(),
                severity: ids_field(&body, "classtype").unwrap_or_default(),
                license: String::new(),
                source_url: ids_field(&body, "reference").unwrap_or_default(),
                condition: clip(&body, 180),
                references: Vec::new(),
                evidence: vec!["pcap".into()],
                compatible,
                reason,
                content_sha256: format!("{:x}", Sha256::digest(body.as_bytes())),
                depends_on: Vec::new(),
            }
        })
        .collect()
}

pub(super) fn ids_blocks(text: &str) -> Vec<(String, String)> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if current.is_empty() && !ids_action(trimmed) {
            continue;
        }
        current.push_str(line);
        current.push('\n');
        if trimmed.ends_with(')') {
            if let Some(sid) = ids_field(&current, "sid") {
                blocks.push((sid, current.clone()));
            }
            current.clear();
        }
    }
    blocks
}

fn ids_action(line: &str) -> bool {
    line.starts_with("alert ")
        || line.starts_with("drop ")
        || line.starts_with("pass ")
        || line.starts_with("reject ")
}

fn ids_support(body: &str) -> (bool, String) {
    if body.contains("dataset:") {
        return (false, IDS_DATASET_REASON.into());
    }
    if body.contains("ja3.") || body.contains("ja3s.") || body.contains("ja4.") {
        return (false, IDS_TLS_REASON.into());
    }
    (true, String::new())
}

fn ids_field(body: &str, key: &str) -> Option<String> {
    let marker = format!("{key}:");
    let start = body.find(&marker)? + marker.len();
    let rest = body[start..].trim_start();
    let end = rest.find([';', ',']).unwrap_or(rest.len());
    let value = rest[..end].trim().trim_matches('"').to_owned();
    (!value.is_empty()).then_some(value)
}

fn ids_msg(body: &str) -> Option<String> {
    let start = body.find("msg:\"")? + 5;
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

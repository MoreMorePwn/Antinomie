// SPDX-License-Identifier: MIT
//! Sigma rule parsing and the captured-category check.
use super::*;

const SIGMA_CATEGORIES: [&str; 9] = [
    "process_creation",
    "file_event",
    "file_delete",
    "file_rename",
    "file_access",
    "dns_query",
    "http_request",
    "antinomie_bpf",
    "antinomie_file_metadata",
];

pub(super) fn parse_sigma(text: &str) -> Vec<IndexedRule> {
    text.split("\n---\n")
        .filter(|doc| doc.contains("title:"))
        .map(|doc| {
            let id = meta_line(doc, "id").unwrap_or_else(|| "missing-id".into());
            let category = meta_line(doc, "category").unwrap_or_default();
            let product = meta_line(doc, "product").unwrap_or_default();
            let (compatible, reason) = sigma_support(&product, &category, doc);
            IndexedRule {
                id: id.clone(),
                name: meta_line(doc, "title").unwrap_or_else(|| id.clone()),
                file: String::new(),
                helper: false,
                tags: sigma_tags(doc),
                severity: meta_line(doc, "level").unwrap_or_default(),
                license: meta_line(doc, "license").unwrap_or_default(),
                source_url: String::new(),
                condition: clip(&meta_line(doc, "description").unwrap_or_default(), 180),
                references: sigma_refs(doc),
                evidence: vec![category.clone()],
                compatible,
                reason,
                content_sha256: format!("{:x}", Sha256::digest(doc.as_bytes())),
                depends_on: Vec::new(),
            }
        })
        .collect()
}

fn sigma_support(product: &str, category: &str, doc: &str) -> (bool, String) {
    if !product.is_empty() && product != "linux" {
        return (
            false,
            format!("product {product} is not a captured Linux event"),
        );
    }
    if !SIGMA_CATEGORIES.contains(&category) {
        return (
            false,
            format!("category {category} is not a captured event category"),
        );
    }
    if doc.contains("\ncorrelation:") || doc.starts_with("correlation:") {
        return (
            false,
            "correlation rules are not a single journal query".into(),
        );
    }
    let unknown = sigma_unknown_fields(doc);
    if !unknown.is_empty() {
        return (
            false,
            format!("fields outside the captured schema: {}", unknown.join(", ")),
        );
    }
    if doc.contains("CommandLine:") || doc.contains("CommandLine|") {
        return (
            true,
            "CommandLine is recorded only when the argument vector is complete; a missing value is not invented and does not satisfy negation".into(),
        );
    }
    (true, String::new())
}

fn sigma_unknown_fields(doc: &str) -> Vec<String> {
    const KNOWN: &[&str] = &[
        "Image",
        "CommandLine",
        "ProcessId",
        "ThreadId",
        "TargetFilename",
        "SourceFilename",
        "QueryName",
        "QueryType",
        "ResponseCode",
        "DestinationIp",
        "DestinationPort",
        "HttpMethod",
        "HttpHost",
        "HttpUri",
        "Syscall",
        "Operation",
        "Result",
        "TransferredSize",
        "BpfCommand",
        "Mode",
        "Setuid",
    ];
    let mut unknown = Vec::new();
    let mut detection = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("detection:") {
            detection = true;
            continue;
        }
        if detection && !line.starts_with(' ') && !line.starts_with('\t') && !trimmed.is_empty() {
            break;
        }
        if !detection {
            continue;
        }
        let Some((key, _)) = trimmed.split_once(':') else {
            continue;
        };
        let field = key.split('|').next().unwrap_or(key).trim();
        if field.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && !KNOWN.contains(&field)
            && !unknown.iter().any(|seen| seen == field)
        {
            unknown.push(field.to_owned());
        }
    }
    unknown
}

pub(super) fn meta_line(doc: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    for line in doc.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix(&prefix) {
            let value = value
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_owned();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

pub(super) fn meta_in(body: &str, key: &str) -> String {
    let marker = format!("{key} =");
    body.lines()
        .find_map(|line| {
            let trimmed = line.trim().trim_end_matches(',');
            trimmed.strip_prefix(&marker).map(|value| {
                value
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'')
                    .to_owned()
            })
        })
        .unwrap_or_default()
}

pub(super) fn reference_list(body: &str) -> Vec<String> {
    let mut refs = Vec::new();
    if let Some(value) = body.lines().find_map(|line| {
        line.trim()
            .strip_prefix("reference =")
            .map(|value| value.trim().trim_matches('"').to_owned())
    }) && !value.is_empty()
    {
        refs.push(value);
    }
    refs
}

fn sigma_tags(doc: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut in_tags = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("tags:") {
            in_tags = true;
            continue;
        }
        if in_tags && trimmed.starts_with("- ") {
            tags.push(trimmed[2..].to_owned());
            if tags.len() == 12 {
                break;
            }
        } else if in_tags && !trimmed.is_empty() {
            break;
        }
    }
    tags
}

fn sigma_refs(doc: &str) -> Vec<String> {
    let mut refs = Vec::new();
    let mut in_refs = false;
    for line in doc.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("references:") {
            in_refs = true;
            continue;
        }
        if in_refs && let Some(value) = trimmed.strip_prefix("- ") {
            refs.push(value.to_owned());
        } else if in_refs && !trimmed.is_empty() {
            break;
        }
    }
    refs
}

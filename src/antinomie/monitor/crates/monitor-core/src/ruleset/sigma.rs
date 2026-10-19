// SPDX-License-Identifier: MIT
//! Sigma rule parsing and the captured-category check.
use super::*;

const SIGMA_CATEGORIES: [&str; 10] = [
    "process_creation",
    "file_event",
    "file_delete",
    "file_rename",
    "file_access",
    "dns_query",
    "http_request",
    "network_connection",
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
            let service = logsource_of(doc).2;
            let (compatible, reason) = sigma_support(&product, &category, &service, doc);
            // auditd rules read the auditd-style records, journal category `auditd`.
            let category = if is_auditd(&category, &service) {
                "auditd".to_owned()
            } else {
                category
            };
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

/// `service: auditd` without a category: evaluated against auditd-style records.
fn is_auditd(category: &str, service: &str) -> bool {
    category.is_empty() && service.eq_ignore_ascii_case("auditd")
}

fn sigma_support(product: &str, category: &str, service: &str, doc: &str) -> (bool, String) {
    let audit = is_auditd(category, service);
    if !product.is_empty() && product != "linux" {
        return (
            false,
            format!("product {product} is not a captured Linux event"),
        );
    }
    if category.is_empty() && !service.is_empty() && !audit {
        return (
            false,
            format!(
                "service {service} log lines are not captured; Antinomie records system calls and network observations, not that service's log"
            ),
        );
    }
    if !audit && !SIGMA_CATEGORIES.contains(&category) {
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
    let unknown = sigma_unknown_fields(doc, audit);
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

fn sigma_unknown_fields(doc: &str, audit: bool) -> Vec<String> {
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
        "Initiated",
        "ParentImage",
        "ParentCommandLine",
        "ParentProcessId",
        "CurrentDirectory",
        "DestinationHostname",
        "SourceIp",
        "SourcePort",
        "Protocol",
        "IsNewFile",
    ];
    // auditd fields the recording cannot supply: credentials, audit rule keys,
    // file ownership and mode. A rule that needs one is not evaluated.
    const AUDITD_ABSENT: &[&str] = &[
        "key", "auid", "uid", "euid", "gid", "egid", "suid", "fsuid", "sgid", "fsgid", "ses",
        "tty", "mode", "inode", "ouid", "ogid", "unit",
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
        let uppercase = field.chars().next().is_some_and(|c| c.is_ascii_uppercase());
        // Field names are case-insensitive: auditd rules write `SYSCALL`.
        let missing = (uppercase && !KNOWN.iter().any(|known| known.eq_ignore_ascii_case(field)))
            || (audit && AUDITD_ABSENT.contains(&field));
        if missing && !unknown.iter().any(|seen| seen == field) {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(logsource: &str, detection: &str) -> IndexedRule {
        let doc = format!(
            "title: t\nid: 11111111-1111-4111-8111-111111111111\nlogsource:\n{logsource}\ndetection:\n{detection}\n    condition: selection\nlevel: low\n"
        );
        parse_sigma(&doc).remove(0)
    }

    #[test]
    fn auditd_rules_need_fields_the_trace_can_supply() {
        let audit = "    product: linux\n    service: auditd";
        let known = rule(
            audit,
            "    selection:\n        type: 'SYSCALL'\n        SYSCALL: 'personality'\n        a0: 40000\n        exe|endswith: '/x'",
        );
        assert!(known.compatible, "{}", known.reason);
        assert_eq!(known.evidence, ["auditd"]);
        for field in ["key", "euid", "auid"] {
            let absent = rule(
                audit,
                &format!("    selection:\n        type: 'SYSCALL'\n        {field}: 'x'"),
            );
            assert!(!absent.compatible, "{field}");
            assert!(absent.reason.contains(field), "{}", absent.reason);
        }
        let other = rule(
            "    product: linux\n    service: syslog",
            "    selection:\n        a0: 'x'",
        );
        assert!(!other.compatible && other.reason.contains("syslog"));
    }
}

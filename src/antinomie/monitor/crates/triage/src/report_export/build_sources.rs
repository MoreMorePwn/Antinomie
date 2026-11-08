// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The report's Network tables, detections, evidence list and custody head:
//! the parts read from the scan's network tabs and from the run's folder.
use super::super::{net_tabs, pcap_scan};
use super::build::{all, table};
use super::*;
use antinomie_monitor_core::{
    report::{Custody, Detection, EvidenceRef, IndicatorKind, NamedTable},
    run_digest::RunDigest,
};
use std::path::Path;

pub fn network(scan: &ArchiveScan) -> Vec<NamedTable> {
    let mut tabs = network_tables(scan);
    let sources: [(&[&str], &[Vec<Cell>]); 4] = [
        (net_tabs::ENDPOINT_HEADERS, &scan.new_tabs.endpoints),
        (net_tabs::DOMAIN_HEADERS, &scan.new_tabs.domains),
        (net_tabs::URL_HEADERS, &scan.new_tabs.urls),
        (net_tabs::TLS_HEADERS, &scan.new_tabs.tls),
    ];
    for (named, (headers, rows)) in tabs.iter_mut().zip(sources) {
        named.table.data = super::rows::network(&named.name, headers, rows);
    }
    tabs
}

fn network_tables(scan: &ArchiveScan) -> Vec<NamedTable> {
    use IndicatorKind::*;
    let tabs = &scan.new_tabs;
    let _ = pcap_scan::SESSION_HEADERS;
    vec![
        NamedTable {
            name: "Endpoints".into(),
            table: table(
                net_tabs::ENDPOINT_HEADERS,
                &all(net_tabs::ENDPOINT_HEADERS.len()),
                &tabs.endpoints,
                tabs.endpoints_omitted,
                &[(0, Endpoint)],
            ),
        },
        NamedTable {
            name: "Domains".into(),
            table: table(
                net_tabs::DOMAIN_HEADERS,
                &all(net_tabs::DOMAIN_HEADERS.len()),
                &tabs.domains,
                tabs.domains_omitted,
                &[(0, Domain)],
            ),
        },
        NamedTable {
            name: "URLs".into(),
            table: table(
                net_tabs::URL_HEADERS,
                &all(net_tabs::URL_HEADERS.len()),
                &tabs.urls,
                scan.http_omitted,
                &[(2, Endpoint), (5, Domain)],
            ),
        },
        NamedTable {
            name: "TLS".into(),
            table: table(
                net_tabs::TLS_HEADERS,
                &all(net_tabs::TLS_HEADERS.len()),
                &tabs.tls,
                tabs.tls_omitted,
                &[(1, Tls), (3, Endpoint)],
            ),
        },
    ]
}

pub fn detections(run_dir: &Path) -> Vec<Detection> {
    RunDigest::read(run_dir)
        .and_then(|digest| digest.detections)
        .unwrap_or_default()
        .into_iter()
        .map(|hit| Detection {
            family: super::super::family::rule_family(&hit).unwrap_or_default(),
            strength: if hit.engine.eq_ignore_ascii_case("yara") {
                match super::super::family::strength(
                    &hit.rule_id,
                    &hit.severity,
                    &hit.source,
                    &hit.family,
                ) {
                    super::super::family::Strength::Strong => "strong",
                    super::super::family::Strength::Weak => "weak",
                    super::super::family::Strength::WrongPlatform => "wrong platform",
                }
                .to_owned()
            } else {
                String::new()
            },
            engine: hit.engine,
            rule_id: hit.rule_id,
            title: hit.title,
            severity: hit.severity,
            mitre: hit.mitre,
            count: hit.count,
            author: hit.author,
            license: hit.license,
            source: hit.source,
            reference: hit.reference,
            ..Detection::default()
        })
        .collect()
}

/// Files up to this size are hashed for the evidence list.
const HASH_LIMIT: u64 = 64 * 1024 * 1024;

fn tree_size(path: &Path, depth: usize, budget: &mut usize, files: &mut u64) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    let mut total = 0;
    for entry in entries.flatten() {
        if *budget == 0 {
            break;
        }
        *budget -= 1;
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() {
            total += meta.len();
            *files += 1;
        } else if meta.is_dir() && depth < 6 {
            total += tree_size(&entry.path(), depth + 1, budget, files);
        }
    }
    total
}

pub fn evidence(run_dir: &Path) -> Vec<EvidenceRef> {
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        // The report's own folder and temporary files are not evidence.
        if name == "report" || name.starts_with('.') || name.ends_with(".tmp") {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        let kind = if name == "telemetry.raw" || lower.contains("telemetry") {
            "telemetry"
        } else if lower.contains("pcap") {
            "network capture"
        } else if lower.contains("memory") {
            "memory dump"
        } else if lower.contains("core") {
            "core dump"
        } else if lower.contains("disk") || lower.ends_with(".qcow2") {
            "disk"
        } else if name == "objects" || lower.contains("object") {
            "object store"
        } else if name == "reconstructed" {
            "reconstructed"
        } else if name == "analysis" {
            "static analysis"
        } else if name == "bpf" {
            "ebpf programs"
        } else {
            "other"
        };
        if meta.is_file() {
            let sha256 = if meta.len() <= HASH_LIMIT {
                antinomie_monitor_core::storage::sha256_file_hex(&entry.path()).unwrap_or_default()
            } else {
                String::new()
            };
            out.push(EvidenceRef {
                kind: kind.into(),
                path: name,
                size: meta.len(),
                sha256,
                files: None,
            });
        } else if meta.is_dir() {
            let mut budget = 200_000;
            let mut files = 0;
            out.push(EvidenceRef {
                kind: kind.into(),
                path: format!("{name}/"),
                size: tree_size(&entry.path(), 0, &mut budget, &mut files),
                sha256: String::new(),
                files: Some(files),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub fn custody(job: &Job) -> Result<Custody, String> {
    let (sample, data_dir) = job
        .sample
        .as_ref()
        .zip(job.data_dir.as_ref())
        .ok_or("the run has no sample record to read a custody log for")?;
    let library = antinomie_monitor_core::samples::Library::open(data_dir)?;
    // A file that is not a library sample has no custody log to report.
    if library.get(&sample.sha256)?.is_none() {
        return Err("the file is not a library sample, so there is no custody log".into());
    }
    let (value, _) = library.custody_record(&sample.sha256)?;
    Ok(Custody {
        sample_sha256: sample.sha256.clone(),
        entries: value["status"]["entries"].as_u64().unwrap_or(0),
        head: value["status"]["head"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        verified: value["status"]["verified"].as_bool().unwrap_or(false),
        library_head: value["library_index"]["head"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        problem: value["status"]["problem"]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
    })
}

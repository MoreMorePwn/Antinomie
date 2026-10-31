// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The report from a whole-run index: each part reads the same rows Triage's
//! tables hold, so the report says what the tabs say.
use super::super::{
    digest, file_activity::start_of, file_tabs, ioc_scan, net_tabs, pcap_scan, rules, FileTab,
};
use super::*;
use antinomie_monitor_core::{
    file_reconstruct::Reconstruction,
    ioc::{
        export as ioc_export,
        verdict::{Outcome, Verdict},
    },
    mitre,
    report::{
        bundle::{self, BundleInput, DroppedFile},
        Counts, Custody, Detection, EvidenceRef, FileRecord, FilesSection, IndicatorColumn,
        IndicatorKind, NamedTable, Part, Report, Summary, Table, Technique,
    },
    run_digest::RunDigest,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What the build made: the report, and the bundle's inputs when asked for.
pub(super) struct Built {
    pub report: Report,
    pub bundle: Option<BundleInput>,
}

/// Rows of `rows` at `keep`, as a table with `columns` named.
fn table(
    headers: &[&str],
    keep: &[usize],
    rows: &[Vec<Cell>],
    omitted: u64,
    indicators: &[(usize, IndicatorKind)],
) -> Table {
    Table {
        columns: keep.iter().map(|&i| headers[i].to_owned()).collect(),
        rows: rows
            .iter()
            .map(|row| {
                keep.iter()
                    .map(|&i| row.get(i).map(|c| c.text.clone()).unwrap_or_default())
                    .collect()
            })
            .collect(),
        omitted,
        indicator_columns: indicators
            .iter()
            .filter_map(|&(shown, kind)| {
                keep.iter()
                    .position(|&i| i == shown)
                    .map(|column| IndicatorColumn { column, kind })
            })
            .collect(),
    }
}

fn all(n: usize) -> Vec<usize> {
    (0..n).collect()
}

fn technique_id(id: &str) -> bool {
    let rest = id.strip_prefix('T').unwrap_or("");
    let (main, sub) = rest
        .split_once('.')
        .map_or((rest, None), |(a, b)| (a, Some(b)));
    main.len() == 4
        && main.bytes().all(|b| b.is_ascii_digit())
        && sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
}

fn tier_rank(tier: &str) -> usize {
    rules::Tier::ALL
        .iter()
        .position(|t| t.tag() == tier)
        .unwrap_or(usize::MAX)
}

fn indicators(job: &Job, scan: &ArchiveScan) -> Vec<(report::Indicator, bool)> {
    let Some(ioc) = &scan.ioc else {
        return Vec::new();
    };
    let fp = job
        .data_dir
        .as_deref()
        .map(antinomie_monitor_core::known_fp::load)
        .unwrap_or_default();
    let online = antinomie_monitor_core::ioc::online::load(&job.archive);
    let verdicts: Vec<Verdict> = ioc_scan::verdicts(ioc, &fp, &online);
    ioc.indicators
        .iter()
        .zip(&verdicts)
        .map(|(indicator, verdict)| {
            let cells = ioc_export::row(indicator, verdict);
            let cell = |name: &str| {
                ioc_export::COLUMNS
                    .iter()
                    .position(|c| *c == name)
                    .and_then(|i| cells.get(i))
                    .cloned()
                    .unwrap_or_default()
            };
            let matched = verdict.outcome == Outcome::Matched;
            let tls = indicator.tls.clone().unwrap_or_default();
            let hashes = indicator.hashes.clone().unwrap_or_default();
            let primary = verdict.primary();
            let item = report::Indicator {
                kind: indicator.ty.id().to_owned(),
                value: indicator.value.clone(),
                path: if indicator.ty == antinomie_monitor_core::ioc::indicator::Type::Url {
                    String::new()
                } else {
                    indicator.path.clone()
                },
                detail: indicator.sub.clone(),
                sources: cell("sources"),
                process: cell("process"),
                first_seen: cell("first_seen_in_run"),
                last_seen: cell("last_seen_in_run"),
                count: indicator.count.clone(),
                verdict: cell("verdict"),
                matched,
                dataset: cell("dataset"),
                record_id: cell("record_id"),
                family: cell("family"),
                confidence: primary.and_then(|m| m.record.confidence),
                reference: cell("reference"),
                url: if indicator.ty == antinomie_monitor_core::ioc::indicator::Type::Url
                    && !indicator.path.is_empty()
                {
                    format!("http://{}", indicator.path)
                } else {
                    String::new()
                },
                sni: tls.sni,
                ja3: tls.ja3,
                ja4: tls.ja4,
                cert_sha1: tls.cert_sha1,
                sha256: hashes.sha256,
                md5: hashes.md5,
                sha1: hashes.sha1,
            };
            (item, matched)
        })
        .collect()
}

fn summary(
    scan: &ArchiveScan,
    behaviour: &digest_types::Behaviour,
    indicators: &[(report::Indicator, bool)],
    techniques: usize,
) -> Summary {
    let matched = indicators.iter().filter(|(_, m)| *m).count();
    let families: BTreeSet<String> = indicators
        .iter()
        .filter(|(_, m)| *m)
        .map(|(i, _)| i.family.clone())
        .filter(|f| !f.is_empty())
        .collect();
    let mut key: Vec<_> = behaviour
        .rules
        .iter()
        .filter(|hit| matches!(hit.tier.as_str(), "high" | "medium"))
        .map(|hit| report::Behaviour {
            rule: hit.rule.clone(),
            tier: hit.tier.clone(),
            category: hit.category.clone(),
            count: hit.count,
        })
        .collect();
    key.sort_by(|a, b| {
        tier_rank(&a.tier)
            .cmp(&tier_rank(&b.tier))
            .then(b.count.cmp(&a.count))
            .then(a.rule.cmp(&b.rule))
    });
    key.truncate(25);
    let (assessment, basis) = if matched > 0 {
        (
            "matched_indicators",
            format!("{matched} indicator(s) matched a stored dataset"),
        )
    } else if matches!(behaviour.highest.as_str(), "high" | "medium") {
        (
            "suspicious_behaviour",
            format!(
                "{} activity rule(s) fired, the worst at {} tier",
                behaviour.rules.len(),
                behaviour.highest.to_uppercase()
            ),
        )
    } else if !behaviour.rules.is_empty() {
        (
            "observed_only",
            format!(
                "only low or informational rules fired ({})",
                behaviour.rules.len()
            ),
        )
    } else {
        ("no_findings", "no activity rule fired".to_owned())
    };
    let mut statement = format!(
        "Triage observed: {basis}.{} These are observations from a recorded run, not a verdict on the sample.",
        if families.is_empty() {
            String::new()
        } else {
            format!(
                " The datasets name the family {}.",
                families.iter().cloned().collect::<Vec<_>>().join(", ")
            )
        }
    );
    if !scan.finding_notes.is_empty() {
        statement.push_str(&format!(
            " {} rule(s) could not be evaluated.",
            scan.finding_notes.len()
        ));
    }
    Summary {
        assessment: assessment.into(),
        statement,
        highest_tier: if behaviour.highest.is_empty() {
            "none".into()
        } else {
            behaviour.highest.clone()
        },
        families: families.into_iter().collect(),
        key_behaviours: key,
        counts: Counts {
            processes: scan.process.len() as u64,
            findings: scan.findings.len() as u64 + scan.findings_omitted,
            indicators: indicators.len() as u64,
            indicators_matched: matched as u64,
            techniques: techniques as u64,
            files_changed: scan.changed.len() as u64 + scan.changed_omitted,
            files_opened: scan.opened.len() as u64 + scan.opened_omitted,
            endpoints: scan.new_tabs.endpoints.len() as u64 + scan.new_tabs.endpoints_omitted,
            domains: scan.new_tabs.domains.len() as u64 + scan.new_tabs.domains_omitted,
        },
    }
}

use antinomie_monitor_core::run_digest as digest_types;

fn attack(behaviour: &digest_types::Behaviour) -> Vec<Technique> {
    let mut found: BTreeMap<String, (BTreeSet<String>, u64)> = BTreeMap::new();
    for hit in &behaviour.rules {
        for id in hit.attack.iter().filter(|id| technique_id(id)) {
            let entry = found.entry(id.clone()).or_default();
            entry.0.insert(hit.rule.clone());
            entry.1 += hit.count.max(1);
        }
    }
    found
        .into_iter()
        .map(|(id, (rules, count))| Technique {
            name: mitre::technique_name(&id).unwrap_or_default(),
            id,
            rules: rules.into_iter().collect(),
            count,
        })
        .collect()
}

fn processes(scan: &ArchiveScan, clock: Option<antinomie_monitor_core::HostClockAnchor>) -> Table {
    let rows = super::super::process_tree::process_rows(&scan.process, clock, &scan.suspicious);
    let headers = [
        "Process",
        "Executable",
        "TID",
        "Argv",
        "First seen",
        "Last seen",
        "Task outcome",
        "Exec history",
    ];
    let mut out = table(&headers, &[0, 1, 3, 4, 5, 6, 7], &rows, 0, &[]);
    for (row, source) in out.rows.iter_mut().zip(&rows) {
        let depth = files::number(&source[0].values, "process.depth").unwrap_or(0) as usize;
        row[0] = format!(
            "{}{}{}",
            "-".repeat(depth),
            if depth > 0 { " " } else { "" },
            row[0]
        );
    }
    out
}

fn findings(scan: &ArchiveScan, clock: Option<antinomie_monitor_core::HostClockAnchor>) -> Table {
    let rows: Vec<Vec<Cell>> = scan
        .findings
        .iter()
        .map(|finding| {
            let mut cells = finding.cells.clone();
            cells[rules::COL_TIME].text = crate::time_format::guest_ns(
                clock,
                files::number(&finding.values, "event.time_ns"),
            );
            cells
        })
        .collect();
    table(
        rules::HEADERS,
        &[rules::COL_TIME, 1, 0, 2, 3, 4, 5, 11],
        &rows,
        scan.findings_omitted,
        &[],
    )
}

fn file_tabs_section(
    scan: &ArchiveScan,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> FilesSection {
    let mut tabs = Vec::new();
    for tab in FileTab::ALL {
        let (_, omitted) = scan.file_rows(tab);
        let named = match tab {
            FileTab::Changed => table(
                file_tabs::CHANGED_HEADERS,
                &all(file_tabs::CHANGED_HEADERS.len()),
                &scan.changed,
                omitted,
                &[],
            ),
            FileTab::Read => table(
                file_tabs::READ_HEADERS,
                file_tabs::READ_COLUMNS,
                &file_category::with_time(&scan.read, clock),
                omitted,
                &[],
            ),
            FileTab::Opened => table(
                file_category::EVENT_HEADERS,
                file_tabs::OPENED_COLUMNS,
                &file_category::with_time(&scan.opened, clock),
                omitted,
                &[],
            ),
            other => table(
                file_category::EVENT_HEADERS,
                &[0, 2, 3, 4, 5, 6],
                &file_category::with_time(&scan.file_tabs[other.slot() - 8].rows, clock),
                omitted,
                &[],
            ),
        };
        tabs.push(NamedTable {
            name: tab.title().to_owned(),
            table: named,
        });
    }
    FilesSection { tabs }
}

fn network(scan: &ArchiveScan) -> Vec<NamedTable> {
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

fn detections(run_dir: &Path) -> Vec<Detection> {
    RunDigest::read(run_dir)
        .and_then(|digest| digest.detections)
        .unwrap_or_default()
        .into_iter()
        .map(|hit| Detection {
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
        })
        .collect()
}

/// Files up to this size are hashed for the evidence list.
const HASH_LIMIT: u64 = 64 * 1024 * 1024;

fn tree_size(path: &Path, depth: usize, budget: &mut usize) -> u64 {
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
        } else if meta.is_dir() && depth < 6 {
            total += tree_size(&entry.path(), depth + 1, budget);
        }
    }
    total
}

fn evidence(run_dir: &Path) -> Vec<EvidenceRef> {
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
            });
        } else if meta.is_dir() {
            let mut budget = 200_000;
            out.push(EvidenceRef {
                kind: kind.into(),
                path: format!("{name}/"),
                size: tree_size(&entry.path(), 0, &mut budget),
                sha256: String::new(),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn custody(job: &Job) -> Result<Custody, String> {
    let (sample, data_dir) = job
        .sample
        .as_ref()
        .zip(job.data_dir.as_ref())
        .ok_or("the run has no sample record to read a custody log for")?;
    let library = antinomie_monitor_core::samples::Library::open(data_dir)?;
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

/// Files the run created or changed, with what the reconstruction knows; when
/// `bundle`, the ones whose bytes are all known are also set aside for the
/// dropped-files archive.
fn file_activity(
    scan: &ArchiveScan,
    bundle: bool,
) -> (Vec<FileRecord>, Vec<DroppedFile>, Vec<(String, String)>) {
    let activity = &scan.file_activity;
    let mut records = Vec::new();
    let mut dropped = Vec::new();
    let mut skipped = Vec::new();
    let mut total = 0u64;
    for (index, file) in activity.files.iter().enumerate() {
        if file.standard_io || file.failed_only || !(file.created || file.changed()) {
            continue;
        }
        let mut map = Reconstruction::new(start_of(file), &file.timeline);
        map.goto(file.timeline.steps().len());
        let counts = map.counts();
        let complete = map.complete();
        let guest = file
            .contents
            .hash
            .as_ref()
            .and_then(|h| h.sha256)
            .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>())
            .unwrap_or_default();
        let mut record = FileRecord {
            path: file.path.clone(),
            created: file.created,
            deleted: file.deleted,
            changed: file.changed(),
            final_size: map.size_known().then(|| map.size()),
            guest_sha256: guest.clone(),
            reconstruction: if complete { "complete" } else { "incomplete" }.into(),
            bytes_written: counts.written,
            bytes_not_captured: counts.not_captured,
            bytes_unknown: counts.unknown + counts.mapping,
            bundle_entry: String::new(),
        };
        if bundle {
            let size = map.size();
            if !complete {
                skipped.push((
                    file.path.clone(),
                    format!("{} bytes have no recorded value", counts.missing()),
                ));
            } else if counts.written == 0 && !file.created {
                // Nothing the run wrote: the starting disk's copy, not a drop.
            } else if size > bundle::DROPPED_FILE_LIMIT {
                skipped.push((
                    file.path.clone(),
                    format!("{size} bytes is over the per-file limit"),
                ));
            } else if total + size > bundle::DROPPED_TOTAL_LIMIT {
                skipped.push((
                    file.path.clone(),
                    "the archive total limit was reached".into(),
                ));
            } else if let Ok(sha256) = map.sha256() {
                total += size;
                record.bundle_entry = format!("dropped-files.zip/{sha256}.bin");
                let shared = activity.clone();
                dropped.push(DroppedFile {
                    path: file.path.clone(),
                    sha256,
                    guest_sha256: guest,
                    size,
                    write: Box::new(move |out| {
                        let file = &shared.files[index];
                        let mut map = Reconstruction::new(start_of(file), &file.timeline);
                        map.goto(file.timeline.steps().len());
                        map.save(out, None).map(|_| ())
                    }),
                });
            }
        }
        records.push(record);
    }
    (records, dropped, skipped)
}

/// The report for `scan` with the parts of `job.choices`.
pub(super) fn build(scan: &ArchiveScan, job: &Job) -> Result<Built, String> {
    let choices = &job.choices;
    let clock = scan.clock_anchor.or(job.clock);
    let mut report = Report::new(job.run.clone(), job.now_ms);
    report.sample = job.sample.clone();
    let behaviour = digest::behaviour(&scan.findings);
    let indicator_rows = indicators(job, scan);
    let techniques = attack(&behaviour);
    if choices.has(Part::Summary) {
        report.summary = Some(summary(scan, &behaviour, &indicator_rows, techniques.len()));
    }
    if choices.has(Part::Indicators) {
        report.indicators = Some(indicator_rows.iter().map(|(i, _)| i.clone()).collect());
    }
    if choices.has(Part::Attack) {
        report.attack = Some(techniques);
    }
    if choices.has(Part::Processes) {
        report.processes = Some(processes(scan, clock));
    }
    if choices.has(Part::Findings) {
        report.findings = Some(findings(scan, clock));
    }
    if choices.has(Part::Files) {
        report.files = Some(file_tabs_section(scan, clock));
    }
    let mut dropped = Vec::new();
    let mut skipped = Vec::new();
    if choices.has(Part::FileActivity) || choices.bundle {
        let (mut records, files, not_bundled) = file_activity(scan, choices.bundle);
        dropped = files;
        skipped = not_bundled;
        if records.len() > 2000 {
            report.notes.push(format!(
                "{} more changed files are not listed.",
                records.len() - 2000
            ));
            records.truncate(2000);
        }
        if choices.has(Part::FileActivity) {
            report.file_activity = Some(records);
        }
    }
    if choices.has(Part::Network) {
        report.network = Some(network(scan));
    }
    if choices.has(Part::Detections) {
        report.detections = Some(detections(&job.archive));
    }
    if choices.has(Part::Evidence) {
        report.evidence = Some(evidence(&job.archive));
    }
    if choices.has(Part::Custody) {
        match custody(job) {
            Ok(custody) => report.custody = Some(custody),
            Err(error) => report
                .notes
                .push(format!("Custody log not included: {error}")),
        }
    }
    if scan.partial {
        report
            .notes
            .push("The recording was still being written; this report covers what was saved when it was read.".into());
    }
    if let Some(warning) = &scan.network_warning {
        report.notes.push(format!("Network: {warning}"));
    }
    let bundle = choices.bundle.then(|| {
        let captures = antinomie_monitor_core::RunArtifacts::load(&job.archive)
            .ok()
            .flatten()
            .map(|artifacts| artifacts.network_captures)
            .unwrap_or_default()
            .into_iter()
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    job.archive.join(path)
                }
            })
            .collect::<Vec<_>>();
        // The capture Triage read counts even when the run lists none.
        let mut captures = captures;
        if let Some(pcap) = &job.pcap {
            if !captures.contains(pcap) {
                captures.push(pcap.clone());
            }
        }
        BundleInput {
            captures,
            dropped,
            skipped,
            custody: Vec::new(),
            run_id: job.run.run_id.clone(),
            generated_ms: job.now_ms,
        }
    });
    Ok(Built { report, bundle })
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The report from a whole-run index: each part reads the same rows Triage's
//! tables hold, so the report says what the tabs say.
use super::super::{digest, file_activity::start_of, file_tabs, ioc_scan, rules, FileTab};
use super::*;
use antinomie_monitor_core::{
    file_reconstruct::Reconstruction,
    ioc::{
        export as ioc_export,
        verdict::{Outcome, Verdict},
    },
    report::{
        bundle::{self, BundleInput, DroppedFile},
        Counts, FileRecord, FilesSection, IndicatorColumn, IndicatorKind, NamedTable, Part, Report,
        Summary, Table,
    },
    run_digest::RunDigest,
};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// What the build made: the report, and the bundle's inputs when asked for.
pub struct Built {
    pub report: Report,
    pub bundle: Option<BundleInput>,
}

/// Rows of `rows` at `keep`, as a table with `columns` named.
pub fn table(
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
        data: Vec::new(),
    }
}

/// The first moment of the run: when its first task was first seen.
fn run_start(scan: &ArchiveScan) -> Option<u64> {
    scan.process.iter().filter_map(|node| node.first_ns).min()
}

pub fn all(n: usize) -> Vec<usize> {
    (0..n).collect()
}

fn tier_rank(tier: &str) -> usize {
    rules::Tier::ALL
        .iter()
        .position(|t| t.tag() == tier)
        .unwrap_or(usize::MAX)
}

fn indicators(job: &Job, scan: &ArchiveScan) -> Vec<(report::Indicator, bool)> {
    let run_ms = super::rows::run_start_ms(scan.clock_anchor.or(job.clock), run_start(scan));
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
            let stand_in = indicator.stand_in.clone().unwrap_or_default();
            let mut noise = indicator.noise.clone().unwrap_or_default();
            // The guest's own resolver: a private address on the DNS port. Its
            // lookups are the names, which are indicators of their own.
            if noise.is_empty() {
                if let Some(why) = antinomie_monitor_core::report::shared::resolver_noise(
                    indicator.ty.id(),
                    &indicator.value,
                ) {
                    noise = why.into();
                }
            }
            let not_shared = antinomie_monitor_core::report::shared::not_shared_reason(
                indicator.ty.id(),
                &indicator.value,
                &indicator.roles,
                indicator.not_checked.as_deref().unwrap_or_default(),
            );
            let mut pids: Vec<u32> = indicator
                .process
                .iter()
                .chain(&indicator.candidates)
                .map(|p| p.pid)
                .filter(|pid| *pid != 0)
                .collect();
            pids.dedup();
            let item = report::Indicator {
                pids,
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
                first_seen_relative_ms: super::rows::capture_time(indicator.first_us, run_ms).1,
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
                base_noise: noise,
                stand_in,
                not_shared,
                ..report::Indicator::default()
            };
            (item, matched)
        })
        .collect()
}

fn summary(
    scan: &ArchiveScan,
    behaviour: &digest_types::Behaviour,
    indicators: &[(report::Indicator, bool)],
    candidates: &[super::super::family::Candidate],
    techniques: usize,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> Summary {
    let matched = indicators.iter().filter(|(_, m)| *m).count();
    let (key_total, key_rows) =
        super::rows::key_findings(&scan.findings, clock, run_start(scan), KEY_FINDINGS);
    // Families come from matched indicators (stored datasets) and from the
    // same candidates the app's Summary shows: Elastic and curated YARA rule
    // names, `family` metadata, IDS messages and the sample's MalwareBazaar
    // record; each with who named it.
    let mut named: Vec<(String, String)> = Vec::new();
    let mut add = |family: &str, source: String| {
        if let Some((_, known)) = named
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case(family))
        {
            if !known.contains(&source) {
                known.push_str("; ");
                known.push_str(&source);
            }
        } else {
            named.push((family.to_owned(), source));
        }
    };
    for (indicator, _) in indicators.iter().filter(|(_, m)| *m) {
        if !indicator.family.is_empty() {
            add(&indicator.family, format!("dataset {}", indicator.dataset));
        }
    }
    // The strongest candidates are the family; one Mirai rule beside twenty
    // Gafgyt ones is "also named".
    let (primary, others) = super::super::family::primary_families(candidates);
    for candidate in &primary {
        add(&candidate.name, pack_names(&candidate.source));
    }
    let other_families: Vec<String> = others
        .iter()
        .filter(|c| !named.iter().any(|(n, _)| n.eq_ignore_ascii_case(&c.name)))
        .map(|c| format!("{} ({})", c.name, pack_names(&c.source)))
        .collect();
    let family_sources: Vec<String> = named
        .iter()
        .map(|(family, sources)| format!("{family}: {sources}"))
        .collect();
    let families: Vec<String> = named.iter().map(|(family, _)| family.clone()).collect();
    // One row per rule: the same rule fires once per object it was seen on
    // (binary_replace 44, 2 and 1), so the counts are added and the highest
    // tier of its rows is kept.
    let mut merged: BTreeMap<&str, report::Behaviour> = BTreeMap::new();
    for hit in behaviour
        .rules
        .iter()
        .filter(|hit| matches!(hit.tier.as_str(), "high" | "medium"))
    {
        let row = merged
            .entry(hit.rule.as_str())
            .or_insert_with(|| report::Behaviour {
                rule: hit.rule.clone(),
                tier: hit.tier.clone(),
                category: hit.category.clone(),
                count: 0,
            });
        row.count += hit.count;
        if tier_rank(&hit.tier) < tier_rank(&row.tier) {
            row.tier.clone_from(&hit.tier);
        }
    }
    let mut key: Vec<_> = merged.into_values().collect();
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
                " Family: {} ({}). A family is the name a rule or dataset gave, not a verdict.",
                families.join(", "),
                family_basis(&named)
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
        families,
        family_sources,
        other_families,
        tiers: {
            // The app's tier chips count every finding, INFO included; the
            // index lists INFO rows only when asked for them.
            let listed = super::super::summary::tier_counts(&scan.findings);
            let all = scan.counts.finding_tiers;
            let counts: [u64; 4] = std::array::from_fn(|at| all[at].max(listed[at]));
            report::TierCounts {
                high: counts[0],
                medium: counts[1],
                low: counts[2],
                info: counts[3],
                info_not_listed: counts[3].saturating_sub(listed[3]),
            }
        },
        key_findings: key_rows,
        key_findings_text: super::super::summary::key_finding_lines(&scan.findings, KEY_FINDINGS),
        key_findings_total: key_total,
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

/// Rows of the report's Key findings table.
const KEY_FINDINGS: usize = 10;

/// A family source with pack paths named as packs:
/// `YARA · selection/pack/yara-forge-core/sekoia.yar rule X` reads
/// `YARA · YARA-Forge Core rule X`.
fn pack_names(source: &str) -> String {
    source
        .split(' ')
        .map(|word| {
            if word.contains("pack/") {
                antinomie_monitor_core::report::layout::pack_label(word)
            } else {
                word.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// "named by 4 rules (strongest: YARA · Elastic rule Linux_Trojan_BPFDoor_f690fe3b)".
fn family_basis(named: &[(String, String)]) -> String {
    let Some((_, sources)) = named.first() else {
        return String::new();
    };
    let strongest = sources.split("; ").next().unwrap_or(sources);
    let extra: usize = sources
        .split("(+")
        .skip(1)
        .filter_map(|rest| rest.split(' ').next()?.parse::<usize>().ok())
        .sum();
    let rules = sources.split("; ").count() + extra;
    let strongest = strongest.split(" (+").next().unwrap_or(strongest);
    if rules > 1 {
        format!("named by {rules} rules or records; strongest: {strongest}")
    } else {
        format!("named by {strongest}")
    }
}

/// A domain that is another domain with its own last label added again
/// (`mircd.xiao.my.id.id`): a resolver's search suffix, not a second name.
fn suffix_variant_note(indicators: &[(report::Indicator, bool)]) -> Option<String> {
    let names: BTreeSet<&str> = indicators
        .iter()
        .filter(|(i, _)| i.kind == "domain")
        .map(|(i, _)| i.value.as_str())
        .collect();
    let pairs: Vec<String> = names
        .iter()
        .filter_map(|name| {
            let (base, last) = name.rsplit_once('.')?;
            (base.ends_with(&format!(".{last}")) && names.contains(base))
                .then(|| format!("{name} looks like a search-suffix variant of {base}"))
        })
        .collect();
    (!pairs.is_empty()).then(|| {
        format!(
            "{}: the guest's resolver tried the name with its search suffix added; both are listed as the run asked for them.",
            pairs.join("; ")
        )
    })
}

/// Which calls the guest recorded without decoding an argument ("schema
/// gaps" in the recorder line): the call and its result are in the report, only
/// the named argument's bytes are missing. Listed so a high count can be traced.
fn schema_gap_note(scan: &ArchiveScan) -> Option<String> {
    if scan.schema_gaps.is_empty() {
        return None;
    }
    let total: u64 = scan.schema_gaps.iter().map(|(_, count)| count).sum();
    let listed: Vec<String> = scan
        .schema_gaps
        .iter()
        .take(10)
        .map(|(call, count)| format!("{call} x{}", crate::values::thousands(*count)))
        .collect();
    let more = scan.schema_gaps.len().saturating_sub(listed.len());
    Some(format!(
        "{} call(s) have an argument the guest had no decoder for (schema gaps): {}{}. The calls and their results are recorded; the argument bytes are not.",
        crate::values::thousands(total),
        listed.join(", "),
        if more > 0 {
            format!(" and {more} more kind(s)")
        } else {
            String::new()
        }
    ))
}

fn processes(scan: &ArchiveScan, clock: Option<antinomie_monitor_core::HostClockAnchor>) -> Table {
    let rows = super::super::process_tree::process_rows(&scan.process, clock, &scan.suspicious);
    let headers = super::super::process_tree::PROCESS_HEADERS;
    let mut out = table(&headers, &[0, 1, 2, 3, 4, 5, 6, 7, 8], &rows, 0, &[]);
    // The tree is the rows' order and each row's `depth`: the document draws
    // the indentation from it, the JSON's first cell is the process alone.
    out.data = super::rows::processes(&rows, clock, run_start(scan));
    out
}

fn findings(scan: &ArchiveScan, clock: Option<antinomie_monitor_core::HostClockAnchor>) -> Table {
    let start = run_start(scan);
    let rows: Vec<Vec<Cell>> = scan
        .findings
        .iter()
        .map(|finding| {
            let mut finding = finding.clone();
            rules::stamp(&mut finding, clock, start);
            finding.cells
        })
        .collect();
    let mut out = table(
        rules::HEADERS,
        &[
            rules::COL_TIME,
            rules::COL_TIER,
            rules::COL_BEHAVIOUR,
            0,
            rules::COL_TARGET,
            rules::COL_PROCESS,
            rules::COL_ATTACK,
            rules::COL_COUNT,
            rules::COL_RESULT,
            rules::COL_SUMMARY,
        ],
        &rows,
        scan.findings_omitted,
        &[],
    );
    out.data = super::rows::findings(&scan.findings, clock, start);
    out
}

/// The paths the run created or changed.
fn written_paths(scan: &ArchiveScan) -> BTreeSet<String> {
    scan.changed
        .iter()
        .filter_map(|row| row.get(1).map(|cell| cell.text.clone()))
        .collect()
}

/// The Read files table without what was read. A cell reads `4096 B: <bytes>`;
/// the report keeps the size, and the bytes only when asked (clipped, with
/// control characters escaped, and never for a file the run wrote): what a
/// sample reads can be the guest's secrets or its own bytes.
pub fn transferred(table: &mut Table, include_content: bool, written: &BTreeSet<String>) {
    let Some(at) = table
        .columns
        .iter()
        .position(|name| name == "Transferred / content")
    else {
        return;
    };
    let path = table.columns.iter().position(|name| name == "Path");
    table.columns[at] = if include_content {
        "Transferred / content".into()
    } else {
        "Transferred".into()
    };
    for row in &mut table.rows {
        let own = path
            .and_then(|path| row.get(path))
            .is_some_and(|path| written.contains(path));
        let Some(cell) = row.get_mut(at) else {
            continue;
        };
        let (size, rest) = cell.split_once(": ").unwrap_or((cell.as_str(), ""));
        let size = size.to_owned();
        let rest = rest.to_owned();
        *cell = if !include_content || own || rest.is_empty() {
            size
        } else if rest.starts_with("kernel transfer") {
            format!("{size}: {rest}")
        } else {
            let clipped: String = rest.chars().take(120).collect();
            let escaped: String = clipped
                .chars()
                .flat_map(|c| {
                    if c.is_control() {
                        format!("\\x{:02x}", c as u32).chars().collect::<Vec<_>>()
                    } else {
                        vec![c]
                    }
                })
                .collect();
            format!(
                "{size}: {escaped}{}",
                if rest.chars().count() > 120 {
                    "..."
                } else {
                    ""
                }
            )
        };
    }
}

fn file_tabs_section(
    scan: &ArchiveScan,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
    include_content: bool,
) -> FilesSection {
    let mut tabs = Vec::new();
    let start = run_start(scan);
    let path_of = |headers: &[&str]| headers.iter().position(|h| *h == "Path").unwrap_or(1);
    for tab in FileTab::ALL {
        let (_, omitted) = scan.file_rows(tab);
        let mut named = match tab {
            FileTab::Changed => {
                let mut changed = table(
                    file_tabs::CHANGED_HEADERS,
                    &all(file_tabs::CHANGED_HEADERS.len()),
                    &scan.changed,
                    omitted,
                    &[],
                );
                changed.data = super::rows::files(
                    &scan.changed,
                    path_of(file_tabs::CHANGED_HEADERS),
                    clock,
                    start,
                );
                changed
            }
            FileTab::Read => {
                let rows = file_category::with_time(&scan.read, clock);
                let mut read = table(
                    file_tabs::READ_HEADERS,
                    file_tabs::READ_COLUMNS,
                    &rows,
                    omitted,
                    &[],
                );
                transferred(&mut read, include_content, &written_paths(scan));
                read.data =
                    super::rows::files(&rows, path_of(file_tabs::READ_HEADERS), clock, start);
                read
            }
            FileTab::Opened => {
                let rows = file_category::with_time(&scan.opened, clock);
                let mut opened = table(
                    file_category::EVENT_HEADERS,
                    file_tabs::OPENED_COLUMNS,
                    &rows,
                    omitted,
                    &[],
                );
                opened.data =
                    super::rows::files(&rows, path_of(file_category::EVENT_HEADERS), clock, start);
                opened
            }
            other => {
                let rows = file_category::with_time(&scan.file_tabs[other.slot() - 8].rows, clock);
                let mut events = table(
                    file_category::EVENT_HEADERS,
                    &[0, 2, 3, 4, 5, 6],
                    &rows,
                    omitted,
                    &[],
                );
                events.data =
                    super::rows::files(&rows, path_of(file_category::EVENT_HEADERS), clock, start);
                events
            }
        };
        if named.data.len() != named.rows.len() {
            named.data.clear();
        }
        tabs.push(NamedTable {
            name: tab.title().to_owned(),
            table: named,
        });
    }
    FilesSection { tabs }
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
            ..FileRecord::default()
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
pub fn build(scan: &ArchiveScan, job: &Job) -> Result<Built, String> {
    let choices = &job.choices;
    let clock = scan.clock_anchor.or(job.clock);
    let mut report = Report::new(job.run.clone(), job.now_ms);
    report.sample = job.sample.clone();
    let behaviour = digest::behaviour(&scan.findings);
    // `None` when no detection engine has run for the run (stored with the run).
    let digest_detections = RunDigest::read(&job.archive).and_then(|digest| digest.detections);
    let indicator_rows = indicators(job, scan);
    let techniques = super::super::attack::techniques(
        &behaviour,
        digest_detections.as_deref().unwrap_or_default(),
    );
    if choices.has(Part::Summary) {
        let bazaar = job
            .sample
            .as_ref()
            .zip(job.data_dir.as_deref())
            .and_then(|(sample, dir)| {
                antinomie_monitor_core::samples::recorded_info(dir, &sample.sha256)
            });
        let candidates = super::super::family::family_candidates(
            digest_detections.as_deref().unwrap_or_default(),
            bazaar
                .as_ref()
                .map(|info| super::super::family::Bazaar {
                    signature: info.signature.as_deref(),
                    tags: &info.tags,
                    looked_up: info.looked_up,
                })
                .unwrap_or_default(),
        );
        report.summary = Some(summary(
            scan,
            &behaviour,
            &indicator_rows,
            &candidates,
            techniques.len(),
            clock,
        ));
    }
    if let Some(note) = schema_gap_note(scan) {
        report.notes.push(note);
    }
    if let Some(note) = suffix_variant_note(&indicator_rows) {
        report.notes.push(note);
    }
    // Said once, in the overview's notes; the Summary's statement keeps to the
    // assessment.
    if let Some(end) = super::super::run_end::run_end(scan) {
        report.notes.push(end.text);
    }
    if let Some(crash) = &scan.root_crash {
        report.notes.push(format!(
            "The sample crashed before its first system call: {crash}. No calls of its program were recorded, so the process table, files and findings below are empty because there was nothing to record, not because it did nothing."
        ));
    }
    if (choices.has(Part::Summary) || choices.has(Part::Detections)) && digest_detections.is_none()
    {
        report.notes.push(
            "YARA, Sigma and IDS had not run for this run when the report was made, so it holds no detections and names no family from them. To include them: open this run's Detection tab, press Scan, then export again."
                .into(),
        );
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
        report.files = Some(file_tabs_section(scan, clock, choices.include_content));
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
        report.network = Some(super::build_sources::network(
            scan,
            super::rows::run_start_ms(clock, run_start(scan)),
        ));
    }
    if choices.has(Part::Detections) {
        report.detections = Some(super::build_sources::detections(&job.archive));
    }
    if choices.has(Part::Evidence) {
        report.evidence = Some(super::build_sources::evidence(&job.archive));
    }
    if choices.has(Part::Custody) {
        match super::build_sources::custody(job) {
            Ok(custody) => report.custody = Some(custody),
            Err(error) => report
                .notes
                .push(format!("Custody log not included: {error}")),
        }
    }
    if scan.partial {
        report.notes.push(partial_note(
            job.request.run_finished,
            &scan.partial_reasons,
        ));
    }
    // Not a failure either: the recorder kept the suspicious-activity calls.
    if let Some((reduced, started)) = antinomie_monitor_core::reduced::read(&job.archive) {
        report
            .notes
            .extend(crate::reduced_text::lines(&reduced, started));
    }
    // First, since every part above misses what was lost.
    if let Some(note) = telemetry_loss_note(&job.archive) {
        report.notes.insert(0, note);
    }
    if let Some(warning) = &scan.network_warning {
        report.notes.push(format!("Network: {warning}"));
    }
    if choices.has(Part::Network) && antinomie_monitor_core::geoip::attribution_due() {
        report.notes.push(format!(
            "Network: {}",
            antinomie_monitor_core::geoip::ATTRIBUTION_NOTE
        ));
    }
    // Every entry its anchor, every mention its link (`*_ref`).
    report::refs::link(&mut report);
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

/// What the run's final manifest says of its lost telemetry, as the run's
/// note words it; `None` for a run that lost none, is not final yet, or was
/// recorded before the count existed.
pub fn telemetry_loss_note(archive: &Path) -> Option<String> {
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(archive.join("manifest.json")).ok()?).ok()?;
    serde_json::from_value::<antinomie_monitor_core::TelemetryLoss>(
        manifest.get("telemetry_loss")?.clone(),
    )
    .ok()?
    .note()
}

/// Why the report may not cover everything. "Still being written" is only said
/// for a run that is still going; a finished run says what was missing.
fn partial_note(run_finished: bool, reasons: &[String]) -> String {
    if !run_finished {
        return "The recording was still being written; this report covers what was saved when it was read.".into();
    }
    if reasons.is_empty() {
        "This report may not cover every recorded call.".into()
    } else {
        format!(
            "The run has ended. What this report may be missing: {}.",
            reasons.join("; ")
        )
    }
}

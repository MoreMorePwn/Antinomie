// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Building the parts of a [`super::SampleReport`] from what the library and
//! the runs hold. Every function takes plain core values, so the Samples
//! window and the tests use the same code.
use super::*;
use crate::analysis::{
    AnalysisData, AnalysisKind, AnalysisReport, AnalysisSectionState, AnalysisState,
};
use crate::run_digest::RunDigest;
use crate::samples::{
    Alias, ChainCheck, EdgeKind, EventRow, LineageGraph, NodeKind, Note, Origin, SampleRecord,
    Similar, Tag, TagKind,
};
use std::collections::{BTreeMap, BTreeSet};

fn plain(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

fn state_name(state: AnalysisSectionState) -> &'static str {
    match state {
        AnalysisSectionState::Pending => "pending",
        AnalysisSectionState::Running => "running",
        AnalysisSectionState::Complete => "complete",
        AnalysisSectionState::Partial => "partial",
        AnalysisSectionState::Unavailable => "unavailable",
        AnalysisSectionState::Timeout => "timeout",
    }
}

fn tier_rank(tier: &str) -> usize {
    ["high", "medium", "low", "info"]
        .iter()
        .position(|known| *known == tier)
        .unwrap_or(4)
}

/// The identity block: the record, its tags, names and origins, and when the
/// sample was first and last seen (library entry, runs, custody entries).
pub fn identity(
    record: &SampleRecord,
    tags: &[Tag],
    aliases: &[Alias],
    origins: &[Origin],
    archived: bool,
    runs: &[RunRow],
    events: &[EventRow],
) -> Identity {
    let started = runs.iter().filter_map(|run| run.started_ms);
    let first = started.clone().chain([record.added_ms]).min();
    let last = started
        .chain(events.iter().map(|event| event.at_ms))
        .chain([record.added_ms])
        .max();
    Identity {
        sha256: record.sha256.clone(),
        sha1: record.sha1.clone(),
        md5: record.md5.clone(),
        tlsh: record.tlsh.clone(),
        name: record.name.clone(),
        description: record.description.clone(),
        size: record.size,
        file_type: record.file_type.clone(),
        arch: record.arch.clone(),
        family: record.family.clone(),
        added_ms: record.added_ms,
        removed_ms: record.removed_ms,
        archived,
        first_seen_ms: first,
        last_seen_ms: last,
        tags: tags
            .iter()
            .map(|tag| TagRow {
                kind: match tag.kind {
                    TagKind::Verdict => "verdict",
                    TagKind::Category => "category",
                    TagKind::Technique => "technique",
                    TagKind::Custom => "custom",
                }
                .into(),
                value: tag.value.clone(),
            })
            .collect(),
        names: aliases
            .iter()
            .take(LIST_ROWS)
            .map(|alias| NameRow {
                name: alias.name.clone(),
                path: alias.path.clone(),
                seen: alias.seen.clone(),
            })
            .collect(),
        origins: origins
            .iter()
            .take(LIST_ROWS)
            .map(|origin| OriginRow {
                kind: origin.kind.label().into(),
                source: origin.source.clone(),
                detail: origin.detail.clone(),
                name: origin.name.clone(),
                path: origin.path.clone(),
                vm: if origin.vm_name.is_empty() {
                    origin.vm_id.clone()
                } else {
                    origin.vm_name.clone()
                },
                run_id: origin.run_id.clone(),
                parent: origin.parent.clone(),
                at_ms: origin.at_ms,
            })
            .collect(),
    }
}

/// The static analysis of the newest finished report (`number` is the run it
/// belongs to), and the static YARA matches with their credits.
pub fn static_analysis(found: Option<(&AnalysisReport, usize)>) -> (StaticAnalysis, Vec<RuleHit>) {
    let Some((report, number)) = found else {
        return (
            StaticAnalysis {
                reason: "No finished static analysis report was found among the sample's runs. \
                         Run the sample with static analysis on, or analyze it, to add one."
                    .into(),
                ..StaticAnalysis::default()
            },
            Vec::new(),
        );
    };
    let mut out = StaticAnalysis {
        available: true,
        state: if report.state == AnalysisState::Complete {
            "complete"
        } else {
            "partial"
        }
        .into(),
        report_id: report.id.clone(),
        from_run: Some(number),
        reason: report.reason.clone().unwrap_or_default(),
        ..StaticAnalysis::default()
    };
    let mut hits = Vec::new();
    let mut packers = BTreeSet::new();
    for section in &report.sections {
        out.checks.push(StaticCheck {
            label: section.kind.label().into(),
            state: state_name(section.state).into(),
            reason: section.reason().map(|(text, _)| text).unwrap_or_default(),
            summary: clip(&plain(&section.summary), 400).0,
            tools: section.tools.clone(),
        });
        for entry in &section.entries {
            let Some(record) = &entry.record else {
                continue;
            };
            match (&record.data, section.kind) {
                (AnalysisData::Layer { .. }, AnalysisKind::Unpacking) => {
                    if let AnalysisData::Layer {
                        index,
                        method,
                        sha256,
                        size,
                        packer,
                        ..
                    } = &record.data
                    {
                        if let Some(name) = packer {
                            packers.insert(name.clone());
                        }
                        out.layers.push(Layer {
                            index: *index,
                            method: method.clone(),
                            sha256: sha256.clone(),
                            size: *size,
                            packer: packer.clone().unwrap_or_default(),
                        });
                    }
                }
                (
                    AnalysisData::Capability {
                        name,
                        namespace,
                        attack,
                        mbc,
                    },
                    _,
                ) => out.capabilities.push(Capability {
                    name: name.clone(),
                    namespace: namespace.clone(),
                    attack: attack.clone(),
                    mbc: mbc.clone(),
                }),
                (AnalysisData::FlossString { origin, .. }, _) => {
                    out.floss_total += 1;
                    if out.floss.len() < FLOSS_ROWS {
                        out.floss.push(FlossRow {
                            origin: origin.clone(),
                            text: clip(&plain(&entry.value), STRING_CHARS).0,
                        });
                    }
                }
                (
                    AnalysisData::RuleMatch {
                        rule,
                        namespace,
                        ruleset,
                        ..
                    },
                    _,
                ) => {
                    // The ruleset reads "<author>; <licence>"; the matched
                    // text in the entry's value is not copied.
                    let (author, license) =
                        ruleset.rsplit_once("; ").unwrap_or((ruleset.as_str(), ""));
                    hits.push(RuleHit {
                        engine: "YARA (static)".into(),
                        rule_id: rule.clone(),
                        title: namespace.clone(),
                        author: if author == "unknown author" {
                            String::new()
                        } else {
                            author.into()
                        },
                        license: license.into(),
                        source: namespace.clone(),
                        count: 1,
                        ..RuleHit::default()
                    });
                }
                _ => {}
            }
        }
    }
    out.packer = packers.into_iter().collect::<Vec<_>>().join(", ");
    out.capabilities_omitted = cap(&mut out.capabilities, LIST_ROWS);
    (out, hits)
}

/// Rules of the runs' detection engines, merged by engine and rule id.
pub fn merge_detections(digests: &[(usize, &RunDigest)]) -> Vec<RuleHit> {
    let mut merged: BTreeMap<(String, String), RuleHit> = BTreeMap::new();
    for (number, digest) in digests {
        for hit in digest.detections.iter().flatten() {
            let entry = merged
                .entry((hit.engine.clone(), hit.rule_id.clone()))
                .or_insert_with(|| RuleHit {
                    engine: hit.engine.clone(),
                    rule_id: hit.rule_id.clone(),
                    ..RuleHit::default()
                });
            if !entry.runs.contains(number) {
                entry.runs.push(*number);
            }
            entry.count += hit.count;
            for (target, value) in [
                (&mut entry.title, &hit.title),
                (&mut entry.severity, &hit.severity),
                (&mut entry.family, &hit.family),
                (&mut entry.author, &hit.author),
                (&mut entry.license, &hit.license),
                (&mut entry.source, &hit.source),
                (&mut entry.reference, &hit.reference),
            ] {
                if target.is_empty() {
                    target.clone_from(value);
                }
            }
            for id in &hit.mitre {
                if !entry.mitre.contains(id) {
                    entry.mitre.push(id.clone());
                }
            }
        }
    }
    let mut out: Vec<RuleHit> = merged.into_values().collect();
    for hit in &mut out {
        hit.runs.sort_unstable();
    }
    out.sort_by(|a, b| {
        tier_rank(&a.severity.to_ascii_lowercase())
            .cmp(&tier_rank(&b.severity.to_ascii_lowercase()))
            .then_with(|| a.engine.cmp(&b.engine))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });
    out
}

/// Indicators of every run, one row per type and value.
pub fn merge_indicators(digests: &[(usize, &RunDigest)]) -> Vec<MergedIndicator> {
    let mut merged: BTreeMap<(String, String), MergedIndicator> = BTreeMap::new();
    for (number, digest) in digests {
        for item in digest.indicators.iter().flatten() {
            let entry = merged
                .entry((item.ty.clone(), item.value.clone()))
                .or_insert_with(|| MergedIndicator {
                    kind: item.ty.clone(),
                    value: item.value.clone(),
                    ..MergedIndicator::default()
                });
            entry.matched |= item.matched;
            if !entry.runs.contains(number) {
                entry.runs.push(*number);
            }
        }
    }
    let mut out: Vec<MergedIndicator> = merged.into_values().collect();
    for item in &mut out {
        item.runs.sort_unstable();
    }
    out.sort_by(|a, b| {
        b.matched
            .cmp(&a.matched)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.value.cmp(&b.value))
    });
    out
}

fn technique_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let main = bytes.len() == 5 || (bytes.len() == 9 && bytes[5] == b'.');
    main && bytes[0] == b'T'
        && bytes[1..5].iter().all(u8::is_ascii_digit)
        && (bytes.len() == 5 || bytes[6..].iter().all(u8::is_ascii_digit))
}

/// ATT&CK techniques the runs' rules cite, with the rules that name them.
pub fn merge_attack(digests: &[(usize, &RunDigest)]) -> Vec<Technique> {
    let mut found: BTreeMap<String, (BTreeSet<String>, u64)> = BTreeMap::new();
    for (_, digest) in digests {
        for hit in digest.behaviour.iter().flat_map(|b| &b.rules) {
            for id in hit.attack.iter().filter(|id| technique_id(id)) {
                let entry = found.entry(id.clone()).or_default();
                entry.0.insert(hit.rule.clone());
                entry.1 += hit.count.max(1);
            }
        }
        for hit in digest.detections.iter().flatten() {
            for id in hit.mitre.iter().filter(|id| technique_id(id)) {
                let entry = found.entry(id.clone()).or_default();
                entry.0.insert(format!("{}: {}", hit.engine, hit.rule_id));
                entry.1 += hit.count.max(1);
            }
        }
    }
    found
        .into_iter()
        .map(|(id, (rules, count))| Technique {
            name: crate::mitre::technique_name(&id).unwrap_or_default(),
            id,
            rules: rules.into_iter().collect(),
            count,
        })
        .collect()
}

/// `path` as the report names it: relative to the data directory, so the
/// user name and the folder layout above it do not reach the report. A path
/// outside the data directory is reduced to its file name.
pub fn in_data_dir(data_dir: &std::path::Path, path: &std::path::Path) -> String {
    match path.strip_prefix(data_dir) {
        Ok(inside) => inside.display().to_string(),
        Err(_) => path
            .file_name()
            .map_or(String::new(), |name| name.to_string_lossy().into_owned()),
    }
}

/// The newest report file a run's Triage export wrote: `report/antinomie-report-*.html`
/// in the run's folder. Empty when the run has none.
pub fn latest_run_report(data_dir: &std::path::Path, run_directory: &std::path::Path) -> String {
    let Ok(listing) = std::fs::read_dir(run_directory.join("report")) else {
        return String::new();
    };
    listing
        .flatten()
        .filter_map(|item| {
            let name = item.file_name().to_string_lossy().into_owned();
            (name.starts_with("antinomie-report-") && name.ends_with(".html")).then_some(name)
        })
        .max()
        .map(|name| in_data_dir(data_dir, &run_directory.join("report").join(name)))
        .unwrap_or_default()
}

/// One run's row: its digest's assessment in the words of the run report.
#[allow(clippy::too_many_arguments)]
pub fn run_row(
    number: usize,
    vm_id: &str,
    vm_name: &str,
    run_id: &str,
    started_ms: Option<u64>,
    exit: &str,
    data_dir: &std::path::Path,
    directory: &std::path::Path,
    folder_present: bool,
    digest: Option<&RunDigest>,
) -> RunRow {
    let mut row = RunRow {
        number,
        vm_id: vm_id.into(),
        vm_name: vm_name.into(),
        run_id: run_id.into(),
        started_ms,
        exit: exit.into(),
        folder_present,
        directory: in_data_dir(data_dir, directory),
        report_file: if folder_present {
            latest_run_report(data_dir, directory)
        } else {
            String::new()
        },
        assessment: "not_read".into(),
        statement: "Triage has not read this run, so it has no assessment. Open the run in \
                    Triage to read it."
            .into(),
        ..RunRow::default()
    };
    let Some(digest) = digest else {
        return row;
    };
    row.triaged = digest.behaviour.is_some() || digest.indicators.is_some();
    row.detections = digest.detections.as_ref().map_or(0, |d| d.len() as u64);
    row.indicators = digest.indicators.as_ref().map_or(0, |i| i.len() as u64);
    row.indicators_matched = digest
        .indicators
        .iter()
        .flatten()
        .filter(|item| item.matched)
        .count() as u64;
    let Some(behaviour) = &digest.behaviour else {
        if row.indicators_matched > 0 {
            row.assessment = "matched_indicators".into();
            row.statement = format!(
                "Triage observed: {} indicator(s) matched a stored dataset. These are \
                 observations from a recorded run, not a verdict on the sample.",
                row.indicators_matched
            );
        }
        return row;
    };
    row.rules = behaviour.rules.len() as u64;
    row.highest_tier = if behaviour.highest.is_empty() {
        "none".into()
    } else {
        behaviour.highest.clone()
    };
    let (assessment, basis) = if row.indicators_matched > 0 {
        (
            "matched_indicators",
            format!(
                "{} indicator(s) matched a stored dataset",
                row.indicators_matched
            ),
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
    row.assessment = assessment.into();
    row.statement = format!(
        "Triage observed: {basis}. These are observations from a recorded run, not a verdict \
         on the sample."
    );
    row
}

/// Parents and children from the lineage graph. `runs_with_lineage` of
/// `runs_total` runs had a lineage index; the reason says what an empty side
/// does and does not mean.
pub fn lineage(graph: &LineageGraph, runs_with_lineage: usize, runs_total: usize) -> Lineage {
    let level: BTreeMap<&str, i32> = graph
        .nodes
        .iter()
        .map(|node| (node.id.as_str(), node.level))
        .collect();
    let mut out = Lineage::default();
    for node in graph.nodes.iter().filter(|n| n.level != 0) {
        // The edge toward the sample: it names how the two are joined.
        let edge = graph.edges.iter().find(|edge| {
            if node.level < 0 {
                edge.from == node.id && level.get(edge.to.as_str()) == Some(&(node.level + 1))
            } else {
                edge.to == node.id && level.get(edge.from.as_str()) == Some(&(node.level - 1))
            }
        });
        let (kind, verdict) = match &node.kind {
            NodeKind::Library { verdict, .. } => ("library sample", verdict.clone()),
            NodeKind::Captured => ("captured file", String::new()),
            NodeKind::Lost => ("file without a hash", String::new()),
            NodeKind::Command => ("command", String::new()),
            NodeKind::System => ("system binary", String::new()),
            NodeKind::Sample => continue,
        };
        let entry = LineageEntry {
            role: if node.level < 0 { "parent" } else { "child" }.into(),
            level: node.level.unsigned_abs(),
            kind: kind.into(),
            label: plain(&node.label),
            path: plain(&node.path),
            sha256: node.sha256.clone(),
            verdict,
            via: edge
                .map(|edge| {
                    EdgeKind::ALL
                        .iter()
                        .filter(|k| edge.kinds.contains_key(k))
                        .map(|k| k.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default(),
            runs: edge.map(|edge| edge.runs.clone()).unwrap_or_default(),
        };
        if node.level < 0 {
            out.parents.push(entry);
        } else {
            out.children.push(entry);
        }
    }
    let key = |a: &LineageEntry| (a.level, a.label.clone(), a.sha256.clone());
    out.parents.sort_by_key(key);
    out.children.sort_by_key(key);
    let mut reason = Vec::new();
    if runs_total == 0 {
        reason.push(
            "The sample has not been run, so no run showed what it dropped or started; only \
             the library's origins are used."
                .to_owned(),
        );
    } else if runs_with_lineage == 0 {
        reason.push(format!(
            "None of the {runs_total} run(s) has a lineage index yet (open a run in Triage to \
             read it); only the library's origins are used."
        ));
    } else if runs_with_lineage < runs_total {
        reason.push(format!(
            "{runs_with_lineage} of {runs_total} runs have a lineage index; the others are not \
             in the graph."
        ));
    }
    if out.parents.is_empty() {
        reason.push(
            "No parent: no library origin and no run shows another file that wrote or fetched \
             this one."
                .into(),
        );
    }
    if out.children.is_empty() {
        reason
            .push("No children: no run shows this sample writing or starting another file.".into());
    }
    if graph.hidden_system > 0 {
        reason.push(format!(
            "{} base-image program(s) are left out.",
            graph.hidden_system
        ));
    }
    out.reason = reason.join(" ");
    out
}

/// The custody log with its verification result; the newest [`LIST_ROWS`]
/// entries when the log is longer (the number left out is returned).
pub fn custody(check: &ChainCheck, events: &[EventRow]) -> (CustodySection, u64) {
    let mut log: Vec<CustodyRow> = events
        .iter()
        .map(|event| CustodyRow {
            seq: event.seq,
            at_ms: event.at_ms,
            by: event.by.clone(),
            event: event.event.label().into(),
            detail: plain(&event.event.detail()),
            state: match check.state_of(event.seq) {
                crate::samples::EntryState::Verified => "verified",
                crate::samples::EntryState::Changed => "changed",
                crate::samples::EntryState::Unverified => "unverified",
            }
            .into(),
            hash: event.hash.clone(),
            before_chain: event.before_chain,
        })
        .collect();
    log.sort_by_key(|row| row.seq);
    let dropped = log.len().saturating_sub(LIST_ROWS);
    log.drain(..dropped);
    (
        CustodySection {
            entries: check.entries,
            head: check.head.clone(),
            verified: check.ok(),
            problem: check
                .problem
                .as_ref()
                .map(|p| format!("entry {}: {}", p.at, p.text))
                .unwrap_or_default(),
            log,
        },
        dropped as u64,
    )
}

/// The analyst's notes, long ones cut.
pub fn notes(notes: &[Note]) -> (Vec<NoteRow>, u64) {
    let mut rows: Vec<NoteRow> = notes
        .iter()
        .map(|note| {
            let (text, cut) = clip(&note.text, NOTE_CHARS);
            NoteRow {
                id: note.id,
                by: note.by.clone(),
                created_ms: note.created_ms,
                edited_ms: note.edited_ms,
                text,
                cut,
                refs: note.refs.iter().map(|r| plain(&r.label)).collect(),
            }
        })
        .collect();
    let dropped = cap(&mut rows, LIST_ROWS);
    (rows, dropped)
}

/// The similar samples; only counts of what they share, never the texts.
pub fn similar(found: &[Similar]) -> Vec<SimilarRow> {
    found
        .iter()
        .map(|item| SimilarRow {
            sha256: item.sha256.clone(),
            name: item.name.clone(),
            distance: item.distance,
            shared: item.shared.label(),
        })
        .collect()
}

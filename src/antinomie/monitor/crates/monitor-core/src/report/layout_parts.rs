// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The tables of the run report's document: key findings, family evidence,
//! indicators, techniques, processes, suspicious activity, files, network and
//! detections, each cell linked to the entry it names.
use super::layout::{
    Block, Builder, Cell, DocTable, FAMILY_EVIDENCE, Span, indicator_stamp, or_unknown, plain_rule,
    severity_text, thousands,
};
use super::refs::RowData;
use super::{DOCUMENT_ROWS, Indicator, IndicatorKind, KeyFinding, Report, Summary, Table, stamp};
use std::collections::BTreeMap;

/// Findings of one rule, tier and result are folded into one row from this
/// many on: 44 cron findings that differ only by pid and temp file are one row.
const FOLD_FINDINGS_AT: usize = 4;

/// The paths of a cell list are cut after this many, with `+N more`.
const LISTED: usize = 3;

/// The pack a rule came from, as its name: `selection/pack/yara-forge-core/
/// sekoia.yar` is `YARA-Forge Core`; a source with no pack path is kept.
pub fn pack_label(source: &str) -> String {
    let Some((_, rest)) = source.split_once("pack/") else {
        return source.to_owned();
    };
    let pack = rest.split('/').next().unwrap_or(rest);
    match pack {
        "yara-forge-core" => "YARA-Forge Core".into(),
        "yara-forge-extended" => "YARA-Forge Extended".into(),
        "yara-forge-full" => "YARA-Forge Full".into(),
        "abuse-ch-yarahub" => "abuse.ch YARAhub".into(),
        "elastic-protections-artifacts" | "elastic" => "Elastic protections-artifacts".into(),
        other => other
            .split('-')
            .map(|word| {
                let mut chars = word.chars();
                chars.next().map_or(String::new(), |c| {
                    c.to_uppercase().collect::<String>() + chars.as_str()
                })
            })
            .collect::<Vec<_>>()
            .join(" "),
    }
}

impl Builder {
    /// The Key findings table: one row per finding, linked to its row in
    /// Suspicious activity, its process, its object and its techniques.
    pub(super) fn key_findings_table(&self, keys: &[KeyFinding]) -> DocTable {
        let columns = [
            "#",
            "Tier",
            "Rule",
            "Behaviour",
            "Object",
            "Process",
            "Count",
            "First seen",
            "ATT&CK",
        ]
        .map(String::from)
        .to_vec();
        let rows = keys
            .iter()
            .enumerate()
            .map(|(at, key)| {
                let (label, finding) = if key.finding_ref.is_empty() {
                    ((at + 1).to_string(), String::new())
                } else {
                    self.finding_label(&key.finding_ref)
                };
                let process = match key.pid {
                    Some(pid) if !key.process.contains(&pid.to_string()) => {
                        format!("{} ({pid})", key.process)
                    }
                    _ => key.process.clone(),
                };
                vec![
                    Cell::link(label, &finding),
                    Cell::plain(key.tier.to_uppercase()),
                    Cell::link(key.rule.clone(), &finding),
                    Cell::plain(self.free(&key.title)),
                    Cell::link(self.free(&key.target), &key.target_ref),
                    Cell::link(self.free(&process), &key.process_ref),
                    Cell::plain(format!("\u{d7}{}", thousands(key.count.max(1)))),
                    Cell::plain(stamp(key.relative_ms, key.first_ms)),
                    self.techniques_cell(&key.attack),
                ]
            })
            .collect();
        DocTable { columns, rows }
    }

    /// Technique ids, each a link to its ATT&CK row.
    fn techniques_cell(&self, ids: &[String]) -> Cell {
        let items: Vec<(String, String)> = ids
            .iter()
            .map(|id| (id.clone(), self.reg.technique(id)))
            .collect();
        Cell::list(&items, ", ")
    }

    /// The rules that named the family, from the detections: Family, Engine,
    /// Rule (to its detection row), Pack, Strength, Count. `None` when the
    /// report has no detection that names one of the families.
    pub(super) fn family_evidence(&self, report: &Report, summary: &Summary) -> Option<DocTable> {
        let detections = report.detections.as_ref()?;
        let families: Vec<String> = summary
            .families
            .iter()
            .chain(&summary.other_families)
            .map(|f| f.to_ascii_lowercase())
            .collect();
        let mut rows: Vec<(usize, Vec<Cell>)> = detections
            .iter()
            .filter(|hit| families.contains(&hit.family.to_ascii_lowercase()))
            .map(|hit| {
                let rank = families
                    .iter()
                    .position(|f| *f == hit.family.to_ascii_lowercase())
                    .unwrap_or(usize::MAX);
                (
                    rank,
                    vec![
                        Cell::plain(hit.family.clone()),
                        Cell::plain(hit.engine.clone()),
                        Cell::link(plain_rule(&hit.rule_id).to_owned(), &hit.id),
                        Cell::plain(pack_label(&hit.source)),
                        Cell::plain(severity_text(&hit.engine, &hit.severity, &hit.strength)),
                        Cell::plain(thousands(hit.count)),
                    ],
                )
            })
            .collect();
        if rows.is_empty() {
            return None;
        }
        rows.sort_by_key(|(rank, _)| *rank);
        Some(DocTable {
            columns: ["Family", "Engine", "Rule", "Pack", "Strength", "Count"]
                .map(String::from)
                .to_vec(),
            rows: rows.into_iter().map(|(_, row)| row).collect(),
        })
    }

    /// The indicators worth sharing, at most eight, linked to their rows.
    pub(super) fn key_indicators(&self, report: &Report) -> Option<Vec<Block>> {
        let all = report.indicators.as_ref()?;
        let shared: Vec<&Indicator> = all.iter().filter(|i| i.shared()).collect();
        if shared.is_empty() {
            return None;
        }
        let rows = shared
            .iter()
            .take(8)
            .map(|i| {
                vec![
                    Cell::plain(i.kind.clone()),
                    Cell::link(
                        self.value(IndicatorKind::from_id(&i.kind), &indicator_text(&[i])),
                        &i.id,
                    ),
                    Cell::plain(i.verdict.clone()),
                    self.process_cell(i),
                    Cell::plain(indicator_stamp(&i.first_seen, i.first_seen_relative_ms)),
                ]
            })
            .collect();
        let mut blocks = vec![Block::Table(DocTable {
            columns: ["Type", "Indicator", "Verdict", "Process", "First seen"]
                .map(String::from)
                .to_vec(),
            rows,
        })];
        if shared.len() > 8 {
            blocks.push(Block::Note(format!(
                "{} more in Indicators of compromise.",
                shared.len() - 8
            )));
        }
        Some(blocks)
    }

    /// An indicator's processes: the name and pid of one, `cat (26
    /// processes)` for many, linked to the first.
    fn process_cell(&self, indicator: &Indicator) -> Cell {
        let first = indicator.process_refs.first().cloned().unwrap_or_default();
        if indicator.pids.len() <= 2 && indicator.process.chars().count() <= 60 {
            return Cell::link(self.free(&indicator.process), &first);
        }
        let list = indicator
            .process
            .split_once("candidates:")
            .map_or(indicator.process.as_str(), |(_, rest)| rest);
        let mut names: Vec<(String, usize)> = Vec::new();
        for item in list.split(", ") {
            let name = item
                .split(" \u{b7} ")
                .next()
                .unwrap_or(item)
                .trim()
                .to_owned();
            if name.is_empty() {
                continue;
            }
            match names.iter_mut().find(|(known, _)| *known == name) {
                Some((_, n)) => *n += 1,
                None => names.push((name, 1)),
            }
        }
        let text = names
            .iter()
            .map(|(name, n)| {
                if *n == 1 {
                    name.clone()
                } else {
                    format!("{name} ({n} processes)")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        let prefix = if indicator.process.starts_with("unattributed") {
            "unattributed; candidates: "
        } else {
            ""
        };
        Cell::link(self.free(&format!("{prefix}{text}")), &first)
    }

    /// The indicators of compromise: shared rows first, then the ones MISP
    /// and STIX leave out with the reason. Files with one hash are one row
    /// with their paths; a Tor stand-in names the domain it stands for.
    pub(super) fn indicators_section(&mut self, report: &Report) {
        let Some(all) = &report.indicators else {
            return;
        };
        let indicators: Vec<&Indicator> = all.iter().filter(|i| i.base_noise.is_empty()).collect();
        let noisy = all.len() - indicators.len();
        let mut blocks = Vec::new();
        if indicators.is_empty() {
            blocks.push(Block::Note("The run produced no indicators.".into()));
        } else {
            let mut order: Vec<Vec<&Indicator>> = Vec::new();
            let mut by_hash: BTreeMap<&str, usize> = BTreeMap::new();
            for indicator in &indicators {
                if indicator.kind == "file" && !indicator.sha256.is_empty() {
                    if let Some(&at) = by_hash.get(indicator.sha256.as_str()) {
                        order[at].push(indicator);
                        continue;
                    }
                    by_hash.insert(indicator.sha256.as_str(), order.len());
                }
                order.push(vec![indicator]);
            }
            // Shared first; the order inside each part is the run's.
            order.sort_by_key(|group| !group[0].shared());
            for group in &order {
                for other in &group[1..] {
                    if !other.id.is_empty() && !group[0].id.is_empty() {
                        self.aliases.insert(other.id.clone(), group[0].id.clone());
                    }
                }
            }
            let rows: Vec<Vec<Cell>> = order
                .iter()
                .take(DOCUMENT_ROWS)
                .map(|group| {
                    let indicator = group[0];
                    let kind = IndicatorKind::from_id(&indicator.kind);
                    let n = indicator.id.trim_start_matches("ioc-").to_owned();
                    vec![
                        Cell::plain(n).with_id(&indicator.id),
                        Cell::plain(indicator.kind.clone()),
                        self.indicator_cell(group, kind),
                        Cell::plain(indicator.verdict.clone()),
                        Cell::plain(indicator.dataset.clone()),
                        Cell::plain(indicator.family.clone()),
                        self.process_cell(indicator),
                        Cell::plain(indicator_stamp(
                            &indicator.first_seen,
                            indicator.first_seen_relative_ms,
                        )),
                        Cell::plain(indicator_seen(group)),
                        Cell::plain(if indicator.not_shared.is_empty() {
                            "yes".to_owned()
                        } else {
                            format!("no: {}", indicator.not_shared)
                        }),
                        self.finding_list(&indicator.finding_refs),
                    ]
                })
                .collect();
            let columns: Vec<String> = [
                "#",
                "Type",
                "Indicator",
                "Verdict",
                "Dataset",
                "Family",
                "Process",
                "First seen",
                "Seen as / count",
                "In MISP / STIX",
                "Findings",
            ]
            .map(String::from)
            .to_vec();
            let mut table = DocTable { columns, rows };
            drop_empty_columns(&mut table, &["Dataset", "Family", "Findings"]);
            blocks.push(Block::Table(table));
            if order.len() > DOCUMENT_ROWS {
                blocks.push(Block::Note(format!(
                    "{} more indicators are in the JSON, MISP and STIX exports.",
                    order.len() - DOCUMENT_ROWS
                )));
            }
        }
        if noisy > 0 {
            blocks.push(Block::Note(format!(
                "{noisy} more are the base image's own traffic (clock sync, DHCP, package \
                 indexes, the guest's resolver), not the sample's. They are in the JSON export \
                 under base_noise."
            )));
        }
        self.section("indicators", "Indicators of compromise", blocks);
    }

    /// The Indicator cell: the value linked to its entry; a Tor stand-in
    /// address with the name it stands for, linked to that domain.
    fn indicator_cell(&self, group: &[&Indicator], kind: Option<IndicatorKind>) -> Cell {
        let first = group[0];
        if first.stand_in.is_empty() {
            return Cell::link(self.value(kind, &indicator_text(group)), &first.target_ref);
        }
        Cell::of(vec![
            Span::to(self.value(kind, &first.value), &first.target_ref),
            Span::plain(" \u{2192} "),
            Span::to(
                self.value(Some(IndicatorKind::Domain), &first.stand_in),
                &self.reg.domain(&first.stand_in),
            ),
            Span::plain(" (Tor stand-in)"),
        ])
    }

    /// The ATT&CK techniques: each row the anchor of its technique, each rule
    /// a link to its first finding or its detection.
    pub(super) fn attack_section(&mut self, report: &Report) {
        let Some(attack) = &report.attack else {
            return;
        };
        let blocks = if attack.is_empty() {
            vec![Block::Note(
                "No rule of the run cites an ATT&CK technique.".into(),
            )]
        } else {
            vec![Block::Table(DocTable {
                columns: ["Technique", "Name", "Tactic", "Count", "Rules"]
                    .map(String::from)
                    .to_vec(),
                rows: attack
                    .iter()
                    .map(|technique| {
                        let rules: Vec<(String, String)> = technique
                            .rules
                            .iter()
                            .enumerate()
                            .map(|(at, rule)| {
                                let to = technique
                                    .rule_refs
                                    .get(at)
                                    .filter(|id| !id.is_empty())
                                    .cloned()
                                    .unwrap_or_else(|| self.reg.rule(rule));
                                (plain_rule(rule).to_owned(), to)
                            })
                            .collect();
                        vec![
                            Cell::plain(technique.id.clone())
                                .with_id(&self.reg.technique(&technique.id)),
                            Cell::plain(technique.name.clone()),
                            Cell::plain(super::tactic_cell(&technique.id)),
                            Cell::plain(technique.count.to_string()),
                            Cell::list(&rules, ", "),
                        ]
                    })
                    .collect(),
            })]
        };
        self.section("attack", "ATT&CK techniques", blocks);
    }

    /// A table of the report as document cells: the row's anchor on its
    /// first cell, times as `+N s · HH:MM:SS.mmm`, and every Process, Path,
    /// Target, Endpoint, Host, Server name, IP and ATT&CK cell linked to its
    /// entry. Processes get their parent, files and findings; an entry the
    /// findings name gets a Findings column.
    pub(super) fn linked(&self, table: &Table, rows: &[usize]) -> DocTable {
        let col = |name: &str| table.columns.iter().position(|c| c == name);
        let empty = RowData::default();
        let data = |at: usize| table.data.get(at).unwrap_or(&empty);
        let any = |f: &dyn Fn(&RowData) -> bool| rows.iter().any(|&at| f(data(at)));
        let is_processes = col("Exec chain").is_some() && col("Argv").is_some();
        let findings_column = col("Findings");
        let add_findings = findings_column.is_none() && any(&|d| !d.finding_refs.is_empty());
        let add_parent = is_processes && any(&|d| !d.parent_ref.is_empty());
        let add_files = is_processes && any(&|d| !d.file_refs.is_empty());
        let mut columns = table.columns.clone();
        if add_parent {
            columns.insert(1, "Parent".into());
        }
        if add_files {
            columns.push("Files written".into());
        }
        if add_findings {
            columns.push("Findings".into());
        }
        let kinds: BTreeMap<usize, IndicatorKind> = table
            .indicator_columns
            .iter()
            .map(|marked| (marked.column, marked.kind))
            .collect();
        let file_names: BTreeMap<&String, &String> =
            self.reg.files.iter().map(|(path, id)| (id, path)).collect();
        let out_rows = rows
            .iter()
            .filter_map(|&at| table.rows.get(at).map(|row| (at, row)))
            .map(|(at, row)| {
                let d = data(at);
                let mut cells: Vec<Cell> = row
                    .iter()
                    .enumerate()
                    .map(|(column, raw)| {
                        let name = table.columns.get(column).map_or("", String::as_str);
                        let text = self.value(kinds.get(&column).copied(), raw);
                        self.cell(name, raw, text, d, Some(column) == findings_column)
                    })
                    .collect();
                if let Some(first) = cells.first_mut() {
                    *first = std::mem::take(first).with_id(&d.id);
                    // The process tree: a child sits under its parent, one
                    // step in for each level (no-break spaces, so the
                    // indentation survives wrapping and HTML).
                    if is_processes && let Some(depth) = d.depth.filter(|d| *d > 0) {
                        let indent = "\u{a0}".repeat(3 * (depth as usize - 1).min(12));
                        first.spans.insert(0, Span::plain(format!("{indent}+- ")));
                    }
                }
                // A rule's anchor sits on its first finding's Rule cell.
                if let Some(rule) = col("Rule").and_then(|c| cells.get_mut(c)) {
                    rule.more_ids.clone_from(&d.anchors);
                } else if let Some(first) = cells.first_mut() {
                    first.more_ids.clone_from(&d.anchors);
                }
                if add_parent {
                    let label = self
                        .reg
                        .labels
                        .get(&d.parent_ref)
                        .cloned()
                        .unwrap_or_default();
                    cells.insert(1, Cell::link(self.free(&label), &d.parent_ref));
                }
                if add_files {
                    let items: Vec<(String, String)> = d
                        .file_refs
                        .iter()
                        .take(LISTED)
                        .map(|id| {
                            (
                                file_names.get(id).map_or(id.clone(), |p| (*p).clone()),
                                id.clone(),
                            )
                        })
                        .collect();
                    let mut cell = Cell::list(&items, ", ");
                    if d.file_refs.len() > LISTED {
                        cell.spans.push(Span::plain(format!(
                            " (+{} more)",
                            d.file_refs.len() - LISTED
                        )));
                    }
                    cells.push(cell);
                }
                if add_findings {
                    cells.push(self.finding_list(&d.finding_refs));
                }
                cells
            })
            .collect();
        DocTable {
            columns,
            rows: out_rows,
        }
    }

    /// One cell of [`Self::linked`].
    fn cell(&self, column: &str, raw: &str, text: String, d: &RowData, findings: bool) -> Cell {
        match column {
            "Time" | "Started" if d.time_ms.is_some() || d.relative_ms.is_some() => {
                Cell::plain(stamp(d.relative_ms, d.time_ms))
            }
            "First seen" if d.time_ms.is_some() || d.relative_ms.is_some() => {
                Cell::plain(stamp(d.relative_ms, d.time_ms))
            }
            "Last seen" if d.last_ms.is_some() || d.last_relative_ms.is_some() => {
                Cell::plain(stamp(d.last_relative_ms, d.last_ms))
            }
            "Tier" => Cell::plain(text.to_uppercase()),
            // A network row's Source links to the process that made it.
            "Process" | "Source" if !d.process_ref.is_empty() => Cell::link(text, &d.process_ref),
            "Path" | "Target" if d.target_ref != d.id => Cell::link(text, &d.target_ref),
            "ATT&CK" => Cell::link(text, d.attack_refs.first().map_or("", String::as_str)),
            "Endpoint" if d.id.is_empty() || !d.id.starts_with("ep-") => {
                let to = d
                    .endpoint_refs
                    .first()
                    .cloned()
                    .unwrap_or_else(|| self.reg.endpoint(raw));
                Cell::link(text, &to)
            }
            "Host" | "Server name" => {
                let to = if d.domain_ref.is_empty() {
                    self.reg.domain(raw)
                } else {
                    d.domain_ref.clone()
                };
                Cell::link(text, &to)
            }
            "Resolved / connected IPs" => {
                let mut spans = Vec::new();
                for (at, ip) in raw.split(", ").enumerate() {
                    if at > 0 {
                        spans.push(Span::plain(", "));
                    }
                    let to = self.reg.endpoints_at(ip.trim()).into_iter().next();
                    spans.push(Span::to(
                        self.value(Some(IndicatorKind::Endpoint), ip),
                        to.as_deref().unwrap_or(""),
                    ));
                }
                Cell::of(spans)
            }
            "Country" | "Organization"
                if raw == "Unavailable" && super::layout_files::reserved(&d.endpoint) =>
            {
                Cell::plain("\u{2014}")
            }
            _ if findings && !d.finding_refs.is_empty() => self.finding_list(&d.finding_refs),
            _ => Cell::plain(text),
        }
    }

    /// The process tree.
    pub(super) fn processes_blocks(&self, table: &Table) -> Vec<Block> {
        if table.rows.is_empty() {
            return vec![Block::Note("No process was recorded.".into())];
        }
        let rows: Vec<usize> = (0..table.rows.len().min(DOCUMENT_ROWS)).collect();
        let mut blocks = vec![Block::Table(self.linked(table, &rows))];
        if let Some(note) = Builder::cut_note(table) {
            blocks.push(Block::Note(note));
        }
        blocks.push(Block::Note(
            "Process reads name (pid \u{b7} tid); a child is indented under its parent (+-), and \
             \"fork\" marks a child that has not run a program of its own."
                .into(),
        ));
        blocks
    }

    /// Suspicious activity: every finding, its row the anchor `finding-<n>`;
    /// four or more of one rule, tier and result are one row with the count
    /// and the first object and process (the rest are in the JSON). Run
    /// before the other sections so their links follow the folds.
    pub(super) fn fold_findings(&mut self, table: &Table) -> Vec<Block> {
        if table.rows.is_empty() {
            return vec![Block::Note("No finding.".into())];
        }
        let col = |name: &str| table.columns.iter().position(|c| c == name);
        let key_of = |at: usize| -> (String, String, String) {
            let row = &table.rows[at];
            let get = |c: Option<usize>| c.and_then(|c| row.get(c)).cloned().unwrap_or_default();
            (get(col("Rule")), get(col("Tier")), get(col("Result")))
        };
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut index: BTreeMap<(String, String, String), usize> = BTreeMap::new();
        for at in 0..table.rows.len() {
            let key = key_of(at);
            match index.get(&key) {
                Some(&g) => groups[g].push(at),
                None => {
                    index.insert(key, groups.len());
                    groups.push(vec![at]);
                }
            }
        }
        // Small groups stay one row per finding.
        let mut shown: Vec<Vec<usize>> = Vec::new();
        for group in groups {
            if group.len() >= FOLD_FINDINGS_AT {
                shown.push(group);
            } else {
                shown.extend(group.into_iter().map(|at| vec![at]));
            }
        }
        shown.sort_by_key(|group| group[0]);
        let empty = RowData::default();
        let data = |at: usize| table.data.get(at).unwrap_or(&empty);
        let mut folded = 0usize;
        for group in &shown {
            let first = &data(group[0]).id;
            for &at in &group[1..] {
                let id = &data(at).id;
                if !id.is_empty() && !first.is_empty() {
                    self.aliases.insert(id.clone(), first.clone());
                }
            }
            folded += group.len() - 1;
        }
        let columns: Vec<String> = [
            "#",
            "First seen",
            "Tier",
            "Behaviour",
            "Rule",
            "Object",
            "Process",
            "ATT&CK",
            "Count",
            "Result",
            "Summary",
        ]
        .map(String::from)
        .to_vec();
        let text = |at: usize, name: &str| -> String {
            col(name)
                .and_then(|c| table.rows[at].get(c))
                .cloned()
                .unwrap_or_default()
        };
        let distinct = |group: &[usize], name: &str| -> usize {
            let mut seen: Vec<String> = group.iter().map(|&at| text(at, name)).collect();
            seen.sort();
            seen.dedup();
            seen.len()
        };
        let rows: Vec<Vec<Cell>> = shown
            .iter()
            .take(DOCUMENT_ROWS)
            .map(|group| {
                let at = group[0];
                let d = data(at);
                let more = |name: &str| -> String {
                    let n = distinct(group, name);
                    if n > 1 {
                        format!(" (+{} more)", n - 1)
                    } else {
                        String::new()
                    }
                };
                let number = super::anchor::finding_number(&d.id).unwrap_or(at + 1);
                let label = if group.len() > 1 {
                    format!("{number} (+{})", group.len() - 1)
                } else {
                    number.to_string()
                };
                let count: u64 = group
                    .iter()
                    .map(|&at| data(at).count.unwrap_or(1).max(1))
                    .sum();
                let mut rule = Cell::plain(text(at, "Rule"));
                rule.more_ids.clone_from(&d.anchors);
                for &other in &group[1..] {
                    rule.more_ids.extend(data(other).anchors.iter().cloned());
                }
                let time = if d.time_ms.is_some() || d.relative_ms.is_some() {
                    stamp(d.relative_ms, d.time_ms)
                } else {
                    text(at, "Time")
                };
                let mut object = Cell::link(self.free(&text(at, "Target")), &d.target_ref);
                object.spans.push(Span::plain(more("Target")));
                let mut process = Cell::link(self.free(&text(at, "Process")), &d.process_ref);
                process.spans.push(Span::plain(more("Process")));
                vec![
                    Cell::plain(label).with_id(&d.id),
                    Cell::plain(time),
                    Cell::plain(text(at, "Tier").to_uppercase()),
                    Cell::plain(self.free(&text(at, "Behaviour"))),
                    rule,
                    object,
                    process,
                    Cell::link(
                        text(at, "ATT&CK"),
                        d.attack_refs.first().map_or("", String::as_str),
                    ),
                    Cell::plain(if group.len() > 1 || d.count.is_some() {
                        format!("\u{d7}{}", thousands(count))
                    } else {
                        text(at, "Count")
                    }),
                    Cell::plain(text(at, "Result")),
                    Cell::plain(self.free(&text(at, "Summary"))),
                ]
            })
            .collect();
        let mut blocks = vec![Block::Table(DocTable { columns, rows })];
        if folded > 0 {
            blocks.push(Block::Note(format!(
                "{} findings of a rule that fired {FOLD_FINDINGS_AT} times or more with the \
                 same tier and result are folded into its first row: # says how many, Count \
                 adds them up, Object and Process name the first and how many others. The JSON \
                 export lists every finding.",
                thousands(folded as u64)
            )));
        }
        if shown.len() > DOCUMENT_ROWS {
            blocks.push(Block::Note(format!(
                "{} more rows are in the JSON export.",
                shown.len() - DOCUMENT_ROWS
            )));
        }
        if table.omitted > 0 {
            blocks.push(Block::Note(format!(
                "{} more matching findings were not kept by the index.",
                thousands(table.omitted)
            )));
        }
        blocks
    }

    /// The detection engines' matches: one vocabulary for strength, the
    /// rule's family, its techniques linked, the reference with its scheme;
    /// the credits a rule's licence asks for in a table under it.
    pub(super) fn detections_section(&mut self, report: &Report) {
        let Some(detections) = &report.detections else {
            return;
        };
        let blocks = if detections.is_empty() {
            vec![Block::Note(
                "No detection engine has a complete report for this run, or none matched.".into(),
            )]
        } else {
            let rows = detections
                .iter()
                .map(|hit| {
                    let rule = plain_rule(&hit.rule_id).to_owned();
                    let title = plain_rule(&hit.title);
                    let attack: Vec<(String, String)> = hit
                        .mitre
                        .iter()
                        .map(|t| {
                            let id = super::anchor::techniques_in(t)
                                .first()
                                .map(|t| self.reg.technique(t))
                                .unwrap_or_default();
                            (t.clone(), id)
                        })
                        .collect();
                    vec![
                        Cell::plain(hit.engine.clone()),
                        Cell::plain(rule.clone()).with_id(&hit.id),
                        Cell::plain(if title == rule {
                            String::new()
                        } else {
                            self.free(title)
                        }),
                        Cell::plain(severity_text(&hit.engine, &hit.severity, &hit.strength)),
                        Cell::link(
                            hit.family.clone(),
                            if hit.family.is_empty() {
                                ""
                            } else {
                                FAMILY_EVIDENCE
                            },
                        ),
                        Cell::list(&attack, ", "),
                        Cell::plain(thousands(hit.count)),
                        // No scheme: the document opens nothing outside
                        // itself; the JSON, MISP and STIX keep the link.
                        Cell::plain(
                            self.free(
                                hit.reference
                                    .split_once("://")
                                    .map_or(hit.reference.as_str(), |(_, rest)| rest),
                            ),
                        ),
                    ]
                })
                .collect();
            let mut table = DocTable {
                columns: [
                    "Engine",
                    "Rule",
                    "Title",
                    "Strength",
                    "Family",
                    "ATT&CK",
                    "Count",
                    "Reference",
                ]
                .map(String::from)
                .to_vec(),
                rows,
            };
            drop_empty_columns(&mut table, &["Title", "Family", "ATT&CK", "Reference"]);
            let credits = detections
                .iter()
                .map(|hit| {
                    vec![
                        Cell::link(plain_rule(&hit.rule_id).to_owned(), &hit.id),
                        Cell::plain(or_unknown(&hit.author)),
                        Cell::plain(hit.license.clone()),
                        Cell::plain(pack_label(&hit.source)),
                    ]
                })
                .collect();
            vec![
                Block::Table(table),
                Block::Note(
                    "References are the rules' own links without their scheme, and not \
                     clickable: this document opens nothing outside itself. The JSON, MISP and \
                     STIX exports keep each link whole."
                        .into(),
                ),
                Block::sub("Rule credits"),
                Block::Table(DocTable {
                    columns: ["Rule", "Author", "License", "Pack"]
                        .map(String::from)
                        .to_vec(),
                    rows: credits,
                }),
                Block::Note(
                    "A rule's licence asks that its author stay with every message that reports \
                     a match, so the author, licence and pack are listed for every rule."
                        .into(),
                ),
            ]
        };
        self.section("detections", "Detection engines", blocks);
    }
}

/// Remove the columns in `names` whose every cell is empty.
pub(crate) fn drop_empty_columns(table: &mut DocTable, names: &[&str]) {
    let gone: Vec<usize> = table
        .columns
        .iter()
        .enumerate()
        .filter(|(at, name)| {
            names.contains(&name.as_str())
                && table.rows.iter().all(|row| {
                    row.get(*at)
                        .is_none_or(|cell| cell.text().trim().is_empty())
                })
        })
        .map(|(at, _)| at)
        .collect();
    for at in gone.into_iter().rev() {
        table.columns.remove(at);
        for row in &mut table.rows {
            if at < row.len() {
                row.remove(at);
            }
        }
    }
}

/// What the Indicator cell of a row says: the value, a stand-in's name, a
/// file's path (with the paths of every file of one hash).
pub(super) fn indicator_text(group: &[&Indicator]) -> String {
    let first = group[0];
    if !first.stand_in.is_empty() {
        return format!("{} \u{2192} {} (Tor stand-in)", first.value, first.stand_in);
    }
    if first.kind != "file" {
        return if first.path.is_empty() {
            first.value.clone()
        } else {
            format!("{} {}", first.value, first.path)
        };
    }
    let mut paths: Vec<&str> = group
        .iter()
        .map(|i| {
            if i.path.is_empty() {
                i.value.as_str()
            } else {
                i.path.as_str()
            }
        })
        .collect();
    paths.sort_unstable();
    paths.dedup();
    let listed: Vec<&str> = paths.iter().take(5).copied().collect();
    let more = paths.len() - listed.len();
    let paths_text = format!(
        "{}{}",
        listed.join(", "),
        if more > 0 {
            format!(" (+{more} more)")
        } else {
            String::new()
        }
    );
    if first.sha256.is_empty() || first.value == "(no content kept)" {
        return paths_text;
    }
    if paths.len() == 1 {
        format!("{} {}", first.value, paths_text)
    } else {
        format!("{} at {} paths: {paths_text}", first.value, paths.len())
    }
}

/// The Count cell: the frames or connections of a network row, or what the
/// run did to a file, over the whole group.
pub(super) fn indicator_seen(group: &[&Indicator]) -> String {
    let first = group[0];
    if first.kind != "file" {
        return first.count.clone();
    }
    let mut roles: Vec<&str> = Vec::new();
    for item in group {
        for role in item.count.split(", ").filter(|r| !r.is_empty()) {
            if !roles.contains(&role) {
                roles.push(role);
            }
        }
    }
    roles.join(", ")
}

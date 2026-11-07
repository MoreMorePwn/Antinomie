// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The page model HTML and PDF both draw: a title, then sections of
//! paragraphs, fact lists, tables and notes, in the same order for both. A
//! [`Report`] becomes a [`Document`] here, with indicators defanged on
//! request and long tables cut to [`DOCUMENT_ROWS`].
use super::fold::{FOLDED_ROWS, fold_events};
use super::{DOCUMENT_ROWS, Indicator, IndicatorKind, NamedTable, Report, Table, defang};

/// One drawn element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Paragraph(String),
    /// Name and value pairs; a value may be a hash or path (drawn in monospace).
    Facts(Vec<(String, String)>),
    Table(DocTable),
    /// A small heading inside a section (a tab's name).
    Sub(String),
    /// A remark in a quieter style: what is missing or cut.
    Note(String),
    /// Short statements, one per line (the Summary's key findings).
    List(Vec<String>),
}

/// A table ready to draw: every cell final text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocTable {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// A titled part of the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Anchor and bookmark id.
    pub id: String,
    pub title: String,
    pub blocks: Vec<Block>,
}

/// The whole document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Document {
    pub title: String,
    pub subtitle: String,
    pub defanged: bool,
    pub sections: Vec<Section>,
    /// What the PDF says of itself and draws on every page.
    pub meta: Meta,
}

/// Document metadata for the PDF's info record and its page header and footer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    /// The kind of report (`Antinomie Triage report`).
    pub creator: String,
    pub subject: String,
    pub keywords: String,
    /// The running header of pages after the first.
    pub header: String,
    /// The footer's left part (when it was generated).
    pub footer: String,
}

struct Builder {
    defang: bool,
    sections: Vec<Section>,
    /// Credits (the geolocation database's) for the closing Notes section.
    credits: Vec<String>,
}

impl Builder {
    fn free(&self, text: &str) -> String {
        if self.defang {
            defang::text(text)
        } else {
            text.to_owned()
        }
    }

    fn value(&self, kind: Option<IndicatorKind>, text: &str) -> String {
        match (self.defang, kind) {
            (true, Some(kind)) => defang::indicator(kind, text),
            (true, None) => defang::text(text),
            (false, _) => text.to_owned(),
        }
    }

    fn doc_table(&self, table: &Table) -> (DocTable, Option<String>) {
        let rows: Vec<Vec<String>> = table
            .rows
            .iter()
            .take(DOCUMENT_ROWS)
            .map(|row| {
                row.iter()
                    .enumerate()
                    .map(|(column, cell)| {
                        let kind = table
                            .indicator_columns
                            .iter()
                            .find(|marked| marked.column == column)
                            .map(|marked| marked.kind);
                        self.value(kind, cell)
                    })
                    .collect()
            })
            .collect();
        let cut = table.rows.len().saturating_sub(DOCUMENT_ROWS) as u64 + table.omitted;
        let total = table.rows.len() as u64 + table.omitted;
        let note = (cut > 0).then(|| {
            format!(
                "First {} of {} rows. {cut} more matching rows are not shown here; the JSON \
                 export keeps the rows the index held (the page size is a Settings value).",
                total - cut,
                total
            )
        });
        (
            DocTable {
                columns: table.columns.clone(),
                rows,
            },
            note,
        )
    }

    fn table_blocks(&self, table: &Table, blocks: &mut Vec<Block>) {
        if table.rows.is_empty() {
            blocks.push(Block::Note("No rows.".into()));
            return;
        }
        let (doc, note) = self.doc_table(table);
        blocks.push(Block::Table(doc));
        if let Some(note) = note {
            blocks.push(Block::Note(note));
        }
    }

    fn named(&self, tables: &[NamedTable], blocks: &mut Vec<Block>) {
        for named in tables {
            blocks.push(Block::Sub(format!(
                "{} ({})",
                named.name,
                named.table.rows.len() as u64 + named.table.omitted
            )));
            self.table_blocks(&named.table, blocks);
        }
    }

    /// The Files tabs: repeated rows folded into one with a count, and each
    /// tab cut to [`FOLDED_ROWS`] rows. The JSON keeps every row.
    fn files(&self, tabs: &[NamedTable], blocks: &mut Vec<Block>) {
        for named in tabs {
            let (folded, gone) = if named.name == "Changed files" {
                (named.table.clone(), 0)
            } else {
                fold_events(&named.table)
            };
            let total = named.table.rows.len() as u64 + named.table.omitted;
            blocks.push(Block::Sub(format!("{} ({})", named.name, thousands(total))));
            if folded.rows.is_empty() {
                blocks.push(Block::Note("No rows.".into()));
                continue;
            }
            let shown = folded.rows.len().min(FOLDED_ROWS);
            let mut table = folded.clone();
            table.rows.truncate(FOLDED_ROWS);
            table.omitted = 0;
            let (doc, _) = self.doc_table(&table);
            blocks.push(Block::Table(doc));
            let mut said = Vec::new();
            if gone > 0 {
                said.push(format!(
                    "{} repeated rows are folded into the count of the row they repeat.",
                    thousands(gone)
                ));
            }
            if folded.rows.len() > shown {
                said.push(format!(
                    "The first {shown} of {} distinct rows are shown.",
                    thousands(folded.rows.len() as u64)
                ));
            }
            if named.table.omitted > 0 {
                said.push(format!(
                    "{} more matching rows were not kept by the index.",
                    thousands(named.table.omitted)
                ));
            }
            if !said.is_empty() {
                said.push("The JSON export keeps every row the index held.".into());
                blocks.push(Block::Note(said.join(" ")));
            }
        }
    }

    fn section(&mut self, id: &str, title: &str, blocks: Vec<Block>) {
        self.sections.push(Section {
            id: id.into(),
            title: title.into(),
            blocks,
        });
    }
}

impl Builder {
    /// The overview: when, what ran, and the notes of the report.
    fn overview_section(&mut self, report: &Report) {
        let run = &report.run;
        let mut head = vec![
            ("Generated".to_owned(), super::shown(report.generated_ms)),
            ("Application".to_owned(), report.app.clone()),
            ("Run".to_owned(), run.run_id.clone()),
            ("Boot".to_owned(), run.boot_id.clone()),
            ("VM".to_owned(), run.vm_id.clone()),
        ];
        if let Some(started) = run.started_ms {
            head.push(("Run started".into(), super::shown(started)));
        }
        head.push((
            "Run state".into(),
            if !run.state.is_empty() {
                let mut text = run.state.clone();
                if !run.finished {
                    text.push_str(" when read");
                }
                text
            } else if run.finished {
                "finished".into()
            } else {
                "still running when read".into()
            },
        ));
        if let Some(ended) = run.ended_ms {
            head.push(("Run ended".into(), super::shown(ended)));
        }
        if let Some(ms) = run.duration_ms {
            head.push(("Duration".into(), duration(ms)));
        }
        if !run.exit.is_empty() {
            head.push(("Root program".into(), run.exit.clone()));
        }
        match &report.sample {
            Some(sample) => {
                let label = if sample.role.is_empty() {
                    "Sample".to_owned()
                } else {
                    format!("Sample ({})", sample.role)
                };
                head.push((label, sample.name.clone()));
                head.push(("Sample SHA-256".into(), sample.sha256.clone()));
                if sample.size.is_some() {
                    head.push((
                        "Sample size".into(),
                        sample
                            .size
                            .map_or(String::new(), crate::byte_size::file_size),
                    ));
                }
            }
            None if !run.command.is_empty() => {
                head.push((
                    "Sample".into(),
                    "none recorded: the run started a command, not a library sample".into(),
                ));
            }
            None => {}
        }
        if !run.command.is_empty() {
            head.push(("Command".into(), run.command.clone()));
        }
        head.retain(|(_, value)| !value.is_empty());
        let mut blocks = vec![Block::Facts(head)];
        let mut environment: Vec<(String, String)> = run
            .environment
            .iter()
            .map(|fact| (fact.name.clone(), fact.value.clone()))
            .collect();
        if run.route.is_empty() || environment.iter().any(|(name, _)| name == "Network route") {
            // The route is already one of the facts.
        } else {
            environment.push(("Network route".into(), run.route.clone()));
        }
        if !environment.is_empty() {
            blocks.push(Block::Sub("Environment".into()));
            blocks.push(Block::Facts(environment));
        }
        blocks.push(Block::Note(zone_note(report.generated_ms)));
        if self.defang {
            blocks.push(Block::Note(
                "Indicators in this document are defanged (hxxp, [.]) so they cannot be opened by \
             accident. The JSON, MISP and STIX exports carry the raw values."
                    .into(),
            ));
        }
        // The geolocation credit closes the document; the rest are about the run.
        let (credits, notes): (Vec<&String>, Vec<&String>) =
            report.notes.iter().partition(|note| note.contains("DB-IP"));
        for note in notes {
            blocks.push(Block::Note(self.free(note)));
        }
        self.section("overview", "Run overview", blocks);
        self.credits = credits.into_iter().map(|note| self.free(note)).collect();
    }

    /// The summary section: the statement, the counts and the key behaviours.
    fn summary_section(&mut self, report: &Report) {
        if let Some(summary) = &report.summary {
            let mut blocks = vec![Block::Paragraph(self.free(&summary.statement))];
            let tiers = &summary.tiers;
            let mut facts = vec![
                (
                    "Highest tier".to_owned(),
                    summary.highest_tier.to_uppercase(),
                ),
                (
                    "Findings by tier".to_owned(),
                    format!(
                        "{} HIGH, {} MEDIUM, {} LOW, {} INFO",
                        thousands(tiers.high),
                        thousands(tiers.medium),
                        thousands(tiers.low),
                        thousands(tiers.info)
                    ),
                ),
            ];
            if !summary.families.is_empty() {
                facts.push(("Family".into(), summary.families.join(", ")));
                facts.push((
                    "Family named by".into(),
                    if summary.family_sources.is_empty() {
                        summary.families.join(", ")
                    } else {
                        summary.family_sources.join("; ")
                    },
                ));
            }
            let c = &summary.counts;
            let many = |n: u64, one: &str, more: &str| {
                format!("{} {}", thousands(n), if n == 1 { one } else { more })
            };
            facts.push((
                "Observed".into(),
                format!(
                    "{}, {}, {} ({} matched a dataset), {}, {} changed of {} opened, {}, {}",
                    many(c.processes, "process", "processes"),
                    many(c.findings, "finding", "findings"),
                    many(c.indicators, "indicator", "indicators"),
                    thousands(c.indicators_matched),
                    many(c.techniques, "ATT&CK technique", "ATT&CK techniques"),
                    many(c.files_changed, "file", "files"),
                    thousands(c.files_opened),
                    many(c.endpoints, "endpoint", "endpoints"),
                    many(c.domains, "domain", "domains"),
                ),
            ));
            blocks.push(Block::Facts(facts));
            if !summary.key_findings.is_empty() {
                blocks.push(Block::Sub("Key findings".into()));
                blocks.push(Block::List(
                    summary
                        .key_findings
                        .iter()
                        .map(|line| self.free(line))
                        .collect(),
                ));
            }
            if !summary.key_behaviours.is_empty() {
                blocks.push(Block::Sub("Key behaviours".into()));
                blocks.push(Block::Table(DocTable {
                    columns: ["Tier", "Category", "Rule", "Count"]
                        .map(String::from)
                        .to_vec(),
                    rows: summary
                        .key_behaviours
                        .iter()
                        .map(|behaviour| {
                            vec![
                                behaviour.tier.to_uppercase(),
                                behaviour.category.clone(),
                                behaviour.rule.clone(),
                                thousands(behaviour.count),
                            ]
                        })
                        .collect(),
                }));
            }
            self.section("summary", "Summary", blocks);
        }
    }

    /// The indicators of compromise table. Files with one hash are one row
    /// with their paths listed; a Tor stand-in address names the domain it
    /// stands for.
    fn indicators_section(&mut self, report: &Report) {
        if let Some(all) = &report.indicators {
            let indicators: Vec<&Indicator> =
                all.iter().filter(|i| i.base_noise.is_empty()).collect();
            let noisy = all.len() - indicators.len();
            let unshared = indicators
                .iter()
                .filter(|i| !i.not_shared.is_empty())
                .count();
            let mut blocks = Vec::new();
            if indicators.is_empty() {
                blocks.push(Block::Note("The run produced no indicators.".into()));
            } else {
                // Group the files that have one hash.
                let mut order: Vec<Vec<&Indicator>> = Vec::new();
                let mut by_hash: std::collections::HashMap<&str, usize> =
                    std::collections::HashMap::new();
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
                let rows: Vec<Vec<String>> = order
                    .iter()
                    .take(DOCUMENT_ROWS)
                    .map(|group| {
                        let indicator = group[0];
                        let kind = IndicatorKind::from_id(&indicator.kind);
                        vec![
                            indicator.kind.clone(),
                            self.value(kind, &indicator_text(group)),
                            indicator.verdict.clone(),
                            indicator.dataset.clone(),
                            indicator.family.clone(),
                            self.free(&indicator.process),
                            shown_iso(&indicator.first_seen),
                            indicator_seen(group),
                        ]
                    })
                    .collect();
                blocks.push(Block::Table(DocTable {
                    columns: [
                        "Type",
                        "Indicator",
                        "Verdict",
                        "Dataset",
                        "Family",
                        "Process",
                        "First seen",
                        "Seen as / count",
                    ]
                    .map(String::from)
                    .to_vec(),
                    rows,
                }));
                if order.len() > DOCUMENT_ROWS {
                    blocks.push(Block::Note(format!(
                        "{} more indicators are in the JSON, MISP and STIX exports.",
                        order.len() - DOCUMENT_ROWS
                    )));
                }
            }
            if unshared > 0 {
                blocks.push(Block::Note(format!(
                    "{unshared} of these are not in the MISP and STIX exports: Tor stand-in \
                     addresses (the domain they stand for is), private addresses of the sandbox, \
                     files with no content kept, and programs of the base image the run only \
                     started."
                )));
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
    }

    /// The ATT&CK techniques table.
    fn attack_section(&mut self, report: &Report) {
        if let Some(attack) = &report.attack {
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
                            vec![
                                technique.id.clone(),
                                technique.name.clone(),
                                super::tactic_cell(&technique.id),
                                technique.count.to_string(),
                                technique.rules.join(", "),
                            ]
                        })
                        .collect(),
                })]
            };
            self.section("attack", "ATT&CK techniques", blocks);
        }
    }

    /// The files the run changed and how far each was reconstructed.
    fn file_activity_section(&mut self, report: &Report) {
        if let Some(records) = &report.file_activity {
            let blocks = if records.is_empty() {
                vec![Block::Note("No file of the run was changed.".into())]
            } else {
                let mut blocks = vec![Block::Table(DocTable {
                    columns: [
                        "Path",
                        "State",
                        "Size",
                        "Guest SHA-256",
                        "Reconstruction",
                        "Written",
                        "Not captured",
                        "In bundle",
                    ]
                    .map(String::from)
                    .to_vec(),
                    rows: records
                        .iter()
                        .take(DOCUMENT_ROWS)
                        .map(|record| {
                            let mut state = Vec::new();
                            if record.created {
                                state.push("created");
                            }
                            if record.changed {
                                state.push("changed");
                            }
                            if record.deleted {
                                state.push("deleted");
                            }
                            vec![
                                record.path.clone(),
                                state.join(", "),
                                record.final_size.map_or(String::new(), |s| s.to_string()),
                                record.guest_sha256.clone(),
                                record.reconstruction.clone(),
                                record.bytes_written.to_string(),
                                (record.bytes_not_captured + record.bytes_unknown).to_string(),
                                record.bundle_entry.clone(),
                            ]
                        })
                        .collect(),
                })];
                if records.len() > DOCUMENT_ROWS {
                    blocks.push(Block::Note(format!(
                        "{} more files are in the JSON export.",
                        records.len() - DOCUMENT_ROWS
                    )));
                }
                blocks
            };
            self.section("file-activity", "File activity and reconstruction", blocks);
        }
    }

    /// The detection engines' matches. Severity is said in one vocabulary
    /// (how much a YARA match says, an IDS or Sigma level), the pack's own
    /// id stays in the JSON, and the rule's reference is a column of its own.
    fn detections_section(&mut self, report: &Report) {
        if let Some(detections) = &report.detections {
            let blocks = if detections.is_empty() {
                vec![Block::Note(
                    "No detection engine has a complete report for this run, or none matched."
                        .into(),
                )]
            } else {
                vec![Block::Table(DocTable {
                    columns: [
                        "Engine",
                        "Rule",
                        "Title",
                        "Severity",
                        "ATT&CK",
                        "Count",
                        "Author",
                        "License",
                        "Source",
                        "Reference",
                    ]
                    .map(String::from)
                    .to_vec(),
                    rows: detections
                        .iter()
                        .map(|hit| {
                            vec![
                                hit.engine.clone(),
                                plain_rule(&hit.rule_id).to_owned(),
                                plain_rule(&hit.title).to_owned(),
                                severity_text(hit),
                                hit.mitre.join(", "),
                                thousands(hit.count),
                                or_unknown(&hit.author),
                                hit.license.clone(),
                                hit.source.clone(),
                                // No scheme: the HTML holds no link or address
                                // outside itself; the JSON, MISP and STIX keep it.
                                self.free(
                                    hit.reference
                                        .split_once("://")
                                        .map_or(hit.reference.as_str(), |(_, rest)| rest),
                                ),
                            ]
                        })
                        .collect(),
                })]
            };
            self.section("detections", "Detection engines", blocks);
        }
    }

    /// The evidence files of the run folder: the recordings, not the small
    /// logs and records that sit beside them.
    fn evidence_section(&mut self, report: &Report) {
        if let Some(evidence) = &report.evidence {
            let main: Vec<_> = evidence
                .iter()
                .filter(|item| item.kind != "other")
                .collect();
            let blocks = if evidence.is_empty() {
                vec![Block::Note(
                    "The run folder holds no evidence files.".into(),
                )]
            } else {
                let mut blocks = vec![Block::Table(DocTable {
                    columns: ["Kind", "Path", "Size", "SHA-256"]
                        .map(String::from)
                        .to_vec(),
                    rows: main
                        .iter()
                        .map(|item| {
                            vec![
                                item.kind.clone(),
                                item.path.clone(),
                                crate::byte_size::file_size(item.size),
                                if item.sha256.is_empty() {
                                    "not hashed (large)".into()
                                } else {
                                    item.sha256.clone()
                                },
                            ]
                        })
                        .collect(),
                })];
                let other = evidence.len() - main.len();
                if other > 0 {
                    blocks.push(Block::Note(format!(
                        "{other} smaller file(s) of the run folder (terminal records, manifests) \
                         are listed in the JSON export."
                    )));
                }
                blocks
            };
            self.section("evidence", "Evidence references", blocks);
        }
    }

    /// The custody log's head and whether its chain verified.
    fn custody_section(&mut self, report: &Report) {
        if let Some(custody) = &report.custody {
            let mut facts = vec![
                ("Sample SHA-256".to_owned(), custody.sample_sha256.clone()),
                ("Entries".into(), custody.entries.to_string()),
                ("Head hash".into(), custody.head.clone()),
                (
                    "Chain".into(),
                    if custody.verified {
                        "verified when exported".into()
                    } else {
                        format!("not verified: {}", custody.problem)
                    },
                ),
            ];
            if !custody.library_head.is_empty() {
                facts.push(("Library index head".into(), custody.library_head.clone()));
            }
            self.section(
                "custody",
                "Custody log",
                vec![
                Block::Facts(facts),
                Block::Note(
                    "Tamper-evident, not tamper-proof. Keep the head hash somewhere else to rule \
                     out a rewritten chain."
                        .into(),
                ),
            ],
            );
        }
    }
}

/// The document for `report`. `defang` rewrites indicators for reading.
pub fn document(report: &Report, defang: bool) -> Document {
    let mut b = Builder {
        defang,
        sections: Vec::new(),
        credits: Vec::new(),
    };
    b.overview_section(report);
    b.summary_section(report);
    b.indicators_section(report);
    b.attack_section(report);
    if let Some(table) = &report.processes {
        let mut blocks = Vec::new();
        b.table_blocks(table, &mut blocks);
        b.section("processes", "Processes", blocks);
    }
    if let Some(table) = &report.findings {
        let mut blocks = Vec::new();
        b.table_blocks(table, &mut blocks);
        b.section("findings", "Suspicious activity", blocks);
    }
    if let Some(files) = &report.files {
        let mut blocks = Vec::new();
        b.files(&files.tabs, &mut blocks);
        b.section("files", "Files", blocks);
    }
    b.file_activity_section(report);
    if let Some(tabs) = &report.network {
        let mut blocks = Vec::new();
        b.named(tabs, &mut blocks);
        b.section("network", "Network", blocks);
    }
    b.detections_section(report);
    b.evidence_section(report);
    b.custody_section(report);
    if !b.credits.is_empty() {
        let blocks = b.credits.iter().cloned().map(Block::Note).collect();
        b.section("notes", "Notes", blocks);
    }

    let name = report
        .sample
        .as_ref()
        .map(|sample| sample.name.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(&report.run.run_id);
    Document {
        title: format!("Antinomie Triage report: {name}"),
        subtitle: format!(
            "Run {} - generated {}",
            report.run.run_id,
            super::shown(report.generated_ms)
        ),
        defanged: defang,
        sections: b.sections,
        meta: Meta {
            creator: "Antinomie Triage report".into(),
            subject: match &report.sample {
                Some(sample) => format!("Run {} of {}", report.run.run_id, sample.sha256),
                None => format!("Run {}", report.run.run_id),
            },
            keywords: {
                let mut words = vec!["Antinomie".to_owned(), "triage".into()];
                words.extend(report.summary.iter().flat_map(|s| s.families.clone()));
                words.push(format!(
                    "run {}",
                    report.run.run_id.get(..8).unwrap_or(&report.run.run_id)
                ));
                words.join(", ")
            },
            header: format!(
                "Antinomie Triage report: {name} - run {}",
                report.run.run_id.get(..8).unwrap_or(&report.run.run_id)
            ),
            footer: format!("Generated {}", super::shown(report.generated_ms)),
        },
    }
}

/// A rule's author, or `unknown` when the rule names none (a rule's licence
/// asks that the author stay with its matches).
fn or_unknown(author: &str) -> String {
    if author.is_empty() {
        "unknown".into()
    } else {
        author.into()
    }
}

/// A rule id or title without the pack's own number (`s1919::Name` is `Name`).
pub(crate) fn plain_rule(text: &str) -> &str {
    if let Some((pack, rest)) = text.split_once("::")
        && pack.len() > 1
        && pack.starts_with('s')
        && pack[1..].bytes().all(|b| b.is_ascii_digit())
    {
        return rest;
    }
    text
}

/// How strong a match is, in the words the app's cards use: a YARA match as
/// strong or weak (with an Elastic score), a Sigma or IDS match by its level.
fn severity_text(hit: &super::Detection) -> String {
    let score: Option<u32> = hit.severity.trim().parse().ok();
    if !hit.strength.is_empty() {
        return match score {
            Some(score) => format!("{} (score {score})", hit.strength),
            None => hit.strength.clone(),
        };
    }
    match (hit.engine.as_str(), hit.severity.is_empty()) {
        (_, true) => String::new(),
        (engine, false) if engine.eq_ignore_ascii_case("sigma") => {
            format!("Sigma {}", hit.severity)
        }
        (engine, false) if engine.eq_ignore_ascii_case("ids") => format!("IDS {}", hit.severity),
        _ => hit.severity.clone(),
    }
}

/// What the Indicator cell of a row says: the value, a stand-in's name, a
/// file's path (with the paths of every file of one hash).
fn indicator_text(group: &[&Indicator]) -> String {
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
fn indicator_seen(group: &[&Indicator]) -> String {
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

/// A count with thousands separators: `167,040`.
pub(crate) fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (at, c) in digits.chars().enumerate() {
        if at > 0 && (digits.len() - at).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A duration as a person reads it: `385 ms`, `6 min 25 s`, `1 h 05 min`.
fn duration(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0 => format!("{ms} ms"),
        1..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {:02} min", seconds / 3600, seconds / 60 % 60),
    }
}

/// The footnote that says which zone every time is in, and what `~` means.
fn zone_note(at_ms: u64) -> String {
    let text = super::shown(at_ms);
    let zone = text.rfind('(').map_or("the display zone", |at| {
        text[at..].trim_matches(|c| c == '(' || c == ')')
    });
    format!(
        "All times are {zone}, the zone the app shows. A time marked ~ is estimated from the \
         guest clock; +N s is the time since the run's first call."
    )
}

/// An ISO time of the JSON (`2026-11-07T10:40:42.662Z`) in the document's
/// zone and notation; other text is left as it is.
pub(crate) fn shown_iso(text: &str) -> String {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[10] != b'T' || !text.ends_with('Z') {
        return text.to_owned();
    }
    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let parsed = (|| {
        let days = crate::date::days_from_civil(
            number(0, 4)? as i32,
            number(5, 7)? as u32,
            number(8, 10)? as u32,
        )?;
        Some(days * 86_400 + number(11, 13)? * 3600 + number(14, 16)? * 60 + number(17, 19)?)
    })();
    match parsed {
        Some(seconds) if seconds >= 0 => super::shown(seconds as u64 * 1000),
        _ => text.to_owned(),
    }
}

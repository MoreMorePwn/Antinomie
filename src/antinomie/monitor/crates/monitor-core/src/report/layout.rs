// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The page model HTML and PDF both draw: a title, then sections of
//! paragraphs, fact lists, tables and notes, in the same order for both. A
//! [`Report`] becomes a [`Document`] here, with indicators defanged on
//! request and long tables cut to [`DOCUMENT_ROWS`].
use super::{DOCUMENT_ROWS, IndicatorKind, NamedTable, Report, Table, defang, iso};

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
}

struct Builder {
    defang: bool,
    sections: Vec<Section>,
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
        let note = (cut > 0).then(|| {
            format!(
                "{cut} more matching rows are not shown here; the JSON export keeps every row \
                 the index held."
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

    fn section(&mut self, id: &str, title: &str, blocks: Vec<Block>) {
        self.sections.push(Section {
            id: id.into(),
            title: title.into(),
            blocks,
        });
    }
}

fn size_text(size: Option<u64>) -> String {
    size.map_or(String::new(), |size| format!("{size} bytes"))
}

/// The document for `report`. `defang` rewrites indicators for reading.
pub fn document(report: &Report, defang: bool) -> Document {
    let mut b = Builder {
        defang,
        sections: Vec::new(),
    };
    let mut head = vec![
        (
            "Generated".to_owned(),
            format!("{} UTC", super::utc(report.generated_ms)),
        ),
        ("Application".to_owned(), report.app.clone()),
        ("Run".to_owned(), report.run.run_id.clone()),
        ("Boot".to_owned(), report.run.boot_id.clone()),
        ("VM".to_owned(), report.run.vm_id.clone()),
    ];
    if let Some(started) = report.run.started_ms {
        head.push(("Run started".into(), format!("{} UTC", super::utc(started))));
    }
    head.push((
        "Run state".into(),
        if report.run.finished {
            "finished"
        } else {
            "still running when read"
        }
        .into(),
    ));
    if let Some(sample) = &report.sample {
        head.push(("Sample".into(), sample.name.clone()));
        head.push(("Sample SHA-256".into(), sample.sha256.clone()));
        if sample.size.is_some() {
            head.push(("Sample size".into(), size_text(sample.size)));
        }
    }
    head.retain(|(_, value)| !value.is_empty());
    let mut blocks = vec![Block::Facts(head)];
    if defang {
        blocks.push(Block::Note(
            "Indicators in this document are defanged (hxxp, [.]) so they cannot be opened by \
             accident. The JSON, MISP and STIX exports carry the raw values."
                .into(),
        ));
    }
    for note in &report.notes {
        blocks.push(Block::Note(b.free(note)));
    }
    b.section("overview", "Run overview", blocks);

    if let Some(summary) = &report.summary {
        let mut blocks = vec![Block::Paragraph(b.free(&summary.statement))];
        let mut facts = vec![(
            "Highest tier".to_owned(),
            summary.highest_tier.to_uppercase(),
        )];
        if !summary.families.is_empty() {
            facts.push((
                "Family named by datasets".into(),
                summary.families.join(", "),
            ));
        }
        let c = &summary.counts;
        facts.push((
            "Observed".into(),
            format!(
                "{} processes, {} findings, {} indicators ({} matched a dataset), {} ATT&CK techniques, \
                 {} files changed of {} opened, {} endpoints, {} domains",
                c.processes,
                c.findings,
                c.indicators,
                c.indicators_matched,
                c.techniques,
                c.files_changed,
                c.files_opened,
                c.endpoints,
                c.domains
            ),
        ));
        blocks.push(Block::Facts(facts));
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
                            behaviour.count.to_string(),
                        ]
                    })
                    .collect(),
            }));
        }
        b.section("summary", "Summary", blocks);
    }

    if let Some(indicators) = &report.indicators {
        let mut blocks = Vec::new();
        if indicators.is_empty() {
            blocks.push(Block::Note("The run produced no indicators.".into()));
        } else {
            blocks.push(Block::Table(DocTable {
                columns: [
                    "Type",
                    "Indicator",
                    "Verdict",
                    "Dataset",
                    "Family",
                    "Process",
                    "First seen",
                    "Count",
                ]
                .map(String::from)
                .to_vec(),
                rows: indicators
                    .iter()
                    .take(DOCUMENT_ROWS)
                    .map(|indicator| {
                        let kind = IndicatorKind::from_id(&indicator.kind);
                        let shown = if indicator.path.is_empty() {
                            indicator.value.clone()
                        } else {
                            format!("{} {}", indicator.value, indicator.path)
                        };
                        vec![
                            indicator.kind.clone(),
                            b.value(kind, &shown),
                            indicator.verdict.clone(),
                            indicator.dataset.clone(),
                            indicator.family.clone(),
                            b.free(&indicator.process),
                            indicator.first_seen.clone(),
                            indicator.count.clone(),
                        ]
                    })
                    .collect(),
            }));
            if indicators.len() > DOCUMENT_ROWS {
                blocks.push(Block::Note(format!(
                    "{} more indicators are in the JSON, MISP and STIX exports.",
                    indicators.len() - DOCUMENT_ROWS
                )));
            }
        }
        b.section("indicators", "Indicators of compromise", blocks);
    }

    if let Some(attack) = &report.attack {
        let blocks = if attack.is_empty() {
            vec![Block::Note(
                "No rule of the run cites an ATT&CK technique.".into(),
            )]
        } else {
            vec![Block::Table(DocTable {
                columns: ["Technique", "Name", "Count", "Rules"]
                    .map(String::from)
                    .to_vec(),
                rows: attack
                    .iter()
                    .map(|technique| {
                        vec![
                            technique.id.clone(),
                            technique.name.clone(),
                            technique.count.to_string(),
                            technique.rules.join(", "),
                        ]
                    })
                    .collect(),
            })]
        };
        b.section("attack", "ATT&CK techniques", blocks);
    }

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
        b.named(&files.tabs, &mut blocks);
        b.section("files", "Files", blocks);
    }
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
        b.section("file-activity", "File activity and reconstruction", blocks);
    }
    if let Some(tabs) = &report.network {
        let mut blocks = Vec::new();
        b.named(tabs, &mut blocks);
        b.section("network", "Network", blocks);
    }
    if let Some(detections) = &report.detections {
        let blocks = if detections.is_empty() {
            vec![Block::Note(
                "No detection engine has a complete report for this run, or none matched.".into(),
            )]
        } else {
            vec![Block::Table(DocTable {
                columns: [
                    "Engine", "Rule", "Title", "Severity", "ATT&CK", "Count", "Author", "License",
                    "Source",
                ]
                .map(String::from)
                .to_vec(),
                rows: detections
                    .iter()
                    .map(|hit| {
                        vec![
                            hit.engine.clone(),
                            hit.rule_id.clone(),
                            hit.title.clone(),
                            hit.severity.clone(),
                            hit.mitre.join(", "),
                            hit.count.to_string(),
                            or_unknown(&hit.author),
                            hit.license.clone(),
                            source_text(hit),
                        ]
                    })
                    .collect(),
            })]
        };
        b.section("detections", "Detection engines", blocks);
    }
    if let Some(evidence) = &report.evidence {
        let blocks = if evidence.is_empty() {
            vec![Block::Note(
                "The run folder holds no evidence files.".into(),
            )]
        } else {
            vec![Block::Table(DocTable {
                columns: ["Kind", "Path", "Size", "SHA-256"]
                    .map(String::from)
                    .to_vec(),
                rows: evidence
                    .iter()
                    .map(|item| {
                        vec![
                            item.kind.clone(),
                            item.path.clone(),
                            item.size.to_string(),
                            if item.sha256.is_empty() {
                                "not hashed (large)".into()
                            } else {
                                item.sha256.clone()
                            },
                        ]
                    })
                    .collect(),
            })]
        };
        b.section("evidence", "Evidence references", blocks);
    }
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
        b.section(
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

    let name = report
        .sample
        .as_ref()
        .map(|sample| sample.name.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(&report.run.run_id);
    Document {
        title: format!("Antinomie Triage report: {name}"),
        subtitle: format!(
            "Run {} - generated {} UTC",
            report.run.run_id,
            iso_short(report)
        ),
        defanged: defang,
        sections: b.sections,
    }
}

fn iso_short(report: &Report) -> String {
    iso(report.generated_ms)[..19].replace('T', " ")
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

/// The rule pack and the rule's own reference. The HTML holds no link, so the
/// reference is written without its scheme here; the JSON, MISP and STIX keep
/// the full address.
fn source_text(hit: &super::Detection) -> String {
    let reference = hit
        .reference
        .split_once("://")
        .map_or(hit.reference.as_str(), |(_, rest)| rest);
    match (hit.source.is_empty(), reference.is_empty()) {
        (_, true) => hit.source.clone(),
        (true, false) => reference.to_owned(),
        (false, false) => format!("{} ({reference})", hit.source),
    }
}

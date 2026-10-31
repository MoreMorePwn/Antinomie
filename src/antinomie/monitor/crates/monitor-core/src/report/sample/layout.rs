// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The page model of a sample report, drawn by the same HTML and PDF writers
//! as a run report (and by [`super::markdown`]): a title, then sections of
//! paragraphs, fact lists, tables and notes. Indicators are defanged on
//! request; tables are cut at [`DOCUMENT_ROWS`] with a note.
use super::super::layout::{Block, DocTable, Document, Section};
use super::super::{DOCUMENT_ROWS, IndicatorKind, defang, iso, utc};
use super::*;

/// The assessment in words.
pub fn assessment_label(assessment: &str) -> &'static str {
    match assessment {
        "matched_indicators" => "Matched indicators",
        "suspicious_behaviour" => "Suspicious behaviour",
        "observed_only" => "Observed only",
        "no_findings" => "No findings",
        _ => "Not read by Triage",
    }
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

    fn indicator(&self, kind: &str, text: &str) -> String {
        match (self.defang, IndicatorKind::from_id(kind)) {
            (true, Some(kind)) => defang::indicator(kind, text),
            (true, None) => defang::text(text),
            (false, _) => text.to_owned(),
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

/// A table block, cut at the document cap with a note; `empty` is the note
/// for no rows.
fn table(columns: &[&str], rows: Vec<Vec<String>>, empty: &str, blocks: &mut Vec<Block>) {
    if rows.is_empty() {
        blocks.push(Block::Note(empty.into()));
        return;
    }
    let total = rows.len();
    blocks.push(Block::Table(DocTable {
        columns: columns.iter().map(|c| (*c).to_owned()).collect(),
        rows: rows.into_iter().take(DOCUMENT_ROWS).collect(),
    }));
    if total > DOCUMENT_ROWS {
        blocks.push(Block::Note(format!(
            "{} more rows are not shown here; the JSON export keeps them.",
            total - DOCUMENT_ROWS
        )));
    }
}

fn time(ms: Option<u64>) -> String {
    ms.filter(|ms| *ms > 0)
        .map_or(String::new(), |ms| format!("{} UTC", utc(ms)))
}

fn runs_text(runs: &[usize]) -> String {
    runs.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn credit(value: &str) -> String {
    if value.is_empty() {
        "unknown".into()
    } else {
        value.into()
    }
}

/// The rule pack and the rule's own reference, the reference without its
/// scheme (the HTML holds no links).
pub(super) fn source_text(hit: &RuleHit) -> String {
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

fn lineage_rows(b: &Builder, nodes: &[LineageEntry]) -> Vec<Vec<String>> {
    nodes
        .iter()
        .map(|node| {
            vec![
                node.level.to_string(),
                node.kind.clone(),
                b.free(&node.label),
                node.path.clone(),
                node.sha256.clone(),
                node.verdict.clone(),
                node.via.clone(),
                runs_text(&node.runs),
            ]
        })
        .collect()
}

/// The document for `report`; `defang` rewrites indicators for reading.
pub fn document(report: &SampleReport, defang: bool) -> Document {
    let mut b = Builder {
        defang,
        sections: Vec::new(),
    };
    let sample = &report.sample;
    let mut head = vec![
        ("Generated".to_owned(), format!("{} UTC", utc(report.generated_ms))),
        ("Application".into(), report.app.clone()),
        ("Sample".into(), b.free(&sample.name)),
        ("SHA-256".into(), sample.sha256.clone()),
        ("SHA-1".into(), sample.sha1.clone()),
        ("MD5".into(), sample.md5.clone()),
        ("TLSH".into(), sample.tlsh.clone()),
        ("File type".into(), sample.file_type.clone()),
        ("Architecture".into(), sample.arch.clone()),
        ("Size".into(), format!("{} bytes", sample.size)),
        ("Family".into(), b.free(&sample.family)),
        (
            "Tags".into(),
            sample
                .tags
                .iter()
                .map(|tag| b.free(&tag.value))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ("First seen".into(), time(sample.first_seen_ms)),
        ("Last seen".into(), time(sample.last_seen_ms)),
        ("Added to the library".into(), time(Some(sample.added_ms))),
        (
            "Archive".into(),
            if sample.removed_ms.is_some() {
                "removed (the record stays)"
            } else if sample.archived {
                "on disk"
            } else {
                "not on disk"
            }
            .into(),
        ),
        ("Description".into(), b.free(&sample.description)),
    ];
    head.retain(|(_, value)| !value.is_empty());
    let mut blocks = vec![Block::Facts(head)];
    blocks.push(Block::Paragraph(if report.runs.is_empty() {
        "The sample has not been run, so there is no behavioural assessment.".into()
    } else {
        format!(
            "{} run(s). The strongest Triage assessment among them: {}. These are observations \
             from recorded runs, not a verdict on the sample.",
            report.runs.len(),
            assessment_label(report.assessment())
        )
    }));
    blocks.push(Block::Note(
        "This report names the sample by its hashes. It holds none of the sample's bytes."
            .into(),
    ));
    if defang {
        blocks.push(Block::Note(
            "Indicators in this document are defanged (hxxp, [.]) so they cannot be opened by \
             accident. The JSON, MISP and STIX exports carry the raw values."
                .into(),
        ));
    }
    for note in &report.remarks {
        blocks.push(Block::Note(b.free(note)));
    }
    b.section("overview", "Sample overview", blocks);

    // Identity: names and origins.
    let mut blocks = Vec::new();
    blocks.push(Block::Sub(format!("Names ({})", sample.names.len())));
    table(
        &["Name", "Path", "Seen"],
        sample
            .names
            .iter()
            .map(|n| vec![b.free(&n.name), n.path.clone(), b.free(&n.seen)])
            .collect(),
        "The sample went by no other name.",
        &mut blocks,
    );
    blocks.push(Block::Sub(format!("Origins ({})", sample.origins.len())));
    table(
        &["When", "How", "Source", "VM", "Run", "Name", "Detail", "Parent"],
        sample
            .origins
            .iter()
            .map(|o| {
                vec![
                    time(Some(o.at_ms)),
                    o.kind.clone(),
                    b.free(&o.source),
                    o.vm.clone(),
                    o.run_id.clone(),
                    b.free(&o.name),
                    b.free(&o.detail),
                    o.parent.clone(),
                ]
            })
            .collect(),
        "No origin is recorded.",
        &mut blocks,
    );
    b.section("identity", "Names and origins", blocks);

    // Static analysis.
    let st = &report.static_analysis;
    let mut blocks = Vec::new();
    if !st.available {
        blocks.push(Block::Note(st.reason.clone()));
    } else {
        let mut facts = vec![
            ("State".to_owned(), st.state.clone()),
            (
                "Report".into(),
                format!(
                    "{}{}",
                    st.report_id,
                    st.from_run.map_or(String::new(), |n| format!(" (run {n})"))
                ),
            ),
            ("Packer".into(), credit_none(&st.packer)),
        ];
        if !st.reason.is_empty() {
            facts.push(("Reason".into(), st.reason.clone()));
        }
        blocks.push(Block::Facts(facts));
        blocks.push(Block::Sub("Checks".into()));
        table(
            &["Check", "State", "Reason", "Summary", "Tools"],
            st.checks
                .iter()
                .map(|c| {
                    vec![
                        c.label.clone(),
                        c.state.clone(),
                        c.reason.clone(),
                        b.free(&c.summary),
                        c.tools.join(", "),
                    ]
                })
                .collect(),
        "No check is recorded.",
            &mut blocks,
        );
        if !st.layers.is_empty() {
            blocks.push(Block::Sub("Unpack chain".into()));
            table(
                &["Layer", "Method", "Size", "SHA-256", "Packer"],
                st.layers
                    .iter()
                    .map(|l| {
                        vec![
                            l.index.to_string(),
                            l.method.clone(),
                            l.size.to_string(),
                            l.sha256.clone(),
                            l.packer.clone(),
                        ]
                    })
                    .collect(),
                "",
                &mut blocks,
            );
        }
        blocks.push(Block::Sub(format!("Capabilities ({})", st.capabilities.len())));
        table(
            &["Capability", "Namespace", "ATT&CK", "MBC"],
            st.capabilities
                .iter()
                .map(|c| {
                    vec![
                        c.name.clone(),
                        c.namespace.clone(),
                        c.attack.join(", "),
                        c.mbc.join(", "),
                    ]
                })
                .collect(),
            "capa reported no capability, or the check did not run.",
            &mut blocks,
        );
        if st.capabilities_omitted > 0 {
            blocks.push(Block::Note(format!(
                "{} more capabilities are not in this report.",
                st.capabilities_omitted
            )));
        }
        blocks.push(Block::Sub(format!(
            "FLOSS strings ({} found, {} shown)",
            st.floss_total,
            st.floss.len()
        )));
        table(
            &["Kind", "String"],
            st.floss
                .iter()
                .map(|f| vec![f.origin.clone(), b.free(&f.text)])
                .collect(),
            "FLOSS recovered no string, or the check did not run.",
            &mut blocks,
        );
        if st.floss_total as usize > st.floss.len() {
            blocks.push(Block::Note(format!(
                "Only the first {FLOSS_ROWS} strings are shown, each cut to {STRING_CHARS} \
                 characters. The Samples window and the static report hold the rest."
            )));
        }
    }
    b.section("static", "Static analysis", blocks);

    // Rules.
    let mut blocks = Vec::new();
    table(
        &[
            "Engine", "Rule", "Title", "Severity", "Runs", "Count", "ATT&CK", "Family", "Author",
            "License", "Source",
        ],
        report
            .detections
            .iter()
            .map(|hit| {
                vec![
                    hit.engine.clone(),
                    hit.rule_id.clone(),
                    b.free(&hit.title),
                    hit.severity.clone(),
                    runs_text(&hit.runs),
                    hit.count.to_string(),
                    hit.mitre.join(", "),
                    hit.family.clone(),
                    credit(&hit.author),
                    credit(&hit.license),
                    source_text(hit),
                ]
            })
            .collect(),
        "No YARA, Sigma or IDS rule matched in the static scan or in a run whose detection \
         report is complete.",
        &mut blocks,
    );
    if report.omitted.detections > 0 {
        blocks.push(Block::Note(format!(
            "{} more rules are not in this report.",
            report.omitted.detections
        )));
    }
    blocks.push(Block::Note(
        "A rule's licence asks that its author stay with every message that reports a match, so \
         the author, licence and source are listed for every rule."
            .into(),
    ));
    b.section("rules", "Rules that matched", blocks);

    // Runs.
    let mut blocks = Vec::new();
    table(
        &[
            "Run", "VM", "Started", "Exit", "Assessment", "Tier", "Rules", "Indicators",
            "Run report",
        ],
        report
            .runs
            .iter()
            .map(|run| {
                vec![
                    run.number.to_string(),
                    b.free(if run.vm_name.is_empty() { &run.vm_id } else { &run.vm_name }),
                    time(run.started_ms),
                    run.exit.clone(),
                    assessment_label(&run.assessment).into(),
                    run.highest_tier.to_uppercase(),
                    run.rules.to_string(),
                    format!("{} ({} matched)", run.indicators, run.indicators_matched),
                    if !run.report_file.is_empty() {
                        run.report_file.clone()
                    } else if run.folder_present {
                        "not exported yet (Triage > Export report)".into()
                    } else {
                        "run deleted".into()
                    },
                ]
            })
            .collect(),
        "The sample has not been run.",
        &mut blocks,
    );
    if report.omitted.runs > 0 {
        blocks.push(Block::Note(format!(
            "{} more runs are not in this report.",
            report.omitted.runs
        )));
    }
    blocks.push(Block::Note(
        "Each run's own report is the Triage export of that run, written in the run's folder. \
         It is named here by its path, since a report holds no links."
            .into(),
    ));
    b.section("runs", "Runs", blocks);

    // Lineage.
    let mut blocks = Vec::new();
    let columns = [
        "Level", "Kind", "Name", "Path", "SHA-256", "Verdict", "Joined by", "Runs",
    ];
    blocks.push(Block::Sub(format!("Parents ({})", report.lineage.parents.len())));
    table(
        &columns,
        lineage_rows(&b, &report.lineage.parents),
        "No parent.",
        &mut blocks,
    );
    blocks.push(Block::Sub(format!("Children ({})", report.lineage.children.len())));
    table(
        &columns,
        lineage_rows(&b, &report.lineage.children),
        "No children.",
        &mut blocks,
    );
    if !report.lineage.reason.is_empty() {
        blocks.push(Block::Note(report.lineage.reason.clone()));
    }
    if report.omitted.lineage > 0 {
        blocks.push(Block::Note(format!(
            "{} more lineage entries are not in this report.",
            report.omitted.lineage
        )));
    }
    b.section("lineage", "Lineage", blocks);

    // Indicators.
    let mut blocks = Vec::new();
    table(
        &["Type", "Indicator", "Dataset", "Runs"],
        report
            .indicators
            .iter()
            .map(|i| {
                vec![
                    i.kind.clone(),
                    b.indicator(&i.kind, &i.value),
                    if i.matched { "matched" } else { "no match" }.into(),
                    runs_text(&i.runs),
                ]
            })
            .collect(),
        "No run of the sample produced an indicator, or Triage has not read the runs.",
        &mut blocks,
    );
    if report.omitted.indicators > 0 {
        blocks.push(Block::Note(format!(
            "{} more indicators are not in this report.",
            report.omitted.indicators
        )));
    }
    b.section("indicators", "Indicators merged across runs", blocks);

    if !report.attack.is_empty() {
        let mut blocks = Vec::new();
        table(
            &["Technique", "Name", "Count", "Rules"],
            report
                .attack
                .iter()
                .map(|t| {
                    vec![
                        t.id.clone(),
                        t.name.clone(),
                        t.count.to_string(),
                        t.rules.join(", "),
                    ]
                })
                .collect(),
            "",
            &mut blocks,
        );
        b.section("attack", "ATT&CK techniques", blocks);
    }

    // Custody.
    let c = &report.custody;
    let mut blocks = vec![Block::Facts(vec![
        ("Entries".to_owned(), c.entries.to_string()),
        ("Head hash".into(), c.head.clone()),
        (
            "Chain".into(),
            if c.verified {
                "verified when exported".into()
            } else {
                format!("not verified: {}", c.problem)
            },
        ),
    ])];
    table(
        &["#", "Time", "By", "Event", "Detail", "State"],
        c.log
            .iter()
            .map(|row| {
                vec![
                    row.seq.to_string(),
                    time(Some(row.at_ms)),
                    row.by.clone(),
                    row.event.clone(),
                    b.free(&row.detail),
                    row.state.clone(),
                ]
            })
            .collect(),
        "The custody log has no entry.",
        &mut blocks,
    );
    if report.omitted.custody > 0 {
        blocks.push(Block::Note(format!(
            "The oldest {} entries are not listed; the head hash covers them.",
            report.omitted.custody
        )));
    }
    blocks.push(Block::Note(
        "Tamper-evident, not tamper-proof. Writing this report adds an Exported entry to the \
         log after the head shown here. Keep the head hash somewhere else to rule out a \
         rewritten chain."
            .into(),
    ));
    b.section("custody", "Custody log", blocks);

    // Notes.
    let mut blocks = Vec::new();
    if report.notes.is_empty() {
        blocks.push(Block::Note("The sample has no notes.".into()));
    }
    for note in &report.notes {
        blocks.push(Block::Sub(format!(
            "Note {} by {}, {}{}",
            note.id,
            note.by,
            time(Some(note.created_ms)),
            note.edited_ms
                .map_or(String::new(), |ms| format!(", edited {}", time(Some(ms))))
        )));
        blocks.push(Block::Paragraph(b.free(&note.text)));
        if note.cut {
            blocks.push(Block::Note(format!("The note was cut to {NOTE_CHARS} characters.")));
        }
        if !note.refs.is_empty() {
            blocks.push(Block::Note(format!("Refers to {}", b.free(&note.refs.join("; ")))));
        }
    }
    if report.omitted.notes > 0 {
        blocks.push(Block::Note(format!(
            "{} more notes are not in this report.",
            report.omitted.notes
        )));
    }
    b.section("notes", "Notes", blocks);

    // Similar.
    let mut blocks = Vec::new();
    table(
        &["Sample", "SHA-256", "TLSH distance", "Shared"],
        report
            .similar
            .rows
            .iter()
            .map(|s| {
                vec![
                    b.free(&s.name),
                    s.sha256.clone(),
                    s.distance.to_string(),
                    s.shared.clone(),
                ]
            })
            .collect(),
        "No other library sample is close to this one.",
        &mut blocks,
    );
    if !report.similar.reason.is_empty() {
        blocks.push(Block::Note(report.similar.reason.clone()));
    }
    b.section("similar", "Similar samples", blocks);

    let name = if sample.name.is_empty() {
        sample.sha256.as_str()
    } else {
        sample.name.as_str()
    };
    Document {
        title: format!("Antinomie Sample report: {name}"),
        subtitle: format!(
            "Sample {} - generated {} UTC",
            sample.sha256.get(..16).unwrap_or(&sample.sha256),
            iso(report.generated_ms)[..19].replace('T', " ")
        ),
        defanged: defang,
        sections: b.sections,
    }
}

fn credit_none(value: &str) -> String {
    if value.is_empty() {
        "none found".into()
    } else {
        value.into()
    }
}

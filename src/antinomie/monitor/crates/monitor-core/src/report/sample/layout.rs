// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The page model of a sample report, drawn by the same HTML and PDF writers
//! as a run report (and by [`super::markdown`]): a title, then sections of
//! paragraphs, fact lists, tables and notes. Indicators are defanged on
//! request; tables are cut at [`DOCUMENT_ROWS`] with a note.
use super::super::layout::{
    Block, Cell, DocTable, Document, Section, Span, pack_label, plain_rule, severity_text,
};
use super::super::{DOCUMENT_ROWS, IndicatorKind, defang};
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
    blocks.push(Block::Table(DocTable::plain(
        columns.iter().map(|c| (*c).to_owned()).collect(),
        rows.into_iter().take(DOCUMENT_ROWS).collect(),
    )));
    if total > DOCUMENT_ROWS {
        blocks.push(Block::Note(format!(
            "{} more rows are not shown here; the JSON export keeps them.",
            total - DOCUMENT_ROWS
        )));
    }
}

/// The note under a table of `total` rows cut at [`DOCUMENT_ROWS`].
fn cut_note(total: usize, blocks: &mut Vec<Block>) {
    if total > DOCUMENT_ROWS {
        blocks.push(Block::Note(format!(
            "{} more rows are not shown here; the JSON export keeps them.",
            total - DOCUMENT_ROWS
        )));
    }
}

fn time(ms: Option<u64>) -> String {
    ms.filter(|ms| *ms > 0)
        .map_or(String::new(), crate::report::shown)
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

/// The first section: the sample's identity facts and what the report is.
fn overview_section(b: &mut Builder, report: &SampleReport) {
    let sample = &report.sample;
    let mut head = vec![
        (
            "Generated".to_owned(),
            crate::report::shown(report.generated_ms),
        ),
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
            "Family named by rules".into(),
            b.free(
                &sample
                    .family_candidates
                    .iter()
                    .map(|candidate| format!("{} ({})", candidate.name, candidate.source))
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
        ),
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
    let mut blocks = vec![Block::facts(head)];
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
        "This report names the sample by its hashes. It holds none of the sample's bytes.".into(),
    ));
    if b.defang {
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
}

/// Names the sample went by and where it came from.
fn identity_section(b: &mut Builder, report: &SampleReport) {
    let sample = &report.sample;
    let mut blocks = Vec::new();
    blocks.push(Block::sub(format!("Names ({})", sample.names.len())));
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
    blocks.push(Block::sub(format!("Origins ({})", sample.origins.len())));
    table(
        &[
            "When", "How", "Source", "VM", "Run", "Name", "Detail", "Parent",
        ],
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
}

/// The retained static analysis of the sample.
fn static_section(b: &mut Builder, report: &SampleReport) {
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
        blocks.push(Block::facts(facts));
        blocks.push(Block::sub("Checks"));
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
            blocks.push(Block::sub("Unpack chain"));
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
        blocks.push(Block::sub(format!(
            "Capabilities ({})",
            st.capabilities.len()
        )));
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
        blocks.push(Block::sub(format!(
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
}

/// The anchor of a rule's row: the run report's `det-<engine>-<rule>`.
fn rule_anchor(hit: &RuleHit) -> String {
    let engine = hit.engine.split(' ').next().unwrap_or(&hit.engine);
    crate::report::anchor::detection(engine, &hit.rule_id)
}

/// How much a match says, in the run report's words: a YARA match strong or
/// weak (with its score), an IDS or Sigma match by its level.
fn strength_text(hit: &RuleHit) -> String {
    let engine = hit.engine.split(' ').next().unwrap_or(&hit.engine);
    let strength = if engine.eq_ignore_ascii_case("yara") {
        match crate::family::strength(&hit.rule_id, &hit.severity, &hit.source, &hit.family) {
            crate::family::Strength::Strong => "strong",
            crate::family::Strength::Weak => "weak",
            crate::family::Strength::WrongPlatform => "wrong platform",
        }
    } else {
        ""
    };
    // A yarahub "indicator" level says nothing a strength does not.
    let severity = if hit.severity.eq_ignore_ascii_case("indicator") {
        ""
    } else {
        hit.severity.as_str()
    };
    severity_text(engine, severity, strength)
}

/// The family a rule names: its own `family`, else what its name says.
fn rule_family(hit: &RuleHit) -> String {
    if !hit.family.is_empty() {
        return hit.family.clone();
    }
    let engine = hit.engine.split(' ').next().unwrap_or(&hit.engine);
    crate::family::rule_family(&crate::run_digest::DetectionHit {
        engine: engine.into(),
        rule_id: hit.rule_id.clone(),
        title: hit.title.clone(),
        severity: hit.severity.clone(),
        source: hit.source.clone(),
        ..Default::default()
    })
    .unwrap_or_default()
}

/// YARA, Sigma and IDS matches in one strength vocabulary, each row the
/// anchor of its rule, with the credits a rule's licence asks for below.
fn rules_section(b: &mut Builder, report: &SampleReport) {
    let mut blocks = Vec::new();
    if report.detections.is_empty() {
        blocks.push(Block::Note(
            "No YARA, Sigma or IDS rule matched in the static scan or in a run whose detection \
             report is complete."
                .into(),
        ));
    } else {
        let rows: Vec<Vec<Cell>> = report
            .detections
            .iter()
            .take(DOCUMENT_ROWS)
            .map(|hit| {
                let rule = plain_rule(&hit.rule_id).to_owned();
                let title = plain_rule(&hit.title);
                let runs: Vec<(String, String)> = hit
                    .runs
                    .iter()
                    .map(|n| (n.to_string(), format!("run-{n}")))
                    .collect();
                let mut seen = Vec::new();
                if hit.in_static_scan {
                    seen.push(Span::plain("static scan"));
                }
                if !runs.is_empty() {
                    seen.push(Span::plain(if hit.in_static_scan {
                        " + runs "
                    } else {
                        "runs "
                    }));
                    seen.extend(Cell::list(&runs, ", ").spans);
                }
                vec![
                    Cell::plain(hit.engine.clone()),
                    Cell::plain(rule.clone()).with_id(&rule_anchor(hit)),
                    Cell::plain(if title == rule {
                        String::new()
                    } else {
                        b.free(title)
                    }),
                    Cell::plain(strength_text(hit)),
                    Cell::of(seen),
                    Cell::plain(hit.count.to_string()),
                    Cell::plain(hit.mitre.join(", ")),
                    Cell::plain(rule_family(hit)),
                ]
            })
            .collect();
        let mut doc = DocTable {
            columns: [
                "Engine", "Rule", "Title", "Strength", "Seen in", "Count", "ATT&CK", "Family",
            ]
            .map(String::from)
            .to_vec(),
            rows,
        };
        crate::report::layout::drop_empty_columns(&mut doc, &["Title", "ATT&CK", "Family"]);
        blocks.push(Block::Table(doc));
        cut_note(report.detections.len(), &mut blocks);
        blocks.push(Block::sub("Rule credits"));
        blocks.push(Block::Table(DocTable {
            columns: ["Rule", "Author", "License", "Pack", "Reference"]
                .map(String::from)
                .to_vec(),
            rows: report
                .detections
                .iter()
                .take(DOCUMENT_ROWS)
                .map(|hit| {
                    vec![
                        Cell::link(plain_rule(&hit.rule_id).to_owned(), &rule_anchor(hit)),
                        Cell::plain(credit(&hit.author)),
                        Cell::plain(credit(&hit.license)),
                        Cell::plain(pack_label(&hit.source)),
                        Cell::plain(
                            hit.reference
                                .split_once("://")
                                .map_or(hit.reference.as_str(), |(_, rest)| rest)
                                .to_owned(),
                        ),
                    ]
                })
                .collect(),
        }));
    }
    if report.omitted.detections > 0 {
        blocks.push(Block::Note(format!(
            "{} more rules are not in this report.",
            report.omitted.detections
        )));
    }
    blocks.push(Block::Note(
        "A rule's licence asks that its author stay with every message that reports a match, so \
         the author, licence and pack are listed for every rule. References are written without \
         their scheme; the JSON keeps each link whole."
            .into(),
    ));
    b.section("rules", "Rules that matched", blocks);
}

/// One row per recorded run, the anchor `run-<n>`; its report a link.
fn runs_section(b: &mut Builder, report: &SampleReport) {
    let mut blocks = Vec::new();
    let rows: Vec<Vec<Cell>> = report
        .runs
        .iter()
        .take(DOCUMENT_ROWS)
        .map(|run| {
            let report_cell = if !run.report_file.is_empty() {
                // Relative to `<data>/sample-reports`, where this report goes
                // unless another folder is chosen.
                Cell::of(vec![Span {
                    text: run.report_file.clone(),
                    href: Some(format!("../{}", run.report_file)),
                }])
            } else if run.folder_present {
                Cell::plain("not exported yet (Triage > Export report)")
            } else {
                Cell::plain("run deleted")
            };
            vec![
                Cell::plain(run.number.to_string()).with_id(&format!("run-{}", run.number)),
                Cell::plain(b.free(if run.vm_name.is_empty() {
                    &run.vm_id
                } else {
                    &run.vm_name
                })),
                Cell::plain(time(run.started_ms)),
                Cell::plain(run.exit.clone()),
                Cell::plain(assessment_label(&run.assessment)),
                Cell::plain(run.highest_tier.to_uppercase()),
                Cell::plain(run.rules.to_string()),
                Cell::plain(format!(
                    "{} ({} matched)",
                    run.indicators, run.indicators_matched
                )),
                report_cell,
            ]
        })
        .collect();
    if rows.is_empty() {
        blocks.push(Block::Note("The sample has not been run.".into()));
    } else {
        blocks.push(Block::Table(DocTable {
            columns: [
                "Run",
                "VM",
                "Started",
                "Exit",
                "Assessment",
                "Tier",
                "Rules",
                "Indicators",
                "Run report",
            ]
            .map(String::from)
            .to_vec(),
            rows,
        }));
        cut_note(report.runs.len(), &mut blocks);
    }
    if report.omitted.runs > 0 {
        blocks.push(Block::Note(format!(
            "{} more runs are not in this report.",
            report.omitted.runs
        )));
    }
    blocks.push(Block::Note(
        "Each run's own report is the Triage export of that run with the most sections, the \
         newest of those, in the run's folder. It is named by its path inside the data folder \
         and, in the HTML and Markdown, linked relative to the data folder's sample-reports \
         folder, where this report is written unless another folder was chosen."
            .into(),
    ));
    b.section("runs", "Runs", blocks);
}

/// Parents and children in the sample lineage.
fn lineage_section(b: &mut Builder, report: &SampleReport) {
    let mut blocks = Vec::new();
    let columns = [
        "Level",
        "Kind",
        "Name",
        "Path",
        "SHA-256",
        "Verdict",
        "Joined by",
        "Runs",
    ];
    blocks.push(Block::sub(format!(
        "Parents ({})",
        report.lineage.parents.len()
    )));
    table(
        &columns,
        lineage_rows(b, &report.lineage.parents),
        "No parent.",
        &mut blocks,
    );
    blocks.push(Block::sub(format!(
        "Children ({})",
        report.lineage.children.len()
    )));
    table(
        &columns,
        lineage_rows(b, &report.lineage.children),
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
}

/// Indicators merged across runs, each row `ioc-<n>`, its runs linked, and
/// whether MISP and STIX carry it.
fn indicators_section(b: &mut Builder, report: &SampleReport) {
    let mut blocks = Vec::new();
    let rows: Vec<Vec<Cell>> = report
        .indicators
        .iter()
        .take(DOCUMENT_ROWS)
        .enumerate()
        .map(|(at, i)| {
            let runs: Vec<(String, String)> = i
                .runs
                .iter()
                .map(|n| (n.to_string(), format!("run-{n}")))
                .collect();
            let mut runs = Cell::list(&runs, ", ");
            if i.every_run {
                runs.spans.push(Span::plain(" (every run)"));
            }
            vec![
                Cell::plain(i.kind.clone()).with_id(&crate::report::anchor::indicator(at + 1)),
                Cell::plain(b.indicator(&i.kind, &i.value)),
                Cell::plain(i.observed.join(", ")),
                Cell::plain(if i.hits.is_empty() {
                    if i.matched { "matched" } else { "no match" }.to_owned()
                } else {
                    i.hits.join("; ")
                }),
                runs,
                Cell::plain(if i.not_shared.is_empty() {
                    "yes".to_owned()
                } else {
                    format!("no: {}", i.not_shared)
                }),
            ]
        })
        .collect();
    if rows.is_empty() {
        blocks.push(Block::Note(
            "No run of the sample produced an indicator, or Triage has not read the runs.".into(),
        ));
    } else {
        blocks.push(Block::Table(DocTable {
            columns: [
                "Type",
                "Indicator",
                "How seen",
                "Dataset",
                "Runs",
                "In MISP / STIX",
            ]
            .map(String::from)
            .to_vec(),
            rows,
        }));
        cut_note(report.indicators.len(), &mut blocks);
    }
    if report.omitted.indicators > 0 {
        blocks.push(Block::Note(format!(
            "{} more indicators are not in this report.",
            report.omitted.indicators
        )));
    }
    b.section("indicators", "Indicators merged across runs", blocks);
}

/// ATT&CK techniques, each row `attack-<id>`, each rule a link to its row
/// under Rules that matched; no section when there are none.
fn attack_section(b: &mut Builder, report: &SampleReport) {
    if !report.attack.is_empty() {
        // `Engine: rule` and a bare rule name both name a rule's row.
        let mut rules: std::collections::BTreeMap<String, String> = Default::default();
        for hit in &report.detections {
            let engine = hit.engine.split(' ').next().unwrap_or(&hit.engine);
            for key in [
                format!("{engine}: {}", plain_rule(&hit.title)),
                format!("{engine}: {}", plain_rule(&hit.rule_id)),
                plain_rule(&hit.rule_id).to_owned(),
            ] {
                rules.entry(key).or_insert_with(|| rule_anchor(hit));
            }
        }
        let rows = report
            .attack
            .iter()
            .map(|t| {
                let items: Vec<(String, String)> = t
                    .rules
                    .iter()
                    .map(|r| {
                        (
                            plain_rule(r).to_owned(),
                            rules.get(r).cloned().unwrap_or_default(),
                        )
                    })
                    .collect();
                vec![
                    Cell::plain(t.id.clone()).with_id(&crate::report::anchor::attack(&t.id)),
                    Cell::plain(t.name.clone()),
                    Cell::plain(crate::report::tactic_cell(&t.id)),
                    Cell::plain(t.count.to_string()),
                    Cell::list(&items, ", "),
                ]
            })
            .collect();
        let blocks = vec![Block::Table(DocTable {
            columns: ["Technique", "Name", "Tactic", "Count", "Rules"]
                .map(String::from)
                .to_vec(),
            rows,
        })];
        b.section("attack", "ATT&CK techniques", blocks);
    }
}

/// The custody chain and its log.
fn custody_section(b: &mut Builder, report: &SampleReport) {
    let c = &report.custody;
    let mut blocks = vec![Block::facts(vec![
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
}

/// The analyst notes.
fn notes_section(b: &mut Builder, report: &SampleReport) {
    let mut blocks = Vec::new();
    if report.notes.is_empty() {
        blocks.push(Block::Note("The sample has no notes.".into()));
    }
    for note in &report.notes {
        blocks.push(Block::sub(format!(
            "Note {} by {}, {}{}",
            note.id,
            note.by,
            time(Some(note.created_ms)),
            note.edited_ms
                .map_or(String::new(), |ms| format!(", edited {}", time(Some(ms))))
        )));
        blocks.push(Block::Paragraph(b.free(&note.text)));
        if note.cut {
            blocks.push(Block::Note(format!(
                "The note was cut to {NOTE_CHARS} characters."
            )));
        }
        if !note.refs.is_empty() {
            blocks.push(Block::Note(format!(
                "Refers to {}",
                b.free(&note.refs.join("; "))
            )));
        }
    }
    if report.omitted.notes > 0 {
        blocks.push(Block::Note(format!(
            "{} more notes are not in this report.",
            report.omitted.notes
        )));
    }
    b.section("notes", "Notes", blocks);
}

/// Library samples close to this one.
fn similar_section(b: &mut Builder, report: &SampleReport) {
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
}

/// The document for `report`; `defang` rewrites indicators for reading.
pub fn document(report: &SampleReport, defang: bool) -> Document {
    let mut b = Builder {
        defang,
        sections: Vec::new(),
    };
    let sample = &report.sample;
    overview_section(&mut b, report);
    identity_section(&mut b, report);
    static_section(&mut b, report);
    rules_section(&mut b, report);
    runs_section(&mut b, report);
    lineage_section(&mut b, report);
    indicators_section(&mut b, report);
    attack_section(&mut b, report);
    custody_section(&mut b, report);
    notes_section(&mut b, report);
    similar_section(&mut b, report);

    let name = if sample.name.is_empty() {
        sample.sha256.as_str()
    } else {
        sample.name.as_str()
    };
    let mut document = Document {
        title: format!("Antinomie Sample report: {name}"),
        subtitle: format!(
            "Sample {} - generated {}",
            sample.sha256.get(..16).unwrap_or(&sample.sha256),
            crate::report::shown(report.generated_ms)
        ),
        defanged: defang,
        sections: b.sections,
        meta: crate::report::layout::Meta {
            creator: "Antinomie Sample report".into(),
            subject: format!("Sample {}", sample.sha256),
            keywords: {
                let mut words = vec!["Antinomie".to_owned(), "sample".into()];
                words.extend(sample.family_candidates.iter().map(|c| c.name.clone()));
                if !sample.family.is_empty() {
                    words.push(sample.family.clone());
                }
                words.join(", ")
            },
            header: format!(
                "Antinomie Sample report: {name} - {}",
                sample.sha256.get(..8).unwrap_or(&sample.sha256)
            ),
            footer: format!("Generated {}", crate::report::shown(report.generated_ms)),
        },
        aliases: Default::default(),
    };
    crate::report::page::finish(&mut document);
    document
}

fn credit_none(value: &str) -> String {
    if value.is_empty() {
        "none found".into()
    } else {
        value.into()
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! A [`Report`] as the page model ([`super::page`]) HTML, PDF and Markdown
//! draw, in the order an analyst reads: At a glance (the run, the key
//! findings, the family evidence), indicators, techniques, processes,
//! suspicious activity, files, network, detections, evidence, custody, notes
//! and the environment. Every mention of a process, file, endpoint, domain,
//! rule, finding, technique or detection links to its entry, and an entry
//! lists the findings about it; the links come from the report's own `id`
//! and `*_ref` fields ([`super::refs`]). Indicators are defanged on request
//! and long tables cut to [`DOCUMENT_ROWS`].
pub(crate) use super::layout_parts::drop_empty_columns;
pub use super::layout_parts::pack_label;
pub use super::page::{Block, Cell, DocTable, Document, Meta, Section, Span};
use super::refs::{self, Registry};
use super::{DOCUMENT_ROWS, IndicatorKind, Report, Table, defang};
use std::collections::BTreeMap;

/// The anchor of the Summary's family evidence table.
pub(super) const FAMILY_EVIDENCE: &str = "overview-family-evidence";

pub(super) struct Builder {
    pub defang: bool,
    pub sections: Vec<Section>,
    /// Credits (the geolocation database's) for the closing Notes section.
    pub credits: Vec<String>,
    /// What the report's entries are, for links made from a cell's text.
    pub reg: Registry,
    /// Findings folded into the row of another: `finding-7` → `finding-3`.
    pub aliases: BTreeMap<String, String>,
    /// Endpoint → the name a Tor stand-in address was handed out for.
    pub stand_ins: BTreeMap<String, String>,
}

impl Builder {
    pub fn free(&self, text: &str) -> String {
        if self.defang {
            defang::text(text)
        } else {
            text.to_owned()
        }
    }

    pub fn value(&self, kind: Option<IndicatorKind>, text: &str) -> String {
        match (self.defang, kind) {
            (true, Some(kind)) => defang::indicator(kind, text),
            (true, None) => defang::text(text),
            (false, _) => text.to_owned(),
        }
    }

    pub fn section(&mut self, id: &str, title: &str, blocks: Vec<Block>) {
        self.sections.push(Section {
            id: id.into(),
            title: title.into(),
            blocks,
        });
    }

    /// The text a link to finding `id` reads: `#3`, after any fold.
    pub fn finding_label(&self, id: &str) -> (String, String) {
        let target = self
            .aliases
            .get(id)
            .cloned()
            .unwrap_or_else(|| id.to_owned());
        let n = super::anchor::finding_number(&target).unwrap_or(0);
        (format!("#{n}"), target)
    }

    /// Links to findings, each once after folding, in finding order.
    pub fn finding_list(&self, refs: &[String]) -> Cell {
        let mut items: Vec<(String, String)> = Vec::new();
        for id in refs {
            let item = self.finding_label(id);
            if !items.contains(&item) {
                items.push(item);
            }
        }
        items.sort_by_key(|(_, id)| super::anchor::finding_number(id).unwrap_or(0));
        Cell::list(&items, ", ")
    }

    /// A note for a table cut at [`DOCUMENT_ROWS`] or by the index's cap.
    pub fn cut_note(table: &Table) -> Option<String> {
        let cut = table.rows.len().saturating_sub(DOCUMENT_ROWS) as u64 + table.omitted;
        let total = table.rows.len() as u64 + table.omitted;
        (cut > 0).then(|| {
            format!(
                "First {} of {} rows. {cut} more matching rows are not shown here; the JSON \
                 export keeps the rows the index held (the page size is a Settings value).",
                thousands(total - cut),
                thousands(total)
            )
        })
    }
}

impl Builder {
    /// At a glance: the run and its sample, how it ended, the family, the
    /// tiers, the key findings and the family evidence, and the notes.
    fn overview_section(&mut self, report: &Report) {
        let run = &report.run;
        let mut head: Vec<(String, Cell)> = Vec::new();
        let mut put = |name: &str, value: Cell| {
            if !value.text().is_empty() {
                head.push((name.to_owned(), value));
            }
        };
        match &report.sample {
            Some(sample) => {
                let label = if sample.role.is_empty() {
                    "Sample".to_owned()
                } else {
                    format!("Sample ({})", sample.role)
                };
                put(&label, Cell::plain(sample.name.clone()));
                put("SHA-256", Cell::plain(sample.sha256.clone()));
                put(
                    "Size",
                    Cell::plain(
                        sample
                            .size
                            .map_or(String::new(), crate::byte_size::file_size),
                    ),
                );
            }
            None if !run.command.is_empty() => put(
                "Sample",
                Cell::plain("none recorded: the run started a command, not a library sample"),
            ),
            None => {}
        }
        if !run.command.is_empty() {
            put("Command", Cell::plain(self.free(&run.command)));
        }
        if let Some(summary) = &report.summary {
            let family = if summary.families.is_empty() {
                Cell::plain("none named by a detection or a dataset")
            } else {
                Cell::link(summary.families.join(", "), FAMILY_EVIDENCE)
            };
            put("Family", family);
            if !summary.other_families.is_empty() {
                put("Also named", Cell::plain(summary.other_families.join("; ")));
            }
        }
        put(
            "Run state",
            Cell::plain(if !run.state.is_empty() {
                let mut text = run.state.clone();
                if !run.finished {
                    text.push_str(" when read");
                }
                text
            } else if run.finished {
                "finished".into()
            } else {
                "still running when read".into()
            }),
        );
        if let Some(started) = run.started_ms {
            put("Run started", Cell::plain(super::shown(started)));
        }
        if let Some(ended) = run.ended_ms {
            put("Run ended", Cell::plain(super::shown(ended)));
        }
        if let Some(ms) = run.duration_ms {
            put("Duration", Cell::plain(duration(ms)));
        }
        if !run.exit.is_empty() {
            put("Root program", Cell::plain(run.exit.clone()));
        }
        let env = |name: &str| {
            run.environment
                .iter()
                .find(|fact| fact.name == name)
                .map(|fact| fact.value.clone())
                .unwrap_or_default()
        };
        let route = if run.route.is_empty() {
            env("Network route")
        } else {
            run.route.clone()
        };
        put("Network route", Cell::plain(route));
        for name in ["Base image", "Kernel", "Stealth profile"] {
            put(name, Cell::plain(env(name)));
        }
        put("Run", Cell::plain(run.run_id.clone()));
        if !run.vm_id.is_empty() || !run.boot_id.is_empty() {
            put(
                "VM / boot",
                Cell::plain(format!("{} / {}", run.vm_id, run.boot_id)),
            );
        }
        put("Generated", Cell::plain(super::shown(report.generated_ms)));
        put("Application", Cell::plain(report.app.clone()));
        if !run.environment.is_empty() {
            put(
                "Environment",
                Cell::link("rule packs, tools and the VM", "environment"),
            );
        }
        let mut blocks = vec![Block::Facts(head)];
        if let Some(summary) = &report.summary {
            blocks.insert(0, Block::Paragraph(self.free(&summary.statement)));
            self.summary_blocks(report, summary, &mut blocks);
        }
        blocks.push(Block::Note(zone_note(report.generated_ms, run.started_ms)));
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
        self.section("overview", "At a glance", blocks);
        self.credits = credits.into_iter().map(|note| self.free(note)).collect();
    }

    /// The Summary's part of At a glance: tier counts, what was observed, the
    /// key findings, the family evidence and the key behaviours.
    fn summary_blocks(&self, report: &Report, summary: &super::Summary, blocks: &mut Vec<Block>) {
        let tiers = &summary.tiers;
        let has = |id: &str| self.reg.ids.contains(id) || report_has_section(report, id);
        let to = |text: String, id: &str| {
            if has(id) {
                Span::to(text, id)
            } else {
                Span::plain(text)
            }
        };
        let mut tier_spans = Vec::new();
        for (at, (n, name)) in [
            (tiers.high, "HIGH"),
            (tiers.medium, "MEDIUM"),
            (tiers.low, "LOW"),
            (tiers.info, "INFO"),
        ]
        .into_iter()
        .enumerate()
        {
            if at > 0 {
                tier_spans.push(Span::plain(" \u{b7} "));
            }
            tier_spans.push(to(format!("{} {name}", thousands(n)), "findings"));
        }
        if tiers.info_not_listed > 0 {
            tier_spans.push(Span::plain(format!(
                " ({} more INFO findings are counted but not listed)",
                thousands(tiers.info_not_listed)
            )));
        }
        let c = &summary.counts;
        let many = |n: u64, one: &str, more: &str| {
            format!("{} {}", thousands(n), if n == 1 { one } else { more })
        };
        let observed = vec![
            to(many(c.processes, "process", "processes"), "processes"),
            Span::plain(", "),
            to(many(c.findings, "finding", "findings"), "findings"),
            Span::plain(", "),
            to(many(c.indicators, "indicator", "indicators"), "indicators"),
            Span::plain(format!(
                " ({} matched a dataset), ",
                thousands(c.indicators_matched)
            )),
            to(
                many(c.techniques, "ATT&CK technique", "ATT&CK techniques"),
                "attack",
            ),
            Span::plain(", "),
            to(
                format!(
                    "{} changed of {} opened",
                    many(c.files_changed, "file", "files"),
                    thousands(c.files_opened)
                ),
                "files",
            ),
            Span::plain(", "),
            to(many(c.endpoints, "endpoint", "endpoints"), "network"),
            Span::plain(", "),
            to(many(c.domains, "domain", "domains"), "network"),
        ];
        blocks.push(Block::Facts(vec![
            (
                "Highest tier".to_owned(),
                Cell::plain(summary.highest_tier.to_uppercase()),
            ),
            ("Findings by tier".to_owned(), Cell::of(tier_spans)),
            ("Observed".to_owned(), Cell::of(observed)),
        ]));
        if !summary.key_findings.is_empty() {
            blocks.push(Block::sub("Key findings"));
            blocks.push(Block::Table(self.key_findings_table(&summary.key_findings)));
            if summary.key_findings_total > summary.key_findings.len() as u64 {
                blocks.push(Block::Note(format!(
                    "The {} worst of {} findings of LOW and above; Suspicious activity lists \
                     them all.",
                    summary.key_findings.len(),
                    thousands(summary.key_findings_total)
                )));
            }
        }
        if !summary.families.is_empty() {
            blocks.push(Block::Sub {
                title: "Family evidence".into(),
                id: FAMILY_EVIDENCE.into(),
            });
            match self.family_evidence(report, summary) {
                Some(table) => blocks.push(Block::Table(table)),
                None => blocks.push(Block::Note(
                    summary
                        .family_sources
                        .iter()
                        .map(|source| self.free(source))
                        .collect::<Vec<_>>()
                        .join("; "),
                )),
            }
        }
        if !summary.key_behaviours.is_empty() {
            blocks.push(Block::sub("Key behaviours"));
            blocks.push(Block::Table(DocTable {
                columns: ["Tier", "Category", "Rule", "Count"]
                    .map(String::from)
                    .to_vec(),
                rows: summary
                    .key_behaviours
                    .iter()
                    .map(|behaviour| {
                        vec![
                            Cell::plain(behaviour.tier.to_uppercase()),
                            Cell::plain(behaviour.category.clone()),
                            Cell::link(behaviour.rule.clone(), &self.reg.rule(&behaviour.rule)),
                            Cell::plain(thousands(behaviour.count)),
                        ]
                    })
                    .collect(),
            }));
        }
        if let Some(table) = self.key_indicators(report) {
            blocks.push(Block::sub("Key indicators"));
            blocks.extend(table);
        }
    }

    /// The environment the run was recorded on, as an appendix.
    fn environment_section(&mut self, report: &Report) {
        let run = &report.run;
        if run.environment.is_empty() {
            return;
        }
        let mut facts = Vec::new();
        let mut lists: Vec<(String, Vec<String>)> = Vec::new();
        for fact in &run.environment {
            // A list of packs or tools reads better as a table, one per row.
            let items: Vec<String> = fact
                .value
                .split("; ")
                .map(str::to_owned)
                .filter(|item| !item.is_empty())
                .collect();
            if items.len() > 2 && matches!(fact.name.as_str(), "Rule packs" | "Tools") {
                lists.push((fact.name.clone(), items));
            } else {
                facts.push((fact.name.clone(), fact.value.clone()));
            }
        }
        if !run.route.is_empty() && !facts.iter().any(|(name, _)| name == "Network route") {
            facts.push(("Network route".into(), run.route.clone()));
        }
        let mut blocks = vec![Block::facts(facts)];
        for (name, items) in lists {
            blocks.push(Block::sub(name.clone()));
            blocks.push(Block::Table(DocTable::plain(
                vec![name.trim_end_matches('s').to_owned(), "Version".into()],
                items
                    .into_iter()
                    .map(|item| {
                        let (what, version) = item.rsplit_once(' ').unwrap_or((&item, ""));
                        vec![what.to_owned(), version.to_owned()]
                    })
                    .collect(),
            )));
        }
        self.section("environment", "Appendix: Environment", blocks);
    }

    /// The evidence files of the run folder: the recordings and the run's
    /// folders of results, not the small logs and records beside them.
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
                let mut blocks = vec![Block::Table(DocTable::plain(
                    ["Kind", "Path", "Size", "SHA-256"]
                        .map(String::from)
                        .to_vec(),
                    main.iter()
                        .map(|item| {
                            vec![
                                item.kind.clone(),
                                item.path.clone(),
                                crate::byte_size::file_size(item.size),
                                if !item.sha256.is_empty() {
                                    item.sha256.clone()
                                } else if item.path.ends_with('/') {
                                    format!(
                                        "folder{}",
                                        item.files.map_or(String::new(), |n| format!(
                                            ", {} file{}",
                                            thousands(n),
                                            if n == 1 { "" } else { "s" }
                                        ))
                                    )
                                } else {
                                    "not hashed (over 64 MiB)".into()
                                },
                            ]
                        })
                        .collect(),
                ))];
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
                    Block::facts(facts),
                    Block::Note(
                        "Tamper-evident, not tamper-proof. Keep the head hash somewhere else to \
                         rule out a rewritten chain."
                            .into(),
                    ),
                ],
            );
        }
    }
}

/// Whether the report has the section `id` (a link to it can be made).
fn report_has_section(report: &Report, id: &str) -> bool {
    match id {
        "findings" => report.findings.is_some(),
        "processes" => report.processes.is_some(),
        "indicators" => report.indicators.is_some(),
        "attack" => report.attack.is_some(),
        "files" => report.files.is_some() || report.file_activity.is_some(),
        "network" => report.network.is_some(),
        _ => false,
    }
}

/// The document for `report`. `defang` rewrites indicators for reading.
pub fn document(report: &Report, defang: bool) -> Document {
    // A report built by an older app or by hand may have no links yet.
    let mut linked;
    let report = if refs::report_ids(report).is_empty() {
        linked = report.clone();
        refs::link(&mut linked);
        &linked
    } else {
        report
    };
    let mut b = Builder {
        defang,
        sections: Vec::new(),
        credits: Vec::new(),
        reg: refs::registry(report),
        aliases: BTreeMap::new(),
        stand_ins: report
            .indicators
            .iter()
            .flatten()
            .filter(|i| i.kind == "endpoint" && !i.stand_in.is_empty())
            .map(|i| (i.value.clone(), i.stand_in.clone()))
            .collect(),
    };
    let findings = report.findings.as_ref().map(|table| b.fold_findings(table));
    b.overview_section(report);
    b.indicators_section(report);
    b.attack_section(report);
    if let Some(table) = &report.processes {
        let blocks = b.processes_blocks(table);
        b.section("processes", "Processes", blocks);
    }
    if let Some(blocks) = findings {
        b.section("findings", "Suspicious activity", blocks);
    }
    b.files_section(report);
    if let Some(tabs) = &report.network {
        let blocks = b.network_blocks(tabs);
        b.section("network", "Network", blocks);
    }
    b.detections_section(report);
    b.evidence_section(report);
    b.custody_section(report);
    if !b.credits.is_empty() {
        let blocks = b.credits.iter().cloned().map(Block::Note).collect();
        b.section("notes", "Notes", blocks);
    }
    b.environment_section(report);

    let name = report
        .sample
        .as_ref()
        .map(|sample| sample.name.as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(&report.run.run_id);
    let run8 = report.run.run_id.get(..8).unwrap_or(&report.run.run_id);
    let mut title = format!("Antinomie Triage report: {name}");
    if let Some(summary) = &report.summary {
        title.push_str(&format!(
            " - {} \u{b7} {} \u{b7} run {run8}",
            if summary.families.is_empty() {
                "no family named".to_owned()
            } else {
                summary.families.join(", ")
            },
            summary.highest_tier.to_uppercase()
        ));
    }
    let mut subtitle = vec![format!("Run {}", report.run.run_id)];
    if let Some(started) = report.run.started_ms {
        subtitle.push(format!("started {}", super::shown(started)));
    }
    subtitle.push(format!("generated {}", super::shown(report.generated_ms)));
    subtitle.push(report.app.clone());
    let mut document = Document {
        title,
        subtitle: subtitle.join(" - "),
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
                words.push(format!("run {run8}"));
                words.join(", ")
            },
            header: format!("Antinomie Triage report: {name} - run {run8}"),
            footer: format!("Generated {}", super::shown(report.generated_ms)),
        },
        aliases: b.aliases,
    };
    super::page::finish(&mut document);
    document
}

/// A rule's author, or `unknown` when the rule names none (a rule's licence
/// asks that the author stay with its matches).
pub(super) fn or_unknown(author: &str) -> String {
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
pub(crate) fn severity_text(engine: &str, severity: &str, strength: &str) -> String {
    let score: Option<u32> = severity.trim().parse().ok();
    if !strength.is_empty() {
        return match score {
            Some(score) => format!("{strength} (score {score})"),
            None => strength.to_owned(),
        };
    }
    match (engine, severity.is_empty()) {
        (_, true) => String::new(),
        (engine, false) if engine.eq_ignore_ascii_case("sigma") => format!("Sigma {severity}"),
        (engine, false) if engine.eq_ignore_ascii_case("ids") => format!("IDS {severity}"),
        _ => severity.to_owned(),
    }
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
pub(super) fn duration(ms: u64) -> String {
    let seconds = ms / 1000;
    match seconds {
        0 => format!("{ms} ms"),
        1..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {:02} min", seconds / 3600, seconds / 60 % 60),
    }
}

/// The footnote that says which zone every time is in, the date of the run,
/// and what `~` and `+N s` mean.
fn zone_note(at_ms: u64, started_ms: Option<u64>) -> String {
    let text = super::shown(at_ms);
    let zone = text.rfind('(').map_or("the display zone", |at| {
        text[at..].trim_matches(|c| c == '(' || c == ')')
    });
    let day = started_ms.map_or(String::new(), |ms| {
        format!(" The run started {}.", super::shown(ms))
    });
    format!(
        "All times are {zone}, the zone the app shows.{day} A table time reads +N s since the \
         run's first call, then the time of day; times of guest events are estimated from the \
         guest clock (~)."
    )
}

/// An ISO time of the JSON (`2026-11-07T10:40:42.662Z`) as ms since the epoch.
pub(crate) fn iso_ms(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[10] != b'T' || !text.ends_with('Z') {
        return None;
    }
    let number = |from: usize, to: usize| text.get(from..to)?.parse::<i64>().ok();
    let days = crate::date::days_from_civil(
        number(0, 4)? as i32,
        number(5, 7)? as u32,
        number(8, 10)? as u32,
    )?;
    let seconds = days * 86_400 + number(11, 13)? * 3600 + number(14, 16)? * 60 + number(17, 19)?;
    let millis = match bytes.get(19) {
        Some(b'.') => text.get(20..23)?.parse::<i64>().ok()?,
        _ => 0,
    };
    u64::try_from(seconds * 1000 + millis).ok()
}

/// A time of an indicator in a document table, as the other tables write
/// theirs: `+5.463 s · 17:38:21.480`. Text that is not an ISO time is kept.
pub(crate) fn indicator_stamp(text: &str, relative_ms: Option<u64>) -> String {
    match iso_ms(text) {
        Some(ms) => super::stamp(relative_ms, Some(ms)),
        None => shown_iso(text),
    }
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

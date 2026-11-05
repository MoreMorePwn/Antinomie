// SPDX-License-Identifier: GPL-3.0-only
//! The Details of a Suspicious activity row, top to bottom: the header, what
//! happened, why it matters, why this tier, the evidence, links to related
//! things, the rule's facts, dumps taken and the observed fields.
use super::rules::{self, Tier};
use super::*;
use crate::widgets::{chip, link};

/// The sections of the Details, in the order they are drawn.
pub(super) const SECTIONS: [&str; 7] = [
    "What happened",
    "Why it matters",
    "Why this tier",
    "Evidence",
    "Related",
    "Rule facts",
    "Dumps taken",
];

fn text<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> Option<&'a str> {
    values.iter().find_map(|(name, value)| match value {
        RowValue::Text(text) if *name == key => Some(text.as_str()),
        _ => None,
    })
}

fn list<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> &'a [String] {
    values
        .iter()
        .find_map(|(name, value)| match value {
            RowValue::List(lines) if *name == key => Some(lines.as_slice()),
            _ => None,
        })
        .unwrap_or_default()
}

/// One call kept as evidence of a row.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Sample {
    pub ns: u64,
    pub stream: u64,
    pub call: u64,
    pub syscall: String,
    pub what: String,
    pub result: String,
}

/// The calls a row kept (`finding.samples`), earliest first.
pub(super) fn samples(values: &[(&'static str, RowValue)]) -> Vec<Sample> {
    list(values, "finding.samples")
        .iter()
        .filter_map(|line| {
            let mut parts = line.split('\u{1f}');
            Some(Sample {
                ns: parts.next()?.parse().ok()?,
                stream: parts.next()?.parse().ok()?,
                call: parts.next()?.parse().ok()?,
                syscall: parts.next()?.to_owned(),
                what: parts.next()?.to_owned(),
                result: parts.next()?.to_owned(),
            })
        })
        .collect()
}

/// The one sentence of "What happened".
pub(super) fn what_happened(
    process: &str,
    values: &[(&'static str, RowValue)],
    when: &str,
) -> String {
    let title = text(values, "finding.title").unwrap_or_default();
    let what = text(values, "finding.what")
        .map(|what| what.trim().trim_end_matches('.'))
        .filter(|what| !what.is_empty())
        .unwrap_or(title);
    let count = files::number(values, "finding.count").unwrap_or(1);
    let times = if count == 1 {
        "once".to_owned()
    } else {
        format!("{count} times")
    };
    let mut parts = vec![times];
    if when != "\u{2014}" {
        parts.push(when.to_owned());
    }
    if let Some(result) = text(values, "finding.result").filter(|result| *result != "\u{2014}") {
        parts.push(result.to_owned());
    }
    let mut sentence = format!("{process}: {what}. Seen {}.", parts.join(", "));
    let siblings = files::number(values, "finding.siblings").unwrap_or(0);
    if siblings > 1 {
        sentence.push_str(&format!(" The same happened in {siblings} processes."));
    }
    sentence
}

/// The target of a row as an address, when it is one: `"1.2.3.4:443"`, `"udp 0.0.0.0:53"`.
pub(super) fn endpoint(object: &str) -> Option<std::net::IpAddr> {
    let last = object.rsplit(' ').next().unwrap_or(object);
    let (ip, port) = last.rsplit_once(':')?;
    port.parse::<u16>().ok()?;
    ip.trim_matches(|c| c == '[' || c == ']').parse().ok()
}

fn heading(ui: &mut egui::Ui, title: &str) {
    ui.add_space(8.0);
    ui.label(theme::bold(ui, title).color(theme::text()));
}

fn paragraph(ui: &mut egui::Ui, body: &str) {
    ui.add(egui::Label::new(body).wrap());
}

impl TriageView {
    /// The Details of the finding whose values are `values`; `process` is the
    /// text of its Process cell.
    pub(super) fn finding_details(
        &mut self,
        ui: &mut egui::Ui,
        values: &[(&'static str, RowValue)],
        process: &str,
    ) {
        let tier = text(values, "finding.tier")
            .and_then(Tier::from_tag)
            .unwrap_or(Tier::Info);
        let base = text(values, "finding.base_tier")
            .and_then(Tier::from_tag)
            .unwrap_or(tier);
        let rule = text(values, "finding.rule").unwrap_or_default();
        let title = text(values, "finding.title").unwrap_or(rule);
        let version = files::number(values, "finding.version").unwrap_or(0);
        let start = self.run_start();
        let when = rules::when_text(
            files::number(values, "finding.first_ns").unwrap_or(0),
            files::number(values, "finding.last_ns").unwrap_or(0),
            start,
        );

        // The header.
        ui.horizontal_wrapped(|ui| {
            chip(ui, tier.label(), tier.tone()).on_hover_text(tier.meaning());
            let size = egui::TextStyle::Heading.resolve(ui.style()).size;
            ui.label(theme::bold(ui, title).size(size).color(theme::heading()));
        });
        ui.label(
            RichText::new(format!("{rule} \u{b7} version {version}"))
                .monospace()
                .small()
                .color(theme::muted()),
        );
        self.finding_facts(ui, values);

        heading(ui, SECTIONS[0]);
        paragraph(ui, &what_happened(process, values, &when));

        heading(ui, SECTIONS[1]);
        let description = rules::rule_description(rule);
        if !description.is_empty() {
            paragraph(ui, description);
        }
        self.technique_links(ui, values);

        heading(ui, SECTIONS[2]);
        why_tier(ui, values, base, tier);

        heading(ui, SECTIONS[3]);
        self.evidence(ui, values, start);

        self.related(ui, values, process);

        let facts: Vec<String> = list(values, "finding.detail")
            .iter()
            .filter(|line| !line.starts_with("Occurrences: calls"))
            .cloned()
            .collect();
        if !facts.is_empty() {
            heading(
                ui,
                if rule.starts_with("evasion.") {
                    "Checks and what the guest answered"
                } else {
                    SECTIONS[5]
                },
            );
            for line in facts {
                ui.add(egui::Label::new(RichText::new(line).monospace()).wrap());
            }
        }
        details::dump_taken(ui, values);
    }

    /// Category, confidence, source, flags: what the table no longer shows.
    fn finding_facts(&self, ui: &mut egui::Ui, values: &[(&'static str, RowValue)]) {
        let mut parts = Vec::new();
        if let Some(category) = text(values, "finding.category") {
            let label = rules::Category::ALL
                .iter()
                .find(|candidate| candidate.tag() == category)
                .map_or(category, |candidate| candidate.label());
            parts.push(format!("Category: {label}"));
        }
        if let Some(confidence) = text(values, "finding.confidence") {
            parts.push(format!("Confidence: {confidence}"));
        }
        let flags = list(values, "finding.flags");
        if !flags.is_empty() {
            parts.push(format!("Flags: {}", flags.join(", ")));
        }
        if let Some(source) = text(values, "finding.source") {
            parts.push(source.to_owned());
        }
        if !parts.is_empty() {
            ui.add(
                egui::Label::new(
                    RichText::new(parts.join(" \u{b7} "))
                        .small()
                        .color(theme::muted()),
                )
                .wrap(),
            );
        }
    }

    /// The techniques a rule cites, by name, with the ways to their rows.
    fn technique_links(&mut self, ui: &mut egui::Ui, values: &[(&'static str, RowValue)]) {
        for id in list(values, "finding.technique")
            .iter()
            .filter(|id| id.starts_with('T') && !id.starts_with("TA"))
        {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("ATT&CK").small().color(theme::muted()));
                ui.label(antinomie_monitor_core::mitre::technique_label(id));
                if link(ui, "Rows of this technique")
                    .on_hover_text("Suspicious activity, filtered to this technique")
                    .clicked()
                {
                    self.filter_findings_by(ui.ctx(), format!("finding.technique == \"{id}\""));
                }
                if link(ui, "Show in Summary")
                    .on_hover_text("The run's ATT&CK list in the Summary")
                    .clicked()
                {
                    self.section = Section::Summary;
                }
            });
        }
    }

    fn evidence(
        &mut self,
        ui: &mut egui::Ui,
        values: &[(&'static str, RowValue)],
        start: Option<u64>,
    ) {
        let kept = samples(values);
        let cookie = files::number(values, "process.cookie").unwrap_or(0);
        let packet = files::number(values, "frame.number");
        if let Some(frame) = packet {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("Packet #{frame}"));
                if link(ui, "Open original packet").clicked() {
                    request_evidence_jump(ui.ctx(), values);
                }
            });
        } else if kept.is_empty() {
            let own = files::number(values, "event.id").is_some()
                && files::number(values, "stream.id").is_some()
                && files::number(values, "process.cookie").is_some();
            if own && link(ui, "Open original syscall").clicked() {
                request_evidence_jump(ui.ctx(), values);
            }
        } else {
            let count = files::number(values, "finding.count").unwrap_or(1);
            // One block per call: when, syscall, result and the way into the
            // trace on a line, what it did under it. It fits a narrow pane.
            for sample in &kept {
                let at = start.map_or_else(
                    || "\u{2014}".to_owned(),
                    |start| rules::offset(sample.ns, start),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(at).monospace().color(theme::muted()));
                    ui.label(RichText::new(&sample.syscall).monospace().strong());
                    let failed = sample.result.starts_with("failed");
                    ui.label(RichText::new(&sample.result).color(if failed {
                        theme::muted()
                    } else {
                        theme::text()
                    }));
                    if link(ui, "Open in Syscall Trace").clicked() {
                        let call = [
                            ("stream.id", RowValue::Number(i128::from(sample.stream))),
                            ("process.cookie", RowValue::Number(i128::from(cookie))),
                            ("event.id", RowValue::Number(i128::from(sample.call))),
                        ];
                        request_evidence_jump(ui.ctx(), &call);
                    }
                });
                ui.add(egui::Label::new(RichText::new(&sample.what).monospace().small()).wrap());
                ui.add_space(4.0);
            }
            if count > kept.len() as u64 {
                ui.weak(format!(
                    "{} of {count} calls are kept as evidence; the rest are in the recording.",
                    kept.len()
                ));
            }
        }
        details::evidence_link(ui, values);
    }

    /// Links to the process, the target and other findings that share them.
    fn related(&mut self, ui: &mut egui::Ui, values: &[(&'static str, RowValue)], process: &str) {
        heading(ui, SECTIONS[4]);
        let pid = files::number(values, "process.pid").unwrap_or(0);
        let cookie = files::number(values, "process.cookie").unwrap_or(0);
        let object = text(values, "finding.object")
            .unwrap_or_default()
            .to_owned();
        let technique = list(values, "finding.technique")
            .iter()
            .find(|id| id.starts_with('T') && !id.starts_with("TA"))
            .cloned();
        if pid != 0 && cookie != 0 {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Process").small().color(theme::muted()));
                if link(ui, format!("{process}: open its details")).clicked() {
                    process_details::open_process(self, ui.ctx(), pid as u32, cookie);
                }
            });
        }
        if object.starts_with('/') {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Target").small().color(theme::muted()));
                if link(ui, format!("{object}: open its history in Files"))
                    .on_hover_text("Per-file history of this file")
                    .clicked()
                {
                    self.section = Section::Files;
                    self.file_history.open_on(&object);
                    self.history_tab = true;
                }
            });
        } else if let Some(ip) = endpoint(&object) {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Target").small().color(theme::muted()));
                if link(ui, format!("{ip}: open it in Network"))
                    .on_hover_text("The endpoints the run reached")
                    .clicked()
                {
                    self.section = Section::Network;
                    self.new_tab = NewTab::Endpoints;
                }
            });
        }
        let me = (
            files::number(values, "stream.id").unwrap_or(0),
            cookie,
            files::number(values, "event.id").unwrap_or(0),
        );
        let (mut same_process, mut same_target, mut same_technique) = (0, 0, 0);
        for other in self.scan.iter().flat_map(|scan| scan.findings.iter()) {
            if other.key == me {
                continue;
            }
            let theirs = |key: &str| files::number(&other.values, key).unwrap_or(0);
            same_process += usize::from(
                pid != 0 && theirs("process.pid") == pid && theirs("process.cookie") == cookie,
            );
            same_target += usize::from(
                !object.is_empty()
                    && text(&other.values, "finding.object") == Some(object.as_str()),
            );
            same_technique += usize::from(technique.as_deref().is_some_and(|id| {
                list(&other.values, "finding.technique")
                    .iter()
                    .any(|other| other == id)
            }));
        }
        let others = |ui: &mut egui::Ui, count: usize, what: String| -> bool {
            count > 0
                && link(
                    ui,
                    format!(
                        "{count} other finding{} {what}",
                        if count == 1 { "" } else { "s" }
                    ),
                )
                .clicked()
        };
        if others(ui, same_process, "in this process".into()) {
            self.filter_findings_by(ui.ctx(), format!("process.pid == {pid}"));
        }
        if !object.contains('"') && others(ui, same_target, "on this target".into()) {
            self.filter_findings_by(ui.ctx(), format!("finding.object == \"{object}\""));
        }
        if let Some(id) = technique {
            if others(ui, same_technique, format!("citing {id}")) {
                self.filter_findings_by(ui.ctx(), format!("finding.technique == \"{id}\""));
            }
        }
    }
}

/// "Why this tier": the rule's tier, each step that moved it, and the tier's meaning.
fn why_tier(ui: &mut egui::Ui, values: &[(&'static str, RowValue)], base: Tier, tier: Tier) {
    paragraph(
        ui,
        &format!("Rule tier {}: {}", base.label(), base.meaning()),
    );
    for line in list(values, "finding.why")
        .iter()
        .filter(|line| !line.starts_with("Rule tier "))
    {
        ui.add(egui::Label::new(format!("\u{2022} {line}")).wrap());
    }
    if tier != base {
        paragraph(
            ui,
            &format!("Shown as {}: {}", tier.label(), tier.meaning()),
        );
    }
    ui.add(
        egui::Label::new(
            RichText::new(rules::CONTEXT_NOTE)
                .small()
                .color(theme::muted()),
        )
        .wrap(),
    );
}

impl TriageView {
    /// Show Suspicious activity filtered by `text`; the tier and category
    /// chips and an older filter are dropped first.
    pub(super) fn filter_findings_by(&mut self, ctx: &egui::Context, text: String) {
        self.section = Section::Process;
        self.process = ProcessTab::Suspicious;
        self.clear_finding_filters(ctx);
        self.filter_drafts[0].clone_from(&text);
        ctx.data_mut(|data| data.insert_temp(egui::Id::new(("triage-filter-draft", 0usize)), text));
        ctx.request_repaint();
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The expanded MITRE ATT&CK list of the Run overview: the run's techniques
//! grouped by tactic in kill-chain order, each row opening to what produced it
//! (Triage rules with their tier and count, YARA, IDS and Sigma rules) and
//! the ways into Suspicious activity, Detection and Syscall Trace.
use super::*;
use crate::widgets::{attack as pills, Tone};
use antinomie_monitor_core::{mitre::Tactic, report::Technique};

/// The chip of a Triage tier.
fn tier_chip(ui: &mut egui::Ui, tier: &str) {
    let (label, tone) = match tier {
        "high" => ("High", Tone::Error),
        "medium" => ("Medium", Tone::Warn),
        "low" => ("Low", Tone::Info),
        _ => ("Info", Tone::Neutral),
    };
    crate::widgets::chip(ui, label, tone);
}

/// "2 rules · 1 detection", the closed row's summary.
fn summary(detail: &attack::Detail) -> String {
    let count =
        |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
    let mut parts = Vec::new();
    if !detail.rules.is_empty() {
        parts.push(count(detail.rules.len(), "rule", "rules"));
    }
    if !detail.detections.is_empty() {
        parts.push(count(detail.detections.len(), "detection", "detections"));
    }
    parts.join(" · ")
}

/// The list as a Mermaid flowchart: each tactic pointing at the techniques
/// filed under it, in kill-chain order.
pub(super) fn mermaid(techniques: &[Technique], details: &[attack::Detail]) -> String {
    let mut chart = crate::mermaid::Flowchart::new("LR");
    for tactic in Tactic::ALL.into_iter().map(Some).chain([None]) {
        let rows: Vec<usize> = (0..techniques.len())
            .filter(|index| details.get(*index).is_some_and(|d| d.primary == tactic))
            .collect();
        if rows.is_empty() {
            continue;
        }
        let (key, name) = match tactic {
            Some(tactic) => (format!("tactic:{}", tactic.name()), tactic.name()),
            None => ("tactic:".to_owned(), "Not in the ATT&CK table"),
        };
        chart.node(&key, name);
        for index in rows {
            let technique = &techniques[index];
            let id = format!("technique:{}", technique.id);
            chart.node(&id, &format!("{}\n{}", technique.id, technique.name));
            chart.edge(&key, &id, None);
        }
    }
    chart.render()
}

/// Draw the grouped list; the click that leaves the Summary is returned.
pub(super) fn show(
    ui: &mut egui::Ui,
    view: &TriageView,
    techniques: &[Technique],
    details: &[attack::Detail],
) -> Option<attack::Jump> {
    let mut jump = None;
    ui.horizontal(|ui| {
        crate::mermaid::button(ui, || mermaid(techniques, details));
    });
    let groups = Tactic::ALL
        .into_iter()
        .map(Some)
        .chain(std::iter::once(None));
    for tactic in groups {
        let rows: Vec<usize> = (0..techniques.len())
            .filter(|index| details.get(*index).is_some_and(|d| d.primary == tactic))
            .collect();
        if rows.is_empty() {
            continue;
        }
        pills::tactic_heading(ui, tactic, rows.len());
        ui.indent(("attack-group", tactic.map(|t| t as usize)), |ui| {
            for index in rows {
                let (technique, detail) = (&techniques[index], &details[index]);
                pills::technique_row(
                    ui,
                    "triage-summary",
                    &technique.id,
                    detail.primary,
                    &summary(detail),
                    |ui| {
                        if let Some(next) = body(ui, view, technique, detail) {
                            jump = Some(next);
                        }
                    },
                );
            }
        });
        ui.add_space(4.0);
    }
    jump
}

/// What an open technique row says.
fn body(
    ui: &mut egui::Ui,
    view: &TriageView,
    technique: &Technique,
    detail: &attack::Detail,
) -> Option<attack::Jump> {
    let mut jump = None;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Technique").small().color(theme::muted()));
        ui.label(RichText::new(&technique.id).monospace().strong());
        ui.label(&technique.name);
    });
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Tactic").small().color(theme::muted()));
        if detail.tactics.is_empty() {
            ui.label(RichText::new("not in the bundled ATT&CK table").color(theme::muted()));
        }
        for tactic in &detail.tactics {
            pills::tactic_chip(ui, *tactic);
        }
    });
    if !detail.rules.is_empty() {
        ui.label(RichText::new("Triage rules").small().color(theme::muted()));
        for cause in &detail.rules {
            ui.horizontal_wrapped(|ui| {
                tier_chip(ui, &cause.tier);
                ui.label(RichText::new(&cause.rule).monospace());
                ui.label(RichText::new(format!("×{}", cause.count)).color(theme::muted()));
            });
        }
    }
    if !detail.detections.is_empty() {
        ui.label(RichText::new("Detections").small().color(theme::muted()));
        for cause in &detail.detections {
            ui.horizontal_wrapped(|ui| {
                crate::widgets::chip(ui, cause.engine.as_str(), Tone::Info);
                ui.label(&cause.title);
                if !cause.severity.is_empty() {
                    ui.label(RichText::new(&cause.severity).small().color(theme::muted()));
                }
                ui.label(RichText::new(format!("×{}", cause.count)).color(theme::muted()));
            });
        }
    }
    ui.horizontal_wrapped(|ui| {
        if !detail.rules.is_empty()
            && crate::widgets::link(ui, "Open in Suspicious activity")
                .on_hover_text(format!("Suspicious activity, filtered to {}", technique.id))
                .clicked()
        {
            jump = Some(attack::Jump::Suspicious(technique.id.clone()));
        }
        let mut engines: Vec<&str> = detail
            .detections
            .iter()
            .map(|d| d.engine.as_str())
            .collect();
        engines.sort_unstable();
        engines.dedup();
        for engine in engines {
            if crate::widgets::link(ui, format!("Open in Detection · {engine}"))
                .on_hover_text(format!("{engine} matches that cite {}", technique.id))
                .clicked()
            {
                jump = Some(attack::Jump::Detection(
                    engine.to_owned(),
                    technique.id.clone(),
                ));
            }
        }
        if view.technique_finding(&technique.id).is_some()
            && crate::widgets::link(ui, "Show the calls in Syscall Trace")
                .on_hover_text("The first call behind this technique's activity")
                .clicked()
        {
            jump = Some(attack::Jump::Calls(technique.id.clone()));
        }
    });
    jump
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tactics_point_at_their_techniques() {
        let technique = |id: &str, name: &str| Technique {
            id: id.into(),
            name: name.into(),
            rules: Vec::new(),
            count: 1,
        };
        let detail = |id: &str, primary| attack::Detail {
            id: id.into(),
            primary,
            tactics: primary.into_iter().collect(),
            rules: Vec::new(),
            detections: Vec::new(),
        };
        let text = mermaid(
            &[
                technique("T1059", "Command and Scripting \"Interpreter\""),
                technique("T1053", "Scheduled Task/Job"),
                technique("T9999", "Unknown"),
            ],
            &[
                detail("T1059", Some(Tactic::Execution)),
                detail("T1053", Some(Tactic::Persistence)),
                detail("T9999", None),
            ],
        );
        assert!(text.starts_with("flowchart LR\n"), "{text}");
        assert_eq!(text.matches(" --> ").count(), 3, "{text}");
        assert!(
            text.contains("T1059<br/>Command and Scripting #quot;Interpreter#quot;"),
            "{text}"
        );
        assert!(text.contains("Not in the ATT#amp;CK table"), "{text}");
        assert_eq!(
            text,
            mermaid(
                &[
                    technique("T1059", "Command and Scripting \"Interpreter\""),
                    technique("T1053", "Scheduled Task/Job"),
                    technique("T9999", "Unknown"),
                ],
                &[
                    detail("T1059", Some(Tactic::Execution)),
                    detail("T1053", Some(Tactic::Persistence)),
                    detail("T9999", None),
                ]
            )
        );
    }
}

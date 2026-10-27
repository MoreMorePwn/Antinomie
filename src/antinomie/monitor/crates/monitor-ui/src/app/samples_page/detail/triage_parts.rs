// SPDX-License-Identifier: GPL-3.0-only
//! The Summary sections that add up Triage over the sample's runs: highest
//! suspicion, rules matched, ATT&CK techniques, evasion attempts and
//! indicators. They read the runs' digests; a run Triage never opened has
//! none and the sections say so instead of guessing.
use super::{parts, *};
use crate::widgets::{table, Tone};
use antinomie_monitor_core::samples::Rollup;

/// "3 of 4 runs"; the run numbers are the tooltip.
fn of_runs(count: usize, total: usize) -> String {
    format!(
        "{count} of {total} run{}",
        if total == 1 { "" } else { "s" }
    )
}

fn run_list(runs: &[usize]) -> String {
    runs.iter()
        .map(|number| parts::run_name(*number))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The chip of a Triage tier: High red, Medium amber.
pub(super) fn tier_chip(ui: &mut egui::Ui, tier: &str) -> egui::Response {
    let (label, tone) = match tier {
        "high" => ("High", Tone::Error),
        "medium" => ("Medium", Tone::Warn),
        "low" => ("Low", Tone::Info),
        _ => ("Info", Tone::Neutral),
    };
    widgets::chip(ui, label, tone)
}

/// The Highest suspicion field: the chip and in how many runs it was reached.
pub(super) fn highest(ui: &mut egui::Ui, data: &Data) {
    let rollup = &data.rollup;
    match &rollup.highest {
        Some((tier, runs)) => {
            tier_chip(ui, tier);
            ui.label(
                RichText::new(format!("In {}", of_runs(runs.len(), rollup.runs)))
                    .small()
                    .color(theme::muted()),
            )
            .on_hover_text(run_list(runs));
        }
        None if data.runs.is_empty() => {
            ui.label(theme::hint_text("Not run"));
        }
        None if rollup.triaged > 0 => {
            ui.label(theme::hint_text("No findings"));
        }
        None => {
            ui.label(theme::hint_text("Not triaged yet"));
        }
    }
}

/// What a run's Triage digest says about it, one word for the Runs table.
pub(super) fn run_suspicion(ui: &mut egui::Ui, entry: &RunEntry) {
    match entry
        .digest
        .as_ref()
        .and_then(|digest| digest.behaviour.as_ref())
    {
        Some(behaviour) if !behaviour.highest.is_empty() => {
            tier_chip(ui, &behaviour.highest);
        }
        Some(_) => {
            ui.label(theme::hint_text("none"));
        }
        None => {
            ui.label(theme::hint_text("not triaged"))
                .on_hover_text("Open the run in Triage to score it");
        }
    }
}

fn not_triaged(ui: &mut egui::Ui, rollup: &Rollup) -> bool {
    if rollup.triaged == 0 {
        parts::muted_line(ui, "Not triaged yet.");
        true
    } else {
        false
    }
}

/// Rules matched: the YARA, IDS and Sigma rules that hit in any run. The rule
/// name opens the latest run it hit in.
pub(super) fn rules_matched(ui: &mut egui::Ui, data: &Data, font: f32) -> Option<usize> {
    let rollup = &data.rollup;
    let mut open = None;
    parts::section(ui, "Rules matched", Some(rollup.rules.len()), |ui| {
        if rollup.detected == 0 {
            parts::muted_line(
                ui,
                if rollup.triaged == 0 {
                    "Not triaged yet."
                } else {
                    "No detection scan has been read for these runs."
                },
            );
            return;
        }
        if rollup.rules.is_empty() {
            parts::muted_line(ui, "No rule matched.");
            return;
        }
        parts::mini_table(ui, "sample_summary_rules")
            .column(egui_extras::Column::remainder().at_least(200.0).clip(true))
            .column(egui_extras::Column::exact(80.0))
            .column(egui_extras::Column::exact(120.0))
            .column(egui_extras::Column::exact(120.0))
            .header(table::header_height(font), |mut header| {
                for title in ["Rule", "Kind", "Runs", "Latest hit"] {
                    header.col(|ui| table::head(ui, title));
                }
            })
            .body(|body| {
                body.rows(
                    table::row_height(font) + 4.0,
                    rollup.rules.len(),
                    |mut row| {
                        let rule = &rollup.rules[row.index()];
                        row.col(|ui| {
                            if widgets::link(ui, &rule.rule)
                                .on_hover_text(format!(
                                    "Open {} in Triage",
                                    parts::run_name(rule.latest)
                                ))
                                .clicked()
                            {
                                open = Some(rule.latest);
                            }
                        });
                        row.col(|ui| {
                            widgets::chip(ui, &rule.engine, Tone::Neutral);
                        });
                        row.col(|ui| {
                            ui.label(of_runs(rule.runs.len(), rollup.runs))
                                .on_hover_text(run_list(&rule.runs));
                        });
                        row.col(|ui| {
                            ui.label(parts::run_name(rule.latest));
                        });
                    },
                );
            });
    });
    open
}

/// ATT&CK techniques: one line per tactic, a chip per technique with the
/// runs it was mapped in.
pub(super) fn techniques(ui: &mut egui::Ui, data: &Data) {
    let rollup = &data.rollup;
    parts::section(ui, "ATT&CK techniques", None, |ui| {
        if not_triaged(ui, rollup) {
            return;
        }
        if rollup.tactics.is_empty() {
            parts::muted_line(ui, "No technique mapped.");
            return;
        }
        for tactic in &rollup.tactics {
            ui.horizontal_wrapped(|ui| {
                ui.add_sized(
                    [150.0, 18.0],
                    egui::Label::new(RichText::new(&tactic.tactic).color(theme::muted())),
                );
                for technique in &tactic.techniques {
                    widgets::chip(
                        ui,
                        format!(
                            "{} {}/{}",
                            antinomie_monitor_core::mitre::technique_label(&technique.id),
                            technique.runs.len(),
                            rollup.triaged
                        ),
                        Tone::Neutral,
                    )
                    .on_hover_text(run_list(&technique.runs));
                }
            });
        }
    });
}

/// Evasion attempts: category > check > one line per run, folded to the
/// categories. Whether a check changed what the sample did is not known to
/// Triage, so a line says what the sample saw and nothing more.
pub(super) fn evasion(ui: &mut egui::Ui, data: &Data) {
    let rollup = &data.rollup;
    let total: usize = rollup.evasion.iter().map(|row| row.checks.len()).sum();
    parts::section(ui, "Evasion attempts", Some(total), |ui| {
        if not_triaged(ui, rollup) {
            return;
        }
        if total == 0 {
            parts::muted_line(ui, "No checks seen.");
            return;
        }
        for category in &rollup.evasion {
            if category.checks.is_empty() {
                ui.horizontal(|ui| {
                    ui.add_space(18.0);
                    ui.label(RichText::new(&category.category).color(theme::muted()));
                    ui.label(theme::hint_text("none seen"));
                });
                continue;
            }
            egui::CollapsingHeader::new(format!(
                "{} · {}",
                category.category,
                if category.checks.len() == 1 {
                    "1 check".to_owned()
                } else {
                    format!("{} checks", category.checks.len())
                }
            ))
            .id_salt(("sample_evasion", &category.category))
            .default_open(false)
            .show(ui, |ui| {
                for check in &category.checks {
                    egui::CollapsingHeader::new(format!(
                        "{}  ·  {}",
                        if check.object.is_empty() {
                            &check.rule
                        } else {
                            &check.object
                        },
                        of_runs(check.runs.len(), rollup.triaged)
                    ))
                    .id_salt((
                        "sample_evasion_check",
                        &category.category,
                        &check.rule,
                        &check.object,
                    ))
                    .default_open(false)
                    .show(ui, |ui| {
                        for (number, line) in &check.lines {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    RichText::new(parts::run_name(*number)).color(theme::muted()),
                                );
                                ui.label(line);
                            });
                        }
                    })
                    .header_response
                    .on_hover_text(&check.rule);
                }
            });
        }
    });
}

/// Indicators: how many, of what kind, how many every run had and how many a
/// stored abuse.ch dataset matched.
pub(super) fn indicators(ui: &mut egui::Ui, data: &Data) {
    let rollup = &data.rollup;
    parts::section(
        ui,
        "Indicators",
        rollup.indicators.as_ref().map(|row| row.total),
        |ui| {
            let Some(row) = &rollup.indicators else {
                parts::muted_line(ui, "Not triaged yet.");
                return;
            };
            if row.total == 0 {
                parts::muted_line(ui, "None seen.");
                return;
            }
            ui.horizontal_wrapped(|ui| {
                for (label, count) in &row.per_type {
                    widgets::chip(ui, format!("{label} {count}"), Tone::Neutral);
                }
                ui.label(
                    RichText::new(format!(
                        "{} in every run · {} matched abuse.ch",
                        row.in_every_run, row.matched
                    ))
                    .color(theme::muted()),
                );
            });
        },
    );
}

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
/// name opens the latest run it hit in, in Triage's Detection on that rule.
pub(super) fn rules_matched(
    ui: &mut egui::Ui,
    data: &Data,
    font: f32,
) -> Option<(usize, String, String)> {
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
        // The run and when it started: the Latest hit column fits it whole.
        let latest = |rule: &antinomie_monitor_core::samples::RuleRow| match data
            .runs
            .iter()
            .find(|entry| entry.number == rule.latest)
            .map(|entry| parts::minute(entry.run.started_ms))
        {
            Some(started) => format!("{} · {started}", parts::run_name(rule.latest)),
            None => parts::run_name(rule.latest),
        };
        let body_font = egui::TextStyle::Body.resolve(ui.style());
        let kind_width = parts::fitted_up_to(
            ui,
            &body_font,
            std::iter::once("Kind".to_owned()).chain(
                rollup
                    .rules
                    .iter()
                    .map(|rule| format!("{}   ", rule.engine)),
            ),
            140.0,
        );
        let runs_width = parts::fitted_up_to(
            ui,
            &body_font,
            std::iter::once("Runs".to_owned()).chain(
                rollup
                    .rules
                    .iter()
                    .map(|rule| of_runs(rule.runs.len(), rollup.runs)),
            ),
            180.0,
        );
        let latest_width = parts::fitted_up_to(
            ui,
            &body_font,
            std::iter::once("Latest hit".to_owned()).chain(rollup.rules.iter().map(latest)),
            360.0,
        );
        parts::on_surface(ui, |ui| {
            parts::mini_table(ui, "sample_summary_rules")
                .column(egui_extras::Column::remainder().at_least(120.0).clip(true))
                .column(egui_extras::Column::exact(kind_width))
                .column(egui_extras::Column::exact(runs_width))
                .column(egui_extras::Column::exact(latest_width).clip(true))
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
                                        "Open {} in Triage on this rule",
                                        parts::run_name(rule.latest)
                                    ))
                                    .clicked()
                                {
                                    open = Some((
                                        rule.latest,
                                        rule.engine.clone(),
                                        rule.rule_id.clone(),
                                    ));
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
                                ui.add(egui::Label::new(latest(rule)).truncate());
                            });
                        },
                    );
                });
        });
    });
    open
}

/// ATT&CK techniques: one line per tactic, a technique tag per technique
/// (the tag look of the sample's own tags) with the runs it was mapped in.
pub(super) fn techniques(ui: &mut egui::Ui, data: &Data) {
    use antinomie_monitor_core::samples::{Tag, TagKind};
    let rollup = &data.rollup;
    parts::section(ui, "ATT&CK techniques", None, |ui| {
        if not_triaged(ui, rollup) {
            return;
        }
        if rollup.tactics.is_empty() {
            parts::muted_line(ui, "No technique mapped.");
            return;
        }
        let body = egui::TextStyle::Body.resolve(ui.style());
        let column = parts::fitted_up_to(
            ui,
            &body,
            rollup.tactics.iter().map(|tactic| tactic.tactic.clone()),
            220.0,
        );
        for tactic in &rollup.tactics {
            ui.horizontal_top(|ui| {
                // The tactic, left-aligned in a column of its own.
                ui.allocate_ui_with_layout(
                    egui::vec2(column, ui.spacing().interact_size.y),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(&tactic.tactic).color(theme::text()))
                                .truncate(),
                        );
                    },
                );
                ui.vertical(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(10.0, 6.0);
                        for technique in &tactic.techniques {
                            let label =
                                antinomie_monitor_core::mitre::technique_label(&technique.id);
                            // The tag and its run count stay together.
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 5.0;
                                crate::sample_tags::tag(ui, &Tag::new(TagKind::Technique, label));
                                ui.label(
                                    RichText::new(format!(
                                        "{}/{}",
                                        technique.runs.len(),
                                        rollup.triaged
                                    ))
                                    .color(theme::text()),
                                )
                                .on_hover_text(run_list(&technique.runs));
                            });
                        }
                    });
                });
            });
        }
    });
}

/// "Run 3" or "Runs 2, 3": where a check tripped.
fn tripped_in(runs: &[usize]) -> String {
    format!(
        "tripped in {}",
        if runs.len() == 1 {
            parts::run_name(runs[0])
        } else {
            format!(
                "Runs {}",
                runs.iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    )
}

/// A disclosure whose header holds chips as well as text; its open state
/// survives re-rendering (it is kept under `id`).
fn disclosure(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    header: impl FnOnce(&mut egui::Ui),
    body: impl FnOnce(&mut egui::Ui),
) -> egui::Response {
    let id = ui.make_persistent_id(id);
    let state =
        egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), id, false);
    let (toggle, ..) = state
        .show_header(ui, |ui| {
            ui.horizontal_wrapped(header);
        })
        .body(body);
    toggle
}

/// Evasion attempts: category > check > one line per run, folded to the
/// categories. A check is *tripped* in a run when the sample quit right after
/// it (the one answer Triage has); every other check says what the sample saw
/// and is never marked.
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
            // The runs this category was seen in, and those it tripped in.
            let mut seen: Vec<usize> = category
                .checks
                .iter()
                .flat_map(|check| check.runs.iter().copied())
                .collect();
            seen.sort_unstable();
            seen.dedup();
            let mut tripped: Vec<usize> = category
                .checks
                .iter()
                .flat_map(|check| check.tripped.iter().copied())
                .collect();
            tripped.sort_unstable();
            tripped.dedup();
            let header = disclosure(
                ui,
                ("sample_evasion", &category.category),
                |ui| {
                    ui.label(RichText::new(&category.category).color(theme::text()));
                    ui.label(
                        RichText::new(if category.checks.len() == 1 {
                            "1 check".to_owned()
                        } else {
                            format!("{} checks", category.checks.len())
                        })
                        .color(theme::muted()),
                    );
                    ui.label(
                        RichText::new(format!("seen in {}", of_runs(seen.len(), rollup.triaged)))
                            .color(theme::muted()),
                    );
                    if tripped.is_empty() {
                        ui.label(theme::hint_text("never tripped"));
                    } else {
                        widgets::chip(ui, tripped_in(&tripped), Tone::Error);
                    }
                },
                |ui| {
                    for check in &category.checks {
                        check_rows(ui, &category.category, check, rollup.triaged);
                    }
                },
            );
            header.on_hover_text(run_list(&seen));
        }
    });
}

/// One check of a category: its header and one line per run.
fn check_rows(
    ui: &mut egui::Ui,
    category: &str,
    check: &antinomie_monitor_core::samples::CheckRow,
    triaged: usize,
) {
    let name = if check.object.is_empty() {
        &check.rule
    } else {
        &check.object
    };
    disclosure(
        ui,
        ("sample_evasion_check", category, &check.rule, &check.object),
        |ui| {
            ui.label(RichText::new(name).color(theme::text()));
            ui.label(RichText::new(of_runs(check.runs.len(), triaged)).color(theme::muted()));
            if !check.tripped.is_empty() {
                widgets::chip(ui, tripped_in(&check.tripped), Tone::Error);
            }
        },
        |ui| {
            for (number, line) in &check.lines {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(parts::run_name(*number)).color(theme::text()));
                    ui.label(line);
                    if check.tripped.contains(number) {
                        widgets::chip(ui, "tripped", Tone::Error)
                            .on_hover_text("The sample quit right after this check");
                    } else {
                        ui.label(theme::hint_text("no change seen"));
                    }
                });
            }
        },
    )
    .on_hover_text(&check.rule);
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

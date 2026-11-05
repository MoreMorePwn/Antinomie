// SPDX-License-Identifier: GPL-3.0-only
//! The Summary sections that add up Triage over the sample's runs: highest
//! suspicion, rules matched, ATT&CK techniques, evasion attempts and
//! indicators. They read the runs' digests; a run Triage never opened has
//! none and the sections say so instead of guessing.
use super::{parts, *};
use crate::widgets::{fit_table, Tone};
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
                .column(
                    crate::widgets::fit_table::Col::rest(80.0)
                        .at_least(120.0)
                        .clip(true),
                )
                .column(crate::widgets::fit_table::Col::fixed(kind_width))
                .column(crate::widgets::fit_table::Col::fixed(runs_width))
                .column(crate::widgets::fit_table::Col::fixed(latest_width).clip(true))
                .header(fit_table::header_height(font), |mut header| {
                    for title in ["Rule", "Kind", "Runs", "Latest hit"] {
                        header.col(|ui| fit_table::head(ui, title));
                    }
                })
                .body(|body| {
                    body.rows(
                        fit_table::row_height(font) + 4.0,
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
/// (the tag look of the sample's own tags) with the runs it was mapped in;
/// "Show all" opens one foldable row per technique instead. The run whose
/// link was clicked is returned.
pub(super) fn techniques(ui: &mut egui::Ui, data: &Data) -> Option<usize> {
    use antinomie_monitor_core::samples::{Tag, TagKind};
    let rollup = &data.rollup;
    let mut open_run = None;
    parts::section(ui, "ATT&CK techniques", None, |ui| {
        if not_triaged(ui, rollup) {
            return;
        }
        if rollup.tactics.is_empty() {
            parts::muted_line(ui, "No technique mapped.");
            return;
        }
        // Folded: the tag rows below; open: one foldable row per technique.
        // Kept for the rest of the app session.
        let total: usize = rollup.tactics.iter().map(|t| t.techniques.len()).sum();
        let fold = ui.make_persistent_id("sample-attack-open");
        let mut state =
            egui::collapsing_header::CollapsingState::load_with_default_open(ui.ctx(), fold, false);
        let open = state.is_open();
        if widgets::link(
            ui,
            &if open {
                "Hide".to_owned()
            } else {
                format!("Show all {total}")
            },
        )
        .on_hover_text("One row per technique, with what cited it and the runs")
        .clicked()
        {
            state.set_open(!open);
        }
        state.store(ui.ctx());
        if open {
            open_run = technique_rows(ui, data);
            ui.add_space(4.0);
            crate::widgets::attack::legend(ui, "sample-attack-legend");
            return;
        }
        let body = egui::TextStyle::Body.resolve(ui.style());
        let column = parts::fitted_up_to(
            ui,
            &body,
            rollup
                .tactics
                .iter()
                .map(|tactic| format!("● {}", tactic.tactic)),
            220.0,
        );
        for tactic in &rollup.tactics {
            ui.horizontal_top(|ui| {
                // The tactic, left-aligned in a column of its own.
                ui.allocate_ui_with_layout(
                    egui::vec2(column, ui.spacing().interact_size.y),
                    egui::Layout::left_to_right(egui::Align::Center),
                    |ui| {
                        // The cell is as wide as the column, not as its text.
                        ui.set_min_width(column);
                        ui.set_max_width(column);
                        let context =
                            antinomie_monitor_core::mitre::Tactic::from_label(&tactic.tactic);
                        let shown = match context {
                            Some(context) => ui.add(crate::widgets::dot::DotLabel::new(
                                crate::widgets::attack::tactic_color(context),
                                &tactic.tactic,
                            )),
                            None => ui.add(egui::Label::new(&tactic.tactic).truncate()),
                        };
                        shown.on_hover_text(&tactic.tactic);
                    },
                );
                ui.vertical(|ui| {
                    // Each technique and its run count are one group, laid
                    // out in rows by hand: a group that does not fit what is
                    // left of a row starts the next one, whole, and one wider
                    // than a whole row is cut (its tooltip has all of it).
                    let width = ui.available_width();
                    let gap = 10.0;
                    let context = antinomie_monitor_core::mitre::Tactic::from_label(&tactic.tactic);
                    let groups: Vec<(Tag, RichText, f32, f32)> = tactic
                        .techniques
                        .iter()
                        .map(|technique| {
                            let tag = Tag::new(
                                TagKind::Technique,
                                antinomie_monitor_core::mitre::technique_label(&technique.id),
                            );
                            let count = RichText::new(format!(
                                "{}/{}",
                                technique.runs.len(),
                                rollup.triaged
                            ))
                            .color(theme::text());
                            let count_width = ui.fonts_mut(|fonts| {
                                fonts
                                    .layout_no_wrap(
                                        count.text().to_owned(),
                                        egui::TextStyle::Body.resolve(ui.style()),
                                        egui::Color32::PLACEHOLDER,
                                    )
                                    .size()
                                    .x
                            });
                            let tag_width = crate::sample_tags::width_of_in(ui, &tag, context);
                            (tag, count, tag_width, count_width)
                        })
                        .collect();
                    let mut rows: Vec<Vec<usize>> = vec![Vec::new()];
                    let mut used = 0.0;
                    for (index, (_, _, tag_width, count_width)) in groups.iter().enumerate() {
                        let group = tag_width + 5.0 + count_width;
                        let row = rows.last_mut().expect("one row");
                        if !row.is_empty() && used + gap + group > width {
                            rows.push(vec![index]);
                            used = group;
                        } else {
                            used += if row.is_empty() { group } else { gap + group };
                            row.push(index);
                        }
                    }
                    for row in rows {
                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing.x = gap;
                            for index in row {
                                let (tag, count, tag_width, count_width) = &groups[index];
                                let technique = &tactic.techniques[index];
                                ui.scope(|ui| {
                                    ui.spacing_mut().item_spacing.x = 5.0;
                                    let room = (ui.available_width() - count_width - 5.0).max(60.0);
                                    ui.allocate_ui_with_layout(
                                        egui::vec2(
                                            tag_width.min(room),
                                            ui.spacing().interact_size.y,
                                        ),
                                        egui::Layout::left_to_right(egui::Align::Center),
                                        |ui| {
                                            crate::sample_tags::tag_in(ui, tag, context);
                                        },
                                    );
                                    ui.add(egui::Label::new(count.clone()).extend())
                                        .on_hover_text(run_list(&technique.runs));
                                });
                            }
                        });
                    }
                });
            });
        }
        ui.add_space(4.0);
        crate::widgets::attack::legend(ui, "sample-attack-legend");
    });
    open_run
}

/// One foldable row per technique, grouped by the tactic of the rule
/// category that cited it: what cited it and the runs, each run a link into
/// Triage. The run whose link was clicked is returned.
fn technique_rows(ui: &mut egui::Ui, data: &Data) -> Option<usize> {
    use crate::widgets::attack as pills;
    use antinomie_monitor_core::mitre::{self, Tactic};
    let rollup = &data.rollup;
    let mut open_run = None;
    for row in &rollup.tactics {
        let context = Tactic::from_label(&row.tactic);
        ui.horizontal(|ui| {
            let (dot, name) = match context {
                Some(tactic) => (pills::tactic_color(tactic), row.tactic.as_str()),
                None => (theme::muted(), row.tactic.as_str()),
            };
            ui.add(
                crate::widgets::dot::DotLabel::new(dot, name)
                    .strong()
                    .text_color(theme::text()),
            );
            ui.label(
                RichText::new(format!("({})", row.techniques.len()))
                    .small()
                    .color(theme::muted()),
            );
        });
        ui.indent(("sample-attack-group", row.tactic.as_str()), |ui| {
            for technique in &row.techniques {
                let summary = format!("{}/{} runs", technique.runs.len(), rollup.triaged);
                pills::technique_row(ui, "sample", &technique.id, context, &summary, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Technique").small().color(theme::muted()));
                        ui.label(RichText::new(&technique.id).monospace().strong());
                        ui.label(mitre::technique_name(&technique.id).unwrap_or_default());
                    });
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Tactic").small().color(theme::muted()));
                        let tactics = mitre::tactics(&technique.id);
                        if tactics.is_empty() {
                            ui.label(
                                RichText::new("not in the bundled ATT&CK table")
                                    .color(theme::muted()),
                            );
                        }
                        for tactic in tactics {
                            pills::tactic_chip(ui, tactic);
                        }
                    });
                    if !technique.rules.is_empty() {
                        ui.label(RichText::new("Cited by").small().color(theme::muted()));
                        for rule in &technique.rules {
                            ui.label(RichText::new(rule).monospace());
                        }
                    }
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Runs").small().color(theme::muted()));
                        for number in &technique.runs {
                            if widgets::link(ui, parts::run_name(*number))
                                .on_hover_text("Open this run in Triage")
                                .clicked()
                            {
                                open_run = Some(*number);
                            }
                        }
                    });
                });
            }
        });
        ui.add_space(4.0);
    }
    open_run
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
    id: impl std::hash::Hash + std::fmt::Debug,
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
pub(super) fn evasion(ui: &mut egui::Ui, data: &Data) -> Option<(usize, String)> {
    let rollup = &data.rollup;
    let mut trace = None;
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
                        if let Some(asked) =
                            check_rows(ui, &category.category, check, rollup.triaged)
                        {
                            trace = Some(asked);
                        }
                    }
                },
            );
            header.on_hover_text(run_list(&seen));
        }
    });
    trace
}

/// The Syscall Trace filter that shows `calls` of the process `cookie`.
fn evidence_filter(cookie: u64, calls: &[u64]) -> String {
    let set = calls
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    if cookie == 0 {
        format!("call.id in {{{set}}}")
    } else {
        format!("process.cookie == {cookie} && call.id in {{{set}}}")
    }
}

/// One check of a category: its header and one line per run, each with a
/// link to its evidence calls in that run's Syscall Trace when the run kept
/// them. Returns the run and Trace filter asked for.
fn check_rows(
    ui: &mut egui::Ui,
    category: &str,
    check: &antinomie_monitor_core::samples::CheckRow,
    triaged: usize,
) -> Option<(usize, String)> {
    let mut trace = None;
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
                    match check.evidence.iter().find(|(run, ..)| run == number) {
                        Some((_, cookie, calls)) => {
                            if parts::more_inline(ui, "Show in Syscall Trace ›")
                                .on_hover_text(format!(
                                    "Open {} in Syscall Trace at the {} {} behind this line",
                                    parts::run_name(*number),
                                    calls.len(),
                                    if calls.len() == 1 { "call" } else { "calls" }
                                ))
                                .clicked()
                            {
                                trace = Some((*number, evidence_filter(*cookie, calls)));
                            }
                        }
                        None => {
                            ui.label(theme::hint_text("triage this run again to link its calls"))
                                .on_hover_text(
                                    "This run's digest was written before checks kept their calls",
                                );
                        }
                    }
                });
            }
        },
    )
    .on_hover_text(&check.rule);
    trace
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

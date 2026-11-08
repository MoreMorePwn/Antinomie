// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Report overview composed from cached run evidence, never from render-time I/O.
use super::sample::SampleInfo;
use super::state::Built;
use super::*;
use super::{header, panels, relations};

/// The status chip of a detector card. A scan waiting or running outranks an
/// older result, so a card never says "Not scanned" while its engine is queued
/// or being checked.
fn scan_status(
    activity: Option<detection::ScanActivity>,
    result: Option<&Result<antinomie_monitor_core::analysis::detection::Report, String>>,
) -> (&'static str, egui::Color32) {
    if let Some(activity) = activity {
        let color = if activity == detection::ScanActivity::Running {
            theme::blue()
        } else {
            theme::muted()
        };
        return (activity.label(), color);
    }
    match result {
        None => ("Not scanned", theme::muted()),
        Some(Err(_)) => ("Failed", theme::error()),
        Some(Ok(report)) => match report.state {
            State::Complete => ("Complete", theme::blue()),
            State::Partial => ("Partial", theme::warn()),
            State::Unavailable => ("Unavailable", theme::muted()),
            State::NoRules => ("No rules enabled", theme::neutral_accent()),
            State::Missing => ("Evidence missing", theme::warn()),
            State::Skipped => ("Skipped", theme::muted()),
        },
    }
}

fn detector(
    ui: &mut egui::Ui,
    view: &TriageView,
    index: usize,
    engine: Engine,
    compact: bool,
) -> bool {
    presentation::frame()
        .fill(theme::panel())
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            let activity = view.detection.scan_activity(index);
            let (status, color) = scan_status(activity, view.detection.results[index].as_ref());
            if compact {
                return ui
                    .horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(detection::name(engine))
                                .strong()
                                .color(theme::heading()),
                        );
                        ui.label(
                            RichText::new(
                                view.detection.counts[index]
                                    .as_ref()
                                    .map_or("–".into(), |counts| {
                                        format!("{} matches", counts.rules)
                                    }),
                            )
                            .strong()
                            .color(theme::text()),
                        );
                        presentation::badge(ui, status, color);
                        ui.button("Open results").clicked()
                    })
                    .inner;
            }
            ui.label(
                RichText::new(detection::name(engine))
                    .strong()
                    .color(theme::heading()),
            );
            // The same height in every card: the figures, a line for the
            // occurrences and a line for YARA's strong/weak split, which
            // IDS and Sigma leave empty, so the tag and the button sit at
            // the same height in all three.
            let small = ui.text_style_height(&egui::TextStyle::Small);
            let big = ui.fonts_mut(|fonts| fonts.row_height(&egui::FontId::proportional(27.0)));
            let spacing = ui.spacing().item_spacing.y;
            let body_height = big + 2.0 * small + 3.0 * spacing;
            let start = ui.cursor().top();
            if let Some(counts) = &view.detection.counts[index] {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(counts.rules.to_string())
                            .size(27.0)
                            .strong()
                            .color(theme::text()),
                    );
                    ui.label(if counts.rules == 1 {
                        "rule matched"
                    } else {
                        "rules matched"
                    });
                });
                ui.label(
                    RichText::new(format!(
                        "{} {}",
                        counts.occurrences,
                        if counts.occurrences == 1 {
                            "occurrence"
                        } else {
                            "occurrences"
                        }
                    ))
                    .small()
                    .color(theme::muted()),
                );
                if let Some(Ok(report)) = view.detection.results[index]
                    .as_ref()
                    .filter(|_| engine == Engine::Yara)
                {
                    let weak = report
                        .findings
                        .iter()
                        .filter(|finding| {
                            detection::yara_strength(report, finding)
                                != crate::triage::family::Strength::Strong
                        })
                        .count();
                    if weak > 0 {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!(
                                    "{} strong \u{b7} {weak} weak or generic",
                                    report.findings.len() - weak
                                ))
                                .small()
                                .color(theme::muted()),
                            )
                            .truncate(),
                        )
                        .on_hover_text(
                            "Weak or generic: unscored community rules without a family, \
                             generic or hunting rules, low-score Elastic rules and rules for \
                             another platform. The count above is the total.",
                        );
                    }
                }
            } else {
                ui.label(RichText::new("–").size(27.0).color(theme::muted()))
                    .on_hover_text("Not scanned");
                ui.add(
                    egui::Label::new(
                        RichText::new(match activity {
                            Some(detection::ScanActivity::Running) => "Scan in progress",
                            Some(detection::ScanActivity::Queued) => "Waiting for its turn",
                            // Why an engine could not run is said in the Detection view.
                            None => match view.detection.results[index].as_ref() {
                                Some(Ok(report))
                                    if matches!(
                                        report.state,
                                        State::Unavailable | State::Missing
                                    ) =>
                                {
                                    "Not available: open Results for why"
                                }
                                None => "Not scanned: open Results to scan",
                                _ => "No evaluated result",
                            },
                        })
                        .small()
                        .color(theme::muted()),
                    )
                    .truncate(),
                );
            }
            let used = ui.cursor().top() - start;
            ui.add_space((body_height - used).max(0.0));
            ui.horizontal_wrapped(|ui| {
                presentation::badge(ui, status, color);
                ui.button("Open results").clicked()
            })
            .inner
        })
        .inner
}

/// What the run recorded about itself: facts about its recording and its
/// device profile that are no warning, with the run's last screenshot.
fn notes(
    ui: &mut egui::Ui,
    notes: &[String],
    shot: Option<(&std::path::Path, &mut super::thumb::Thumb)>,
) -> bool {
    let mut open = false;
    if notes.is_empty() && shot.is_none() {
        return open;
    }
    presentation::frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        if !notes.is_empty() {
            presentation::heading(ui, "Notes", "");
        }
        for note in notes {
            ui.add(egui::Label::new(RichText::new(note).color(theme::muted())).wrap());
        }
        // A reached quota is changed in the Recording settings.
        if notes.iter().any(|note| note.contains("recording quota")) {
            crate::settings_link::button(ui, "Recording");
        }
        if let Some((path, thumb)) = shot {
            ui.add_space(6.0);
            ui.label(
                RichText::new("Last screenshot")
                    .small()
                    .color(theme::muted()),
            );
            open = thumb.show(ui, path);
        }
    });
    open
}

/// What the run saved: its cores, memory dumps, capture segments and trigger
/// log, in the rows of the sample page's Artifacts. Nothing when it saved none.
fn run_artifacts(ui: &mut egui::Ui, view: &mut TriageView) {
    if view.run_box.is_empty() {
        return;
    }
    ui.add_space(10.0);
    let font = egui::TextStyle::Body.resolve(ui.style()).size;
    let data_dir = view.scan_request.data_dir.clone().unwrap_or_default();
    let count = view.run_box.count();
    let mut open = None;
    presentation::frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        presentation::heading(
            ui,
            "Run artifacts",
            &format!("{count} saved by this run; Open shows them in their tab, for this run only."),
        );
        open = crate::app::samples_page::detail::show_run_box(ui, &view.run_box, &data_dir, font);
    });
    if open.is_some() {
        view.open_artifact = open;
    }
}

/// The three detector cards, and the line that says one needs attention.
fn engines(
    ui: &mut egui::Ui,
    view: &TriageView,
    scan: &ArchiveScan,
    destination: &mut Option<Destination>,
) {
    presentation::heading(ui, "Detection engines", "");
    if ui.available_width() >= 620.0 {
        ui.columns(3, |columns| {
            for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
                .into_iter()
                .enumerate()
            {
                if detector(&mut columns[index], view, index, engine, false) {
                    *destination = Some(Destination::Detection(engine));
                }
            }
        });
    } else {
        for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
            .into_iter()
            .enumerate()
        {
            if detector(ui, view, index, engine, true) {
                *destination = Some(Destination::Detection(engine));
            }
            ui.add_space(6.0);
        }
    }
    // Notes and errors stay in the Detection view; one line says when
    // something there needs attention.
    let attention: Vec<Engine> = [Engine::Yara, Engine::Ids, Engine::Sigma]
        .into_iter()
        .enumerate()
        .filter(|(index, _)| match view.detection.results[*index].as_ref() {
            Some(Ok(report)) => matches!(report.state, State::Partial | State::Missing),
            Some(Err(_)) => true,
            None => false,
        })
        .map(|(_, engine)| engine)
        .collect();
    if scan.event_error.is_some() || !attention.is_empty() {
        let count = attention.len() + usize::from(scan.event_error.is_some());
        let first = attention.first().copied().unwrap_or(Engine::Sigma);
        if ui
            .link(format!(
                "Detection: {count} {} need attention (open Detection)",
                if count == 1 { "note" } else { "notes" }
            ))
            .clicked()
        {
            *destination = Some(Destination::Detection(first));
        }
    }
    if scan.network_warning.is_some() {
        // The note itself is in the Network view.
        if ui.link("Network: 1 note (open Network)").clicked() {
            *destination = Some(Destination::Http);
        }
    }
}

pub(super) fn content(
    view: &mut TriageView,
    ui: &mut egui::Ui,
    input: &TriageInput<'_>,
) -> Option<Destination> {
    let mut destination = None;
    let mut pop_out = false;
    let mut attack_jump = None;
    let mut acts: Vec<Act> = Vec::new();
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new("Run overview")
                .strong()
                .color(theme::heading())
                .size(ui.text_style_height(&egui::TextStyle::Heading)),
        );
        if view
            .scan
            .as_ref()
            .is_some_and(|scan| scan.network_counts.is_none())
        {
            ui.label(RichText::new("Network").small().color(theme::muted()));
            presentation::badge(ui, "Unavailable", theme::muted());
        }
        if ui
            .add_enabled(
                input.archive.is_some(),
                egui::Button::new(egui_phosphor::regular::ARROW_CLOCKWISE),
            )
            .on_hover_text("Refresh")
            .clicked()
        {
            view.request_refresh();
        }
        if view.scan_rx.is_some() {
            crate::theme::spinner(ui);
        }
    });
    ui.add_space(8.0);
    let mut state = std::mem::take(&mut view.summary_state);
    egui::ScrollArea::vertical()
        .id_salt("triage-summary")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if let Some(error) = &view.scan_error {
                crate::activity::error(ui, format!("The saved-recording index failed: {error}"));
            }
            let (attack, attack_details) = {
                let (list, details) = view.attack_list();
                (list.to_vec(), details.to_vec())
            };
            let Some(scan) = &view.scan else {
                // Centred in the panel, both ways.
                let title = theme::section_title(ui, "Preparing run evidence");
                theme::loading_centered(ui, title);
                return;
            };
            if !state
                .built
                .as_ref()
                .is_some_and(|built| built.current(view, scan))
            {
                state.built = Some(Built::of(
                    view,
                    scan,
                    view.scan_request.packed.is_some(),
                    input
                        .analysis
                        .and_then(|report| report.specimen_sha256.as_deref()),
                ));
            }
            let ioc_line = view.ioc_headline();
            let sample = input.analysis.map(SampleInfo::of);
            let program = view
                .scan_request
                .launch
                .as_ref()
                .map(|(_, path, _)| process_cells::file_name(path).to_owned())
                .unwrap_or_default();
            if let Some(built) = &state.built {
                let facts = header::Facts {
                    sample: sample.as_ref(),
                    run: &view.run_facts,
                    route: &view.route,
                    program: &program,
                };
                header::show(ui, built, scan, &facts, &mut acts);
                ui.add_space(10.0);
                panels::key_findings(ui, built, scan, &mut state.keys_open, &mut acts);
                ui.add_space(10.0);
                panels::indicators(ui, built, ioc_line.clone(), &mut state.more, &mut acts);
                ui.add_space(10.0);
            }
            relations::ui::show(ui, &mut state, &mut acts);
            ui.add_space(10.0);
            // The strip of findings over the run's time: its own way into the Graph.
            let busy = view.preparing();
            let strip = view.strip.show(
                ui,
                &scan.graph.overview,
                scan.counts.finding_tiers,
                scan.clock_anchor.or(input.clock_anchor),
                busy,
                view.graph_spacing,
            );
            if strip.open_graph {
                destination = Some(Destination::Graph);
            }
            pop_out |= strip.open_window;
            ui.add_space(10.0);
            // One-line rows, then the full ATT&CK list folded below them.
            presentation::frame().show(ui, |ui| {
                ui.set_width(ui.available_width());
                panels::attack_row(ui, attack.len(), &attack_details);
                if let Some(built) = &state.built {
                    panels::interest_row(ui, &built.interest, scan, &mut acts);
                }
                panels::files_row(ui, scan, &mut acts);
                panels::network_row(ui, scan, &mut acts);
            });
            if !attack.is_empty() {
                ui.add_space(4.0);
                egui::CollapsingHeader::new(
                    RichText::new(format!("MITRE ATT&CK techniques ({})", attack.len()))
                        .strong()
                        .color(theme::heading()),
                )
                .id_salt("summary-attack-open")
                .default_open(false)
                .show(ui, |ui| {
                    if let Some(jump) = attack_list::show(ui, view, &attack, &attack_details) {
                        attack_jump = Some(jump);
                    }
                    crate::widgets::attack::legend(ui, "summary-attack-legend");
                });
            }
            ui.add_space(10.0);
            engines(ui, view, scan, &mut destination);
            ui.add_space(14.0);
            let mut shown = view.notes.clone();
            shown.extend(super::run_end::run_end(scan).map(|end| end.text));
            let shot = view.run_facts.screenshot.clone();
            if notes(
                ui,
                &shown,
                shot.as_deref().map(|path| (path, &mut state.thumb)),
            ) {
                acts.push(Act::Screenshot(shot.unwrap_or_default()));
            }
            run_artifacts(ui, view);
        });
    view.summary_state = state;
    if attack_jump.is_some() {
        view.attack_jump = attack_jump;
    }
    if pop_out {
        view.clear_finding_filters(ui.ctx());
        view.open_graph_window(ui.ctx());
    }
    for act in acts {
        match act {
            Act::Go(target) => destination = Some(target),
            other => view.apply_act(ui.ctx(), other, &mut destination),
        }
    }
    destination
}

#[cfg(test)]
mod tests {
    use super::*;
    use detection::ScanActivity;

    #[test]
    fn a_card_does_not_say_not_scanned_while_its_scan_waits_or_runs() {
        assert_eq!(scan_status(None, None).0, "Not scanned");
        assert_eq!(
            scan_status(Some(ScanActivity::Queued), None).0,
            "Queued",
            "waiting for its turn"
        );
        assert_eq!(
            scan_status(Some(ScanActivity::Running), None).0,
            "Scanning",
            "being checked"
        );
        // A scan waiting or running outranks an older failed result.
        let failed = Err("boom".to_owned());
        assert_eq!(scan_status(None, Some(&failed)).0, "Failed");
        assert_eq!(
            scan_status(Some(ScanActivity::Running), Some(&failed)).0,
            "Scanning"
        );
    }
}

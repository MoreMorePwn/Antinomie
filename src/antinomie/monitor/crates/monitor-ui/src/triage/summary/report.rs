// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Report overview composed from cached run evidence, never from render-time I/O.
use super::*;

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
            State::NoRules => ("No rules enabled", theme::warn()),
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
                                    .map_or("—".into(), |counts| {
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
            ui.set_min_height(ui.text_style_height(&egui::TextStyle::Body) * 5.4);
            ui.label(
                RichText::new(detection::name(engine))
                    .strong()
                    .color(theme::heading()),
            );
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
            } else {
                ui.label(RichText::new("—").size(27.0).color(theme::muted()));
                ui.label(
                    RichText::new(match activity {
                        Some(detection::ScanActivity::Running) => "Scan in progress",
                        Some(detection::ScanActivity::Queued) => "Waiting for its turn",
                        None => "No evaluated result",
                    })
                    .small()
                    .color(theme::muted()),
                );
            }
            ui.horizontal_wrapped(|ui| {
                presentation::badge(ui, status, color);
                ui.button("Open results").clicked()
            })
            .inner
        })
        .inner
}

fn activity(ui: &mut egui::Ui, scan: &ArchiveScan) -> Option<Destination> {
    presentation::heading(ui, "Behavior & files", "");
    let mut target = None;
    egui::Grid::new("triage-summary-activity")
        .num_columns(2)
        .max_col_width(ui.available_width() * 0.66)
        .spacing(egui::vec2(16.0, 9.0))
        .show(ui, |ui| {
            for (title, count, destination) in [
                ("Syscalls", scan.counts.calls, Destination::Tasks),
                (
                    "Observed task identities",
                    scan.process.len() as u64,
                    Destination::Tasks,
                ),
                (
                    "Suspicious observations",
                    scan.counts.findings,
                    Destination::Findings,
                ),
                (
                    "Opened-file operations",
                    scan.counts.opened,
                    Destination::Opened,
                ),
                (
                    "Read-file operations",
                    scan.counts.reads,
                    Destination::Reads,
                ),
                (
                    "Changed-file groups",
                    scan.counts.changed,
                    Destination::Changed,
                ),
            ] {
                if metric(ui, title, Some(count)) {
                    target = Some(destination);
                }
            }
        });
    target
}

fn network(
    ui: &mut egui::Ui,
    scan: &ArchiveScan,
    route: &crate::route_ui::RouteText,
) -> Option<Destination> {
    presentation::heading(ui, "Network evidence", "");
    let mut target = None;
    crate::route_ui::line(ui, route);
    egui::Grid::new("triage-summary-network")
        .num_columns(2)
        .max_col_width(ui.available_width() * 0.66)
        .spacing(egui::vec2(16.0, 9.0))
        .show(ui, |ui| {
            for (title, count, destination) in [
                (
                    "Capture frames",
                    scan.network_counts.map(|count| count.0),
                    Destination::Http,
                ),
                (
                    "Destination IPs",
                    scan.network_counts.map(|count| count.1),
                    Destination::Ips,
                ),
                (
                    "Observed hostnames",
                    scan.network_counts.map(|count| count.2),
                    Destination::Hosts,
                ),
                (
                    "HTTP/1 requests",
                    scan.network_counts.map(|_| scan.counts.http),
                    Destination::Http,
                ),
                (
                    "DNS questions",
                    scan.network_counts.map(|_| scan.counts.dns),
                    Destination::Dns,
                ),
            ] {
                let hover = if title == "HTTP/1 requests" {
                    "Encrypted request contents are unavailable."
                } else {
                    ""
                };
                if super::metric_hover(ui, title, count, hover) {
                    target = Some(destination);
                }
            }
        });
    target
}

/// The IOC card: how many of the run's indicators matched a dataset.
fn indicators(ui: &mut egui::Ui, view: &TriageView) -> bool {
    presentation::frame()
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            presentation::heading(ui, "Indicators (IOC)", "");
            match view.ioc_headline() {
                Some((matched, total, date)) => {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(matched.to_string())
                                .size(27.0)
                                .strong()
                                .color(if matched > 0 {
                                    theme::error()
                                } else {
                                    theme::text()
                                }),
                        );
                        ui.label(format!(
                            "of {total} indicator{} matched",
                            if total == 1 { "" } else { "s" }
                        ))
                        .on_hover_text(super::super::ioc_view::NO_MATCH_NOTE);
                    });
                    ui.add(
                        egui::Label::new(
                            RichText::new(if date.is_empty() {
                                "No datasets loaded".to_owned()
                            } else {
                                format!("Datasets dated {date}")
                            })
                            .small()
                            .color(theme::muted()),
                        )
                        .wrap(),
                    );
                }
                None => {
                    ui.label(RichText::new("—").size(27.0).color(theme::muted()));
                    ui.label(
                        RichText::new("Indicators appear after the recording is indexed")
                            .small()
                            .color(theme::muted()),
                    );
                }
            }
            ui.button("Open IOC").clicked()
        })
        .inner
}

fn observations(ui: &mut egui::Ui, scan: &ArchiveScan) -> bool {
    presentation::frame()
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            presentation::heading(ui, "Observed activity", "");
            // The worst rows first, then the earliest.
            let mut worst: Vec<&Finding> = scan.findings.iter().collect();
            worst.sort_by_key(|finding| {
                rules::Tier::ALL.iter().position(|tier| {
                    finding
                        .cells
                        .get(rules::COL_TIER)
                        .is_some_and(|cell| cell.text == tier.tag())
                })
            });
            for (index, finding) in worst.into_iter().take(4).enumerate() {
                let severity = finding
                    .cells
                    .get(rules::COL_TIER)
                    .map_or("Observed", |cell| cell.text.as_str());
                let color = match severity {
                    "high" => theme::error(),
                    "medium" => theme::warn(),
                    "low" => theme::blue(),
                    _ => theme::muted(),
                };
                // One syscall can produce several observations, so the click
                // target needs the rule as well as the invocation.
                let rule = finding
                    .cells
                    .first()
                    .map(|cell| cell.text.as_str())
                    .unwrap_or("");
                let response = egui::Frame::new()
                    .fill(theme::panel())
                    .corner_radius(4)
                    .inner_margin(8)
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            presentation::badge(ui, severity, color);
                            if !rule.is_empty() {
                                ui.label(RichText::new(rule).strong().color(theme::text()));
                            }
                            if let Some(process) = finding.cells.get(rules::COL_PROCESS) {
                                ui.label(
                                    RichText::new(&process.text).small().color(theme::muted()),
                                );
                            }
                        });
                        if let Some(summary) = finding.cells.get(rules::COL_SUMMARY) {
                            ui.add(egui::Label::new(&summary.text).truncate());
                        }
                    })
                    .response;
                let clicked = ui.interact(
                    response.rect,
                    ui.id()
                        .with(("summary-observation", index, finding.key, rule)),
                    egui::Sense::click(),
                );
                if clicked.clicked() {
                    let mut cells = finding.cells.clone();
                    if let Some(first) = cells.first_mut() {
                        first.values.clone_from(&finding.values);
                    }
                    details::select(ui.ctx(), "triage-findings", rules::HEADERS, &cells);
                    details::clicked(ui.ctx(), "triage-findings");
                }
                if clicked.double_clicked() {
                    request_evidence_jump(ui.ctx(), &finding.values);
                }
                ui.add_space(5.0);
            }
            if scan.findings.is_empty() {
                ui.weak("No observations.");
            }
            ui.button("Open suspicious activity").clicked()
        })
        .inner
}

/// What the run recorded about itself: facts about its recording and its
/// device profile that are no warning, at the bottom of the Summary.
fn notes(ui: &mut egui::Ui, notes: &[String]) {
    if notes.is_empty() {
        return;
    }
    presentation::frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        presentation::heading(ui, "Notes", "");
        for note in notes {
            ui.add(egui::Label::new(RichText::new(note).color(theme::muted())).wrap());
        }
        // A reached quota is changed in the Recording settings.
        if notes.iter().any(|note| note.contains("recording quota")) {
            crate::settings_link::button(ui, "Recording");
        }
    });
}

pub(super) fn content(
    view: &mut TriageView,
    ui: &mut egui::Ui,
    input: &TriageInput<'_>,
) -> Option<Destination> {
    let mut destination = None;
    let mut pop_out = false;
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
            .add_enabled(input.archive.is_some(), egui::Button::new("Refresh"))
            .clicked()
        {
            view.request_refresh();
        }
        if view.scan_rx.is_some() {
            crate::theme::spinner(ui);
        }
        if ui.button("Open properties").clicked() {
            destination = Some(Destination::Properties);
        }
    });
    ui.add_space(8.0);
    egui::ScrollArea::vertical()
        .id_salt("triage-summary")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if let Some(error) = &view.scan_error {
                crate::activity::warning(ui, error);
            }
            let Some(scan) = &view.scan else {
                presentation::frame().show(ui, |ui| {
                    presentation::heading_busy(ui, "Preparing run evidence", "", true);
                });
                return;
            };
            if let Some(error) = &scan.event_error {
                crate::activity::warning(ui, error);
            }
            presentation::heading(ui, "Detection evidence", "");
            if ui.available_width() >= 620.0 {
                ui.columns(3, |columns| {
                    for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
                        .into_iter()
                        .enumerate()
                    {
                        if detector(&mut columns[index], view, index, engine, false) {
                            destination = Some(Destination::Detection(engine));
                        }
                    }
                });
            } else {
                for (index, engine) in [Engine::Yara, Engine::Ids, Engine::Sigma]
                    .into_iter()
                    .enumerate()
                {
                    if detector(ui, view, index, engine, true) {
                        destination = Some(Destination::Detection(engine));
                    }
                    ui.add_space(6.0);
                }
            }
            ui.add_space(8.0);
            if !view.detection.references.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("MITRE ATT&CK").small().color(theme::muted()));
                    for reference in view.detection.references.iter().take(16) {
                        presentation::badge(
                            ui,
                            &antinomie_monitor_core::mitre::technique_label(reference),
                            theme::blue(),
                        );
                    }
                    if view.detection.references.len() > 16 {
                        ui.label(format!(
                            "+{} in Detection",
                            view.detection.references.len() - 16
                        ));
                    }
                });
            }
            ui.add_space(14.0);
            let (mut left, mut right) = (None, None);
            presentation::pair(
                ui,
                |ui| left = activity(ui, scan),
                |ui| right = network(ui, scan, &view.route),
            );
            destination = left.or(right).or(destination);
            if let Some(warning) = &scan.network_warning {
                crate::activity::warning(ui, warning);
            }
            ui.add_space(14.0);
            let busy = view.scan_rx.is_some();
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
            ui.add_space(14.0);
            if indicators(ui, view) {
                destination = Some(Destination::Ioc);
            }
            ui.add_space(14.0);
            if observations(ui, scan) {
                destination = Some(Destination::Findings);
            }
            ui.add_space(14.0);
            notes(ui, &view.notes);
        });
    if pop_out {
        view.clear_finding_filters(ui.ctx());
        view.open_graph_window(ui.ctx());
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

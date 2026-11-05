// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Key findings, Indicators and one-line rows.
use super::indicators::SHOWN;
use super::state::Built;
use super::{header::dot, Act, Destination};
use crate::theme;
use crate::triage::{attack, presentation, process_cells, ArchiveScan, FileTab};
use antinomie_monitor_core::mitre::Tactic;
use eframe::egui::{self, RichText};

/// A box with a title and, after it, the buttons that act on it.
pub(super) fn boxed(
    ui: &mut egui::Ui,
    title: &str,
    acts: &mut Vec<Act>,
    actions: impl FnOnce(&mut egui::Ui, &mut Vec<Act>),
    body: impl FnOnce(&mut egui::Ui, &mut Vec<Act>),
) {
    presentation::frame().show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.horizontal_wrapped(|ui| {
            ui.label(theme::section_title(ui, title));
            actions(ui, acts);
        });
        ui.add_space(4.0);
        body(ui, acts);
    });
}

pub(super) fn key_findings(
    ui: &mut egui::Ui,
    built: &Built,
    scan: &ArchiveScan,
    acts: &mut Vec<Act>,
) {
    let start = scan.process.iter().filter_map(|node| node.first_ns).min();
    boxed(
        ui,
        "Key findings",
        acts,
        |ui, acts| {
            if ui
                .link(format!("all {} \u{2192}", built.key_total))
                .on_hover_text("Open Suspicious activity")
                .clicked()
            {
                acts.push(Act::Go(Destination::Findings));
            }
        },
        |ui, acts| {
            if built.keys.is_empty() {
                ui.weak("No findings of LOW or above.");
            }
            for key in &built.keys {
                let color = key.tier.color();
                let response = egui::Frame::new()
                    .corner_radius(4)
                    .inner_margin(egui::Margin::symmetric(6, 3))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal_wrapped(|ui| {
                            dot(ui, color);
                            ui.label(RichText::new(&key.title).strong().color(theme::text()));
                            if !key.target.is_empty() {
                                ui.label(
                                    RichText::new(&key.target).monospace().color(theme::text()),
                                );
                            }
                            let name = node_name(scan, key.pid, key.cookie, &key.exe);
                            ui.label(
                                RichText::new(format!("{name} ({})", key.pid))
                                    .small()
                                    .color(theme::muted()),
                            );
                            ui.label(
                                RichText::new(format!("\u{d7}{}", key.count))
                                    .small()
                                    .color(theme::muted()),
                            );
                            ui.label(
                                RichText::new(process_cells::relative(Some(key.first_ns), start))
                                    .small()
                                    .monospace()
                                    .color(theme::muted()),
                            );
                            if !key.why.is_empty() {
                                ui.label(RichText::new(&key.why).small().color(theme::muted()));
                            }
                        });
                    })
                    .response;
                let click = ui.interact(
                    response.rect,
                    ui.id().with(("summary-key", key.index)),
                    egui::Sense::click(),
                );
                if click.hovered() {
                    ui.painter().rect_stroke(
                        response.rect,
                        4.0,
                        egui::Stroke::new(1.0, color),
                        egui::StrokeKind::Inside,
                    );
                }
                if click.double_clicked() {
                    acts.push(Act::Evidence(key.index));
                }
                if click
                    .on_hover_text("Open this finding's details (double click: the call)")
                    .clicked()
                {
                    acts.push(Act::Finding(key.index));
                }
            }
        },
    );
}

/// The process's name: the recorded one, else the image's file name.
fn node_name(scan: &ArchiveScan, pid: u32, cookie: u64, exe: &str) -> String {
    scan.process
        .iter()
        .find(|node| node.pid == pid && node.cookie == cookie)
        .map(|node| process_cells::file_name(&node.comm).to_owned())
        .filter(|name| !name.is_empty() && name != "?")
        .unwrap_or_else(|| process_cells::file_name(exe).to_owned())
}

/// One kind of indicator: its title and the first few, each a link to its view.
fn group(
    ui: &mut egui::Ui,
    title: &str,
    total: usize,
    destination: Destination,
    acts: &mut Vec<Act>,
    mut item: impl FnMut(&mut egui::Ui, usize) -> bool,
) {
    if total == 0 {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(title).small().color(theme::muted()));
        for at in 0..total.min(SHOWN) {
            if item(ui, at) {
                acts.push(Act::Go(destination));
            }
        }
        if total > SHOWN {
            ui.label(
                RichText::new(format!("+{} more", total - SHOWN))
                    .small()
                    .color(theme::muted()),
            );
        }
    });
}

pub(super) fn indicators(
    ui: &mut egui::Ui,
    built: &Built,
    status: &mut Option<String>,
    acts: &mut Vec<Act>,
) {
    let found = &built.indicators;
    let mut copy = false;
    let mut export = false;
    boxed(
        ui,
        "Indicators",
        acts,
        |ui, _| {
            copy = ui
                .add_enabled(!found.is_empty(), egui::Button::new("Copy all"))
                .on_hover_text("Copy every indicator as plain text, one per line, grouped")
                .clicked();
            export = ui
                .add_enabled(!found.is_empty(), egui::Button::new("Export"))
                .on_hover_text("Write the indicators as JSON beside the run's other files")
                .clicked();
        },
        |ui, acts| {
            if found.is_empty() {
                ui.weak("No endpoints, DNS names, URLs or dropped files were recorded.");
            }
            group(
                ui,
                "Contacted",
                found.endpoints.len(),
                Destination::Ips,
                acts,
                |ui, at| {
                    let row = &found.endpoints[at];
                    let place = super::indicators::Indicators::place(row);
                    let text = if place.is_empty() {
                        row.endpoint.clone()
                    } else {
                        format!("{} ({place})", row.endpoint)
                    };
                    ui.link(text)
                        .on_hover_text("Open the Endpoints tab")
                        .clicked()
                },
            );
            group(
                ui,
                "DNS",
                found.domains.len(),
                Destination::Dns,
                acts,
                |ui, at| {
                    ui.link(&found.domains[at])
                        .on_hover_text("Open the Domains tab")
                        .clicked()
                },
            );
            group(
                ui,
                "URLs",
                found.urls.len(),
                Destination::Http,
                acts,
                |ui, at| {
                    ui.link(&found.urls[at])
                        .on_hover_text("Open the URLs tab")
                        .clicked()
                },
            );
            group(
                ui,
                "Dropped / run",
                found.files.len(),
                Destination::Executed,
                acts,
                |ui, at| {
                    let row = &found.files[at];
                    let text = if row.sha256.is_empty() {
                        format!("{} ({})", row.path, row.kind)
                    } else {
                        format!(
                            "{} ({}) {}",
                            row.path,
                            row.kind,
                            super::sample::short_hash(&row.sha256)
                        )
                    };
                    ui.link(text).on_hover_text(row.sha256.clone()).clicked()
                },
            );
            if let Some(text) = status.as_ref() {
                ui.label(RichText::new(text).small().color(theme::muted()));
            }
        },
    );
    if copy {
        ui.ctx().copy_text(found.copy_text());
        *status = Some(format!("Copied {} indicators", found.total()));
    }
    if export {
        acts.push(Act::ExportIndicators);
    }
}

/// "Execution 2 \u{b7} Persistence 2": the techniques of each tactic.
pub(super) fn tactic_counts(details: &[attack::Detail]) -> Vec<(&'static str, usize)> {
    Tactic::ALL
        .into_iter()
        .filter_map(|tactic| {
            let count = details.iter().filter(|d| d.primary == Some(tactic)).count();
            (count > 0).then(|| (tactic.name(), count))
        })
        .collect()
}

/// A one-line row: a title, what it counts, and its way in.
fn line(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(title).strong().color(theme::heading()));
        body(ui);
    });
}

pub(super) fn attack_row(
    ui: &mut egui::Ui,
    total: usize,
    details: &[attack::Detail],
    open: bool,
    toggle: &mut bool,
) {
    if total == 0 {
        return;
    }
    line(ui, &format!("MITRE ATT&CK ({total})"), |ui| {
        let counts: Vec<String> = tactic_counts(details)
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect();
        ui.label(RichText::new(counts.join(" \u{b7} ")).color(theme::muted()));
        if crate::widgets::link(ui, if open { "hide" } else { "list" })
            .on_hover_text("One row per technique, by tactic, with what produced it")
            .clicked()
        {
            *toggle = true;
        }
    });
}

pub(super) fn interest_row(
    ui: &mut egui::Ui,
    built: &Built,
    scan: &ArchiveScan,
    acts: &mut Vec<Act>,
) {
    line(ui, "Processes of interest", |ui| {
        if built.interest.is_empty() {
            ui.label(RichText::new("none with findings or an argv mismatch").color(theme::muted()));
        }
        for item in &built.interest {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 3.0;
                if let Some(tier) = item.tier {
                    dot(ui, tier.color());
                    ui.label(
                        RichText::new(item.findings.to_string())
                            .small()
                            .color(tier.color()),
                    );
                }
                let text = if item.warn {
                    format!("{} \u{26a0}", item.label)
                } else {
                    item.label.clone()
                };
                if ui
                    .link(text)
                    .on_hover_text("Open this process's details")
                    .clicked()
                {
                    acts.push(Act::Process(item.key));
                }
            });
        }
        if ui
            .link(
                RichText::new(format!(
                    "of {} processes \u{b7} {} syscalls",
                    scan.process.len(),
                    scan.counts.calls
                ))
                .small(),
            )
            .on_hover_text("Open the Process tree")
            .clicked()
        {
            acts.push(Act::Go(Destination::Tasks));
        }
    });
}

pub(super) fn files_row(ui: &mut egui::Ui, scan: &ArchiveScan, acts: &mut Vec<Act>) {
    let tab = |tab: FileTab| scan.counts.tabs[tab.slot() - 8];
    line(ui, "Files", |ui| {
        ui.label(
            RichText::new(format!(
                "{} created \u{b7} {} executed \u{b7} {} deleted \u{b7} {} changed",
                tab(FileTab::Created),
                tab(FileTab::Executed),
                tab(FileTab::Deleted),
                scan.counts.changed
            ))
            .color(theme::muted()),
        );
        if ui
            .link("\u{2192}")
            .on_hover_text("Open the Files section")
            .clicked()
        {
            acts.push(Act::Go(Destination::Changed));
        }
    });
}

pub(super) fn network_row(ui: &mut egui::Ui, scan: &ArchiveScan, acts: &mut Vec<Act>) {
    line(ui, "Network", |ui| {
        if scan.network_counts.is_none() {
            ui.label(
                RichText::new("no capture for this run (turn on Capture network in Run program)")
                    .color(theme::muted()),
            );
        } else {
            let endpoints = scan.new_tabs.endpoints.len() as u64 + scan.new_tabs.endpoints_omitted;
            ui.label(
                RichText::new(format!(
                    "{endpoints} endpoints \u{b7} {} DNS \u{b7} {} HTTP",
                    scan.counts.dns, scan.counts.http
                ))
                .color(theme::muted()),
            );
        }
        if ui
            .link("\u{2192}")
            .on_hover_text("Open the Network section")
            .clicked()
        {
            acts.push(Act::Go(Destination::Ips));
        }
    });
}

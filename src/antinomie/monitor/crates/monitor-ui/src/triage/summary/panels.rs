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

/// Rows of Key findings listed before "Show more".
const KEY_SHOWN: usize = super::insight::KEY_ROWS;
/// The height of the list when it shows every finding.
const KEY_LIST_HEIGHT: f32 = 380.0;

pub(super) fn key_findings(
    ui: &mut egui::Ui,
    built: &Built,
    scan: &ArchiveScan,
    open: &mut bool,
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
            let more = built.keys.len() > KEY_SHOWN;
            if *open && more {
                egui::ScrollArea::vertical()
                    .id_salt("summary-keys")
                    .max_height(KEY_LIST_HEIGHT)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        for key in &built.keys {
                            key_row(ui, scan, start, key, acts);
                        }
                    });
            } else {
                for key in built.keys.iter().take(KEY_SHOWN) {
                    key_row(ui, scan, start, key, acts);
                }
            }
            if more {
                ui.add_space(4.0);
                let label = if *open {
                    "Show less".to_owned()
                } else {
                    format!("Show more ({})", built.keys.len() - KEY_SHOWN)
                };
                if ui
                    .button(label)
                    .on_hover_text("List every finding in a scrolling list")
                    .clicked()
                {
                    *open = !*open;
                }
            }
        },
    );
}

/// One finding: its row, and its description on a line of its own below.
fn key_row(
    ui: &mut egui::Ui,
    scan: &ArchiveScan,
    start: Option<u64>,
    key: &super::insight::Key,
    acts: &mut Vec<Act>,
) {
    let color = key.tier.color();
    let more_id = ui.id().with(("summary-key-more", key.index));
    let mut head = egui::Rect::NOTHING;
    let response = egui::Frame::new()
        .corner_radius(4)
        .inner_margin(egui::Margin::symmetric(6, 3))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            head = ui
                .horizontal_wrapped(|ui| {
                    dot(ui, color);
                    ui.label(RichText::new(&key.title).strong().color(theme::text()));
                    if !key.target.is_empty() {
                        ui.label(RichText::new(&key.target).monospace().color(theme::text()));
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
                })
                .response
                .rect;
            description(ui, key, more_id);
        })
        .response;
    // The row's own line opens the finding; the description line folds.
    let click = ui.interact(
        response.rect.with_max_y(head.max.y + 3.0),
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

/// The finding's description: its first sentence, and the whole text
/// after a click on a cut one ("\u{2026}"); another click folds it again.
fn description(ui: &mut egui::Ui, key: &super::insight::Key, id: egui::Id) {
    if key.why.is_empty() {
        return;
    }
    let open = !key.full.is_empty() && ui.data(|data| data.get_temp::<bool>(id)).unwrap_or(false);
    let text = if open { &key.full } else { &key.why };
    let label = egui::Label::new(RichText::new(text).small().color(theme::muted())).wrap();
    if key.full.is_empty() {
        ui.add(label);
        return;
    }
    let response = ui
        .add(label.sense(egui::Sense::click()))
        .on_hover_text(if open {
            "Show only the first sentence"
        } else {
            "Show the whole description"
        });
    if response.hovered() {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    if response.clicked() {
        ui.data_mut(|data| data.insert_temp(id, !open));
    }
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

/// One kind of indicator as a branch of the tree: the first few, each a link
/// to its view, and "Show N more" for the rest in a scrolling list.
fn category(
    ui: &mut egui::Ui,
    title: &str,
    total: usize,
    more: &mut bool,
    destination: Destination,
    acts: &mut Vec<Act>,
    mut item: impl FnMut(&mut egui::Ui, usize) -> bool,
) {
    if total == 0 {
        return;
    }
    egui::CollapsingHeader::new(
        RichText::new(format!("{title} ({total})"))
            .strong()
            .color(theme::heading()),
    )
    .id_salt(("summary-indicators", title))
    .default_open(true)
    .show(ui, |ui| {
        let mut row = |ui: &mut egui::Ui, at: usize| {
            ui.horizontal(|ui| {
                if item(ui, at) {
                    acts.push(Act::Go(destination));
                }
            });
        };
        if *more {
            egui::ScrollArea::vertical()
                .id_salt(("summary-indicators-list", title))
                .max_height(240.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for at in 0..total {
                        row(ui, at);
                    }
                });
        } else {
            for at in 0..total.min(SHOWN) {
                row(ui, at);
            }
        }
        if total > SHOWN {
            let label = if *more {
                "Show fewer".to_owned()
            } else {
                format!("Show {} more", total - SHOWN)
            };
            if crate::widgets::link(ui, label).clicked() {
                *more = !*more;
            }
        }
    });
}

pub(super) fn indicators(
    ui: &mut egui::Ui,
    built: &Built,
    matched: Option<(usize, usize, String)>,
    more: &mut [bool; 4],
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
        |ui, acts| {
            if let Some((hit, all, date)) = &matched {
                let text = format!(
                    "{hit} of {all} indicator{} matched{}",
                    if *all == 1 { "" } else { "s" },
                    if date.is_empty() {
                        " (no datasets loaded)".to_owned()
                    } else {
                        format!(" (datasets dated {date})")
                    }
                );
                if ui
                    .link(RichText::new(text).small())
                    .on_hover_text(format!(
                        "Open the IOC view. {}",
                        super::super::ioc_view::NO_MATCH_NOTE
                    ))
                    .clicked()
                {
                    acts.push(Act::Go(Destination::Ioc));
                }
            }
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
            let [endpoints, domains, urls, files] = more;
            category(
                ui,
                "Endpoints",
                found.endpoints.len(),
                endpoints,
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
            category(
                ui,
                "DNS names",
                found.domains.len(),
                domains,
                Destination::Dns,
                acts,
                |ui, at| {
                    ui.link(&found.domains[at])
                        .on_hover_text("Open the Domains tab")
                        .clicked()
                },
            );
            category(
                ui,
                "URLs",
                found.urls.len(),
                urls,
                Destination::Http,
                acts,
                |ui, at| {
                    ui.link(&found.urls[at])
                        .on_hover_text("Open the URLs tab")
                        .clicked()
                },
            );
            category(
                ui,
                "Files",
                found.files.len(),
                files,
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
        ui.spacing_mut().item_spacing.x = 10.0;
        ui.label(RichText::new(title).strong().color(theme::heading()));
        body(ui);
    });
}

pub(super) fn attack_row(ui: &mut egui::Ui, total: usize, details: &[attack::Detail]) {
    if total == 0 {
        return;
    }
    line(ui, &format!("MITRE ATT&CK ({total})"), |ui| {
        let counts: Vec<String> = tactic_counts(details)
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect();
        ui.label(RichText::new(counts.join(" \u{b7} ")).color(theme::muted()));
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
            // The tier dot, the count and the name share one text size, so
            // their middles are one line.
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 10.0;
                let (color, count) = match item.tier {
                    Some(tier) => (tier.color(), format!("\u{d7}{}", item.findings)),
                    None => (theme::muted(), "argv".to_owned()),
                };
                ui.add(crate::widgets::dot::DotLabel::new(color, count).text_color(color));
                if ui
                    .link(&item.label)
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

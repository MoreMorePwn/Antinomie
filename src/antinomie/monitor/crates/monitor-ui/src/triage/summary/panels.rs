// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Key findings, Indicators and one-line rows.
use super::indicators::SHOWN;
use super::rows::{self, Part};
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
            let rest = built.keys.len().saturating_sub(KEY_SHOWN);
            // A finding is two lines: a title row and its description.
            let row = ui.text_style_height(&egui::TextStyle::Body)
                + ui.text_style_height(&egui::TextStyle::Small)
                + 6.0
                + 2.0 * ui.spacing().item_spacing.y;
            rows::scroll_list(
                ui,
                "summary-keys",
                *open && rest > 0,
                KEY_SHOWN as f32 * row,
                (KEY_SHOWN, built.keys.len()),
                |ui, at| key_row(ui, scan, start, &built.keys[at], acts),
            );
            if rest > 0 {
                ui.add_space(4.0);
                let label = if *open {
                    "Show less".to_owned()
                } else {
                    format!("Show more ({rest})")
                };
                if ui
                    .button(label)
                    .on_hover_text("List every finding in the same space, with a scroll bar")
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

/// One kind of indicator as a branch of the tree: the first few, each
/// a clickable item for its view, and "Show N more" to turn them into one
/// scroll area with all of them.
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
    // The title in the text colour (strong), its count muted: not a link.
    let mut head = egui::text::LayoutJob::default();
    for (text, color) in [
        (title.to_owned(), theme::text()),
        (format!(" ({total})"), theme::muted()),
    ] {
        let rich = RichText::new(text).color(color);
        let rich = if color == theme::text() {
            rich.strong()
        } else {
            rich
        };
        rich.append_to(
            &mut head,
            ui.style(),
            egui::FontSelection::Default,
            egui::Align::Center,
        );
    }
    egui::CollapsingHeader::new(egui::WidgetText::from(head))
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
            let height =
                SHOWN as f32 * (ui.spacing().interact_size.y + ui.spacing().item_spacing.y);
            rows::scroll_list(
                ui,
                ("summary-indicators-list", title),
                *more && total > SHOWN,
                height,
                (SHOWN, total),
                |ui, at| row(ui, at),
            );
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
                    let mut parts = vec![Part::Value(&row.endpoint)];
                    if !place.is_empty() {
                        parts.push(Part::Note(&place));
                    }
                    rows::item(ui, &parts, "Open the Endpoints tab")
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
                    rows::item(
                        ui,
                        &[Part::Value(&found.domains[at])],
                        "Open the Domains tab",
                    )
                },
            );
            category(
                ui,
                "URLs",
                found.urls.len(),
                urls,
                Destination::Http,
                acts,
                |ui, at| rows::item(ui, &[Part::Value(&found.urls[at])], "Open the URLs tab"),
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
                    let hash = super::sample::short_hash(&row.sha256);
                    let mut parts = vec![Part::Value(&row.path), Part::Note(row.kind)];
                    if !row.sha256.is_empty() {
                        parts.push(Part::Note(&hash));
                    }
                    let hint = if row.sha256.is_empty() {
                        "Open the Executed files tab".to_owned()
                    } else {
                        format!("SHA-256 {}. Open the Executed files tab.", row.sha256)
                    };
                    rows::item(ui, &parts, &hint)
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
        let counts: Vec<(String, &str, bool)> = tactic_counts(details)
            .into_iter()
            .map(|(name, n)| (n.to_string(), name, false))
            .collect();
        rows::figures(ui, &counts);
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
                if rows::item(
                    ui,
                    &[Part::Name(&item.label)],
                    "Open this process's details",
                ) {
                    acts.push(Act::Process(item.key));
                }
            });
        }
        let sections = [
            ("of ".to_owned(), false),
            (scan.process.len().to_string(), true),
            (" processes \u{b7} ".to_owned(), false),
            (scan.counts.calls.to_string(), true),
            (" syscalls".to_owned(), false),
        ];
        if rows::counted_item(ui, &sections, "Open the Process tree") {
            acts.push(Act::Go(Destination::Tasks));
        }
    });
}

pub(super) fn files_row(ui: &mut egui::Ui, scan: &ArchiveScan, acts: &mut Vec<Act>) {
    let tab = |tab: FileTab| scan.counts.tabs[tab.slot() - 8];
    line(ui, "Files", |ui| {
        rows::figures(
            ui,
            &[
                (tab(FileTab::Created).to_string(), "created", true),
                (tab(FileTab::Executed).to_string(), "executed", true),
                (tab(FileTab::Deleted).to_string(), "deleted", true),
                (scan.counts.changed.to_string(), "changed", true),
            ],
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
            rows::figures(
                ui,
                &[
                    (endpoints.to_string(), "endpoints", true),
                    (scan.counts.dns.to_string(), "DNS", true),
                    (scan.counts.http.to_string(), "HTTP", true),
                ],
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

// SPDX-License-Identifier: GPL-3.0-only
//! The details of the selected indicator: its sources, process, the dataset
//! record that matched, what excused it and where its evidence is.
use super::{
    list::{jump_of, source_tone, Jump},
    *,
};
use antinomie_monitor_core::ioc::online;

fn row(ui: &mut egui::Ui, name: &str, value: &str, mono: bool) {
    ui.label(RichText::new(name).small().color(theme::muted()));
    let text = RichText::new(value).color(theme::text());
    ui.add(egui::Label::new(if mono { text.monospace() } else { text }).wrap());
    ui.end_row();
}

impl View {
    pub(super) fn detail(
        &mut self,
        ui: &mut egui::Ui,
        ioc: &IocScan,
        selected: Option<usize>,
    ) -> Option<Jump> {
        let Some(at) = selected else {
            ui.colored_label(
                theme::muted(),
                "Select a row to see its sources, process and dataset records.",
            );
            return None;
        };
        let (indicator, verdict) = (&ioc.indicators[at], self.verdicts[at].clone());
        let mut jump = None;
        presentation::frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(match indicator.ty {
                        Type::Endpoint => "Endpoint",
                        Type::Domain => "Domain",
                        Type::Url => "URL",
                        Type::Tls => "TLS session",
                        Type::File => "File",
                    })
                    .strong()
                    .color(theme::heading()),
                );
                verdict_chip(ui, &verdict);
            });
            let shown = if indicator.ty == Type::File { &indicator.path } else { &indicator.value };
            ui.add(egui::Label::new(RichText::new(shown).monospace().color(theme::text())).wrap());
            if ui.small_button("Copy").clicked() {
                let copy = indicator
                    .hashes
                    .as_ref()
                    .map_or_else(|| indicator.value.clone(), |hashes| hashes.sha256.clone());
                ui.ctx().copy_text(copy);
            }
            ui.add_space(4.0);
            egui::Grid::new(("ioc-facts", indicator.id()))
                .num_columns(2)
                .spacing(egui::vec2(10.0, 4.0))
                .show(ui, |ui| {
                    if let Some(hashes) = &indicator.hashes {
                        row(ui, "SHA-256", &hashes.sha256, true);
                        if !hashes.md5.is_empty() {
                            row(ui, "MD5", &hashes.md5, true);
                        }
                        if !hashes.sha1.is_empty() {
                            row(ui, "SHA-1", &hashes.sha1, true);
                        }
                    }
                    if let Some(tls) = &indicator.tls {
                        row(ui, "SNI", if tls.sni.is_empty() { "(none)" } else { &tls.sni }, true);
                        row(ui, "JA3", &tls.ja3, true);
                        row(ui, "JA4", &format!("{} · no feed", tls.ja4), true);
                        row(ui, "JA3S", &format!("{} · no feed", tls.ja3s), true);
                        row(ui, "Cert SHA-1", if tls.cert_sha1.is_empty() { "(not seen: TLS 1.3 encrypts it)" } else { &tls.cert_sha1 }, true);
                        row(ui, "ALPN", &tls.alpn, false);
                    }
                    row(ui, "Seen as", &indicator.sub, false);
                    row(ui, "Count", &indicator.count, false);
                    let process = match (&indicator.process, indicator.candidates.is_empty()) {
                        (Some(process), _) => process.label(),
                        (None, false) => format!(
                            "unattributed; candidates: {}",
                            indicator.candidates.iter().map(|p| p.label()).collect::<Vec<_>>().join(", ")
                        ),
                        (None, true) if indicator.sources.contains(&Source::Pcap) => {
                            "unattributed: the capture is VM-wide, and no one process made a matching call".to_owned()
                        }
                        (None, true) => "none: not seen in the run".to_owned(),
                    };
                    row(ui, "Process", &process, false);
                    row(
                        ui,
                        "First / last",
                        &format!("{} / {}", time_text_of(indicator.first_us), time_text_of(indicator.last_us)),
                        true,
                    );
                });
        });
        presentation::frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(theme::section_title(ui, "Sources"));
            for (source, line) in &indicator.details {
                ui.horizontal_wrapped(|ui| {
                    widgets::chip(ui, source.label(), source_tone(*source));
                    ui.add(egui::Label::new(RichText::new(line).color(theme::muted())).wrap());
                });
            }
        });
        presentation::frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::section_title(ui, "Match"));
                if let Some(date) = &verdict.date {
                    ui.colored_label(theme::muted(), format!("dataset {date}"));
                }
            });
            match verdict.outcome {
                Outcome::Matched | Outcome::KnownFp => {
                    let shown = verdict
                        .matches
                        .iter()
                        .chain(verdict.excused.as_ref().map(|(found, _)| found))
                        .take(4);
                    for found in shown {
                        let record = &found.record;
                        egui::Grid::new(("ioc-record", indicator.id(), &record.feed, &record.record_id))
                            .num_columns(2)
                            .spacing(egui::vec2(10.0, 3.0))
                            .show(ui, |ui| {
                                row(ui, "Dataset", &format!("{} · {}", ioc_scan::dataset_name(&record.feed), record.record_id), false);
                                row(ui, "Family", &record.family, false);
                                row(
                                    ui,
                                    "Confidence",
                                    &record.confidence.map_or("not given by this feed".to_owned(), |c| format!("{c}%")),
                                    false,
                                );
                                row(ui, "First seen", &record.first_seen, false);
                                row(ui, "Record", &record.detail, false);
                                row(ui, "Reference", &record.reference, true);
                            });
                        if let Some(at) = found.online_at {
                            ui.colored_label(
                                theme::muted(),
                                format!(
                                    "Found by the online check at {}. It is not in the local datasets.",
                                    crate::time_format::local_seconds(at)
                                ),
                            );
                        }
                        ui.separator();
                    }
                    if let Some((_, entry)) = &verdict.excused {
                        ui.label(RichText::new("Known false positive.").strong().color(theme::text()));
                        ui.add(egui::Label::new(RichText::new(&entry.reason).color(theme::muted())).wrap());
                        ui.colored_label(
                            theme::muted(),
                            format!(
                                "Entry for {}{} · added {}",
                                entry.value,
                                entry.dataset.as_ref().map_or(String::new(), |d| format!(" ({d})")),
                                feeds::date_text(entry.added_unix)
                            ),
                        );
                    }
                }
                Outcome::NoMatch => {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "Not found in the loaded feeds{}.",
                                if verdict.partial() {
                                    format!(" ({} of {} feeds for this type)", verdict.feeds_used, verdict.feeds_needed)
                                } else {
                                    String::new()
                                }
                            ))
                            .color(theme::muted()),
                        )
                        .wrap(),
                    );
                }
                Outcome::NotChecked => {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("Not checked: {}.", verdict.why)).color(theme::muted()),
                        )
                        .wrap(),
                    );
                }
            }
            ui.add_space(4.0);
            let eligible = online::eligible(indicator, &verdict);
            ui.horizontal_wrapped(|ui| {
                if !eligible.is_empty() {
                    let ready = self.online_on && self.job.is_none();
                    if ui
                        .add_enabled(ready, egui::Button::new("Check online"))
                        .on_hover_text(if self.online_on {
                            "Ask abuse.ch about this value only"
                        } else {
                            "Turn on online lookups first"
                        })
                        .clicked()
                    {
                        self.start_online(eligible.clone());
                    }
                }
                if verdict.outcome == Outcome::Matched
                    && verdict.matches.iter().all(|found| found.online_at.is_none())
                    && ui.button("Mark as false positive").clicked()
                {
                    self.mark(indicator, &verdict);
                }
            });
            if verdict.outcome == Outcome::Matched {
                ui.add(
                    egui::TextEdit::singleline(&mut self.reason)
                        .hint_text(theme::hint_text("Why is this harmless? (optional)"))
                        .desired_width(ui.available_width()),
                );
            }
        });
        presentation::frame().show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(
                RichText::new("Jump to evidence")
                    .strong()
                    .color(theme::heading()),
            );
            if indicator.evidence.is_empty() {
                ui.colored_label(
                    theme::muted(),
                    "No single call or packet stands for this row.",
                );
            }
            for evidence in &indicator.evidence {
                ui.horizontal_wrapped(|ui| {
                    widgets::chip(ui, evidence.source.label(), source_tone(evidence.source));
                    ui.add(
                        egui::Label::new(RichText::new(&evidence.label).color(theme::text()))
                            .wrap(),
                    );
                    if ui.small_button("Open").clicked() {
                        jump = jump_of(&evidence.jump);
                    }
                });
            }
        });
        jump
    }
}

fn time_text_of(us: Option<u64>) -> String {
    us.map_or("—".into(), crate::time_format::short_time_us)
}

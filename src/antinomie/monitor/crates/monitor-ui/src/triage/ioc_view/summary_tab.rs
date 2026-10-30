// SPDX-License-Identifier: GPL-3.0-only
//! The IOC window's Summary tab: a card per type, the matched indicators and
//! where the indicators came from.
use super::list::source_tone;
use super::*;

impl View {
    pub(super) fn summary_tab(&mut self, ui: &mut egui::Ui, ioc: &IocScan) -> Option<Tab> {
        let mut next = None;
        let total = self.count_of(None);
        egui::ScrollArea::vertical()
            .id_salt("ioc-summary")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for ty in Type::ALL {
                        let count = self.count_of(Some(ty));
                        let response = presentation::frame()
                            .fill(theme::panel())
                            .show(ui, |ui| {
                                ui.set_min_width(130.0);
                                ui.label(RichText::new(ty.label()).small().color(theme::muted()));
                                ui.label(
                                    RichText::new(count.all().to_string())
                                        .size(24.0)
                                        .strong()
                                        .color(theme::text()),
                                );
                                ui.horizontal_wrapped(|ui| {
                                    if count.matched > 0 {
                                        widgets::chip(ui, format!("{} matched", count.matched), Tone::Error);
                                    }
                                    if count.known_fp > 0 {
                                        widgets::chip(ui, format!("{} known FP", count.known_fp), Tone::Info);
                                    }
                                    if count.no_match > 0 {
                                        widgets::chip(ui, format!("{} no match", count.no_match), Tone::Plain);
                                    }
                                    if count.not_checked > 0 {
                                        widgets::chip(ui, format!("{} not checked", count.not_checked), Tone::Neutral);
                                    }
                                    if count.all() == 0 {
                                        widgets::chip(ui, "none", Tone::Plain);
                                    }
                                });
                            })
                            .response
                            .interact(egui::Sense::click());
                        if response.clicked() {
                            self.outcome = None;
                            next = Some(Tab::Of(ty));
                        }
                    }
                });
                ui.add_space(8.0);
                ui.label(
                    RichText::new(format!(
                        "Matched indicators · {} of {}{}",
                        total.matched,
                        total.all(),
                        if total.known_fp > 0 {
                            format!(", {} more filtered as known false positives", total.known_fp)
                        } else {
                            String::new()
                        }
                    ))
                    .strong()
                    .color(theme::heading()),
                )
                .on_hover_text(
                    "Click a row to open it in its tab. Known FP rows are not counted as matches.",
                );
                if ioc.scan.loaded.is_empty() {
                    // The banner above says that nothing was checked.
                } else if total.matched == 0 {
                    ui.colored_label(
                        theme::muted(),
                        format!(
                            "No match in datasets dated {}.",
                            ioc.scan.loaded.iter().map(|f| f.date.clone()).min().unwrap_or_default()
                        ),
                    );
                } else {
                    let matched: Vec<usize> = (0..ioc.indicators.len())
                        .filter(|&at| self.verdicts[at].outcome == Outcome::Matched)
                        .take(200)
                        .collect();
                    for at in matched {
                        let (indicator, verdict) = (&ioc.indicators[at], &self.verdicts[at]);
                        let Some(found) = verdict.primary() else {
                            continue;
                        };
                        let response = ui
                            .horizontal_wrapped(|ui| {
                                widgets::chip(ui, indicator.ty.label(), Tone::Plain);
                                ui.label(RichText::new(&indicator.value).monospace().color(theme::text()));
                                ui.colored_label(theme::muted(), &found.record.family);
                                ui.colored_label(theme::muted(), ioc_scan::dataset_name(&found.record.feed));
                                if found.online_at.is_some() {
                                    widgets::chip(ui, "online", Tone::Warn);
                                }
                                ui.colored_label(
                                    theme::muted(),
                                    found.record.confidence.map_or("—".to_owned(), |c| format!("{c}%")),
                                );
                                ui.colored_label(theme::muted(), &found.record.first_seen);
                            })
                            .response
                            .interact(egui::Sense::click());
                        if response.clicked() {
                            self.selected.insert(indicator.ty, indicator.id());
                            self.outcome = None;
                            next = Some(Tab::Of(indicator.ty));
                        }
                    }
                }
                ui.add_space(10.0);
                presentation::frame().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(theme::section_title(ui, "Where the indicators came from"));
                    let line = |ui: &mut egui::Ui, source: Source, text: String| {
                        ui.horizontal_wrapped(|ui| {
                            widgets::chip(ui, source.label(), source_tone(source));
                            ui.colored_label(theme::muted(), text);
                        });
                    };
                    line(
                        ui,
                        Source::Pcap,
                        match &ioc.capture {
                            Capture::Read => ioc.frames.map_or(
                                "Network capture, read by TShark".to_owned(),
                                |frames| format!("{frames} frames, read by TShark"),
                            ),
                            Capture::Off => "No network capture was recorded for this run".to_owned(),
                            Capture::Failed(error) => format!("The capture could not be read: {error}"),
                        },
                    );
                    line(ui, Source::Syscall, "Recorded calls: connect, sendto, execve and the files the run changed".into());
                    line(ui, Source::Static, "Strings and hashes of the sample".into());
                    if ioc.disk_notes.is_empty() {
                        line(
                            ui,
                            Source::Disk,
                            "No saved disk dump of this run: files are hashed from the recorded calls only (Disks > Dump)".into(),
                        );
                    }
                    for note in &ioc.disk_notes {
                        line(ui, Source::Disk, note.clone());
                    }
                });
                let mut families: BTreeMap<&str, usize> = BTreeMap::new();
                for (indicator, verdict) in ioc.indicators.iter().zip(&self.verdicts) {
                    let _ = indicator;
                    if let (Outcome::Matched, Some(found)) = (verdict.outcome, verdict.primary()) {
                        if !found.record.family.is_empty() {
                            *families.entry(found.record.family.as_str()).or_default() += 1;
                        }
                    }
                }
                ui.add_space(6.0);
                ui.label(theme::section_title(ui, "Families"));
                if families.is_empty() {
                    ui.colored_label(theme::muted(), "No family to show.");
                } else {
                    ui.horizontal_wrapped(|ui| {
                        for (family, count) in families {
                            widgets::chip(ui, format!("{family} ×{count}"), Tone::Error);
                        }
                    });
                }
            });
        next
    }
}

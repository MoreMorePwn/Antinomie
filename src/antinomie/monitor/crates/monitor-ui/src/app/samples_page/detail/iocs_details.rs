// SPDX-License-Identifier: GPL-3.0-only
//! The selected indicator of the IOCs tab in the shared Details pane: the
//! value, how and when it was seen, the stored dataset records that listed it,
//! and one line per run that had it, each with its way into that run's Triage.
use super::iocs::{check_online, key_of, note_reference, runs_text, shown, time_text, Go};
use super::{parts, *};
use eframe::egui::RichText;

impl MonitorApp {
    pub(super) fn ioc_details(&mut self, ui: &mut egui::Ui, data: &Arc<Data>) {
        let Some(detail) = self.samples_page.detail.as_mut() else {
            return;
        };
        let defanged = detail.iocs.defang;
        let key = detail.iocs.selected.clone();
        let have_key = detail.iocs.has_key(&self.options.data_dir);
        let row = key.and_then(|key| data.iocs.rows.iter().find(|row| key_of(row) == key));
        let Some(row) = row else {
            crate::widgets::info_panel(
                ui,
                &crate::widgets::InfoPanel {
                    icon: egui_phosphor::regular::LIST_MAGNIFYING_GLASS,
                    title: "Select an indicator to view its details",
                    about: "Details show where an indicator was seen, in which runs, how it was observed and which stored abuse.ch records list it.",
                    steps_title: "To see an indicator",
                    steps: &["Open the IOCs tab and select a row."],
                },
            );
            return;
        };
        let listed = data.iocs.listed.len();
        let mut go = None;
        crate::details_scroll::show(
            ui,
            "sample_ioc_details_scroll",
            format!("{}:{}", row.ty, row.value),
            |ui, _| {
                ui.add(
                    egui::Label::new(
                        RichText::new(shown(row, defanged))
                            .monospace()
                            .strong()
                            .color(theme::text()),
                    )
                    .wrap(),
                );
                ui.add_space(4.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Copy").clicked() {
                        ui.ctx().copy_text(shown(row, defanged));
                    }
                    if defanged && ui.button("Copy raw value").clicked() {
                        ui.ctx().copy_text(row.value.clone());
                    }
                    if ui.button("Add note…").clicked() {
                        self.samples_page.start_note(vec![note_reference(row)]);
                    }
                    check_online(ui, have_key, row, &mut go);
                });
                ui.add_space(4.0);
                egui::Grid::new("sample-ioc-facts")
                    .num_columns(2)
                    .spacing([12.0, 4.0])
                    .show(ui, |ui| {
                        let fact = |ui: &mut egui::Ui, name: &str, value: &str| {
                            ui.label(RichText::new(name).color(theme::muted()));
                            ui.add(egui::Label::new(value).wrap());
                            ui.end_row();
                        };
                        fact(
                            ui,
                            "Kind",
                            antinomie_monitor_core::samples::ioc_kind_label(&row.ty),
                        );
                        if !row.path.is_empty() {
                            fact(ui, "Path", &row.path);
                        }
                        if row.ty == "file" {
                            fact(ui, "SHA-256", &row.value);
                        }
                        fact(ui, "Seen in", &runs_text(row, listed));
                        fact(
                            ui,
                            "Every run",
                            if row.in_every_run(listed) {
                                "yes"
                            } else {
                                "no, only some runs"
                            },
                        );
                        fact(ui, "Observed", &row.observed().join(", "));
                        fact(ui, "First seen", &time_text(row.first_us()));
                        fact(ui, "Last seen", &time_text(row.last_us()));
                        let processes = row.processes();
                        if !processes.is_empty() {
                            fact(ui, "Process", &processes.join(", "));
                        }
                    });
                ui.add_space(6.0);
                ui.label(RichText::new("Detections").strong().color(theme::heading()));
                let hits = row.hits();
                if hits.is_empty() {
                    parts::muted_line(
                        ui,
                        "No stored abuse.ch record lists it. That is not a clean result.",
                    );
                }
                for hit in &hits {
                    ui.horizontal_wrapped(|ui| {
                        widgets::chip(ui, &hit.dataset, Tone::Error);
                        ui.label(&hit.family);
                        ui.label(RichText::new(&hit.record_id).color(theme::muted()));
                        if !hit.reference.is_empty() {
                            ui.label(RichText::new(&hit.reference).small().color(theme::muted()));
                        }
                    });
                }
                ui.add_space(6.0);
                ui.label(RichText::new("Runs").strong().color(theme::heading()));
                for seen in &row.sightings {
                    let entry = &seen.entry;
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(parts::run_name(seen.run)).color(theme::text()));
                        for source in &entry.sources {
                            widgets::chip(ui, source, crate::triage::ioc_source_tone(source));
                        }
                        ui.label(
                            RichText::new(format!(
                                "{} – {}",
                                time_text(entry.first_us),
                                time_text(entry.last_us)
                            ))
                            .monospace()
                            .color(theme::muted()),
                        );
                        let mut extra: Vec<&str> = Vec::new();
                        for text in [entry.count.as_str(), entry.process.as_str()] {
                            if !text.is_empty() {
                                extra.push(text);
                            }
                        }
                        if !extra.is_empty() {
                            ui.label(RichText::new(extra.join(" · ")).color(theme::muted()));
                        }
                        let folder = data
                            .runs
                            .iter()
                            .any(|run| run.number == seen.run && run.folder);
                        if ui
                            .add_enabled(folder, egui::Button::new("Open in Triage ›").small())
                            .on_disabled_hover_text("The run's folder was deleted")
                            .on_hover_text("Open this run in Triage at this indicator")
                            .clicked()
                        {
                            go = Some(Go::Triage(seen.run, key_of(row)));
                        }
                    });
                }
            },
        );
        self.apply_ioc_go(ui.ctx(), data, go);
    }
}

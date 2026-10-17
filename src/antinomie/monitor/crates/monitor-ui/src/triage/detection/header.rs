// SPDX-License-Identifier: MIT
//! The top of the Detection panel: engine tabs, the rule-set list, the scan
//! controls, the progress bar and the matched-rule summary.
use super::*;
use antinomie_monitor_core::ruleset::EngineSet;

pub(super) fn rule_set_title(sets: &[EngineSet]) -> String {
    let enabled = sets.iter().filter(|set| set.enabled).count();
    let rules: u64 = sets
        .iter()
        .filter(|set| set.enabled)
        .map(|set| set.rules)
        .sum();
    format!(
        "Rule sets: {enabled} enabled · {} {}",
        engine::group_digits(rules),
        if rules == 1 { "rule" } else { "rules" }
    )
}

pub(super) fn limitation_line(state: &State) -> Option<&'static str> {
    match state {
        State::Complete => None,
        State::Partial => Some("Limited: coverage is incomplete."),
        State::Unavailable => Some("Limited: this scan could not evaluate the evidence."),
        State::NoRules => Some("Limited: no rules are enabled."),
        State::Missing => Some("Limited: the evidence for this engine is missing."),
    }
}

pub(super) fn state(state: &State) -> &'static str {
    match state {
        State::Complete => "Complete",
        State::Partial => "Partial",
        State::Unavailable => "Unavailable",
        State::NoRules => "No rules enabled",
        State::Missing => "Evidence missing",
    }
}

/// "3 matched rules" and the colored state of the scan that produced them.
fn matched_summary(count: usize, state_value: &State) -> (String, egui::Color32) {
    let label = if count == 1 {
        "matched rule"
    } else {
        "matched rules"
    };
    let tone = match state_value {
        State::Complete => theme::blue(),
        State::Partial | State::NoRules | State::Missing => theme::warn(),
        State::Unavailable => theme::muted(),
    };
    (format!("{count} {label}"), tone)
}

impl View {
    pub(super) fn engine_tabs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            for engine in ENGINES {
                let selected = self.selected == engine;
                let label = if selected {
                    theme::palette().primary_text
                } else {
                    theme::text()
                };
                if ui
                    .add(
                        egui::Button::new(RichText::new(name(engine)).strong().color(label))
                            .selected(selected)
                            .min_size(egui::vec2(80.0, 32.0)),
                    )
                    .clicked()
                {
                    self.selected = engine;
                }
            }
        });
    }

    /// The collapsible list of installed packs and the Rule manager button.
    pub(super) fn rule_sets(&mut self, ui: &mut egui::Ui, index: usize) {
        let loading = self.registry_rx.is_some() && self.sets[index].is_empty();
        let title = if loading {
            "Rule sets: loading…".to_owned()
        } else {
            rule_set_title(&self.sets[index])
        };
        egui::CollapsingHeader::new(RichText::new(title).color(theme::text()))
            .id_salt(("detector-rule-sets", index))
            .default_open(false)
            .show(ui, |ui| {
                if self.sets[index].is_empty() {
                    ui.weak(if loading {
                        "Reading installed packs…"
                    } else {
                        "No packs or custom groups for this engine."
                    });
                }
                for set in &self.sets[index] {
                    ui.horizontal_wrapped(|ui| {
                        let rules = if set.rules == 1 { "rule" } else { "rules" };
                        ui.label(
                            RichText::new(format!(
                                "{} {} · {} {rules}",
                                set.name,
                                set.revision,
                                engine::group_digits(set.rules)
                            ))
                            .color(theme::text()),
                        );
                        if !set.enabled {
                            ui.label(RichText::new("disabled").small().color(theme::muted()));
                        }
                    });
                }
            });
        ui.horizontal_wrapped(|ui| {
            if ui.button("Rule manager…").clicked() {
                self.open_manager = true;
            }
        });
        if !self.notes[index].is_empty() {
            ui.colored_label(theme::warn(), &self.notes[index]);
        }
    }

    /// Scan, Cancel and the Result menu.
    pub(super) fn scan_controls(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        scan: Option<&ArchiveScan>,
    ) {
        ui.horizontal_wrapped(|ui| {
            let ready = self.rx.is_none() && self.identity.is_some();
            if ui.add_enabled(ready, egui::Button::new("Scan")).clicked() {
                let partial = !self.notes[index].is_empty();
                self.auto_key[index].clear();
                self.start(
                    ui.ctx(),
                    scan.and_then(|scan| scan.event_journal.as_ref())
                        .map(|summary| summary.sha256.clone()),
                    partial,
                );
            }
            if self.rx.is_some() {
                ui.spinner();
                if let Some(cancel) = &self.cancel {
                    if ui.button("Cancel").clicked() {
                        cancel.store(true, Ordering::Relaxed);
                    }
                }
            }
            if let Some((directory, _)) = &self.identity {
                let directory = engine::result_directory(directory, self.selected);
                ui.menu_button("Result", |ui| {
                    crate::evidence::menu(ui, &directory);
                    if let Some(Ok(report)) = &self.results[index] {
                        if ui.button("Copy result as JSON").clicked() {
                            match serde_json::to_string_pretty(report) {
                                Ok(json) => ui.ctx().copy_text(json),
                                Err(error) => self.bytes = Some(Err(error.to_string())),
                            }
                            ui.close_menu();
                        }
                    }
                });
            }
        });
    }

    pub(super) fn is_scanning(&self, index: usize) -> bool {
        self.busy == Some(index)
            || matches!(
                self.phase[index].as_str(),
                "queued" | "preparing" | "running"
            )
    }

    /// While scanning, one row holds the progress bar and, beside it, the
    /// matched-rule count and state. Otherwise the status line replaces the bar.
    pub(super) fn scan_status(&self, ui: &mut egui::Ui, index: usize, scanning: bool) {
        let matched = self.results[index]
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|report| (report.findings.len(), report.state.clone()));
        if scanning {
            let fraction = self.progress[index]
                .as_ref()
                .and_then(engine::progress_fraction);
            let label = match self.progress[index].as_ref() {
                Some(progress) => engine::progress_text(progress),
                None if self.phase[index].is_empty() => "running".to_owned(),
                None => self.phase[index].clone(),
            };
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some((count, state_value)) = &matched {
                        let (text, tone) = matched_summary(*count, state_value);
                        presentation::badge(ui, state(state_value), tone);
                        ui.label(RichText::new(text).color(theme::text()));
                    }
                    ui.add(
                        egui::ProgressBar::new(fraction.unwrap_or(0.0))
                            .animate(fraction.is_none())
                            .text(label)
                            .desired_width(ui.available_width()),
                    );
                });
            });
        } else {
            let status = match self.progress[index].as_ref() {
                Some(progress) => engine::progress_text(progress),
                None => self.phase[index].clone(),
            };
            if !status.is_empty() || matched.is_some() {
                ui.horizontal_wrapped(|ui| {
                    if !status.is_empty() {
                        ui.label(RichText::new(format!("Scan: {status}")).color(theme::muted()));
                    }
                    if let Some((count, state_value)) = &matched {
                        let (text, tone) = matched_summary(*count, state_value);
                        ui.label(RichText::new(text).color(theme::text()));
                        presentation::badge(ui, state(state_value), tone);
                    }
                });
            }
        }
        if let Some(line) = matched
            .as_ref()
            .and_then(|(_, state_value)| limitation_line(state_value))
        {
            ui.label(RichText::new(line).small().color(theme::warn()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{finding, frames, rendered_text, report};
    use super::*;

    fn panel_text(view: &mut View) -> String {
        let ctx = egui::Context::default();
        rendered_text(&frames(&ctx, 1, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.show(ui, None));
        }))
    }

    fn partial_view() -> View {
        let mut view = View::default();
        view.sets[0] = vec![EngineSet {
            name: "YARA-Forge Core".into(),
            revision: "20261004".into(),
            enabled: true,
            rules: 2094,
        }];
        let mut report = report(vec![finding(
            "sample",
            "Sample",
            vec![Evidence::Bytes {
                path: PathBuf::from("/tmp/specimen"),
                offset: Some(1),
                address: None,
                report_id: None,
                block: None,
            }],
        )]);
        report.state = State::Partial;
        report.scanned_objects = 1;
        report.scanned_rules = Some(2094);
        view.results[0] = Some(Ok(report));
        view.rows(0);
        view
    }

    #[test]
    fn rule_set_title_counts_only_enabled_sets() {
        let sets = vec![
            EngineSet {
                name: "Core".into(),
                revision: "20261004".into(),
                enabled: true,
                rules: 2094,
            },
            EngineSet {
                name: "Extra".into(),
                revision: "r2".into(),
                enabled: false,
                rules: 4,
            },
            EngineSet {
                name: "Local".into(),
                revision: "r1".into(),
                enabled: true,
                rules: 1,
            },
        ];
        assert_eq!(rule_set_title(&sets), "Rule sets: 2 enabled · 2,095 rules");
        assert_eq!(limitation_line(&State::Complete), None);
        assert_eq!(
            limitation_line(&State::Partial),
            Some("Limited: coverage is incomplete.")
        );
        assert!(limitation_line(&State::Missing)
            .unwrap()
            .starts_with("Limited:"));
    }

    #[test]
    fn detection_panel_drops_the_old_sections_and_keeps_rule_sets() {
        let mut view = partial_view();
        view.phase[0] = "idle".into();
        let joined = panel_text(&mut view);
        assert!(
            joined.contains("Rule sets: 1 enabled · 2,094 rules"),
            "{joined}"
        );
        assert!(joined.contains("1 matched rule"), "{joined}");
        assert!(
            joined.contains("Limited: coverage is incomplete."),
            "{joined}"
        );
        assert!(joined.contains("Scan: idle"), "{joined}");
        assert!(!joined.contains("Local rules and data sources"), "{joined}");
        assert!(!joined.contains("Coverage and provenance"), "{joined}");
        assert!(!joined.contains("Copy YARA-Forge"), "{joined}");
        assert!(!joined.contains("rule sample"), "{joined}");
    }

    #[test]
    fn the_status_line_is_hidden_while_scanning_and_the_bar_carries_the_text() {
        let mut view = partial_view();
        view.phase[0] = "running".into();
        let joined = panel_text(&mut view);
        assert!(!joined.contains("Scan: running"), "{joined}");
        // The bar shows the progress text; the result summary sits beside it.
        assert!(joined.contains("running"), "{joined}");
        assert!(joined.contains("1 matched rule"), "{joined}");
        assert!(joined.contains("Partial"), "{joined}");
    }
}

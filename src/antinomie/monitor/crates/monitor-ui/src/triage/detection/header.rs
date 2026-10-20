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

/// "3 matched rules · 2 succeeded, 1 failed, 1 skipped": the matches and what
/// happened to each input, which is what the scan result is made of.
fn matched_summary(report: &Report) -> String {
    let count = report.findings.len();
    let label = if count == 1 {
        "matched rule"
    } else {
        "matched rules"
    };
    let outcomes = report
        .inputs
        .as_deref()
        .map(super::inputs::outcome_counts)
        .unwrap_or_default();
    if outcomes.is_empty() {
        format!("{count} {label}")
    } else {
        format!("{count} {label} · {outcomes}")
    }
}

/// The color of an engine state badge.
fn state_tone(state_value: &State) -> egui::Color32 {
    match state_value {
        State::Complete => theme::blue(),
        State::Partial | State::NoRules | State::Missing => theme::warn(),
        State::Unavailable => theme::muted(),
    }
}

impl View {
    fn tab_count(&self, index: usize) -> super::super::counts::Count {
        use super::super::counts::Count;
        if self.is_scanning(index) || (self.rx.is_some() && self.busy.is_none()) {
            return Count::Pending;
        }
        if self.results[index]
            .as_ref()
            .is_some_and(|result| match result {
                Err(_) => true,
                Ok(report) => matches!(
                    report.state,
                    State::Unavailable | State::Missing | State::NoRules
                ),
            })
        {
            return Count::Unavailable;
        }
        self.counts[index]
            .as_ref()
            .map_or(Count::Unavailable, |counts| Count::Ready(counts.rules))
    }

    pub(super) fn engine_tabs(&mut self, ui: &mut egui::Ui) {
        crate::widgets::tab_row(ui, |ui| {
            for (index, engine) in ENGINES.into_iter().enumerate() {
                let selected = self.selected == engine;
                let count = self.tab_count(index);
                if super::super::counts::tab(ui, selected, name(engine), count, true) {
                    self.selected = engine;
                }
            }
        });
    }

    /// The collapsible list of installed packs; the Rule manager button sits
    /// on the same row as its title.
    pub(super) fn rule_sets(&mut self, ui: &mut egui::Ui, index: usize) {
        let loading = self.registry_rx.is_some() && self.sets[index].is_empty();
        let title = if loading {
            "Rule sets: loading…".to_owned()
        } else {
            rule_set_title(&self.sets[index])
        };
        let open = self.sets_open[index];
        let caret = if open {
            egui_phosphor::regular::CARET_DOWN
        } else {
            egui_phosphor::regular::CARET_RIGHT
        };
        let mut manager = false;
        let mut toggle = false;
        egui::Sides::new().show(
            ui,
            |ui| {
                ui.set_max_width((ui.available_width() - 140.0).max(80.0));
                if loading {
                    theme::spinner(ui);
                }
                toggle = ui
                    .add(
                        egui::Button::new(
                            RichText::new(format!("{caret} {title}")).color(theme::text()),
                        )
                        .frame(false)
                        .truncate(),
                    )
                    .on_hover_text("Show or hide the installed rule sets")
                    .clicked();
            },
            |ui| manager = ui.button("Rule manager…").clicked(),
        );
        self.open_manager |= manager;
        if toggle {
            self.sets_open[index] = !open;
        }
        if open {
            ui.indent(("detector-rule-sets", index), |ui| {
                if self.sets[index].is_empty() {
                    if loading {
                        theme::loading_weak(ui, "Reading installed packs…");
                    } else {
                        ui.weak("No packs or custom groups for this engine.");
                    }
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
                    if !set.source.is_empty() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(&set.source).small().color(theme::muted()),
                            )
                            .wrap(),
                        );
                    }
                }
            });
        }
    }

    /// The Scan row: Scan, Cancel and the Result menu on the left, and on the
    /// right the scan status, matched-rule count, state and evaluated counts.
    /// A narrow pane lets the status wrap below the buttons.
    pub(super) fn scan_controls(
        &mut self,
        ui: &mut egui::Ui,
        index: usize,
        scan: Option<&ArchiveScan>,
        scanning: bool,
    ) {
        let parts = self.status_parts(index, scanning);
        if ui.available_width() < SIDE_BY_SIDE_WIDTH {
            ui.horizontal_wrapped(|ui| {
                self.scan_buttons(ui, index, scan);
                for part in &parts {
                    part.show(ui);
                }
            });
        } else {
            egui::Sides::new().show(
                ui,
                |ui| self.scan_buttons(ui, index, scan),
                |ui| {
                    // Right-to-left: the first item added is the rightmost.
                    for part in parts.iter().rev() {
                        part.show(ui);
                    }
                },
            );
        }
    }

    fn scan_buttons(&mut self, ui: &mut egui::Ui, index: usize, scan: Option<&ArchiveScan>) {
        let ready = self.rx.is_none() && self.identity.is_some();
        if ui.add_enabled(ready, egui::Button::new("Scan")).clicked() {
            self.scan_now(ui.ctx(), index, scan);
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
    }

    /// What the Scan button and the Scan buttons of the scanned inputs start:
    /// the selected engine, over every one of its inputs.
    pub(super) fn scan_now(
        &mut self,
        ctx: &egui::Context,
        index: usize,
        scan: Option<&ArchiveScan>,
    ) {
        let partial = !self.notes[index].is_empty();
        self.auto_key[index].clear();
        self.start(
            ctx,
            scan.and_then(|scan| scan.event_journal.as_ref())
                .map(|summary| summary.sha256.clone()),
            partial,
        );
    }

    pub(super) fn is_scanning(&self, index: usize) -> bool {
        self.busy == Some(index)
            || matches!(
                self.phase[index].as_str(),
                "queued" | "preparing" | "running"
            )
    }

    /// Left to right: the scan status (only when no scan runs), the matched
    /// rules, their state and how much was evaluated.
    fn status_parts(&self, index: usize, scanning: bool) -> Vec<StatusPart> {
        let mut parts = Vec::new();
        if !scanning {
            let status = match self.progress[index].as_ref() {
                Some(progress) => engine::progress_text(progress),
                None => self.phase[index].clone(),
            };
            if !status.is_empty() {
                parts.push(StatusPart::Muted(format!("Scan: {status}")));
            }
        }
        if let Some(Ok(report)) = self.results[index].as_ref() {
            parts.push(StatusPart::Count(matched_summary(report)));
            // Input outcomes speak for a complete scan; only a limit of the
            // engine itself (or a result saved without inputs) gets a badge.
            if report.state != State::Complete || report.inputs.is_none() {
                parts.push(StatusPart::Badge(
                    state(&report.state),
                    state_tone(&report.state),
                ));
            }
            let (short, long) = evaluated_text(report);
            parts.push(StatusPart::Evaluated(short, long));
        }
        parts
    }

    /// While scanning, the progress bar has a row of its own.
    pub(super) fn scan_progress(&self, ui: &mut egui::Ui, index: usize) {
        let fraction = self.progress[index]
            .as_ref()
            .and_then(engine::progress_fraction);
        let label = match self.progress[index].as_ref() {
            Some(progress) => engine::progress_text(progress),
            None if self.phase[index].is_empty() => "running".to_owned(),
            None => self.phase[index].clone(),
        };
        ui.add(
            egui::ProgressBar::new(fraction.unwrap_or(0.0))
                .animate(fraction.is_none())
                .text(label)
                .desired_width(ui.available_width()),
        );
    }

    /// One muted line for limits of the result, with the full wording on hover.
    pub(super) fn notes_line(&self, ui: &mut egui::Ui, index: usize) {
        let mut short = Vec::new();
        let mut long = Vec::new();
        let mut note = |brief: String, full: String| {
            short.push(brief);
            long.push(full);
        };
        if let Some(Ok(report)) = self.results[index].as_ref() {
            if let Some(line) = limitation_line(&report.state) {
                note(line.to_owned(), line.to_owned());
            }
            if report.omitted_evidence > 0 {
                note(
                    format!(
                        "{} evidence locations not previewed",
                        engine::group_digits(report.omitted_evidence)
                    ),
                    format!(
                        "{} evidence locations exceed the preview or have no recorded position",
                        report.omitted_evidence
                    ),
                );
            }
        }
        if !self.notes[index].is_empty() {
            note(self.notes[index].clone(), self.notes[index].clone());
        }
        if short.is_empty() {
            return;
        }
        crate::activity::warning_details(ui, short.join(" · "), long.join("\n"));
    }
}

/// Narrower rows stack the status under the scan buttons.
const SIDE_BY_SIDE_WIDTH: f32 = 780.0;

/// One item of the status cluster beside the scan buttons.
enum StatusPart {
    Muted(String),
    Count(String),
    Badge(&'static str, egui::Color32),
    /// Short text and the longer wording shown on hover.
    Evaluated(String, String),
}

impl StatusPart {
    fn show(&self, ui: &mut egui::Ui) {
        // Whole items move to the next row; none breaks across rows.
        let label = |text: RichText| egui::Label::new(text).wrap_mode(egui::TextWrapMode::Extend);
        match self {
            Self::Muted(text) => {
                ui.add(label(RichText::new(text).color(theme::muted())));
            }
            Self::Count(text) => {
                ui.add(label(RichText::new(text).color(theme::text())));
            }
            Self::Badge(text, tone) => presentation::badge(ui, text, *tone),
            Self::Evaluated(short, long) => {
                ui.add(label(RichText::new(short).small().color(theme::muted())))
                    .on_hover_text(long);
            }
        }
    }
}

/// "1 object · 2,096 rules evaluated" and the same in full words.
fn evaluated_text(report: &Report) -> (String, String) {
    let objects = engine::group_digits(report.scanned_objects);
    let noun = if report.scanned_objects == 1 {
        "object"
    } else {
        "objects"
    };
    let rules = report.scanned_rules.map_or_else(
        || "Unknown rules".to_owned(),
        |count| {
            format!(
                "{} {}",
                engine::group_digits(count),
                if count == 1 { "rule" } else { "rules" }
            )
        },
    );
    (
        format!("{objects} {noun} · {rules} evaluated"),
        format!("{objects} {noun} evaluated · {rules} evaluated"),
    )
}

#[cfg(test)]
mod tests {
    use super::super::tests::{finding, frames, rendered_text, report};
    use super::*;
    use antinomie_monitor_core::analysis::detection::{InputOutcome, ScannedInput};

    #[test]
    fn engine_tab_badges_use_all_findings_and_show_pending_and_zero() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut view = View::default();
        view.counts[0] = Some(Counts {
            rules: 1234,
            occurrences: 9999,
            references: Default::default(),
        });
        view.counts[1] = Some(Counts {
            rules: 0,
            occurrences: 0,
            references: Default::default(),
        });
        view.phase[2] = "running".into();
        let output = frames(&ctx, 3, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.engine_tabs(ui));
        });
        let texts = rendered_text(&output);
        for label in ["YARA", "IDS", "Sigma", "1,234", "0", "…"] {
            assert!(texts.contains(label), "{texts}");
        }
        for state in [State::Missing, State::Unavailable, State::NoRules] {
            let mut missing = report(Vec::new());
            missing.state = state;
            view.results[1] = Some(Ok(missing));
            assert_eq!(
                view.tab_count(1),
                super::super::super::counts::Count::Unavailable
            );
        }
    }

    #[test]
    fn rule_sets_loading_shows_a_spinner_only_while_the_registry_loads() {
        let ctx = egui::Context::default();
        let mut view = View::default();
        view.sets_open[0] = true;
        let (_tx, rx) = std::sync::mpsc::channel();
        view.registry_rx = Some(rx);
        let draw = |view: &mut View| {
            frames(&ctx, 2, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.rule_sets(ui, 0));
            })
        };
        let loading = draw(&mut view);
        assert!(rendered_text(&loading).contains("Reading installed packs…"));
        // The title button and the body line each carry one.
        assert_eq!(theme::spinners_in(&loading), 2);
        view.registry_rx = None;
        let done = draw(&mut view);
        assert!(rendered_text(&done).contains("No packs or custom groups"));
        assert_eq!(theme::spinners_in(&done), 0);
    }

    #[test]
    fn scanning_shows_a_spinner_beside_cancel() {
        let ctx = egui::Context::default();
        let mut view = View::default();
        let (_tx, rx) = std::sync::mpsc::channel();
        view.rx = Some(rx);
        view.cancel = Some(Arc::new(AtomicBool::new(false)));
        let draw = |view: &mut View| {
            frames(&ctx, 2, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| view.scan_buttons(ui, 0, None));
            })
        };
        let running = draw(&mut view);
        assert!(rendered_text(&running).contains("Cancel"));
        assert_eq!(theme::spinners_in(&running), 1);
        view.rx = None;
        assert_eq!(theme::spinners_in(&draw(&mut view)), 0);
    }

    fn panel_text(view: &mut View) -> String {
        let ctx = egui::Context::default();
        rendered_text(&frames(&ctx, 1, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| view.show(ui, None));
        }))
    }

    fn input(outcome: InputOutcome) -> ScannedInput {
        ScannedInput {
            outcome,
            reason: "reason".into(),
            ..ScannedInput::default()
        }
    }

    fn scanned_view() -> View {
        let mut view = View::default();
        view.sets[0] = vec![EngineSet {
            name: "YARA-Forge Core".into(),
            revision: "20261004".into(),
            enabled: true,
            rules: 2094,
            source: String::new(),
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
        report.inputs = Some(vec![
            input(InputOutcome::Succeeded),
            input(InputOutcome::Failed),
            input(InputOutcome::Skipped),
        ]);
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
                source: String::new(),
            },
            EngineSet {
                name: "Extra".into(),
                revision: "r2".into(),
                enabled: false,
                rules: 4,
                source: String::new(),
            },
            EngineSet {
                name: "Local".into(),
                revision: "r1".into(),
                enabled: true,
                rules: 1,
                source: String::new(),
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
        let mut view = scanned_view();
        view.phase[0] = "idle".into();
        let joined = panel_text(&mut view);
        assert!(
            joined.contains("Rule sets: 1 enabled · 2,094 rules"),
            "{joined}"
        );
        assert!(joined.contains("1 matched rule"), "{joined}");
        assert!(joined.contains("Scan: idle"), "{joined}");
        assert!(!joined.contains("Local rules and data sources"), "{joined}");
        assert!(!joined.contains("Coverage and provenance"), "{joined}");
        assert!(!joined.contains("Copy YARA-Forge"), "{joined}");
        assert!(!joined.contains("rule sample"), "{joined}");
    }

    #[test]
    fn the_status_line_is_hidden_while_scanning_and_the_bar_carries_the_text() {
        let mut view = scanned_view();
        view.phase[0] = "running".into();
        let joined = panel_text(&mut view);
        assert!(!joined.contains("Scan: running"), "{joined}");
        // The bar shows the progress text; the result summary sits beside it.
        assert!(joined.contains("running"), "{joined}");
        assert!(
            joined.contains("1 matched rule · 1 succeeded, 1 failed, 1 skipped"),
            "{joined}"
        );
    }

    #[test]
    fn the_scan_result_shows_outcome_counts_and_never_partial_for_input_problems() {
        let mut view = scanned_view();
        view.phase[0] = "idle".into();
        let joined = panel_text(&mut view);
        assert!(
            joined.contains("1 matched rule · 1 succeeded, 1 failed, 1 skipped"),
            "{joined}"
        );
        let lower = joined.to_lowercase();
        for word in ["partial", "complete", "limited"] {
            assert!(!lower.contains(word), "{word}: {joined}");
        }
        // A real engine limit still has its badge; results saved without
        // inputs keep the state badge they always had.
        let Some(Ok(report)) = view.results[0].as_mut() else {
            unreachable!()
        };
        report.state = State::Partial;
        assert!(panel_text(&mut view).contains("Partial"));
        let Some(Ok(report)) = view.results[0].as_mut() else {
            unreachable!()
        };
        report.state = State::Complete;
        report.inputs = None;
        let old = panel_text(&mut view);
        assert!(
            old.contains("1 matched rule") && old.contains("Complete"),
            "{old}"
        );
        assert!(!old.contains("succeeded"), "{old}");
    }

    /// Every painted text of a pane of the given size, in paint order.
    fn pane_texts(view: &mut View, size: egui::Vec2, above: f32) -> Vec<(String, egui::Rect)> {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut shapes = Vec::new();
        for _ in 0..3 {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        // Stands in for the run selector and section tabs above.
                        ui.add_space(above);
                        view.show(ui, None)
                    });
                },
            );
            shapes = output.shapes;
        }
        let mut texts = Vec::new();
        for shape in &shapes {
            super::super::tests::each_galley_rect(&shape.shape, &mut |text, rect| {
                texts.push((text.to_owned(), rect));
            });
        }
        texts
    }

    /// The text equal to `needle`, else the first that contains it ("Scan"
    /// must find the button, not "Scanned inputs").
    fn rect_of(texts: &[(String, egui::Rect)], needle: &str) -> egui::Rect {
        texts
            .iter()
            .find(|(text, _)| text == needle)
            .or_else(|| texts.iter().find(|(text, _)| text.contains(needle)))
            .unwrap_or_else(|| panic!("{needle} is not painted: {texts:?}"))
            .1
    }

    #[test]
    fn first_match_card_is_visible_in_a_docked_pane() {
        let mut view = scanned_view();
        view.phase[0] = "canceled".into();
        let size = egui::vec2(900.0, 600.0);
        // Triage's run selector and section tabs take about 120 points.
        let texts = pane_texts(&mut view, size, 120.0);
        let title = rect_of(&texts, "Sample");
        let details = rect_of(&texts, "Details…");
        assert!(
            title.max.y <= size.y && details.max.y <= size.y,
            "card title {title:?}"
        );
        assert!(title.min.y < size.y * 0.7, "card title {title:?}");
    }

    #[test]
    fn status_and_counts_sit_right_of_the_scan_button_on_one_row() {
        let mut view = scanned_view();
        view.phase[0] = "canceled".into();
        let texts = pane_texts(&mut view, egui::vec2(900.0, 600.0), 0.0);
        let scan = rect_of(&texts, "Scan");
        for needle in [
            "Scan: canceled",
            "1 matched rule · 1 succeeded, 1 failed, 1 skipped",
            "1 object · 2,094 rules evaluated",
        ] {
            let item = rect_of(&texts, needle);
            assert!(item.min.x > scan.max.x, "{needle} is not right of Scan");
            assert!(
                (item.center().y - scan.center().y).abs() < 6.0,
                "{needle} is on another row: {item:?} vs {scan:?}"
            );
        }
        // Counts are the rightmost item; the separate counts block is gone.
        assert!(rect_of(&texts, "rules evaluated").min.x > rect_of(&texts, "1 matched rule").max.x);
        assert!(!texts
            .iter()
            .any(|(text, _)| text.contains("objects evaluated")));
        // The rule-set title and the manager button share a row.
        let sets = rect_of(&texts, "Rule sets");
        let manager = rect_of(&texts, "Rule manager");
        assert!((sets.center().y - manager.center().y).abs() < 6.0);
    }

    #[test]
    fn a_narrow_pane_wraps_the_status_below_the_scan_buttons() {
        let mut view = scanned_view();
        view.phase[0] = "canceled".into();
        let size = egui::vec2(420.0, 600.0);
        let texts = pane_texts(&mut view, size, 0.0);
        let counts = rect_of(&texts, "rules evaluated");
        assert!(counts.max.x <= size.x, "counts are clipped: {counts:?}");
        assert!(counts.min.y > rect_of(&texts, "Scan").max.y);
    }
}

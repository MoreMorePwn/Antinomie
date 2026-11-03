// SPDX-License-Identifier: GPL-3.0-only
//! What a category says when a bound cut its result short: the sentence for
//! each bound, and the buttons that change it or try again.
use super::ReportAction;
use antinomie_monitor_core::{
    AnalysisKind, AnalysisLimit, AnalysisLimitKind, AnalysisReport, AnalysisSection, AnalysisState,
    TIME_LIMIT_MAX_MINUTES,
};
use eframe::egui;

/// The time limit a rerun of `limit`'s tool gets: twice the one that was hit,
/// up to what a run may ask for. None once it is already the longest.
pub(in crate::analysis) fn doubled(limit: &AnalysisLimit) -> Option<u64> {
    let most = u64::from(TIME_LIMIT_MAX_MINUTES) * 60;
    let seconds = limit.seconds.filter(|&seconds| seconds > 0)?;
    (seconds < most).then(|| (seconds * 2).min(most))
}

/// One warning per bound the category met. A time limit also offers to run
/// the check again with twice the time and to open the setting.
pub(super) fn notes(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    section: &AnalysisSection,
    first_shown: bool,
) -> Option<ReportAction> {
    let mut action = None;
    let finished = matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    );
    for (at, limit) in section.limits.iter().enumerate() {
        // The first note's sentence stands at the badge; its buttons stay here.
        if limit.kind == AnalysisLimitKind::Text {
            // How much of a long value the report keeps is information, not
            // a limit of the check: a muted Info note, never a warning. The
            // setting that keeps more stays one click away.
            crate::activity::info(ui, value_note(&limit.text));
        } else if !(first_shown && at == 0) {
            crate::activity::warning(ui, &limit.text);
        }
        if limit.kind != AnalysisLimitKind::Time {
            // A bound a setting raises leads to that setting's field; the rest
            // (a file that disagrees with itself, an unpacking depth) are fixed.
            if let Some(setting) = limit.setting
                && ui
                    .small_button("Analysis settings…")
                    .on_hover_text("Open Settings > Analysis at the setting that raises this bound")
                    .clicked()
            {
                action = Some(ReportAction::OpenAnalysisLimit(setting));
            }
            continue;
        }
        ui.horizontal_wrapped(|ui| {
            if let Some(seconds) = doubled(limit)
                && section.kind != AnalysisKind::Regex
            {
                let label = format!("Run again with 2× time ({})", antinomie_monitor_core::analysis::duration_text(seconds));
                if ui
                    .add_enabled(finished, egui::Button::new(label))
                    .on_hover_text(
                        "Run this check again, alone, with twice the time it had; the rest of the analysis is not repeated",
                    )
                    .on_disabled_hover_text("Wait for the analysis to finish")
                    .clicked()
                {
                    action = Some(ReportAction::RunCheckLonger {
                        report_id: report.id.clone(),
                        kind: section.kind,
                        seconds,
                    });
                }
            }
            if ui
                .button("Time limit settings…")
                .on_hover_text("Open Settings, where the time each analysis tool may run is set")
                .clicked()
            {
                action = Some(ReportAction::OpenAnalysisSettings);
            }
        });
    }
    action
}

/// The note of a shortened value, saying where the whole of it is (reports
/// from before 0.8.0 did not).
pub(in crate::analysis) fn value_note(text: &str) -> String {
    if text.contains("specimen") {
        text.to_owned()
    } else {
        format!("{text} The full bytes are in the specimen.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::LimitSetting;

    fn limit(seconds: Option<u64>) -> AnalysisLimit {
        AnalysisLimit {
            kind: AnalysisLimitKind::Time,
            text: "capa ran out of time".into(),
            seconds,
            setting: None,
        }
    }

    #[test]
    fn a_rerun_gets_twice_the_time_up_to_the_most_a_run_may_ask_for() {
        assert_eq!(doubled(&limit(Some(240))), Some(480));
        let most = u64::from(TIME_LIMIT_MAX_MINUTES) * 60;
        assert_eq!(doubled(&limit(Some(most - 60))), Some(most));
        assert_eq!(doubled(&limit(Some(most))), None);
        assert_eq!(doubled(&limit(None)), None);
        assert_eq!(doubled(&limit(Some(0))), None);
    }

    fn report_with(limit: AnalysisLimit) -> (AnalysisReport, usize) {
        let mut section = AnalysisSection::new(AnalysisKind::Strings);
        section.state = antinomie_monitor_core::AnalysisSectionState::Partial;
        section.limits = vec![limit];
        let report = AnalysisReport {
            id: "r1".into(),
            state: AnalysisState::Complete,
            source_path: "/fixture/sample".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: vec![section],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
            limits: None,
        };
        (report, 0)
    }

    /// Draw the warnings of the section and press the button called `label`.
    fn press(
        report: &AnalysisReport,
        at: usize,
        label: &str,
    ) -> (Vec<String>, Option<ReportAction>) {
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut shown = Vec::new();
        let mut action = None;
        // The first frame lays the buttons out; the pointer then presses one.
        let mut rect: Option<egui::Rect> = None;
        for step in 0..3 {
            let mut events = Vec::new();
            if let (2, Some(rect)) = (step, rect) {
                let pos = rect.center();
                events = vec![
                    egui::Event::PointerMoved(pos),
                    egui::Event::PointerButton {
                        pos,
                        button: egui::PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ];
            }
            let output = ctx.run_ui(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |root| {
                    egui::CentralPanel::default().show(root, |ui| {
                        if let Some(next) = notes(ui, report, &report.sections[at], false) {
                            action = Some(next);
                        }
                    });
                },
            );
            let found = crate::app::tests::texts(&output);
            rect = found
                .iter()
                .find(|(text, _)| text == label)
                .map(|(_, rect)| *rect);
            shown = found.into_iter().map(|(text, _)| text).collect();
        }
        // Release on the next frame completes the click.
        let pos = rect.unwrap_or(egui::Rect::ZERO).center();
        let _ = ctx.run_ui(
            egui::RawInput {
                events: vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            },
            |root| {
                egui::CentralPanel::default().show(root, |ui| {
                    if let Some(next) = notes(ui, report, &report.sections[at], false) {
                        action = Some(next);
                    }
                });
            },
        );
        (shown, action)
    }

    #[test]
    fn a_row_size_or_text_limit_has_a_button_to_the_field_that_raises_it() {
        for (kind, setting) in [
            (AnalysisLimitKind::Rows, LimitSetting::Rows),
            (AnalysisLimitKind::Size, LimitSetting::Listing),
            (AnalysisLimitKind::Text, LimitSetting::Value),
            (AnalysisLimitKind::Size, LimitSetting::FlossFile),
        ] {
            let (report, at) = report_with(AnalysisLimit {
                kind,
                text: "A bound was met.".into(),
                seconds: None,
                setting: Some(setting),
            });
            let (shown, action) = press(&report, at, "Analysis settings…");
            // A shortened value's note also says where the whole value is.
            let note = if kind == AnalysisLimitKind::Text {
                value_note("A bound was met.")
            } else {
                "A bound was met.".to_owned()
            };
            assert!(shown.contains(&note), "{shown:?}");
            assert!(
                matches!(action, Some(ReportAction::OpenAnalysisLimit(found)) if found == setting),
                "{kind:?}: {shown:?}"
            );
        }
    }

    #[test]
    fn a_bound_no_setting_raises_has_no_button() {
        let (report, at) = report_with(AnalysisLimit {
            kind: AnalysisLimitKind::Input,
            text: "A bound was met.".into(),
            seconds: None,
            setting: None,
        });
        let (shown, action) = press(&report, at, "Analysis settings…");
        assert!(shown.iter().any(|text| text == "A bound was met."));
        assert!(!shown.iter().any(|text| text == "Analysis settings…"));
        assert!(action.is_none());
    }

    #[test]
    fn a_time_limit_keeps_its_own_buttons() {
        let (report, at) = report_with(limit(Some(240)));
        let (shown, action) = press(&report, at, "Time limit settings…");
        assert!(
            shown.iter().any(|text| text == "Time limit settings…"),
            "{shown:?}"
        );
        assert!(!shown.iter().any(|text| text == "Analysis settings…"));
        assert!(matches!(action, Some(ReportAction::OpenAnalysisSettings)));
    }

    #[test]
    fn durations_read_as_minutes_and_seconds() {
        assert_eq!(
            antinomie_monitor_core::analysis::duration_text(480),
            "8 minutes"
        );
        assert_eq!(
            antinomie_monitor_core::analysis::duration_text(90),
            "1 minute 30 seconds"
        );
        assert_eq!(
            antinomie_monitor_core::analysis::duration_text(60),
            "1 minute"
        );
    }
}

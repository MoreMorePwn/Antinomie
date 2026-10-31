// SPDX-License-Identifier: GPL-3.0-only
//! What a category says when a bound cut its result short: the sentence for
//! each bound, and the buttons that change it or try again.
use super::ReportAction;
use antinomie_monitor_core::{
    AnalysisKind, AnalysisLimit, AnalysisLimitKind, AnalysisReport, AnalysisSection, AnalysisState,
    LimitSetting, TIME_LIMIT_MAX_MINUTES,
};
use eframe::egui;

/// "4 minutes", "90 seconds" or "1 minute 30 seconds".
pub(in crate::analysis) fn duration_text(seconds: u64) -> String {
    let (minutes, rest) = (seconds / 60, seconds % 60);
    let plural =
        |count: u64, unit: &str| format!("{count} {unit}{}", if count == 1 { "" } else { "s" });
    match (minutes, rest) {
        (0, rest) => plural(rest, "second"),
        (minutes, 0) => plural(minutes, "minute"),
        (minutes, rest) => format!("{} {}", plural(minutes, "minute"), plural(rest, "second")),
    }
}

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
) -> Option<ReportAction> {
    let mut action = None;
    let finished = matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    );
    for limit in &section.limits {
        crate::activity::warning(ui, &limit.text);
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
                let label = format!("Run again with 2× time ({})", duration_text(seconds));
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

#[cfg(test)]
mod tests {
    use super::*;

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
            let output = ctx.run(
                egui::RawInput {
                    events,
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| {
                        if let Some(next) = notes(ui, report, &report.sections[at]) {
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
        let _ = ctx.run(
            egui::RawInput {
                events: vec![egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    if let Some(next) = notes(ui, report, &report.sections[at]) {
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
            assert!(
                shown.iter().any(|text| text == "A bound was met."),
                "{shown:?}"
            );
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
        assert_eq!(duration_text(480), "8 minutes");
        assert_eq!(duration_text(90), "1 minute 30 seconds");
        assert_eq!(duration_text(60), "1 minute");
    }
}

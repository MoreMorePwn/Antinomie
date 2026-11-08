// SPDX-License-Identifier: GPL-3.0-only
//! Triage for a run that never started: no recording, so no tabs; why it did
//! not start, the request, the sample and the static analysis there is, and
//! the button for its short report.
use super::*;

/// The page. Returns whether Export report… was pressed.
pub(crate) fn not_started_panel(ui: &mut egui::Ui, run: &NotStartedRun) -> bool {
    let mut export = false;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.label(theme::section_title(ui, "This run did not start"));
            ui.add_space(4.0);
            ui.add(
                egui::Label::new(RichText::new(&run.reason).color(theme::error()))
                    .wrap()
                    .selectable(true),
            );
            if !run.detail.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(&run.detail).small().color(theme::muted()))
                        .wrap()
                        .selectable(true),
                );
            }
            ui.add_space(8.0);
            ui.add(
                egui::Label::new(
                    RichText::new(
                        "A run that did not start recorded nothing, so there are no tabs to \
                         read. Its report holds the request, the failure, the static analysis \
                         and the sample's identity.",
                    )
                    .small()
                    .color(theme::muted()),
                )
                .wrap(),
            );
            ui.add_space(8.0);
            if !run.request.is_empty() {
                crate::widgets::fact_line(ui, "Request", &run.request);
            }
            if let Some(sample) = &run.sample {
                crate::widgets::fact_line(ui, "Sample", &sample.name);
                crate::widgets::fact_line(ui, "SHA-256", &sample.sha256);
            }
            if !run.route.is_empty() {
                crate::widgets::fact_line(ui, "Route", &run.route);
            }
            if !run.environment.is_empty() {
                crate::widgets::fact_line(ui, "Environment", &run.environment);
            }
            ui.add_space(8.0);
            ui.label(theme::section_title(ui, "Static analysis"));
            if run.static_analysis.is_empty() {
                ui.weak("None was recorded for this run.");
            }
            for (check, found) in &run.static_analysis {
                crate::widgets::fact_line(ui, check, found);
            }
            ui.add_space(10.0);
            if ui
                .button("Export report…")
                .on_hover_text("Write this run's short report: the failure, the request, the static analysis and the sample")
                .clicked()
            {
                export = true;
            }
        });
    export
}

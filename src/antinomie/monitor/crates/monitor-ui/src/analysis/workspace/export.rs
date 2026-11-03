// SPDX-License-Identifier: GPL-3.0-only
//! The Export and Open result directory buttons of a report or a category.
use super::*;

/// Export operations are explicit UI actions; no file or tool IO runs here.
/// Both callers draw them in a row that already wraps: a wrapping row of
/// their own would get only the width left and squeeze each button's words
/// one under another (the report header at 1100 px).
pub(super) fn export_controls(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    kind: Option<AnalysisKind>,
    directory: bool,
) -> Option<ReportAction> {
    let mut action = None;
    ui.menu_button(if kind.is_some() { "Export category…" } else { "Export report…" }, |ui| {
        for (label, format) in [("Plain text (.txt)", AnalysisExportFormat::Text), ("Structured results (.json)", AnalysisExportFormat::Json)] {
            if ui.button(label).clicked() {
                action = Some(ReportAction::Export { report_id: report.id.clone(), kind, format });
                ui.close();
            }
        }
        if kind.is_none() || kind == Some(AnalysisKind::Decompilation) {
            let retained = report.sections.iter().any(|s| s.summary.contains("native Ghidra project retained"));
            if ui.add_enabled(retained, egui::Button::new("Native Ghidra project (.gpr + .rep)"))
                .on_disabled_hover_text("A native project is available after a successful Ghidra analysis with project retention. Older and radare2 reports export as text.").clicked() {
                action = Some(ReportAction::Export { report_id: report.id.clone(), kind: Some(AnalysisKind::Decompilation), format: AnalysisExportFormat::GhidraProject });
                ui.close();
            }
            if ui.add_enabled(retained, egui::Button::new("Open in Ghidra"))
                .on_disabled_hover_text("No native Ghidra project retained for this report").clicked() {
                action = Some(ReportAction::OpenGhidra { report_id: report.id.clone() });
                ui.close();
            }
        }
    })
    .response
    .on_hover_text("Exports include all retained rows");
    if directory
        && ui
            .button("Open result directory")
            .on_hover_text(
                "Show retained report, specimen, complete listings and any native artifacts",
            )
            .clicked()
    {
        action = Some(ReportAction::ShowDirectory {
            report_id: report.id.clone(),
        });
    }
    action
}

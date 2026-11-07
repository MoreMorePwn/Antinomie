// SPDX-License-Identifier: GPL-3.0-only
//! The Overview's Categories card: one row per analysis category.
use super::*;

/// Every category the analysis can run: its state and size, a name that
/// opens its tab and the way to open it in a separate pane. One this report
/// does not have is listed disabled, with the reason as its tooltip.
pub(super) fn categories(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    state: &mut WorkspaceState,
    pair: Option<(&str, usize)>,
) -> Option<ReportAction> {
    use crate::widgets::Tone;
    let mut action = None;
    // Checks can be added to an analysis that is not being made.
    let finished = matches!(
        report.state,
        AnalysisState::Complete | AnalysisState::Partial
    );
    // One column of state tags, as wide as the longest word, so the tags line
    // up from one category to the next; the counts and buttons line up too.
    let tag_width = crate::widgets::chip_width(ui, TAG_WORDS);
    let regex_total = state.regex.total();
    // As wide as the longest count shown, so a narrow pane keeps it in view.
    let rows_width = {
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let widest = report
            .sections
            .iter()
            .map(|section| row_count(report, section))
            .chain(regex_total)
            .max()
            .unwrap_or(0);
        let text = format!(
            "{} rows",
            antinomie_monitor_core::analysis::detection::group_digits(widest)
        );
        ui.fonts_mut(|fonts| {
            fonts
                .layout_no_wrap(text, font, egui::Color32::PLACEHOLDER)
                .size()
                .x
        })
    };
    // The title column fits the longest title (a reason a check is not
    // complete needs a little more); a narrow pane cuts titles with an
    // ellipsis (the full title is one hover away) instead of squeezing them.
    let name_width = {
        let font = egui::TextStyle::Button.resolve(ui.style());
        let longest = ui.fonts_mut(|fonts| {
            ALL_KINDS
                .iter()
                .map(|kind| {
                    fonts
                        .layout_no_wrap(
                            section_title(*kind).to_owned(),
                            font.clone(),
                            egui::Color32::PLACEHOLDER,
                        )
                        .size()
                        .x
                })
                .fold(0.0_f32, f32::max)
        }) + 2.0 * ui.spacing().button_padding.x;
        let wanted = longest;
        let others = tag_width
            + rows_width
            + ui.spacing().interact_size.x
            + 3.0 * 12.0
            + 2.0 * ui.spacing().item_spacing.x
            + 24.0;
        wanted.min((ui.available_width() - others).max(90.0))
    };
    paired_card(
        ui,
        pair,
        "Categories",
        |_| {},
        |ui| {
            egui::Grid::new("analysis-categories")
                .num_columns(5)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    for kind in ALL_KINDS {
                        let Some(section) =
                            report.sections.iter().find(|section| section.kind == kind)
                        else {
                            ui.add_enabled(
                                false,
                                egui::Label::new(section_title(kind)).truncate(),
                            )
                                .on_disabled_hover_text(NOT_REQUESTED);
                            crate::widgets::chip_wide(ui, "Not requested", Tone::Neutral, tag_width);
                            ui.label("");
                            if run_button(
                                ui,
                                finished,
                                "Run this check now; the rest of the analysis is not repeated",
                            ) {
                                action = Some(ReportAction::RunCheck {
                                    report_id: report.id.clone(),
                                    kind,
                                });
                            }
                            ui.end_row();
                            continue;
                        };
                        let clicked = ui
                            .vertical(|ui| {
                                ui.set_width(name_width);
                                ui.add(
                                    egui::Button::new(
                                        egui::RichText::new(section_title(kind))
                                            .color(crate::theme::palette().accent),
                                    )
                                    .frame(false)
                                    .truncate(),
                                )
                                .on_hover_cursor(egui::CursorIcon::PointingHand)
                                .on_hover_text(format!(
                                    "{}\n{}",
                                    section_title(kind),
                                    section.summary
                                ))
                                .clicked()
                            })
                            .inner;
                        if clicked {
                            state.show(kind);
                        }
                        let tag = crate::widgets::chip_wide(
                            ui,
                            state_word(report, section),
                            state_tone(section),
                            tag_width,
                        );
                        // Why a check is not complete is one hover away.
                        if !section.summary.is_empty()
                            && section.state != antinomie_monitor_core::AnalysisSectionState::Complete
                        {
                            tag.on_hover_text(&section.summary);
                        }
                        // The regex matches are read from the strings: they
                        // have a count once the matches have been scanned.
                        let rows = if kind == AnalysisKind::Regex {
                            regex_total
                        } else {
                            Some(row_count(report, section))
                        };
                        ui.allocate_ui_with_layout(
                            egui::vec2(rows_width, ui.spacing().interact_size.y),
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if let Some(rows) = rows {
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{} rows",
                                            antinomie_monitor_core::analysis::detection::group_digits(rows)
                                        ))
                                        .monospace(),
                                    );
                                }
                            },
                        );
                        if ui
                            .button(egui_phosphor::regular::ARROW_SQUARE_OUT)
                            .on_hover_text("Open category in a separate pane")
                            .clicked()
                        {
                            action = Some(ReportAction::OpenSection {
                                report_id: report.id.clone(),
                                kind,
                            });
                        }
                        // Why a check is not complete: right of the button, wrapping
                        // under itself, so every button is in one column.
                        if let Some((text, _)) = section.reason() {
                            let width = ui.available_width().max(160.0);
                            ui.allocate_ui_with_layout(
                                egui::vec2(width, 0.0),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.set_width(width);
                                    let color = if section.state
                                        == antinomie_monitor_core::AnalysisSectionState::Unavailable
                                    {
                                        crate::theme::error()
                                    } else {
                                        crate::theme::warn()
                                    };
                                    ui.add(
                                        egui::Label::new(
                                            egui::RichText::new(&text).small().color(color),
                                        )
                                        .wrap(),
                                    )
                                    .on_hover_text(&text);
                                },
                            );
                        }
                        ui.end_row();
                    }
                });
        },
    );
    action
}

/// Every word a category's state tag can say, to size the tag column.
const TAG_WORDS: &[&str] = &[
    "Complete",
    "Partial",
    "Unavailable",
    "Timeout",
    "Pending",
    "Running…",
    "Queued…",
    "Waiting…",
    "Not requested",
];

// SPDX-License-Identifier: GPL-3.0-only
//! Run History's table geometry and its executable cell: the column widths for
//! a pane, and the run's short id beside the executable's name.
use super::*;

/// The widths of Run History's columns for a pane: each column's wish, and
/// the least it keeps, shrunk together so the whole row fits the pane.
pub(super) struct HistoryColumns {
    /// The pane's width in whole hundreds, so a table is rebuilt only when the
    /// pane is a hundred points narrower, never while it is dragged.
    pub(super) pane: f32,
    pub(super) start: f32,
    pub(super) start_least: f32,
    pub(super) sample: f32,
    pub(super) arguments: f32,
    pub(super) status: f32,
    pub(super) exit: f32,
    /// The Open terminal and Stop icons.
    pub(super) actions: f32,
}

impl HistoryColumns {
    pub(super) const EXECUTABLE_LEAST: f32 = 150.0;
    pub(super) const SAMPLE_LEAST: f32 = 70.0;
    pub(super) const ARGUMENTS_LEAST: f32 = 70.0;
    pub(super) const STATUS_LEAST: f32 = 90.0;
    pub(super) const EXIT_LEAST: f32 = 60.0;
    pub(super) const START_LEAST: f32 = 120.0;

    pub(super) fn fit(ui: &egui::Ui) -> Self {
        let spacing = ui.spacing();
        // Each icon button is as wide as its glyph and padding, or the minimum
        // height, whichever is more (a bigger text size widens the glyph).
        let body = ui.text_style_height(&egui::TextStyle::Body);
        let icon = spacing
            .interact_size
            .y
            .max(body + 2.0 * spacing.button_padding.x);
        let actions = 2.0 * icon + 3.0 * spacing.item_spacing.x;
        let gaps = 7.0 * spacing.item_spacing.x;
        let pane = (ui.available_width() / 100.0).floor().max(6.0) * 100.0;
        // What each column wants, and the least it keeps.
        let wanted = [190.0, 120.0, 170.0, 190.0, 110.0];
        let least = [
            Self::START_LEAST,
            Self::SAMPLE_LEAST,
            Self::ARGUMENTS_LEAST,
            Self::STATUS_LEAST,
            Self::EXIT_LEAST,
        ];
        let room = (pane - actions - gaps - Self::EXECUTABLE_LEAST).max(least.iter().sum());
        let scale = (room / wanted.iter().sum::<f32>()).min(1.0);
        let at = |index: usize| (wanted[index] * scale).max(least[index]);
        Self {
            pane,
            start: at(0),
            start_least: Self::START_LEAST,
            sample: at(1),
            arguments: at(2),
            status: at(3),
            exit: at(4),
            actions,
        }
    }
}

/// The run's short id, as in `[a1b2c3d4]`: the first eight characters of its id.
pub(crate) fn short_run_id(run: &RunSummary) -> String {
    format!("[{}]", run.id.chars().take(8).collect::<String>())
}

/// The executable's name with the run's short id beside it. The name gives way
/// when the column is narrow; the id stays.
pub(super) fn executable_cell(ui: &mut egui::Ui, title: String, run: &RunSummary) {
    let id = short_run_id(run);
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let id_width = ui.fonts(|fonts| {
        fonts
            .layout_no_wrap(id.clone(), font, egui::Color32::PLACEHOLDER)
            .size()
            .x
    });
    let room = (ui.available_width() - id_width - ui.spacing().item_spacing.x).max(20.0);
    ui.scope(|ui| {
        ui.set_max_width(room);
        ui.add(
            egui::Label::new(title)
                .selectable(false)
                .sense(egui::Sense::hover())
                .truncate(),
        )
        .on_hover_text(&run.request.path);
    });
    ui.add(
        egui::Label::new(egui::RichText::new(id).monospace().color(theme::muted()))
            .selectable(false)
            .sense(egui::Sense::hover()),
    )
    .on_hover_text(format!("Run {}", run.id));
}

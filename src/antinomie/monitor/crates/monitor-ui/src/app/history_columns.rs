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
    pub(super) executable_least: f32,
    pub(super) sample: f32,
    pub(super) sample_least: f32,
    pub(super) arguments: f32,
    pub(super) arguments_least: f32,
    pub(super) status: f32,
    pub(super) status_least: f32,
    pub(super) exit: f32,
    pub(super) exit_least: f32,
    /// The Open terminal and Stop icons.
    pub(super) actions: f32,
    /// The pane has room for the Sample and Arguments columns.
    pub(super) wide: bool,
}

impl HistoryColumns {
    /// What each column keeps at least in a wide pane: start time, executable,
    /// sample, arguments, tree status, root exit.
    const LEAST: [f32; 6] = [120.0, 150.0, 70.0, 70.0, 90.0, 60.0];
    /// The share of those minimums a narrow pane gives up before the icons
    /// would be cut off.
    const SHRINK_MIN: f32 = 0.4;
    /// The narrowest pane that keeps the Sample and Arguments columns.
    const WIDE_PANE: f32 = 700.0;

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
        let pane = (ui.available_width() / 100.0).floor().max(3.0) * 100.0;
        // A pane too narrow for every column drops Sample and Arguments; the
        // minimums of the others then shrink together if they still do not fit.
        let wide = pane >= Self::WIDE_PANE;
        let kept = if wide { 6.0 } else { 4.0 };
        let gaps = gaps * kept / 6.0;
        let sum: f32 = Self::LEAST
            .iter()
            .enumerate()
            .filter(|(index, _)| wide || !matches!(index, 2 | 3))
            .map(|(_, least)| least)
            .sum();
        let share = ((pane - actions - gaps) / sum).clamp(Self::SHRINK_MIN, 1.0);
        let least = Self::LEAST.map(|least| least * share);
        // What each wide column wants.
        let wanted = [190.0, 120.0, 170.0, 190.0, 110.0];
        let others = [least[0], least[2], least[3], least[4], least[5]];
        let kept_others: f32 = others
            .iter()
            .enumerate()
            .filter(|(index, _)| wide || !matches!(index, 1 | 2))
            .map(|(_, least)| least)
            .sum();
        let room = (pane - actions - gaps - least[1]).max(kept_others);
        let wanted_kept: f32 = wanted
            .iter()
            .enumerate()
            .filter(|(index, _)| wide || !matches!(index, 1 | 2))
            .map(|(_, wanted)| wanted)
            .sum();
        let scale = (room / wanted_kept).min(1.0);
        let at = |index: usize| (wanted[index] * scale).max(others[index]);
        Self {
            pane,
            start: at(0),
            start_least: least[0],
            executable_least: least[1],
            sample: at(1),
            sample_least: least[2],
            arguments: at(2),
            arguments_least: least[3],
            status: at(3),
            status_least: least[4],
            exit: at(4),
            exit_least: least[5],
            actions,
            wide,
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

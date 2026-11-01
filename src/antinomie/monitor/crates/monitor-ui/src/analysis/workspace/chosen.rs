// SPDX-License-Identifier: GPL-3.0-only
//! The row the Details panel shows for Static analysis.
use super::{row_menu, AnalysisEntry};
use eframe::egui;

/// The row the Details panel shows for Static analysis.
#[derive(Clone)]
pub(super) struct ChosenRow {
    pub(super) entry: AnalysisEntry,
    pub(super) specimen_len: Option<u64>,
    pub(super) category: &'static str,
}

pub(super) const CHOSEN_ROW: &str = "static-details-row";

/// The Details panel body: the row selected last in a Static analysis pane.
pub(crate) fn details(ui: &mut egui::Ui) {
    let chosen = ui
        .ctx()
        .data(|data| data.get_temp::<ChosenRow>(egui::Id::new(CHOSEN_ROW)));
    let Some(chosen) = chosen else {
        ui.weak("Select a row to see its details.");
        return;
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(egui::RichText::new(&chosen.entry.label).strong());
        ui.weak(format!("from Static · {}", chosen.category));
    });
    ui.separator();
    row_menu::details(ui, chosen.specimen_len, &chosen.entry);
}

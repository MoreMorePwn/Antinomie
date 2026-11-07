// SPDX-License-Identifier: GPL-3.0-only
//! The Open Packets button. The network inventory is in
//! `antinomie_triage::network`.
use super::*;

pub(super) use antinomie_triage::network::*;


/// Temp-data key Open Packets leaves for the app.
pub const OPEN_PACKETS: &str = "triage-open-packets";

/// The button that links the derived tables to the raw capture.
pub fn open_packets_button(ui: &mut egui::Ui, available: bool) {
    let label = format!("{} Open Packets", egui_phosphor::regular::NETWORK);
    if ui
        .add_enabled(available, egui::Button::new(label))
        .on_hover_text("Show this run's capture in Packets")
        .on_disabled_hover_text("This run has no packet capture")
        .clicked()
    {
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new(OPEN_PACKETS), true));
    }
}
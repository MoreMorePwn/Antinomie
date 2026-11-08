// SPDX-License-Identifier: GPL-3.0-only
//! The menu of a file hash. The columns are in `antinomie_triage::file_shown`.
use super::*;

pub(super) use antinomie_triage::file_shown::*;

/// The run's SHA-256 note in a row's menu: copy the whole digest.
pub fn copy_hash_menu(ui: &mut egui::Ui, values: &[(&str, RowValue)]) {
    let hash = values.iter().find_map(|(name, value)| match value {
        RowValue::Text(hash) if *name == "file.sha256" && !hash.is_empty() => Some(hash),
        _ => None,
    });
    if let Some(hash) = hash {
        if ui
            .button("Copy SHA-256")
            .on_hover_text(hash.as_str())
            .clicked()
        {
            ui.ctx().copy_text(hash.clone());
            ui.close();
        }
    }
}

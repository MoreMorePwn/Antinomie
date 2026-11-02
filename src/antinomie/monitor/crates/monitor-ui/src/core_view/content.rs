// SPDX-License-Identifier: GPL-3.0-only
//! The Content tab: the captured bytes of one mapping of the core as a hex
//! dump or raw text, at virtual addresses (file offsets on hover), with the
//! on-demand Strings and Regex sub-windows of the shared Content window. The
//! sub-windows search the mapping shown; the Strings tab searches the whole
//! core.
use super::*;
use crate::content_view::ContentSource;
use antinomie_monitor_core::content_scan::FileRange;

/// The octets of `mapping` the core file holds.
fn captured_size(mapping: &CoreMapping, file_size: u64) -> u64 {
    mapping
        .available_size
        .min(mapping.memory_size)
        .min(file_size.saturating_sub(mapping.file_offset))
}

/// The Content window's source for `mapping` of `core`.
pub(super) fn mapping_source(core: &CoreDump, index: usize) -> Option<ContentSource> {
    let mapping = core.mappings.get(index)?;
    let size = captured_size(mapping, core.source_size);
    Some(ContentSource {
        key: format!(
            "{}:{index}:{:x}:{size}",
            core.source.display(),
            mapping.file_offset
        ),
        source: Arc::new(FileRange {
            path: core.source.clone(),
            start: mapping.file_offset,
            size,
        }),
        address_base: mapping.start,
        file_base: Some(mapping.file_offset),
        address_name: "Address",
    })
}

impl CoreView {
    pub(super) fn content(&mut self, ui: &mut egui::Ui, record: &CoreRecord) {
        let choices = mapping_choices(&record.core);
        if choices.is_empty() {
            ui.label("This core retained no memory mappings.");
            return;
        }
        let mut index = self.mapping_index.min(choices.len() - 1);
        ui.horizontal(|ui| {
            ui.label("Mapping");
            egui::ComboBox::from_id_salt("core-content-mapping")
                .width(ui.available_width().min(560.0))
                .selected_text(&choices[index].0)
                .show_ui(ui, |ui| {
                    for (position, (label, tip)) in choices.iter().enumerate() {
                        ui.selectable_value(&mut index, position, label)
                            .on_hover_text(tip);
                    }
                });
        });
        if index != self.mapping_index {
            self.mapping_index = index;
            self.window_offset = 0;
            self.page = None;
        }
        if let Some(source) = mapping_source(&record.core, index) {
            if source.size() < record.core.mappings[index].memory_size {
                crate::activity::info(
                    ui,
                    format!(
                        "{} of {} octets of this mapping are in the core; the rest was not captured.",
                        source.size(),
                        record.core.mappings[index].memory_size
                    ),
                );
            }
            self.content.show(ui, &source);
        }
    }
}

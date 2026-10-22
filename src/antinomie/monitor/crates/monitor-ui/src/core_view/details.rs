// SPDX-License-Identifier: GPL-3.0-only
//! What the shared Details panel shows for a core: the function, mapping,
//! string or note chosen last in the Cores view.
use super::*;
use antinomie_monitor_core::core_strings;

/// One chosen row, as a title, where it came from and its fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreDetail {
    pub what: &'static str,
    pub title: String,
    /// The tab it was chosen in.
    pub from: &'static str,
    pub fields: Vec<(&'static str, String)>,
}

pub(super) fn note(kind: &str, name: &str, source: &str, value: &str) -> CoreDetail {
    CoreDetail {
        what: "Note",
        title: name.chars().take(48).collect(),
        from: "Recovered notes",
        fields: vec![
            ("Kind", kind.into()),
            ("Name", name.into()),
            ("Source", source.into()),
            ("Value", value.into()),
        ],
    }
}

pub(super) fn string(string: &core_strings::CoreString, segment: &str) -> CoreDetail {
    CoreDetail {
        what: "String",
        title: string.text.chars().take(48).collect(),
        from: "Strings",
        fields: vec![
            ("Text", string.text.clone()),
            ("Address", format!("0x{:x}", string.address)),
            ("File offset", format!("0x{:x}", string.file_offset)),
            ("Encoding", string.encoding.into()),
            ("Length", format!("{} octets", string.byte_len)),
            ("Segment", segment.into()),
        ],
    }
}

impl CoreView {
    pub(super) fn function_detail(&self, index: usize) -> CoreDetail {
        let function = &self.functions[index];
        let view = self.listing_view();
        CoreDetail {
            what: "Function",
            title: function.name.clone(),
            from: "Disassembly",
            fields: vec![
                ("Name", function.name.clone()),
                ("Address", format!("0x{:x}", function.address)),
                ("Size", format!("{} octets", function.size)),
                (
                    view.label(),
                    crate::code_listing::lines_text(self.function_lines(view, index)),
                ),
            ],
        }
    }

    pub(super) fn mapping_detail(&self, record: &CoreRecord, index: usize) -> Option<CoreDetail> {
        let core = &record.core;
        let mapping = core.mappings.get(index)?;
        Some(CoreDetail {
            what: "Mapping",
            title: format!("{:x}-{:x}", mapping.start, mapping.end()),
            from: "Memory mappings",
            fields: vec![
                (
                    "Range",
                    format!("0x{:x}-0x{:x}", mapping.start, mapping.end()),
                ),
                ("Permissions", mapping.permissions()),
                ("File", mapping_name(core, mapping)),
                ("Size", format!("{} octets", mapping.memory_size)),
                (
                    "Captured",
                    format!(
                        "{} of {} octets",
                        mapping.available_size, mapping.memory_size
                    ),
                ),
                (
                    "File offset in the core",
                    format!("0x{:x}", mapping.file_offset),
                ),
            ],
        })
    }

    /// The Details panel's body.
    pub(crate) fn details(&self, ui: &mut egui::Ui) {
        let Some(detail) = &self.detail else {
            ui.weak("Nothing selected. Select a mapping, function, string or note in Cores to inspect it here.");
            return;
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new(format!("{} {}", detail.what, detail.title)).strong());
            ui.weak(format!("from Cores · {}", detail.from));
        });
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt("core-details")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                egui::Grid::new("core-detail-fields")
                    .num_columns(2)
                    .striped(true)
                    .show(ui, |ui| {
                        for (name, value) in &detail.fields {
                            ui.label(egui::RichText::new(*name).color(crate::theme::muted()));
                            ui.horizontal(|ui| {
                                ui.add(
                                    egui::Label::new(egui::RichText::new(value).monospace()).wrap(),
                                );
                                if ui
                                    .small_button(egui_phosphor::regular::COPY)
                                    .on_hover_text(format!("Copy {name}"))
                                    .clicked()
                                {
                                    ui.ctx().copy_text(value.clone());
                                }
                            });
                            ui.end_row();
                        }
                    });
            });
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The Catalog tab of the Detection rules page: the packs on offer for the
//! engine and the details of the selected one. Nothing here fetches a rule.
use super::{
    page::{CELL_PAD, ROW_PAD},
    theme, Model,
};
use crate::widgets::{self, table, Tone};
use antinomie_monitor_core::ruleset;
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::path::Path;

impl Model {
    pub(super) fn catalog_tab(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool) {
        let Some(catalog) = self.catalog.clone() else {
            ui.weak("Unavailable: no catalog has been checked yet. Use Check for updates.");
            return;
        };
        let offers: Vec<_> = self
            .offers()
            .into_iter()
            .filter(|offer| offer.engine == self.engine)
            .collect();
        if offers.is_empty() {
            ui.weak("The catalog has no pack for this engine.");
            return;
        }
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let order =
            crate::table_sort::order(ui.ctx(), "rules_catalog", offers.len(), |column, a, b| {
                let (a, b): (&super::first_run::Offer, &super::first_run::Offer) =
                    (&offers[a], &offers[b]);
                match column {
                    0 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    1 => a.version.cmp(&b.version),
                    2 => a.rules.cmp(&b.rules),
                    3 => a.size.cmp(&b.size),
                    4 => a.license.to_lowercase().cmp(&b.license.to_lowercase()),
                    _ => self
                        .catalog_state(&catalog, a)
                        .cmp(self.catalog_state(&catalog, b)),
                }
            });
        let mut picked = None;
        let row_height = table::row_height(font) + ROW_PAD;
        let height = row_height * (offers.len().min(6) as f32 + 1.5) + 8.0;
        egui::ScrollArea::horizontal()
            .id_salt("rules_catalog_scroll")
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.x += CELL_PAD;
                ui.set_min_width(640.0);
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt("rules_catalog")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .column(Column::remainder().at_least(180.0).clip(true))
                    .column(
                        Column::initial(130.0)
                            .at_least(60.0)
                            .resizable(true)
                            .clip(true),
                    )
                    .column(Column::exact(90.0))
                    .column(Column::exact(150.0))
                    .column(
                        Column::initial(150.0)
                            .at_least(60.0)
                            .resizable(true)
                            .clip(true),
                    )
                    .column(Column::exact(130.0))
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(table::header_height(font), |mut header| {
                        for (column, title) in
                            ["Pack", "Version", "Rules", "Size", "License", "State"]
                                .into_iter()
                                .enumerate()
                        {
                            header.col(|ui| {
                                crate::table_sort::header_aligned(
                                    ui,
                                    "rules_catalog",
                                    column,
                                    title,
                                    table::numeric_align(matches!(column, 2 | 3)),
                                )
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_height, offers.len(), |mut row| {
                            let offer = &offers[order[row.index()]];
                            let selected = self.catalog_pick == offer.id;
                            row.set_selected(selected);
                            row.col(|ui| {
                                table::row_mark(
                                    ui,
                                    if selected {
                                        table::Mark::Selected
                                    } else {
                                        table::Mark::None
                                    },
                                );
                                table::cell_click(ui, table::Cell::Text, &offer.name);
                            });
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Mono, &offer.version);
                            });
                            row.col(|ui| {
                                table::cell_click(
                                    ui,
                                    table::Cell::Number,
                                    &offer.rules.to_string(),
                                );
                            });
                            row.col(|ui| {
                                table::cell_click(
                                    ui,
                                    table::Cell::Number,
                                    &crate::values::file_size(offer.size),
                                );
                            });
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Text, &offer.license);
                            });
                            row.col(|ui| {
                                let state = self.catalog_state(&catalog, offer);
                                widgets::chip(
                                    ui,
                                    state,
                                    match state {
                                        "Installed" => Tone::Good,
                                        "Update available" => Tone::Accent,
                                        _ => Tone::Neutral,
                                    },
                                );
                            });
                            if row.response().clicked() {
                                picked = Some(offer.id.clone());
                            }
                        });
                    });
            });
        if let Some(id) = picked {
            self.catalog_pick = id;
        }
        let Some(offer) = offers.iter().find(|offer| offer.id == self.catalog_pick) else {
            ui.weak("Select a pack for its details.");
            return;
        };
        ui.separator();
        if let Some(pack) = catalog
            .sources
            .iter()
            .find(|pack| pack.id == offer.id)
            .cloned()
        {
            self.source_entry(ui, data_dir, outbound, &pack);
        } else if let Some(entry) = catalog
            .packs
            .iter()
            .find(|entry| entry.id == offer.id)
            .cloned()
        {
            self.archive_entry(ui, data_dir, outbound, &entry);
        }
        ui.add_space(4.0);
        theme::section(ui, "Rules");
    }

    /// Installed, an update of an installed pack, or only on offer.
    fn catalog_state(
        &self,
        catalog: &ruleset::Catalog,
        offer: &super::first_run::Offer,
    ) -> &'static str {
        match self.registry.packs.iter().find(|pack| pack.id == offer.id) {
            None => "Available",
            Some(pack) => {
                let newer = if catalog.schema == ruleset::CATALOG_SCHEMA_SOURCES {
                    ruleset::source_update(catalog, pack).is_some()
                } else {
                    catalog
                        .packs
                        .iter()
                        .any(|entry| entry.id == pack.id && entry.version != pack.version)
                };
                if newer {
                    "Update available"
                } else {
                    "Installed"
                }
            }
        }
    }

    /// A schema 1 catalog entry: its facts and the download.
    fn archive_entry(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        outbound: bool,
        entry: &ruleset::PackEntry,
    ) {
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} {} · {} rules, {} helpers",
                    entry.name, entry.version, entry.rules, entry.helpers
                ))
                .strong()
                .color(theme::text()),
            )
            .wrap(),
        );
        ui.label(
            RichText::new(format!("{} · {}", entry.license, entry.upstream_revision))
                .small()
                .color(theme::muted()),
        );
        let installed = self
            .registry
            .packs
            .iter()
            .any(|pack| pack.id == entry.id && pack.version == entry.version);
        if installed {
            ui.colored_label(theme::good(), "installed");
        } else if ui.button("Download").clicked() {
            self.install(data_dir, outbound, entry.clone());
        }
    }
}

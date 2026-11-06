// SPDX-License-Identifier: GPL-3.0-only
//! The Detection rules page: YARA, IDS and Sigma tabs; inside each, Installed
//! and Catalog tabs. A pack lists all of its rules in a table and a rule
//! shows its details and source text. Catalog packs show the catalog's
//! metadata only: their rules exist locally after install.
use super::{first_run::ENGINES, theme, Done, Model};
use crate::widgets::fit_table::{Col, FitBuilder};
use crate::widgets::{self, fit_table, TabItem, Tone};
use antinomie_monitor_core::ruleset::{self, IndexedRule};
use eframe::egui::{self, RichText};
use std::{path::Path, sync::mpsc, thread};

/// The two tabs inside an engine.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Tab {
    #[default]
    Installed,
    Catalog,
    /// The IDS engine's abuse.ch packs, with update checks.
    Abusech,
}

/// An installed pack or custom group, as the table lists it.
struct SetRow {
    id: String,
    group: bool,
    name: String,
    version: String,
    enabled: bool,
    update: bool,
}

/// Room above and below the status lines under the toolbar.
const NOTICE_GAP: f32 = 6.0;
/// Extra row height of the pack and rule tables, so the text has room around
/// it. The column spacing stays the theme's: a wider one made each cell's
/// fill and the header rule stick out past the table by half of it.
pub(super) const ROW_PAD: f32 = 8.0;

pub(super) fn severity_rank(severity: &str) -> u8 {
    match severity {
        "informational" | "info" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 0,
    }
}

pub(super) fn severity_tone(severity: &str) -> Tone {
    match severity_rank(severity) {
        4 | 5 => Tone::Error,
        3 => Tone::Warn,
        0 => Tone::Neutral,
        _ => Tone::Info,
    }
}

impl Model {
    pub(super) fn contents(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        outbound: &mut bool,
        detection: &mut antinomie_monitor_core::analysis::detection::Settings,
    ) {
        if !self.loaded {
            self.ensure(data_dir);
        }
        self.regex.load(data_dir);
        // The counts sit in the heading row like the IOC tab's "x of y loaded"
        // sits in its button row; each tab repeats them for its own rules.
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new("Detection rules")
                    .size(ui.text_style_height(&egui::TextStyle::Heading))
                    .color(theme::heading()),
            );
            ui.weak(self.counts_line()).on_hover_text(
                "Installed packs and how many are enabled, custom groups, and the string patterns that are switched on. Each tab counts its own rules.",
            );
        });
        ui.label(RichText::new("Scans never use the network.").color(theme::muted()))
            .on_hover_text("Installed packs and custom groups are the only production rules. Scans do not download rules or upload evidence.");
        let mut engine = ENGINES
            .iter()
            .map(|(id, _)| *id)
            .chain(["regex", super::ioc::TAB])
            .find(|id| *id == self.engine)
            .unwrap_or("yara");
        let mut items: Vec<_> = ENGINES
            .iter()
            .map(|(id, label)| {
                let count = self
                    .registry
                    .packs
                    .iter()
                    .filter(|p| p.engine == *id)
                    .count();
                (
                    *id,
                    TabItem::new(*label).badge(count.to_string(), Tone::Plain),
                )
            })
            .collect();
        items.push((
            "regex",
            TabItem::new("Strings regex").badge(self.regex.badge(), Tone::Plain),
        ));
        items.push((super::ioc::TAB, TabItem::new("IOC")));
        if widgets::tabs(ui, items, &mut engine) {
            self.engine = engine.into();
            self.select_none();
        }
        if self.engine == "regex" {
            self.regex_tab(ui, data_dir);
            return;
        }
        if self.engine == super::ioc::TAB {
            self.ioc_tab(ui, data_dir, outbound);
            return;
        }
        if let Some(next) = self.engine_status(ui) {
            self.requested = Some(next);
        }
        self.options(ui, data_dir, detection);
        self.toolbar(ui, data_dir, *outbound);
        self.notices(ui, outbound);
        let installed = self
            .registry
            .packs
            .iter()
            .filter(|p| p.engine == self.engine)
            .count()
            + self.groups_of_engine().count();
        let offered = self
            .offers()
            .iter()
            .filter(|o| o.engine == self.engine)
            .count();
        let mut tab = self.tab;
        let mut tabs = vec![
            (
                Tab::Installed,
                TabItem::new("Installed").badge(installed.to_string(), Tone::Plain),
            ),
            (
                Tab::Catalog,
                TabItem::new("Catalog").badge(offered.to_string(), Tone::Plain),
            ),
        ];
        if self.engine == "ids" {
            tabs.push((Tab::Abusech, TabItem::new("abuse.ch")));
        } else if tab == Tab::Abusech {
            tab = Tab::Installed;
        }
        widgets::tabs(ui, tabs, &mut tab);
        self.tab = tab;
        match self.tab {
            Tab::Installed => self.installed_tab(ui, data_dir, *outbound),
            Tab::Catalog => self.catalog_tab(ui, data_dir, *outbound),
            Tab::Abusech => self.abusech_tab(ui, data_dir, outbound),
        }
    }

    fn groups_of_engine(&self) -> impl Iterator<Item = &ruleset::CustomGroup> {
        self.registry
            .groups
            .iter()
            .filter(|group| group.engine == self.engine && !group.deleted)
    }

    /// Open on the engine tab `engine` ("yara", "ids", "sigma", "regex" or
    /// "ioc"), on its Catalog list when `catalog` and the engine has one.
    pub(crate) fn show_engine(&mut self, engine: &str, catalog: bool) {
        self.engine = engine.into();
        self.tab = if catalog {
            Tab::Catalog
        } else {
            Tab::Installed
        };
        self.select_none();
        if engine == super::ioc::TAB {
            self.show_ioc();
        }
    }

    /// Open the IDS engine on its abuse.ch packs tab.
    pub(crate) fn show_abusech(&mut self) {
        self.show_engine("ids", false);
        self.tab = Tab::Abusech;
    }

    /// A rule is selected in an open rule list, so "Rule details" has
    /// something to show.
    pub(crate) fn has_rule_selected(&self) -> bool {
        self.rule_lists.iter().any(|list| list.has_selection())
    }

    /// Forget the selected pack or group and the rules listed for it.
    fn select_none(&mut self) {
        self.pack_id.clear();
        self.group_id.clear();
        self.catalog_pick.clear();
        self.clear_rules();
    }

    fn clear_rules(&mut self) {
        self.rows.clear();
        self.rows_key.clear();
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool) {
        ui.horizontal_wrapped(|ui| {
            let busy = self.job.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Reload local rules"))
                .on_hover_text("Read the installed packs and groups from the rules folder again. No network.")
                .clicked()
            {
                self.loaded = false;
                self.status_error = None;
                self.rows_key.clear();
                self.ensure(data_dir);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Check for updates"))
                .on_hover_text("Read the rule catalog from the network. Needs Allow downloads; scans stay offline.")
                .clicked()
            {
                self.refresh_catalog(data_dir, outbound);
            }
            if busy
                && ui
                    .button("Cancel")
                    .on_hover_text("Stop the running job; nothing is changed.")
                    .clicked()
            {
                self.cancel_job();
            }
            if ui
                .button("Open rules directory")
                .on_hover_text("Show the folder where the installed rules are kept.")
                .clicked()
            {
                let root = ruleset::rules_root(data_dir);
                crate::folders::show_created_detached(root);
            }
            ui.weak(self.engine_counts()).on_hover_text(
                "The packs of this engine that are switched on, and its custom groups. Rules are counted per pack in the Installed list.",
            );
        });
    }

    /// The status lines under the buttons: downloads off, the last result, a
    /// running job. They sit on the content's left edge with room above and
    /// below, between the buttons and the table.
    pub(super) fn notices(&mut self, ui: &mut egui::Ui, outbound: &mut bool) {
        // A failure was raised as a toast when it arrived.
        let status =
            self.status_error.as_deref() != Some(self.status.as_str()) && !self.status.is_empty();
        if *outbound && !status && self.job.is_none() {
            return;
        }
        ui.add_space(NOTICE_GAP);
        if !*outbound {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Downloads are off.").color(theme::muted()));
                if ui
                    .button("Allow downloads")
                    .on_hover_text(format!(
                        "Antinomie contacts no server unless you allow it. This turns on Tools > Settings > Detection > Allow outbound catalog and rule downloads. \
                         Only Check for updates and installing or updating a pack use the network, \
                         and only the hosts listed here; scans stay offline.\n{}",
                        self.hosts_line()
                    ))
                    .clicked()
                {
                    *outbound = true;
                    self.blocked = None;
                    self.status = "Downloads allowed. Check for updates reads the catalog.".into();
                }
            });
        }
        if status {
            let blocked = self.blocked.as_deref() == Some(self.status.as_str());
            // A finished job's result ("Installed ...", "Saved ...") is green;
            // progress, hints and a cancel stay muted.
            let done = self.status_done.as_deref() == Some(self.status.as_str());
            let closed = if blocked {
                crate::activity::status(ui, crate::activity::Level::Error, &self.status, None)
            } else if done {
                crate::activity::success(ui, &self.status, None)
            } else {
                crate::activity::status(ui, crate::activity::Level::Info, &self.status, None)
            };
            if closed {
                self.status.clear();
            }
        }
        if self.job.is_some() {
            let progress = self.progress_line();
            theme::loading(
                ui,
                if progress.is_empty() {
                    "Working…"
                } else {
                    progress.as_str()
                },
            );
        }
        ui.add_space(NOTICE_GAP);
    }

    // ---- Installed ----

    fn set_rows(&self) -> Vec<SetRow> {
        let mut rows: Vec<SetRow> = self
            .registry
            .packs
            .iter()
            .filter(|pack| pack.engine == self.engine)
            .map(|pack| SetRow {
                id: pack.id.clone(),
                group: false,
                name: pack.name.clone(),
                version: pack.version.clone(),
                enabled: pack.enabled,
                update: self.pack_update(pack),
            })
            .collect();
        rows.extend(self.groups_of_engine().map(|group| SetRow {
            id: group.id.clone(),
            group: true,
            name: group.name.clone(),
            version: format!("r{}", group.revision),
            enabled: group.enabled,
            update: false,
        }));
        rows
    }

    /// The catalog lists a different version of this pack.
    fn pack_update(&self, pack: &ruleset::InstalledPack) -> bool {
        let Some(catalog) = &self.catalog else {
            return false;
        };
        if catalog.schema == ruleset::CATALOG_SCHEMA_SOURCES {
            ruleset::source_update(catalog, pack).is_some()
        } else {
            catalog
                .packs
                .iter()
                .any(|entry| entry.id == pack.id && entry.version != pack.version)
        }
    }

    fn installed_tab(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool) {
        let rows = self.set_rows();
        if self.pack_id.is_empty() && self.group_id.is_empty() {
            if let Some(first) = rows.first() {
                self.choose(first.group, &first.id, data_dir);
            }
        } else if !rows
            .iter()
            .any(|row| row.id == self.pack_id || row.id == self.group_id)
        {
            self.select_none();
        }
        if rows.is_empty() {
            ui.weak("None installed.");
        } else {
            self.sets_table(ui, data_dir, &rows);
        }
        self.group_import(ui, data_dir);
        let Some(row) = rows
            .iter()
            .find(|row| row.id == self.pack_id || row.id == self.group_id)
        else {
            return;
        };
        ui.separator();
        self.set_actions(ui, data_dir, outbound, row);
        if self.rows_key == self.rule_key() {
            return;
        }
        // The selected set's rules are not loaded yet: read them once the
        // worker is free.
        if self.job.is_none() {
            self.load_rules(data_dir);
        }
    }

    fn choose(&mut self, group: bool, id: &str, data_dir: &Path) {
        if group {
            self.group_id = id.into();
            self.pack_id.clear();
        } else {
            self.pack_id = id.into();
            self.group_id.clear();
        }
        self.clear_rules();
        if self.job.is_none() {
            self.load_rules(data_dir);
        }
    }

    fn load_rules(&mut self, data_dir: &Path) {
        let dir = data_dir.to_path_buf();
        let key = self.rule_key();
        let engine = self.engine.clone();
        let (pack, group) = (self.pack_id.clone(), self.group_id.clone());
        self.spawn(move |_| {
            let rows = if group.is_empty() {
                ruleset::pack_index(&dir, &engine, &pack)?
            } else {
                ruleset::group_index(&dir, &group)?
            };
            Ok(Done::Rules(key, rows))
        });
    }

    fn sets_table(&mut self, ui: &mut egui::Ui, data_dir: &Path, rows: &[SetRow]) {
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = fit_table::row_height(font) + ROW_PAD;
        let order = crate::table_sort::order(ui.ctx(), "rules_sets", rows.len(), |column, a, b| {
            let (a, b) = (&rows[a], &rows[b]);
            match column {
                1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                2 => a.version.cmp(&b.version),
                3 => a.group.cmp(&b.group),
                _ => (a.enabled, a.update).cmp(&(b.enabled, b.update)),
            }
        });
        let mut toggle: Option<(String, bool, bool)> = None;
        let mut picked: Option<(bool, String)> = None;
        let selected = if self.group_id.is_empty() {
            self.pack_id.clone()
        } else {
            self.group_id.clone()
        };
        let height = row_height * (rows.len().min(5) as f32 + 1.5) + 8.0;
        ui.scope(|ui| {
            FitBuilder::new(ui)
                .id_salt("rules_sets")
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .striped(true)
                .column(Col::fixed(34.0))
                .column(Col::rest(80.0).at_least(180.0))
                .column(Col::flex(110.0).at_least(60.0).resizable(true))
                .column(Col::fixed(72.0))
                .column(Col::flex(150.0).at_least(90.0))
                .max_scroll_height(height)
                .min_scrolled_height(0.0)
                .header(fit_table::header_height(font), |mut header| {
                    header.col(|ui| fit_table::head(ui, "On"));
                    for (column, title) in
                        ["Pack", "Version", "Kind", "State"].into_iter().enumerate()
                    {
                        header.col(|ui| {
                            crate::table_sort::header(ui, "rules_sets", column + 1, title)
                        });
                    }
                })
                .body(|body| {
                    body.rows(row_height, rows.len(), |mut row| {
                        let set = &rows[order[row.index()]];
                        let is_selected = selected == set.id;
                        row.set_selected(is_selected);
                        row.col(|ui| {
                            fit_table::row_mark(
                                ui,
                                if is_selected {
                                    fit_table::Mark::Selected
                                } else {
                                    fit_table::Mark::None
                                },
                            );
                            let mut on = set.enabled;
                            if ui.checkbox(&mut on, "").changed() {
                                toggle = Some((set.id.clone(), set.group, on));
                            }
                        });
                        row.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Text, &set.name);
                        });
                        row.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Mono, &set.version);
                        });
                        row.col(|ui| {
                            fit_table::cell_click(
                                ui,
                                fit_table::Cell::Text,
                                if set.group { "Custom" } else { "Pack" },
                            );
                        });
                        row.col(|ui| {
                            if set.update {
                                widgets::chip(ui, "Update available", Tone::Accent);
                            } else if set.enabled {
                                widgets::chip(ui, "Enabled", Tone::Good);
                            } else {
                                widgets::chip(ui, "Disabled", Tone::Neutral);
                            }
                        });
                        if row.response().clicked() {
                            picked = Some((set.group, set.id.clone()));
                        }
                    });
                });
        });
        if let Some((id, group, on)) = toggle {
            let dir = data_dir.to_path_buf();
            self.spawn(move |_| {
                if group {
                    ruleset::set_group_enabled(&dir, &id, on)?;
                } else {
                    ruleset::set_pack_enabled(&dir, &id, on)?;
                }
                let registry = ruleset::load_registry(&dir)?;
                Ok(Done::Registry(registry, format!("Updated {id}.")))
            });
        }
        if let Some((group, id)) = picked {
            if id != selected {
                self.choose(group, &id, data_dir);
            }
        }
    }

    /// What can be done with the selected pack or group.
    fn set_actions(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool, set: &SetRow) {
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!("{} {}", set.name, set.version))
                    .strong()
                    .color(theme::heading()),
            );
            if self.rows_key == self.rule_key() {
                ui.label(RichText::new(format!("{} rules", self.rows.len())).color(theme::muted()));
            }
        });
        if set.group {
            self.group_actions(ui, data_dir, &set.id, &set.name);
            return;
        }
        let Some(pack) = self.registry.packs.iter().find(|p| p.id == set.id).cloned() else {
            return;
        };
        ui.horizontal_wrapped(|ui| {
            if pack.versions.len() > 1 && ui.button("Rollback").clicked() {
                if let Some(older) = pack
                    .versions
                    .iter()
                    .rev()
                    .find(|version| *version != &pack.version)
                    .cloned()
                {
                    let dir = data_dir.to_path_buf();
                    let id = pack.id.clone();
                    self.spawn(move |_| {
                        ruleset::rollback(&dir, &id, &older)?;
                        Ok(Done::Message(format!(
                            "Rolled back to {older}. Previous selections were kept."
                        )))
                    });
                }
            }
            self.rules_button(ui, data_dir, false, &pack.id, &set.name);
            if ui.button("Export manifest").clicked() {
                self.export_manifest(data_dir, &pack);
            }
            self.remove_button(ui, data_dir, &pack.id);
        });
        self.installed_source(ui, data_dir, outbound, &pack);
        // A hosted-archive pack (schema 1) updates from its own catalog entry.
        if let Some(catalog) = self
            .catalog
            .clone()
            .filter(|c| c.schema == ruleset::CATALOG_SCHEMA)
        {
            if let Some(entry) = catalog
                .packs
                .iter()
                .find(|entry| entry.id == pack.id)
                .cloned()
            {
                if entry.version != pack.version {
                    let newer = entry.version.clone();
                    ui.horizontal_wrapped(|ui| {
                        crate::activity::info(ui, format!("Update available: {newer}"));
                        if ui.button("Update").clicked() {
                            self.install(data_dir, outbound, entry.clone());
                        }
                    });
                }
            } else if pack.source.is_none() {
                ui.weak("This installed version is not in the current catalog.");
            }
        }
    }

    /// Opens the floating list of the set's rules.
    fn rules_button(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        group: bool,
        id: &str,
        name: &str,
    ) {
        let clicked = ui
            .button(format!("{} Rules", egui_phosphor::regular::ARROW_SQUARE_OUT))
            .on_hover_text(
                "Opens every rule of this set in a window of its own, with a filter, sorting, an on/off box per rule and the rule's details. The window stays open while you use other pages.",
            )
            .clicked();
        if clicked {
            let engine = self.engine.clone();
            let (pack, group_id) = if group { ("", id) } else { (id, "") };
            self.open_rule_list(data_dir, &engine, pack, group_id, name);
        }
    }

    fn export_manifest(&mut self, data_dir: &Path, pack: &ruleset::InstalledPack) {
        let dir = data_dir.to_path_buf();
        let engine = pack.engine.clone();
        let id = pack.id.clone();
        let version = pack.version.clone();
        let tools = self.tools.clone();
        self.spawn(move |_| {
            let snap = ruleset::snapshot(&dir, &engine, &tools)?;
            let source = ruleset::rules_root(&dir)
                .join("profiles")
                .join(&engine)
                .join(&snap.digest)
                .join("manifest.json");
            let dest_dir = ruleset::rules_root(&dir).join("exports");
            std::fs::create_dir_all(&dest_dir).map_err(|error| error.to_string())?;
            let dest = dest_dir.join(format!("{id}-{version}-selection.json"));
            std::fs::copy(&source, &dest).map_err(|error| error.to_string())?;
            Ok(Done::Status(format!("Exported {}", dest.display())))
        });
    }

    /// The import fields of custom groups; they work for any engine.
    fn group_import(&mut self, ui: &mut egui::Ui, data_dir: &Path) {
        egui::CollapsingHeader::new(
            RichText::new("Custom groups")
                .strong()
                .color(theme::heading()),
        )
        .id_salt("rules-groups")
        .default_open(false)
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.group_name)
                        .desired_width(crate::theme::plain_edit_width(140.0))
                        .hint_text(crate::theme::placeholder(ui, "Group name")),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.tags_text)
                        .desired_width(crate::theme::plain_edit_width(140.0))
                        .hint_text(crate::theme::placeholder(ui, "Tags, comma separated")),
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.import_path)
                        .desired_width(crate::theme::plain_edit_width(
                            crate::theme::row_room(ui).min(280.0),
                        ))
                        .hint_text(crate::theme::placeholder(ui, "File or folder")),
                );
                if ui.button("Import").clicked() {
                    let dir = data_dir.to_path_buf();
                    let name = self.group_name.clone();
                    let engine = self.engine.clone();
                    let path = self.import_path.clone();
                    self.spawn(move |_| {
                        let id = ruleset::import_group(&dir, &name, &engine, Path::new(&path))?;
                        Ok(Done::Message(format!("Imported {id} as a managed copy.")))
                    });
                }
            });
            ui.weak("Select a group to edit it.");
        });
    }

    fn group_actions(&mut self, ui: &mut egui::Ui, data_dir: &Path, id: &str, name: &str) {
        ui.horizontal_wrapped(|ui| {
            self.rules_button(ui, data_dir, true, id, name);
            if ui.button("Rename").clicked() {
                let dir = data_dir.to_path_buf();
                let id = id.to_owned();
                let name = self.group_name.clone();
                self.spawn(move |_| {
                    ruleset::rename_group(&dir, &id, &name)?;
                    Ok(Done::Message(format!("Renamed group {id}.")))
                });
            }
            if ui.button("Save tags").clicked() {
                let dir = data_dir.to_path_buf();
                let id = id.to_owned();
                let tags = self
                    .tags_text
                    .split(',')
                    .map(|tag| tag.trim().to_owned())
                    .filter(|tag| !tag.is_empty())
                    .collect::<Vec<_>>();
                self.spawn(move |_| {
                    ruleset::set_group_tags(&dir, &id, tags)?;
                    Ok(Done::Message(format!("Updated tags for {id}.")))
                });
            }
            if ui.button("Replace").clicked() {
                let dir = data_dir.to_path_buf();
                let id = id.to_owned();
                let path = self.import_path.clone();
                self.spawn(move |_| {
                    let revision = ruleset::replace_group_revision(&dir, &id, Path::new(&path))?;
                    let registry = ruleset::load_registry(&dir)?;
                    Ok(Done::Registry(
                        registry,
                        format!("Replaced {id} with revision {revision}."),
                    ))
                });
                self.rows_key.clear();
            }
            if ui.button("Add rules").clicked() {
                let dir = data_dir.to_path_buf();
                let id = id.to_owned();
                let path = self.import_path.clone();
                self.spawn(move |_| {
                    let revision = ruleset::revise_group(&dir, &id, Some(Path::new(&path)), &[])?;
                    let registry = ruleset::load_registry(&dir)?;
                    Ok(Done::Registry(
                        registry,
                        format!("Added rules to {id} as revision {revision}."),
                    ))
                });
                self.rows_key.clear();
            }
            if ui.button("Delete").clicked() {
                let dir = data_dir.to_path_buf();
                let id = id.to_owned();
                self.spawn(move |_| {
                    ruleset::delete_group(&dir, &id, false)?;
                    let registry = ruleset::load_registry(&dir)?;
                    Ok(Done::Registry(
                        registry,
                        "Group disabled. Retained files stay so older results keep their source."
                            .into(),
                    ))
                });
            }
        });
    }

    // ---- Rules of the selected set ----

    /// The state of a rule of the set `key` (`pack:<id>` or `group:<id>`).
    pub(super) fn state_in(&self, key: &str, rule: &IndexedRule) -> &'static str {
        if !rule.compatible {
            "incompatible"
        } else if self.rule_disabled(key, rule) {
            "disabled"
        } else {
            "enabled"
        }
    }

    /// Opens a rule's details window (or brings the one it already has to
    /// the front: one window per rule). `pack` or `group` is the set it is
    /// in; the other is empty.
    pub(super) fn open_rule(
        &mut self,
        data_dir: &Path,
        engine: &str,
        pack: &str,
        group: &str,
        rule: IndexedRule,
    ) {
        let set = if group.is_empty() {
            format!("pack:{pack}")
        } else {
            format!("group:{group}")
        };
        let key = (set, rule.id.clone());
        if let Some(open) = self.rule_windows.iter().find(|open| open.key == key) {
            open.raise.set(true);
            return;
        }
        let (tx, rx) = mpsc::channel();
        let dir = data_dir.to_path_buf();
        let (engine, pack, group) = (engine.to_owned(), pack.to_owned(), group.to_owned());
        let source = rule.clone();
        let started = {
            let group = group.clone();
            thread::Builder::new()
                .name("rule-text".into())
                .spawn(move || {
                    let text = if group.is_empty() {
                        ruleset::pack_rule_source(&dir, &engine, &pack, &source)
                    } else {
                        ruleset::group_rule_source(&dir, &group, &source)
                    };
                    let _ = tx.send(text);
                })
        };
        let (rx, text) = match started {
            Ok(_) => (Some(rx), None),
            Err(error) => (None, Some(Err(error.to_string()))),
        };
        self.rule_windows.push(super::rule_window::RuleWindow {
            key,
            rule,
            group,
            text,
            rx,
            raise: std::cell::Cell::new(false),
        });
    }
}

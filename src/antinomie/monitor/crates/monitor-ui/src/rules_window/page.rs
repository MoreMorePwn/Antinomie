// SPDX-License-Identifier: GPL-3.0-only
//! The Detection rules page: YARA, IDS and Sigma tabs; inside each, Installed
//! and Catalog tabs. A pack lists all of its rules in a table and a rule
//! shows its details and source text. Catalog packs show the catalog's
//! metadata only: their rules exist locally after install.
use super::{first_run::ENGINES, theme, Done, Model};
use crate::widgets::{self, table, TabItem, Tone};
use antinomie_monitor_core::ruleset::{self, IndexedRule};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
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

/// The source text of the rule shown in the details.
pub(super) struct RuleText {
    /// The rule set and rule it was read for.
    pub key: (String, String),
    /// `None` while it is read.
    pub text: Option<Result<String, String>>,
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

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "informational" | "info" => 1,
        "low" => 2,
        "medium" => 3,
        "high" => 4,
        "critical" => 5,
        _ => 0,
    }
}

fn severity_tone(severity: &str) -> Tone {
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
        ui.label(RichText::new("Installed packs and custom groups are the only production rules. Scans do not download rules or upload evidence.").color(theme::text()));
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

    /// Forget the selected pack or group and the rules listed for it.
    fn select_none(&mut self) {
        self.pack_id.clear();
        self.group_id.clear();
        self.catalog_pick.clear();
        self.clear_rules();
    }

    fn clear_rules(&mut self) {
        self.rows.clear();
        self.visible.clear();
        self.rows_key.clear();
        self.detail = None;
        self.rule_text = None;
        self.list_gen += 1;
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool) {
        ui.horizontal_wrapped(|ui| {
            let busy = self.job.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Reload local rules"))
                .clicked()
            {
                self.loaded = false;
                self.status_error = None;
                self.rows_key.clear();
                self.ensure(data_dir);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Check for updates"))
                .clicked()
            {
                self.refresh_catalog(data_dir, outbound);
            }
            if busy && ui.button("Cancel").clicked() {
                self.cancel_job();
            }
            if ui.button("Open rules directory").clicked() {
                let root = ruleset::rules_root(data_dir);
                let _ = std::fs::create_dir_all(&root);
                crate::folders::show_detached(root);
            }
        });
    }

    pub(super) fn notices(&mut self, ui: &mut egui::Ui, outbound: &mut bool) {
        if !*outbound {
            ui.horizontal_wrapped(|ui| {
                crate::activity::warning(
                    ui,
                    "Downloads are off: Antinomie contacts no server unless you allow it.",
                );
                if ui
                    .button("Allow downloads")
                    .on_hover_text(
                        "Turns on Settings > Allow outbound catalog and rule downloads. \
                         Only Check for updates and installing or updating a pack use the network, \
                         and only the hosts listed here; scans stay offline.",
                    )
                    .clicked()
                {
                    *outbound = true;
                    self.status = "Downloads allowed. Check for updates reads the catalog.".into();
                }
            });
            ui.add(egui::Label::new(RichText::new(self.hosts_line()).color(theme::text())).wrap());
        }
        // A failure was raised as a toast when it arrived.
        if self.status_error.as_deref() != Some(self.status.as_str()) && !self.status.is_empty() {
            ui.label(RichText::new(&self.status).color(theme::text()));
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
            ui.weak("No pack installed for this engine. Install one from the Catalog tab, or import your own rules below.");
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
        ui.add_space(4.0);
        self.rules_area(ui, data_dir);
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
        self.filter.clear();
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
        let height = table::row_height(font) * (rows.len().min(5) as f32 + 1.5) + 8.0;
        egui::ScrollArea::horizontal()
            .id_salt("rules_sets_scroll")
            .show(ui, |ui| {
                ui.set_min_width(520.0);
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt("rules_sets")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .column(Column::exact(34.0))
                    .column(Column::remainder().at_least(180.0))
                    .column(Column::initial(110.0).at_least(60.0).resizable(true))
                    .column(Column::exact(72.0))
                    .column(Column::initial(150.0).at_least(90.0))
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(table::header_height(font), |mut header| {
                        header.col(|ui| table::head(ui, "On"));
                        for (column, title) in
                            ["Pack", "Version", "Kind", "State"].into_iter().enumerate()
                        {
                            header.col(|ui| {
                                crate::table_sort::header(ui, "rules_sets", column + 1, title)
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(table::row_height(font), rows.len(), |mut row| {
                            let set = &rows[order[row.index()]];
                            let is_selected = selected == set.id;
                            row.set_selected(is_selected);
                            row.col(|ui| {
                                let mut on = set.enabled;
                                if ui.checkbox(&mut on, "").changed() {
                                    toggle = Some((set.id.clone(), set.group, on));
                                }
                            });
                            row.col(|ui| {
                                table::row_mark(
                                    ui,
                                    if is_selected {
                                        table::Mark::Selected
                                    } else {
                                        table::Mark::None
                                    },
                                );
                                table::cell_click(ui, table::Cell::Text, &set.name);
                            });
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Mono, &set.version);
                            });
                            row.col(|ui| {
                                table::cell_click(
                                    ui,
                                    table::Cell::Text,
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
            self.group_actions(ui, data_dir, &set.id);
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
            if ui.button("Export manifest").clicked() {
                self.export_manifest(data_dir, &pack);
            }
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
                        crate::activity::warning(ui, format!("Update available: {newer}"));
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
        egui::CollapsingHeader::new(RichText::new("Custom groups").strong().color(theme::heading()))
            .id_salt("rules-groups")
            .default_open(false)
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.group_name)
                            .desired_width(140.0)
                            .hint_text(theme::hint_text("Group name")),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.tags_text)
                            .desired_width(140.0)
                            .hint_text(theme::hint_text("Tags, comma separated")),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut self.import_path)
                            .desired_width(ui.available_width().min(280.0))
                            .hint_text(theme::hint_text("File or folder")),
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
                ui.weak("Select a custom group in the table to rename it, change its tags, replace or add rules.");
            });
    }

    fn group_actions(&mut self, ui: &mut egui::Ui, data_dir: &Path, id: &str) {
        ui.horizontal_wrapped(|ui| {
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
        ui.weak("Name, tags and the file or folder come from the Custom groups fields above.");
    }

    // ---- Rules of the selected set ----

    fn rule_state(&self, rule: &IndexedRule) -> &'static str {
        if !rule.compatible {
            "incompatible"
        } else if self.rule_disabled(rule) {
            "disabled"
        } else {
            "enabled"
        }
    }

    fn rule_order(&mut self, ctx: &egui::Context) {
        let spec = crate::triage::sort_current(ctx, "rules_list")
            .map(|spec| (spec.column, spec.descending));
        let key = (spec, self.list_gen);
        if self.sorted_for == Some(key) {
            return;
        }
        let mut order = self.visible.clone();
        if let Some((column, descending)) = spec {
            order.sort_by(|&a, &b| {
                let (a, b) = (&self.rows[a], &self.rows[b]);
                let ordering = match column {
                    1 => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
                    2 => severity_rank(&a.severity).cmp(&severity_rank(&b.severity)),
                    3 => self.rule_state(a).cmp(self.rule_state(b)),
                    _ => a.file.to_lowercase().cmp(&b.file.to_lowercase()),
                };
                if descending {
                    ordering.reverse()
                } else {
                    ordering
                }
            });
        }
        self.sorted = order;
        self.sorted_for = Some(key);
    }

    fn rules_area(&mut self, ui: &mut egui::Ui, data_dir: &Path) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Rules").strong().color(theme::heading()));
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(260.0)
                    .hint_text(theme::hint_text("filter e.g. credential")),
            );
            if response.changed() || self.applied != self.filter {
                self.apply_filter();
            }
            ui.label(
                RichText::new(format!(
                    "{} of {} rules",
                    self.visible.len(),
                    self.rows.len()
                ))
                .color(theme::muted()),
            );
        });
        if self.rows_key != self.rule_key() {
            theme::loading(ui, "Reading the rules…");
            return;
        }
        self.rule_order(ui.ctx());
        let total = ui.available_width();
        let gap = 12.0;
        let wide = total >= 760.0;
        let left = if wide { (total - gap) * 0.56 } else { total };
        let height = (ui.clip_rect().bottom() - ui.cursor().top()).clamp(240.0, 640.0);
        let mut picked = None;
        let mut toggle = None;
        ui.horizontal_top(|ui| {
            ui.allocate_ui_with_layout(
                egui::vec2(left, height),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    ui.set_width(left);
                    self.rules_table(ui, height, &mut picked, &mut toggle);
                },
            );
            if wide {
                ui.add_space(gap);
                ui.allocate_ui_with_layout(
                    egui::vec2(total - left - gap, height),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(total - left - gap);
                        self.rule_detail(ui, height, data_dir);
                    },
                );
            }
        });
        if !wide {
            self.rule_detail(ui, 320.0, data_dir);
        }
        if let Some(index) = picked {
            self.pick_rule(index, data_dir);
        }
        if let Some((id, on)) = toggle {
            let dir = data_dir.to_path_buf();
            let key = self.rule_key();
            self.spawn(move |_| {
                ruleset::set_rule_enabled(&dir, &key, &id, on)?;
                let registry = ruleset::load_registry(&dir)?;
                Ok(Done::Registry(registry, format!("Updated rule {id}.")))
            });
        }
    }

    fn rules_table(
        &self,
        ui: &mut egui::Ui,
        height: f32,
        picked: &mut Option<usize>,
        toggle: &mut Option<(String, bool)>,
    ) {
        let font = ui.text_style_height(&egui::TextStyle::Body);
        egui::ScrollArea::horizontal()
            .id_salt("rules_list_scroll")
            .show(ui, |ui| {
                ui.set_min_width(480.0);
                table::begin(ui);
                TableBuilder::new(ui)
                    .id_salt("rules_list")
                    .sense(egui::Sense::click())
                    .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                    .striped(true)
                    .column(Column::exact(34.0))
                    .column(Column::remainder().at_least(160.0).clip(true))
                    .column(Column::exact(96.0))
                    .column(Column::exact(104.0))
                    .column(
                        Column::initial(130.0)
                            .at_least(60.0)
                            .resizable(true)
                            .clip(true),
                    )
                    .max_scroll_height(height)
                    .min_scrolled_height(0.0)
                    .header(table::header_height(font), |mut header| {
                        header.col(|ui| table::head(ui, "On"));
                        for (column, title) in ["Rule", "Severity", "State", "File"]
                            .into_iter()
                            .enumerate()
                        {
                            header.col(|ui| {
                                crate::table_sort::header(ui, "rules_list", column + 1, title)
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(table::row_height(font), self.sorted.len(), |mut row| {
                            let index = self.sorted[row.index()];
                            let rule = &self.rows[index];
                            let state = self.rule_state(rule);
                            let selected = self.detail == Some(index);
                            row.set_selected(selected);
                            row.col(|ui| {
                                let mut on = state == "enabled";
                                if ui
                                    .add_enabled(rule.compatible, egui::Checkbox::new(&mut on, ""))
                                    .changed()
                                {
                                    *toggle = Some((rule.id.clone(), on));
                                }
                            });
                            row.col(|ui| {
                                table::row_mark(
                                    ui,
                                    if selected {
                                        table::Mark::Selected
                                    } else {
                                        table::Mark::None
                                    },
                                );
                                table::cell_click(ui, table::Cell::Mono, &rule.name);
                            });
                            row.col(|ui| {
                                if !rule.severity.is_empty() {
                                    widgets::chip(
                                        ui,
                                        &rule.severity,
                                        severity_tone(&rule.severity),
                                    );
                                }
                            });
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Text, state);
                            });
                            row.col(|ui| {
                                table::cell_click(ui, table::Cell::Text, &rule.file);
                            });
                            if row.response().clicked() {
                                *picked = Some(index);
                            }
                        });
                    });
            });
    }

    fn pick_rule(&mut self, index: usize, data_dir: &Path) {
        self.detail = Some(index);
        let Some(rule) = self.rows.get(index).cloned() else {
            return;
        };
        let key = (self.rule_key(), rule.id.clone());
        let (tx, rx) = mpsc::channel();
        self.rule_text = Some(RuleText { key, text: None });
        self.rule_text_rx = Some(rx);
        let dir = data_dir.to_path_buf();
        let engine = self.engine.clone();
        let (pack, group) = (self.pack_id.clone(), self.group_id.clone());
        let started = thread::Builder::new()
            .name("rule-text".into())
            .spawn(move || {
                let text = if group.is_empty() {
                    ruleset::pack_rule_source(&dir, &engine, &pack, &rule)
                } else {
                    ruleset::group_rule_source(&dir, &group, &rule)
                };
                let _ = tx.send(text);
            });
        if let Err(error) = started {
            if let Some(shown) = &mut self.rule_text {
                shown.text = Some(Err(error.to_string()));
            }
        }
    }

    fn rule_detail(&mut self, ui: &mut egui::Ui, height: f32, data_dir: &Path) {
        let Some(rule) = self.detail.and_then(|index| self.rows.get(index)).cloned() else {
            ui.weak("Select a rule for its details and source text.");
            return;
        };
        let state = self.rule_state(&rule);
        let mut remove = false;
        egui::ScrollArea::vertical()
            .id_salt("rule-detail")
            .max_height(height)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.add(
                    egui::Label::new(RichText::new(&rule.name).strong().color(theme::heading()))
                        .wrap(),
                );
                ui.horizontal_wrapped(|ui| {
                    if !rule.severity.is_empty() {
                        widgets::chip(ui, &rule.severity, severity_tone(&rule.severity));
                    }
                    widgets::chip(
                        ui,
                        state,
                        match state {
                            "enabled" => Tone::Good,
                            "incompatible" => Tone::Warn,
                            _ => Tone::Neutral,
                        },
                    );
                    if rule.helper {
                        widgets::chip(ui, "helper", Tone::Neutral);
                    }
                });
                let tags = rule.tags.join(", ");
                let evidence = rule.evidence.join(", ");
                let references = rule.references.join(", ");
                let depends = rule.depends_on.join(", ");
                for (label, value) in [
                    ("Id", rule.id.as_str()),
                    ("File", rule.file.as_str()),
                    ("License", rule.license.as_str()),
                    ("Source", rule.source_url.as_str()),
                    ("Description", rule.condition.as_str()),
                    ("Tags", tags.as_str()),
                    ("Evidence", evidence.as_str()),
                    ("References", references.as_str()),
                    ("Uses rules", depends.as_str()),
                    (
                        "Compatibility",
                        if rule.compatible {
                            "compatible"
                        } else {
                            rule.reason.as_str()
                        },
                    ),
                ] {
                    if !value.is_empty() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(format!("{label}: {value}")).color(theme::text()),
                            )
                            .wrap(),
                        );
                    }
                }
                if !self.group_id.is_empty() && ui.button("Remove from group").clicked() {
                    remove = true;
                }
                theme::section(ui, "Source text");
                match self
                    .rule_text
                    .as_ref()
                    .filter(|shown| shown.key == (self.rule_key(), rule.id.clone()))
                {
                    Some(RuleText {
                        text: Some(Ok(text)),
                        ..
                    }) => {
                        if ui.small_button("Copy").clicked() {
                            ui.ctx().copy_text(text.clone());
                        }
                        let mut shown = text.as_str();
                        ui.add(
                            egui::TextEdit::multiline(&mut shown)
                                .code_editor()
                                .desired_width(f32::INFINITY),
                        );
                    }
                    Some(RuleText {
                        text: Some(Err(error)),
                        ..
                    }) => {
                        crate::activity::warning(ui, error);
                    }
                    _ => {
                        theme::loading(ui, "Reading the rule…");
                    }
                }
            });
        if remove {
            let dir = data_dir.to_path_buf();
            let id = self.group_id.clone();
            let removed = rule.id.clone();
            self.spawn(move |_| {
                let revision = ruleset::revise_group(&dir, &id, None, &[removed])?;
                let registry = ruleset::load_registry(&dir)?;
                Ok(Done::Registry(
                    registry,
                    format!("Removed a rule from {id} as revision {revision}."),
                ))
            });
            self.rows_key.clear();
        }
    }
}

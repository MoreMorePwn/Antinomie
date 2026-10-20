// SPDX-License-Identifier: MIT
//! Tools → Rule manager. Catalog checks and downloads happen only from buttons.
use crate::theme;
use antinomie_monitor_core::ruleset::{self, Catalog, IndexedRule, Registry};
use eframe::egui::{self, RichText};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

pub(crate) mod first_run;
#[cfg(test)]
mod source_tests;
mod sources;

pub(crate) const WINDOW_ID: &str = "rule_manager";

/// A window the Rule manager asks the app to open, to repair an engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RulesAction {
    AppDependencies,
    AnalysisTools,
}

enum Done {
    Catalog(Catalog),
    Message(String),
    Rules(Vec<IndexedRule>),
    Registry(Registry, String),
    Opened(Registry, Option<Catalog>, String),
    Status(String),
}

struct Job {
    cancel: Arc<AtomicBool>,
    /// The latest status line of a long job, such as a download.
    progress: Arc<Mutex<String>>,
    rx: Receiver<Result<Done, String>>,
}

#[derive(Default)]
pub(crate) struct Model {
    /// A window an engine repair asked for, handed to the app once.
    requested: Option<RulesAction>,
    loaded: bool,
    engine: String,
    filter: String,
    applied: String,
    catalog: Option<Catalog>,
    registry: Registry,
    rows: Vec<IndexedRule>,
    visible: Vec<usize>,
    pack_id: String,
    group_id: String,
    status: String,
    status_error: Option<String>,
    detail: Option<usize>,
    page: usize,
    job: Option<Job>,
    group_name: String,
    import_path: String,
    tags_text: String,
    /// Options chosen per source pack before installing, by pack id.
    choices: BTreeMap<String, BTreeSet<String>>,
    changed: bool,
    /// Tools the triage scans run; a manifest export qualifies packs against them.
    tools: ruleset::ToolConfig,
    #[cfg(test)]
    next_at: Option<egui::Pos2>,
}

impl Model {
    pub(crate) fn changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    fn ensure(&mut self, data_dir: &Path) {
        if self.loaded || self.job.is_some() || self.status_error.is_some() {
            return;
        }
        if self.engine.is_empty() {
            self.engine = "yara".into();
        }
        let dir = data_dir.to_path_buf();
        self.status = "Loading the local rules registry…".into();
        self.spawn(move |_| {
            let migration = ruleset::migrate_indexes(&dir)?;
            let registry = ruleset::load_registry(&dir)?;
            let catalog = ruleset::load_catalog(&dir).ok().flatten();
            let note = if migration.rebuilt.is_empty() {
                "Catalog is local. Check for updates only when you want a download.".into()
            } else {
                format!(
                    "Rebuilt {} obsolete rule indexes from the installed files. Catalog is local.",
                    migration.rebuilt.len()
                )
            };
            Ok(Done::Opened(registry, catalog, note))
        });
    }

    pub(crate) fn profile(&self) -> String {
        if self.loaded {
            ruleset::profile_label_of(&self.registry)
        } else if self.status_error.is_some() {
            "Rules registry unavailable".into()
        } else {
            "Loading rules…".into()
        }
    }

    /// Load and poll local state even when the manager window is closed.
    /// No catalog fetch or rule download is admitted by this operation.
    pub(crate) fn tick(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let previous = self.status_error.clone();
        self.ensure(data_dir);
        self.poll();
        if let Some(error) = self
            .status_error
            .as_ref()
            .filter(|_| self.status_error != previous)
        {
            self.changed |= !self.loaded;
            crate::activity::report(ctx, crate::activity::Level::Error, error);
        }
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    /// Show the manager. `outbound` is the Settings permission; the manager
    /// can turn it on when asked to. Returns a window the manager asks for.
    pub(crate) fn show(
        &mut self,
        ctx: &egui::Context,
        open: &mut bool,
        data_dir: &Path,
        outbound: &mut bool,
        tools: &ruleset::ToolConfig,
        detection: &mut antinomie_monitor_core::analysis::detection::Settings,
    ) -> Option<RulesAction> {
        if self.tools != *tools {
            self.tools = tools.clone();
        }
        self.tick(ctx, data_dir);
        let mut window_open = *open;
        crate::widgets::window("Rule manager")
            .id(egui::Id::new(WINDOW_ID))
            .open(&mut window_open)
            .resizable(true)
            .default_width(720.0)
            .default_height(ctx.screen_rect().height().max(240.0) * 0.92)
            .show(ctx, |ui| {
                ui.set_min_width(0.0);
                ui.set_width(ui.available_width());
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .animated(false)
                    .drag_to_scroll(false)
                    .id_salt("rule-manager-body")
                    .show(ui, |ui| {
                        self.contents(ui, data_dir, outbound, detection);
                    });
            });
        *open = window_open;
        self.requested.take()
    }

    fn poll(&mut self) {
        let finished = self.job.as_ref().and_then(|job| match job.rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("Rules worker ended without a result".into()))
            }
        });
        if let Some(result) = finished {
            self.job = None;
            match result {
                Ok(Done::Catalog(catalog)) => {
                    self.catalog = Some(catalog);
                    self.status = "Catalog updated.".into();
                    self.changed = true;
                }
                Ok(Done::Message(text)) => {
                    self.status = text;
                    self.changed = true;
                    self.loaded = false;
                }
                Ok(Done::Rules(rows)) => {
                    self.rows = rows;
                    self.apply_filter();
                    self.detail = None;
                    self.status = format!("Indexed {} rules.", self.rows.len());
                }
                Ok(Done::Registry(registry, note)) => {
                    if registry.generation < self.registry.generation {
                        self.status = "A newer rules change was kept.".into();
                    } else {
                        self.registry = registry;
                        self.status = note;
                        self.changed = true;
                    }
                }
                Ok(Done::Opened(registry, catalog, note)) => {
                    self.registry = registry;
                    self.catalog = catalog;
                    self.loaded = true;
                    self.status = note;
                    self.changed = true;
                }
                Ok(Done::Status(text)) => self.status = text,
                Err(error) => {
                    self.changed |= !self.loaded;
                    self.status_error = Some(error.clone());
                    self.status = error;
                }
            }
        }
    }

    fn apply_filter(&mut self) {
        self.applied = self.filter.clone();
        let needle = self.filter.to_ascii_lowercase();
        self.visible = self
            .rows
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                needle.is_empty()
                    || rule.id.to_ascii_lowercase().contains(&needle)
                    || rule.name.to_ascii_lowercase().contains(&needle)
                    || rule.file.to_ascii_lowercase().contains(&needle)
                    || rule.severity.to_ascii_lowercase().contains(&needle)
                    || rule
                        .tags
                        .iter()
                        .any(|tag| tag.to_ascii_lowercase().contains(&needle))
                    || rule.reason.to_ascii_lowercase().contains(&needle)
            })
            .map(|(index, _)| index)
            .collect();
        self.page = 0;
    }

    /// Whether the selected engine can scan, and how to repair it if not.
    /// Engine facts come from the shared non-blocking probe.
    fn engine_status(&self, ui: &mut egui::Ui) -> Option<RulesAction> {
        use ruleset::ToolProbe;
        let mut action = None;
        if self.engine == "yara" {
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(theme::good(), "YARA-X is built in.");
                ui.colored_label(
                    theme::muted(),
                    "A downloaded pack is not scanned until it is enabled.",
                );
            });
            return None;
        }
        let repaint = ui.ctx().clone();
        let Some(facts) = ruleset::try_tool_facts(&self.tools, move || {
            repaint.request_repaint_of(egui::ViewportId::ROOT)
        }) else {
            theme::loading(ui, "Checking the engine…");
            return None;
        };
        ui.horizontal_wrapped(
            |ui| match (self.engine.as_str(), &facts.suricata, &facts.sigma) {
                ("ids", probe @ ToolProbe::Found { .. }, _) => {
                    ui.colored_label(theme::good(), format!("{} is installed.", probe.identity()));
                    ui.colored_label(
                        theme::muted(),
                        "Rules that need unsupported keywords or datasets stay skipped.",
                    );
                }
                ("ids", probe, _) => {
                    crate::activity::warning(
                        ui,
                        match probe {
                            ToolProbe::Absent(_) => {
                                "Suricata is not installed, so IDS scans are unavailable. \
                             It is a system package: sudo apt install suricata"
                                    .to_owned()
                            }
                            probe => format!("Suricata cannot scan: {}", probe.identity()),
                        },
                    );
                    if ui.small_button("Copy command").clicked() {
                        ui.ctx().copy_text("sudo apt install suricata".into());
                    }
                    if ui.button("App dependencies…").clicked() {
                        action = Some(RulesAction::AppDependencies);
                    }
                }
                (_, _, probe @ ToolProbe::Found { .. }) => {
                    ui.colored_label(theme::good(), format!("{} is ready.", probe.identity()));
                    ui.colored_label(
                        theme::muted(),
                        format!("Python: {}", facts.sigma_python.display()),
                    );
                }
                (_, _, probe) => {
                    crate::activity::warning(
                        ui,
                        format!(
                            "Sigma cannot scan with {}: {}",
                            facts.sigma_python.display(),
                            probe.identity()
                        ),
                    );
                    if ui
                        .button("Install the Sigma tool…")
                        .on_hover_text(
                            "Tools > Analysis tools installs pySigma and its SQLite backend into \
                         Antinomie's own environment; scans then use it automatically.",
                        )
                        .clicked()
                    {
                        action = Some(RulesAction::AnalysisTools);
                    }
                }
            },
        );
        action
    }

    fn contents(
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
        crate::widgets::tab_row(ui, |ui| {
            for (id, label) in [("yara", "YARA"), ("ids", "IDS"), ("sigma", "Sigma")] {
                if crate::widgets::tab(ui, self.engine == id, &crate::widgets::TabItem::new(label))
                    .clicked()
                {
                    self.engine = id.into();
                    self.rows.clear();
                    self.visible.clear();
                    self.detail = None;
                }
            }
        });
        if let Some(next) = self.engine_status(ui) {
            self.requested = Some(next);
        }
        self.options(ui, data_dir, detection);
        ui.horizontal_wrapped(|ui| {
            let busy = self.job.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Reload local rules"))
                .clicked()
            {
                self.loaded = false;
                self.status_error = None;
                self.ensure(data_dir);
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Check for updates"))
                .clicked()
            {
                self.refresh_catalog(data_dir, *outbound);
            }
            if busy && ui.button("Cancel").clicked() {
                if let Some(job) = &self.job {
                    job.cancel.store(true, Ordering::Relaxed);
                }
            }
            if ui.button("Open rules directory").clicked() {
                let root = ruleset::rules_root(data_dir);
                let _ = std::fs::create_dir_all(&root);
                crate::folders::show_detached(root);
            }
        });
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
        if self.status_error.as_deref() == Some(self.status.as_str()) {
            crate::activity::error(ui, &self.status);
        } else {
            ui.label(RichText::new(&self.status).color(theme::text()));
        }
        if self.job.is_some() {
            let progress = self
                .job
                .as_ref()
                .and_then(|job| job.progress.lock().ok().map(|text| text.clone()))
                .unwrap_or_default();
            ui.horizontal_wrapped(|ui| {
                ui.spinner();
                ui.label(if progress.is_empty() {
                    "Working…"
                } else {
                    progress.as_str()
                });
            });
        }
        ui.separator();
        ui.label(RichText::new("Installed").strong().color(theme::heading()));
        let packs: Vec<_> = self
            .registry
            .packs
            .iter()
            .filter(|pack| pack.engine == self.engine)
            .cloned()
            .collect();
        if packs.is_empty() {
            ui.weak("No pack installed for this engine.");
        }
        for pack in packs {
            let state = if pack.enabled {
                "installed"
            } else {
                "disabled"
            };
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{} {} · {state}", pack.name, pack.version))
                        .color(theme::text()),
                )
                .wrap(),
            );
            ui.horizontal_wrapped(|ui| {
                let mut enabled = pack.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    let dir = data_dir.to_path_buf();
                    let id = pack.id.clone();
                    self.spawn(move |_| {
                        ruleset::set_pack_enabled(&dir, &id, enabled)?;
                        let registry = ruleset::load_registry(&dir)?;
                        Ok(Done::Registry(registry, format!("Updated {id}.")))
                    });
                }
                if ui.button("Rules").clicked() {
                    let dir = data_dir.to_path_buf();
                    let engine = pack.engine.clone();
                    let id = pack.id.clone();
                    self.pack_id = id.clone();
                    self.group_id.clear();
                    self.spawn(move |_| Ok(Done::Rules(ruleset::pack_index(&dir, &engine, &id)?)));
                }
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
                            let registry = ruleset::load_registry(&dir)?;
                            Ok(Done::Registry(
                                registry,
                                format!("Rolled back to {older}. Previous selections were kept."),
                            ))
                        });
                    }
                }
                if ui.button("Export manifest").clicked() {
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
            });
            self.installed_source(ui, data_dir, *outbound, &pack);
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
                                self.install(data_dir, *outbound, entry.clone());
                            }
                        });
                    }
                } else if pack.source.is_none() {
                    ui.weak("This installed version is not in the current catalog.");
                }
            }
        }
        ui.separator();
        ui.label(RichText::new("Catalog").strong().color(theme::heading()));
        if let Some(catalog) = self
            .catalog
            .clone()
            .filter(|catalog| catalog.schema == ruleset::CATALOG_SCHEMA_SOURCES)
        {
            self.source_catalog(ui, data_dir, *outbound, &catalog);
        } else if let Some(catalog) = self.catalog.clone() {
            let entries: Vec<_> = catalog
                .packs
                .iter()
                .filter(|entry| entry.engine == self.engine)
                .cloned()
                .collect();
            if entries.is_empty() {
                ui.weak("The catalog has no pack for this engine.");
            }
            for entry in entries {
                let installed = self
                    .registry
                    .packs
                    .iter()
                    .any(|pack| pack.id == entry.id && pack.version == entry.version);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{} {} · {} rules, {} helpers",
                            entry.name, entry.version, entry.rules, entry.helpers
                        ))
                        .color(theme::text()),
                    )
                    .wrap(),
                );
                ui.horizontal_wrapped(|ui| {
                    if installed {
                        ui.colored_label(theme::good(), "installed");
                    } else if ui.button("Download").clicked() {
                        self.install(data_dir, *outbound, entry.clone());
                    }
                });
                ui.label(
                    RichText::new(format!("{} · {}", entry.license, entry.upstream_revision))
                        .small()
                        .color(theme::muted()),
                );
            }
        } else {
            ui.weak("unavailable — no catalog has been checked yet");
        }
        ui.separator();
        ui.label(
            RichText::new("Custom groups")
                .strong()
                .color(theme::heading()),
        );
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.group_name)
                    .desired_width(140.0)
                    .hint_text(crate::theme::hint_text("Group name")),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.tags_text)
                    .desired_width(140.0)
                    .hint_text(crate::theme::hint_text("Tags, comma separated")),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.import_path)
                    .desired_width(ui.available_width().min(280.0))
                    .hint_text(crate::theme::hint_text("File or folder")),
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
        let groups: Vec<_> = self
            .registry
            .groups
            .iter()
            .filter(|group| group.engine == self.engine && !group.deleted)
            .cloned()
            .collect();
        for group in groups {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{} r{}", group.name, group.revision))
                        .color(theme::text()),
                )
                .wrap(),
            );
            ui.horizontal_wrapped(|ui| {
                let mut enabled = group.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    let dir = data_dir.to_path_buf();
                    let id = group.id.clone();
                    self.spawn(move |_| {
                        ruleset::set_group_enabled(&dir, &id, enabled)?;
                        let registry = ruleset::load_registry(&dir)?;
                        Ok(Done::Registry(registry, format!("Updated group {id}.")))
                    });
                }
                if ui.button("Rules").clicked() {
                    let dir = data_dir.to_path_buf();
                    let id = group.id.clone();
                    self.group_id = id.clone();
                    self.pack_id.clear();
                    self.spawn(move |_| Ok(Done::Rules(ruleset::group_index(&dir, &id)?)));
                }
                if ui.button("Rename").clicked() {
                    let dir = data_dir.to_path_buf();
                    let id = group.id.clone();
                    let name = self.group_name.clone();
                    self.spawn(move |_| {
                        ruleset::rename_group(&dir, &id, &name)?;
                        Ok(Done::Message(format!("Renamed group {id}.")))
                    });
                }
                if ui.button("Save tags").clicked() {
                    let dir = data_dir.to_path_buf();
                    let id = group.id.clone();
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
                    let id = group.id.clone();
                    let path = self.import_path.clone();
                    self.spawn(move |_| {
                        let revision =
                            ruleset::replace_group_revision(&dir, &id, Path::new(&path))?;
                        let registry = ruleset::load_registry(&dir)?;
                        Ok(Done::Registry(
                            registry,
                            format!("Replaced {id} with revision {revision}."),
                        ))
                    });
                }
                if ui.button("Add rules").clicked() {
                    let dir = data_dir.to_path_buf();
                    let id = group.id.clone();
                    let path = self.import_path.clone();
                    self.spawn(move |_| {
                        let revision =
                            ruleset::revise_group(&dir, &id, Some(Path::new(&path)), &[])?;
                        let registry = ruleset::load_registry(&dir)?;
                        Ok(Done::Registry(
                            registry,
                            format!("Added rules to {id} as revision {revision}."),
                        ))
                    });
                }
                if ui.button("Delete").clicked() {
                    let dir = data_dir.to_path_buf();
                    let id = group.id.clone();
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
        ui.separator();
        ui.label(RichText::new("Rules").strong().color(theme::heading()));
        let response = ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .desired_width(ui.available_width())
                .hint_text(crate::theme::hint_text("filter e.g. credential")),
        );
        if response.changed() || self.applied != self.filter {
            self.apply_filter();
        }
        let page_len = 80;
        let pages = self.visible.len().div_ceil(page_len).max(1);
        if self.page >= pages {
            self.page = pages - 1;
        }
        let start = self.page * page_len;
        let end = (start + page_len).min(self.visible.len());
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(self.page > 0, egui::Button::new("Previous"))
                .clicked()
            {
                self.page -= 1;
            }
            let next = ui.add_enabled(self.page + 1 < pages, egui::Button::new("Next"));
            #[cfg(test)]
            {
                self.next_at = Some(next.rect.center());
            }
            if next.clicked() {
                self.page += 1;
            }
        });
        ui.add(
            egui::Label::new(format!(
                "Showing {}–{} of {} matches ({} indexed)",
                if self.visible.is_empty() {
                    0
                } else {
                    start + 1
                },
                end,
                self.visible.len(),
                self.rows.len()
            ))
            .wrap(),
        );
        egui::ScrollArea::vertical()
            .max_height(280.0)
            .id_salt("rule-rows")
            .show(ui, |ui| {
                let page: Vec<usize> = self.visible[start..end].to_vec();
                for index in page {
                    let Some(rule) = self.rows.get(index) else {
                        continue;
                    };
                    let mark = if !rule.compatible {
                        "incompatible"
                    } else if self.rule_disabled(rule) {
                        "disabled"
                    } else {
                        "enabled"
                    };
                    let compatible = rule.compatible;
                    let rule_id = rule.id.clone();
                    let rule_name = rule.name.clone();
                    ui.horizontal_wrapped(|ui| {
                        let mut on = mark == "enabled";
                        if ui
                            .add_enabled(compatible, egui::Checkbox::new(&mut on, ""))
                            .changed()
                        {
                            let dir = data_dir.to_path_buf();
                            let key = self.rule_key();
                            let id = rule_id.clone();
                            self.spawn(move |_| {
                                ruleset::set_rule_enabled(&dir, &key, &id, on)?;
                                let registry = ruleset::load_registry(&dir)?;
                                Ok(Done::Registry(registry, format!("Updated rule {id}.")))
                            });
                        }
                        if !self.group_id.is_empty() && ui.button("Remove").clicked() {
                            let dir = data_dir.to_path_buf();
                            let id = self.group_id.clone();
                            let remove = rule_id.clone();
                            self.spawn(move |_| {
                                let revision = ruleset::revise_group(&dir, &id, None, &[remove])?;
                                let registry = ruleset::load_registry(&dir)?;
                                Ok(Done::Registry(
                                    registry,
                                    format!("Removed a rule from {id} as revision {revision}."),
                                ))
                            });
                        }
                        if ui
                            .add(
                                egui::Button::new(format!("{rule_name} · {mark}"))
                                    .selected(self.detail == Some(index))
                                    .frame(false)
                                    .truncate(),
                            )
                            .clicked()
                        {
                            self.detail = Some(index);
                        }
                    });
                }
            });
        if let Some(index) = self.detail {
            if let Some(rule) = self.rows.get(index) {
                ui.separator();
                ui.label(RichText::new(&rule.name).strong().color(theme::heading()));
                for (label, value) in [
                    ("Id", rule.id.as_str()),
                    ("File", rule.file.as_str()),
                    ("License", rule.license.as_str()),
                    ("Source", rule.source_url.as_str()),
                    ("Severity", rule.severity.as_str()),
                    ("Condition", rule.condition.as_str()),
                    ("Evidence", &rule.evidence.join(", ")),
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
                        ui.label(RichText::new(format!("{label}: {value}")).color(theme::text()));
                    }
                }
                if !rule.references.is_empty() {
                    ui.label(
                        RichText::new(format!("References: {}", rule.references.join(", ")))
                            .color(theme::text()),
                    );
                }
            }
        }
    }

    fn options(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        detection: &mut antinomie_monitor_core::analysis::detection::Settings,
    ) {
        egui::CollapsingHeader::new("Options")
            .id_salt("rule-manager-options")
            .default_open(true)
            .show(ui, |ui| {
                match self.engine.as_str() {
                    "yara" => {
                        ui.checkbox(
                            &mut detection.scan_memory,
                            "Scan recorded core / RAM extents",
                        );
                        ui.checkbox(&mut detection.scan_recovered, "Scan recovered files");
                    }
                    "sigma" => {
                        ui.label("Python with pySigma and its SQLite backend");
                        ui.add(
                            egui::TextEdit::singleline(&mut detection.sigma_python)
                                .desired_width(ui.available_width())
                                .hint_text(crate::theme::hint_text("Empty: Antinomie's Sigma tool")),
                        );
                    }
                    _ => {}
                }
                let legacy = match self.engine.as_str() {
                    "yara" => detection.yara_rules.clone(),
                    "ids" => detection.ids_rules.clone(),
                    "sigma" => detection.sigma_rules.clone(),
                    _ => String::new(),
                };
                let legacy = legacy.trim().to_owned();
                if legacy.is_empty() {
                    return;
                }
                ui.label(
                    RichText::new(format!("Saved local path: {legacy}")).color(theme::text()),
                );
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Import as custom group").clicked() {
                        let dir = data_dir.to_path_buf();
                        let engine = self.engine.clone();
                        let path = legacy.clone();
                        let name = Path::new(&path)
                            .file_stem()
                            .and_then(|name| name.to_str())
                            .unwrap_or("local")
                            .to_owned();
                        self.spawn(move |_| {
                            let id = ruleset::import_group(&dir, &name, &engine, Path::new(&path))?;
                            Ok(Done::Message(format!(
                                "Imported {id} as a managed copy. Scans still use the saved path until Forget."
                            )))
                        });
                    }
                    if ui.button("Forget").clicked() {
                        match self.engine.as_str() {
                            "yara" => detection.yara_rules.clear(),
                            "ids" => detection.ids_rules.clear(),
                            "sigma" => detection.sigma_rules.clear(),
                            _ => {}
                        }
                    }
                });
            });
    }

    fn rule_key(&self) -> String {
        if !self.pack_id.is_empty() {
            format!("pack:{}", self.pack_id)
        } else {
            format!("group:{}", self.group_id)
        }
    }

    fn rule_disabled(&self, rule: &IndexedRule) -> bool {
        self.registry
            .disabled
            .get(&self.rule_key())
            .is_some_and(|ids| ids.contains(&rule.id))
    }

    fn refresh_catalog(&mut self, data_dir: &Path, outbound: bool) {
        if !outbound {
            self.status = "Enable outbound catalog access in Settings, then check again.".into();
            return;
        }
        let dir = data_dir.to_path_buf();
        self.status = "Checking the catalog…".into();
        self.spawn(move |cancel| {
            let catalog = ruleset::refresh_catalog(
                &dir,
                ruleset::CATALOG_URL,
                &ruleset::Curl::default(),
                &cancel,
            )?;
            Ok(Done::Catalog(catalog))
        });
    }

    fn install(&mut self, data_dir: &Path, outbound: bool, entry: ruleset::PackEntry) {
        if !outbound {
            self.status =
                "Enable outbound catalog access in Settings before downloading a pack.".into();
            return;
        }
        let dir = data_dir.to_path_buf();
        self.status = format!("Downloading {}…", entry.name);
        self.spawn(move |cancel| {
            let bytes =
                ruleset::download_archive(&dir, &entry, &ruleset::Curl::default(), &cancel)?;
            ruleset::install_archive(&dir, &entry, &bytes)?;
            Ok(Done::Message(format!(
                "Installed {} {}.",
                entry.name, entry.version
            )))
        });
    }

    fn spawn(
        &mut self,
        work: impl FnOnce(Arc<AtomicBool>) -> Result<Done, String> + Send + 'static,
    ) {
        self.spawn_with_progress(move |cancel, _| work(cancel));
    }

    fn spawn_with_progress(
        &mut self,
        work: impl FnOnce(Arc<AtomicBool>, Arc<Mutex<String>>) -> Result<Done, String> + Send + 'static,
    ) {
        if self.job.is_some() {
            self.status = "A rules job is already running.".into();
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let progress = Arc::new(Mutex::new(String::new()));
        let shown = Arc::clone(&progress);
        let (tx, rx) = mpsc::channel();
        if let Err(error) = thread::Builder::new()
            .name("rules-job".into())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(flag, shown)));
                let message = match result {
                    Ok(result) => result,
                    Err(_) => Err("rules job panicked".into()),
                };
                let _ = tx.send(message);
            })
        {
            self.status_error = Some(error.to_string());
            self.status = error.to_string();
            return;
        }
        self.job = Some(Job {
            cancel,
            progress,
            rx,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_manager_pages_a_large_pack_in_narrow_dark_and_light_panes() {
        let dir = std::env::temp_dir().join(format!("ant-rules-ui-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../monitor-core/assets/rules/yara-forge-core.yar");
        let archive_path = dir.join("pack.tar.gz");
        let script = r#"
import gzip, io, sys, tarfile
source, destination = sys.argv[1], sys.argv[2]
data = open(source, "rb").read()
raw = io.BytesIO()
with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as archive:
    info = tarfile.TarInfo("yara-forge-core.yar")
    info.size = len(data)
    info.mtime = 0
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(data))
with open(destination, "wb") as output:
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
        compressed.write(raw.getvalue())
"#;
        let packed = std::process::Command::new("python3")
            .args([
                "-c",
                script,
                source.to_str().unwrap(),
                archive_path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(packed.success());
        let bytes = std::fs::read(&archive_path).unwrap();
        let sha = antinomie_monitor_core::storage::sha256_hex(&bytes);
        let entry = ruleset::PackEntry {
            id: "yara-forge-core".into(),
            engine: "yara".into(),
            name: "YARA-Forge Core".into(),
            version: "20261004-r3".into(),
            upstream_revision: "20261004".into(),
            upstream_url: "https://github.com/YARAHQ/yara-forge".into(),
            download_url: "https://example.invalid/yara.tar.gz".into(),
            sha256: sha,
            size: bytes.len() as u64,
            app: ">=0.6.2".into(),
            engine_requirement: "YARA-X 1.21".into(),
            rules: 2094,
            helpers: 2,
            license: "per-rule".into(),
            evidence: vec!["sample".into()],
            limits: Vec::new(),
        };
        ruleset::install_archive(&dir, &entry, &bytes).unwrap();
        let mut model = Model::default();
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let narrow = egui::vec2(420.0, 2400.0);
        for (light, font) in [(false, 22.0_f32), (true, 22.0_f32)] {
            crate::theme::apply(&ctx, light);
            crate::theme::text_size(&ctx, font);
            let start = std::time::Instant::now();
            let mut output = render_manager(&ctx, &mut model, &dir, narrow, Vec::new());
            while !texts(&output)
                .iter()
                .any(|(text, _, _)| text.contains("YARA-Forge Core"))
            {
                assert!(
                    start.elapsed() < Duration::from_secs(60),
                    "registry did not load: status={} packs={}",
                    model.status,
                    model.registry.packs.len()
                );
                thread::sleep(Duration::from_millis(20));
                output = render_manager(
                    &ctx,
                    &mut model,
                    &dir,
                    narrow,
                    vec![
                        egui::Event::PointerMoved(egui::pos2(160.0, 180.0)),
                        egui::Event::MouseWheel {
                            unit: egui::MouseWheelUnit::Point,
                            delta: egui::vec2(0.0, -200.0),
                            modifiers: egui::Modifiers::NONE,
                        },
                    ],
                );
            }
            let shown = texts(&output);
            assert!(
                shown
                    .iter()
                    .any(|(text, _, _)| text.contains("YARA-Forge Core")),
                "pack missing in {} theme; packs={} status={} texts={:?}",
                if light { "light" } else { "dark" },
                model.registry.packs.len(),
                model.status,
                shown
                    .iter()
                    .map(|(text, _, _)| text.clone())
                    .collect::<Vec<_>>()
            );
            let overflow: Vec<String> = shown
                .iter()
                .filter(|(_, rect, clip)| {
                    let visible = rect.intersect(*clip);
                    visible.right() > narrow.x + 1.0
                        || visible.left() < -1.0
                        || (rect.right() > narrow.x + 1.0 && clip.right() >= narrow.x - 1.0)
                })
                .map(|(text, rect, _)| format!("{rect:?} {text}"))
                .collect();
            assert!(
                overflow.is_empty(),
                "text extends past the narrow pane: {overflow:?}"
            );
            let sample = shown
                .iter()
                .find(|(text, _, _)| text.contains("YARA-Forge Core"))
                .unwrap()
                .1
                .height();
            assert!(sample >= font, "large text did not grow the pack label");
        }
        let rules = texts(&render_manager(&ctx, &mut model, &dir, narrow, Vec::new()))
            .into_iter()
            .find(|(text, _, _)| text == "Rules")
            .expect("Rules control")
            .1
            .center();
        click_manager(&ctx, &mut model, &dir, narrow, rules);
        let start = std::time::Instant::now();
        while model.rows.len() < 1_000 {
            let _ = render_manager(&ctx, &mut model, &dir, narrow, Vec::new());
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "rule index did not load"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert!(model.rows.len() > 2_000);
        assert!(
            model.visible.len() > 2_000,
            "loaded rules were not listed: visible={}",
            model.visible.len()
        );
        let first = texts(&render_manager(&ctx, &mut model, &dir, narrow, Vec::new()));
        assert!(
            first.iter().all(|(_, rect, clip)| {
                let visible = rect.intersect(*clip);
                visible.right() <= narrow.x + 1.0
                    && visible.left() >= -1.0
                    && !(rect.right() > narrow.x + 1.0 && clip.right() >= narrow.x - 1.0)
            }),
            "rule text extends past the narrow pane"
        );
        assert!(
            first.iter().any(|(text, _, _)| text.contains("Showing 1–")),
            "page label missing; page={} visible={} texts={:?}",
            model.page,
            model.visible.len(),
            first
                .iter()
                .map(|(text, _, _)| text.as_str())
                .filter(|text| {
                    text.contains("Showing") || *text == "Next" || text.contains("Indexed")
                })
                .collect::<Vec<_>>()
        );
        let next = first
            .iter()
            .find(|(text, _, _)| text == "Next")
            .expect("Next page")
            .1
            .center();
        click_manager(&ctx, &mut model, &dir, narrow, next);
        let second = texts(&render_manager(&ctx, &mut model, &dir, narrow, Vec::new()));
        assert!(
            second
                .iter()
                .any(|(text, _, _)| text.contains("Showing 81–")),
            "paging did not advance: {:?}",
            second
                .iter()
                .map(|(text, _, _)| text.as_str())
                .filter(|text| text.contains("Showing"))
                .collect::<Vec<_>>()
        );
        for (width, height) in [(800.0_f32, 480.0_f32), (520.0, 640.0)] {
            model.page = 0;
            let size = egui::vec2(width, height);
            ctx.memory_mut(|memory| {
                memory.reset_areas();
                memory.data.clear();
            });
            for light in [false, true] {
                model.page = 0;
                crate::theme::apply(&ctx, light);
                crate::theme::text_size(&ctx, 22.0);
                let next = visible_control(&ctx, &mut model, &dir, size, "Next");
                click_manager(&ctx, &mut model, &dir, size, next);
                let page = model.page;
                let shown = texts(&render_manager(&ctx, &mut model, &dir, size, Vec::new()));
                assert!(
                    shown
                        .iter()
                        .any(|(text, _, _)| text.contains("Showing 81–")),
                    "short {}x{} {} theme did not page: page={page} click={next:?} {:?}",
                    width,
                    height,
                    if light { "light" } else { "dark" },
                    shown
                        .iter()
                        .map(|(text, _, _)| text.as_str())
                        .filter(|text| text.contains("Showing") || *text == "Next")
                        .collect::<Vec<_>>()
                );
                let overflow: Vec<String> = shown
                    .iter()
                    .filter(|(_, rect, clip)| {
                        let visible = rect.intersect(*clip);
                        visible.right() > width + 1.0
                            || visible.left() < -1.0
                            || (rect.right() > width + 1.0 && clip.right() >= width - 1.0)
                    })
                    .map(|(text, rect, _)| format!("{rect:?} {text}"))
                    .collect();
                assert!(
                    overflow.is_empty(),
                    "text extends past {width}x{height}: {overflow:?}"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn render_manager(
        ctx: &egui::Context,
        model: &mut Model,
        dir: &Path,
        size: egui::Vec2,
        events: Vec<egui::Event>,
    ) -> egui::FullOutput {
        render_with(
            ctx,
            model,
            dir,
            size,
            events,
            &mut false,
            &ruleset::ToolConfig::default(),
        )
        .0
    }

    fn render_with(
        ctx: &egui::Context,
        model: &mut Model,
        dir: &Path,
        size: egui::Vec2,
        events: Vec<egui::Event>,
        outbound: &mut bool,
        tools: &ruleset::ToolConfig,
    ) -> (egui::FullOutput, Option<RulesAction>) {
        let mut open = true;
        let mut action = None;
        let mut detection = antinomie_monitor_core::analysis::detection::Settings::default();
        ctx.style_mut(|style| {
            style.animation_time = 0.0;
        });
        let output = ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                events,
                ..Default::default()
            },
            |ctx| {
                action = model.show(ctx, &mut open, dir, outbound, tools, &mut detection);
            },
        );
        (output, action)
    }

    #[test]
    fn options_move_scan_settings_and_keep_a_legacy_path_until_forget() {
        let dir = std::env::temp_dir().join(format!("ant-rules-options-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut model = Model {
            loaded: true,
            engine: "yara".into(),
            ..Default::default()
        };
        let mut detection = antinomie_monitor_core::analysis::detection::Settings {
            yara_rules: dir.join("old.yar").display().to_string(),
            scan_memory: false,
            ..Default::default()
        };
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let size = egui::vec2(960.0, 900.0);
        let mut open = true;
        let mut outbound = false;
        let tools = ruleset::ToolConfig::default();
        let mut paint =
            |events: Vec<egui::Event>,
             model: &mut Model,
             detection: &mut antinomie_monitor_core::analysis::detection::Settings| {
                ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, size)),
                        events,
                        ..Default::default()
                    },
                    |ctx| {
                        let _ = model.show(ctx, &mut open, &dir, &mut outbound, &tools, detection);
                    },
                )
            };
        let _ = paint(Vec::new(), &mut model, &mut detection);
        let output = paint(Vec::new(), &mut model, &mut detection);
        let joined = texts(&output)
            .into_iter()
            .map(|(text, _, _)| text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("Scan recorded core / RAM extents"),
            "shapes={} text={joined:?}",
            output.shapes.len()
        );
        assert!(joined.contains("Scan recovered files"), "{joined}");
        assert!(joined.contains("Saved local path:"), "{joined}");
        assert!(joined.contains("Import as custom group"), "{joined}");
        assert!(joined.contains("Forget"), "{joined}");
        assert!(!joined.contains("Additional local rule"), "{joined}");
        let forget = texts(&output)
            .into_iter()
            .find(|(text, _, _)| text == "Forget")
            .expect("Forget")
            .1
            .center();
        let _ = paint(
            vec![
                egui::Event::PointerMoved(forget),
                egui::Event::PointerButton {
                    pos: forget,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
                egui::Event::PointerButton {
                    pos: forget,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            &mut model,
            &mut detection,
        );
        assert!(
            detection.yara_rules.is_empty(),
            "Forget clears the saved path scans keep using"
        );
        model.engine = "sigma".into();
        let output = paint(Vec::new(), &mut model, &mut detection);
        let joined = texts(&output)
            .into_iter()
            .map(|(text, _, _)| text)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            joined.contains("Python with pySigma and its SQLite backend"),
            "{joined}"
        );
        assert!(joined.contains("Empty: Antinomie's Sigma tool"), "{joined}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Click the first text that equals `label`, rendering until it shows.
    fn click_label(
        ctx: &egui::Context,
        model: &mut Model,
        dir: &Path,
        outbound: &mut bool,
        tools: &ruleset::ToolConfig,
        label: &str,
    ) -> Option<RulesAction> {
        let size = egui::vec2(900.0, 900.0);
        let start = std::time::Instant::now();
        let position = loop {
            let (output, _) = render_with(ctx, model, dir, size, Vec::new(), outbound, tools);
            if let Some((_, rect, _)) = texts(&output)
                .into_iter()
                .find(|(text, _, _)| text == label)
            {
                break rect.center();
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "{label} never appeared"
            );
            thread::sleep(Duration::from_millis(20));
        };
        let mut action = None;
        for pressed in [None, Some(true), Some(false)] {
            let mut events = vec![egui::Event::PointerMoved(position)];
            if let Some(pressed) = pressed {
                events.push(egui::Event::PointerButton {
                    pos: position,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                });
            }
            action = render_with(ctx, model, dir, size, events, outbound, tools)
                .1
                .or(action);
        }
        action
    }

    #[test]
    fn the_manager_allows_downloads_and_sends_each_engine_to_its_repair() {
        let dir = std::env::temp_dir().join(format!("ant-rules-repair-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ctx = egui::Context::default();
        crate::theme::install(&ctx);
        let mut model = Model::default();
        let mut outbound = false;
        let tools = ruleset::ToolConfig::from_sigma_setting("/nonexistent/antinomie-python");
        // Opening the manager loads the local registry in a job; let it finish
        // so the check below sees only what the button started.
        let start = std::time::Instant::now();
        while !model.loaded || model.job.is_some() {
            let size = egui::vec2(900.0, 900.0);
            let _ = render_with(
                &ctx,
                &mut model,
                &dir,
                size,
                Vec::new(),
                &mut outbound,
                &tools,
            );
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "the registry never loaded"
            );
            thread::sleep(Duration::from_millis(20));
        }
        click_label(
            &ctx,
            &mut model,
            &dir,
            &mut outbound,
            &tools,
            "Allow downloads",
        );
        assert!(outbound, "the button grants the Settings permission");
        assert!(model.status.starts_with("Downloads allowed"));
        assert!(
            model.job.is_none(),
            "allowing downloads does not contact the catalog"
        );

        model.engine = "sigma".into();
        let action = click_label(
            &ctx,
            &mut model,
            &dir,
            &mut outbound,
            &tools,
            "Install the Sigma tool…",
        );
        assert_eq!(action, Some(RulesAction::AnalysisTools));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn visible_control(
        ctx: &egui::Context,
        model: &mut Model,
        dir: &Path,
        size: egui::Vec2,
        label: &str,
    ) -> egui::Pos2 {
        let mut settled = None;
        for _ in 0..30 {
            let _ = render_manager(
                ctx,
                model,
                dir,
                size,
                vec![egui::Event::PointerMoved(egui::pos2(
                    size.x * 0.5,
                    size.y * 0.5,
                ))],
            );
            if let Some(pos) = model.next_at {
                let on_screen = pos.x >= 0.0 && pos.y >= 0.0 && pos.x <= size.x && pos.y <= size.y;
                if on_screen && settled == Some(pos) {
                    return pos;
                }
                settled = Some(pos);
            }
            let _ = render_manager(
                ctx,
                model,
                dir,
                size,
                vec![egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(0.0, -160.0),
                    modifiers: egui::Modifiers::NONE,
                }],
            );
        }
        panic!("{label} was not reachable in {size:?}");
    }

    fn click_manager(
        ctx: &egui::Context,
        model: &mut Model,
        dir: &Path,
        size: egui::Vec2,
        pos: egui::Pos2,
    ) {
        let frames = [
            vec![egui::Event::PointerMoved(pos)],
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
            vec![
                egui::Event::PointerMoved(pos),
                egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        ];
        for events in frames {
            let _ = render_manager(ctx, model, dir, size, events);
        }
    }

    fn texts(output: &egui::FullOutput) -> Vec<(String, egui::Rect, egui::Rect)> {
        fn collect(
            shape: &egui::epaint::Shape,
            clip: egui::Rect,
            out: &mut Vec<(String, egui::Rect, egui::Rect)>,
        ) {
            match shape {
                egui::epaint::Shape::Text(text) => out.push((
                    text.galley.text().to_owned(),
                    egui::Rect::from_min_size(text.pos, text.galley.size()),
                    clip,
                )),
                egui::epaint::Shape::Vec(shapes) => {
                    for shape in shapes {
                        collect(shape, clip, out);
                    }
                }
                _ => {}
            }
        }
        let mut result = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, shape.clip_rect, &mut result);
        }
        result
    }
}

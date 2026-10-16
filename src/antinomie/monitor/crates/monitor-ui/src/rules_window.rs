// SPDX-License-Identifier: MIT
//! Tools → Rule manager. Catalog checks and downloads happen only from buttons.
use crate::theme;
use antinomie_monitor_core::ruleset::{self, Catalog, IndexedRule, Registry};
use eframe::egui::{self, RichText};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
    thread,
    time::Duration,
};

pub(crate) const WINDOW_ID: &str = "rule_manager";

enum Done {
    Catalog(Catalog),
    Message(String),
    Rules(Vec<IndexedRule>),
}

struct Job {
    cancel: Arc<AtomicBool>,
    rx: Receiver<Result<Done, String>>,
}

#[derive(Default)]
pub(crate) struct Model {
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
    detail: Option<usize>,
    page: usize,
    job: Option<Job>,
    group_name: String,
    import_path: String,
    tags_text: String,
    changed: bool,
}

impl Model {
    pub(crate) fn changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }

    fn ensure(&mut self, data_dir: &Path) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        if self.engine.is_empty() {
            self.engine = "yara".into();
        }
        self.registry = ruleset::load_registry(data_dir).unwrap_or_default();
        self.catalog = ruleset::load_catalog(data_dir).ok().flatten();
        self.status = "Catalog is local. Check for updates only when you want a download.".into();
    }

    pub(crate) fn show(
        &mut self,
        ctx: &egui::Context,
        open: &mut bool,
        data_dir: &Path,
        outbound: bool,
    ) {
        self.ensure(data_dir);
        self.poll();
        let mut window_open = *open;
        egui::Window::new("Rule manager")
            .id(egui::Id::new(WINDOW_ID))
            .open(&mut window_open)
            .resizable(true)
            .default_width(720.0)
            .show(ctx, |ui| {
                ui.set_min_width(0.0);
                self.contents(ui, data_dir, outbound);
            });
        *open = window_open;
    }

    fn poll(&mut self) {
        let finished = self.job.as_ref().and_then(|job| job.rx.try_recv().ok());
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
                    self.applied.clear();
                    self.page = 0;
                    self.detail = None;
                    self.status = format!("Indexed {} rules.", self.rows.len());
                }
                Err(error) => self.status = error,
            }
        }
    }

    fn contents(&mut self, ui: &mut egui::Ui, data_dir: &Path, outbound: bool) {
        if !self.loaded {
            self.ensure(data_dir);
        }
        ui.label(RichText::new("Installed packs and custom groups are the only production rules. Scans do not download rules or upload evidence.").color(theme::text()));
        ui.horizontal_wrapped(|ui| {
            for (id, label) in [("yara", "YARA"), ("ids", "IDS"), ("sigma", "Sigma")] {
                if ui
                    .selectable_value(&mut self.engine, id.into(), label)
                    .clicked()
                {
                    self.rows.clear();
                    self.visible.clear();
                    self.detail = None;
                }
            }
        });
        let suricata = [
            "/usr/bin/suricata",
            "/usr/sbin/suricata",
            "/usr/local/bin/suricata",
        ]
        .iter()
        .any(|path| Path::new(path).is_file());
        let engine_note = match self.engine.as_str() {
            "yara" => "YARA-X is built in. A downloaded pack is not scanned until it is enabled.",
            "ids" if suricata => "Suricata is installed. Rules that need unsupported keywords or datasets stay skipped.",
            "ids" => "Suricata is not installed. Install it from App dependencies before an IDS scan.",
            _ => "Sigma scans need local Python with pySigma and the SQLite backend. A missing tool stays unavailable.",
        };
        ui.label(RichText::new(engine_note).color(theme::muted()));
        ui.horizontal_wrapped(|ui| {
            let busy = self.job.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Check for updates"))
                .clicked()
            {
                self.refresh_catalog(data_dir, outbound);
            }
            if busy && ui.button("Cancel").clicked() {
                if let Some(job) = &self.job {
                    job.cancel.store(true, Ordering::Relaxed);
                }
            }
            if ui.button("Open rules directory").clicked() {
                let root = ruleset::rules_root(data_dir);
                let _ = std::fs::create_dir_all(&root);
                let _ = std::process::Command::new("xdg-open").arg(&root).spawn();
            }
        });
        if !outbound {
            ui.colored_label(
                theme::warn(),
                "Outbound catalog access is disabled in Settings.",
            );
        }
        ui.label(RichText::new(&self.status).color(theme::text()));
        if self.job.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Working…");
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
            ui.horizontal_wrapped(|ui| {
                let mut enabled = pack.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    let _ = ruleset::set_pack_enabled(data_dir, &pack.id, enabled);
                    self.changed = true;
                    self.loaded = false;
                }
                let state = if pack.enabled {
                    "installed"
                } else {
                    "disabled"
                };
                ui.label(
                    RichText::new(format!("{} {} · {state}", pack.name, pack.version))
                        .color(theme::text()),
                );
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
                    {
                        match ruleset::rollback(data_dir, &pack.id, older) {
                            Ok(()) => {
                                self.status = format!(
                                    "Rolled back to {older}. Previous selections were kept."
                                );
                                self.changed = true;
                                self.loaded = false;
                            }
                            Err(error) => self.status = error,
                        }
                    }
                }
                if ui.button("Export manifest").clicked() {
                    self.export_manifest(data_dir, &pack.engine, &pack.id, &pack.version);
                }
            });
            if let Some(catalog) = &self.catalog {
                if let Some(entry) = catalog
                    .packs
                    .iter()
                    .find(|entry| entry.id == pack.id)
                    .cloned()
                {
                    if entry.version != pack.version {
                        let newer = entry.version.clone();
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!("Update available: {newer}"))
                                    .color(theme::warn()),
                            );
                            if ui.button("Update").clicked() {
                                self.install(data_dir, outbound, entry.clone());
                            }
                        });
                    }
                } else {
                    ui.weak("This installed version is not in the current catalog.");
                }
            }
        }
        ui.separator();
        ui.label(RichText::new("Catalog").strong().color(theme::heading()));
        if let Some(catalog) = self.catalog.clone() {
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
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} {} · {} rules, {} helpers",
                            entry.name, entry.version, entry.rules, entry.helpers
                        ))
                        .color(theme::text()),
                    );
                    if installed {
                        ui.colored_label(theme::good(), "installed");
                    } else if ui.button("Download").clicked() {
                        self.install(data_dir, outbound, entry.clone());
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
                    .hint_text("Group name"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.tags_text)
                    .desired_width(140.0)
                    .hint_text("Tags, comma separated"),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.import_path)
                    .desired_width(ui.available_width().min(280.0))
                    .hint_text("File or folder"),
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
            ui.horizontal_wrapped(|ui| {
                let mut enabled = group.enabled;
                if ui.checkbox(&mut enabled, "").changed() {
                    let _ = ruleset::set_group_enabled(data_dir, &group.id, enabled);
                    self.changed = true;
                    self.loaded = false;
                }
                ui.label(
                    RichText::new(format!("{} r{}", group.name, group.revision))
                        .color(theme::text()),
                );
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
                if ui.button("Delete").clicked() {
                    let _ = ruleset::delete_group(data_dir, &group.id, false);
                    self.status =
                        "Group disabled. Retained files stay so older results keep their source."
                            .into();
                    self.changed = true;
                    self.loaded = false;
                }
            });
        }
        ui.separator();
        ui.label(RichText::new("Rules").strong().color(theme::heading()));
        let response = ui.add(
            egui::TextEdit::singleline(&mut self.filter)
                .desired_width(ui.available_width())
                .hint_text("Filter by id, name, source, tag, severity"),
        );
        if response.changed() || self.applied != self.filter {
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
            if ui
                .add_enabled(self.page + 1 < pages, egui::Button::new("Next"))
                .clicked()
            {
                self.page += 1;
            }
            ui.weak(format!(
                "Showing {}–{} of {} matches ({} indexed)",
                if self.visible.is_empty() {
                    0
                } else {
                    start + 1
                },
                end,
                self.visible.len(),
                self.rows.len()
            ));
        });
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
                            let key = self.rule_key();
                            let _ = ruleset::set_rule_enabled(data_dir, &key, &rule_id, on);
                            self.changed = true;
                            self.loaded = false;
                        }
                        if ui
                            .selectable_label(
                                self.detail == Some(index),
                                format!("{rule_name} · {mark}"),
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
        self.spawn(move |cancel| {
            let bytes = fetch(ruleset::CATALOG_URL, &cancel, 2 * 1024 * 1024)?;
            let value = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
            let catalog = ruleset::validate_catalog(&value)?;
            ruleset::store_catalog(&dir, &catalog)?;
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
            let bytes = fetch(&entry.download_url, &cancel, entry.size)?;
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
        if self.job.is_some() {
            self.status = "A rules job is already running.".into();
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancel);
        let (tx, rx) = mpsc::channel();
        if let Err(error) = thread::Builder::new()
            .name("rules-job".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(flag)));
                let message = match result {
                    Ok(result) => result,
                    Err(_) => Err("rules job panicked".into()),
                };
                let _ = tx.send(message);
            })
        {
            self.status = error.to_string();
            return;
        }
        self.job = Some(Job { cancel, rx });
    }

    fn export_manifest(&mut self, data_dir: &Path, engine: &str, id: &str, version: &str) {
        let source = ruleset::rules_root(data_dir)
            .join("packs")
            .join(engine)
            .join(id)
            .join(version)
            .join("manifest.json");
        let dest_dir = ruleset::rules_root(data_dir).join("exports");
        if let Err(error) = std::fs::create_dir_all(&dest_dir) {
            self.status = error.to_string();
            return;
        }
        let dest = dest_dir.join(format!("{id}-{version}.json"));
        match std::fs::copy(&source, &dest) {
            Ok(_) => self.status = format!("Exported {}", dest.display()),
            Err(error) => self.status = error.to_string(),
        }
    }
}

fn fetch(url: &str, cancel: &AtomicBool, max_bytes: u64) -> Result<Vec<u8>, String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let output = std::env::temp_dir().join(format!(
        "ant-rules-download-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&output);
    let limit = max_bytes.max(1).to_string();
    let mut child = std::process::Command::new("curl")
        .args(["-fsSL", "--max-time", "300", "--max-filesize", &limit, "-o"])
        .arg(&output)
        .arg(url)
        .spawn()
        .map_err(|error| format!("curl: {error}"))?;
    loop {
        if cancel.load(Ordering::Relaxed) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_file(&output);
            return Err("cancelled".into());
        }
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(status) if status.success() => break,
            Some(status) => return Err(format!("download failed ({status})")),
            None => thread::sleep(Duration::from_millis(150)),
        }
    }
    let bytes = std::fs::read(&output).map_err(|error| error.to_string())?;
    let _ = std::fs::remove_file(&output);
    Ok(bytes)
}

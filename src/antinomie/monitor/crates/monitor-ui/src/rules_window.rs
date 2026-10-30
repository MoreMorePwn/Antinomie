// SPDX-License-Identifier: GPL-3.0-only
//! Library → Detection rules. Catalog checks and downloads happen only from buttons.
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

mod abusech;
mod catalog_tab;
pub(crate) mod first_run;
mod ioc;
mod page;
#[cfg(test)]
mod page_tests;
mod regex_tab;
#[cfg(test)]
pub(crate) mod source_tests;
mod sources;

use page::{RuleText, Tab};

/// A window or page the Detection rules page asks the app to open, to repair an engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RulesAction {
    AppDependencies,
    AnalysisTools,
    /// Tools > API keys, where the abuse.ch Auth-Key is set.
    ApiKeys,
}

enum Done {
    Catalog(Catalog),
    Message(String),
    /// The rules of the set with this key (`pack:<id>` or `group:<id>`).
    Rules(String, Vec<IndexedRule>),
    Registry(Registry, String),
    Opened(Registry, Option<Catalog>, String),
    Status(String),
    /// A dataset download finished; the text says what was updated or failed.
    Ioc(String),
    /// abuse.ch packs were checked or installed; the flag says a pack was installed.
    Live(String, bool),
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
    tab: Tab,
    /// The catalog pack whose details show, by id.
    catalog_pick: String,
    /// The set `rows` were read for; empty while none are.
    rows_key: String,
    /// `visible` in the order the rules table header chose, and what that
    /// order was made for (sort, `list_gen`).
    sorted: Vec<usize>,
    sorted_for: Option<(Option<(usize, bool)>, u64)>,
    /// Changes whenever the filter, the rules or their states do.
    list_gen: u64,
    rule_text: Option<RuleText>,
    rule_text_rx: Option<Receiver<Result<String, String>>>,
    job: Option<Job>,
    group_name: String,
    import_path: String,
    tags_text: String,
    /// Options chosen per source pack before installing, by pack id.
    choices: BTreeMap<String, BTreeSet<String>>,
    changed: bool,
    /// Tools the triage scans run; a manifest export qualifies packs against them.
    tools: ruleset::ToolConfig,
    regex: regex_tab::RegexState,
    /// The IOC tab: the abuse.ch datasets and the known false positives.
    ioc: ioc::State,
    /// The abuse.ch tab of the IDS engine.
    live: abusech::State,
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
        if self.job.is_some() || self.rule_text_rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    /// Draw the page. `outbound` is the Settings permission; the page can
    /// turn it on when asked to. Returns a window the page asks for.
    pub(crate) fn page(
        &mut self,
        ui: &mut egui::Ui,
        data_dir: &Path,
        outbound: &mut bool,
        tools: &ruleset::ToolConfig,
        detection: &mut antinomie_monitor_core::analysis::detection::Settings,
    ) -> Option<RulesAction> {
        if self.tools != *tools {
            self.tools = tools.clone();
        }
        self.tick(ui.ctx(), data_dir);
        ui.set_min_width(0.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .animated(false)
            .drag_to_scroll(false)
            .id_salt("rule-manager-body")
            .show(ui, |ui| {
                self.contents(ui, data_dir, outbound, detection);
            });
        self.requested.take()
    }

    fn poll(&mut self) {
        if let Some(done) = self
            .rule_text_rx
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("The rule could not be read".into()))
                }
            })
        {
            self.rule_text_rx = None;
            if let Some(shown) = &mut self.rule_text {
                shown.text = Some(done);
            }
        }
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
                    self.rows_key.clear();
                }
                Ok(Done::Rules(key, rows)) => {
                    self.rows = rows;
                    self.rows_key = key;
                    self.apply_filter();
                    self.detail = None;
                    self.rule_text = None;
                    self.status = format!("Indexed {} rules.", self.rows.len());
                }
                Ok(Done::Registry(registry, note)) => {
                    if registry.generation < self.registry.generation {
                        self.status = "A newer rules change was kept.".into();
                    } else {
                        self.registry = registry;
                        self.status = note;
                        self.changed = true;
                        self.list_gen += 1;
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
                Ok(Done::Ioc(text)) => self.ioc_done(text),
                Ok(Done::Live(text, installed)) => {
                    // The registry is read again after an install and writes its
                    // own status line, so the tab keeps what happened.
                    self.live.note.clone_from(&text);
                    self.status = text;
                    if installed {
                        // The registry changed: read it again.
                        self.changed = true;
                        self.loaded = false;
                        self.rows_key.clear();
                    }
                }
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
        self.list_gen += 1;
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
                    ui.colored_label(theme::good(), format!("{} is installed.", probe.identity()))
                        .on_hover_text(
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

    /// The running job's latest status line.
    fn progress_line(&self) -> String {
        self.job
            .as_ref()
            .and_then(|job| job.progress.lock().ok().map(|text| text.clone()))
            .unwrap_or_default()
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
            self.status =
                "Allow downloads in Tools > Settings > Detection, then check again.".into();
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
                "Allow downloads in Tools > Settings > Detection before downloading a pack.".into();
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

    fn render_with(
        ctx: &egui::Context,
        model: &mut Model,
        dir: &Path,
        size: egui::Vec2,
        events: Vec<egui::Event>,
        outbound: &mut bool,
        tools: &ruleset::ToolConfig,
    ) -> (egui::FullOutput, Option<RulesAction>) {
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
                egui::CentralPanel::default().show(ctx, |ui| {
                    action = model.page(ui, dir, outbound, tools, &mut detection);
                });
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
                        egui::CentralPanel::default().show(ctx, |ui| {
                            let _ = model.page(ui, &dir, &mut outbound, &tools, detection);
                        });
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

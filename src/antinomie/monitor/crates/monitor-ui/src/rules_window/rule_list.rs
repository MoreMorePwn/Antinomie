// SPDX-License-Identifier: GPL-3.0-only
//! The floating list of one rule set's rules (an installed pack or a custom
//! group): the filter box, the count, the sortable table with its on/off
//! boxes, and "Open details". One window per set, drawn by the app every
//! frame like the rule detail windows, so it stays up across pages.
use super::{
    page::{severity_rank, severity_tone, ROW_PAD},
    Done, Model,
};
use crate::{
    theme,
    widgets::{
        self, fit_table,
        fit_table::{Col, FitBuilder},
    },
};
use antinomie_monitor_core::ruleset::{self, IndexedRule};
use eframe::egui::{self, RichText};
use std::{
    cell::Cell,
    path::Path,
    sync::mpsc::{self, Receiver},
    thread,
};

/// What the sorted order was made for: the sort, the list's edits, the model's states.
type OrderKey = (Option<(usize, bool)>, u64, u64);
type Rows = Result<Vec<IndexedRule>, String>;

pub(super) struct RuleList {
    /// The set: `pack:<id>` or `group:<id>`.
    pub key: String,
    pub engine: String,
    pub pack: String,
    pub group: String,
    pub title: String,
    rows: Vec<IndexedRule>,
    rx: Option<Receiver<Rows>>,
    error: Option<String>,
    /// The registry generation the rows were read at.
    generation: u64,
    pub(super) filter: String,
    applied: String,
    visible: Vec<usize>,
    sorted: Vec<usize>,
    sorted_for: Option<OrderKey>,
    /// Changes whenever the filter or the rows do.
    edits: u64,
    selected: Option<usize>,
    pub raise: Cell<bool>,
}

/// What a frame of the list asked for.
#[derive(Default)]
struct Asked {
    picked: Option<usize>,
    toggle: Option<(String, bool)>,
}

impl RuleList {
    pub fn new(
        key: String,
        engine: &str,
        pack: &str,
        group: &str,
        title: String,
        data_dir: &Path,
        generation: u64,
    ) -> Self {
        let mut list = Self {
            key,
            engine: engine.into(),
            pack: pack.into(),
            group: group.into(),
            title,
            rows: Vec::new(),
            rx: None,
            error: None,
            generation,
            filter: String::new(),
            applied: String::new(),
            visible: Vec::new(),
            sorted: Vec::new(),
            sorted_for: None,
            edits: 0,
            selected: None,
            raise: Cell::new(false),
        };
        list.read(data_dir, generation);
        list
    }

    /// Reads the set's rules in the background; the rows now shown stay until
    /// the new ones arrive.
    pub fn read(&mut self, data_dir: &Path, generation: u64) {
        self.generation = generation;
        let (tx, rx) = mpsc::channel();
        let dir = data_dir.to_path_buf();
        let (engine, pack, group) = (self.engine.clone(), self.pack.clone(), self.group.clone());
        let started = thread::Builder::new()
            .name("rule-list".into())
            .spawn(move || {
                let rows = if group.is_empty() {
                    ruleset::pack_index(&dir, &engine, &pack)
                } else {
                    ruleset::group_index(&dir, &group)
                };
                let _ = tx.send(rows);
            });
        match started {
            Ok(_) => self.rx = Some(rx),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    pub fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        let done = match rx.try_recv() {
            Ok(done) => done,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err("The rules could not be read".into()),
        };
        self.rx = None;
        match done {
            Ok(rows) => {
                self.rows = rows;
                self.error = None;
                self.selected = None;
                self.apply_filter();
            }
            Err(error) => self.error = Some(error),
        }
    }

    pub fn is_reading(&self) -> bool {
        self.rx.is_some()
    }

    pub fn has_selection(&self) -> bool {
        self.selected.is_some_and(|index| index < self.rows.len())
    }

    pub(super) fn id(&self) -> egui::Id {
        egui::Id::new(("rule-list-window", &self.key))
    }

    fn table(&self) -> String {
        format!("rules_list:{}", self.key)
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
        self.edits += 1;
    }

    fn order(&mut self, ctx: &egui::Context, model: &Model) {
        let spec = crate::triage::sort_current(ctx, &self.table())
            .map(|spec| (spec.column, spec.descending));
        let key = (spec, self.edits, model.list_gen);
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
                    3 => model
                        .state_in(&self.key, a)
                        .cmp(model.state_in(&self.key, b)),
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

    fn body(&mut self, ui: &mut egui::Ui, model: &Model) -> Asked {
        let mut asked = Asked::default();
        ui.horizontal_wrapped(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(theme::plain_edit_width(260.0))
                    .hint_text(theme::placeholder(ui, "filter e.g. credential")),
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
            let selected = self.selected.filter(|index| *index < self.rows.len());
            if ui
                .add_enabled(selected.is_some(), egui::Button::new("Open details"))
                .on_hover_text(
                    "Opens the selected rule's metadata and source text in a window of its own. A click on a rule does the same.",
                )
                .clicked()
            {
                asked.picked = selected;
            }
        });
        if let Some(error) = &self.error {
            crate::activity::error(ui, format!("The rules could not be read: {error}"));
        }
        if self.rows.is_empty() && self.rx.is_some() {
            theme::loading(ui, "Reading the rules…");
            return asked;
        }
        self.order(ui.ctx(), model);
        let height = ui.available_height().max(120.0);
        self.table_of(ui, model, height, &mut asked);
        asked
    }

    fn table_of(&mut self, ui: &mut egui::Ui, model: &Model, height: f32, asked: &mut Asked) {
        let font = ui.text_style_height(&egui::TextStyle::Body);
        let row_height = fit_table::row_height(font) + ROW_PAD;
        let table = self.table();
        // The table fits the width it is given: no horizontal scroll area,
        // whose content width fed the Rule column's width back to it every
        // frame. Long names are cut and the tooltip has them whole.
        ui.scope(|ui| {
            let width = ui.available_width();
            ui.set_max_width(width);
            FitBuilder::new(ui)
                .id_salt(&table)
                .sense(egui::Sense::click())
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .striped(true)
                .column(Col::fixed(34.0))
                .column(Col::rest(80.0).at_least(120.0).clip(true))
                .column(Col::fixed(84.0))
                .column(Col::fixed(84.0))
                .column(Col::flex(100.0).at_least(40.0).resizable(true).clip(true))
                .max_scroll_height(height)
                .min_scrolled_height(height)
                .header(fit_table::header_height(font), |mut header| {
                    header.col(|ui| fit_table::head(ui, "On"));
                    for (column, title) in ["Rule", "Severity", "State", "File"]
                        .into_iter()
                        .enumerate()
                    {
                        header.col(|ui| crate::table_sort::header(ui, &table, column + 1, title));
                    }
                })
                .body(|body| {
                    body.rows(row_height, self.sorted.len(), |mut row| {
                        let index = self.sorted[row.index()];
                        let rule = &self.rows[index];
                        let state = model.state_in(&self.key, rule);
                        let selected = self.selected == Some(index);
                        row.set_selected(selected);
                        row.col(|ui| {
                            fit_table::row_mark(
                                ui,
                                if selected {
                                    fit_table::Mark::Selected
                                } else {
                                    fit_table::Mark::None
                                },
                            );
                            let mut on = state == "enabled";
                            if ui
                                .add_enabled(rule.compatible, egui::Checkbox::new(&mut on, ""))
                                .changed()
                            {
                                asked.toggle = Some((rule.id.clone(), on));
                            }
                        });
                        row.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Mono, &rule.name)
                                .on_hover_text(&rule.name);
                        });
                        row.col(|ui| {
                            if !rule.severity.is_empty() {
                                widgets::chip(ui, &rule.severity, severity_tone(&rule.severity));
                            }
                        });
                        row.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Text, state);
                        });
                        row.col(|ui| {
                            fit_table::cell_click(ui, fit_table::Cell::Text, &rule.file)
                                .on_hover_text(&rule.file);
                        });
                        if row.response().clicked() {
                            asked.picked = Some(index);
                        }
                    });
                });
        });
    }
}

impl Model {
    /// The window of a set's rules: opens it, or brings the open one to the
    /// front (one window per set).
    pub(super) fn open_rule_list(
        &mut self,
        data_dir: &Path,
        engine: &str,
        pack: &str,
        group: &str,
        title: &str,
    ) {
        let key = if group.is_empty() {
            format!("pack:{pack}")
        } else {
            format!("group:{group}")
        };
        if let Some(open) = self.rule_lists.iter().find(|open| open.key == key) {
            open.raise.set(true);
            return;
        }
        let generation = self.registry.generation;
        self.rule_lists.push(RuleList::new(
            key,
            engine,
            pack,
            group,
            title.to_owned(),
            data_dir,
            generation,
        ));
    }

    /// Draws every open rule list; a closed one is dropped, and so is one
    /// whose pack or group is gone.
    pub(super) fn show_rule_lists(&mut self, ctx: &egui::Context, data_dir: &Path) {
        let lists = std::mem::take(&mut self.rule_lists);
        let mut kept = Vec::new();
        let mut asked_by = Vec::new();
        for mut list in lists {
            let exists = if list.group.is_empty() {
                self.registry.packs.iter().any(|pack| pack.id == list.pack)
            } else {
                self.registry
                    .groups
                    .iter()
                    .any(|group| group.id == list.group && !group.deleted)
            };
            if !exists && self.loaded {
                continue;
            }
            if self.loaded && list.generation != self.registry.generation && !list.is_reading() {
                list.read(data_dir, self.registry.generation);
            }
            let mut open = true;
            let area = crate::title_bar::content_rect(ctx);
            let mut asked = Asked::default();
            crate::widgets::window(format!("Rules · {}", list.title))
                .id(list.id())
                .open(&mut open)
                .default_pos(egui::pos2(area.left() + 16.0, area.top() + 112.0))
                .default_size([
                    (area.width() * 0.38).clamp(480.0, 640.0),
                    (area.height() * 0.8).max(360.0),
                ])
                .resizable(true)
                .show(ctx, |ui| {
                    asked = list.body(ui, self);
                });
            if list.raise.replace(false) {
                ctx.move_to_top(egui::LayerId::new(egui::Order::Middle, list.id()));
            }
            if let Some(index) = asked.picked {
                list.selected = Some(index);
            }
            asked_by.push((list.key.clone(), asked));
            if open {
                kept.push(list);
            }
        }
        // Lists opened while these were drawn are kept too.
        kept.append(&mut self.rule_lists);
        for (key, asked) in asked_by {
            if let Some(index) = asked.picked {
                if let Some(list) = kept.iter().find(|list| list.key == key) {
                    if let Some(rule) = list.rows.get(index).cloned() {
                        let (engine, pack, group) =
                            (list.engine.clone(), list.pack.clone(), list.group.clone());
                        self.open_rule(data_dir, &engine, &pack, &group, rule);
                    }
                }
            }
            if let Some((id, on)) = asked.toggle {
                let dir = data_dir.to_path_buf();
                self.spawn(move |_| {
                    ruleset::set_rule_enabled(&dir, &key, &id, on)?;
                    let registry = ruleset::load_registry(&dir)?;
                    Ok(Done::Registry(registry, format!("Updated rule {id}.")))
                });
            }
        }
        self.rule_lists = kept;
    }
}

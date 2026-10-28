// SPDX-License-Identifier: GPL-3.0-only
//! The custody log across every sample: newest entry first, filtered by event
//! kind and text, with the library index chain's head (copyable) and a check
//! of every sample's chain. Replaces the list like the sample window does; a
//! row opens its sample's Custody log tab.
use super::custody_parts;
use crate::{theme, widgets, widgets::table};
use antinomie_monitor_core::samples::{
    CustodyQuery, EntryState, GlobalRow, Library, LibraryCheck, KINDS,
};
use eframe::egui::{self, RichText};
use egui_extras::{Column, TableBuilder};
use std::{
    collections::BTreeSet,
    path::Path,
    sync::mpsc::{self, Receiver},
};

/// What one read of the log returns.
pub(super) struct Loaded {
    pub(super) rows: Vec<GlobalRow>,
    pub(super) check: LibraryCheck,
}

pub(in crate::app) struct CustodyAll {
    kinds: BTreeSet<String>,
    query: String,
    loaded: Option<Loaded>,
    loading: Option<Receiver<Result<Loaded, String>>>,
    /// Read again at the next frame.
    stale: bool,
    error: Option<String>,
}

/// What the view asks of the page.
pub(super) enum Outcome {
    None,
    Back,
    /// Open this sample's Custody log tab.
    Open(String),
}

impl CustodyAll {
    pub(super) fn new() -> Self {
        Self {
            kinds: BTreeSet::new(),
            query: String::new(),
            loaded: None,
            loading: None,
            stale: true,
            error: None,
        }
    }

    pub(in crate::app) fn refresh(&mut self) {
        self.stale = true;
    }

    fn start(&mut self, ctx: &egui::Context, data_dir: &Path) {
        self.stale = false;
        let (sender, receiver) = mpsc::channel();
        let (data_dir, kinds) = (data_dir.to_path_buf(), self.kinds.clone());
        let wake = ctx.clone();
        match std::thread::Builder::new()
            .name("custody-log".into())
            .spawn(move || {
                let result = Library::open(&data_dir).and_then(|library| {
                    Ok(Loaded {
                        rows: library.custody_log(&CustodyQuery {
                            kinds,
                            ..CustodyQuery::default()
                        })?,
                        check: library.custody_check_all()?,
                    })
                });
                let _ = sender.send(result);
                wake.request_repaint();
            }) {
            Ok(_) => self.loading = Some(receiver),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self) {
        if let Some(receiver) = &self.loading {
            if let Ok(result) = receiver.try_recv() {
                self.loading = None;
                match result {
                    Ok(loaded) => {
                        self.loaded = Some(loaded);
                        self.error = None;
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui, data_dir: &Path, font: f32) -> Outcome {
        let ctx = ui.ctx().clone();
        self.poll();
        if self.stale && self.loading.is_none() {
            self.start(&ctx, data_dir);
        }
        let mut outcome = Outcome::None;
        egui::Sides::new().show(
            ui,
            |ui| {
                if widgets::link(ui, "‹ All samples").clicked() {
                    outcome = Outcome::Back;
                }
                ui.label(
                    RichText::new("Custody log")
                        .strong()
                        .size(ui.text_style_height(&egui::TextStyle::Heading))
                        .color(theme::palette().heading),
                );
                if self.loading.is_some() {
                    theme::spinner(ui);
                }
            },
            |ui| {
                if ui
                    .add_enabled(self.loading.is_none(), egui::Button::new("Verify all"))
                    .on_hover_text("Recompute every hash of every sample and the library index")
                    .clicked()
                {
                    self.stale = true;
                }
            },
        );
        if let Some(error) = &self.error {
            ui.colored_label(theme::error(), error);
        }
        let Some(loaded) = &self.loaded else {
            return outcome;
        };
        self.status(ui, &loaded.check);
        ui.add_space(4.0);
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text(theme::hint_text("Sample, SHA-256, actor or detail"))
                    .desired_width(300.0),
            );
            for (key, label) in KINDS {
                let on = self.kinds.contains(key);
                if widgets::toggle_chip(ui, label, on || self.kinds.is_empty(), None).clicked() {
                    if self.kinds.is_empty() || !self.kinds.remove(key) {
                        self.kinds.insert(key.to_owned());
                    }
                    changed = true;
                }
            }
            if !self.kinds.is_empty() && ui.small_button("All kinds").clicked() {
                self.kinds.clear();
                changed = true;
            }
        });
        if changed {
            self.stale = true;
        }
        let needle = self.query.trim().to_lowercase();
        let shown: Vec<&GlobalRow> = loaded
            .rows
            .iter()
            .filter(|row| row.matches(&needle))
            .collect();
        ui.weak(format!("{} of {} entries", shown.len(), loaded.rows.len()));
        ui.add_space(2.0);
        if shown.is_empty() {
            theme::empty_state(ui, "No entries match.");
            return outcome;
        }
        let height = ui.available_height().max(80.0);
        table::begin(ui);
        TableBuilder::new(ui)
            .id_salt("custody_all")
            .striped(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::exact(150.0))
            .column(Column::exact(180.0))
            .column(Column::exact(130.0))
            .column(Column::exact(80.0))
            .column(Column::remainder().at_least(160.0).clip(true))
            .column(Column::exact(86.0))
            .max_scroll_height(height)
            .min_scrolled_height(0.0)
            .header(table::header_height(font), |mut header| {
                for title in ["Time", "Sample", "Event", "By", "Detail", "Check"] {
                    header.col(|ui| table::head(ui, title));
                }
            })
            .body(|body| {
                body.rows(table::row_height(font), shown.len(), |mut row| {
                    let found = shown[row.index()];
                    let state = loaded
                        .check
                        .samples
                        .get(&found.sha256)
                        .map_or(EntryState::Verified, |check| check.state_of(found.row.seq));
                    row.col(|ui| {
                        table::cell(
                            ui,
                            table::Cell::Mono,
                            &super::detail::second(found.row.at_ms),
                        );
                    });
                    row.col(|ui| {
                        let name = if found.name.is_empty() {
                            &found.sha256[..12]
                        } else {
                            &found.name
                        };
                        if table::cell_click(ui, table::Cell::Text, name)
                            .on_hover_text(format!("{}\nOpen its custody log", found.sha256))
                            .clicked()
                        {
                            outcome = Outcome::Open(found.sha256.clone());
                        }
                    });
                    row.col(|ui| {
                        table::cell_rich(
                            ui,
                            table::Cell::Text,
                            RichText::new(found.row.event.label()).strong(),
                        );
                    });
                    row.col(|ui| {
                        table::cell(ui, table::Cell::Text, &found.row.by);
                    });
                    row.col(|ui| {
                        let mut detail = found.row.event.detail();
                        if found.row.before_chain {
                            detail.push_str(" (recorded before the custody log)");
                        }
                        table::cell(ui, table::Cell::Text, &detail).on_hover_text(&detail);
                    });
                    row.col(|ui| {
                        custody_parts::check_mark(ui, state, &found.row.prev, &found.row.hash);
                    });
                });
            });
        outcome
    }

    /// The line over the filters: the index chain's state and head, and how
    /// many sample logs verified.
    fn status(&self, ui: &mut egui::Ui, check: &LibraryCheck) {
        ui.horizontal_wrapped(|ui| {
            if check.ok() {
                ui.colored_label(theme::good(), "All logs verified.");
                ui.label(format!(
                    "{} sample logs; library index {} records, head",
                    check.samples.len(),
                    check.index.records
                ));
                custody_parts::head(ui, &check.index.head);
            } else if let Some(problem) = &check.index.problem {
                ui.colored_label(
                    theme::error(),
                    format!(
                        "The library index chain is broken at record {}: {}.",
                        problem.at, problem.text
                    ),
                );
            } else {
                let broken = check.broken();
                ui.colored_label(
                    theme::error(),
                    format!(
                        "{} of {} sample logs did not verify:",
                        broken.len(),
                        check.samples.len()
                    ),
                );
                for sha256 in broken.iter().take(3) {
                    ui.label(RichText::new(&sha256[..12]).monospace());
                }
            }
        });
        custody_parts::note(ui);
    }
}

#[cfg(test)]
impl CustodyAll {
    pub(in crate::app) fn probe(&self) -> Option<(usize, usize, bool)> {
        let loaded = self.loaded.as_ref()?;
        Some((
            loaded.rows.len(),
            loaded.check.samples.len(),
            loaded.check.ok(),
        ))
    }
    pub(in crate::app) fn toggle_kind(&mut self, key: &str) {
        if !self.kinds.remove(key) {
            self.kinds.insert(key.to_owned());
        }
        self.stale = true;
    }
    pub(in crate::app) fn set_query(&mut self, text: &str) {
        self.query = text.into();
    }
    pub(in crate::app) fn visible(&self) -> usize {
        let needle = self.query.trim().to_lowercase();
        self.loaded.as_ref().map_or(0, |loaded| {
            loaded
                .rows
                .iter()
                .filter(|row| row.matches(&needle))
                .count()
        })
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The regex matches view: every match of the built-in and custom
//! patterns in a set of strings, by category, with a type for each match.
//! Static analysis shows it as the Regex matches tab (over Strings and FLOSS
//! strings) and Core dumps in a window (strings and binary socket addresses);
//! the scan runs on a worker thread.
use crate::widgets::{
    self,
    table::{self, Cell, Mark},
    TabItem, Tone,
};
use antinomie_monitor_core::strings_regex::{Category, Config, Match, RuleSet, Scan};
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver},
        Arc,
    },
};

/// The data folder whose rule manager configuration scans read; the app
/// sets it whenever its options change.
static DATA_DIR: std::sync::RwLock<Option<PathBuf>> = std::sync::RwLock::new(None);

pub(crate) fn remember_data_dir(data_dir: &Path) {
    if let Ok(mut current) = DATA_DIR.write() {
        if current.as_deref() != Some(data_dir) {
            *current = Some(data_dir.to_path_buf());
        }
    }
}

fn data_dir() -> Option<PathBuf> {
    DATA_DIR.read().ok().and_then(|current| current.clone())
}

/// What a scan does with the patterns it is given.
pub(crate) type Work = Arc<dyn Fn(&RuleSet, &AtomicBool) -> Result<Scan, String> + Send + Sync>;

/// A finished scan with the custom patterns that did not compile.
type Outcome = Result<(Scan, Vec<(String, String)>), String>;

struct Running {
    receiver: Receiver<Outcome>,
    cancel: Arc<AtomicBool>,
}

/// Rows kept by the category, type and text filters, as indices into the
/// scan's matches.
#[derive(Default)]
struct Shown {
    key: Option<(Option<Category>, Option<String>, String)>,
    rows: Vec<usize>,
}

#[derive(Default)]
pub(crate) struct RegexWindow {
    open: bool,
    /// What the scan is of; a new request for the same thing reopens it.
    key: String,
    title: String,
    work: Option<Work>,
    running: Option<Running>,
    scan: Option<Arc<Scan>>,
    rejected: Vec<(String, String)>,
    error: Option<String>,
    category: Option<Category>,
    kind: Option<String>,
    query: String,
    shown: Shown,
    selected: Option<usize>,
}

impl RegexWindow {
    /// Open the window for `key`: as it was when it is the same scan, else
    /// scanning afresh with `work`.
    pub(crate) fn open_for(&mut self, key: &str, title: String, work: Work) {
        self.open = true;
        if self.key == key && (self.scan.is_some() || self.running.is_some()) {
            return;
        }
        self.cancel();
        *self = Self {
            open: true,
            key: key.into(),
            title,
            work: Some(work),
            ..Self::default()
        };
        self.start();
    }

    #[cfg(test)]
    pub(crate) fn is_open(&self) -> bool {
        self.open
    }

    fn cancel(&mut self) {
        if let Some(running) = &self.running {
            running.cancel.store(true, Ordering::Relaxed);
        }
    }

    /// Scan again with the patterns as the rule manager has them now.
    fn start(&mut self) {
        let Some(work) = self.work.clone() else {
            return;
        };
        self.cancel();
        let Some(data_dir) = data_dir() else {
            self.error = Some("the data folder is unknown".into());
            return;
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let spawned = std::thread::Builder::new()
            .name("regex-matches".into())
            .spawn(move || {
                let result = Config::load(&data_dir).and_then(|config| {
                    let rules = RuleSet::build(&config);
                    work(&rules, &worker_cancel).map(|scan| (scan, rules.rejected.clone()))
                });
                // The window may be closed by now; a lost result is fine.
                let _ = sender.send(result);
            });
        match spawned {
            Ok(_) => {
                self.error = None;
                self.scan = None;
                self.selected = None;
                self.shown = Shown::default();
                self.running = Some(Running { receiver, cancel });
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self) {
        let Some(running) = &self.running else {
            return;
        };
        let result = match running.receiver.try_recv() {
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => Err("the scan stopped unexpectedly".into()),
            Ok(result) => result,
        };
        self.running = None;
        match result {
            Ok((scan, rejected)) => {
                self.rejected = rejected;
                self.scan = Some(Arc::new(scan));
            }
            Err(error) => self.error = Some(error),
        }
    }

    /// Draw the window if it is open.
    pub(crate) fn show(&mut self, ctx: &egui::Context, salt: &str) {
        if !self.open {
            return;
        }
        self.poll();
        if self.running.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(75));
        }
        let mut open = true;
        egui::Window::new(format!("Regex matches · {}", self.title))
            .id(egui::Id::new(("regex-matches", salt)))
            .open(&mut open)
            .default_size([900.0, 520.0])
            .resizable(true)
            .show(ctx, |ui| self.body(ui));
        if !open {
            self.open = false;
            // A scan in progress is not wanted any more; the result stays.
            self.cancel();
        }
    }

    /// Draw the matches as a pane of the view that owns them (Static analysis
    /// › Strings & regex); the scan is kept for as long as the owner is.
    pub(crate) fn pane(&mut self, ui: &mut egui::Ui) {
        self.poll();
        if self.running.is_some() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(75));
        }
        self.body(ui);
    }

    fn body(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.running.is_none(), egui::Button::new("Scan again"))
                .on_hover_text(
                    "Scan again with the patterns as the rule manager has them now \
                     (Library > Detection rules > Strings regex)",
                )
                .clicked()
            {
                self.start();
            }
            if self.running.is_some() && ui.button("Cancel").clicked() {
                self.cancel();
            }
        });
        if let Some(error) = &self.error {
            crate::activity::error(ui, error);
        }
        if self.running.is_some() {
            crate::theme::loading(ui, "Scanning strings…");
            return;
        }
        let Some(scan) = self.scan.clone() else {
            return;
        };
        for (id, reason) in &self.rejected {
            crate::activity::warning(ui, format!("Pattern {id} is not used: {reason}"));
        }
        if scan.cancelled {
            crate::activity::warning(ui, "The scan was stopped; these are the matches so far.");
        }
        if scan.truncated {
            crate::activity::warning(
                ui,
                format!(
                    "Only the first {} different matches are listed; the counts are complete.",
                    antinomie_monitor_core::strings_regex::MATCH_MAX_COUNT
                ),
            );
        }
        self.categories(ui, &scan);
        self.filters(ui, &scan);
        let key = (self.category, self.kind.clone(), self.query.clone());
        if self.shown.key.as_ref() != Some(&key) {
            self.shown = Shown {
                rows: filtered(&scan, &key),
                key: Some(key),
            };
            self.selected = None;
        }
        ui.weak(format!(
            "{} of {} different matches · {} strings scanned",
            self.shown.rows.len(),
            scan.matches.len(),
            scan.strings
        ));
        self.table(ui, &scan);
        if let Some(found) = self.selected.and_then(|index| scan.matches.get(index)) {
            let mut text = format!("{} · {}", found.kind, found.origin);
            if !found.via.is_empty() {
                text.push_str(&format!(" · inside {}", found.via.join(" > ")));
            }
            if !found.note.is_empty() {
                text.push_str(&format!(" · {}", found.note));
            }
            ui.add(egui::Label::new(egui::RichText::new(text).color(crate::theme::muted())).wrap());
        }
    }

    /// The categories with their counts; a click keeps one.
    fn categories(&mut self, ui: &mut egui::Ui, scan: &Scan) {
        let mut items = vec![(
            None,
            TabItem::new("All").badge(scan.total().to_string(), Tone::Plain),
        )];
        for category in Category::ALL {
            let count = scan.counts.get(&category).copied().unwrap_or(0);
            if count > 0 || self.category == Some(category) {
                items.push((
                    Some(category),
                    TabItem::new(category.label()).badge(count.to_string(), Tone::Plain),
                ));
            }
        }
        let mut current = self.category;
        if widgets::tabs(ui, items, &mut current) {
            self.category = current;
            self.kind = None;
        }
    }

    fn filters(&mut self, ui: &mut egui::Ui, scan: &Scan) {
        ui.horizontal(|ui| {
            ui.label("Type");
            let label = self.kind.clone().unwrap_or_else(|| "any".into());
            egui::ComboBox::from_id_salt("regex-kind")
                .selected_text(label)
                .width(220.0)
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.kind, None, "any");
                    for (kind, count) in &scan.kinds {
                        let belongs = self.category.is_none_or(|category| {
                            scan.matches
                                .iter()
                                .any(|m| &m.kind == kind && m.category == category)
                        });
                        if belongs {
                            ui.selectable_value(
                                &mut self.kind,
                                Some(kind.clone()),
                                format!("{kind} ({count})"),
                            );
                        }
                    }
                });
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("Filter the matches")
                    .desired_width(ui.available_width()),
            );
        });
    }

    fn table(&mut self, ui: &mut egui::Ui, scan: &Scan) {
        let font = egui::TextStyle::Monospace.resolve(ui.style()).size;
        let rows = self.shown.rows.clone();
        let mut chosen = None;
        table::begin(ui);
        let height = ui.available_height().max(120.0);
        TableBuilder::new(ui)
            .id_salt("regex-matches-table")
            .max_scroll_height(height)
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(110.0).at_least(70.0).clip(true))
            .column(Column::initial(170.0).at_least(80.0).clip(true))
            .column(Column::initial(320.0).at_least(120.0).clip(true))
            .column(Column::initial(150.0).at_least(80.0).clip(true))
            .column(Column::exact(44.0))
            .column(Column::remainder().at_least(60.0).clip(true))
            .header(table::header_height(font), |mut header| {
                for title in ["Category", "Type", "Match", "Found in", "Seen", "Inside"] {
                    header.col(|ui| table::head(ui, title));
                }
            })
            .body(|body| {
                body.rows(table::row_height(font), rows.len(), |mut row| {
                    let index = rows[row.index()];
                    let found = &scan.matches[index];
                    let selected = self.selected == Some(index);
                    row.set_selected(selected);
                    row.col(|ui| {
                        table::row_mark(ui, if selected { Mark::Selected } else { Mark::None });
                        table::cell_click(ui, Cell::Text, found.category.label());
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Text, &found.kind);
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Mono, &found.text);
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Text, &place(found));
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Number, &(found.repeats + 1).to_string());
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Text, &found.via.join(" > "));
                    });
                    let response = row.response();
                    response.context_menu(|ui| {
                        for (label, text) in [
                            ("Copy match", found.text.clone()),
                            ("Copy type", found.kind.clone()),
                            ("Copy row", row_text(found)),
                        ] {
                            if ui.button(label).clicked() {
                                ui.ctx().copy_text(text);
                                ui.close_menu();
                            }
                        }
                    });
                    if response.clicked() || response.secondary_clicked() {
                        chosen = Some(index);
                    }
                });
            });
        if chosen.is_some() {
            self.selected = chosen;
        }
    }
}

/// "Strings @ 0x1a2b" or "Core strings @ 0x7f00".
fn place(found: &Match) -> String {
    match found.position {
        Some(position) => format!("{} @ 0x{position:x}", found.origin),
        None => found.origin.clone(),
    }
}

fn row_text(found: &Match) -> String {
    [
        found.category.label().to_owned(),
        found.kind.clone(),
        found.text.clone(),
        place(found),
        (found.repeats + 1).to_string(),
        found.via.join(" > "),
    ]
    .join("\t")
}

/// The matches the category, type and text keep, in category and type order.
fn filtered(scan: &Scan, key: &(Option<Category>, Option<String>, String)) -> Vec<usize> {
    let needle = key.2.to_lowercase();
    let mut rows: Vec<usize> = (0..scan.matches.len())
        .filter(|&index| {
            let found = &scan.matches[index];
            key.0.is_none_or(|category| found.category == category)
                && key.1.as_ref().is_none_or(|kind| &found.kind == kind)
                && (needle.is_empty()
                    || found.text.to_lowercase().contains(&needle)
                    || found.kind.to_lowercase().contains(&needle)
                    || found.origin.to_lowercase().contains(&needle))
        })
        .collect();
    rows.sort_by(|&a, &b| {
        let (a, b) = (&scan.matches[a], &scan.matches[b]);
        (a.category, &a.kind).cmp(&(b.category, &b.kind))
    });
    rows
}

#[cfg(test)]
mod tests;

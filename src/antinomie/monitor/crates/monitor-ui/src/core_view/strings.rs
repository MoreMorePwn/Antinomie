// SPDX-License-Identifier: GPL-3.0-only
//! The Strings tab: printable ASCII and UTF-16LE text of the core's captured
//! memory, found by the Static analysis extractor on a worker thread. The
//! filter and the sort run on a worker too and the table shows one page of
//! the result, so a core with a hundred thousand strings costs the frame the
//! same as one with ten.
use super::*;
use crate::query::{FieldSpec, RowValue};
use crate::widgets::table::{self, Cell, Mark};
use antinomie_monitor_core::core_strings::{self, CoreString, Stopped};
use egui_extras::{Column, TableBuilder};
use std::sync::atomic::AtomicU64;

/// Strings per page of the table.
pub(super) const PAGE_ROWS: usize = 500;

const TABLE: &str = "core_strings";

const STRING_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("string.text", "The string"),
    FieldSpec::number("string.address", "Virtual address of the first character"),
    FieldSpec::number(
        "string.offset",
        "Offset of the first character in the core file",
    ),
    FieldSpec::text("string.encoding", "ASCII or UTF-16LE"),
    FieldSpec::number("string.length", "Extent in the core, in octets"),
    FieldSpec::text(
        "string.segment",
        "Mapped file, or [anonymous] with its permissions",
    ),
];

/// What one extraction found.
pub(super) struct Extracted {
    source: PathBuf,
    strings: Vec<CoreString>,
    /// The name of each of the core's mappings, indexed like `CoreDump::mappings`.
    names: Vec<String>,
    scanned: u64,
    stopped: Option<Stopped>,
}

impl Extracted {
    /// The name `string` shows in the Segment column.
    fn segment(&self, string: &CoreString) -> &str {
        self.names.get(string.mapping).map_or("", String::as_str)
    }

    fn row(&self, string: &CoreString) -> Vec<(&'static str, RowValue)> {
        vec![
            ("string.text", RowValue::Text(string.text.clone())),
            (
                "string.address",
                RowValue::Number(i128::from(string.address)),
            ),
            (
                "string.offset",
                RowValue::Number(i128::from(string.file_offset)),
            ),
            ("string.encoding", RowValue::Text(string.encoding.into())),
            (
                "string.length",
                RowValue::Number(i128::from(string.byte_len)),
            ),
            (
                "string.segment",
                RowValue::Text(self.segment(string).into()),
            ),
        ]
    }
}

/// A running extraction.
struct Running {
    receiver: Receiver<Result<Extracted, String>>,
    cancel: Arc<AtomicBool>,
    progress: Arc<AtomicU64>,
    total: u64,
}

/// The filter text and sort a derived order belongs to.
#[derive(Clone, PartialEq, Eq)]
struct Key {
    filter: String,
    sort: Option<(usize, bool)>,
}

#[derive(Default)]
pub(super) struct StringsState {
    running: Option<Running>,
    extracted: Option<Arc<Extracted>>,
    error: Option<String>,
    /// The filter as typed, and the last text of it that compiled.
    query: String,
    applied: String,
    page: usize,
    /// Indices into the strings that pass the filter, in table order; None
    /// shows them all in extraction order.
    order: Option<(Key, Arc<Vec<u32>>)>,
    deriving: Option<(Key, Receiver<Vec<u32>>)>,
    selected: Option<usize>,
}

impl StringsState {
    /// Forget everything, stopping a search in progress.
    pub(super) fn reset(&mut self) {
        if let Some(running) = &self.running {
            running.cancel.store(true, Ordering::Relaxed);
        }
        *self = Self::default();
    }

    pub(super) fn running(&self) -> bool {
        self.running.is_some()
    }

    /// How many strings the last search found, once it has finished.
    pub(super) fn count(&self) -> Option<usize> {
        self.extracted
            .as_ref()
            .map(|extracted| extracted.strings.len())
    }

    /// Run `work` on a worker thread. It gets the cancel flag and a counter
    /// to report the octets searched; its result is taken by `poll`.
    fn start_with(
        &mut self,
        total: u64,
        work: impl FnOnce(&AtomicBool, &AtomicU64) -> Result<Extracted, String> + Send + 'static,
    ) {
        if self.running.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(AtomicU64::new(0));
        let (worker_cancel, worker_progress) = (Arc::clone(&cancel), Arc::clone(&progress));
        let spawned = std::thread::Builder::new()
            .name("core-strings".into())
            .spawn(move || {
                // The view may be closed by now; a lost result is fine.
                let _ = sender.send(work(&worker_cancel, &worker_progress));
            });
        match spawned {
            Ok(_) => {
                self.error = None;
                self.extracted = None;
                self.order = None;
                self.selected = None;
                self.page = 0;
                self.running = Some(Running {
                    receiver,
                    cancel,
                    progress,
                    total,
                });
            }
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    /// Search the captured memory of `core`.
    fn start(&mut self, core: &CoreDump) {
        let core = core.clone();
        let names = core
            .mappings
            .iter()
            .map(|mapping| segment_name(&core, mapping))
            .collect();
        self.start_with(
            core_strings::captured_size(&core),
            move |cancel, progress| {
                let found = core_strings::find(&core, cancel, progress)
                    .map_err(|error| error.to_string())?;
                Ok(Extracted {
                    source: core.source.clone(),
                    strings: found.strings,
                    names,
                    scanned: found.scanned,
                    stopped: found.stopped,
                })
            },
        );
    }

    /// Take a finished extraction or order without waiting for one.
    pub(super) fn poll(&mut self) {
        if let Some(running) = &self.running {
            let result = match running.receiver.try_recv() {
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("string search stopped unexpectedly".to_owned()))
                }
                Ok(result) => Some(result),
            };
            if let Some(result) = result {
                self.running = None;
                match result {
                    Ok(extracted) if extracted.stopped == Some(Stopped::Cancelled) => {}
                    Ok(extracted) => self.extracted = Some(Arc::new(extracted)),
                    Err(error) => self.error = Some(error),
                }
            }
        }
        if let Some((key, receiver)) = &self.deriving {
            match receiver.try_recv() {
                Ok(order) => {
                    self.order = Some((key.clone(), Arc::new(order)));
                    self.deriving = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => self.deriving = None,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
    }

    /// Ask for the order of `key`, unless it is known or being worked out.
    fn derive(&mut self, key: &Key) {
        let Some(extracted) = &self.extracted else {
            return;
        };
        if self.order.as_ref().is_some_and(|(known, _)| known == key) || self.deriving.is_some() {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        let extracted = Arc::clone(extracted);
        let worker_key = key.clone();
        let spawned = std::thread::Builder::new()
            .name("core-strings-order".into())
            .spawn(move || {
                let _ = sender.send(derive_order(&extracted, &worker_key));
            });
        if spawned.is_ok() {
            self.deriving = Some((key.clone(), receiver));
        }
    }

    /// The positions into the extracted strings shown now, if they are not all.
    fn visible(&self, key: &Key) -> Option<&[u32]> {
        self.order
            .as_ref()
            .filter(|(known, _)| known == key)
            .map(|(_, order)| order.as_slice())
    }

    /// Draw the tab. Returns the detail of a string chosen this frame.
    pub(super) fn show(
        &mut self,
        ui: &mut egui::Ui,
        record: &CoreRecord,
    ) -> Option<details::CoreDetail> {
        self.poll();
        if self
            .extracted
            .as_ref()
            .is_some_and(|extracted| extracted.source != record.core.source)
        {
            self.reset();
        }
        if self.extracted.is_none() && self.running.is_none() && self.error.is_none() {
            self.start(&record.core);
        }
        if self.running.is_some() || self.deriving.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(75));
        }
        if let Some(running) = &self.running {
            crate::theme::loading(
                ui,
                format!(
                    "Searching the core's memory for strings… {} of {}",
                    crate::values::file_size(running.progress.load(Ordering::Relaxed)),
                    crate::values::file_size(running.total),
                ),
            );
            if ui.button("Cancel").clicked() {
                running.cancel.store(true, Ordering::Relaxed);
            }
            return None;
        }
        if let Some(error) = &self.error {
            crate::activity::error(ui, error);
            if ui.button("Search again").clicked() {
                self.error = None;
            }
            return None;
        }
        let extracted = Arc::clone(self.extracted.as_ref()?);
        self.toolbar(ui, record, &extracted);
        let compiled = crate::query::compile_table(&self.query, STRING_FIELDS);
        match &compiled.error {
            Some(error) => {
                crate::activity::warning(ui, format!("{error} · showing the last valid filter"));
            }
            None => {
                self.applied = self.query.clone();
                crate::query::remember_valid_filter(ui, &self.applied);
            }
        }
        let key = Key {
            filter: self.applied.clone(),
            sort: crate::triage::sort_current(ui.ctx(), TABLE)
                .map(|spec| (spec.column, spec.descending)),
        };
        let identity = key.filter.trim().is_empty() && key.sort.is_none();
        if !identity {
            self.derive(&key);
        }
        let order = if identity {
            None
        } else {
            self.visible(&key).map(<[u32]>::to_vec)
        };
        let settled = identity || order.is_some();
        if !settled {
            crate::theme::loading(ui, "Filtering and sorting…");
        }
        // While a new order is worked out the last one stays on screen.
        let shown: Option<Vec<u32>> = if settled {
            order
        } else {
            self.order.as_ref().map(|(_, order)| order.to_vec())
        };
        let count = shown.as_ref().map_or(extracted.strings.len(), Vec::len);
        let pages = count.div_ceil(PAGE_ROWS).max(1);
        self.page = self.page.min(pages - 1);
        self.pager(ui, count, extracted.strings.len(), pages);
        let first = self.page * PAGE_ROWS;
        let rows = PAGE_ROWS.min(count.saturating_sub(first));
        let at = |slot: usize| -> usize {
            shown
                .as_ref()
                .map_or(first + slot, |order| order[first + slot] as usize)
        };
        let font = egui::TextStyle::Monospace.resolve(ui.style()).size;
        let mut chosen = None;
        let mut filter = None;
        table::begin(ui);
        TableBuilder::new(ui)
            .id_salt(("core-strings-table", &record.dir))
            .striped(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(130.0).at_least(100.0).clip(true))
            .column(Column::initial(80.0).at_least(60.0).clip(true))
            .column(Column::exact(84.0))
            .column(Column::exact(72.0))
            .column(Column::initial(120.0).at_least(70.0).clip(true))
            .column(Column::remainder().at_least(100.0).clip(true))
            .header(table::header_height(font), |mut header| {
                for (column, title) in ["Address", "File offset", "Encoding"]
                    .into_iter()
                    .enumerate()
                {
                    header.col(|ui| crate::table_sort::header(ui, TABLE, column, title));
                }
                header.col(|ui| {
                    crate::table_sort::header_aligned(ui, TABLE, 3, "Length", egui::Align::Max)
                });
                header.col(|ui| crate::table_sort::header(ui, TABLE, 4, "Segment"));
                header.col(|ui| crate::table_sort::header(ui, TABLE, 5, "Text"));
            })
            .body(|body| {
                body.rows(table::row_height(font), rows, |mut row| {
                    let index = at(row.index());
                    let string = &extracted.strings[index];
                    let selected = self.selected == Some(index);
                    row.set_selected(selected);
                    row.col(|ui| {
                        table::row_mark(ui, if selected { Mark::Selected } else { Mark::None });
                        table::cell_click(ui, Cell::Mono, &format!("0x{:x}", string.address));
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Mono, &format!("0x{:x}", string.file_offset));
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Text, string.encoding);
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Number, &string.byte_len.to_string());
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Text, extracted.segment(string));
                    });
                    row.col(|ui| {
                        table::cell_click(ui, Cell::Mono, &string.text);
                    });
                    let response = row.response();
                    response.context_menu(|ui| {
                        if ui.button("Copy string").clicked() {
                            ui.ctx().copy_text(string.text.clone());
                            ui.close_menu();
                        }
                        if ui.button("Copy address").clicked() {
                            ui.ctx().copy_text(format!("0x{:x}", string.address));
                            ui.close_menu();
                        }
                        ui.menu_button("Filter by field", |ui| {
                            for (field, value) in extracted.row(string) {
                                ui.menu_button(field, |ui| {
                                    let mut text = self.query.clone();
                                    crate::query::value_menu(ui, field, &value, &mut text);
                                    if text != self.query {
                                        filter = Some(text);
                                    }
                                });
                            }
                        });
                    });
                    if response.clicked() || response.secondary_clicked() {
                        chosen = Some(index);
                    }
                });
            });
        if let Some(text) = filter {
            self.query = text;
            self.page = 0;
        }
        let index = chosen?;
        self.selected = Some(index);
        let string = &extracted.strings[index];
        Some(details::string(string, extracted.segment(string)))
    }

    /// The filter, what was searched and the way to search again.
    fn toolbar(&mut self, ui: &mut egui::Ui, record: &CoreRecord, extracted: &Extracted) {
        ui.horizontal(|ui| {
            if ui
                .button("Search again")
                .on_hover_text("Read the core's memory again")
                .clicked()
            {
                self.reset();
                self.start(&record.core);
            }
            ui.add(
                egui::Label::new(egui::RichText::new(format!(
                    "{} strings in {} of captured memory",
                    extracted.strings.len(),
                    crate::values::file_size(extracted.scanned),
                )).color(crate::theme::muted()))
                .truncate(),
            )
            .on_hover_text("ASCII of 4 or more octets and UTF-16LE of 4 or more characters, as in Static analysis");
        });
        if self.running.is_some() {
            return;
        }
        if extracted.stopped == Some(Stopped::Limit) {
            crate::activity::warning(
                ui,
                format!(
                    "Only the first {} strings are listed; the core has more.",
                    core_strings::MAX_STRINGS
                ),
            );
        }
        let before = self.query.clone();
        crate::query::filter_edit_fields(
            ui,
            &mut self.query,
            "string.text contains http",
            ui.available_width(),
            STRING_FIELDS,
            &[],
        );
        if self.query != before {
            self.page = 0;
        }
    }

    /// "Previous · Page 2 of 9 · 4,500 of 12,000 strings · Next".
    fn pager(&mut self, ui: &mut egui::Ui, shown: usize, total: usize, pages: usize) {
        ui.horizontal(|ui| {
            if ui
                .add_enabled(self.page > 0, egui::Button::new("Previous"))
                .clicked()
            {
                self.page -= 1;
            }
            ui.label(format!("Page {} of {pages}", self.page + 1));
            let mut page = self.page + 1;
            ui.label("Go to page");
            if ui
                .add(egui::DragValue::new(&mut page).range(1..=pages.max(1)))
                .changed()
            {
                self.page = page - 1;
            }
            if ui
                .add_enabled(self.page + 1 < pages, egui::Button::new("Next"))
                .clicked()
            {
                self.page += 1;
            }
            ui.weak(format!("{shown} of {total} strings"));
        });
    }
}

/// "libc.so.6" for a mapping of a file; "[anonymous rw-]" for one without.
fn segment_name(core: &CoreDump, mapping: &CoreMapping) -> String {
    let name = mapping_name(core, mapping);
    if name == "unknown" {
        return format!("[anonymous {}]", mapping.permissions());
    }
    if name.ends_with(" file extents)") {
        return name;
    }
    Path::new(&name)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&name)
        .to_owned()
}

/// Positions of the strings `key.filter` keeps, in the order `key.sort` asks.
fn derive_order(extracted: &Extracted, key: &Key) -> Vec<u32> {
    let compiled = crate::query::compile_table(&key.filter, STRING_FIELDS);
    let everything = compiled.keeps_everything();
    let mut order: Vec<u32> = (0..extracted.strings.len() as u32)
        .filter(|&index| {
            everything || compiled.keep_table(&extracted.row(&extracted.strings[index as usize]))
        })
        .collect();
    if let Some((column, descending)) = key.sort {
        let string = |index: &u32| &extracted.strings[*index as usize];
        match column {
            0 => order.sort_by_key(|index| string(index).address),
            1 => order.sort_by_key(|index| string(index).file_offset),
            2 => order.sort_by_key(|index| string(index).encoding),
            3 => order.sort_by_key(|index| string(index).byte_len),
            4 => order.sort_by_cached_key(|index| extracted.segment(string(index)).to_lowercase()),
            _ => order.sort_by_cached_key(|index| string(index).text.to_lowercase()),
        }
        if descending {
            order.reverse();
        }
    }
    order
}

#[cfg(test)]
#[path = "strings_tests.rs"]
mod tests;

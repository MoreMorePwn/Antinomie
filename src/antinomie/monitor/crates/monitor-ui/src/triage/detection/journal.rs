// SPDX-License-Identifier: MIT
//! Detection > Event journal: a read-only, paged view of the normalized events
//! Sigma evaluated, with each event's source call or packet one click away.
//!
//! Every read runs on a worker thread, bounded and cancellable. The viewer
//! never writes the journal; "Open file" only hands its path to the desktop.
use super::*;
use antinomie_monitor_core::analysis::detection::journal::{
    self as reader, Focus, Page, Query, PAGE_SIZE,
};
use antinomie_monitor_core::analysis::detection::{Event, Moment, JOURNAL_FILE};
use antinomie_monitor_core::HostClockAnchor;
use egui_extras::{Column, TableBuilder};

const ROW_HEIGHT: f32 = 22.0;

/// The read in flight. Dropping it, on a new request or a run switch, cancels it.
struct Job {
    rx: Receiver<Result<Page, String>>,
    cancel: Arc<AtomicBool>,
}

impl Drop for Job {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

#[derive(Default)]
pub(super) struct Viewer {
    open: bool,
    /// Journal digest the inspected scan recorded, if the viewer was opened from one.
    scanned: Option<String>,
    category: String,
    /// The search box, which may be ahead of `applied`.
    search: String,
    /// The search the shown page was read with.
    applied: String,
    /// Matching-row index of the page asked for.
    offset: usize,
    /// Event to land on; consumed by the page that contains it.
    focus: Option<Focus>,
    /// A read is wanted and has not started.
    wanted: bool,
    job: Option<Job>,
    page: Option<Page>,
    error: Option<String>,
    selected: Option<u64>,
    scroll_to: Option<u64>,
    note: String,
}

impl Viewer {
    #[cfg(test)]
    pub(super) fn is_open(&self) -> bool {
        self.open
    }

    /// Show the journal, on the page holding `focus` when given. Filters start
    /// clear so the focused event cannot be hidden by an earlier choice.
    pub(super) fn open(
        &mut self,
        ctx: &egui::Context,
        scanned: Option<String>,
        focus: Option<Focus>,
    ) {
        *self = Self {
            open: true,
            scanned,
            selected: match &focus {
                Some(Focus::Event(id)) => Some(*id),
                _ => None,
            },
            focus,
            wanted: true,
            ..Self::default()
        };
        ctx.request_repaint();
    }

    /// Hide the viewer and cancel its read (run switch or close).
    pub(super) fn close(&mut self) {
        *self = Self::default();
    }

    /// Ask for a page again after the filter, page or file changed.
    fn restart(&mut self, offset: usize) {
        self.offset = offset;
        self.focus = None;
        self.wanted = true;
    }

    fn start(&mut self, ctx: &egui::Context, directory: &Path, identity: &Identity) {
        self.wanted = false;
        // The previous read, if any, is cancelled as it is replaced.
        self.job = None;
        let query = Query {
            directory: directory.to_path_buf(),
            identity: identity.clone(),
            scanned: self.scanned.clone(),
            category: self.category.clone(),
            text: self.applied.clone(),
            offset: self.offset,
            focus: self.focus.clone(),
        };
        let (tx, rx) = mpsc::sync_channel(1);
        let cancel = Arc::new(AtomicBool::new(false));
        let (flag, repaint) = (Arc::clone(&cancel), ctx.clone());
        match std::thread::Builder::new()
            .name("triage-journal-page".into())
            .spawn(move || {
                let _ = tx.send(reader::read_page(&query, &flag));
                repaint.request_repaint_of(egui::ViewportId::ROOT);
            }) {
            Ok(_) => self.job = Some(Job { rx, cancel }),
            Err(error) => self.error = Some(error.to_string()),
        }
    }

    fn poll(&mut self) {
        let Some(job) = &self.job else {
            return;
        };
        let result = match job.rx.try_recv() {
            Ok(result) => result,
            Err(mpsc::TryRecvError::Empty) => return,
            Err(mpsc::TryRecvError::Disconnected) => {
                Err("The journal reader ended without a result".into())
            }
        };
        self.job = None;
        match result {
            Ok(page) => {
                self.error = None;
                self.land(&page);
                if self.note.is_empty()
                    && self
                        .page
                        .as_ref()
                        .is_some_and(|old| old.sha256 != page.sha256)
                {
                    self.note = "The journal was rebuilt since the previous page was read.".into();
                }
                self.page = Some(page);
            }
            // The previous page, if any, stays beside the reason.
            Err(error) => {
                self.focus = None;
                self.error = Some(error);
            }
        }
    }

    /// Select the event a focused read was asked for.
    fn land(&mut self, page: &Page) {
        self.note.clear();
        let Some(focus) = self.focus.take() else {
            return;
        };
        self.offset = page.offset;
        if let Focus::Source(source) = focus {
            self.selected = page
                .rows
                .iter()
                .find(|row| row.event.evidence == source)
                .map(|row| row.id);
            if page.source_matches > 1 {
                self.note = format!(
                    "{} events were recorded for this one call or packet; the first is selected.",
                    page.source_matches
                );
            }
        }
        self.scroll_to = self.selected;
    }

    /// Draw the window and start any read it needs. Call once per frame.
    pub(super) fn show(
        &mut self,
        ctx: &egui::Context,
        run: Option<&(PathBuf, Identity)>,
        clock: Option<HostClockAnchor>,
    ) {
        if !self.open {
            return;
        }
        let Some((directory, identity)) = run else {
            self.close();
            return;
        };
        self.poll();
        if self.wanted {
            self.start(ctx, directory, identity);
        }
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let path = directory.join(JOURNAL_FILE);
        let mut open = true;
        egui::Window::new("Event journal")
            .id(egui::Id::new("detection-event-journal"))
            .open(&mut open)
            .default_size([900.0, 640.0])
            .resizable(true)
            .show(ctx, |ui| self.body(ui, &path, clock));
        if !open {
            self.close();
        }
    }

    fn body(&mut self, ui: &mut egui::Ui, path: &Path, clock: Option<HostClockAnchor>) {
        self.header(ui, path);
        ui.separator();
        self.filters(ui);
        self.table(ui, clock);
        ui.separator();
        self.detail(ui, clock);
    }

    fn header(&mut self, ui: &mut egui::Ui, path: &Path) {
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("Open file")
                .on_hover_text(
                    "Open the raw JSONL in your default application. This app only reads the file and never writes it.",
                )
                .clicked()
            {
                crate::folders::open_file_detached(path.to_path_buf());
            }
            if ui.button("Copy path").clicked() {
                ui.ctx().copy_text(path.display().to_string());
            }
            if ui
                .button("Reload")
                .on_hover_text("Read the journal again")
                .clicked()
            {
                self.restart(self.offset);
            }
            if self.job.is_some() {
                crate::theme::loading_weak(ui, "Reading…");
            }
        });
        if let Some(error) = &self.error {
            notice(ui, error);
        }
        let Some(page) = &self.page else {
            if self.job.is_none() && self.error.is_none() {
                ui.weak("No journal has been read yet.");
            }
            return;
        };
        let (label, color, reason) = coverage(page);
        ui.horizontal_wrapped(|ui| {
            presentation::badge(ui, label, color);
            ui.add(egui::Label::new(reason).wrap());
        });
        ui.add(
            egui::Label::new(
                RichText::new(reader::category_detail(&page.categories))
                    .small()
                    .color(theme::muted()),
            )
            .wrap(),
        );
        ui.add(
            egui::Label::new(
                RichText::new(format!(
                    "{} · {} · SHA-256 {}",
                    path.display(),
                    crate::network_view::format_bytes(page.size),
                    page.sha256
                ))
                .small()
                .monospace()
                .color(theme::muted()),
            )
            .wrap(),
        );
        match page.scanned_match {
            Some(true) => {
                ui.weak("Identical to the journal this scan read.");
            }
            Some(false) => notice(
                ui,
                "This journal differs from the one the scan read, so finding event numbers may not apply. Scan again.",
            ),
            None => {}
        }
        for warning in &page.warnings {
            notice(ui, warning);
        }
        if !self.note.is_empty() {
            ui.weak(&self.note);
        }
    }

    fn filters(&mut self, ui: &mut egui::Ui) {
        let categories: Vec<_> = self.page.as_ref().map_or_else(Vec::new, |page| {
            page.categories
                .iter()
                .map(|(name, count)| (name.clone(), *count))
                .collect()
        });
        let mut category = None;
        let mut search = None;
        ui.horizontal_wrapped(|ui| {
            let shown = if self.category.is_empty() {
                "All categories"
            } else {
                self.category.as_str()
            };
            egui::ComboBox::from_id_salt("journal-category")
                .selected_text(shown)
                .show_ui(ui, |ui| {
                    if ui
                        .selectable_label(self.category.is_empty(), "All categories")
                        .clicked()
                    {
                        category = Some(String::new());
                    }
                    for (name, count) in &categories {
                        let label = format!("{name} ({})", engine::group_digits(*count));
                        if ui.selectable_label(self.category == *name, label).clicked() {
                            category = Some(name.clone());
                        }
                    }
                });
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.search)
                    .hint_text(crate::theme::hint_text("Search category, field or value"))
                    .desired_width(260.0),
            );
            let entered =
                edit.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
            if ui.button("Search").clicked() || entered {
                search = Some(self.search.trim().to_owned());
            }
            if (!self.category.is_empty() || !self.applied.is_empty() || !self.search.is_empty())
                && ui.button("Clear").clicked()
            {
                category = Some(String::new());
                search = Some(String::new());
            }
        });
        if category.is_some() || search.is_some() {
            if let Some(category) = category {
                self.category = category;
            }
            if let Some(search) = search {
                self.search = search.clone();
                self.applied = search;
            }
            self.selected = None;
            self.note.clear();
            self.restart(0);
        }
    }

    fn table(&mut self, ui: &mut egui::Ui, clock: Option<HostClockAnchor>) {
        let Some(page) = &self.page else {
            return;
        };
        let (first, last, matching) = (page.offset, page.offset + page.rows.len(), page.matching);
        let mut to_page = None;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(first > 0, egui::Button::new("Previous"))
                .clicked()
            {
                to_page = Some(first.saturating_sub(PAGE_SIZE));
            }
            if ui
                .add_enabled((last as u64) < matching, egui::Button::new("Next"))
                .clicked()
            {
                to_page = Some(last);
            }
            let range = if page.rows.is_empty() {
                "No events".to_owned()
            } else {
                format!("Events {}–{}", first + 1, last)
            };
            let filtered = if matching == page.events {
                String::new()
            } else {
                format!(
                    " matching, of {} in the journal",
                    engine::group_digits(page.events)
                )
            };
            ui.label(format!(
                "{range} of {}{filtered}",
                engine::group_digits(matching)
            ));
        });
        if page.rows.is_empty() {
            ui.weak(if page.events == 0 {
                "The journal has no events."
            } else {
                "No events match the filters."
            });
        } else {
            let height = (ui.available_height() - 230.0).clamp(140.0, 420.0);
            let mut table = TableBuilder::new(ui)
                .id_salt("journal-rows")
                .striped(true)
                .sense(egui::Sense::click())
                .column(Column::exact(64.0))
                .column(Column::initial(150.0).at_least(80.0).clip(true))
                .column(Column::initial(190.0).at_least(80.0).clip(true))
                .column(Column::initial(220.0).at_least(80.0).clip(true))
                .column(Column::remainder().at_least(120.0).clip(true))
                .min_scrolled_height(0.0)
                .max_scroll_height(height);
            if let Some(index) = self
                .scroll_to
                .take()
                .and_then(|id| page.rows.iter().position(|row| row.id == id))
            {
                table = table.scroll_to_row(index, Some(egui::Align::Center));
            }
            let mut chosen = None;
            table
                .header(ROW_HEIGHT, |mut header| {
                    for label in ["Event", "Category", "Time", "Process", "Fields"] {
                        header.col(|ui| {
                            ui.strong(label);
                        });
                    }
                })
                .body(|body| {
                    body.rows(ROW_HEIGHT, page.rows.len(), |mut line| {
                        let row = &page.rows[line.index()];
                        line.set_selected(self.selected == Some(row.id));
                        let process = process_text(&row.event);
                        let fields = field_text(&row.event);
                        line.col(|ui| {
                            ui.monospace(row.id.to_string());
                        });
                        line.col(|ui| {
                            ui.label(&row.event.category);
                        });
                        line.col(|ui| {
                            ui.label(time_text(row.event.time, clock));
                        });
                        line.col(|ui| {
                            ui.label(&process).on_hover_text(&process);
                        });
                        line.col(|ui| {
                            ui.label(&fields).on_hover_text(&fields);
                        });
                        if line.response().clicked() {
                            chosen = Some(row.id);
                        }
                    });
                });
            if chosen.is_some() {
                self.selected = chosen;
            }
        }
        if let Some(offset) = to_page {
            self.restart(offset);
        }
    }

    fn detail(&mut self, ui: &mut egui::Ui, clock: Option<HostClockAnchor>) {
        let Some(row) = self
            .page
            .as_ref()
            .zip(self.selected)
            .and_then(|(page, id)| page.rows.iter().find(|row| row.id == id))
        else {
            ui.weak("Select an event to see all of its fields.");
            return;
        };
        egui::ScrollArea::vertical()
            .id_salt("journal-detail")
            .max_height(220.0)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(format!("Event #{} · {}", row.id, row.event.category))
                            .strong()
                            .color(theme::heading()),
                    );
                    if ui.small_button("Copy fields").clicked() {
                        let fields = serde_json::to_string_pretty(&row.event.fields);
                        ui.ctx().copy_text(fields.unwrap_or_default());
                    }
                });
                egui::Grid::new("journal-fields")
                    .num_columns(2)
                    .spacing([12.0, 3.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Time").color(theme::muted()));
                        ui.label(time_detail(row.event.time, clock));
                        ui.end_row();
                        for (name, value) in &row.event.fields {
                            ui.label(RichText::new(name).color(theme::muted()));
                            ui.add(
                                egui::Label::new(RichText::new(value_text(value)).monospace())
                                    .wrap(),
                            );
                            ui.end_row();
                        }
                    });
                ui.weak("A field that was not captured for this event is absent, not empty.");
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("Source").color(theme::muted()));
                    if ui
                        .add(egui::Button::new(finding::evidence_label(&row.event.evidence)).wrap())
                        .on_hover_text(
                            "Open the recorded call in Syscall Trace, or the packet in Network",
                        )
                        .clicked()
                    {
                        jump_to_source(ui.ctx(), &row.event);
                    }
                });
            });
    }
}

/// Leave the call or packet behind `event` for the app to open.
fn jump_to_source(ctx: &egui::Context, event: &Event) {
    request_evidence_jump(ctx, &finding::evidence_values(&event.evidence));
}

fn notice(ui: &mut egui::Ui, message: &str) {
    ui.add(egui::Label::new(RichText::new(message).color(theme::warn())).wrap());
}

/// Whether the journal covers everything, and if not, why.
fn coverage(page: &Page) -> (&'static str, egui::Color32, String) {
    if page.complete() {
        return (
            "Complete",
            theme::good(),
            "The end record says every recorded call and packet was normalized and none was left out.".into(),
        );
    }
    let reason = match page.end {
        None => "There is no usable end record, so events may be missing.".to_owned(),
        Some(end) if end.omitted > 0 => format!(
            "{} {} left out because {} too large or past the size limit.",
            engine::group_digits(end.omitted),
            if end.omitted == 1 {
                "event was"
            } else {
                "events were"
            },
            if end.omitted == 1 {
                "it was"
            } else {
                "they were"
            },
        ),
        Some(end) if !end.complete => "The journal does not cover every recorded call.".to_owned(),
        Some(_) => "The file could not be read in full; see the notes below.".to_owned(),
    };
    ("Partial", theme::warn(), reason)
}

fn value_text(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// `Image (pid)`, with whichever half the event has.
fn process_text(event: &Event) -> String {
    let image = event.fields.get("Image").map(value_text);
    let pid = event.fields.get("ProcessId").map(value_text);
    match (image, pid) {
        (Some(image), Some(pid)) => format!("{image} ({pid})"),
        (Some(image), None) => image,
        (None, Some(pid)) => format!("pid {pid}"),
        (None, None) => "—".into(),
    }
}

/// The fields beyond the process columns, as `Name=value`.
fn field_text(event: &Event) -> String {
    event
        .fields
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), "Image" | "ProcessId" | "ThreadId"))
        .map(|(name, value)| format!("{name}={}", value_text(value)))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Calls carry the guest clock, which needs the recording's anchor to become
/// wall time; without one the raw guest value is shown.
fn time_text(time: Option<Moment>, clock: Option<HostClockAnchor>) -> String {
    match time {
        Some(Moment::GuestNs(ns)) => clock
            .and_then(|anchor| anchor.host_us(ns))
            .map(|us| format!("~{}", crate::time_format::short_time_us(us)))
            .unwrap_or_else(|| format!("{ns} ns (guest clock)")),
        Some(Moment::EpochUs(us)) => crate::time_format::short_time_us(us),
        None => "—".into(),
    }
}

fn time_detail(time: Option<Moment>, clock: Option<HostClockAnchor>) -> String {
    match time {
        Some(Moment::GuestNs(ns)) => match clock.and_then(|anchor| anchor.host_us(ns)) {
            Some(us) => format!("~{} (guest clock {ns} ns)", crate::time_format::unix_us(us)),
            None => format!("{ns} ns on the guest clock; this recording has no wall-clock anchor"),
        },
        Some(Moment::EpochUs(us)) => crate::time_format::unix_us(us),
        None => "Not recorded for this event".into(),
    }
}

#[cfg(test)]
mod tests;

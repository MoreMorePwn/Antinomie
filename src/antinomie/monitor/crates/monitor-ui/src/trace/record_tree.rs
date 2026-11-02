// SPDX-License-Identifier: GPL-3.0-only
//! A captured array of records (directory entries, pollfds, control messages,
//! BPF instructions, ...) as an expandable tree in the Details pane: a header
//! with the entry count, one collapsed line per record that opens to its
//! fields, copy as JSON for a row or the whole array, and "Decode all
//! captured" to read the field's evidence past the 256-byte preview.
//!
//! The decoders are `antinomie_monitor_core::typed_fields::Records`; this file
//! only draws, pages and copies. The whole capture is read on a worker thread
//! in the archive's 64 KiB reads, at most [`data_view::DATA_WINDOW_CAP`] bytes,
//! and only the contiguous bytes from offset 0 are decoded: records cannot be
//! found across a gap.
use super::{covered_preview, theme};
use crate::data_view;
use antinomie_monitor_core::{
    recording,
    typed_fields::{self, record_json, About, Call, Records},
    FieldSummary,
};
use eframe::egui::{self, RichText};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
};

/// Records shown on one page.
const PAGE: usize = 100;
/// Records one "Copy all as JSON" or saved file carries.
const JSON_RECORDS: usize = 50_000;
/// The archive hands out at most this many captured bytes per read.
const READ_CHUNK: u64 = 65536;

struct Loader {
    receiver: mpsc::Receiver<Result<Vec<u8>, String>>,
    progress: Arc<AtomicU64>,
    total: u64,
    cancelled: Arc<AtomicBool>,
}

impl Drop for Loader {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// The captured bytes read for "Decode all captured" and their records.
struct Full {
    bytes: Vec<u8>,
    records: Option<Records>,
    /// Bytes of the capture past the contiguous run that were left out.
    left_out: u64,
}

/// The tree's state for the field on show; reset when the field changes.
#[derive(Default)]
pub(crate) struct State {
    identity: String,
    loader: Option<Loader>,
    full: Option<Full>,
    error: Option<String>,
    page: usize,
    status: Option<String>,
}

/// What the tree is drawn for.
pub(super) struct Shown<'a> {
    /// Names this selection among all fields of all calls.
    pub identity: &'a str,
    pub call: Option<&'a Call<'a>>,
    pub syscall: &'a str,
    pub field: &'a FieldSummary,
    /// The recording the field's bytes can be read from.
    pub directory: Option<&'a Path>,
}

/// Bytes from offset 0 that the capture covers without a gap.
fn contiguous(field: &FieldSummary) -> u64 {
    let mut end = 0u64;
    loop {
        let next = field
            .ranges
            .iter()
            .filter(|(start, len)| *start <= end && start.saturating_add(*len) > end)
            .map(|(start, len)| start.saturating_add(*len))
            .max();
        match next {
            Some(next) => end = next,
            None => return end,
        }
    }
}

impl State {
    fn reset(&mut self, identity: &str) {
        *self = Self {
            identity: identity.to_owned(),
            ..Self::default()
        };
    }

    fn start(&mut self, ctx: &egui::Context, directory: PathBuf, field: &FieldSummary) {
        let total = contiguous(field).min(data_view::DATA_WINDOW_CAP);
        let (sender, receiver) = mpsc::channel();
        let progress = Arc::new(AtomicU64::new(0));
        let cancelled = Arc::new(AtomicBool::new(false));
        let (worker_progress, worker_cancelled) = (Arc::clone(&progress), Arc::clone(&cancelled));
        let (field, ctx) = (field.clone(), ctx.clone());
        let spawned = thread::Builder::new()
            .name("record-tree-reader".into())
            .spawn(move || {
                let mut bytes = Vec::with_capacity(usize::try_from(total).unwrap_or(0));
                let mut at = 0u64;
                while at < total {
                    if worker_cancelled.load(Ordering::Relaxed) {
                        return;
                    }
                    let count = (total - at).min(READ_CHUNK) as usize;
                    match recording::read_captured_range(&directory, &field, at, count) {
                        Ok(chunk) => bytes.extend_from_slice(&chunk),
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            ctx.request_repaint();
                            return;
                        }
                    }
                    at += count as u64;
                    worker_progress.store(at, Ordering::Relaxed);
                }
                let _ = sender.send(Ok(bytes));
                ctx.request_repaint();
            });
        match spawned {
            Ok(_) => {
                self.loader = Some(Loader {
                    receiver,
                    progress,
                    total,
                    cancelled,
                });
                self.error = None;
            }
            Err(error) => self.error = Some(format!("Could not read the capture: {error}")),
        }
    }

    fn poll(&mut self, field: &FieldSummary, full: &mut Option<Full>) {
        let Some(loader) = &self.loader else { return };
        match loader.receiver.try_recv() {
            Ok(Ok(bytes)) => {
                let left_out = field.captured_len.saturating_sub(bytes.len() as u64);
                *full = Some(Full {
                    bytes,
                    records: None,
                    left_out,
                });
                self.page = 0;
                self.loader = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("Could not read the capture: {error}"));
                self.loader = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => self.loader = None,
        }
    }
}

/// Draw the field as a record tree. False when it is not a record array (or
/// has no bytes), so the caller shows its usual decoding.
pub(super) fn show(ui: &mut egui::Ui, state: &mut State, shown: &Shown<'_>) -> bool {
    let mut full = None;
    if state.identity == shown.identity {
        full = state.full.take();
    }
    let drawn = draw(ui, state, shown, &mut full);
    if state.identity == shown.identity && state.full.is_none() {
        state.full = full;
    }
    drawn
}

fn draw(ui: &mut egui::Ui, state: &mut State, shown: &Shown<'_>, full: &mut Option<Full>) -> bool {
    let field = shown.field;
    let layout = typed_fields::layout_type(&field.layout);
    if !typed_fields::is_array(layout) {
        return false;
    }
    if state.identity != shown.identity {
        state.reset(shown.identity);
    }
    state.poll(field, full);
    let preview = covered_preview(field);
    if full.is_none() && preview.is_empty() {
        return false;
    }
    if let Some(full) = full.as_mut()
        && full.records.is_none()
    {
        full.records = Records::open(shown.call, layout, &field.key, &full.bytes);
    }
    let preview_records;
    let (records, data, decoded_all) = match &*full {
        Some(Full {
            bytes,
            records: Some(records),
            ..
        }) => (records, bytes.as_slice(), true),
        _ => {
            let Some(opened) = Records::open(shown.call, layout, &field.key, preview) else {
                return false;
            };
            preview_records = opened;
            (&preview_records, preview, false)
        }
    };
    let total = records.count();
    let holds_more = !decoded_all
        && (field.captured_len > preview.len() as u64
            || field
                .logical_len
                .is_some_and(|len| len > preview.len() as u64));
    let about = About {
        syscall: shown.syscall,
        field: &field.key,
        layout: &field.layout,
        captured_bytes: field.captured_len,
        more: holds_more,
    };

    let mut action = header(ui, state, shown, records, total, holds_more, decoded_all);
    if let Some(error) = &state.error {
        crate::activity::error(ui, error.clone());
    }
    if let Some(loader) = &state.loader {
        let done = loader.progress.load(Ordering::Relaxed);
        theme::loading_colored(
            ui,
            theme::muted(),
            format!("Reading capture… {done} of {} bytes", loader.total),
        );
    }
    if let Some(cut) = records.cut() {
        let note = cut.note(records.element());
        let note = if decoded_all || !holds_more {
            note
        } else {
            format!("{note} The preview ends here; Decode all captured reads the rest.")
        };
        super::warning_line(ui, &note);
    }
    if records.capped() {
        super::warning_line(
            ui,
            &format!(
                "More than {} records: the rest are not decoded.",
                typed_fields::MAX_RECORDS
            ),
        );
    }
    if let Some(full) = &*full
        && full.left_out > 0
    {
        super::warning_line(
            ui,
            &format!(
                "{} captured bytes are not decoded (a gap in the capture, or more than {} MiB).",
                full.left_out,
                data_view::DATA_WINDOW_CAP / (1024 * 1024)
            ),
        );
    }

    let pages = total.div_ceil(PAGE).max(1);
    state.page = state.page.min(pages - 1);
    let first = state.page * PAGE;
    let last = (first + PAGE).min(total);
    ui.horizontal_wrapped(|ui| {
        let more = if holds_more || records.cut().is_some() {
            "+"
        } else {
            ""
        };
        let text = if total == 0 {
            "no entries decoded".to_owned()
        } else {
            format!("showing {}-{} of {total}{more}", first + 1, last)
        };
        ui.colored_label(theme::muted(), text);
        if pages > 1 {
            if ui
                .add_enabled(state.page > 0, egui::Button::new("Previous"))
                .clicked()
            {
                state.page -= 1;
            }
            ui.colored_label(
                theme::muted(),
                format!("page {} of {pages}", state.page + 1),
            );
            if ui
                .add_enabled(state.page + 1 < pages, egui::Button::new("Next"))
                .clicked()
            {
                state.page += 1;
            }
        }
    });
    if let Some(status) = &state.status {
        ui.colored_label(theme::muted(), status);
    }
    for (index, record) in records.page(data, first, PAGE) {
        let response = egui::CollapsingHeader::new(
            RichText::new(format!("[{index}] {}", record.summary)).monospace(),
        )
        .id_salt((shown.identity, index))
        .show(ui, |ui| {
            egui::Grid::new((shown.identity, "fields", index))
                .num_columns(2)
                .show(ui, |ui| {
                    for (name, value) in &record.fields {
                        ui.colored_label(theme::muted(), name);
                        let label = ui.add(
                            egui::Label::new(RichText::new(value).monospace())
                                .wrap()
                                .sense(egui::Sense::click()),
                        );
                        label.context_menu(|ui| {
                            if ui.button("Copy value").clicked() {
                                ui.ctx().copy_text(value.clone());
                                ui.close_menu();
                            }
                        });
                        ui.end_row();
                    }
                });
            if ui.small_button("Copy row as JSON").clicked() {
                ui.ctx().copy_text(record_json(index, &record));
                state.status = Some(format!("Copied record {index} as JSON."));
            }
        });
        response.header_response.context_menu(|ui| {
            if ui.button("Copy row as JSON").clicked() {
                ui.ctx().copy_text(record_json(index, &record));
                state.status = Some(format!("Copied record {index} as JSON."));
                ui.close_menu();
            }
            if ui.button("Copy summary").clicked() {
                ui.ctx().copy_text(record.summary.clone());
                ui.close_menu();
            }
        });
    }

    // Buttons act on the whole array.
    if let Some(action) = action.take() {
        let json = records.json(data, 0, JSON_RECORDS, &about);
        match action {
            Action::Copy => {
                ui.ctx().copy_text(json);
                state.status = Some(format!(
                    "Copied {} records as JSON.",
                    total.min(JSON_RECORDS)
                ));
            }
            Action::Save => {
                state.status = Some(match shown.directory {
                    Some(directory) => save(directory, shown, json.as_bytes()),
                    None => "There is no recording folder to save into.".into(),
                })
            }
        }
    }
    true
}

enum Action {
    Copy,
    Save,
}

fn header(
    ui: &mut egui::Ui,
    state: &mut State,
    shown: &Shown<'_>,
    records: &Records,
    total: usize,
    holds_more: bool,
    decoded_all: bool,
) -> Option<Action> {
    let field = shown.field;
    let mut action = None;
    ui.horizontal_wrapped(|ui| {
        let noun = if total == 1 { "entry" } else { "entries" };
        ui.label(RichText::new(format!("{total} {noun}")).strong());
        ui.colored_label(
            theme::muted(),
            format!(
                "{} · {} of {} bytes decoded{}",
                records.element(),
                records.consumed(),
                field.captured_len,
                if holds_more { " (preview)" } else { "" }
            ),
        );
    });
    ui.horizontal_wrapped(|ui| {
        if holds_more {
            let readable = shown.directory.is_some() && field.raw_path.is_some();
            let button = ui.add_enabled(
                readable && state.loader.is_none(),
                egui::Button::new(format!(
                    "Decode all captured ({} bytes)",
                    field.captured_len
                )),
            );
            let button = if readable {
                button.on_hover_text("Read the field's whole capture and decode every record")
            } else {
                button.on_disabled_hover_text(
                    "The full capture is not readable here; only the preview is decoded",
                )
            };
            if button.clicked()
                && let Some(directory) = shown.directory
            {
                state.start(ui.ctx(), directory.to_path_buf(), field);
            }
        } else if decoded_all {
            ui.colored_label(theme::muted(), "All captured bytes decoded");
        }
        if ui.button("Copy all as JSON").clicked() {
            action = Some(Action::Copy);
        }
        if ui
            .button("Save as JSON")
            .on_hover_text("Write the records beside the run's other files, in records/")
            .clicked()
        {
            action = Some(Action::Save);
        }
    });
    action
}

/// Write the JSON into `directory/records/`, never over a file.
fn save(directory: &Path, shown: &Shown<'_>, json: &[u8]) -> String {
    use std::{
        io::Write,
        os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    };
    let sanitized: String = shown
        .field
        .key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let folder = directory.join("records");
    let name = format!(
        "{}-{sanitized}-{}.json",
        shown.syscall,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs())
    );
    let path = folder.join(name);
    let written = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&folder)
        .and_then(|()| {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
        })
        .and_then(|mut file| file.write_all(json).and_then(|()| file.sync_all()));
    match written {
        Ok(()) => format!("Saved {}", path.display()),
        Err(error) => format!("Could not save {}: {error}", path.display()),
    }
}

/// Every array field of the call (from the owned previews) as one JSON
/// document: the call's identity and, per field, its records. Empty when the
/// call has no record array.
pub(crate) fn call_json(invocation: &super::InvocationSummary) -> String {
    let Some(event) = super::representative(invocation) else {
        return String::new();
    };
    let call = super::field_call(event.syscall_nr, super::call_args(invocation));
    let mut arrays = Vec::new();
    for field in invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .flat_map(|event| &event.fields)
    {
        let layout = typed_fields::layout_type(&field.layout);
        let data = covered_preview(field);
        let Some(records) = Records::open(call.as_ref(), layout, &field.key, data) else {
            continue;
        };
        let about = About {
            syscall: &event.syscall_name,
            field: &field.key,
            layout: &field.layout,
            captured_bytes: field.captured_len,
            more: field.captured_len > data.len() as u64,
        };
        arrays.push(records.json(data, 0, JSON_RECORDS, &about));
    }
    if arrays.is_empty() {
        return String::new();
    }
    format!("[\n{}\n]", arrays.join(",\n"))
}

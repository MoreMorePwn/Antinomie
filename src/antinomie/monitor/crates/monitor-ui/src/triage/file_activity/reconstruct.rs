// SPDX-License-Identifier: GPL-3.0-only
//! The File Reconstruction window of Triage > Files > Per-file history: a
//! file's calls replayed in write order over what it held when the run
//! started, with the state of every byte after the chosen call, how each byte
//! became known, the hash check against what the guest took, and a save with
//! a mask of the bytes nobody saw.
use super::{Activity, FileActivity};
use crate::theme;
use crate::widgets::{self, Tone};
use antinomie_monitor_core::file_reconstruct::{
    self as model, Action, Cell, Change, Event, Incomplete, Reconstruction, Start, State, START,
};
use eframe::egui::{self, Color32, RichText};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// The request a Files tab's row menu leaves for the Per-file history.
pub(in crate::triage) const REQUEST: &str = "triage-reconstruct-request";
/// The Files tab tables whose rows can be reconstructed.
const TABLES: &[&str] = &[
    "triage-opened",
    "triage-created",
    "triage-read",
    "triage-written",
    "triage-deleted",
    "triage-renamed",
    "triage-executed",
    "triage-attributes",
    "triage-probed",
    "triage-other",
    "triage-changed",
];
/// Bytes in a row of the byte map.
const ROW: usize = 16;
/// Largest file the line diff is offered for.
const TEXT_LIMIT: u64 = 1 << 20;
/// Bytes the hex copy holds at most.
const COPY_LIMIT: u64 = 256 << 10;
/// Rows of the byte map kept ready.
const CACHE_ROWS: usize = 4096;

/// The path of the file a Files tab row is about, when it is one.
pub(in crate::triage) fn row_path(
    table: &str,
    values: &[(&str, crate::triage::RowValue)],
) -> Option<String> {
    if !TABLES.contains(&table) {
        return None;
    }
    values
        .iter()
        .find_map(|(name, value)| match (*name, value) {
            ("file.path", crate::triage::RowValue::Text(path)) => Some(path.clone()),
            _ => None,
        })
}

/// The row menu entry: "Reconstruct contents…" opens the file in the Per-file
/// history with its reconstruction.
pub(in crate::triage) fn menu(
    ui: &mut egui::Ui,
    table: &str,
    values: &[(&str, crate::triage::RowValue)],
) {
    if let Some(path) = row_path(table, values) {
        if ui
            .button("Reconstruct contents…")
            .on_hover_text("Open this file's reconstruction in the Per-file history")
            .clicked()
        {
            ui.ctx()
                .data_mut(|data| data.insert_temp(egui::Id::new(REQUEST), path));
            ui.close_menu();
        }
    }
}

/// A job running on its own thread.
struct Pending<T>(Arc<Mutex<Option<T>>>);

impl<T: Send + 'static> Pending<T> {
    fn spawn(ctx: &egui::Context, work: impl FnOnce() -> T + Send + 'static) -> Self {
        let slot = Arc::new(Mutex::new(None));
        let (out, ctx) = (Arc::clone(&slot), ctx.clone());
        std::thread::spawn(move || {
            let done = work();
            if let Ok(mut slot) = out.lock() {
                *slot = Some(done);
            }
            ctx.request_repaint();
        });
        Self(slot)
    }

    fn done(&self) -> Option<T> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// The hash of the reconstruction at a point in the story.
struct Hashed {
    position: usize,
    result: Result<String, Incomplete>,
}

/// The file's bytes before the run: from the starting disk, empty for a file
/// the run created, unknown otherwise.
pub(in crate::triage) fn start_of(file: &FileActivity) -> Start {
    match file.earlier.as_ref() {
        Some(earlier) => Start::from_earlier(Some(&earlier.before), earlier.file.as_ref()),
        None if file.created => Start::empty(),
        None => Start::default(),
    }
}

/// An open reconstruction of one file.
pub(super) struct Open {
    /// The file: path and first call.
    key: (String, u64),
    map: Reconstruction,
    selected: Option<u64>,
    text_view: bool,
    /// Rows of the byte map already read, for the position they were read at.
    cache: HashMap<u64, Vec<Cell>>,
    cache_at: usize,
    hashing: Option<Pending<Hashed>>,
    hashed: Option<Hashed>,
    saving: Option<Pending<Result<String, String>>>,
    status: Option<String>,
    /// The line diff for a position.
    diff: Option<(usize, Result<Vec<model::DiffLine>, String>)>,
    hovered: bool,
}

impl Open {
    pub(super) fn new(file: &FileActivity) -> Self {
        Self::with_start(file, start_of(file))
    }

    /// The reconstruction of `file` over a given starting state.
    pub(super) fn with_start(file: &FileActivity, start: Start) -> Self {
        let mut map = Reconstruction::new(start, &file.timeline);
        map.goto(file.timeline.steps().len());
        Self {
            key: (file.path.clone(), file.first_ns),
            map,
            selected: None,
            text_view: false,
            cache: HashMap::new(),
            cache_at: 0,
            hashing: None,
            hashed: None,
            saving: None,
            status: None,
            diff: None,
            hovered: false,
        }
    }

    pub(super) fn key(&self) -> &(String, u64) {
        &self.key
    }

    /// Hash the state now and wait for it, and choose the text view, for the
    /// screenshots.
    #[cfg(test)]
    pub(super) fn prepare(&mut self, text_view: bool) {
        self.hashed = Some(Hashed {
            position: self.map.position(),
            result: self.map.sha256(),
        });
        self.text_view = text_view;
    }

    /// The size the map spans, for the tests.
    #[cfg(test)]
    pub(super) fn size(&self) -> u64 {
        self.map.size()
    }

    fn goto(&mut self, position: usize) {
        if position != self.map.position() {
            self.map.goto(position);
            self.hashed = None;
        }
    }

    /// The window. Returns false once it is closed.
    pub(super) fn show(
        &mut self,
        ctx: &egui::Context,
        activity: &Activity,
        file: &FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
        directory: Option<&Path>,
    ) -> bool {
        if let Some(done) = self.hashing.as_ref().and_then(Pending::done) {
            self.hashing = None;
            self.hashed = Some(done);
        }
        if let Some(done) = self.saving.as_ref().and_then(Pending::done) {
            self.saving = None;
            self.status = Some(done.unwrap_or_else(|error| error));
        }
        if self.hovered {
            let (back, forward) = ctx.input(|input| {
                (
                    input.key_pressed(egui::Key::ArrowLeft),
                    input.key_pressed(egui::Key::ArrowRight),
                )
            });
            let at = self.map.position();
            if back && at > 0 {
                self.goto(at - 1);
            }
            if forward {
                self.goto(at + 1);
            }
        }
        if self.cache_at != self.map.position() || self.cache.len() > CACHE_ROWS {
            self.cache.clear();
            self.cache_at = self.map.position();
        }
        let mut open = true;
        let shown = egui::Window::new("File reconstruction")
            .id(egui::Id::new("file-reconstruction-window"))
            .open(&mut open)
            .default_size([1020.0, 720.0])
            .min_width(520.0)
            .resizable(true)
            .show(ctx, |ui| self.body(ui, activity, file, clock, directory));
        self.hovered = shown.is_some_and(|shown| shown.response.contains_pointer());
        open
    }

    fn body(
        &mut self,
        ui: &mut egui::Ui,
        activity: &Activity,
        file: &FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
        directory: Option<&Path>,
    ) {
        self.header(ui, file);
        self.controls(ui, activity, file, clock);
        ui.separator();
        egui::SidePanel::right("file-reconstruction-side")
            .resizable(true)
            .default_width(300.0)
            .width_range(220.0..=520.0)
            .show_inside(ui, |ui| self.side(ui, file, clock, directory));
        egui::CentralPanel::default().show_inside(ui, |ui| {
            self.legend(ui);
            if self.text_view {
                self.text(ui);
            } else {
                self.bytes(ui, clock);
            }
        });
    }

    fn header(&self, ui: &mut egui::Ui, file: &FileActivity) {
        ui.add(egui::Label::new(RichText::new(&file.path).strong().monospace()).wrap());
        for name in &file.names {
            ui.weak(format!("also seen as {name}"));
        }
        let size = if self.map.size_known() {
            format!("{} B", self.map.size())
        } else {
            format!("at least {} B (the size is not known)", self.map.size())
        };
        ui.horizontal_wrapped(|ui| {
            if file.created {
                widgets::chip(ui, "created by the run", Tone::Good);
            }
            if file.deleted {
                widgets::chip(ui, "deleted", Tone::Error);
            }
            ui.weak(format!("Size after this call: {size}"));
        });
        if let Some(earlier) = &file.earlier {
            ui.weak(super::earlier::describe(earlier));
        }
        let tally = &file.writes.tally;
        if tally.offset_unknown > 0 {
            crate::activity::warning(
                ui,
                format!(
                    "{} B were written where the host could not place them (append or shared descriptor without a position record); they are not in the map.",
                    tally.offset_unknown
                ),
            );
        }
        if file.timeline.unlisted > 0 {
            crate::activity::warning(
                ui,
                format!(
                    "{} more calls changed this file after the list of steps was full; the map stops before them.",
                    file.timeline.unlisted
                ),
            );
        }
    }

    /// The step control: buttons, slider and the strip of calls.
    fn controls(
        &mut self,
        ui: &mut egui::Ui,
        activity: &Activity,
        file: &FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let total = self.map.steps().len();
        let mut at = self.map.position();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(at > 0, egui::Button::new("◀"))
                .on_hover_text("Previous call (←)")
                .clicked()
            {
                at -= 1;
            }
            ui.add(egui::Slider::new(&mut at, 0..=total).show_value(false));
            if ui
                .add_enabled(at < total, egui::Button::new("▶"))
                .on_hover_text("Next call (→)")
                .clicked()
            {
                at += 1;
            }
            ui.label(format!("Call {at} of {total}"));
            if total > 0 && ui.small_button("Start").clicked() {
                at = 0;
            }
            if total > 0 && ui.small_button("End").clicked() {
                at = total;
            }
        });
        if let Some(clicked) = strip(ui, self.map.steps(), at) {
            at = clicked;
        }
        ui.add(
            egui::Label::new(
                RichText::new(describe(&self.map, at, activity, file, clock)).color(theme::muted()),
            )
            .wrap(),
        );
        self.goto(at);
    }

    /// How many bytes are in each state, as the legend.
    fn legend(&self, ui: &mut egui::Ui) {
        let counts = self.map.counts();
        let entries: [(State, u64); 6] = [
            (State::Unknown, counts.unknown),
            (State::Read, counts.read),
            (State::Before, counts.before),
            (State::Written, counts.written),
            (
                State::NotCaptured(antinomie_monitor_core::file_writes::Gap::NotRecorded),
                counts.not_captured,
            ),
            (State::Mapping, counts.mapping),
        ];
        ui.horizontal_wrapped(|ui| {
            for (state, count) in entries {
                let glyph = state.glyph().unwrap_or(match state {
                    State::Read => "rd",
                    State::Before => "bf",
                    _ => "wr",
                });
                ui.label(
                    RichText::new(format!(" {glyph} "))
                        .monospace()
                        .color(tint(ui, state))
                        .background_color(ui.visuals().faint_bg_color),
                )
                .on_hover_text(state.label());
                ui.weak(format!("{} {}", count, short(state)));
            }
        });
    }

    /// The byte map.
    fn bytes(&mut self, ui: &mut egui::Ui, clock: Option<antinomie_monitor_core::HostClockAnchor>) {
        let size = self.map.size();
        if size == 0 {
            theme::empty_state(ui, "The file is empty at this point");
            return;
        }
        let rows = size.div_ceil(ROW as u64) as usize;
        let height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        egui::ScrollArea::vertical()
            .id_salt("file-reconstruction-bytes")
            .auto_shrink([false, false])
            .show_rows(ui, height, rows, |ui, range| {
                ui.spacing_mut().item_spacing.x = 4.0;
                for row in range {
                    let offset = (row * ROW) as u64;
                    let cells = match self.cache.get(&offset) {
                        Some(cells) => cells.clone(),
                        None => {
                            let cells = self.map.row(offset, ROW);
                            self.cache.insert(offset, cells.clone());
                            cells
                        }
                    };
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{offset:08x}"))
                                .monospace()
                                .color(theme::muted()),
                        );
                        for (index, cell) in cells.iter().enumerate() {
                            let at = offset + index as u64;
                            let text = match (cell.state.glyph(), cell.byte) {
                                (Some(glyph), _) => glyph.to_owned(),
                                (None, Some(byte)) => format!("{byte:02x}"),
                                (None, None) => "!!".to_owned(),
                            };
                            let mut rich =
                                RichText::new(text).monospace().color(tint(ui, cell.state));
                            if self.selected == Some(at) {
                                rich = rich
                                    .background_color(theme::primary().gamma_multiply(0.45))
                                    .strong();
                            }
                            let response = ui.add(
                                egui::Label::new(rich)
                                    .sense(egui::Sense::click())
                                    .selectable(false),
                            );
                            if response.clicked() {
                                self.selected = Some(at);
                            }
                            response.on_hover_ui(|ui| {
                                ui.label(format!("0x{at:x} · {}", cell.state.label()));
                                if cell.learned != START {
                                    let step = &self.map.steps()[cell.learned];
                                    ui.weak(format!(
                                        "learned at {} (call {})",
                                        crate::time_format::guest_ns(clock, Some(step.time_ns)),
                                        cell.learned + 1
                                    ));
                                } else if cell.state != State::Unknown {
                                    ui.weak("known from the start of the run");
                                }
                            });
                        }
                        let ascii: String = cells
                            .iter()
                            .map(|cell| match (cell.state.has_value(), cell.byte) {
                                (true, Some(byte @ 32..=126)) => char::from(byte),
                                (true, Some(_)) => '.',
                                _ => '·',
                            })
                            .collect();
                        ui.label(
                            RichText::new(format!("|{ascii}|"))
                                .monospace()
                                .color(theme::muted()),
                        );
                    });
                }
            });
    }

    /// The line diff of the file at the start of the run and now.
    fn text(&mut self, ui: &mut egui::Ui) {
        let position = self.map.position();
        if self.diff.as_ref().is_none_or(|(at, _)| *at != position) {
            let now = self.map.text(TEXT_LIMIT);
            let mut start = Reconstruction::new(self.start(), &model::Timeline::default());
            start.goto(0);
            let before = start.text(TEXT_LIMIT);
            let result = match (before, now) {
                (Ok(before), Ok(now)) => Ok(model::line_diff(&before, &now)),
                (Err(error), _) => Err(format!(
                    "The file at the start of the run has no text view: {}.",
                    error.label()
                )),
                (_, Err(error)) => Err(format!(
                    "The file at this call has no text view: {}.",
                    error.label()
                )),
            };
            self.diff = Some((position, result));
        }
        match self.diff.as_ref().map(|(_, result)| result) {
            Some(Ok(lines)) => {
                if lines.iter().all(|line| line.change == Change::Same) {
                    ui.weak("No line differs from the start of the run.");
                }
                egui::ScrollArea::both()
                    .id_salt("file-reconstruction-diff")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        for (number, line) in lines.iter().enumerate() {
                            let (mark, color) = match line.change {
                                Change::Same => (' ', theme::muted()),
                                Change::Added => ('+', theme::good()),
                                Change::Removed => ('-', theme::error()),
                            };
                            ui.label(
                                RichText::new(format!("{:>4} {mark} {}", number + 1, line.text))
                                    .monospace()
                                    .color(color),
                            );
                        }
                    });
            }
            Some(Err(why)) => {
                ui.weak(why.as_str());
            }
            None => {}
        }
    }

    fn start(&self) -> Start {
        self.map.start().clone()
    }

    fn side(
        &mut self,
        ui: &mut egui::Ui,
        file: &FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
        directory: Option<&Path>,
    ) {
        egui::ScrollArea::vertical()
            .id_salt("file-reconstruction-side-scroll")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.text_view, false, "Bytes");
                    ui.selectable_value(&mut self.text_view, true, "Text diff")
                        .on_hover_text("Lines changed since the start of the run, for text files whose every byte is known");
                });
                heading(ui, "What this call changed");
                self.changed(ui);
                heading(ui, "Byte history");
                self.history(ui, clock);
                heading(ui, "Hash check");
                self.hash(ui, file, clock);
                heading(ui, "Reconstruction");
                self.actions(ui, file, directory);
            });
    }

    fn changed(&self, ui: &mut egui::Ui) {
        let position = self.map.position();
        let Some(step) = position
            .checked_sub(1)
            .and_then(|at| self.map.steps().get(at))
        else {
            ui.weak("The start of the run: nothing changed yet.");
            return;
        };
        let ranges = step.ranges();
        if ranges.is_empty() {
            if let Action::Resize(to) = step.action {
                ui.weak(format!("The file was resized to {to} B."));
            } else {
                ui.weak("No bytes changed (a read of bytes already known).");
            }
        }
        for (offset, len, state) in ranges.iter().take(12) {
            let end = if *len == u64::MAX {
                self.map.size()
            } else {
                offset.saturating_add(*len)
            };
            let cells = self
                .map
                .row(*offset, 8.min(end.saturating_sub(*offset) as usize));
            let hex: Vec<String> = cells
                .iter()
                .map(|cell| match (cell.state.glyph(), cell.byte) {
                    (Some(glyph), _) => glyph.to_owned(),
                    (None, Some(byte)) => format!("{byte:02x}"),
                    (None, None) => "!!".into(),
                })
                .collect();
            let what = match state {
                Some(state) => state.label(),
                None => "bytes seen",
            };
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "0x{offset:x} +{} · {what}\n{}{}",
                        if *len == u64::MAX {
                            "to the end".to_owned()
                        } else {
                            len.to_string()
                        },
                        hex.join(" "),
                        if end.saturating_sub(*offset) > 8 {
                            " …"
                        } else {
                            ""
                        }
                    ))
                    .monospace()
                    .small(),
                )
                .wrap(),
            );
        }
        if ranges.len() > 12 {
            ui.weak(format!("… and {} more ranges", ranges.len() - 12));
        }
    }

    fn history(&self, ui: &mut egui::Ui, clock: Option<antinomie_monitor_core::HostClockAnchor>) {
        let Some(offset) = self.selected else {
            ui.weak("Click a byte to see how it became known.");
            return;
        };
        ui.label(RichText::new(format!("Byte 0x{offset:x}")).strong());
        let history = self.map.history(offset);
        if history.is_empty() {
            ui.weak("No call has shown this byte: it is unknown.");
            return;
        }
        for entry in &history {
            let when = if entry.step == START {
                "start of the run".to_owned()
            } else {
                let step = &self.map.steps()[entry.step];
                format!(
                    "{} (call {})",
                    crate::time_format::guest_ns(clock, Some(step.time_ns)),
                    entry.step + 1
                )
            };
            let value = entry
                .byte
                .map_or(String::new(), |byte| format!(" = {byte:02x}"));
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{when}\n  {}{value}", entry.event.label()))
                        .monospace()
                        .small(),
                )
                .wrap(),
            );
        }
        if let Some(last) = history.iter().rfind(|entry| entry.event != Event::Cut) {
            if last.event == Event::Read {
                ui.weak("A read shows the file as it was then; a process outside the trace could have changed it later.");
            }
        }
    }

    fn hash(
        &mut self,
        ui: &mut egui::Ui,
        file: &FileActivity,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let mut guest: Vec<(String, String)> = file
            .hashes
            .iter()
            .filter_map(|note| {
                Some((
                    note.sha256.clone()?,
                    format!(
                        "{} at {}",
                        note.moment,
                        crate::time_format::guest_ns(clock, Some(note.time))
                    ),
                ))
            })
            .collect();
        if let Some(hex) = file
            .contents
            .hash
            .as_ref()
            .and_then(|hash| hash.sha256_hex())
        {
            if !guest.iter().any(|(known, _)| *known == hex) {
                guest.push((hex, "the guest's hash".into()));
            }
        }
        if guest.is_empty() {
            ui.weak("The guest took no hash of this file.");
        }
        for (hex, moment) in &guest {
            ui.add(
                egui::Label::new(
                    RichText::new(format!("{moment}\n{hex}"))
                        .monospace()
                        .small(),
                )
                .wrap(),
            );
        }
        ui.horizontal(|ui| {
            let busy = self.hashing.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Hash this state"))
                .on_hover_text("SHA-256 of the file as reconstructed at the chosen call, when every byte is known")
                .clicked()
            {
                let (ctx, map) = (ui.ctx().clone(), self.map.clone());
                let position = map.position();
                self.hashing = Some(Pending::spawn(&ctx, move || Hashed {
                    position,
                    result: map.sha256(),
                }));
            }
            let last = file.hashes.iter().rev().find(|note| note.sha256.is_some());
            if let Some(note) = last {
                if ui
                    .button("Go to the last hash")
                    .on_hover_text("Show the file as it stood when the guest took its last hash")
                    .clicked()
                {
                    let position = self.map.steps_until(note.time);
                    self.goto(position);
                }
            }
        });
        if self.hashing.is_some() {
            ui.weak("Hashing…");
        }
        if let Some(hashed) = &self.hashed {
            match &hashed.result {
                Ok(hex) => {
                    ui.add(egui::Label::new(RichText::new(hex).monospace().small()).wrap());
                    match guest.iter().find(|(known, _)| known == hex) {
                        Some((_, moment)) => {
                            widgets::chip(ui, "matches the guest's hash", Tone::Good);
                            ui.weak(format!("Same as the hash taken {moment}: the reconstruction is byte-exact."));
                        }
                        None if guest.is_empty() => {
                            ui.weak("There is no guest hash to compare with.");
                        }
                        None => {
                            widgets::chip(ui, "differs from the guest's hash", Tone::Warn);
                            ui.weak("Step to the call just before a hash was taken, or use Go to the last hash.");
                        }
                    }
                }
                Err(Incomplete::SizeUnknown) => {
                    ui.weak("No hash: the file's size is not known.");
                }
                Err(Incomplete::Missing(count)) => {
                    ui.weak(format!("No hash: {count} bytes have no value (?? ## ~~)."));
                }
                Err(Incomplete::Unreadable) => {
                    ui.weak(
                        "No hash: some bytes could not be read back (the starting disk is gone).",
                    );
                }
            }
            if hashed.position != self.map.position() {
                ui.weak("(for an earlier position)");
            }
        }
    }

    fn actions(&mut self, ui: &mut egui::Ui, file: &FileActivity, directory: Option<&Path>) {
        ui.horizontal_wrapped(|ui| {
            let can = directory.is_some() && self.saving.is_none();
            let response = ui
                .add_enabled(can, egui::Button::new("Save reconstruction…"))
                .on_hover_text("Unknown bytes save as 00; a .mask file next to it marks them (00 known, 01 unknown, 02 not captured, 03 mapping)");
            if let (true, true, Some(directory)) = (can, response.clicked(), directory) {
                let target = directory.join("reconstructed");
                let name = save_name(&file.path, file.first_ns);
                let (ctx, map) = (ui.ctx().clone(), self.map.clone());
                self.saving = Some(Pending::spawn(&ctx, move || save(&map, &target, &name)));
            }
            if ui.button("Copy hex").on_hover_text("The byte map as hex, the first 256 KiB").clicked() {
                let text = hex_dump(&self.map, COPY_LIMIT);
                ui.ctx().copy_text(text);
            }
            let step = self.map.position().checked_sub(1).and_then(|at| self.map.steps().get(at));
            let event = step.and_then(|step| step.event).and_then(|event| file.events.get(event as usize));
            if ui
                .add_enabled(event.is_some(), egui::Button::new("Show call in Trace"))
                .on_hover_text("Open the original syscall of the chosen call")
                .clicked()
            {
                if let Some(event) = event {
                    let (stream, task, call) = event.key;
                    crate::triage::table::request_evidence_jump(
                        ui.ctx(),
                        &[
                            ("stream.id", crate::triage::RowValue::Number(i128::from(stream))),
                            ("process.cookie", crate::triage::RowValue::Number(i128::from(task))),
                            ("event.id", crate::triage::RowValue::Number(i128::from(call))),
                        ],
                    );
                }
            }
        });
        if directory.is_none() {
            ui.weak("Saving needs a recording on disk.");
        }
        if self.saving.is_some() {
            ui.weak("Saving…");
        }
        if let Some(status) = &self.status {
            ui.add(egui::Label::new(RichText::new(status).small()).wrap());
        }
    }
}

fn heading(ui: &mut egui::Ui, text: &str) {
    ui.add_space(8.0);
    ui.label(theme::section_title(ui, text));
}

fn short(state: State) -> &'static str {
    match state {
        State::Unknown => "unknown",
        State::Read => "read",
        State::Before => "before-image",
        State::Written => "written",
        State::NotCaptured(_) => "not captured",
        State::Mapping => "mapping",
    }
}

/// The colour a byte of `state` is drawn in.
pub(super) fn tint(ui: &egui::Ui, state: State) -> Color32 {
    match state {
        State::Unknown => theme::muted().gamma_multiply(0.7),
        State::Read => theme::info(),
        State::Before => theme::text(),
        State::Written => theme::good(),
        State::NotCaptured(_) => theme::warn(),
        State::Mapping if ui.visuals().dark_mode => Color32::from_rgb(196, 160, 255),
        State::Mapping => Color32::from_rgb(112, 64, 190),
    }
}

/// The strip of calls: one tick for each, coloured by what it did; a click
/// gives the position after that call.
fn strip(ui: &mut egui::Ui, steps: &[model::Step], at: usize) -> Option<usize> {
    if steps.is_empty() {
        return None;
    }
    let width = ui.available_width().max(60.0);
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(width, 16.0), egui::Sense::click_and_drag());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, ui.visuals().faint_bg_color);
    let columns = (rect.width() as usize).max(1);
    for column in 0..columns {
        let (from, to) = (
            column * steps.len() / columns,
            ((column + 1) * steps.len() / columns).max(column * steps.len() / columns + 1),
        );
        let color = steps[from..to.min(steps.len())]
            .iter()
            .map(|step| step_color(ui, step))
            .max_by_key(|(rank, _)| *rank)
            .map_or(theme::muted(), |(_, color)| color);
        let x = rect.left() + column as f32;
        painter.rect_filled(
            egui::Rect::from_min_max(
                egui::pos2(x, rect.top() + 3.0),
                egui::pos2(x + 1.0, rect.bottom() - 3.0),
            ),
            0.0,
            if to <= at {
                color
            } else {
                color.gamma_multiply(0.35)
            },
        );
    }
    let x = rect.left() + rect.width() * at as f32 / steps.len() as f32;
    painter.line_segment(
        [egui::pos2(x, rect.top()), egui::pos2(x, rect.bottom())],
        egui::Stroke::new(2.0_f32, theme::primary()),
    );
    response
        .on_hover_text("Click to jump to a call")
        .interact_pointer_pos()
        .map(|pos| {
            (((pos.x - rect.left()) / rect.width() * steps.len() as f32).round() as usize)
                .clamp(0, steps.len())
        })
        .filter(|clicked| *clicked != at)
}

fn step_color(ui: &egui::Ui, step: &model::Step) -> (u8, Color32) {
    match &step.action {
        Action::Write(extents)
            if extents.iter().any(|e| {
                matches!(
                    e.piece,
                    antinomie_monitor_core::file_writes::Piece::NotCaptured(_)
                )
            }) =>
        {
            (
                4,
                tint(
                    ui,
                    State::NotCaptured(antinomie_monitor_core::file_writes::Gap::NotRecorded),
                ),
            )
        }
        Action::Write(_) | Action::Zero { .. } => (3, tint(ui, State::Written)),
        Action::Mapping { .. } => (5, tint(ui, State::Mapping)),
        Action::Changed { .. } => (
            4,
            tint(
                ui,
                State::NotCaptured(antinomie_monitor_core::file_writes::Gap::NotRecorded),
            ),
        ),
        Action::Resize(_) => (2, theme::heading()),
        Action::Read(_) => (1, tint(ui, State::Read)),
    }
}

/// The line under the controls: the call the map shows the file after.
fn describe(
    map: &Reconstruction,
    at: usize,
    activity: &Activity,
    file: &FileActivity,
    clock: Option<antinomie_monitor_core::HostClockAnchor>,
) -> String {
    let Some(step) = at.checked_sub(1).and_then(|at| map.steps().get(at)) else {
        return "Start of the run: the file as it was, before any call.".into();
    };
    let call = step
        .event
        .and_then(|event| file.events.get(event as usize))
        .map(|event| {
            format!(
                "{} by {}",
                event.operation,
                activity.process_label(event.process)
            )
        })
        .unwrap_or_else(|| "a call not listed in the history".into());
    let range = |extents: &[antinomie_monitor_core::file_writes::Extent]| {
        let total: u64 = extents.iter().map(|extent| extent.len).sum();
        let first = extents.first().map_or(0, |extent| extent.offset);
        format!("{total} B at 0x{first:x}")
    };
    let what = match &step.action {
        Action::Read(extents) => format!("read {}", range(extents)),
        Action::Write(extents) => format!("wrote {}", range(extents)),
        Action::Resize(to) => format!("resized the file to {to} B"),
        Action::Zero { offset, len } => format!("zeroed {len} B at 0x{offset:x}"),
        Action::Changed { offset, len } if *len == u64::MAX => {
            format!("changed the bytes from 0x{offset:x} on (not seen)")
        }
        Action::Changed { offset, len } => format!("changed {len} B at 0x{offset:x} (not seen)"),
        Action::Mapping { .. } => "a shared writable mapping covers the file".to_owned(),
    };
    format!(
        "{} · {call} · {what}",
        crate::time_format::guest_ns(clock, Some(step.time_ns))
    )
}

/// `file name` made safe for one path component.
pub(super) fn save_name(path: &str, first_ns: u64) -> String {
    let name: String = path
        .trim_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                c
            } else {
                '_'
            }
        })
        .take(100)
        .collect();
    format!(
        "{}-{first_ns}",
        if name.is_empty() { "file".into() } else { name }
    )
}

/// Write the reconstruction and its mask into `directory`.
fn save(map: &Reconstruction, directory: &Path, name: &str) -> Result<String, String> {
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("Could not create {}: {error}", directory.display()))?;
    let (data, mask): (PathBuf, PathBuf) = (
        directory.join(format!("{name}.bin")),
        directory.join(format!("{name}.mask")),
    );
    let open = |path: &Path| {
        std::fs::File::create(path)
            .map(std::io::BufWriter::new)
            .map_err(|error| format!("Could not write {}: {error}", path.display()))
    };
    let (mut data_out, mut mask_out) = (open(&data)?, open(&mask)?);
    let saved = map
        .save(&mut data_out, Some(&mut mask_out))
        .map_err(|error| format!("Could not write the reconstruction: {error}"))?;
    use std::io::Write;
    data_out
        .flush()
        .and(mask_out.flush())
        .map_err(|error| format!("Could not write the reconstruction: {error}"))?;
    Ok(format!(
        "Saved {} B to {} and the mask to {}; {} B were filled with 00.{}",
        saved.bytes,
        data.display(),
        mask.display(),
        saved.filled,
        if saved.unreadable > 0 {
            format!(
                " {} of them could not be read from the starting disk.",
                saved.unreadable
            )
        } else {
            String::new()
        }
    ))
}

/// The byte map as text: offset, 16 bytes in hex (`??`, `##`, `~~` where there is
/// no value), up to `limit` bytes.
pub(super) fn hex_dump(map: &Reconstruction, limit: u64) -> String {
    let mut out = String::new();
    let end = map.size().min(limit);
    let mut at = 0;
    while at < end {
        let cells = map.row(at, ROW.min((end - at) as usize));
        let hex: Vec<String> = cells
            .iter()
            .map(|cell| match (cell.state.glyph(), cell.byte) {
                (Some(glyph), _) => glyph.to_owned(),
                (None, Some(byte)) => format!("{byte:02x}"),
                (None, None) => "!!".into(),
            })
            .collect();
        out.push_str(&format!("{at:08x}  {}\n", hex.join(" ")));
        at += ROW as u64;
    }
    out
}

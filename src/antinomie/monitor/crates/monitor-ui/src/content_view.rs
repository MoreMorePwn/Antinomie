// SPDX-License-Identifier: GPL-3.0-only
//! The Content window: the bytes of a RAM dump or of one mapping of a process
//! core as a hex dump or as raw text, one page at a time. A page is read on a
//! worker thread when it is wanted, so a multi-gigabyte dump is never loaded;
//! the Strings and Regex sub-windows (`scan_pane`) search the whole source
//! only when asked, and each hit jumps this view to its offset.
use crate::hex_view::{self, Cell};
use antinomie_monitor_core::content_scan::{self, ByteSource};
use eframe::egui::{self, RichText};
use std::{
    io,
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
    time::Duration,
};

mod scan_pane;

use scan_pane::ScanPane;

/// Octets per page read; 1024 hex rows.
pub(crate) const PAGE_SIZE: u64 = 16 * 1024;
/// Octets of one raw-text row before it wraps.
const TEXT_ROW_LEN: usize = 128;
/// Most octets one copy takes.
const COPY_MAX_SIZE: u64 = 1 << 20;

/// What the view shows: the readable bytes and how to name their places.
#[derive(Clone)]
pub(crate) struct ContentSource {
    /// Identity of the data; a new key resets the view.
    pub key: String,
    pub source: Arc<dyn ByteSource>,
    /// Address shown for offset 0 (a mapping's virtual start, else 0).
    pub address_base: u64,
    /// Offset in the file of offset 0, for the hover text of a core.
    pub file_base: Option<u64>,
    /// "Offset" for a dump, "Address" for a core.
    pub address_name: &'static str,
}

impl ContentSource {
    pub(super) fn size(&self) -> u64 {
        self.source.size()
    }

    /// The text of `offset` as shown: the address in hex.
    pub(super) fn place(&self, offset: u64) -> String {
        format!("0x{:x}", self.address_base.saturating_add(offset))
    }

    /// Where `offset` lies in the file, for a hover.
    pub(super) fn hover(&self, offset: u64) -> String {
        match self.file_base {
            Some(base) => format!(
                "{} 0x{:x} · file offset 0x{:x}",
                self.address_name,
                self.address_base.saturating_add(offset),
                base.saturating_add(offset)
            ),
            None => format!("{} 0x{offset:x}", self.address_name),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
enum Mode {
    #[default]
    Hex,
    Text,
}

/// One loaded page and the row layout of it.
struct Page {
    start: u64,
    data: Vec<u8>,
    /// Raw-text rows as (first octet, length) in `data`.
    lines: Vec<(usize, usize)>,
}

impl Page {
    fn new(start: u64, data: Vec<u8>) -> Self {
        let mut lines = Vec::new();
        let mut first = 0;
        while first < data.len() {
            let mut end = first;
            while end < data.len() && end - first < TEXT_ROW_LEN && data[end] != b'\n' {
                end += 1;
            }
            // A newline ends its row and belongs to it.
            if end < data.len() && data[end] == b'\n' {
                end += 1;
            }
            lines.push((first, end - first));
            first = end;
        }
        Self { start, data, lines }
    }

    /// Row `index` as (offset in the source, length).
    fn row(&self, mode: Mode, index: usize) -> (u64, usize) {
        match mode {
            Mode::Hex => {
                let first = index * 16;
                (self.start + first as u64, (self.data.len() - first).min(16))
            }
            Mode::Text => {
                let (first, len) = self.lines[index];
                (self.start + first as u64, len)
            }
        }
    }

    fn row_count(&self, mode: Mode) -> usize {
        match mode {
            Mode::Hex => self.data.len().div_ceil(16),
            Mode::Text => self.lines.len(),
        }
    }

    /// The row holding `offset`.
    fn row_of(&self, mode: Mode, offset: u64) -> usize {
        let at = offset.saturating_sub(self.start) as usize;
        match mode {
            Mode::Hex => at / 16,
            Mode::Text => self
                .lines
                .partition_point(|(first, _)| *first <= at)
                .saturating_sub(1),
        }
    }
}

struct Loading {
    start: u64,
    receiver: Receiver<io::Result<Vec<u8>>>,
}

pub(crate) struct ContentView {
    /// Distinguishes this view's widget ids from another panel's.
    salt: &'static str,
    key: String,
    mode: Mode,
    page_start: u64,
    page: Option<Page>,
    loading: Option<Loading>,
    error: Option<String>,
    goto: String,
    goto_error: Option<String>,
    /// A jump waiting for its page: (offset, length).
    focus: Option<(u64, u64)>,
    highlight: Option<(u64, u64)>,
    /// Selected rows as (first row offset, last row offset).
    selection: Option<(u64, u64)>,
    /// The distance between two rows as drawn last frame; a jump scrolls by it.
    pitch: Option<f32>,
    strings: ScanPane,
    regex: ScanPane,
}

/// The view the process-core panel owns.
impl Default for ContentView {
    fn default() -> Self {
        Self::new("core")
    }
}

impl Drop for ContentView {
    fn drop(&mut self) {
        self.strings.cancel();
        self.regex.cancel();
    }
}

impl ContentView {
    pub(crate) fn new(salt: &'static str) -> Self {
        Self {
            salt,
            key: String::new(),
            mode: Mode::default(),
            page_start: 0,
            page: None,
            loading: None,
            error: None,
            goto: String::new(),
            goto_error: None,
            focus: None,
            highlight: None,
            selection: None,
            pitch: None,
            strings: ScanPane::new(scan_pane::Kind::Strings),
            regex: ScanPane::new(scan_pane::Kind::Regex),
        }
    }

    /// Forget the data shown and stop any search.
    fn reset(&mut self, key: &str) {
        let (salt, mode) = (self.salt, self.mode);
        self.strings.cancel();
        self.regex.cancel();
        *self = Self::new(salt);
        self.mode = mode;
        self.key = key.to_owned();
    }

    /// The searches under way, for the Jobs window.
    pub(crate) fn running_jobs(
        &self,
        target: &str,
        panel: crate::workspace::Panel,
    ) -> Vec<crate::jobs::Job> {
        [&self.strings, &self.regex]
            .into_iter()
            .filter_map(|pane| pane.job(self.salt, target))
            .map(|job| job.open(panel.clone()))
            .collect()
    }

    /// Show the page containing `offset` and mark `len` octets from it.
    pub(crate) fn jump(&mut self, offset: u64, len: u64) {
        self.page_start = offset / PAGE_SIZE * PAGE_SIZE;
        self.focus = Some((offset, len.max(1)));
        self.highlight = Some((offset, len.max(1)));
        self.selection = None;
    }

    fn poll(&mut self, ctx: &egui::Context, source: &ContentSource) {
        if let Some(loading) = &self.loading {
            match loading.receiver.try_recv() {
                Ok(Ok(data)) => {
                    let start = loading.start;
                    self.loading = None;
                    self.error = None;
                    if start == self.page_start {
                        self.page = Some(Page::new(start, data));
                    }
                }
                Ok(Err(error)) => {
                    self.loading = None;
                    self.error = Some(error.to_string());
                    self.page = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.loading = None;
                    self.error = Some("the page reader stopped unexpectedly".into());
                }
                Err(mpsc::TryRecvError::Empty) => {
                    ctx.request_repaint_after(Duration::from_millis(50));
                }
            }
        }
        let wanted = self.page_start;
        let have = self.page.as_ref().is_some_and(|page| page.start == wanted);
        let fetching = self.loading.as_ref().is_some_and(|l| l.start == wanted);
        if !have && !fetching && self.error.is_none() && source.size() > 0 {
            let (sender, receiver) = mpsc::sync_channel(1);
            let reader = Arc::clone(&source.source);
            let spawned = std::thread::Builder::new()
                .name("content-page".into())
                .spawn(move || {
                    let _ = sender.send(content_scan::read_page(
                        &*reader,
                        wanted,
                        PAGE_SIZE as usize,
                    ));
                });
            match spawned {
                Ok(_) => {
                    self.loading = Some(Loading {
                        start: wanted,
                        receiver,
                    })
                }
                Err(error) => self.error = Some(error.to_string()),
            }
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    pub(crate) fn show(&mut self, ui: &mut egui::Ui, source: &ContentSource) {
        if self.key != source.key {
            self.reset(&source.key);
        }
        self.poll(ui.ctx(), source);
        let size = source.size();
        self.toolbar(ui, source);
        if size == 0 {
            ui.colored_label(crate::theme::muted(), "Nothing was captured here.");
        } else if let Some(error) = &self.error {
            let error = error.clone();
            crate::activity::error(ui, &error);
            if ui.button("Try again").clicked() {
                self.error = None;
            }
        } else {
            self.rows(ui, source);
        }
        let ctx = ui.ctx().clone();
        let jumps = [
            self.strings.window(&ctx, self.salt, source),
            self.regex.window(&ctx, self.salt, source),
        ];
        if let Some((offset, len)) = jumps.into_iter().flatten().next() {
            self.jump(offset, len);
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, source: &ContentSource) {
        let size = source.size();
        let last_page = size.saturating_sub(1) / PAGE_SIZE * PAGE_SIZE;
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(&mut self.mode, Mode::Hex, "Hex")
                .on_hover_text("Sixteen octets a row, as hex and as characters");
            ui.selectable_value(&mut self.mode, Mode::Text, "Text")
                .on_hover_text(
                    "The octets as raw text; a byte that is not printable shows as a dot",
                );
            ui.separator();
            let go = egui::TextEdit::singleline(&mut self.goto)
                .hint_text(crate::theme::placeholder(
                    ui,
                    format!("{} (hex)", source.address_name),
                ))
                .desired_width(crate::theme::plain_edit_width(150.0))
                .id(egui::Id::new((self.salt, "content-goto")));
            let entered = ui.add(go);
            let pressed = entered.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("Go to").clicked() || pressed {
                match parse_hex(&self.goto)
                    .and_then(|typed| typed.checked_sub(source.address_base))
                    .filter(|offset| *offset < size)
                {
                    Some(offset) => {
                        self.goto_error = None;
                        self.jump(offset, 1);
                    }
                    None => {
                        self.goto_error = Some(format!(
                            "{} must be hex, between {} and {}.",
                            source.address_name,
                            source.place(0),
                            source.place(size.saturating_sub(1))
                        ))
                    }
                }
            }
            ui.separator();
            if ui
                .add_enabled(self.page_start > 0, egui::Button::new("Start"))
                .clicked()
            {
                self.page_start = 0;
            }
            if ui
                .add_enabled(self.page_start > 0, egui::Button::new("Page up"))
                .clicked()
            {
                self.page_start = self.page_start.saturating_sub(PAGE_SIZE);
            }
            if ui
                .add_enabled(self.page_start < last_page, egui::Button::new("Page down"))
                .clicked()
            {
                self.page_start = (self.page_start + PAGE_SIZE).min(last_page);
            }
            if ui
                .add_enabled(self.page_start < last_page, egui::Button::new("End"))
                .clicked()
            {
                self.page_start = last_page;
            }
            ui.separator();
            let open_strings = ui
                .selectable_label(self.strings.open(), "Strings…")
                .on_hover_text("Search for printable strings; runs only when you press Search");
            if open_strings.clicked() {
                self.strings.toggle();
            }
            let open_regex = ui
                .selectable_label(self.regex.open(), "Regex…")
                .on_hover_text("Search for a regular expression; runs only when you press Search");
            if open_regex.clicked() {
                self.regex.toggle();
            }
        });
        if let Some(error) = &self.goto_error {
            crate::activity::inline_only(ui, crate::activity::Level::Warn, error);
        }
        ui.horizontal_wrapped(|ui| {
            let first = self.page_start.min(size);
            let end = (self.page_start + PAGE_SIZE).min(size);
            ui.colored_label(
                crate::theme::muted(),
                format!(
                    "{} {}–{} of {} · {}",
                    source.address_name,
                    source.place(first),
                    source.place(end.saturating_sub(1).max(first)),
                    crate::values::file_size(size),
                    if self.mode == Mode::Hex {
                        "hex"
                    } else {
                        "text"
                    }
                ),
            );
            self.copy_buttons(ui, source);
        });
    }

    fn copy_buttons(&mut self, ui: &mut egui::Ui, source: &ContentSource) {
        let Some(page) = &self.page else {
            return;
        };
        let Some((from, to)) = self.selection else {
            return;
        };
        let (from, to) = (from.min(to), from.max(to));
        let (_, last_len) = page.row(
            self.mode,
            page.row_of(self.mode, to)
                .min(page.row_count(self.mode) - 1),
        );
        let end = (to + last_len as u64).min(page.start + page.data.len() as u64);
        let end = end.min(from.saturating_add(COPY_MAX_SIZE));
        if from < page.start || from >= end {
            return;
        }
        let bytes = &page.data[(from - page.start) as usize..(end - page.start) as usize];
        ui.colored_label(
            crate::theme::muted(),
            format!("{} selected", crate::values::file_size(bytes.len() as u64)),
        );
        if ui.button("Copy hex").clicked() {
            ui.ctx().copy_text(
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<Vec<_>>()
                    .join(" "),
            );
        }
        if ui.button("Copy text").clicked() {
            ui.ctx().copy_text(
                bytes
                    .iter()
                    .map(|byte| printable(*byte, true))
                    .collect::<String>(),
            );
        }
        if ui.button("Copy address").clicked() {
            ui.ctx().copy_text(source.place(from));
        }
    }

    fn rows(&mut self, ui: &mut egui::Ui, source: &ContentSource) {
        let Some(page) = self.page.as_ref().filter(|p| p.start == self.page_start) else {
            crate::theme::loading(ui, "Reading the page…");
            return;
        };
        let mode = self.mode;
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let row_height = self.pitch.unwrap_or_else(|| {
            ui.fonts_mut(|fonts| fonts.row_height(&font)) + ui.spacing().item_spacing.y
        });
        let count = page.row_count(mode);
        let mut area = egui::ScrollArea::both()
            .id_salt((self.salt, "content-rows", mode as u8, page.start))
            .auto_shrink([false, false]);
        // The first frame only measures the rows; a jump waits for that.
        let ready = self.pitch.is_some();
        if let Some((offset, _)) = self.focus.filter(|_| ready) {
            self.focus = None;
            let row = page.row_of(mode, offset).saturating_sub(3);
            area = area.vertical_scroll_offset(row as f32 * row_height);
        }
        let mut measured = None;
        let (mut clicked, shift) = (None, ui.input(|i| i.modifiers.shift));
        let (selection, highlight) = (self.selection, self.highlight);
        area.show_rows(ui, row_height, count, |ui, range| {
            for index in range {
                let (offset, len) = page.row(mode, index);
                let text = match mode {
                    Mode::Hex => hex_view::row_text(source.address_base + offset, |at| {
                        let at = at - source.address_base - page.start;
                        page.data
                            .get(at as usize)
                            .map_or(Cell::Outside, |byte| Cell::Byte(*byte))
                    }),
                    Mode::Text => {
                        let (first, _) = page.lines[index];
                        let line = &page.data[first..first + len];
                        let shown: String = line
                            .iter()
                            .filter(|byte| **byte != b'\n')
                            .map(|byte| printable(*byte, false))
                            .collect();
                        format!("{:>10x}  {shown}", source.address_base + offset)
                    }
                };
                let end = offset + len as u64;
                let marked = highlight.is_some_and(|(at, n)| offset < at + n && at < end);
                let chosen =
                    selection.is_some_and(|(a, b)| offset >= a.min(b) && offset <= a.max(b));
                let fill = if chosen {
                    ui.visuals().selection.bg_fill
                } else if marked {
                    crate::theme::raised()
                } else {
                    egui::Color32::TRANSPARENT
                };
                let inner = egui::Frame::new().fill(fill).show(ui, |ui| {
                    ui.add(
                        egui::Label::new(RichText::new(text).monospace())
                            .extend()
                            .selectable(false),
                    )
                });
                measured = Some(inner.response.rect.height() + ui.spacing().item_spacing.y);
                let response = ui
                    .interact(
                        inner.response.rect,
                        ui.id().with(("content-row", offset)),
                        egui::Sense::click(),
                    )
                    .on_hover_text(source.hover(offset));
                if response.clicked() {
                    clicked = Some(offset);
                }
            }
        });
        if let Some(pitch) = measured {
            if self.pitch.is_none_or(|known| (known - pitch).abs() > 0.01) {
                self.pitch = Some(pitch);
                ui.ctx().request_repaint();
            }
        }
        if let Some(offset) = clicked {
            self.selection = match (self.selection, shift) {
                (Some((anchor, _)), true) => Some((anchor, offset)),
                _ => Some((offset, offset)),
            };
        }
    }
}

/// How an octet reads in text: printable ASCII as itself, a tab or newline as
/// itself when `keep_space`, anything else as a dot.
fn printable(byte: u8, keep_space: bool) -> char {
    match byte {
        b' '..=b'~' => char::from(byte),
        b'\n' | b'\t' if keep_space => char::from(byte),
        _ => '.',
    }
}

/// A hex number, with or without `0x`.
pub(crate) fn parse_hex(text: &str) -> Option<u64> {
    let text = text.trim().replace('_', "");
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(&text);
    u64::from_str_radix(digits, 16).ok()
}

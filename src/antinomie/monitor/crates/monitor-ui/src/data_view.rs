//! Captured data in common text forms (UTF-8, hexdump, C array, Base64, ...),
//! the windows that show a field's whole capture, and the copy menus of
//! numeric values.
use crate::{theme, trace};
use antinomie_monitor_core::{recording, FieldSummary};
use eframe::egui::{self, RichText};
use std::{
    fmt::Write as _,
    ops::Range,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

/// Most captured bytes one data window loads.
pub(crate) const DATA_WINDOW_CAP: u64 = 16 * 1024 * 1024;
/// The archive hands out at most this many captured bytes per read.
const READ_CHUNK: u64 = 65536;
/// Open data windows; opening another closes the oldest.
const DATA_WINDOW_LIMIT: usize = 8;
/// Longest displayed row; a longer line continues on the next row.
const ROW_CHARS: usize = 160;
/// Longest value a copy menu row shows before eliding it.
const MENU_VALUE_CHARS: usize = 40;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DataFormat {
    #[default]
    Utf8,
    Ascii,
    Hex,
    Hexdump,
    CArray,
    Base64,
    Decimal,
    Escaped,
    HexEscaped,
}

impl DataFormat {
    pub(crate) const ALL: [Self; 9] = [
        Self::Utf8,
        Self::Ascii,
        Self::Hex,
        Self::Hexdump,
        Self::CArray,
        Self::Base64,
        Self::Decimal,
        Self::Escaped,
        Self::HexEscaped,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Utf8 => "UTF-8",
            Self::Ascii => "ASCII",
            Self::Hex => "Hex",
            Self::Hexdump => "Hexdump",
            Self::CArray => "C array",
            Self::Base64 => "Base64",
            Self::Decimal => "Decimal bytes",
            Self::Escaped => "Escaped string",
            Self::HexEscaped => "\\x escaped bytes",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Self::Utf8 => "Text; invalid UTF-8 sequences show as \u{FFFD}",
            Self::Ascii => "Printable ASCII; other bytes show as '.', line breaks are kept",
            Self::Hex => "Two hex digits per byte, separated by spaces",
            Self::Hexdump => "Offset, 16 bytes in hex and their ASCII, like hexdump -C",
            Self::CArray => "An unsigned char array initializer",
            Self::Base64 => "Standard Base64 with padding",
            Self::Decimal => "Each byte as a decimal number",
            Self::Escaped => "A quoted string with \\n, \\t, \\\\, \\\" and \\x.. escapes",
            Self::HexEscaped => "Every byte as \\x.., as in shellcode",
        }
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut String, byte: u8) {
    out.push(char::from(HEX[usize::from(byte >> 4)]));
    out.push(char::from(HEX[usize::from(byte & 15)]));
}

fn printable(byte: u8) -> bool {
    (0x20..0x7f).contains(&byte)
}

/// `data` in `format`; `base` is the offset of its first byte (hexdump only).
pub(crate) fn format_bytes(format: DataFormat, data: &[u8], base: u64) -> String {
    match format {
        DataFormat::Utf8 => String::from_utf8_lossy(data).into_owned(),
        DataFormat::Ascii => data
            .iter()
            .map(|&byte| {
                if printable(byte) || byte == b'\n' {
                    char::from(byte)
                } else {
                    '.'
                }
            })
            .collect(),
        DataFormat::Hex => {
            let mut out = String::with_capacity(data.len() * 3);
            for (index, &byte) in data.iter().enumerate() {
                if index > 0 {
                    out.push(' ');
                }
                push_hex(&mut out, byte);
            }
            out
        }
        DataFormat::Hexdump => hexdump(data, base),
        DataFormat::CArray => c_array(data),
        DataFormat::Base64 => base64(data),
        DataFormat::Decimal => {
            let mut out = String::with_capacity(data.len() * 4);
            for (index, byte) in data.iter().enumerate() {
                if index > 0 {
                    out.push(' ');
                }
                let _ = write!(out, "{byte}");
            }
            out
        }
        DataFormat::Escaped => escaped(data),
        DataFormat::HexEscaped => {
            let mut out = String::with_capacity(data.len() * 4);
            for &byte in data {
                out.push_str("\\x");
                push_hex(&mut out, byte);
            }
            out
        }
    }
}

fn hexdump(data: &[u8], base: u64) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(16) * 79 + 8);
    for (line, chunk) in data.chunks(16).enumerate() {
        let _ = write!(out, "{:08x}  ", base.wrapping_add(line as u64 * 16));
        for column in 0..16 {
            match chunk.get(column) {
                Some(&byte) => {
                    push_hex(&mut out, byte);
                    out.push(' ');
                }
                None => out.push_str("   "),
            }
            if column == 7 {
                out.push(' ');
            }
        }
        out.push_str(" |");
        for &byte in chunk {
            out.push(if printable(byte) {
                char::from(byte)
            } else {
                '.'
            });
        }
        out.push_str("|\n");
    }
    let _ = write!(out, "{:08x}", base.wrapping_add(data.len() as u64));
    out
}

fn c_array(data: &[u8]) -> String {
    let mut out = format!("unsigned char data[{}] = {{", data.len());
    for (index, &byte) in data.iter().enumerate() {
        out.push_str(if index % 12 == 0 { "\n    " } else { " " });
        out.push_str("0x");
        push_hex(&mut out, byte);
        if index + 1 < data.len() {
            out.push(',');
        }
    }
    out.push_str(if data.is_empty() { "};" } else { "\n};" });
    out
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(
                    ALPHABET[((bits >> (18 - 6 * index)) & 63) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn escaped(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() + 2);
    out.push('"');
    for &byte in data {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            byte if printable(byte) => out.push(char::from(byte)),
            byte => {
                out.push_str("\\x");
                push_hex(&mut out, byte);
            }
        }
    }
    out.push('"');
    out
}

/// Captured segments (offset, bytes) in `format`; a range that was not
/// captured is named on its own line rather than silently joined over.
pub(crate) fn format_segments(format: DataFormat, segments: &[(u64, Vec<u8>)]) -> String {
    if let [(0, data)] = segments {
        return format_bytes(format, data, 0);
    }
    let mut out = String::new();
    let mut end = 0u64;
    for (offset, data) in segments {
        if *offset > end {
            if !out.is_empty() {
                out.push('\n');
            }
            let _ = write!(out, "[{end:#x}..{offset:#x} not captured]");
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(&format_bytes(format, data, *offset));
        end = offset.saturating_add(data.len() as u64);
    }
    out
}

/// Display rows of `text`: its lines, each cut into rows of at most
/// [`ROW_CHARS`] characters.
fn rows(text: &str) -> Vec<Range<usize>> {
    let mut rows = Vec::new();
    let mut start = 0;
    for line in text.split('\n') {
        let mut row = 0;
        for (count, (index, _)) in line.char_indices().enumerate() {
            if count > 0 && count % ROW_CHARS == 0 {
                rows.push(start + row..start + index);
                row = index;
            }
        }
        rows.push(start + row..start + line.len());
        start += line.len() + 1;
    }
    rows
}

/// The screen form of one display row. The monospace font has no glyph for
/// U+FFFD or control characters, so invalid UTF-8 shows as a warning-colored
/// box and control characters as a muted dot; copying keeps the real text.
fn display_row(row: &str, font: &egui::FontId) -> egui::text::LayoutJob {
    let format = |color| egui::TextFormat {
        font_id: font.clone(),
        color,
        ..Default::default()
    };
    let mut job = egui::text::LayoutJob::default();
    let mut start = 0;
    for (index, character) in row.char_indices() {
        let stand_in = match character {
            '\u{FFFD}' => ("\u{25A1}", theme::WARN),
            '\t' => ("    ", theme::TEXT),
            character if character.is_control() => ("\u{B7}", theme::MUTED),
            _ => continue,
        };
        if start < index {
            job.append(&row[start..index], 0.0, format(theme::TEXT));
        }
        job.append(stand_in.0, 0.0, format(stand_in.1));
        start = index + character.len_utf8();
    }
    if start < row.len() || row.is_empty() {
        job.append(&row[start..], 0.0, format(theme::TEXT));
    }
    job
}

/// A numeric value in the forms a copy menu offers, labelled.
pub(crate) fn number_items(value: u64, width: usize, shown: &str) -> Vec<(String, String)> {
    let width = width.clamp(1, 8);
    let bits = width * 8;
    let value = if bits == 64 {
        value
    } else {
        value & ((1u64 << bits) - 1)
    };
    let signed = ((value << (64 - bits)) as i64) >> (64 - bits);
    let mut items = Vec::new();
    if !shown.is_empty() {
        items.push(("As shown".to_owned(), shown.to_owned()));
    }
    items.push(("Decimal".to_owned(), value.to_string()));
    if signed < 0 {
        items.push(("Signed decimal".to_owned(), signed.to_string()));
    }
    items.push(("Hex".to_owned(), format!("{value:#x}")));
    items.push((
        format!("Hex, {width} byte{}", if width == 1 { "" } else { "s" }),
        format!("0x{value:0digits$x}", digits = width * 2),
    ));
    items.push(("Octal".to_owned(), format!("{value:#o}")));
    items.push(("Binary".to_owned(), format!("{value:#b}")));
    if width > 1 {
        items.push((
            "Bytes, little endian".to_owned(),
            format_bytes(DataFormat::Hex, &value.to_le_bytes()[..width], 0),
        ));
    }
    items
}

fn elide(value: &str) -> String {
    let line = value.lines().next().unwrap_or_default();
    if line.len() == value.len() && value.chars().count() <= MENU_VALUE_CHARS {
        return value.to_owned();
    }
    let mut short: String = line.chars().take(MENU_VALUE_CHARS - 1).collect();
    short.push('…');
    short
}

/// Rows of a context menu that each copy one labelled value.
pub(crate) fn copy_items(ui: &mut egui::Ui, items: &[(String, String)]) {
    ui.label(RichText::new("Copy").color(theme::MUTED));
    for (label, value) in items {
        if ui
            .add(egui::Button::new(label.as_str()).shortcut_text(elide(value)))
            .on_hover_text(format!("Copy {}", label.to_lowercase()))
            .clicked()
        {
            ui.ctx().copy_text(value.clone());
            ui.close_menu();
        }
    }
}

/// A right-click menu copying a numeric value as shown, in decimal, hex,
/// octal, binary and its bytes; `extra` rows come first.
pub(crate) fn number_menu(
    response: &egui::Response,
    value: u64,
    width: usize,
    shown: &str,
    extra: &[(&str, &str)],
) {
    response.context_menu(|ui| {
        let mut items: Vec<_> = extra
            .iter()
            .map(|(label, value)| ((*label).to_owned(), (*value).to_owned()))
            .collect();
        items.extend(number_items(value, width, shown));
        copy_items(ui, &items);
    });
}

/// A request to show a captured field's whole data in its own window.
#[derive(Clone, Debug)]
pub(crate) struct OpenData {
    /// Identifies the field within its trace; one window per field.
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) field: FieldSummary,
}

struct Loaded {
    segments: Vec<(u64, Vec<u8>)>,
    truncated: bool,
}

struct Loader {
    receiver: mpsc::Receiver<Result<Loaded, String>>,
    progress: Arc<AtomicU64>,
    total: u64,
    cancelled: Arc<AtomicBool>,
}

impl Drop for Loader {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

/// The captured ranges to read, sorted and merged, keeping at most `cap`
/// bytes; true when that left some out.
fn plan(field: &FieldSummary, cap: u64) -> (Vec<(u64, u64)>, bool) {
    let mut ranges: Vec<_> = field
        .ranges
        .iter()
        .copied()
        .filter(|(_, len)| *len > 0)
        .collect();
    ranges.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (offset, len) in ranges {
        let end = offset.saturating_add(len);
        if let Some(last) = merged.last_mut() {
            let last_end = last.0.saturating_add(last.1);
            if offset <= last_end {
                last.1 = last_end.max(end) - last.0;
                continue;
            }
        }
        merged.push((offset, len));
    }
    let mut kept = Vec::new();
    let mut total = 0u64;
    for (offset, len) in merged {
        let take = len.min(cap - total);
        if take > 0 {
            kept.push((offset, take));
            total += take;
        }
        if take < len {
            return (kept, true);
        }
    }
    (kept, false)
}

fn spawn_loader(
    ctx: &egui::Context,
    directory: PathBuf,
    field: FieldSummary,
) -> Result<Loader, String> {
    let (ranges, truncated) = plan(&field, DATA_WINDOW_CAP);
    let total = ranges.iter().map(|(_, len)| len).sum();
    let (sender, receiver) = mpsc::channel();
    let progress = Arc::new(AtomicU64::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (worker_progress, worker_cancelled) = (Arc::clone(&progress), Arc::clone(&cancelled));
    let ctx = ctx.clone();
    thread::Builder::new()
        .name("data-window-reader".into())
        .spawn(move || {
            let mut segments = Vec::new();
            for (offset, len) in ranges {
                let end = offset + len;
                let mut data = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
                let mut at = offset;
                while at < end {
                    if worker_cancelled.load(Ordering::Relaxed) {
                        return;
                    }
                    let count = (end - at).min(READ_CHUNK) as usize;
                    match recording::read_captured_range(&directory, &field, at, count) {
                        Ok(chunk) => data.extend_from_slice(&chunk),
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string()));
                            ctx.request_repaint();
                            return;
                        }
                    }
                    at += count as u64;
                    worker_progress.fetch_add(count as u64, Ordering::Relaxed);
                }
                segments.push((offset, data));
            }
            let _ = sender.send(Ok(Loaded {
                segments,
                truncated,
            }));
            ctx.request_repaint();
        })
        .map_err(|error| error.to_string())?;
    Ok(Loader {
        receiver,
        progress,
        total,
        cancelled,
    })
}

struct Rendered {
    format: DataFormat,
    text: String,
    rows: Vec<Range<usize>>,
}

struct DataWindow {
    key: String,
    title: String,
    field: FieldSummary,
    loader: Option<Loader>,
    segments: Vec<(u64, Vec<u8>)>,
    truncated: bool,
    note: Option<String>,
    error: Option<String>,
    format: DataFormat,
    rendered: Option<Rendered>,
    open: bool,
}

impl DataWindow {
    fn new(
        ctx: &egui::Context,
        key: String,
        request: OpenData,
        directory: Option<PathBuf>,
    ) -> Self {
        let field = request.field;
        let preview = trace::covered_preview(&field).to_vec();
        let (ranges, _) = plan(&field, u64::MAX);
        let preview_covers = match ranges.as_slice() {
            [] => true,
            [(0, len)] => *len <= preview.len() as u64,
            _ => false,
        };
        let mut window = Self {
            key,
            title: request.title,
            loader: None,
            segments: if preview.is_empty() {
                Vec::new()
            } else {
                vec![(0, preview)]
            },
            truncated: false,
            note: None,
            error: None,
            format: DataFormat::default(),
            rendered: None,
            open: true,
            field,
        };
        if ranges.is_empty() {
            window.note = Some("No bytes of this object were captured.".into());
        } else if !preview_covers {
            match directory.filter(|_| window.field.raw_path.is_some()) {
                Some(directory) => match spawn_loader(ctx, directory, window.field.clone()) {
                    Ok(loader) => window.loader = Some(loader),
                    Err(error) => {
                        window.error = Some(format!("Could not read the capture: {error}"))
                    }
                },
                None => {
                    window.note = Some(format!(
                        "Showing the {}-byte preview kept with the trace; the full capture is not \
                         readable here.",
                        window.segments.first().map_or(0, |(_, data)| data.len())
                    ))
                }
            }
        }
        window
    }

    fn id(&self) -> egui::Id {
        egui::Id::new(("data-window", &self.key))
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(loader) = &self.loader else {
            return;
        };
        match loader.receiver.try_recv() {
            Ok(Ok(loaded)) => {
                self.segments = loaded.segments;
                self.truncated = loaded.truncated;
                self.rendered = None;
                self.loader = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!(
                    "Could not read the capture: {error}; showing the preview"
                ));
                self.loader = None;
            }
            Err(mpsc::TryRecvError::Empty) => ctx.request_repaint_after(Duration::from_millis(100)),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.error = Some("The capture reader stopped; showing the preview".into());
                self.loader = None;
            }
        }
    }

    fn loaded_len(&self) -> u64 {
        self.segments
            .iter()
            .map(|(_, data)| data.len() as u64)
            .sum()
    }

    fn rendered(&mut self) -> &Rendered {
        if self
            .rendered
            .as_ref()
            .is_none_or(|rendered| rendered.format != self.format)
        {
            let text = format_segments(self.format, &self.segments);
            self.rendered = Some(Rendered {
                format: self.format,
                rows: rows(&text),
                text,
            });
        }
        self.rendered.as_ref().expect("rendered above")
    }

    fn show(&mut self, ctx: &egui::Context) {
        self.poll(ctx);
        let mut open = self.open;
        egui::Window::new(self.title.as_str())
            .id(self.id())
            .open(&mut open)
            .default_size([860.0, 460.0])
            .resizable(true)
            .show(ctx, |ui| self.contents(ui));
        self.open = open;
    }

    fn contents(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.strong(&self.field.key);
            ui.label(trace::capture_summary(&self.field));
            if !self.field.layout.is_empty() {
                ui.label(RichText::new(&self.field.layout).color(theme::MUTED));
            }
        });
        if !self.field.complete {
            ui.colored_label(
                theme::WARN,
                format!("Partial capture: {}", trace::incomplete_reason(&self.field)),
            );
        }
        if let Some(loader) = &self.loader {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(format!(
                    "Loading captured bytes: {} of {}",
                    loader.progress.load(Ordering::Relaxed),
                    loader.total
                ));
            });
            return;
        }
        if self.truncated {
            ui.colored_label(
                theme::WARN,
                format!(
                    "Showing the first {} MiB ({} bytes) of {} captured bytes",
                    DATA_WINDOW_CAP / (1024 * 1024),
                    self.loaded_len(),
                    self.field.captured_len
                ),
            );
        }
        if self.segments.len() > 1 || self.segments.first().is_some_and(|(offset, _)| *offset > 0) {
            ui.colored_label(
                theme::MUTED,
                "Ranges that were not captured are marked in the text.",
            );
        }
        if let Some(note) = &self.note {
            ui.colored_label(theme::MUTED, note);
        }
        if let Some(error) = &self.error {
            ui.colored_label(theme::ERROR, error);
        }
        ui.horizontal_wrapped(|ui| {
            let label = ui.label("Format");
            egui::ComboBox::from_id_salt(("data-format", &self.key))
                .selected_text(self.format.label())
                .show_ui(ui, |ui| {
                    for format in DataFormat::ALL {
                        ui.selectable_value(&mut self.format, format, format.label())
                            .on_hover_text(format.hint());
                    }
                })
                .response
                .labelled_by(label.id)
                .on_hover_text(self.format.hint());
            if ui
                .button(format!("{} Copy", egui_phosphor::regular::COPY))
                .on_hover_text(format!("Copy as {}", self.format.label()))
                .clicked()
            {
                let text = self.rendered().text.clone();
                ui.ctx().copy_text(text);
            }
            ui.menu_button("Copy as", |ui| {
                for format in DataFormat::ALL {
                    if ui
                        .button(format.label())
                        .on_hover_text(format.hint())
                        .clicked()
                    {
                        let text = format_segments(format, &self.segments);
                        ui.ctx().copy_text(text);
                        ui.close_menu();
                    }
                }
            });
            ui.label(RichText::new(format!("{} bytes", self.loaded_len())).color(theme::MUTED));
        });
        if self.format == DataFormat::Utf8 {
            ui.label(
                RichText::new(
                    "\u{25A1} marks bytes that are not valid UTF-8, \u{B7} control characters",
                )
                .small()
                .color(theme::MUTED),
            );
        }
        ui.separator();
        if self.segments.is_empty() {
            ui.colored_label(theme::MUTED, "No captured bytes");
            return;
        }
        let font = egui::TextStyle::Monospace.resolve(ui.style());
        let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
        let rendered = self.rendered();
        egui::ScrollArea::both()
            .id_salt("data-window-text")
            .auto_shrink([false, false])
            .show_rows(ui, row_height, rendered.rows.len(), |ui, range| {
                for row in &rendered.rows[range] {
                    ui.add(
                        egui::Label::new(display_row(&rendered.text[row.clone()], &font)).extend(),
                    );
                }
            });
    }
}

/// The open data windows, one per captured field.
#[derive(Default)]
pub(crate) struct DataWindows {
    windows: Vec<DataWindow>,
}

impl DataWindows {
    /// Open a window for `request`, or raise the one already showing it.
    pub(crate) fn open(
        &mut self,
        ctx: &egui::Context,
        request: OpenData,
        directory: Option<PathBuf>,
    ) {
        let key = match &directory {
            Some(directory) => format!("{}|{}", directory.display(), request.key),
            None => request.key.clone(),
        };
        if let Some(window) = self.windows.iter().find(|window| window.key == key) {
            ctx.move_to_top(egui::LayerId::new(egui::Order::Middle, window.id()));
            return;
        }
        if self.windows.len() >= DATA_WINDOW_LIMIT {
            self.windows.remove(0);
        }
        self.windows
            .push(DataWindow::new(ctx, key, request, directory));
    }

    pub(crate) fn show(&mut self, ctx: &egui::Context) {
        for window in &mut self.windows {
            window.show(ctx);
        }
        self.windows.retain(|window| window.open);
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.windows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(data: &[u8]) -> FieldSummary {
        FieldSummary {
            object_id: 7,
            key: "buf".into(),
            layout: String::new(),
            logical_len: Some(data.len() as u64),
            captured_len: data.len() as u64,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: data[..data.len().min(256)].to_vec(),
            raw_path: None,
            ranges: vec![(0, data.len() as u64)],
        }
    }

    #[test]
    fn hexdump_matches_hexdump_canonical_layout() {
        assert_eq!(
            format_bytes(DataFormat::Hexdump, b"Hello world\n\x00\x01\x02\x03XYZ", 0),
            "00000000  48 65 6c 6c 6f 20 77 6f  72 6c 64 0a 00 01 02 03  |Hello world.....|\n\
             00000010  58 59 5a                                          |XYZ|\n\
             00000013"
        );
        assert_eq!(
            format_bytes(DataFormat::Hexdump, b"abc", 0x20),
            "00000020  61 62 63                                          |abc|\n00000023"
        );
        assert_eq!(format_bytes(DataFormat::Hexdump, b"", 0), "00000000");
    }

    #[test]
    fn c_array_wraps_twelve_bytes_per_line() {
        assert_eq!(
            format_bytes(DataFormat::CArray, b"ab\x00", 0),
            "unsigned char data[3] = {\n    0x61, 0x62, 0x00\n};"
        );
        let array = format_bytes(DataFormat::CArray, &[0xff; 13], 0);
        assert_eq!(array.lines().count(), 4);
        assert!(array.contains("0xff, 0xff,\n    0xff\n};"));
        assert_eq!(
            format_bytes(DataFormat::CArray, b"", 0),
            "unsigned char data[0] = {};"
        );
    }

    #[test]
    fn base64_pads_like_rfc_4648() {
        for (data, expected) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
            (b"hi\xff", "aGn/"),
        ] {
            assert_eq!(format_bytes(DataFormat::Base64, data, 0), expected);
        }
    }

    #[test]
    fn text_forms_escape_or_replace_what_is_not_printable() {
        let data = b"a\"b\\\n\t\r\x00\x7f\xffz";
        assert_eq!(
            format_bytes(DataFormat::Escaped, data, 0),
            "\"a\\\"b\\\\\\n\\t\\r\\x00\\x7f\\xffz\""
        );
        assert_eq!(format_bytes(DataFormat::Ascii, data, 0), "a\"b\\\n.....z");
        assert_eq!(
            format_bytes(DataFormat::Utf8, b"ok\xffok", 0),
            "ok\u{FFFD}ok"
        );
        assert_eq!(format_bytes(DataFormat::Utf8, "é".as_bytes(), 0), "é");
        assert_eq!(format_bytes(DataFormat::Hex, b"\x00\xab", 0), "00 ab");
        assert_eq!(format_bytes(DataFormat::Decimal, b"\x00\xab", 0), "0 171");
        assert_eq!(
            format_bytes(DataFormat::HexEscaped, b"\x90A", 0),
            "\\x90\\x41"
        );
    }

    #[test]
    fn uncaptured_ranges_are_named_between_segments() {
        let segments = vec![(0, b"ab".to_vec()), (8, b"cd".to_vec())];
        assert_eq!(
            format_segments(DataFormat::Hex, &segments),
            "61 62\n[0x2..0x8 not captured]\n63 64"
        );
        assert_eq!(
            format_segments(DataFormat::Hexdump, &segments[1..]),
            "[0x0..0x8 not captured]\n\
             00000008  63 64                                             |cd|\n\
             0000000a"
        );
        assert_eq!(format_segments(DataFormat::Utf8, &[]), "");
    }

    #[test]
    fn number_formats_cover_bases_and_sign() {
        let items = number_items(u64::MAX - 1, 8, "-2");
        let get = |label: &str| {
            items
                .iter()
                .find(|(name, _)| name == label)
                .map(|(_, value)| value.as_str())
        };
        assert_eq!(get("As shown"), Some("-2"));
        assert_eq!(get("Decimal"), Some("18446744073709551614"));
        assert_eq!(get("Signed decimal"), Some("-2"));
        assert_eq!(get("Hex"), Some("0xfffffffffffffffe"));
        assert_eq!(get("Octal"), Some("0o1777777777777777777776"));
        assert_eq!(get("Binary").map(str::len), Some(66));
        let items = number_items(0x1234, 4, "");
        assert!(items.iter().all(|(name, _)| name != "As shown"));
        assert!(items.iter().all(|(name, _)| name != "Signed decimal"));
        assert!(items.contains(&("Hex, 4 bytes".into(), "0x00001234".into())));
        assert!(items.contains(&("Bytes, little endian".into(), "34 12 00 00".into())));
        assert!(items.contains(&("Binary".into(), "0b1001000110100".into())));
        assert!(number_items(0x1ff, 1, "").contains(&("Signed decimal".into(), "-1".into())));
    }

    #[test]
    fn screen_rows_mark_invalid_utf8_and_control_characters() {
        let font = egui::FontId::monospace(14.0);
        let job = display_row("a\u{FFFD}\u{1}\tb\r", &font);
        assert_eq!(job.text, "a\u{25A1}\u{B7}    b\u{B7}");
        assert_eq!(job.sections[1].format.color, theme::WARN);
        assert_eq!(job.sections[2].format.color, theme::MUTED);
        assert_eq!(display_row("", &font).text, "");
    }

    #[test]
    fn long_text_is_split_into_bounded_rows() {
        let text = format!("{}\nshort\n", "é".repeat(ROW_CHARS * 2 + 1));
        let rows = rows(&text);
        assert_eq!(rows.len(), 5);
        assert_eq!(text[rows[0].clone()].chars().count(), ROW_CHARS);
        assert_eq!(&text[rows[2].clone()], "é");
        assert_eq!(&text[rows[3].clone()], "short");
        assert_eq!(&text[rows[4].clone()], "");
    }

    #[test]
    fn read_plan_merges_ranges_and_stops_at_the_cap() {
        let mut field = field(b"");
        field.ranges = vec![(16, 4), (0, 8), (4, 8), (30, 10)];
        assert_eq!(plan(&field, 100), (vec![(0, 12), (16, 4), (30, 10)], false));
        assert_eq!(plan(&field, 14), (vec![(0, 12), (16, 2)], true));
        assert_eq!(plan(&field, 16), (vec![(0, 12), (16, 4)], true));
    }

    fn render(ctx: &egui::Context, windows: &mut DataWindows) -> egui::FullOutput {
        ctx.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 900.0),
                )),
                ..Default::default()
            },
            |ctx| windows.show(ctx),
        )
    }

    fn texts(output: &egui::FullOutput) -> Vec<String> {
        fn collect(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(text) => out.push(text.galley.text().to_owned()),
                egui::Shape::Vec(shapes) => shapes.iter().for_each(|shape| collect(shape, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        for shape in &output.shapes {
            collect(&shape.shape, &mut out);
        }
        out
    }

    #[test]
    fn data_window_shows_utf8_first_and_switches_format() {
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut windows = DataWindows::default();
        let request = OpenData {
            key: "call/1/7".into(),
            title: "buf / write".into(),
            field: field(b"hello\xff"),
        };
        windows.open(&ctx, request.clone(), None);
        windows.open(&ctx, request, None);
        assert_eq!(windows.len(), 1, "one window per field");
        let mut output = render(&ctx, &mut windows);
        for _ in 0..2 {
            output = render(&ctx, &mut windows);
        }
        let shown = texts(&output);
        assert!(shown.iter().any(|text| text == "buf / write"));
        assert!(shown.iter().any(|text| text == "UTF-8"));
        assert!(shown.iter().any(|text| text == "hello\u{25A1}"));
        assert!(shown.iter().any(|text| text == "Captured bytes (6 bytes)"));
        windows.windows[0].format = DataFormat::Hexdump;
        let shown = texts(&render(&ctx, &mut windows));
        assert!(shown
            .iter()
            .any(|text| text.starts_with("00000000  68 65 6c 6c 6f ff")));
        windows.windows[0].open = false;
        render(&ctx, &mut windows);
        assert_eq!(windows.len(), 0);
    }

    #[test]
    fn data_window_reads_the_whole_capture_past_the_preview() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ant-ui-data-window-{}-{unique}",
            std::process::id()
        ));
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(directory.clone());
        std::fs::create_dir_all(directory.join("objects")).unwrap();
        let data: Vec<u8> = (0..150_000u32).map(|n| (n % 251) as u8).collect();
        std::fs::write(directory.join("objects/object"), &data).unwrap();
        let mut captured = field(&data);
        captured.raw_path = Some(PathBuf::from("objects/object"));
        captured.complete = false;
        captured.status = Some(1);
        captured.logical_len = Some(200_000);
        let ctx = egui::Context::default();
        theme::install(&ctx);
        let mut windows = DataWindows::default();
        windows.open(
            &ctx,
            OpenData {
                key: "call/1/7".into(),
                title: "buf / read".into(),
                field: captured,
            },
            Some(directory.clone()),
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while windows.windows[0].loader.is_some() && std::time::Instant::now() < deadline {
            let shown = texts(&render(&ctx, &mut windows));
            if windows.windows[0].loader.is_some() {
                assert!(
                    shown
                        .iter()
                        .any(|text| text.starts_with("Loading captured bytes")),
                    "{shown:?}"
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(windows.windows[0].loader.is_none(), "reader finished");
        assert_eq!(windows.windows[0].segments, vec![(0, data.clone())]);
        let shown = texts(&render(&ctx, &mut windows));
        assert!(shown
            .iter()
            .any(|text| text == "Captured bytes (150000 of 200000 bytes, copy fault)"));
        assert!(shown
            .iter()
            .any(|text| text == "Partial capture: copy fault"));
        assert_eq!(
            format_segments(DataFormat::Base64, &windows.windows[0].segments).len(),
            200_000
        );
    }
}

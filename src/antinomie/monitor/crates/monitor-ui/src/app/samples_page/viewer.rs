// SPDX-License-Identifier: GPL-3.0-only
//! The file viewer: a window over the Samples page that shows one archived
//! sample 4 KiB at a time, like Static Analysis › Content, plus a Strings
//! format that lists the printable runs of the whole file with their offsets.
//! It only reads the archive; it never runs or unpacks anything.
use super::*;
use crate::analysis::workspace::content::{parse_offset, render, Format};
use std::sync::Arc;

/// One page, as Static Analysis › Content reads it.
const PAGE: u64 = 4096;
/// The shortest printable run Strings lists.
const MIN_RUN: usize = 5;
/// Strings keeps this many; the title says when more were found.
const MAX_STRINGS: usize = 100_000;
const MIN_PX: f32 = 8.0;
const MAX_PX: f32 = 32.0;
const DEFAULT_PX: f32 = 13.0;

/// What the viewer shows the bytes as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Show {
    Bytes(Format),
    Strings,
}

impl Show {
    const ALL: [Show; 7] = [
        Show::Bytes(Format::Text),
        Show::Bytes(Format::Hex),
        Show::Strings,
        Show::Bytes(Format::CArray),
        Show::Bytes(Format::Python),
        Show::Bytes(Format::Base64),
        Show::Bytes(Format::HexString),
    ];

    fn label(self) -> &'static str {
        match self {
            Show::Bytes(format) => format.label(),
            Show::Strings => "Strings",
        }
    }
}

enum Bytes {
    Reading(Receiver<Result<Vec<u8>, String>>),
    Ready(Arc<Vec<u8>>),
    Failed(String),
}

/// The printable runs of `data` of at least [`MIN_RUN`] bytes with their
/// offsets, at most `cap` of them, and how many there were in all.
pub(super) fn printable_runs(data: &[u8], cap: usize) -> (Vec<(u64, String)>, usize) {
    let mut out = Vec::new();
    let mut total = 0usize;
    let mut start = None;
    let mut flush = |from: usize, to: usize, out: &mut Vec<(u64, String)>| {
        if to - from >= MIN_RUN {
            total += 1;
            if out.len() < cap {
                out.push((
                    from as u64,
                    String::from_utf8_lossy(&data[from..to]).into_owned(),
                ));
            }
        }
    };
    for (at, byte) in data.iter().enumerate() {
        let printable = matches!(byte, 0x20..=0x7e | b'\t');
        match (printable, start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                flush(from, at, &mut out);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(from) = start {
        flush(from, data.len(), &mut out);
    }
    (out, total)
}

/// Whether the first page reads as text, so the viewer opens on Text.
fn looks_like_text(head: &[u8]) -> bool {
    !head.is_empty()
        && head
            .iter()
            .filter(|byte| matches!(byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e))
            .count()
            * 100
            >= head.len() * 95
}

pub(super) struct Viewer {
    pub(super) sha256: String,
    name: String,
    size: u64,
    bytes: Bytes,
    show: Show,
    /// The first byte of the page shown.
    offset: u64,
    go_to: String,
    px: f32,
    strings: Option<(Vec<(u64, String)>, usize)>,
    pub(super) open: bool,
}

impl Viewer {
    /// Read the archived sample on a worker thread.
    pub(super) fn open(
        ctx: &egui::Context,
        sha256: &str,
        name: &str,
        size: u64,
        archive: std::path::PathBuf,
    ) -> Self {
        let (sender, receiver) = std::sync::mpsc::channel();
        let wake = ctx.clone();
        let hash = sha256.to_owned();
        let started = std::thread::Builder::new()
            .name("sample-viewer".into())
            .spawn(move || {
                let _ = sender.send(antinomie_monitor_core::samples::open_sample(
                    &archive, &hash,
                ));
                wake.request_repaint();
            });
        Self {
            sha256: sha256.to_owned(),
            name: name.to_owned(),
            size,
            bytes: match started {
                Ok(_) => Bytes::Reading(receiver),
                Err(error) => Bytes::Failed(error.to_string()),
            },
            show: Show::Bytes(Format::Hex),
            offset: 0,
            go_to: String::new(),
            px: DEFAULT_PX,
            strings: None,
            open: true,
        }
    }

    fn poll(&mut self) {
        let Bytes::Reading(receiver) = &self.bytes else {
            return;
        };
        if let Ok(result) = receiver.try_recv() {
            self.bytes = match result {
                Ok(data) => {
                    let head = &data[..data.len().min(PAGE as usize)];
                    self.show = Show::Bytes(if looks_like_text(head) {
                        Format::Text
                    } else {
                        Format::Hex
                    });
                    Bytes::Ready(Arc::new(data))
                }
                Err(error) => Bytes::Failed(error),
            };
        }
    }

    fn title(&self) -> String {
        format!(
            "{} · {} · {}",
            self.name,
            crate::values::file_size(self.size),
            &self.sha256[..self.sha256.len().min(8)]
        )
    }

    /// Draw the window.
    pub(super) fn show(&mut self, ctx: &egui::Context) {
        self.poll();
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            self.open = false;
        }
        let mut open = self.open;
        let ready = match &self.bytes {
            Bytes::Ready(data) => Some(Arc::clone(data)),
            _ => None,
        };
        let failed = match &self.bytes {
            Bytes::Failed(error) => Some(error.clone()),
            _ => None,
        };
        egui::Window::new(self.title())
            .id(egui::Id::new("sample_viewer"))
            .open(&mut open)
            .default_size([780.0, 540.0])
            .resizable(true)
            .collapsible(false)
            .show(ctx, |ui| match (ready, failed) {
                (Some(data), _) => self.body(ui, &data),
                (None, Some(error)) => {
                    crate::activity::error(ui, &error);
                }
                (None, None) => {
                    crate::theme::loading(ui, "Reading the archive…");
                }
            });
        self.open = open && self.open;
    }

    fn body(&mut self, ui: &mut egui::Ui, data: &Arc<Vec<u8>>) {
        let total = data.len() as u64;
        if total == 0 {
            ui.label("The sample is empty.");
            return;
        }
        self.offset = self.offset.min(total - 1) / PAGE * PAGE;
        let strings = self.show == Show::Strings;
        ui.horizontal_wrapped(|ui| {
            if !strings {
                let last = (total - 1) / PAGE * PAGE;
                let mut target = None;
                for (icon, hover, enabled, offset) in [
                    (
                        egui_phosphor::regular::CARET_DOUBLE_LEFT,
                        "First page",
                        self.offset > 0,
                        0,
                    ),
                    (
                        egui_phosphor::regular::CARET_LEFT,
                        "Previous page",
                        self.offset > 0,
                        self.offset.saturating_sub(PAGE),
                    ),
                    (
                        egui_phosphor::regular::CARET_RIGHT,
                        "Next page",
                        self.offset + PAGE < total,
                        self.offset + PAGE,
                    ),
                    (
                        egui_phosphor::regular::CARET_DOUBLE_RIGHT,
                        "Last page",
                        self.offset < last,
                        last,
                    ),
                ] {
                    if ui
                        .add_enabled(enabled, egui::Button::new(icon))
                        .on_hover_text(hover)
                        .clicked()
                    {
                        target = Some(offset);
                    }
                }
                let field = ui.add(
                    egui::TextEdit::singleline(&mut self.go_to)
                        .hint_text(crate::theme::hint_text("Offset, e.g. 0x1f00"))
                        .desired_width(150.0),
                );
                let entered =
                    field.lost_focus() && ui.input(|input| input.key_pressed(egui::Key::Enter));
                if ui.button("Go").clicked() || entered {
                    match parse_offset(&self.go_to) {
                        Some(offset) if offset < total => target = Some(offset / PAGE * PAGE),
                        _ => self.go_to = format!("beyond 0x{:x}", total - 1),
                    }
                }
                if let Some(offset) = target {
                    self.offset = offset;
                }
            }
            egui::ComboBox::from_id_salt("sample_viewer_format")
                .selected_text(self.show.label())
                .show_ui(ui, |ui| {
                    for show in Show::ALL {
                        ui.selectable_value(&mut self.show, show, show.label());
                    }
                });
            if ui.small_button("−").on_hover_text("Smaller text").clicked() {
                self.px = (self.px - 1.0).max(MIN_PX);
            }
            ui.label(format!("{:.0} px", self.px));
            if ui.small_button("+").on_hover_text("Larger text").clicked() {
                self.px = (self.px + 1.0).min(MAX_PX);
            }
            if ui.small_button("Reset").clicked() {
                self.px = DEFAULT_PX;
            }
        });
        // Ctrl+wheel over the window zooms the text too.
        if ui.rect_contains_pointer(ui.max_rect()) {
            let (ctrl, scroll) =
                ui.input(|input| (input.modifiers.command, input.raw_scroll_delta.y));
            if ctrl && scroll != 0.0 {
                self.px = (self.px + scroll.signum()).clamp(MIN_PX, MAX_PX);
            }
        }
        match self.show {
            Show::Strings => self.strings_body(ui, data),
            Show::Bytes(format) => {
                let end = (self.offset + PAGE).min(total);
                ui.monospace(format!(
                    "0x{:x}–0x{:x} of {}",
                    self.offset,
                    end - 1,
                    crate::values::file_size(total)
                ));
                let text = render(
                    format,
                    self.offset,
                    &data[self.offset as usize..end as usize],
                );
                if ui
                    .button(format!("{} Copy page", egui_phosphor::regular::COPY))
                    .on_hover_text(format!("Copy this page as {}", format.label()))
                    .clicked()
                {
                    ui.ctx().copy_text(text.clone());
                }
                let wrap = !matches!(format, Format::Hex);
                egui::ScrollArea::both()
                    .id_salt("sample_viewer_page")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut text.as_str())
                                .code_editor()
                                .font(egui::FontId::monospace(self.px))
                                .desired_width(if wrap {
                                    ui.available_width()
                                } else {
                                    f32::INFINITY
                                })
                                .desired_rows(24),
                        );
                    });
            }
        }
    }

    fn strings_body(&mut self, ui: &mut egui::Ui, data: &Arc<Vec<u8>>) {
        let (list, total) = self
            .strings
            .get_or_insert_with(|| printable_runs(data, MAX_STRINGS));
        ui.label(if *total > list.len() {
            format!("{} strings, the first {} shown", total, list.len())
        } else {
            format!("{total} strings")
        });
        let height = self.px + 4.0;
        egui::ScrollArea::both()
            .id_salt("sample_viewer_strings")
            .auto_shrink([false, false])
            .show_rows(ui, height, list.len(), |ui, range| {
                for (offset, text) in &list[range] {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!("{offset:08x}  {text}"))
                                .font(egui::FontId::monospace(self.px)),
                        )
                        .selectable(true)
                        .wrap_mode(egui::TextWrapMode::Extend),
                    );
                }
            });
    }

    #[cfg(test)]
    pub(super) fn is_ready(&self) -> bool {
        matches!(self.bytes, Bytes::Ready(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_runs_of_five_or_more_with_their_offsets() {
        let mut data = b"ab\0\0hello\x01world!!\0\xff/etc/ld.so.preload".to_vec();
        data.extend_from_slice(b"\0abcd");
        let (found, total) = printable_runs(&data, 10);
        let texts: Vec<(u64, &str)> = found.iter().map(|(at, t)| (*at, t.as_str())).collect();
        assert_eq!(texts[0], (4, "hello"));
        assert_eq!(texts[1], (10, "world!!"));
        assert_eq!(texts[2].1, "/etc/ld.so.preload");
        assert_eq!(total, 3);
        // The cap keeps the first ones and still counts all.
        let (capped, all) = printable_runs(&data, 1);
        assert_eq!((capped.len(), all), (1, 3));
    }

    #[test]
    fn a_script_opens_as_text_and_a_binary_as_hex() {
        assert!(looks_like_text(b"#!/bin/sh\necho hi\n"));
        assert!(!looks_like_text(
            b"\x7fELF\x02\x01\x01\0\0\0\0\0\xff\xfe\x00\x01"
        ));
        assert!(!looks_like_text(b""));
    }
}

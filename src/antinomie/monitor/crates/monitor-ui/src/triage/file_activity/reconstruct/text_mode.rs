// SPDX-License-Identifier: GPL-3.0-only
//! The byte map of the File Reconstruction window as text: UTF-8 with escapes
//! for invalid bytes, or UTF-16LE. Every byte keeps the colour of its state,
//! and a byte with no value stays visibly marked (`??` never seen, `##` not
//! captured, `~~` shared mapping, `!!` unreadable) in both modes, so a gap in
//! the text is a gap in the file.
use super::{tint, Open};
use crate::theme;
use antinomie_monitor_core::file_reconstruct::{Cell, State, START};
use eframe::egui::{self, RichText};

/// Bytes in a row of the text modes.
pub(super) const TEXT_ROW: usize = 32;
/// Cached rows of the text modes live under this bit of the offset.
const TEXT_KEY: u64 = 1 << 63;
const MEMORY: &str = "file-reconstruction-view";

/// What the central panel shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum View {
    /// Hex and ASCII, sixteen bytes a row.
    #[default]
    Hex,
    /// UTF-8; an invalid byte is shown as `\xNN`.
    Utf8,
    /// UTF-16LE, two bytes a character.
    Utf16,
    /// Lines changed since the start of the run.
    Diff,
}

/// The choice made earlier in this session, if any.
pub(super) fn remembered(ctx: &egui::Context) -> Option<View> {
    ctx.data(|data| data.get_temp::<View>(egui::Id::new(MEMORY)))
}

pub(super) fn remember(ctx: &egui::Context, view: View) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::new(MEMORY), view));
}

/// One drawn piece of a row: a character, an escape or a marker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Piece {
    pub text: String,
    /// The offset of its first byte, and that byte.
    pub at: u64,
    pub cell: Cell,
}

fn marker(cell: &Cell) -> String {
    match (cell.state.glyph(), cell.byte) {
        (Some(glyph), _) => glyph.to_owned(),
        _ => "!!".to_owned(),
    }
}

fn shown(c: char) -> String {
    match c {
        '\n' => "\\n".into(),
        '\r' => "\\r".into(),
        '\t' => "\\t".into(),
        '\\' => "\\\\".into(),
        c if c.is_control() => format!("\\u{{{:x}}}", c as u32),
        c => c.to_string(),
    }
}

/// Decode `cells`, which start at `first` in the file, into the pieces whose
/// first byte lies in `from..to`. The cells reach a few bytes before and after
/// so a character that crosses a row edge is whole.
pub(super) fn decode(cells: &[Cell], first: u64, from: u64, to: u64, view: View) -> Vec<Piece> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < cells.len() {
        let at = first + i as u64;
        let (text, used) = match view {
            View::Utf16 => unit16(&cells[i..]),
            _ => unit8(&cells[i..]),
        };
        if at >= from && at < to {
            out.push(Piece {
                text,
                at,
                cell: cells[i],
            });
        }
        i += used.max(1);
    }
    out
}

/// The byte, when the cell has a value that could be read.
fn value(cell: &Cell) -> Option<u8> {
    cell.state.has_value().then_some(cell.byte).flatten()
}

fn unit8(cells: &[Cell]) -> (String, usize) {
    let Some(byte) = value(&cells[0]) else {
        return (marker(&cells[0]), 1);
    };
    let wanted = match byte {
        0..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 0,
    };
    if wanted > 0 && cells.len() >= wanted {
        let bytes: Option<Vec<u8>> = cells[..wanted].iter().map(value).collect();
        if let Some(Ok(text)) = bytes.as_deref().map(std::str::from_utf8) {
            if let Some(c) = text.chars().next() {
                return (shown(c), wanted);
            }
        }
    }
    (format!("\\x{byte:02x}"), 1)
}

fn unit16(cells: &[Cell]) -> (String, usize) {
    let pair = |at: usize| -> Option<Result<u16, String>> {
        let (low, high) = (cells.get(at)?, cells.get(at + 1)?);
        Some(match (value(low), value(high)) {
            (Some(low), Some(high)) => Ok(u16::from_le_bytes([low, high])),
            (None, _) => Err(marker(low)),
            (_, None) => Err(marker(high)),
        })
    };
    match pair(0) {
        None => match value(&cells[0]) {
            Some(byte) => (format!("\\x{byte:02x}"), 1),
            None => (marker(&cells[0]), 1),
        },
        Some(Err(glyph)) => (glyph, 2),
        Some(Ok(unit @ 0xd800..=0xdbff)) => match pair(2) {
            Some(Ok(low @ 0xdc00..=0xdfff)) => match char::decode_utf16([unit, low]).next() {
                Some(Ok(c)) => (shown(c), 4),
                _ => (format!("\\u{{{unit:04x}}}"), 2),
            },
            _ => (format!("\\u{{{unit:04x}}}"), 2),
        },
        Some(Ok(unit)) => match char::from_u32(u32::from(unit)) {
            Some(c) => (shown(c), 2),
            None => (format!("\\u{{{unit:04x}}}"), 2),
        },
    }
}

impl Open {
    /// The text view of the byte map.
    pub(super) fn text_rows(
        &mut self,
        ui: &mut egui::Ui,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
        let size = self.map.size();
        if size == 0 {
            theme::empty_state(ui, "The file is empty at this point");
            return;
        }
        let view = self.view;
        let rows = size.div_ceil(TEXT_ROW as u64) as usize;
        let height = ui.text_style_height(&egui::TextStyle::Monospace) + 4.0;
        egui::ScrollArea::both()
            .id_salt("file-reconstruction-text")
            .auto_shrink([false, false])
            .show_rows(ui, height, rows, |ui, range| {
                ui.spacing_mut().item_spacing.x = 0.0;
                for row in range {
                    let offset = (row * TEXT_ROW) as u64;
                    // Three bytes either side: a UTF-8 character is up to four
                    // bytes, and a UTF-16 pair is four.
                    let first = offset.saturating_sub(3);
                    let last = (offset + TEXT_ROW as u64 + 3).min(size);
                    let cells = match self.cache.get(&(TEXT_KEY | offset)) {
                        Some(cells) => cells.clone(),
                        None => {
                            let cells = self.map.row(first, (last - first) as usize);
                            self.cache.insert(TEXT_KEY | offset, cells.clone());
                            cells
                        }
                    };
                    // UTF-16 units pair up from the start of the file.
                    let skip = if view == View::Utf16 { first % 2 } else { 0 };
                    let pieces = decode(
                        &cells[skip as usize..],
                        first + skip,
                        offset,
                        (offset + TEXT_ROW as u64).min(size),
                        view,
                    );
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("{offset:08x}  "))
                                .monospace()
                                .color(theme::muted()),
                        );
                        for piece in &pieces {
                            let mut rich = RichText::new(&piece.text)
                                .monospace()
                                .color(tint(piece.cell.state));
                            if self.selected == Some(piece.at) {
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
                                self.selected = Some(piece.at);
                            }
                            response.on_hover_ui(|ui| self.hover(ui, piece.at, &piece.cell, clock));
                        }
                    });
                }
            });
    }

    /// What a byte of the map says when hovered.
    pub(super) fn hover(
        &self,
        ui: &mut egui::Ui,
        at: u64,
        cell: &Cell,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) {
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
    }
}

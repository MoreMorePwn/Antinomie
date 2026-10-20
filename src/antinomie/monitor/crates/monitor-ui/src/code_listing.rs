// SPDX-License-Identifier: MIT
//! The one listing widget behind Static analysis' Disassembly and
//! Decompilation tabs and the Cores view (the Debugger joins them later): the
//! function sidebar, with the number of lines each function has in the view
//! being shown, and the painting of instructions and decompiled source. Each
//! host decides what its lines are and where they come from; the look and the
//! wording live here.
use crate::theme;
use eframe::egui::{self, text::LayoutJob, Color32, FontId, Sense, TextFormat, TextStyle};
use std::hash::Hash;

/// What the listing shows. The count beside a function is per view: its
/// instructions in one, its source lines in the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum View {
    Disassembly,
    Decompilation,
}

impl View {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Disassembly => "Disassembly",
            Self::Decompilation => "Decompilation",
        }
    }
}

/// One function of the sidebar. `lines` is None while its lines in this view
/// are not known (a core function not disassembled yet).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Function<'a> {
    pub name: &'a str,
    pub address: u64,
    pub lines: Option<u64>,
}

/// "7 lines", "1 line", or "– lines" when not counted yet.
pub(crate) fn lines_text(lines: Option<u64>) -> String {
    match lines {
        Some(1) => "1 line".to_owned(),
        Some(count) => format!("{count} lines"),
        None => "– lines".to_owned(),
    }
}

/// The detail line under a function name: "0x401c20 · 7 lines".
pub(crate) fn detail_text(function: &Function<'_>) -> String {
    format!("0x{:x} · {}", function.address, lines_text(function.lines))
}

/// The sidebar head: "Functions · 12", or "Functions · 3 / 12" when a filter
/// hides some.
pub(crate) fn heading(ui: &mut egui::Ui, shown: usize, total: usize) {
    let count = if shown == total {
        total.to_string()
    } else {
        format!("{shown} / {total}")
    };
    ui.label(theme::hint_text(format!("Functions · {count}")));
}

/// The functions, one two-line row each (name, then address and line count),
/// scrolled by row so a long list costs only what is on screen. `selected`
/// is a position in 0..count. `menu` fills a row's context menu. Returns the
/// position clicked.
pub(crate) fn function_list<'a>(
    ui: &mut egui::Ui,
    id: impl Hash,
    count: usize,
    function: impl Fn(usize) -> Function<'a>,
    selected: Option<usize>,
    mut menu: impl FnMut(&mut egui::Ui, usize),
) -> Option<usize> {
    let name_font = TextStyle::Body.resolve(ui.style());
    let detail_font = TextStyle::Monospace.resolve(ui.style());
    let height =
        ui.fonts(|fonts| fonts.row_height(&name_font) + fonts.row_height(&detail_font)) + 10.0;
    let mut clicked = None;
    egui::ScrollArea::vertical()
        .id_salt(("function-list", id))
        .auto_shrink([false, false])
        .show_rows(ui, height, count, |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for position in range {
                let function = function(position);
                let (rect, response) = ui
                    .allocate_exact_size(egui::vec2(ui.available_width(), height), Sense::click());
                let palette = theme::palette();
                if selected == Some(position) {
                    ui.painter().rect_filled(rect, 3.0, palette.selection);
                    let bar = egui::Rect::from_min_size(rect.min, egui::vec2(3.0, rect.height()));
                    ui.painter().rect_filled(bar, 0.0, palette.accent);
                } else if response.hovered() {
                    ui.painter().rect_filled(rect, 3.0, palette.hover);
                }
                let clip = ui
                    .painter()
                    .with_clip_rect(rect.shrink2(egui::vec2(8.0, 0.0)));
                let name =
                    clip.layout_no_wrap(function.name.to_owned(), name_font.clone(), palette.text);
                let detail =
                    clip.layout_no_wrap(detail_text(&function), detail_font.clone(), palette.muted);
                let top = rect.top() + 5.0;
                let left = rect.left() + 10.0;
                let below = top + name.size().y;
                clip.galley(egui::pos2(left, top), name, Color32::PLACEHOLDER);
                clip.galley(egui::pos2(left, below), detail, Color32::PLACEHOLDER);
                response.context_menu(|ui| menu(ui, position));
                if response.clicked() {
                    clicked = Some(position);
                }
            }
        });
    clicked
}

/// Mnemonic color: calls blue, jumps and returns warn, undecodable bytes error.
pub(crate) fn mnemonic_color(mnemonic: &str) -> Color32 {
    if mnemonic.starts_with("call") {
        theme::blue()
    } else if mnemonic.starts_with('j') || mnemonic.starts_with("ret") {
        theme::warn()
    } else if mnemonic == "(bad)" {
        theme::error()
    } else {
        theme::text()
    }
}

fn format(font: &FontId, color: Color32) -> TextFormat {
    TextFormat::simple(font.clone(), color)
}

/// An instruction: the mnemonic padded to eight columns, then its operands.
pub(crate) fn instruction(mnemonic: &str, operands: &str, font: &FontId) -> LayoutJob {
    let mut job = LayoutJob::default();
    job.append(
        &format!("{mnemonic:<8} "),
        0.0,
        format(font, mnemonic_color(mnemonic)),
    );
    job.append(operands, 0.0, format(font, theme::text()));
    job
}

/// A line of the disassembly text the core decoder writes: "address  mnemonic
/// operands". Anything else (a header or note line) is shown as it is.
pub(crate) fn text_instruction(ui: &mut egui::Ui, line: &str) {
    let font = TextStyle::Monospace.resolve(ui.style());
    let Some((address, rest)) = line.split_once("  ") else {
        ui.add(
            egui::Label::new(egui::RichText::new(line).font(font).color(theme::muted())).extend(),
        );
        return;
    };
    let (mnemonic, operands) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        ui.add(egui::Label::new(
            egui::RichText::new(address)
                .font(font.clone())
                .color(theme::value(theme::ValueKind::Pointer)),
        ));
        ui.add(egui::Label::new(instruction(mnemonic, operands.trim_start(), &font)).extend());
    });
}

const KEYWORDS: &[&str] = &[
    "if", "else", "while", "for", "do", "return", "goto", "switch", "case", "default", "break",
    "continue", "sizeof",
];
const TYPES: &[&str] = &[
    "void",
    "char",
    "short",
    "int",
    "long",
    "unsigned",
    "signed",
    "float",
    "double",
    "bool",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "uint",
    "ulong",
    "byte",
    "word",
    "dword",
    "qword",
    "code",
    "struct",
    "const",
    "size_t",
    "uchar",
    "ushort",
];

/// Light C highlighting: comments, strings, numbers, keywords and types.
pub(crate) fn highlight(line: &str, font: &FontId) -> LayoutJob {
    let mut job = LayoutJob::default();
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        job.append(line, 0.0, format(font, theme::muted()));
        return job;
    }
    let mut rest = line;
    while !rest.is_empty() {
        let first = rest.chars().next().unwrap_or(' ');
        let (token, color) = if first == '"' || first == '\'' {
            let end = rest[1..]
                .find(first)
                .map_or(rest.len(), |at| at + 2)
                .min(rest.len());
            (&rest[..end], theme::good())
        } else if first.is_ascii_digit() {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
                .unwrap_or(rest.len());
            (&rest[..end], theme::warn())
        } else if first.is_alphabetic() || first == '_' {
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let word = &rest[..end];
            let color = if KEYWORDS.contains(&word) {
                theme::error()
            } else if TYPES.contains(&word) {
                theme::blue()
            } else {
                theme::text()
            };
            (word, color)
        } else {
            let end = rest.char_indices().nth(1).map_or(rest.len(), |(at, _)| at);
            (&rest[..end], theme::text())
        };
        job.append(token, 0.0, format(font, color));
        rest = &rest[token.len()..];
    }
    job
}

#[cfg(test)]
mod tests;

// SPDX-License-Identifier: GPL-3.0-only
//! The help icon: the one place where a control's explanation lives. A muted
//! question mark beside the control shows the text on hover and, pinned, on
//! a click (touch and keyboard users: it takes focus, Space or Enter opens
//! it). It works in a disabled row too: egui shows an enabled widget's
//! tooltip only while it is enabled, so a read-only window used to hide every
//! hint.
//!
//! Controls keep no long hover text. What may stay on a control (the guard
//! `scripts/check-control-hover.py` enforces it): a name of one to four words
//! for an icon-only button, a value that is only shown whole on hover, and a
//! short reason why a control is disabled. The [`Tip`] helpers mark those.
//!
//! The text is plain, with a few conventions:
//! - paragraphs are separated by a blank line (`\n\n`) and drawn with room
//!   between them;
//! - the first paragraph is the bold title when it is one short line and
//!   more paragraphs follow; a text with no line break whose first sentence
//!   is short gets that sentence as its title;
//! - a line that starts with `- ` is a bullet;
//! - `code` (keys, option names, paths) is monospace and `**word**` is bold.
//!
//! The text wraps at [`HELP_WIDTH`].

use crate::theme;
use eframe::egui::{self, text::LayoutJob, RichText, TextFormat};

/// The widest a help text runs before it wraps.
pub const HELP_WIDTH: f32 = 360.0;
/// The longest hover text a control may keep: a name of one to four words.
pub const NAME_WORDS: usize = 4;
/// ... and at most this many characters.
pub const NAME_CHARS: usize = 40;
/// A first sentence longer than this is not made a title.
const TITLE_CHARS: usize = 80;
/// A one-line text longer than this is split after its first sentence.
const LONG_CHARS: usize = 200;

#[cfg(test)]
#[path = "help_tests.rs"]
mod tests;

/// One block of a help text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Block {
    Title(String),
    Paragraph(String),
    Bullet(String),
}

/// A help icon with `text`; see the module for the format.
pub fn help(ui: &mut egui::Ui, text: impl AsRef<str>) -> egui::Response {
    let text = text.as_ref();
    let response = ui
        .add(
            egui::Label::new(RichText::new(egui_phosphor::regular::QUESTION).color(theme::muted()))
                .selectable(false)
                .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::Help);
    // A disabled widget never reports a click; the pointer still tells.
    let clicked = response.clicked()
        || (!response.enabled()
            && response.contains_pointer()
            && ui.input(|input| input.pointer.primary_clicked()));
    #[cfg(test)]
    let clicked = clicked || qa_pin(ui, text);
    let pinned = egui::Popup::from_response(&response)
        .id(response.id.with("help_pinned"))
        .open_memory(clicked.then_some(egui::SetOpenCommand::Toggle))
        .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
        .width(HELP_WIDTH)
        .show(|ui| body(ui, text))
        .is_some();
    if pinned {
        response
    } else if response.enabled() {
        response.on_hover_ui(|ui| body(ui, text))
    } else {
        response.on_disabled_hover_ui(|ui| body(ui, text))
    }
}

/// Screenshot fixtures: the key under which a fixture names a help text to
/// open pinned (the first icon whose text holds it opens once).
#[cfg(test)]
pub(crate) fn qa_pin_key() -> egui::Id {
    egui::Id::new("qa_pin_help")
}

#[cfg(test)]
fn qa_pin(ui: &egui::Ui, text: &str) -> bool {
    let wanted: Option<String> = ui.data(|data| data.get_temp(qa_pin_key()));
    match wanted {
        Some(wanted) if !wanted.is_empty() && text.contains(&wanted) => {
            ui.data_mut(|data| data.remove::<String>(qa_pin_key()));
            true
        }
        _ => false,
    }
}

/// A control drawn by `add` with a help icon beside it. Both sit in one row,
/// so the icon stays next to its control in a grid cell, a wrapping row or a
/// column. Returns the control's response.
pub fn with_help(
    ui: &mut egui::Ui,
    text: impl AsRef<str>,
    add: impl FnOnce(&mut egui::Ui) -> egui::Response,
) -> egui::Response {
    row(ui, |ui, own| {
        let response = beside_icon(ui, own, add);
        help(ui, text);
        response
    })
}

/// [`with_help`] for a control that may be disabled: while it is, the icon
/// leads with `reason` (and shows even when `text` is empty).
pub fn with_help_or(
    ui: &mut egui::Ui,
    text: impl AsRef<str>,
    reason: impl AsRef<str>,
    add: impl FnOnce(&mut egui::Ui) -> egui::Response,
) -> egui::Response {
    row(ui, |ui, own| {
        let response = beside_icon(ui, own, add);
        let (text, reason) = (text.as_ref(), reason.as_ref());
        if response.enabled() || reason.is_empty() {
            if !text.is_empty() {
                help(ui, text);
            }
        } else if text.is_empty() {
            help(ui, reason);
        } else {
            help(ui, format!("{reason}\n\n{text}"));
        }
        response
    })
}

/// Where a control and its icon go. A wrapping row places them itself (a
/// row of its own there would start in what is left of the line and squeeze
/// the control). Anywhere else (a column, a grid cell, a plain row) they get
/// a row of their own that wraps text as the control's place did: a row does
/// not wrap by itself, so a long checkbox label in a column would otherwise
/// run past the window's edge.
fn row(
    ui: &mut egui::Ui,
    add: impl FnOnce(&mut egui::Ui, bool) -> egui::Response,
) -> egui::Response {
    let layout = *ui.layout();
    if layout.main_dir().is_horizontal() && layout.main_wrap() {
        return add(ui, false);
    }
    let wrap = ui.wrap_mode();
    ui.horizontal(|ui| {
        ui.style_mut().wrap_mode = Some(wrap);
        add(ui, true)
    })
    .inner
}

/// Draws `add` in a fresh row with the icon's room kept free at the end, so a
/// control that takes the width it is given (a full-width button, a text
/// field) still leaves its icon in view. The icon itself is placed past
/// that width (a row lays out what overflows it).
fn beside_icon(
    ui: &mut egui::Ui,
    own_row: bool,
    add: impl FnOnce(&mut egui::Ui) -> egui::Response,
) -> egui::Response {
    if own_row {
        let room = ui.text_style_height(&egui::TextStyle::Body) + ui.spacing().item_spacing.x + 2.0;
        ui.set_max_width((ui.available_width() - room).max(0.0));
    }
    add(ui)
}

/// A help text for a set of choices (a list's entries, a row of tabs):
/// `title`, then one bullet per choice, its name in bold.
pub fn list_help<N: AsRef<str>, D: AsRef<str>>(
    title: &str,
    choices: impl IntoIterator<Item = (N, D)>,
) -> String {
    let mut text = title.to_owned();
    if !text.is_empty() {
        text.push_str("\n\n");
    }
    for (name, description) in choices {
        text.push_str(&format!(
            "- **{}**: {}\n",
            name.as_ref(),
            description.as_ref()
        ));
    }
    text.trim_end().to_owned()
}

/// The hover texts a control may keep (module docs). Each is a plain tooltip;
/// the name marks the kind for the reader and the guard.
pub trait Tip {
    /// The name of an icon-only control: one to four words.
    fn name_tip(self, name: impl Into<String>) -> Self;
    /// A value the control shows cut short (a path, a hash, a time), whole.
    fn value_tip(self, value: impl Into<egui::WidgetText>) -> Self;
    /// Why the control is disabled, where there is no room for an icon: one
    /// short line.
    fn reason_tip(self, reason: impl Into<egui::WidgetText>) -> Self;
}

impl Tip for egui::Response {
    fn name_tip(self, name: impl Into<String>) -> Self {
        let name = name.into();
        debug_assert!(is_name(&name), "not a short name: {name:?}");
        if self.enabled() {
            self.on_hover_text(name)
        } else {
            self.on_disabled_hover_text(name)
        }
    }

    fn value_tip(self, value: impl Into<egui::WidgetText>) -> Self {
        let value = value.into();
        if self.enabled() {
            self.on_hover_text(value)
        } else {
            self.on_disabled_hover_text(value)
        }
    }

    fn reason_tip(self, reason: impl Into<egui::WidgetText>) -> Self {
        self.on_disabled_hover_text(reason)
    }
}

/// Is `text` short enough to stay on a control as its name?
pub fn is_name(text: &str) -> bool {
    text.split_whitespace().count() <= NAME_WORDS && text.chars().count() <= NAME_CHARS
}

/// Draws a help text: blocks one below the other, a blank line between
/// paragraphs, bullets with a hanging indent, at most [`HELP_WIDTH`] wide.
pub(crate) fn body(ui: &mut egui::Ui, text: &str) {
    ui.set_max_width(HELP_WIDTH);
    let gap = ui.text_style_height(&egui::TextStyle::Body) * 0.6;
    let mut previous: Option<Block> = None;
    for block in blocks(text) {
        let tight = matches!(
            (&previous, &block),
            (Some(Block::Bullet(_)), Block::Bullet(_))
        );
        if previous.is_some() && !tight {
            ui.add_space(gap);
        }
        match &block {
            Block::Title(title) => {
                ui.add(
                    egui::Label::new(
                        theme::bold(ui, title.as_str()).color(ui.visuals().strong_text_color()),
                    )
                    .wrap(),
                );
            }
            Block::Paragraph(text) => {
                ui.add(egui::Label::new(inline(ui, text)).wrap());
            }
            Block::Bullet(text) => {
                ui.horizontal_top(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    ui.label("•");
                    ui.add(egui::Label::new(inline(ui, text)).wrap());
                });
            }
        }
        previous = Some(block);
    }
}

/// Splits a help text into blocks (module docs for the rules).
pub(crate) fn blocks(text: &str) -> Vec<Block> {
    let text = text.trim();
    if text.is_empty() {
        return Vec::new();
    }
    if !text.contains('\n') {
        // One line: a short first sentence is the title; a long text gets
        // its first sentence as a paragraph of its own.
        return match first_sentence(text) {
            Some((head, rest)) if head.chars().count() <= TITLE_CHARS => {
                vec![
                    Block::Title(head.to_owned()),
                    Block::Paragraph(rest.to_owned()),
                ]
            }
            Some((head, rest)) if text.chars().count() > LONG_CHARS => vec![
                Block::Paragraph(head.to_owned()),
                Block::Paragraph(rest.to_owned()),
            ],
            _ => vec![Block::Paragraph(text.to_owned())],
        };
    }
    let mut out = Vec::new();
    let paragraphs: Vec<&str> = text
        .split("\n\n")
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    for (index, paragraph) in paragraphs.iter().enumerate() {
        let one_line = !paragraph.contains('\n');
        if index == 0
            && paragraphs.len() > 1
            && one_line
            && !paragraph.starts_with("- ")
            && paragraph.chars().count() <= TITLE_CHARS
        {
            out.push(Block::Title(paragraph.to_string()));
            continue;
        }
        // Lines of a paragraph: bullets on their own, other lines run on.
        let mut running = String::new();
        for line in paragraph.lines().map(str::trim) {
            if let Some(item) = line.strip_prefix("- ") {
                if !running.is_empty() {
                    out.push(Block::Paragraph(std::mem::take(&mut running)));
                }
                out.push(Block::Bullet(item.trim().to_owned()));
            } else if let (Some(Block::Bullet(item)), true) = (out.last_mut(), running.is_empty()) {
                // A bullet's continuation line.
                if line.is_empty() {
                    continue;
                }
                item.push(' ');
                item.push_str(line);
            } else {
                if !running.is_empty() {
                    running.push(' ');
                }
                running.push_str(line);
            }
        }
        if !running.is_empty() {
            out.push(Block::Paragraph(running));
        }
    }
    out
}

/// The first sentence of `text` and the rest, when there is a rest.
fn first_sentence(text: &str) -> Option<(&str, &str)> {
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut code = false;
    for (index, &byte) in bytes.iter().enumerate() {
        match byte {
            b'`' => code = !code,
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'.' | b'?' | b'!' if depth <= 0 && !code => {
                let next = &text[index + 1..];
                let Some(after) = next.strip_prefix(' ') else {
                    continue;
                };
                let starts_sentence = after
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_uppercase() || c.is_ascii_digit() || c == '`');
                let head = &text[..=index];
                if !starts_sentence || abbreviation(head) {
                    continue;
                }
                let rest = after.trim();
                return (!rest.is_empty()).then_some((head, rest));
            }
            _ => {}
        }
    }
    None
}

/// Does `head` end with an abbreviation's dot rather than a sentence's?
fn abbreviation(head: &str) -> bool {
    let word = head
        .trim_end_matches('.')
        .rsplit(|c: char| c.is_whitespace() || c == '(')
        .next()
        .unwrap_or("");
    matches!(
        word.to_ascii_lowercase().as_str(),
        "e.g" | "i.e" | "etc" | "vs" | "approx" | "no" | "cf"
    ) || word.len() == 1
}

/// A paragraph's text with `code` and **bold** spans.
fn inline(ui: &egui::Ui, text: &str) -> LayoutJob {
    let body = egui::TextStyle::Body.resolve(ui.style());
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let color = ui.visuals().text_color();
    let plain = TextFormat::simple(body.clone(), color);
    let bold = TextFormat::simple(theme::bold_font(ui), ui.visuals().strong_text_color());
    let code = TextFormat {
        background: ui.visuals().code_bg_color,
        ..TextFormat::simple(mono, color)
    };
    let mut job = LayoutJob::default();
    let mut rest = text;
    while !rest.is_empty() {
        let next_code = rest.find('`');
        let next_bold = rest.find("**");
        match (next_code, next_bold) {
            (Some(at), bold_at) if bold_at.is_none_or(|b| at < b) => {
                let after = &rest[at + 1..];
                match after.find('`') {
                    Some(end) => {
                        job.append(&rest[..at], 0.0, plain.clone());
                        job.append(&after[..end], 0.0, code.clone());
                        rest = &after[end + 1..];
                    }
                    None => {
                        job.append(rest, 0.0, plain.clone());
                        rest = "";
                    }
                }
            }
            (_, Some(at)) => {
                let after = &rest[at + 2..];
                match after.find("**") {
                    Some(end) => {
                        job.append(&rest[..at], 0.0, plain.clone());
                        job.append(&after[..end], 0.0, bold.clone());
                        rest = &after[end + 2..];
                    }
                    None => {
                        job.append(rest, 0.0, plain.clone());
                        rest = "";
                    }
                }
            }
            _ => {
                job.append(rest, 0.0, plain.clone());
                rest = "";
            }
        }
    }
    job
}

// SPDX-License-Identifier: GPL-3.0-only
//! The Raw view's text: the terminal byte stream with every escape made
//! visible, and a note of which escapes can hide output.
use std::collections::VecDeque;

#[cfg(test)]
mod tests;

/// Lines kept, like the Formatted view's scrollback.
const MAX_LINES: usize = super::SCROLLBACK;
/// Characters kept in all lines together.
const MAX_CHARS: usize = 16 * 1024 * 1024;
/// A longer line is split here, so one unbroken stream stays bounded.
const LINE_MAX: usize = 4096;
/// Bytes of an escape sequence examined to classify it.
const SEQ_MAX: usize = 64;
/// An escape sequence that never ends is closed after this many characters.
const SEQ_LIMIT: usize = 4096;

/// What an escape sequence does to what is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Mark {
    /// A recognized sequence that cannot hide output (colors, modes).
    Plain,
    /// Cursor moves, scrolling, save and restore: later text lands on top
    /// of what is already shown.
    Cursor,
    /// Erase of lines, the screen or characters, and terminal reset.
    Erase,
    /// A carriage return not followed by a line feed, or a backspace:
    /// later text overwrites the line.
    Overwrite,
    /// SGR 8: text drawn but not visible.
    Conceal,
    /// Operating system commands and other control strings: title,
    /// hyperlinks and the like.
    Osc,
    /// OSC 52: the program writes to or reads the clipboard.
    Clipboard,
    /// Switching to or from the alternate screen.
    AltScreen,
}

impl Mark {
    /// Whether this can make output disappear or change what is shown.
    pub(super) fn hides(self) -> bool {
        self != Mark::Plain
    }

    /// Short plain-text explanation, for the hover on a highlighted escape.
    pub(super) fn hint(self) -> &'static str {
        match self {
            Mark::Plain => "Escape sequence that does not hide output",
            Mark::Cursor => "Moves the cursor: later text can land on top of earlier output",
            Mark::Erase => "Erases text that was shown",
            Mark::Overwrite => "Returns to the start of the line: later text overwrites it",
            Mark::Conceal => "Text after this is drawn but not visible (SGR 8)",
            Mark::Osc => "Control string (title, hyperlink): not drawn as text",
            Mark::Clipboard => "Sets or reads the clipboard (OSC 52)",
            Mark::AltScreen => "Switches to or from the alternate screen",
        }
    }
}

/// One marked stretch of a line, in characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Span {
    pub start: usize,
    pub end: usize,
    pub mark: Mark,
}

#[derive(Clone, Debug, Default)]
pub(super) struct RawLine {
    pub text: String,
    /// Characters in `text`.
    pub chars: usize,
    pub spans: Vec<Span>,
    /// A line the viewer added, not terminal output.
    pub note: bool,
}

#[derive(Clone, Debug)]
enum Seq {
    /// After ESC.
    Esc {
        start: usize,
    },
    Csi {
        start: usize,
        body: Vec<u8>,
    },
    /// An OSC or other control string; `body` keeps its first bytes.
    Str {
        start: usize,
        osc: bool,
        body: Vec<u8>,
        escape: bool,
    },
}

/// The escaped stream, line by line. The last line is the one still open.
#[derive(Debug)]
pub(super) struct RawLog {
    lines: VecDeque<RawLine>,
    chars: usize,
    /// Lines dropped from the front so far; shifts selections.
    evicted: usize,
    /// Changes whenever the text does.
    generation: u64,
    seq: Option<Seq>,
    /// A UTF-8 sequence cut by the end of a chunk.
    pending: Vec<u8>,
    /// Start (in the open line) of a carriage return waiting for its next byte.
    cr: Option<usize>,
}

impl Default for RawLog {
    fn default() -> Self {
        Self {
            lines: VecDeque::from([RawLine::default()]),
            chars: 0,
            evicted: 0,
            generation: 0,
            seq: None,
            pending: Vec::new(),
            cr: None,
        }
    }
}

impl RawLog {
    pub(super) fn lines(&self) -> &VecDeque<RawLine> {
        &self.lines
    }

    pub(super) fn evicted(&self) -> usize {
        self.evicted
    }

    pub(super) fn generation(&self) -> u64 {
        self.generation
    }

    /// Appends a line of viewer text that is not part of the stream.
    pub(super) fn note(&mut self, text: &str) {
        self.settle_cr();
        self.abort_seq();
        self.flush_pending();
        if self.last().chars > 0 {
            self.break_line();
        }
        for ch in text.chars() {
            self.push_char(ch);
        }
        self.last_mut().note = true;
        self.break_line();
    }

    pub(super) fn push(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.generation = self.generation.wrapping_add(1);
        for &byte in bytes {
            self.byte(byte);
        }
    }

    fn last(&self) -> &RawLine {
        self.lines.back().expect("an open line always exists")
    }

    fn last_mut(&mut self) -> &mut RawLine {
        self.lines.back_mut().expect("an open line always exists")
    }

    fn byte(&mut self, byte: u8) {
        if !self.pending.is_empty() {
            if (0x80..0xc0).contains(&byte) {
                self.pending.push(byte);
                if self.pending.len() == utf8_len(self.pending[0]) {
                    self.finish_pending();
                }
                return;
            }
            self.flush_pending();
        }
        if byte >= 0xc2 && utf8_len(byte) > 1 {
            self.settle_cr();
            self.pending.push(byte);
            return;
        }
        if byte >= 0x80 {
            self.settle_cr();
            self.invalid(byte);
            return;
        }
        self.ascii(byte);
    }

    fn finish_pending(&mut self) {
        let bytes = std::mem::take(&mut self.pending);
        match std::str::from_utf8(&bytes) {
            Ok(text) => {
                for ch in text.chars() {
                    self.character(ch);
                }
            }
            Err(_) => {
                for byte in bytes {
                    self.invalid(byte);
                }
            }
        }
    }

    fn flush_pending(&mut self) {
        for byte in std::mem::take(&mut self.pending) {
            self.invalid(byte);
        }
    }

    fn invalid(&mut self, byte: u8) {
        self.abort_seq();
        self.escaped(byte);
    }

    /// A decoded non-ASCII character.
    fn character(&mut self, ch: char) {
        if let Some(Seq::Str { .. }) = self.seq {
            if ch == '\u{9c}' {
                self.emit(&format!("\\u{{{:x}}}", ch as u32));
                self.finish_string();
                return;
            }
            self.push_body(None);
            self.display_char(ch);
            return;
        }
        self.abort_seq();
        self.display_char(ch);
    }

    fn display_char(&mut self, ch: char) {
        if ('\u{80}'..='\u{9f}').contains(&ch) {
            self.emit(&format!("\\u{{{:x}}}", ch as u32));
        } else {
            self.push_char(ch);
        }
    }

    fn ascii(&mut self, byte: u8) {
        // A carriage return is an overwrite unless a line feed follows it.
        if byte == b'\n' {
            self.cr = None;
        } else {
            self.settle_cr();
        }
        match self.seq.clone() {
            Some(Seq::Esc { start }) => self.after_esc(byte, start),
            Some(Seq::Csi { start, mut body }) => match byte {
                0x1b => {
                    self.abort_seq();
                    self.begin_esc();
                }
                0x40..=0x7e => {
                    self.emit_ascii(byte);
                    self.seq = None;
                    let mark = classify_csi(&body, byte);
                    self.mark_from(start, mark);
                }
                0x20..=0x3f => {
                    self.emit_ascii(byte);
                    if body.len() < SEQ_MAX {
                        body.push(byte);
                        self.seq = Some(Seq::Csi { start, body });
                    }
                    self.limit(start);
                }
                _ => self.control(byte),
            },
            Some(Seq::Str {
                start,
                osc,
                body,
                escape,
            }) => {
                if escape {
                    if byte == b'\\' {
                        self.emit("\\\\");
                        self.finish_string();
                    } else {
                        // Not a string terminator: the string ended unfinished and
                        // the ESC before this byte began a new sequence.
                        let esc = self.last().chars.saturating_sub(2);
                        self.finish_string();
                        self.seq = Some(Seq::Esc { start: esc });
                        self.after_esc(byte, esc);
                    }
                } else if byte == 0x07 {
                    self.emit("\\a");
                    self.finish_string();
                } else if byte == 0x1b {
                    self.emit("\\e");
                    self.seq = Some(Seq::Str {
                        start,
                        osc,
                        body,
                        escape: true,
                    });
                } else if byte == b'\n' {
                    self.control(byte);
                } else {
                    self.push_body(Some(byte));
                    self.escaped_or_plain(byte);
                    self.limit(start);
                }
            }
            None => match byte {
                0x1b => self.begin_esc(),
                _ => self.control(byte),
            },
        }
    }

    fn begin_esc(&mut self) {
        let start = self.last().chars;
        self.emit("\\e");
        self.seq = Some(Seq::Esc { start });
    }

    fn after_esc(&mut self, byte: u8, start: usize) {
        match byte {
            b'[' => {
                self.emit_ascii(byte);
                self.seq = Some(Seq::Csi {
                    start,
                    body: Vec::new(),
                });
            }
            b']' | b'P' | b'X' | b'^' | b'_' => {
                self.emit_ascii(byte);
                self.seq = Some(Seq::Str {
                    start,
                    osc: byte == b']',
                    body: Vec::new(),
                    escape: false,
                });
            }
            0x1b => {
                // ESC ESC: the first one is dropped, the second begins anew.
                self.seq = None;
                self.begin_esc();
            }
            0x20..=0x2f => self.emit_ascii(byte),
            0x30..=0x7e => {
                self.emit_ascii(byte);
                self.seq = None;
                let mark = match byte {
                    b'c' => Mark::Erase,
                    b'7' | b'8' | b'D' | b'E' | b'M' => Mark::Cursor,
                    _ => Mark::Plain,
                };
                self.mark_from(start, mark);
            }
            _ => {
                self.seq = None;
                self.control(byte);
            }
        }
    }

    fn finish_string(&mut self) {
        let Some(Seq::Str {
            start, osc, body, ..
        }) = self.seq.take()
        else {
            return;
        };
        let number: String = body
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .map(|&byte| byte as char)
            .collect();
        let mark = if osc && number == "52" {
            Mark::Clipboard
        } else {
            Mark::Osc
        };
        self.mark_from(start, mark);
    }

    fn push_body(&mut self, byte: Option<u8>) {
        if let Some(Seq::Str { body, .. }) = &mut self.seq {
            if body.len() < SEQ_MAX {
                body.push(byte.unwrap_or(b'?'));
            }
        }
    }

    /// Closes a sequence that has gone on far too long.
    fn limit(&mut self, start: usize) {
        if self.last().chars.saturating_sub(start) < SEQ_LIMIT {
            return;
        }
        match self.seq.take() {
            Some(Seq::Str { osc, body, .. }) => {
                self.seq = Some(Seq::Str {
                    start,
                    osc,
                    body,
                    escape: false,
                });
                self.finish_string();
            }
            Some(Seq::Csi { .. }) => self.mark_from(start, Mark::Plain),
            other => self.seq = other,
        }
    }

    fn abort_seq(&mut self) {
        if let Some(seq) = self.seq.take() {
            match seq {
                Seq::Str { start, .. } => self.mark_from(start, Mark::Osc),
                Seq::Esc { start } | Seq::Csi { start, .. } => self.mark_from(start, Mark::Plain),
            }
        }
    }

    /// A control byte outside any sequence, or one that ends it.
    fn control(&mut self, byte: u8) {
        if !matches!(self.seq, Some(Seq::Str { .. })) {
            self.abort_seq();
        }
        match byte {
            b'\n' => {
                self.emit("\\n");
                self.break_line();
            }
            b'\r' => {
                let start = self.last().chars;
                self.emit("\\r");
                self.cr = Some(start);
            }
            0x08 => {
                let start = self.last().chars;
                self.emit("\\b");
                self.mark_range(start, start + 2, Mark::Overwrite);
            }
            0x20..=0x7e => self.emit_ascii(byte),
            _ => self.escaped(byte),
        }
    }

    fn escaped_or_plain(&mut self, byte: u8) {
        if byte == b'\\' {
            self.emit("\\\\");
        } else if byte.is_ascii_graphic() || byte == b' ' {
            self.emit_ascii(byte);
        } else {
            self.escaped(byte);
        }
    }

    fn escaped(&mut self, byte: u8) {
        let text = match byte {
            0x07 => "\\a".to_string(),
            0x09 => "\\t".to_string(),
            0x0b => "\\v".to_string(),
            0x0c => "\\f".to_string(),
            0x1b => "\\e".to_string(),
            _ => format!("\\x{byte:02x}"),
        };
        self.emit(&text);
    }

    fn emit_ascii(&mut self, byte: u8) {
        if byte == b'\\' {
            self.emit("\\\\");
        } else if byte.is_ascii_graphic() || byte == b' ' {
            self.push_char(byte as char);
        } else {
            self.escaped(byte);
        }
    }

    /// A carriage return that no line feed followed was an overwrite.
    fn settle_cr(&mut self) {
        if let Some(start) = self.cr.take() {
            self.mark_range(start, start + 2, Mark::Overwrite);
        }
    }

    fn emit(&mut self, text: &str) {
        for ch in text.chars() {
            self.push_char(ch);
        }
    }

    fn push_char(&mut self, ch: char) {
        if self.last().chars >= LINE_MAX {
            self.break_line();
        }
        let line = self.last_mut();
        line.text.push(ch);
        line.chars += 1;
        self.chars += 1;
    }

    fn break_line(&mut self) {
        // The next line starts with nothing pending from this one.
        if let Some(Seq::Esc { start } | Seq::Csi { start, .. } | Seq::Str { start, .. }) =
            &mut self.seq
        {
            *start = 0;
        }
        self.cr = self.cr.map(|_| 0);
        self.lines.push_back(RawLine::default());
        while self.lines.len() > MAX_LINES || (self.chars > MAX_CHARS && self.lines.len() > 1) {
            if let Some(line) = self.lines.pop_front() {
                self.chars -= line.chars;
                self.evicted += 1;
            }
        }
    }

    fn mark_from(&mut self, start: usize, mark: Mark) {
        let end = self.last().chars;
        self.mark_range(start, end, mark);
    }

    fn mark_range(&mut self, start: usize, end: usize, mark: Mark) {
        let end = end.min(self.last().chars);
        if start < end {
            self.last_mut().spans.push(Span { start, end, mark });
        }
    }
}

fn utf8_len(lead: u8) -> usize {
    match lead {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => 1,
    }
}

/// What the CSI sequence with `body` (parameters and intermediates) and
/// final byte `last` does to the screen.
fn classify_csi(body: &[u8], last: u8) -> Mark {
    let private = body.first() == Some(&b'?');
    let params = std::str::from_utf8(body).unwrap_or("");
    match last {
        b'h' | b'l' if private => {
            let alternate = params[1..]
                .split(';')
                .any(|param| matches!(param, "47" | "1047" | "1049"));
            if alternate {
                Mark::AltScreen
            } else {
                Mark::Plain
            }
        }
        _ if body.iter().any(|byte| (0x20..=0x2f).contains(byte)) || private => Mark::Plain,
        b'A'..=b'H' | b'f' | b'd' | b's' | b'u' | b'S' | b'T' => Mark::Cursor,
        b'J' | b'K' | b'X' | b'P' | b'M' => Mark::Erase,
        b'm' if sgr_conceals(params) => Mark::Conceal,
        _ => Mark::Plain,
    }
}

/// Whether SGR `params` include 8 as an attribute, not as a color index.
fn sgr_conceals(params: &str) -> bool {
    let mut skip = 0;
    let mut extended = false;
    for token in params.split(';') {
        if skip > 0 {
            skip -= 1;
            continue;
        }
        if extended {
            extended = false;
            match token {
                "5" => skip = 1,
                "2" => skip = 3,
                _ => {}
            }
            continue;
        }
        // Colon-separated sub-parameters belong to one attribute.
        let head = token.split(':').next().unwrap_or("");
        match head {
            "38" | "48" | "58" => {
                if !token.contains(':') {
                    extended = true;
                }
            }
            "8" if !token.contains(':') => return true,
            _ => {}
        }
    }
    false
}

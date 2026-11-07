// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The three standard PDF fonts the report uses (Helvetica, Helvetica-Bold,
//! Courier), their character widths and the WinAnsi encoding. No font file is
//! embedded, so no font licence applies and nothing is fetched: every PDF
//! reader has these fonts. A character WinAnsi lacks prints as `?`.

/// A font of the document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Font {
    Regular,
    Bold,
    Oblique,
    Mono,
}

impl Font {
    /// The resource name used in the content streams.
    pub(super) fn resource(self) -> &'static str {
        match self {
            Self::Regular => "F1",
            Self::Bold => "F2",
            Self::Oblique => "F3",
            Self::Mono => "F4",
        }
    }

    /// The base-14 font name.
    pub(super) fn base_name(self) -> &'static str {
        match self {
            Self::Regular => "Helvetica",
            Self::Bold => "Helvetica-Bold",
            Self::Oblique => "Helvetica-Oblique",
            Self::Mono => "Courier",
        }
    }
}

/// Helvetica widths of the printable ASCII range (0x20 to 0x7e), in 1/1000 em.
const HELVETICA: [u16; 95] = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278,
    278, // space to /
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, // 0 to 9
    278, 278, 584, 584, 584, 556, 1015, // : to @
    667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667,
    611, 722, 667, 944, 667, 667, 611, // A to Z
    278, 278, 278, 469, 556, 333, // [ to `
    556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500,
    278, 556, 500, 722, 500, 500, 500, // a to z
    334, 260, 334, 584, // { to ~
];

/// Helvetica-Bold widths of the same range.
const HELVETICA_BOLD: [u16; 95] = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, //
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, //
    333, 333, 584, 584, 584, 611, 975, //
    722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667,
    611, 722, 667, 944, 667, 667, 611, //
    333, 278, 333, 584, 556, 333, //
    556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556,
    333, 611, 556, 778, 556, 556, 500, //
    389, 280, 389, 584,
];

/// The WinAnsi code of `c`, or `None` for a character it lacks.
pub(super) fn winansi(c: char) -> Option<u8> {
    match c as u32 {
        0x20..=0x7e => Some(c as u8),
        0xa0..=0xff => Some(c as u8),
        0x20ac => Some(0x80),
        0x2018 => Some(0x91),
        0x2019 => Some(0x92),
        0x201c => Some(0x93),
        0x201d => Some(0x94),
        0x2022 => Some(0x95),
        0x2013 => Some(0x96),
        0x2014 => Some(0x97),
        0x2026 => Some(0x85),
        0x2122 => Some(0x99),
        _ => None,
    }
}

/// Characters the base-14 fonts lack that have a plain ASCII spelling: the
/// arrow of a lifecycle cell prints as `->`, not `?`.
fn ascii_spelling(c: char) -> Option<&'static str> {
    Some(match c {
        '\u{2192}' | '\u{21d2}' | '\u{2794}' | '\u{279c}' => "->",
        '\u{2190}' | '\u{21d0}' => "<-",
        '\u{2194}' => "<->",
        '\u{2248}' => "~",
        '\u{2264}' => "<=",
        '\u{2265}' => ">=",
        '\u{2260}' => "!=",
        '\u{2212}' | '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2015}' => "-",
        '\u{2032}' => "'",
        '\u{2033}' => "\"",
        '\u{2713}' | '\u{2714}' => "ok",
        '\u{2717}' | '\u{2718}' => "x",
        '\u{25cf}' | '\u{25aa}' => "*",
        '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' => "",
        _ => return None,
    })
}

/// The codes `c` is drawn with: its WinAnsi code, its ASCII spelling, or `?`.
fn codes(c: char) -> Vec<u8> {
    match c {
        '\t' | '\n' | '\r' => vec![b' '],
        c => match winansi(c) {
            Some(code) => vec![code],
            None => match ascii_spelling(c) {
                Some(text) => text.bytes().collect(),
                None => vec![b'?'],
            },
        },
    }
}

/// The bytes `text` is drawn with: WinAnsi, an ASCII spelling for the few
/// symbols that have one (`->` for an arrow), `?` for what the font lacks,
/// spaces for tabs and line ends.
pub(super) fn encode(text: &str) -> Vec<u8> {
    text.chars().flat_map(codes).collect()
}

/// The width of one WinAnsi code in `font`, in 1/1000 em.
fn code_width(font: Font, code: u8) -> u16 {
    match font {
        Font::Mono => 600,
        Font::Regular | Font::Oblique => match code {
            0x20..=0x7e => HELVETICA[usize::from(code - 0x20)],
            _ => 556,
        },
        Font::Bold => match code {
            0x20..=0x7e => HELVETICA_BOLD[usize::from(code - 0x20)],
            _ => 611,
        },
    }
}

/// The width of `text` in points at `size`.
pub(super) fn width(font: Font, size: f32, text: &str) -> f32 {
    let units: u32 = encode(text)
        .iter()
        .map(|&code| u32::from(code_width(font, code)))
        .sum();
    units as f32 * size / 1000.0
}

/// The width of one character.
pub(super) fn char_width(font: Font, size: f32, c: char) -> f32 {
    codes(c)
        .into_iter()
        .map(|code| f32::from(code_width(font, code)) * size / 1000.0)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_follow_the_font_tables() {
        // "Hello" in Helvetica: 722 + 556 + 222 + 222 + 556.
        assert!((width(Font::Regular, 10.0, "Hello") - 22.78).abs() < 0.01);
        assert_eq!(width(Font::Mono, 10.0, "abcd"), 24.0);
        assert_eq!(HELVETICA.len(), 95);
        assert_eq!(HELVETICA_BOLD.len(), 95);
        assert_eq!(encode("a\u{4e2d}\u{e9}"), vec![b'a', b'?', 0xe9]);
    }

    #[test]
    fn an_arrow_prints_as_an_ascii_arrow_not_a_question_mark() {
        assert_eq!(encode("created \u{2192} deleted"), b"created -> deleted");
        assert_eq!(encode("a \u{2248} b \u{2264} c"), b"a ~ b <= c");
        assert!(
            (char_width(Font::Mono, 10.0, '\u{2192}') - 12.0).abs() < 0.01,
            "its width is the two characters it prints"
        );
    }
}

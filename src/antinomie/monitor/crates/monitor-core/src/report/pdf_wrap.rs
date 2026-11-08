// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Breaking a cell's spans into lines for the PDF, keeping where each link
//! lands so a link annotation can cover exactly its text.
use super::page::Span;
use super::pdf_font::{Font, char_width, width};

/// A run of text on a line: where it starts (from the line's left edge), how
/// wide it is, and the link it is, if any.
#[derive(Clone, Debug, PartialEq)]
pub(super) struct Frag {
    pub text: String,
    pub x: f32,
    pub w: f32,
    pub href: Option<String>,
}

/// A word, as pieces of the spans it is made of.
type Word = Vec<(String, Option<String>)>;

enum Token {
    Word(Word),
    /// A line break in the text.
    Break,
}

fn tokens(spans: &[Span]) -> Vec<Token> {
    let mut out = Vec::new();
    let mut word: Word = Vec::new();
    let push_char = |word: &mut Word, c: char, href: &Option<String>| match word.last_mut() {
        Some((text, last)) if last == href => text.push(c),
        _ => word.push((c.to_string(), href.clone())),
    };
    for span in spans {
        for c in span.text.chars() {
            match c {
                ' ' => {
                    if !word.is_empty() {
                        out.push(Token::Word(std::mem::take(&mut word)));
                    }
                }
                '\n' => {
                    if !word.is_empty() {
                        out.push(Token::Word(std::mem::take(&mut word)));
                    }
                    out.push(Token::Break);
                }
                c => push_char(&mut word, c, &span.href),
            }
        }
    }
    if !word.is_empty() {
        out.push(Token::Word(word));
    }
    out
}

/// One line being filled.
#[derive(Default)]
struct Line {
    pieces: Vec<(String, Option<String>)>,
    w: f32,
}

impl Line {
    fn push(&mut self, text: &str, href: &Option<String>, w: f32) {
        match self.pieces.last_mut() {
            Some((last, link)) if link == href => last.push_str(text),
            _ => self.pieces.push((text.to_owned(), href.clone())),
        }
        self.w += w;
    }

    fn is_empty(&self) -> bool {
        self.pieces.is_empty()
    }

    fn frags(self, font: Font, size: f32) -> Vec<Frag> {
        let mut x = 0.0;
        self.pieces
            .into_iter()
            .map(|(text, href)| {
                let w = width(font, size, &text);
                let frag = Frag { text, x, w, href };
                x += w;
                frag
            })
            .collect()
    }
}

/// `spans` broken into lines no wider than `limit`; a word wider than the line
/// is broken at a character. `max_lines` cuts the result with `...`. A space
/// between two pieces of one link belongs to the link.
pub(super) fn wrap_spans(
    spans: &[Span],
    font: Font,
    size: f32,
    limit: f32,
    max_lines: usize,
) -> Vec<Vec<Frag>> {
    let mut lines: Vec<Line> = Vec::new();
    let mut line = Line::default();
    let space_w = char_width(font, size, ' ');
    for token in tokens(spans) {
        let word = match token {
            Token::Break => {
                lines.push(std::mem::take(&mut line));
                continue;
            }
            Token::Word(word) => word,
        };
        let word_w: f32 = word.iter().map(|(t, _)| width(font, size, t)).sum();
        let space = if line.is_empty() { 0.0 } else { space_w };
        if line.w + space + word_w <= limit {
            if !line.is_empty() {
                let before = line.pieces.last().and_then(|(_, h)| h.clone());
                let after = word.first().and_then(|(_, h)| h.clone());
                let href = if before == after { before } else { None };
                line.push(" ", &href, space_w);
            }
            for (text, href) in &word {
                line.push(text, href, width(font, size, text));
            }
            continue;
        }
        if !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        if word_w <= limit {
            for (text, href) in &word {
                line.push(text, href, width(font, size, text));
            }
            continue;
        }
        // Longer than a line: break it after a `_`, `/`, `.`, `-` or `:` (a
        // rule name, a path), and only a part with none at a character.
        for (text, href) in &word {
            for part in text.split_inclusive(['_', '/', '.', '-', ':']) {
                let part_w = width(font, size, part);
                if line.w + part_w <= limit {
                    line.push(part, href, part_w);
                    continue;
                }
                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                }
                if part_w <= limit {
                    line.push(part, href, part_w);
                    continue;
                }
                for c in part.chars() {
                    let cw = char_width(font, size, c);
                    if line.w + cw > limit && !line.is_empty() {
                        lines.push(std::mem::take(&mut line));
                    }
                    line.push(&c.to_string(), href, cw);
                }
            }
        }
    }
    lines.push(line);
    let mut out: Vec<Vec<Frag>> = lines.into_iter().map(|l| l.frags(font, size)).collect();
    if out.len() > max_lines {
        out.truncate(max_lines);
        if let Some(last) = out.last_mut() {
            let x = last.last().map_or(0.0, |f| f.x + f.w);
            last.push(Frag {
                text: " ...".into(),
                x,
                w: width(font, size, " ..."),
                href: None,
            });
        }
    }
    out
}

/// `text` broken into lines no wider than `limit`, as plain strings.
pub(super) fn wrap(text: &str, font: Font, size: f32, limit: f32, max_lines: usize) -> Vec<String> {
    wrap_spans(&[Span::plain(text)], font, size, limit, max_lines)
        .into_iter()
        .map(|line| line.into_iter().map(|frag| frag.text).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_keeps_its_place_on_the_line() {
        let spans = [
            Span::plain("seen in "),
            Span::to("cat (1465)", "proc-1465"),
            Span::plain(" and more"),
        ];
        let lines = wrap_spans(&spans, Font::Regular, 8.0, 1000.0, 5);
        assert_eq!(lines.len(), 1);
        let link: Vec<&Frag> = lines[0].iter().filter(|f| f.href.is_some()).collect();
        assert_eq!(link.len(), 1, "{lines:?}");
        assert_eq!(link[0].text, "cat (1465)", "the inner space is the link's");
        let before = width(Font::Regular, 8.0, "seen in ");
        assert!((link[0].x - before).abs() < 0.01);
    }

    #[test]
    fn a_link_that_wraps_is_on_both_lines() {
        let spans = [Span::to("alpha beta gamma delta", "x")];
        let limit = width(Font::Regular, 8.0, "alpha beta") + 0.1;
        let lines = wrap_spans(&spans, Font::Regular, 8.0, limit, 5);
        assert!(lines.len() >= 2, "{lines:?}");
        assert!(lines.iter().all(|l| l.iter().all(|f| f.href.is_some())));
    }

    #[test]
    fn a_long_identifier_breaks_after_its_separators() {
        let rule = "SIGNATURE_BASE_APT_MAL_LNX_Redmenshen_Bpfdoor_Controller_May22_1";
        let limit = width(Font::Regular, 7.0, "SIGNATURE_BASE_APT_MAL_LNX_") + 0.1;
        let lines = wrap(rule, Font::Regular, 7.0, limit, 9);
        assert_eq!(lines[0], "SIGNATURE_BASE_APT_MAL_LNX_", "{lines:?}");
        assert!(
            lines
                .iter()
                .all(|line| line.ends_with('_') || rule.ends_with(line.as_str()))
        );
        assert_eq!(lines.concat(), rule);
    }

    #[test]
    fn plain_wrap_breaks_long_words_and_keeps_empty_lines() {
        assert_eq!(wrap("a\n\nb", Font::Regular, 8.0, 100.0, 9), ["a", "", "b"]);
        let long = "x".repeat(200);
        let lines = wrap(&long, Font::Mono, 8.0, 100.0, 3);
        assert_eq!(lines.len(), 3);
        assert!(lines[2].ends_with(" ..."));
    }
}

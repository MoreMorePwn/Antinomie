// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The Markdown form of the sample report: the same document as the HTML,
//! as GitHub-flavoured Markdown (pipe tables). Text is escaped so a sample
//! name or a note cannot become markup; hashes and paths sit in code spans.
use super::super::layout::{Block, Document};

/// A hash, a path or an address reads better as code.
fn mono(text: &str) -> bool {
    text.starts_with('/')
        || text.len() >= 32 && text.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

/// `text` as one line of Markdown that cannot start markup, a table cell
/// break or an HTML tag.
fn inline(text: &str) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if mono(&flat) {
        return format!("`{}`", flat.replace('`', "'").replace('|', "\\|"));
    }
    let mut out = String::with_capacity(flat.len());
    let chars: Vec<char> = flat.chars().collect();
    for (at, &c) in chars.iter().enumerate() {
        match c {
            // `[.]` of a defanged address is not a link; `](` would end one.
            ']' if chars.get(at + 1) != Some(&'(') => out.push(c),
            '[' => out.push(c),
            '\\' | '`' | '*' | '_' | ']' | '|' | '~' => {
                out.push('\\');
                out.push(c);
            }
            // A bare `>` and `&` are plain text except where `&` would start
            // an entity; `<` is the one that can open a tag.
            '<' => out.push_str("&lt;"),
            '&' if entity_follows(&chars[at + 1..]) => out.push_str("\\&"),
            c => out.push(c),
        }
    }
    out
}

/// Whether `rest` (the text after a `&`) spells an entity: `amp;`, `#38;`.
fn entity_follows(rest: &[char]) -> bool {
    let name: String = rest
        .iter()
        .take_while(|c| c.is_ascii_alphanumeric() || **c == '#')
        .collect();
    !name.is_empty() && rest.get(name.chars().count()) == Some(&';')
}

/// Whether a line, as it would start a block, reads as markup: a heading
/// (`#` and a space), a quote (`>`), a list item (`-`, `+`, `*` and a space), an
/// ordered one (`1.` or `1)` and a space), a rule or a setext underline.
fn block_marker(line: &str) -> bool {
    let first = line.chars().next();
    let followed_by_space = |at: usize| matches!(line.chars().nth(at), None | Some(' '));
    match first {
        Some('#') => {
            line.trim_start_matches('#').starts_with(' ') || line.chars().all(|c| c == '#')
        }
        Some('>') => true,
        Some('-' | '+') => followed_by_space(1) || line.chars().all(|c| matches!(c, '-' | '=')),
        Some('=') => line.chars().all(|c| c == '='),
        Some(c) if c.is_ascii_digit() => {
            let digits = line.chars().take_while(char::is_ascii_digit).count();
            digits <= 9
                && matches!(line.chars().nth(digits), Some('.' | ')'))
                && followed_by_space(digits + 1)
        }
        _ => false,
    }
}

/// A paragraph that may span lines: each line escaped, a leading `#`, `>`,
/// `-` or digit-dot not read as a block marker.
fn paragraph(text: &str) -> String {
    text.lines()
        .map(|line| {
            let line = inline(line.trim_end());
            if !block_marker(&line) {
                return line;
            }
            // Escape the marker's own punctuation, which is what CommonMark
            // allows: `1\. text`, `\# text`, `\> text`.
            if line.starts_with(|c: char| c.is_ascii_digit()) {
                let digits = line.chars().take_while(char::is_ascii_digit).count();
                format!("{}\\{}", &line[..digits], &line[digits..])
            } else {
                format!("\\{line}")
            }
        })
        .collect::<Vec<_>>()
        .join("  \n")
}

fn row(cells: &[String]) -> String {
    format!(
        "| {} |",
        cells
            .iter()
            .map(|cell| {
                let text = inline(cell);
                if text.is_empty() { " ".into() } else { text }
            })
            .collect::<Vec<_>>()
            .join(" | ")
    )
}

/// The report as Markdown.
pub fn render(document: &Document) -> String {
    let mut out = format!(
        "# {}\n\n{}\n\n",
        inline(&document.title),
        inline(&document.subtitle)
    );
    out.push_str("Contents: ");
    out.push_str(
        &document
            .sections
            .iter()
            .map(|s| format!("[{}](#{})", inline(&s.title), anchor(&s.title)))
            .collect::<Vec<_>>()
            .join(" - "),
    );
    out.push_str("\n\n");
    for section in &document.sections {
        out.push_str(&format!("## {}\n\n", inline(&section.title)));
        for block in &section.blocks {
            match block {
                Block::Paragraph(text) => out.push_str(&format!("{}\n\n", paragraph(text))),
                Block::Note(text) => {
                    out.push_str(&format!("*{}*\n\n", paragraph(text).replace('\n', " ")))
                }
                Block::Sub(text) => out.push_str(&format!("### {}\n\n", inline(text))),
                Block::List(items) => {
                    for item in items {
                        out.push_str(&format!("- {}\n", inline(item)));
                    }
                    out.push('\n');
                }
                Block::Facts(facts) => {
                    out.push_str("| Field | Value |\n| --- | --- |\n");
                    for (name, value) in facts {
                        out.push_str(&row(&[name.clone(), value.clone()]));
                        out.push('\n');
                    }
                    out.push('\n');
                }
                Block::Table(table) => {
                    out.push_str(&row(&table.columns));
                    out.push('\n');
                    out.push_str(&format!("|{}\n", " --- |".repeat(table.columns.len())));
                    for cells in &table.rows {
                        out.push_str(&row(cells));
                        out.push('\n');
                    }
                    out.push('\n');
                }
            }
        }
    }
    out
}

/// GitHub's heading anchor.
fn anchor(title: &str) -> String {
    title
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            c if c.is_alphanumeric() || c == '-' => Some(c),
            ' ' => Some('-'),
            _ => None,
        })
        .collect()
}

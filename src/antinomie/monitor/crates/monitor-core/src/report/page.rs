// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The page model the HTML, PDF and Markdown writers draw: a title, then
//! sections of paragraphs, fact lists, tables and notes. A table cell is a
//! run of [`Span`]s, each optionally a link, and may carry an anchor id, so
//! one model gives every format its row anchors and cross-links.
//!
//! An internal link is `#<id>`; [`finish`] keeps only the links whose id is
//! in the same document, so no format ever holds a dangling link, and keeps
//! each id once. Any other href is a relative link to another file (the
//! sample report's run reports); the PDF draws it as text.
use std::collections::{BTreeMap, BTreeSet};

/// A piece of text, a link when `href` is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Span {
    pub text: String,
    pub href: Option<String>,
}

impl Span {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            href: None,
        }
    }

    /// A link to the anchor `id` of the same document.
    pub fn to(text: impl Into<String>, id: &str) -> Self {
        Self {
            text: text.into(),
            href: (!id.is_empty()).then(|| format!("#{id}")),
        }
    }

    /// The anchor id an internal link names.
    pub fn target(&self) -> Option<&str> {
        self.href.as_deref().and_then(|href| href.strip_prefix('#'))
    }
}

/// A table cell or a fact's value: spans of text and an optional anchor.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cell {
    pub spans: Vec<Span>,
    /// The anchor this cell is (`proc-1352`): a link elsewhere can jump here.
    pub id: Option<String>,
    /// More anchors on the same cell (a rule's first finding is also `rule-…`).
    pub more_ids: Vec<String>,
}

impl Cell {
    pub fn plain(text: impl Into<String>) -> Self {
        Self {
            spans: vec![Span::plain(text)],
            ..Self::default()
        }
    }

    /// A cell that links to anchor `id`; plain text when `id` is empty.
    pub fn link(text: impl Into<String>, id: &str) -> Self {
        Self {
            spans: vec![Span::to(text, id)],
            ..Self::default()
        }
    }

    pub fn of(spans: Vec<Span>) -> Self {
        Self {
            spans,
            ..Self::default()
        }
    }

    /// This cell, being the anchor `id` (nothing when `id` is empty).
    pub fn with_id(mut self, id: &str) -> Self {
        if !id.is_empty() {
            self.id = Some(id.to_owned());
        }
        self
    }

    /// The cell's whole text.
    pub fn text(&self) -> String {
        self.spans.iter().map(|s| s.text.as_str()).collect()
    }

    /// Every anchor of the cell.
    pub fn ids(&self) -> impl Iterator<Item = &String> {
        self.id.iter().chain(&self.more_ids)
    }

    pub fn has_links(&self) -> bool {
        self.spans.iter().any(|s| s.href.is_some())
    }

    /// Spans with links joined by `separator`, every item a link to its id.
    pub fn list(items: &[(String, String)], separator: &str) -> Self {
        let mut spans = Vec::new();
        for (at, (text, id)) in items.iter().enumerate() {
            if at > 0 {
                spans.push(Span::plain(separator));
            }
            spans.push(Span::to(text.clone(), id));
        }
        Self::of(spans)
    }
}

impl From<String> for Cell {
    fn from(text: String) -> Self {
        Self::plain(text)
    }
}

impl From<&str> for Cell {
    fn from(text: &str) -> Self {
        Self::plain(text)
    }
}

/// One drawn element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Block {
    Paragraph(String),
    /// Name and value pairs; a value may be a hash or path (drawn in monospace).
    Facts(Vec<(String, Cell)>),
    Table(DocTable),
    /// A small heading inside a section (a tab's name), with its anchor;
    /// [`finish`] makes one from the section's and the heading's names when
    /// `id` is empty.
    Sub {
        title: String,
        id: String,
    },
    /// A remark in a quieter style: what is missing or cut.
    Note(String),
}

impl Block {
    /// A sub-heading whose anchor [`finish`] chooses.
    pub fn sub(title: impl Into<String>) -> Self {
        Self::Sub {
            title: title.into(),
            id: String::new(),
        }
    }

    /// A facts list of plain values.
    pub fn facts(facts: Vec<(String, String)>) -> Self {
        Self::Facts(
            facts
                .into_iter()
                .map(|(name, value)| (name, Cell::plain(value)))
                .collect(),
        )
    }
}

/// A table ready to draw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocTable {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
}

impl DocTable {
    /// A table of plain text cells.
    pub fn plain(columns: Vec<String>, rows: Vec<Vec<String>>) -> Self {
        Self {
            columns,
            rows: rows
                .into_iter()
                .map(|row| row.into_iter().map(Cell::plain).collect())
                .collect(),
        }
    }

    /// The text of every cell, row by row.
    pub fn texts(&self) -> Vec<Vec<String>> {
        self.rows
            .iter()
            .map(|row| row.iter().map(Cell::text).collect())
            .collect()
    }
}

/// A titled part of the document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    /// Anchor and bookmark id.
    pub id: String,
    pub title: String,
    pub blocks: Vec<Block>,
}

/// The whole document.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Document {
    pub title: String,
    pub subtitle: String,
    pub defanged: bool,
    pub sections: Vec<Section>,
    /// What the PDF says of itself and draws on every page.
    pub meta: Meta,
    /// Ids of rows folded into another row: a link to the first goes to the
    /// second (`finding-7` → `finding-3`).
    pub aliases: BTreeMap<String, String>,
}

/// Document metadata for the PDF's info record and its page header and footer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    /// The kind of report (`Antinomie Triage report`).
    pub creator: String,
    pub subject: String,
    pub keywords: String,
    /// The running header of pages after the first.
    pub header: String,
    /// The footer's left part (when it was generated).
    pub footer: String,
}

/// The id of the document's title, the target of "Back to the top".
pub const TOP: &str = "top";

/// `text` as an anchor id: ASCII letters, digits, `.`, `_` and `-`; any other
/// character is `-`. Never empty.
pub fn slug(text: &str) -> String {
    let out: String = text
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    if out.is_empty() { "x".into() } else { out }
}

/// The anchors of the document, in reading order.
pub fn ids(document: &Document) -> Vec<String> {
    let mut out = vec![TOP.to_owned()];
    for section in &document.sections {
        out.push(section.id.clone());
        for block in &section.blocks {
            match block {
                Block::Sub { id, .. } if !id.is_empty() => out.push(id.clone()),
                Block::Table(table) => {
                    for row in &table.rows {
                        for cell in row {
                            out.extend(cell.ids().cloned());
                        }
                    }
                }
                Block::Facts(facts) => {
                    for (_, cell) in facts {
                        out.extend(cell.ids().cloned());
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Every internal link target of the document, in reading order.
pub fn links(document: &Document) -> Vec<String> {
    let mut out = Vec::new();
    let mut take = |cell: &Cell| {
        out.extend(
            cell.spans
                .iter()
                .filter_map(|s| s.target().map(str::to_owned)),
        );
    };
    for section in &document.sections {
        for block in &section.blocks {
            match block {
                Block::Table(table) => table.rows.iter().flatten().for_each(&mut take),
                Block::Facts(facts) => facts.iter().for_each(|(_, cell)| take(cell)),
                _ => {}
            }
        }
    }
    out
}

/// Make the document consistent before it is drawn: every sub-heading gets an
/// anchor, each anchor is kept once (the first in reading order), a link to a
/// folded row follows its alias, and an internal link whose anchor is not in
/// the document (a row cut by the page cap, a section left out) or that points
/// at its own cell is plain text.
pub fn finish(document: &mut Document) {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    seen.insert(TOP.to_owned());
    let keep = |id: &mut Option<String>, seen: &mut BTreeSet<String>| {
        if let Some(name) = id
            && !seen.insert(name.clone())
        {
            *id = None;
        }
    };
    for section in &mut document.sections {
        let mut section_id = Some(section.id.clone());
        keep(&mut section_id, &mut seen);
        for block in &mut section.blocks {
            match block {
                Block::Sub { title, id } => {
                    if id.is_empty() {
                        let name = title.split(" (").next().unwrap_or(title);
                        *id = format!("{}-{}", section.id, slug(&name.to_ascii_lowercase()));
                    }
                    let mut candidate = Some(id.clone());
                    keep(&mut candidate, &mut seen);
                    if candidate.is_none() {
                        id.clear();
                    }
                }
                Block::Table(table) => {
                    for cell in table.rows.iter_mut().flatten() {
                        keep(&mut cell.id, &mut seen);
                        cell.more_ids.retain(|name| seen.insert(name.clone()));
                    }
                }
                Block::Facts(facts) => {
                    for (_, cell) in facts.iter_mut() {
                        keep(&mut cell.id, &mut seen);
                        cell.more_ids.retain(|name| seen.insert(name.clone()));
                    }
                }
                _ => {}
            }
        }
    }
    let aliases = document.aliases.clone();
    let resolve = |target: &str| -> Option<String> {
        let mut at = target.to_owned();
        // Aliases chain at most a few steps; a loop is cut.
        for _ in 0..8 {
            match aliases.get(&at) {
                Some(next) if *next != at => at = next.clone(),
                _ => break,
            }
        }
        seen.contains(&at).then_some(at)
    };
    let fix = |cell: &mut Cell| {
        let own: Vec<String> = cell.ids().cloned().collect();
        for span in &mut cell.spans {
            let Some(target) = span.target().map(str::to_owned) else {
                continue;
            };
            span.href = match resolve(&target) {
                Some(found) if !own.contains(&found) => Some(format!("#{found}")),
                _ => None,
            };
        }
        // Neighbouring spans that are now plain text are one span.
        let mut merged: Vec<Span> = Vec::new();
        for span in cell.spans.drain(..) {
            match merged.last_mut() {
                Some(last) if last.href.is_none() && span.href.is_none() => {
                    last.text.push_str(&span.text)
                }
                _ => merged.push(span),
            }
        }
        cell.spans = merged;
    };
    for section in &mut document.sections {
        for block in &mut section.blocks {
            match block {
                Block::Table(table) => table.rows.iter_mut().flatten().for_each(fix),
                Block::Facts(facts) => facts.iter_mut().for_each(|(_, cell)| fix(cell)),
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(rows: Vec<Vec<Cell>>) -> Document {
        Document {
            sections: vec![Section {
                id: "files".into(),
                title: "Files".into(),
                blocks: vec![
                    Block::sub("Opened files (3)"),
                    Block::Table(DocTable {
                        columns: vec!["Path".into(), "Process".into()],
                        rows,
                    }),
                ],
            }],
            ..Document::default()
        }
    }

    #[test]
    fn finish_keeps_each_anchor_once_and_only_links_that_resolve() {
        let mut document = doc(vec![
            vec![
                Cell::link("/etc/shadow", "file-1").with_id("file-1"),
                Cell::link("cat (1465)", "proc-1465"),
            ],
            vec![
                Cell::link("/etc/shadow", "file-1").with_id("file-1"),
                Cell::link("cat (1466)", "proc-1466"),
            ],
        ]);
        document.aliases.insert("proc-1466".into(), "file-1".into());
        finish(&mut document);
        let ids = ids(&document);
        let unique: BTreeSet<&String> = ids.iter().collect();
        assert_eq!(unique.len(), ids.len(), "anchors are unique: {ids:?}");
        assert!(ids.contains(&"files-opened-files".to_owned()), "{ids:?}");
        let Block::Table(table) = &document.sections[0].blocks[1] else {
            panic!()
        };
        // The first row is the file's entry: no link to itself.
        assert_eq!(table.rows[0][0].id.as_deref(), Some("file-1"));
        assert!(!table.rows[0][0].has_links());
        // The second mentions it: a link, and no second anchor.
        assert_eq!(table.rows[1][0].id, None);
        assert_eq!(table.rows[1][0].spans[0].target(), Some("file-1"));
        // proc-1465 is not in the document: plain text.
        assert!(!table.rows[0][1].has_links());
        // An alias is followed.
        assert_eq!(table.rows[1][1].spans[0].target(), Some("file-1"));
        for target in links(&document) {
            assert!(ids.contains(&target), "{target} resolves");
        }
    }

    #[test]
    fn slugs_are_ascii_and_never_empty() {
        assert_eq!(slug("198.18.0.1:20"), "198.18.0.1-20");
        assert_eq!(slug("c2.bpf_backdoor"), "c2.bpf_backdoor");
        assert_eq!(slug("Opened files"), "Opened-files");
        assert_eq!(slug("ü"), "-");
        assert_eq!(slug(""), "x");
    }

    #[test]
    fn a_list_cell_links_each_item() {
        let cell = Cell::list(
            &[
                ("#1".into(), "finding-1".into()),
                ("#4".into(), "finding-4".into()),
            ],
            ", ",
        );
        assert_eq!(cell.text(), "#1, #4");
        assert_eq!(cell.spans.len(), 3);
        assert_eq!(cell.spans[2].target(), Some("finding-4"));
    }
}

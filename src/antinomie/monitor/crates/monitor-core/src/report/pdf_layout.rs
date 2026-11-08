// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Laying a [`Document`] out on A4 landscape pages: a contents block, wrapped
//! text, tables with repeated header rows, section bookmarks. Every anchor of
//! the document becomes a named destination where it is drawn, and every
//! internal link a link rectangle over its text. The result is a list of
//! drawing operations and links per page; `pdf.rs` writes them.
use super::page::{Block, Cell, DocTable, Document, Span, TOP};
use super::pdf_font::{Font, width};
use super::pdf_wrap::{Frag, wrap, wrap_spans};
use std::collections::BTreeMap;

pub(super) const PAGE_W: f32 = 841.89;
pub(super) const PAGE_H: f32 = 595.28;
const MARGIN: f32 = 36.0;
/// Space kept at the bottom for the footer.
const FOOTER: f32 = 30.0;
const PAD: f32 = 3.0;
/// Lines of one table cell kept; a cell with more ends in `...`.
const CELL_LINES: usize = 24;
/// Font sizes tried for a table, largest first.
const TABLE_SIZES: [f32; 5] = [7.5, 7.0, 6.5, 6.0, 5.5];

/// The width the longest word of a column title needs, in bold, with padding.
fn header_word(title: &str, size: f32) -> f32 {
    title
        .split_whitespace()
        .map(|word| width(Font::Bold, size, word))
        .fold(0.0, f32::max)
        + 2.0 * PAD
}

/// A colour, as the three components of `rg`.
pub(super) type Rgb = [f32; 3];
const INK: Rgb = [0.1, 0.12, 0.14];
const MUTED: Rgb = [0.36, 0.4, 0.44];
const NOTE: Rgb = [0.42, 0.31, 0.0];
const HEAD_FILL: Rgb = [0.93, 0.94, 0.96];
const LINE: Rgb = [0.78, 0.8, 0.83];
/// Link text, the accent of the HTML's light theme.
const LINK: Rgb = [0.04, 0.36, 0.68];

/// One drawing operation; `y` is from the page bottom, as in PDF.
#[derive(Clone, Debug)]
pub(super) enum Op {
    Text {
        x: f32,
        y: f32,
        font: Font,
        size: f32,
        color: Rgb,
        text: String,
    },
    Rect {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        fill: Rgb,
    },
    /// A horizontal rule.
    Rule {
        x1: f32,
        x2: f32,
        y: f32,
        color: Rgb,
    },
    /// A box outline.
    Frame {
        x: f32,
        y: f32,
        w: f32,
        h: f32,
        color: Rgb,
    },
}

/// A link rectangle on a page: `[x1 y1 x2 y2]` and the destination's name.
#[derive(Clone, Debug)]
pub(super) struct Link {
    pub rect: [f32; 4],
    pub dest: String,
}

#[derive(Default)]
pub(super) struct Page {
    pub ops: Vec<Op>,
    pub links: Vec<Link>,
}

/// A bookmark: a section title and where it sits.
pub(super) struct Bookmark {
    /// 0 for a section, 1 for a sub-heading under the section before it.
    pub level: u8,
    pub title: String,
    pub page: usize,
    pub y: f32,
}

/// A named destination: an anchor id and where it is drawn.
#[derive(Clone, Debug)]
pub(super) struct Dest {
    pub page: usize,
    pub y: f32,
}

pub(super) struct Laid {
    pub pages: Vec<Page>,
    pub bookmarks: Vec<Bookmark>,
    /// Every anchor, in the order it was first drawn.
    pub dests: Vec<(String, Dest)>,
}

struct Cursor {
    pages: Vec<Page>,
    bookmarks: Vec<Bookmark>,
    dests: Vec<(String, Dest)>,
    /// Anchors already placed: a cell drawn twice (a repeated first column)
    /// keeps its first place.
    placed: std::collections::BTreeSet<String>,
    /// Top of the free space on the current page.
    y: f32,
}

/// A cell that is a hash, a path or an address is drawn in Courier.
fn is_mono(text: &str) -> bool {
    text.starts_with('/')
        || text.len() >= 32 && text.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

impl Cursor {
    fn new() -> Self {
        Self {
            pages: vec![Page::default()],
            bookmarks: Vec::new(),
            dests: Vec::new(),
            placed: std::collections::BTreeSet::new(),
            y: PAGE_H - MARGIN,
        }
    }

    /// Anchor `id` at height `y` of the current page.
    fn dest(&mut self, id: &str, y: f32) {
        if !id.is_empty() && self.placed.insert(id.to_owned()) {
            let page = self.pages.len() - 1;
            self.dests.push((id.to_owned(), Dest { page, y }));
        }
    }

    /// Draw a wrapped line of fragments at `x`, `y`: link text in the accent
    /// colour with a link rectangle over it.
    fn frags(&mut self, x: f32, y: f32, font: Font, size: f32, ink: Rgb, line: &[Frag]) {
        for frag in line {
            let internal = frag.href.as_deref().and_then(|h| h.strip_prefix('#'));
            let color = if internal.is_some() { LINK } else { ink };
            if !frag.text.trim().is_empty() {
                self.text(x + frag.x, y, font, size, color, &frag.text);
            }
            if let Some(dest) = internal {
                let rect = [
                    x + frag.x,
                    y - size * 0.25,
                    x + frag.x + frag.w,
                    y + size * 0.85,
                ];
                self.page().links.push(Link {
                    rect,
                    dest: dest.to_owned(),
                });
            }
        }
    }

    fn page(&mut self) -> &mut Page {
        self.pages.last_mut().expect("a page exists")
    }

    fn new_page(&mut self) {
        self.pages.push(Page::default());
        self.y = PAGE_H - MARGIN;
    }

    fn room(&self) -> f32 {
        self.y - (MARGIN + FOOTER)
    }

    fn need(&mut self, height: f32) {
        if self.room() < height && self.y < PAGE_H - MARGIN - 1.0 {
            self.new_page();
        }
    }

    fn text(&mut self, x: f32, y: f32, font: Font, size: f32, color: Rgb, text: &str) {
        self.page().ops.push(Op::Text {
            x,
            y,
            font,
            size,
            color,
            text: text.to_owned(),
        });
    }

    fn paragraph(&mut self, text: &str, font: Font, size: f32, color: Rgb) {
        let lines = wrap(text, font, size, PAGE_W - 2.0 * MARGIN, usize::MAX);
        let leading = size * 1.35;
        for line in lines {
            self.need(leading);
            self.y -= leading;
            let y = self.y;
            self.text(MARGIN, y, font, size, color, &line);
        }
        self.y -= size * 0.5;
    }

    fn heading(&mut self, title: &str, id: &str, bookmark: bool) {
        self.need(90.0);
        self.y -= 22.0;
        let (page, y) = (self.pages.len() - 1, self.y + 16.0);
        if bookmark {
            self.bookmarks.push(Bookmark {
                level: 0,
                title: title.to_owned(),
                page,
                y,
            });
        }
        self.dest(id, y);
        let y = self.y;
        self.text(MARGIN, y, Font::Bold, 13.0, INK, title);
        self.y -= 5.0;
        let y = self.y;
        self.page().ops.push(Op::Rule {
            x1: MARGIN,
            x2: PAGE_W - MARGIN,
            y,
            color: LINE,
        });
        self.y -= 4.0;
    }

    fn sub(&mut self, title: &str, id: &str) {
        self.need(70.0);
        self.y -= 12.0;
        let y = self.y + 2.0;
        self.dest(id, y);
        if !id.is_empty() {
            let page = self.pages.len() - 1;
            self.bookmarks.push(Bookmark {
                level: 1,
                title: title.to_owned(),
                page,
                y,
            });
        }
        let size = 10.0;
        self.y -= size;
        let y = self.y;
        self.text(MARGIN, y, Font::Bold, size, MUTED, title);
        self.y -= 4.0;
    }

    /// Rows of cells: wrapped lines per cell, drawn on as many pages as needed.
    fn rows(
        &mut self,
        widths: &[f32],
        header: Option<&[String]>,
        rows: &[Vec<Cell>],
        size: f32,
        first_bold: bool,
    ) {
        let leading = size * 1.3;
        let tier_column = header.and_then(|header| header.iter().position(|c| c == "Tier"));
        type Prepared = (Vec<Vec<Frag>>, Font, Vec<String>);
        let draw_row = |this: &mut Self, cells: &[Prepared], height: f32, head: bool| {
            let top = this.y;
            let bottom = top - height;
            let mut x = MARGIN;
            if head {
                this_rect(this, x, bottom, widths.iter().sum(), height, HEAD_FILL);
            }
            for (column, ((lines, font, ids), w)) in cells.iter().zip(widths).enumerate() {
                for id in ids {
                    this.dest(id, top);
                }
                let joined: Vec<String> = lines
                    .iter()
                    .map(|line| line.iter().map(|f| f.text.as_str()).collect())
                    .collect();
                for (i, line) in lines.iter().enumerate() {
                    let y = top - PAD - size - i as f32 * leading + (size * 0.15);
                    // The tier words in the colours of the app's chips.
                    let ink = match (
                        head,
                        Some(column) == tier_column,
                        joined[i].to_ascii_lowercase().as_str(),
                    ) {
                        (false, true, "high") => [0.70, 0.15, 0.12],
                        (false, true, "medium") => [0.63, 0.36, 0.0],
                        (false, true, "low") => [0.04, 0.36, 0.68],
                        _ => INK,
                    };
                    let font = if ink == INK { *font } else { Font::Bold };
                    this.frags(x + PAD, y, font, size, ink, line);
                }
                this.page().ops.push(Op::Frame {
                    x,
                    y: bottom,
                    w: *w,
                    h: height,
                    color: LINE,
                });
                x += w;
            }
            this.y = bottom;
        };
        let prepare = |row: &[Cell], bold_all: bool| -> (Vec<Prepared>, f32) {
            let cells: Vec<Prepared> = row
                .iter()
                .enumerate()
                .zip(widths)
                .map(|((column, cell), w)| {
                    let text = cell.text();
                    let font = if bold_all || (first_bold && column == 0) {
                        Font::Bold
                    } else if is_mono(&text) {
                        Font::Mono
                    } else {
                        Font::Regular
                    };
                    (
                        wrap_spans(&cell.spans, font, size, w - 2.0 * PAD + 0.05, CELL_LINES),
                        font,
                        cell.ids().cloned().collect(),
                    )
                })
                .collect();
            let lines = cells
                .iter()
                .map(|(l, _, _)| l.len())
                .max()
                .unwrap_or(1)
                .max(1);
            (cells, lines as f32 * leading + 2.0 * PAD)
        };
        let header_cells: Option<Vec<Cell>> =
            header.map(|header| header.iter().map(|h| Cell::plain(h.clone())).collect());
        let head = header_cells.as_deref().map(|header| prepare(header, true));
        if let Some((cells, height)) = &head {
            self.need(height + 40.0);
            draw_row(self, cells, *height, true);
        }
        for row in rows {
            let (cells, height) = prepare(row, false);
            if self.room() < height {
                self.new_page();
                if let Some((hc, hh)) = &head {
                    draw_row(self, hc, *hh, true);
                }
            }
            draw_row(self, &cells, height, false);
        }
        self.y -= 8.0;
    }

    /// A table whose column titles never break inside a word: at the usual
    /// size when the longest word of each title fits the page side by side,
    /// else at a smaller size a step at a time, else split into column groups
    /// with the first column repeated.
    fn table(&mut self, table: &DocTable) {
        let avail = PAGE_W - 2.0 * MARGIN;
        let fits = |columns: &[usize], size: f32| -> bool {
            columns
                .iter()
                .map(|&c| header_word(&table.columns[c], size))
                .sum::<f32>()
                <= avail
        };
        let all: Vec<usize> = (0..table.columns.len()).collect();
        if let Some(size) = TABLE_SIZES.into_iter().find(|&size| fits(&all, size)) {
            let widths = column_widths(table, size);
            self.rows(&widths, Some(&table.columns), &table.rows, size, false);
            return;
        }
        let size = TABLE_SIZES[TABLE_SIZES.len() - 1];
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut current = vec![0usize];
        for at in 1..table.columns.len() {
            let mut trial = current.clone();
            trial.push(at);
            if current.len() > 1 && !fits(&trial, size) {
                groups.push(std::mem::replace(&mut current, vec![0, at]));
            } else {
                current = trial;
            }
        }
        groups.push(current);
        let count = groups.len();
        for (number, group) in groups.into_iter().enumerate() {
            let part = DocTable {
                columns: group.iter().map(|&c| table.columns[c].clone()).collect(),
                rows: table
                    .rows
                    .iter()
                    .map(|row| group.iter().filter_map(|&c| row.get(c).cloned()).collect())
                    .collect(),
            };
            self.paragraph(
                &format!(
                    "Columns of this table, part {} of {count}; the first column is repeated.",
                    number + 1
                ),
                Font::Oblique,
                7.5,
                MUTED,
            );
            let widths = column_widths(&part, size);
            self.rows(&widths, Some(&part.columns), &part.rows, size, false);
        }
    }

    fn facts(&mut self, facts: &[(String, Cell)]) {
        let size = 8.5;
        let label = 130.0;
        let widths = [label, PAGE_W - 2.0 * MARGIN - label];
        let rows: Vec<Vec<Cell>> = facts
            .iter()
            .map(|(name, value)| vec![Cell::plain(name.clone()), value.clone()])
            .collect();
        self.rows(&widths, None, &rows, size, true);
    }

    /// The contents block: one line per section and per sub-heading of Files
    /// and Network, each a link, with its page once `pages` knows it.
    fn contents(&mut self, document: &Document, pages: Option<&BTreeMap<String, usize>>) {
        self.heading("Contents", "contents", false);
        let size = 9.0;
        let leading = size * 1.45;
        let mut entries: Vec<(String, String, f32)> = Vec::new();
        for section in &document.sections {
            entries.push((section.title.clone(), section.id.clone(), 0.0));
            if matches!(section.id.as_str(), "files" | "network") {
                for block in &section.blocks {
                    if let Block::Sub { title, id } = block
                        && !id.is_empty()
                    {
                        entries.push((title.clone(), id.clone(), 14.0));
                    }
                }
            }
        }
        for (title, id, indent) in entries {
            self.need(leading);
            self.y -= leading;
            let y = self.y;
            let line = [Span::to(title, &id)];
            let frags = wrap_spans(&line, Font::Regular, size, 520.0, 1);
            self.frags(MARGIN + indent, y, Font::Regular, size, INK, &frags[0]);
            let number = pages
                .and_then(|pages| pages.get(&id))
                .map_or(String::new(), |page| (page + 1).to_string());
            let w = width(Font::Regular, size, &number);
            let right = MARGIN + 620.0;
            self.text(right - w, y, Font::Regular, size, MUTED, &number);
            self.page().links.push(Link {
                rect: [MARGIN + indent, y - size * 0.25, right, y + size * 0.85],
                dest: id,
            });
        }
        self.y -= 6.0;
    }
}

fn this_rect(this: &mut Cursor, x: f32, y: f32, w: f32, h: f32, fill: Rgb) {
    this.page().ops.push(Op::Rect { x, y, w, h, fill });
}

/// Column widths: each column its natural width when everything fits, else a
/// floor for each and the rest shared by what the columns want beyond it.
fn column_widths(table: &DocTable, size: f32) -> Vec<f32> {
    let avail = PAGE_W - 2.0 * MARGIN;
    let columns = table.columns.len().max(1);
    let mut natural = vec![0.0f32; columns];
    let mut floor = vec![0.0f32; columns];
    let measure = |text: &str, column: usize, natural: &mut [f32], floor: &mut [f32]| {
        let font = if is_mono(text) {
            Font::Mono
        } else {
            Font::Regular
        };
        let line = width(font, size, text) + 2.0 * PAD;
        if line > natural[column] {
            natural[column] = line;
        }
        let word = text
            .split(' ')
            .map(|w| width(font, size, w))
            .fold(0.0, f32::max)
            + 2.0 * PAD;
        if word > floor[column] {
            floor[column] = word;
        }
    };
    for (column, name) in table.columns.iter().enumerate() {
        measure(name, column, &mut natural, &mut floor);
    }
    for row in table.rows.iter().take(400) {
        for (column, cell) in row.iter().enumerate().take(columns) {
            measure(&cell.text(), column, &mut natural, &mut floor);
        }
    }
    // A single word of a cell is never worth more than a third of the page as
    // a floor; a title's longest word (in bold) is a floor nothing goes under.
    let heads: Vec<f32> = table
        .columns
        .iter()
        .map(|name| header_word(name, size))
        .collect();
    for (f, head) in floor.iter_mut().zip(&heads) {
        *f = f.min(avail / 3.0).max(*head);
    }
    for (n, head) in natural.iter_mut().zip(&heads) {
        *n = n.max(*head);
    }
    // When the longest words side by side are wider than the page, only the
    // widest of them give way (a hash, a long path); a narrow column keeps its
    // longest word whole instead of every column falling back to its title.
    if floor.iter().sum::<f32>() > avail {
        let fitted = |cap: f32| -> f32 {
            floor
                .iter()
                .zip(&heads)
                .map(|(f, head)| f.min(cap).max(*head))
                .sum()
        };
        let (mut low, mut high) = (0.0f32, floor.iter().copied().fold(0.0, f32::max));
        for _ in 0..30 {
            let middle = (low + high) / 2.0;
            if fitted(middle) > avail {
                high = middle;
            } else {
                low = middle;
            }
        }
        for (f, head) in floor.iter_mut().zip(&heads) {
            *f = f.min(low).max(*head);
        }
    }
    let total: f32 = natural.iter().sum();
    if total <= avail {
        let extra = (avail - total) / columns as f32;
        return natural.iter().map(|n| n + extra).collect();
    }
    let floor_total: f32 = floor.iter().sum();
    if floor_total >= avail {
        return floor.iter().map(|f| f * avail / floor_total).collect();
    }
    let want: Vec<f32> = natural
        .iter()
        .zip(&floor)
        .map(|(n, f)| (n - f).max(0.0))
        .collect();
    let want_total: f32 = want.iter().sum();
    let spare = avail - floor_total;
    floor
        .iter()
        .zip(&want)
        .map(|(f, w)| {
            f + if want_total > 0.0 {
                spare * w / want_total
            } else {
                0.0
            }
        })
        .collect()
}

/// The document as pages, laid out twice: the second time the contents block
/// knows the page of every section (it is the same height both times, so
/// nothing moves).
pub(super) fn lay_out(document: &Document) -> Laid {
    let first = lay(document, None);
    let pages: BTreeMap<String, usize> = first
        .dests
        .iter()
        .map(|(id, dest)| (id.clone(), dest.page))
        .collect();
    lay(document, Some(&pages))
}

fn lay(document: &Document, pages: Option<&BTreeMap<String, usize>>) -> Laid {
    let mut cursor = Cursor::new();
    cursor.y -= 18.0;
    let y = cursor.y;
    cursor.dest(TOP, y + 18.0);
    let title_lines = wrap(&document.title, Font::Bold, 18.0, PAGE_W - 2.0 * MARGIN, 3);
    let mut y = y;
    for line in &title_lines {
        cursor.text(MARGIN, y, Font::Bold, 18.0, INK, line);
        y -= 22.0;
    }
    cursor.text(MARGIN, y, Font::Regular, 9.0, MUTED, &document.subtitle);
    cursor.y = y - 8.0;
    if document.sections.len() > 1 {
        cursor.contents(document, pages);
    }
    for section in &document.sections {
        cursor.heading(&section.title, &section.id, true);
        for block in &section.blocks {
            match block {
                Block::Paragraph(text) => cursor.paragraph(text, Font::Regular, 9.5, INK),
                Block::Note(text) => cursor.paragraph(text, Font::Oblique, 8.5, NOTE),
                Block::Sub { title, id } => cursor.sub(title, id),
                Block::Facts(facts) => cursor.facts(facts),
                Block::Table(table) => cursor.table(table),
            }
        }
    }
    let placed: std::collections::BTreeSet<String> =
        cursor.dests.iter().map(|(id, _)| id.clone()).collect();
    for page in &mut cursor.pages {
        page.links.retain(|link| placed.contains(&link.dest));
    }
    Laid {
        pages: cursor.pages,
        bookmarks: cursor.bookmarks,
        dests: cursor.dests,
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The self-contained HTML report: one file, inline CSS, no script and no
//! reference to another file or address. The markup is also well-formed XML
//! (void elements self-close, five entities), so any XML parser can read it.
use super::layout::{Block, DocTable, Document};

/// Text safe inside an element or an attribute. Characters XML cannot hold
/// become U+FFFD.
pub(super) fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            '\t' | '\n' | '\r' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{7f}' || ('\u{80}'..'\u{a0}').contains(&c) => {
                out.push('\u{fffd}')
            }
            '\u{fffe}' | '\u{ffff}' => out.push('\u{fffd}'),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = "\
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#5c6670;--line:#d3d8de;--head:#eef1f4;--accent:#0b5cad;--note:#6b4e00}\
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--fg:#e4e8ec;--muted:#98a2ad;--line:#333b44;--head:#1f262d;--accent:#6cb2ff;--note:#e0b95a}}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif}\
main{max-width:1200px;margin:0 auto;padding:24px 20px 60px}\
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}\
h3{font-size:14px;margin:18px 0 6px;color:var(--muted)}\
.sub{color:var(--muted);margin:0 0 16px}\
nav ul{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:4px 14px;margin:0 0 8px}\
nav a{color:var(--accent);text-decoration:none}\
table{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:13px}\
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;overflow-wrap:anywhere}\
th{background:var(--head);overflow-wrap:normal;word-break:keep-all;hyphens:none;white-space:normal}\
table.t12{font-size:12px}table.t11{font-size:11px}table.t10{font-size:10px}table.t9{font-size:9px}\
.facts th{width:14em;font-weight:600}\
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}\
.note{color:var(--note);font-size:13px;margin:4px 0 10px}\
.wide{overflow-x:auto}\
.tac{display:inline-block;margin:1px 3px 1px 0;padding:0 6px;border:1px solid var(--c);border-left-width:6px;border-radius:4px;white-space:nowrap}\
@page{size:landscape;margin:12mm}\
@media print{body{font-size:11px}main{max-width:none;padding:0}h2{break-after:avoid}tr{break-inside:avoid}.wide{overflow:visible}}";

/// One class per tactic: its colour on a light page, and on a dark one.
fn tactic_style() -> String {
    use crate::mitre::Tactic;
    let hex = |tactic: Tactic, light: bool| {
        let [r, g, b] = tactic.rgb(light);
        format!("#{r:02x}{g:02x}{b:02x}")
    };
    let mut light = String::new();
    let mut dark = String::new();
    for (index, tactic) in Tactic::ALL.into_iter().enumerate() {
        light.push_str(&format!(".t{index}{{--c:{}}}", hex(tactic, true)));
        dark.push_str(&format!(".t{index}{{--c:{}}}", hex(tactic, false)));
    }
    format!("{light}@media (prefers-color-scheme:dark){{{dark}}}")
}

/// The cell of the Tactic column: one outlined chip per tactic, named in text
/// so the colour is never the only cue.
fn tactic_cell(cell: &str) -> String {
    let chips: Vec<String> = super::cell_tactics(cell)
        .into_iter()
        .map(|tactic| {
            format!(
                "<span class=\"tac t{}\">{}</span>",
                tactic as usize,
                escape(tactic.name())
            )
        })
        .collect();
    if chips.is_empty() {
        escape(cell)
    } else {
        chips.join(" ")
    }
}

/// A cell that looks like a hash, a path or an address reads better in monospace.
fn mono(text: &str) -> bool {
    text.starts_with('/')
        || text.len() >= 32 && text.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

/// The widest a table's column headers may need, in CSS pixels: a landscape
/// A4 or Letter page less its margins, and about what the page holds on screen.
const TABLE_WIDTH: f32 = 1000.0;
/// Font sizes tried for a table, largest first (the table's own: 13).
const SIZES: [u32; 5] = [13, 12, 11, 10, 9];
/// The size at which a table that still does not fit is split.
const SPLIT_SIZE: u32 = 10;

/// The widest word of a header, in characters.
fn longest_word(text: &str) -> usize {
    text.split_whitespace()
        .map(|word| word.chars().count())
        .max()
        .unwrap_or(0)
}

/// The least width a header of `columns` needs at `size` pixels: the longest
/// word of each, in bold, plus padding. Headers wrap only at spaces.
fn header_width(columns: &[&String], size: u32) -> f32 {
    columns
        .iter()
        .map(|name| longest_word(name) as f32 * 0.66 * size as f32 + 18.0)
        .sum()
}

/// The columns of a table that does not fit at [`SPLIT_SIZE`], cut into groups
/// that do; the first column (the row's key) is in every group.
fn groups(columns: &[String]) -> Vec<Vec<usize>> {
    let mut out: Vec<Vec<usize>> = Vec::new();
    let mut current = vec![0usize];
    for at in 1..columns.len() {
        let mut trial = current.clone();
        trial.push(at);
        let names: Vec<&String> = trial.iter().map(|&i| &columns[i]).collect();
        if current.len() > 1 && header_width(&names, SPLIT_SIZE) > TABLE_WIDTH {
            out.push(std::mem::replace(&mut current, vec![0, at]));
        } else {
            current = trial;
        }
    }
    out.push(current);
    out
}

fn one_table(out: &mut String, columns: &[&String], rows: &[Vec<&String>], size: u32) {
    let class = if size >= SIZES[0] {
        String::new()
    } else {
        format!(" class=\"t{size}\"")
    };
    let tactics = columns
        .iter()
        .position(|column| column.as_str() == super::TACTIC_COLUMN);
    out.push_str(&format!("<div class=\"wide\"><table{class}><thead><tr>"));
    for column in columns {
        out.push_str(&format!("<th>{}</th>", escape(column)));
    }
    out.push_str("</tr></thead><tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for (column, cell) in row.iter().enumerate() {
            if Some(column) == tactics {
                out.push_str(&format!("<td>{}</td>", tactic_cell(cell)));
            } else if mono(cell) {
                out.push_str(&format!("<td class=\"mono\">{}</td>", escape(cell)));
            } else {
                out.push_str(&format!("<td>{}</td>", escape(cell)));
            }
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
}

/// A table. Its headers never break inside a word (CSS), so when the longest
/// words side by side are wider than a page the table takes a smaller font a
/// step at a time, and past that is split in column groups with the first
/// column repeated.
fn table(out: &mut String, table: &DocTable) {
    let all: Vec<&String> = table.columns.iter().collect();
    if let Some(size) = SIZES
        .into_iter()
        .find(|&size| header_width(&all, size) <= TABLE_WIDTH)
    {
        let rows: Vec<Vec<&String>> = table.rows.iter().map(|row| row.iter().collect()).collect();
        one_table(out, &all, &rows, size);
        return;
    }
    let parts = groups(&table.columns);
    for (number, part) in parts.iter().enumerate() {
        out.push_str(&format!(
            "<p class=\"note\">Columns of this table, part {} of {}; the first column is repeated.</p>\n",
            number + 1,
            parts.len()
        ));
        let columns: Vec<&String> = part.iter().map(|&i| &table.columns[i]).collect();
        let rows: Vec<Vec<&String>> = table
            .rows
            .iter()
            .map(|row| part.iter().filter_map(|&i| row.get(i)).collect())
            .collect();
        one_table(out, &columns, &rows, SPLIT_SIZE);
    }
}

/// The report as an HTML document.
pub(super) fn render(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head>");
    out.push_str("<meta charset=\"utf-8\" />");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
    out.push_str("<meta name=\"generator\" content=\"Antinomie\" />");
    out.push_str(&format!("<title>{}</title>", escape(&document.title)));
    out.push_str(&format!(
        "<style>{STYLE}{}</style></head><body><main>\n",
        tactic_style()
    ));
    out.push_str(&format!(
        "<h1>{}</h1><p class=\"sub\">{}</p>\n<nav><ul>",
        escape(&document.title),
        escape(&document.subtitle)
    ));
    for section in &document.sections {
        out.push_str(&format!(
            "<li><a href=\"#{}\">{}</a></li>",
            escape(&section.id),
            escape(&section.title)
        ));
    }
    out.push_str("</ul></nav>\n");
    for section in &document.sections {
        out.push_str(&format!(
            "<section id=\"{}\"><h2>{}</h2>\n",
            escape(&section.id),
            escape(&section.title)
        ));
        for block in &section.blocks {
            match block {
                Block::Paragraph(text) => out.push_str(&format!("<p>{}</p>\n", escape(text))),
                Block::Note(text) => {
                    out.push_str(&format!("<p class=\"note\">{}</p>\n", escape(text)))
                }
                Block::Sub(text) => out.push_str(&format!("<h3>{}</h3>\n", escape(text))),
                Block::Facts(facts) => {
                    out.push_str("<table class=\"facts\"><tbody>\n");
                    for (name, value) in facts {
                        let class = if mono(value) { " class=\"mono\"" } else { "" };
                        out.push_str(&format!(
                            "<tr><th>{}</th><td{class}>{}</td></tr>\n",
                            escape(name),
                            escape(value)
                        ));
                    }
                    out.push_str("</tbody></table>\n");
                }
                Block::Table(t) => table(&mut out, t),
            }
        }
        out.push_str("</section>\n");
    }
    out.push_str("</main></body></html>\n");
    out
}

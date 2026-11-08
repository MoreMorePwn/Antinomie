// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The self-contained HTML report: one file, inline CSS, no script and no
//! reference to an address. Every entry row is an anchor (`<td id>`) and
//! every mention of it a link (`<a href="#…">`) inside the same file; the
//! sample report's links to run reports are relative paths. The markup is
//! also well-formed XML (void elements self-close, five entities), so any XML
//! parser can read it.
use super::page::{Block, Cell, DocTable, Document};

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
:root{color-scheme:light dark;--bg:#fff;--fg:#1b1f24;--muted:#5c6670;--line:#d3d8de;--head:#eef1f4;--accent:#0b5cad;--note:#6b4e00;--hit:#fff4c2}\
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--fg:#e4e8ec;--muted:#98a2ad;--line:#333b44;--head:#1f262d;--accent:#6cb2ff;--note:#e0b95a;--hit:#3d3415}}\
*{box-sizing:border-box}\
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif}\
main{max-width:1200px;margin:0 auto;padding:24px 20px 60px}\
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--line)}\
p.back{font-size:12px;margin:2px 0 0}p.back a{color:var(--muted)}h3{font-size:14px;margin:18px 0 6px;color:var(--muted)}\
.sub{color:var(--muted);margin:0 0 16px}\
nav ul{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:4px 14px;margin:0 0 8px}\
nav a{color:var(--accent);text-decoration:none}\
table{border-collapse:collapse;width:100%;margin:6px 0 10px;font-size:13px}\
th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top;overflow-wrap:normal}\
td.mono,td.long{overflow-wrap:anywhere}td.nw{white-space:nowrap}\
th{background:var(--head);overflow-wrap:normal;word-break:keep-all;hyphens:none;white-space:normal}\
table.t12{font-size:12px}table.t11{font-size:11px}table.t10{font-size:10px}table.t9{font-size:9px}\
.facts th{width:14em;font-weight:600}\
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}\
.note{color:var(--note);font-size:13px;margin:4px 0 10px}\
.wide{overflow-x:auto}.wide:focus{outline:2px solid var(--accent)}\
td a,.facts a{color:var(--accent);text-decoration:none}td a:hover,.facts a:hover{text-decoration:underline}\
:target{scroll-margin-top:48px}td:target,tr:has(>td:target)>td{background:var(--hit)}\
.tier{font-weight:600;white-space:nowrap}.tier.high{color:#b3261e}.tier.medium{color:#a15c00}.tier.low{color:#0b5cad}.tier.info{color:var(--muted)}\
@media (prefers-color-scheme:dark){.tier.high{color:#ff8a80}.tier.medium{color:#ffb74d}.tier.low{color:#6cb2ff}}\
caption{caption-side:top;text-align:left;color:var(--muted);font-size:12px;padding:2px 0}\
@media (min-width:900px){nav{position:sticky;top:0;background:var(--bg);padding:6px 0;z-index:1}}\
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

/// A short cell with no long text in it (an enum word, a count, a time) is not
/// broken across lines: "succeeded" never reads "succee/ded".
fn no_wrap(text: &str) -> bool {
    let chars = text.chars().count();
    chars <= 14 && !text.contains(' ')
        || chars <= 36
            && text.len() >= 10
            && text.as_bytes()[..4].iter().all(u8::is_ascii_digit)
            && text.as_bytes()[4] == b'-'
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

/// A cell's spans as markup: text, and `<a>` for each link.
fn spans(cell: &Cell) -> String {
    cell.spans
        .iter()
        .map(|span| match &span.href {
            Some(href) => format!("<a href=\"{}\">{}</a>", escape(href), escape(&span.text)),
            None => escape(&span.text),
        })
        .collect()
}

/// ` id="…"` of a cell's first anchor, and an empty `<a id>` for each more.
fn anchors(cell: &Cell) -> (String, String) {
    let first = cell
        .id
        .as_ref()
        .map_or(String::new(), |id| format!(" id=\"{}\"", escape(id)));
    let more = cell
        .more_ids
        .iter()
        .map(|id| format!("<a id=\"{}\"></a>", escape(id)))
        .collect();
    (first, more)
}

fn one_table(out: &mut String, columns: &[&String], rows: &[Vec<&Cell>], size: u32, caption: &str) {
    let class = if size >= SIZES[0] {
        String::new()
    } else {
        format!(" class=\"t{size}\"")
    };
    let tactics = columns
        .iter()
        .position(|column| column.as_str() == super::TACTIC_COLUMN);
    out.push_str(&format!(
        "<div class=\"wide\" tabindex=\"0\" role=\"region\" aria-label=\"{}\"><table{class}><caption>{}</caption><thead><tr>",
        escape(caption),
        escape(caption)
    ));
    for column in columns {
        out.push_str(&format!("<th scope=\"col\">{}</th>", escape(column)));
    }
    let tiers = columns.iter().position(|column| column.as_str() == "Tier");
    out.push_str("</tr></thead><tbody>\n");
    for row in rows {
        out.push_str("<tr>");
        for (column, cell) in row.iter().enumerate() {
            let text = cell.text();
            let (id, more) = anchors(cell);
            let tier = Some(column) == tiers
                && matches!(
                    text.to_ascii_lowercase().as_str(),
                    "high" | "medium" | "low" | "info"
                );
            let class = if mono(&text) {
                " class=\"mono\""
            } else if text.chars().count() > 40 {
                " class=\"long\""
            } else if no_wrap(&text) {
                " class=\"nw\""
            } else {
                ""
            };
            if Some(column) == tactics && !cell.has_links() {
                out.push_str(&format!("<td{id}>{more}{}</td>", tactic_cell(&text)));
            } else if tier && !cell.has_links() {
                out.push_str(&format!(
                    "<td{id}>{more}<span class=\"tier {}\">{}</span></td>",
                    text.to_ascii_lowercase(),
                    escape(&text)
                ));
            } else {
                out.push_str(&format!("<td{id}{class}>{more}{}</td>", spans(cell)));
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
fn table(out: &mut String, table: &DocTable, caption: &str) {
    let all: Vec<&String> = table.columns.iter().collect();
    if let Some(size) = SIZES
        .into_iter()
        .find(|&size| header_width(&all, size) <= TABLE_WIDTH)
    {
        let rows: Vec<Vec<&Cell>> = table.rows.iter().map(|row| row.iter().collect()).collect();
        one_table(out, &all, &rows, size, caption);
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
        let rows: Vec<Vec<&Cell>> = table
            .rows
            .iter()
            .map(|row| part.iter().filter_map(|&i| row.get(i)).collect())
            .collect();
        one_table(out, &columns, &rows, SPLIT_SIZE, caption);
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
        "<h1 id=\"top\">{}</h1><p class=\"sub\">{}</p>\n<nav aria-label=\"Sections\"><ul>",
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
        let mut caption = section.title.clone();
        for block in &section.blocks {
            match block {
                Block::Paragraph(text) => out.push_str(&format!("<p>{}</p>\n", escape(text))),
                Block::Note(text) => {
                    out.push_str(&format!("<p class=\"note\">{}</p>\n", escape(text)))
                }
                Block::Sub { title, id } => {
                    caption.clone_from(title);
                    let id = if id.is_empty() {
                        String::new()
                    } else {
                        format!(" id=\"{}\"", escape(id))
                    };
                    out.push_str(&format!("<h3{id}>{}</h3>\n", escape(title)));
                }
                Block::Facts(facts) => {
                    out.push_str("<table class=\"facts\"><tbody>\n");
                    for (name, value) in facts {
                        let class = if mono(&value.text()) {
                            " class=\"mono\""
                        } else {
                            ""
                        };
                        let (id, more) = anchors(value);
                        out.push_str(&format!(
                            "<tr><th scope=\"row\">{}</th><td{id}{class}>{more}{}</td></tr>\n",
                            escape(name),
                            spans(value)
                        ));
                    }
                    out.push_str("</tbody></table>\n");
                }
                Block::Table(t) => table(&mut out, t, &caption),
            }
        }
        out.push_str("<p class=\"back\"><a href=\"#top\">Back to the top</a></p>\n</section>\n");
    }
    out.push_str("</main></body></html>\n");
    out
}

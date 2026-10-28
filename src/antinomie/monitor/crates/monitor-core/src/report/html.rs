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
th{background:var(--head)}\
.facts th{width:14em;font-weight:600}\
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}\
.note{color:var(--note);font-size:13px;margin:4px 0 10px}\
.wide{overflow-x:auto}\
@media print{body{font-size:11px}main{max-width:none;padding:0}h2{break-after:avoid}tr{break-inside:avoid}.wide{overflow:visible}}";

/// A cell that looks like a hash, a path or an address reads better in monospace.
fn mono(text: &str) -> bool {
    text.starts_with('/')
        || text.len() >= 32 && text.chars().all(|c| c.is_ascii_hexdigit() || c == ':')
}

fn table(out: &mut String, table: &DocTable) {
    out.push_str("<div class=\"wide\"><table><thead><tr>");
    for column in &table.columns {
        out.push_str(&format!("<th>{}</th>", escape(column)));
    }
    out.push_str("</tr></thead><tbody>\n");
    for row in &table.rows {
        out.push_str("<tr>");
        for cell in row {
            if mono(cell) {
                out.push_str(&format!("<td class=\"mono\">{}</td>", escape(cell)));
            } else {
                out.push_str(&format!("<td>{}</td>", escape(cell)));
            }
        }
        out.push_str("</tr>\n");
    }
    out.push_str("</tbody></table></div>\n");
}

/// The report as an HTML document.
pub(super) fn render(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html>\n<html lang=\"en\"><head>");
    out.push_str("<meta charset=\"utf-8\" />");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
    out.push_str("<meta name=\"generator\" content=\"Antinomie\" />");
    out.push_str(&format!("<title>{}</title>", escape(&document.title)));
    out.push_str(&format!("<style>{STYLE}</style></head><body><main>\n"));
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

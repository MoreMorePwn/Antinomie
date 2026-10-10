//! Paged views of a category's full listing: disassembly as an address /
//! bytes / instruction table, decompilation as numbered source, strings as a
//! table. Rows load from the retained listing in pages, as they scroll in.
use super::ReportAction;
use crate::theme;
use antinomie_monitor_core::{
    AnalysisData, AnalysisEntry, AnalysisKind, AnalysisListingPage, AnalysisReport,
    AnalysisSection, LISTING_PAGE_MAX_ROWS,
};
use eframe::egui::{self, text::LayoutJob, Color32, FontId, RichText, TextFormat};
use egui_extras::{Column, TableBuilder};

#[derive(Default)]
pub(super) struct ListingState {
    pub query: String,
    /// The selected row: listing index and entry.
    pub selected: Option<(u64, AnalysisEntry)>,
}

/// Rows read ahead of the first one that is needed.
const LOOK_BEHIND: u64 = 128;

pub(super) fn show(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    section: &AnalysisSection,
    page: Option<&Result<AnalysisListingPage, String>>,
    state: &mut ListingState,
) -> Option<ReportAction> {
    let kind = section.kind;
    let mut action = None;
    let request = |start: u64, query: &str| {
        Some(ReportAction::ReadListing {
            report_id: report.id.clone(),
            kind,
            start,
            query: query.to_owned(),
        })
    };
    let listing = section.listing.as_ref();
    ui.horizontal(|ui| {
        let label = ui.label(egui_phosphor::regular::MAGNIFYING_GLASS);
        ui.add(
            egui::TextEdit::singleline(&mut state.query)
                .desired_width((ui.available_width() - 160.0).max(120.0))
                .hint_text(match kind {
                    AnalysisKind::Disassembly => "Search instructions, functions or addresses",
                    AnalysisKind::Decompilation => "Search decompiled code",
                    _ => "Search all rows",
                }),
        )
        .labelled_by(label.id);
        let current = page
            .and_then(|page| page.as_ref().ok())
            .filter(|page| page.kind == kind && page.query == state.query);
        ui.label(match (current, listing) {
            (Some(_), Some(listing)) if state.query.is_empty() => {
                format!("{} rows", listing.rows)
            }
            (Some(page), _) => format!("{} matching", page.total),
            _ => "Reading…".into(),
        });
    });
    let page = match page {
        Some(Ok(page)) if page.kind == kind && page.query == state.query => page,
        Some(Err(error)) => {
            ui.colored_label(theme::error(), error);
            if ui.button("Retry").clicked() {
                action = request(0, &state.query);
            }
            return action;
        }
        _ => {
            ui.label("Reading the listing…");
            return request(0, &state.query);
        }
    };
    if page.total == 0 {
        ui.label(if state.query.is_empty() {
            "This listing is empty."
        } else {
            "No row matches the search."
        });
        return action;
    }
    let mono = FontId::monospace(ui.text_style_height(&egui::TextStyle::Monospace) - 2.0);
    let row_height = mono.size + 10.0;
    let loaded = page.start..page.start + page.rows.len() as u64;
    let mut needed = None;
    let mut clicked = None;
    let columns: &[(&str, Column)] = match kind {
        AnalysisKind::Disassembly => &[
            ("Address", Column::exact(mono.size * 7.5)),
            (
                "Bytes",
                Column::initial(mono.size * 9.0).at_least(40.0).clip(true),
            ),
            (
                "Instruction",
                Column::remainder().at_least(200.0).clip(true),
            ),
        ],
        AnalysisKind::Decompilation => &[
            ("Line", Column::exact(mono.size * 4.0)),
            ("Code", Column::remainder().at_least(240.0).clip(true)),
        ],
        AnalysisKind::Strings => &[
            ("Offset", Column::exact(mono.size * 8.0)),
            ("Encoding", Column::exact(mono.size * 6.0)),
            ("Length", Column::exact(mono.size * 5.0)),
            ("Text", Column::remainder().at_least(200.0).clip(true)),
        ],
        _ => &[
            ("Name", Column::initial(200.0).clip(true)),
            ("Value", Column::remainder().at_least(200.0).clip(true)),
        ],
    };
    ui.push_id(("listing-table", kind_salt(kind)), |ui| {
        // Rows select on click; text selection would swallow it.
        ui.style_mut().interaction.selectable_labels = false;
        let height = ui.available_height().max(row_height);
        let mut table = TableBuilder::new(ui)
            .id_salt(("listing", kind_salt(kind)))
            .striped(kind != AnalysisKind::Decompilation)
            .resizable(true)
            .sense(egui::Sense::click())
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .max_scroll_height(height);
        for (_, column) in columns {
            table = table.column(*column);
        }
        table
            .header(row_height, |mut header| {
                for (title, _) in columns {
                    header.col(|ui| {
                        ui.strong(*title);
                    });
                }
            })
            .body(|body| {
                body.rows(row_height, page.total as usize, |mut row| {
                    let index = row.index() as u64;
                    let Some((listing_index, entry)) = loaded
                        .contains(&index)
                        .then(|| &page.rows[(index - page.start) as usize])
                    else {
                        needed.get_or_insert(index);
                        row.col(|ui| {
                            ui.weak("…");
                        });
                        return;
                    };
                    let selected = state
                        .selected
                        .as_ref()
                        .is_some_and(|(selected, _)| selected == listing_index);
                    row.set_selected(selected);
                    cells(&mut row, kind, entry, &mono);
                    if row.response().clicked() {
                        clicked = Some((*listing_index, entry.clone()));
                    }
                });
            });
    });
    if let Some(selection) = clicked {
        state.selected = Some(selection);
    }
    if let Some(index) = needed {
        action = request(index.saturating_sub(LOOK_BEHIND), &state.query);
    }
    // Keep the page size in the type system's view of the bound.
    debug_assert!(page.rows.len() <= LISTING_PAGE_MAX_ROWS);
    action
}

fn kind_salt(kind: AnalysisKind) -> &'static str {
    match kind {
        AnalysisKind::Disassembly => "disassembly",
        AnalysisKind::Decompilation => "decompilation",
        AnalysisKind::Strings => "strings",
        _ => "other",
    }
}

fn mono_text(text: impl Into<String>, font: &FontId, color: Color32) -> RichText {
    RichText::new(text).font(font.clone()).color(color)
}

fn cells(
    row: &mut egui_extras::TableRow,
    kind: AnalysisKind,
    entry: &AnalysisEntry,
    mono: &FontId,
) {
    let data = entry.record.as_ref().map(|record| &record.data);
    match (kind, data) {
        (
            _,
            Some(AnalysisData::Function {
                name,
                address,
                size,
            }),
        ) => {
            // A function header spans the row visually: address, then name.
            let first = match kind {
                AnalysisKind::Decompilation => String::new(),
                _ => format!("{address:x}"),
            };
            row.col(|ui| {
                ui.label(mono_text(first, mono, theme::blue()).strong());
            });
            let title = if *size > 0 {
                format!("{name}  ·  0x{address:x}, {size} octets")
            } else {
                format!("{name}  ·  0x{address:x}")
            };
            if kind == AnalysisKind::Disassembly {
                row.col(|_| {});
            }
            row.col(|ui| {
                ui.add(egui::Label::new(mono_text(title, mono, theme::blue()).strong()).truncate());
            });
        }
        (
            AnalysisKind::Disassembly,
            Some(AnalysisData::Instruction {
                address,
                bytes,
                mnemonic,
                operands,
                ..
            }),
        ) => {
            row.col(|ui| {
                ui.label(mono_text(format!("{address:x}"), mono, theme::muted()));
            });
            row.col(|ui| {
                ui.add(egui::Label::new(mono_text(bytes.clone(), mono, theme::muted())).truncate());
            });
            row.col(|ui| {
                let mut job = LayoutJob::default();
                let color = if mnemonic.starts_with("call") {
                    theme::blue()
                } else if mnemonic.starts_with('j') || mnemonic.starts_with("ret") {
                    theme::warn()
                } else if mnemonic == "(bad)" {
                    theme::error()
                } else {
                    theme::text()
                };
                job.append(&format!("{mnemonic:<8} "), 0.0, format(mono, color));
                job.append(operands, 0.0, format(mono, theme::text()));
                ui.add(egui::Label::new(job).truncate());
            });
        }
        (AnalysisKind::Decompilation, Some(AnalysisData::SourceLine { line, .. })) => {
            row.col(|ui| {
                ui.label(mono_text(line.to_string(), mono, theme::muted()));
            });
            row.col(|ui| {
                ui.add(egui::Label::new(highlight(&entry.value, mono)).truncate());
            });
        }
        (
            AnalysisKind::Strings,
            Some(AnalysisData::String {
                encoding, byte_len, ..
            }),
        ) => {
            let offset = entry.offset.unwrap_or(0);
            row.col(|ui| {
                ui.label(mono_text(format!("{offset:x}"), mono, theme::muted()));
            });
            row.col(|ui| {
                ui.label(encoding.as_str());
            });
            row.col(|ui| {
                ui.label(byte_len.to_string());
            });
            row.col(|ui| {
                ui.add(
                    egui::Label::new(mono_text(entry.value.clone(), mono, theme::text()))
                        .truncate(),
                )
                .on_hover_text(&entry.value);
            });
        }
        _ => {
            row.col(|ui| {
                ui.add(egui::Label::new(entry.label.as_str()).truncate());
            });
            row.col(|ui| {
                ui.add(egui::Label::new(entry.value.as_str()).truncate())
                    .on_hover_text(&entry.value);
            });
        }
    }
}

fn format(font: &FontId, color: Color32) -> TextFormat {
    TextFormat::simple(font.clone(), color)
}

const KEYWORDS: &[&str] = &[
    "if", "else", "while", "for", "do", "return", "goto", "switch", "case", "default", "break",
    "continue", "sizeof",
];
const TYPES: &[&str] = &[
    "void",
    "char",
    "short",
    "int",
    "long",
    "unsigned",
    "signed",
    "float",
    "double",
    "bool",
    "undefined",
    "undefined1",
    "undefined2",
    "undefined4",
    "undefined8",
    "uint",
    "ulong",
    "byte",
    "word",
    "dword",
    "qword",
    "code",
    "struct",
    "const",
    "size_t",
    "uchar",
    "ushort",
];

/// Light C highlighting: comments, strings, numbers, keywords and types.
fn highlight(line: &str, font: &FontId) -> LayoutJob {
    let mut job = LayoutJob::default();
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*') {
        job.append(line, 0.0, format(font, theme::muted()));
        return job;
    }
    let mut rest = line;
    while !rest.is_empty() {
        let first = rest.chars().next().unwrap_or(' ');
        let (token, color) = if first == '"' || first == '\'' {
            let end = rest[1..]
                .find(first)
                .map_or(rest.len(), |at| at + 2)
                .min(rest.len());
            (&rest[..end], theme::good())
        } else if first.is_ascii_digit() {
            let end = rest
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.'))
                .unwrap_or(rest.len());
            (&rest[..end], theme::warn())
        } else if first.is_alphabetic() || first == '_' {
            let end = rest
                .find(|c: char| !(c.is_alphanumeric() || c == '_'))
                .unwrap_or(rest.len());
            let word = &rest[..end];
            let color = if KEYWORDS.contains(&word) {
                theme::error()
            } else if TYPES.contains(&word) {
                theme::blue()
            } else {
                theme::text()
            };
            (word, color)
        } else {
            let end = rest.char_indices().nth(1).map_or(rest.len(), |(at, _)| at);
            (&rest[..end], theme::text())
        };
        job.append(token, 0.0, format(font, color));
        rest = &rest[token.len()..];
    }
    job
}

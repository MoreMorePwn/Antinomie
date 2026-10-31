// SPDX-License-Identifier: GPL-3.0-only
//! Paged views of a category's full listing: disassembly as an address /
//! bytes / instruction table, decompilation as numbered source, strings as a
//! table. Rows load from the retained listing in pages, as they scroll in.
use super::records::{self, Structure};
use super::row_menu::{self, RowCommand};
use super::ReportAction;
use crate::theme;
use antinomie_monitor_core::{
    AnalysisData, AnalysisEntry, AnalysisKind, AnalysisListingPage, AnalysisReport,
    AnalysisSection, ListingSort, StructureField, LISTING_PAGE_MAX_ROWS,
};
use eframe::egui::{self, Color32, FontId, RichText};
use egui_extras::{Column, TableBuilder};

mod fields;
mod row_text;
#[cfg(test)]
pub(crate) use fields::listing_row;
pub(crate) use fields::{listing_fields, listing_row_with};

#[derive(Default)]
pub(super) struct ListingState {
    pub query: String,
    applied_query: String,
    /// The selected row: listing index and entry.
    pub selected: Option<(u64, AnalysisEntry)>,
    /// Selected function, stored as "{address:x}:{name}".
    pub function: Option<String>,
    /// Function headers already seen, in first-seen order.
    /// Keyed by "{address:x}:{name}". Empty until a page is shown.
    functions: Vec<ListedFunction>,
    /// Lines each function has in this view, by identity; counted over the
    /// whole listing by every page read.
    lines: std::collections::HashMap<String, u64>,
    record: Vec<(&'static str, crate::query::RowValue)>,
    /// The structures view a Structures listing shows.
    pub(super) scope: Option<Structure>,
    /// Whether the Content tab can show a row's offset.
    pub(super) content: bool,
    /// What the last row menu chose; the caller takes and carries it out.
    pub(super) command: Option<RowCommand>,
}

impl ListingState {
    pub(crate) fn set_record(&mut self, record: Vec<(&'static str, crate::query::RowValue)>) {
        self.record = record;
    }
}

/// Rows read ahead of the first one that is needed.
const LOOK_BEHIND: u64 = 128;

/// The sort state of the Strings table. Its header sorts the whole listing on
/// the archive reader, not the page on screen.
const STRINGS_TABLE: &str = "static-strings";

pub(super) fn show(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    section: &AnalysisSection,
    page: Option<&Result<AnalysisListingPage, String>>,
    state: &mut ListingState,
) -> Option<ReportAction> {
    let kind = section.kind;
    let mut action = None;
    let sort = listing_sort(ui.ctx(), kind, state.scope);
    let request = |start: u64, query: &str| {
        Some(ReportAction::ReadListing {
            report_id: report.id.clone(),
            kind,
            start,
            query: query.to_owned(),
            sort,
        })
    };
    let listing = section.listing.as_ref();
    let fields = listing_fields(kind);
    let tags = state
        .record
        .iter()
        .find_map(|(field, value)| {
            if *field == "tag" {
                if let crate::query::RowValue::List(values) = value {
                    return Some(values.as_slice());
                }
            }
            None
        })
        .unwrap_or_default();
    ui.horizontal(|ui| {
        let label = ui.label(egui_phosphor::regular::MAGNIFYING_GLASS);
        crate::query::filter_edit_fields(
            ui,
            &mut state.query,
            match kind {
                AnalysisKind::Disassembly => "mnemonic == call",
                AnalysisKind::Decompilation => "function contains main",
                _ => "value contains http",
            },
            ui.available_width(),
            &fields,
            tags,
        )
        .labelled_by(label.id);
    });
    let compiled = crate::query::compile_table(&state.query, &fields);
    if let Some(error) = compiled.error.as_ref() {
        crate::activity::warning(ui, format!("{error} · showing the last valid filter"));
    } else {
        state.applied_query = state.query.clone();
        crate::query::remember_valid_filter(ui, &state.applied_query);
        if state
            .selected
            .as_ref()
            .is_some_and(|(_, entry)| !compiled.keep_table(&listing_row_with(entry, &state.record)))
        {
            state.selected = None;
            ui.weak("The selected row is hidden by this filter.");
        }
    }
    let query = scoped_query(state.scope, &state.applied_query);
    let query = query.as_str();
    let current = page
        .and_then(|page| page.as_ref().ok())
        .filter(|page| page.kind == kind && page.query == query);
    match (current, listing) {
        (Some(page), Some(listing)) => {
            ui.label(format!("{} / {} rows", page.total, listing.rows));
        }
        (Some(page), _) => {
            ui.label(format!("{} matching rows", page.total));
        }
        _ => {
            crate::theme::loading(ui, "Reading…");
        }
    }
    let page = match page {
        Some(Ok(page)) if page.kind == kind && page.query == query => page,
        Some(Err(error)) => {
            crate::activity::error(ui, error);
            if ui.button("Retry").clicked() {
                action = request(0, query);
            }
            return action;
        }
        _ => {
            crate::theme::loading(ui, "Reading the listing…");
            return request(0, query);
        }
    };
    remember_functions(&mut state.functions, section, page);
    remember_lines(&mut state.lines, page);
    // A new order is read while the last one stays on screen.
    let resorting = page.sort != sort;
    if resorting {
        crate::theme::loading(ui, "Sorting…");
        action = request(0, query);
    }
    if page.total == 0 {
        ui.label(if state.applied_query.is_empty() {
            "This listing is empty."
        } else {
            "No row matches the search."
        });
        return action;
    }
    let mono = egui::TextStyle::Monospace.resolve(ui.style());
    let row_height = mono.size + 10.0;
    let loaded = page.start..page.start + page.rows.len() as u64;
    let mut needed = None;
    let mut clicked = None;
    let split = matches!(
        kind,
        AnalysisKind::Disassembly | AnalysisKind::Decompilation
    );
    let names = if split {
        state.functions.clone()
    } else {
        Vec::new()
    };
    if split {
        let panel_id = match kind {
            AnalysisKind::Disassembly => "listing-functions-disassembly",
            _ => "listing-functions-decompilation",
        };
        egui::SidePanel::left(panel_id)
            .resizable(true)
            .default_width(220.0)
            .width_range(160.0..=420.0)
            .frame(egui::Frame::new().inner_margin(egui::Margin {
                right: 8,
                ..Default::default()
            }))
            .show_inside(ui, |ui| {
                crate::code_listing::heading(ui, names.len(), names.len());
                if ui.button("Export text").clicked() {
                    action = Some(ReportAction::Export {
                        report_id: report.id.clone(),
                        kind: Some(kind),
                        format: antinomie_monitor_core::AnalysisExportFormat::Text,
                    });
                }
                if names.is_empty() {
                    ui.add(egui::Label::new("No function symbols loaded.").wrap());
                }
                let identities: Vec<String> = names
                    .iter()
                    .map(|item| function_identity(item.address, &item.name))
                    .collect();
                let selected = state
                    .function
                    .as_ref()
                    .and_then(|chosen| identities.iter().position(|identity| identity == chosen));
                let chosen = crate::code_listing::function_list(
                    ui,
                    kind_salt(kind),
                    names.len(),
                    |index| crate::code_listing::Function {
                        name: &names[index].name,
                        address: names[index].address,
                        lines: state.lines.get(&identities[index]).copied(),
                    },
                    selected,
                    |_, _| {},
                );
                if let Some(index) = chosen {
                    state.function = Some(identities[index].clone());
                }
            });
    }
    let structure_columns: Vec<(&str, Column)> = match state.scope {
        Some(scope) if kind == AnalysisKind::Structures => records::columns(kind, scope, false)
            .iter()
            .enumerate()
            .map(|(at, column)| {
                let width = if *column == records::Column::Value {
                    300.0
                } else {
                    140.0
                };
                // The last column takes what the others leave, so the table
                // spans the pane.
                let spec = if at + 1 == records::columns(kind, scope, false).len() {
                    Column::remainder().at_least(70.0).clip(true)
                } else {
                    Column::initial(width).at_least(70.0).clip(true)
                };
                (column.label(), spec)
            })
            .collect(),
        _ => Vec::new(),
    };
    let columns: &[(&str, Column)] = match kind {
        AnalysisKind::Structures if !structure_columns.is_empty() => &structure_columns,
        AnalysisKind::Disassembly => &[
            ("Address", Column::exact(mono.size * 7.5)),
            (
                "Bytes",
                Column::initial(mono.size * 9.0).at_least(40.0).clip(true),
            ),
            // The last column takes what the others leave, so the listing
            // spans its pane at any width.
            (
                "Instruction",
                Column::remainder().at_least(350.0).clip(true),
            ),
        ],
        AnalysisKind::Decompilation => &[
            ("Line", Column::exact(mono.size * 4.0)),
            ("Code", Column::remainder().at_least(400.0).clip(true)),
        ],
        AnalysisKind::Strings => &[
            ("Offset", Column::exact(mono.size * 8.0)),
            ("Encoding", Column::exact(mono.size * 6.0)),
            (
                "Length",
                Column::initial(mono.size * 12.0).at_least(40.0).clip(true),
            ),
            ("Text", Column::remainder().at_least(200.0).clip(true)),
        ],
        _ => &[
            ("Name", Column::initial(200.0).clip(true)),
            ("Value", Column::remainder().at_least(200.0).clip(true)),
        ],
    };
    if split {
        let surface = ui.available_rect_before_wrap();
        ui.painter().rect_filled(surface, 0.0, theme::terminal());
    }
    egui::ScrollArea::horizontal()
        .id_salt(("listing-horizontal", kind_salt(kind)))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.push_id(("listing-table", kind_salt(kind)), |ui| {
                // Rows select on click; text selection would swallow it.
                ui.style_mut().interaction.selectable_labels = false;
                let focus: Option<Vec<usize>> = state.function.as_ref().map(|identity| {
                    let mut current = None;
                    page.rows
                        .iter()
                        .enumerate()
                        .filter(|(_, (_, entry))| {
                            row_function_identity(entry, &names, &mut current, identity).as_deref()
                                == Some(identity.as_str())
                        })
                        .map(|(index, _)| index)
                        .collect()
                });
                let row_total = focus.as_ref().map_or(page.total as usize, Vec::len);
                if focus.as_ref().is_some_and(Vec::is_empty) {
                    ui.label("No rows of this function are in the loaded listing page.");
                }
                let height = ui.available_height().max(row_height);
                crate::widgets::table::begin(ui);
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
                        for (column, (title, _)) in columns.iter().enumerate() {
                            header.col(|ui| match kind {
                                AnalysisKind::Strings => {
                                    crate::table_sort::header(ui, STRINGS_TABLE, column, title)
                                }
                                AnalysisKind::Disassembly | AnalysisKind::Decompilation => {
                                    ordered_head(ui, title, kind)
                                }
                                _ => crate::table_sort::header(
                                    ui,
                                    &sort_table(kind, state.scope),
                                    column,
                                    title,
                                ),
                            });
                        }
                    })
                    .body(|body| {
                        body.rows(row_height, row_total, |mut row| {
                            let index = row.index();
                            let Some((listing_index, entry)) = (if let Some(focus) = &focus {
                                focus.get(index).map(|slot| &page.rows[*slot])
                            } else {
                                let index = index as u64;
                                loaded
                                    .contains(&index)
                                    .then(|| &page.rows[(index - page.start) as usize])
                            }) else {
                                needed.get_or_insert(index as u64);
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
                            cells(&mut row, kind, state.scope, entry, &mono, &state.lines);
                            row.response().context_menu(|ui| {
                                let cells: Vec<_> = columns
                                    .iter()
                                    .map(|(title, _)| *title)
                                    .zip(row_text::texts(kind, state.scope, entry))
                                    .collect();
                                if let Some(next) = row_menu::menu(
                                    ui,
                                    &cells,
                                    entry,
                                    report.specimen_len,
                                    state.content,
                                ) {
                                    state.command = Some(next);
                                }
                                ui.separator();
                                let field = match kind {
                                    AnalysisKind::Disassembly => "mnemonic",
                                    AnalysisKind::Decompilation => "code",
                                    AnalysisKind::Strings => "text",
                                    _ => "name",
                                };
                                if let Some((_, value)) = listing_row_with(entry, &state.record)
                                    .iter()
                                    .find(|(name, _)| *name == field)
                                {
                                    crate::query::value_menu(ui, field, value, &mut state.query);
                                }
                                ui.menu_button("Filter by field", |ui| {
                                    for (field, value) in listing_row_with(entry, &state.record) {
                                        ui.menu_button(field, |ui| {
                                            crate::query::value_menu(
                                                ui,
                                                field,
                                                &value,
                                                &mut state.query,
                                            );
                                        });
                                    }
                                });
                                if ui.button("Copy label and value").clicked() {
                                    ui.ctx()
                                        .copy_text(format!("{}\n{}", entry.label, entry.value));
                                    ui.close_menu();
                                }
                            });
                            let response = row.response();
                            if response.clicked() || response.secondary_clicked() {
                                clicked = Some((*listing_index, entry.clone()));
                            }
                        });
                    });
            });
        });
    if let Some(selection) = clicked {
        state.selected = Some(selection);
    }
    if let Some(index) = needed.filter(|_| !resorting) {
        action = request(index.saturating_sub(LOOK_BEHIND), query);
    }
    // Keep the page size in the type system's view of the bound.
    debug_assert!(page.rows.len() <= LISTING_PAGE_MAX_ROWS);
    action
}

/// Adds function headers from this page and from `section.entries`.
/// Later pages append; an identity already stored is left in place.
/// Instruction and source rows are not turned into functions.
fn remember_functions(
    functions: &mut Vec<ListedFunction>,
    section: &AnalysisSection,
    page: &AnalysisListingPage,
) {
    for entry in section
        .entries
        .iter()
        .chain(page.rows.iter().map(|(_, entry)| entry))
    {
        let Some(AnalysisData::Function { name, address, .. }) =
            entry.record.as_ref().map(|record| &record.data)
        else {
            continue;
        };
        let identity = function_identity(*address, name);
        if functions
            .iter()
            .any(|existing| function_identity(existing.address, &existing.name) == identity)
        {
            continue;
        }
        functions.push(ListedFunction {
            name: name.clone(),
            address: *address,
        });
    }
    for entry in section
        .entries
        .iter()
        .chain(page.rows.iter().map(|(_, entry)| entry))
    {
        for text in [&entry.label, &entry.value] {
            for function in index_ghidra_markers(text) {
                let identity = function_identity(function.address, &function.name);
                if functions
                    .iter()
                    .any(|existing| function_identity(existing.address, &existing.name) == identity)
                {
                    continue;
                }
                functions.push(ListedFunction {
                    name: function.name,
                    address: function.address,
                });
            }
        }
    }
}

/// Keep the line counts a page read brought.
fn remember_lines(lines: &mut std::collections::HashMap<String, u64>, page: &AnalysisListingPage) {
    for function in &page.functions {
        lines.insert(
            function_identity(function.address, &function.name),
            function.lines,
        );
    }
}

/// Every `@@ANTINOMIE-FUNCTION` marker in a saved Ghidra export.
/// Identity is the address plus the name Ghidra wrote. A second read of the
/// same text returns the same identities.
pub(crate) fn index_ghidra_markers(text: &str) -> Vec<GhidraFunction> {
    let mut functions = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("@@ANTINOMIE-FUNCTION\t") else {
            continue;
        };
        let mut parts = rest.split('\t');
        let address = parts
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let size = parts
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let name = parts
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("FUN");
        let identity = format!("{address:x}:{name}");
        if functions.iter().any(|existing: &GhidraFunction| {
            format!("{:x}:{}", existing.address, existing.name) == identity
        }) {
            continue;
        }
        functions.push(GhidraFunction {
            address,
            size,
            name: name.to_string(),
        });
    }
    functions
}

/// The saved export text, unchanged, so a later open sees the same markers.
pub(crate) fn export_ghidra_text(text: &str) -> String {
    if text.ends_with('\n') || text.is_empty() {
        text.to_string()
    } else {
        format!("{text}\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GhidraFunction {
    pub address: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Clone)]
struct ListedFunction {
    name: String,
    address: u64,
}

fn function_identity(address: u64, name: &str) -> String {
    format!("{address:x}:{name}")
}

/// Identity of one loaded row. Function headers carry the address. Later
/// instructions and source lines keep that header when the name matches.
/// A row before the first header on this page uses a function already
/// remembered from section entries or pages loaded in this view; it is not
/// matched when two remembered functions share the name and neither covers
/// the row.
fn row_function_identity(
    entry: &AnalysisEntry,
    functions: &[ListedFunction],
    current: &mut Option<String>,
    selected: &str,
) -> Option<String> {
    match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::Function { name, address, .. }) => {
            let identity = function_identity(*address, name);
            *current = Some(identity.clone());
            Some(identity)
        }
        Some(AnalysisData::Instruction {
            function, address, ..
        }) => body_identity(
            function.as_deref(),
            Some(*address),
            functions,
            current.as_deref(),
            selected,
        ),
        Some(AnalysisData::SourceLine {
            function, address, ..
        }) => body_identity(
            Some(function.as_str()),
            *address,
            functions,
            current.as_deref(),
            selected,
        ),
        _ => None,
    }
}

fn body_identity(
    name: Option<&str>,
    address: Option<u64>,
    functions: &[ListedFunction],
    current: Option<&str>,
    selected: &str,
) -> Option<String> {
    let name = name?;
    if let Some(address) = address {
        if let Some(owner) = functions
            .iter()
            .filter(|function| function.name == name && function.address <= address)
            .max_by_key(|function| function.address)
        {
            let blocked = functions
                .iter()
                .any(|function| function.address > owner.address && function.address <= address);
            if !blocked {
                return Some(function_identity(owner.address, &owner.name));
            }
        }
    }
    if let Some(current) = current {
        if identity_name(current) == Some(name) {
            return Some(current.to_owned());
        }
    }
    let same_name = functions.iter().any(|function| function.name == name);
    if !same_name && identity_name(selected) == Some(name) {
        return Some(selected.to_owned());
    }
    None
}

fn identity_name(identity: &str) -> Option<&str> {
    identity.split_once(':').map(|(_, name)| name)
}

/// The user's filter limited to one structures view.
fn scoped_query(scope: Option<Structure>, query: &str) -> String {
    let base = scope.map_or("", Structure::kind_query);
    match (base.is_empty(), query.trim().is_empty()) {
        (true, _) => query.to_owned(),
        (false, true) => base.to_owned(),
        (false, false) => format!("{base} && ({query})"),
    }
}

fn kind_salt(kind: AnalysisKind) -> &'static str {
    match kind {
        AnalysisKind::Disassembly => "disassembly",
        AnalysisKind::Decompilation => "decompilation",
        AnalysisKind::Strings => "strings",
        _ => "other",
    }
}

/// The sort state of a record table: one per category, and for the Structures
/// views one per view, whose columns differ.
fn sort_table(kind: AnalysisKind, scope: Option<Structure>) -> String {
    match (kind, scope) {
        (AnalysisKind::Structures, Some(scope)) => format!("static-structures-{}", scope.label()),
        _ => format!("static-{}", kind_salt(kind)),
    }
}

/// The column a header of this table stands for.
fn sort_field(
    kind: AnalysisKind,
    scope: Option<Structure>,
    column: usize,
) -> Option<StructureField> {
    use records::Column as C;
    let shown = match (kind, scope) {
        (AnalysisKind::Structures, Some(scope)) => records::columns(kind, scope, false),
        _ => &[C::Name, C::Value],
    };
    Some(match shown.get(column)? {
        C::Name => StructureField::Name,
        C::Value => StructureField::Value,
        C::Address => StructureField::Address,
        C::Offset => StructureField::Offset,
        C::VirtualSize => StructureField::VirtualSize,
        C::FileSize => StructureField::FileSize,
        C::Flags => StructureField::Flags,
        C::Library => StructureField::Library,
        C::Ordinal => StructureField::Ordinal,
        C::Kind => StructureField::Kind,
        C::Scope => StructureField::Scope,
        C::Defined => StructureField::Defined,
        C::Size => StructureField::Size,
        _ => return None,
    })
}

/// The order the header clicks chose for this listing, as the archive reader
/// takes it: the whole listing is sorted there, not the page on screen.
fn listing_sort(
    ctx: &egui::Context,
    kind: AnalysisKind,
    scope: Option<Structure>,
) -> Option<ListingSort> {
    match kind {
        AnalysisKind::Disassembly | AnalysisKind::Decompilation => None,
        AnalysisKind::Strings => {
            crate::triage::sort_current(ctx, STRINGS_TABLE).map(|spec| ListingSort {
                column: spec.column,
                descending: spec.descending,
                field: None,
            })
        }
        _ => {
            let spec = crate::triage::sort_current(ctx, &sort_table(kind, scope))?;
            Some(ListingSort {
                column: spec.column,
                descending: spec.descending,
                field: Some(sort_field(kind, scope, spec.column)?),
            })
        }
    }
}

/// A header that does not sort: these listings are in the order that means
/// something, with each function's rows under its header.
fn ordered_head(ui: &mut egui::Ui, title: &str, kind: AnalysisKind) {
    let why = match kind {
        AnalysisKind::Disassembly => {
            "Disassembly stays in address order: each function's instructions follow its header."
        }
        _ => "Decompiled source stays in line order: each function's lines follow its header.",
    };
    crate::widgets::table::head_cell(ui, |ui| {
        ui.add(egui::Label::new(crate::widgets::table::head_text(title)).truncate())
            .on_hover_text(why)
            .on_hover_cursor(egui::CursorIcon::NotAllowed);
    });
}

/// Room between the parts of a function's header row.
const FUNCTION_PART_GAP: f32 = 24.0;

fn code_format(font: &FontId, color: Color32) -> egui::text::TextFormat {
    egui::text::TextFormat {
        font_id: font.clone(),
        color,
        ..Default::default()
    }
}

fn mono_text(text: impl Into<String>, font: &FontId, color: Color32) -> RichText {
    RichText::new(text).font(font.clone()).color(color)
}

fn cells(
    row: &mut egui_extras::TableRow,
    kind: AnalysisKind,
    scope: Option<Structure>,
    entry: &AnalysisEntry,
    mono: &FontId,
    lines: &std::collections::HashMap<String, u64>,
) {
    let data = entry.record.as_ref().map(|record| &record.data);
    if let (AnalysisKind::Structures, Some(scope)) = (kind, scope) {
        for column in records::columns(kind, scope, false) {
            let text = column.text(entry);
            row.col(|ui| {
                ui.add(
                    egui::Label::new(super::meaning::meaning_text(
                        kind,
                        *column,
                        entry,
                        text.clone(),
                    ))
                    .truncate(),
                )
                .on_hover_text(&text);
            });
        }
        return;
    }
    match (kind, data) {
        (_, Some(AnalysisData::Function { name, address, .. })) => {
            // A function header spans the row visually: address, then name.
            let first = match kind {
                AnalysisKind::Decompilation => String::new(),
                _ => format!("{address:x}"),
            };
            row.col(|ui| {
                ui.label(mono_text(first, mono, theme::blue()).strong());
            });
            let count = lines.get(&function_identity(*address, name)).copied();
            if kind == AnalysisKind::Disassembly {
                row.col(|_| {});
            }
            row.col(|ui| {
                // Name, address and size are separate parts with room between
                // them (the address is also in the first column of a
                // disassembly, so only the decompilation repeats it here).
                let mut job = egui::text::LayoutJob::default();
                job.append(name, 0.0, code_format(&theme::bold_font(ui), theme::blue()));
                if kind == AnalysisKind::Decompilation {
                    job.append(
                        &format!("0x{address:x}"),
                        FUNCTION_PART_GAP,
                        code_format(mono, theme::muted()),
                    );
                }
                job.append(
                    &crate::code_listing::lines_text(count),
                    FUNCTION_PART_GAP,
                    code_format(mono, theme::muted()),
                );
                ui.add(egui::Label::new(job).truncate());
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
                let job = crate::code_listing::instruction(mnemonic, operands, mono);
                ui.add(egui::Label::new(job).truncate())
                    .on_hover_text(format!("{mnemonic} {operands}"));
            });
        }
        (AnalysisKind::Decompilation, Some(AnalysisData::SourceLine { line, .. })) => {
            row.col(|ui| {
                ui.label(mono_text(line.to_string(), mono, theme::muted()));
            });
            row.col(|ui| {
                ui.add(
                    egui::Label::new(crate::code_listing::highlight(&entry.value, mono)).truncate(),
                )
                .on_hover_text(&entry.value);
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
                ui.label(super::meaning::meaning_text(
                    kind,
                    records::Column::Encoding,
                    entry,
                    encoding.clone(),
                ));
            });
            row.col(|ui| {
                ui.label(crate::values::file_size(*byte_len));
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
            let label =
                super::meaning::shown_text(kind, records::Column::Name, entry, &entry.label);
            let value =
                super::meaning::shown_text(kind, records::Column::Value, entry, &entry.value);
            row.col(|ui| {
                ui.add(
                    egui::Label::new(super::meaning::meaning_text(
                        kind,
                        records::Column::Name,
                        entry,
                        label,
                    ))
                    .truncate(),
                );
            });
            row.col(|ui| {
                ui.add(
                    egui::Label::new(super::meaning::meaning_text(
                        kind,
                        records::Column::Value,
                        entry,
                        value.clone(),
                    ))
                    .truncate(),
                )
                .on_hover_text(value);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_annotation_context_does_not_replace_typed_row_fields() {
        use crate::query::RowValue as V;
        let entry = AnalysisEntry {
            label: "retained string".into(),
            value: "sample text".into(),
            offset: Some(0),
            record: None,
        };
        let mut state = ListingState::default();
        state.set_record(vec![
            ("entry.name", V::Text("renamed report".into())),
            ("tag", V::List(vec!["needs review".into()])),
            ("vm.id", V::Text("vm-one".into())),
            ("name", V::Text("wrong override".into())),
            ("offset", V::Number(123)),
        ]);
        let row = listing_row_with(&entry, &state.record);
        let query = crate::query::compile_table("name == \"retained string\" && offset == 0 && entry.name == \"renamed report\" && tag == \"needs review\" && vm.id == \"vm-one\"", &listing_fields(AnalysisKind::Strings));
        assert!(query.error.is_none(), "{:?}", query.error);
        assert!(query.keep_table(&row));
        assert!(!crate::query::compile_table(
            "name == \"wrong override\"",
            &listing_fields(AnalysisKind::Strings)
        )
        .keep_table(&row));
    }

    #[test]
    fn ghidra_markers_reopen_with_the_same_identities() {
        let text = "@@ANTINOMIE-BASE\t0\n@@ANTINOMIE-FUNCTION\t4294795840\t17\tFUN_fffd6240\nvoid FUN_fffd6240(void) {}\n@@ANTINOMIE-FUNCTION\t4096\t8\tFUN_00001000\nint other(void) { return 1; }\n";
        let first = index_ghidra_markers(text);
        let exported = export_ghidra_text(text);
        let second = index_ghidra_markers(&exported);
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].name, "FUN_fffd6240");
        assert_eq!(first[0].address, 4294795840);
        assert_eq!(first[1].address, 4096);
        assert!(exported.contains("FUN_fffd6240"));
        assert!(exported.contains("FUN_00001000"));
    }
}

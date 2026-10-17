//! Paged views of a category's full listing: disassembly as an address /
//! bytes / instruction table, decompilation as numbered source, strings as a
//! table. Rows load from the retained listing in pages, as they scroll in.
use super::records::{self, Structure};
use super::row_menu::{self, RowCommand};
use super::ReportAction;
use crate::theme;
use antinomie_monitor_core::{
    AnalysisData, AnalysisEntry, AnalysisKind, AnalysisListingPage, AnalysisReport,
    AnalysisSection, LISTING_PAGE_MAX_ROWS,
};
use eframe::egui::{self, text::LayoutJob, Color32, FontId, RichText, TextFormat};
use egui_extras::{Column, TableBuilder};

mod row_text;

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
                AnalysisKind::Disassembly => "Search instructions, functions or addresses",
                AnalysisKind::Decompilation => "Search decompiled code",
                _ => "Search all rows",
            },
            ui.available_width(),
            &fields,
            tags,
        )
        .labelled_by(label.id);
    });
    let compiled = crate::query::compile_table(&state.query, &fields);
    if let Some(error) = compiled.error.as_ref() {
        ui.colored_label(
            theme::warn(),
            format!("{error} · showing the last valid filter"),
        );
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
    ui.label(match (current, listing) {
        (Some(page), Some(listing)) => format!("{} / {} rows", page.total, listing.rows),
        (Some(page), _) => format!("{} matching rows", page.total),
        _ => "Reading…".into(),
    });
    let page = match page {
        Some(Ok(page)) if page.kind == kind && page.query == query => page,
        Some(Err(error)) => {
            ui.colored_label(theme::error(), error);
            if ui.button("Retry").clicked() {
                action = request(0, query);
            }
            return action;
        }
        _ => {
            ui.label("Reading the listing…");
            return request(0, query);
        }
    };
    remember_functions(&mut state.functions, section, page);
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
                ui.label(RichText::new("Functions").strong());
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
                egui::ScrollArea::vertical()
                    .id_salt(("listing-functions", kind_salt(kind)))
                    .show(ui, |ui| {
                        ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
                        for item in &names {
                            let identity = function_identity(item.address, &item.name);
                            // One line: the name, then its address.
                            let mut label = LayoutJob::default();
                            label.append(
                                &item.name,
                                0.0,
                                format(&egui::TextStyle::Body.resolve(ui.style()), theme::text()),
                            );
                            label.append(
                                &format!("  0x{:x}", item.address),
                                0.0,
                                format(&mono, theme::muted()),
                            );
                            let selected = state.function.as_deref() == Some(identity.as_str());
                            let mut response = ui.selectable_label(selected, label);
                            if !report.source_path.is_empty() {
                                response = response.on_hover_text(&report.source_path);
                            }
                            if response.clicked() {
                                state.function = Some(identity);
                            }
                        }
                    });
            });
    }
    let structure_columns: Vec<(&str, Column)> = match state.scope {
        Some(scope) if kind == AnalysisKind::Structures => records::columns(kind, scope, false)
            .iter()
            .map(|column| {
                let width = if *column == records::Column::Value {
                    300.0
                } else {
                    140.0
                };
                (
                    column.label(),
                    Column::initial(width).at_least(70.0).clip(true),
                )
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
            (
                "Instruction",
                Column::initial(800.0).at_least(350.0).clip(true),
            ),
        ],
        AnalysisKind::Decompilation => &[
            ("Line", Column::exact(mono.size * 4.0)),
            ("Code", Column::initial(1000.0).at_least(600.0).clip(true)),
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
                            cells(&mut row, kind, state.scope, entry, &mono);
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
    if let Some(index) = needed {
        action = request(index.saturating_sub(LOOK_BEHIND), query);
    }
    // Keep the page size in the type system's view of the bound.
    debug_assert!(page.rows.len() <= LISTING_PAGE_MAX_ROWS);
    action
}

/// Registry used both by the listing input and the whole retained listing reader.
pub(crate) fn listing_fields(kind: AnalysisKind) -> Vec<crate::query::FieldSpec<'static>> {
    use crate::query::FieldSpec as F;
    let mut fields = vec![
        F::text("name", "Row label"),
        F::text("value", "Complete retained row value"),
        F::number("offset", "File offset in octets"),
        F::number("record.id", "Structured record identity"),
        F::text("kind", "Structured record kind"),
    ];
    fields.extend(crate::query::LABEL_FIELDS);
    fields.extend(crate::query::ANALYSIS_FIELDS);
    fields.extend(match kind {
        AnalysisKind::Disassembly => vec![
            F::number("address", "Original instruction or function address"),
            F::text("bytes", "Instruction octets as hex text"),
            F::text("mnemonic", "Instruction mnemonic"),
            F::text("operands", "Instruction operands"),
            F::text("function", "Containing function name"),
            F::number("size", "Function extent in octets"),
        ],
        AnalysisKind::Decompilation => vec![
            F::number("address", "Original function address"),
            F::text("function", "Function name"),
            F::number("line", "Source line number"),
            F::text("code", "Retained source text"),
            F::number("size", "Function extent in octets"),
        ],
        AnalysisKind::Strings => vec![
            F::text("encoding", "String encoding"),
            F::number("length", "Observed string extent in octets"),
            F::number("retained_len", "Retained text extent in octets"),
            F::text("text", "Retained string text"),
        ],
        AnalysisKind::Structures => vec![
            F::text("group", "Metadata group"),
            F::text("scope", "Symbol scope"),
            F::text("symbol.kind", "Symbol kind"),
            F::boolean("undefined", "Undefined symbol"),
            F::text("library", "Import library"),
            F::number("ordinal", "Import/export ordinal"),
            F::number("address", "Recorded object address"),
            F::number("size", "Symbol or virtual section extent in octets"),
            F::number("file_size", "Section extent in file octets"),
            F::tags("flags", "Decoded section flags"),
            F::text("raw_flags", "Original section flags"),
        ],
        AnalysisKind::Entropy => vec![
            F::number("length", "Sampled range extent in octets"),
            F::number(
                "milli_bits",
                "Shannon entropy in thousandths of a bit per octet",
            ),
        ],
        AnalysisKind::Hardening => vec![
            F::text("scope", "Property scope"),
            F::text("observed", "Observed property"),
            F::text("evidence", "Property evidence"),
        ],
        AnalysisKind::Rules => vec![
            F::text("rule", "Rule name"),
            F::text("namespace", "Rule namespace"),
            F::tags("rule.tags", "Tags emitted by the rule engine"),
            F::text("ruleset", "Source rule set"),
        ],
        AnalysisKind::Capabilities => vec![
            F::text("namespace", "Capability namespace"),
            F::tags("attack", "ATT&CK references"),
            F::tags("mbc", "Malware behavior references"),
        ],
        AnalysisKind::Identification => vec![
            F::text("category", "Identification category"),
            F::text("version", "Identified version, when present"),
        ],
        AnalysisKind::Metadata => vec![F::text("group", "Metadata group")],
        AnalysisKind::Embedded => vec![F::text("description", "binwalk signature description")],
    });
    fields
}

/// An unavailable legacy/typed field remains missing instead of becoming zero or a placeholder.
pub(crate) fn listing_row_with(
    entry: &AnalysisEntry,
    context: &[(&'static str, crate::query::RowValue)],
) -> Vec<(&'static str, crate::query::RowValue)> {
    let mut row = listing_row(entry);
    row.extend(
        context
            .iter()
            .filter(|(field, _)| {
                crate::query::LABEL_FIELDS
                    .iter()
                    .chain(crate::query::ANALYSIS_FIELDS)
                    .any(|spec| spec.name == *field)
            })
            .cloned(),
    );
    row
}

/// A category's own row fields, without evidence annotation metadata.
pub(crate) fn listing_row(entry: &AnalysisEntry) -> Vec<(&'static str, crate::query::RowValue)> {
    use crate::query::RowValue as V;
    let number =
        |value: Option<u64>| value.map_or(V::Missing, |value| V::Number(i128::from(value)));
    let text = |value: &Option<String>| {
        value
            .as_ref()
            .map_or(V::Missing, |value| V::Text(value.clone()))
    };
    let mut row = vec![
        ("name", V::Text(entry.label.clone())),
        ("value", V::Text(entry.value.clone())),
        ("offset", number(entry.offset)),
    ];
    let Some(record) = &entry.record else {
        return row;
    };
    row.push(("record.id", number(Some(record.id))));
    let kind = match &record.data {
        AnalysisData::Field { group } => {
            row.push(("group", V::Text(group.clone())));
            "field"
        }
        AnalysisData::Section {
            name,
            address,
            virtual_size,
            file_size,
            raw_flags,
            flags,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("address", number(Some(*address))),
                ("size", number(Some(*virtual_size))),
                ("file_size", number(*file_size)),
                ("raw_flags", V::Text(raw_flags.clone())),
                ("flags", V::List(flags.clone())),
            ]);
            if entry.label == "Segment" {
                "segment"
            } else {
                "section"
            }
        }
        AnalysisData::Symbol {
            name,
            kind,
            scope,
            undefined,
            address,
            size,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("symbol.kind", V::Text(kind.clone())),
                ("scope", V::Text(scope.clone())),
                ("undefined", V::Bool(*undefined)),
                ("address", number(*address)),
                ("size", number(Some(*size))),
            ]);
            "symbol"
        }
        AnalysisData::Import {
            name,
            library,
            ordinal,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", text(name)),
                ("library", text(library)),
                ("ordinal", number(*ordinal)),
            ]);
            "import"
        }
        AnalysisData::Export {
            name,
            ordinal,
            address,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", text(name)),
                ("ordinal", number(*ordinal)),
                ("address", number(*address)),
            ]);
            "export"
        }
        AnalysisData::String {
            encoding,
            byte_len,
            retained_len,
        } => {
            row.extend([
                ("encoding", V::Text(encoding.clone())),
                ("length", number(Some(*byte_len))),
                ("retained_len", number(Some(*retained_len))),
                ("text", V::Text(entry.value.clone())),
            ]);
            "string"
        }
        AnalysisData::Entropy { range, milli_bits } => {
            row.retain(|(name, _)| *name != "offset");
            row.extend([
                ("offset", number(Some(range.offset))),
                ("length", number(Some(range.len))),
                ("milli_bits", V::Number(i128::from(*milli_bits))),
            ]);
            "entropy"
        }
        AnalysisData::Property {
            scope,
            observed,
            evidence,
        } => {
            row.extend([
                ("scope", V::Text(scope.clone())),
                ("observed", V::Text(observed.clone())),
                ("evidence", V::Text(evidence.clone())),
            ]);
            "property"
        }
        AnalysisData::Instruction {
            address,
            bytes,
            mnemonic,
            operands,
            function,
        } => {
            row.extend([
                ("address", number(Some(*address))),
                ("bytes", V::Text(bytes.clone())),
                ("mnemonic", V::Text(mnemonic.clone())),
                ("operands", V::Text(operands.clone())),
                ("function", text(function)),
            ]);
            "instruction"
        }
        AnalysisData::Function {
            name,
            address,
            size,
        } => {
            row.extend([
                ("address", number(Some(*address))),
                ("function", V::Text(name.clone())),
                ("size", number(Some(*size))),
            ]);
            "function"
        }
        AnalysisData::SourceLine {
            function,
            address,
            line,
        } => {
            row.extend([
                ("address", number(*address)),
                ("function", V::Text(function.clone())),
                ("line", V::Number(i128::from(*line))),
                ("code", V::Text(entry.value.clone())),
            ]);
            "source_line"
        }
        AnalysisData::Signature {
            offset,
            description,
        } => {
            row.retain(|(name, _)| *name != "offset");
            row.extend([
                ("offset", number(Some(*offset))),
                ("description", V::Text(description.clone())),
            ]);
            "signature"
        }
        AnalysisData::RuleMatch {
            rule,
            namespace,
            tags,
            ruleset,
        } => {
            row.extend([
                ("rule", V::Text(rule.clone())),
                ("namespace", V::Text(namespace.clone())),
                ("rule.tags", V::List(tags.clone())),
                ("ruleset", V::Text(ruleset.clone())),
            ]);
            "rule_match"
        }
        AnalysisData::Capability {
            name,
            namespace,
            attack,
            mbc,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("namespace", V::Text(namespace.clone())),
                ("attack", V::List(attack.clone())),
                ("mbc", V::List(mbc.clone())),
            ]);
            "capability"
        }
        AnalysisData::Identification {
            category,
            name,
            version,
        } => {
            row.retain(|(name, _)| *name != "name");
            row.extend([
                ("name", V::Text(name.clone())),
                ("category", V::Text(category.clone())),
                ("version", text(version)),
            ]);
            "identification"
        }
    };
    row.push(("kind", V::Text(kind.into())));
    row
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

fn mono_text(text: impl Into<String>, font: &FontId, color: Color32) -> RichText {
    RichText::new(text).font(font.clone()).color(color)
}

fn cells(
    row: &mut egui_extras::TableRow,
    kind: AnalysisKind,
    scope: Option<Structure>,
    entry: &AnalysisEntry,
    mono: &FontId,
) {
    let data = entry.record.as_ref().map(|record| &record.data);
    if let (AnalysisKind::Structures, Some(scope)) = (kind, scope) {
        for column in records::columns(kind, scope, false) {
            let text = column.text(entry);
            row.col(|ui| {
                ui.add(egui::Label::new(text.as_str()).truncate())
                    .on_hover_text(&text);
            });
        }
        return;
    }
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
                ui.add(egui::Label::new(job).truncate())
                    .on_hover_text(format!("{mnemonic} {operands}"));
            });
        }
        (AnalysisKind::Decompilation, Some(AnalysisData::SourceLine { line, .. })) => {
            row.col(|ui| {
                ui.label(mono_text(line.to_string(), mono, theme::muted()));
            });
            row.col(|ui| {
                ui.add(egui::Label::new(highlight(&entry.value, mono)).truncate())
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

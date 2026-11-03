// SPDX-License-Identifier: GPL-3.0-only
//! The parts of a listing page: the filter bar, the function list, the columns and the row menu.
use super::*;

/// The search box of a listing and what its filter does to the selection.
pub(super) fn filter_bar(ui: &mut egui::Ui, state: &mut ListingState, kind: AnalysisKind) {
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
        crate::activity::inline_only(
            ui,
            crate::activity::Level::Warn,
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
}

/// The list of functions beside a disassembly or a decompilation.
pub(super) fn function_panel(
    ui: &mut egui::Ui,
    report: &AnalysisReport,
    kind: AnalysisKind,
    names: &[ListedFunction],
    state: &mut ListingState,
    action: &mut Option<ReportAction>,
) {
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
            if ui
                .button("Export text")
                .on_hover_text(
                    "Save this listing as a text file. Export category… in the report menu offers more formats.",
                )
                .clicked()
            {
                *action = Some(ReportAction::Export {
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

/// The columns of a listing table, by what the listing shows.
pub(super) fn listing_columns(
    kind: AnalysisKind,
    scope: Option<Structure>,
    from_ghidra: bool,
    size: f32,
) -> Vec<(&'static str, Col)> {
    let structure_columns: Vec<(&str, Col)> = match scope {
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
                    Col::rest(80.0).at_least(70.0).clip(true)
                } else {
                    Col::flex(width).at_least(70.0).clip(true)
                };
                (column.label(), spec)
            })
            .collect(),
        _ => Vec::new(),
    };
    let columns: &[(&str, Col)] = match kind {
        AnalysisKind::Structures if !structure_columns.is_empty() => &structure_columns,
        AnalysisKind::Disassembly if from_ghidra => &[
            ("Address", Col::fixed(size * 7.5)),
            ("Bytes", Col::flex(size * 9.0).at_least(40.0).clip(true)),
            ("Instruction", Col::rest(80.0).at_least(350.0).clip(true)),
            ("Xrefs", Col::fixed(size * 4.5)),
        ],
        AnalysisKind::Disassembly => &[
            ("Address", Col::fixed(size * 7.5)),
            ("Bytes", Col::flex(size * 9.0).at_least(40.0).clip(true)),
            // The last column takes what the others leave, so the listing
            // spans its pane at any width.
            ("Instruction", Col::rest(80.0).at_least(350.0).clip(true)),
        ],
        AnalysisKind::Decompilation => &[
            ("Line", Col::fixed(size * 4.0)),
            ("Code", Col::rest(80.0).at_least(400.0).clip(true)),
        ],
        AnalysisKind::Strings => &[
            ("Offset", Col::fixed(size * 8.0)),
            ("Encoding", Col::fixed(size * 6.0)),
            ("Length", Col::flex(size * 12.0).at_least(40.0).clip(true)),
            ("Text", Col::rest(80.0).at_least(200.0).clip(true)),
        ],
        _ => &[
            ("Name", Col::flex(200.0).clip(true)),
            ("Value", Col::rest(80.0).at_least(200.0).clip(true)),
        ],
    };
    columns.to_vec()
}

/// The menu of a row: its copy and search items, and the filters its values offer.
pub(super) fn row_context_menu(
    ui: &mut egui::Ui,
    state: &mut ListingState,
    report: &AnalysisReport,
    kind: AnalysisKind,
    columns: &[(&str, Col)],
    entry: &AnalysisEntry,
    from_ghidra: bool,
) {
    let cells: Vec<_> = columns
        .iter()
        .map(|(title, _)| *title)
        .zip(if from_ghidra && kind == AnalysisKind::Disassembly {
            let ghidra = ghidra::texts(entry);
            if ghidra.is_empty() {
                row_text::texts(kind, state.scope, entry)
            } else {
                ghidra
            }
        } else {
            row_text::texts(kind, state.scope, entry)
        })
        .collect();
    if let Some(next) = row_menu::menu(ui, &cells, entry, report, kind, state.content) {
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
                crate::query::value_menu(ui, field, &value, &mut state.query);
            });
        }
    });
    if ui.button("Copy label and value").clicked() {
        ui.ctx()
            .copy_text(format!("{}\n{}", entry.label, entry.value));
        ui.close_menu();
    }
}

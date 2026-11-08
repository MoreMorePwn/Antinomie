// SPDX-License-Identifier: GPL-3.0-only
//! The table filter bar and the row menus: the egui side of the filter
//! language (the compiler of table filters is in `antinomie_triage::query`).
use super::*;

/// Retain the last valid filter while a draft is incomplete. State is scoped by the caller's UI id.
pub(crate) fn applied_table(
    ui: &mut egui::Ui,
    filter: &str,
    fields: &[FieldSpec<'_>],
    id: impl std::hash::Hash + std::fmt::Debug,
) -> Compiled {
    let id = ui.id().with(("applied-table-filter", id));
    let compiled = compile_table(filter, fields);
    if let Some(error) = compiled.error.as_ref() {
        crate::activity::inline_only(
            ui,
            crate::activity::Level::Warn,
            format!("{error} · showing the last valid filter"),
        );
        let applied = ui
            .data(|data| data.get_temp::<String>(id))
            .unwrap_or_default();
        // A changed table schema must never reuse an incompatible expression.
        let last = compile_table(&applied, fields);
        if last.error.is_none() {
            last
        } else {
            compile_table("", fields)
        }
    } else {
        ui.data_mut(|data| data.insert_temp(id, filter.to_owned()));
        compiled
    }
}

/// A full-width table filter with local draft/last-applied state.
/// Empty the filter of the table called `id`, so a row a note's chip opens is
/// not hidden by it.
pub(crate) fn clear_table_filter(ui: &egui::Ui, id: impl std::hash::Hash + std::fmt::Debug) {
    let id = ui.id().with(("table-filter", id));
    ui.data_mut(|data| data.insert_temp(id, String::new()));
}

pub(crate) fn table_filter(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash + std::fmt::Debug,
    hint: &str,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
) -> Compiled {
    let base = ui.id();
    table_filter_under(ui, base, id, hint, fields, known_values)
}

/// [`table_filter`] drawn inside a child ui (a row beside other controls) while
/// its draft stays keyed under the parent's id `base`, where callers look for it.
pub(crate) fn table_filter_under(
    ui: &mut egui::Ui,
    base: egui::Id,
    id: impl std::hash::Hash + std::fmt::Debug,
    hint: &str,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
) -> Compiled {
    let id = base.with(("table-filter", id));
    let mut text = ui
        .data(|data| data.get_temp::<String>(id))
        .unwrap_or_default();
    filter_edit_fields(
        ui,
        &mut text,
        hint,
        ui.available_width(),
        fields,
        known_values,
    );
    let history_id = id.with("history");
    let mut history = ui
        .data(|data| data.get_temp::<Vec<String>>(history_id))
        .unwrap_or_default();
    let applied = applied_table(ui, &text, fields, id);
    if !text.trim().is_empty()
        && compile_table(&text, fields).error.is_none()
        && history.first() != Some(&text)
    {
        history.retain(|entry| entry != &text);
        history.insert(0, text.clone());
        history.truncate(24);
    }
    ui.data_mut(|data| {
        data.insert_temp(
            ui.id().with(("filter-edit", hint)).with("history"),
            history.clone(),
        );
        data.insert_temp(history_id, history);
    });
    ui.data_mut(|data| data.insert_temp(id, text));
    applied
}

/// Context actions build valid typed clauses, including escaped text and unavailable values.
pub(crate) fn value_menu(ui: &mut egui::Ui, field: &str, value: &RowValue, filter: &mut String) {
    let clause = match value {
        RowValue::Missing => format!("missing({field})"),
        RowValue::Text(value) => format!("{field} == {}", quote_value(value, true)),
        RowValue::Number(value) => format!("{field} == {value}"),
        RowValue::Bool(value) => format!("{field} == {value}"),
        RowValue::List(values) if !values.is_empty() => format!(
            "{field} in {{{}}}",
            values
                .iter()
                .map(|value| quote_value(value, true))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        RowValue::List(_) => format!("missing({field})"),
    };
    for (label, join, exclude) in [
        ("Apply as filter", None, false),
        ("Add AND", Some("&&"), false),
        ("Add OR", Some("||"), false),
        ("Exclude", Some("&&"), true),
    ] {
        if ui.button(label).clicked() {
            let clause = if exclude {
                format!("!({clause})")
            } else {
                clause.clone()
            };
            *filter = if let Some(join) =
                join.filter(|_| !filter.trim().is_empty() && structured(filter))
            {
                format!("({filter}) {join} ({clause})")
            } else {
                clause
            };
            ui.close();
        }
    }
}

/// Row menu for a table whose draft lives in egui state: the short menu of
/// [`row_menu`](super::row_menu) on the cell that was clicked. The caller
/// supplies its parent UI's filter id, because a context menu has a different
/// UI identity.
pub(crate) fn table_row_menu(ui: &mut egui::Ui, filter_id: egui::Id, row: &[(&str, RowValue)]) {
    super::row_menu::menu(
        ui,
        filter_id,
        super::row_menu::Draft::State(filter_id),
        row,
        super::row_menu::Extras::default(),
    );
}

/// [`table_row_menu`] with an "Add note…" item for the row.
pub(crate) fn table_row_menu_with(
    ui: &mut egui::Ui,
    filter_id: egui::Id,
    row: &[(&str, RowValue)],
    extras: super::row_menu::Extras,
) {
    super::row_menu::menu(
        ui,
        filter_id,
        super::row_menu::Draft::State(filter_id),
        row,
        extras,
    );
}

/// The menu of a row of a table that has no filter: copy, and a note.
pub(crate) fn row_menu_plain(
    ui: &mut egui::Ui,
    key: egui::Id,
    row: &[(&str, RowValue)],
    extras: super::row_menu::Extras,
) {
    super::row_menu::menu(ui, key, super::row_menu::Draft::None, row, extras);
}

/// [`table_row_menu_with`] for a table whose filter text the caller owns.
pub(crate) fn row_menu_into(
    ui: &mut egui::Ui,
    key: egui::Id,
    filter: &mut String,
    row: &[(&str, RowValue)],
    extras: super::row_menu::Extras,
) {
    super::row_menu::menu(ui, key, super::row_menu::Draft::Text(filter), row, extras);
}

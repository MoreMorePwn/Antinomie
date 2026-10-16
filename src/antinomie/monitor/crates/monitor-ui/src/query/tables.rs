// SPDX-License-Identifier: MIT
//! Filters over generic evidence tables and their value menus.
use super::*;

/// Parse a table filter against only the fields the table supplies.
pub(crate) fn compile_table(filter: &str, fields: &[FieldSpec<'_>]) -> Compiled {
    let parse = || -> Result<Mode, String> {
        let filter = filter.trim();
        if filter.is_empty() {
            return Ok(Mode::All);
        }
        if !is_expression(filter)
            && !fields
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case(filter))
        {
            return Ok(Mode::Text(filter.into()));
        }
        let (tokens, offsets) = tokenize_with_positions(filter)?;
        let mut parser = Parser { tokens, at: 0 };
        let mut expr = parser.parse_or().map_err(|error| {
            position_error(
                error,
                filter,
                offsets.get(parser.at).copied().unwrap_or(filter.len()),
            )
        })?;
        if parser.at != parser.tokens.len() {
            return Err(position_error(
                "Unexpected text after the filter".into(),
                filter,
                offsets.get(parser.at).copied().unwrap_or(filter.len()),
            ));
        }
        validate_table(&mut expr, fields).map_err(|error| position_error(error, filter, 0))?;
        Ok(Mode::Expr(expr))
    };
    match parse() {
        Ok(mode) => Compiled { error: None, mode },
        Err(error) => Compiled {
            error: Some(error),
            mode: Mode::All,
        },
    }
}

/// Retain the last valid filter while a draft is incomplete. State is scoped by the caller's UI id.
pub(crate) fn applied_table(
    ui: &mut egui::Ui,
    filter: &str,
    fields: &[FieldSpec<'_>],
    id: impl std::hash::Hash,
) -> Compiled {
    let id = ui.id().with(("applied-table-filter", id));
    let compiled = compile_table(filter, fields);
    if let Some(error) = compiled.error.as_ref() {
        ui.colored_label(
            crate::theme::warn(),
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
pub(crate) fn table_filter(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    hint: &str,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
) -> Compiled {
    let id = ui.id().with(("table-filter", id));
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
            ui.close_menu();
        }
    }
}

/// Row menu for a table whose draft lives in egui state. The caller supplies its
/// parent UI's filter id, because a context menu has a different UI identity.
pub(crate) fn table_row_menu(ui: &mut egui::Ui, filter_id: egui::Id, row: &[(&str, RowValue)]) {
    ui.menu_button("Filter by field", |ui| {
        for (field, value) in row {
            ui.menu_button(*field, |ui| {
                let mut draft = ui
                    .data(|data| data.get_temp::<String>(filter_id))
                    .unwrap_or_default();
                value_menu(ui, field, value, &mut draft);
                ui.data_mut(|data| data.insert_temp(filter_id, draft));
            });
        }
    });
}

pub(crate) fn label_row(
    id: &str,
    name: &str,
    path: &str,
    tags: &[String],
) -> Vec<(&'static str, RowValue)> {
    vec![
        ("entry.id", RowValue::Text(id.into())),
        (
            "entry.name",
            if name.is_empty() {
                RowValue::Missing
            } else {
                RowValue::Text(name.into())
            },
        ),
        ("entry.path", RowValue::Text(path.into())),
        ("tag", RowValue::List(tags.into())),
        ("tags", RowValue::List(tags.into())),
        ("entry.tag", RowValue::List(tags.into())),
    ]
}

fn table_kind<'a>(value: &Value, fields: &'a [FieldSpec<'_>]) -> Result<&'a str, String> {
    match value {
        Value::Field(name) => fields
            .iter()
            .find(|field| field.name.eq_ignore_ascii_case(name))
            .map(|field| field.kind)
            .ok_or_else(|| format!("Unknown filter field {name}")),
        Value::Masked(inner, _) => {
            if table_kind(inner, fields)? != "integer" {
                return Err("A bit mask needs an integer field".into());
            }
            Ok("integer")
        }
        Value::Lower(inner) => {
            let kind = table_kind(inner, fields)?;
            if !matches!(kind, "text" | "text list") {
                return Err("lower needs a text field".into());
            }
            Ok(kind)
        }
        Value::Raw(index)
            if fields
                .iter()
                .any(|field| field.name == format!("args.raw[{index}]")) =>
        {
            Ok("integer")
        }
        _ => Err("Expected a field".into()),
    }
}

pub(super) fn literal(value: &mut Value) {
    if let Value::Field(name) = value {
        *value = Value::Text(name.clone());
    }
}

pub(super) fn validate_table(expr: &mut Expr, fields: &[FieldSpec<'_>]) -> Result<(), String> {
    match expr {
        Expr::Not(inner) => validate_table(inner, fields),
        Expr::And(left, right) | Expr::Or(left, right) => {
            validate_table(left, fields)?;
            validate_table(right, fields)
        }
        Expr::Value(value) | Expr::Exists(value) | Expr::Missing(value) => {
            table_kind(value, fields)?;
            Ok(())
        }
        Expr::Cmp(left, op, right) => {
            let kind = table_kind(left, fields)?;
            literal(right);
            validate_literal(kind, right)?;
            if matches!(op, Cmp::Lt | Cmp::Le | Cmp::Gt | Cmp::Ge) && kind != "integer" {
                return Err("Ordering needs an integer field".into());
            }
            if matches!(op, Cmp::Contains) && !matches!(kind, "text" | "text list") {
                return Err("contains needs a text field".into());
            }
            Ok(())
        }
        Expr::In(left, items) => {
            let kind = table_kind(left, fields)?;
            for item in items {
                literal(item);
                validate_literal(kind, item)?;
            }
            Ok(())
        }
    }
}

fn validate_literal(kind: &str, value: &Value) -> Result<(), String> {
    match (kind, value) {
        ("integer", Value::Number(_)) | ("text" | "text list" | "ip", Value::Text(_)) => Ok(()),
        ("boolean", Value::Text(value)) if value == "true" || value == "false" => Ok(()),
        ("boolean", _) => Err("Expected lowercase true or false".into()),
        ("integer", _) => Err("Expected an integer value".into()),
        _ => Err("Expected a text value (quote text containing spaces or punctuation)".into()),
    }
}

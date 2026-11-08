// SPDX-License-Identifier: GPL-3.0-only
//! The tables of the Triage reads (design 5.12.3 class T, 5.12.4, 5.12.5): the
//! field lists are the Triage crate's own `FieldSpec`s, so the filter language,
//! the sortable columns and the catalogue are the ones the window has. Filter,
//! sort and page are done over the whole row set of the cached scan, never
//! within one page.

use super::{
    catalogue::{FieldInfo, FieldType, TableInfo},
    cursor::{Cursor, CursorBinding},
    limits::fit_in_page,
    page::{Page, PageRequest},
    request::{Sort, SortDir},
    service::Opened,
};
use crate::api::error::ApiError;
use antinomie_triage::{
    Cell,
    query::{Compiled, FieldSpec, RowValue, compile_table},
    sorting,
};
use serde::Serialize;

/// The values one row offers a filter and a sort: `(field, value)`.
pub type Values = [(&'static str, RowValue)];

/// The catalogue type of a `FieldSpec` kind.
pub fn field_type(kind: &str) -> FieldType {
    match kind {
        "integer" => FieldType::Number,
        "boolean" => FieldType::Boolean,
        "text list" => FieldType::Tags,
        _ => FieldType::Text,
    }
}

/// The published table of a field list: every column is sortable.
pub fn table_info(fields: &[FieldSpec<'_>]) -> TableInfo {
    TableInfo {
        fields: fields
            .iter()
            .map(|field| FieldInfo {
                name: field.name.to_owned(),
                kind: field_type(field.kind),
                description: field.detail.to_owned(),
                sortable: true,
            })
            .collect(),
    }
}

/// The values of a stored row: its first cell carries them.
pub fn values_of(row: &[Cell]) -> &Values {
    row.first()
        .map(|cell| cell.values.as_slice())
        .unwrap_or_default()
}

/// Read access to a row's values, with the defaults an absent value takes.
pub struct V<'a>(pub &'a Values);

impl V<'_> {
    fn find(&self, key: &str) -> Option<&RowValue> {
        self.0
            .iter()
            .find(|(name, _)| *name == key)
            .map(|(_, value)| value)
    }

    pub fn text(&self, key: &str) -> String {
        self.opt_text(key).unwrap_or_default()
    }

    pub fn opt_text(&self, key: &str) -> Option<String> {
        match self.find(key)? {
            RowValue::Text(text) => Some(text.clone()),
            RowValue::Number(number) => Some(number.to_string()),
            RowValue::Bool(value) => Some(value.to_string()),
            RowValue::List(items) => Some(items.join(", ")),
            RowValue::Missing => None,
        }
    }

    pub fn number(&self, key: &str) -> Option<i128> {
        match self.find(key)? {
            RowValue::Number(number) => Some(*number),
            _ => None,
        }
    }

    pub fn u64(&self, key: &str) -> u64 {
        self.number(key)
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0)
    }

    pub fn opt_u64(&self, key: &str) -> Option<u64> {
        self.number(key).and_then(|n| u64::try_from(n).ok())
    }

    pub fn u32(&self, key: &str) -> u32 {
        u32::try_from(self.u64(key)).unwrap_or(u32::MAX)
    }

    pub fn flag(&self, key: &str) -> Option<bool> {
        match self.find(key)? {
            RowValue::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn list(&self, key: &str) -> Vec<String> {
        match self.find(key) {
            Some(RowValue::List(items)) => items.clone(),
            Some(RowValue::Text(text)) if !text.is_empty() => vec![text.clone()],
            _ => Vec::new(),
        }
    }
}

/// `q` compiled against a table's fields. A syntax or unknown-field error is
/// `invalid_argument` naming `q`, with `details.position` (the 1-based column).
pub fn compile_q(q: Option<&str>, fields: &[FieldSpec<'_>]) -> Result<Compiled, ApiError> {
    let compiled = compile_table(q.unwrap_or(""), fields);
    match &compiled.error {
        None => Ok(compiled),
        Some(text) => Err(q_error(text)),
    }
}

/// The `invalid_argument` of a filter error such as "Unknown field x at column 3".
pub fn q_error(text: &str) -> ApiError {
    let error = ApiError::invalid_argument("q", text.to_owned());
    match text
        .rsplit_once(" at column ")
        .and_then(|(_, column)| column.trim().parse::<u64>().ok())
    {
        Some(position) => error.with_detail("position", serde_json::json!(position)),
        None => error,
    }
}

/// The sort, checked against a table's fields: `invalid_argument` naming
/// `sort` for a field the table does not publish.
pub fn check_sort(sort: Option<&Sort>, fields: &[FieldSpec<'_>]) -> Result<(), ApiError> {
    match sort {
        Some(sort) if !fields.iter().any(|field| field.name == sort.field) => {
            Err(ApiError::invalid_argument(
                "sort",
                format!("{} is not a sortable field of this table", sort.field),
            ))
        }
        _ => Ok(()),
    }
}

/// The indexes of `rows` that pass `keep`, in the order of `sort` (the rows'
/// own order, for ties and when there is no sort).
pub fn select<'a>(
    rows: impl IntoIterator<Item = &'a Values>,
    compiled: &Compiled,
    keep: impl Fn(&Values) -> bool,
    sort: Option<&Sort>,
) -> Vec<usize> {
    let rows: Vec<&Values> = rows.into_iter().collect();
    let mut order: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, values)| keep(values) && compiled.keep_table(values))
        .map(|(at, _)| at)
        .collect();
    if let Some(sort) = sort {
        let descending = sort.dir == SortDir::Desc;
        let atom = |at: usize| {
            rows[at]
                .iter()
                .find(|(name, _)| *name == sort.field)
                .map_or(sorting::Atom::Missing, |(_, value)| sorting::value(value))
        };
        // `sort_by` is stable: equal keys keep the default order.
        order.sort_by(|a, b| sorting::compare(&atom(*a), &atom(*b), descending));
    }
    order
}

/// What a table page needs besides its rows.
pub struct Cut<'a> {
    pub request: &'a PageRequest,
    pub max: u32,
    pub binding: CursorBinding,
    /// Rows the scan left out of its table (past its per-table limit): the
    /// page is `partial` and the total not exact.
    pub omitted: u64,
    /// The rows carry sample or guest text.
    pub untrusted: bool,
}

/// One page of the rows `order` names, `convert`ed; the cursor of the next.
pub fn page_of<T: Serialize>(
    opened: &Opened,
    order: &[usize],
    cut: &Cut<'_>,
    convert: impl Fn(usize) -> T,
) -> Result<Page<T>, ApiError> {
    let limit = cut.request.effective_limit(100, cut.max)? as usize;
    let start = match &cut.request.cursor {
        Some(text) => Cursor::resume(text, cut.binding)?,
        None => 0,
    } as usize;
    let end = start.saturating_add(limit).min(order.len());
    let mut items: Vec<T> = order
        .get(start..end)
        .unwrap_or_default()
        .iter()
        .map(|at| convert(*at))
        .collect();
    let kept = fit_in_page(
        items
            .iter()
            .map(|item| serde_json::to_vec(item).map_or(0, |bytes| bytes.len())),
    );
    items.truncate(kept);
    let next = start + items.len();
    let total = order.len() as u64 + cut.omitted;
    let mut page = opened.counted_page(items, total, cut.untrusted);
    if cut.omitted > 0 {
        page.total_exact = Some(false);
        page.partial = Some(true);
    }
    page.next_cursor = (next < order.len()).then(|| {
        Cursor {
            offset: next as u64,
            binding: cut.binding,
        }
        .encode()
    });
    Ok(page)
}

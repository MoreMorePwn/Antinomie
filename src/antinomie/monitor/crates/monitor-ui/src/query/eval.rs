// SPDX-License-Identifier: GPL-3.0-only
//! Filter expressions, values and their evaluation against a row.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

pub(super) enum Expr {
    Value(Value),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(Value, Cmp, Value),
    Exists(Value),
    Missing(Value),
    In(Value, Vec<Value>),
}

pub(super) enum Value {
    Field(String),
    Number(i128),
    Text(String),
    Raw(usize),
    Masked(Box<Value>, u64),
    Lower(Box<Value>),
}

pub(super) enum Resolved {
    Number(i128),
    Text(String),
    List(Vec<String>),
    Bool(bool),
    Missing,
}

impl Expr {
    pub(super) fn eval_table(&self, row: &[(&str, RowValue)]) -> bool {
        match self {
            Self::Not(inner) => !inner.eval_table(row),
            Self::And(left, right) => left.eval_table(row) && right.eval_table(row),
            Self::Or(left, right) => left.eval_table(row) || right.eval_table(row),
            Self::Value(Value::Field(name))
                if row.iter().any(|(field, value)| {
                    field.eq_ignore_ascii_case(name) && matches!(value, RowValue::Bool(_))
                }) =>
            {
                row.iter().any(|(field, value)| {
                    field.eq_ignore_ascii_case(name) && matches!(value, RowValue::Bool(true))
                })
            }
            Self::Value(value) => match value.resolve_table(row) {
                Resolved::Number(number) => number != 0,
                Resolved::Bool(value) => value,
                value => is_present(&value),
            },
            Self::Exists(value) => is_present(&value.resolve_table(row)),
            Self::Missing(value) => !is_present(&value.resolve_table(row)),
            Self::Cmp(left, op, right) => {
                compare(*op, &left.resolve_table(row), &right.resolve_table(row))
            }
            Self::In(left, values) => values
                .iter()
                .any(|right| compare(Cmp::Eq, &left.resolve_table(row), &right.resolve_table(row))),
        }
    }
    pub(super) fn eval(&self, invocation: &InvocationSummary) -> Result<bool, String> {
        match self {
            Expr::Not(inner) => Ok(!inner.eval(invocation)?),
            Expr::And(left, right) => Ok(left.eval(invocation)? && right.eval(invocation)?),
            Expr::Or(left, right) => Ok(left.eval(invocation)? || right.eval(invocation)?),
            Expr::Value(value) => Ok(match value.resolve(invocation)? {
                Resolved::Number(number) => number != 0,
                Resolved::Text(text) => !text.is_empty(),
                Resolved::List(items) => !items.is_empty(),
                Resolved::Missing => false,
                Resolved::Bool(value) => value,
            }),
            Expr::Exists(value) => Ok(is_present(&value.resolve(invocation)?)),
            Expr::Missing(value) => Ok(!is_present(&value.resolve(invocation)?)),
            Expr::Cmp(left, op, right) => {
                let left = left.resolve(invocation)?;
                let right = right.resolve(invocation)?;
                Ok(compare(*op, &left, &right))
            }
            Expr::In(left, items) => in_list(left.resolve(invocation)?, items, |item| {
                item.resolve(invocation)
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn eval_record(&self, labels: &RecordLabels<'_>) -> Result<bool, String> {
        match self {
            Expr::Not(inner) => Ok(!inner.eval_record(labels)?),
            Expr::And(left, right) => Ok(left.eval_record(labels)? && right.eval_record(labels)?),
            Expr::Or(left, right) => Ok(left.eval_record(labels)? || right.eval_record(labels)?),
            Expr::Value(value) => Ok(match value.resolve_record(labels)? {
                Resolved::Number(number) => number != 0,
                Resolved::Text(text) => !text.is_empty(),
                Resolved::List(items) => !items.is_empty(),
                Resolved::Missing => false,
                Resolved::Bool(value) => value,
            }),
            Expr::Exists(value) => Ok(is_present(&value.resolve_record(labels)?)),
            Expr::Missing(value) => Ok(!is_present(&value.resolve_record(labels)?)),
            Expr::Cmp(left, op, right) => Ok(compare(
                *op,
                &left.resolve_record(labels)?,
                &right.resolve_record(labels)?,
            )),
            Expr::In(left, items) => in_list(left.resolve_record(labels)?, items, |item| {
                item.resolve_record(labels)
            }),
        }
    }
}

fn in_list(
    left: Resolved,
    items: &[Value],
    mut resolve: impl FnMut(&Value) -> Result<Resolved, String>,
) -> Result<bool, String> {
    if matches!(left, Resolved::Missing) {
        return Ok(false);
    }
    for item in items {
        if compare(Cmp::Eq, &left, &resolve(item)?) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn is_present(value: &Resolved) -> bool {
    match value {
        Resolved::Number(_) => true,
        Resolved::Bool(_) => true,
        Resolved::Text(_) => true,
        Resolved::List(items) => !items.is_empty(),
        Resolved::Missing => false,
    }
}

impl Value {
    fn resolve_table(&self, row: &[(&str, RowValue)]) -> Resolved {
        match self {
            Self::Number(number) => Resolved::Number(*number),
            Self::Text(text) => Resolved::Text(text.clone()),
            Self::Masked(inner, mask) => match inner.resolve_table(row) {
                Resolved::Number(number) => Resolved::Number(number & i128::from(*mask)),
                _ => Resolved::Missing,
            },
            Self::Raw(_) => Resolved::Missing,
            Self::Lower(inner) => lower_value(inner.resolve_table(row)),
            Self::Field(name) => match row
                .iter()
                .find(|(field, _)| field.eq_ignore_ascii_case(name))
                .map(|(_, value)| value)
            {
                Some(RowValue::Number(number)) => Resolved::Number(*number),
                Some(RowValue::Text(text)) => Resolved::Text(text.clone()),
                Some(RowValue::Bool(value)) => Resolved::Bool(*value),
                Some(RowValue::List(values)) if !values.is_empty() => {
                    Resolved::List(values.clone())
                }
                _ => Resolved::Missing,
            },
        }
    }
    fn resolve(&self, invocation: &InvocationSummary) -> Result<Resolved, String> {
        match self {
            Self::Lower(inner) => Ok(lower_value(inner.resolve(invocation)?)),
            Value::Number(number) => Ok(Resolved::Number(*number)),
            Value::Text(text) => Ok(Resolved::Text(text.clone())),
            Value::Raw(index) => {
                let Some(event) = trace::representative(invocation) else {
                    return Ok(Resolved::Missing);
                };
                Ok(event
                    .args
                    .and_then(|args| args.get(*index).copied())
                    .map(|value| Resolved::Number(i128::from(value)))
                    .unwrap_or(Resolved::Missing))
            }
            Value::Masked(value, mask) => match value.resolve(invocation)? {
                Resolved::Number(number) => Ok(Resolved::Number(number & i128::from(*mask))),
                _ => Ok(Resolved::Missing),
            },
            Value::Field(name) => match field(invocation, name) {
                Ok(value) => Ok(value),
                Err(_) if !name.contains('.') => Ok(Resolved::Text(name.clone())),
                Err(error) => Err(error),
            },
        }
    }

    #[cfg(test)]
    fn resolve_record(&self, labels: &RecordLabels<'_>) -> Result<Resolved, String> {
        match self {
            Self::Lower(inner) => Ok(lower_value(inner.resolve_record(labels)?)),
            Value::Number(number) => Ok(Resolved::Number(*number)),
            Value::Text(text) => Ok(Resolved::Text(text.clone())),
            Value::Raw(_) => Err("args.raw is a syscall field".into()),
            Value::Masked(value, mask) => match value.resolve_record(labels)? {
                Resolved::Number(number) => Ok(Resolved::Number(number & i128::from(*mask))),
                _ => Ok(Resolved::Missing),
            },
            Value::Field(name) => record_field(labels, name),
        }
    }
}

fn lower_value(value: Resolved) -> Resolved {
    match value {
        Resolved::Text(text) => Resolved::Text(text.to_lowercase()),
        Resolved::List(values) => {
            Resolved::List(values.into_iter().map(|text| text.to_lowercase()).collect())
        }
        _ => Resolved::Missing,
    }
}

#[cfg(test)]
fn record_field(labels: &RecordLabels<'_>, name: &str) -> Result<Resolved, String> {
    match name.to_ascii_lowercase().as_str() {
        "tag" | "tags" | "entry.tag" => Ok(if labels.tags.is_empty() {
            Resolved::Missing
        } else {
            Resolved::List(labels.tags.to_vec())
        }),
        "entry.name" | "name" => {
            if labels.name.is_empty() {
                Ok(Resolved::Missing)
            } else {
                Ok(Resolved::Text(labels.name.to_string()))
            }
        }
        "entry.id" => Ok(Resolved::Text(labels.id.to_string())),
        "entry.path" => Ok(Resolved::Text(labels.path.to_string())),
        _ => Err(unknown_field(name)),
    }
}

pub(super) fn compare(op: Cmp, left: &Resolved, right: &Resolved) -> bool {
    match (left, right) {
        (Resolved::Missing, _) | (_, Resolved::Missing) => false,
        (Resolved::Bool(left), Resolved::Text(right)) => match op {
            Cmp::Eq => right == if *left { "true" } else { "false" },
            Cmp::Ne => right != if *left { "true" } else { "false" },
            _ => false,
        },
        (Resolved::Bool(left), Resolved::Bool(right)) => match op {
            Cmp::Eq => left == right,
            Cmp::Ne => left != right,
            _ => false,
        },
        (Resolved::Bool(_), _) | (_, Resolved::Bool(_)) => false,
        (Resolved::List(items), Resolved::Text(needle)) => match op {
            Cmp::Eq => items.iter().any(|item| item == needle),
            Cmp::Ne => !items.iter().any(|item| item == needle),
            Cmp::Contains => items.iter().any(|item| item.contains(needle.as_str())),
            Cmp::Lt | Cmp::Le | Cmp::Gt | Cmp::Ge => false,
        },
        (Resolved::List(items), Resolved::Number(number)) => match op {
            Cmp::Eq => items.iter().any(|item| item == &number.to_string()),
            Cmp::Ne => !items.iter().any(|item| item == &number.to_string()),
            _ => false,
        },
        (Resolved::List(_), _) | (_, Resolved::List(_)) => false,
        (Resolved::Number(left), Resolved::Number(right)) => match op {
            Cmp::Eq => left == right,
            Cmp::Ne => left != right,
            Cmp::Lt => left < right,
            Cmp::Le => left <= right,
            Cmp::Gt => left > right,
            Cmp::Ge => left >= right,
            Cmp::Contains => left.to_string().contains(&right.to_string()),
        },
        (left, right) => {
            let left = match left {
                Resolved::Text(text) => text.clone(),
                Resolved::Number(number) => number.to_string(),
                Resolved::List(items) => items.join(", "),
                Resolved::Missing => return false,
                Resolved::Bool(value) => value.to_string(),
            };
            let right = match right {
                Resolved::Text(text) => text.clone(),
                Resolved::Number(number) => number.to_string(),
                Resolved::List(items) => items.join(", "),
                Resolved::Missing => return false,
                Resolved::Bool(value) => value.to_string(),
            };
            match op {
                Cmp::Eq => left == right,
                Cmp::Ne => left != right,
                Cmp::Contains => left.contains(&right),
                Cmp::Lt | Cmp::Le | Cmp::Gt | Cmp::Ge => false,
            }
        }
    }
}

/// Captured path text for one argument name. A pointer in `args` is not a path.
fn captured_path(event: &EventSummary, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(text) = event.fields.iter().find_map(|field| {
            let key = field.key.rsplit('.').next().unwrap_or(field.key.as_str());
            if key != *name {
                return None;
            }
            let captured = crate::trace::covered_preview(field);
            if captured.is_empty() {
                return None;
            }
            let text = String::from_utf8_lossy(captured);
            Some(text.split('\0').next().unwrap_or_default().to_owned())
        }) {
            return Some(text);
        }
    }
    None
}

fn path_names(alias: &str, argument: &str) -> Option<&'static [&'static str]> {
    match alias {
        "path" | "filename" | "pathname" => Some(&["path", "filename", "pathname"]),
        "old_path" | "oldname" => Some(&["old_path", "oldname"]),
        "new_path" | "newname" => Some(&["new_path", "newname"]),
        _ => match argument {
            "path" | "filename" | "pathname" => Some(&["path", "filename", "pathname"]),
            "old_path" | "oldname" => Some(&["old_path", "oldname"]),
            "new_path" | "newname" => Some(&["new_path", "newname"]),
            _ => None,
        },
    }
}

pub(super) fn field(invocation: &InvocationSummary, name: &str) -> Result<Resolved, String> {
    let key = name.to_ascii_lowercase();
    if antinomie_monitor_core::filter_members::descriptor(&key).is_some() {
        use antinomie_monitor_core::filter_members::MemberValue;
        return Ok(
            match antinomie_monitor_core::filter_members::decode(invocation, &key) {
                MemberValue::Integer(value) => Resolved::Number(value),
                MemberValue::Text(value) => Resolved::Text(value),
                MemberValue::Boolean(value) => Resolved::Bool(value),
                MemberValue::Missing => Resolved::Missing,
            },
        );
    }
    // Every invocation row carries call_id. A row with no entry, exit, or async
    // event still has that id; there is no separate call record to look up.
    if matches!(key.as_str(), "call.id" | "call_id") {
        return Ok(Resolved::Number(i128::from(invocation.call_id)));
    }
    let Some(event) = trace::representative(invocation) else {
        return Ok(Resolved::Missing);
    };
    let number = match key.as_str() {
        "stream.id" => Some(i128::from(invocation.stream_id)),
        "syscall.num" | "syscall.number" => Some(i128::from(event.syscall_nr)),
        "tid" | "process.tid" => Some(i128::from(event.tid)),
        "pid" | "process.pid" | "process.tgid" if event.pid != 0 => Some(i128::from(event.pid)),
        "cpu" => Some(i128::from(event.cpu)),
        "task" | "cookie" | "task.cookie" | "process.cookie" => Some(i128::from(event.task_cookie)),
        "event.id" | "event.sequence" => Some(i128::from(event.event_seq)),
        "event.time_ns" => Some(i128::from(event.timestamp_ns)),
        _ => None,
    };
    if let Some(number) = number {
        return Ok(Resolved::Number(number));
    }
    if matches!(key.as_str(), "pid" | "process.pid" | "process.tgid") {
        return Ok(Resolved::Missing);
    }
    if matches!(
        key.as_str(),
        "process.ppid" | "process.parent_cookie" | "process.uid" | "process.gid" | "process.comm"
    ) {
        return Ok(Resolved::Missing);
    }
    if key == "process.state" {
        return Ok(if invocation.task_exit.is_some() {
            Resolved::Text("exited".into())
        } else {
            Resolved::Missing
        });
    }
    if matches!(key.as_str(), "process.exe" | "process.argv") {
        let events: Vec<_> = invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
            .chain(invocation.task_exit.iter())
            .collect();
        let committed = events.iter().any(|event| {
            event.fields.iter().any(|field| {
                field.key == "lifecycle.exec_commit"
                    && field.complete
                    && crate::trace::covered_preview(field).len() >= 8
            })
        }) || matches!(event.syscall_nr, 59 | 322)
            && invocation
                .exit
                .as_ref()
                .and_then(|exit| exit.result)
                .is_some_and(|result| result == 0);
        if !committed {
            return Ok(Resolved::Missing);
        }
        if key == "process.exe" {
            return Ok(events
                .iter()
                .find_map(|event| captured_path(event, &["path", "filename", "pathname"]))
                .map_or(Resolved::Missing, Resolved::Text));
        }
        let mut arguments = std::collections::BTreeMap::new();
        for field in events.iter().flat_map(|event| &event.fields) {
            let Some(suffix) = field.key.split_once("argv[").map(|(_, suffix)| suffix) else {
                continue;
            };
            let Some(index) = suffix
                .strip_suffix(']')
                .and_then(|index| index.parse::<u64>().ok())
            else {
                continue;
            };
            let data = crate::trace::covered_preview(field);
            if data.is_empty() || !data.contains(&0) {
                continue;
            }
            let value = String::from_utf8_lossy(data)
                .split('\0')
                .next()
                .unwrap_or_default()
                .to_owned();
            if arguments
                .insert(index, value.clone())
                .is_some_and(|previous| previous != value)
            {
                return Ok(Resolved::Missing);
            }
        }
        return Ok(if arguments.is_empty() {
            Resolved::Missing
        } else {
            Resolved::List(arguments.into_values().collect())
        });
    }
    if key == "event.complete" {
        return Ok(Resolved::Bool(
            invocation
                .entry
                .iter()
                .chain(invocation.exit.iter())
                .chain(invocation.async_events.iter())
                .chain(invocation.task_exit.iter())
                .all(|event| event.complete),
        ));
    }
    if key == "event.gap" {
        let issues: Vec<_> = invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
            .chain(invocation.task_exit.iter())
            .flat_map(|event| event.issues.iter().cloned())
            .collect();
        return Ok(if issues.is_empty() {
            Resolved::Missing
        } else {
            Resolved::List(issues)
        });
    }
    if key == "syscall.group" {
        return Ok(
            antinomie_monitor_core::syscall_groups::SyscallGroup::of(&event.syscall_name)
                .map_or(Resolved::Missing, |group| {
                    Resolved::Text(group.label().into())
                }),
        );
    }
    if key == "syscall.duration_ns" {
        return Ok(invocation
            .entry
            .as_ref()
            .zip(invocation.exit.as_ref())
            .and_then(|(entry, exit)| exit.timestamp_ns.checked_sub(entry.timestamp_ns))
            .map_or(Resolved::Missing, |duration| {
                Resolved::Number(i128::from(duration))
            }));
    }
    if matches!(key.as_str(), "syscall.errno" | "syscall.success") {
        let outcome = match invocation.exit.as_ref() {
            Some(exit) => exit.result,
            None => event.result,
        };
        return Ok(outcome.map_or(Resolved::Missing, |result| {
            let error = (-4095..=-1).contains(&result);
            if key == "syscall.success" {
                Resolved::Bool(!error)
            } else if error {
                Resolved::Number(-i128::from(result))
            } else {
                Resolved::Missing
            }
        }));
    }
    if matches!(key.as_str(), "ret" | "result" | "syscall.ret") {
        // The return is the exit record. `representative` prefers the entry,
        // whose result is often absent even when the exit has already returned.
        let outcome = match invocation.exit.as_ref() {
            Some(exit) => exit.result,
            None => event.result,
        };
        return Ok(outcome.map_or(Resolved::Missing, |value| {
            Resolved::Number(i128::from(value))
        }));
    }
    if matches!(key.as_str(), "syscall.name" | "syscall" | "name") {
        return Ok(Resolved::Text(event.syscall_name.clone()));
    }
    if key == "info" {
        return Ok(Resolved::Text(trace::info(invocation)));
    }
    if matches!(key.as_str(), "tag" | "tags") {
        return Ok(Resolved::Missing);
    }
    if let Some(index) = key.strip_prefix("args.") {
        if let Ok(index) = index.parse::<usize>() {
            return Ok(event
                .args
                .and_then(|args| args.get(index).copied())
                .map_or(Resolved::Missing, |value| {
                    Resolved::Number(i128::from(value))
                }));
        }
        let alias = match index {
            "addr" | "address" => "address",
            "len" | "length" => "length",
            "prot" | "protection" => "protection",
            "buf" | "buffer" => "buf",
            "file" | "filename" | "pathname" => "path",
            "old_path" | "oldname" => "oldname",
            "new_path" | "newname" => "newname",
            other => other,
        };
        let slot = if let Ok(index) = alias.parse::<usize>() {
            Some(index)
        } else {
            (0..6).find(|index| {
                let name = argument_name(event.syscall_nr, *index);
                name.eq_ignore_ascii_case(alias)
                    || (alias == "address" && name.eq_ignore_ascii_case("addr"))
                    || (alias == "length" && name.eq_ignore_ascii_case("len"))
                    || (alias == "protection" && name.eq_ignore_ascii_case("prot"))
                    || (alias == "buf" && name.eq_ignore_ascii_case("buffer"))
                    || (alias == "oldname" && name.eq_ignore_ascii_case("old_path"))
                    || (alias == "newname" && name.eq_ignore_ascii_case("new_path"))
                    || (alias == "path"
                        && matches!(
                            name,
                            "path" | "old_path" | "new_path" | "filename" | "pathname"
                        ))
            })
        };
        let Some(index) = slot else {
            return Ok(Resolved::Missing);
        };
        let argument = argument_name(event.syscall_nr, index);
        if let Some(names) = path_names(alias, argument) {
            return Ok(captured_path(event, names).map_or(Resolved::Missing, Resolved::Text));
        }
        return Ok(event
            .args
            .and_then(|args| args.get(index).copied())
            .map(|value| {
                let signed_type = antinomie_monitor_core::syscalls::syscall(event.syscall_nr)
                    .and_then(|syscall| syscall.arguments.get(index))
                    .map(|argument| argument.c_type.trim());
                let number = match signed_type {
                    Some("int" | "pid_t" | "clockid_t" | "key_t" | "mqd_t") => {
                        i128::from(value as u32 as i32)
                    }
                    Some("long" | "off_t" | "loff_t" | "ssize_t") => i128::from(value as i64),
                    _ => i128::from(value),
                };
                Resolved::Number(number)
            })
            .unwrap_or(Resolved::Missing));
    }
    Err(unknown_field(name))
}

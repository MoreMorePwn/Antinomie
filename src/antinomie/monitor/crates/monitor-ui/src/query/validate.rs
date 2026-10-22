// SPDX-License-Identifier: GPL-3.0-only
//! Compiling and checking a filter before it is applied.
use super::*;

#[cfg(test)]
pub(crate) fn matches(filter: &str, invocation: &InvocationSummary) -> Result<bool, String> {
    let compiled = compile_note(filter);
    if let Some(error) = compiled.error.clone() {
        return Err(error);
    }
    Ok(compiled.keep(invocation))
}

pub(super) fn compiled(filter: &str, record: bool) -> Result<Mode, String> {
    let filter = filter.trim();
    if filter.is_empty() {
        return Ok(Mode::All);
    }
    if !is_expression(filter)
        && !(if record {
            known_record_field(filter)
        } else {
            known_field(filter)
        })
    {
        return Ok(Mode::Text(filter.to_owned()));
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
    normalize_literals(&mut expr);
    check_fields(&expr, record).map_err(|error| position_error(error, filter, 0))?;
    let fields = fields_for(if record {
        FilterScope::Record
    } else {
        FilterScope::Syscall
    });
    validate_table(&mut expr, &fields).map_err(|error| position_error(error, filter, 0))?;
    Ok(Mode::Expr(expr))
}

fn normalize_literals(expr: &mut Expr) {
    match expr {
        Expr::Cmp(_, _, right) => literal(right),
        Expr::Not(inner) => normalize_literals(inner),
        Expr::And(left, right) | Expr::Or(left, right) => {
            normalize_literals(left);
            normalize_literals(right);
        }
        _ => {}
    }
}

fn check_fields(expr: &Expr, record: bool) -> Result<(), String> {
    match expr {
        Expr::Value(value) => require_field(value, record),
        Expr::Not(inner) => check_fields(inner, record),
        Expr::And(left, right) | Expr::Or(left, right) => {
            check_fields(left, record)?;
            check_fields(right, record)
        }
        Expr::Cmp(left, _, right) => {
            require_field(left, record)?;
            check_value(right, record)
        }
        Expr::Exists(value) | Expr::Missing(value) => require_field(value, record),
        Expr::In(left, items) => {
            require_field(left, record)?;
            if items.is_empty() {
                return Err("Empty set".into());
            }
            for item in items {
                check_literal(item)?;
            }
            Ok(())
        }
    }
}

fn check_value(value: &Value, record: bool) -> Result<(), String> {
    match value {
        Value::Field(name) => {
            if record {
                if !known_record_field(name) {
                    return Err(unknown_field(name));
                }
                return Ok(());
            }
            if name.contains('.') && !known_field(name) {
                return Err(unknown_field(name));
            }
            Ok(())
        }
        Value::Masked(inner, _) | Value::Lower(inner) => check_value(inner, record),
        Value::Raw(_) if record => Err("args.raw is a syscall field".into()),
        Value::Raw(_) | Value::Number(_) | Value::Text(_) => Ok(()),
    }
}

fn require_field(value: &Value, record: bool) -> Result<(), String> {
    match value {
        Value::Raw(_) if record => Err("args.raw is a syscall field".into()),
        Value::Raw(_) => Ok(()),
        Value::Field(name) if record && known_record_field(name) => Ok(()),
        Value::Field(name) if !record && known_field(name) => Ok(()),
        Value::Field(name) => Err(unknown_field(name)),
        Value::Masked(inner, _) | Value::Lower(inner) => require_field(inner, record),
        Value::Number(_) | Value::Text(_) => Err("Expected a field".into()),
    }
}

fn known_record_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "tag" | "tags" | "entry.tag" | "entry.name" | "entry.id" | "entry.path" | "name"
    )
}

fn check_literal(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(_) | Value::Text(_) => Ok(()),
        _ => Err("Expected a number or quoted text in the set".into()),
    }
}

pub(super) fn unknown_field(name: &str) -> String {
    format!(
        "Unknown filter field {name}. Fields: syscall.num, syscall.name, tid, pid, ret, info, tag, call.id, args.N, args.<name>"
    )
}

fn known_field(name: &str) -> bool {
    let key = name.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "syscall.num"
            | "syscall.number"
            | "syscall.name"
            | "syscall"
            | "name"
            | "tid"
            | "pid"
            | "cpu"
            | "task"
            | "cookie"
            | "task.cookie"
            | "ret"
            | "result"
            | "syscall.ret"
            | "info"
            | "tag"
            | "tags"
            | "call.id"
            | "call_id"
            | "event.id"
            | "event.sequence"
            | "stream.id"
            | "event.time_ns"
            | "event.complete"
            | "event.gap"
            | "syscall.group"
            | "syscall.errno"
            | "syscall.success"
            | "syscall.duration_ns"
            | "process.cookie"
            | "process.pid"
            | "process.tgid"
            | "process.tid"
            | "process.ppid"
            | "process.parent_cookie"
            | "process.uid"
            | "process.gid"
            | "process.comm"
            | "process.exe"
            | "process.argv"
            | "process.state"
    ) || key.strip_prefix("args.").is_some_and(|rest| {
        rest.parse::<usize>().is_ok_and(|slot| slot < 6)
            || matches!(
                rest,
                "addr"
                    | "address"
                    | "len"
                    | "length"
                    | "prot"
                    | "protection"
                    | "buf"
                    | "buffer"
                    | "file"
                    | "filename"
                    | "pathname"
                    | "path"
                    | "old_path"
                    | "new_path"
            )
            || schema_argument_fields()
                .iter()
                .any(|field| field.name.eq_ignore_ascii_case(name))
            || antinomie_monitor_core::filter_members::descriptor(&key).is_some()
    })
}

pub(super) fn is_expression(filter: &str) -> bool {
    filter.contains("==")
        || filter.contains("!=")
        || filter.contains("&&")
        || filter.contains("||")
        || filter.contains('<')
        || filter.contains('>')
        || filter.contains('(')
        || filter.contains('&')
        || filter.contains('{')
        || filter.contains('[')
        || filter.starts_with('!')
        || filter.to_lowercase().contains(" contains ")
        || has_filter_word(filter, "exists")
        || has_filter_word(filter, "missing")
        || has_filter_word(filter, "in")
        || has_filter_word(filter, "and")
        || has_filter_word(filter, "or")
        || has_filter_word(filter, "not")
        || filter.split_whitespace().any(|word| word.contains('.'))
}

fn has_filter_word(filter: &str, word: &str) -> bool {
    filter
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|part| part.eq_ignore_ascii_case(word))
}

// SPDX-License-Identifier: GPL-3.0-only
//! Output formats (design 3.2): `human`, `json` and `ndjson`.
//!
//! A command returns a [`Reply`]; this module turns a reply or a [`CliError`]
//! into the text for standard output and standard error. Nothing else prints
//! results, so every command obeys the same envelope.
use crate::error::CliError;
use antinomie_service::API_VERSION;
use clap::ValueEnum;
use serde::Serialize;
use serde_json::{Value, json};
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    Human,
    Json,
    Ndjson,
}

impl Format {
    /// `human` on a terminal, `json` otherwise (design 3.1).
    pub fn default_for(stdout_is_terminal: bool) -> Self {
        if stdout_is_terminal {
            Format::Human
        } else {
            Format::Json
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum ColorWhen {
    Auto,
    Always,
    Never,
}

impl ColorWhen {
    /// Whether human output uses colour. `NO_COLOR` (any non-empty value)
    /// turns `auto` off; `always` and `never` ignore it.
    pub fn enabled(self, stderr_is_terminal: bool, no_color: bool) -> bool {
        match self {
            ColorWhen::Always => true,
            ColorWhen::Never => false,
            ColorWhen::Auto => stderr_is_terminal && !no_color,
        }
    }
}

/// What a successful command returns.
#[derive(Clone, Debug)]
pub struct Reply {
    pub body: Body,
    /// Text for the human format; absent, a generic rendering of the value is used.
    pub human: Option<String>,
}

#[derive(Clone, Debug)]
pub enum Body {
    /// One object: the `result` member.
    Value(Value),
    /// A list: `{"items": [...], "next_cursor": ...}` in `json`, one item per
    /// line in `ndjson`.
    List {
        items: Vec<Value>,
        next_cursor: Option<String>,
    },
}

impl Reply {
    pub fn value(value: Value) -> Self {
        Self {
            body: Body::Value(value),
            human: None,
        }
    }

    pub fn list(items: Vec<Value>, next_cursor: Option<String>) -> Self {
        Self {
            body: Body::List { items, next_cursor },
            human: None,
        }
    }

    pub fn with_human(mut self, text: String) -> Self {
        self.human = Some(text);
        self
    }

    /// The `result` member of the JSON envelope.
    pub fn result(&self) -> Value {
        match &self.body {
            Body::Value(value) => value.clone(),
            Body::List { items, next_cursor } => {
                json!({"items": items, "next_cursor": next_cursor})
            }
        }
    }
}

#[derive(Serialize)]
struct Success<'a> {
    api_version: u32,
    ok: bool,
    result: &'a Value,
}

#[derive(Serialize)]
struct Failure {
    api_version: u32,
    ok: bool,
    error: Value,
}

/// Text for the two standard streams. Each non-empty part ends with a newline.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rendered {
    pub stdout: String,
    pub stderr: String,
}

fn line(value: &impl Serialize) -> String {
    let mut text = serde_json::to_string(value).expect("a JSON value always serializes");
    text.push('\n');
    text
}

pub fn render_success(format: Format, reply: &Reply) -> Rendered {
    let stdout = match format {
        Format::Json => line(&Success {
            api_version: API_VERSION,
            ok: true,
            result: &reply.result(),
        }),
        Format::Ndjson => match &reply.body {
            Body::Value(value) => line(&json!({"result": value})),
            Body::List { items, next_cursor } => {
                let mut text: String = items.iter().map(line).collect();
                text.push_str(&line(&json!({
                    "result": {"count": items.len(), "next_cursor": next_cursor}
                })));
                text
            }
        },
        Format::Human => match &reply.human {
            Some(text) => with_newline(text.clone()),
            None => with_newline(generic_human(&reply.result())),
        },
    };
    Rendered {
        stdout,
        stderr: String::new(),
    }
}

/// `color` only affects the human error line.
pub fn render_failure(format: Format, error: &CliError, color: bool) -> Rendered {
    match format {
        Format::Json => Rendered {
            stdout: line(&Failure {
                api_version: API_VERSION,
                ok: false,
                error: error.to_value(),
            }),
            stderr: String::new(),
        },
        Format::Ndjson => Rendered {
            stdout: line(&json!({"error": error.to_value()})),
            stderr: String::new(),
        },
        Format::Human => {
            let label = if color {
                "\x1b[31mError:\x1b[0m"
            } else {
                "Error:"
            };
            Rendered {
                stdout: error
                    .human_output
                    .clone()
                    .map(with_newline)
                    .unwrap_or_default(),
                stderr: format!("{label} {}\n", error.message),
            }
        }
    }
}

fn with_newline(mut text: String) -> String {
    if !text.ends_with('\n') {
        text.push('\n');
    }
    text
}

/// A table with a header row; columns are padded to their widest cell and the
/// last column is not padded.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(cell.chars().count());
        }
    }
    let mut out = String::new();
    let mut emit = |cells: &mut dyn Iterator<Item = &str>| {
        let cells: Vec<&str> = cells.collect();
        let last = cells.len().saturating_sub(1);
        for (index, cell) in cells.iter().enumerate() {
            if index == last {
                out.push_str(cell);
            } else {
                let _ = write!(out, "{cell:<width$}  ", width = widths[index]);
            }
        }
        out.push('\n');
    };
    emit(&mut headers.iter().copied());
    for row in rows {
        emit(&mut row.iter().map(String::as_str));
    }
    out
}

/// `key: value` lines with the values aligned.
pub fn block(pairs: &[(&str, String)]) -> String {
    let width = pairs.iter().map(|(key, _)| key.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (key, value) in pairs {
        let _ = writeln!(
            out,
            "{:<width$}  {value}",
            format!("{key}:"),
            width = width + 1
        );
    }
    out
}

fn scalar(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// The fallback rendering: an object as a block, a list of objects as a table
/// (columns in the order the keys first appear).
fn generic_human(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            if let Some(Value::Array(items)) = map.get("items")
                && map.len() <= 2
            {
                return generic_human(&Value::Array(items.clone()));
            }
            let pairs: Vec<(&str, String)> = map
                .iter()
                .map(|(key, value)| (key.as_str(), scalar(value)))
                .collect();
            block(&pairs)
        }
        Value::Array(items) => {
            let mut headers: Vec<&str> = Vec::new();
            for item in items {
                if let Value::Object(map) = item {
                    for key in map.keys() {
                        if !headers.contains(&key.as_str()) {
                            headers.push(key);
                        }
                    }
                }
            }
            if headers.is_empty() {
                return items.iter().map(|i| scalar(i) + "\n").collect();
            }
            let rows: Vec<Vec<String>> = items
                .iter()
                .map(|item| {
                    headers
                        .iter()
                        .map(|key| item.get(*key).map(scalar).unwrap_or_else(|| "-".into()))
                        .collect()
                })
                .collect();
            table(&headers, &rows)
        }
        other => scalar(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn default_format_follows_the_terminal() {
        assert_eq!(Format::default_for(true), Format::Human);
        assert_eq!(Format::default_for(false), Format::Json);
    }

    #[test]
    fn json_success_is_one_document_with_the_envelope() {
        let reply = Reply::value(json!({"answer": 42}));
        let out = render_success(Format::Json, &reply);
        assert_eq!(
            out.stdout,
            "{\"api_version\":1,\"ok\":true,\"result\":{\"answer\":42}}\n"
        );
        assert!(out.stderr.is_empty());
    }

    #[test]
    fn json_failure_is_the_envelope_on_stdout() {
        let error = CliError::new(ErrorCode::NotFound, "no such run").with_field("run");
        let out = render_failure(Format::Json, &error, false);
        assert_eq!(
            out.stdout,
            "{\"api_version\":1,\"ok\":false,\"error\":{\"code\":\"not_found\",\
\"message\":\"no such run\",\"field\":\"run\",\"retryable\":false,\"details\":{}}}\n"
        );
        assert!(out.stderr.is_empty());
        let value = parse(&out.stdout);
        assert_eq!(value["ok"], json!(false));
        assert_eq!(value["api_version"], json!(1));
    }

    #[test]
    fn json_list_carries_the_cursor() {
        let reply = Reply::list(vec![json!({"a": 1}), json!({"a": 2})], Some("c1".into()));
        let value = parse(&render_success(Format::Json, &reply).stdout);
        assert_eq!(value["result"]["items"].as_array().unwrap().len(), 2);
        assert_eq!(value["result"]["next_cursor"], json!("c1"));
        let last = parse(&render_success(Format::Json, &Reply::list(vec![], None)).stdout);
        assert_eq!(last["result"]["next_cursor"], Value::Null);
    }

    #[test]
    fn ndjson_value_is_one_result_line() {
        let out = render_success(Format::Ndjson, &Reply::value(json!({"k": "v"})));
        assert_eq!(out.stdout, "{\"result\":{\"k\":\"v\"}}\n");
    }

    #[test]
    fn ndjson_list_is_one_item_per_line_then_the_result_line() {
        let reply = Reply::list(vec![json!({"n": 1}), json!({"n": 2})], None);
        let out = render_success(Format::Ndjson, &reply).stdout;
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(parse(lines[0]), json!({"n": 1}));
        assert_eq!(parse(lines[1]), json!({"n": 2}));
        assert_eq!(
            parse(lines[2]),
            json!({"result": {"count": 2, "next_cursor": null}})
        );
    }

    #[test]
    fn ndjson_failure_is_an_error_line() {
        let out = render_failure(Format::Ndjson, &CliError::internal("boom"), false);
        let value = parse(&out.stdout);
        assert_eq!(value["error"]["code"], json!("internal"));
        assert_eq!(out.stdout.lines().count(), 1);
    }

    #[test]
    fn human_failure_goes_to_stderr_with_optional_stdout_text() {
        let error = CliError::internal("boom").with_human_output("table".into());
        let out = render_failure(Format::Human, &error, false);
        assert_eq!(out.stdout, "table\n");
        assert_eq!(out.stderr, "Error: boom\n");
        let colored = render_failure(Format::Human, &error, true);
        assert!(colored.stderr.starts_with("\x1b[31mError:"));
    }

    #[test]
    fn colour_rules() {
        assert!(ColorWhen::Always.enabled(false, true));
        assert!(!ColorWhen::Never.enabled(true, false));
        assert!(ColorWhen::Auto.enabled(true, false));
        assert!(!ColorWhen::Auto.enabled(true, true));
        assert!(!ColorWhen::Auto.enabled(false, false));
    }

    #[test]
    fn tables_align_columns_and_leave_the_last_unpadded() {
        let text = table(
            &["name", "ok"],
            &[
                vec!["qemu".into(), "yes".into()],
                vec!["kvm".into(), "no".into()],
            ],
        );
        assert_eq!(text, "name  ok\nqemu  yes\nkvm   no\n");
    }

    #[test]
    fn blocks_align_values() {
        let text = block(&[("a", "1".into()), ("long", "2".into())]);
        assert_eq!(text, "a:     1\nlong:  2\n");
    }

    #[test]
    fn generic_human_renders_objects_and_lists() {
        let object = render_success(Format::Human, &Reply::value(json!({"b": 2, "a": "x"})));
        assert_eq!(object.stdout, "b:  2\na:  x\n");
        let list = render_success(
            Format::Human,
            &Reply::list(vec![json!({"k": "one"}), json!({"k": "two"})], None),
        );
        assert_eq!(list.stdout, "k\none\ntwo\n");
    }

    #[test]
    fn explicit_human_text_wins() {
        let reply = Reply::value(json!({"a": 1})).with_human("custom".into());
        assert_eq!(render_success(Format::Human, &reply).stdout, "custom\n");
    }
}

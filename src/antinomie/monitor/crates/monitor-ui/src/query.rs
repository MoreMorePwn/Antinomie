// SPDX-License-Identifier: MIT
//! Display filter for syscall rows. A bare word still matches the row text.
//! A comparison such as `syscall.num == 9 && args.fd < 3` uses the fields below.
use crate::trace::{self, argument_name};
use antinomie_monitor_core::{EventSummary, InvocationSummary};
use eframe::egui;

pub(crate) const HELP: &str = "\
syscall.num  syscall.name  syscall\n\
tid  pid  ret  result  cpu  task  cookie  call.id  call_id\n\
info  tag\n\
args.0 … args.5   args.<name>  (fd, path, buf, addr, len, prot, flags, dirfd, …)\n\
args.raw[0] … args.raw[5]\n\
==  !=  <  <=  >  >=  contains  in\n\
exists  missing  &  &&  ||  !  ( )\n\
exists ret\n\
syscall.num in {9, 10}\n\
args.prot & 7 == 7\n\
args.raw[4] == 2\n\
call.id == 1\n\
A word with none of these matches the syscall name, TID, task or info text.
tag and tags on a syscall row are missing unless that row has an annotation.
On a run or result they match annotation.json, not path text.";

/// Fields the syscall and record filters actually implement.
const KEYWORDS: &[(&str, &str, &str)] = &[
    ("event.id", "integer", "Recorded event sequence identity"),
    ("event.sequence", "integer", "Recorded event sequence"),
    ("event.time_ns", "integer", "Guest monotonic event timestamp in ns"),
    ("event.complete", "boolean", "All retained invocation events are complete"),
    ("event.gap", "text list", "Recorded completeness issues"),
    ("syscall.group", "text", "Native syscall group"),
    ("syscall.errno", "integer", "Positive errno for Linux error returns; missing on success"),
    ("syscall.success", "boolean", "Observed syscall result is not a Linux errno"),
    ("syscall.duration_ns", "integer", "Exit minus entry guest timestamp in ns"),
    ("process.cookie", "integer", "Recorded task cookie"),
    ("stream.id", "integer", "Recorded telemetry stream identity"),
    ("process.pid", "integer", "Recorded process ID"),
    ("process.tgid", "integer", "Recorded process thread-group ID"),
    ("process.tid", "integer", "Recorded thread ID"),
    ("process.ppid", "integer", "Recorded parent PID; missing without per-task provenance"),
    ("process.parent_cookie", "integer", "Recorded parent cookie; missing without per-task provenance"),
    ("process.uid", "integer", "Recorded task UID; missing when not observed"),
    ("process.gid", "integer", "Recorded task GID; missing when not observed"),
    ("process.comm", "text", "Recorded task comm; not guessed from a file basename"),
    ("process.exe", "text", "Captured executable path on an observed committed exec"),
    ("process.argv", "text list", "Captured argument strings on an observed committed exec"),
    ("process.state", "text", "Observed task exit; otherwise missing without state evidence"),
    ("syscall.num", "integer", "Native syscall number"),
    ("syscall.name", "text", "Syscall name, case-sensitive in =="),
    ("tid", "integer", "Thread id"),
    ("pid", "integer", "Process id"),
    ("cpu", "integer", "CPU recorded on the event"),
    ("task", "integer", "Task cookie"),
    ("cookie", "integer", "Task cookie"),
    ("ret", "integer", "Exit result; missing when the exit was not recorded"),
    ("result", "integer", "Same as ret"),
    ("syscall.ret", "integer", "Same as ret"),
    ("info", "text", "Rendered trace text"),
    (
        "tag",
        "text list",
        "Annotation tag. Missing on a syscall row. On a run or result, one stored tag.",
    ),
    ("tags", "text list", "Same as tag"),
    ("entry.tag", "text list", "Same as tag, for a run or result annotation"),
    ("call.id", "integer", "Invocation id"),
    ("args.raw[0..5]", "integer", "Captured argument word. Not decoded path text."),
    (
        "args.path",
        "text",
        "Captured path, filename, or pathname string. Not the pointer in args.raw.",
    ),
    ("args.old_path", "text", "Captured old path string"),
    ("args.new_path", "text", "Captured new path string"),
    (
        "args.<name>",
        "integer",
        "Named argument word for this syscall: fd, dirfd, flags, prot, addr, len, and the schema name.",
    ),
    ("entry.id", "text", "Run or result id"),
    ("entry.name", "text", "Annotation name. Missing when the annotation has no name."),
    ("name", "text", "Syscall name on a syscall row; annotation name on a run or result"),
    ("entry.path", "text", "Run executable or result path"),
];

/// Short recommended filters. Opened from Help → Filter guide.
pub(crate) fn guide(ctx: &egui::Context) {
    let id = egui::Id::new("filter-guide-open");
    let mut open = ctx.data(|data| data.get_temp::<bool>(id).unwrap_or(false));
    if !open {
        return;
    }
    egui::Window::new("Filter guide")
        .open(&mut open)
        .resizable(true)
        .show(ctx, |ui| {
            ui.label("Use typed fields to compare values. A bare word searches the row. Text comparisons are case-sensitive; lower(field) makes text matching case-insensitive.");
            ui.label("Unavailable values stay missing. Packet filters use the installed TShark engine and its own field registry.");
            let query_id = egui::Id::new("filter-guide-query");
            let mut query = ui.ctx().data(|data| data.get_temp::<String>(query_id).unwrap_or_default());
            ui.add(
                egui::TextEdit::singleline(&mut query)
                    .hint_text("Search fields, operators, schema argument names, syscall names")
                    .desired_width(f32::INFINITY),
            );
            let needle = query.to_lowercase();
            ui.ctx().data_mut(|data| data.insert_temp(query_id, query));
            ui.add_space(6.0);
            ui.strong("Examples");
            let packet = ctx.data(|data| data.get_temp::<bool>(egui::Id::new("filter-guide-packet"))).unwrap_or(false);
            let contextual = ui.ctx().data(|data| data.get_temp::<std::sync::Arc<Vec<(String, String, String)>>>(egui::Id::new("filter-guide-fields")));
            let fallback: Vec<_> = syscall_fields().iter().map(|field| (field.name.to_owned(), field.kind.to_owned(), field.detail.to_owned())).collect();
            let rows = contextual.as_deref().map(Vec::as_slice).unwrap_or(&fallback);
            let examples = guide_examples(rows, packet);
            for line in &examples {
                ui.monospace(line);
            }
            ui.add_space(4.0);
            ui.label("Fields available in this filter. Right-click a value to build a clause.");
            let rows: Vec<_> = rows.iter().filter(|(field, kind, meaning)| {
                needle.is_empty() || field.to_lowercase().contains(&needle)
                    || kind.to_lowercase().contains(&needle)
                    || meaning.to_lowercase().contains(&needle)
            }).collect();
            use egui_extras::{Column, TableBuilder};
            TableBuilder::new(ui)
                .id_salt("filter-keywords")
                .striped(true)
                .column(Column::initial(160.0))
                .column(Column::initial(120.0))
                .column(Column::remainder())
                .header(22.0, |mut header| {
                    for title in ["Field", "Type", "Meaning"] {
                        header.col(|ui| {
                            ui.strong(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(22.0, rows.len(), |mut row| {
                            let (field, kind, meaning) = rows[row.index()];
                            row.col(|ui| {
                                ui.monospace(field);
                            });
                            row.col(|ui| {
                                ui.label(kind);
                            });
                            row.col(|ui| {
                                ui.label(meaning);
                            });
                    });
                });

        });
    ctx.data_mut(|data| data.insert_temp(id, open));
}

fn guide_examples(fields: &[(String, String, String)], packet: bool) -> Vec<String> {
    if packet {
        return [
            "ip.src == 10.0.2.15 && tcp.dstport == 80",
            "http.request.method == \"GET\"",
            "dns.qry.name contains \"example\"",
            "tcp && !udp",
        ]
        .map(str::to_owned)
        .into();
    }
    let mut examples = vec!["==  !=  <  <=  >  >=  contains  in  &  &&  ||  !  ( )".into()];
    if let Some((field, _, _)) = fields.iter().find(|(_, kind, _)| kind == "integer") {
        examples.push(format!("{field} >= 0 && exists({field})"));
        examples.push(format!("{field} in {{0, 1}}"));
    }
    if let Some((field, _, _)) = fields.iter().find(|(_, kind, _)| kind == "text") {
        examples.push(format!("{field} contains \"sample\""));
        examples.push(format!("lower({field}) == \"sample\""));
    }
    if let Some((field, _, _)) = fields.iter().find(|(_, kind, _)| kind == "text list") {
        examples.push(format!("{field} == \"needs review\""));
    }
    examples
}

pub(crate) fn open_guide(ctx: &egui::Context) {
    ctx.data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-open"), true));
}

#[cfg(test)]
fn guide_rows() -> &'static [(String, String, String)] {
    use std::collections::BTreeSet;
    use std::sync::OnceLock;
    static ROWS: OnceLock<Vec<(String, String, String)>> = OnceLock::new();
    ROWS.get_or_init(|| {
        let mut rows = Vec::new();
        for (field, kind, meaning) in KEYWORDS {
            rows.push(((*field).into(), (*kind).into(), (*meaning).into()));
        }
        for (field, meaning) in [
            ("==", "Equal. Text compare is case-sensitive on syscall rows."),
            ("!=", "Not equal."),
            ("<", "Less than. Numbers only."),
            ("<=", "Less than or equal. Numbers only."),
            (">", "Greater than. Numbers only."),
            (">=", "Greater than or equal. Numbers only."),
            ("&&", "And. Binds looser than a comparison."),
            ("||", "Or. Binds looser than &&."),
            ("!", "Not."),
            ("contains", "Substring on a text field."),
            ("in", "Membership. Example: syscall.num in {9, 10}."),
            ("exists", "The field was recorded."),
            ("missing", "The field was not recorded."),
            ("&", "Bit test. Example: args.prot & 7 == 7."),
        ] {
            rows.push(((*field).into(), "operator".into(), (*meaning).into()));
        }
        for (field, meaning) in [
            ("ip.src", "Source IP. Equality only."),
            ("ip.dst", "Destination IP. Equality only."),
            ("ip.addr", "Either IP endpoint."),
            ("tcp.srcport", "TCP source port."),
            ("tcp.dstport", "TCP destination port."),
            ("udp.port", "Either UDP port."),
            ("frame.len", "Captured frame length."),
            ("http.request", "Bare field: decoded HTTP request line, not a status line."),
            (
                "http.request.method",
                "Method token of the decoded HTTP request line.",
            ),
            (
                "http.request.uri",
                "Request-target token of the decoded HTTP request line.",
            ),
            (
                "dns.qry.name",
                "Name from a decoded query TYPE name or response TYPE name summary. A bare field means the packet is DNS.",
            ),
            ("frame contains", "Substring of the packet summary. Not a field comparison."),
        ] {
            rows.push(((*field).into(), "packet".into(), (*meaning).into()));
        }
        let mut arguments = BTreeSet::new();
        let mut names = BTreeSet::new();
        for syscall in antinomie_monitor_core::syscalls::all() {
            names.insert(syscall.name.clone());
            for argument in &syscall.arguments {
                arguments.insert(argument.name.clone());
            }
        }
        for name in arguments {
            rows.push((
                format!("args.{name}"),
                "schema argument".into(),
                "Argument name from protocol/native-syscalls.json.".into(),
            ));
        }
        for name in names {
            rows.push((
                name,
                "syscall name".into(),
                "syscall.name value from the native schema.".into(),
            ));
        }
        rows
    })
    .as_slice()
}

#[cfg(test)]
fn guide_has(needle: &str) -> bool {
    guide_rows().iter().any(|(field, _, _)| field == needle)
}

pub(crate) struct Compiled {
    pub error: Option<String>,
    mode: Mode,
}

enum Mode {
    All,
    Text(String),
    Expr(Expr),
}

impl Compiled {
    pub(crate) fn keep(&self, invocation: &InvocationSummary) -> bool {
        if self.error.is_some() {
            return false;
        }
        match &self.mode {
            Mode::All => true,
            Mode::Text(filter) => {
                let Some(event) = trace::representative(invocation) else {
                    return false;
                };
                let haystack = format!(
                    "{} {} {} {} {}",
                    event.syscall_name,
                    event.tid,
                    event.task_cookie,
                    event.pid,
                    trace::info(invocation)
                );
                haystack.to_lowercase().contains(&filter.to_lowercase())
            }
            Mode::Expr(expr) => expr.eval(invocation).unwrap_or(false),
        }
    }

    #[cfg(test)]
    pub(crate) fn keep_record(&self, labels: &RecordLabels<'_>) -> bool {
        if self.error.is_some() {
            return false;
        }
        match &self.mode {
            Mode::All => true,
            Mode::Text(filter) => {
                let haystack = format!(
                    "{} {} {} {}",
                    labels.id,
                    labels.name,
                    labels.path,
                    labels.tags.join(" ")
                );
                haystack.to_lowercase().contains(&filter.to_lowercase())
            }
            Mode::Expr(expr) => expr.eval_record(labels).unwrap_or(false),
        }
    }
}

pub(crate) fn compile_note(filter: &str) -> Compiled {
    compile_with(filter, false)
}

/// Run and result rows. `tag` is the annotation on that directory.
/// An invalid expression is an error and is not a text search.
#[cfg(test)]
pub(crate) fn compile_record(filter: &str) -> Compiled {
    compile_with(filter, true)
}

pub(crate) fn structured(filter: &str) -> bool {
    is_expression(filter.trim())
}

fn compile_with(filter: &str, record: bool) -> Compiled {
    match compiled(filter, record) {
        Ok(mode) => Compiled { error: None, mode },
        Err(error) => Compiled {
            error: Some(error),
            mode: Mode::All,
        },
    }
}

/// Labels stored beside a run or result. Tags do not come from path text.
#[cfg(test)]
pub(crate) struct RecordLabels<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub path: &'a str,
    pub tags: &'a [String],
}

/// A table's displayed fields. The same registry validates filters and drives completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FieldSpec<'a> {
    pub name: &'a str,
    pub kind: &'a str,
    pub detail: &'a str,
}

impl<'a> FieldSpec<'a> {
    pub const fn text(name: &'a str, detail: &'a str) -> Self {
        Self {
            name,
            kind: "text",
            detail,
        }
    }
    pub const fn number(name: &'a str, detail: &'a str) -> Self {
        Self {
            name,
            kind: "integer",
            detail,
        }
    }
    pub const fn boolean(name: &'a str, detail: &'a str) -> Self {
        Self {
            name,
            kind: "boolean",
            detail,
        }
    }
    pub const fn tags(name: &'a str, detail: &'a str) -> Self {
        Self {
            name,
            kind: "text list",
            detail,
        }
    }
}

/// Owned row values; an unavailable cell must use Missing, never a display placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RowValue {
    Number(i128),
    Text(String),
    Bool(bool),
    List(Vec<String>),
    Missing,
}

impl Compiled {
    pub(crate) fn keep_table(&self, row: &[(&str, RowValue)]) -> bool {
        if self.error.is_some() {
            return false;
        }
        match &self.mode {
            Mode::All => true,
            Mode::Text(needle) => row.iter().any(|(_, value)| match value {
                RowValue::Missing => false,
                RowValue::Text(value) => value.to_lowercase().contains(&needle.to_lowercase()),
                RowValue::List(values) => values
                    .iter()
                    .any(|value| value.to_lowercase().contains(&needle.to_lowercase())),
                RowValue::Number(value) => value.to_string().contains(needle),
                RowValue::Bool(value) => value.to_string().contains(&needle.to_lowercase()),
            }),
            Mode::Expr(expr) => expr.eval_table(row),
        }
    }
}

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

pub(crate) const LABEL_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("entry.kind", "Evidence category"),
    FieldSpec::text("entry.id", "Recorded identity"),
    FieldSpec::text("entry.name", "Annotation name"),
    FieldSpec::text("entry.path", "Evidence path"),
    FieldSpec::tags("tag", "Stored annotation tags"),
    FieldSpec::tags("tags", "Stored annotation tags"),
    FieldSpec::tags("entry.tag", "Stored annotation tags"),
    FieldSpec::text("entry.state", "Recorded outcome"),
    FieldSpec::boolean("entry.complete", "Evidence completeness"),
    FieldSpec::number("entry.time_ms", "Unix timestamp in milliseconds"),
    FieldSpec::number("entry.size", "Saved extent in octets"),
    FieldSpec::text("vm.id", "Recorded VM identity"),
    FieldSpec::text("boot.id", "Recorded boot identity"),
    FieldSpec::text("run.id", "Associated run identity"),
];

pub(crate) const CAPTURE_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.kind", "Capture category"),
    FieldSpec::number(
        "capture.started_ms",
        "Unix start milliseconds; missing when not recorded",
    ),
    FieldSpec::number(
        "capture.ended_ms",
        "Unix end milliseconds; missing when not recorded",
    ),
    FieldSpec::number("capture.size", "Retained extent in octets"),
    FieldSpec::number(
        "capture.expected_size",
        "Expected extent in octets; missing when not recorded",
    ),
    FieldSpec::boolean("capture.complete", "Recorded capture completeness"),
    FieldSpec::text("capture.state", "Recorded capture state"),
    FieldSpec::text(
        "capture.run_id",
        "Linked program run identity; missing for unlinked captures",
    ),
];

pub(crate) const ANALYSIS_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("analysis.id", "Retained analysis identity"),
    FieldSpec::text("analysis.kind", "Analysis result category"),
    FieldSpec::tags("analysis.tool", "Tools recorded for this analysis"),
    FieldSpec::text("analysis.state", "Recorded analysis state"),
    FieldSpec::text("analysis.sha256", "Recorded specimen SHA-256"),
    FieldSpec::boolean(
        "analysis.has_run",
        "Analysis has a recorded program run link",
    ),
    FieldSpec::text("analysis.run_id", "Linked program run identity"),
    FieldSpec::text("analysis.source", "Recorded analysis source"),
    FieldSpec::text("analysis.path", "Recorded specimen or result path"),
];

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

fn literal(value: &mut Value) {
    if let Value::Field(name) = value {
        *value = Value::Text(name.clone());
    }
}

fn validate_table(expr: &mut Expr, fields: &[FieldSpec<'_>]) -> Result<(), String> {
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

#[cfg(test)]
pub(crate) fn matches(filter: &str, invocation: &InvocationSummary) -> Result<bool, String> {
    let compiled = compile_note(filter);
    if let Some(error) = compiled.error.clone() {
        return Err(error);
    }
    Ok(compiled.keep(invocation))
}

fn compiled(filter: &str, record: bool) -> Result<Mode, String> {
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

fn unknown_field(name: &str) -> String {
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

fn is_expression(filter: &str) -> bool {
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

#[derive(Clone, Debug)]
enum Token {
    Ident(String),
    Number(i128),
    Text(String),
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
    Exists,
    Missing,
    In,
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBrace,
    RBrace,
    LBracket,
    RBracket,
    Comma,
    Amp,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    tokenize_with_positions(input).map(|(tokens, _)| tokens)
}

fn position_error(error: String, input: &str, offset: usize) -> String {
    format!(
        "{error} at column {}",
        input[..floor_boundary(input, offset.min(input.len()))]
            .chars()
            .count()
            + 1
    )
}

fn tokenize_with_positions(input: &str) -> Result<(Vec<Token>, Vec<usize>), String> {
    if input.len() > 64 * 1024 {
        return Err("Filter exceeds 64 KiB at column 1".into());
    }
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut offsets = Vec::new();
    let mut index = 0;
    let mut nesting = 0usize;
    let mut boolean_count = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let rest = &input[index..];
        offsets.push(index);
        if rest.starts_with("&&") {
            tokens.push(Token::And);
            index += 2;
        } else if rest.starts_with("||") {
            tokens.push(Token::Or);
            index += 2;
        } else if rest.starts_with("==") {
            tokens.push(Token::Eq);
            index += 2;
        } else if rest.starts_with("!=") {
            tokens.push(Token::Ne);
            index += 2;
        } else if rest.starts_with("<=") {
            tokens.push(Token::Le);
            index += 2;
        } else if rest.starts_with(">=") {
            tokens.push(Token::Ge);
            index += 2;
        } else if rest
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("contains"))
            && rest[8..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_alphanumeric())
        {
            tokens.push(Token::Contains);
            index += 8;
        } else if byte == b'<' {
            tokens.push(Token::Lt);
            index += 1;
        } else if byte == b'>' {
            tokens.push(Token::Gt);
            index += 1;
        } else if byte == b'!' {
            tokens.push(Token::Not);
            index += 1;
        } else if byte == b'(' {
            tokens.push(Token::LParen);
            index += 1;
        } else if byte == b')' {
            tokens.push(Token::RParen);
            index += 1;
        } else if byte == b'{' {
            tokens.push(Token::LBrace);
            index += 1;
        } else if byte == b'}' {
            tokens.push(Token::RBrace);
            index += 1;
        } else if byte == b'[' {
            tokens.push(Token::LBracket);
            index += 1;
        } else if byte == b']' {
            tokens.push(Token::RBracket);
            index += 1;
        } else if byte == b',' {
            tokens.push(Token::Comma);
            index += 1;
        } else if byte == b'&' {
            tokens.push(Token::Amp);
            index += 1;
        } else if byte == b'"' || byte == b'\'' {
            let quote = byte as char;
            index += 1;
            let mut value = String::new();
            let mut closed = false;
            while index < input.len() {
                let ch = input[index..]
                    .chars()
                    .next()
                    .ok_or("Unclosed quote in the filter")?;
                index += ch.len_utf8();
                if ch == quote {
                    closed = true;
                    break;
                }
                if ch == '\\' {
                    let escaped = input[index..]
                        .chars()
                        .next()
                        .ok_or("Incomplete escape in the filter")?;
                    index += escaped.len_utf8();
                    match escaped {
                        '\\' | '"' | '\'' => value.push(escaped),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        't' => value.push('\t'),
                        _ => return Err(format!("Unknown escape \\{escaped}")),
                    }
                } else {
                    value.push(ch);
                }
            }
            if !closed {
                return Err("Unclosed quote in the filter".into());
            }
            tokens.push(Token::Text(value));
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            index += 1;
            if rest.starts_with("0x") || rest.starts_with("0X") {
                index += 1;
                while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
                    index += 1;
                }
                let text = &input[start..index];
                let value = i128::from_str_radix(
                    text.trim_start_matches("0x").trim_start_matches("0X"),
                    16,
                )
                .map_err(|_| format!("Invalid number {text}"))?;
                tokens.push(Token::Number(value));
            } else {
                while index < bytes.len() && (bytes[index].is_ascii_digit()) {
                    index += 1;
                }
                let text = &input[start..index];
                let value = text
                    .parse::<i128>()
                    .map_err(|_| format!("Invalid number {text}"))?;
                tokens.push(Token::Number(value));
            }
        } else if byte.is_ascii_alphabetic() || byte == b'_' || byte == b'.' {
            let start = index;
            index += 1;
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || bytes[index] == b'_'
                    || bytes[index] == b'.'
                    || bytes[index] == b'['
                    || bytes[index] == b']')
            {
                index += 1;
            }
            let word = input[start..index].to_owned();
            match word.to_ascii_lowercase().as_str() {
                "and" => tokens.push(Token::And),
                "or" => tokens.push(Token::Or),
                "not" => tokens.push(Token::Not),
                "contains" => tokens.push(Token::Contains),
                "exists" => tokens.push(Token::Exists),
                "missing" => tokens.push(Token::Missing),
                "in" => tokens.push(Token::In),
                _ => tokens.push(Token::Ident(word)),
            }
        } else {
            return Err(format!(
                "Unexpected character in the filter: {}",
                byte as char
            ));
        }
        match tokens.last() {
            Some(Token::LParen) => nesting += 1,
            Some(Token::RParen) => nesting = nesting.saturating_sub(1),
            Some(Token::And | Token::Or | Token::Not) => boolean_count += 1,
            _ => {}
        }
        if tokens.len() > 2048 || nesting > 64 || boolean_count > 256 {
            return Err(position_error("Filter is too complex (maximum 2048 tokens, 64 nested parentheses, 256 boolean operators)".into(), input, index));
        }
    }
    Ok((tokens, offsets))
}

struct Parser {
    tokens: Vec<Token>,
    at: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn pop(&mut self) -> Result<Token, String> {
        let token = self
            .tokens
            .get(self.at)
            .cloned()
            .ok_or_else(|| "Filter ended early".to_owned())?;
        self.at += 1;
        Ok(token)
    }

    fn parse_or(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.at += 1;
            left = Expr::Or(Box::new(left), Box::new(self.parse_and()?));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, String> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Token::And)) {
            self.at += 1;
            left = Expr::And(Box::new(left), Box::new(self.parse_not()?));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.at += 1;
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_cmp()
    }

    fn parse_cmp(&mut self) -> Result<Expr, String> {
        if matches!(self.peek(), Some(Token::LParen)) {
            self.at += 1;
            let inner = self.parse_or()?;
            if !matches!(self.pop()?, Token::RParen) {
                return Err("Missing closing parenthesis".into());
            }
            if let Expr::Value(left) = inner {
                if let Some(op) = self.comparison() {
                    self.at += 1;
                    return Ok(Expr::Cmp(left, op, self.parse_value()?));
                }
                return Ok(Expr::Value(left));
            }
            return Ok(inner);
        }
        if matches!(self.peek(), Some(Token::Exists | Token::Missing)) {
            let missing = matches!(self.peek(), Some(Token::Missing));
            self.at += 1;
            let parenthesized = matches!(self.peek(), Some(Token::LParen));
            if parenthesized {
                self.at += 1;
            }
            let field = self.parse_value()?;
            if parenthesized && !matches!(self.pop()?, Token::RParen) {
                return Err("Expected ) after the presence field".into());
            }
            return Ok(if missing {
                Expr::Missing(field)
            } else {
                Expr::Exists(field)
            });
        }
        let mut left = self.parse_value()?;
        if matches!(self.peek(), Some(Token::Amp)) {
            self.at += 1;
            let mask = match self.pop()? {
                Token::Number(number) if number >= 0 => {
                    u64::try_from(number).map_err(|_| "Negative mask".to_owned())?
                }
                Token::Number(_) => return Err("Negative mask".into()),
                _ => return Err("Expected a number after &".into()),
            };
            left = Value::Masked(Box::new(left), mask);
            if matches!(self.peek(), Some(Token::RParen)) {
                return Ok(Expr::Value(left));
            }
            let op = match self.pop()? {
                Token::Eq => Cmp::Eq,
                Token::Ne => Cmp::Ne,
                _ => return Err("Expected == or != after the mask".into()),
            };
            let right = self.parse_value()?;
            return Ok(Expr::Cmp(left, op, right));
        }
        if matches!(self.peek(), Some(Token::In)) {
            self.at += 1;
            return Ok(Expr::In(left, self.parse_set()?));
        }
        let op = match self.peek() {
            Some(Token::Eq) => Cmp::Eq,
            Some(Token::Ne) => Cmp::Ne,
            Some(Token::Lt) => Cmp::Lt,
            Some(Token::Le) => Cmp::Le,
            Some(Token::Gt) => Cmp::Gt,
            Some(Token::Ge) => Cmp::Ge,
            Some(Token::Contains) => Cmp::Contains,
            _ => return Ok(Expr::Value(left)),
        };
        self.at += 1;
        let right = self.parse_value()?;
        Ok(Expr::Cmp(left, op, right))
    }

    fn parse_set(&mut self) -> Result<Vec<Value>, String> {
        if !matches!(self.pop()?, Token::LBrace) {
            return Err("Expected { after in".into());
        }
        if matches!(self.peek(), Some(Token::RBrace)) {
            return Err("Empty set".into());
        }
        let mut items = Vec::new();
        loop {
            items.push(self.parse_set_item()?);
            match self.peek() {
                Some(Token::Comma) => {
                    self.at += 1;
                    if matches!(self.peek(), Some(Token::RBrace)) {
                        return Err("Expected a value in the set".into());
                    }
                }
                Some(Token::RBrace) => {
                    self.at += 1;
                    break;
                }
                _ => return Err("Expected } to close the set".into()),
            }
        }
        Ok(items)
    }

    fn parse_set_item(&mut self) -> Result<Value, String> {
        match self.pop()? {
            Token::Number(number) => Ok(Value::Number(number)),
            Token::Text(text) => Ok(Value::Text(text)),
            Token::Ident(name) => Ok(Value::Text(name)),
            _ => Err("Expected a number or quoted text in the set".into()),
        }
    }

    fn parse_value(&mut self) -> Result<Value, String> {
        match self.pop()? {
            Token::Ident(name) if name == "lower" => {
                if !matches!(self.pop()?, Token::LParen) {
                    return Err("Expected ( after lower".into());
                }
                let value = self.parse_value()?;
                if !matches!(self.pop()?, Token::RParen) {
                    return Err("Expected ) after lower field".into());
                }
                Ok(Value::Lower(Box::new(value)))
            }
            Token::Ident(name) if name.eq_ignore_ascii_case("args.raw") => self.parse_raw_slot(),
            Token::Ident(name) if name.to_ascii_lowercase().starts_with("args.raw[") => {
                let index = name
                    .get(9..)
                    .and_then(|suffix| suffix.strip_suffix(']'))
                    .and_then(|index| index.parse::<usize>().ok())
                    .filter(|index| *index < 6)
                    .ok_or_else(|| {
                        "args.raw slot must be an integer from 0 through 5".to_owned()
                    })?;
                Ok(Value::Raw(index))
            }
            Token::Ident(name) => Ok(Value::Field(name)),
            Token::Number(number) => Ok(Value::Number(number)),
            Token::Text(text) => Ok(Value::Text(text)),
            _ => Err("Expected a field, number or quoted text".into()),
        }
    }

    fn comparison(&self) -> Option<Cmp> {
        match self.peek()? {
            Token::Eq => Some(Cmp::Eq),
            Token::Ne => Some(Cmp::Ne),
            Token::Lt => Some(Cmp::Lt),
            Token::Le => Some(Cmp::Le),
            Token::Gt => Some(Cmp::Gt),
            Token::Ge => Some(Cmp::Ge),
            Token::Contains => Some(Cmp::Contains),
            _ => None,
        }
    }

    fn parse_raw_slot(&mut self) -> Result<Value, String> {
        if !matches!(self.peek(), Some(Token::LBracket)) {
            return Err("args.raw needs an index from 0 through 5".into());
        }
        self.at += 1;
        let index = match self.pop()? {
            Token::Number(number) if (0..6).contains(&number) => number as usize,
            Token::Number(number) => {
                return Err(format!("args.raw index {number} is outside 0 through 5"));
            }
            Token::Ident(_) => return Err("args.raw takes a slot number, not a name".into()),
            _ => return Err("args.raw needs an index from 0 through 5".into()),
        };
        if !matches!(self.pop()?, Token::RBracket) {
            return Err("Expected ] after the args.raw index".into());
        }
        Ok(Value::Raw(index))
    }
}

#[derive(Clone, Copy)]
enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Contains,
}

enum Expr {
    Value(Value),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
    Cmp(Value, Cmp, Value),
    Exists(Value),
    Missing(Value),
    In(Value, Vec<Value>),
}

enum Value {
    Field(String),
    Number(i128),
    Text(String),
    Raw(usize),
    Masked(Box<Value>, u64),
    Lower(Box<Value>),
}

enum Resolved {
    Number(i128),
    Text(String),
    List(Vec<String>),
    Bool(bool),
    Missing,
}

impl Expr {
    fn eval_table(&self, row: &[(&str, RowValue)]) -> bool {
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
    fn eval(&self, invocation: &InvocationSummary) -> Result<bool, String> {
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
    fn eval_record(&self, labels: &RecordLabels<'_>) -> Result<bool, String> {
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

fn compare(op: Cmp, left: &Resolved, right: &Resolved) -> bool {
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

fn field(invocation: &InvocationSummary, name: &str) -> Result<Resolved, String> {
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterScope {
    Syscall,
    Record,
    #[cfg(test)]
    Packet,
    Table(&'static [FieldSpec<'static>]),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub start: usize,
    pub end: usize,
    pub insert: String,
    pub detail: String,
}

#[cfg(test)]
pub(crate) fn completions(text: &str, cursor: usize, scope: FilterScope) -> Vec<Completion> {
    completions_with(text, cursor, scope, &[])
}

#[cfg(test)]
pub(crate) fn completions_with(
    text: &str,
    cursor: usize,
    scope: FilterScope,
    known_values: &[String],
) -> Vec<Completion> {
    completions_fields(text, cursor, &fields_for(scope), known_values, None)
}

#[cfg(test)]
fn completions_fields(
    text: &str,
    cursor: usize,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
    selection: Option<(usize, usize)>,
) -> Vec<Completion> {
    completions_field_iter(
        text,
        cursor,
        fields.iter().copied(),
        known_values,
        selection,
        false,
    )
}

fn completions_field_iter<'a>(
    text: &str,
    cursor: usize,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
    selection: Option<(usize, usize)>,
    packet: bool,
) -> Vec<Completion> {
    let cursor = floor_boundary(text, cursor.min(text.len()));
    let (start, end, prefix_end) =
        if let Some((start, end)) = selection.filter(|(start, end)| start != end) {
            let start = floor_boundary(text, start.min(text.len()));
            let end = floor_boundary(text, end.min(text.len())).max(start);
            (start, end, end)
        } else {
            (token_start(text, cursor), token_end(text, cursor), cursor)
        };
    let prefix = &text[start..prefix_end];
    let previous = previous_word(text, start);
    let mut items = Vec::new();
    let function = editor_tokens(&text[..start])
        .windows(2)
        .last()
        .and_then(|tokens| {
            (text[tokens[1].0..tokens[1].1].trim() == "(")
                .then(|| text[tokens[0].0..tokens[0].1].trim())
        })
        .filter(|name| matches!(*name, "lower" | "exists" | "missing"));
    let clause_start = function.is_none()
        && previous.as_deref().is_none_or(|word| {
            matches!(word, "&&" | "||" | "(" | "!")
                || word.eq_ignore_ascii_case("and")
                || word.eq_ignore_ascii_case("or")
        });
    if clause_start && !packet {
        let needle = prefix.to_ascii_lowercase();
        for (insert, detail) in [
            ("exists", "Recorded field, written before the field name"),
            ("missing", "Absent field, written before the field name"),
        ] {
            if needle.is_empty() || insert.starts_with(&needle) {
                items.push(Completion {
                    start,
                    end,
                    insert: format!("{insert} "),
                    detail: detail.into(),
                });
            }
        }
    }
    if let Some(field) = previous.as_deref().and_then(|word| {
        fields
            .clone()
            .find(|field| field.name.eq_ignore_ascii_case(word))
    }) {
        if prefix.is_empty() || operator_prefix(prefix) {
            for (insert, detail) in if packet {
                packet_operators(field.kind)
            } else {
                operators(field.kind)
            } {
                if insert
                    .trim()
                    .to_ascii_lowercase()
                    .starts_with(&prefix.to_ascii_lowercase())
                    || prefix.is_empty()
                {
                    items.push(Completion {
                        start,
                        end,
                        insert: format!(" {insert} "),
                        detail: (*detail).into(),
                    });
                }
            }
        }
    }
    if let Some(field_name) = field_before_operator(text, start) {
        let quoted_prefix = prefix.starts_with(['"', '\'']);
        let value_prefix = if quoted_prefix { &prefix[1..] } else { prefix };
        for (insert, detail) in values_for(&field_name, value_prefix, known_values) {
            items.push(Completion {
                start,
                end,
                insert: if fields.clone().any(|field| {
                    field.name.eq_ignore_ascii_case(&field_name) && field.kind == "integer"
                }) {
                    insert
                } else {
                    quote_value(&insert, quoted_prefix)
                },
                detail,
            });
        }
        if let Some(field) = fields
            .clone()
            .find(|field| field.name.eq_ignore_ascii_case(&field_name))
        {
            if field.kind == "boolean" || field.kind == "FT_BOOLEAN" {
                for value in ["true", "false"] {
                    if value.starts_with(value_prefix) {
                        items.push(Completion {
                            start,
                            end,
                            insert: value.into(),
                            detail: "boolean value".into(),
                        });
                    }
                }
            }
        }
        return items;
    }
    if unclosed_quote(&text[..cursor]) {
        return Vec::new();
    }
    if let Ok(tokens) = tokenize(text[..start].trim_end()) {
        let mut parser = Parser { tokens, at: 0 };
        if parser
            .parse_or()
            .is_ok_and(|expr| !matches!(expr, Expr::Value(_)))
            && parser.at == parser.tokens.len()
        {
            for (insert, detail) in [("&&", "And"), ("||", "Or"), ("and", "And"), ("or", "Or")] {
                if insert.starts_with(&prefix.to_ascii_lowercase()) {
                    items.push(Completion {
                        start,
                        end,
                        insert: format!(" {insert} "),
                        detail: detail.into(),
                    });
                }
            }
            return items;
        }
    }
    let offering_operator = previous.as_deref().is_some_and(|word| {
        fields
            .clone()
            .any(|field| field.name.eq_ignore_ascii_case(word))
            && (prefix.is_empty() || operator_prefix(prefix))
    });
    if !offering_operator && !prefix.is_empty() {
        let needle = prefix.to_ascii_lowercase();
        for field in fields.clone() {
            if function == Some("lower") && !matches!(field.kind, "text" | "text list") {
                continue;
            }
            if field
                .name
                .get(..needle.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(&needle))
            {
                items.push(Completion {
                    start,
                    end,
                    insert: field.name.into(),
                    detail: format!("{} · {}", field.kind, field.detail),
                });
                if items.len() >= 12 {
                    break;
                }
            }
        }
    } else if !offering_operator && prefix.is_empty() {
        for field in fields
            .clone()
            .filter(|field| function != Some("lower") || matches!(field.kind, "text" | "text list"))
            .take(8)
        {
            items.push(Completion {
                start,
                end,
                insert: field.name.into(),
                detail: format!("{} · {}", field.kind, field.detail),
            });
        }
    }
    items.truncate(12);
    items
}

fn quote_value(value: &str, force: bool) -> String {
    let reserved = matches!(
        value.to_ascii_lowercase().as_str(),
        "and" | "or" | "not" | "exists" | "missing" | "contains" | "in"
    );
    if !force
        && !reserved
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return value.to_owned();
    }
    format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    )
}

pub(crate) fn filter_edit(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
) -> egui::Response {
    filter_edit_with(ui, text, hint, width, scope, &[])
}

pub(crate) fn filter_edit_with(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    scope: FilterScope,
    known_values: &[String],
) -> egui::Response {
    filter_edit_fields(ui, text, hint, width, &fields_for(scope), known_values)
}

pub(crate) fn filter_edit_fields(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: &[FieldSpec<'_>],
    known_values: &[String],
) -> egui::Response {
    filter_edit_field_iter(ui, text, hint, width, fields.iter().copied(), known_values)
}

/// Borrow large external field registries without allocating a per-frame adapter vector.
pub(crate) fn filter_edit_field_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
) -> egui::Response {
    filter_edit_iter(ui, text, hint, width, fields, known_values, false)
}

pub(crate) fn filter_edit_packet_field_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
) -> egui::Response {
    filter_edit_iter(ui, text, hint, width, fields, known_values, true)
}

fn filter_edit_iter<'a>(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    width: f32,
    fields: impl Iterator<Item = FieldSpec<'a>> + Clone,
    known_values: &[String],
    packet: bool,
) -> egui::Response {
    let id = ui.id().with(("filter-edit", hint));
    ui.ctx().data_mut(|data| {
        data.insert_temp(egui::Id::new("filter-history-target"), id.with("history"))
    });
    let mut dismiss = ui
        .data(|data| data.get_temp::<bool>(id.with("dismiss")))
        .unwrap_or(false);
    let mut selected = ui
        .data(|data| data.get_temp::<usize>(id.with("selected")))
        .unwrap_or(0);
    let was_focused = ui
        .data(|data| data.get_temp::<bool>(id.with("focus")))
        .unwrap_or(false);
    let pending = ui
        .data(|data| data.get_temp::<Vec<Completion>>(id.with("items")))
        .unwrap_or_default();
    let mut caret = None;
    let mut accepted = false;
    if was_focused {
        let reopen = ui.input_mut(|input| {
            input.consume_key(egui::Modifiers::CTRL, egui::Key::Space)
                || input.consume_key(egui::Modifiers::COMMAND, egui::Key::Space)
        });
        if reopen {
            dismiss = false;
        }
        if !pending.is_empty() && !dismiss {
            let accept = ui.input_mut(|input| {
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowDown) {
                    selected = selected.saturating_add(1) % pending.len();
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::ArrowUp) {
                    selected = if selected == 0 {
                        pending.len() - 1
                    } else {
                        selected - 1
                    };
                }
                if input.consume_key(egui::Modifiers::NONE, egui::Key::Escape) {
                    dismiss = true;
                }
                input.consume_key(egui::Modifiers::NONE, egui::Key::Enter)
                    || input.consume_key(egui::Modifiers::NONE, egui::Key::Tab)
            });
            if accept && !dismiss {
                if let Some(item) = pending.get(selected.min(pending.len() - 1)).cloned() {
                    let byte = apply_completion(text, &item);
                    caret = Some(char_index(text, byte));
                    dismiss = true;
                    accepted = true;
                }
            }
        }
    }
    let mut output = egui::TextEdit::singleline(text)
        .hint_text(hint)
        .desired_width(width)
        .margin(crate::theme::TEXT_EDIT_MARGIN)
        .show(ui);
    if let Some(caret) = caret {
        let mut state = output.state.clone();
        state
            .cursor
            .set_char_range(Some(egui::text::CCursorRange::one(
                egui::text::CCursor::new(caret),
            )));
        state.store(ui.ctx(), output.response.id);
    }
    if accepted {
        output.response.mark_changed();
    }
    let cursor_chars = caret.unwrap_or_else(|| {
        output
            .cursor_range
            .map(|range| range.primary.ccursor.index)
            .unwrap_or(text.chars().count())
    });
    let cursor = byte_index(text, cursor_chars);
    let changed = output.response.changed();
    if changed && !accepted {
        dismiss = false;
        selected = 0;
    }
    let items = if output.response.has_focus() && !dismiss {
        let selection = output.cursor_range.and_then(|range| {
            let first = byte_index(text, range.primary.ccursor.index);
            let second = byte_index(text, range.secondary.ccursor.index);
            (first != second).then_some((first.min(second), first.max(second)))
        });
        completions_field_iter(
            text,
            cursor,
            fields.clone(),
            known_values,
            selection,
            packet,
        )
    } else {
        Vec::new()
    };
    let popup_id = id.with("popup");
    if items.is_empty() {
        ui.memory_mut(|memory| {
            if memory.is_popup_open(popup_id) {
                memory.close_popup();
            }
        });
    } else {
        ui.memory_mut(|memory| memory.open_popup(popup_id));
        let shown = items.clone();
        let mut picked = None;
        egui::popup::popup_below_widget(
            ui,
            popup_id,
            &output.response,
            egui::PopupCloseBehavior::IgnoreClicks,
            |ui| {
                let popup_width = width
                    .min(ui.ctx().screen_rect().width() - 24.0)
                    .clamp(80.0, 560.0);
                ui.set_min_width(popup_width);
                ui.set_max_width(popup_width);
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for (index, item) in shown.iter().enumerate() {
                            let label = format!("{}  {}", item.insert.trim(), item.detail);
                            let response =
                                ui.add(egui::Button::new(label).selected(index == selected).wrap());
                            if index == selected {
                                response.scroll_to_me(Some(egui::Align::Center));
                            }
                            if response.clicked() {
                                picked = Some(item.clone());
                            }
                        }
                    });
            },
        );
        if let Some(item) = picked {
            let byte = apply_completion(text, &item);
            let caret = char_index(text, byte);
            let mut state = output.state.clone();
            state
                .cursor
                .set_char_range(Some(egui::text::CCursorRange::one(
                    egui::text::CCursor::new(caret),
                )));
            state.store(ui.ctx(), output.response.id);
            output.response.request_focus();
            output.response.mark_changed();
            dismiss = true;
        }
    }
    let focused = output.response.has_focus();
    ui.data_mut(|data| {
        data.insert_temp(id.with("dismiss"), dismiss);
        data.insert_temp(id.with("selected"), selected);
        data.insert_temp(id.with("focus"), focused);
        data.insert_temp(id.with("items"), items);
    });
    let mut menu_changed = false;
    output.response.context_menu(|ui| {
        let history = ui.data(|data| data.get_temp::<Vec<String>>(id.with("history"))).unwrap_or_default();
        if !history.is_empty() {
            ui.menu_button("Recent filters", |ui| {
                for entry in &history {
                    if ui.button(entry).clicked() { *text = entry.clone(); menu_changed = true; ui.close_menu(); }
                }
            });
        }
        if ui.button("Clear filter").clicked() { text.clear(); menu_changed = true; ui.close_menu(); }
        if ui.button("Filter fields and examples").clicked() {
            ui.ctx().data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-packet"), packet));
            let rows: Vec<_> = fields.clone().map(|field| (field.name.to_owned(), field.kind.to_owned(), field.detail.to_owned())).collect();
            ui.ctx().data_mut(|data| data.insert_temp(egui::Id::new("filter-guide-fields"), std::sync::Arc::new(rows)));
            open_guide(ui.ctx());
            ui.close_menu();
        }
        if ui.button("Copy field registry as JSON").clicked() {
            let rows: Vec<_> = fields.clone().map(|field| serde_json::json!({"name": field.name, "type": field.kind, "meaning": field.detail})).collect();
            match serde_json::to_string_pretty(&rows) {
                Ok(json) => ui.ctx().copy_text(json),
                Err(error) => { ui.colored_label(crate::theme::error(), error.to_string()); }
            }
            ui.close_menu();
        }
    });
    if menu_changed {
        output.response.mark_changed();
    }
    output.response
}

/// Call immediately after this UI's filter editor, once its filter has been
/// validated by the caller's parser or external engine.
pub(crate) fn remember_valid_filter(ui: &egui::Ui, filter: &str) {
    if filter.trim().is_empty() {
        return;
    }
    let Some(id) = ui
        .ctx()
        .data(|data| data.get_temp::<egui::Id>(egui::Id::new("filter-history-target")))
    else {
        return;
    };
    ui.ctx().data_mut(|data| {
        let mut history = data.get_temp::<Vec<String>>(id).unwrap_or_default();
        if history.first().is_some_and(|entry| entry == filter) {
            return;
        }
        history.retain(|entry| entry != filter);
        history.insert(0, filter.to_owned());
        history.truncate(24);
        data.insert_temp(id, history);
    });
}

fn apply_completion(text: &mut String, item: &Completion) -> usize {
    let start = item.start.min(text.len());
    let end = item.end.min(text.len()).max(start);
    text.replace_range(start..end, &item.insert);
    start + item.insert.len()
}

fn fields_for(scope: FilterScope) -> Vec<FieldSpec<'static>> {
    match scope {
        FilterScope::Syscall => syscall_fields(),
        FilterScope::Table(fields) => fields.to_vec(),
        FilterScope::Record => vec![
            FieldSpec {
                name: "entry.id",
                kind: "text",
                detail: "Run or result id",
            },
            FieldSpec {
                name: "entry.name",
                kind: "text",
                detail: "Annotation name",
            },
            FieldSpec {
                name: "entry.path",
                kind: "text",
                detail: "Run executable or result path",
            },
            FieldSpec {
                name: "entry.tag",
                kind: "text",
                detail: "Annotation tag",
            },
            FieldSpec {
                name: "tag",
                kind: "text",
                detail: "Annotation tag",
            },
            FieldSpec {
                name: "tags",
                kind: "text",
                detail: "Annotation tag",
            },
            FieldSpec {
                name: "name",
                kind: "text",
                detail: "Annotation name",
            },
        ],
        #[cfg(test)]
        FilterScope::Packet => vec![
            FieldSpec {
                name: "ip.src",
                kind: "ip",
                detail: "Source IP",
            },
            FieldSpec {
                name: "ip.dst",
                kind: "ip",
                detail: "Destination IP",
            },
            FieldSpec {
                name: "ip.addr",
                kind: "ip",
                detail: "Either IP endpoint",
            },
            FieldSpec {
                name: "ipv6.addr",
                kind: "ip",
                detail: "IPv6 endpoint",
            },
            FieldSpec {
                name: "tcp.srcport",
                kind: "integer",
                detail: "TCP source port",
            },
            FieldSpec {
                name: "tcp.dstport",
                kind: "integer",
                detail: "TCP destination port",
            },
            FieldSpec {
                name: "tcp.port",
                kind: "integer",
                detail: "Either TCP port",
            },
            FieldSpec {
                name: "udp.srcport",
                kind: "integer",
                detail: "UDP source port",
            },
            FieldSpec {
                name: "udp.dstport",
                kind: "integer",
                detail: "UDP destination port",
            },
            FieldSpec {
                name: "udp.port",
                kind: "integer",
                detail: "Either UDP port",
            },
            FieldSpec {
                name: "frame.number",
                kind: "integer",
                detail: "Frame number",
            },
            FieldSpec {
                name: "frame.len",
                kind: "integer",
                detail: "Captured frame length",
            },
            FieldSpec {
                name: "frame.protocol",
                kind: "text",
                detail: "Protocol column",
            },
            FieldSpec {
                name: "frame.info",
                kind: "text",
                detail: "Info column",
            },
            FieldSpec {
                name: "frame.contains",
                kind: "text",
                detail: "Substring of the packet summary",
            },
            FieldSpec {
                name: "http.request",
                kind: "text",
                detail: "Decoded HTTP request line",
            },
            FieldSpec {
                name: "http.request.method",
                kind: "text",
                detail: "HTTP method",
            },
            FieldSpec {
                name: "http.request.uri",
                kind: "text",
                detail: "HTTP request target",
            },
            FieldSpec {
                name: "http.host",
                kind: "text",
                detail: "HTTP Host header",
            },
            FieldSpec {
                name: "dns.qry.name",
                kind: "text",
                detail: "DNS query name",
            },
            FieldSpec {
                name: "tcp.flags.syn",
                kind: "integer",
                detail: "TCP SYN",
            },
            FieldSpec {
                name: "tcp.flags.ack",
                kind: "integer",
                detail: "TCP ACK",
            },
            FieldSpec {
                name: "tcp.flags.fin",
                kind: "integer",
                detail: "TCP FIN",
            },
            FieldSpec {
                name: "tcp.flags.reset",
                kind: "integer",
                detail: "TCP RST",
            },
            FieldSpec {
                name: "tcp.flags.push",
                kind: "integer",
                detail: "TCP PSH",
            },
        ],
    }
}

fn syscall_fields() -> Vec<FieldSpec<'static>> {
    let mut fields: Vec<FieldSpec<'static>> = KEYWORDS
        .iter()
        .filter(|(name, _, _)| {
            *name != "args.<name>" && *name != "args.raw[0..5]" && !name.starts_with("entry.")
        })
        .map(|(name, kind, detail)| FieldSpec { name, kind, detail })
        .collect();
    fields.extend([
        FieldSpec::number("syscall.number", "Alias of syscall.num"),
        FieldSpec::text("syscall", "Alias of syscall.name"),
        FieldSpec::number("task.cookie", "Alias of task"),
        FieldSpec::number("call_id", "Alias of call.id"),
        FieldSpec::number("args.address", "Captured addr or address argument"),
        FieldSpec::number("args.addr", "Captured addr or address argument"),
        FieldSpec::number("args.length", "Captured len or length argument"),
        FieldSpec::number("args.len", "Captured len or length argument"),
        FieldSpec::number("args.protection", "Captured prot or protection argument"),
        FieldSpec::number("args.prot", "Captured prot or protection argument"),
        FieldSpec::number("args.buffer", "Captured buf or buffer pointer"),
        FieldSpec::number("args.buf", "Captured buf or buffer pointer"),
        FieldSpec::text("args.file", "Captured path text; pointer is in args.raw"),
        FieldSpec::text("args.filename", "Captured filename text"),
        FieldSpec::text("args.pathname", "Captured pathname text"),
        FieldSpec::text("args.oldname", "Captured old path text"),
        FieldSpec::text("args.newname", "Captured new path text"),
    ]);
    for index in 0..6 {
        fields.push(FieldSpec::number(
            match index {
                0 => "args.0",
                1 => "args.1",
                2 => "args.2",
                3 => "args.3",
                4 => "args.4",
                _ => "args.5",
            },
            "Captured argument word",
        ));
        fields.push(FieldSpec {
            name: match index {
                0 => "args.raw[0]",
                1 => "args.raw[1]",
                2 => "args.raw[2]",
                3 => "args.raw[3]",
                4 => "args.raw[4]",
                _ => "args.raw[5]",
            },
            kind: "integer",
            detail: "Captured argument word",
        });
    }
    let known: std::collections::BTreeSet<&str> = fields.iter().map(|field| field.name).collect();
    fields.extend(
        schema_argument_fields()
            .into_iter()
            .filter(|field| !known.contains(field.name)),
    );
    fields.extend(
        antinomie_monitor_core::filter_members::registry()
            .iter()
            .map(|member| {
                use antinomie_monitor_core::filter_members::MemberKind;
                FieldSpec {
                    name: &member.name,
                    kind: match member.kind {
                        MemberKind::Integer => "integer",
                        MemberKind::Text => "text",
                        MemberKind::Boolean => "boolean",
                    },
                    detail: &member.detail,
                }
            }),
    );
    fields
}

fn schema_argument_fields() -> Vec<FieldSpec<'static>> {
    use std::sync::OnceLock;
    static FIELDS: OnceLock<Vec<(String, String)>> = OnceLock::new();
    let stored = FIELDS.get_or_init(|| {
        let mut names = std::collections::BTreeSet::new();
        for syscall in antinomie_monitor_core::syscalls::all() {
            for argument in &syscall.arguments {
                names.insert(argument.name.clone());
            }
        }
        names
            .into_iter()
            .map(|name| (format!("args.{name}"), "Schema argument".into()))
            .collect()
    });
    stored
        .iter()
        .map(|(name, detail)| FieldSpec {
            name: name.as_str(),
            kind: if matches!(
                name.as_str(),
                "args.path"
                    | "args.pathname"
                    | "args.filename"
                    | "args.old_path"
                    | "args.new_path"
                    | "args.oldname"
                    | "args.newname"
            ) {
                "text"
            } else {
                "integer"
            },
            detail: detail.as_str(),
        })
        .collect()
}

fn operators(kind: &str) -> &'static [(&'static str, &'static str)] {
    match kind {
        "text" | "text list" => &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Substring"),
            ("in", "Membership set"),
        ],
        "boolean" => &[("==", "Equal"), ("!=", "Not equal")],
        "ip" => &[("==", "Equal"), ("!=", "Not equal")],
        _ => &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("<", "Less than"),
            ("<=", "Less than or equal"),
            (">", "Greater than"),
            (">=", "Greater than or equal"),
            ("in", "Membership set"),
            ("&", "Bit mask"),
        ],
    }
}

fn packet_operators(kind: &str) -> &'static [(&'static str, &'static str)] {
    if kind == "FT_PROTOCOL" {
        return &[("&&", "And"), ("||", "Or")];
    }
    if matches!(kind, "FT_BOOLEAN" | "boolean") {
        return &[("==", "Equal"), ("!=", "Not equal")];
    }
    if kind.starts_with("FT_STRING") || kind == "text" {
        return &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Substring"),
            ("matches", "Regular expression"),
            ("in", "Membership set"),
        ];
    }
    if matches!(kind, "FT_BYTES" | "FT_UINT_BYTES" | "bytes") {
        return &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("contains", "Byte sequence"),
            ("in", "Membership set"),
        ];
    }
    if matches!(
        kind,
        "FT_IPv4" | "FT_IPv6" | "FT_ETHER" | "FT_GUID" | "FT_OID" | "FT_REL_OID" | "ip"
    ) {
        return &[
            ("==", "Equal"),
            ("!=", "Not equal"),
            ("in", "Membership set"),
        ];
    }
    &[
        ("==", "Equal"),
        ("!=", "Not equal"),
        ("<", "Less than"),
        ("<=", "Less than or equal"),
        (">", "Greater than"),
        (">=", "Greater than or equal"),
        ("in", "Membership set"),
    ]
}

fn values_for(field: &str, prefix: &str, known_values: &[String]) -> Vec<(String, String)> {
    let needle = prefix.to_ascii_lowercase();
    let mut values = Vec::new();
    if matches!(
        field.to_ascii_lowercase().as_str(),
        "tag" | "tags" | "entry.tag"
    ) {
        for value in known_values {
            if value.to_ascii_lowercase().starts_with(&needle) {
                values.push((value.clone(), "recorded tag".into()));
            }
            if values.len() == 12 {
                break;
            }
        }
    }
    if field.eq_ignore_ascii_case("syscall.name") {
        for syscall in antinomie_monitor_core::syscalls::all() {
            if syscall.name.to_ascii_lowercase().starts_with(&needle) {
                values.push((syscall.name.clone(), "syscall name".into()));
            }
            if values.len() == 12 {
                break;
            }
        }
    } else if field.eq_ignore_ascii_case("http.request.method") {
        for method in ["GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"] {
            if method.to_ascii_lowercase().starts_with(&needle) {
                values.push((method.into(), "HTTP method".into()));
            }
        }
    } else if field.eq_ignore_ascii_case("args.prot") {
        for (value, detail) in [
            ("0", "PROT_NONE"),
            ("1", "PROT_READ"),
            ("2", "PROT_WRITE"),
            ("4", "PROT_EXEC"),
            ("7", "read, write and execute"),
        ] {
            if value.starts_with(prefix) {
                values.push((value.into(), detail.into()));
            }
        }
    }
    values
}

fn operator_prefix(prefix: &str) -> bool {
    prefix.starts_with(['=', '!', '<', '>', '&', '|', 'c', 'i', 'e', 'm'])
}

fn field_before_operator(text: &str, start: usize) -> Option<String> {
    let tokens = tokenize(text[..start].trim_end()).ok()?;
    if matches!(tokens.last(), Some(Token::LBrace | Token::Comma)) {
        for pair in tokens.windows(2).rev() {
            if let [Token::Ident(field), Token::In] = pair {
                return Some(field.clone());
            }
            if matches!(pair[1], Token::And | Token::Or) {
                break;
            }
        }
    }
    let mut tail = tokens.iter().rev();
    if !matches!(
        tail.next()?,
        Token::Eq
            | Token::Ne
            | Token::Lt
            | Token::Le
            | Token::Gt
            | Token::Ge
            | Token::Contains
            | Token::Amp
    ) {
        return None;
    }
    match tail.next()? {
        Token::Ident(field) => Some(field.clone()),
        _ => None,
    }
}

fn previous_word(text: &str, start: usize) -> Option<String> {
    let before = text[..start].trim_end();
    let (begin, end) = editor_tokens(before).last().copied()?;
    Some(before[begin..end].to_owned())
}

fn byte_index(text: &str, chars: usize) -> usize {
    text.char_indices()
        .nth(chars)
        .map(|(index, _)| index)
        .unwrap_or(text.len())
}

fn char_index(text: &str, byte: usize) -> usize {
    text[..byte.min(text.len())].chars().count()
}

fn token_end(text: &str, cursor: usize) -> usize {
    active_token(text, cursor).map_or(cursor, |(_, end)| end)
}

fn token_start(text: &str, cursor: usize) -> usize {
    active_token(text, cursor).map_or(cursor, |(start, _)| start)
}

fn active_token(text: &str, cursor: usize) -> Option<(usize, usize)> {
    let tokens = editor_tokens(text);
    tokens
        .iter()
        .copied()
        .find(|(start, end)| *start <= cursor && cursor < *end)
        .or_else(|| {
            tokens.into_iter().find(|(start, end)| {
                *start < cursor
                    && cursor == *end
                    && !matches!(
                        &text[*start..*end],
                        "(" | ")" | "{" | "}" | "," | "&&" | "||" | "!"
                    )
            })
        })
}

fn editor_tokens(text: &str) -> Vec<(usize, usize)> {
    let mut tokens = Vec::new();
    let mut iter = text.char_indices().peekable();
    while let Some((start, ch)) = iter.next() {
        if ch.is_whitespace() {
            continue;
        }
        let mut end = start + ch.len_utf8();
        if ch == '"' || ch == '\'' {
            let mut escape = false;
            for (at, next) in iter.by_ref() {
                end = at + next.len_utf8();
                if escape {
                    escape = false;
                    continue;
                }
                if next == '\\' {
                    escape = true;
                } else if next == ch {
                    break;
                }
            }
        } else if ch.is_alphanumeric() || matches!(ch, '_' | '.' | '-' | '/') {
            while let Some(&(at, next)) = iter.peek() {
                if !next.is_alphanumeric()
                    && !matches!(next, '_' | '.' | '[' | ']' | '-' | '/' | ':')
                {
                    break;
                }
                end = at + next.len_utf8();
                iter.next();
            }
        } else if matches!(ch, '=' | '!' | '<' | '>' | '&' | '|') {
            while let Some(&(at, next)) = iter.peek() {
                if !matches!(next, '=' | '&' | '|') {
                    break;
                }
                end = at + next.len_utf8();
                iter.next();
            }
        }
        tokens.push((start, end));
    }
    tokens
}

fn floor_boundary(text: &str, mut index: usize) -> usize {
    while index > 0 && !text.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn unclosed_quote(text: &str) -> bool {
    let mut quote = None;
    let mut escape = false;
    for ch in text.chars() {
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && quote.is_some() {
            escape = true;
            continue;
        }
        if Some(ch) == quote {
            quote = None;
        } else if quote.is_none() && matches!(ch, '"' | '\'') {
            quote = Some(ch);
        }
    }
    quote.is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::{EventSummary, FieldSummary, InvocationSummary};

    const TABLE_FIELDS: &[FieldSpec<'static>] = &[
        FieldSpec::text("name", "Displayed name"),
        FieldSpec::number("address", "Address"),
        FieldSpec::boolean("complete", "Completeness"),
        FieldSpec::tags("tag", "Annotation tags"),
    ];

    #[test]
    fn typed_tables_preserve_unsigned_addresses_missing_values_and_string_case() {
        let row = [
            ("name", RowValue::Text("Needs Review".into())),
            ("address", RowValue::Number(i128::from(u64::MAX))),
            ("complete", RowValue::Bool(false)),
            (
                "tag",
                RowValue::List(vec!["needs review".into(), "triaged".into()]),
            ),
        ];
        for filter in [
            "address == 0xffffffffffffffff",
            "address > 9223372036854775807",
            "complete == false",
            "!complete",
            "exists(complete)",
            "lower(name) == \"needs review\"",
            "tag == \"needs review\"",
            "tag != \"unknown\"",
            "tag in {\"unknown\", \"triaged\"}",
            "name contains \"Review\" and not missing(address)",
            "(address & 7) == 7",
            "address & 7 == 7",
        ] {
            let compiled = compile_table(filter, TABLE_FIELDS);
            assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
            assert!(compiled.keep_table(&row), "{filter}");
        }
        for filter in [
            "complete",
            "name == \"needs review\"",
            "tag != \"triaged\"",
            "name contains \"review\"",
        ] {
            assert!(
                !compile_table(filter, TABLE_FIELDS).keep_table(&row),
                "{filter}"
            );
        }
        let absent = [("name", RowValue::Missing), ("complete", RowValue::Missing)];
        for filter in ["name != \"unknown\"", "complete == false", "exists(name)"] {
            assert!(
                !compile_table(filter, TABLE_FIELDS).keep_table(&absent),
                "{filter}"
            );
        }
        assert!(
            compile_table("missing(name) && missing(complete)", TABLE_FIELDS).keep_table(&absent)
        );
        for filter in [
            "typo == 2",
            "address contains 7",
            "name > 7",
            "complete == FALSE",
            "complete == 0",
            "lower(address) == 1",
            "name ==",
        ] {
            assert!(
                compile_table(filter, TABLE_FIELDS).error.is_some(),
                "{filter}"
            );
        }
    }

    #[test]
    fn known_tag_completion_quotes_spaces_quotes_backslashes_and_unicode() {
        for tag in ["needs review", "a\"b", "a\\b", "révision", "and", "123"] {
            let source = "tag == ";
            let item = completions_with(source, source.len(), FilterScope::Record, &[tag.into()])
                .into_iter()
                .next()
                .expect("tag completion");
            let mut edited = source.to_owned();
            apply_completion(&mut edited, &item);
            let compiled = compile_record(&edited);
            assert!(compiled.error.is_none(), "{edited}: {:?}", compiled.error);
            assert!(
                compiled.keep_record(&RecordLabels {
                    id: "record",
                    name: "",
                    path: "/tmp",
                    tags: &[tag.into()]
                }),
                "{edited}"
            );
        }
        let text = "entry.id == \"é\" && tag == \"nee tail\" || entry.id == other";
        let caret = text.find("nee tail").unwrap() + 3;
        let item = completions_with(text, caret, FilterScope::Record, &["needs review".into()])
            .into_iter()
            .next()
            .expect("quoted completion");
        let mut edited = text.to_owned();
        apply_completion(&mut edited, &item);
        assert_eq!(
            edited,
            "entry.id == \"é\" && tag == \"needs review\" || entry.id == other"
        );
    }

    #[test]
    fn completion_replaces_selection_and_does_not_offer_fields_as_values() {
        let text = "syscall.num == 9 && args.pr || tid == 2";
        let start = text.find("args.pr").unwrap();
        let end = start + 7;
        let item = completions_fields(
            text,
            end,
            &fields_for(FilterScope::Syscall),
            &[],
            Some((start, end)),
        )
        .into_iter()
        .find(|item| item.insert == "args.prot")
        .expect("selection completion");
        let mut edited = text.to_owned();
        apply_completion(&mut edited, &item);
        assert_eq!(edited, "syscall.num == 9 && args.prot || tid == 2");
        assert!(completions("syscall.num == ", 15, FilterScope::Syscall).is_empty());
        assert!(completions("syscall.num ex", 14, FilterScope::Syscall)
            .iter()
            .all(|item| !item.insert.starts_with("exists")));
    }

    #[test]
    fn incomplete_table_drafts_keep_the_last_applied_filter() {
        let ctx = egui::Context::default();
        let row = [("address", RowValue::Number(9))];
        for (draft, expected) in [
            ("address == 9", true),
            ("address ==", true),
            ("address == 10", false),
            ("address == 10 &&", false),
            ("", true),
        ] {
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| {
                    let compiled = applied_table(ui, draft, TABLE_FIELDS, "retention");
                    assert!(compiled.keep_table(&row) == expected, "{draft}");
                });
            });
        }
    }

    #[test]
    fn oversized_recursive_expressions_are_rejected_before_parser_recursion() {
        for source in [
            format!("{}name{}", "(".repeat(65), ")".repeat(65)),
            format!("{}name", "!".repeat(257)),
            (0..258)
                .map(|_| "name == \"x\"")
                .collect::<Vec<_>>()
                .join(" || "),
            format!("name == \"{}\"", "x".repeat(65 * 1024)),
        ] {
            let query = compile_table(&source, TABLE_FIELDS);
            assert!(query.error.is_some(), "large query was accepted");
        }
        let source = "name == \"x\"";
        assert!(compile_table(source, TABLE_FIELDS).error.is_none());
    }

    #[test]
    fn help_lists_schema_argument_names() {
        assert!(guide_has("args.filename"));
        assert!(guide_has("execve"));
        assert!(guide_has("http.request.method"));
        assert!(guide_has("dns.qry.name"));
    }

    fn call(nr: u64, name: &str, args: [u64; 6]) -> InvocationSummary {
        InvocationSummary {
            stream_id: 1,
            task_cookie: 4,
            call_id: 1,
            entry: Some(EventSummary {
                root_task_cookie: 4,
                stream_id: 1,
                task_cookie: 4,
                call_id: 1,
                event_seq: 1,
                phase: 1,
                syscall_nr: nr,
                syscall_name: name.into(),
                pid: 9,
                tid: 9,
                cpu: 0,
                timestamp_ns: 0,
                args: Some(args),
                result: Some(3),
                complete: true,
                issues: Vec::new(),
                fields: Vec::new(),
            }),
            exit: None,
            async_events: Vec::new(),
            task_exit: None,
        }
    }

    #[test]
    fn call_id_matches_only_that_invocation() {
        let one = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        assert_eq!(one.call_id, 1);
        assert!(compile_note("call.id == 5").error.is_none());
        assert!(matches("call.id == 1", &one).unwrap());
        assert!(matches("call_id == 1", &one).unwrap());
        let mut other = one.clone();
        other.call_id = 2;
        assert!(!matches("call.id == 1", &other).unwrap());
        assert!(!matches("call_id == 1", &other).unwrap());
    }

    #[test]
    fn comparisons_combine_syscall_number_and_named_argument() {
        let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        assert!(matches("syscall.num == 9 && args.fd < 3", &mmap).unwrap());
        assert!(!matches("syscall.num == 9 && args.fd < 2", &mmap).unwrap());
        assert!(matches("syscall.name == mmap", &mmap).unwrap());
        assert!(matches("mmap", &mmap).unwrap());
        assert!(matches("args.prot == 7", &mmap).unwrap());
    }

    #[test]
    fn syscall_aliases_are_registered_and_resolve_schema_argument_spellings() {
        let mmap = call(9, "mmap", [0x1234, 4096, 7, 0, 2, 0]);
        for filter in [
            "syscall.number == 9",
            "syscall == mmap",
            "task.cookie == 4",
            "call_id == 1",
            "args.addr == 4660",
            "args.address == 4660",
            "args.len == 4096",
            "args.length == 4096",
            "args.prot == 7",
            "args.protection == 7",
        ] {
            assert!(matches(filter, &mmap).unwrap(), "{filter}");
        }
        let read = call(0, "read", [0, 0x4321, 10, 0, 0, 0]);
        for filter in ["args.buf == 17185", "args.buffer == 17185"] {
            assert!(matches(filter, &read).unwrap(), "{filter}");
        }
    }

    #[test]
    fn generated_captured_members_validate_complete_values_and_missing_ranges() {
        let mut invocation = call(437, "openat2", [u64::MAX - 99, 0x1000, 0x2000, 24, 0, 0]);
        let mut preview = Vec::new();
        for value in [7u64, 0o700, 0x1234] {
            preview.extend(value.to_le_bytes());
        }
        invocation
            .entry
            .as_mut()
            .unwrap()
            .fields
            .push(FieldSummary {
                object_id: 1,
                key: "arg2.how".into(),
                layout: "linux-6.12.94/x86_64/open_how".into(),
                logical_len: Some(24),
                captured_len: 24,
                status: None,
                capture_error: 0,
                complete: true,
                preview,
                raw_path: None,
                ranges: vec![(0, 24)],
            });
        assert!(matches("args.how.flags == 7 && args.how.mode == 448 && args.how.resolve == 4660 && args.how.complete == true", &invocation).unwrap());
        invocation.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 8), (16, 8)];
        assert!(matches("missing(args.how.mode) && args.how.flags == 7", &invocation).unwrap());
        let fields = syscall_fields();
        let indexed = antinomie_monitor_core::filter_members::registry()
            .iter()
            .find(|member| {
                member.name.contains("[0].")
                    && member.kind == antinomie_monitor_core::filter_members::MemberKind::Integer
            })
            .expect("generated array member");
        let expression = format!("missing({})", indexed.name);
        assert!(compile_note(&expression).error.is_none(), "{expression}");
        assert!(fields.iter().any(|field| field.name == indexed.name));
        assert!(compile_note("args.how.invented_member == 0")
            .error
            .is_some());
    }

    #[test]
    fn process_provenance_requires_committed_exec_and_never_guesses_identity() {
        let mut invocation = call(59, "execve", [0x1000, 0x2000, 0, 0, 0, 0]);
        invocation.entry.as_mut().unwrap().result = None;
        for (key, value) in [
            ("arg0.path", b"/bin/example\0".as_slice()),
            ("arg1.argv[1]", b"second\0".as_slice()),
            ("arg1.argv[0]", b"first\0".as_slice()),
        ] {
            invocation
                .entry
                .as_mut()
                .unwrap()
                .fields
                .push(FieldSummary {
                    object_id: 1,
                    key: key.into(),
                    layout: String::new(),
                    logical_len: Some(value.len() as u64),
                    captured_len: value.len() as u64,
                    status: None,
                    capture_error: 0,
                    complete: true,
                    preview: value.to_vec(),
                    raw_path: None,
                    ranges: vec![(0, value.len() as u64)],
                });
        }
        assert!(matches("missing(process.exe) && missing(process.argv)", &invocation).unwrap());
        let mut exit = invocation.entry.clone().unwrap();
        exit.phase = 2;
        exit.result = Some(-2);
        invocation.exit = Some(exit);
        assert!(matches("missing(process.exe)", &invocation).unwrap());
        invocation.exit.as_mut().unwrap().result = Some(0);
        assert!(matches("process.exe == \"/bin/example\" && process.argv == \"first\" && process.argv == \"second\"", &invocation).unwrap());
        assert!(matches("missing(process.ppid) && missing(process.parent_cookie) && missing(process.uid) && missing(process.gid) && missing(process.comm) && missing(process.state)", &invocation).unwrap());
        invocation.task_exit = invocation.exit.clone();
        assert!(matches("process.state == exited", &invocation).unwrap());
    }

    #[test]
    fn ret_uses_exit_outcome_when_entry_result_is_absent() {
        let mut paired = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        paired.entry.as_mut().unwrap().result = None;
        let mut exit = paired.entry.clone().unwrap();
        exit.phase = 2;
        exit.event_seq = 2;
        exit.result = Some(7);
        paired.exit = Some(exit);
        assert!(trace::representative(&paired).unwrap().result.is_none());
        for filter in ["ret == 7", "result == 7", "syscall.ret == 7"] {
            assert!(
                matches(filter, &paired).unwrap(),
                "{filter} should use the exit result"
            );
        }
        paired.entry.as_mut().unwrap().result = Some(3);
        paired.exit.as_mut().unwrap().result = None;
        assert!(matches(
            "missing(syscall.success) && missing(syscall.errno) && missing(ret)",
            &paired
        )
        .unwrap());
    }

    #[test]
    fn tag_does_not_match_path_text_stored_only_in_info() {
        let mut row = call(2, "open", [0x1000, 0, 0, 0, 0, 0]);
        let path = b"/tmp/example\0";
        let captured = path.len() as u64;
        row.entry.as_mut().unwrap().fields.push(FieldSummary {
            object_id: 1,
            key: "path".into(),
            layout: String::new(),
            logical_len: Some(captured),
            captured_len: captured,
            status: None,
            capture_error: 0,
            complete: true,
            preview: path.to_vec(),
            raw_path: None,
            ranges: vec![(0, captured)],
        });
        let info = trace::info(&row);
        assert!(info.contains("/tmp"), "{info}");
        assert!(!matches(r#"tag contains "tmp""#, &row).unwrap());
        assert!(!matches(r#"tags contains "tmp""#, &row).unwrap());
        assert!(matches(r#"info contains "tmp""#, &row).unwrap());
        assert!(matches(r#"args.path == "/tmp/example""#, &row).unwrap());
        assert!(matches("args.raw[0] == 4096", &row).unwrap());
        assert!(matches("args.0 == 4096", &row).unwrap());
        assert!(!matches(r#"args.path == "4096""#, &row).unwrap());
        row.entry.as_mut().unwrap().fields[0].preview = b" /tmp/spaces \0".to_vec();
        row.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 14)];
        row.entry.as_mut().unwrap().fields[0].captured_len = 14;
        row.entry.as_mut().unwrap().fields[0].logical_len = Some(14);
        assert!(matches(r#"args.path == " /tmp/spaces ""#, &row).unwrap());
        row.entry.as_mut().unwrap().fields[0].preview = vec![0];
        row.entry.as_mut().unwrap().fields[0].ranges = vec![(0, 1)];
        row.entry.as_mut().unwrap().fields[0].captured_len = 1;
        row.entry.as_mut().unwrap().fields[0].logical_len = Some(1);
        assert!(matches(r#"exists(args.path) && args.path == """#, &row).unwrap());
    }

    #[test]
    fn typo_in_dotted_field_is_a_compile_error() {
        let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        let compiled = compile_note("syscall.typo == 9");
        assert!(compiled.error.is_some());
        assert!(matches("syscall.typo == 9", &mmap).is_err());
    }

    #[test]
    fn exists_set_mask_and_raw_slot() {
        let mmap = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        assert!(matches("exists ret", &mmap).unwrap());
        assert!(!matches("missing ret", &mmap).unwrap());
        assert!(matches("syscall.num in {9, 10}", &mmap).unwrap());
        assert!(!matches("syscall.num in {10, 11}", &mmap).unwrap());
        assert!(matches(r#"syscall.name in {"mmap", "open"}"#, &mmap).unwrap());
        assert!(matches("args.prot & 7 == 7", &mmap).unwrap());
        assert!(matches("args.prot & 7 != 1", &mmap).unwrap());
        assert!(!matches("args.prot & 7 == 1", &mmap).unwrap());
        assert!(matches("args.raw[4] == 2", &mmap).unwrap());
        assert!(matches("args.raw[0] == 0", &mmap).unwrap());
        assert!(matches("args.raw[5] == 0", &mmap).unwrap());
        assert!(matches("exists ret && syscall.num in {9, 10}", &mmap).unwrap());

        let mut zero = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        zero.entry.as_mut().unwrap().result = Some(0);
        assert!(matches("exists ret", &zero).unwrap());
        let mut absent = call(9, "mmap", [0, 4096, 7, 0, 2, 0]);
        absent.entry.as_mut().unwrap().result = None;
        assert!(!matches("exists ret", &absent).unwrap());
        assert!(matches("missing ret", &absent).unwrap());

        let mut tagged = call(2, "open", [0x1000, 0, 0, 0, 0, 0]);
        let path = b"/tmp/example\0";
        let captured = path.len() as u64;
        tagged.entry.as_mut().unwrap().fields.push(FieldSummary {
            object_id: 1,
            key: "path".into(),
            layout: String::new(),
            logical_len: Some(captured),
            captured_len: captured,
            status: None,
            capture_error: 0,
            complete: true,
            preview: path.to_vec(),
            raw_path: None,
            ranges: vec![(0, captured)],
        });
        assert!(trace::info(&tagged).contains("/tmp"));
        assert!(!matches("exists tag", &tagged).unwrap());
        assert!(matches("missing tag", &tagged).unwrap());

        assert!(matches("syscall.num in {}", &mmap).is_err());
        assert!(matches("args.prot & -1 == 7", &mmap).is_err());
        assert!(matches("args.raw[6]", &mmap).is_err());
        assert!(matches("args.raw[6] == 0", &mmap).is_err());
        assert!(matches("args.raw[prot] == 7", &mmap).is_err());
    }

    #[test]
    fn record_tags_come_from_annotations_not_from_the_path() {
        let labels = RecordLabels {
            id: "run-1",
            name: "sample",
            path: "/tmp/example",
            tags: &["review".into()],
        };
        let tagged = compile_record(r#"tag == "review""#);
        assert!(tagged.error.is_none());
        assert!(tagged.keep_record(&labels));
        assert!(!compile_record(r#"tag == "tmp""#).keep_record(&labels));
        assert!(!compile_record(r#"tag contains "tmp""#).keep_record(&labels));
        assert!(compile_record(r#"entry.path contains "tmp""#).keep_record(&labels));
        let untagged = RecordLabels {
            tags: &[],
            ..labels
        };
        assert!(!compile_record("exists tag").keep_record(&untagged));
        assert!(compile_record("missing tag").keep_record(&untagged));
        let invalid = compile_record("syscall.typo == 9");
        assert!(invalid.error.is_some());
        assert!(!invalid.keep_record(&labels));
    }

    #[test]
    fn completions_keep_the_surrounding_clause_and_follow_the_registry() {
        let text = "syscall.num == 9 && args.pr";
        let items = completions(text, text.len(), FilterScope::Syscall);
        let prot = items
            .iter()
            .find(|item| item.insert == "args.prot")
            .expect("args.prot");
        let mut edited = text.to_owned();
        edited.replace_range(prot.start..prot.end, &prot.insert);
        assert_eq!(edited, "syscall.num == 9 && args.prot");
        let sysc = completions("sysc", 4, FilterScope::Syscall);
        let names: Vec<_> = sysc.iter().map(|item| item.insert.as_str()).collect();
        assert!(names.contains(&"syscall.name"), "{names:?}");
        assert!(names.contains(&"syscall.num"), "{names:?}");
        let method = completions("http.req", 8, FilterScope::Packet);
        assert!(method
            .iter()
            .any(|item| item.insert == "http.request.method"));
        assert!(method.iter().any(|item| item.insert == "http.request.uri"));
        let operators = completions("syscall.num ", 12, FilterScope::Syscall);
        assert!(operators.iter().any(|item| item.insert.contains("==")));
        assert!(operators.iter().any(|item| item.insert.contains("<=")));
        let inside = "info contains \"exa";
        assert!(completions(inside, inside.len(), FilterScope::Syscall).is_empty());
        let text = "syscall.num == 9 && args.prot";
        let caret = text.find("args.pr").unwrap() + "args.pr".len();
        let prot = completions(text, caret, FilterScope::Syscall)
            .into_iter()
            .find(|item| item.insert == "args.prot")
            .expect("whole token");
        let mut edited = text.to_owned();
        let next = apply_completion(&mut edited, &prot);
        assert_eq!(edited, "syscall.num == 9 && args.prot");
        assert_eq!(next, edited.len());
        let unicode = "info contains \"é\" && args.pr";
        let byte_caret = unicode.find("args.pr").unwrap() + "args.pr".len();
        let char_caret = char_index(unicode, byte_caret);
        assert_ne!(char_caret, byte_caret);
        assert_eq!(byte_index(unicode, char_caret), byte_caret);
        let prot = completions(
            unicode,
            byte_index(unicode, char_caret),
            FilterScope::Syscall,
        )
        .into_iter()
        .find(|item| item.insert == "args.prot")
        .expect("unicode caret");
        let mut edited = unicode.to_owned();
        apply_completion(&mut edited, &prot);
        assert_eq!(edited, "info contains \"é\" && args.prot");
        let presence = completions("ex", 2, FilterScope::Syscall);
        assert!(presence.iter().any(|item| item.insert == "exists "));
        assert!(completions("syscall.num ex", 14, FilterScope::Syscall)
            .iter()
            .all(|item| !item.insert.contains("exists")));
        let tags = completions_with("tag == mal", 10, FilterScope::Record, &["malware".into()]);
        assert!(tags.iter().any(|item| item.insert == "malware"));
    }

    #[test]
    #[ignore = "native X11 filter popup; stays open long enough to cover a 30s refresh"]
    fn native_filter_autocomplete() {
        use std::time::{Duration, Instant};
        use winit::platform::x11::EventLoopBuilderExtX11;
        struct App {
            syscall: String,
            history: String,
            packet: String,
            frames: u64,
            started: Instant,
            deadline: Instant,
            focused: bool,
        }
        impl eframe::App for App {
            fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
                self.frames += 1;
                let elapsed = self.started.elapsed().as_secs();
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.label(format!("refresh {elapsed}s · frame {}", self.frames));
                    ui.label("Syscall filter");
                    let syscall = crate::query::filter_edit(
                        ui,
                        &mut self.syscall,
                        "Filter syscalls",
                        ui.available_width(),
                        FilterScope::Syscall,
                    );
                    ui.label("Run history filter");
                    let _ = crate::query::filter_edit(
                        ui,
                        &mut self.history,
                        "Filter runs",
                        ui.available_width(),
                        FilterScope::Record,
                    );
                    ui.label("Packet filter");
                    let _ = crate::query::filter_edit(
                        ui,
                        &mut self.packet,
                        "Filter packets",
                        ui.available_width(),
                        FilterScope::Packet,
                    );
                    if !self.focused {
                        syscall.request_focus();
                        self.focused = true;
                    }
                });
                let _ = std::fs::write(
                    "/tmp/antinomie-filter-refresh",
                    format!("{elapsed} {}\n", self.frames),
                );
                if Instant::now() >= self.deadline {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                ctx.request_repaint_after(Duration::from_millis(100));
            }
        }
        let wide = std::env::var_os("ANTINOMIE_FILTER_QA_WIDE").is_some();
        let font = std::env::var("ANTINOMIE_FILTER_QA_FONT")
            .ok()
            .and_then(|value| value.parse::<f32>().ok())
            .unwrap_or(if wide { 16.0 } else { 24.0 });
        let seconds = std::env::var("ANTINOMIE_FILTER_QA_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(35)
            .clamp(1, 90);
        eframe::run_native(
            "Antinomie Filter QA",
            eframe::NativeOptions {
                viewport: egui::ViewportBuilder::default()
                    .with_inner_size(if wide {
                        [1100.0, 720.0]
                    } else {
                        [420.0, 760.0]
                    })
                    .with_position([80.0, 60.0]),
                persist_window: false,
                event_loop_builder: Some(Box::new(|builder| {
                    builder.with_x11().with_any_thread(true);
                })),
                ..Default::default()
            },
            Box::new(move |cc| {
                crate::theme::install(&cc.egui_ctx);
                crate::theme::text_size(&cc.egui_ctx, font);
                Ok(Box::new(App {
                    syscall: "syscall.num == 9 && args.pr".into(),
                    history: "entry.na".into(),
                    packet: "tcp.f".into(),
                    frames: 0,
                    started: Instant::now(),
                    deadline: Instant::now() + Duration::from_secs(seconds),
                    focused: false,
                }))
            }),
        )
        .unwrap();
    }
}

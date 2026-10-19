// SPDX-License-Identifier: MIT
//! Display filter for syscall rows. A bare word still matches the row text.
//! A comparison such as `syscall.num == 9 && args.fd < 3` uses the fields below.
use crate::trace::{self, argument_name};
use antinomie_monitor_core::{EventSummary, InvocationSummary};
use eframe::egui;

mod completion;
mod editor;
mod eval;
mod guide;
mod lexer;
mod parser;
mod tables;
mod validate;

use self::{completion::*, eval::*, lexer::*, parser::*, validate::*};
pub(crate) use self::{editor::*, guide::*, tables::*};

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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum RowValue {
    Number(i128),
    Text(String),
    Bool(bool),
    List(Vec<String>),
    Missing,
}

impl Compiled {
    /// An empty filter: every row is kept without looking at it.
    pub(crate) fn keeps_everything(&self) -> bool {
        self.error.is_none() && matches!(self.mode, Mode::All)
    }
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

pub(crate) const LABEL_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("entry.kind", "Evidence category"),
    FieldSpec::text("entry.id", "Recorded identity"),
    FieldSpec::text("entry.name", "Annotation name"),
    FieldSpec::text("entry.path", "Evidence path"),
    FieldSpec::tags("tag", "Stored annotation tags"),
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
mod tests;

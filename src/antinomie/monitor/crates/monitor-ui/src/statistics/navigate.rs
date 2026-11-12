// SPDX-License-Identifier: GPL-3.0-only
//! Where a click on a number goes (design 6): the Syscall Trace, with a filter
//! that lists exactly the calls behind the number. The clauses use the Trace's
//! own filter language, so the Trace's "N matching" equals the number.
use crate::query::quote_value;
use antinomie_monitor_core::syscall_groups::SyscallGroup;
use antinomie_triage::statistics::aggregate::ResultKey;

/// What the window asks the app to do; the app owns the Trace.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Navigate {
    /// Show these calls in the Syscall Trace (`scope_trace`).
    Filter(String),
    /// Show a hidden category in the Trace (a saved preference), then these calls.
    ShowGroup { group: SyscallGroup, filter: String },
    /// Open Run History to choose another run.
    RunHistory,
}

/// `syscall.group == "File & filesystem"`; `missing syscall.group` for Other.
pub(crate) fn group_clause(label: &str) -> String {
    if label == antinomie_triage::statistics::aggregate::OTHER_GROUP {
        "missing syscall.group".into()
    } else {
        format!("syscall.group == {}", quote_value(label, true))
    }
}

pub(crate) fn call_clause(name: &str) -> String {
    format!("syscall.name == {}", quote_value(name, false))
}

/// The result part alone: `syscall.errno == 2`, `syscall.success == true`,
/// `missing ret`.
pub(crate) fn result_part(key: ResultKey) -> String {
    match key {
        ResultKey::Returned => "syscall.success == true".into(),
        ResultKey::Errno(n) => format!("syscall.errno == {n}"),
        ResultKey::NoResult => "missing ret".into(),
    }
}

pub(crate) const FAILED: &str = "syscall.success == false";

/// `a && b`, either may be empty.
pub(crate) fn and(a: &str, b: &str) -> String {
    match (a.is_empty(), b.is_empty()) {
        (true, _) => b.into(),
        (_, true) => a.into(),
        _ => format!("{a} && {b}"),
    }
}

/// `(<window filter>) && <clause>`, the first part left out when empty. A
/// filter with `||` keeps its parentheses; a plain one needs none.
pub(crate) fn with_window_filter(window: &str, clause: &str) -> String {
    let window = window.trim();
    if window.is_empty() {
        clause.into()
    } else {
        format!("({window}) && {clause}")
    }
}

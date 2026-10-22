// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The coverage matrix: for every native x86-64 slot, whether a fixture
//! exercised it and whether its arguments, result, captured data, rendering
//! and async records were right. A slot that could not be exercised, or a gap
//! the recorder or the view cannot close yet, needs an explicit reason in
//! tests/monitor/conformance/trace/gaps.json; an unexplained one fails.
use crate::{
    judge::{CaseResult, Gap},
    render::Views,
    trace::GroupReport,
};
use antinomie_monitor_core::syscalls;
use std::{collections::BTreeMap, path::Path};

#[derive(serde::Deserialize)]
struct GapEntry {
    syscall: String,
    kind: String,
    /// Exact `Gap::what`, or a prefix ending with `*`.
    what: String,
    reason: String,
}

#[derive(serde::Deserialize)]
struct Unexercised {
    syscall: String,
    reason: String,
}

/// A warning of calls nobody describes (libc start-up, the fixture's own
/// output) that the capture contract explains.
#[derive(serde::Deserialize)]
struct Undescribed {
    /// The warning as the suite words it: "SYSCALL: ISSUE".
    warning: String,
    reason: String,
}

#[derive(serde::Deserialize, Default)]
pub struct AcceptedGaps {
    #[serde(default)]
    gaps: Vec<GapEntry>,
    #[serde(default)]
    unexercised: Vec<Unexercised>,
    #[serde(default)]
    undescribed: Vec<Undescribed>,
}

impl AcceptedGaps {
    pub fn load(repo: &Path) -> Result<Self, String> {
        let path = repo.join("tests/monitor/conformance/trace/gaps.json");
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn reason(&self, name: &str, gap: &Gap) -> Option<&str> {
        self.gaps
            .iter()
            .find(|entry| {
                entry.syscall == name
                    && entry.kind == gap.kind
                    && match entry.what.strip_suffix('*') {
                        Some(prefix) => gap.what.starts_with(prefix),
                        None => entry.what == gap.what,
                    }
            })
            .map(|entry| entry.reason.as_str())
    }

    /// The reason an undescribed call's warning is accepted, if it is.
    pub fn undescribed(&self, warning: &str) -> Option<&str> {
        self.undescribed
            .iter()
            .find(|entry| glob(&entry.warning, warning))
            .map(|entry| entry.reason.as_str())
    }

    fn unexercised(&self, name: &str) -> Option<&str> {
        self.unexercised
            .iter()
            .find(|entry| entry.syscall == name)
            .map(|entry| entry.reason.as_str())
    }
}

/// `pattern` with `*` standing for any text.
fn glob(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or_default();
    let Some(mut rest) = text.strip_prefix(first) else {
        return false;
    };
    let parts: Vec<&str> = parts.collect();
    for (index, part) in parts.iter().enumerate() {
        if index + 1 == parts.len() {
            return rest.ends_with(part);
        }
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    rest.is_empty()
}

pub struct Built {
    pub passed: bool,
    pub json: serde_json::Value,
    pub table: String,
    pub summary: Vec<String>,
}

/// The view's verdict on one case: fallbacks that are defects, and gaps.
fn render_verdict(
    case: &CaseResult,
    view: Option<&crate::render::CallView>,
) -> (Vec<String>, Vec<Gap>) {
    let Some(view) = view else {
        return (vec!["not rendered".into()], Vec::new());
    };
    let mut problems = Vec::new();
    let mut gaps = Vec::new();
    let data_gap = |arg: &str| {
        case.gaps
            .iter()
            .any(|gap| gap.what.contains(&format!("{arg}.")) || gap.what.ends_with(arg))
    };
    for fallback in &view.fallbacks {
        let (kind, arg) = fallback.split_once(':').unwrap_or((fallback, ""));
        let index = arg.strip_prefix("arg").and_then(|n| n.parse::<u8>().ok());
        match kind {
            "raw-pointer" => {
                if index.is_some_and(|index| case.data_args.contains(&index)) {
                    if data_gap(arg) {
                        gaps.push(Gap {
                            nr: case.nr,
                            kind: "render".into(),
                            what: format!("{arg} shown as an address: not captured"),
                        });
                    } else {
                        problems.push(format!(
                            "{arg} shows its address although its data was captured"
                        ));
                    }
                }
            }
            "unknown-flags" | "unknown-selector" if case.success => gaps.push(Gap {
                nr: case.nr,
                kind: "render".into(),
                what: format!("{kind} {arg}"),
            }),
            "unknown-flags" | "unknown-selector" => {}
            // A row with no argument schema (no entry point) has only
            // positional names.
            "generic-name" => gaps.push(Gap {
                nr: case.nr,
                kind: "render".into(),
                what: format!("generic name {arg}"),
            }),
            _ => problems.push(format!("view fallback {fallback}")),
        }
    }
    (problems, gaps)
}

#[derive(Default)]
struct Slot {
    cases: u64,
    success: u64,
    failure: u64,
    unmatched: u64,
    args_bad: u64,
    ret_bad: u64,
    data_bad: u64,
    async_cases: u64,
    async_bad: u64,
    render_bad: u64,
    rendered: u64,
    gaps: BTreeMap<Gap, u64>,
    problems: Vec<String>,
}

fn mark(ok: bool, applicable: bool) -> &'static str {
    match (applicable, ok) {
        (false, _) => "-",
        (true, true) => "ok",
        (true, false) => "FAIL",
    }
}

pub fn build(
    reports: &[GroupReport],
    views: &Views,
    accepted: &AcceptedGaps,
    render: bool,
) -> Built {
    let mut slots: BTreeMap<u64, Slot> = BTreeMap::new();
    for report in reports {
        let group_views = views.get(&report.group);
        for case in &report.cases {
            let slot = slots.entry(case.nr).or_default();
            slot.cases += 1;
            if case.matched.is_none() {
                slot.unmatched += 1;
            } else if case.success {
                slot.success += 1;
            } else {
                slot.failure += 1;
            }
            slot.args_bad += u64::from(!case.args_ok);
            slot.ret_bad += u64::from(!case.ret_ok);
            slot.data_bad += u64::from(!case.data_ok || case.file_ok == Some(false));
            if let Some(ok) = case.async_ok {
                slot.async_cases += 1;
                slot.async_bad += u64::from(!ok);
            }
            for gap in &case.gaps {
                *slot.gaps.entry(gap.clone()).or_default() += 1;
            }
            for problem in &case.problems {
                slot.problems
                    .push(format!("{} [{}]: {problem}", case.label, report.group));
            }
            if render && let Some(key) = case.matched {
                let view = group_views.and_then(|views| views.calls.get(&key));
                let (problems, gaps) = render_verdict(case, view);
                slot.rendered += 1;
                slot.render_bad += u64::from(!problems.is_empty());
                for problem in problems {
                    slot.problems.push(format!(
                        "{} [{}]: render: {problem}",
                        case.label, report.group
                    ));
                }
                for gap in gaps {
                    *slot.gaps.entry(gap).or_default() += 1;
                }
            }
        }
    }
    let mut rows = Vec::new();
    let mut table = String::new();
    table.push_str(&format!(
        "{:>4} {:<24} {:>5} {:>4} {:>4} {:>4} {:<5} {:<5} {:<5} {:<6} {:<5} notes\n",
        "nr", "syscall", "cases", "ok", "err", "miss", "args", "ret", "data", "render", "async"
    ));
    let (mut exercised, mut decoded, mut returned, mut captured, mut rendered_ok) = (0, 0, 0, 0, 0);
    let mut failed_slots = 0;
    let mut gap_lines = Vec::new();
    let mut unexplained = Vec::new();
    for info in syscalls::all() {
        let slot = slots.remove(&info.number).unwrap_or_default();
        let pointer = info.arguments.iter().any(|argument| argument.pointer);
        let matched = slot.cases > slot.unmatched;
        let mut notes = Vec::new();
        let mut gaps_json = Vec::new();
        let mut slot_failed = false;
        for (gap, count) in &slot.gaps {
            let reason = accepted.reason(&info.name, gap);
            if reason.is_none() {
                slot_failed = true;
                unexplained.push(format!("{} {}: {} ×{count}", info.name, gap.kind, gap.what));
            }
            gap_lines.push(format!(
                "{:<24} {:<12} {:<48} {}",
                info.name,
                gap.kind,
                gap.what,
                reason.unwrap_or("UNEXPLAINED")
            ));
            gaps_json.push(serde_json::json!({
                "kind": gap.kind, "what": gap.what, "cases": count,
                "reason": reason, "accepted": reason.is_some(),
            }));
        }
        let data_gap = slot
            .gaps
            .keys()
            .any(|gap| gap.kind == "no_decoder" || gap.kind == "not_captured");
        let render_gap = slot.gaps.keys().any(|gap| gap.kind == "render");
        let skip = (!matched)
            .then(|| accepted.unexercised(&info.name))
            .flatten();
        if !matched {
            match skip {
                Some(reason) => notes.push(format!("not exercised: {reason}")),
                None => {
                    slot_failed = true;
                    notes.push("not exercised, no reason given".into());
                }
            }
        }
        if slot.unmatched > 0
            || slot.args_bad + slot.ret_bad + slot.data_bad + slot.async_bad + slot.render_bad > 0
        {
            slot_failed = true;
        }
        let args = mark(slot.args_bad == 0, matched);
        let ret = mark(slot.ret_bad == 0, matched);
        let data = if !matched {
            "-"
        } else if slot.data_bad > 0 {
            "FAIL"
        } else if data_gap {
            "gap"
        } else if pointer {
            "ok"
        } else {
            "-"
        };
        let render_mark = if !matched || !render {
            "-"
        } else if slot.render_bad > 0 {
            "FAIL"
        } else if render_gap {
            "gap"
        } else {
            "ok"
        };
        let async_mark = mark(slot.async_bad == 0, slot.async_cases > 0);
        exercised += u64::from(matched);
        decoded += u64::from(matched && slot.args_bad == 0);
        returned += u64::from(matched && slot.ret_bad == 0);
        captured += u64::from(matched && slot.data_bad == 0 && !data_gap);
        rendered_ok += u64::from(matched && render && slot.render_bad == 0 && !render_gap);
        failed_slots += u64::from(slot_failed);
        if slot_failed && !slot.problems.is_empty() {
            notes.push(format!("{} problems", slot.problems.len()));
        }
        if !info
            .entry_point
            .as_deref()
            .is_some_and(|entry| entry != "sys_ni_syscall")
        {
            notes.push("no entry point".into());
        }
        table.push_str(&format!(
            "{:>4} {:<24} {:>5} {:>4} {:>4} {:>4} {:<5} {:<5} {:<5} {:<6} {:<5} {}\n",
            info.number,
            info.name,
            slot.cases,
            slot.success,
            slot.failure,
            slot.unmatched,
            args,
            ret,
            data,
            render_mark,
            async_mark,
            notes.join("; ")
        ));
        rows.push(serde_json::json!({
            "nr": info.number, "name": info.name, "cases": slot.cases,
            "success_cases": slot.success, "failure_cases": slot.failure,
            "unmatched": slot.unmatched, "exercised": matched,
            "args": args, "ret": ret, "data": data, "render": render_mark, "async": async_mark,
            "gaps": gaps_json, "not_exercised_reason": skip,
            "failed": slot_failed, "problems": slot.problems,
        }));
    }
    let total = syscalls::all().len();
    let mut summary = vec![format!(
        "{} matrix: {total} slots; exercised {exercised}, arguments decoded {decoded}, results decoded {returned}, data captured without gaps {captured}, rendered without fallbacks {rendered_ok}; {failed_slots} slots failing",
        if failed_slots == 0 && slots.is_empty() {
            "PASS"
        } else {
            "FAIL"
        }
    )];
    for (nr, slot) in &slots {
        summary.push(format!(
            "FAIL cases for syscall {nr} outside the native table ({} cases)",
            slot.cases
        ));
    }
    for line in &unexplained {
        summary.push(format!("FAIL unexplained gap: {line}"));
    }
    table.push_str("\nGaps (kind, what, reason):\n");
    for line in &gap_lines {
        table.push_str(line);
        table.push('\n');
    }
    Built {
        passed: failed_slots == 0 && slots.is_empty(),
        json: serde_json::json!({
            "slots": total, "exercised": exercised, "arguments_decoded": decoded,
            "results_decoded": returned, "data_captured": captured,
            "rendered": rendered_ok, "failing_slots": failed_slots, "rows": rows,
        }),
        table,
        summary,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn warning_patterns_match_with_wildcards() {
        let pattern = "*: field capture incomplete, status NOT_RESIDENT (*)";
        assert!(super::glob(
            pattern,
            "openat: field capture incomplete, status NOT_RESIDENT (arg1.path)"
        ));
        assert!(!super::glob(
            pattern,
            "openat: field capture incomplete, status COPY_FAULT (arg1.path)"
        ));
        assert!(super::glob("ioctl: x", "ioctl: x"));
        assert!(!super::glob("ioctl: x", "ioctl: xy"));
        assert!(super::glob("a*c*e", "abcde"));
    }
}

// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Golden files of how the Syscall Trace view shows each described call,
//! normalised so a rerun reproduces them: process and thread IDs become
//! `<pid>`, addresses `<addr>`, and content the program could not predict
//! (`volatile` cases, exit-time buffers) is left out. The files live in
//! tests/monitor/conformance/trace/golden/GROUP.txt; `--bless` rewrites them.
use crate::{Context, judge::CaseResult, oracle, recording, render::Views, trace::GroupReport};
use std::collections::{BTreeMap, BTreeSet};

/// Groups whose calls happen in a fixed order with fixed values.
const GOLDEN_GROUPS: [&str; 2] = ["user", "root"];

pub struct Checked {
    pub passed: bool,
    pub summary: Vec<String>,
}

fn looks_like_address(text: &str) -> bool {
    text.strip_prefix("0x")
        .is_some_and(|digits| digits.len() >= 5 && digits.chars().all(|c| c.is_ascii_hexdigit()))
}

/// What a golden line must not depend on: process and thread IDs, and the
/// fixture's private directory.
pub struct Volatile {
    pub ids: BTreeSet<String>,
    pub work_dir: Option<String>,
}

/// One value as the golden file keeps it. Only values that name a process
/// (`pidish`) are compared with the run's IDs.
fn normal(text: &str, volatile: &Volatile, pidish: bool) -> String {
    if looks_like_address(text) {
        return "<addr>".into();
    }
    // A process or thread number other than 0 and -1, whoever it names.
    if pidish && text.parse::<i64>().is_ok_and(|id| id > 0) {
        return "<pid>".into();
    }
    // Kernel-chosen handles printed in decimal (an AIO context).
    if text
        .parse::<u64>()
        .is_ok_and(|value| value > u64::from(u32::MAX))
    {
        return "<handle>".into();
    }
    // A CPU clock names its process or thread: "… of process 120".
    for owner in [" of process ", " of thread "] {
        if let Some((head, id)) = text.rsplit_once(owner)
            && id.chars().all(|c| c.is_ascii_digit())
        {
            return format!("{head}{owner}<pid>");
        }
    }
    let mut text = text.to_owned();
    if let Some(dir) = &volatile.work_dir {
        text = text.replace(dir.as_str(), "<work>");
    }
    // IDs inside text (/proc/1234/...): whole numbers only.
    let mut out = String::with_capacity(text.len());
    let mut digits = String::new();
    for c in text.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        if !digits.is_empty() {
            let embedded = out.ends_with('/') || out.ends_with(':') || out.ends_with('-');
            if embedded && volatile.ids.contains(&digits) {
                out.push_str("<pid>");
            } else {
                out.push_str(&digits);
            }
            digits.clear();
        }
        if c != '\0' {
            out.push(c);
        }
    }
    out
}

/// A captured object as the golden file keeps it: text, socket addresses and
/// exec vectors are stable; raw bytes (structs holding times, addresses,
/// inode numbers) are not, so only their presence is kept.
fn data(preview: &str, volatile: &Volatile) -> String {
    let readable = preview.starts_with('"')
        || preview.starts_with('[')
        || preview.starts_with("unix:")
        || preview.ends_with(" captured objects")
        || preview
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.chars().all(|c| c.is_ascii_digit()));
    if readable {
        normal(preview, volatile, false)
    } else if preview == "uncaptured" {
        preview.into()
    } else {
        "<bytes>".into()
    }
}

/// Syscalls whose result is a process or thread ID.
const RETURNS_ID: [&str; 12] = [
    "getpid",
    "getppid",
    "gettid",
    "fork",
    "vfork",
    "clone",
    "clone3",
    "getpgid",
    "getpgrp",
    "getsid",
    "setsid",
    "set_tid_address",
];

fn line(
    case: &CaseResult,
    volatile: bool,
    view: &crate::render::CallView,
    ids: &Volatile,
) -> String {
    let arguments: Vec<String> = view
        .arguments
        .iter()
        .map(|argument| {
            let shown = match &argument.data {
                Some(_) if volatile => "<data>".to_owned(),
                Some(preview) => data(preview, ids),
                // In a case the fixture marks volatile, large numbers are
                // kernel-chosen (key serials, timer ids).
                None if volatile
                    && argument
                        .text
                        .parse::<i64>()
                        .is_ok_and(|value| value.unsigned_abs() > 0xffff) =>
                {
                    "<value>".to_owned()
                }
                None => normal(
                    &argument.text,
                    ids,
                    ["pid", "tid", "tgid", "pgid", "pgrp", "sid"]
                        .iter()
                        .any(|name| argument.name.contains(name)),
                ),
            };
            format!("{}={shown}", argument.name)
        })
        .collect();
    let result = view.result.as_deref().map_or("-".to_owned(), |text| {
        if volatile && !text.starts_with('E') {
            "<value>".into()
        } else {
            normal(
                text,
                ids,
                RETURNS_ID.contains(&view.name.as_str()) || view.name.starts_with("wait"),
            )
        }
    });
    let fields: Vec<String> = view
        .fields
        .iter()
        .map(|field| {
            let key = field["key"].as_str().unwrap_or("?");
            let mut status = field["status"].as_str().unwrap_or("?").to_owned();
            // A field captured after the Entry (contract 22) says how.
            if let Some(mark) = field["recapture"].as_str() {
                status = format!("{status}@{mark}");
            }
            if field["phase"].as_u64() == Some(1) && !volatile {
                format!(
                    "{key}:{status}:{}",
                    field["preview"]
                        .as_str()
                        .map_or("?".into(), |p| data(p, ids))
                )
            } else {
                format!("{key}:{status}")
            }
        })
        .collect();
    let warnings = if view.warnings.is_empty() {
        String::new()
    } else {
        format!(" !{}", view.warnings.len())
    };
    format!(
        "{} | {}({}) = {result} | {}{warnings}",
        case.label,
        view.name,
        arguments.join(", "),
        fields.join(" ")
    )
    .trim_end()
    .to_owned()
}

/// Line-based diff: lines only in the golden file (-) and only in the run (+).
fn diff(old: &str, new: &str) -> Vec<String> {
    let old: Vec<&str> = old.lines().collect();
    let new: Vec<&str> = new.lines().collect();
    let (n, m) = (old.len(), new.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if old[i] == new[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && old[i] == new[j] {
            i += 1;
            j += 1;
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push(format!("+{}", new[j]));
            j += 1;
        } else {
            out.push(format!("-{}", old[i]));
            i += 1;
        }
    }
    out
}

pub fn check(context: &Context, reports: &[GroupReport], views: &Views) -> Result<Checked, String> {
    let directory = context.repo.join("tests/monitor/conformance/trace/golden");
    let mut passed = true;
    let mut summary = Vec::new();
    for report in reports
        .iter()
        .filter(|report| GOLDEN_GROUPS.contains(&report.group.as_str()))
    {
        let Some(group_views) = views.get(&report.group) else {
            continue;
        };
        let transcript = oracle::parse(&recording::transcript(std::path::Path::new(
            &report.run_dir,
        ))?);
        let mut ids = Volatile {
            ids: BTreeSet::new(),
            work_dir: transcript.work_dir.clone(),
        };
        let mut volatile: BTreeMap<u64, bool> = BTreeMap::new();
        for expect in &transcript.expects {
            ids.ids.insert(expect.pid.to_string());
            ids.ids.insert(expect.tid.to_string());
            volatile.insert(expect.seq, expect.is_volatile);
        }
        ids.ids.extend(transcript.roles.keys().map(u32::to_string));
        let mut text = String::new();
        let mut cases: Vec<&CaseResult> = report.cases.iter().collect();
        cases.sort_by(|a, b| a.label.cmp(&b.label).then(a.seq.cmp(&b.seq)));
        for case in cases {
            let Some(view) = case.matched.and_then(|key| group_views.calls.get(&key)) else {
                text.push_str(&format!("{} | not recorded\n", case.label));
                continue;
            };
            let volatile = volatile.get(&case.seq).copied().unwrap_or(false);
            text.push_str(&line(case, volatile, view, &ids));
            text.push('\n');
        }
        let path = directory.join(format!("{}.txt", report.group));
        if context.bless {
            std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
            std::fs::write(&path, &text).map_err(|e| e.to_string())?;
            summary.push(format!("BLESSED golden {}", path.display()));
            continue;
        }
        let old = std::fs::read_to_string(&path).unwrap_or_default();
        if old == text {
            summary.push(format!("PASS golden {}", report.group));
            continue;
        }
        passed = false;
        let changes = diff(&old, &text);
        let out = context.out.join(format!("golden-{}.txt", report.group));
        std::fs::write(&out, &text).map_err(|e| e.to_string())?;
        summary.push(format!(
            "FAIL golden {}: {} changed lines (run written to {})",
            report.group,
            changes.len(),
            out.display()
        ));
        for change in changes.iter().take(60) {
            summary.push(format!("    {change}"));
        }
    }
    Ok(Checked { passed, summary })
}

#[cfg(test)]
mod tests {
    #[test]
    fn diff_shows_removed_and_added_lines() {
        assert_eq!(super::diff("a\nb\nc\n", "a\nc\nd\n"), ["-b", "+d"]);
        assert!(super::diff("a\n", "a\n").is_empty());
    }

    #[test]
    fn raw_bytes_are_kept_only_as_present() {
        let ids = super::Volatile {
            ids: Default::default(),
            work_dir: None,
        };
        assert_eq!(super::data("06 00 00 00 b6 c8", &ids), "<bytes>");
        assert_eq!(super::data("\"io-at\"", &ids), "\"io-at\"");
        assert_eq!(super::data("127.0.0.1:80", &ids), "127.0.0.1:80");
        assert_eq!(super::data("[\"sh\", \"-c\"]", &ids), "[\"sh\", \"-c\"]");
        assert_eq!(super::data("uncaptured", &ids), "uncaptured");
    }

    #[test]
    fn addresses_ids_and_the_work_directory_are_normalised() {
        let ids = super::Volatile {
            ids: ["1234".to_owned()].into_iter().collect(),
            work_dir: Some("/tmp/ant-conformance-AbC123".into()),
        };
        assert_eq!(super::normal("0x7ffe00001000", &ids, false), "<addr>");
        assert_eq!(super::normal("1234", &ids, true), "<pid>");
        assert_eq!(super::normal("-1", &ids, true), "-1");
        assert_eq!(
            super::normal("CPU clock (scheduler) of process 120", &ids, false),
            "CPU clock (scheduler) of process <pid>"
        );
        assert_eq!(super::normal("140291445530624", &ids, false), "<handle>");
        assert_eq!(super::normal("1234", &ids, false), "1234");
        assert_eq!(super::normal("O_RDONLY", &ids, true), "O_RDONLY");
        assert_eq!(super::normal("0x10", &ids, false), "0x10");
        assert_eq!(
            super::normal("\"/tmp/ant-conformance-AbC123/io-at\"", &ids, false),
            "\"<work>/io-at\""
        );
        assert_eq!(
            super::normal("\"/proc/1234/ns\"", &ids, false),
            "\"/proc/<pid>/ns\""
        );
        assert_eq!(super::normal("\"a1234\"", &ids, false), "\"a1234\"");
    }
}

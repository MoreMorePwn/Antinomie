// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Attribution groups: who wrote an io_uring entry, as the run says it
//! (`trace/fixture/attribution.c`). A ring one process maps was written by
//! that process: every request says so (`async.flags` bit 3) and the run's
//! async observation is complete, with no note. A ring two processes map, or
//! one whose kernel thread submits, has no proven writer: its requests say so
//! (bit 1) and the run is OBSERVATION_INCOMPLETE with the attribution note,
//! which is information, never loss. Every recorded call is whole and every
//! record accounted for, as in the other groups.
use crate::{Group, matrix::AcceptedGaps, oracle, recording, trace, vm::GroupRun};
use antinomie_monitor_core::ASYNC_ATTRIBUTION_NOTE;
use std::collections::BTreeMap;

#[derive(serde::Serialize)]
pub struct AttributionReport {
    pub group: String,
    pub run_dir: String,
    pub passed: bool,
    pub problems: Vec<String>,
    pub incomplete_expected: bool,
    pub flags: Option<u32>,
    pub notes: Vec<String>,
    pub calls: u64,
    pub accounting: serde_json::Value,
}

/// Whether the group's ring leaves the writer of its entries unproven.
pub fn incomplete_expected(group: &str) -> bool {
    group != "ring-private"
}

pub fn check(
    group: &Group,
    run: &GroupRun,
    accepted: &AcceptedGaps,
) -> Result<AttributionReport, String> {
    let directory = run.run.directory.clone();
    let scan = recording::scan_raw(&directory)?;
    let mut problems = trace::run_problems(group, run, &scan);
    let transcript = oracle::parse(&recording::transcript(&directory)?);
    problems.extend(crate::judge::transcript_problems(&transcript));
    let mut calls = 0u64;
    let mut issues = BTreeMap::new();
    let page_issues = recording::for_each_invocation(&directory, |call| {
        calls += 1;
        for issue in trace::unlabeled_issues(call) {
            *issues.entry(issue).or_insert(0u64) += 1;
        }
    })?;
    problems.extend(
        page_issues
            .into_iter()
            .map(|issue| format!("trace page: {issue}")),
    );
    for (issue, count) in &issues {
        if accepted.undescribed(issue).is_none() {
            problems.push(format!("warning ×{count}: {issue}"));
        }
    }
    let incomplete = incomplete_expected(&group.name);
    let execution = run.run.execution.as_ref();
    let flags = execution.map(|e| e.flags);
    match execution {
        Some(e) if e.observation_incomplete() != incomplete => problems.push(format!(
            "OBSERVATION_INCOMPLETE is {}, expected {incomplete} (flags {:#x})",
            e.observation_incomplete(),
            e.flags
        )),
        Some(e) if !incomplete && e.flags & 8 == 0 => {
            problems.push(format!("not ASYNC_COMPLETE (flags {:#x})", e.flags))
        }
        Some(e) if e.async_loss_count != 0 => {
            problems.push(format!("async observation losses: {}", e.async_loss_count))
        }
        Some(_) => {}
        None => problems.push("no execution status".into()),
    }
    let expected_notes: &[&str] = if incomplete {
        &[ASYNC_ATTRIBUTION_NOTE]
    } else {
        &[]
    };
    if run.run.notes != expected_notes {
        problems.push(format!(
            "run notes {:?}, expected {expected_notes:?}",
            run.run.notes
        ));
    }
    // The requests themselves: an SQPOLL ring's are attributed to its creator
    // with no call; the others ride on the program's io_uring_enter.
    if scan.async_requests == 0 || scan.async_without_final != 0 || scan.async_payload_missing != 0
    {
        problems.push(format!(
            "{} async requests, {} without a final record, {} without their payload",
            scan.async_requests, scan.async_without_final, scan.async_payload_missing
        ));
    }
    let (proven, unproven) = if incomplete {
        (0, scan.async_requests)
    } else {
        (scan.async_requests, 0)
    };
    if (scan.async_producer_process, scan.async_producer_unknown) != (proven, unproven) {
        problems.push(format!(
            "{} requests written by their process and {} by an unproven writer, expected {proven} and {unproven}",
            scan.async_producer_process, scan.async_producer_unknown
        ));
    }
    Ok(AttributionReport {
        group: group.name.clone(),
        run_dir: directory.display().to_string(),
        passed: problems.is_empty(),
        problems,
        incomplete_expected: incomplete,
        flags,
        notes: run.run.notes.clone(),
        calls,
        accounting: trace::accounting(run, &scan, calls),
    })
}

pub fn summary_line(report: &AttributionReport) -> String {
    format!(
        "{} group {}: run flags {}, {} attribution, {} calls, notes {:?}",
        if report.passed { "PASS" } else { "FAIL" },
        report.group,
        report
            .flags
            .map_or_else(|| "unknown".into(), |flags| format!("{flags:#x}")),
        if report.incomplete_expected {
            "unproven"
        } else {
            "process-level"
        },
        report.calls,
        report.notes,
    )
}

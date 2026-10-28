// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Stress groups: `ant-workload` at one level. Nothing describes the calls, so
//! every one must be well formed (both phases, a result, no warning) and every
//! record that is missing must be one the loss counters count.
use crate::{Group, oracle, recording, trace, vm::GroupRun};
use std::collections::BTreeMap;

#[derive(serde::Serialize)]
pub struct StressReport {
    pub group: String,
    pub level: String,
    pub run_dir: String,
    pub passed: bool,
    pub problems: Vec<String>,
    pub calls: u64,
    /// Warnings of the trace by kind, split by whether lost packets explain them.
    pub loss_issues: BTreeMap<String, u64>,
    pub other_issues: BTreeMap<String, u64>,
    pub calls_with_loss: u64,
    pub scorecard: Option<String>,
    pub accounting: serde_json::Value,
    pub throughput: serde_json::Value,
}

/// How a page says a call's async observations were only previewed.
const ASYNC_PARTIAL: &str = "some calls list only the first 256 of their saved async observations";

/// Issues a lost packet causes; anything else is a defect even under loss.
fn loss_issue(issue: &str) -> bool {
    [
        "missing Entry",
        "missing Exit",
        "missing EVENT_BEGIN",
        "missing EVENT_END",
        "FIELD_BEGIN",
        "FIELD_END",
        "packet loss or inconsistent event packet count",
        "packet sequence gap",
        "recorder reports event loss or capture failure",
        "recorder header reports incomplete capture",
        "recorder failed to send",
        "recorder lost this call's Entry record",
        "missing or inconsistent object count",
        "Entry without arguments",
        "Exit without a result",
        "status ABORTED_ON_LOSS",
        "status missing",
    ]
    .iter()
    .any(|pattern| issue.contains(pattern))
}

pub fn check(
    group: &Group,
    run: &GroupRun,
    accepted: &crate::matrix::AcceptedGaps,
) -> Result<StressReport, String> {
    let directory = run.run.directory.clone();
    let scan = recording::scan_raw(&directory)?;
    let mut problems = trace::run_problems(group, run, &scan);
    let mut calls = 0u64;
    let mut calls_with_loss = 0u64;
    let mut loss_issues = BTreeMap::new();
    let mut other_issues = BTreeMap::new();
    let page_issues = recording::for_each_invocation(&directory, |call| {
        calls += 1;
        let issues = trace::unlabeled_issues(call);
        // In a call that lost packets every other mark follows from it (an
        // exit with no saved entry state records CONTEXT_MISSING).
        let lost = issues.iter().any(|issue| loss_issue(issue));
        calls_with_loss += u64::from(lost);
        for issue in issues {
            let target = if lost {
                &mut loss_issues
            } else {
                &mut other_issues
            };
            *target.entry(issue).or_insert(0u64) += 1;
        }
    })?;
    // A call with more saved observations than a page previews says so; the
    // raw scan accounts for every one of them.
    problems.extend(
        page_issues
            .into_iter()
            .filter(|issue| !issue.starts_with(ASYNC_PARTIAL))
            .map(|issue| format!("trace page: {issue}")),
    );
    let stats = run.recorder_stats.unwrap_or_default();
    let (failed, entered) = (stats[6], stats[3]);
    // Each damaged call lost at least one packet, so the recorder's failed
    // sends bound them; without loss there is nothing to explain.
    if calls_with_loss > failed {
        problems.push(format!(
            "{calls_with_loss} calls show loss, more than the {failed} packets the recorder failed to send"
        ));
    }
    if failed == 0 && calls != entered {
        problems.push(format!(
            "{calls} calls saved, the recorder entered {entered}, and nothing was lost"
        ));
    }
    if failed != 0 && calls > entered {
        problems.push(format!(
            "{calls} calls saved, more than the {entered} entered"
        ));
    }
    // Async requests the recording cannot complete are what the guest counted
    // as observation loss: each one cost at least one counted loss.
    let async_losses = run
        .run
        .execution
        .as_ref()
        .map_or(0, |execution| execution.async_loss_count);
    let incomplete = scan.async_without_final + scan.async_payload_missing;
    if incomplete > async_losses {
        problems.push(format!(
            "{} async requests have no final record and {} lack their payload, more than the {async_losses} observation losses counted",
            scan.async_without_final, scan.async_payload_missing
        ));
    }
    for (issue, count) in &other_issues {
        if accepted.undescribed(issue).is_none() {
            problems.push(format!("warning ×{count}: {issue}"));
        }
    }
    let transcript = oracle::parse(&recording::transcript(&directory)?);
    let scorecard = transcript
        .other
        .iter()
        .find(|line| line.starts_with("== scorecard:"))
        .cloned();
    match &scorecard {
        Some(line) if line.contains(" 0 fail") => {}
        Some(line) => problems.push(format!("workload: {line}")),
        None => problems.push("workload printed no scorecard".into()),
    }
    for line in transcript
        .other
        .iter()
        .filter(|line| line.starts_with("FAIL"))
    {
        problems.push(format!("workload: {line}"));
    }
    let seconds = run.run_seconds.max(0.001);
    let attempted = stats[5].max(1);
    let bytes = std::fs::metadata(directory.join("telemetry.raw"))
        .map(|m| m.len())
        .unwrap_or(0);
    // The wait the group configured; the health's `send_wait_us` is what the
    // guest runs with when the run ends.
    let mut accounting = trace::accounting(run, &scan, calls);
    accounting["transport"]["configured_send_wait_us"] =
        serde_json::json!(if group.plan.transport.lossless {
            u64::from(group.plan.transport.max_wait_ms) * 1000
        } else {
            0
        });
    Ok(StressReport {
        group: group.name.clone(),
        level: group.plan.args.get(1).cloned().unwrap_or_default(),
        run_dir: directory.display().to_string(),
        passed: problems.is_empty(),
        problems,
        calls,
        loss_issues,
        other_issues,
        calls_with_loss,
        scorecard,
        accounting,
        throughput: serde_json::json!({
            "seconds": run.run_seconds,
            "stop_seconds": run.stop_seconds,
            "calls": calls,
            "calls_per_second": calls as f64 / seconds,
            "packets_per_second": scan.packets as f64 / seconds,
            "recorded_mib": bytes as f64 / 1048576.0,
            "mib_per_second": bytes as f64 / 1048576.0 / seconds,
            "packet_loss_percent": 100.0 * stats[6] as f64 / attempted as f64,
            "transport_waits": run.health.transport_waits,
            "transport_wait_ms": run.health.transport_wait_ns as f64 / 1e6,
        }),
    })
}

pub fn summary_line(report: &StressReport) -> String {
    format!(
        "{} group {} (level {}): {} calls in {:.0} s ({:.0} calls/s, {:.1} MiB/s), packet loss {:.3} %, {} calls with loss, async loss {}",
        if report.passed { "PASS" } else { "FAIL" },
        report.group,
        report.level,
        report.calls,
        report.throughput["seconds"].as_f64().unwrap_or(0.0),
        report.throughput["calls_per_second"]
            .as_f64()
            .unwrap_or(0.0),
        report.throughput["mib_per_second"].as_f64().unwrap_or(0.0),
        report.throughput["packet_loss_percent"]
            .as_f64()
            .unwrap_or(0.0),
        report.calls_with_loss,
        report.accounting["async_loss_count"],
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn loss_issues_are_told_from_capture_defects() {
        assert!(super::loss_issue("read: missing Exit"));
        assert!(super::loss_issue("write: packet sequence gap (arg1.data)"));
        assert!(!super::loss_issue(
            "rt_sigaction: field capture incomplete, status COPY_FAULT (arg1.act)"
        ));
    }
}

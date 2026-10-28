// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Part 1: the syscall trace log. Groups `user` (UID 1000), `root` (UID 0) and
//! `threads` run the oracle fixture (tests/monitor/conformance/trace/fixture);
//! `stress-light`, `stress-heavy`, `stress-extreme` and `stress-lossy` run
//! `ant-workload`. Oracle groups are judged call by call; every group must be
//! free of warnings and errors and account for every lost record.
use crate::{
    Context, Group, GroupKind, Outcome, Part, attribution, golden,
    judge::{self, CaseResult, Judge},
    matrix, oracle, recording, render, stress,
    vm::{GroupRun, VmPlan},
};
use antinomie_monitor_core::{InvocationSummary, RunState, TransportSettings, WaitStatus};
use std::collections::BTreeMap;

pub struct TracePart;

const FIXTURE: &str = "/tmp/trace-fixture";
const WORKLOAD: &str = "/tmp/ant-workload";
/// The workload modules that load the syscall trace (network, terminal,
/// detection and crash modules belong to other parts).
const STRESS_MODULES: &str =
    "syscall-load,object-capture,process-tree,file-churn,async-io,decoder-variants,argv-env,timing";

fn oracle_group(context: &Context, name: &str, uid: u32) -> Group {
    Group {
        name: name.into(),
        kind: GroupKind::Oracle,
        plan: VmPlan {
            cpus: 4,
            ram_mib: 2048,
            transport: TransportSettings::default(),
            uploads: vec![(context.bin().join("trace-fixture"), FIXTURE.into())],
            program: FIXTURE.into(),
            args: vec![name.into()],
            uid,
            gid: uid,
            timeout: 300,
        },
    }
}

/// One run of the fixture's io_uring attribution group `name`.
fn attribution_group(context: &Context, name: &str) -> Group {
    Group {
        kind: GroupKind::Attribution,
        ..oracle_group(context, name, 1000)
    }
}

fn stress_group(context: &Context, name: &str, level: &str, transport: TransportSettings) -> Group {
    Group {
        name: name.into(),
        kind: GroupKind::Stress,
        plan: VmPlan {
            cpus: 4,
            ram_mib: 2048,
            transport,
            uploads: vec![(context.bin().join("ant-workload"), WORKLOAD.into())],
            program: WORKLOAD.into(),
            args: vec![
                "--level".into(),
                level.into(),
                "--only".into(),
                STRESS_MODULES.into(),
            ],
            uid: 0,
            gid: 0,
            timeout: 3600,
        },
    }
}

/// What one group's check found, saved as `trace/<group>.json`.
#[derive(serde::Serialize)]
pub struct GroupReport {
    pub group: String,
    pub run_dir: String,
    pub passed: bool,
    pub problems: Vec<String>,
    pub cases: Vec<CaseResult>,
    /// Calls the fixture made without describing them (its own output,
    /// libc start-up), by syscall: how many and what was wrong with them.
    pub unlabeled: BTreeMap<String, u64>,
    pub accounting: serde_json::Value,
    pub throughput: serde_json::Value,
}

/// Problems every group must not have: the run's end, the recorder health
/// and the exact packet accounting.
pub fn run_problems(group: &Group, run: &GroupRun, scan: &recording::RawScan) -> Vec<String> {
    let mut problems = Vec::new();
    let summary = &run.run;
    if summary.state != RunState::Finished {
        problems.push(format!("run state {:?}", summary.state));
    }
    match summary.execution.as_ref().and_then(|e| e.root_exit.clone()) {
        Some(WaitStatus::Exited { code: 0 }) => {}
        other => problems.push(format!("root ended {other:?}")),
    }
    if let Some(error) = &summary.recording_error {
        problems.push(format!("recording error: {error}"));
    }
    for error in &run.errors {
        problems.push(error.clone());
    }
    let health = &run.health;
    // Losses the guest counts are allowed only where load causes them: stress
    // groups may lose async observations and hash records (bounded queues),
    // only the lossy group may drop packets in the transport.
    let stress = group.kind == crate::GroupKind::Stress;
    for (name, value, allowed) in [
        (
            "transport drops",
            health.dropped,
            group.name == "stress-lossy",
        ),
        ("bad commands", health.bad_commands, false),
        ("reply stalls", health.reply_stalls, false),
        ("parser errors", health.parser_errors, false),
        // Events whose END was lost never finish; the live table evicts them
        // (the raw recording keeps every packet).
        (
            "parser evictions",
            health.parser_evicted_count,
            group.name == "stress-lossy",
        ),
        ("storage drops", health.storage_dropped_packets, false),
        ("guest note losses", health.guest_note_lost, stress),
    ] {
        if value != 0 && !allowed {
            problems.push(format!("{name}: {value}"));
        }
    }
    if let Some(error) = &health.persistence_error {
        problems.push(format!("persistence error: {error}"));
    }
    if let Some(error) = &health.recorder_stats_error {
        problems.push(format!("recorder statistics: {error}"));
    }
    if scan.framing_error.is_some() || !scan.parse_errors.is_empty() {
        problems.push(format!(
            "raw recording: framing {:?}, parse errors {:?}",
            scan.framing_error, scan.parse_errors
        ));
    }
    // Every packet the guest sent is saved, or counted as dropped.
    let Some(stats) = run.recorder_stats else {
        problems.push("no recorder statistics".into());
        return problems;
    };
    let (attempted, failed) = (stats[5], stats[6]);
    // Every packet the recorder built either failed (its async staging was
    // full, or the transport dropped it) or reached the host; every packet
    // that reached the host was saved or counted as not saved.
    let delivered = health.attempted.saturating_sub(health.dropped);
    if attempted.checked_sub(failed) != Some(delivered) || health.received_packets != delivered {
        problems.push(format!(
            "the recorder built {attempted} packets and failed {failed}; the transport took {} and dropped {}; the host received {}",
            health.attempted, health.dropped, health.received_packets
        ));
    }
    if health.persisted_packets + health.storage_dropped_packets != health.received_packets
        || scan.packets != health.persisted_packets
    {
        problems.push(format!(
            "{} packets in the recording, {} persisted, {} not saved, {} received",
            scan.packets,
            health.persisted_packets,
            health.storage_dropped_packets,
            health.received_packets
        ));
    }
    if failed != 0 && !stress {
        problems.push(format!("the recorder failed to send {failed} packets"));
    }
    if scan.packets_missing_by_end > failed {
        problems.push(format!(
            "events are missing {} packets their END counted, more than the {failed} the recorder failed to send",
            scan.packets_missing_by_end
        ));
    }
    if failed == 0
        && (scan.packets_missing_by_end != 0
            || scan.events_without_end != 0
            || scan.events_reporting_loss != 0)
    {
        problems.push(format!(
            "no packet was lost, yet {} packets are missing by END, {} events have no END and {} report loss",
            scan.packets_missing_by_end, scan.events_without_end, scan.events_reporting_loss
        ));
    }
    if failed == 0 && scan.events != stats[4] {
        problems.push(format!(
            "{} events saved, the recorder attempted {}",
            scan.events, stats[4]
        ));
    }
    problems
}

pub fn accounting(run: &GroupRun, scan: &recording::RawScan, calls: u64) -> serde_json::Value {
    let stats = run.recorder_stats.unwrap_or_default();
    // Packets the recorder failed that never reached the transport: async
    // records its bounded staging could not hold.
    let staging_failed = stats[6].saturating_sub(run.health.dropped);
    serde_json::json!({
        "lost": {"transport_drops": run.health.dropped, "async_staging": staging_failed,
                 "guest_notes": run.health.guest_note_lost,
                 "async_observations": run.run.execution.as_ref().map(|e| e.async_loss_count),
                 "events_entirely_lost": stats[4].saturating_sub(scan.events)},
        "recorder": {"calls_entered": stats[3], "events_attempted": stats[4],
                     "packets_attempted": stats[5], "packets_failed": stats[6],
                     "copy_faults": stats[7], "schema_gaps": stats[8], "context_failures": stats[9]},
        "transport": {"attempted": run.health.attempted, "dropped": run.health.dropped,
                      "received": run.health.received_packets, "persisted": run.health.persisted_packets,
                      "storage_dropped": run.health.storage_dropped_packets,
                      "waits": run.health.transport_waits, "wait_ns": run.health.transport_wait_ns,
                      "writer_held_ms": run.health.writer_held_ns / 1_000_000,
                      "writer_held_longest_ms": run.health.writer_held_longest_ns / 1_000_000,
                      "send_wait_us": run.health.send_wait_us},
        "read_gaps": run.health.read_gaps,
        "dropped_packets": scan.dropped_packets,
        "async": {"requests": scan.async_requests, "without_final": scan.async_without_final,
                  "payload_missing": scan.async_payload_missing},
        "saved": {"packets": scan.packets, "events": scan.events, "calls": calls,
                  "events_reporting_loss": scan.events_reporting_loss,
                  "packets_missing_by_end": scan.packets_missing_by_end,
                  "events_without_end": scan.events_without_end},
        "async_loss_count": run.run.execution.as_ref().map(|e| e.async_loss_count),
    })
}

/// Issues of a call nobody described: each is a warning the trace shows.
pub fn unlabeled_issues(call: &InvocationSummary) -> Vec<String> {
    let mut issues = Vec::new();
    let name = call
        .entry
        .as_ref()
        .or(call.exit.as_ref())
        .map_or("?", |event| event.syscall_name.as_str());
    if call.entry.is_none() {
        issues.push(format!("{name}: missing Entry"));
    }
    if call.exit.is_none() && call.task_exit.is_none() {
        issues.push(format!("{name}: missing Exit"));
    }
    if call
        .entry
        .as_ref()
        .is_some_and(|entry| entry.args.is_none())
    {
        issues.push(format!("{name}: Entry without arguments"));
    }
    if call.exit.as_ref().is_some_and(|exit| exit.result.is_none()) {
        issues.push(format!("{name}: Exit without a result"));
    }
    if crate::judge::name_mismatch(call) {
        issues.push(format!("{name}: phases name different system calls"));
    }
    for event in call.entry.iter().chain(call.exit.iter()) {
        for issue in &event.issues {
            // Field ids differ between calls; the status is what matters.
            let issue = match issue.split_once(" capture incomplete, status ") {
                Some((_, status)) => format!("field capture incomplete, status {status}"),
                None => issue.clone(),
            };
            let field = event
                .fields
                .iter()
                .find(|field| field.status.is_some_and(|s| s != 0))
                .map_or(String::new(), |field| format!(" ({})", field.key));
            issues.push(format!("{name}: {issue}{field}"));
        }
    }
    issues
}

fn judge_group(
    group: &Group,
    run: &GroupRun,
    accepted: &matrix::AcceptedGaps,
) -> Result<GroupReport, String> {
    let directory = run.run.directory.clone();
    let scan = recording::scan_raw(&directory)?;
    let mut problems = run_problems(group, run, &scan);
    let (calls, page_issues) = recording::invocations(&directory)?;
    problems.extend(
        page_issues
            .into_iter()
            .map(|issue| format!("trace page: {issue}")),
    );
    let text = recording::transcript(&directory)?;
    let transcript = oracle::parse(&text);
    problems.extend(judge::transcript_problems(&transcript));
    let mut judge = Judge::new(&directory, &calls);
    let mut cases: Vec<CaseResult> = transcript
        .expects
        .iter()
        .map(|expect| judge.judge(expect))
        .collect();
    judge::check_write_order(&transcript.expects, &mut cases, &calls);
    for case in &cases {
        for problem in &case.problems {
            problems.push(format!("{}: {problem}", case.label));
        }
    }
    let mut unlabeled = BTreeMap::new();
    for (call, used) in calls.iter().zip(judge.used()) {
        if !used {
            for issue in unlabeled_issues(call) {
                *unlabeled.entry(issue).or_insert(0u64) += 1;
            }
        }
    }
    for (issue, count) in &unlabeled {
        if accepted.undescribed(issue).is_none() {
            problems.push(format!("undescribed call warning ×{count}: {issue}"));
        }
    }
    // The fixture's rings are each mapped by one process, which wrote their
    // entries: the run's async observation is complete and has no note.
    for note in &run.run.notes {
        problems.push(format!("run note: {note}"));
    }
    if run
        .run
        .execution
        .as_ref()
        .is_some_and(|e| e.observation_incomplete())
    {
        problems.push("async observation incomplete (OBSERVATION_INCOMPLETE)".into());
    }
    let execution = run.run.execution.as_ref();
    if execution.is_some_and(|e| e.async_loss_count != 0) {
        problems.push(format!(
            "async observation losses: {}",
            execution.map_or(0, |e| e.async_loss_count)
        ));
    }
    let seconds = run.run_seconds.max(0.001);
    Ok(GroupReport {
        group: group.name.clone(),
        run_dir: directory.display().to_string(),
        passed: problems.is_empty(),
        problems,
        cases,
        unlabeled,
        accounting: accounting(run, &scan, calls.len() as u64),
        throughput: serde_json::json!({
            "seconds": run.run_seconds, "calls": calls.len(),
            "calls_per_second": calls.len() as f64 / seconds,
            "packets_per_second": scan.packets as f64 / seconds,
        }),
    })
}

impl Part for TracePart {
    fn name(&self) -> &'static str {
        "trace"
    }

    fn groups(&self, context: &Context) -> Vec<Group> {
        let lossy = TransportSettings {
            ring_kib: 256,
            lossless: false,
            ..TransportSettings::default()
        };
        // Never drop, with the smallest ring and a short wait: senders find
        // their ring full all the time and compete for the room the host
        // frees. A waiting sender that loses that race for the whole wait
        // drops; with turns and a wait that ends only when the host stops
        // reading, none should.
        let contended = TransportSettings {
            ring_kib: 256,
            lossless: true,
            max_wait_ms: 100,
            ..TransportSettings::default()
        };
        vec![
            oracle_group(context, "user", 1000),
            oracle_group(context, "root", 0),
            oracle_group(context, "threads", 1000),
            attribution_group(context, "ring-private"),
            attribution_group(context, "ring-shared"),
            attribution_group(context, "ring-sqpoll"),
            stress_group(
                context,
                "stress-light",
                "light",
                TransportSettings::default(),
            ),
            stress_group(
                context,
                "stress-heavy",
                "heavy",
                TransportSettings::default(),
            ),
            stress_group(
                context,
                "stress-extreme",
                "extreme",
                TransportSettings::default(),
            ),
            stress_group(context, "stress-lossy", "heavy", lossy),
            stress_group(context, "stress-contended", "heavy", contended),
        ]
    }

    fn check(&self, context: &Context, runs: &[(Group, GroupRun)]) -> Result<Outcome, String> {
        let reports_dir = context.out.join("trace");
        std::fs::create_dir_all(&reports_dir).map_err(|e| e.to_string())?;
        let mut passed = true;
        let mut summary = Vec::new();
        let mut reports = Vec::new();
        let accepted = matrix::AcceptedGaps::load(&context.repo)?;
        for (group, run) in runs {
            let started = std::time::Instant::now();
            eprintln!("conformance: checking {}", group.name);
            match group.kind {
                GroupKind::Oracle => {
                    let report = judge_group(group, run, &accepted)?;
                    std::fs::write(
                        reports_dir.join(format!("{}.json", group.name)),
                        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    passed &= report.passed;
                    summary.push(format!(
                        "{} group {}: {} cases, {} problems, {} calls ({:.0}/s)",
                        if report.passed { "PASS" } else { "FAIL" },
                        group.name,
                        report.cases.len(),
                        report.problems.len(),
                        report.throughput["calls"],
                        report.throughput["calls_per_second"]
                            .as_f64()
                            .unwrap_or(0.0)
                    ));
                    for problem in report.problems.iter().take(400) {
                        summary.push(format!("    {problem}"));
                    }
                    if report.problems.len() > 400 {
                        summary.push(format!(
                            "    … {} more in trace/{}.json",
                            report.problems.len() - 400,
                            group.name
                        ));
                    }
                    reports.push(report);
                }
                GroupKind::Attribution => {
                    let report = attribution::check(group, run, &accepted)?;
                    std::fs::write(
                        reports_dir.join(format!("{}.json", group.name)),
                        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    passed &= report.passed;
                    summary.push(attribution::summary_line(&report));
                    for problem in report.problems.iter().take(100) {
                        summary.push(format!("    {problem}"));
                    }
                }
                GroupKind::Stress => {
                    let report = stress::check(group, run, &accepted)?;
                    std::fs::write(
                        reports_dir.join(format!("{}.json", group.name)),
                        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
                    )
                    .map_err(|e| e.to_string())?;
                    passed &= report.passed;
                    summary.push(stress::summary_line(&report));
                    summary.push(format!(
                        "    checked {} calls in {:.0} s",
                        report.calls,
                        started.elapsed().as_secs_f64()
                    ));
                    for problem in report.problems.iter().take(100) {
                        summary.push(format!("    {problem}"));
                    }
                }
            }
        }
        // The Syscall Trace view's rendering, through the application's code.
        let views = if context.render && !runs.is_empty() {
            match render::render(context, runs) {
                Ok(views) => views,
                Err(error) => {
                    passed = false;
                    summary.push(format!("FAIL render: {error}"));
                    BTreeMap::new()
                }
            }
        } else {
            BTreeMap::new()
        };
        let render_problems = if context.render {
            render::stress_warnings(runs, &views)
        } else {
            Vec::new()
        };
        for problem in &render_problems {
            summary.push(format!("FAIL render: {problem}"));
        }
        passed &= render_problems.is_empty();
        if reports.is_empty() {
            return Ok(Outcome { passed, summary });
        }
        let built = matrix::build(&reports, &views, &accepted, context.render);
        std::fs::write(
            context.out.join("trace-matrix.json"),
            serde_json::to_vec_pretty(&built.json).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        std::fs::write(context.out.join("trace-matrix.txt"), &built.table)
            .map_err(|e| e.to_string())?;
        passed &= built.passed;
        summary.extend(built.summary);
        if context.render {
            let goldens = golden::check(context, &reports, &views)?;
            passed &= goldens.passed;
            summary.extend(goldens.summary);
        }
        Ok(Outcome { passed, summary })
    }
}

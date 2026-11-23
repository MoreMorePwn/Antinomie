// SPDX-License-Identifier: GPL-3.0-only
//! The run side of Start persistence: the hold set with the tree's end, the
//! choice, the notes, and the end of the hold.
use super::*;
use crate::dump_trigger::{DumpTrigger, LiveFinding, LiveJudge, Watch};
use crate::persist_start::{StartPersistence, Written};

struct Quiet;

impl LiveJudge for Quiet {
    fn judge(&mut self, _call: &crate::api::InvocationSummary) -> Vec<LiveFinding> {
        Vec::new()
    }
}

fn run(name: &str, option: Option<StartPersistence>, written: &[(&str, &str)]) -> ProgramRun {
    let directory = std::env::temp_dir().join(format!(
        "ant-persist-run-{name}-{}",
        crate::storage::unique_id()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let summary = RunSummary {
        started_ms: Some(unix_ms().saturating_sub(3_000)),
        clock_anchor: None,
        id: name.into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 2,
        pid: 3,
        request: ExecRequest {
            path: "/tmp/sample".into(),
            uid: 0,
            gid: 0,
            start_persistence: option,
            ..ExecRequest::default()
        },
        directory,
        terminal_eof: true,
        state: RunState::Finished,
        notes: Vec::new(),
        machine: None,
        route: None,
        environment: None,
        reduced: None,
        boot_wait: None,
        triggers: None,
        stopped_by_user: false,
        stop_reason: None,
        stopped_at_ms: None,
        persisted: None,
        persistence_start: None,
        recording_error: None,
        execution: None,
        analysis: None,
    };
    let mut run = ProgramRun::new(summary, 1 << 20).unwrap();
    let mut watch = Watch::with_judge(Box::new(Quiet), &DumpTrigger::default(), &[]);
    watch.dumps = false;
    watch.written = written
        .iter()
        .map(|(rule, path)| Written {
            rule: (*rule).into(),
            path: (*path).into(),
            failed: false,
            pid: 3,
        })
        .collect();
    run.watch = Some(watch);
    run
}

const INSTALLED: &[(&str, &str)] = &[
    ("persistence.cron", "/etc/cron.d/job"),
    ("persistence.rc_init", "/etc/init.d/job"),
];

#[test]
fn with_the_option_on_the_run_is_held_and_the_entries_are_chosen() {
    let mut run = run(
        "on",
        Some(StartPersistence {
            run_limit_s: Some(300),
        }),
        INSTALLED,
    );
    assert!(run.recording_complete());
    run.persistence_tree_ended();
    // Held from the status that ends the tree, before anything is chosen.
    assert!(run.summary.held_open() && run.summary.stoppable());
    assert!(!run.recording_complete());
    run.persistence_decide(true);
    let record = run.summary.persistence_start.clone().unwrap();
    assert!(record.holding);
    let paths: Vec<&str> = record.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["/etc/init.d/job", "/etc/cron.d/job"]);
    assert!(
        record
            .entries
            .iter()
            .all(|e| e.started_by == persist_start::STARTED_BY)
    );
    assert_eq!(run.starting.plan.len(), 2);
    assert!(
        run.summary.notes[0].contains("started by Antinomie (persistence)"),
        "{:?}",
        run.summary.notes
    );
    // Stop ends the hold; nothing was launched, so nothing is to be stopped.
    assert!(run.end_persistence_hold("the run was stopped").is_empty());
    assert!(!run.summary.held_open());
    assert!(run.recording_complete());
    assert!(run.starting.plan.is_empty());
    let record = run.summary.persistence_start.as_ref().unwrap();
    assert_eq!(record.hold_ended.as_deref(), Some("the run was stopped"));
}

#[test]
fn with_the_option_off_the_run_ends_and_says_why() {
    let mut run = run("off", None, INSTALLED);
    run.persistence_tree_ended();
    assert!(!run.summary.held_open());
    assert!(run.recording_complete());
    run.persistence_decide(true);
    let record = run.summary.persistence_start.as_ref().unwrap();
    assert!(record.entries.is_empty() && !record.holding);
    assert_eq!(
        record.not_started.as_deref(),
        Some("the tree ended after 3 s; persistence installed but not started (option off)")
    );
    assert_eq!(
        run.summary.notes,
        ["The tree ended after 3 s; persistence installed but not started (option off)."]
    );
}

#[test]
fn a_run_that_persisted_nothing_keeps_no_record() {
    let mut run = run("none", Some(StartPersistence::default()), &[]);
    run.persistence_tree_ended();
    assert!(run.summary.held_open());
    run.persistence_decide(true);
    assert_eq!(run.summary.persistence_start, None);
    assert!(!run.summary.held_open());
    assert!(run.summary.notes.is_empty());
}

#[test]
fn a_run_that_ended_close_to_its_run_time_starts_nothing() {
    let mut run = run(
        "late",
        Some(StartPersistence {
            run_limit_s: Some(20),
        }),
        INSTALLED,
    );
    run.persistence_tree_ended();
    run.persistence_decide(true);
    let record = run.summary.persistence_start.as_ref().unwrap();
    assert!(!record.holding && record.entries.is_empty());
    assert!(
        record
            .not_started
            .as_deref()
            .unwrap()
            .contains("less than 30 s")
    );
}

#[test]
fn a_vm_that_stops_before_the_choice_still_says_what_was_installed() {
    let mut run = run("stopped", Some(StartPersistence::default()), INSTALLED);
    run.persistence_tree_ended();
    run.begin_finalize(1 << 20);
    let record = run.summary.persistence_start.as_ref().unwrap();
    assert!(!record.holding && record.entries.is_empty());
    assert!(
        record
            .not_started
            .as_deref()
            .unwrap()
            .contains("recording ended before")
    );
    assert!(!run.summary.held_open());
}

// SPDX-License-Identifier: GPL-3.0-only
//! The pool's order without threads: first come, first served by job arrival,
//! the worker limit, dependencies, the memory wait and cancels. The pool with
//! its workers on a real recording is in `stages::pool_tests`.
use super::state::{Concluded, JobPhase, PoolJob, PoolState, PoolStop, Task};
use crate::{
    api::{
        failure::{Failure, FailureCode},
        ids::JobId,
        job::{HostItemState, Job, Outcome, Stage},
    },
    stages::{
        items::{ItemKind, JobWork, PhaseEnd, host_item, items_for},
        plan::HostPlan,
        timing::{Inputs, Timing},
    },
};
use antinomie_monitor_core::analysis::{AnalysisKind, detection::Engine as DetectionEngine};
use std::sync::{Arc, Mutex};

pub(super) fn plan(statics: &[AnalysisKind], engines: bool) -> HostPlan {
    HostPlan {
        static_checks: statics.to_vec(),
        static_limit_min: None,
        required_checks: Vec::new(),
        triage: true,
        engines: if engines {
            vec![DetectionEngine::Yara]
        } else {
            Vec::new()
        },
        formats: vec![crate::api::spec::ReportFormat::Json],
        bundle: false,
        defang: true,
        required: Vec::new(),
        retry_analysis: false,
        max_attempts: 1,
    }
}

pub(super) fn job(n: u8, created_ms: u64) -> Job {
    let id = JobId::from_parts(1_794_000_000_000 + u64::from(n), [n; 10]);
    serde_json::from_value(serde_json::json!({
        "api_version": 1, "id": id, "state": "running", "created_ms": created_ms,
        "attempt": 1, "max_attempts": 1, "client_id": "local:1000",
        "spec": {"sample": {"sha256": "ab".repeat(32)}},
        "policy": {"name": "default", "digest": "d"},
        "artifacts": [], "warnings": [], "labels": {},
    }))
    .unwrap()
}

fn pool_job(job: Job, plan: HostPlan, deadline_ms: u64) -> PoolJob {
    let items = items_for(&plan);
    let timing = Timing::default();
    let inputs = Inputs {
        sample_bytes: Some(1 << 20),
        recording_bytes: Some(1 << 20),
        load: 1.0,
    };
    let views = items
        .iter()
        .map(|spec| host_item(spec, &items, &timing.of(&spec.kind, &plan, &inputs)))
        .collect();
    PoolJob {
        job,
        items,
        views,
        work: Arc::new(Mutex::new(JobWork::new(plan, Outcome::Succeeded))),
        deadline_ms,
        phase: JobPhase::Analyse,
        begun: false,
        busy: false,
        running: 0,
        stop: None,
    }
}

fn add(state: &mut PoolState, job: Job, plan: HostPlan) -> JobId {
    let id = job.id.clone();
    state
        .jobs
        .insert(PoolState::key(&job), pool_job(job, plan, u64::MAX));
    id
}

fn no_deadline(_: &Job) -> Failure {
    Failure::new(FailureCode::Internal, Stage::Analyse, "late", None)
}

fn next(state: &mut PoolState) -> Option<Task> {
    state.next(1_000, &mut || None, &no_deadline)
}

fn item(task: &Option<Task>) -> (JobId, String) {
    match task {
        Some(Task::Item { job, kind, .. }) => (job.clone(), kind.name()),
        other => panic!("not an item: {other:?}"),
    }
}

fn done(state: &mut PoolState, task: &Option<Task>) {
    if let Some(Task::Item { job, index, .. }) = task {
        state.item_ended(job, *index, 2_000, Ok((HostItemState::Done, None)));
    }
}

#[test]
fn the_items_follow_their_dependencies_and_regex_goes_with_strings() {
    let items = items_for(&plan(
        &[
            AnalysisKind::Strings,
            AnalysisKind::Regex,
            AnalysisKind::Floss,
        ],
        true,
    ));
    let names: Vec<String> = items.iter().map(|i| i.kind.name()).collect();
    assert_eq!(
        names,
        [
            "triage",
            "static:strings+regex",
            "static:floss",
            "detection",
            "assess",
            "report"
        ]
    );
    assert_eq!(items[3].after, [0]);
    assert_eq!(items[4].after, [0, 3]);
    assert_eq!(items[5].after, [0, 1, 2, 3, 4]);
    // Nothing to analyse: only the label and the report.
    let mut empty = plan(&[], false);
    empty.triage = false;
    let names: Vec<String> = items_for(&empty).iter().map(|i| i.kind.name()).collect();
    assert_eq!(names, ["assess", "report"]);
}

#[test]
fn an_older_job_starts_every_item_before_a_newer_job_starts_any() {
    let mut state = PoolState::new(2);
    // Submitted later, collected first: arrival is the submit time.
    let newer = add(
        &mut state,
        job(2, 200),
        plan(&[AnalysisKind::Strings], false),
    );
    let older = add(
        &mut state,
        job(1, 100),
        plan(&[AnalysisKind::Metadata], false),
    );
    let first = next(&mut state);
    let second = next(&mut state);
    assert_eq!(item(&first), (older.clone(), "triage".into()));
    assert_eq!(item(&second), (older.clone(), "static:metadata".into()));
    // Two items run: the pool is full.
    assert!(next(&mut state).is_none());
    done(&mut state, &first);
    // The older job's `assess` waits for `triage` only: it starts, not the
    // newer job's items.
    let third = next(&mut state);
    assert_eq!(item(&third), (older.clone(), "assess".into()));
    done(&mut state, &second);
    // The older job's report waits for the end of analyse: the head waits,
    // and no item of the newer job goes ahead of it.
    assert!(next(&mut state).is_none());
    done(&mut state, &third);
    assert!(matches!(next(&mut state), Some(Task::EndAnalyse(id)) if id == older));
    state.analyse_ended(&older, Ok(PhaseEnd::Next));
    let report = next(&mut state);
    assert_eq!(item(&report), (older.clone(), "report".into()));
    // Every item of the older job has started: the newer job's turn.
    let fifth = next(&mut state);
    assert_eq!(item(&fifth), (newer.clone(), "triage".into()));
    done(&mut state, &report);
    assert!(matches!(next(&mut state), Some(Task::Conclude(id)) if id == older));
    assert!(state.concluded(&older, Concluded::Done).is_some());
    assert_eq!(state.jobs.len(), 1);
}

#[test]
fn at_most_the_pool_size_runs_and_the_count_is_shown() {
    let mut state = PoolState::new(1);
    add(
        &mut state,
        job(1, 100),
        plan(&[AnalysisKind::Metadata, AnalysisKind::Strings], false),
    );
    let first = next(&mut state);
    assert!(first.is_some());
    assert!(next(&mut state).is_none(), "one worker, one item");
    let (queued, running) = state.counts();
    assert_eq!((queued, running), (4, 1));
    done(&mut state, &first);
    assert!(next(&mut state).is_some());
}

#[test]
fn the_head_waits_for_memory_and_nothing_jumps_it() {
    let mut state = PoolState::new(2);
    let older = add(&mut state, job(1, 100), plan(&[AnalysisKind::Floss], false));
    add(
        &mut state,
        job(2, 200),
        plan(&[AnalysisKind::Metadata], false),
    );
    let mut short = || Some("memory: 1000 MiB are available, an item needs 2048 MiB".to_owned());
    assert!(state.next(1_000, &mut short, &no_deadline).is_none());
    assert!(state.waiting_for.as_deref().unwrap().contains("1000 MiB"));
    // Still short: nothing of the newer job starts either.
    assert!(state.next(1_500, &mut short, &no_deadline).is_none());
    // Room again: the head starts, the same item as before.
    let task = next(&mut state);
    assert_eq!(item(&task), (older, "triage".into()));
    assert!(state.waiting_for.is_none());
}

#[test]
fn a_cancelled_job_skips_its_queued_items_and_settles_once_nothing_runs() {
    let mut state = PoolState::new(2);
    let id = add(&mut state, job(1, 100), plan(&[AnalysisKind::Floss], false));
    let first = next(&mut state);
    state.get_mut(&id).unwrap().stop = Some(PoolStop::Cancelled);
    // The running item has not ended: no settle yet, and nothing starts.
    assert!(next(&mut state).is_none());
    let pooled = state.get(&id).unwrap();
    assert!(
        pooled
            .views
            .iter()
            .skip(1)
            .all(|v| v.state == HostItemState::Skipped)
    );
    if let Some(Task::Item { index, .. }) = &first {
        state.item_ended(&id, *index, 2_000, Err(PoolStop::Cancelled));
    }
    assert!(matches!(
        next(&mut state),
        Some(Task::Settle(job, PoolStop::Cancelled)) if job == id
    ));
}

#[test]
fn a_job_past_its_deadline_is_stopped() {
    let mut state = PoolState::new(2);
    let job = job(1, 100);
    let id = job.id.clone();
    state
        .jobs
        .insert(PoolState::key(&job), pool_job(job, plan(&[], false), 5_000));
    assert!(matches!(
        state.next(6_000, &mut || None, &no_deadline),
        Some(Task::Settle(job, PoolStop::Failed(_))) if job == id
    ));
}

#[test]
fn a_retry_queues_the_items_again_in_place() {
    let mut state = PoolState::new(2);
    let id = add(&mut state, job(1, 100), plan(&[], false));
    let triage = next(&mut state);
    done(&mut state, &triage);
    let assess = next(&mut state);
    done(&mut state, &assess);
    assert!(matches!(next(&mut state), Some(Task::EndAnalyse(_))));
    state.analyse_ended(&id, Ok(PhaseEnd::Again));
    assert_eq!(item(&next(&mut state)), (id, "triage".into()));
}

#[test]
fn the_limit_is_twice_the_estimate_and_a_policy_limit_overrides_it() {
    let timing = Timing::default();
    let inputs = Inputs {
        sample_bytes: Some(2 << 20),
        recording_bytes: Some(10 << 20),
        load: 1.0,
    };
    let plain = plan(&[AnalysisKind::Floss], true);
    let floss = ItemKind::Static(vec![AnalysisKind::Floss]);
    let time = timing.of(&floss, &plain, &inputs);
    assert_eq!(time.basis, "estimate");
    assert_eq!(time.expected_s, 150, "90 s and 30 s a MiB");
    assert_eq!(time.limit_s, 300);
    let triage = timing.of(&ItemKind::Triage, &plain, &inputs);
    assert_eq!((triage.expected_s, triage.limit_s), (120, 240));
    // A loaded host stretches the estimate.
    let loaded = timing.of(
        &floss,
        &plain,
        &Inputs {
            load: 2.0,
            ..inputs
        },
    );
    assert_eq!(loaded.limit_s, 600);
    // No size known: the fixed limit of 4.1 is the expected time.
    let unknown = timing.of(&ItemKind::Report, &plain, &Inputs::default());
    assert_eq!(
        (unknown.basis, unknown.expected_s, unknown.limit_s),
        ("fixed", 300, 600)
    );
    // The factor is the operator's.
    let three = Timing {
        factor: 3.0,
        ..Timing::default()
    };
    assert_eq!(three.of(&floss, &plain, &inputs).limit_s, 450);
    // A policy's fixed minutes win: tools x minutes x 60 + 60.
    let mut fixed = plain.clone();
    fixed.static_limit_min = Some(4);
    let time = timing.of(&floss, &fixed, &inputs);
    assert_eq!((time.basis, time.limit_s), ("policy", 300));
}

#[test]
fn a_recent_median_on_this_host_replaces_the_estimate() {
    let dir = std::env::temp_dir().join(format!(
        "ant-pool-median-{}",
        crate::clock::random_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("host-times.json");
    let timing = Timing {
        factor: 2.0,
        medians: crate::stages::timing::Medians::load(&file),
    };
    let plain = plan(&[AnalysisKind::Floss], false);
    let floss = ItemKind::Static(vec![AnalysisKind::Floss]);
    let inputs = Inputs {
        sample_bytes: Some(1 << 20),
        recording_bytes: None,
        load: 1.0,
    };
    timing.medians.record("static:floss", 40);
    timing.medians.record("static:floss", 400);
    assert_eq!(
        timing.of(&floss, &plain, &inputs).basis,
        "estimate",
        "two runs are not enough"
    );
    timing.medians.record("static:floss", 50);
    let time = timing.of(&floss, &plain, &inputs);
    assert_eq!(
        (time.basis, time.expected_s, time.limit_s),
        ("median", 50, 100)
    );
    // The history is kept for the next start.
    let again = crate::stages::timing::Medians::load(&file);
    assert_eq!(again.median("static:floss"), Some(50));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_job_behind_a_long_queue_gets_the_time_of_the_work_ahead_too() {
    let mut state = PoolState::new(1);
    add(&mut state, job(1, 100), plan(&[AnalysisKind::Floss], true));
    let older: u64 = state.jobs.values().map(|j| j.remaining_s()).sum();
    assert!(older > 0);
    let newer = job(2, 200);
    let ahead = state.ahead_s(&PoolState::key(&newer));
    assert_eq!(ahead, older, "every item of the older job is ahead");
    // 2 x (ahead + own): the newer job's deadline covers the queue.
    assert_eq!(PoolState::budget_ms(ahead, 30, 2.0), (ahead + 30) * 2000);
    assert_eq!(
        PoolState::budget_ms(0, 30, 0.5),
        30_000,
        "the factor is at least 1"
    );
    // Nothing is ahead of the oldest job.
    assert_eq!(state.ahead_s(&(0, job(3, 0).id)), 0);
}

/// BH-07 (bug hunt 0.9.0): the job's host-stage deadline is the factor times
/// the expected times, with no floor, while each item may take at least
/// `MIN_LIMIT` (30 s). Once the medians are small (three quick jobs), a job
/// is failed by its deadline while its running item is well inside its own
/// limit.
#[test]
fn bh_07_a_job_is_not_failed_by_its_deadline_while_an_item_is_within_its_limit() {
    let plan = plan(&[AnalysisKind::Metadata], false);
    let items = items_for(&plan);
    let timing = Timing::default();
    // Three earlier jobs on this host: every item took one second.
    for spec in &items {
        for _ in 0..3 {
            timing.medians.record(&spec.kind.name(), 1);
        }
    }
    let inputs = Inputs {
        sample_bytes: Some(1 << 20),
        recording_bytes: Some(512 << 20),
        load: 1.0,
    };
    let views: Vec<_> = items
        .iter()
        .map(|spec| host_item(spec, &items, &timing.of(&spec.kind, &plan, &inputs)))
        .collect();
    let own: u64 = views.iter().map(|v| v.expected_s).sum();
    let budget = PoolState::budget_ms(0, own, timing.factor);
    let job = job(1, 1);
    let id = job.id.clone();
    let key = PoolState::key(&job);
    let mut pooled = pool_job(job, plan, budget);
    pooled.views = views;
    let mut state = PoolState::new(2);
    state.jobs.insert(key, pooled);
    // The first item (Triage) starts at 0 ms ...
    let first = state.next(0, &mut || None, &no_deadline);
    let (_, name) = item(&first);
    let Some(Task::Item { limit, .. }) = first else {
        unreachable!()
    };
    // ... and is still running 20 s later, inside its own limit.
    let at_ms = 20_000;
    assert!(std::time::Duration::from_millis(at_ms) < limit);
    let _ = state.next(at_ms, &mut || None, &no_deadline);
    assert!(
        state.get(&id).unwrap().stop.is_none(),
        "the job was failed by its {budget} ms deadline while {name} was {at_ms} ms into its {limit:?} limit"
    );
}

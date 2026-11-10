// SPDX-License-Identifier: GPL-3.0-only
//! The digest a finished run builds by itself (ANT-T0400): which runs need one,
//! the budget a heavy recording is read within, the partial marks, and the
//! queue that builds one at a time.
use super::*;
use crate::digest_job::{self as job, Budget, Built, Status};
use crate::report_export::fixtures::test_run;
use crate::scan_progress::ScanProgress;
use crate::tests::write_rwx_calls;
use antinomie_monitor_core::{run_digest::RunDigest, BackendOptions, RunState, RunSummary};
use std::time::Duration;

fn cancel() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// A finished run whose recording holds `calls` RWX mapping calls of the root.
fn run_with(calls: u64, manifest: Option<serde_json::Value>) -> (PacketSpool, RunSummary) {
    let temp = PacketSpool::new().unwrap();
    let mut raw = std::io::BufWriter::new(
        std::fs::File::create(temp.directory.join("telemetry.raw")).unwrap(),
    );
    write_rwx_calls(&mut raw, 0..calls);
    std::io::Write::flush(&mut raw).unwrap();
    drop(raw);
    if let Some(manifest) = manifest {
        std::fs::write(
            temp.directory.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }
    let mut run = test_run("run-1", "/tmp/sample");
    run.root_task_cookie = 55;
    run.state = RunState::Finished;
    run.directory = temp.directory.clone();
    (temp, run)
}

fn manifest(health: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "run": {"id": "run-1", "vm_id": "chosen", "boot_id": "boot"},
        "started_ms": 1_792_000_000_000u64,
        "health": health,
    })
}

fn saved(run: &RunSummary) -> SavedRun {
    SavedRun::new(run.clone(), TriageSettings::default())
}

fn build(run: &RunSummary, budget: Budget) -> Built {
    job::build(&saved(run), budget, &cancel(), &Arc::default()).unwrap()
}

#[test]
fn a_finished_run_with_no_digest_gets_one_and_is_then_left_alone() {
    let (_temp, run) = run_with(
        3,
        Some(manifest(
            serde_json::json!({"dropped": 0, "storage_dropped_packets": 0}),
        )),
    );
    assert!(job::needs(&run));
    assert_eq!(job::pending([run.clone()]).len(), 1);
    let first = build(&run, Budget::default());
    assert!(
        matches!(first, Built::Whole | Built::Partial(_)),
        "{first:?}"
    );
    let digest = RunDigest::read(&run.directory).expect("the digest was written");
    assert!(digest.behaviour.is_some() && digest.lineage.is_some());
    let coverage = digest
        .coverage
        .expect("the digest says what it was built from");
    assert_eq!(coverage.calls_read, 3);
    assert!(!coverage.budget_reached);
    // Idempotent: nothing is built twice.
    assert!(!job::needs(&run));
    assert_eq!(build(&run, Budget::default()), Built::Current);
}

#[test]
fn a_live_run_a_run_that_never_started_and_a_failed_launch_need_none() {
    let (_temp, mut run) = run_with(2, None);
    run.state = RunState::Running;
    assert!(!job::needs(&run));
    run.state = RunState::Finished;
    run.root_task_cookie = 0;
    assert!(!job::needs(&run));
    run.root_task_cookie = 55;
    RunDigest::update(&run.directory, |digest| {
        *digest = RunDigest::for_failed_launch("no such file");
    })
    .unwrap();
    assert!(!job::needs(&run));
}

#[test]
fn a_digest_the_window_wrote_before_this_build_is_whole_and_not_made_again() {
    let (_temp, run) = run_with(2, None);
    RunDigest::update(&run.directory, |digest| {
        digest.behaviour = Some(Default::default());
    })
    .unwrap();
    assert!(!job::needs(&run));
}

#[test]
fn a_large_recording_is_read_to_a_budget_and_the_digest_is_partial() {
    // Generated here: 30,000 calls, 4 packets each (about 25 MB).
    let (_temp, run) = run_with(
        30_000,
        Some(manifest(
            serde_json::json!({"dropped": 0, "storage_dropped_packets": 0}),
        )),
    );
    let progress = Arc::new(ScanProgress::default());
    let budget = Budget {
        calls: 1_000,
        time: Duration::from_secs(600),
    };
    let built = job::build(&saved(&run), budget, &cancel(), &progress).unwrap();
    let Built::Partial(reasons) = built else {
        panic!("{built:?}");
    };
    assert!(reasons[0].contains("first 1,000 calls"), "{reasons:?}");
    let coverage = RunDigest::read(&run.directory).unwrap().coverage.unwrap();
    assert!(coverage.partial && coverage.budget_reached);
    // Pages of 256 calls: it stops at the first page past the budget.
    assert!(
        (1_000..1_000 + 256).contains(&coverage.calls_read),
        "{}",
        coverage.calls_read
    );
    assert!(!coverage.revisit, "a budget does not change by waiting");
    // The budget does not make the digest empty: what it read is in it.
    let digest = RunDigest::read(&run.directory).unwrap();
    assert!(!digest.behaviour.unwrap().rules.is_empty());
    // A partial digest is not rebuilt by itself.
    assert!(!job::needs(&run));
}

#[test]
fn a_spent_time_budget_ends_the_read_and_says_so() {
    let (_temp, run) = run_with(
        2_000,
        Some(manifest(
            serde_json::json!({"dropped": 0, "storage_dropped_packets": 0}),
        )),
    );
    let budget = Budget {
        calls: u64::MAX,
        time: Duration::ZERO,
    };
    let built = build(&run, budget);
    let Built::Partial(reasons) = built else {
        panic!("{built:?}");
    };
    assert!(reasons[0].contains("time budget"), "{reasons:?}");
    let coverage = RunDigest::read(&run.directory).unwrap().coverage.unwrap();
    assert!(coverage.budget_reached && coverage.calls_read < 2_000);
}

#[test]
fn a_run_that_lost_telemetry_gets_a_partial_digest_with_the_loss_named() {
    let (_temp, run) = run_with(
        50,
        Some(manifest(
            serde_json::json!({"dropped": 1_180_000u64, "storage_dropped_packets": 0}),
        )),
    );
    let Built::Partial(reasons) = build(&run, Budget::default()) else {
        panic!("a lossy run is partial");
    };
    assert!(
        reasons.iter().any(|r| r.contains("1180000 dropped")),
        "{reasons:?}"
    );
    let digest = RunDigest::read(&run.directory).unwrap();
    let coverage = digest.coverage.unwrap();
    assert!(coverage.partial && !coverage.budget_reached && !coverage.revisit);
    assert!(
        digest.behaviour.is_some(),
        "the digest still holds what was seen"
    );
    assert!(!job::needs(&run));
}

#[test]
fn a_recording_still_being_written_is_built_again_once_it_changes() {
    let (_temp, run) = run_with(
        5,
        Some(manifest(
            serde_json::json!({"dropped": 0, "storage_dropped_packets": 0}),
        )),
    );
    // Its capture was still open when the digest was made.
    RunDigest::update(&run.directory, |digest| {
        digest.behaviour = Some(Default::default());
        digest.coverage = Some(antinomie_monitor_core::run_digest::Coverage {
            partial: true,
            reasons: vec!["the network capture was still open".into()],
            revisit: true,
            source: antinomie_monitor_core::run_digest::source_stamp(&run.directory),
            ..Default::default()
        });
    })
    .unwrap();
    assert!(!job::needs(&run));
    let mut raw = std::fs::OpenOptions::new()
        .append(true)
        .open(run.directory.join("telemetry.raw"))
        .unwrap();
    write_rwx_calls(&mut raw, 5..8);
    drop(raw);
    assert!(job::needs(&run));
}

#[test]
fn a_recording_that_cannot_be_read_is_marked_and_not_retried() {
    let (_temp, run) = run_with(
        3,
        Some(serde_json::json!({"run": {"id": "another", "vm_id": "chosen", "boot_id": "boot"}})),
    );
    let Built::Failed(reason) = build(&run, Budget::default()) else {
        panic!("a manifest of another run cannot be read");
    };
    assert!(reason.contains("could not be read"), "{reason}");
    assert!(!job::needs(&run));
}

#[test]
fn a_cancelled_build_writes_nothing_and_is_made_again() {
    let (_temp, run) = run_with(500, None);
    let stop = Arc::new(AtomicBool::new(true));
    let result = job::build(&saved(&run), Budget::default(), &stop, &Arc::default());
    assert_eq!(result, Err("cancelled".to_owned()));
    assert!(RunDigest::read(&run.directory).is_none());
    assert!(job::needs(&run));
}

#[test]
fn two_builds_of_one_run_never_run_together() {
    let (_temp, run) = run_with(10, None);
    let _held = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(run.directory.join(".triage-digest.lock"))
        .unwrap();
    rustix::fs::flock(&_held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    assert_eq!(build(&run, Budget::default()), Built::Busy);
    assert!(RunDigest::read(&run.directory).is_none());
}

fn leaked() -> &'static job::Queue {
    Box::leak(Box::default())
}

fn job_of(run: &RunSummary) -> job::Job {
    job::Job {
        run: run.clone(),
        options: BackendOptions {
            data_dir: std::env::temp_dir().join("antinomie-digest-job-no-settings"),
            ..BackendOptions::default()
        },
        budget: Budget::default(),
    }
}

#[test]
fn the_queue_builds_one_at_a_time_the_smallest_first_and_shows_progress() {
    let queue = leaked();
    let (_a, big) = run_with(4_000, None);
    let (_b, small) = run_with(10, None);
    assert_eq!(queue.status(&big.directory), Status::Idle);
    assert!(queue.submit(job_of(&big)));
    assert!(!queue.submit(job_of(&big)), "one build per run");
    assert!(queue.submit(job_of(&small)));
    assert_ne!(queue.status(&small.directory), Status::Idle);
    assert!(queue.wait_idle(Duration::from_secs(120)));
    for run in [&big, &small] {
        assert_eq!(queue.status(&run.directory), Status::Idle);
        assert!(RunDigest::read(&run.directory).is_some());
    }
    // Nothing left to do for either.
    assert!(job::pending([big, small]).is_empty());
}

#[test]
fn a_blocking_build_answers_with_the_result_and_release_drops_a_waiting_one() {
    let queue = leaked();
    let (_a, run) = run_with(20, None);
    let built = queue.build_blocking(job_of(&run), &cancel()).unwrap();
    assert!(matches!(built, Built::Whole | Built::Partial(_)));
    let (_b, other) = run_with(20, None);
    // Hold the worker with a build that cannot start (its run is locked).
    let _held = std::fs::File::create(other.directory.join(".triage-digest.lock")).unwrap();
    rustix::fs::flock(&_held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let (_c, third) = run_with(20, None);
    queue.submit(job_of(&other));
    queue.submit(job_of(&third));
    queue.release(&third.directory);
    assert!(queue.wait_idle(Duration::from_secs(60)));
    assert!(
        RunDigest::read(&third.directory).is_none()
            || queue.status(&third.directory) == Status::Idle
    );
}

/// The measurement of the card: `ANT_DIGEST_MEASURE_DIR=<dir> ANT_DIGEST_MEASURE_CALLS=1000000
/// [ANT_DIGEST_MEASURE_BUDGET=<calls>] cargo test --release -p antinomie-triage
/// --features test-support -- --ignored measure_the_digest_build`, under `/usr/bin/time -v`
/// for the peak RSS. Reuses the recording in the directory when it is there.
#[test]
#[ignore = "a measurement: it writes a recording of ~860 bytes a call"]
fn measure_the_digest_build() {
    let Ok(dir) = std::env::var("ANT_DIGEST_MEASURE_DIR") else {
        return;
    };
    let number = |name: &str, default: u64| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default)
    };
    let calls = number("ANT_DIGEST_MEASURE_CALLS", 1_000_000);
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let raw = dir.join("telemetry.raw");
    if !raw.is_file() {
        let started = std::time::Instant::now();
        let mut file = std::io::BufWriter::new(std::fs::File::create(&raw).unwrap());
        write_rwx_calls(&mut file, 0..calls);
        std::io::Write::flush(&mut file).unwrap();
        eprintln!("wrote {calls} calls in {:?}", started.elapsed());
    }
    let _ = std::fs::remove_file(dir.join("triage-digest.json"));
    let mut run = test_run("run-1", "/tmp/sample");
    run.root_task_cookie = 55;
    run.state = RunState::Finished;
    run.directory = dir.clone();
    let budget = Budget {
        calls: number("ANT_DIGEST_MEASURE_BUDGET", job::MAX_CALLS),
        time: job::MAX_TIME,
    };
    let progress = Arc::new(ScanProgress::default());
    let started = std::time::Instant::now();
    let built = job::build(&saved(&run), budget, &cancel(), &progress).unwrap();
    let coverage = RunDigest::read(&dir).unwrap().coverage.unwrap();
    eprintln!(
        "MEASURE budget={} built={:?} calls_read={} elapsed={:?} digest_bytes={}",
        budget.calls,
        built,
        coverage.calls_read,
        started.elapsed(),
        std::fs::metadata(dir.join("triage-digest.json"))
            .unwrap()
            .len()
    );
}

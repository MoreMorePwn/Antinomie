// SPDX-License-Identifier: GPL-3.0-only
//! ANT-T0471: a sandboxed host tool that is stopped (its time limit, a cancel)
//! gets SIGTERM, the grace to end, then SIGKILL. These need bubblewrap and
//! usable user namespaces, like the other sandbox tests.
use super::sandbox_run::{Bounds, run_bounded};
use super::*;

fn test_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ant-stop-{name}-{}", storage::unique_id()));
    storage::private_dir(&dir).unwrap();
    dir
}

fn shell(dir: &Path, script: &str, grace: Duration) -> (Result<(), String>, Duration) {
    let started = Instant::now();
    let result = run_bounded(
        Path::new("/usr/bin/sh"),
        &["-c".into(), script.into()],
        dir,
        &Mounts::default(),
        &[],
        &AtomicBool::new(false),
        Bounds {
            timeout: Duration::from_secs(1),
            address_space_size: 8 * 1024 * 1024 * 1024,
            grace,
        },
    );
    (result, started.elapsed())
}

fn log_text(dir: &Path) -> String {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|s| s == "log"))
        .map(|p| String::from_utf8_lossy(&fs::read(p).unwrap()).into_owned())
        .collect()
}

/// The tool past its limit gets SIGTERM and the grace it needs: its handler
/// takes a second, and it is not killed before it is done.
#[test]
#[ignore = "requires installed bubblewrap/prlimit and usable user namespaces"]
fn t0471_a_stopped_tool_gets_sigterm_and_the_grace_to_end() {
    let dir = test_dir("graceful");
    let marker = dir.join("stopped");
    let script = format!(
        "trap 'sleep 1; echo done > {}; exit 0' TERM; while :; do sleep 0.1; done",
        marker.display()
    );
    let (result, took) = shell(&dir, &script, Duration::from_secs(20));
    let error = result.unwrap_err();
    assert!(error.contains("timed out"), "{error}");
    assert!(
        marker.is_file(),
        "the SIGTERM handler did not finish: {error}"
    );
    // It ended on its own, long before the grace ran out.
    assert!(took < Duration::from_secs(15), "{took:?}");
    assert!(log_text(&dir).contains("it ended within the grace"));
    fs::remove_dir_all(&dir).unwrap();
}

/// Without a grace (the desktop app) the stop is immediate, as before: the
/// handler never gets its second.
#[test]
#[ignore = "requires installed bubblewrap/prlimit and usable user namespaces"]
fn t0471_without_a_grace_the_stop_is_immediate() {
    let dir = test_dir("immediate");
    let marker = dir.join("stopped");
    let script = format!(
        "trap 'sleep 1; echo done > {}; exit 0' TERM; while :; do sleep 0.1; done",
        marker.display()
    );
    let (result, _) = shell(&dir, &script, Duration::ZERO);
    assert!(result.unwrap_err().contains("timed out"));
    std::thread::sleep(Duration::from_millis(1500));
    assert!(!marker.exists());
    fs::remove_dir_all(&dir).unwrap();
}

/// A tool that ignores SIGTERM is killed once the grace has passed, and not
/// before.
#[test]
#[ignore = "requires installed bubblewrap/prlimit and usable user namespaces"]
fn t0471_sigkill_follows_when_sigterm_is_ignored() {
    let dir = test_dir("ignored");
    let grace = Duration::from_secs(3);
    let (result, took) = shell(&dir, "trap '' TERM; sleep 60", grace);
    let error = result.unwrap_err();
    // Timed out (not a cleanup failure): the cleanup killed and reaped it.
    assert!(
        error.contains("timed out") && !error.contains("cleanup failed"),
        "{error}"
    );
    assert!(took >= Duration::from_secs(1) + grace, "{took:?}");
    assert!(took < Duration::from_secs(30), "{took:?}");
    assert!(log_text(&dir).contains("SIGKILL follows"));
    fs::remove_dir_all(&dir).unwrap();
}

/// The static-analysis worker past its deadline: SIGTERM, the grace, SIGKILL;
/// the analysis ends `partial` with what it had finished.
fn worker_job(dir: &Path, script: &str) -> Job {
    let worker = dir.join("worker-fixture");
    fs::write(&worker, format!("#!/bin/sh\n{script}\n")).unwrap();
    crate::test_exec::make_executable(&worker, 0o700);
    let specimen = fs::read("/usr/bin/true").unwrap();
    fs::write(dir.join("specimen"), &specimen).unwrap();
    let mut report = new_report(
        "/usr/bin/true",
        &AnalysisSelection {
            enabled: true,
            checks: vec![AnalysisKind::Metadata],
            time_limit_minutes: 0,
            limits: Default::default(),
        },
    );
    report.specimen_len = Some(specimen.len() as u64);
    report.specimen_sha256 = Some(format!("{:x}", Sha256::digest(&specimen)));
    report.state = AnalysisState::Running;
    let mut job = Job {
        run_id: None,
        report,
        directory: dir.to_path_buf(),
        handle: None,
        total_len: specimen.len() as u64,
        received_len: specimen.len() as u64,
        file: None,
        // Already past its deadline.
        deadline: Instant::now(),
        child: None,
        cleanup_reason: None,
        reserved_len: 0,
        digest: Sha256::new(),
        disk_len: 0,
        worker_len: 0,
        report_len: 0,
        specimen_publication: None,
        progress: Default::default(),
        host_copy: None,
        supplement: None,
    };
    job.child = Some(spawn_worker_binary(&job, &worker, None).unwrap());
    job
}

fn run_out(jobs: &mut Jobs) -> (AnalysisReport, Duration) {
    let started = Instant::now();
    while jobs.active.is_some() {
        assert!(started.elapsed() < Duration::from_secs(60), "never ended");
        jobs.worker_tick();
        std::thread::sleep(Duration::from_millis(20));
    }
    let report = jobs.updates().pop().unwrap().1;
    (report, started.elapsed())
}

#[test]
#[ignore = "requires installed bubblewrap and usable user namespaces"]
fn t0471_a_worker_past_its_deadline_is_stopped_gracefully() {
    let dir = test_dir("worker-term");
    // Let the sandbox start (the init must be pinned) before the deadline.
    let mut job = worker_job(
        &dir,
        "trap 'echo done > /output/artifacts/stopped; exit 0' TERM\nwhile :; do sleep 0.1; done",
    );
    std::thread::sleep(Duration::from_millis(500));
    job.deadline = Instant::now();
    let mut jobs = Jobs::default();
    jobs.stop_grace = Some(Duration::from_secs(20));
    jobs.active = Some(job);
    let (report, took) = run_out(&mut jobs);
    assert_eq!(report.state, AnalysisState::Partial, "{:?}", report.reason);
    assert!(dir.join("output/artifacts/stopped").is_file());
    assert!(took < Duration::from_secs(15), "{took:?}");
    assert!(
        report
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("worker cleanup completed")),
        "{:?}",
        report.reason
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires installed bubblewrap and usable user namespaces"]
fn t0471_a_worker_ignoring_sigterm_is_killed_after_the_grace() {
    let dir = test_dir("worker-kill");
    let mut job = worker_job(&dir, "trap '' TERM\nsleep 60");
    std::thread::sleep(Duration::from_millis(500));
    job.deadline = Instant::now();
    let grace = Duration::from_secs(3);
    let mut jobs = Jobs::default();
    jobs.stop_grace = Some(grace);
    jobs.active = Some(job);
    let (report, took) = run_out(&mut jobs);
    assert_eq!(report.state, AnalysisState::Partial, "{:?}", report.reason);
    assert!(took >= grace, "{took:?}");
    assert!(took < Duration::from_secs(30), "{took:?}");
    let _ = fs::remove_dir_all(&dir);
}

/// A cancel of the running analysis is graceful too; with no grace it is
/// immediate, as before.
#[test]
#[ignore = "requires installed bubblewrap and usable user namespaces"]
fn t0471_a_cancelled_worker_gets_sigterm_first() {
    let dir = test_dir("worker-cancel");
    let mut job = worker_job(
        &dir,
        "trap 'echo done > /output/artifacts/stopped; exit 0' TERM\nwhile :; do sleep 0.1; done",
    );
    std::thread::sleep(Duration::from_millis(500));
    job.deadline = Instant::now() + Duration::from_secs(600);
    let id = job.report.id.clone();
    let mut jobs = Jobs::default();
    jobs.stop_grace = Some(Duration::from_secs(20));
    jobs.active = Some(job);
    jobs.cancel(&id).unwrap();
    assert!(jobs.active.is_some(), "the worker is given its grace");
    let (report, _) = run_out(&mut jobs);
    assert_eq!(report.state, AnalysisState::Cancelled);
    assert!(dir.join("output/artifacts/stopped").is_file());
    let _ = fs::remove_dir_all(&dir);
}

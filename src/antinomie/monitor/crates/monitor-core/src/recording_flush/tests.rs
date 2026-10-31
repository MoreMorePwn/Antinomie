// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::{
    api::{ExecRequest, Health, RunState, RunSummary},
    run::ProgramRun,
    storage,
    writer::held::SlowWriter,
};
use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

fn wait_until_idle(flusher: &mut Flusher) -> Vec<String> {
    let started = Instant::now();
    let mut errors = Vec::new();
    while flusher.is_busy() {
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "flush did not finish"
        );
        thread::sleep(Duration::from_millis(5));
    }
    errors.extend(flusher.collect());
    errors
}

#[test]
fn steps_run_in_order_on_their_own_thread_and_show_progress() {
    let mut flusher = Flusher::default();
    let (release, gate) = mpsc::channel::<()>();
    let (log, entries) = mpsc::channel();
    let record = |name: &'static str| {
        let log = log.clone();
        move || -> Result<(), String> {
            log.send((name, thread::current().name().map(str::to_owned)))
                .unwrap();
            Ok(())
        }
    };
    let second = record("second");
    let started = Instant::now();
    assert!(
        flusher
            .spawn(
                "boot".into(),
                vec![
                    ("first".into(), Box::new(record("first"))),
                    (
                        "second".into(),
                        Box::new(move || {
                            gate.recv().unwrap();
                            second()
                        }),
                    ),
                    ("third".into(), Box::new(record("third"))),
                ],
            )
            .is_ok()
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "spawn does not run the steps"
    );
    let status = loop {
        let status = flusher.status().expect("job is running");
        if status.done_count == 1 && status.current == "second" {
            break status;
        }
        thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(status.total_count, 3);
    assert_eq!(status.boot_ids, ["boot"]);
    assert_eq!(status.label(), "Saving recordings 1/3: second");
    assert!(flusher.is_busy());
    release.send(()).unwrap();
    assert!(wait_until_idle(&mut flusher).is_empty());
    assert!(flusher.status().is_none());
    let order: Vec<_> = entries.try_iter().collect();
    assert_eq!(
        order.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        ["first", "second", "third"]
    );
    assert!(
        order
            .iter()
            .all(|(_, thread)| thread.as_deref() == Some("antinomie-flush"))
    );
}

#[test]
fn a_failing_or_panicking_step_is_reported_and_never_wedges_the_job() {
    let mut flusher = Flusher::default();
    assert!(
        flusher
            .spawn(
                "boot".into(),
                vec![
                    ("bad".into(), Box::new(|| Err("disk full".into()))),
                    ("good".into(), Box::new(|| Ok(()))),
                ],
            )
            .is_ok()
    );
    assert_eq!(wait_until_idle(&mut flusher), ["bad: disk full"]);
    assert!(
        flusher
            .spawn(
                "other".into(),
                vec![("boom".into(), Box::new(|| panic!("step panicked")))],
            )
            .is_ok()
    );
    let errors = wait_until_idle(&mut flusher);
    assert_eq!(errors.len(), 1);
    assert!(errors[0].contains("stopped unexpectedly"));
    assert!(!flusher.is_busy());
}

#[test]
fn jobs_for_one_boot_share_the_serial_worker_and_reject_over_capacity() {
    let mut flusher = Flusher::default();
    let (started, began) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let (log, entries) = mpsc::channel();
    assert!(
        flusher
            .spawn(
                "boot".into(),
                vec![(
                    "retired capture".into(),
                    Box::new(move || {
                        started.send(()).unwrap();
                        gate.recv().unwrap();
                        Ok(())
                    }),
                )],
            )
            .is_ok()
    );
    began.recv_timeout(Duration::from_secs(1)).unwrap();

    assert!(
        flusher
            .spawn(
                "boot".into(),
                vec![(
                    "boot archive".into(),
                    Box::new(move || {
                        log.send(thread::current().name().map(str::to_owned))
                            .unwrap();
                        Ok(())
                    }),
                )],
            )
            .is_ok()
    );
    assert!(
        entries.try_recv().is_err(),
        "later boot step ran before capture finalizer"
    );

    // The first blocked job plus the queued final job leave two bounded slots.
    for n in 0..(MAX_FLUSH_JOBS - 2) {
        assert!(
            flusher
                .spawn(
                    "other".into(),
                    vec![(format!("queued {n}"), Box::new(|| Ok(())))],
                )
                .is_ok()
        );
    }
    let rejected = flusher
        .spawn(
            "overflow".into(),
            vec![("retained".into(), Box::new(|| Ok(())))],
        )
        .unwrap_err();
    assert_eq!(rejected.boot_id, "overflow");
    assert_eq!(rejected.steps.len(), 1);
    assert_eq!(rejected.reason, "recording flush queue is full");

    release.send(()).unwrap();
    assert!(wait_until_idle(&mut flusher).is_empty());
    assert_eq!(
        entries.try_iter().collect::<Vec<_>>(),
        [Some("antinomie-flush".into())]
    );
}

#[test]
fn inline_runs_report_every_failure() {
    let errors = run_inline(vec![
        ("one".into(), Box::new(|| Err("a".into()))),
        ("two".into(), Box::new(|| Ok(()))),
        ("three".into(), Box::new(|| Err("b".into()))),
    ]);
    assert_eq!(errors, ["one: a", "three: b"]);
}

fn run_summary(directory: &std::path::Path) -> RunSummary {
    RunSummary {
        environment: None,
        started_ms: None,
        clock_anchor: None,
        id: "run".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 2,
        pid: 3,
        request: ExecRequest::default(),
        directory: directory.to_owned(),
        terminal_eof: false,
        state: RunState::Running,
        notes: Vec::new(),
        machine: None,
        route: None,
        recording_error: None,
        execution: None,
        analysis: None,
    }
}

/// With the recording writer stopped, the transport-thread half of
/// finalization returns, the job waits, and final files appear only after the
/// raw data is written.
#[test]
fn stop_seals_without_the_disk_and_publishes_final_files_after_the_data() {
    let _writer = SlowWriter::install();
    let directory = std::env::temp_dir().join(format!("ant-stop-order-{}", storage::unique_id()));
    let mut run = ProgramRun::new(run_summary(&directory), 1 << 20).unwrap();
    _writer.pause();
    assert!(run.capture.append(b"telemetry before stop"));
    run.output(b"last words", 1 << 20).unwrap();
    run.capture.flush();

    // Transport-thread half: no wait for either stopped disk path.
    let started = Instant::now();
    run.begin_finalize(1 << 20);
    let mut flusher = Flusher::default();
    assert!(
        flusher
            .spawn(
                "boot".into(),
                vec![(
                    "run".into(),
                    Box::new(move || run.complete_finalize("clean", &Health::default())),
                )],
            )
            .is_ok()
    );
    assert!(started.elapsed() < Duration::from_secs(30));
    thread::sleep(Duration::from_millis(150));
    let on_disk = std::fs::read_to_string(directory.join("run.json")).unwrap_or_default();
    assert!(
        !on_disk.contains("Finalized"),
        "the final summary waits for the data: {on_disk}"
    );
    assert!(flusher.is_busy());

    // The raw data reaches the disk first; only then are the final files published.
    _writer.resume();
    let deadline = Instant::now() + Duration::from_secs(60);
    while std::fs::metadata(directory.join("telemetry.raw")).map_or(0, |m| m.len()) == 0 {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
    assert!(wait_until_idle(&mut flusher).is_empty());
    let summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("run.json")).unwrap()).unwrap();
    assert_eq!(summary["state"], "Finalized");
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["final_state"], "clean");
    assert_eq!(
        std::fs::read(directory.join("telemetry.raw"))
            .unwrap()
            .len(),
        4 + b"telemetry before stop".len()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

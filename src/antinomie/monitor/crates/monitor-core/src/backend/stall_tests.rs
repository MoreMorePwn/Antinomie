// SPDX-License-Identifier: GPL-3.0-only
//! The transport thread never waits for the disk: Run acceptance, status
//! files, terminal and telemetry bookkeeping and the seal at Stop all return
//! while both the recording writer and the status-file thread are stopped,
//! and what they queued is on disk, in order, once the disk answers again.
use super::*;
use crate::{storage::slow_disk::SlowDisk, writer::held::SlowWriter};

fn summary(directory: PathBuf) -> RunSummary {
    RunSummary {
        started_ms: None,
        clock_anchor: None,
        id: "stalled-run".into(),
        vm_id: "vm".into(),
        boot_id: "boot".into(),
        session_id: 1,
        root_task_cookie: 2,
        pid: 3,
        request: ExecRequest {
            memory_dump_on_exit: true,
            ..Default::default()
        },
        directory,
        terminal_eof: false,
        state: RunState::Running,
        recording_error: None,
        notes: Vec::new(),
        route: None,
        execution: None,
        analysis: None,
    }
}

#[test]
fn run_acceptance_and_bookkeeping_do_not_wait_for_a_stalled_disk() {
    let writer = SlowWriter::install();
    let disk = SlowDisk::install();
    let root = std::env::temp_dir().join(format!("ant-stall-{}", storage::unique_id()));
    let directory = root.join("runs/stalled-run");
    // The thread that stands for the transport thread. Everything it does
    // here is what a Run command and a drain pass do on it.
    let sync_writes = storage::transport_sync_writes();
    let transport = {
        let (inherit_writer, inherit_disk) = (
            crate::writer::held::inherit(),
            crate::storage::slow_disk::inherit(),
        );
        let directory = directory.clone();
        let (done, finished) = mpsc::channel();
        writer.pause();
        disk.pause();
        let handle = thread::spawn(move || {
            inherit_writer();
            inherit_disk();
            storage::mark_transport_thread();
            let mut run = ProgramRun::new(summary(directory.clone()), 1 << 20).unwrap();
            let mut artifacts = RunArtifactOwner::new(&run.summary);
            artifacts.save().unwrap();
            run.summary.state = RunState::Running;
            run.persist_summary().unwrap();
            // A heavy drain pass: raw packets and object chunks for the writer.
            for n in 0..2_000u32 {
                run.capture.append(&[n as u8; 512]);
            }
            run.capture.flush();
            run.assembler.flush();
            artifacts.summary.memory_state = RunArtifactState::Queued;
            artifacts.save().unwrap();
            run.output(b"terminal output", 1 << 20).unwrap();
            run.eof(1 << 20).unwrap();
            run.save_screen(1 << 20).unwrap();
            // Seal at Stop: states and quota only.
            run.begin_finalize(1 << 20);
            let mut flusher = crate::recording_flush::Flusher::default();
            let health = Health::default();
            assert!(
                flusher
                    .spawn(
                        "boot".into(),
                        vec![(
                            "run".into(),
                            Box::new(move || run.complete_finalize("clean", &health)),
                        )],
                    )
                    .is_ok()
            );
            done.send(()).unwrap();
            flusher
        });
        match finished.recv_timeout(Duration::from_secs(10)) {
            Ok(()) => handle,
            Err(_) => panic!("the transport thread waited for the disk"),
        }
    };
    let mut flusher = transport.join().unwrap();
    assert_eq!(
        storage::transport_sync_writes(),
        sync_writes,
        "no fsync'd publication ran on the transport thread"
    );
    // Nothing reached the disk yet but the files created at once.
    assert!(flusher.is_busy());
    assert!(writer.queued_len() > 0);
    assert!(
        !fs::read_to_string(directory.join("run.json"))
            .unwrap_or_default()
            .contains("Finalized")
    );
    writer.resume();
    disk.resume();
    let deadline = Instant::now() + Duration::from_secs(60);
    while flusher.is_busy() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    assert!(flusher.collect().is_empty());
    let saved: RunSummary =
        serde_json::from_slice(&fs::read(directory.join("run.json")).unwrap()).unwrap();
    assert_eq!(saved.state, RunState::Finalized);
    let artifacts: serde_json::Value =
        serde_json::from_slice(&fs::read(directory.join("artifacts.json")).unwrap()).unwrap();
    assert_eq!(artifacts["memory_state"], "queued", "the later value won");
    assert_eq!(
        fs::metadata(directory.join("telemetry.raw")).unwrap().len(),
        2_000 * (4 + 512)
    );
    drop((writer, disk));
    fs::remove_dir_all(root).unwrap();
}

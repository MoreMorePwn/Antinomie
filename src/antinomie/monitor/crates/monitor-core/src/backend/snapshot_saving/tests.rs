// SPDX-License-Identifier: GPL-3.0-only
use super::*;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("snapshot-saving-{}", storage::unique_id()));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
    fn worker(&self) -> Worker {
        let worker = crate::backend::tests::download_worker(self.0.clone());
        let directory = self.0.join("vm");
        fs::create_dir(&directory).unwrap();
        let vm = VmConfig {
            id: "vm".into(),
            ..Default::default()
        };
        storage::atomic_json(&directory.join("config.json"), &vm).unwrap();
        storage::atomic_json(
            &directory.join("run-layer.json"),
            &crate::snapshots::run_layer::Record {
                format: 1,
                vm_id: vm.id,
                boot_id: "boot".into(),
                boot_dir: self.0.join("boot"),
                sealed: "disk.qcow2".into(),
                top: "snapshots/top.qcow2".into(),
                manifest_absent: true,
            },
        )
        .unwrap();
        worker
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn command() -> Command {
    Command::RenameVmSnapshot {
        vm_id: "vm".into(),
        snapshot_id: "checkpoint".into(),
        name: "Renamed".into(),
    }
}

#[test]
fn a_snapshot_waits_for_the_real_flusher_and_publishes_its_wait() {
    let root = Directory::new();
    let mut worker = root.worker();
    let (release, gate) = mpsc::sync_channel(1);
    let saved = Arc::new(AtomicBool::new(false));
    let completed = Arc::clone(&saved);
    worker
        .flusher
        .spawn(
            "boot".into(),
            vec![(
                "save evidence".into(),
                Box::new(move || {
                    gate.recv_timeout(Duration::from_secs(5))
                        .map_err(|error| error.to_string())?;
                    completed.store(true, Ordering::Release);
                    Ok(())
                }),
            )],
        )
        .unwrap();
    let latest = Arc::clone(&worker.latest_snapshot);
    let displayed = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&displayed);
    worker.wake = Some(Arc::new(move || {
        if latest.lock().unwrap().as_ref().is_some_and(|snapshot| {
            snapshot
                .vm_snapshot_progress
                .as_ref()
                .is_some_and(|progress| progress.stage == "Waiting for saved recordings")
        }) {
            seen.store(true, Ordering::Release);
            let _ = release.try_send(());
        }
    }));
    worker.wait_snapshot_recordings(&command()).unwrap();
    assert!(
        saved.load(Ordering::Acquire),
        "disk changes must not overtake evidence saving"
    );
    assert!(displayed.load(Ordering::Acquire));
    assert!(!worker.flusher.is_busy());
    assert!(worker.snapshot.vm_snapshot_progress.is_none());
    assert!(crate::snapshots::run_layer::pending_record(&worker.options, "vm").is_some());
}

#[test]
fn timeout_and_shutdown_leave_the_pending_layer_untouched() {
    let root = Directory::new();
    let mut worker = root.worker();
    let (release, gate) = mpsc::sync_channel(1);
    worker
        .flusher
        .spawn(
            "boot".into(),
            vec![(
                "save evidence".into(),
                Box::new(move || {
                    gate.recv_timeout(Duration::from_secs(5))
                        .map_err(|error| error.to_string())
                }),
            )],
        )
        .unwrap();
    let before = fs::read(root.0.join("vm/run-layer.json")).unwrap();
    let error = worker
        .wait_snapshot_flush_until("vm", Instant::now())
        .unwrap_err();
    assert!(error.contains("still being saved"));
    worker.closing.store(true, Ordering::Release);
    let error = worker.wait_snapshot_recordings(&command()).unwrap_err();
    assert!(error.contains("cancelled"));
    assert_eq!(fs::read(root.0.join("vm/run-layer.json")).unwrap(), before);
    assert!(worker.snapshot.vm_snapshot_progress.is_none());
    release.send(()).unwrap();
}

#[test]
fn a_deferred_recording_is_submitted_before_the_snapshot_continues() {
    let root = Directory::new();
    let mut worker = root.worker();
    let saved = Arc::new(AtomicBool::new(false));
    let completed = Arc::clone(&saved);
    worker.deferred_flush = Some(crate::recording_flush::RejectedFlushJob {
        boot_id: "boot".into(),
        reason: "queue was full".into(),
        steps: vec![(
            "save evidence".into(),
            Box::new(move || {
                completed.store(true, Ordering::Release);
                Ok(())
            }),
        )],
    });
    worker.wait_snapshot_recordings(&command()).unwrap();
    assert!(saved.load(Ordering::Acquire));
    assert!(worker.deferred_flush.is_none());
}

#[test]
fn unconfirmed_deletion_does_not_start_or_wait_for_a_deferred_recording() {
    let root = Directory::new();
    let mut worker = root.worker();
    let saved = Arc::new(AtomicBool::new(false));
    let completed = Arc::clone(&saved);
    worker.deferred_flush = Some(crate::recording_flush::RejectedFlushJob {
        boot_id: "boot".into(),
        reason: "queue was full".into(),
        steps: vec![(
            "save evidence".into(),
            Box::new(move || {
                completed.store(true, Ordering::Release);
                Ok(())
            }),
        )],
    });
    worker.closing.store(true, Ordering::Release);
    worker
        .wait_snapshot_recordings(&Command::DeleteVmSnapshot {
            vm_id: "vm".into(),
            snapshot_id: "checkpoint".into(),
            confirmed: false,
        })
        .unwrap();
    assert!(worker.deferred_flush.is_some());
    assert!(!saved.load(Ordering::Acquire));
    assert!(worker.snapshot.vm_snapshot_progress.is_none());
}

#[test]
fn another_running_vm_cannot_bypass_the_stopped_targets_pending_layer() {
    let root = Directory::new();
    let mut worker = root.worker();
    let before = fs::read(root.0.join("vm/run-layer.json")).unwrap();
    worker.snapshot.active_vm = Some("other".into());
    let error = worker.wait_snapshot_recordings(&command()).unwrap_err();
    assert!(error.contains("stop the other VM"));
    assert_eq!(fs::read(root.0.join("vm/run-layer.json")).unwrap(), before);
    assert!(worker.snapshot.vm_snapshot_progress.is_none());
    // A snapshot of the live target keeps its layer and does not finalize it.
    worker.snapshot.active_vm = Some("vm".into());
    worker.wait_snapshot_recordings(&command()).unwrap();
    assert_eq!(fs::read(root.0.join("vm/run-layer.json")).unwrap(), before);
}

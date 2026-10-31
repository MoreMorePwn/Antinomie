// SPDX-License-Identifier: GPL-3.0-only
use super::*;

struct Fixture {
    worker: Worker,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("restart-{}", storage::unique_id()));
        fs::create_dir_all(root.join("vm")).unwrap();
        storage::atomic_json(
            &root.join("vm/config.json"),
            &VmConfig {
                id: "vm".into(),
                ..Default::default()
            },
        )
        .unwrap();
        storage::atomic_json(
            &root.join("vm/run-layer.json"),
            &crate::snapshots::run_layer::Record {
                format: 1,
                vm_id: "vm".into(),
                boot_id: "old-boot".into(),
                boot_dir: root.join("old-boot"),
                sealed: "disk.qcow2".into(),
                top: "snapshots/top.qcow2".into(),
                manifest_absent: true,
            },
        )
        .unwrap();
        let mut worker = crate::backend::tests::download_worker(root.clone());
        worker.reconnect = (3, Some(Instant::now()));
        Self { worker, root }
    }

    fn block_flush(&mut self) -> mpsc::SyncSender<()> {
        let (release, gate) = mpsc::sync_channel(1);
        self.worker
            .flusher
            .spawn(
                "old-boot".into(),
                vec![(
                    "save evidence".into(),
                    Box::new(move || {
                        gate.recv_timeout(Duration::from_secs(30))
                            .map_err(|error| error.to_string())
                    }),
                )],
            )
            .unwrap();
        release
    }

    fn drain(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.worker.flusher.is_busy() {
            assert!(Instant::now() < deadline, "flusher did not complete");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

#[test]
fn restart_cannot_overtake_an_active_recording_and_retry_preserves_state() {
    let mut fixture = Fixture::new();
    let release = fixture.block_flush();
    let layer = fixture.root.join("vm/run-layer.json");
    let before = fs::read(&layer).unwrap();
    let reconnect = fixture.worker.reconnect;
    for closing in [false, true] {
        fixture.worker.closing.store(closing, Ordering::Release);
        let error = fixture.worker.start("vm").unwrap_err();
        assert!(error.contains("previous boot's recordings"), "{error}");
        assert_eq!(fs::read(&layer).unwrap(), before);
        assert_eq!(fixture.worker.reconnect, reconnect);
        assert!(fixture.worker.snapshot.active_vm.is_none());
    }
    fixture.worker.closing.store(false, Ordering::Release);
    // No sleep in start: the blocked save can still be released by its owner.
    release.send(()).unwrap();
    fixture.drain();
    assert_eq!(fixture.worker.start("vm").unwrap_err(), "unknown VM");
    assert_eq!(fs::read(layer).unwrap(), before);
}

#[test]
fn a_deferred_recording_is_retained_when_restart_is_refused() {
    let mut fixture = Fixture::new();
    let saved = Arc::new(AtomicBool::new(false));
    let completed = Arc::clone(&saved);
    fixture.worker.deferred_flush = Some(crate::recording_flush::RejectedFlushJob {
        boot_id: "old-boot".into(),
        reason: "queue was full".into(),
        steps: vec![(
            "save evidence".into(),
            Box::new(move || {
                completed.store(true, Ordering::Release);
                Ok(())
            }),
        )],
    });
    assert!(
        fixture
            .worker
            .start("vm")
            .unwrap_err()
            .contains("still being saved")
    );
    assert!(!saved.load(Ordering::Acquire));
    assert!(fixture.worker.deferred_flush.is_some());
    fixture.worker.poll_flush();
    fixture.drain();
    assert!(saved.load(Ordering::Acquire));
    assert!(fixture.worker.deferred_flush.is_none());
    assert_eq!(fixture.worker.start("vm").unwrap_err(), "unknown VM");
}

#[test]
fn unrelated_vm_without_a_pending_layer_is_not_blocked_by_one_save() {
    let mut fixture = Fixture::new();
    let release = fixture.block_flush();
    assert_eq!(fixture.worker.start("other").unwrap_err(), "unknown VM");
    assert!(
        fixture
            .worker
            .start("vm")
            .unwrap_err()
            .contains("still being saved")
    );
    release.send(()).unwrap();
    fixture.drain();
}

#[test]
fn a_full_flush_queue_still_prevents_starting_an_unrelated_vm() {
    let mut fixture = Fixture::new();
    let release = fixture.block_flush();
    for _ in 0..2 {
        fixture
            .worker
            .flusher
            .spawn(
                "another-boot".into(),
                vec![("save evidence".into(), Box::new(|| Ok(())))],
            )
            .unwrap();
    }
    assert!(
        fixture
            .worker
            .start("other")
            .unwrap_err()
            .contains("queue is full")
    );
    assert_eq!(fixture.worker.reconnect.0, 3);
    release.send(()).unwrap();
    fixture.drain();
    assert_eq!(fixture.worker.start("other").unwrap_err(), "unknown VM");
}

#[test]
fn cold_restore_waits_for_its_sealed_recording_before_starting() {
    let mut fixture = Fixture::new();
    let release = fixture.block_flush();
    let latest = Arc::clone(&fixture.worker.latest_snapshot);
    let displayed = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&displayed);
    fixture.worker.wake = Some(Arc::new(move || {
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
    assert_eq!(
        fixture.worker.start_restored_disk("vm").unwrap_err(),
        "unknown VM"
    );
    assert!(displayed.load(Ordering::Acquire));
    assert!(!fixture.worker.flusher.is_busy());
    assert!(fixture.worker.snapshot.vm_snapshot_progress.is_none());
}

#[test]
fn cancelled_cold_restore_reports_that_the_disk_was_already_restored() {
    let mut fixture = Fixture::new();
    let release = fixture.block_flush();
    let layer = fixture.root.join("vm/run-layer.json");
    let before = fs::read(&layer).unwrap();
    fixture.worker.closing.store(true, Ordering::Release);
    let error = fixture.worker.start_restored_disk("vm").unwrap_err();
    assert!(
        error.contains("snapshot disk restored, but guest was not started"),
        "{error}"
    );
    assert!(error.contains("cancelled"));
    assert_eq!(fs::read(layer).unwrap(), before);
    assert!(fixture.worker.snapshot.vm_snapshot_progress.is_none());
    release.send(()).unwrap();
    fixture.drain();
}

#[test]
fn failed_save_is_reported_and_does_not_leave_restart_permanently_blocked() {
    let mut fixture = Fixture::new();
    fixture
        .worker
        .flusher
        .spawn(
            "old-boot".into(),
            vec![(
                "save evidence".into(),
                Box::new(|| Err("injected disk failure".into())),
            )],
        )
        .unwrap();
    fixture.drain();
    fixture.worker.poll_flush();
    assert!(
        fixture
            .worker
            .snapshot
            .last_error
            .as_deref()
            .unwrap()
            .contains("injected disk failure")
    );
    assert_eq!(fixture.worker.start("vm").unwrap_err(), "unknown VM");
    assert!(crate::snapshots::run_layer::pending_record(&fixture.worker.options, "vm").is_some());
}

/// The sandboxed disk reader this check needs: `ANTINOMIE_TEST_READER`, or the
/// app built in this workspace's target directory.
fn test_reader() -> Option<PathBuf> {
    if let Some(reader) = std::env::var_os("ANTINOMIE_TEST_READER") {
        return Some(PathBuf::from(reader));
    }
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target");
    ["release", "debug"]
        .iter()
        .map(|profile| target.join(profile).join("antinomie-monitor"))
        .find(|candidate| candidate.is_file())
}

fn have_host_tool(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("-V")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Integration check with the real sandboxed disk reader, qemu-img/qemu-io and
/// e2fsprogs, without a VM. It skips itself (and says so) when the reader
/// (`ANTINOMIE_TEST_READER`, or a built app in the target directory) or a tool
/// is missing, so a plain `cargo test` runs it wherever they exist.
#[test]
fn restart_retains_old_file_bytes_before_real_qcow_layers_merge() {
    use crate::{disk_start, file_before, file_before_store, snapshots::run_layer};
    use std::process::Command as Process;

    fn run(program: &str, args: &[&std::ffi::OsStr]) -> Vec<u8> {
        let output = Process::new(program).args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    let Some(reader) = test_reader() else {
        eprintln!(
            "skipped: no disk-reader executable (build the app or set ANTINOMIE_TEST_READER)"
        );
        return;
    };
    for tool in ["qemu-img", "qemu-io", "mkfs.ext4", "debugfs"] {
        if !have_host_tool(tool) {
            eprintln!("skipped: {tool} is not installed");
            return;
        }
    }
    let mut fixture = Fixture::new();
    fs::remove_file(fixture.root.join("vm/run-layer.json")).unwrap();
    let source = fixture.root.join("source");
    fs::create_dir(&source).unwrap();
    let old = vec![b'A'; 4096];
    let new = vec![b'B'; 4096];
    fs::write(source.join("changed"), &old).unwrap();
    let raw = fixture.root.join("fs.raw");
    fs::File::create(&raw).unwrap().set_len(32 << 20).unwrap();
    run(
        "mkfs.ext4",
        &[
            "-q".as_ref(),
            "-F".as_ref(),
            "-b".as_ref(),
            "4096".as_ref(),
            "-d".as_ref(),
            source.as_os_str(),
            raw.as_os_str(),
        ],
    );
    let blocks = run(
        "debugfs",
        &["-R".as_ref(), "blocks /changed".as_ref(), raw.as_os_str()],
    );
    let block: u64 = String::from_utf8(blocks)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    let disk = fixture.root.join("vm/disk.qcow2");
    run(
        "qemu-img",
        &[
            "convert".as_ref(),
            "-f".as_ref(),
            "raw".as_ref(),
            "-O".as_ref(),
            "qcow2".as_ref(),
            raw.as_os_str(),
            disk.as_os_str(),
        ],
    );
    let vm = VmConfig {
        id: "vm".into(),
        ..Default::default()
    };
    storage::atomic_json(&fixture.root.join("vm/config.json"), &vm).unwrap();
    let boot = fixture.root.join("old-boot");
    fs::create_dir(&boot).unwrap();
    run_layer::begin(&fixture.worker.options, &vm, &boot, "old-boot").unwrap();
    let top = crate::snapshots::active_disk(&fixture.worker.options, &vm).unwrap();
    let start = disk_start::DiskStart::capture(&top, "old-boot", disk_start::Via::Start);
    let before = file_before::StartDisk::open(&start, Some(reader.clone())).unwrap();
    assert_eq!(before.read("/changed", 0, 4096).unwrap(), old);
    let write = format!("write -P 66 {} 4096", block * 4096);
    run(
        "qemu-io",
        &[
            "-f".as_ref(),
            "qcow2".as_ref(),
            "-c".as_ref(),
            write.as_ref(),
            top.as_os_str(),
        ],
    );
    run_layer::ended("vm");

    let (release, gate) = mpsc::sync_channel(1);
    let saved_boot = boot.clone();
    fixture
        .worker
        .flusher
        .spawn(
            "old-boot".into(),
            vec![(
                "save earlier file".into(),
                Box::new(move || {
                    gate.recv_timeout(Duration::from_secs(30))
                        .map_err(|error| error.to_string())?;
                    storage::atomic_json(
                        &saved_boot.join("run.json"),
                        &serde_json::json!({"boot_id":"old-boot"}),
                    )?;
                    let status = before.find("/changed", None);
                    let mut writer = file_before_store::Writer::open(
                        &saved_boot,
                        "old-boot",
                        crate::file_writes::Limits::default(),
                    );
                    writer.record(
                        "/changed",
                        &[],
                        None,
                        &status,
                        Some(&file_before::DiskFile {
                            disk: before,
                            path: "/changed".into(),
                        }),
                    );
                    writer.finish(true, None)
                }),
            )],
        )
        .unwrap();
    assert!(
        fixture
            .worker
            .start("vm")
            .unwrap_err()
            .contains("still being saved")
    );
    assert!(top.exists());
    assert!(
        !boot.join("run.json").exists(),
        "save must still be blocked"
    );
    release.send(()).unwrap();
    fixture.drain();
    assert!(fixture.worker.flusher.collect().is_empty());
    assert!(
        file_before_store::Store::open(&boot)
            .unwrap()
            .index
            .complete
    );

    // Start's gate now allows the next stage (the fixture deliberately lacks a
    // launchable bundle). Exercise that stage with the real automatic layer.
    assert_eq!(fixture.worker.start("vm").unwrap_err(), "unknown VM");
    let next = fixture.root.join("next-boot");
    fs::create_dir(&next).unwrap();
    run_layer::begin(&fixture.worker.options, &vm, &next, "next-boot").unwrap();
    assert!(!top.exists(), "previous automatic layer was merged");
    let store = file_before_store::Store::open(&boot).unwrap();
    assert_eq!(store.read("/changed", 0, 4096).unwrap(), old);
    assert_eq!(store.index.files[0].sha256, Some(storage::sha256_hex(&old)));
    let active = crate::snapshots::active_disk(&fixture.worker.options, &vm).unwrap();
    let next_start = disk_start::DiskStart::capture(&active, "next-boot", disk_start::Via::Start);
    let after = file_before::StartDisk::open(&next_start, Some(reader)).unwrap();
    assert_eq!(after.read("/changed", 0, 4096).unwrap(), new);
    run_layer::ended("vm");
    run_layer::finalize(&fixture.worker.options, "vm").unwrap();
    assert!(run_layer::pending_record(&fixture.worker.options, "vm").is_none());
}

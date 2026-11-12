// SPDX-License-Identifier: GPL-3.0-only
use super::super::tests::Fixture;
use super::*;

/// The live-boot set is process-wide and every fixture is the same VM.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn have_qemu() -> bool {
    Command::new("qemu-img").arg("--version").output().is_ok()
        && Command::new("qemu-io").arg("--version").output().is_ok()
}

fn boot_dir(fixture: &Fixture, name: &str) -> PathBuf {
    let dir = fixture.root.join("rec/boots").join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn active(fixture: &Fixture) -> PathBuf {
    active_disk(&fixture.options, &fixture.vm).unwrap()
}

/// `finalize` as the worker uses it: a "still being finished" refusal is tried
/// again. The lock is a non-blocking `flock`, and other tests of the process
/// start `qemu-img` children in parallel; a child forked while this test held
/// the lock keeps a copy of it until it execs, so the next `finalize` can be
/// refused for a moment (seen in 2 of 5 runs of `snapshots::`). The worker
/// retries through `mark_due`; the tests wait up to 5 s the same way.
fn finish(fixture: &Fixture) -> Result<Option<Outcome>, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match finalize(&fixture.options, &fixture.vm.id) {
            Err(why)
                if why.contains("still being finished") && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

#[test]
fn a_boots_writes_go_to_the_automatic_layer_and_merge_back_down() {
    let _serial = serial();
    if !have_qemu() {
        eprintln!("skipped: qemu-img and qemu-io are needed");
        return;
    }
    let fixture = Fixture::new();
    fixture.write(7);
    let disk = fixture.directory.join("disk.qcow2");
    let boot = boot_dir(&fixture, "b1");
    begin(&fixture.options, &fixture.vm, &boot, "b1").unwrap();
    // The boot's disk is a new, empty layer; the sealed one is untouched.
    let top = active(&fixture);
    assert_ne!(top, disk);
    assert!(live(&fixture.vm.id));
    assert!(fixture.directory.join(MANIFEST).exists());
    fixture.write(9);
    fixture.read(&disk, 7);
    fixture.read(&top, 9);
    // It is no checkpoint: the Snapshots view lists nothing.
    assert!(
        list(&fixture.options, &fixture.vm)
            .unwrap()
            .nodes
            .is_empty()
    );
    // A running boot is not finished.
    assert!(finalize(&fixture.options, &fixture.vm.id).is_err());
    ended(&fixture.options, &fixture.vm.id);
    assert_eq!(finish(&fixture).unwrap(), Some(Outcome::Merged));
    // Back to one overlay holding both boots' data; nothing left over.
    assert_eq!(active(&fixture), disk);
    fixture.read(&disk, 9);
    assert!(!top.exists());
    assert!(
        !fixture.directory.join(MANIFEST).exists(),
        "not managed again"
    );
    assert!(pending_record(&fixture.options, &fixture.vm.id).is_none());
    assert_eq!(finish(&fixture).unwrap(), None);
}

#[test]
fn a_crash_leaves_a_bootable_disk_and_the_next_start_finishes_it() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    let disk = fixture.directory.join("disk.qcow2");
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    fixture.write(5);
    // The process dies here: the record stays and the disk chain is intact.
    let first = pending_record(&fixture.options, &fixture.vm.id).unwrap();
    assert_eq!(first.boot_id, "b1");
    fixture.read(&active(&fixture), 5);
    crate::snapshots::validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
    // The next start merges the old layer (no copier here, so the boot's
    // recording says it was not copied) and seals again.
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b2"),
        "b2",
    )
    .unwrap();
    fixture.read(&disk, 5);
    assert_eq!(
        pending_record(&fixture.options, &fixture.vm.id)
            .unwrap()
            .boot_id,
        "b2"
    );
    let index = crate::file_before_store::Index::load(&first.boot_dir).unwrap();
    assert!(!index.complete);
    assert!(index.note.unwrap().contains("not (fully) copied"));
    ended(&fixture.options, &fixture.vm.id);
    finish(&fixture).unwrap();
    assert_eq!(active(&fixture), disk);
}

#[test]
fn a_commit_cut_short_is_repeated_safely() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    let disk = fixture.directory.join("disk.qcow2");
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    fixture.write(3);
    let top = active(&fixture);
    // Dies after the data reached the sealed layer, before the switch back.
    commit(&fixture.options, &top).unwrap();
    ended(&fixture.options, &fixture.vm.id);
    assert_eq!(finish(&fixture).unwrap(), Some(Outcome::Merged));
    fixture.read(&disk, 3);
    assert_eq!(active(&fixture), disk);
    // Dies after the switch back, before the file and record went.
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b2"),
        "b2",
    )
    .unwrap();
    let record = pending_record(&fixture.options, &fixture.vm.id).unwrap();
    let mut manifest = load(&fixture.directory, &fixture.vm).unwrap();
    manifest.active_disk = record.sealed.clone();
    save(&fixture.directory, &manifest).unwrap();
    ended(&fixture.options, &fixture.vm.id);
    assert_eq!(finish(&fixture).unwrap(), Some(Outcome::Cleaned));
    assert!(!fixture.directory.join(&record.top).exists());
    assert_eq!(active(&fixture), disk);
}

#[test]
fn a_user_snapshot_taken_during_the_boot_is_never_merged() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    fixture.write(1);
    let disk = fixture.directory.join("disk.qcow2");
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    let top = active(&fixture);
    fixture.write(2);
    let checkpoint = fixture.take("During the boot");
    let after = active(&fixture);
    assert_ne!(after, top);
    fixture.write(4);
    ended(&fixture.options, &fixture.vm.id);
    assert_eq!(finish(&fixture).unwrap(), Some(Outcome::KeptInChain));
    // The checkpoint is the user's: its layer is the boot's layer, the sealed
    // layer is still below it, and the working disk is untouched.
    let tree = list(&fixture.options, &fixture.vm).unwrap();
    assert_eq!(tree.nodes.len(), 1);
    assert_eq!(tree.nodes[0].id, checkpoint.id);
    fixture.read(&top, 2);
    fixture.read(&disk, 1);
    fixture.read(&active(&fixture), 4);
    assert!(pending_record(&fixture.options, &fixture.vm.id).is_none());
    crate::snapshots::validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
}

#[test]
fn a_user_snapshot_that_exists_before_the_boot_stays_as_it_is() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    fixture.write(1);
    let checkpoint = fixture.take("Before");
    let frozen = fixture.directory.join("disk.qcow2");
    fixture.write(2);
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    fixture.write(6);
    ended(&fixture.options, &fixture.vm.id);
    assert_eq!(finish(&fixture).unwrap(), Some(Outcome::Merged));
    let tree = list(&fixture.options, &fixture.vm).unwrap();
    assert_eq!(tree.nodes.len(), 1);
    assert_eq!(tree.nodes[0].id, checkpoint.id);
    assert_eq!(
        tree.active_parent_id.as_deref(),
        Some(checkpoint.id.as_str())
    );
    fixture.read(&frozen, 1);
    // The manifest stays: the VM has a snapshot.
    assert!(fixture.directory.join(MANIFEST).exists());
    fixture.read(&active(&fixture), 6);
}

#[test]
fn resize_and_delete_wait_for_a_pending_layer() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    assert!(ensure_idle(&fixture.options, &fixture.vm.id).is_err());
    ended(&fixture.options, &fixture.vm.id);
    finish(&fixture).unwrap();
    ensure_idle(&fixture.options, &fixture.vm.id).unwrap();
}

#[test]
fn a_snapshot_after_the_boot_settles_the_pending_layer_first() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    fixture.write(1);
    let disk = fixture.directory.join("disk.qcow2");
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    let top = active(&fixture);
    fixture.write(8);
    // The boot is over but its layer is still pending (the background
    // finalize has not run): the snapshot of the stopped VM finishes it first,
    // so it freezes the merged disk and not a layer that is deleted a moment later.
    ended(&fixture.options, &fixture.vm.id);
    let checkpoint = fixture.take("After the boot");
    assert!(pending_record(&fixture.options, &fixture.vm.id).is_none());
    assert!(!top.exists(), "the automatic layer is merged and removed");
    fixture.read(&disk, 8);
    let tree = list(&fixture.options, &fixture.vm).unwrap();
    assert_eq!(tree.nodes.len(), 1);
    assert_eq!(tree.nodes[0].id, checkpoint.id);
    crate::snapshots::validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
}

#[test]
fn a_snapshot_waits_for_a_finalize_at_work() {
    let _serial = serial();
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::new();
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    fixture.write(5);
    ended(&fixture.options, &fixture.vm.id);
    // Another finalize holds the folder's lock: the snapshot must neither load
    // the manifest under it nor fail; it takes the layer over once it is free.
    let held = lock(&fixture.directory).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        drop(held);
    });
    let started = std::time::Instant::now();
    let checkpoint = fixture.take("Waited");
    assert!(started.elapsed() >= std::time::Duration::from_millis(300));
    release.join().unwrap();
    assert!(pending_record(&fixture.options, &fixture.vm.id).is_none());
    fixture.read(&fixture.directory.join("disk.qcow2"), 5);
    assert_eq!(
        list(&fixture.options, &fixture.vm).unwrap().nodes[0].id,
        checkpoint.id
    );
}

fn write_record(fixture: &Fixture, boot: &str, marker: Marker) {
    Record {
        format: 1,
        vm_id: fixture.vm.id.clone(),
        boot_id: boot.into(),
        boot_dir: fixture.root.join("rec/boots").join(boot),
        sealed: "disk.qcow2".into(),
        top: "snapshots/top.qcow2".into(),
        manifest_absent: true,
        marker,
    }
    .store(&fixture.directory)
    .unwrap();
}

#[test]
fn the_marker_follows_a_boot_from_live_to_saving_to_finalizing() {
    let _serial = serial();
    if !have_qemu() {
        eprintln!("skipped: qemu-img and qemu-io are needed");
        return;
    }
    let fixture = Fixture::new();
    fixture.write(1);
    let before = now_ms();
    begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(&fixture, "b1"),
        "b1",
    )
    .unwrap();
    let vms = [fixture.vm.id.clone()];
    let record = pending_record(&fixture.options, &fixture.vm.id).unwrap();
    assert_eq!(record.marker.phase, Some(LayerPhase::Live));
    assert_eq!(record.marker.owner, Owner::current());
    assert!(record.marker.started_ms.unwrap() >= before);
    let layers = disk_layers(&fixture.options, &vms);
    assert_eq!(layers.len(), 1);
    assert_eq!(
        (layers[0].boot_id.as_str(), layers[0].phase),
        ("b1", LayerPhase::Live)
    );
    assert_eq!(layers[0].started_ms, record.marker.started_ms.unwrap());

    // QEMU stopped: the recording is being saved, the layer is still pending.
    ended(&fixture.options, &fixture.vm.id);
    let layers = disk_layers(&fixture.options, &vms);
    assert_eq!(layers[0].phase, LayerPhase::Saving);
    assert!(layers[0].phase_ms >= layers[0].started_ms);
    // The file is whole and a 0.8.x reader still accepts it.
    let text = fs::read_to_string(fixture.directory.join(RECORD)).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["format"], 1);
    assert_eq!(value["phase"], "saving");

    // Finishing removes the file: no entry means done.
    finish(&fixture).unwrap();
    assert!(disk_layers(&fixture.options, &vms).is_empty());
}

#[test]
fn settle_marks_finalizing_before_it_copies_and_a_failed_one_leaves_it() {
    let _serial = serial();
    let fixture = Fixture::new();
    // A record whose layer path is not ours to touch: settle fails after the
    // marker was written, so the marker is what is left.
    write_record(
        &fixture,
        "b1",
        Marker {
            phase: Some(LayerPhase::Saving),
            phase_ms: Some(1),
            started_ms: Some(1),
            owner: Owner::current(),
        },
    );
    let mut record = pending_record(&fixture.options, &fixture.vm.id).unwrap();
    record.sealed = "../escape".into();
    record.store(&fixture.directory).unwrap();
    assert!(finalize(&fixture.options, &fixture.vm.id).is_err());
    let after = pending_record(&fixture.options, &fixture.vm.id).unwrap();
    assert_eq!(after.marker.phase, Some(LayerPhase::Finalizing));
    assert!(after.marker.phase_ms.unwrap() > 1);
}

#[test]
fn a_record_another_process_left_is_adopted_as_finalizing() {
    let fixture = Fixture::new();
    let vms = [fixture.vm.id.clone()];
    // Written by 0.8.x: no marker at all.
    write_record(&fixture, "old", Marker::default());
    let layers = disk_layers(&fixture.options, &vms);
    assert_eq!(layers.len(), 1);
    assert_eq!(layers[0].phase, LayerPhase::Finalizing);
    assert_eq!(layers[0].started_ms, 0);
    // Written by a 0.9 process that is gone (not this one).
    let mut other = Owner::current();
    other.pid = Some(std::process::id().wrapping_add(1));
    write_record(
        &fixture,
        "old",
        Marker {
            phase: Some(LayerPhase::Live),
            phase_ms: Some(7),
            started_ms: Some(3),
            owner: other,
        },
    );
    let layers = disk_layers(&fixture.options, &vms);
    assert_eq!(layers[0].phase, LayerPhase::Finalizing);
    assert_eq!((layers[0].started_ms, layers[0].phase_ms), (3, 7));
    // No record, no entry.
    fs::remove_file(fixture.directory.join(RECORD)).unwrap();
    assert!(disk_layers(&fixture.options, &vms).is_empty());
}

#[test]
fn the_lock_probe_sees_a_held_finalizer_lock_and_touches_nothing_else() {
    let fixture = Fixture::new();
    assert_eq!(lock_free(&fixture.directory), None);
    let held = lock(&fixture.directory).unwrap();
    assert_eq!(lock_free(&fixture.directory), Some(false));
    drop(held);
    assert_eq!(lock_free(&fixture.directory), Some(true));
}

/// A data folder of its own with one VM `vm` and a pending layer of it that
/// `settle` refuses (its sealed path leaves the VM folder), as a lane's.
fn lane_folder(tag: &str, vm: &str) -> (BackendOptions, PathBuf) {
    let root = std::env::temp_dir().join(format!("ant-runlayer-{tag}-{}", unique_id()));
    let directory = root.join(vm);
    private_dir(&directory).unwrap();
    let config = VmConfig {
        id: vm.into(),
        name: vm.into(),
        ..VmConfig::default()
    };
    atomic_json(&directory.join("config.json"), &config).unwrap();
    Record {
        format: 1,
        vm_id: vm.into(),
        boot_id: "b1".into(),
        boot_dir: root.join("boots/b1"),
        sealed: "../escape".into(),
        top: "snapshots/top.qcow2".into(),
        manifest_absent: true,
        marker: Marker {
            phase: Some(LayerPhase::Saving),
            phase_ms: Some(1),
            started_ms: Some(1),
            owner: Owner::current(),
        },
    }
    .store(&directory)
    .unwrap();
    let options = BackendOptions {
        data_dir: root.clone(),
        ..BackendOptions::default()
    };
    (options, root)
}

fn phase_of(options: &BackendOptions, vm: &str) -> Option<LayerPhase> {
    pending_record(options, vm).and_then(|record| record.marker.phase)
}

fn until_idle(vms: &[String]) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while working(vms) && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(!working(vms), "a finalize did not end");
}

#[test]
fn each_engine_of_a_process_finishes_only_its_own_vms_layers() {
    // ANT-T0455 (found by the 2-lane VM run): two lanes' engines in one
    // daemon, each over its own data folder. The boot of lane 1's VM ended
    // and was marked due; lane 2's engine came by first. It must leave lane
    // 1's layer to lane 1's engine, which finds the VM in its own folder.
    let _serial = serial();
    let one_vm = format!("lane1-{}", unique_id());
    let two_vm = format!("lane2-{}", unique_id());
    let (one, one_root) = lane_folder("one", &one_vm);
    let (two, two_root) = lane_folder("two", &two_vm);
    let (ones, twos) = (vec![one_vm.clone()], vec![two_vm.clone()]);
    mark_due(&one_vm);
    mark_due(&two_vm);
    finalize_due(&two, &twos);
    until_idle(&twos);
    assert_eq!(phase_of(&two, &two_vm), Some(LayerPhase::Finalizing));
    // Lane 1's VM is still due, and its record untouched.
    assert!(working(&ones));
    assert_eq!(phase_of(&one, &one_vm), Some(LayerPhase::Saving));
    finalize_due(&one, &ones);
    until_idle(&ones);
    assert_eq!(phase_of(&one, &one_vm), Some(LayerPhase::Finalizing));
    let _ = fs::remove_dir_all(&one_root);
    let _ = fs::remove_dir_all(&two_root);
}

#[test]
fn every_data_folder_of_a_process_is_scanned_for_a_layer_left_behind() {
    // A layer an earlier process left in lane 2's folder is found by lane 2's
    // first pass even though lane 1's engine scanned its own folder first.
    let _serial = serial();
    let one_vm = format!("lane1-{}", unique_id());
    let two_vm = format!("lane2-{}", unique_id());
    let (one, one_root) = lane_folder("scan-one", &one_vm);
    let (two, two_root) = lane_folder("scan-two", &two_vm);
    let (ones, twos) = (vec![one_vm.clone()], vec![two_vm.clone()]);
    finalize_due(&one, &ones);
    until_idle(&ones);
    finalize_due(&two, &twos);
    until_idle(&twos);
    assert_eq!(phase_of(&one, &one_vm), Some(LayerPhase::Finalizing));
    assert_eq!(phase_of(&two, &two_vm), Some(LayerPhase::Finalizing));
    let _ = fs::remove_dir_all(&one_root);
    let _ = fs::remove_dir_all(&two_root);
}

#[test]
fn a_finalize_that_found_the_disk_full_is_tried_again_and_others_are_not() {
    // ANT-T0475: a layer left pending by ENOSPC kept the lane out until the
    // next start; only a full disk (or quota) is worth another try.
    for why in [
        "automatic layer cleanup: No space left on device (os error 28)",
        "qemu-img commit: write failed: Disk quota exceeded (os error 122)",
    ] {
        assert!(out_of_space(why), "{why}");
    }
    for why in [
        "the automatic layer's backing file is not the sealed layer; left as it is",
        "the VM is running",
        "Permission denied (os error 13)",
        "Unknown error 280 (os error 280)",
    ] {
        assert!(!out_of_space(why), "{why}");
    }
}

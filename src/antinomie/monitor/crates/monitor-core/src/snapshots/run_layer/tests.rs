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
    ended(&fixture.vm.id);
    assert_eq!(
        finalize(&fixture.options, &fixture.vm.id).unwrap(),
        Some(Outcome::Merged)
    );
    // Back to one overlay holding both boots' data; nothing left over.
    assert_eq!(active(&fixture), disk);
    fixture.read(&disk, 9);
    assert!(!top.exists());
    assert!(
        !fixture.directory.join(MANIFEST).exists(),
        "not managed again"
    );
    assert!(pending_record(&fixture.options, &fixture.vm.id).is_none());
    assert_eq!(finalize(&fixture.options, &fixture.vm.id).unwrap(), None);
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
    ended(&fixture.vm.id);
    finalize(&fixture.options, &fixture.vm.id).unwrap();
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
    ended(&fixture.vm.id);
    assert_eq!(
        finalize(&fixture.options, &fixture.vm.id).unwrap(),
        Some(Outcome::Merged)
    );
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
    ended(&fixture.vm.id);
    assert_eq!(
        finalize(&fixture.options, &fixture.vm.id).unwrap(),
        Some(Outcome::Cleaned)
    );
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
    ended(&fixture.vm.id);
    assert_eq!(
        finalize(&fixture.options, &fixture.vm.id).unwrap(),
        Some(Outcome::KeptInChain)
    );
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
    ended(&fixture.vm.id);
    assert_eq!(
        finalize(&fixture.options, &fixture.vm.id).unwrap(),
        Some(Outcome::Merged)
    );
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
    ended(&fixture.vm.id);
    finalize(&fixture.options, &fixture.vm.id).unwrap();
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
    ended(&fixture.vm.id);
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
    ended(&fixture.vm.id);
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

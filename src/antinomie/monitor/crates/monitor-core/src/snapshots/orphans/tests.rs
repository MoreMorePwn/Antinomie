// SPDX-License-Identifier: GPL-3.0-only
use super::super::tests::Fixture;
use super::*;

fn have_qemu() -> bool {
    Command::new("qemu-img").arg("--version").output().is_ok()
        && Command::new("qemu-io").arg("--version").output().is_ok()
}

/// The `snapshots/*.qcow2` files of the fixture's VM.
fn layers(fixture: &Fixture) -> BTreeSet<PathBuf> {
    fs::read_dir(fixture.directory.join("snapshots"))
        .map(|entries| {
            entries
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "qcow2"))
                .collect()
        })
        .unwrap_or_default()
}

fn active(fixture: &Fixture) -> PathBuf {
    active_disk(&fixture.options, &fixture.vm).unwrap()
}

/// A revert as a lane makes it: a disk restore of `id`, committed.
fn revert(fixture: &Fixture, id: &str) {
    let restore = prepare_restore(&fixture.options, &fixture.vm, id, true).unwrap();
    commit_restore(&fixture.options, &fixture.vm, &restore).unwrap();
}

fn boot_dir(fixture: &Fixture, name: &str) -> PathBuf {
    let dir = fixture.root.join("rec/boots").join(name);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// A boot's start: its automatic layer over the active disk.
fn start(fixture: &Fixture, boot: &str) {
    run_layer::begin(
        &fixture.options,
        &fixture.vm,
        &boot_dir(fixture, boot),
        boot,
    )
    .unwrap();
}

/// The boot is over and its layer finished, as the worker does it: a refusal
/// because a forked child still holds a copy of the lock is tried again.
fn stop_and_settle(fixture: &Fixture) -> Option<run_layer::Outcome> {
    run_layer::ended(&fixture.options, &fixture.vm.id);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match run_layer::finalize(&fixture.options, &fixture.vm.id) {
            Err(why)
                if why.contains("still being finished") && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other.unwrap(),
        }
    }
}

/// A sweep pass, tried again while a forked child holds a copy of the lock.
fn sweep_pass(fixture: &Fixture, limit: usize) -> Sweep {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match sweep(&fixture.options, &fixture.vm.id, limit).unwrap() {
            Sweep::Busy if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            other => return other,
        }
    }
}

#[test]
fn n_lane_jobs_leave_a_constant_number_of_layers() {
    if !have_qemu() {
        eprintln!("skipped: qemu-img and qemu-io are needed");
        return;
    }
    let fixture = Fixture::named("orphans-lane");
    fixture.write(17);
    let clean = fixture.take("auto-clean");
    let mut counts = Vec::new();
    for job in 0..30u8 {
        // provision: revert to the clean checkpoint, then the job's boot.
        revert(&fixture, &clean.id);
        fixture.read(&active(&fixture), 17);
        start(&fixture, &format!("job-{job}"));
        fixture.write(100 + job);
        assert_eq!(stop_and_settle(&fixture), Some(run_layer::Outcome::Merged));
        fixture.read(&active(&fixture), 100 + job);
        counts.push(layers(&fixture).len());
    }
    // One working disk; the checkpoint's own layer is `disk.qcow2`.
    assert!(counts.iter().all(|count| *count == 1), "{counts:?}");
    assert_eq!(layers(&fixture), BTreeSet::from([active(&fixture)]));
    validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
    assert_eq!(list(&fixture.options, &fixture.vm).unwrap().nodes.len(), 1);
    // The checkpoint itself is untouched.
    revert(&fixture, &clean.id);
    fixture.read(&active(&fixture), 17);
}

#[test]
fn full_reverts_without_a_boot_layer_also_stay_flat() {
    if !have_qemu() {
        return;
    }
    // A Full lane resumes into the restored child itself (no run layer).
    let fixture = Fixture::named("orphans-full");
    let clean = fixture.take("auto-clean");
    for value in 1..=10u8 {
        revert(&fixture, &clean.id);
        fixture.write(value);
    }
    assert_eq!(layers(&fixture).len(), 1);
}

#[test]
fn a_pending_run_layer_is_kept_until_it_settles() {
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::named("orphans-pending");
    fixture.write(1);
    let clean = fixture.take("auto-clean");
    revert(&fixture, &clean.id);
    let sealed = active(&fixture);
    start(&fixture, "b1");
    let top = active(&fixture);
    fixture.write(2);
    // The boot ended, its layer is being saved (`saving`, not finalized).
    run_layer::ended(&fixture.options, &fixture.vm.id);
    let both = [
        PathBuf::from("snapshots").join(sealed.file_name().unwrap()),
        PathBuf::from("snapshots").join(top.file_name().unwrap()),
    ];
    assert_eq!(
        remove_unreferenced(&fixture.directory, &fixture.vm.id, &both).unwrap(),
        0
    );
    assert_eq!(
        sweep_pass(&fixture, SWEEP_LIMIT),
        Sweep::Done { removed: 0 }
    );
    assert!(sealed.exists() && top.exists());
    assert_eq!(stop_and_settle(&fixture), Some(run_layer::Outcome::Merged));
    assert!(!top.exists());
    fixture.read(&sealed, 2);
}

#[test]
fn a_restore_during_a_boot_keeps_the_layer_until_it_settles_then_removes_it() {
    if !have_qemu() {
        return;
    }
    // The desktop app restores a running VM: the boot's layer is pending
    // (live) while the restore commits, and settles at the next start.
    let fixture = Fixture::named("orphans-desktop");
    fixture.write(1);
    let clean = fixture.take("Clean");
    revert(&fixture, &clean.id);
    let sealed = active(&fixture);
    start(&fixture, "b1");
    let top = active(&fixture);
    fixture.write(2);
    revert(&fixture, &clean.id);
    assert!(top.exists() && sealed.exists(), "the pending layer is kept");
    // The restored disk boots: the earlier record settles first.
    start(&fixture, "b2");
    assert!(!top.exists() && !sealed.exists());
    fixture.write(3);
    assert_eq!(stop_and_settle(&fixture), Some(run_layer::Outcome::Merged));
    assert_eq!(layers(&fixture).len(), 1);
    fixture.read(&active(&fixture), 3);
}

#[test]
fn a_user_snapshot_taken_during_a_boot_is_kept_with_the_layer_below_it() {
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::named("orphans-user");
    fixture.write(1);
    let clean = fixture.take("Clean");
    revert(&fixture, &clean.id);
    let sealed = active(&fixture);
    fixture.write(2);
    start(&fixture, "b1");
    let top = active(&fixture);
    fixture.write(3);
    let user = fixture.take("During the boot");
    let working = active(&fixture);
    fixture.write(4);
    // Back to the clean state while the VM runs, then the next boot.
    revert(&fixture, &clean.id);
    assert!(
        !working.exists(),
        "the unsaved changes after the snapshot go"
    );
    start(&fixture, "b2");
    assert_eq!(stop_and_settle(&fixture), Some(run_layer::Outcome::Merged));
    // The user's checkpoint is the boot's layer over the sealed one: both stay.
    assert!(top.exists() && sealed.exists());
    fixture.read(&top, 3);
    fixture.read(&sealed, 2);
    revert(&fixture, &user.id);
    fixture.read(&active(&fixture), 3);
    // A sweep agrees: nothing it may remove.
    assert_eq!(
        sweep_pass(&fixture, SWEEP_LIMIT),
        Sweep::Done { removed: 0 }
    );
    assert_eq!(layers(&fixture).len(), 3);
    validate_active(&fixture.options, &fixture.vm, &fixture.base).unwrap();
}

#[test]
fn the_startup_sweep_removes_only_unreferenced_layers_in_bounded_passes() {
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::named("orphans-sweep");
    fixture.write(1);
    let clean = fixture.take("Clean");
    revert(&fixture, &clean.id);
    fixture.write(2);
    let kept = fixture.take("Kept");
    let kept_disk = fixture.directory.join(
        &load(&fixture.directory, &fixture.vm)
            .unwrap()
            .nodes
            .iter()
            .find(|node| node.checkpoint.id == kept.id)
            .unwrap()
            .disk,
    );
    let working = active(&fixture);
    // What 0.9.0 before the fix left: children of the checkpoint, one per job.
    let clean_disk = fixture.directory.join("disk.qcow2");
    let mut left = Vec::new();
    for _ in 0..10 {
        left.push(
            fixture
                .directory
                .join(make_child(&fixture.options, &fixture.directory, &clean_disk).unwrap()),
        );
    }
    // Files the sweep never removes: not a layer name, a symbolic link with a
    // layer name, a note.
    let folder = fixture.directory.join("snapshots");
    let outside = fixture.root.join("outside.qcow2");
    Fixture::command("qemu-img", &["create", "-f", "qcow2"], &outside, Some("1M"));
    std::os::unix::fs::symlink(&outside, folder.join("0123abcd.qcow2")).unwrap();
    fs::write(folder.join("user-note.qcow2"), b"keep").unwrap();
    fs::write(folder.join("note.txt"), b"keep").unwrap();
    let before = fs::read_dir(&folder).unwrap().count();
    // An unfinished operation's journal: nothing is judged.
    fs::write(fixture.directory.join(JOURNAL), b"{}").unwrap();
    assert_eq!(sweep_pass(&fixture, 4), Sweep::Done { removed: 0 });
    fs::remove_file(fixture.directory.join(JOURNAL)).unwrap();
    // Bounded passes: 4, 4, then the last 2.
    assert_eq!(sweep_pass(&fixture, 4), Sweep::More { removed: 4 });
    assert_eq!(sweep_pass(&fixture, 4), Sweep::More { removed: 4 });
    assert_eq!(sweep_pass(&fixture, 4), Sweep::Done { removed: 2 });
    assert_eq!(sweep_pass(&fixture, 4), Sweep::Done { removed: 0 });
    assert!(left.iter().all(|path| !path.exists()));
    assert_eq!(fs::read_dir(&folder).unwrap().count(), before - 10);
    assert!(kept_disk.exists() && working.exists() && outside.exists());
    assert!(fs::symlink_metadata(folder.join("0123abcd.qcow2")).is_ok());
    fixture.read(&working, 2);
    revert(&fixture, &kept.id);
    fixture.read(&active(&fixture), 2);
    revert(&fixture, &clean.id);
    fixture.read(&active(&fixture), 1);
}

#[test]
fn the_startup_sweep_removes_memory_files_no_checkpoint_names() {
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::named("orphans-states");
    fixture.write(1);
    let clean = fixture.take("Clean");
    let folder = fixture.directory.join("snapshots");
    // What a failed Full take left: a memory file of a hex id no node names.
    let left = [folder.join("abcdef.state"), folder.join("0123-4567.state")];
    for path in &left {
        fs::write(path, b"state").unwrap();
    }
    // Never removed: other names, a symbolic link with a state name.
    let outside = fixture.root.join("outside.state");
    fs::write(&outside, b"keep").unwrap();
    std::os::unix::fs::symlink(&outside, folder.join("fedcba.state")).unwrap();
    fs::write(folder.join("user-note.state"), b"keep").unwrap();
    fs::write(folder.join("note.txt"), b"keep").unwrap();
    // An unfinished operation's journal: nothing is judged.
    fs::write(fixture.directory.join(JOURNAL), b"{}").unwrap();
    assert_eq!(sweep_pass(&fixture, 8), Sweep::Done { removed: 0 });
    assert!(left.iter().all(|path| path.exists()));
    fs::remove_file(fixture.directory.join(JOURNAL)).unwrap();
    assert_eq!(sweep_pass(&fixture, 8), Sweep::Done { removed: 2 });
    assert!(left.iter().all(|path| !path.exists()));
    assert!(outside.exists());
    assert!(fs::symlink_metadata(folder.join("fedcba.state")).is_ok());
    assert!(folder.join("user-note.state").exists() && folder.join("note.txt").exists());
    assert_eq!(sweep_pass(&fixture, 8), Sweep::Done { removed: 0 });
    revert(&fixture, &clean.id);
    fixture.read(&active(&fixture), 1);
}

#[test]
fn a_chain_that_cannot_be_read_removes_nothing() {
    if !have_qemu() {
        return;
    }
    let fixture = Fixture::named("orphans-unreadable");
    let clean = fixture.take("Clean");
    revert(&fixture, &clean.id);
    let left = fixture.directory.join(
        make_child(
            &fixture.options,
            &fixture.directory,
            &fixture.directory.join("disk.qcow2"),
        )
        .unwrap(),
    );
    // The working disk's header is damaged: its chain cannot be proved.
    let working = active(&fixture);
    fs::write(&working, b"not a qcow2 image").unwrap();
    assert!(sweep(&fixture.options, &fixture.vm.id, SWEEP_LIMIT).is_err());
    assert!(left.exists());
}

#[test]
fn a_vm_with_more_than_4096_layers_left_behind_is_still_deletable() {
    if !have_qemu() {
        return;
    }
    // A lane that ran a day of jobs on 0.9.0 code before the fix.
    let fixture = Fixture::named("orphans-delete");
    let clean = fixture.take("Clean");
    revert(&fixture, &clean.id);
    let folder = fixture.directory.join("snapshots");
    for index in 0..4500u32 {
        fs::write(folder.join(format!("{index:032x}.qcow2")), b"").unwrap();
    }
    crate::storage::delete_vm(&fixture.options, &fixture.vm.id).unwrap();
    assert!(!folder.exists());
    assert!(fixture.base.exists());
}

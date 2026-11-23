// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::disk_start::{Frozen, Via};

struct Dirs {
    root: PathBuf,
    boot: PathBuf,
    sealed: PathBuf,
    base: PathBuf,
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// A boot folder whose `disk-start.json` names `sealed` over `base`, both
/// plain files (only their size and time are read here).
fn dirs(start: Option<Start>) -> Dirs {
    let root = std::env::temp_dir().join(format!("ant-kept-{}", crate::storage::unique_id()));
    let boot = root.join("rec/boots/b1");
    let vm = root.join("vm/snapshots");
    fs::create_dir_all(&boot).unwrap();
    fs::create_dir_all(&vm).unwrap();
    let sealed = vm.join("a.qcow2");
    let base = root.join("vm/base.qcow2");
    fs::write(&sealed, vec![7u8; 4096]).unwrap();
    fs::write(&base, vec![1u8; 8192]).unwrap();
    let sealed = fs::canonicalize(&sealed).unwrap();
    let base = fs::canonicalize(&base).unwrap();
    let start = start.unwrap_or_else(|| {
        Start::Frozen(Frozen {
            layers: vec![Layer::of(&sealed).unwrap(), Layer::of(&base).unwrap()],
        })
    });
    DiskStart {
        format: 1,
        boot_id: "b1".into(),
        via: Via::Start,
        start,
    }
    .save(&boot)
    .unwrap();
    Dirs {
        root,
        boot,
        sealed,
        base,
    }
}

fn frozen(start: &DiskStart) -> &Frozen {
    match &start.start {
        Start::Frozen(frozen) => frozen,
        other => panic!("not frozen: {other:?}"),
    }
}

#[test]
fn the_kept_layer_stands_in_for_the_sealed_one_after_the_merge() {
    let d = dirs(None);
    keep(&d.boot, "b1", &d.sealed).unwrap();
    let marker = pending(&d.boot).unwrap();
    assert_eq!(marker.original.as_deref(), Some(d.sealed.as_path()));
    assert_eq!(marker.boot_id, "b1");
    let kept = d.boot.join(DIR).join(LAYER);
    assert_eq!(fs::read(&kept).unwrap(), vec![7u8; 4096]);
    // The merge writes into `A`.
    fs::write(&d.sealed, vec![9u8; 8192]).unwrap();
    let saved = DiskStart::load_as_saved(&d.boot).unwrap();
    assert!(
        frozen(&saved).verify().is_err(),
        "A changed under the saved record"
    );
    let read = DiskStart::load(&d.boot).unwrap();
    assert_eq!(frozen(&read).layers[0].path, kept);
    assert_eq!(frozen(&read).layers[1].path, d.base);
    frozen(&read).verify().unwrap();
}

#[test]
fn a_sealed_layer_over_the_limit_is_not_kept() {
    let d = dirs(None);
    let file = fs::OpenOptions::new().write(true).open(&d.sealed).unwrap();
    file.set_len(KEEP_LIMIT + 1).unwrap();
    drop(file);
    // The record names the big file as it is now.
    let start = Start::Frozen(Frozen {
        layers: vec![Layer::of(&d.sealed).unwrap(), Layer::of(&d.base).unwrap()],
    });
    DiskStart {
        format: 1,
        boot_id: "b1".into(),
        via: Via::Start,
        start,
    }
    .save(&d.boot)
    .unwrap();
    let why = keep(&d.boot, "b1", &d.sealed).unwrap_err();
    assert!(why.contains("over 256 MiB"), "{why}");
    assert!(pending(&d.boot).is_none());
    assert!(!d.boot.join(DIR).join(LAYER).exists());
}

#[test]
fn a_start_that_was_not_frozen_waits_with_nothing_kept() {
    let d = dirs(Some(Start::Changed));
    keep(&d.boot, "b1", &d.sealed).unwrap();
    let marker = pending(&d.boot).unwrap();
    assert_eq!(marker.original, None);
    assert!(!d.boot.join(DIR).join(LAYER).exists());
    assert_eq!(DiskStart::load(&d.boot).unwrap().start, Start::Changed);
}

#[test]
fn another_sealed_layer_than_the_start_is_refused() {
    let d = dirs(None);
    let why = keep(&d.boot, "b1", &d.base).unwrap_err();
    assert!(why.contains("not the sealed layer"), "{why}");
    assert!(pending(&d.boot).is_none());
}

#[test]
fn finish_makes_the_copy_once_and_drops_the_kept_layer() {
    let d = dirs(None);
    assert_eq!(finish(&d.boot), Finished::Nothing);
    keep(&d.boot, "b1", &d.sealed).unwrap();
    // Held elsewhere: busy, and a reader sees a copy at work.
    let held = open_lock(&d.boot).unwrap();
    rustix::fs::flock(&held, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(at_work(&d.boot));
    assert_eq!(finish(&d.boot), Finished::Busy);
    drop(held);
    assert!(!at_work(&d.boot));
    // No copy program in a unit test: the recording says it was not copied.
    assert_eq!(finish(&d.boot), Finished::Copied);
    assert!(pending(&d.boot).is_none());
    assert!(!d.boot.join(DIR).exists());
    let index = crate::file_before_store::Index::load(&d.boot).unwrap();
    assert!(!index.complete);
    assert!(
        index
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("no program"),
        "{:?}",
        index.note
    );
    assert_eq!(finish(&d.boot), Finished::Nothing);
    // Without the marker the record reads as it was saved.
    let read = DiskStart::load(&d.boot).unwrap();
    assert_eq!(frozen(&read).layers[0].path, d.sealed);
}

// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::process::Command;

fn qemu_img(args: &[&str]) -> bool {
    Command::new("qemu-img")
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

/// base <- checkpoint <- active: an empty active overlay starts from the two
/// frozen layers; once the overlay holds data the start is "changed"; a
/// layer that changes or goes away fails verification.
#[test]
fn the_start_is_the_frozen_layers_under_an_empty_overlay() {
    if Command::new("qemu-img").arg("--version").output().is_err() {
        eprintln!("skipped: qemu-img is needed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("ant-diskstart-{}", crate::storage::unique_id()));
    crate::storage::private_dir(&dir).unwrap();
    let base = dir.join("base.qcow2");
    let checkpoint = dir.join("checkpoint.qcow2");
    let active = dir.join("active.qcow2");
    assert!(qemu_img(&[
        "create",
        "-q",
        "-f",
        "qcow2",
        base.to_str().unwrap(),
        "8M"
    ]));
    for (child, parent) in [(&checkpoint, &base), (&active, &checkpoint)] {
        assert!(qemu_img(&[
            "create",
            "-q",
            "-f",
            "qcow2",
            "-b",
            parent.to_str().unwrap(),
            "-F",
            "qcow2",
            child.to_str().unwrap(),
        ]));
    }
    let start = DiskStart::capture(&active, "boot-1", Via::Start);
    let Start::Frozen(frozen) = &start.start else {
        panic!("{start:?}");
    };
    assert_eq!(
        frozen.paths(),
        [
            std::fs::canonicalize(&checkpoint).unwrap(),
            std::fs::canonicalize(&base).unwrap()
        ]
    );
    frozen.verify().unwrap();
    start.save(&dir).unwrap();
    assert_eq!(DiskStart::find(&dir.join("runs/one")), Some(start.clone()));
    // A write into the overlay: the next boot's start is not recoverable.
    assert!(qemu_img(&[
        "bench",
        "-q",
        "-f",
        "qcow2",
        "-w",
        "-c",
        "1",
        "-s",
        "4k",
        active.to_str().unwrap(),
    ]));
    assert_eq!(
        DiskStart::capture(&active, "boot-2", Via::Start).start,
        Start::Changed
    );
    // A frozen layer touched afterwards no longer verifies.
    std::fs::OpenOptions::new()
        .append(true)
        .open(&checkpoint)
        .unwrap();
    let appended = std::fs::OpenOptions::new()
        .append(true)
        .open(&checkpoint)
        .unwrap();
    appended
        .set_len(std::fs::metadata(&checkpoint).unwrap().len() + 512)
        .unwrap();
    assert!(frozen.verify().unwrap_err().contains("changed"));
    std::fs::remove_file(&base).unwrap();
    assert!(frozen.verify().is_err());
    assert!(matches!(
        DiskStart::capture(&dir.join("missing.qcow2"), "b", Via::Start).start,
        Start::Unknown(_)
    ));
    let _ = std::fs::remove_dir_all(dir);
}

// SPDX-License-Identifier: GPL-3.0-only
//! Promoting a file out of a saved disk dump with the real `--disk-reader`
//! worker of the `antinomie-monitor` binary, on a small ext4 image built with
//! `mkfs.ext4 -d`. The run's folder is `<rec>/runs/<id>` and the dump lives
//! in `<rec>/disks/<id>/`, as the app saves them. Skipped without bubblewrap
//! or e2fsprogs.
use antinomie_monitor_core::{
    disks::dump::{DiskDump, DiskImageFormat},
    samples::promote,
    storage::sha256_hex,
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn mkfs() -> Option<PathBuf> {
    ["/sbin", "/usr/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join("mkfs.ext4"))
        .find(|path| path.is_file())
}

#[test]
fn a_file_is_promoted_from_the_recordings_dump_through_the_runs_folder() {
    let Some(mkfs) = mkfs().filter(|_| {
        Path::new("/usr/bin/bwrap").is_file() && Path::new("/usr/bin/prlimit").is_file()
    }) else {
        eprintln!("skipped: bubblewrap, prlimit and mkfs.ext4 are needed");
        return;
    };
    let root = std::env::temp_dir().join(format!("ant-promote-dump-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let (tree, rec) = (root.join("tree"), root.join("rec"));
    let run = rec.join("runs").join("r1");
    let dump_dir = rec.join("disks").join("d1");
    for dir in [
        tree.join("tmp"),
        tree.join("var/tmp"),
        run.clone(),
        dump_dir.clone(),
    ] {
        fs::create_dir_all(dir).unwrap();
    }
    let payload: Vec<u8> = (0..=255u8).chain(*b"ELFQA\n").collect();
    fs::write(tree.join("tmp/dropped.bin"), &payload).unwrap();
    fs::write(tree.join("var/tmp/note.txt"), "known text\n").unwrap();
    let image = dump_dir.join("root.ext4");
    fs::File::create(&image).unwrap().set_len(16 << 20).unwrap();
    let status = Command::new(mkfs)
        .args(["-q", "-F", "-b", "4096", "-d"])
        .arg(&tree)
        .arg(&image)
        .status()
        .unwrap();
    assert!(status.success());
    DiskDump {
        id: "d1".into(),
        vm_name: "QA".into(),
        file: "root.ext4".into(),
        format: DiskImageFormat::RawExt4,
        finished_ms: Some(1),
        dir: dump_dir,
        ..DiskDump::default()
    }
    .save()
    .unwrap();

    let app = Path::new(env!("CARGO_BIN_EXE_antinomie-monitor"));
    // The run's folder alone finds the recording's dump.
    assert_eq!(promote::dump_label(&run).as_deref(), Some("d1 (QA)"));
    let got = match promote::extract_with(app, &run, "/tmp/dropped.bin") {
        Ok(got) => got,
        // The sandbox needs user namespaces.
        Err(error) if error.contains("namespace") || error.contains("sandbox") => {
            eprintln!("skipped: {error}");
            let _ = fs::remove_dir_all(&root);
            return;
        }
        Err(error) => panic!("{error}"),
    };
    assert_eq!(sha256_hex(&got), sha256_hex(&payload));
    assert_eq!(got, payload);
    assert_eq!(
        promote::extract_with(app, &run, "/var/tmp/note.txt").unwrap(),
        b"known text\n"
    );
    // A file that is not on the disk (it lived in tmpfs) and a directory are
    // refused with the reason.
    let missing = promote::extract_with(app, &run, "/dev/shm/x").unwrap_err();
    assert!(missing.contains("not in the disk dump"), "{missing}");
    assert!(promote::extract_with(app, &run, "/tmp").is_err());
    assert!(promote::extract_with(app, &run, "/tmp/../etc/passwd").is_err());
    // A run in a recording without a dump offers nothing.
    let bare = root.join("bare/runs/r2");
    fs::create_dir_all(&bare).unwrap();
    assert!(promote::dump_label(&bare).is_none());
    let _ = fs::remove_dir_all(&root);
}

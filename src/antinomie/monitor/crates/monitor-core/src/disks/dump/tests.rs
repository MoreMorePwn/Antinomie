// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::disks::{
    disks_dir,
    fixture::{Fixture, require_tools},
    scratch_dir,
};
use std::{os::unix::fs::PermissionsExt, process::Command};

fn dump_in(fixture: &Fixture, id: &str, started_ms: u64) -> DiskDump {
    let dir = disks_dir(&fixture.root).join(id);
    fs::create_dir_all(&dir).unwrap();
    let dump = DiskDump {
        id: id.into(),
        vm_id: "vm-1".into(),
        vm_name: "Fixture".into(),
        file: IMAGE_FILE.into(),
        started_ms,
        finished_ms: Some(started_ms + 1),
        logical_size: 4096,
        dir,
        ..DiskDump::default()
    };
    dump.save().unwrap();
    dump
}

fn never() -> AtomicBool {
    AtomicBool::new(false)
}

#[test]
fn dumps_save_list_newest_first_and_delete() {
    let fixture = Fixture::new();
    let old = dump_in(&fixture, "a-old", 1_000);
    let new = dump_in(&fixture, "b-new", 3_000);
    let mid = dump_in(&fixture, "c-mid", 2_000);
    fs::write(old.dir.join(IMAGE_FILE), b"x").unwrap();
    fs::create_dir_all(new.extract_dir()).unwrap();
    fs::write(new.extract_dir().join("1-passwd"), b"x").unwrap();
    let roots = [fixture.root.clone(), fixture.root.clone()];
    let listed = list(&roots);
    // Newest first, and a directory named twice is listed once.
    let ids: Vec<_> = listed.iter().map(|dump| dump.id.as_str()).collect();
    assert_eq!(ids, ["b-new", "c-mid", "a-old"]);
    assert_eq!(listed[0].dir, new.dir);
    assert_eq!(listed[0], new);
    assert!(listed.iter().all(DiskDump::complete));
    delete(&mid).unwrap();
    assert!(!mid.dir.exists());
    // Extractions go with their dump.
    delete(&new).unwrap();
    assert!(!new.dir.exists());
    assert_eq!(list(&roots).len(), 1);
    assert!(delete(&new).is_err());
}

#[test]
fn only_dump_folders_are_listed_or_deleted() {
    let fixture = Fixture::new();
    let disks = disks_dir(&fixture.root);
    dump_in(&fixture, "real", 5);
    // A view, the extraction folder, a half-written dump, a hidden folder, a
    // folder with a broken sidecar, one with an oversized sidecar.
    fs::create_dir_all(scratch_dir(&disks, "view")).unwrap();
    fs::write(scratch_dir(&disks, "view").join(SUMMARY_FILE), "{}").unwrap();
    fs::create_dir_all(disks.join(EXTRACTED_DIR).join("view")).unwrap();
    fs::write(disks.join(EXTRACTED_DIR).join(SUMMARY_FILE), "{}").unwrap();
    fs::create_dir_all(disks.join("half")).unwrap();
    fs::write(disks.join("half").join(PART_FILE), b"x").unwrap();
    fs::create_dir_all(disks.join(".hidden")).unwrap();
    fs::write(disks.join(".hidden").join(SUMMARY_FILE), "{}").unwrap();
    fs::create_dir_all(disks.join("broken")).unwrap();
    fs::write(disks.join("broken").join(SUMMARY_FILE), "not json").unwrap();
    fs::create_dir_all(disks.join("huge")).unwrap();
    fs::write(
        disks.join("huge").join(SUMMARY_FILE),
        format!("{{\"id\":\"huge\",\"system\":\"{}\"}}", "x".repeat(2 << 20)),
    )
    .unwrap();
    fs::write(disks.join("loose-file"), "x").unwrap();
    fs::create_dir_all(disks.join("real").join("nested")).unwrap();
    fs::write(disks.join("real").join("nested").join(SUMMARY_FILE), "{}").unwrap();
    let listed = list(&[fixture.root.clone(), fixture.path("missing")]);
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, "real");

    // The delete guard names a dump folder directly under `disks/` only.
    for dir in [
        scratch_dir(&disks, "view"),
        disks.join(EXTRACTED_DIR),
        disks.join(".hidden"),
        disks.join("half"),
        disks.join("real").join("nested"),
        fixture.root.clone(),
        PathBuf::from("/"),
    ] {
        let probe = DiskDump {
            dir: dir.clone(),
            ..DiskDump::default()
        };
        assert!(delete(&probe).is_err(), "{}", dir.display());
        assert!(dir.exists());
    }
    assert!(disks.join("half").exists());
}

#[test]
fn a_symlinked_dump_folder_is_not_followed() {
    let fixture = Fixture::new();
    let disks = disks_dir(&fixture.root);
    let target = fixture.path("elsewhere");
    fs::create_dir_all(&target).unwrap();
    fs::write(target.join(SUMMARY_FILE), "{}").unwrap();
    fs::write(target.join("keep.txt"), "mine").unwrap();
    fs::create_dir_all(&disks).unwrap();
    std::os::unix::fs::symlink(&target, disks.join("link")).unwrap();
    let probe = DiskDump {
        dir: disks.join("link"),
        ..DiskDump::default()
    };
    assert!(delete(&probe).is_err());
    assert!(target.join("keep.txt").exists());
}

#[test]
fn sidecars_from_other_versions_still_load() {
    let fixture = Fixture::new();
    let disks = disks_dir(&fixture.root);
    // Unknown fields and a newer image format are tolerated; missing fields
    // take their defaults.
    let dir = disks.join("future");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join(SUMMARY_FILE),
        r#"{"id":"future","finished_ms":9,"format":"qcow2_disk","new_field":{"a":1},
            "source":{"kind":{"kind":"current"},"layers":[{"filename":"disk.qcow2","extra":1}]}}"#,
    )
    .unwrap();
    let listed = list(std::slice::from_ref(&fixture.root));
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].format, DiskImageFormat::Unsupported);
    assert!(listed[0].complete() && !listed[0].browsable());
    assert_eq!(listed[0].source.layers[0].sha256, None);
    assert_eq!(listed[0].fs_state, Ext4State::Unknown);

    // What this version writes is plain JSON with no required fields.
    let dump = dump_in(&fixture, "mine", 7);
    let text = fs::read_to_string(dump.dir.join(SUMMARY_FILE)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["id"], "mine");
    assert!(value.get("dir").is_none());
}

#[test]
fn a_sidecar_cannot_point_a_dump_outside_its_folder() {
    let fixture = Fixture::new();
    let mut dump = dump_in(&fixture, "escape", 1);
    dump.file = PathBuf::from("../../../etc/passwd");
    assert_eq!(dump.path(), dump.dir.join("passwd"));
    dump.file = PathBuf::from("/etc/shadow");
    assert_eq!(dump.path(), dump.dir.join("shadow"));
    dump.file = PathBuf::new();
    assert_eq!(dump.path(), dump.dir.join(IMAGE_FILE));
    // An imported dump is exactly the file it was given.
    dump.imported = true;
    dump.file = PathBuf::from("/data/x.ext4");
    assert_eq!(dump.path(), PathBuf::from("/data/x.ext4"));
}

#[test]
fn completeness_and_missing_files() {
    let fixture = Fixture::new();
    let mut dump = dump_in(&fixture, "state", 1);
    assert!(dump.missing(), "no image written");
    fs::write(dump.path(), b"x").unwrap();
    assert!(!dump.missing() && dump.browsable());
    dump.error = Some("failed".into());
    assert!(!dump.complete() && !dump.browsable() && !dump.missing());
    dump.error = None;
    dump.finished_ms = None;
    assert!(!dump.complete());
}

#[test]
fn leftovers_of_a_cancelled_or_crashed_dump_are_swept() {
    let fixture = Fixture::new();
    let disks = disks_dir(&fixture.root);
    // A crash during conversion, after the rename, and an empty folder.
    for (name, files) in [
        ("crashed-converting", vec![PART_FILE]),
        ("crashed-renamed", vec![IMAGE_FILE]),
        ("crashed-both", vec![IMAGE_FILE, PART_FILE]),
        ("crashed-empty", vec![]),
    ] {
        let dir = disks.join(name);
        fs::create_dir_all(&dir).unwrap();
        for file in files {
            fs::write(dir.join(file), vec![1u8; 4096]).unwrap();
        }
    }
    // Not ours: somebody's folder, scratch views, extractions, finished dumps.
    fs::create_dir_all(disks.join("somebody")).unwrap();
    fs::write(disks.join("somebody/notes.txt"), "keep").unwrap();
    fs::create_dir_all(scratch_dir(&disks, "view")).unwrap();
    fs::write(scratch_dir(&disks, "view").join(PART_FILE), "x").unwrap();
    fs::create_dir_all(disks.join(EXTRACTED_DIR).join("view")).unwrap();
    let finished = dump_in(&fixture, "finished", 9);
    fs::write(finished.dir.join(IMAGE_FILE), b"image").unwrap();
    fs::write(finished.dir.join(PART_FILE), b"stale").unwrap();

    assert_eq!(sweep_partial(&disks), 4);
    for name in [
        "crashed-converting",
        "crashed-renamed",
        "crashed-both",
        "crashed-empty",
    ] {
        assert!(!disks.join(name).exists(), "{name}");
    }
    assert!(disks.join("somebody/notes.txt").exists());
    assert!(scratch_dir(&disks, "view").join(PART_FILE).exists());
    assert!(disks.join(EXTRACTED_DIR).join("view").exists());
    assert!(finished.dir.join(IMAGE_FILE).exists());
    assert!(!finished.dir.join(PART_FILE).exists());
    assert_eq!(list(std::slice::from_ref(&fixture.root)).len(), 1);
    assert_eq!(sweep_partial(&fixture.path("missing")), 0);
}

#[test]
fn sha256_of_a_sparse_image_matches_sha256sum() {
    let fixture = Fixture::new();
    let image = fixture.path("sparse.img");
    let file = fs::File::create(&image).unwrap();
    // 40 MiB logical, three small islands of data.
    file.set_len(40 * 1024 * 1024).unwrap();
    for (offset, byte) in [
        (0u64, 1u8),
        (7 * 1024 * 1024 + 13, 2),
        (39 * 1024 * 1024, 3),
    ] {
        use std::os::unix::fs::FileExt;
        file.write_all_at(&vec![byte; 5000], offset).unwrap();
    }
    drop(file);
    let mut seen = Vec::new();
    let sum = sha256_file(&image, &never(), |done, total| seen.push((done, total))).unwrap();
    let reference = Command::new("sha256sum").arg(&image).output().unwrap();
    let reference = String::from_utf8(reference.stdout).unwrap();
    assert_eq!(sum, reference.split_whitespace().next().unwrap());
    assert_eq!(seen.first(), Some(&(0, 40 * 1024 * 1024)));
    assert_eq!(seen.last(), Some(&(40 * 1024 * 1024, 40 * 1024 * 1024)));
    assert!(seen.windows(2).all(|pair| pair[0].0 <= pair[1].0));
    // The empty file hashes to the well-known digest; a missing one fails.
    let empty = fixture.path("empty");
    fs::write(&empty, b"").unwrap();
    assert_eq!(
        sha256_file(&empty, &never(), |_, _| {}).unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert!(sha256_file(&fixture.path("absent"), &never(), |_, _| {}).is_err());
    // Cancel stops the pass.
    assert_eq!(
        sha256_file(&image, &AtomicBool::new(true), |_, _| {}).unwrap_err(),
        "cancelled"
    );
}

#[test]
fn import_accepts_a_raw_ext4_image_and_leaves_it_in_place() {
    require_tools!();
    let fixture = Fixture::new();
    let tree = fixture.standard_tree("tree");
    let clean = fixture.ext4("clean.ext4", &tree, &[]);
    let forced = fixture.ext4("forced.ext4", &tree, &["ssv state 0"]);
    let recordings = fixture.path("recordings");
    let dump = import(&recordings, "vm-1", "Fixture", &clean).unwrap();
    assert!(dump.imported && dump.complete() && dump.browsable());
    assert_eq!(dump.fs_state, Ext4State::Clean);
    assert_eq!(dump.logical_size, 32 * 1024 * 1024);
    assert_eq!(dump.path(), fs::canonicalize(&clean).unwrap());
    assert_eq!(dump.source.kind, DiskSourceKind::Imported);
    assert_eq!(dump.sha256, None);
    assert_eq!(
        fs::metadata(&dump.dir).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        import(&recordings, "vm-1", "Fixture", &forced)
            .unwrap()
            .fs_state,
        Ext4State::NotClean
    );
    let listed = list(std::slice::from_ref(&recordings));
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|dump| dump.imported));
    // Deleting an imported dump removes the folder, never the image.
    delete(&dump).unwrap();
    assert!(!dump.dir.exists());
    assert!(clean.exists());
    // A relative path and a link resolve to the real file.
    let link = fixture.path("link.ext4");
    std::os::unix::fs::symlink(&clean, &link).unwrap();
    let linked = import(&recordings, "vm-1", "Fixture", &link).unwrap();
    assert_eq!(linked.path(), fs::canonicalize(&clean).unwrap());
}

#[test]
fn import_refuses_what_is_not_a_whole_ext4_image() {
    require_tools!();
    let fixture = Fixture::new();
    let tree = fixture.standard_tree("tree");
    let good = fixture.ext4("good.ext4", &tree, &[]);
    let recordings = fixture.path("recordings");
    let refuse = |path: &Path| import(&recordings, "vm-1", "Fixture", path).unwrap_err();

    // Not ext4: zeros, text, an empty file, a tiny file.
    let zeros = fixture.path("zeros.img");
    fs::write(&zeros, vec![0u8; 4 * 1024 * 1024]).unwrap();
    assert!(refuse(&zeros).contains("ext2/3/4"), "{}", refuse(&zeros));
    let text = fixture.path("text.img");
    fs::write(&text, "hello ".repeat(2000)).unwrap();
    assert!(refuse(&text).contains("ext2/3/4"));
    let empty = fixture.path("empty.img");
    fs::write(&empty, b"").unwrap();
    assert!(refuse(&empty).contains("too small"));
    let tiny = fixture.path("tiny.img");
    fs::write(&tiny, vec![0xEF; 1500]).unwrap();
    assert!(refuse(&tiny).contains("too small"));

    // Truncated: the first 10 MiB of a 32 MiB filesystem.
    let truncated = fixture.path("truncated.ext4");
    let bytes = fs::read(&good).unwrap();
    fs::write(&truncated, &bytes[..10 * 1024 * 1024]).unwrap();
    let error = refuse(&truncated);
    assert!(error.contains("cut short"), "{error}");
    // A superblock cut inside itself.
    let cut = fixture.path("cut.ext4");
    fs::write(&cut, &bytes[..1500]).unwrap();
    assert!(refuse(&cut).contains("too small"));

    // A corrupt superblock: an absurd block size, zero blocks.
    let mut absurd = bytes[..4 * 1024 * 1024].to_vec();
    absurd[1024 + 0x18..1024 + 0x1C].copy_from_slice(&40u32.to_le_bytes());
    let absurd_path = fixture.path("absurd.ext4");
    fs::write(&absurd_path, &absurd).unwrap();
    assert!(refuse(&absurd_path).contains("block size"));
    let mut none = bytes[..4 * 1024 * 1024].to_vec();
    none[1024 + 0x04..1024 + 0x08].copy_from_slice(&0u32.to_le_bytes());
    let none_path = fixture.path("none.ext4");
    fs::write(&none_path, &none).unwrap();
    assert!(refuse(&none_path).contains("no blocks"));

    // A qcow2 image is named as such.
    let qcow = fixture.path("disk.qcow2");
    assert!(
        Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&good)
            .arg(&qcow)
            .status()
            .unwrap()
            .success()
    );
    assert!(refuse(&qcow).contains("qcow2"));
    // A partitioned disk (boot signature, no filesystem at its start).
    let mut mbr = vec![0u8; 4 * 1024 * 1024];
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    let mbr_path = fixture.path("mbr.img");
    fs::write(&mbr_path, &mbr).unwrap();
    assert!(refuse(&mbr_path).contains("partitioned"));

    // A folder, a missing file, a fifo.
    assert!(refuse(&fixture.root).contains("not a regular file"));
    assert!(refuse(&fixture.path("absent.img")).contains("absent.img"));
    let fifo = fixture.path("fifo");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(refuse(&fifo).contains("not a regular file"));

    // Nothing was recorded for any refusal.
    assert!(list(&[recordings]).is_empty());
}

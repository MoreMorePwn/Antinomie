// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::file_before::{Before, DiskFile};
use std::sync::Arc;

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-before-store-{name}-{}",
        crate::storage::unique_id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A boot folder holding one copied file, written the way [`Writer`] does:
/// the recording's own copy serves as the "disk" the next copy reads from.
fn holding(dir: &Path, path: &str, bytes: &[u8]) {
    let mut index = Index::new("b", Limits::default());
    std::fs::create_dir_all(dir.join(DIR)).unwrap();
    std::fs::write(dir.join(DIR).join("000000"), bytes).unwrap();
    index.copied_bytes = bytes.len() as u64;
    index.files.push(Entry {
        path: path.into(),
        names: vec![],
        key: Some(Key {
            dev: 1,
            ino: 2,
            generation: 3,
        }),
        exact: true,
        size: bytes.len() as u64,
        sha256: Some(crate::storage::sha256_hex(bytes)),
        status: Status::Copied,
        blob: Some("000000".into()),
    });
    index.complete = true;
    index.save(dir).unwrap();
}

fn key(ino: u64) -> FileKey {
    FileKey {
        dev: 1,
        ino,
        generation: 3,
    }
}

#[test]
fn a_copied_file_reads_back_by_path_and_identity() {
    let dir = scratch("read");
    holding(&dir, "/etc/passwd", b"root:x:0:0\n");
    let store = Store::open(&dir).unwrap();
    assert_eq!(
        store.find("/etc/passwd", Some(key(2))),
        Some(Before::Recorded {
            size: 11,
            exact: true
        })
    );
    // No identity: the path alone matches. Another inode: another file.
    assert!(store.find("/etc/passwd", None).is_some());
    assert!(store.find("/etc/passwd", Some(key(9))).is_none());
    assert!(store.find("/etc/shadow", None).is_none());
    assert_eq!(store.read("/etc/passwd", 0, 100).unwrap(), b"root:x:0:0\n");
    assert_eq!(store.read("/etc/passwd", 5, 3).unwrap(), b"x:0");
    assert_eq!(store.read("/etc/passwd", 11, 4).unwrap(), b"");
    assert!(store.read("/etc/shadow", 0, 1).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn files_within_the_caps_are_copied_and_the_rest_keep_size_and_hash() {
    let from = scratch("from");
    holding(&from, "/a", &[1u8; 100]);
    let disk = StartDisk::recorded(&from).unwrap();
    let to = scratch("to");
    let mut writer = Writer::open(
        &to,
        "b",
        Limits {
            per_file: 150,
            per_run: 120,
        },
    );
    let file = |path: &str| DiskFile {
        disk: Arc::clone(&disk),
        path: path.into(),
    };
    let on_disk = Before::OnDisk {
        size: 100,
        exact: true,
    };
    // First fits both caps.
    writer.record("/a", &[], Some(key(2)), &on_disk, Some(&file("/a")));
    // The same file again is not copied twice.
    writer.record("/a", &[], Some(key(2)), &on_disk, Some(&file("/a")));
    // The per-run cap is reached: 100 + 100 > 120.
    writer.record("/b", &["/b2".into()], None, &on_disk, Some(&file("/a")));
    // Over the per-file cap.
    let big = Before::OnDisk {
        size: 200,
        exact: false,
    };
    writer.record("/c", &[], None, &big, Some(&file("/a")));
    writer.record("/d", &[], None, &Before::Elsewhere("tmpfs".into()), None);
    writer.record("/e", &[], None, &Before::Unavailable("gone".into()), None);
    writer.record("/f", &[], None, &Before::TooLarge(5 << 30), None);
    writer.record("/g", &[], None, &Before::Created, None);
    writer.record("/g", &[], None, &Before::Created, None);
    writer.finish(true, None).unwrap();

    let index = Index::load(&to).unwrap();
    assert!(index.complete);
    assert_eq!(index.copied_bytes, 100);
    assert_eq!(index.files.len(), 7, "{:?}", index.files);
    let store = Store::open(&to).unwrap();
    assert_eq!(
        store.find("/a", None),
        Some(Before::Recorded {
            size: 100,
            exact: true
        })
    );
    assert_eq!(store.read("/a", 0, 1000).unwrap(), vec![1u8; 100]);
    let sha = crate::storage::sha256_hex(&[1u8; 100]);
    // Reading is bounded by the file's size, whatever the disk says.
    match store.find("/b2", None) {
        Some(Before::NotCopied { size, sha256, why }) => {
            assert_eq!(size, 100);
            assert_eq!(sha256.as_deref(), Some(sha.as_str()));
            assert!(why.contains("per-run cap"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    match store.find("/c", None) {
        Some(Before::NotCopied { size: 200, why, .. }) => assert!(why.contains("per-file cap")),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        store.find("/d", None),
        Some(Before::Elsewhere("tmpfs".into()))
    );
    assert_eq!(
        store.find("/e", None),
        Some(Before::Unavailable("gone".into()))
    );
    assert!(
        matches!(store.find("/f", None), Some(Before::NotCopied { size, sha256: None, .. }) if size == 5 << 30)
    );
    assert_eq!(store.find("/g", None), Some(Before::Created));
    assert!(store.read("/b", 0, 1).is_err(), "nothing was copied for it");
    // A second pass over the same boot keeps what is there.
    let mut again = Writer::open(&to, "b", Limits::default());
    assert!(again.has("/a", None));
    assert!(!again.has("/zzz", None));
    let _ = (
        &mut again,
        std::fs::remove_dir_all(from),
        std::fs::remove_dir_all(to),
    );
}

#[test]
fn a_copy_that_did_not_happen_is_said_in_the_recording() {
    let dir = scratch("note");
    note_not_copied(&dir, "b9", "the VM was started again first");
    let index = Index::load(&dir).unwrap();
    assert!(!index.complete);
    assert_eq!(index.boot_id, "b9");
    assert!(index.note.unwrap().contains("started again first"));
    // A complete copy is not downgraded by an empty reason.
    holding(&dir, "/x", b"x");
    note_not_copied(&dir, "b", "");
    assert!(Index::load(&dir).unwrap().complete);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_blob_name_cannot_leave_the_folder() {
    let dir = scratch("evil");
    holding(&dir, "/x", b"x");
    let mut index = Index::load(&dir).unwrap();
    index.files[0].blob = Some("../../etc/passwd".into());
    index.save(&dir).unwrap();
    assert!(Store::open(&dir).unwrap().read("/x", 0, 1).is_err());
    let _ = std::fs::remove_dir_all(dir);
}

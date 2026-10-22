// SPDX-License-Identifier: GPL-3.0-only
use super::{image::Image, *};
use crate::disks::{
    Ext4State,
    fixture::{Fixture, require_tools},
    read_state,
};
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

struct Opened {
    fixture: Fixture,
    image: Image,
    path: PathBuf,
    out: PathBuf,
}

fn open_with(build: impl FnOnce(&Fixture) -> PathBuf) -> Opened {
    let fixture = Fixture::new();
    let path = build(&fixture);
    let out = fixture.path("out");
    fs::create_dir(&out).unwrap();
    Opened {
        image: Image::open(&path, &out),
        fixture,
        path,
        out,
    }
}

fn open() -> Opened {
    open_with(|fixture| fixture.standard_image())
}

fn list(opened: &Opened, path: &str, offset: usize) -> Result<DiskListing, ReadError> {
    match opened.image.handle(
        1,
        DiskRequest::List {
            path: path.into(),
            offset,
        },
    )? {
        DiskAnswer::Listed(listing) => Ok(listing),
        other => panic!("{other:?}"),
    }
}

fn info(opened: &Opened, path: &str, hash_cap: u64) -> Result<DiskFileInfo, ReadError> {
    match opened.image.handle(
        2,
        DiskRequest::Info {
            path: path.into(),
            hash_cap,
        },
    )? {
        DiskAnswer::Info(info) => Ok(info),
        other => panic!("{other:?}"),
    }
}

fn find(opened: &Opened, pattern: &str, mode: FindMode) -> FindResults {
    match opened
        .image
        .handle(
            3,
            DiskRequest::Find {
                query: FindQuery {
                    pattern: pattern.into(),
                    mode,
                },
            },
        )
        .unwrap()
    {
        DiskAnswer::Found(found) => found,
        other => panic!("{other:?}"),
    }
}

fn extract(
    opened: &Opened,
    id: u64,
    path: &str,
    max_len: u64,
) -> Result<ExtractReceipt, ReadError> {
    match opened.image.handle(
        id,
        DiskRequest::Extract {
            path: path.into(),
            max_len,
        },
    )? {
        DiskAnswer::Extracted(receipt) => Ok(receipt),
        other => panic!("{other:?}"),
    }
}

fn entry<'a>(listing: &'a DiskListing, name: &str) -> &'a DiskEntry {
    listing
        .entries
        .iter()
        .find(|entry| entry.name == name)
        .unwrap_or_else(|| panic!("{name} in {:?}", listing.entries))
}

#[test]
fn the_root_lists_directories_first_with_kinds_modes_and_owners() {
    require_tools!();
    let opened = open();
    let root = list(&opened, "/", 0).unwrap();
    let names: Vec<_> = root
        .entries
        .iter()
        .map(|entry| entry.name.as_str())
        .collect();
    let first_file = root
        .entries
        .iter()
        .position(|entry| entry.kind != DiskEntryKind::Dir)
        .unwrap();
    assert!(
        root.entries[..first_file]
            .iter()
            .all(|e| e.kind == DiskEntryKind::Dir)
    );
    assert!(names.contains(&"etc") && names.contains(&"lost+found"));
    assert!(!names.contains(&".") && !names.contains(&".."));
    assert_eq!(entry(&root, "fifo").kind, DiskEntryKind::Fifo);
    assert_eq!(entry(&root, "fifo").size, 0);
    assert_eq!(entry(&root, "null").kind, DiskEntryKind::CharDev);

    let home = list(&opened, "/home", 0).unwrap();
    let user = entry(&home, "user");
    assert_eq!(
        (user.kind, user.uid, user.gid),
        (DiskEntryKind::Dir, 1000, 1000)
    );

    let user_files = list(&opened, "/home/user", 0).unwrap();
    assert_eq!(entry(&user_files, ".hidden").uid, 1000);
    let notes = entry(&user_files, "notes.txt");
    assert_eq!(
        (notes.kind, notes.size, notes.mode),
        (DiskEntryKind::File, 18, 0o644)
    );

    let bin = list(&opened, "/bin", 0).unwrap();
    assert_eq!(entry(&bin, "busybox").mode, 0o755);
}

#[test]
fn symlinks_are_shown_with_their_target_and_never_followed() {
    require_tools!();
    let opened = open();
    let etc = list(&opened, "/etc", 0).unwrap();
    let dangling = entry(&etc, "shadow-link");
    assert_eq!(dangling.kind, DiskEntryKind::Symlink);
    assert_eq!(dangling.link_target.as_deref(), Some("/etc/shadow"));
    let looping = entry(&etc, "loop");
    assert_eq!(looping.link_target.as_deref(), Some("/etc"));
    // A link to a directory cannot be listed, and a path through it is refused.
    assert!(matches!(
        list(&opened, "/etc/loop", 0),
        Err(ReadError::Io(_))
    ));
    assert!(matches!(
        list(&opened, "/etc/loop/loop", 0),
        Err(ReadError::Io(_))
    ));
    assert!(matches!(
        info(&opened, "/etc/loop/passwd", 1 << 20),
        Err(ReadError::Io(_))
    ));
    // Details of the link itself, not of its target.
    let details = info(&opened, "/etc/shadow-link", 1 << 20).unwrap();
    assert_eq!(details.entry.kind, DiskEntryKind::Symlink);
    assert!(details.sha256.is_none());
}

#[test]
fn odd_names_are_marked_unaddressable_and_paths_are_checked() {
    require_tools!();
    let opened = open();
    let tmp = list(&opened, "/tmp", 0).unwrap();
    let bad = tmp
        .entries
        .iter()
        .find(|entry| entry.name.starts_with("bad"))
        .unwrap();
    assert!(!bad.addressable && bad.name.contains('\u{fffd}'));
    assert!(entry(&tmp, "new\nline").addressable);
    for path in [
        "etc",
        "/etc/../etc",
        "/a\0b",
        &format!("/{}", "x".repeat(5000)),
    ] {
        assert!(
            matches!(list(&opened, path, 0), Err(ReadError::Io(_))),
            "{path:?}"
        );
    }
    assert!(matches!(
        list(&opened, "/nope", 0),
        Err(ReadError::NotFound)
    ));
    assert!(matches!(
        list(&opened, "/etc/passwd", 0),
        Err(ReadError::Io(_))
    ));
    // `.` components are harmless and normalized.
    assert_eq!(list(&opened, "//etc/./", 0).unwrap().path, "/etc");
}

#[test]
fn listings_page_at_256_entries() {
    require_tools!();
    let opened = open_with(|fixture| {
        let tree = fixture.standard_tree("tree");
        fs::create_dir(tree.join("many")).unwrap();
        for index in 0..300 {
            fs::write(tree.join(format!("many/f{index:03}")), "").unwrap();
        }
        fixture.ext4("many.ext4", &tree, &[])
    });
    let first = list(&opened, "/many", 0).unwrap();
    assert_eq!((first.entries.len(), first.more), (PAGE_LEN, true));
    let second = list(&opened, "/many", PAGE_LEN).unwrap();
    assert_eq!((second.entries.len(), second.more), (44, false));
    assert_eq!(first.entries[0].name, "f000");
    assert_eq!(second.entries[0].name, "f256");
}

#[test]
fn info_hashes_small_files_and_notes_the_cap() {
    require_tools!();
    let opened = open();
    let details = info(&opened, "/bin/busybox", 1 << 20).unwrap();
    assert!(details.elf);
    let content = fs::read(opened.fixture.path("tree/bin/busybox")).unwrap();
    assert_eq!(
        details.sha256.unwrap(),
        format!("{:x}", Sha256::digest(&content))
    );
    assert!(details.md5.is_some());
    let capped = info(&opened, "/lib/libc.so.6", 100).unwrap();
    assert!(capped.sha256.is_none() && capped.hash_note.unwrap().contains("not hashed"));
    assert!(!capped.elf);
    let directory = info(&opened, "/home", 100).unwrap();
    assert_eq!(directory.entry.kind, DiskEntryKind::Dir);
}

#[test]
fn extraction_writes_a_private_file_and_enforces_the_cap() {
    require_tools!();
    let opened = open();
    let receipt = extract(&opened, 7, "/bin/busybox", 1 << 20).unwrap();
    let written = opened.out.join("7");
    let content = fs::read(opened.fixture.path("tree/bin/busybox")).unwrap();
    assert_eq!(fs::read(&written).unwrap(), content);
    assert_eq!(receipt.size, content.len() as u64);
    assert_eq!(receipt.sha256, format!("{:x}", Sha256::digest(&content)));
    // Private and never executable, whatever the guest mode was.
    assert_eq!(
        fs::metadata(&written).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // Over the cap: refused, nothing left behind.
    assert!(matches!(
        extract(&opened, 8, "/lib/libc.so.6", 100),
        Err(ReadError::Limit(_))
    ));
    assert!(!opened.out.join("8").exists());
    // A directory and a special file are not extracted.
    assert!(extract(&opened, 9, "/home", 1 << 20).is_err());
    assert!(extract(&opened, 10, "/fifo", 1 << 20).is_err());
    assert!(!opened.out.join("9").exists() && !opened.out.join("10").exists());
    // A link extracts its target as data, never the file it points to.
    extract(&opened, 11, "/etc/shadow-link", 1 << 20).unwrap();
    assert_eq!(
        fs::read_to_string(opened.out.join("11")).unwrap(),
        "/etc/shadow"
    );
    // The same request id cannot overwrite an earlier extraction.
    assert!(extract(&opened, 7, "/etc/passwd", 1 << 20).is_err());
    assert_eq!(fs::read(&written).unwrap(), content);
}

#[test]
fn a_file_of_sixteen_exabytes_is_refused_not_read() {
    require_tools!();
    let opened = open_with(|fixture| {
        let tree = fixture.standard_tree("tree");
        fixture.ext4(
            "huge.ext4",
            &tree,
            &["sif /home/user/notes.txt size 0xfffffffffffff000"],
        )
    });
    // ext4-view refuses an inode that claims more blocks than exist: an error,
    // never a read of 16 EiB.
    let described = info(&opened, "/home/user/notes.txt", 64 * 1024 * 1024);
    assert!(
        matches!(&described, Err(ReadError::Corrupt(_) | ReadError::Limit(_)))
            || described
                .as_ref()
                .is_ok_and(|details| details.sha256.is_none()),
        "{described:?}"
    );
    let extracted = extract(&opened, 1, "/home/user/notes.txt", 256 * 1024 * 1024);
    assert!(
        matches!(extracted, Err(ReadError::Corrupt(_) | ReadError::Limit(_))),
        "{extracted:?}"
    );
    assert!(!opened.out.join("1").exists());
    // The rest of the tree still reads.
    assert!(list(&opened, "/home/user", 0).is_ok() || list(&opened, "/", 0).is_ok());
}

#[test]
fn find_matches_names_paths_and_globs() {
    require_tools!();
    let opened = open();
    let by_name = find(&opened, "BUSY", FindMode::Name);
    assert_eq!(by_name.matches.len(), 1);
    assert_eq!(by_name.matches[0].path, "/bin/busybox");
    assert_eq!(by_name.matches[0].kind, DiskEntryKind::File);
    let by_path = find(&opened, "var/log", FindMode::Path);
    assert!(
        by_path
            .matches
            .iter()
            .any(|m| m.path == "/var/log/messages.log")
    );
    let globbed = find(&opened, "*.so*", FindMode::Glob);
    assert_eq!(
        globbed
            .matches
            .iter()
            .map(|m| m.path.as_str())
            .collect::<Vec<_>>(),
        ["/lib/libc.so.6"]
    );
    let rooted = find(&opened, "/etc/*", FindMode::Glob);
    assert!(rooted.matches.iter().any(|m| m.path == "/etc/passwd"));
    assert!(
        find(&opened, "no-such-file", FindMode::Name)
            .matches
            .is_empty()
    );
    // A link is listed but its directory target is not descended: one `loop`.
    assert_eq!(find(&opened, "loop", FindMode::Name).matches.len(), 1);
    assert!(!by_name.truncated && !by_name.timed_out && by_name.scanned > 10);
}

#[test]
fn a_directory_cycle_ends_the_walk() {
    require_tools!();
    // `/a/loop` is a hard link to `/a`: a cycle in the directory tree.
    let opened = open_with(|fixture| {
        let tree = fixture.standard_tree("tree");
        fixture.ext4("cycle.ext4", &tree, &["ln /a /a/loop"])
    });
    let found = find(&opened, "deep.txt", FindMode::Name);
    // The walk is bounded by depth; it ends and finds the real one.
    assert!(found.matches.iter().any(|m| m.path == "/a/b/deep.txt"));
    assert!(found.scanned < 10_000, "scanned {}", found.scanned);
    assert!(!found.timed_out);
}

#[test]
fn a_forced_off_image_is_not_clean_and_its_journal_is_applied() {
    require_tools!();
    let fixture = Fixture::new();
    let tree = fixture.standard_tree("tree");
    let forced = fixture.ext4("forced.ext4", &tree, &[]);
    assert_eq!(read_state(&forced).unwrap(), Ext4State::Clean);

    // Commit a transaction that replaces the data block of /etc/passwd
    // without replaying it, and mark the filesystem not cleanly unmounted:
    // what a forced stop leaves behind.
    let block = fixture.first_block(&forced, "/etc/passwd");
    let mut content = b"committed-in-the-journal\n".to_vec();
    content.resize(4096, 0);
    let replacement = fixture.path("replacement.blk");
    fs::write(&replacement, &content).unwrap();
    fixture.debugfs(
        &forced,
        &[
            "jo -c".into(),
            format!("jw -b {block} {}", replacement.display()),
            "jc".into(),
            "ssv state 0".into(),
        ],
    );
    assert_eq!(read_state(&forced).unwrap(), Ext4State::NotClean);
    // On disk the block is still the old content.
    let raw = fs::read(&forced).unwrap();
    let start = block as usize * 4096;
    assert!(raw[start..].starts_with(b"root:x"));

    let out = fixture.path("out");
    fs::create_dir(&out).unwrap();
    let opened = Image::open(&forced, &out);
    let DiskAnswer::Probed(probe) = opened.handle(1, DiskRequest::Probe).unwrap() else {
        panic!()
    };
    assert_eq!(probe.fs_state, Ext4State::NotClean);
    assert_eq!(probe.label, "fixture");
    // The reader applies the committed transaction in memory.
    let receipt = match opened
        .handle(
            2,
            DiskRequest::Extract {
                path: "/etc/passwd".into(),
                max_len: 1 << 20,
            },
        )
        .unwrap()
    {
        DiskAnswer::Extracted(receipt) => receipt,
        other => panic!("{other:?}"),
    };
    assert_eq!(receipt.size, 30);
    assert!(
        fs::read(out.join("2"))
            .unwrap()
            .starts_with(b"committed-in-the-journal\n")
    );
    // And the image on disk is untouched.
    assert_eq!(fs::read(&forced).unwrap(), raw);
}

#[test]
fn an_image_that_is_not_ext4_answers_errors_without_panicking() {
    let fixture = Fixture::new();
    let out = fixture.path("out");
    fs::create_dir(&out).unwrap();
    let cases: [(&str, Vec<u8>); 4] = [
        ("empty", Vec::new()),
        ("zeros", vec![0; 64 * 1024]),
        (
            "noise",
            (0..200_000u32)
                .map(|n| (n.wrapping_mul(2_654_435_761) >> 13) as u8)
                .collect(),
        ),
        ("ntfs", {
            let mut data = vec![0; 64 * 1024];
            data[3..11].copy_from_slice(b"NTFS    ");
            data
        }),
    ];
    for (name, data) in cases {
        let path = fixture.path(name);
        fs::write(&path, data).unwrap();
        assert!(read_state(&path).is_err() || name == "noise");
        let image = Image::open(&path, &out);
        for request in [
            DiskRequest::Probe,
            DiskRequest::List {
                path: "/".into(),
                offset: 0,
            },
            DiskRequest::Find {
                query: FindQuery {
                    pattern: "a".into(),
                    mode: FindMode::Name,
                },
            },
        ] {
            let reply = image.handle(1, request);
            assert!(
                matches!(
                    reply,
                    Err(ReadError::Unsupported(_) | ReadError::Corrupt(_) | ReadError::Io(_))
                ),
                "{name}: {reply:?}"
            );
        }
    }
}

#[test]
fn a_truncated_or_damaged_ext4_image_is_reported_not_fatal() {
    require_tools!();
    let fixture = Fixture::new();
    let image = fixture.standard_image();
    let bytes = fs::read(&image).unwrap();
    let out = fixture.path("out");
    fs::create_dir(&out).unwrap();
    // Cut short after the metadata, and with the root directory's blocks wiped.
    let truncated = fixture.path("truncated.ext4");
    fs::write(&truncated, &bytes[..64 * 1024]).unwrap();
    let damaged = fixture.path("damaged.ext4");
    let mut wiped = bytes.clone();
    for byte in &mut wiped[1024 * 1024..4 * 1024 * 1024] {
        *byte = 0xA5;
    }
    fs::write(&damaged, wiped).unwrap();
    for path in [truncated, damaged] {
        let opened = Image::open(&path, &out);
        for request in [
            DiskRequest::List {
                path: "/".into(),
                offset: 0,
            },
            DiskRequest::List {
                path: "/etc".into(),
                offset: 0,
            },
            DiskRequest::Info {
                path: "/etc/passwd".into(),
                hash_cap: 1 << 20,
            },
            DiskRequest::Extract {
                path: "/etc/passwd".into(),
                max_len: 1 << 20,
            },
            DiskRequest::Find {
                query: FindQuery {
                    pattern: "a".into(),
                    mode: FindMode::Name,
                },
            },
        ] {
            // Either an answer or a typed error: never a panic.
            let _ = opened.handle(5, request);
        }
    }
}

#[test]
fn the_line_protocol_answers_requests_and_rejects_bad_ones() {
    require_tools!();
    let opened = open();
    let mut input = Vec::new();
    for (id, request) in [
        (1, DiskRequest::Probe),
        (
            2,
            DiskRequest::List {
                path: "/etc".into(),
                offset: 0,
            },
        ),
    ] {
        input.extend(serde_json::to_vec(&Envelope { id, body: request }).unwrap());
        input.push(b'\n');
    }
    input.extend(b"{\"not\":\"a request\"}\n");
    let mut output = Vec::new();
    serve::serve(&opened.image, input.as_slice(), &mut output).unwrap();
    let answers: Vec<Envelope<Reply>> = output
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).unwrap())
        .collect();
    assert_eq!(answers.len(), 3);
    assert!(matches!(&answers[0].body, Ok(DiskAnswer::Probed(_))) && answers[0].id == 1);
    assert!(matches!(&answers[1].body, Ok(DiskAnswer::Listed(_))) && answers[1].id == 2);
    assert!(matches!(&answers[2].body, Err(ReadError::Io(text)) if text.contains("bad request")));
    // An unterminated (oversized) request line ends the loop with an error.
    let long = vec![b'x'; 70_000];
    assert!(serve::serve(&opened.image, long.as_slice(), Vec::new()).is_err());
    let _ = &opened.path;
}

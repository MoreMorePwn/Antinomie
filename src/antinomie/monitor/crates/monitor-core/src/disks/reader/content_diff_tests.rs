// SPDX-License-Identifier: GPL-3.0-only
//! Content search and image comparison in the reader.
use super::{
    content::{self, Limits as FindLimits},
    diff::Limits as DiffLimits,
    image::Image,
    *,
};
use crate::disks::fixture::{Fixture, require_tools};
use std::{fs, path::Path};

fn query(pattern: &str, mode: FindMode) -> FindQuery {
    FindQuery {
        pattern: pattern.into(),
        mode,
    }
}

fn opened(fixture: &Fixture, image: &Path) -> Image {
    let out = fixture.path("out");
    let _ = fs::create_dir(&out);
    Image::open(image, &out)
}

/// A standard image plus whatever `extra` adds to the tree first.
fn image_with(fixture: &Fixture, extra: impl FnOnce(&Path)) -> std::path::PathBuf {
    let tree = fixture.standard_tree("tree");
    extra(&tree);
    fixture.ext4("content.ext4", &tree, &[])
}

#[test]
fn content_find_reports_the_offset_and_a_clean_snippet() {
    require_tools!();
    let fixture = Fixture::new();
    let image = opened(&fixture, &fixture.standard_image());
    let found = match image
        .handle(
            1,
            DiskRequest::Find {
                query: query("the milk", FindMode::Content),
            },
        )
        .unwrap()
    {
        DiskAnswer::Found(found) => found,
        other => panic!("{other:?}"),
    };
    assert_eq!(found.matches.len(), 1, "{found:?}");
    let hit = &found.matches[0];
    assert_eq!(hit.path, "/home/user/notes.txt");
    assert_eq!(hit.offset, Some(9));
    let snippet = hit.snippet.as_deref().unwrap();
    assert!(snippet.contains("remember the milk"), "{snippet}");
    assert!(found.files_read > 3 && found.bytes_read > 0);
    // Exact bytes unless asked for any case.
    let miss = image
        .find_limited(query("THE MILK", FindMode::Content), FindLimits::default())
        .unwrap();
    assert!(miss.matches.is_empty());
    let any_case = image
        .find_limited(
            query("THE MILK", FindMode::ContentAnyCase),
            FindLimits::default(),
        )
        .unwrap();
    assert_eq!(any_case.matches.len(), 1);
    // A binary file: the snippet has no control characters.
    let binary = image
        .find_limited(query("\x7fELF", FindMode::Content), FindLimits::default())
        .unwrap();
    assert!(
        binary
            .matches
            .iter()
            .any(|hit| hit.path == "/bin/busybox" && hit.offset == Some(0))
    );
    assert!(binary.matches.iter().all(|hit| {
        hit.snippet
            .as_deref()
            .unwrap()
            .chars()
            .all(|c| !c.is_control())
    }));
}

#[test]
fn a_hit_that_spans_a_read_boundary_is_found() {
    require_tools!();
    let fixture = Fixture::new();
    let boundary = 64 * 1024;
    let image = image_with(&fixture, |tree| {
        let mut bytes = vec![b'.'; boundary - 3];
        bytes.extend_from_slice(b"NEEDLE-ACROSS");
        bytes.extend(vec![b'.'; 1000]);
        fs::write(tree.join("etc/spans.bin"), bytes).unwrap();
    });
    let image = opened(&fixture, &image);
    let found = image
        .find_limited(
            query("NEEDLE-ACROSS", FindMode::Content),
            FindLimits::default(),
        )
        .unwrap();
    assert_eq!(found.matches.len(), 1, "{found:?}");
    assert_eq!(found.matches[0].path, "/etc/spans.bin");
    assert_eq!(found.matches[0].offset, Some(boundary as u64 - 3));
}

#[test]
fn content_search_stops_at_its_limits_and_says_so() {
    require_tools!();
    let fixture = Fixture::new();
    let image = image_with(&fixture, |tree| {
        // Needles at 1 KiB and at 3 MiB of a 4 MiB sparse file.
        let file = fs::File::create(tree.join("etc/big.bin")).unwrap();
        file.set_len(4 * 1024 * 1024).unwrap();
        use std::os::unix::fs::FileExt;
        file.write_all_at(b"EARLY-HIT", 1024).unwrap();
        file.write_all_at(b"LATE-HIT", 3 * 1024 * 1024).unwrap();
    });
    let image = opened(&fixture, &image);
    let per_file = FindLimits {
        per_file: 1024 * 1024,
        ..FindLimits::default()
    };
    let early = image
        .find_limited(query("EARLY-HIT", FindMode::Content), per_file)
        .unwrap();
    assert_eq!(early.matches.len(), 1);
    // Past the per-file cap: not found, and the file is reported as partial.
    let late = image
        .find_limited(query("LATE-HIT", FindMode::Content), per_file)
        .unwrap();
    assert!(late.matches.is_empty());
    assert_eq!(late.partial_files, 1);
    let uncapped = image
        .find_limited(query("LATE-HIT", FindMode::Content), FindLimits::default())
        .unwrap();
    assert_eq!(uncapped.matches.len(), 1);
    assert_eq!(uncapped.partial_files, 0);
    // The total byte limit ends the whole search.
    let total = image
        .find_limited(
            query("never-present-text", FindMode::Content),
            FindLimits {
                total: 100 * 1024,
                ..FindLimits::default()
            },
        )
        .unwrap();
    assert!(total.byte_limit_reached, "{total:?}");
    assert!(total.bytes_read <= 100 * 1024);
    // The time budget too.
    let timed = image
        .find_limited(
            query("never-present-text", FindMode::Content),
            FindLimits {
                seconds: Some(0),
                ..FindLimits::default()
            },
        )
        .unwrap();
    assert!(timed.timed_out);
}

#[test]
fn content_search_text_must_be_two_to_256_bytes() {
    require_tools!();
    let fixture = Fixture::new();
    let image = opened(&fixture, &fixture.standard_image());
    for pattern in ["a".to_string(), "x".repeat(257), String::new()] {
        let error = image
            .handle(
                1,
                DiskRequest::Find {
                    query: query(&pattern, FindMode::Content),
                },
            )
            .unwrap_err();
        assert!(matches!(error, ReadError::Limit(_)), "{error:?}");
    }
    // Name search keeps accepting short patterns.
    assert!(
        image
            .handle(
                1,
                DiskRequest::Find {
                    query: query("e", FindMode::Name),
                },
            )
            .is_ok()
    );
}

#[test]
fn byte_search_handles_edges() {
    assert_eq!(content::find_bytes(b"abc", b"abc", false), Some(0));
    assert_eq!(content::find_bytes(b"abc", b"abcd", false), None);
    assert_eq!(content::find_bytes(b"xxabxab", b"xab", false), Some(1));
    assert_eq!(content::find_bytes(b"xxABc", b"abc", true), Some(2));
    assert_eq!(content::find_bytes(b"", b"a", false), None);
    assert_eq!(content::find_bytes(b"aaaa", b"aab", false), None);
}

// --- diff -----------------------------------------------------------------

const EPOCH: i64 = 1_000_000_000;

/// Two images: `before` is the standard tree, `after` has had files added,
/// deleted, changed, touched, chmod-ed, renamed and re-typed.
fn pair(fixture: &Fixture) -> (std::path::PathBuf, std::path::PathBuf) {
    use std::os::unix::fs::symlink;
    let t1 = fixture.standard_tree("before-tree");
    fixture.stamp_tree(&t1, EPOCH);
    let before = fixture.ext4("before.ext4", &t1, &[]);
    let t2 = fixture.standard_tree("after-tree");
    fixture.stamp_tree(&t2, EPOCH);
    let later = std::time::UNIX_EPOCH + std::time::Duration::from_secs(EPOCH as u64 + 5000);
    let touch = |path: &Path| {
        fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(later)
            .unwrap();
    };
    // Added: a file, and a directory with files.
    fs::write(t2.join("etc/new-file"), "new\n").unwrap();
    fs::create_dir_all(t2.join("opt/tool")).unwrap();
    fs::write(t2.join("opt/tool/run"), "#!/bin/sh\n").unwrap();
    fs::write(t2.join("opt/tool/data"), "d").unwrap();
    // Deleted: a file, and a directory with its file.
    fs::remove_file(t2.join("home/user/notes.txt")).unwrap();
    fs::remove_dir_all(t2.join("a/b")).unwrap();
    // Changed size.
    fs::write(
        t2.join("etc/passwd"),
        "root:x:0:0:root:/root:/bin/sh\nmallory:x:0:0\n",
    )
    .unwrap();
    // Same size, different bytes, later time: content.
    fs::write(t2.join("var/log/messages.log"), "boot XX\n").unwrap();
    touch(&t2.join("var/log/messages.log"));
    // Only the time.
    touch(&t2.join("lib/libc.so.6"));
    // Renamed: shown as a deletion and an addition.
    fs::rename(t2.join("home/user/.hidden"), t2.join("home/user/.hidden2")).unwrap();
    // A link that points elsewhere, and a link that became a file.
    fs::remove_file(t2.join("etc/shadow-link")).unwrap();
    symlink("/etc/other", t2.join("etc/shadow-link")).unwrap();
    fs::remove_file(t2.join("etc/loop")).unwrap();
    fs::write(t2.join("etc/loop"), "no longer a link").unwrap();
    // Everything the changes above touched is at a later time, except the
    // directories, whose own times are not compared.
    let after = fixture.ext4("after.ext4", &t2, &["sif /bin/busybox mode 0100700"]);
    (before, after)
}

fn compare(fixture: &Fixture, before: &Path, after: &Path) -> Image {
    let out = fixture.path("out");
    let _ = fs::create_dir(&out);
    Image::open_with(after, Some(before), &out)
}

fn status<'a>(results: &'a DiffResults, path: &str) -> Option<&'a DiffEntry> {
    results.entries.iter().find(|entry| entry.path == path)
}

#[test]
fn a_diff_lists_added_deleted_and_changed_entries() {
    require_tools!();
    let fixture = Fixture::new();
    let (before, after) = pair(&fixture);
    let image = compare(&fixture, &before, &after);
    let results = match image.handle(1, DiskRequest::Diff).unwrap() {
        DiskAnswer::Diffed(results) => results,
        other => panic!("{other:?}"),
    };
    let of =
        |path: &str| status(&results, path).unwrap_or_else(|| panic!("{path} in {results:#?}"));
    let reasons = |path: &str| of(path).reasons.clone();

    for added in [
        "/etc/new-file",
        "/opt",
        "/opt/tool",
        "/opt/tool/run",
        "/opt/tool/data",
        "/home/user/.hidden2",
    ] {
        let entry = of(added);
        assert_eq!(entry.status, DiffStatus::Added, "{added}");
        assert!(entry.before.is_none() && entry.after.is_some());
    }
    for deleted in [
        "/home/user/notes.txt",
        "/a/b",
        "/a/b/deep.txt",
        "/home/user/.hidden",
    ] {
        let entry = of(deleted);
        assert_eq!(entry.status, DiffStatus::Deleted, "{deleted}");
        assert!(entry.before.is_some() && entry.after.is_none());
    }
    // A rename is a deletion and an addition, not a pairing.
    assert_eq!(of("/home/user/.hidden").status, DiffStatus::Deleted);
    assert_eq!(of("/home/user/.hidden2").status, DiffStatus::Added);

    assert_eq!(of("/etc/passwd").status, DiffStatus::Changed);
    assert!(reasons("/etc/passwd").contains(&DiffReason::Size));
    assert_eq!(reasons("/var/log/messages.log"), vec![DiffReason::Content]);
    assert_eq!(reasons("/lib/libc.so.6"), vec![DiffReason::Time]);
    assert_eq!(reasons("/bin/busybox"), vec![DiffReason::Mode]);
    assert!(reasons("/etc/shadow-link").contains(&DiffReason::Target));
    assert!(reasons("/etc/loop").contains(&DiffReason::Type));
    let link = of("/etc/shadow-link");
    assert_eq!(
        link.before.as_ref().unwrap().link_target.as_deref(),
        Some("/etc/shadow")
    );
    assert_eq!(
        link.after.as_ref().unwrap().link_target.as_deref(),
        Some("/etc/other")
    );

    // Unchanged files and the directories above the changes are not listed.
    for same in [
        "/etc",
        "/home",
        "/home/user",
        "/var/log",
        "/a",
        "/lost+found",
        "/lib",
        "/fifo",
    ] {
        assert!(status(&results, same).is_none(), "{same} listed");
    }
    assert_eq!(results.added, 6);
    assert_eq!(results.deleted, 4);
    assert_eq!(results.changed, 6);
    assert!(!results.truncated && !results.timed_out && results.unreadable == 0);
    // Directory by directory, by name inside each directory.
    let root: Vec<_> = results
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .filter(|path| path.matches('/').count() == 1)
        .collect();
    let mut sorted = root.clone();
    sorted.sort();
    assert_eq!(root, sorted);
}

#[test]
fn identical_images_have_no_differences_and_a_missing_reference_is_an_error() {
    require_tools!();
    let fixture = Fixture::new();
    let tree = fixture.standard_tree("tree");
    fixture.stamp_tree(&tree, EPOCH);
    let one = fixture.ext4("one.ext4", &tree, &[]);
    let two = fixture.ext4("two.ext4", &tree, &[]);
    let image = compare(&fixture, &one, &two);
    match image.handle(1, DiskRequest::Diff).unwrap() {
        DiskAnswer::Diffed(results) => {
            assert!(results.entries.is_empty(), "{results:#?}");
            assert!(results.scanned > 10);
        }
        other => panic!("{other:?}"),
    }
    let alone = opened(&fixture, &one);
    assert!(alone.handle(1, DiskRequest::Diff).is_err());
}

#[test]
fn a_diff_is_bounded_and_keeps_counting_past_its_listing_limit() {
    require_tools!();
    let fixture = Fixture::new();
    let (before, after) = pair(&fixture);
    let image = compare(&fixture, &before, &after);
    let limited = image
        .diff_limited(DiffLimits {
            results: 3,
            ..DiffLimits::default()
        })
        .unwrap();
    assert_eq!(limited.entries.len(), 3);
    assert!(limited.truncated);
    assert_eq!(limited.added + limited.deleted + limited.changed, 16);
    // The entry limit and the time budget end the walk and say so.
    let scanned = image
        .diff_limited(DiffLimits {
            scanned: 5,
            ..DiffLimits::default()
        })
        .unwrap();
    assert!(scanned.timed_out && scanned.scanned <= 6);
    let timed = image
        .diff_limited(DiffLimits {
            seconds: 0,
            ..DiffLimits::default()
        })
        .unwrap();
    assert!(timed.timed_out);
}

#[test]
fn a_damaged_reference_is_an_error_not_a_crash() {
    require_tools!();
    let fixture = Fixture::new();
    let good = fixture.standard_image();
    let bad = fixture.path("bad.ext4");
    fs::write(&bad, vec![0u8; 64 * 1024]).unwrap();
    let image = compare(&fixture, &bad, &good);
    let error = image.handle(1, DiskRequest::Diff).unwrap_err();
    assert!(error.to_string().contains("reference"), "{error}");
}

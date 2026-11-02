// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::sync::atomic::{AtomicBool, AtomicU64};

/// A file in a private temporary directory, removed with the guard.
struct Temp(PathBuf);

impl Temp {
    fn new(name: &str, data: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ant-content-{name}-{}",
            crate::storage::unique_id()
        ));
        std::fs::write(&path, data).unwrap();
        Self(path)
    }
}

impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn idle() -> (AtomicBool, AtomicU64) {
    (AtomicBool::new(false), AtomicU64::new(0))
}

#[test]
fn a_page_at_the_end_is_short_and_beyond_it_is_empty() {
    let file = Temp::new("page", &(0..100u8).collect::<Vec<_>>());
    let source = FileRange::whole(file.0.clone()).unwrap();
    assert_eq!(
        read_page(&source, 0, 10).unwrap(),
        (0..10u8).collect::<Vec<_>>()
    );
    assert_eq!(
        read_page(&source, 90, 64).unwrap(),
        (90..100u8).collect::<Vec<_>>()
    );
    assert!(read_page(&source, 100, 16).unwrap().is_empty());
    assert!(read_page(&source, u64::MAX, 16).unwrap().is_empty());
    assert_eq!(read_page(&source, 0, usize::MAX).unwrap().len(), 100);
}

#[test]
fn a_page_never_exceeds_the_page_limit() {
    let file = Temp::new("limit", &vec![7u8; PAGE_MAX_SIZE * 2]);
    let source = FileRange::whole(file.0.clone()).unwrap();
    assert_eq!(
        read_page(&source, 5, PAGE_MAX_SIZE * 2).unwrap().len(),
        PAGE_MAX_SIZE
    );
}

#[test]
fn a_range_reads_only_inside_itself() {
    let file = Temp::new("range", b"0123456789abcdef");
    let source = FileRange {
        path: file.0.clone(),
        start: 4,
        size: 6,
    };
    assert_eq!(read_page(&source, 0, 100).unwrap(), b"456789");
    assert_eq!(read_page(&source, 4, 100).unwrap(), b"89");
    assert!(read_page(&source, 6, 100).unwrap().is_empty());
}

#[test]
fn a_missing_file_is_an_error_not_a_panic() {
    let source = FileRange {
        path: std::env::temp_dir().join("ant-content-never-there"),
        start: 0,
        size: 10,
    };
    assert!(read_page(&source, 0, 4).is_err());
    let (cancel, progress) = idle();
    let scan = find_strings(&source, StringsOptions::default(), &cancel, &progress);
    assert_eq!(scan.stopped, Some(Stopped::Unreadable));
}

#[test]
fn strings_across_block_boundaries_are_found_once_whole() {
    let mut data = vec![0u8; BLOCK_SIZE * 2 + 100];
    let at = BLOCK_SIZE - 3;
    data[at..at + 10].copy_from_slice(b"spansblock");
    let at2 = BLOCK_SIZE * 2 - 2;
    data[at2..at2 + 8].copy_from_slice(b"secondgo");
    let end = data.len() - 4;
    data[end..].copy_from_slice(b"tail");
    let file = Temp::new("strings", &data);
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let scan = find_strings(&source, StringsOptions::default(), &cancel, &progress);
    let found: Vec<_> = scan
        .hits
        .iter()
        .map(|h| (h.offset, h.text.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            (at as u64, "spansblock"),
            (at2 as u64, "secondgo"),
            (end as u64, "tail")
        ]
    );
    assert_eq!(scan.scanned, data.len() as u64);
    assert_eq!(progress.load(Ordering::Relaxed), data.len() as u64);
    assert_eq!(scan.stopped, None);
}

#[test]
fn the_minimum_length_and_encodings_are_honoured() {
    let mut data = vec![0u8; 64];
    data[2..5].copy_from_slice(b"abc");
    data[10..18].copy_from_slice(b"abcdefgh");
    for (slot, unit) in b"wide".iter().enumerate() {
        data[30 + slot * 2] = *unit;
    }
    let file = Temp::new("minlen", &data);
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let run = |options| find_strings(&source, options, &cancel, &progress).hits;
    let default = run(StringsOptions::default());
    assert_eq!(default.len(), 2);
    assert_eq!(default[0].kind, "ASCII");
    assert_eq!(default[1].kind, "UTF-16LE");
    assert_eq!(default[1].len, 8);
    let short = run(StringsOptions {
        min_len: 3,
        ..StringsOptions::default()
    });
    assert_eq!(short.len(), 3);
    let ascii = run(StringsOptions {
        utf16: false,
        ..StringsOptions::default()
    });
    assert_eq!(ascii.len(), 1);
    let wide = run(StringsOptions {
        ascii: false,
        ..StringsOptions::default()
    });
    assert_eq!(wide.len(), 1);
    assert_eq!(wide[0].text, "wide");
}

#[test]
fn the_hit_limit_stops_a_search_and_says_so() {
    let data: Vec<u8> = (0..100).flat_map(|_| b"word\0".to_vec()).collect();
    let file = Temp::new("limit-hits", &data);
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let options = StringsOptions {
        max_hits: 7,
        ..StringsOptions::default()
    };
    let scan = find_strings(&source, options, &cancel, &progress);
    assert_eq!(scan.hits.len(), 7);
    assert_eq!(scan.stopped, Some(Stopped::Limit));
}

#[test]
fn a_cancelled_search_stops_before_reading() {
    let file = Temp::new("cancel", b"some text here");
    let source = FileRange::whole(file.0.clone()).unwrap();
    let cancel = AtomicBool::new(true);
    let progress = AtomicU64::new(0);
    let scan = find_strings(&source, StringsOptions::default(), &cancel, &progress);
    assert_eq!(scan.stopped, Some(Stopped::Cancelled));
    assert!(scan.hits.is_empty());
    let regex = compile_regex("text", false).unwrap();
    let scan = find_matches(&source, &regex, 10, &cancel, &progress);
    assert_eq!(scan.stopped, Some(Stopped::Cancelled));
}

#[test]
fn matches_across_block_boundaries_are_found_once_whole() {
    let mut data = vec![b'.'; BLOCK_SIZE * 2 + 50];
    let at = BLOCK_SIZE - 4;
    data[at..at + 12].copy_from_slice(b"KEY=secret-1");
    let end = data.len() - 6;
    data[end..].copy_from_slice(b"KEY=ab");
    let file = Temp::new("regex", &data);
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let regex = compile_regex(r"KEY=[a-z0-9-]+", false).unwrap();
    let scan = find_matches(&source, &regex, 100, &cancel, &progress);
    let found: Vec<_> = scan
        .hits
        .iter()
        .map(|h| (h.offset, h.text.as_str()))
        .collect();
    assert_eq!(found, [(at as u64, "KEY=secret-1"), (end as u64, "KEY=ab")]);
    assert_eq!(scan.scanned, data.len() as u64);
    assert_eq!(scan.stopped, None);
}

#[test]
fn a_match_spanning_the_overlap_is_not_reported_twice() {
    let mut data = vec![b' '; BLOCK_SIZE + 4096];
    let at = BLOCK_SIZE - 100;
    for byte in &mut data[at..at + 300] {
        *byte = b'x';
    }
    let file = Temp::new("overlap", &data);
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let regex = compile_regex("x+", false).unwrap();
    let scan = find_matches(&source, &regex, 100, &cancel, &progress);
    assert_eq!(scan.hits.len(), 1);
    assert_eq!((scan.hits[0].offset, scan.hits[0].len), (at as u64, 300));
}

#[test]
fn patterns_match_raw_octets_and_bad_ones_are_refused() {
    let file = Temp::new("raw", &[0x41, 0xff, 0xfe, 0x00, 0x42, b'a', b'B']);
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let raw = compile_regex(r"\xff\xfe\x00", false).unwrap();
    let scan = find_matches(&source, &raw, 10, &cancel, &progress);
    assert_eq!(scan.hits.len(), 1);
    assert_eq!(scan.hits[0].offset, 1);
    let nocase = compile_regex("ab", true).unwrap();
    assert_eq!(
        find_matches(&source, &nocase, 10, &cancel, &progress)
            .hits
            .len(),
        1
    );
    assert!(compile_regex("", false).is_err());
    assert!(compile_regex("(unclosed", false).is_err());
    assert!(compile_regex(&"a".repeat(PATTERN_MAX_LEN + 1), false).is_err());
    assert!(compile_regex(r"(\w{1000}){1000}", false).is_err());
    // An empty-matching pattern keeps no hits.
    let empty = compile_regex("z*", false).unwrap();
    assert!(
        find_matches(&source, &empty, 10, &cancel, &progress)
            .hits
            .is_empty()
    );
}

#[test]
fn the_match_limit_stops_a_regex_search() {
    let file = Temp::new("match-limit", &b"ab ".repeat(50));
    let source = FileRange::whole(file.0.clone()).unwrap();
    let (cancel, progress) = idle();
    let regex = compile_regex("ab", false).unwrap();
    let scan = find_matches(&source, &regex, 5, &cancel, &progress);
    assert_eq!(scan.hits.len(), 5);
    assert_eq!(scan.stopped, Some(Stopped::Limit));
}

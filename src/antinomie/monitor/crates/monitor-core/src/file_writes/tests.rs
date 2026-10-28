// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn inline(bytes: &[u8]) -> Vec<Captured> {
    vec![Captured {
        rel: 0,
        len: bytes.len() as u64,
        source: Source::Inline(bytes.to_vec()),
    }]
}

fn small(per_file: u64, per_run: u64) -> Budget {
    Budget::new(Limits { per_file, per_run })
}

#[test]
fn writes_within_the_cap_read_back_exactly_in_any_order() {
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    file.add(&mut budget, Some(4), 4, inline(b"4567"));
    file.add(&mut budget, Some(0), 4, inline(b"0123"));
    file.add(&mut budget, Some(8), 2, inline(b"89"));
    assert_eq!(file.read(0, 10).unwrap(), b"0123456789");
    assert_eq!(file.tally.kept, 10);
    assert_eq!(file.tally.skipped(), 0);
    assert_eq!(budget.run, file.tally);
}

#[test]
fn a_later_write_covers_an_earlier_one_and_splits_it() {
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    file.add(&mut budget, Some(0), 8, inline(b"AAAAAAAA"));
    file.add(&mut budget, Some(2), 3, inline(b"bbb"));
    assert_eq!(file.read(0, 8).unwrap(), b"AAbbbAAA");
    let layout = file.layout();
    assert_eq!(
        layout.iter().map(|e| (e.offset, e.len)).collect::<Vec<_>>(),
        [(0, 2), (2, 3), (5, 3)]
    );
    // A write that swallows several extents leaves one.
    file.add(&mut budget, Some(0), 8, inline(b"ZZZZZZZZ"));
    assert_eq!(file.layout().len(), 1);
    assert_eq!(file.read(0, 8).unwrap(), b"ZZZZZZZZ");
}

#[test]
fn racing_writes_lie_in_the_order_the_file_system_applied_them() {
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    // Applied as 1, 2, 3; the exit of 2 reached the host last.
    file.add_ordered(&mut budget, Some(0), 4, inline(b"AAAA"), Some(1));
    file.add_ordered(&mut budget, Some(0), 4, inline(b"CCCC"), Some(3));
    file.add_ordered(&mut budget, Some(2), 4, inline(b"BBBB"), Some(2));
    // In trace order it would read CCBBBB.
    assert_eq!(file.read(0, 6).unwrap(), b"CCCCBB");
    // An unnumbered write is never passed: it stays where the trace put it.
    let mut file = Writes::default();
    file.add_ordered(&mut budget, Some(0), 2, inline(b"aa"), Some(5));
    file.add(&mut budget, Some(0), 2, inline(b"bb"));
    file.add_ordered(&mut budget, Some(0), 2, inline(b"cc"), Some(4));
    assert_eq!(file.read(0, 2).unwrap(), b"cc");
}

#[test]
fn over_the_file_cap_the_first_bytes_are_kept_and_the_rest_is_a_gap() {
    let mut budget = small(6, 100);
    let mut file = Writes::default();
    file.add(&mut budget, Some(0), 4, inline(b"HEAD"));
    file.add(&mut budget, Some(4), 4, inline(b"tail"));
    file.add(&mut budget, Some(8), 2, inline(b"zz"));
    assert_eq!(file.read(0, 6).unwrap(), b"HEADta");
    assert_eq!(file.read(0, 7), Err(ReadError::NotCaptured(6)));
    assert_eq!(file.tally.kept, 6);
    assert_eq!(file.tally.file_cap, 4);
    assert_eq!(file.tally.skipped(), 4);
    let gaps: Vec<_> = file
        .layout()
        .into_iter()
        .filter(|e| matches!(e.piece, Piece::NotCaptured(Gap::FileCap)))
        .map(|e| (e.offset, e.len))
        .collect();
    assert_eq!(gaps, [(6, 2), (8, 2)]);
}

#[test]
fn the_run_cap_is_shared_by_every_file() {
    let mut budget = small(100, 6);
    let (mut a, mut b) = (Writes::default(), Writes::default());
    a.add(&mut budget, Some(0), 4, inline(b"aaaa"));
    b.add(&mut budget, Some(0), 4, inline(b"bbbb"));
    assert_eq!(a.tally.kept, 4);
    assert_eq!((b.tally.kept, b.tally.run_cap), (2, 2));
    assert_eq!(b.read(0, 2).unwrap(), b"bb");
    assert_eq!(b.read(0, 4), Err(ReadError::NotCaptured(2)));
    assert_eq!(budget.run.kept, 6);
    assert_eq!(budget.run.skipped(), 2);
}

#[test]
fn bytes_the_kernel_did_not_capture_and_unplaced_writes_are_counted() {
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    // 10 bytes written; the kernel captured bytes 2..5 only.
    file.add(
        &mut budget,
        Some(100),
        10,
        vec![Captured {
            rel: 2,
            len: 3,
            source: Source::Inline(b"abc".to_vec()),
        }],
    );
    file.add(&mut budget, None, 7, inline(b"unknown"));
    assert_eq!(file.tally.kept, 3);
    assert_eq!(file.tally.not_recorded, 7);
    assert_eq!(file.tally.offset_unknown, 7);
    assert_eq!(file.read(102, 3).unwrap(), b"abc");
    assert_eq!(file.read(100, 3), Err(ReadError::NotCaptured(100)));
    assert_eq!(file.read(90, 4), Err(ReadError::Unknown(90)));
    assert_eq!(file.read(105, 6), Err(ReadError::NotCaptured(105)));
}

#[test]
fn a_full_extent_list_counts_the_bytes_as_unlisted() {
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    for index in 0..EXTENTS_PER_FILE as u64 {
        file.add(&mut budget, Some(index), 1, inline(b"x"));
    }
    file.add(
        &mut budget,
        Some(EXTENTS_PER_FILE as u64),
        5,
        inline(b"hello"),
    );
    assert_eq!(file.tally.unlisted, 5);
    assert_eq!(file.tally.kept, EXTENTS_PER_FILE as u64);
    assert_eq!(file.extents().len(), EXTENTS_PER_FILE);
}

#[test]
fn bytes_in_the_object_store_are_read_back_across_chunks() {
    let root = std::env::temp_dir().join(format!("ant-file-writes-{}", std::process::id()));
    let objects = root.join("objects");
    std::fs::create_dir_all(&objects).unwrap();
    // 200 000 bytes, more than one read chunk, with a recognisable pattern.
    let payload: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
    std::fs::write(objects.join("f.raw"), &payload).unwrap();
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    file.add(
        &mut budget,
        Some(10),
        payload.len() as u64,
        vec![Captured {
            rel: 0,
            len: payload.len() as u64,
            source: object_source(
                &Arc::new(root.clone()),
                &Arc::new(PathBuf::from("objects/f.raw")),
                0,
            ),
        }],
    );
    assert_eq!(file.read(10, payload.len() as u64).unwrap(), payload);
    assert_eq!(file.read(1010, 100).unwrap(), payload[1000..1100]);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn a_missing_object_is_unreadable_not_empty() {
    let mut budget = Budget::new(Limits::default());
    let mut file = Writes::default();
    file.add(
        &mut budget,
        Some(0),
        4,
        vec![Captured {
            rel: 0,
            len: 4,
            source: object_source(
                &Arc::new(PathBuf::from("/nonexistent")),
                &Arc::new(PathBuf::from("objects/none.raw")),
                0,
            ),
        }],
    );
    assert_eq!(file.read(0, 4), Err(ReadError::Unreadable));
}

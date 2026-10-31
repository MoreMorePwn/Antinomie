// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::fs;

fn key(call: u64, object: u32) -> FieldKey {
    FieldKey {
        stream: 7,
        task: 9,
        call,
        phase: 1,
        seq: 0,
        object,
    }
}

fn directory(label: &str) -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("ant-pack-{label}-{}", crate::storage::unique_id()));
    fs::create_dir_all(&path).unwrap();
    path
}

fn store(
    pack: &mut PackWriter,
    key: &FieldKey,
    field: &mut Option<u32>,
    offset: u64,
    data: &[u8],
) -> Placed {
    pack.put(key, field, offset, data, u64::MAX).unwrap()
}

fn disk_len(directory: &Path) -> u64 {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum()
}

#[test]
fn field_names_round_trip_and_reject_anything_else() {
    let key = key(3, 12);
    assert_eq!(key.file_name(), "7-9-3-1-0-12.raw");
    assert_eq!(FieldKey::parse(&key.file_name()), Some(key));
    for bad in [
        "",
        "1-2-3.raw",
        "7-9-3-1-0-12",
        "7-9-3-1-0-12-4.raw",
        "a-9-3-1-0-12.raw",
        "7-9-3-300-0-12.raw",
    ] {
        assert_eq!(FieldKey::parse(bad), None, "{bad}");
    }
}

#[test]
fn chunks_round_trip_across_fields_offsets_and_segments() {
    let root = directory("round-trip");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    pack.set_segment_size(64);
    let (first, second) = (key(1, 1), key(2, 1));
    let (mut a, mut b) = (None, None);
    // Interleaved fields, one split in two chunks, enough to roll segments.
    store(&mut pack, &first, &mut a, 0, &[1; 40]);
    store(&mut pack, &second, &mut b, 0, &[2; 30]);
    store(&mut pack, &first, &mut a, 40, &[3; 40]);
    store(&mut pack, &second, &mut b, 30, &[4; 50]);
    pack.settle();
    assert!(pack.segment.as_ref().unwrap().number >= 2);
    let mut expected = vec![1; 40];
    expected.extend([3; 40]);
    assert_eq!(
        read_field_range(&root, &first, 0, 80).unwrap().unwrap(),
        expected
    );
    // A range inside a chunk and one that straddles two chunks.
    assert_eq!(
        read_field_range(&root, &first, 10, 5).unwrap().unwrap(),
        vec![1; 5]
    );
    assert_eq!(
        read_field_range(&root, &second, 28, 4).unwrap().unwrap(),
        vec![2, 2, 4, 4]
    );
    // Bytes beyond what was stored are an error, an unknown field is not here.
    assert!(read_field_range(&root, &first, 70, 20).is_err());
    assert_eq!(read_field_range(&root, &key(9, 9), 0, 1).unwrap(), None);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identical_chunks_are_stored_once_and_both_read_back() {
    let root = directory("dedup");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    let payload = vec![0x42; 200];
    let (mut a, mut b) = (None, None);
    let (one, two) = (key(1, 1), key(2, 1));
    let first = store(&mut pack, &one, &mut a, 0, &payload);
    let second = store(&mut pack, &two, &mut b, 0, &payload);
    assert_eq!(first.location, second.location);
    assert_eq!(first.added - second.added, 200 + HEADER_SIZE);
    assert_eq!(second.added, CHUNK_RECORD_SIZE + FIELD_RECORD_SIZE);
    pack.settle();
    let segment = fs::metadata(root.join(segment_name(0))).unwrap().len();
    assert_eq!(segment, 200);
    for field in [&one, &two] {
        assert_eq!(
            read_field_range(&root, field, 0, 200).unwrap().unwrap(),
            payload
        );
    }
    assert!(pack.remembers(first.location, &payload));
    assert!(!pack.remembers(first.location, &[0; 200]));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn what_is_counted_is_what_is_on_disk() {
    let root = directory("counted");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    let mut counted = 0;
    for call in 0..300u64 {
        let mut field = None;
        let data = format!("value {}", call % 40).into_bytes();
        let placed = store(&mut pack, &key(call, 1), &mut field, 0, &data);
        counted += placed.added;
        if call % 3 == 0 {
            counted += store(
                &mut pack,
                &key(call, 1),
                &mut field,
                data.len() as u64,
                b"tail",
            )
            .added;
        }
    }
    pack.sync().unwrap();
    assert_eq!(counted, disk_len(&root));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn thousands_of_fields_use_a_handful_of_files() {
    let root = directory("few-files");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    for call in 0..5000u64 {
        let mut field = None;
        store(
            &mut pack,
            &key(call, 1),
            &mut field,
            0,
            format!("path /tmp/{call}").as_bytes(),
        );
    }
    pack.sync().unwrap();
    let files = fs::read_dir(&root).unwrap().count();
    assert_eq!(files, 2, "one segment and one index");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_chunk_over_the_budget_stores_nothing() {
    let root = directory("budget");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    let mut field = None;
    let tight = HEADER_SIZE + FIELD_RECORD_SIZE + CHUNK_RECORD_SIZE + 9;
    assert_eq!(
        pack.put(&key(1, 1), &mut field, 0, b"0123456789", tight),
        Err(PutError::Quota)
    );
    assert!(
        fs::read_dir(&root).unwrap().next().is_none(),
        "no file was created"
    );
    assert!(field.is_none());
    let placed = pack
        .put(&key(1, 1), &mut field, 0, b"012345678", tight)
        .unwrap();
    assert_eq!(placed.added, tight);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn empty_chunks_are_indexed_without_a_segment_file() {
    let root = directory("empty-chunk");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    let field_key = key(1, 1);
    let mut field = None;
    let placed = store(&mut pack, &field_key, &mut field, 0, b"");
    assert_eq!(
        placed.added,
        HEADER_SIZE + FIELD_RECORD_SIZE + CHUNK_RECORD_SIZE
    );
    pack.sync().unwrap();
    assert!(!root.join(segment_name(0)).exists());
    assert_eq!(
        read_field_range(&root, &field_key, 0, 0).unwrap(),
        Some(Vec::new())
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_writer_error_is_reported_and_a_cut_index_stays_readable() {
    let root = directory("cut");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    let (mut a, mut b) = (None, None);
    store(&mut pack, &key(1, 1), &mut a, 0, b"first");
    store(&mut pack, &key(2, 1), &mut b, 0, b"second");
    pack.sync().unwrap();
    // A crash in the middle of the last record keeps the earlier ones.
    let index = root.join(INDEX_FILE);
    let len = fs::metadata(&index).unwrap().len();
    fs::OpenOptions::new()
        .write(true)
        .open(&index)
        .unwrap()
        .set_len(len - 10)
        .unwrap();
    assert_eq!(
        read_field_range(&root, &key(1, 1), 0, 5).unwrap().unwrap(),
        b"first"
    );
    assert_eq!(read_field_range(&root, &key(2, 1), 0, 6).unwrap(), None);
    // A segment that cannot be created is a synchronous failure.
    let blocked = directory("blocked");
    fs::create_dir(blocked.join(segment_name(0))).unwrap();
    let mut pack = PackWriter::new(blocked.clone(), writer::error_slot());
    let result = pack.put(&key(1, 1), &mut None, 0, b"x", u64::MAX);
    assert!(
        matches!(result, Err(PutError::Failed(message)) if message.contains("host object persistence"))
    );
    // Data written to a file the writer thread cannot write is latched.
    let slot = writer::error_slot();
    let mut pack = PackWriter::new(blocked.clone(), slot.clone());
    pack.index = Some(Arc::new(File::open(root.join(INDEX_FILE)).unwrap()));
    pack.index_buffer.extend(b"junk");
    pack.settle();
    assert!(writer::error_of(&slot).is_some_and(|error| error.contains("host object persistence")));
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(blocked).unwrap();
}

#[test]
fn an_unknown_index_format_is_refused() {
    let root = directory("format");
    fs::write(root.join(INDEX_FILE), b"NOTANIDX00000000records").unwrap();
    assert!(read_field_range(&root, &key(1, 1), 0, 1).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn malformed_chunk_extent_is_refused() {
    let root = directory("bad-extent");
    let mut index = Vec::from(MAGIC.as_slice());
    index.extend(VERSION.to_le_bytes());
    index.extend(0u32.to_le_bytes());
    index.push(FIELD_TAG);
    index.extend(0u32.to_le_bytes());
    index.extend(7u64.to_le_bytes());
    index.extend(9u64.to_le_bytes());
    index.extend(1u64.to_le_bytes());
    index.extend(0u64.to_le_bytes());
    index.push(1);
    index.extend(1u32.to_le_bytes());
    index.push(CHUNK_TAG);
    index.extend(0u32.to_le_bytes());
    index.extend(0u64.to_le_bytes());
    index.extend(u32::MAX.to_le_bytes());
    index.extend(0u64.to_le_bytes());
    fs::write(root.join(INDEX_FILE), index).unwrap();
    assert_eq!(
        read_field_range(&root, &key(1, 1), 0, 1)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidData
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn an_index_growing_while_it_is_read_is_read_again() {
    let root = directory("growing");
    let mut pack = PackWriter::new(root.clone(), writer::error_slot());
    let mut a = None;
    store(&mut pack, &key(1, 1), &mut a, 0, b"early");
    pack.settle();
    assert_eq!(
        read_field_range(&root, &key(1, 1), 0, 5).unwrap().unwrap(),
        b"early"
    );
    let mut b = None;
    store(&mut pack, &key(2, 1), &mut b, 0, b"later");
    store(&mut pack, &key(1, 1), &mut a, 5, b"more");
    pack.settle();
    assert_eq!(
        read_field_range(&root, &key(2, 1), 0, 5).unwrap().unwrap(),
        b"later"
    );
    assert_eq!(
        read_field_range(&root, &key(1, 1), 3, 6).unwrap().unwrap(),
        b"lymore"
    );
    fs::remove_dir_all(root).unwrap();
}

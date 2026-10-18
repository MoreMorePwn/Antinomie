// SPDX-License-Identifier: MIT
use super::super::{CHUNK_TAG, FIELD_TAG, FieldKey, INDEX_FILE, MAGIC, VERSION};
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io::{BufWriter, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    time::Instant,
};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root =
            std::env::temp_dir().join(format!("ant-packed-index-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        Self { root }
    }

    fn index(&self) -> PathBuf {
        self.root.join(INDEX_FILE)
    }

    fn segment(&self) -> PathBuf {
        self.root.join("objects-000000.seg")
    }

    fn clean_cache(&self) {
        let path = cache::cache_file_for_test(&self.root).unwrap();
        let _ = fs::remove_file(path);
    }

    fn reopen_cache(&self) {
        cache::discard_cached_connection_for_test(&self.root).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.clean_cache();
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn key(stream: u64) -> FieldKey {
    FieldKey {
        stream,
        task: u64::MAX,
        call: stream.wrapping_mul(3),
        phase: 2,
        seq: stream.wrapping_mul(5),
        object: 7,
    }
}

fn write_header(writer: &mut impl Write) -> std::io::Result<()> {
    writer.write_all(MAGIC)?;
    writer.write_all(&VERSION.to_le_bytes())?;
    writer.write_all(&0_u32.to_le_bytes())
}

fn field_record(writer: &mut impl Write, number: u32, key: &FieldKey) -> std::io::Result<()> {
    writer.write_all(&[FIELD_TAG])?;
    writer.write_all(&number.to_le_bytes())?;
    writer.write_all(&key.stream.to_le_bytes())?;
    writer.write_all(&key.task.to_le_bytes())?;
    writer.write_all(&key.call.to_le_bytes())?;
    writer.write_all(&key.seq.to_le_bytes())?;
    writer.write_all(&[key.phase])?;
    writer.write_all(&key.object.to_le_bytes())
}

fn chunk_record(
    writer: &mut impl Write,
    number: u32,
    object_offset: u64,
    size: u32,
    location: u64,
) -> std::io::Result<()> {
    writer.write_all(&[CHUNK_TAG])?;
    writer.write_all(&number.to_le_bytes())?;
    writer.write_all(&object_offset.to_le_bytes())?;
    writer.write_all(&size.to_le_bytes())?;
    writer.write_all(&location.to_le_bytes())
}

fn one_chunk_index(path: &Path, field: &FieldKey, size: u32, object_offset: u64) {
    let mut writer = File::create(path).unwrap();
    write_header(&mut writer).unwrap();
    field_record(&mut writer, 0, field).unwrap();
    chunk_record(&mut writer, 0, object_offset, size, 0).unwrap();
    writer.sync_all().unwrap();
}

#[test]
fn cache_streams_more_than_132k_legitimate_fields_without_in_memory_limits() {
    const FIELDS: u32 = 132_001;
    let fixture = Fixture::new();
    fs::write(fixture.segment(), b"x").unwrap();
    let file = File::create(fixture.index()).unwrap();
    let mut writer = BufWriter::with_capacity(64 * 1024, file);
    write_header(&mut writer).unwrap();
    for number in 0..FIELDS {
        let field = key(u64::from(number));
        field_record(&mut writer, number, &field).unwrap();
        chunk_record(&mut writer, number, 0, 1, 0).unwrap();
    }
    writer.flush().unwrap();
    writer.get_ref().sync_all().unwrap();

    assert_eq!(
        read_field_range(&fixture.root, &key(u64::from(FIELDS - 1)), 0, 1)
            .unwrap()
            .unwrap(),
        b"x"
    );
    let last_key = key(u64::from(FIELDS - 1));
    assert_eq!(lookup(&fixture.root, &last_key, 0).unwrap().unwrap().0, 1);
    let started = Instant::now();
    for _ in 0..1_000 {
        assert_eq!(lookup(&fixture.root, &last_key, 0).unwrap().unwrap().0, 1);
    }
    eprintln!(
        "1,000 repeated packed-object index lookups: {:?}",
        started.elapsed()
    );
}

#[test]
fn cache_reopens_and_resumes_after_a_truncated_tail_is_appended() {
    let fixture = Fixture::new();
    fs::write(fixture.segment(), b"oldnew").unwrap();
    let mut writer = File::create(fixture.index()).unwrap();
    write_header(&mut writer).unwrap();
    field_record(&mut writer, 0, &key(1)).unwrap();
    chunk_record(&mut writer, 0, 0, 3, 0).unwrap();
    writer.flush().unwrap();
    let tail = {
        let mut bytes = Vec::new();
        chunk_record(&mut bytes, 0, 3, 3, 3).unwrap();
        bytes
    };
    writer.write_all(&tail[..11]).unwrap();
    writer.sync_all().unwrap();

    assert_eq!(
        read_field_range(&fixture.root, &key(1), 0, 3)
            .unwrap()
            .unwrap(),
        b"old"
    );
    fixture.reopen_cache();
    drop(writer);
    OpenOptions::new()
        .append(true)
        .open(fixture.index())
        .unwrap()
        .write_all(&tail[11..])
        .unwrap();
    assert_eq!(
        read_field_range(&fixture.root, &key(1), 0, 6)
            .unwrap()
            .unwrap(),
        b"oldnew"
    );
}

#[test]
fn cache_discards_rows_when_the_index_at_the_same_path_is_replaced() {
    let fixture = Fixture::new();
    fs::write(fixture.segment(), b"oldnew").unwrap();
    one_chunk_index(&fixture.index(), &key(1), 3, 0);
    assert_eq!(
        read_field_range(&fixture.root, &key(1), 0, 3)
            .unwrap()
            .unwrap(),
        b"old"
    );

    let replacement = fixture.root.join("replacement.idx");
    one_chunk_index(&replacement, &key(2), 3, 0);
    assert_ne!(
        fs::metadata(fixture.index()).unwrap().ino(),
        fs::metadata(&replacement).unwrap().ino()
    );
    fs::rename(replacement, fixture.index()).unwrap();

    assert_eq!(
        read_field_range(&fixture.root, &key(1), 0, 3).unwrap(),
        None
    );
    assert_eq!(
        read_field_range(&fixture.root, &key(2), 0, 3)
            .unwrap()
            .unwrap(),
        b"old"
    );
}

#[test]
fn cache_discards_index_rows_after_the_source_file_shrinks() {
    let fixture = Fixture::new();
    fs::write(fixture.segment(), b"old").unwrap();
    one_chunk_index(&fixture.index(), &key(8), 3, 0);
    let inode = fs::metadata(fixture.index()).unwrap().ino();
    assert_eq!(lookup(&fixture.root, &key(8), 0).unwrap().unwrap().0, 3);

    OpenOptions::new()
        .write(true)
        .open(fixture.index())
        .unwrap()
        .set_len(16 + 42)
        .unwrap();
    assert_eq!(fs::metadata(fixture.index()).unwrap().ino(), inode);
    assert_eq!(lookup(&fixture.root, &key(8), 0).unwrap(), None);
}

#[test]
fn chunks_keep_the_field_identity_declared_when_each_record_was_read() {
    let fixture = Fixture::new();
    fs::write(fixture.segment(), b"oldnew").unwrap();
    let first = key(11);
    let second = key(12);
    let mut writer = File::create(fixture.index()).unwrap();
    write_header(&mut writer).unwrap();
    field_record(&mut writer, 9, &first).unwrap();
    chunk_record(&mut writer, 9, 0, 3, 0).unwrap();
    field_record(&mut writer, 9, &second).unwrap();
    chunk_record(&mut writer, 9, 0, 3, 3).unwrap();
    writer.sync_all().unwrap();

    assert_eq!(
        read_field_range(&fixture.root, &first, 0, 3)
            .unwrap()
            .unwrap(),
        b"old"
    );
    assert_eq!(
        read_field_range(&fixture.root, &second, 0, 3)
            .unwrap()
            .unwrap(),
        b"new"
    );
}

#[test]
fn zero_length_chunk_does_not_hide_preceding_range_bytes() {
    let fixture = Fixture::new();
    fs::write(fixture.segment(), b"oldnew").unwrap();
    let field = key(21);
    let mut writer = File::create(fixture.index()).unwrap();
    write_header(&mut writer).unwrap();
    field_record(&mut writer, 1, &field).unwrap();
    chunk_record(&mut writer, 1, 0, 6, 0).unwrap();
    chunk_record(&mut writer, 1, 3, 0, 6).unwrap();
    writer.sync_all().unwrap();

    assert_eq!(
        read_field_range(&fixture.root, &field, 0, 6)
            .unwrap()
            .unwrap(),
        b"oldnew"
    );
    assert_eq!(lookup(&fixture.root, &field, 3).unwrap().unwrap().0, 0);
}

#[test]
fn malformed_chunk_lengths_and_field_extents_fail_before_payload_allocation() {
    let fixture = Fixture::new();
    let malformed_length = fixture.root.join("malformed-length.idx");
    one_chunk_index(&malformed_length, &key(3), u32::MAX, 0);
    fs::rename(malformed_length, fixture.index()).unwrap();
    let error = lookup(&fixture.root, &key(3), 0).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(read_at(&fixture.root, ChunkLocation(0), usize::MAX).is_err());

    let overflowing_extent = fixture.root.join("overflowing-extent.idx");
    one_chunk_index(&overflowing_extent, &key(4), 1, u64::MAX);
    fs::rename(overflowing_extent, fixture.index()).unwrap();
    let error = lookup(&fixture.root, &key(4), u64::MAX).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
}

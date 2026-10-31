// SPDX-License-Identifier: GPL-3.0-only
use super::super::*;
use crate::{api::FieldSummary, recording::read_captured_range};
use std::{fs, path::Path};

fn packet(call: u64, kind: u8, id: u32, offset: u64, body: &[u8], seq: u64) -> Vec<u8> {
    let mut p = vec![0; 128];
    p[..4].copy_from_slice(b"ANTT");
    p[4..6].copy_from_slice(&1u16.to_le_bytes());
    p[8..10].copy_from_slice(&128u16.to_le_bytes());
    p[10..12].copy_from_slice(&1u16.to_le_bytes());
    p[12..16].copy_from_slice(&(128u32 + body.len() as u32).to_le_bytes());
    p[20..24].copy_from_slice(&1u32.to_le_bytes());
    p[40..48].copy_from_slice(&call.to_le_bytes());
    p[56..64].copy_from_slice(&seq.to_le_bytes());
    p[96..98].copy_from_slice(&1u16.to_le_bytes());
    p[98] = 1;
    p[99] = kind;
    p[100..104].copy_from_slice(&id.to_le_bytes());
    p[104..112].copy_from_slice(&offset.to_le_bytes());
    p[112..120].copy_from_slice(&u64::MAX.to_le_bytes());
    p[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
    p.extend(body);
    p
}

fn recording(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "ant-objects-{label}-{}",
        crate::storage::unique_id()
    ));
    private_dir(&root).unwrap();
    root
}

fn field_of(assembler: &Assembler, call: u64) -> FieldSummary {
    assembler
        .history()
        .into_iter()
        .flat_map(|event| event.fields)
        .find(|field| {
            field
                .raw_path
                .as_ref()
                .is_some_and(|path| path.to_string_lossy().contains(&format!("-0-{call}-1-0-")))
        })
        .expect("field was ingested")
}

/// Events built from chunks alone are incomplete; what matters is that no
/// issue is about the stored chunks.
fn object_issues(events: &[crate::api::EventSummary]) -> Vec<&String> {
    events
        .iter()
        .flat_map(|event| &event.issues)
        .filter(|issue| {
            [
                "differs",
                "persistence",
                "escapes",
                "overlapping",
                "conflicting",
                "regular file",
            ]
            .iter()
            .any(|word| issue.contains(word))
        })
        .collect()
}

fn disk_len(objects: &Path) -> u64 {
    fs::read_dir(objects)
        .unwrap()
        .map(|entry| entry.unwrap().metadata().unwrap().len())
        .sum()
}

fn texts(calls: std::ops::RangeInclusive<u64>) -> Vec<Vec<u8>> {
    calls
        .flat_map(|call| {
            let text = format!("argument {call}");
            [
                packet(call, 3, 1, 0, text.as_bytes(), 1),
                packet(call, 3, 1, text.len() as u64, b" and more", 2),
            ]
        })
        .collect()
}

#[test]
fn a_new_archive_packs_objects_replays_and_reads_through_the_unchanged_reader_api() {
    let root = recording("packed");
    let objects = root.join("objects");
    let mut live = Assembler::new(objects.clone(), 1 << 20).unwrap();
    let packets = texts(1..=50);
    for packet in &packets {
        live.ingest(packet).unwrap();
    }
    live.sync().unwrap();
    assert!(live.saving_error().is_none());
    // Fifty objects, one segment and one index.
    assert_eq!(fs::read_dir(&objects).unwrap().count(), 2);
    // The quota counts the bytes that are on the disk.
    assert_eq!(live.stored_len(), disk_len(&objects));

    // The field summary alone is enough to read the bytes back.
    let field = field_of(&live, 7);
    assert_eq!(
        read_captured_range(&root, &field, 0, 19).unwrap(),
        b"argument 7 and more"
    );
    assert_eq!(read_captured_range(&root, &field, 9, 4).unwrap(), b"7 an");

    // A reader of the saved archive replays the packets against the store.
    let mut replay = Assembler::open_archive(objects).unwrap();
    for packet in &packets {
        replay.ingest(packet).unwrap();
    }
    let replayed = field_of(&replay, 7);
    assert_eq!(replayed.ranges, field.ranges);
    assert_eq!(replayed.ranges, vec![(0, 10), (10, 9)]);
    assert!(object_issues(&replay.history()).is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sparse_field_offsets_do_not_consume_storage_quota_and_replay_with_zero_reader_quota() {
    let root = recording("sparse-offset");
    let objects = root.join("objects");
    let offset = 1 << 30;
    let packet = packet(7, 3, 1, offset, b"small", 1);
    let mut live = Assembler::new(objects.clone(), 1024).unwrap();
    let event = live.ingest(&packet).unwrap().unwrap();
    assert!(object_issues(&[event]).is_empty());
    live.sync().unwrap();
    assert!(live.stored_len() < 1024);
    assert_eq!(live.stored_len(), disk_len(&objects));

    let field = field_of(&live, 7);
    assert_eq!(field.ranges, vec![(offset, 5)]);
    assert_eq!(
        read_captured_range(&root, &field, offset, 5).unwrap(),
        b"small"
    );

    // Archive validation is read-only and has no live storage quota.
    let mut replay = Assembler::open_archive(objects).unwrap();
    let event = replay.ingest(&packet).unwrap().unwrap();
    assert!(object_issues(&[event]).is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replaying_a_packet_that_differs_from_the_store_is_an_issue_not_a_range() {
    let root = recording("tampered");
    let objects = root.join("objects");
    let mut live = Assembler::new(objects.clone(), 1 << 20).unwrap();
    live.ingest(&packet(1, 3, 1, 0, b"original", 1)).unwrap();
    live.sync().unwrap();
    let mut replay = Assembler::open_archive(objects).unwrap();
    let event = replay
        .ingest(&packet(1, 3, 1, 0, b"altered!", 1))
        .unwrap()
        .unwrap();
    assert!(event.fields[0].ranges.is_empty());
    assert!(event.issues.iter().any(|issue| issue.contains("differs")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn archives_made_with_one_file_per_object_still_replay_and_read() {
    let root = recording("legacy");
    let objects = root.join("objects");
    private_dir(&objects).unwrap();
    for call in 1..=3u64 {
        fs::write(
            objects.join(format!("0-0-{call}-1-0-1.raw")),
            format!("argument {call} and more"),
        )
        .unwrap();
    }
    let mut replay = Assembler::open_archive(objects).unwrap();
    for packet in texts(1..=3) {
        replay.ingest(&packet).unwrap();
    }
    assert!(object_issues(&replay.history()).is_empty());
    let field = field_of(&replay, 2);
    assert_eq!(field.ranges, vec![(0, 10), (10, 9)]);
    assert_eq!(
        read_captured_range(&root, &field, 0, 19).unwrap(),
        b"argument 2 and more"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn identical_objects_are_stored_once_and_repeated_chunks_are_compared() {
    let root = recording("dedup");
    let objects = root.join("objects");
    let mut live = Assembler::new(objects.clone(), 1 << 20).unwrap();
    let same = |call, seq| packet(call, 3, 1, 0, b"/etc/ld.so.cache", seq);
    live.ingest(&same(1, 1)).unwrap();
    live.ingest(&same(2, 1)).unwrap();
    live.ingest(&same(3, 1)).unwrap();
    live.sync().unwrap();
    assert_eq!(
        fs::metadata(objects.join(crate::object_pack::segment_name(0)))
            .unwrap()
            .len(),
        16,
        "three fields share one stored copy"
    );
    for call in 1..=3 {
        let field = field_of(&live, call);
        assert_eq!(
            read_captured_range(&root, &field, 0, 16).unwrap(),
            b"/etc/ld.so.cache"
        );
    }
    // The same packet again is a duplicate, not a conflict; different bytes
    // for the same range are.
    let event = live.ingest(&same(1, 1)).unwrap().unwrap();
    assert!(object_issues(&[event]).is_empty());
    let event = live
        .ingest(&packet(1, 3, 1, 0, b"/etc/passwd.xxxx", 9))
        .unwrap()
        .unwrap();
    assert!(
        event
            .issues
            .iter()
            .any(|issue| issue.contains("conflicting duplicate chunk"))
    );
    assert_eq!(live.stored_len(), disk_len(&objects));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_heavy_run_of_tiny_objects_stays_a_handful_of_files() {
    let root = recording("heavy");
    let objects = root.join("objects");
    let mut live = Assembler::new(objects.clone(), 64 << 20).unwrap();
    for call in 1..=4000u64 {
        live.ingest(&packet(
            call,
            3,
            1,
            0,
            format!("/tmp/file-{call}").as_bytes(),
            1,
        ))
        .unwrap();
    }
    live.sync().unwrap();
    assert!(live.saving_error().is_none());
    assert_eq!(fs::read_dir(&objects).unwrap().count(), 2);
    fs::remove_dir_all(root).unwrap();
}

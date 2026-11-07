// SPDX-License-Identifier: GPL-3.0-only
//! A call's whole captured buffer is placed in the rebuilt file, within the
//! budgets only, and the short-capture note fires for a real short capture.
use super::*;
use crate::tests::{call, captured, path_call};
use std::path::PathBuf;

pub const SIZE: u64 = 1_286_144;

pub fn pattern(length: u64) -> Vec<u8> {
    (0..length).map(|at| (at % 251) as u8).collect()
}

pub fn scratch(name: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("ant-file-bytes-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("objects")).unwrap();
    root
}

/// A pwrite64 of `size` bytes whose buffer the recording kept `kept` of.
pub fn pwrite(size: u64, kept: u64) -> InvocationSummary {
    let mut write = call(1, 18, "pwrite64", size as i64);
    write.call_id = 2;
    let entry = write.entry.as_mut().unwrap();
    entry.call_id = 2;
    entry.args = Some([3, 0, size, 0, 0, 0]);
    write.exit.as_mut().unwrap().call_id = 2;
    let mut field = captured("arg1.data", "", b"");
    field.raw_path = Some(PathBuf::from("objects/big.raw"));
    field.logical_len = Some(size);
    field.captured_len = kept;
    field.ranges = vec![(0, kept)];
    write.entry.as_mut().unwrap().fields.push(field);
    write
}

pub fn rebuild(directory: &Path, calls: &[InvocationSummary], retention: Retention) -> Change {
    let mut index = FileIndex::default();
    index.set_retention(retention);
    let mut files = FdState::default();
    for call in calls {
        let event = trace::representative(call).unwrap();
        remember_open(&mut files, call, event);
        index.observe(&files, call, event, Some(directory));
    }
    let mut changes = index.finish();
    assert_eq!(changes.len(), 1);
    changes.remove(0)
}

pub fn open() -> InvocationSummary {
    let mut open = path_call(1, 2, "open", 3, "/tmp/file");
    open.call_id = 1;
    open.entry.as_mut().unwrap().args = Some([0, 0x41, 0, 0, 0, 0]);
    open
}

#[test]
pub fn a_write_the_recording_holds_whole_is_rebuilt_whole_with_no_short_note() {
    let root = scratch("whole");
    let data = pattern(SIZE);
    std::fs::write(root.join("objects/big.raw"), &data).unwrap();
    let change = rebuild(&root, &[open(), pwrite(SIZE, SIZE)], Retention::default());
    assert_eq!(change.final_data.len() as u64, SIZE);
    assert!(change.final_data.values().eq(data.iter().copied()));
    assert!(change.short_capture.is_none());
    assert!(change.gap_notes().iter().all(|note| note.limit));
    assert!(change.gap_notes().is_empty());
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
pub fn a_buffer_the_recording_kept_only_64_kib_of_gets_the_corrected_note() {
    let root = scratch("short");
    std::fs::write(root.join("objects/big.raw"), pattern(65_536)).unwrap();
    let change = rebuild(&root, &[open(), pwrite(SIZE, 65_536)], Retention::default());
    assert_eq!(change.final_data.len(), 65_536);
    let notes = change.gap_notes();
    assert_eq!(notes.len(), 1);
    assert_eq!(
        notes[0].text,
        "This write moved 1,286,144 B, but the recording kept only 65,536 B of its buffer \
         (1,220,608 B were not recorded). Those bytes are a gap in the rebuilt file; \
         the call's own record shows what was kept."
    );
    assert!(!notes[0].limit);
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
pub fn the_per_file_budget_stops_the_rebuild_with_its_own_note_not_a_capture_note() {
    let root = scratch("budget");
    std::fs::write(root.join("objects/big.raw"), pattern(SIZE)).unwrap();
    let change = rebuild(
        &root,
        &[open(), pwrite(SIZE, SIZE)],
        Retention::from_mib(1, 256),
    );
    assert_eq!(change.final_data.len(), 1 << 20);
    assert!(change.short_capture.is_none());
    let notes = change.gap_notes();
    assert_eq!(notes.len(), 1);
    assert!(notes[0].limit);
    assert!(
        notes[0]
            .text
            .starts_with("Byte reconstruction stopped at the limit per file"),
        "{}",
        notes[0].text
    );
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
pub fn an_unreadable_object_is_a_short_capture_not_a_silent_hole() {
    let root = scratch("missing");
    // The record names 1.2 MiB, but the object file holds only 100 KiB.
    std::fs::write(root.join("objects/big.raw"), pattern(100_000)).unwrap();
    let change = rebuild(&root, &[open(), pwrite(SIZE, SIZE)], Retention::default());
    assert_eq!(change.final_data.len(), 65_536);
    let short = change.short_capture.as_ref().expect("a note");
    assert_eq!((short.moved, short.captured), (SIZE, 65_536));
    std::fs::remove_dir_all(&root).unwrap();
}

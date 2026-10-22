// SPDX-License-Identifier: GPL-3.0-only
//! Dense async observations: the page previews them, a continuation browses
//! them all, and every saved raw identity stays reachable.
use super::*;
use std::collections::BTreeSet;

const CALL: (u64, u64, u64) = (9, 10, 1);
/// Sequence of the task end of call 1: after every observation of the call.
const TASK_EXIT_SEQ: u64 = 99_999;

fn directory() -> PathBuf {
    let directory = std::env::temp_dir().join(format!("ant-async-browse-{}", storage::unique_id()));
    storage::private_dir(&directory).unwrap();
    storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
    directory
}

/// Remove a fixture and the index cache built for it.
fn cleanup(directory: &Path) {
    let index = archive_index_path(directory).unwrap();
    fs::remove_dir_all(directory).unwrap();
    let _ = fs::remove_file(index);
}

fn write(raw: &mut File, packet: Vec<u8>) {
    raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
    raw.write_all(&packet).unwrap();
}

/// The packets of one observation of `call`: begin, a field named `name`, end.
/// `skip` names fragments (1, 2 or 5) that are lost.
fn observation(call: u64, event_seq: u64, name: &[u8], skip: &[u8]) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    if !skip.contains(&1) {
        let mut begin = event_packet(call, 3, 1, 1);
        begin[48..56].copy_from_slice(&event_seq.to_le_bytes());
        packets.push(begin);
    }
    if !skip.contains(&2) {
        let mut body = vec![0; 40];
        body[0] = 255;
        body[1] = 1;
        body[2..4].copy_from_slice(&1u16.to_le_bytes());
        body[4..6].copy_from_slice(&1u16.to_le_bytes());
        body[32..34].copy_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend(name);
        let mut field = event_packet(call, 3, 2, 2);
        field.truncate(136);
        field[48..56].copy_from_slice(&event_seq.to_le_bytes());
        field[100..104].copy_from_slice(&1u32.to_le_bytes());
        field[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
        field[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
        field.extend(body);
        packets.push(field);
    }
    if !skip.contains(&5) {
        let mut end = event_packet(call, 3, 5, 3);
        end[48..56].copy_from_slice(&event_seq.to_le_bytes());
        packets.push(end);
    }
    packets
}

fn lifecycle(call: u64, event_seq: u64, name: &[u8]) -> Vec<Vec<u8>> {
    observation(call, event_seq, name, &[])
}

/// What the raw archive retains: `(call, phase, event_seq)` of every packet.
fn raw_identities(directory: &Path) -> BTreeSet<(u64, u8, u64)> {
    let mut reader = BufReader::new(File::open(directory.join("telemetry.raw")).unwrap());
    let mut found = BTreeSet::new();
    while let Some((_, packet)) = next_packet(&mut reader).unwrap() {
        let (header, _) = parser::parse_packet(&packet).unwrap();
        found.insert((header.call_id, header.phase, header.event_seq));
    }
    found
}

fn browse_all(recording: &Recording, call: (u64, u64, u64), limit: usize) -> (Vec<u64>, u64) {
    let cancel = AtomicBool::new(false);
    let (mut seqs, mut cursor) = (Vec::new(), 0);
    loop {
        let page = recording
            .async_page_cancellable(call, cursor, limit, &cancel)
            .unwrap();
        assert!(page.events.len() <= limit);
        seqs.extend(page.events.iter().map(|event| event.event_seq));
        match page.next_event_seq {
            Some(next) => {
                assert!(next > cursor || cursor == 0, "cursor did not advance");
                assert_eq!(page.events.len(), limit, "a short page has a next cursor");
                cursor = next;
            }
            None => return (seqs, page.total),
        }
    }
}

/// Call 1 is dense and mixed with other calls; call 2 is an exec with a
/// lifecycle record; call 3 has an exit and a few observations.
fn dense_recording(completions: u64) -> (PathBuf, Recording) {
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    write(&mut raw, event_packet(1, 1, 5, 2));
    write(&mut raw, event_packet(2, 1, 1, 1));
    write(&mut raw, event_packet(3, 2, 5, 2));
    for number in 0..completions {
        for packet in observation(1, 1000 + number, b"async.request_id", &[]) {
            write(&mut raw, packet);
        }
        if number % 500 == 0 {
            for packet in observation(3, 5000 + number, b"async.stage", &[]) {
                write(&mut raw, packet);
            }
        }
    }
    for packet in lifecycle(2, 77, b"lifecycle.exec_commit") {
        write(&mut raw, packet);
    }
    // The task ends in call 1 after all its completions: a preview cut by
    // sequence would lose it.
    for packet in lifecycle(1, TASK_EXIT_SEQ, b"lifecycle.task_exit") {
        write(&mut raw, packet);
    }
    write(&mut raw, event_packet(1, 2, 5, 2));
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    (directory, recording)
}

#[test]
fn dense_call_keeps_its_facts_counts_every_completion_and_browses_them_all() {
    let (directory, recording) = dense_recording(2600);
    let page = recording.invocation_page(0, 10).unwrap();
    let dense = &page.invocations[0];
    assert_eq!(dense.call_id, 1);
    assert!(dense.entry.is_some() && dense.exit.is_some());
    let ended = dense
        .task_exit
        .as_ref()
        .expect("task end evicted by async load");
    assert_eq!(ended.event_seq, TASK_EXIT_SEQ);
    assert_eq!(dense.async_events.len(), ASYNC_PREVIEW_LIMIT);
    assert_eq!(dense.async_saved, 2600);
    assert_eq!(dense.async_omitted(), 2600 - 256);
    assert_eq!(dense.async_events[0].event_seq, 1000);
    assert!(page.issues.iter().any(|issue| issue.contains("first 256")));
    assert!(page.issues.iter().all(|issue| !issue.contains("2048")));
    // The exec and the three-observation call are not partial.
    for call in &page.invocations[1..] {
        assert_eq!(call.async_omitted(), 0, "call {}", call.call_id);
    }
    let quiet = page.invocations.iter().find(|c| c.call_id == 3).unwrap();
    assert_eq!(quiet.async_saved, 6);
    assert!(quiet.exit.is_some());

    // Browse: every observation once, in order, whatever the page size.
    let expected: Vec<u64> = (0..2600).map(|number| 1000 + number).collect();
    for limit in [1, 7, 255, 256] {
        let (seqs, total) = browse_all(&recording, CALL, limit);
        assert_eq!(seqs, expected, "limit {limit}");
        assert_eq!(total, 2600);
    }

    // Compare with the retained raw identities: nothing is neither shown nor
    // browsable, except the lifecycle record that is not an observation.
    let mut reachable = BTreeSet::new();
    for call in &page.invocations {
        for event in call.entry.iter().chain(&call.exit).chain(&call.task_exit) {
            reachable.insert((event.call_id, event.phase, event.event_seq));
        }
        if call.call_id != 1 {
            reachable.extend(
                call.async_events
                    .iter()
                    .map(|event| (event.call_id, event.phase, event.event_seq)),
            );
        }
    }
    let (seqs, _) = browse_all(&recording, CALL, 256);
    reachable.extend(seqs.into_iter().map(|seq| (1, 3, seq)));
    let mut saved = raw_identities(&directory);
    assert!(
        saved.remove(&(2, 3, 77)),
        "exec commit is a lifecycle record"
    );
    assert_eq!(
        saved.difference(&reachable).collect::<Vec<_>>(),
        Vec::<&(u64, u8, u64)>::new()
    );
    // Entry packets of call 2 and the like are retained and shown too.
    assert!(reachable.is_superset(&saved));
    cleanup(&directory);
}

#[test]
fn credential_and_hash_records_come_back_with_their_call_and_are_not_observations() {
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    write(&mut raw, event_packet(1, 1, 5, 2));
    // Many completions after the credential record, so a preview cut by
    // sequence would lose it, and a hash record that arrives after the exit.
    for packet in observation(1, 10, b"lifecycle.creds", &[]) {
        write(&mut raw, packet);
    }
    for number in 0..600u64 {
        for packet in observation(1, 1000 + number, b"async.request_id", &[]) {
            write(&mut raw, packet);
        }
    }
    write(&mut raw, event_packet(1, 2, 5, 2));
    for packet in observation(1, 5000, b"lifecycle.file_hash", &[]) {
        write(&mut raw, packet);
    }
    for packet in observation(1, 5001, b"lifecycle.exec_commit", &[]) {
        write(&mut raw, packet);
    }
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    let page = recording.invocation_page(0, 10).unwrap();
    let call = &page.invocations[0];
    let keys: Vec<_> = call
        .kernel_notes
        .iter()
        .flat_map(|event| event.fields.iter().map(|field| field.key.as_str()))
        .collect();
    assert_eq!(keys, ["lifecycle.creds", "lifecycle.file_hash"]);
    assert_eq!(call.async_saved, 600, "notes are not async observations");
    let (seqs, total) = browse_all(&recording, (9, 10, 1), 256);
    assert_eq!((seqs.len(), total), (600, 600));
    cleanup(&directory);
}

#[test]
fn an_index_built_before_kernel_notes_is_rebuilt_and_an_old_recording_still_loads() {
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    write(&mut raw, event_packet(1, 1, 5, 2));
    for packet in observation(1, 10, b"lifecycle.creds", &[]) {
        write(&mut raw, packet);
    }
    write(&mut raw, event_packet(1, 2, 5, 2));
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    assert_eq!(
        recording.invocation_page(0, 10).unwrap().invocations[0]
            .kernel_notes
            .len(),
        1
    );
    // The cache an earlier version wrote: no layout version, and a lifecycle
    // row that only says "not a task end".
    let index = archive_index_path(&directory).unwrap();
    let connection = rusqlite::Connection::open(&index).unwrap();
    connection
        .execute_batch("PRAGMA user_version = 0; UPDATE lifecycle SET task_exit = 0;")
        .unwrap();
    drop(connection);
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations[0].kernel_notes.len(), 1, "index rebuilt");
    // A recording from a kernel without the records has none, and loads.
    let plain = directory.join("plain");
    fs::create_dir(&plain).unwrap();
    storage::atomic_json(&plain.join("manifest.json"), &serde_json::json!({})).unwrap();
    let mut raw = File::create(plain.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    write(&mut raw, event_packet(1, 1, 5, 2));
    write(&mut raw, event_packet(1, 2, 5, 2));
    raw.sync_all().unwrap();
    let page = open_recording(&plain)
        .unwrap()
        .invocation_page(0, 10)
        .unwrap();
    assert!(page.invocations[0].kernel_notes.is_empty());
    assert!(page.invocations[0].entry.is_some());
    let _ = fs::remove_file(archive_index_path(&plain).unwrap());
    cleanup(&directory);
}

#[test]
fn an_index_appended_by_an_older_build_is_rebuilt_not_resumed() {
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    write(&mut raw, event_packet(1, 1, 5, 2));
    for packet in observation(1, 10, b"lifecycle.creds", &[]) {
        write(&mut raw, packet);
    }
    write(&mut raw, event_packet(1, 2, 5, 2));
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    assert_eq!(
        recording.invocation_page(0, 10).unwrap().invocations[0]
            .kernel_notes
            .len(),
        1
    );
    // What 0.6.2 leaves behind after appending: the same layout number, rows of
    // the old kind, and the cursor row rewritten without the writer stamp.
    let index = archive_index_path(&directory).unwrap();
    let connection = rusqlite::Connection::open(&index).unwrap();
    connection
        .execute_batch(
            "UPDATE lifecycle SET task_exit = 0; \
             UPDATE indexed SET writer = NULL;",
        )
        .unwrap();
    drop(connection);
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations[0].kernel_notes.len(), 1, "index rebuilt");
    // The rebuilt index is stamped, so the next open resumes it.
    let connection = rusqlite::Connection::open(&index).unwrap();
    let writer: Option<i64> = connection
        .query_row("SELECT writer FROM indexed", [], |row| row.get(0))
        .unwrap();
    assert_eq!(writer, Some(INDEX_VERSION));
    cleanup(&directory);
}

#[test]
fn matching_pages_and_filters_agree_with_ordinary_pages() {
    let (directory, recording) = dense_recording(700);
    let cancel = AtomicBool::new(false);
    let filtered = recording
        .filtered_page_cancellable(0, 10, None, &cancel, |call| call.async_omitted() > 0)
        .unwrap();
    assert_eq!((filtered.total, filtered.source_total), (1, 3));
    assert_eq!(filtered.page.invocations[0].async_saved, 700);
    let by_process = recording
        .process_page_cancellable(0, 2, None, &cancel)
        .unwrap();
    assert_eq!(by_process.invocations.len(), 2);
    assert!(by_process.next_offset.is_some());
    cleanup(&directory);
}

#[test]
fn a_preview_reads_only_its_window_and_a_page_only_its_page() {
    let (directory, recording) = dense_recording(1000);
    // Index it, then damage a packet far outside the first 256 observations.
    recording
        .invocation_count_cancellable(None, &AtomicBool::new(false))
        .unwrap();
    let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
    let far: i64 = index
        .query_row(
            "SELECT offset FROM packets WHERE phase=3 AND seq=?1 ORDER BY offset LIMIT 1",
            [async_page::seq_index(1000 + 800)],
            |row| row.get(0),
        )
        .unwrap();
    let mut raw = fs::OpenOptions::new()
        .write(true)
        .open(directory.join("telemetry.raw"))
        .unwrap();
    raw.seek(SeekFrom::Start(far as u64 + 4 + 40)).unwrap();
    raw.write_all(&[0xff; 8]).unwrap();
    drop(raw);
    drop(index);
    // The call's page does not touch it...
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations[0].async_saved, 1000);
    // ...the page that holds it reports the damage instead of hiding it.
    let cancel = AtomicBool::new(false);
    assert!(
        recording
            .async_page_cancellable(CALL, 1000 + 800, 256, &cancel)
            .is_err()
    );
    // Pages before it still read.
    assert_eq!(
        recording
            .async_page_cancellable(CALL, 1000 + 256, 256, &cancel)
            .unwrap()
            .events
            .len(),
        256
    );
    cleanup(&directory);
}

#[test]
fn missing_packets_leave_incomplete_observations_that_are_still_counted() {
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    for (seq, skip) in [
        (10, &[][..]),
        (11, &[1][..]),
        (12, &[2][..]),
        (13, &[5][..]),
        (14, &[1, 5][..]),
    ] {
        for packet in observation(1, seq, b"async.stage", skip) {
            write(&mut raw, packet);
        }
    }
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    let page = recording.invocation_page(0, 10).unwrap();
    let call = &page.invocations[0];
    assert_eq!((call.async_saved, call.async_omitted()), (5, 0));
    assert!(page.issues.is_empty());
    let browsed = recording
        .async_page_cancellable(CALL, 0, 3, &AtomicBool::new(false))
        .unwrap();
    assert_eq!(browsed.total, 5);
    assert_eq!(browsed.next_event_seq, Some(13));
    let seqs: Vec<_> = browsed.events.iter().map(|e| e.event_seq).collect();
    assert_eq!(seqs, [10, 11, 12]);
    // Each keeps what its packets carried and nothing it lost.
    assert!(browsed.events[0].args.is_some() && !browsed.events[0].fields.is_empty());
    assert!(browsed.events[1].args.is_none() && !browsed.events[1].fields.is_empty());
    assert!(browsed.events[2].args.is_some() && browsed.events[2].fields.is_empty());
    cleanup(&directory);
}

#[test]
fn page_arguments_cancellation_and_unknown_calls_are_rejected() {
    let (directory, recording) = dense_recording(10);
    let live = AtomicBool::new(false);
    for limit in [0, 257] {
        assert!(
            recording
                .async_page_cancellable(CALL, 0, limit, &live)
                .is_err()
        );
    }
    assert!(
        recording
            .async_page_cancellable(CALL, 0, 5, &AtomicBool::new(true))
            .is_err()
    );
    assert!(
        recording
            .async_page_cancellable((9, 10, 404), 0, 5, &live)
            .is_err()
    );
    // A cursor past the last observation is an empty page, not an error.
    let past = recording
        .async_page_cancellable(CALL, u64::MAX, 5, &live)
        .unwrap();
    assert!(past.events.is_empty() && past.next_event_seq.is_none());
    assert_eq!(past.total, 10);
    cleanup(&directory);
}

#[test]
fn an_index_from_the_previous_version_is_rebuilt_not_trusted() {
    let (directory, recording) = dense_recording(300);
    let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
    // The old schema had no phase or sequence columns.
    index
        .execute_batch(
            "DROP TABLE packets; DROP TABLE lifecycle; \
             CREATE TABLE packets(key BLOB NOT NULL, offset INTEGER NOT NULL); \
             UPDATE indexed SET identity=replace(identity,'index-v8','index-v7');",
        )
        .unwrap();
    drop(index);
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations[0].async_saved, 300);
    assert_eq!(browse_all(&recording, CALL, 100).0.len(), 300);
    cleanup(&directory);
}

#[test]
fn dense_index_stays_within_its_disk_budget() {
    let (directory, _) = dense_recording(2600);
    let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
    let pages: i64 = index
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    let raw = fs::metadata(directory.join("telemetry.raw")).unwrap().len();
    assert!((pages as u64) * 4096 < raw * 2 + 1024 * 1024);
    cleanup(&directory);
}

#[test]
fn page_boundaries_are_exact_at_the_preview_and_at_whole_pages() {
    let live = AtomicBool::new(false);
    // One short of, exactly, and one past the preview.
    for (completions, omitted) in [(255, 0), (256, 0), (257, 1)] {
        let (directory, recording) = dense_recording(completions);
        let page = recording.invocation_page(0, 10).unwrap();
        let dense = &page.invocations[0];
        assert_eq!(dense.async_omitted(), omitted, "{completions}");
        let partial = page.issues.iter().any(|issue| issue.contains("first 256"));
        assert_eq!(partial, omitted > 0, "{completions}");
        cleanup(&directory);
    }
    // Whole pages end without an empty trailing page.
    let (directory, recording) = dense_recording(512);
    let first = recording
        .async_page_cancellable(CALL, 0, 256, &live)
        .unwrap();
    let second = recording
        .async_page_cancellable(CALL, first.next_event_seq.unwrap(), 256, &live)
        .unwrap();
    assert_eq!((first.events.len(), second.events.len()), (256, 256));
    assert_eq!(second.next_event_seq, None);
    assert_eq!(second.events[255].event_seq, 1000 + 511);
    cleanup(&directory);
}

#[test]
fn interleaved_dense_calls_keep_their_own_observations() {
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    for call in [1, 4] {
        write(&mut raw, event_packet(call, 1, 1, 1));
        write(&mut raw, event_packet(call, 2, 5, 2));
    }
    for number in 0..600 {
        for call in [1, 4] {
            for packet in observation(call, call * 10_000 + number, b"async.request_id", &[]) {
                write(&mut raw, packet);
            }
        }
    }
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations.len(), 2);
    for call in &page.invocations {
        assert_eq!((call.async_saved, call.async_events.len()), (600, 256));
        assert!(call.entry.is_some() && call.exit.is_some());
    }
    for call in [1, 4] {
        let (seqs, total) = browse_all(&recording, (9, 10, call), 100);
        let expected: Vec<u64> = (0..600).map(|number| call * 10_000 + number).collect();
        assert_eq!((seqs, total), (expected, 600), "call {call}");
    }
    cleanup(&directory);
}

/// Packets, calls and lifecycle rows an index holds.
fn index_counts(connection: &rusqlite::Connection) -> (i64, i64, i64) {
    let count = |table: &str| -> i64 {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                row.get(0)
            })
            .unwrap()
    };
    (count("packets"), count("invocations"), count("lifecycle"))
}

#[test]
fn an_index_build_that_stops_between_chunks_resumes_from_its_cursor() {
    let (directory, recording) = dense_recording(300);
    let cancel = AtomicBool::new(false);
    let index_path = archive_index_path(&directory).unwrap();
    let (full, _) = archive_index(&directory, &cancel).unwrap();
    let reference = index_counts(&full);
    drop(full);
    fs::remove_file(&index_path).unwrap();
    // A build that dies after two chunks of a few packets each.
    let stopped = index_archive(&directory, &cancel, 512, 2);
    assert!(matches!(stopped, Err(RecordingError::Limit(_))));
    let partial = rusqlite::Connection::open(&index_path).unwrap();
    let (cursor, writer): (i64, Option<i64>) = partial
        .query_row("SELECT length, writer FROM indexed", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    let raw = fs::metadata(directory.join("telemetry.raw")).unwrap().len();
    assert!(
        cursor > 0 && (cursor as u64) < raw,
        "the cursor is inside the archive"
    );
    assert_eq!(writer, Some(INDEX_VERSION), "the partial index is stamped");
    let held = index_counts(&partial);
    assert!(held.0 > 0 && held.0 < reference.0, "a prefix is indexed");
    drop(partial);
    // The next open continues after the cursor instead of starting over or
    // appending the same packets twice.
    let (resumed, _) = archive_index(&directory, &cancel).unwrap();
    assert_eq!(index_counts(&resumed), reference);
    drop(resumed);
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations[0].async_saved, 300);
    cleanup(&directory);
}

#[test]
fn a_cancelled_first_index_keeps_the_chunks_it_committed() {
    let (directory, _) = dense_recording(300);
    let index_path = archive_index_path(&directory).unwrap();
    let _ = fs::remove_file(&index_path);
    let cancel = AtomicBool::new(false);
    let _ = index_archive(&directory, &cancel, 512, 1);
    cancel.store(true, Ordering::Relaxed);
    assert!(index_archive(&directory, &cancel, 512, usize::MAX).is_err());
    let connection = rusqlite::Connection::open(&index_path).unwrap();
    assert!(index_counts(&connection).0 > 0);
    cleanup(&directory);
}

#[test]
fn observations_attributed_to_a_task_outside_its_calls_are_read_by_the_task() {
    // An SQPOLL ring's thread submits for the ring's creator with call id 0;
    // the launch's lifecycle records share that key and are not observations.
    let directory = directory();
    let mut raw = File::create(directory.join("telemetry.raw")).unwrap();
    write(&mut raw, event_packet(1, 1, 1, 1));
    for packet in lifecycle(0, 5, b"lifecycle.launch") {
        write(&mut raw, packet);
    }
    for number in 0..300 {
        for packet in observation(0, 100 + number, b"async.request_id", &[]) {
            write(&mut raw, packet);
        }
    }
    write(&mut raw, event_packet(1, 2, 5, 2));
    raw.sync_all().unwrap();
    let recording = open_recording(&directory).unwrap();
    let cancel = AtomicBool::new(false);
    // No call owns them: the trace shows only call 1.
    let page = recording.invocation_page(0, 10).unwrap();
    assert_eq!(page.invocations.len(), 1);
    assert!(
        recording
            .async_page_cancellable((9, 10, 0), 0, 256, &cancel)
            .is_err()
    );
    let first = recording
        .attributed_async_page_cancellable(9, 10, 0, 256, &cancel)
        .unwrap();
    assert_eq!(first.events.len(), 256);
    assert_eq!(first.total, 300);
    assert!(first.events.iter().all(|event| event.event_seq >= 100));
    let rest = recording
        .attributed_async_page_cancellable(9, 10, first.next_event_seq.unwrap(), 256, &cancel)
        .unwrap();
    assert_eq!((rest.events.len(), rest.next_event_seq), (44, None));
    // Another task has none.
    let none = recording
        .attributed_async_page_cancellable(9, 11, 0, 256, &cancel)
        .unwrap();
    assert!(none.events.is_empty() && none.next_event_seq.is_none());
    cleanup(&directory);
}

#[test]
fn a_page_whose_previews_would_pass_its_budget_ends_early_and_the_next_goes_on() {
    let (directory, recording) = dense_recording(600);
    let cancel = AtomicBool::new(false);
    let whole = recording.invocation_page(0, 10).unwrap();
    assert_eq!(whole.invocations.len(), 3);
    let size = |call: &InvocationSummary| {
        call.entry
            .iter()
            .chain(call.exit.iter())
            .chain(&call.async_events)
            .chain(call.task_exit.iter())
            .map(event_preview_size)
            .sum::<usize>()
    };
    let sizes: Vec<_> = whole.invocations.iter().map(size).collect();
    // Room for the dense call's preview and not for the next one with it.
    let budget = sizes[0] + sizes[1] - 1;
    assert!(budget >= sizes[1] + sizes[2]);
    let first = recording
        .matching_page_within(0, 10, None, &cancel, |_| true, budget)
        .unwrap()
        .page;
    assert_eq!(first.invocations.len(), 1);
    assert_eq!(first.invocations[0].call_id, 1);
    let rest = recording
        .matching_page_within(
            first.next_offset.unwrap(),
            10,
            None,
            &cancel,
            |_| true,
            budget,
        )
        .unwrap()
        .page;
    let calls: Vec<_> = rest.invocations.iter().map(|call| call.call_id).collect();
    assert_eq!(calls, [2, 3]);
    assert_eq!(rest.next_offset, None);
    // A call alone past the budget cannot be shown.
    assert!(
        recording
            .matching_page_within(0, 10, None, &cancel, |_| true, sizes[0] - 1)
            .is_err()
    );
    cleanup(&directory);
}

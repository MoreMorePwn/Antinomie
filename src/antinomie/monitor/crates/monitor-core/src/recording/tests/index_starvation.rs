// SPDX-License-Identifier: GPL-3.0-only
//! A long walk of the packet index (the window's count) and the other reads
//! of the same run (the background digest) must not hold each other up
//! (ANT-T0575).
use super::*;
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

/// Long enough for a loaded host: a stalled read never ends.
const PATIENCE: Duration = Duration::from_secs(60);

fn fixture(calls: u64) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("ant-index-starvation-{}", storage::unique_id()));
    storage::private_dir(&directory).unwrap();
    fs::write(directory.join("telemetry.raw"), []).unwrap();
    storage::atomic_json(&directory.join("manifest.json"), &serde_json::json!({})).unwrap();
    append(&directory, 1, calls);
    directory
}

fn append(directory: &Path, first: u64, calls: u64) {
    let mut buffer = Vec::new();
    for call in first..first + calls {
        let packet = event_packet(call, 1, 1, call);
        buffer.extend((packet.len() as u32).to_le_bytes());
        buffer.extend(packet);
    }
    fs::OpenOptions::new()
        .append(true)
        .open(directory.join("telemetry.raw"))
        .unwrap()
        .write_all(&buffer)
        .unwrap();
}

fn recording(directory: &Path) -> Recording {
    Recording {
        directory: directory.to_path_buf(),
        manifest: serde_json::json!({}),
        events: vec![],
    }
}

fn cleanup(directory: &Path) {
    let index = archive_index_path(directory).unwrap();
    fs::remove_dir_all(directory).unwrap();
    for suffix in ["", "-journal"] {
        let mut path = index.clone().into_os_string();
        path.push(suffix);
        let _ = fs::remove_file(PathBuf::from(path));
    }
}

/// The window's count of `directory` on a thread of its own, slowed down so
/// it is still walking while the test reads; returns once it has started
/// walking. Setting the flag stops it.
fn slow_count(directory: &Path) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let stop = Arc::new(AtomicBool::new(false));
    let (started, walking) = mpsc::channel();
    let thread = {
        let directory = directory.to_path_buf();
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut first = true;
            let counted = recording(&directory).matching_totals_cancellable(None, &stop, |_| {
                if first {
                    first = false;
                    started.send(()).unwrap();
                }
                std::thread::sleep(Duration::from_millis(2));
                true
            });
            assert!(
                stop.load(Ordering::Relaxed),
                "the count ended before the test stopped it: {:?}",
                counted.map(|totals| totals.total)
            );
        })
    };
    walking.recv_timeout(PATIENCE).unwrap();
    (stop, thread)
}

/// What the digest does first: count the calls, then read the first page.
/// `None` when it did not get through within the patience.
fn digest_reads(directory: &Path) -> Option<(u64, usize)> {
    let cancel = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();
    let reader = {
        let directory = directory.to_path_buf();
        let cancel = Arc::clone(&cancel);
        std::thread::spawn(move || {
            let recording = recording(&directory);
            let read = recording
                .invocation_count_cancellable(None, &cancel)
                .and_then(|total| {
                    let page = recording.invocation_page_cancellable(0, 256, &cancel)?;
                    Ok((total, page.invocations.len()))
                });
            let _ = tx.send(read.map_err(|error| error.to_string()));
        })
    };
    let read = rx.recv_timeout(PATIENCE).ok();
    cancel.store(true, Ordering::Relaxed);
    reader.join().unwrap();
    read.map(Result::unwrap)
}

#[test]
fn the_digest_reads_a_run_while_the_window_counts_its_calls() {
    let directory = fixture(20_000);
    drop(archive_index(&directory, &AtomicBool::new(false)).unwrap());
    let (stop, count) = slow_count(&directory);
    // Every open of the index used to take the writer reservation and commit
    // it, which needs the file to itself: the digest waited for the end of
    // the count.
    assert_eq!(digest_reads(&directory), Some((20_000, 256)));
    stop.store(true, Ordering::Relaxed);
    count.join().unwrap();
    cleanup(&directory);
}

#[test]
fn an_index_left_part_built_by_a_crash_finishes_while_the_window_counts() {
    let directory = fixture(20_000);
    let never = AtomicBool::new(false);
    let index_path = archive_index_path(&directory).unwrap();
    let _ = fs::remove_file(&index_path);
    // The app was killed after the first chunk of the build.
    assert!(index_archive(&directory, &never, 256 * 1024, 1).is_err());
    let (stop, count) = slow_count(&directory);
    assert_eq!(digest_reads(&directory), Some((20_000, 256)));
    // More calls than the counted prefix (a recording still being written):
    // the digest extends the index while the window is still walking it.
    append(&directory, 20_001, 5_000);
    assert_eq!(digest_reads(&directory), Some((25_000, 256)));
    stop.store(true, Ordering::Relaxed);
    count.join().unwrap();
    cleanup(&directory);
}

#[test]
fn a_recording_cut_off_inside_a_packet_is_read_while_the_window_counts() {
    let directory = fixture(20_000);
    let tail = event_packet(20_001, 1, 1, 20_001);
    let mut raw = fs::OpenOptions::new()
        .append(true)
        .open(directory.join("telemetry.raw"))
        .unwrap();
    raw.write_all(&(tail.len() as u32).to_le_bytes()).unwrap();
    raw.write_all(&tail[..80]).unwrap();
    drop(raw);
    drop(archive_index(&directory, &AtomicBool::new(false)).unwrap());
    let (stop, count) = slow_count(&directory);
    // The cursor stops before the cut-off packet, short of the file's end:
    // an open must not rewrite it each time.
    assert_eq!(digest_reads(&directory), Some((20_000, 256)));
    stop.store(true, Ordering::Relaxed);
    count.join().unwrap();
    cleanup(&directory);
}

#[test]
fn a_read_that_waits_for_the_index_says_so() {
    let directory = fixture(100);
    let (mut held, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
    // A builder holds the index to itself.
    let transaction = held
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let reader = {
        let directory = directory.clone();
        std::thread::spawn(move || {
            let told = tx.clone();
            with_index_wait(
                move |waiting| told.send(Some(waiting)).unwrap(),
                || {
                    recording(&directory)
                        .invocation_count_cancellable(None, &AtomicBool::new(false))
                        .unwrap()
                },
            );
            tx.send(None).unwrap();
        })
    };
    assert_eq!(rx.recv_timeout(PATIENCE).unwrap(), Some(true));
    transaction.commit().unwrap();
    assert_eq!(rx.recv_timeout(PATIENCE).unwrap(), Some(false));
    assert_eq!(rx.recv_timeout(PATIENCE).unwrap(), None);
    reader.join().unwrap();
    drop(held);
    cleanup(&directory);
}

// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::{
    sync::{Arc, Barrier, mpsc},
    time::Duration,
};

fn fixture() -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("ant-index-concurrency-{}", storage::unique_id()));
    storage::private_dir(&directory).unwrap();
    fs::write(directory.join("telemetry.raw"), []).unwrap();
    directory
}

fn append(directory: &Path, start: u64, count: u64) {
    let mut raw = fs::OpenOptions::new()
        .append(true)
        .open(directory.join("telemetry.raw"))
        .unwrap();
    for call in start..start + count {
        let packet = event_packet(call, 1, 1, call);
        raw.write_all(&(packet.len() as u32).to_le_bytes()).unwrap();
        raw.write_all(&packet).unwrap();
    }
}

fn cleanup(directory: &Path) {
    let index = archive_index_path(directory).unwrap();
    fs::remove_dir_all(directory).unwrap();
    fs::remove_file(index).unwrap();
}

#[test]
fn busy_index_waits_beyond_old_timeout_and_can_be_cancelled() {
    let directory = fixture();
    append(&directory, 1, 100);
    let (mut held, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
    let transaction = held
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let path = directory.clone();
    let reader = std::thread::spawn(move || {
        tx.send(archive_index(&path, &AtomicBool::new(false)).map(|_| ()))
            .unwrap();
    });
    assert!(matches!(
        rx.recv_timeout(Duration::from_millis(1200)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    transaction.commit().unwrap();
    rx.recv_timeout(Duration::from_secs(60)).unwrap().unwrap();
    reader.join().unwrap();

    let transaction = held
        .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
        .unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&cancel);
    let path = directory.clone();
    let (tx, rx) = mpsc::sync_channel(1);
    let reader =
        std::thread::spawn(move || tx.send(archive_index(&path, &flag).map(|_| ())).unwrap());
    std::thread::sleep(Duration::from_millis(100));
    cancel.store(true, Ordering::Relaxed);
    // The wait for the lock ends on the cancellation; how soon a loaded host
    // gets to it is not what is tested.
    let error = rx
        .recv_timeout(Duration::from_secs(60))
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("cancelled"));
    reader.join().unwrap();
    transaction.commit().unwrap();
    drop(held);
    cleanup(&directory);
}

#[test]
fn concurrent_append_indexing_keeps_each_packet_once() {
    let directory = fixture();
    append(&directory, 1, 100);
    drop(archive_index(&directory, &AtomicBool::new(false)).unwrap());
    append(&directory, 101, 2000);
    let barrier = Arc::new(Barrier::new(4));
    let readers: Vec<_> = (0..4)
        .map(|_| {
            let barrier = Arc::clone(&barrier);
            let directory = directory.clone();
            std::thread::spawn(move || {
                barrier.wait();
                let recording = Recording {
                    directory,
                    manifest: serde_json::json!({}),
                    events: vec![],
                };
                assert_eq!(
                    recording
                        .invocation_count_cancellable(None, &AtomicBool::new(false))
                        .unwrap(),
                    2100
                );
            })
        })
        .collect();
    for reader in readers {
        reader.join().unwrap();
    }
    let (index, _) = archive_index(&directory, &AtomicBool::new(false)).unwrap();
    let counts: (i64, i64) = index
        .query_row(
            "SELECT count(*), count(DISTINCT offset) FROM packets",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(counts, (2100, 2100));
    drop(index);
    cleanup(&directory);
}

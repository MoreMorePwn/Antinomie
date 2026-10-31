// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::time::Duration;

#[test]
fn appends_and_positioned_writes_land_in_order_and_errors_are_reported() {
    let root = std::env::temp_dir().join(format!("ant-writer-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    let raw = Arc::new(File::create(root.join("raw")).unwrap());
    let object = Arc::new(File::create(root.join("object")).unwrap());
    let slot = error_slot();
    for part in [&b"one"[..], b"two"] {
        submit(Op::Append {
            file: raw.clone(),
            data: part.to_vec(),
            rollback: 0,
            error: slot.clone(),
        });
    }
    for (offset, part) in [(3, &b"def"[..]), (0, b"abc")] {
        submit(Op::WriteAt {
            file: object.clone(),
            offset,
            data: part.to_vec(),
            error: slot.clone(),
        });
    }
    let bad = error_slot();
    let read_only = Arc::new(File::open(root.join("raw")).unwrap());
    submit(Op::WriteAt {
        file: read_only,
        offset: 0,
        data: b"x".to_vec(),
        error: bad.clone(),
    });
    barrier();
    assert_eq!(std::fs::read(root.join("raw")).unwrap(), b"onetwo");
    assert_eq!(std::fs::read(root.join("object")).unwrap(), b"abcdef");
    assert!(error_of(&slot).is_none());
    assert!(error_of(&bad).is_some_and(|e| e.contains("host object persistence")));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_ticket_waits_for_its_own_write_and_no_ticket_waits_for_nothing() {
    let root =
        std::env::temp_dir().join(format!("ant-writer-ticket-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    let slow = held::SlowWriter::install();
    let slot = error_slot();
    let file = Arc::new(File::create(root.join("held")).unwrap());
    slow.pause();
    let ticket = submit(Op::Append {
        file,
        data: b"late".to_vec(),
        rollback: 0,
        error: slot,
    });
    // A recording that submitted nothing does not wait for a stalled disk.
    let started = Instant::now();
    wait_for(0);
    // Returns at once or, with the disk stalled, never: the bound is loose.
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(slow.queued_len(), 4);
    slow.resume();
    wait_for(ticket);
    assert_eq!(std::fs::read(root.join("held")).unwrap(), b"late");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn try_submit_returns_when_the_bounded_queue_is_full() {
    let root = std::env::temp_dir().join(format!("ant-writer-try-{}", crate::storage::unique_id()));
    std::fs::create_dir_all(&root).unwrap();
    let slow = held::SlowWriter::install_with_limit(4);
    slow.pause();
    let slot = error_slot();
    let file = Arc::new(File::create(root.join("held")).unwrap());
    let ticket = try_submit(Op::Append {
        file: file.clone(),
        data: b"full".to_vec(),
        rollback: 0,
        error: slot.clone(),
    })
    .unwrap_or_else(|_| panic!("bounded writer accepted the first operation"));
    let started = Instant::now();
    let rejected = try_submit(Op::Append {
        file,
        data: b"x".to_vec(),
        rollback: 4,
        error: slot,
    });
    // A full queue answers at once; the bound is loose for a loaded host.
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(matches!(rejected, Err(Op::Append { data, .. }) if data == b"x"));
    assert_eq!(slow.queued_len(), 4);
    slow.resume();
    wait_for(ticket);
    assert_eq!(std::fs::read(root.join("held")).unwrap(), b"full");
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn time_spent_waiting_for_the_writer_is_counted_on_the_waiting_thread_only() {
    let root = std::env::temp_dir().join(format!(
        "ant-writer-blocked-{}",
        crate::storage::unique_id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let slow = held::SlowWriter::install();
    let file = Arc::new(File::create(root.join("held")).unwrap());
    slow.pause();
    let ticket = submit(Op::Append {
        file,
        data: b"x".to_vec(),
        rollback: 0,
        error: error_slot(),
    });
    let before = blocked_on_this_thread();
    // The private writer is looked up per thread; resume it from this one
    // after a delay by a helper that only flips the flag.
    let resumer = {
        let writer = writer();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            writer
                .paused
                .store(false, std::sync::atomic::Ordering::Release);
            let _state = writer.state.lock().unwrap();
            writer.changed.notify_all();
        })
    };
    wait_for(ticket);
    resumer.join().unwrap();
    assert!(blocked_on_this_thread() - before >= Duration::from_millis(100));
    let other = thread::spawn(blocked_on_this_thread).join().unwrap();
    assert_eq!(other, Duration::ZERO);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_raw_capture_keeps_what_a_full_queue_cannot_take_and_saves_it_later() {
    let root =
        std::env::temp_dir().join(format!("ant-writer-held-{}", crate::storage::unique_id()));
    let slow = held::SlowWriter::install_with_limit(1536 * 1024);
    slow.pause();
    let mut capture = crate::storage::RawCapture::new(root.clone(), 1 << 30).unwrap();
    assert!(!backlogged());
    let mut expected = Vec::new();
    for number in 0..24u8 {
        let packet = vec![number; 100 * 1024];
        assert!(capture.append(&packet), "saving goes on");
        expected.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        expected.extend_from_slice(&packet);
    }
    assert!(capture.flush());
    // One block is queued; the rest waits in the capture, and the transport
    // owner takes no more telemetry meanwhile.
    assert!(backlogged());
    assert!(slow.queued_len() <= 1536 * 1024);
    assert_eq!(capture.error, None);
    slow.resume();
    capture.sync().unwrap();
    assert!(!backlogged());
    assert_eq!(std::fs::read(root.join("telemetry.raw")).unwrap(), expected);
    drop(capture);
    drop(slow);
    std::fs::remove_dir_all(root).unwrap();
}

// SPDX-License-Identifier: GPL-3.0-only
use super::*;

fn reply(sequence: u64, age: u64, flags: u32) -> Vec<u8> {
    let mut data = vec![0u8; 96];
    let mut put = |at: usize, bytes: &[u8]| data[at..at + bytes.len()].copy_from_slice(bytes);
    put(0, &sequence.to_le_bytes());
    put(8, &age.to_le_bytes());
    put(16, &flags.to_le_bytes());
    put(24, &10240u64.to_le_bytes());
    put(32, &4096u64.to_le_bytes());
    put(40, &(100 * 4096u64).to_le_bytes());
    put(48, &(40 * 4096u64).to_le_bytes());
    put(56, &(30 * 4096u64).to_le_bytes());
    put(64, &7u32.to_le_bytes());
    put(68, &0xef53u32.to_le_bytes());
    data
}
fn ask(producer: &mut KernelResources, id: u64, now: Instant) {
    let (opcode, args) = producer.command(now).expect("request due");
    assert_eq!(opcode, control::RESOURCES);
    assert_eq!(args, control::header(0));
    producer.submitted(id, now);
}

#[test]
fn reports_memory_and_root_filesystem_with_reserved_space_separate() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.reply(1, 0, &reply(5, 300, 3), "boot", now));
    let value = producer.sample("boot", false);
    assert_eq!(value.memory_total_size, Some(10240));
    assert_eq!(value.memory_used_size, Some(6144));
    assert_eq!(value.root_total_size, Some(100 * 4096));
    assert_eq!(value.root_used_size, Some(60 * 4096));
    assert_eq!(value.root_free_size, Some(40 * 4096));
    assert_eq!(value.root_available_size, Some(30 * 4096));
    assert_eq!(value.sample_sequence, 5);
    assert!(!value.stale && value.error.is_none());
    assert!(value.age_ms.unwrap() >= 300);
    assert!(producer.sample("boot", true).stale);
}

#[test]
fn one_request_is_in_flight_and_foreign_replies_are_not_consumed() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.command(now + Duration::from_secs(1)).is_none());
    assert!(!producer.reply(2, 0, &reply(1, 0, 3), "boot", now));
    assert!(producer.pending.is_some());
    assert!(producer.reply(1, 0, &reply(1, 0, 3), "boot", now));
    assert!(producer.command(now + Duration::from_millis(500)).is_none());
    assert!(producer.command(now + Duration::from_secs(1)).is_some());
}

#[test]
fn a_late_reply_marks_stale_without_resending_and_then_recovers() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.reply(1, 0, &reply(1, 0, 3), "boot", now));
    ask(&mut producer, 2, now + Duration::from_secs(1));
    assert!(producer.command(now + Duration::from_secs(6)).is_none());
    let late = producer.sample("boot", false);
    assert!(late.stale && late.error.as_deref().unwrap().contains("late"));
    assert!(producer.reply(2, 0, &reply(2, 0, 3), "boot", now + Duration::from_secs(7)));
    assert!(!producer.sample("boot", false).stale);
}

#[test]
fn a_request_that_never_gets_a_reply_is_abandoned_and_polling_resumes() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.command(now + Duration::from_secs(59)).is_none());
    // Past the deadline the id is dropped and a new request is offered.
    assert!(producer.command(now + Duration::from_secs(61)).is_some());
    let value = producer.sample("boot", false);
    assert!(value.error.as_deref().unwrap().contains("never arrived"));
    // The abandoned id is no longer owned, so a very late reply is ignored.
    assert!(!producer.reply(1, 0, &reply(1, 0, 3), "boot", now + Duration::from_secs(62)));
    ask(&mut producer, 2, now + Duration::from_secs(62));
    assert!(producer.reply(2, 0, &reply(1, 0, 3), "boot", now + Duration::from_secs(63)));
    assert!(producer.sample("boot", false).error.is_none());
}

#[test]
fn first_poll_without_a_sample_retries_quickly_and_is_unavailable() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.reply(1, 0, &reply(0, u64::MAX, 4), "boot", now));
    let value = producer.sample("boot", false);
    assert!(value.stale && value.memory_used_size.is_none() && value.age_ms.is_none());
    assert!(producer.command(now + Duration::from_millis(250)).is_some());
}

#[test]
fn independent_failures_and_blocked_refresh_are_reported() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    let mut data = reply(3, 0, 1 | 4);
    data[20..24].copy_from_slice(&(-5i32).to_le_bytes());
    data[80..88].copy_from_slice(&9000u64.to_le_bytes());
    assert!(producer.reply(1, 0, &data, "boot", now));
    let value = producer.sample("boot", false);
    assert!(value.memory_used_size.is_some() && value.root_used_size.is_none());
    let error = value.error.unwrap();
    assert!(error.contains("errno 5") && error.contains("blocked"));
}

#[test]
fn invalid_replies_are_errors_not_samples() {
    let now = Instant::now();
    for mutate in [
        |data: &mut Vec<u8>| data.truncate(95),
        |data: &mut Vec<u8>| data[92] = 1,
        |data: &mut Vec<u8>| data[16..20].copy_from_slice(&8u32.to_le_bytes()),
        |data: &mut Vec<u8>| data[32..40].copy_from_slice(&20000u64.to_le_bytes()),
        |data: &mut Vec<u8>| data[48..56].copy_from_slice(&u64::MAX.to_le_bytes()),
        |data: &mut Vec<u8>| data[56..64].copy_from_slice(&(50 * 4096u64).to_le_bytes()),
    ] {
        let mut producer = KernelResources::default();
        ask(&mut producer, 1, now);
        let mut data = reply(1, 0, 3);
        mutate(&mut data);
        assert!(producer.reply(1, 0, &data, "boot", now));
        let value = producer.sample("boot", false);
        assert!(value.stale && value.error.is_some() && value.memory_used_size.is_none());
    }
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.reply(1, 0, &reply(9, 0, 3), "boot", now));
    ask(&mut producer, 2, now + Duration::from_secs(1));
    assert!(producer.reply(2, 0, &reply(8, 0, 3), "boot", now + Duration::from_secs(1)));
    assert!(
        producer
            .sample("boot", false)
            .error
            .unwrap()
            .contains("backwards")
    );
}

#[test]
fn rejections_back_off_and_unsupported_stops_polling() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.reply(1, -12, &[], "boot", now));
    assert!(producer.command(now + Duration::from_secs(1)).is_none());
    assert!(producer.command(now + Duration::from_secs(2)).is_some());
    producer.submitted(2, now + Duration::from_secs(2));
    assert!(producer.reply(2, EOPNOTSUPP, &[], "boot", now + Duration::from_secs(2)));
    assert!(producer.command(now + Duration::from_secs(60)).is_none());
    assert!(producer.sample("boot", false).stale);
}

#[test]
fn timeline_reset_drops_readings_and_ignores_the_answer_in_flight() {
    let now = Instant::now();
    let mut producer = KernelResources::default();
    ask(&mut producer, 1, now);
    assert!(producer.reply(1, 0, &reply(4, 0, 3), "boot", now));
    ask(&mut producer, 2, now + Duration::from_secs(1));
    producer.reset_timeline();
    assert!(producer.sample("boot", false).memory_used_size.is_none());
    assert!(producer.command(now + Duration::from_secs(9)).is_none());
    assert!(producer.reply(2, 0, &reply(5, 0, 3), "boot", now + Duration::from_secs(2)));
    assert!(producer.sample("boot", false).memory_used_size.is_none());
    ask(&mut producer, 3, now + Duration::from_secs(3));
    assert!(producer.reply(3, 0, &reply(1, 0, 3), "boot", now + Duration::from_secs(3)));
    assert!(producer.sample("boot", false).memory_used_size.is_some());
}

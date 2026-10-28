use super::*;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn tracker() -> (ReadGapTracker, Instant) {
    let mut tracker = ReadGapTracker::default();
    tracker.set_send_wait(100_000);
    (tracker, Instant::now())
}

#[test]
fn reads_closer_than_the_threshold_record_nothing() {
    let (mut tracker, t0) = tracker();
    let mut stats = ReadGapStats::default();
    for step in 0..10 {
        tracker.read(t0 + ms(step * 10), Duration::ZERO, &mut stats);
    }
    assert_eq!(stats.count, 0);
    assert!(stats.gaps.is_empty());
    assert_eq!(stats.threshold_ns, 50_000_000);
}

#[test]
fn a_long_pause_is_recorded_with_its_guest_time_and_length() {
    let (mut tracker, t0) = tracker();
    let mut stats = ReadGapStats::default();
    tracker.packet(7_000);
    tracker.read(t0, Duration::ZERO, &mut stats);
    tracker.read(t0 + ms(130), Duration::ZERO, &mut stats);
    assert_eq!(
        (stats.count, stats.total_ns, stats.longest_ns),
        (1, 130_000_000, 130_000_000)
    );
    assert_eq!(stats.gaps[0].guest_ns, 7_000);
    assert_eq!(stats.gaps[0].len_ns, 130_000_000);
}

#[test]
fn the_first_read_and_a_new_transport_start_no_pause() {
    let (mut tracker, t0) = tracker();
    let mut stats = ReadGapStats::default();
    tracker.read(t0 + ms(900), Duration::ZERO, &mut stats);
    assert_eq!(stats.count, 0);
    tracker.reset();
    tracker.read(t0 + ms(2000), Duration::ZERO, &mut stats);
    assert_eq!(stats.count, 0);
}

#[test]
fn the_threshold_follows_the_send_wait() {
    let mut tracker = ReadGapTracker::default();
    for (wait_us, expected) in [
        (0, 50),
        (100_000, 50),
        (40_000, 20),
        (1_000, 10),
        (900_000, 50),
    ] {
        tracker.set_send_wait(wait_us);
        let mut stats = ReadGapStats::default();
        tracker.read(Instant::now(), Duration::ZERO, &mut stats);
        assert_eq!(
            stats.threshold_ns,
            expected * 1_000_000,
            "send wait {wait_us} us"
        );
    }
}

#[test]
fn the_cause_is_the_writer_the_pass_or_the_loop() {
    let (mut tracker, t0) = tracker();
    let mut stats = ReadGapStats::default();
    // Held back for the writer: a pass started held.
    tracker.read(t0, Duration::ZERO, &mut stats);
    tracker.enter(t0 + ms(10), true);
    tracker.exit(t0 + ms(12));
    tracker.read(t0 + ms(100), Duration::ZERO, &mut stats);
    // Waiting inside a pass for the writer queue.
    tracker.enter(t0 + ms(100), false);
    tracker.read(t0 + ms(101), ms(1), &mut stats);
    tracker.read(t0 + ms(201), ms(90), &mut stats);
    // Mostly inside the pass, not waiting.
    tracker.read(t0 + ms(202), ms(90), &mut stats);
    tracker.read(t0 + ms(300), ms(90), &mut stats);
    tracker.exit(t0 + ms(300));
    // Away from the pass for 200 ms with no scheduler data.
    tracker.enter(t0 + ms(500), false);
    tracker.read(t0 + ms(500), ms(90), &mut stats);
    let causes: Vec<_> = stats.gaps.iter().map(|gap| gap.cause).collect();
    assert_eq!(
        causes,
        [
            GapCause::WriterBacklog,
            GapCause::WriterWait,
            GapCause::Pump,
            GapCause::Blocked
        ]
    );
    assert_eq!(stats.gaps[1].blocked_ns, 89_000_000);
    assert_eq!(stats.count, 4);
}

#[test]
fn a_full_buffer_keeps_the_longest_pauses_and_counts_the_rest() {
    let mut stats = ReadGapStats::default();
    for len in 1..=MAX_RECORDED_GAPS as u64 + 10 {
        stats.record(ReadGap {
            len_ns: len * 1_000,
            ..ReadGap::default()
        });
    }
    let capacity = stats.gaps.capacity();
    stats.record(ReadGap {
        len_ns: 1,
        ..ReadGap::default()
    });
    assert_eq!(stats.gaps.len(), MAX_RECORDED_GAPS);
    assert_eq!(
        stats.gaps.capacity(),
        capacity,
        "no growth past the fixed buffer"
    );
    assert_eq!(stats.count, MAX_RECORDED_GAPS as u64 + 11);
    assert_eq!(stats.unrecorded, 11);
    assert_eq!(stats.longest_ns, (MAX_RECORDED_GAPS as u64 + 10) * 1_000);
    assert!(stats.gaps.iter().all(|gap| gap.len_ns > 10_000));
}

#[test]
fn the_causes_add_up_by_total_time() {
    let mut stats = ReadGapStats::default();
    for (cause, len_ns) in [
        (GapCause::Pump, 100),
        (GapCause::Busy, 300),
        (GapCause::Pump, 250),
    ] {
        stats.record(ReadGap {
            cause,
            len_ns,
            ..ReadGap::default()
        });
    }
    assert_eq!(
        stats.by_cause(),
        [(GapCause::Pump, 2, 350), (GapCause::Busy, 1, 300)]
    );
}

#[test]
fn schedstat_of_this_thread_parses_when_the_kernel_has_it() {
    if let Some(file) = SchedFile::open() {
        let first = file.sample().expect("a schedstat sample");
        let mut spin = 0u64;
        for n in 0..2_000_000u64 {
            spin = spin.wrapping_add(n);
        }
        assert!(spin > 0);
        assert!(file.sample().expect("a second sample").cpu_ns >= first.cpu_ns);
    }
}

#[test]
fn a_ring_whose_head_waited_long_is_a_gap_of_that_ring() {
    let (mut tracker, t0) = tracker();
    let mut stats = ReadGapStats::default();
    tracker.read(t0, Duration::ZERO, &mut stats);
    tracker.packet(9_000_000_000);
    tracker.ring_wait(1, 10_000_000, &mut stats);
    assert_eq!(stats.count, 0, "a short wait is not recorded");
    tracker.ring_wait(2, 120_000_000, &mut stats);
    assert_eq!(stats.count, 1);
    let gap = stats.gaps[0];
    assert_eq!(
        (gap.ring, gap.cause, gap.len_ns),
        (Some(2), GapCause::RingStarved, 120_000_000)
    );
    assert_eq!(gap.guest_ns, 9_000_000_000 - 120_000_000);
}

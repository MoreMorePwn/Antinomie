// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use std::cell::Cell;

/// A clock the test moves: the pass bounds are about time, and the wall clock
/// of a loaded host would decide them instead of the code.
struct Clock {
    base: Instant,
    elapsed: Cell<Duration>,
}

impl Clock {
    fn new() -> Self {
        Self {
            base: Instant::now(),
            elapsed: Cell::new(Duration::ZERO),
        }
    }
    fn now(&self) -> Instant {
        self.base + self.elapsed.get()
    }
    fn pass(&self, time: Duration) {
        self.elapsed.set(self.elapsed.get() + time);
    }
}

fn full() -> Result<TerminalRead, String> {
    Ok(TerminalRead {
        len: TERMINAL_READ_SIZE,
        full: true,
    })
}

#[test]
fn a_pass_reads_every_full_chunk_until_a_short_one() {
    let reads = Cell::new(0);
    let clock = Clock::new();
    drain_pass_on(
        || clock.now(),
        Duration::from_secs(1),
        |_| {
            reads.set(reads.get() + 1);
            if reads.get() <= 9 {
                full()
            } else {
                Ok(TerminalRead {
                    len: 100,
                    full: false,
                })
            }
        },
    )
    .unwrap();
    assert_eq!(
        reads.get(),
        10,
        "nine full reads and the short one that ends the pass"
    );
}

#[test]
fn a_pass_with_nothing_to_read_makes_one_read() {
    let reads = Cell::new(0);
    let clock = Clock::new();
    drain_pass_on(
        || clock.now(),
        Duration::from_millis(100),
        |_| {
            reads.set(reads.get() + 1);
            Ok(TerminalRead::default())
        },
    )
    .unwrap();
    assert_eq!(reads.get(), 1);
}

#[test]
fn a_pass_stops_at_the_size_bound_for_an_endless_terminal() {
    let reads = Cell::new(0);
    let clock = Clock::new();
    drain_pass_on(
        || clock.now(),
        Duration::from_secs(60),
        |_| {
            reads.set(reads.get() + 1);
            full()
        },
    )
    .unwrap();
    assert_eq!(reads.get(), TERMINAL_PASS_SIZE / TERMINAL_READ_SIZE);
}

#[test]
fn a_pass_stops_at_the_time_slice_when_each_read_is_slow() {
    let reads = Cell::new(0);
    let clock = Clock::new();
    drain_pass_on(
        || clock.now(),
        Duration::from_secs(60),
        |_| {
            reads.set(reads.get() + 1);
            clock.pass(Duration::from_millis(10));
            full()
        },
    )
    .unwrap();
    // Reads start at 0, 10, 20 and 30 ms; the slice is over after the fourth.
    assert_eq!(reads.get(), 4);
    assert_eq!(clock.elapsed.get(), TERMINAL_PASS_SLICE);
}

#[test]
fn each_read_gets_the_time_left_and_an_error_ends_the_pass() {
    let seen = std::cell::RefCell::new(Vec::new());
    let clock = Clock::new();
    let result = drain_pass_on(
        || clock.now(),
        Duration::from_millis(100),
        |left| {
            seen.borrow_mut().push(left);
            if seen.borrow().len() == 3 {
                return Err("guest command deadline exhausted".into());
            }
            clock.pass(Duration::from_millis(3));
            full()
        },
    );
    assert_eq!(result.unwrap_err(), "guest command deadline exhausted");
    let seen = seen.into_inner();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0], TERMINAL_PASS_SLICE);
    assert!(
        seen[2] < seen[0],
        "the deadline shrinks as the pass goes on"
    );
    assert_eq!(seen[2], TERMINAL_PASS_SLICE - Duration::from_millis(6));
}

#[test]
fn one_late_reply_cannot_consume_the_whole_command_timeout() {
    let reads = Cell::new(0);
    let clock = Clock::new();
    drain_pass_on(
        || clock.now(),
        Duration::from_millis(200),
        |budget| {
            assert!(budget <= TERMINAL_PASS_SLICE);
            reads.set(reads.get() + 1);
            // The reply takes all of the time the read was given.
            clock.pass(budget);
            Ok(TerminalRead {
                len: TERMINAL_READ_SIZE,
                full: true,
            })
        },
    )
    .unwrap();
    assert_eq!(reads.get(), 1, "a single read used up the pass slice");
    assert_eq!(clock.elapsed.get(), TERMINAL_PASS_SLICE);
}

#[test]
fn a_zero_timeout_still_reads_once_and_reports_the_deadline_error() {
    let result = drain_pass(Duration::ZERO, |left| {
        assert!(left.is_zero());
        Err("guest command deadline exhausted before submission".into())
    });
    assert!(result.is_err());
}

fn chunk(sequence: u64, size: usize) -> Notification {
    Notification::Terminal {
        run_id: "run".into(),
        sequence,
        data: vec![b'x'; size],
        eof: false,
    }
}

fn sequences(receiver: &std::sync::mpsc::Receiver<Notification>) -> Vec<u64> {
    receiver
        .try_iter()
        .map(|notification| match notification {
            Notification::Terminal { sequence, .. } => sequence,
            _ => unreachable!(),
        })
        .collect()
}

#[test]
fn output_that_finds_the_lane_full_waits_and_keeps_its_order() {
    let (sender, receiver) = std::sync::mpsc::sync_channel(2);
    let mut backlog = TerminalBacklog::default();
    for sequence in 1..=5 {
        assert_eq!(backlog.send(&sender, chunk(sequence, 10), 10), 0);
    }
    assert_eq!(backlog.waiting(), 3);
    assert_eq!(sequences(&receiver), [1, 2]);
    backlog.flush(&sender);
    assert_eq!(sequences(&receiver), [3, 4]);
    // A new chunk goes after the one still waiting, never before it.
    assert_eq!(backlog.send(&sender, chunk(6, 10), 10), 0);
    assert_eq!(sequences(&receiver), [5, 6]);
    assert_eq!(backlog.waiting(), 0);
}

#[test]
fn past_the_bound_the_oldest_output_is_dropped_and_counted() {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let mut backlog = TerminalBacklog::default();
    let big = TERMINAL_BACKLOG_SIZE / 2;
    assert_eq!(backlog.send(&sender, chunk(1, 1), 1), 0);
    assert_eq!(backlog.send(&sender, chunk(2, big), big), 0);
    assert_eq!(backlog.send(&sender, chunk(3, big), big), 0);
    assert_eq!(backlog.send(&sender, chunk(4, big), big), 1);
    assert_eq!(sequences(&receiver), [1]);
    backlog.flush(&sender);
    assert_eq!(sequences(&receiver), [3]);
}

#[test]
fn a_gone_frontend_empties_the_backlog() {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    drop(receiver);
    let mut backlog = TerminalBacklog::default();
    backlog.send(&sender, chunk(1, 10), 10);
    assert_eq!(backlog.waiting(), 0);
}

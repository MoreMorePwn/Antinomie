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

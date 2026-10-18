use super::*;
use std::cell::Cell;

fn full() -> Result<TerminalRead, String> {
    Ok(TerminalRead {
        len: TERMINAL_READ_SIZE,
        full: true,
    })
}

#[test]
fn a_pass_reads_every_full_chunk_until_a_short_one() {
    let reads = Cell::new(0);
    drain_pass(Duration::from_secs(1), |_| {
        reads.set(reads.get() + 1);
        if reads.get() <= 9 {
            full()
        } else {
            Ok(TerminalRead {
                len: 100,
                full: false,
            })
        }
    })
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
    drain_pass(Duration::from_millis(100), |_| {
        reads.set(reads.get() + 1);
        Ok(TerminalRead::default())
    })
    .unwrap();
    assert_eq!(reads.get(), 1);
}

#[test]
fn a_pass_stops_at_the_size_bound_for_an_endless_terminal() {
    let reads = Cell::new(0);
    drain_pass(Duration::from_secs(60), |_| {
        reads.set(reads.get() + 1);
        full()
    })
    .unwrap();
    assert_eq!(reads.get(), TERMINAL_PASS_SIZE / TERMINAL_READ_SIZE);
}

#[test]
fn a_pass_stops_at_the_time_slice_when_each_read_is_slow() {
    let reads = Cell::new(0);
    let started = Instant::now();
    drain_pass(Duration::from_secs(60), |_| {
        reads.set(reads.get() + 1);
        std::thread::sleep(Duration::from_millis(10));
        full()
    })
    .unwrap();
    assert!(started.elapsed() < TERMINAL_PASS_SLICE + Duration::from_millis(100));
    assert!((2..=8).contains(&reads.get()), "{} reads", reads.get());
}

#[test]
fn each_read_gets_the_time_left_and_an_error_ends_the_pass() {
    let seen = std::cell::RefCell::new(Vec::new());
    let result = drain_pass(Duration::from_millis(100), |left| {
        seen.borrow_mut().push(left);
        if seen.borrow().len() == 3 {
            return Err("guest command deadline exhausted".into());
        }
        std::thread::sleep(Duration::from_millis(3));
        full()
    });
    assert_eq!(result.unwrap_err(), "guest command deadline exhausted");
    let seen = seen.into_inner();
    assert_eq!(seen.len(), 3);
    assert!(seen[0] <= TERMINAL_PASS_SLICE);
    assert!(
        seen[2] < seen[0],
        "the deadline shrinks as the pass goes on"
    );
}

#[test]
fn one_late_reply_cannot_consume_the_whole_command_timeout() {
    let started = Instant::now();
    drain_pass(Duration::from_millis(200), |budget| {
        assert!(budget <= TERMINAL_PASS_SLICE);
        std::thread::sleep(budget);
        Ok(TerminalRead {
            len: TERMINAL_READ_SIZE,
            full: true,
        })
    })
    .unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "a single read exceeded its pass slice: {:?}",
        started.elapsed()
    );
}

#[test]
fn a_zero_timeout_still_reads_once_and_reports_the_deadline_error() {
    let result = drain_pass(Duration::ZERO, |left| {
        assert!(left.is_zero());
        Err("guest command deadline exhausted before submission".into())
    });
    assert!(result.is_err());
}

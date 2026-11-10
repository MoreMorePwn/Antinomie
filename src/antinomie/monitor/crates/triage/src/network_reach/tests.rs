// SPDX-License-Identifier: GPL-3.0-only
use super::*;
use crate::run_end::SignalNotes;
use crate::tests::call;

const SECOND: u64 = 1_000_000_000;

fn at(name: &str, result: i64, ns: u64) -> InvocationSummary {
    let mut row = call(700, 42, name, result);
    for event in row.entry.iter_mut().chain(row.exit.iter_mut()) {
        event.timestamp_ns = ns;
    }
    row
}

fn scan(rows: &[InvocationSummary]) -> SignalNotes {
    let mut notes = SignalNotes::default();
    for row in rows {
        notes.observe(row, row.entry.as_ref().unwrap());
    }
    notes
}

/// Mirai on Debian arm64 (ANT-T0420 run fb2292f8): 19 connects ENETUNREACH
/// in the first ~19 s, then the C2 connects go out.
#[test]
fn a_network_that_came_up_late_is_said_with_its_window() {
    let mut rows = vec![at("execve", 0, SECOND)];
    for n in 0..19 {
        rows.push(at("connect", -101, 2 * SECOND + n * SECOND));
    }
    rows.push(at("sendto", -101, 3 * SECOND));
    rows.push(at("connect", -115, 21 * SECOND));
    let mut notes = scan(&rows);
    let note = unreachable_note(&notes).unwrap();
    assert!(
        note.starts_with("20 network calls failed with ENETUNREACH (\"network is unreachable\": the guest had no address or route) from +1.0 s to +19.0 s (connect ×19, sendto ×1)."),
        "{note}"
    );
    assert!(
        note.contains("From +20.0 s on, the calls went out"),
        "{note}"
    );
    notes.network_wait = Some(NetworkWait {
        waited_ms: 0,
        outcome: BootWaitOutcome::Skipped,
        detail: Some("the network wait is off in the settings".into()),
    });
    assert!(unreachable_note(&notes).unwrap().ends_with(
        "The launch did not wait for the guest's network: the network wait is off in the settings."
    ));
}

/// Mirai on BusyBox (run 2e7dfbd9): 1,491 connects all ENETUNREACH; the
/// launch had waited and timed out.
#[test]
fn a_run_that_never_had_a_network_says_so_and_names_the_wait() {
    let mut rows = vec![at("execve", 0, 0)];
    for n in 0..5 {
        rows.push(at("connect", -101, n * 60 * SECOND));
    }
    let mut notes = scan(&rows);
    notes.network_wait = Some(NetworkWait {
        waited_ms: 300_000,
        outcome: BootWaitOutcome::Timeout,
        detail: None,
    });
    let note = unreachable_note(&notes).unwrap();
    assert!(
        note.contains("No later call went out: the guest stayed without a network"),
        "{note}"
    );
    assert!(note.ends_with("The launch waited 300 s for the guest's network address and started the program without one."), "{note}");
}

#[test]
fn calls_that_reached_a_network_or_failed_otherwise_give_no_note() {
    let notes = scan(&[
        at("connect", -111, SECOND),
        at("connect", -110, 2 * SECOND),
        at("sendto", 12, 3 * SECOND),
        at("connect", -13, 4 * SECOND),
        // Another call with the same errno is not a network call.
        at("bind", -101, 5 * SECOND),
    ]);
    assert_eq!(notes.unreachable.count(), 0);
    assert_eq!(unreachable_note(&notes), None);
}

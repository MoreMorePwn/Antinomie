// SPDX-License-Identifier: MIT
use super::*;

fn event(call_id: u64, event_seq: u64, phase: u8, timestamp_ns: u64) -> EventSummary {
    EventSummary {
        root_task_cookie: 1,
        stream_id: 1,
        task_cookie: 2,
        call_id,
        event_seq,
        phase,
        syscall_nr: 0,
        syscall_name: "read".into(),
        pid: 3,
        tid: 3,
        cpu: 0,
        timestamp_ns,
        args: None,
        result: None,
        complete: true,
        issues: Vec::new(),
        fields: Vec::new(),
    }
}

#[test]
fn live_history_is_ordered_by_time_and_keeps_only_the_newest_events() {
    let total = LIVE_HISTORY as u64 + 10;
    // Delivered newest first.
    let events: Vec<_> = (0..total)
        .rev()
        .map(|index| event(index + 1, 1, 1, 1_000 + index))
        .collect();
    let kept = bounded_live_history(events);
    assert_eq!(kept.len(), LIVE_HISTORY);
    assert_eq!(kept.first().unwrap().timestamp_ns, 1_010);
    assert_eq!(kept.last().unwrap().timestamp_ns, 1_000 + total - 1);
    assert!(
        kept.windows(2)
            .all(|pair| pair[0].timestamp_ns <= pair[1].timestamp_ns)
    );
    assert!(bounded_live_history(Vec::new()).is_empty());
}

#[test]
fn an_event_in_the_boot_archive_and_a_run_is_listed_once_with_the_run_copy() {
    let mut from_boot = event(7, 1, 2, 500);
    from_boot.issues.push("boot".into());
    let mut from_run = event(7, 1, 2, 500);
    from_run.issues.push("run".into());
    let other_phase = event(7, 1, 1, 400);
    let other_call = event(8, 1, 2, 600);
    let merged = canonical_live_history(
        vec![from_boot, other_phase],
        [vec![from_run], vec![other_call]],
    );
    assert_eq!(merged.len(), 3);
    let times: Vec<_> = merged.iter().map(|event| event.timestamp_ns).collect();
    assert_eq!(times, [400, 500, 600]);
    assert_eq!(merged[1].issues, ["run"], "the run copy supplies the paths");
}

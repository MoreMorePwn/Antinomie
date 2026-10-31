// SPDX-License-Identifier: GPL-3.0-only
//! Field statuses that say there was nothing to copy, the recorder's own
//! incomplete marks, and packet numbers shared by a task's events.
use super::{tests::packet, *};

/// One event of `phase` with fields of the given (key, status, scalar);
/// `flags` go in every header, `seqs` number its packets.
fn event(
    phase: u8,
    flags: u32,
    fields: &[(&str, u32, Option<u64>)],
    seqs: &[u64],
    failed: u64,
) -> EventSummary {
    let directory =
        std::env::temp_dir().join(format!("ant-status-{}", crate::storage::unique_id()));
    let mut assembler = Assembler::new(directory.clone(), 1 << 20).unwrap();
    let mut packets = vec![packet(1, 0, 0, &[0; 120], 0)];
    for (index, (key, status, scalar)) in fields.iter().enumerate() {
        let id = index as u32 + 1;
        let mut begin = vec![0; 40];
        begin[..3].copy_from_slice(&[255, 1, 1]);
        begin[4] = 1;
        begin[32..34].copy_from_slice(&(key.len() as u16).to_le_bytes());
        begin.extend_from_slice(key.as_bytes());
        packets.push(packet(2, id, 0, &begin, 0));
        let len = scalar.map_or(0u64, |_| 8);
        if let Some(value) = scalar {
            packets.push(packet(3, id, 0, &value.to_le_bytes(), 0));
        }
        let mut end = [0; 32];
        end[..8].copy_from_slice(&len.to_le_bytes());
        end[8..16].copy_from_slice(&len.to_le_bytes());
        end[16..20].copy_from_slice(&status.to_le_bytes());
        end[24..32].copy_from_slice(&u64::from(scalar.is_some()).to_le_bytes());
        packets.push(packet(4, id, 0, &end, 0));
    }
    let mut end = [0; 32];
    end[..8].copy_from_slice(&(fields.len() as u64).to_le_bytes());
    end[8..16].copy_from_slice(&(packets.len() as u64 + 1 + failed).to_le_bytes());
    end[16..24].copy_from_slice(&failed.to_le_bytes());
    packets.push(packet(5, 0, 0, &end, 0));
    let mut last = None;
    for (index, mut packet) in packets.into_iter().enumerate() {
        packet[56..64].copy_from_slice(
            &seqs
                .get(index)
                .copied()
                .unwrap_or(index as u64 + 1)
                .to_le_bytes(),
        );
        packet[98] = phase;
        packet[16..20].copy_from_slice(&flags.to_le_bytes());
        last = assembler.ingest(&packet).unwrap();
    }
    std::fs::remove_dir_all(directory).unwrap();
    last.unwrap()
}

#[test]
fn nothing_to_copy_statuses_leave_the_event_complete() {
    for status in [5, 6, 11] {
        let summary = event(1, 0, &[("arg1.data", status, None)], &[], 0);
        assert!(summary.complete, "{status}: {:?}", summary.issues);
        assert!(summary.fields[0].complete);
    }
    // The recorder marks the event for a deferred field; the field explains it.
    let deferred = event(2, 1, &[("arg3.child_tid", 7, None)], &[], 0);
    assert!(deferred.complete, "{:?}", deferred.issues);
}

#[test]
fn real_gaps_stay_incomplete_with_one_precise_issue() {
    let fault = event(1, 1, &[("arg1.path", 1, None)], &[], 0);
    assert!(!fault.complete);
    assert_eq!(
        fault.issues,
        ["object 1 capture incomplete, status COPY_FAULT"]
    );
    let gap = event(1, 1, &[("arg2.buf", 4, None)], &[], 0);
    assert_eq!(
        gap.issues,
        ["object 1 capture incomplete, status NO_DECODER"]
    );
}

#[test]
fn an_async_payload_marker_is_a_gap_only_on_the_final_record() {
    let pending = event(
        3,
        1,
        &[("async.final", 0, Some(0)), ("async.payload", 7, None)],
        &[],
        0,
    );
    assert!(pending.complete, "{:?}", pending.issues);
    let last = event(
        3,
        1,
        &[("async.final", 0, Some(1)), ("async.payload", 7, None)],
        &[],
        0,
    );
    assert!(!last.complete);
    let foreign = event(
        3,
        1,
        &[
            ("async.final", 0, Some(0)),
            ("async.payload.output", 7, None),
        ],
        &[],
        0,
    );
    assert!(!foreign.complete);
    // An AIO read's output is read at reap, after its final completion.
    let aio = event(
        3,
        1,
        &[
            ("async.final", 0, Some(1)),
            ("async.opcode", 0, Some(0)),
            (
                "async.system",
                0,
                Some(u64::from_le_bytes(*b"AIO\0\0\0\0\0")),
            ),
            ("async.payload", 7, None),
        ],
        &[],
        0,
    );
    assert!(aio.complete, "{:?}", aio.issues);
}

#[test]
fn packet_numbers_shared_with_other_events_are_not_a_gap() {
    // Another event of the same task took numbers 3 and 4.
    let summary = event(1, 0, &[("arg1.path", 0, Some(7))], &[1, 2, 5, 6, 7], 0);
    assert!(summary.complete, "{:?}", summary.issues);
}

#[test]
fn recorder_loss_and_lost_entries_are_reported() {
    let lost = event(1, 1, &[], &[], 2);
    assert!(
        lost.issues
            .iter()
            .any(|issue| issue == "recorder failed to send 2 packets of this event"),
        "{:?}",
        lost.issues
    );
    let entry = event(2, 3, &[], &[], 0);
    assert!(
        entry
            .issues
            .iter()
            .any(|issue| issue == "recorder lost this call's Entry record"),
        "{:?}",
        entry.issues
    );
    let unexplained = event(1, 1, &[], &[], 0);
    assert_eq!(
        unexplained.issues,
        ["recorder header reports incomplete capture"]
    );
}

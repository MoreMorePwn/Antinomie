// SPDX-License-Identifier: GPL-3.0-only
//! The cost of one packet does not grow with the fields its event already has
//! (a large writev, sendmmsg or execve records thousands of fields).
use super::{field_tests::fields, *};

/// Feed one event of `count` fields, packet by packet, as a recording would.
/// Returns the number of per-field summaries built and the time taken.
fn feed(count: u32) -> (u64, std::time::Duration, usize) {
    let directory =
        std::env::temp_dir().join(format!("ant-parser-cost-{}", crate::storage::unique_id()));
    let packets = fields(count);
    let mut assembler = Assembler::new(directory.join("objects"), 64 * 1024 * 1024).unwrap();
    assembler.set_event_table(count as usize * 2);
    FIELD_SUMMARIES.with(|built| built.set(0));
    let started = std::time::Instant::now();
    // Like the recorder, look at each summary and let it go before the next
    // packet: a copy kept alive would make the next update copy the fields.
    for packet in &packets[..packets.len() - 1] {
        assembler.ingest(packet).unwrap();
    }
    let last = assembler.ingest(&packets[packets.len() - 1]).unwrap();
    let elapsed = started.elapsed();
    let built = FIELD_SUMMARIES.with(std::cell::Cell::get);
    let event = last.expect("the last packet returns the event");
    assert!(event.complete, "{:?}", event.issues);
    assert_eq!(event.fields.len(), count as usize);
    assert_eq!(assembler.evicted_count, 0);
    std::fs::remove_dir_all(directory).unwrap();
    (built, elapsed, packets.len())
}

#[test]
fn packet_cost_does_not_grow_with_the_events_field_count() {
    let (small, _, small_packets) = feed(1_000);
    let (large, _, large_packets) = feed(4_000);
    // Per packet, a constant number of field summaries: four times the
    // fields must not cost much more than four times the work.
    assert!(
        large * small_packets as u64 <= small * large_packets as u64 * 2,
        "{small} summaries for {small_packets} packets, {large} for {large_packets}"
    );
    assert!(
        large <= large_packets as u64 * 4,
        "{large} field summaries for {large_packets} packets"
    );
}

/// `cargo test --release -p antinomie-monitor-core -- --ignored parser_cost_timing --nocapture`
#[test]
#[ignore = "timing report"]
fn parser_cost_timing() {
    for count in [3_000, 12_000] {
        let (built, elapsed, packets) = feed(count);
        println!(
            "{count} fields, {packets} packets: {built} field summaries, {elapsed:?} ({:?} per packet)",
            elapsed / packets as u32
        );
    }
}

/// The summary kept up to date packet by packet is the one built from
/// scratch, for packets in any order, repeated and conflicting.
#[test]
fn the_kept_summary_matches_one_built_from_scratch_after_every_packet() {
    let directory =
        std::env::temp_dir().join(format!("ant-parser-kept-{}", crate::storage::unique_id()));
    let mut packets = fields(40);
    // Out of order: ends first, then data, then begins, the event's own
    // records last; some packets twice, one changed.
    packets.reverse();
    let mut again = packets[5].clone();
    let last = again.len() - 1;
    again[last] ^= 0xff;
    packets.push(packets[3].clone());
    packets.push(again);
    packets.push(packets[7].clone());
    let mut assembler = Assembler::new(directory.join("objects"), 64 * 1024 * 1024).unwrap();
    for packet in &packets {
        let _ = assembler.ingest(packet);
        for event in assembler.events.values() {
            let phase = event.summary.phase;
            let built: Vec<_> = event
                .fields
                .values()
                .map(|field| field.summary(phase, event.pending))
                .collect();
            assert_eq!(
                format!("{:?}", event.summary.fields.to_vec()),
                format!("{built:?}")
            );
            let unsettled: Vec<u32> = event
                .fields
                .iter()
                .filter(|(_, field)| !field.settled(phase, event.pending))
                .map(|(id, _)| *id)
                .collect();
            assert_eq!(
                event.unsettled.iter().copied().collect::<Vec<_>>(),
                unsettled
            );
            assert_eq!(
                event.open_fields,
                event.fields.values().filter(|f| f.end.is_none()).count()
            );
            assert_eq!(
                event.failed_fields,
                event
                    .fields
                    .values()
                    .filter(|f| f.summary.status.is_some_and(|s| s != 0))
                    .count()
            );
        }
    }
    let event = &assembler.history()[0];
    assert!(!event.complete, "a changed packet is a conflict");
    std::fs::remove_dir_all(directory).unwrap();
}

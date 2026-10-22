// SPDX-License-Identifier: GPL-3.0-only
//! A scan of a call with more async observations than its page previews says so.
use super::*;

/// The three packets of one `async.stage` observation of call 0.
fn observation(raw: &mut Vec<u8>, event_seq: u64) {
    let mut write = |fragment: u8, body: Vec<u8>, packet_seq: u64| {
        let mut packet = vec![0u8; 136];
        packet[..4].copy_from_slice(b"ANTT");
        for (offset, value) in [(4, 1u16), (6, 1), (8, 136), (10, 1)] {
            packet[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        packet[12..16].copy_from_slice(&(136u32 + body.len() as u32).to_le_bytes());
        packet[20..24].copy_from_slice(&1u32.to_le_bytes());
        packet[24..32].copy_from_slice(&1u64.to_le_bytes());
        packet[32..40].copy_from_slice(&55u64.to_le_bytes());
        packet[48..56].copy_from_slice(&event_seq.to_le_bytes());
        packet[56..64].copy_from_slice(&packet_seq.to_le_bytes());
        packet[72..76].copy_from_slice(&55u32.to_le_bytes());
        packet[76..80].copy_from_slice(&55u32.to_le_bytes());
        packet[96..98].copy_from_slice(&1u16.to_le_bytes());
        packet[98] = 3;
        packet[99] = fragment;
        if fragment == 2 {
            packet[100..104].copy_from_slice(&1u32.to_le_bytes());
        }
        packet[120..124].copy_from_slice(&(body.len() as u32).to_le_bytes());
        packet.extend(body);
        raw.extend((packet.len() as u32).to_le_bytes());
        raw.extend(packet);
    };
    write(1, vec![0; 120], 1);
    let mut field = vec![0u8; 40];
    field[0] = 255;
    field[1] = 1;
    field[2..4].copy_from_slice(&1u16.to_le_bytes());
    field[4..6].copy_from_slice(&1u16.to_le_bytes());
    field[32..34].copy_from_slice(&11u16.to_le_bytes());
    field.extend(b"async.stage");
    write(2, field, 2);
    write(5, vec![0; 32], 3);
}

fn scan(completions: u64) -> ArchiveScan {
    let temp = PacketSpool::new().unwrap();
    let mut raw = Vec::new();
    write_rwx_calls(&mut raw, 0..1);
    for number in 0..completions {
        observation(&mut raw, 1000 + number);
    }
    std::fs::write(temp.directory.join("telemetry.raw"), raw).unwrap();
    scan_archive(&temp.directory, None, false, &AtomicBool::new(false)).unwrap()
}

#[test]
fn a_dense_call_is_reported_as_previewed_and_the_scan_as_partial() {
    let scan = scan(2600);
    assert!(
        scan.coverage.contains(
            "2344 saved async observations on 1 calls are past the 256 each call previews"
        ),
        "{}",
        scan.coverage
    );
    assert!(scan.partial, "{}", scan.coverage);
    // Both walks reported the same page diagnostic once, not once per page.
    assert!(
        scan.coverage.contains("1 archive read issues"),
        "{}",
        scan.coverage
    );
}

#[test]
fn a_call_within_its_preview_is_not_reported() {
    let scan = scan(256);
    assert!(
        !scan.coverage.contains("async observations"),
        "{}",
        scan.coverage
    );
    assert!(
        !scan.coverage.contains("archive read issues"),
        "{}",
        scan.coverage
    );
}

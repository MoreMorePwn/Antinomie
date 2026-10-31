// SPDX-License-Identifier: GPL-3.0-only
//! Measure how fast the host persists a recorded telemetry stream.
//!
//! usage: replay-bench TELEMETRY.raw OUTPUT_DIR [COPIES]
//!
//! Replays every packet of a saved `telemetry.raw` (LE32 length + packet)
//! through the same raw append and assembler the backend uses on its
//! transport thread (disk writes go to the recording writer thread), `COPIES` times per packet (2 = a launched run or boot
//! recording plus a Capture All observer copy), and prints packets/s and
//! the slowest single packets, which bound how long the guest rings wait.

use antinomie_monitor_core::{parser::Assembler, storage::RawCapture};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return Err("usage: replay-bench TELEMETRY.raw OUTPUT_DIR [COPIES]".into());
    }
    let raw = fs::read(&args[0]).map_err(|e| e.to_string())?;
    let copies: usize = args.get(2).and_then(|c| c.parse().ok()).unwrap_or(1);
    let out = PathBuf::from(&args[1]);
    let mut sinks = Vec::new();
    for copy in 0..copies {
        let dir = out.join(format!("copy-{copy}"));
        sinks.push((
            RawCapture::new(dir.clone(), u64::MAX / 4)?,
            Assembler::new(dir.join("objects"), u64::MAX / 4).map_err(|e| e.to_string())?,
        ));
    }
    let mut offset = 0;
    let (mut packets, mut bytes) = (0u64, 0u64);
    let mut slow = Vec::new();
    let mut over_1ms = 0u64;
    let mut errors = std::collections::BTreeMap::new();
    let started = Instant::now();
    while offset + 4 <= raw.len() {
        if offset + 4 + u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize
            > raw.len()
        {
            break; // a truncated copy ends mid-packet
        }
        let len = u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap()) as usize;
        let packet = &raw[offset + 4..offset + 4 + len];
        offset += 4 + len;
        let one = Instant::now();
        for (capture, assembler) in &mut sinks {
            capture.append_with_reserved(packet, 0);
            if let Err(error) = assembler.ingest(packet) {
                *errors.entry(error.to_string()).or_insert(0u64) += 1;
            }
        }
        let took = one.elapsed();
        if took > Duration::from_millis(1) {
            over_1ms += 1;
        }
        slow.push(took);
        packets += 1;
        bytes += len as u64;
    }
    let queued = started.elapsed();
    drop(sinks);
    antinomie_monitor_core::writer::barrier();
    let total = started.elapsed();
    slow.sort_unstable();
    let pct = |p: f64| slow[((slow.len() as f64 * p) as usize).min(slow.len() - 1)];
    println!(
        "{packets} packets, {:.1} MB, {copies} cop{} in {:.2?}: {:.0} packets/s, {:.1} MB/s",
        bytes as f64 / 1e6,
        if copies == 1 { "y" } else { "ies" },
        total,
        packets as f64 / total.as_secs_f64(),
        bytes as f64 / 1e6 / total.as_secs_f64()
    );
    println!("transport thread done after {queued:.2?}; the writer thread finished at {total:.2?}");
    println!(
        "per packet: p50 {:?}, p99 {:?}, p99.9 {:?}, max {:?}; {over_1ms} packets over 1 ms",
        pct(0.5),
        pct(0.99),
        pct(0.999),
        slow.last().unwrap()
    );
    for (error, count) in &errors {
        println!("parser error x{count}: {error}");
    }
    Ok(())
}

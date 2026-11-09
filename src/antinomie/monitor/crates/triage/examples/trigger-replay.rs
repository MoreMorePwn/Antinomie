// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Replay a recorded run through the dump trigger's live judge, the way the
//! recorder feeds it: the app's Triage rules, its list of watched calls as the
//! filter (or every call with `--all`), every tier. Prints one line per
//! finding the trigger would have acted on.
//!
//!   trigger-replay RUN_DIR [--all]
use antinomie_monitor_core::dump_trigger::{replay, DumpTrigger, TriggerTier};
use antinomie_monitor_core::parser::Assembler;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = args.first().map(PathBuf::from) else {
        eprintln!("usage: trigger-replay RUN_DIR [--all]");
        std::process::exit(2);
    };
    let keep = if args.iter().any(|a| a == "--all") {
        Vec::new()
    } else {
        antinomie_triage::rules::watched_calls()
    };
    let scratch = std::env::temp_dir().join(format!("trigger-replay-{}", std::process::id()));
    let mut assembler = Assembler::new(scratch.clone(), u64::MAX).expect("assembler");
    assembler.set_arch(antinomie_monitor_core::recording::Recording::raw(&dir).guest_arch());
    let mut reader = BufReader::new(File::open(dir.join("telemetry.raw")).expect("telemetry.raw"));
    // Each event once, when it is first whole, in the order it became whole:
    // what the recorder hands the watch (`Assembler::just_finished`).
    let mut seen = BTreeMap::new();
    let mut events = Vec::new();
    let mut prefix = [0; 4];
    while reader.read_exact(&mut prefix).is_ok() {
        let mut packet = vec![0; u32::from_le_bytes(prefix) as usize];
        if reader.read_exact(&mut packet).is_err() {
            break;
        }
        if let Ok(Some(event)) = assembler.ingest(&packet)
            && event.complete
            && seen
                .insert(
                    (
                        event.stream_id,
                        event.task_cookie,
                        event.call_id,
                        event.phase,
                        event.event_seq,
                    ),
                    (),
                )
                .is_none()
        {
            events.push(event);
        }
    }
    let plan = DumpTrigger {
        min_tier: TriggerTier::Low,
        ..DumpTrigger::default()
    };
    let found = replay(antinomie_triage::live_judge::make(), &plan, &keep, events);
    for finding in &found {
        println!(
            "{} pid {} call {} {}: {}",
            finding.rule_with_tier(),
            finding.pid,
            finding.call_id,
            finding.syscall,
            finding.summary
        );
    }
    println!("{} findings", found.len());
    let _ = std::fs::remove_dir_all(scratch);
}

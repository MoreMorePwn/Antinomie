// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Print a recording's assembled events, every phase including lifecycle
//! records, with each captured field: key, status (and "at exit" or "kernel
//! copy" for an input read after the Entry), length and preview.
//!
//! usage: event-dump RUN_DIR [SYSCALL_OR_PID...]
use antinomie_monitor_core::parser::Assembler;
use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(dir) = args.first().map(PathBuf::from) else {
        eprintln!("usage: event-dump RUN_DIR [SYSCALL_OR_PID...]");
        std::process::exit(2);
    };
    let filters = &args[1..];
    let scratch = std::env::temp_dir().join(format!("event-dump-{}", std::process::id()));
    let mut assembler = Assembler::new(scratch.clone(), u64::MAX).expect("assembler");
    let mut reader = BufReader::new(File::open(dir.join("telemetry.raw")).expect("raw"));
    let mut prefix = [0; 4];
    while reader.read_exact(&mut prefix).is_ok() {
        let mut packet = vec![0; u32::from_le_bytes(prefix) as usize];
        if reader.read_exact(&mut packet).is_err() {
            break;
        }
        let Ok(Some(event)) = assembler.ingest(&packet) else {
            continue;
        };
        let shown = filters.is_empty()
            || filters
                .iter()
                .any(|f| *f == event.syscall_name || *f == event.pid.to_string());
        if !shown {
            continue;
        }
        println!(
            "{} pid {} tid {} {} call {} phase {} args {:x?} result {:?} complete {}{}",
            event.event_seq,
            event.pid,
            event.tid,
            event.syscall_name,
            event.call_id,
            event.phase,
            event.args,
            event.result,
            event.complete,
            if event.issues.is_empty() {
                String::new()
            } else {
                format!(" issues {:?}", event.issues)
            }
        );
        for field in &event.fields {
            let text: String = String::from_utf8_lossy(&field.preview)
                .chars()
                .take(48)
                .map(|c| if c.is_control() { '.' } else { c })
                .collect();
            println!(
                "    {} status {:?}{} logical {:?} captured {} complete {} {:?} {}",
                field.key,
                field.status,
                field
                    .recapture
                    .map_or(String::new(), |mark| format!(" ({})", mark.label())),
                field.logical_len,
                field.captured_len,
                field.complete,
                text,
                field
                    .preview
                    .iter()
                    .take(16)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
        }
    }
    let _ = std::fs::remove_dir_all(scratch);
}

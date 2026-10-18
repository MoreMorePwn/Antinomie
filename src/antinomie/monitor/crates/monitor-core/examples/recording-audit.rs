// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Replay every packet without copying captured objects; summarize capture gaps.
//! Usage: recording-audit RUN_DIR
use antinomie_monitor_core::{parser, recording};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    sync::atomic::AtomicBool,
};

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let directory = PathBuf::from(
        std::env::args_os()
            .nth(1)
            .ok_or("usage: recording-audit RUN_DIR")?,
    );
    let mut reader = BufReader::new(File::open(directory.join("telemetry.raw"))?);
    let mut packets = 0u64;
    let mut events = 0u64;
    let mut incomplete = 0u64;
    let mut phases = BTreeMap::<u8, u64>::new();
    let mut syscalls = BTreeMap::<String, u64>::new();
    let mut issues = BTreeMap::<String, u64>::new();
    let mut errors = BTreeMap::<String, u64>::new();
    let mut statuses = BTreeMap::<String, u64>::new();
    let mut field_gaps = BTreeMap::<String, u64>::new();
    let mut tasks = BTreeSet::new();
    let mut root_cookies = BTreeSet::new();
    let mut framing_error = None;
    loop {
        let mut prefix = [0u8; 4];
        let first = reader.read(&mut prefix[..1])?;
        if first == 0 {
            break;
        }
        if let Err(error) = reader.read_exact(&mut prefix[1..]) {
            framing_error = Some(format!("truncated packet prefix: {error}"));
            break;
        }
        let size = u32::from_le_bytes(prefix) as usize;
        if size > 16 * 1024 * 1024 {
            return Err("raw packet exceeds audit allocation bound".into());
        }
        let mut packet = vec![0; size];
        if let Err(error) = reader.read_exact(&mut packet) {
            framing_error = Some(format!("truncated packet payload: {error}"));
            break;
        }
        packets += 1;
        match parser::parse_packet(&packet) {
            Ok((header, _)) => {
                tasks.insert(header.task_cookie);
                root_cookies.insert(header.root_task_cookie);
            }
            Err(error) => *errors.entry(error.to_string()).or_default() += 1,
        }
    }
    let archive = recording::open_recording(&directory)?;
    let mut cursor = Some(0);
    let mut calls = 0u64;
    let mut unmatched = 0u64;
    let mut page_issues = BTreeSet::new();
    while let Some(offset) = cursor {
        let page = archive.invocation_page(offset, 256)?;
        page_issues.extend(page.issues);
        for call in page.invocations {
            calls += 1;
            unmatched += u64::from(
                call.entry.is_none() || (call.exit.is_none() && call.task_exit.is_none()),
            );
            for event in call
                .entry
                .into_iter()
                .chain(call.exit)
                .chain(call.task_exit)
                .chain(call.async_events)
            {
                events += 1;
                incomplete += u64::from(!event.complete);
                *phases.entry(event.phase).or_default() += 1;
                *syscalls.entry(event.syscall_name).or_default() += 1;
                for issue in event.issues {
                    *issues.entry(issue).or_default() += 1;
                }
                for field in event.fields {
                    *statuses
                        .entry(format!("{:?}/{}", field.status, field.capture_error))
                        .or_default() += 1;
                    if !field.complete
                        || field
                            .logical_len
                            .is_some_and(|len| field.captured_len < len)
                    {
                        *field_gaps.entry(field.key).or_default() += 1;
                    }
                }
            }
        }
        cursor = page.next_offset;
    }
    let root = archive.manifest.get("run");
    let pid = root
        .and_then(|run| run.get("pid"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as u32;
    let path = root
        .and_then(|run| run.pointer("/request/path"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (tree, tree_issues) =
        archive.process_tree_cancellable(pid, path, &AtomicBool::new(false))?;
    Ok(json!({
        "directory": directory, "packets": packets, "invocation_events": events, "calls": calls, "unmatched_calls": unmatched, "page_issues": page_issues,
        "incomplete_events": incomplete, "phases": phases, "syscalls": syscalls,
        "event_issues": issues, "parser_errors": errors, "field_status_error": statuses,
        "field_gaps": field_gaps, "task_cookies": tasks.len(), "root_cookies": root_cookies,
        "framing_error": framing_error, "process_tree": tree, "tree_issues": tree_issues,
        "manifest": archive.manifest,
    }))
}

fn main() {
    match run() {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("recording-audit: {error}");
            std::process::exit(1);
        }
    }
}

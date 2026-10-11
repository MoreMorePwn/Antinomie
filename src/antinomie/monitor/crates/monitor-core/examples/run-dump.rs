// SPDX-License-Identifier: MIT
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Print a recorded run's syscalls, one line each: process, thread, call,
//! arguments, the first captured field and the result.
//!
//! usage: run-dump RUN_DIR [LIMIT]
use antinomie_monitor_core::recording;
use std::path::PathBuf;

fn main() {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let Some(dir) = args.first() else {
        eprintln!("usage: run-dump RUN_DIR [LIMIT]");
        std::process::exit(2);
    };
    let limit: usize = args
        .get(1)
        .and_then(|value| value.to_str()?.parse().ok())
        .unwrap_or(5000);
    let run = match recording::open_recording(&PathBuf::from(dir)) {
        Ok(run) => run,
        Err(error) => {
            eprintln!("run-dump: {error}");
            std::process::exit(1);
        }
    };
    let (mut offset, mut shown) = (Some(0), 0);
    while let Some(at) = offset {
        let page = match run.invocation_page(at, 256) {
            Ok(page) => page,
            Err(error) => {
                eprintln!("run-dump: {error}");
                std::process::exit(1);
            }
        };
        for issue in &page.issues {
            println!("! {issue}");
        }
        for call in &page.invocations {
            let event = call.exit.as_ref().or(call.entry.as_ref());
            let Some(event) = event else { continue };
            let field = call
                .entry
                .iter()
                .chain(call.exit.iter())
                .flat_map(|event| event.fields.iter())
                .find(|field| !field.preview.is_empty())
                .map(|field| {
                    let text: String = String::from_utf8_lossy(&field.preview)
                        .chars()
                        .take(60)
                        .map(|c| if c.is_control() { '.' } else { c })
                        .collect();
                    format!(" {}={text:?}", field.key)
                })
                .unwrap_or_default();
            println!(
                "{:>6} {:>6} {:<18} {:x?}{} = {}{}",
                event.pid,
                event.tid,
                event.syscall_name,
                call.entry
                    .as_ref()
                    .and_then(|entry| entry.args)
                    .unwrap_or_default(),
                field,
                call.exit
                    .as_ref()
                    .and_then(|exit| exit.result)
                    .map_or("?".into(), |result| result.to_string()),
                if call.async_events.is_empty() {
                    String::new()
                } else {
                    format!(" (+{} async)", call.async_events.len())
                }
            );
            shown += 1;
            if shown >= limit {
                return;
            }
        }
        offset = page.next_offset;
    }
}

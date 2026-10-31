// SPDX-License-Identifier: GPL-3.0-only
//! Install one optional analysis tool the way Tools > Analysis tools does.
//!
//! usage: install-tool DATA_DIR capa|floss|upx|die|ghidra|volatility3|memnixfs|sigma|magika|gef|pwndbg
use std::{path::PathBuf, process::ExitCode, sync::atomic::AtomicBool};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [data, id] = args.as_slice() else {
        eprintln!(
            "usage: install-tool DATA_DIR capa|floss|upx|die|ghidra|volatility3|memnixfs|sigma|magika|gef|pwndbg"
        );
        return ExitCode::FAILURE;
    };
    let mut last = String::new();
    let result = antinomie_monitor_core::analysis_tools::install(
        &PathBuf::from("curl"),
        &PathBuf::from(data),
        id,
        &AtomicBool::new(false),
        |stage, received, total| {
            let line = format!("{stage} {}%", received * 100 / total.max(1));
            if line != last {
                println!("{line}");
                last = line;
            }
        },
    );
    match result {
        Ok(()) => {
            for status in antinomie_monitor_core::analysis_tools::statuses(&PathBuf::from(data)) {
                println!("{status:?}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("install-tool: {error}");
            ExitCode::FAILURE
        }
    }
}

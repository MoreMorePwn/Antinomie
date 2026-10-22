// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Test-only helpers for the ignored memory probes.
//!
//! The probes read this process's anonymous resident memory from
//! `/proc/self/status`, so they need no allocator hook and no unsafe code.
//! Run them one at a time (`--ignored --exact --test-threads=1`): other test
//! threads and the backend workers share the same process counters. Set
//! `ANTINOMIE_MEM_PROBE_OUT` to also append each line to a file.
use std::io::Write;

/// Anonymous resident memory of this process, in KiB (heap, stacks, textures).
pub(crate) fn anon_kib() -> u64 {
    status_field("RssAnon:")
}

/// Highest resident set size of this process so far, in KiB.
pub(crate) fn peak_kib() -> u64 {
    status_field("VmHWM:")
}

fn status_field(name: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .and_then(|rest| rest.split_whitespace().next()?.parse().ok())
        })
        .unwrap_or(0)
}

/// Prints one tab-separated measurement line, and appends it to the output file.
pub(crate) fn report(probe: &str, what: &str, value: impl std::fmt::Display) {
    let line = format!("PROBE\t{probe}\t{what}\t{value}");
    println!("{line}");
    if let Some(path) = std::env::var_os("ANTINOMIE_MEM_PROBE_OUT") {
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(file, "{line}");
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! How much of a run's terminal one worker pass reads.
//!
//! A terminal READ returns at most [`TERMINAL_READ_SIZE`] bytes. Reading one
//! per pass capped a chatty program at the pass rate, about 200 KB/s, and
//! blocked it on its PTY. A full read means more is waiting, so the next one
//! follows at once, up to a bound that keeps other runs, commands and the
//! telemetry drain from waiting for one noisy terminal.
use std::time::{Duration, Instant};

/// What one terminal READ returned; more may be waiting when it was full.
#[derive(Default)]
pub(super) struct TerminalRead {
    pub len: usize,
    pub full: bool,
}

/// Bytes asked for by one terminal READ (the most a reply may carry).
pub(super) const TERMINAL_READ_SIZE: usize = 4096;
/// Terminal bytes read from one run in one pass.
pub(super) const TERMINAL_PASS_SIZE: usize = 4 * 1024 * 1024;
/// Time one run's terminal may take in one pass.
pub(super) const TERMINAL_PASS_SLICE: Duration = Duration::from_millis(40);

/// Read until the terminal has no more, a pass bound is reached or a read
/// returns without data (late guest). `read_once` gets the time left of
/// `timeout` for its reply; the first read always happens.
pub(super) fn drain_pass(
    timeout: Duration,
    read_once: impl FnMut(Duration) -> Result<TerminalRead, String>,
) -> Result<(), String> {
    drain_pass_on(Instant::now, timeout, read_once)
}

/// [`drain_pass`] reading the time from `clock`, which the tests drive.
fn drain_pass_on(
    mut clock: impl FnMut() -> Instant,
    timeout: Duration,
    mut read_once: impl FnMut(Duration) -> Result<TerminalRead, String>,
) -> Result<(), String> {
    let started = clock();
    let drain_until = started + TERMINAL_PASS_SLICE.min(timeout);
    let mut total = 0usize;
    loop {
        let now = clock();
        let read = read_once(
            timeout
                .saturating_sub(now.saturating_duration_since(started))
                .min(drain_until.saturating_duration_since(now)),
        )?;
        total += read.len;
        if !read.full || total >= TERMINAL_PASS_SIZE || clock() >= drain_until {
            return Ok(());
        }
    }
}

#[cfg(test)]
mod tests;

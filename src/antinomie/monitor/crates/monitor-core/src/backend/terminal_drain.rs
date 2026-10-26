// SPDX-License-Identifier: GPL-3.0-only
//! How much of a run's terminal one worker pass reads.
//!
//! A terminal READ returns at most [`TERMINAL_READ_SIZE`] bytes. Reading one
//! per pass capped a chatty program at the pass rate, about 200 KB/s, and
//! blocked it on its PTY. A full read means more is waiting, so the next one
//! follows at once, up to a bound that keeps other runs, commands and the
//! telemetry drain from waiting for one noisy terminal.
use crate::api::Notification;
use std::collections::VecDeque;
use std::sync::mpsc::{SyncSender, TrySendError};
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

/// Terminal bytes that may wait for the frontend (all runs): a busy frontend
/// lets the shared notification lane fill up, and the output then waits here.
pub(super) const TERMINAL_BACKLOG_SIZE: usize = 8 * 1024 * 1024;

/// Terminal output on its way to the frontend, in order. The notification lane
/// is bounded and shared with every other update; a chunk that does not fit
/// used to be dropped, and the frontend lost those bytes from its view
/// (scrolled-off text included, which a screen resync does not bring back).
/// Now it waits here and goes first at the next send. Past
/// [`TERMINAL_BACKLOG_SIZE`] the oldest waiting chunk is dropped and counted;
/// the frontend sees the sequence gap and resynchronises its screen. The
/// recording has every byte either way.
#[derive(Default)]
pub(super) struct TerminalBacklog {
    waiting: VecDeque<Notification>,
    size: usize,
}

impl TerminalBacklog {
    /// Send `notification` (`size` bytes of output) after whatever waits.
    /// Returns the number of chunks dropped to stay within the bound.
    pub(super) fn send(
        &mut self,
        sender: &SyncSender<Notification>,
        notification: Notification,
        size: usize,
    ) -> u64 {
        self.waiting.push_back(notification);
        self.size += size;
        let mut dropped = 0;
        while self.size > TERMINAL_BACKLOG_SIZE && self.waiting.len() > 1 {
            if let Some(old) = self.waiting.pop_front() {
                self.size = self.size.saturating_sub(output_size(&old));
                dropped += 1;
            }
        }
        self.flush(sender);
        dropped
    }

    /// Send what waits, in order, until the lane is full.
    pub(super) fn flush(&mut self, sender: &SyncSender<Notification>) {
        while let Some(notification) = self.waiting.pop_front() {
            let size = output_size(&notification);
            match sender.try_send(notification) {
                Ok(()) => self.size = self.size.saturating_sub(size),
                Err(TrySendError::Full(notification)) => {
                    self.waiting.push_front(notification);
                    return;
                }
                // No frontend any more: nothing will read it.
                Err(TrySendError::Disconnected(_)) => {
                    self.waiting.clear();
                    self.size = 0;
                    return;
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn waiting(&self) -> usize {
        self.waiting.len()
    }
}

fn output_size(notification: &Notification) -> usize {
    match notification {
        Notification::Terminal { data, .. } => data.len(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests;

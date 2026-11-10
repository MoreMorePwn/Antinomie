// SPDX-License-Identifier: GPL-3.0-only
//! Network calls that failed because the guest had no network yet.
//!
//! A program started before the guest has its address gets ENETUNREACH
//! ("network is unreachable") for every connection: the guest has no route
//! anywhere. A bot that kills the DHCP client before the lease never gets
//! one. The recording shows it as failed `connect` and `sendto` calls; this
//! counts them and says when they happened, and what the launch's network
//! wait (`run.json` `boot_wait.network`) did, so a run without a network is
//! not read as a C2 that was down.
use super::*;
use antinomie_monitor_core::boot_wait::{BootWaitOutcome, NetworkWait};

/// `-ENETUNREACH`.
const ENETUNREACH: i64 = -101;
/// Results that show the guest had a route: the call went out (success,
/// EINPROGRESS) or reached a host that refused or did not answer.
const REACHED: [i64; 4] = [-111, -110, -113, -115];

/// What the scan saw of calls that needed a network.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unreachable {
    /// Calls that failed with ENETUNREACH, by system call name.
    pub calls: std::collections::BTreeMap<String, u64>,
    pub first_ns: Option<u64>,
    pub last_ns: Option<u64>,
    /// The first call after which the guest had a route: a connect or send
    /// that went out.
    pub first_reached_ns: Option<u64>,
    /// The run's first recorded call, the zero of the times said.
    pub start_ns: Option<u64>,
}

impl Unreachable {
    pub fn observe(&mut self, invocation: &InvocationSummary, event: &EventSummary) {
        if self.start_ns.is_none_or(|start| event.timestamp_ns < start) {
            self.start_ns = Some(event.timestamp_ns);
        }
        let name = event.syscall_name.as_str();
        if !matches!(name, "connect" | "sendto" | "sendmsg" | "sendmmsg") {
            return;
        }
        let Some(result) = invocation.exit.as_ref().and_then(|exit| exit.result) else {
            return;
        };
        let at = event.timestamp_ns;
        if result == ENETUNREACH {
            *self.calls.entry(name.to_owned()).or_default() += 1;
            self.first_ns = Some(self.first_ns.map_or(at, |first| first.min(at)));
            self.last_ns = Some(self.last_ns.map_or(at, |last| last.max(at)));
        } else if (result >= 0 || REACHED.contains(&result))
            && self.first_reached_ns.is_none_or(|first| at < first)
        {
            self.first_reached_ns = Some(at);
        }
    }

    pub fn count(&self) -> u64 {
        self.calls.values().sum()
    }
}

/// "19 network calls failed with ENETUNREACH ...": the note of a run whose
/// program had no network for a while, or `None` when none failed so.
pub fn unreachable_note(notes: &run_end::SignalNotes) -> Option<String> {
    let seen = &notes.unreachable;
    let count = seen.count();
    let (first, last) = (seen.first_ns?, seen.last_ns?);
    if count == 0 {
        return None;
    }
    let start = seen.start_ns.unwrap_or(first);
    let at = |ns: u64| run_end::millis(ns.saturating_sub(start));
    let calls: Vec<String> = seen
        .calls
        .iter()
        .map(|(name, n)| format!("{name} ×{n}"))
        .collect();
    let mut note = format!(
        "{count} network call{} failed with ENETUNREACH (\"network is unreachable\": the guest had no address or route) from +{} to +{} ({}).",
        if count == 1 { "" } else { "s" },
        at(first),
        at(last),
        calls.join(", ")
    );
    match seen.first_reached_ns {
        Some(reached) if reached > last => note.push_str(&format!(
            " From +{} on, the calls went out: the guest's network came up while the program ran, so the failures say nothing about the destinations.",
            at(reached)
        )),
        Some(_) => note.push_str(" Other calls went out in between."),
        None => note.push_str(
            " No later call went out: the guest stayed without a network for the whole run (a program that kills the DHCP client before the lease leaves it so), so the failed destinations were never tried.",
        ),
    }
    if let Some(wait) = &notes.network_wait {
        note.push(' ');
        note.push_str(&wait_text(wait));
    }
    Some(note)
}

fn wait_text(wait: &NetworkWait) -> String {
    match wait.outcome {
        BootWaitOutcome::Timeout => format!(
            "The launch waited {} s for the guest's network address and started the program without one.",
            wait.waited_ms / 1000
        ),
        BootWaitOutcome::Ready if wait.waited_ms > 0 => format!(
            "The launch waited {} for the guest's network address, which it then had.",
            run_end::millis(wait.waited_ms.saturating_mul(1_000_000))
        ),
        BootWaitOutcome::Ready => {
            "The guest had its network address when the program started, so the program (or something it ended) took the network away.".into()
        }
        BootWaitOutcome::Skipped => format!(
            "The launch did not wait for the guest's network: {}.",
            wait.detail.as_deref().unwrap_or("no wait applied")
        ),
    }
}

#[cfg(test)]
mod tests;

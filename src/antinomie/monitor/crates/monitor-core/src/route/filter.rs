// SPDX-License-Identifier: GPL-3.0-only
//! The egress abuse filter: limits on what a sample can do through a live
//! route (Internet, Tor, VPN, SOCKS5), so a detonation does not turn the
//! analyst's connection into a spam relay, a scanner or a flood source.
//!
//! The filter sits in the gateway, where the guest's TCP connection is about
//! to be dialled (`gateway.rs`), so it needs nothing from the guest and
//! changes no wire contract. It never applies to Drop, InetSim or the
//! cloud metadata service: nothing leaves the host there.
//!
//! | Limit | Default | What is refused |
//! |---|---|---|
//! | Blocked ports | 25, 26, 465, 587, 2525 | connections to mail submission/relay ports |
//! | New connections per second | 30 | the connection over the rate |
//! | Concurrent connections | 200 | the connection over the count |
//! | Distinct destinations per minute | 100 | a new destination over the count (scan guard) |
//! | Run time limit | off | every connection once the route has been up that long |
//! | ICMP echo replies per second | 20 | the reply over the rate |
//!
//! A refused connection gets a reset (the sample sees "connection refused")
//! and is counted by reason; blocked ports are also counted per port. UDP
//! other than DNS, ICMP beyond the router and raw protocols are never
//! forwarded at all, so floods of them are dropped by construction and
//! counted as before. A limit of 0 turns that limit off.
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

/// The saved settings of the filter (Settings > Network routes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EgressFilter {
    /// The filter applies to live routes. Turning it off is an analyst's
    /// choice for a run that must connect freely.
    pub enabled: bool,
    /// Outbound TCP ports that are always refused.
    pub blocked_ports: Vec<u16>,
    /// New outbound connections per second; 0 = no limit.
    pub max_new_per_second: u32,
    /// Outbound connections open at once; 0 = no limit (the gateway still
    /// carries at most 256).
    pub max_concurrent: u32,
    /// Distinct destinations (address or name) per minute; 0 = no limit.
    pub max_destinations_per_minute: u32,
    /// Minutes after which the route stops forwarding; 0 = no limit.
    pub run_limit_minutes: u32,
    /// ICMP echo replies the gateway sends per second; 0 = no limit.
    pub max_icmp_per_second: u32,
}

/// Mail submission and relay ports: SMTP, its common alternates, SMTPS and
/// submission.
pub const MAIL_PORTS: [u16; 5] = [25, 26, 465, 587, 2525];

impl Default for EgressFilter {
    fn default() -> Self {
        Self {
            enabled: true,
            blocked_ports: MAIL_PORTS.to_vec(),
            max_new_per_second: 30,
            max_concurrent: 200,
            max_destinations_per_minute: 100,
            run_limit_minutes: 0,
            max_icmp_per_second: 20,
        }
    }
}

impl EgressFilter {
    /// A filter that limits nothing, for the routes it does not cover.
    pub fn off() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }

    /// The settings are usable (used when they are saved).
    pub fn validate(&self) -> Result<(), String> {
        if self.blocked_ports.contains(&0) {
            return Err("Egress filter: port 0 is not a port".into());
        }
        if self.blocked_ports.len() > 64 {
            return Err("Egress filter: at most 64 blocked ports".into());
        }
        if self.run_limit_minutes > 7 * 24 * 60 {
            return Err("Egress filter: the run time limit is at most 7 days".into());
        }
        Ok(())
    }

    /// The route time limit.
    pub(crate) fn run_limit(&self) -> Option<Duration> {
        (self.enabled && self.run_limit_minutes > 0)
            .then(|| Duration::from_secs(u64::from(self.run_limit_minutes) * 60))
    }
}

/// Why a connection was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Block {
    Port(u16),
    Rate,
    Concurrent,
    Destinations,
    TimeLimit,
}

/// What the gateway remembers to apply the limits; one per route in force.
#[derive(Default)]
pub(crate) struct FilterState {
    starts: VecDeque<Instant>,
    destinations: HashMap<String, Instant>,
    echoes: VecDeque<Instant>,
}

const SECOND: Duration = Duration::from_secs(1);
const MINUTE: Duration = Duration::from_secs(60);

fn within(times: &mut VecDeque<Instant>, now: Instant, span: Duration) -> usize {
    while times
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= span)
    {
        times.pop_front();
    }
    times.len()
}

impl FilterState {
    /// Decides on a new connection to `destination`:`port` while `open`
    /// connections are open; `expired` is true once the run time limit has
    /// passed. An admitted connection is remembered for the rate limits.
    pub fn admit(
        &mut self,
        filter: &EgressFilter,
        now: Instant,
        destination: &str,
        port: u16,
        open: usize,
        expired: bool,
    ) -> Result<(), Block> {
        if expired {
            return Err(Block::TimeLimit);
        }
        if filter.blocked_ports.contains(&port) {
            return Err(Block::Port(port));
        }
        if filter.max_concurrent > 0 && open >= filter.max_concurrent as usize {
            return Err(Block::Concurrent);
        }
        if filter.max_new_per_second > 0
            && within(&mut self.starts, now, SECOND) >= filter.max_new_per_second as usize
        {
            return Err(Block::Rate);
        }
        self.destinations
            .retain(|_, seen| now.saturating_duration_since(*seen) < MINUTE);
        if filter.max_destinations_per_minute > 0
            && !self.destinations.contains_key(destination)
            && self.destinations.len() >= filter.max_destinations_per_minute as usize
        {
            return Err(Block::Destinations);
        }
        self.starts.push_back(now);
        self.destinations.insert(destination.to_owned(), now);
        Ok(())
    }

    /// Whether the gateway may answer another ping now.
    pub fn echo_allowed(&mut self, filter: &EgressFilter, now: Instant) -> bool {
        if !filter.enabled || filter.max_icmp_per_second == 0 {
            return true;
        }
        if within(&mut self.echoes, now, SECOND) >= filter.max_icmp_per_second as usize {
            return false;
        }
        self.echoes.push_back(now);
        true
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! Which process a network flow belongs to. The capture is VM-wide and the
//! guest kernel tags no packet, so the link is made on the host from what the
//! recording already holds: the run's network calls (`connect`, `sendto`,
//! `sendmsg`, `accept`, `recvfrom`, `bind`) with the address they named, the
//! protocol and the time. It needs nothing but the recording, so runs
//! recorded by earlier releases attribute too.
//!
//! A flow's [`Source`] is one of: the processes whose calls match it; the base
//! image's own background traffic (NTP, DHCP, apt, as the Indicators call it);
//! or unattributed, when no recorded call matches (a raw socket, a packet
//! socket, a call the recording lost).
use antinomie_monitor_core::ioc::baseline;
use std::{collections::BTreeMap, net::IpAddr};

/// How far the host's estimate of a guest time may be off, in microseconds
/// (a run on the PC showed 5 s between the guest's clock and the capture's).
pub const SLACK_US: u64 = 15_000_000;
/// How long a datagram call still stands for the replies that follow it.
pub const UDP_REPLY_US: u64 = 5_000_000;
/// How far outside the run's span a packet may be and still be the run's.
pub const WINDOW_SLACK_US: u64 = 30_000_000;
/// Two calls of one process to one peer closer than this are one burst.
pub const BURST_NS: u64 = 2_000_000_000;
/// Callers named in one cell before "+N".
const NAMED: usize = 2;

/// What a call says about the address it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// `connect`, `sendto`, `sendmsg`: the remote end the process reached.
    Remote,
    /// `accept`: the client that reached the process.
    Accepted,
    /// `recvfrom`: the peer a datagram came from.
    Received,
    /// `bind`: the local address the process listens on.
    Bound,
}

/// The process (and thread) that made a call.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Caller {
    pub pid: u32,
    pub tid: u32,
    /// The task's stable identity.
    pub cookie: u64,
    pub name: String,
}

impl Caller {
    /// `curl (412 · 413)`.
    pub fn label(&self) -> String {
        format!("{} ({} \u{b7} {})", self.name, self.pid, self.tid)
    }

    /// Whether the base image runs this program on its own.
    pub fn base(&self) -> bool {
        baseline::base_program(&antinomie_monitor_core::ioc::indicator::Process {
            pid: self.pid,
            cookie: self.cookie,
            name: self.name.clone(),
        })
    }
}

/// One network call, or a burst of them, with host times.
#[derive(Clone, Debug)]
pub struct FlowCall {
    pub ip: IpAddr,
    pub port: u16,
    pub udp: bool,
    pub role: Role,
    pub call: &'static str,
    pub caller: Caller,
    pub first_us: Option<u64>,
    pub last_us: Option<u64>,
    pub stream: u64,
    pub call_id: u64,
}

/// What the Source column of a flow says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    /// The processes that made a matching call, the first by time first.
    Process(Vec<Caller>),
    /// The base image's own traffic: "NTP", "DHCP", "apt", "system".
    Background { kind: &'static str, why: String },
    /// No recorded call matches.
    Unattributed,
}

pub const BACKGROUND_LABEL: &str = "Base image background";
pub const UNATTRIBUTED_LABEL: &str = "Unattributed";

impl Source {
    /// `curl (412 · 413)`, `curl (412 · 413) +1`, `Base image background: NTP`
    /// or `Unattributed`.
    pub fn label(&self) -> String {
        match self {
            Source::Process(callers) => {
                let named: Vec<String> = callers.iter().take(NAMED).map(Caller::label).collect();
                let more = callers.len().saturating_sub(NAMED);
                if more == 0 {
                    named.join(", ")
                } else {
                    format!("{} +{more}", named.join(", "))
                }
            }
            Source::Background { kind, .. } => format!("{BACKGROUND_LABEL}: {kind}"),
            Source::Unattributed => UNATTRIBUTED_LABEL.into(),
        }
    }

    /// The word a filter compares: `process`, `background`, `unattributed`.
    pub fn kind(&self) -> &'static str {
        match self {
            Source::Process(_) => "process",
            Source::Background { .. } => "background",
            Source::Unattributed => "unattributed",
        }
    }

    /// What the hover says.
    pub fn explain(&self) -> String {
        match self {
            Source::Process(callers) => format!(
                "Made by {}. Matched on the address, protocol and time of the process's network calls.",
                callers
                    .iter()
                    .map(Caller::label)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Source::Background { why, .. } => {
                format!("The base image's own traffic: {why}.")
            }
            Source::Unattributed => "No recorded network call matches this flow (a raw or \
                packet socket, or a call the recording does not hold)."
                .into(),
        }
    }

    /// What a `source` quick filter compares to pick the same sources.
    pub fn kind_filter(&self) -> String {
        match self {
            Source::Process(callers) => callers
                .first()
                .map_or_else(String::new, |caller| caller.name.clone()),
            Source::Background { .. } => "background".into(),
            Source::Unattributed => "unattributed".into(),
        }
    }

    pub fn first(&self) -> Option<&Caller> {
        match self {
            Source::Process(callers) => callers.first(),
            _ => None,
        }
    }
}

/// A flow to attribute: a remote `ip:port`, its protocol and its span.
pub struct FlowKey<'a> {
    pub udp: Option<bool>,
    pub endpoint: (IpAddr, u16),
    /// The other side of the frames the endpoint was counted from (the
    /// client of an accepted connection).
    pub others: &'a [(IpAddr, u16)],
    pub first_us: Option<u64>,
    pub last_us: Option<u64>,
}

/// The run's network calls, in time order, and the base image's names.
#[derive(Clone, Debug, Default)]
pub struct NetAttribution {
    calls: Vec<FlowCall>,
    /// Where the calls that name a port are in `calls`.
    by_port: std::collections::HashMap<u16, Vec<usize>>,
    /// When the run was live, host microseconds: packets far outside it are
    /// not named by its calls.
    window: Option<(u64, u64)>,
    /// Addresses the run's own DNS answers gave to a name, by address.
    names_at: BTreeMap<IpAddr, Vec<String>>,
}

fn unspecified(ip: IpAddr) -> bool {
    ip.is_unspecified()
}

impl NetAttribution {
    pub fn new(mut calls: Vec<FlowCall>) -> Self {
        calls.sort_by_key(|call| (call.first_us, call.call_id));
        let mut by_port: std::collections::HashMap<u16, Vec<usize>> = Default::default();
        for (at, call) in calls.iter().enumerate() {
            by_port.entry(call.port).or_default().push(at);
        }
        Self {
            calls,
            by_port,
            window: None,
            names_at: BTreeMap::new(),
        }
    }

    /// The attribution of the calls a scan collected, with host times from
    /// `clock` (none: the calls carry no time and match on address alone).
    pub fn from_log(
        calls: &[crate::rules::ioc::NetCall],
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) -> Self {
        let name = |image: &Option<String>| {
            image
                .as_deref()
                .and_then(|image| image.rsplit('/').find(|part| !part.is_empty()))
                .unwrap_or("unknown")
                .to_owned()
        };
        Self::new(
            calls
                .iter()
                .map(|call| FlowCall {
                    ip: call.ip,
                    port: call.port,
                    udp: call.udp,
                    role: call.role,
                    call: call.name,
                    caller: Caller {
                        pid: call.who.pid,
                        tid: call.who.tid,
                        cookie: call.who.cookie,
                        name: name(&call.who.image),
                    },
                    first_us: crate::ioc_scan::host_us(clock, call.who.time_ns),
                    last_us: crate::ioc_scan::host_us(clock, call.last_ns),
                    stream: call.who.stream,
                    call_id: call.who.call_id,
                })
                .collect(),
        )
    }

    /// Say when the run was live (host Unix milliseconds): a packet more than
    /// [`WINDOW_SLACK_US`] outside is not named by this run's calls.
    #[must_use]
    pub fn within(mut self, started_ms: Option<u64>, ended_ms: Option<u64>) -> Self {
        self.window = started_ms
            .zip(ended_ms.or(started_ms))
            .map(|(from, to)| (from.saturating_mul(1000), to.max(from).saturating_mul(1000)));
        self
    }

    pub fn calls(&self) -> &[FlowCall] {
        &self.calls
    }

    pub fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    /// Learn that a DNS answer gave `ip` for `name`.
    pub fn learn_name(&mut self, ip: IpAddr, name: &str) {
        let names = self.names_at.entry(ip).or_default();
        if names.len() < 16 && !names.iter().any(|known| known == name) {
            names.push(name.to_owned());
        }
    }

    fn matches_address(call: &FlowCall, ip: IpAddr, port: u16) -> bool {
        call.port == port && (call.ip == ip || (call.role == Role::Bound && unspecified(call.ip)))
    }

    fn names_endpoint(call: &FlowCall, key: &FlowKey<'_>) -> bool {
        let sides = std::iter::once(&key.endpoint).chain(key.others);
        match call.role {
            Role::Bound => sides
                .into_iter()
                .any(|(ip, port)| Self::matches_address(call, *ip, *port)),
            _ => sides
                .into_iter()
                .any(|(ip, port)| call.ip == *ip && call.port == *port),
        }
    }

    /// Whether a call's time fits a span, within the clock slack. A bind holds
    /// its port from then on.
    fn fits_time(call: &FlowCall, first: Option<u64>, last: Option<u64>) -> bool {
        match (call.first_us, call.last_us, first, last) {
            (Some(from), _, _, Some(last)) if call.role == Role::Bound => {
                from <= last.saturating_add(SLACK_US)
            }
            (Some(from), Some(to), Some(first), Some(last)) => {
                to.saturating_add(SLACK_US) >= first && from <= last.saturating_add(SLACK_US)
            }
            _ => true,
        }
    }

    /// The calls that name a flow: its address (or a bind of its port) and
    /// its protocol. The host's estimate of the guest clock can be seconds
    /// off, so time only tells processes apart: when one process made every
    /// matching call it is the flow's, whatever the clocks say; when several
    /// did, those whose calls overlap the flow (within [`SLACK_US`]) are, and
    /// all of them when none does. A bind only counts when no call names the
    /// address itself.
    fn flow_calls(&self, key: &FlowKey<'_>) -> Vec<&FlowCall> {
        let mut at: Vec<usize> = std::iter::once(key.endpoint.1)
            .chain(key.others.iter().map(|other| other.1))
            .flat_map(|port| self.by_port.get(&port).into_iter().flatten().copied())
            .collect();
        at.sort_unstable();
        at.dedup();
        let found: Vec<&FlowCall> = at
            .into_iter()
            .map(|at| &self.calls[at])
            .filter(|call| Self::names_endpoint(call, key))
            .filter(|call| key.udp.is_none_or(|udp| udp == call.udp))
            .collect();
        let named: Vec<&FlowCall> = found
            .iter()
            .copied()
            .filter(|call| call.role != Role::Bound)
            .collect();
        let found = if named.is_empty() { found } else { named };
        Self::by_time(found, |call| {
            Self::fits_time(call, key.first_us, key.last_us)
        })
    }

    /// `calls`, narrowed by `fits` when more than one process made them and
    /// some of them fit.
    fn by_time(calls: Vec<&FlowCall>, fits: impl Fn(&FlowCall) -> bool) -> Vec<&FlowCall> {
        let distinct: std::collections::BTreeSet<u64> =
            calls.iter().map(|call| call.caller.cookie).collect();
        if distinct.len() < 2 {
            return calls;
        }
        let fitting: Vec<&FlowCall> = calls.iter().copied().filter(|call| fits(call)).collect();
        if fitting.is_empty() {
            calls
        } else {
            fitting
        }
    }

    /// The distinct callers of `calls`, the earliest first.
    fn callers(calls: &[&FlowCall]) -> Vec<Caller> {
        let mut seen = std::collections::BTreeSet::new();
        calls
            .iter()
            .filter(|call| seen.insert(call.caller.cookie))
            .map(|call| call.caller.clone())
            .collect()
    }

    /// Whom a flow belongs to by its calls alone: the processes, or none.
    pub fn callers_of(&self, key: &FlowKey<'_>) -> Vec<Caller> {
        Self::callers(&self.flow_calls(key))
    }

    /// The Source of a flow: its processes, else the base image's background,
    /// else unattributed. A flow made by base image programs only is
    /// background; one a base program and another process both made names
    /// the other process.
    pub fn source_of(&self, key: &FlowKey<'_>) -> Source {
        let callers = self.callers_of(key);
        let own: Vec<Caller> = callers.iter().filter(|c| !c.base()).cloned().collect();
        if !own.is_empty() {
            return Source::Process(own);
        }
        if let Some(base) = callers.first() {
            let why = format!("{} is part of the base image", base.name);
            return Source::Background {
                kind: crate::summary::indicators::background_kind(&base.name, &why),
                why,
            };
        }
        self.background(key.endpoint, key.udp.unwrap_or(false))
            .map_or(Source::Unattributed, |(kind, why)| Source::Background {
                kind,
                why,
            })
    }

    /// Why an endpoint no call names is still the base image's: clock sync,
    /// the DHCP exchange, or the address the base's own lookup of an apt or
    /// NTP name got.
    pub fn background(&self, endpoint: (IpAddr, u16), udp: bool) -> Option<(&'static str, String)> {
        let value = antinomie_monitor_core::ioc::kind::ip_port(endpoint.0, endpoint.1);
        if let Some(why) = baseline::endpoint_noise(&value, udp) {
            return Some((
                crate::summary::indicators::background_kind(&value, why),
                why.to_owned(),
            ));
        }
        let names = self.names_at.get(&endpoint.0).filter(|n| !n.is_empty())?;
        if names.iter().all(|name| baseline::domain_noise(name)) {
            let why = format!(
                "{} is the address the base image's lookup of {} got",
                endpoint.0, names[0]
            );
            return Some((
                crate::summary::indicators::background_kind(&value, &why),
                why,
            ));
        }
        None
    }

    /// The Source of one packet of a flow seen at `time_us`: the processes
    /// whose latest call to either end came before it, a datagram call only
    /// standing for the replies that follow it.
    pub fn source_of_packet(&self, udp: bool, ends: [(IpAddr, u16); 2], time_us: u64) -> Source {
        // A packet outside the run's own span (a capture shared with another
        // run) is not named by this run's calls.
        let outside = self.window.is_some_and(|(from, to)| {
            time_us.saturating_add(WINDOW_SLACK_US) < from
                || time_us > to.saturating_add(WINDOW_SLACK_US)
        });
        let mut at: Vec<usize> = ends
            .iter()
            .flat_map(|end| self.by_port.get(&end.1).into_iter().flatten().copied())
            .collect();
        at.sort_unstable();
        at.dedup();
        let found: Vec<&FlowCall> = at
            .into_iter()
            .map(|at| &self.calls[at])
            .filter(|call| {
                !outside
                    && call.udp == udp
                    && ends
                        .iter()
                        .any(|(ip, port)| Self::matches_address(call, *ip, *port))
            })
            .collect();
        // A bind names a port, not a peer: it counts when nothing else does.
        let named: Vec<&FlowCall> = found
            .iter()
            .copied()
            .filter(|call| call.role != Role::Bound)
            .collect();
        let found = if named.is_empty() { found } else { named };
        // One call per process; time only tells processes apart (see `flow_calls`).
        let mut latest: BTreeMap<u64, &FlowCall> = BTreeMap::new();
        for call in Self::by_time(found, |call| {
            let began = call
                .first_us
                .is_none_or(|from| from <= time_us.saturating_add(SLACK_US));
            let live = call.role == Role::Bound
                || !udp
                || call.last_us.is_none_or(|to| {
                    time_us <= to.saturating_add(UDP_REPLY_US).saturating_add(SLACK_US)
                });
            began && live
        }) {
            latest
                .entry(call.caller.cookie)
                .and_modify(|held| {
                    if call.last_us > held.last_us {
                        *held = call;
                    }
                })
                .or_insert(call);
        }
        let mut named: Vec<&FlowCall> = latest.values().copied().collect();
        named.sort_by_key(|call| (call.first_us, call.call_id));
        let callers = Self::callers(&named);
        let own: Vec<Caller> = callers.iter().filter(|c| !c.base()).cloned().collect();
        if !own.is_empty() {
            return Source::Process(own);
        }
        if let Some(base) = callers.first() {
            let why = format!("{} is part of the base image", base.name);
            return Source::Background {
                kind: crate::summary::indicators::background_kind(&base.name, &why),
                why,
            };
        }
        // The remote end is the one that is not a guest-local address.
        for end in ends {
            if let Some((kind, why)) = self.background(end, udp) {
                return Source::Background { kind, why };
            }
        }
        Source::Unattributed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    pub fn caller(pid: u32, name: &str) -> Caller {
        Caller {
            pid,
            tid: pid + 1,
            cookie: u64::from(pid) * 10,
            name: name.into(),
        }
    }

    pub fn call(
        who: Caller,
        name: &'static str,
        role: Role,
        peer: (&str, u16),
        udp: bool,
        us: u64,
    ) -> FlowCall {
        FlowCall {
            ip: ip(peer.0),
            port: peer.1,
            udp,
            role,
            call: name,
            caller: who,
            first_us: Some(us),
            last_us: Some(us),
            stream: 1,
            call_id: us,
        }
    }

    fn key(udp: bool, endpoint: (&str, u16), span: (u64, u64)) -> FlowKey<'static> {
        FlowKey {
            udp: Some(udp),
            endpoint: (ip(endpoint.0), endpoint.1),
            others: &[],
            first_us: Some(span.0),
            last_us: Some(span.1),
        }
    }

    const SEC: u64 = 1_000_000;

    #[test]
    fn a_tcp_connect_names_the_process_that_made_it() {
        let attribution = NetAttribution::new(vec![call(
            caller(40, "curl"),
            "connect",
            Role::Remote,
            ("192.0.2.9", 80),
            false,
            100 * SEC,
        )]);
        let source = attribution.source_of(&key(false, ("192.0.2.9", 80), (100 * SEC, 101 * SEC)));
        assert_eq!(source.label(), "curl (40 \u{b7} 41)");
        assert_eq!(source.kind(), "process");
        // Another protocol or another port is not this call.
        assert_eq!(
            attribution
                .source_of(&key(true, ("192.0.2.9", 80), (100 * SEC, 101 * SEC)))
                .kind(),
            "unattributed"
        );
        assert_eq!(
            attribution
                .source_of(&key(false, ("192.0.2.9", 81), (100 * SEC, 101 * SEC)))
                .kind(),
            "unattributed"
        );
    }

    #[test]
    fn a_udp_dns_lookup_through_sendto_names_the_resolver_caller() {
        let attribution = NetAttribution::new(vec![
            call(
                caller(52, "nslookup"),
                "sendto",
                Role::Remote,
                ("10.0.2.3", 53),
                true,
                50 * SEC,
            ),
            call(
                caller(60, "dig"),
                "sendto",
                Role::Remote,
                ("10.0.2.3", 53),
                true,
                400 * SEC,
            ),
        ]);
        let source =
            attribution.source_of(&key(true, ("10.0.2.3", 53), (50 * SEC, 50 * SEC + 30_000)));
        assert_eq!(source.label(), "nslookup (52 \u{b7} 53)");
        // The reply 4 s later is the first caller's; the second caller's own
        // packet a few minutes on is the second's.
        let ends = [(ip("10.0.2.3"), 53), (ip("10.0.2.15"), 40000)];
        assert_eq!(
            attribution.source_of_packet(true, ends, 54 * SEC).label(),
            "nslookup (52 \u{b7} 53)"
        );
        assert_eq!(
            attribution
                .source_of_packet(true, ends, 400 * SEC + 20_000)
                .label(),
            "dig (60 \u{b7} 61)"
        );
    }

    #[test]
    fn a_clock_that_is_seconds_off_still_names_the_only_process_that_called() {
        // The PC run: the guest's clock put the lookup 5 s before the capture's.
        let attribution = NetAttribution::new(vec![call(
            caller(165, "exe"),
            "connect",
            Role::Remote,
            ("10.0.2.3", 53),
            true,
            100 * SEC,
        )]);
        let late = key(true, ("10.0.2.3", 53), (105 * SEC + 90_000, 110 * SEC));
        assert_eq!(attribution.source_of(&late).label(), "exe (165 \u{b7} 166)");
        let ends = [(ip("10.0.2.3"), 53), (ip("10.0.2.15"), 40000)];
        assert_eq!(
            attribution
                .source_of_packet(true, ends, 105 * SEC + 90_000)
                .kind(),
            "process"
        );
    }

    #[test]
    fn packets_far_outside_the_runs_span_are_not_named_by_its_calls() {
        // A capture shared with another run: this run was live 100..200 s.
        let attribution = NetAttribution::new(vec![call(
            caller(52, "nslookup"),
            "sendto",
            Role::Remote,
            ("10.0.2.3", 53),
            true,
            150 * SEC,
        )])
        .within(Some(100 * 1000), Some(200 * 1000));
        let ends = [(ip("10.0.2.3"), 53), (ip("10.0.2.15"), 40000)];
        assert_eq!(
            attribution.source_of_packet(true, ends, 151 * SEC).kind(),
            "process"
        );
        assert_eq!(
            attribution.source_of_packet(true, ends, 500 * SEC),
            Source::Unattributed
        );
        // The base image's NTP is still the base image's.
        let ntp = [(ip("203.0.113.5"), 123), (ip("10.0.2.15"), 123)];
        assert_eq!(
            attribution.source_of_packet(true, ntp, 500 * SEC).kind(),
            "background"
        );
    }

    #[test]
    fn an_accepted_connection_names_the_server_and_a_bind_is_the_fallback() {
        let attribution = NetAttribution::new(vec![
            call(
                caller(70, "nc"),
                "bind",
                Role::Bound,
                ("0.0.0.0", 8080),
                false,
                10 * SEC,
            ),
            call(
                caller(70, "nc"),
                "accept",
                Role::Accepted,
                ("10.0.2.2", 51000),
                false,
                20 * SEC,
            ),
        ]);
        // The capture counted the guest's own side as the endpoint.
        let others = [(ip("10.0.2.2"), 51000)];
        let accepted = FlowKey {
            udp: Some(false),
            endpoint: (ip("10.0.2.15"), 8080),
            others: &others,
            first_us: Some(19 * SEC),
            last_us: Some(22 * SEC),
        };
        let source = attribution.source_of(&accepted);
        assert_eq!(source.label(), "nc (70 \u{b7} 71)");
        // A client the process never accepted: only the bind names it.
        let refused = key(false, ("10.0.2.15", 8080), (40 * SEC, 41 * SEC));
        assert_eq!(attribution.source_of(&refused).kind(), "process");
        assert_eq!(attribution.callers_of(&refused).len(), 1);
    }

    #[test]
    fn ntp_with_no_call_is_background_and_a_raw_flow_is_unattributed() {
        let attribution = NetAttribution::default();
        let ntp = attribution.source_of(&key(true, ("203.0.113.5", 123), (5 * SEC, 5 * SEC)));
        assert_eq!(ntp.label(), "Base image background: NTP");
        let raw = attribution.source_of(&key(false, ("203.0.113.77", 22), (5 * SEC, 6 * SEC)));
        assert_eq!(raw, Source::Unattributed);
        assert_eq!(raw.label(), "Unattributed");
    }

    #[test]
    fn a_base_image_program_makes_background_and_a_sample_that_talks_ntp_keeps_its_row() {
        let attribution = NetAttribution::new(vec![
            call(
                caller(5, "chronyd"),
                "sendto",
                Role::Remote,
                ("203.0.113.5", 123),
                true,
                5 * SEC,
            ),
            call(
                caller(90, "beacon"),
                "sendto",
                Role::Remote,
                ("203.0.113.6", 123),
                true,
                6 * SEC,
            ),
        ]);
        let base = attribution.source_of(&key(true, ("203.0.113.5", 123), (5 * SEC, 5 * SEC)));
        assert_eq!(base.kind(), "background");
        let own = attribution.source_of(&key(true, ("203.0.113.6", 123), (6 * SEC, 6 * SEC)));
        assert_eq!(own.label(), "beacon (90 \u{b7} 91)");
    }

    #[test]
    fn an_address_the_base_images_lookup_got_is_background() {
        let mut attribution = NetAttribution::default();
        attribution.learn_name(ip("198.18.0.7"), "metadata.ftp-master.debian.org");
        let source = attribution.source_of(&key(false, ("198.18.0.7", 443), (1, 2)));
        assert_eq!(source.label(), "Base image background: apt");
    }

    #[test]
    fn two_runs_on_one_vm_are_told_apart_by_time() {
        // The same server, called by two programs a minute apart.
        let attribution = NetAttribution::new(vec![
            call(
                caller(10, "first"),
                "connect",
                Role::Remote,
                ("192.0.2.9", 443),
                false,
                100 * SEC,
            ),
            call(
                caller(20, "second"),
                "connect",
                Role::Remote,
                ("192.0.2.9", 443),
                false,
                200 * SEC,
            ),
        ]);
        let a = attribution.source_of(&key(false, ("192.0.2.9", 443), (100 * SEC, 110 * SEC)));
        let b = attribution.source_of(&key(false, ("192.0.2.9", 443), (200 * SEC, 210 * SEC)));
        assert_eq!(a.first().map(|c| c.pid), Some(10));
        assert_eq!(b.first().map(|c| c.pid), Some(20));
        // A flow spanning both lists both.
        let both = attribution.source_of(&key(false, ("192.0.2.9", 443), (100 * SEC, 210 * SEC)));
        assert_eq!(both.label(), "first (10 \u{b7} 11), second (20 \u{b7} 21)");
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! Per-run network routes. A VM set to "Routed" network gets a virtual NIC
//! that QEMU connects to a gateway inside Antinomie (host side only: nothing
//! in the guest changes). The gateway is the guest's DHCP server, DNS server
//! and router, and what it does with the guest's traffic is the run's route:
//!
//! * `Drop`: nothing leaves; the attempts are still on the wire for the pcap.
//! * `Internet`: TCP is connected from the host, DNS resolved by the host.
//! * `InetSim`: every TCP connection and DNS name goes to fake services.
//! * `Tor`, `Vpn`, `Socks5`: every TCP connection goes through a SOCKS5
//!   proxy (for Tor, a tor Antinomie starts for the run or one the analyst
//!   runs; for the VPN, wireproxy), with the destination name given to the proxy (no DNS leaks).
//!
//! A route that cannot start fails closed: the run does not start, and the
//! gateway itself starts on `Drop` and returns to it when the run ends.
//! Nothing here needs root.
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

mod config;
mod dhcp;
mod dns;
mod frame;
mod gateway;
mod inetsim;
mod managed;
mod names;
mod probe;
mod qemu;
mod run;
mod socks;
mod tcp;
mod tor;
mod upstream;

pub use self::{
    config::{
        InetSimConfig, InetSimMode, RouteConfig, RouteSpec, Socks5Config, TorConfig, TorMode,
        VpnConfig, load_config, save_config, tool_on_path,
    },
    gateway::{Claimed, Gateway, GatewayNet},
    qemu::require_qemu_support,
    run::{RouteClaim, claim_for_run, release_for_run, test_route},
};

/// Where a run's traffic went.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteKind {
    /// Nothing leaves the VM.
    #[default]
    Drop,
    /// The host's own Internet connection.
    Internet,
    /// Fake services (INetSim or the built-in responder).
    InetSim,
    /// Through Tor: a tor Antinomie runs for the run, or a SOCKS port.
    Tor,
    /// Through WireGuard (wireproxy's SOCKS port).
    Vpn,
    /// Through a SOCKS5 proxy of the analyst's.
    Socks5,
}

impl RouteKind {
    pub const ALL: [RouteKind; 6] = [
        RouteKind::Drop,
        RouteKind::Internet,
        RouteKind::InetSim,
        RouteKind::Tor,
        RouteKind::Vpn,
        RouteKind::Socks5,
    ];

    pub fn label(self) -> &'static str {
        match self {
            RouteKind::Drop => "None (drop)",
            RouteKind::Internet => "Internet",
            RouteKind::InetSim => "InetSim (fake services)",
            RouteKind::Tor => "Tor",
            RouteKind::Vpn => "VPN (WireGuard)",
            RouteKind::Socks5 => "SOCKS5 proxy",
        }
    }

    pub fn explain(self) -> &'static str {
        match self {
            RouteKind::Drop => {
                "The guest has a link and an address but nothing leaves: connections and DNS \
                 go unanswered. The attempts are still captured."
            }
            RouteKind::Internet => {
                "The host connects for the guest, directly. The sample can reach the real \
                 Internet, not the host or your local network."
            }
            RouteKind::InetSim => {
                "Every DNS name resolves to a fake address and every connection reaches a fake \
                 service. Nothing leaves the host."
            }
            RouteKind::Tor => {
                "Every connection goes through Tor, which Antinomie starts for the run and stops \
                 afterwards (or through a SOCKS address you set); names are resolved by Tor. \
                 UDP other than DNS is dropped."
            }
            RouteKind::Vpn => {
                "Every connection goes through a WireGuard tunnel run by wireproxy (userspace, \
                 no root); names are resolved through the tunnel. UDP other than DNS is dropped."
            }
            RouteKind::Socks5 => {
                "Every connection goes through the SOCKS5 proxy set in Settings; names are \
                 resolved by the proxy. UDP other than DNS is dropped."
            }
        }
    }

    /// [`explain`](Self::explain) in one short line, for a form's hint.
    pub fn summary(self) -> &'static str {
        match self {
            RouteKind::Drop => "Nothing leaves; attempts are still captured.",
            RouteKind::Internet => "Direct to the Internet, never the host or LAN.",
            RouteKind::InetSim => "Fake DNS and services; nothing leaves the host.",
            RouteKind::Tor => "Through Tor; UDP besides DNS is dropped.",
            RouteKind::Vpn => "Through a WireGuard tunnel; UDP besides DNS is dropped.",
            RouteKind::Socks5 => "Through your SOCKS5 proxy; UDP besides DNS is dropped.",
        }
    }

    /// Short name for tables and the run header.
    pub fn short(self) -> &'static str {
        match self {
            RouteKind::Drop => "None",
            RouteKind::Internet => "Internet",
            RouteKind::InetSim => "InetSim",
            RouteKind::Tor => "Tor",
            RouteKind::Vpn => "VPN",
            RouteKind::Socks5 => "SOCKS5",
        }
    }
}

/// How the VM's network carried the route.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteVia {
    /// The Routed gateway; the route was chosen for the run.
    #[default]
    Gateway,
    /// The VM's NAT (QEMU user networking): fixed for the VM.
    VmNat,
    /// The VM's isolated network: nothing leaves.
    VmIsolated,
    /// The VM has no network card.
    VmDisconnected,
}

/// What the gateway did with the traffic while the route was in use. Counts
/// cover the whole VM during the run, as the packet capture does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteStats {
    /// TCP connections the gateway carried upstream.
    pub tcp_connections: u64,
    /// Connections it tried and could not make.
    pub tcp_failed: u64,
    /// Connections refused or dropped by the route's rules.
    pub tcp_blocked: u64,
    pub dns_queries: u64,
    /// Queries it could not answer (no route, no data, resolver error).
    pub dns_unanswered: u64,
    /// UDP datagrams other than DNS and DHCP.
    pub udp_dropped: u64,
    pub icmp_dropped: u64,
    /// IPv6 and other frames.
    pub other_dropped: u64,
    /// Payload bytes from the guest and to the guest.
    pub up_len: u64,
    pub down_len: u64,
}

impl RouteStats {
    /// What happened since `earlier`.
    pub fn since(self, earlier: RouteStats) -> RouteStats {
        let d = |now: u64, then: u64| now.saturating_sub(then);
        RouteStats {
            tcp_connections: d(self.tcp_connections, earlier.tcp_connections),
            tcp_failed: d(self.tcp_failed, earlier.tcp_failed),
            tcp_blocked: d(self.tcp_blocked, earlier.tcp_blocked),
            dns_queries: d(self.dns_queries, earlier.dns_queries),
            dns_unanswered: d(self.dns_unanswered, earlier.dns_unanswered),
            udp_dropped: d(self.udp_dropped, earlier.udp_dropped),
            icmp_dropped: d(self.icmp_dropped, earlier.icmp_dropped),
            other_dropped: d(self.other_dropped, earlier.other_dropped),
            up_len: d(self.up_len, earlier.up_len),
            down_len: d(self.down_len, earlier.down_len),
        }
    }

    /// One line for the UI; empty when nothing was seen.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        let mut add = |count: u64, what: &str| {
            if count > 0 {
                parts.push(format!("{count} {what}"));
            }
        };
        add(self.tcp_connections, "TCP connections");
        add(self.tcp_failed, "failed");
        add(self.tcp_blocked, "blocked");
        add(self.dns_queries, "DNS queries");
        add(self.dns_unanswered, "unanswered");
        add(self.udp_dropped, "UDP dropped");
        add(self.icmp_dropped, "ICMP dropped");
        add(self.other_dropped, "other frames dropped");
        parts.join(", ")
    }
}

/// The route a run used, as saved in `run.json` and `artifacts.json`. It
/// holds no credentials, only the proxy's host and port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRecord {
    pub kind: RouteKind,
    /// Plain text for the UI: `Tor via 127.0.0.1:9050`.
    pub label: String,
    pub via: RouteVia,
    /// When the route was checked up, before the sample started (host Unix
    /// milliseconds); absent for a VM network that needs no check.
    #[serde(default)]
    pub checked_ms: Option<u64>,
    /// What the gateway counted, saved when the run's tree ended.
    #[serde(default)]
    pub stats: Option<RouteStats>,
}

impl RouteRecord {
    /// The route of a VM that is not Routed (its fixed network), or `Drop`
    /// for a Routed VM that has had no route chosen yet.
    pub fn for_network(network: crate::api::VmNetwork) -> Self {
        use crate::api::VmNetwork;
        Self::fixed(match network {
            VmNetwork::Nat => RouteVia::VmNat,
            VmNetwork::Isolated => RouteVia::VmIsolated,
            VmNetwork::Disconnected => RouteVia::VmDisconnected,
            VmNetwork::Routed => RouteVia::Gateway,
        })
    }

    /// The route of a VM that is not Routed: its fixed network.
    pub fn fixed(via: RouteVia) -> Self {
        let (kind, label) = match via {
            RouteVia::VmNat => (
                RouteKind::Internet,
                "Internet (VM NAT, QEMU user networking)",
            ),
            RouteVia::VmIsolated => (RouteKind::Drop, "None (VM isolated network)"),
            RouteVia::VmDisconnected => (RouteKind::Drop, "None (VM has no network card)"),
            RouteVia::Gateway => (RouteKind::Drop, "None"),
        };
        RouteRecord {
            kind,
            label: label.into(),
            via,
            checked_ms: None,
            stats: None,
        }
    }
}

/// Counters the gateway threads share.
#[derive(Default)]
pub(crate) struct Counters {
    pub tcp_connections: AtomicU64,
    pub tcp_failed: AtomicU64,
    pub tcp_blocked: AtomicU64,
    pub dns_queries: AtomicU64,
    pub dns_unanswered: AtomicU64,
    pub udp_dropped: AtomicU64,
    pub icmp_dropped: AtomicU64,
    pub other_dropped: AtomicU64,
    pub up_len: AtomicU64,
    pub down_len: AtomicU64,
}

impl Counters {
    pub fn add(counter: &AtomicU64, count: u64) {
        counter.fetch_add(count, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RouteStats {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        RouteStats {
            tcp_connections: get(&self.tcp_connections),
            tcp_failed: get(&self.tcp_failed),
            tcp_blocked: get(&self.tcp_blocked),
            dns_queries: get(&self.dns_queries),
            dns_unanswered: get(&self.dns_unanswered),
            udp_dropped: get(&self.udp_dropped),
            icmp_dropped: get(&self.icmp_dropped),
            other_dropped: get(&self.other_dropped),
            up_len: get(&self.up_len),
            down_len: get(&self.down_len),
        }
    }
}

#[cfg(test)]
mod tests;

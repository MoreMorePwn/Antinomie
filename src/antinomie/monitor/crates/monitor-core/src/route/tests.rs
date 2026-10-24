//! Tests for the route module: a scripted guest talks to the real gateway
//! over a Unix socket (as QEMU's stream netdev would), and a fake SOCKS5
//! server stands in for Tor, a VPN or a proxy. Nothing leaves the machine.
use super::{
    Gateway, GatewayNet, RouteConfig, RouteKind, RouteRecord, RouteStats, RouteVia, claim_for_run,
    release_for_run,
};
use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

mod config;
mod guest;
mod managed;
mod metadata;
mod qemu;
mod socks_server;
mod tor;
mod traffic;

use guest::Guest;
use socks_server::FakeSocks;

pub(super) fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ant-route-{name}-{}-{}",
        std::process::id(),
        crate::storage::unique_id()
    ));
    crate::storage::private_dir(&dir).unwrap();
    dir
}

/// A gateway on the Drop route and a guest connected to it.
pub(super) struct Rig {
    pub gateway: Gateway,
    pub guest: Guest,
    pub dir: PathBuf,
}

impl Rig {
    pub fn new(name: &str) -> Rig {
        let dir = scratch(name);
        let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
        let gateway = Gateway::start(&dir, net).unwrap();
        let guest = Guest::connect(gateway.socket_path());
        Rig {
            gateway,
            guest,
            dir,
        }
    }

    /// Claims `kind` for run `run` under `config`.
    pub fn claim(&self, run: &str, config: &RouteConfig, kind: RouteKind) -> Result<(), String> {
        self.gateway
            .claim(run, config.spec(no_data(), kind)?)
            .map(|_| ())
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
pub(super) const DNS: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);
pub(super) const GUEST: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
pub(super) const WAIT: Duration = Duration::from_secs(5);

/// Settings for a route through the fake SOCKS5 server `socks`.
pub(super) fn config_for(socks: &FakeSocks) -> RouteConfig {
    let mut config = RouteConfig::default();
    config.tor.mode = super::TorMode::Socks;
    config.tor.socks = format!("127.0.0.1:{}", socks.port());
    config.tor.probe = String::new();
    config.socks5.host = "127.0.0.1".into();
    config.socks5.port = socks.port();
    config.socks5.probe = String::new();
    config
}

/// A data folder that does not exist: no installed tools, no tor state.
pub(super) fn no_data() -> &'static std::path::Path {
    std::path::Path::new("/nonexistent-antinomie-data")
}

pub(super) fn record_for(kind: RouteKind) -> RouteRecord {
    RouteRecord {
        kind,
        label: kind.label().into(),
        via: RouteVia::Gateway,
        checked_ms: None,
        stats: None,
    }
}

#[test]
fn route_kinds_have_words_for_the_ui() {
    for kind in RouteKind::ALL {
        assert!(!kind.label().is_empty() && !kind.short().is_empty());
        assert!(kind.explain().len() > 20);
    }
    assert_eq!(RouteKind::default(), RouteKind::Drop);
    let _ = RouteStats::default();
    let _ = (claim_for_run, release_for_run, RouteVia::Gateway);
}

// SPDX-License-Identifier: GPL-3.0-only
//! The saved route settings (Settings > Network routes) and the checked,
//! ready-to-use form of one route.
//!
//! The file is `network/routes.json` in the data folder, owner-only like the
//! sample sources' API keys because it can hold a proxy password. Passwords
//! are never logged, never shown in a `Debug` print, never put in a run's
//! metadata and never exported.
use super::RouteKind;
use serde::{Deserialize, Serialize};
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
};

const CONFIG_DIR: &str = "network";
const CONFIG_FILE: &str = "routes.json";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TorMode {
    /// Antinomie runs its own tor for the run: a private data folder, a free
    /// SocksPort on 127.0.0.1, started with the route and stopped with it.
    #[default]
    Own,
    /// Connect to a SOCKS address (a tor the analyst already runs).
    Socks,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TorConfig {
    pub mode: TorMode,
    /// Own mode: the tor program; empty looks on `PATH`, in the system's
    /// usual places and then at the copy Antinomie installed.
    pub program: String,
    /// Socks mode: Tor's SOCKS port, `host:port`.
    pub socks: String,
    /// `host:port` the route connects to through Tor before a run starts, to
    /// prove the circuit works; empty checks only that Tor answers SOCKS.
    pub probe: String,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            mode: TorMode::Own,
            program: String::new(),
            socks: "127.0.0.1:9050".into(),
            probe: "check.torproject.org:443".into(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnConfig {
    /// The wireproxy executable; empty looks on `PATH`, in the system's
    /// usual places and then at the copy Antinomie installed.
    pub wireproxy: String,
    /// wireproxy's configuration file (WireGuard peer plus a `[Socks5]`
    /// section). Antinomie starts wireproxy with it for each run and stops it
    /// afterwards.
    pub config: String,
    /// Checked through the tunnel before a run; empty skips the check.
    pub probe: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Socks5Config {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub probe: String,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            host: String::new(),
            port: 1080,
            username: String::new(),
            password: String::new(),
            probe: "1.1.1.1:443".into(),
        }
    }
}

impl std::fmt::Debug for Socks5Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &!self.username.is_empty())
            .field("password", &"[redacted]")
            .field("probe", &self.probe)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InetSimMode {
    /// Antinomie's own small responder: DNS, HTTP, SMTP and a catch-all.
    #[default]
    Builtin,
    /// A running INetSim: connections go to its ports plus an offset.
    External,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InetSimConfig {
    pub mode: InetSimMode,
    /// External mode: where INetSim listens.
    pub host: String,
    /// External mode: a guest connection to port P goes to `host:P+offset`,
    /// so INetSim can run as a normal user on high ports.
    pub port_offset: u16,
    /// The address every DNS name resolves to. It is never connected to.
    pub sinkhole: String,
}

impl Default for InetSimConfig {
    fn default() -> Self {
        Self {
            mode: InetSimMode::Builtin,
            host: "127.0.0.1".into(),
            port_offset: 10_000,
            sinkhole: "198.51.100.1".into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RouteConfig {
    /// The route a run uses when the run dialog does not pick one.
    pub default_route: RouteKind,
    pub tor: TorConfig,
    pub vpn: VpnConfig,
    pub socks5: Socks5Config,
    pub inetsim: InetSimConfig,
    /// The Internet route may reach private (RFC 1918) addresses of the
    /// host's network. Off: it reaches only public addresses.
    pub allow_lan: bool,
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            default_route: RouteKind::Drop,
            tor: TorConfig::default(),
            vpn: VpnConfig::default(),
            socks5: Socks5Config::default(),
            inetsim: InetSimConfig::default(),
            allow_lan: false,
        }
    }
}

/// `host:port` with a name or IPv4 address and a non-zero port.
pub(crate) fn host_port(text: &str) -> Result<(String, u16), String> {
    let text = text.trim();
    let (host, port) = text
        .rsplit_once(':')
        .ok_or_else(|| format!("{text:?} is not host:port"))?;
    let port: u16 = port
        .parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("{text:?} has no valid port"))?;
    check_host(host)?;
    Ok((host.to_owned(), port))
}

fn check_host(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(format!("{host:?} is not a host name or IPv4 address"));
    }
    Ok(())
}

fn check_probe(text: &str) -> Result<Option<(String, u16)>, String> {
    if text.trim().is_empty() {
        return Ok(None);
    }
    host_port(text)
        .map(Some)
        .map_err(|error| format!("check target: {error}"))
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Credentials {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credentials([redacted])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SocksProxy {
    pub host: String,
    pub port: u16,
    pub credentials: Option<Credentials>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Sink {
    /// What DNS answers.
    pub address: Ipv4Addr,
    /// External INetSim: host and port offset.
    pub external: Option<(String, u16)>,
}

/// Where a route sends the guest's TCP connections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Egress {
    Drop,
    Direct { allow_lan: bool },
    Sink(Sink),
    Socks(SocksProxy),
}

/// wireproxy as the VPN route starts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireproxyLaunch {
    pub binary: PathBuf,
    pub config: PathBuf,
}

/// The tor Antinomie starts for the Tor route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TorLaunch {
    pub binary: PathBuf,
    /// The Expert Bundle's own libevent and OpenSSL, set as the library
    /// path; `None` for a tor from the system.
    pub lib_dir: Option<PathBuf>,
    /// The bundle's `geoip` files, when it has them.
    pub geoip_dir: Option<PathBuf>,
    /// Where each gateway gets its private data folder.
    pub state_root: PathBuf,
}

/// One route, checked and resolved from the saved settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub kind: RouteKind,
    pub(crate) egress: Egress,
    /// Connected through the route before a run starts.
    pub(crate) probe: Option<(String, u16)>,
    pub label: String,
    pub wireproxy: Option<WireproxyLaunch>,
    pub tor: Option<TorLaunch>,
}

impl RouteSpec {
    /// The route that lets nothing out.
    pub fn drop_all() -> Self {
        RouteSpec {
            kind: RouteKind::Drop,
            egress: Egress::Drop,
            probe: None,
            label: RouteKind::Drop.label().into(),
            wireproxy: None,
            tor: None,
        }
    }

    /// Own-tor routes learn their SOCKS port when tor starts.
    pub(crate) fn set_socks_port(&mut self, port: u16) {
        if let Egress::Socks(proxy) = &mut self.egress {
            proxy.port = port;
        }
    }
}

/// The `BindAddress` of the `[Socks5]` section of a wireproxy configuration.
pub(crate) fn wireproxy_socks(config: &str) -> Result<(String, u16), String> {
    let mut in_socks = false;
    for line in config.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if let Some(section) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_socks = section.trim().eq_ignore_ascii_case("socks5");
        } else if in_socks
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("bindaddress")
        {
            return host_port(value);
        }
    }
    Err("the wireproxy configuration has no [Socks5] section with a BindAddress".into())
}

/// An executable on `PATH`, for the tools a route can use (`wireproxy`,
/// `tor`, `inetsim`); the Settings page shows whether one is installed.
pub fn tool_on_path(name: &str) -> Option<PathBuf> {
    find_on_path(name)
}

/// The program for a route tool, in the order the other tools use: the
/// path set in Settings, `PATH`, the system's usual places, then the copy
/// Antinomie installed under the data folder.
fn find_program(id: &str, configured: &str, data_dir: &Path) -> Result<Option<PathBuf>, String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let path = PathBuf::from(configured);
        return if path.is_file() {
            Ok(Some(path))
        } else {
            Err(format!("{} is not a file", path.display()))
        };
    }
    Ok(find_on_path(id)
        .or_else(|| {
            crate::analysis_tools::system_candidates(id)
                .iter()
                .map(PathBuf::from)
                .find(|path| path.is_file())
        })
        .or_else(|| crate::analysis_tools::managed_entry(data_dir, id)))
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

impl RouteConfig {
    /// The settings are well formed (nothing is looked up on disk or the
    /// network); used when they are saved.
    pub fn validate(&self) -> Result<(), String> {
        if self.tor.mode == TorMode::Socks {
            host_port(&self.tor.socks).map_err(|e| format!("Tor SOCKS address: {e}"))?;
        }
        check_probe(&self.tor.probe).map_err(|e| format!("Tor: {e}"))?;
        check_probe(&self.vpn.probe).map_err(|e| format!("VPN: {e}"))?;
        check_probe(&self.socks5.probe).map_err(|e| format!("SOCKS5: {e}"))?;
        if !self.socks5.host.is_empty() {
            check_host(&self.socks5.host).map_err(|e| format!("SOCKS5 host: {e}"))?;
            if self.socks5.port == 0 {
                return Err("SOCKS5 port is 1 to 65535".into());
            }
        }
        let socks5 = &self.socks5;
        if socks5.username.len() > 255 || socks5.password.len() > 255 {
            return Err("SOCKS5 user name and password are at most 255 bytes".into());
        }
        if socks5.username.is_empty() != socks5.password.is_empty() {
            return Err("SOCKS5 needs both a user name and a password, or neither".into());
        }
        if socks5.username.contains('\0') || socks5.password.contains('\0') {
            return Err("SOCKS5 credentials cannot contain a NUL byte".into());
        }
        self.inetsim
            .sinkhole
            .parse::<Ipv4Addr>()
            .map_err(|_| "InetSim sinkhole address is not an IPv4 address".to_string())?;
        if self.inetsim.mode == InetSimMode::External {
            check_host(&self.inetsim.host).map_err(|e| format!("InetSim host: {e}"))?;
        }
        Ok(())
    }

    /// What is missing from the settings for `kind`, without looking at the
    /// disk or the network; `None` when nothing obvious is. Used to warn in
    /// the Run form before a run is tried.
    pub fn setup_problem(&self, kind: RouteKind) -> Option<&'static str> {
        match kind {
            RouteKind::Vpn if self.vpn.config.trim().is_empty() => {
                Some("Set the wireproxy configuration file in Settings > Network routes.")
            }
            RouteKind::Socks5 if self.socks5.host.trim().is_empty() => {
                Some("Set the SOCKS5 proxy host in Settings > Network routes.")
            }
            _ => None,
        }
    }

    /// `kind` ready to use, or why it cannot be: a missing setting, a
    /// missing file or program. Never falls back to another route.
    ///
    /// `data_dir` is the app's data folder: Antinomie's own copies of tor
    /// and wireproxy are looked for under it, and its tor keeps its private
    /// data folder there.
    pub fn spec(&self, data_dir: &Path, kind: RouteKind) -> Result<RouteSpec, String> {
        self.validate()?;
        let spec = |egress, probe, label: String, wireproxy| RouteSpec {
            kind,
            egress,
            probe,
            label,
            wireproxy,
            tor: None,
        };
        Ok(match kind {
            RouteKind::Drop => RouteSpec::drop_all(),
            RouteKind::Internet => spec(
                Egress::Direct {
                    allow_lan: self.allow_lan,
                },
                None,
                "Internet (host connection)".into(),
                None,
            ),
            RouteKind::InetSim => {
                let address = self.inetsim.sinkhole.parse().map_err(|_| "sinkhole")?;
                let (external, label) = match self.inetsim.mode {
                    InetSimMode::Builtin => (None, "InetSim (built-in services)".to_owned()),
                    InetSimMode::External => (
                        Some((self.inetsim.host.clone(), self.inetsim.port_offset)),
                        format!(
                            "InetSim ({}, ports +{})",
                            self.inetsim.host, self.inetsim.port_offset
                        ),
                    ),
                };
                spec(Egress::Sink(Sink { address, external }), None, label, None)
            }
            RouteKind::Tor if self.tor.mode == TorMode::Own => {
                let binary = find_program("tor", &self.tor.program, data_dir)
                    .map_err(|e| format!("Tor: {e}"))?
                    .ok_or(
                        "Tor: no tor program was found; install Tor in Settings > Network \
                         routes, or use an existing SOCKS address",
                    )?;
                let bundle = crate::analysis_tools::managed_entry(data_dir, "tor");
                let lib_dir = (bundle.as_ref() == Some(&binary))
                    .then(|| binary.parent().map(Path::to_path_buf))
                    .flatten();
                let geoip_dir = lib_dir
                    .as_ref()
                    .and_then(|dir| dir.parent())
                    .map(|root| root.join("data"));
                let mut route = spec(
                    Egress::Socks(SocksProxy {
                        host: "127.0.0.1".into(),
                        port: 0,
                        credentials: None,
                    }),
                    check_probe(&self.tor.probe)?,
                    "Tor (started by Antinomie)".into(),
                    None,
                );
                route.tor = Some(TorLaunch {
                    binary,
                    lib_dir,
                    geoip_dir,
                    state_root: data_dir.join(CONFIG_DIR).join("tor"),
                });
                route
            }
            RouteKind::Tor => {
                let (host, port) = host_port(&self.tor.socks)?;
                let label = format!("Tor via {host}:{port}");
                spec(
                    Egress::Socks(SocksProxy {
                        host,
                        port,
                        credentials: None,
                    }),
                    check_probe(&self.tor.probe)?,
                    label,
                    None,
                )
            }
            RouteKind::Vpn => {
                let config = Path::new(self.vpn.config.trim());
                if self.vpn.config.trim().is_empty() {
                    return Err("VPN: set the wireproxy configuration file in Settings".into());
                }
                let text = std::fs::read_to_string(config)
                    .map_err(|e| format!("VPN: {}: {e}", config.display()))?;
                let (host, port) = wireproxy_socks(&text).map_err(|e| format!("VPN: {e}"))?;
                let binary = find_program("wireproxy", &self.vpn.wireproxy, data_dir)
                    .map_err(|e| format!("VPN: {e}"))?
                    .ok_or(
                        "VPN: wireproxy was not found; install it in Settings > Network \
                         routes or set its path there",
                    )?;
                let label = format!("VPN (WireGuard via wireproxy, {host}:{port})");
                spec(
                    Egress::Socks(SocksProxy {
                        host,
                        port,
                        credentials: None,
                    }),
                    check_probe(&self.vpn.probe)?,
                    label,
                    Some(WireproxyLaunch {
                        binary,
                        config: config.to_path_buf(),
                    }),
                )
            }
            RouteKind::Socks5 => {
                if self.socks5.host.is_empty() {
                    return Err("SOCKS5: set the proxy host in Settings".into());
                }
                let socks5 = &self.socks5;
                let credentials = (!socks5.username.is_empty()).then(|| Credentials {
                    username: socks5.username.clone(),
                    password: socks5.password.clone(),
                });
                let label = format!("SOCKS5 proxy {}:{}", socks5.host, socks5.port);
                spec(
                    Egress::Socks(SocksProxy {
                        host: socks5.host.clone(),
                        port: socks5.port,
                        credentials,
                    }),
                    check_probe(&socks5.probe)?,
                    label,
                    None,
                )
            }
        })
    }
}

fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_DIR).join(CONFIG_FILE)
}

/// The saved settings; the defaults when none were saved. A file that
/// exists but cannot be read is an error, never silently the defaults.
pub fn load_config(data_dir: &Path) -> Result<RouteConfig, String> {
    let path = config_path(data_dir);
    match std::fs::metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(RouteConfig::default()),
        Err(error) => Err(format!("{}: {error}", path.display())),
        Ok(_) => crate::storage::read_json(&path),
    }
}

/// Saves the settings owner-only after checking them.
pub fn save_config(data_dir: &Path, config: &RouteConfig) -> Result<(), String> {
    config.validate()?;
    let path = config_path(data_dir);
    let dir = path.parent().ok_or("route settings folder")?;
    crate::storage::private_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    crate::storage::atomic_json(&path, config)
}

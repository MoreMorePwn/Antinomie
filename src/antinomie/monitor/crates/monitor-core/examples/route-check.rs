// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Real-VM check of the network routes: what a run reaches on each route of
//! a Routed VM, on a NAT VM and on a VM without a network card, and which
//! combinations are refused before anything starts.
//!
//!   route-check BUNDLE NEW_DATA_DIR ROUTE_PROBE [CASE...]
//!
//! ROUTE_PROBE is the static `tests/monitor/route-probe` program. It looks
//! up `example.com`, sends one plain HTTP GET of "/" to it (or to 1.1.1.1
//! when the name does not resolve) and asks 169.254.169.254, the metadata
//! address of the VM's cloud profile, for "/". Internet traffic is that one
//! benign request; the Tor, VPN and SOCKS5 routes go to local fakes this
//! program runs, which answer every request themselves and record what the
//! gateway asked them to connect to.
//!
//! Three VMs boot one after the other, BusyBox, 2 vCPUs, 2 GiB:
//!
//! * routed: Routed network with the Vultr cloud profile (so its gateway
//!   runs the metadata service). One run per route (Drop, Internet with a
//!   run network capture, InetSim, Tor, VPN, SOCKS5), the toolbar network
//!   capture, and the failure paths: a SOCKS5 proxy that is down, a VPN
//!   whose configuration file is missing, a Tor program that does not
//!   exist (each must fail before the run exists), and a program that does
//!   not exist (the run is listed as failed to start).
//! * nat: NAT network with the same profile: the Internet works, the
//!   metadata address is silent, and a route cannot be chosen.
//! * none: no network card: no route, no capture, nothing reaches out.
//!
//! CASE names limit the VMs (`routed`, `nat`, `none`). Every check prints a
//! PASS or FAIL line; `route-check.md` in the data folder holds the table.
//! The data folder must be new and disposable.
//!
//! Started as `route-check -c CONFIG` the program is the fake wireproxy of
//! the VPN route: a SOCKS5 server on the `BindAddress` of CONFIG.
use antinomie_monitor_core::route::{
    RouteConfig, RouteKind, RouteVia, Socks5Config, TorConfig, TorMode, VpnConfig,
};
use antinomie_monitor_core::stealth::{CLOUDS, StealthProfile};
use antinomie_monitor_core::*;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const PROBE: &str = "/tmp/route-probe";
const NAME: &str = "example.com";
const FALLBACK_IP: &str = "1.1.1.1";
const SOCKS_USER: &str = "routecheck";
const SOCKS_PASSWORD: &str = "route-check-password";

/// What a fake proxy was asked: `target:port`, and `|probe` when the
/// request on it came from the route probe in the guest.
type Seen = Arc<Mutex<Vec<String>>>;

/// Serves SOCKS5 on `listener` forever: every CONNECT succeeds, and an HTTP
/// request on it is answered by the fake itself with `X-Route-Fake: label`.
fn serve_socks(listener: TcpListener, label: &'static str, login: bool, seen: Seen) {
    for stream in listener.incoming().flatten() {
        let seen = seen.clone();
        thread::spawn(move || {
            let _ = socks_session(stream, label, login, &seen);
        });
    }
}

fn socks_session(
    mut stream: TcpStream,
    label: &str,
    login: bool,
    seen: &Seen,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    let mut head = [0u8; 2];
    stream.read_exact(&mut head)?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods)?;
    if login {
        if !methods.contains(&2) {
            return stream.write_all(&[5, 0xff]);
        }
        stream.write_all(&[5, 2])?;
        let mut version = [0u8; 2];
        stream.read_exact(&mut version)?;
        let mut user = vec![0u8; usize::from(version[1])];
        stream.read_exact(&mut user)?;
        let mut length = [0u8; 1];
        stream.read_exact(&mut length)?;
        let mut password = vec![0u8; usize::from(length[0])];
        stream.read_exact(&mut password)?;
        let good = user == SOCKS_USER.as_bytes() && password == SOCKS_PASSWORD.as_bytes();
        stream.write_all(&[1, u8::from(!good)])?;
        if !good {
            return Ok(());
        }
    } else {
        stream.write_all(&[5, 0])?;
    }
    let mut request = [0u8; 4];
    stream.read_exact(&mut request)?;
    let target = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip)?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length)?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return stream.write_all(&[5, 8, 0, 1, 0, 0, 0, 0, 0, 0]),
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port)?;
    let target = format!("{target}:{}", u16::from_be_bytes(port));
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    // The route check connects and closes; a guest request follows.
    let mut text = Vec::new();
    let mut buffer = [0u8; 2048];
    while !text.windows(4).any(|w| w == b"\r\n\r\n") && text.len() < 16 * 1024 {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(n) => text.extend_from_slice(&buffer[..n]),
        }
    }
    let from_probe = String::from_utf8_lossy(&text).contains("antinomie-route-probe");
    if let Ok(mut seen) = seen.lock() {
        seen.push(if from_probe {
            format!("{target}|probe")
        } else {
            target
        });
    }
    if text.is_empty() {
        return Ok(());
    }
    let body = "fake";
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\nX-Route-Fake: {label}\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    )
}

/// A fake SOCKS5 proxy on a free port of 127.0.0.1.
fn fake_proxy(label: &'static str, login: bool) -> Result<(u16, Seen), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let seen = Seen::default();
    let shared = seen.clone();
    thread::spawn(move || serve_socks(listener, label, login, shared));
    Ok((port, seen))
}

/// A free port of 127.0.0.1 nothing listens on (closed again at once).
fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|e| e.to_string())
}

/// The fake wireproxy: `-c CONFIG`, SOCKS5 on its `BindAddress`; every
/// CONNECT it gets is appended to the file named by `# route-check-log =`.
fn fake_wireproxy(config: &str) -> Result<(), String> {
    let text = fs::read_to_string(config).map_err(|e| e.to_string())?;
    let value = |key: &str| {
        text.lines()
            .find_map(|line| {
                let (name, value) = line.trim_start_matches('#').split_once('=')?;
                (name.trim().eq_ignore_ascii_case(key)).then(|| value.trim().to_owned())
            })
            .ok_or(format!("no {key} in {config}"))
    };
    let bind: SocketAddr = value("BindAddress")?
        .parse()
        .map_err(|e| format!("BindAddress: {e}"))?;
    let log = PathBuf::from(value("route-check-log")?);
    let listener = TcpListener::bind(bind).map_err(|e| e.to_string())?;
    let seen = Seen::default();
    let shared = seen.clone();
    thread::spawn(move || serve_socks(listener, "vpn", false, shared));
    let mut written = 0;
    loop {
        thread::sleep(Duration::from_millis(100));
        let lines: Vec<String> = seen.lock().map(|s| s.clone()).unwrap_or_default();
        if lines.len() > written {
            let mut file = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .map_err(|e| e.to_string())?;
            for line in &lines[written..] {
                writeln!(file, "{line}").map_err(|e| e.to_string())?;
            }
            written = lines.len();
        }
    }
}

struct Fakes {
    tor: (u16, Seen),
    socks: (u16, Seen),
    vpn_port: u16,
    vpn_config: PathBuf,
    vpn_log: PathBuf,
    /// This program, the VPN route's wireproxy.
    me: PathBuf,
}

impl Fakes {
    fn start(data: &Path) -> Result<Self, String> {
        let vpn_port = free_port()?;
        let dir = data.join("fakes");
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let vpn_log = dir.join("vpn-connects.txt");
        let vpn_config = dir.join("wireproxy.conf");
        fs::write(
            &vpn_config,
            format!(
                "# A fake for route-check, not a WireGuard peer.\n\
                 # route-check-log = {}\n[Interface]\nAddress = 10.200.0.2/32\n\n\
                 [Socks5]\nBindAddress = 127.0.0.1:{vpn_port}\n",
                vpn_log.display()
            ),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            tor: fake_proxy("tor", false)?,
            socks: fake_proxy("socks5", true)?,
            vpn_port,
            vpn_config,
            vpn_log,
            me: std::env::current_exe().map_err(|e| e.to_string())?,
        })
    }

    /// Settings > Network routes with every route on the fakes.
    fn config(&self) -> RouteConfig {
        RouteConfig {
            default_route: RouteKind::Drop,
            tor: TorConfig {
                mode: TorMode::Socks,
                program: String::new(),
                socks: format!("127.0.0.1:{}", self.tor.0),
                probe: "check.torproject.org:443".into(),
            },
            vpn: VpnConfig {
                wireproxy: self.me.display().to_string(),
                config: self.vpn_config.display().to_string(),
                probe: format!("{NAME}:80"),
            },
            socks5: Socks5Config {
                host: "127.0.0.1".into(),
                port: self.socks.0,
                username: SOCKS_USER.into(),
                password: SOCKS_PASSWORD.into(),
                probe: format!("{NAME}:80"),
            },
            ..RouteConfig::default()
        }
    }

    fn vpn_seen(&self) -> Vec<String> {
        fs::read_to_string(&self.vpn_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn seen(list: &Seen) -> Vec<String> {
    list.lock().map(|s| s.clone()).unwrap_or_default()
}

struct Driver {
    backend: Backend,
    options: BackendOptions,
    snapshot: Snapshot,
    replies: BTreeMap<u64, Result<String, String>>,
    output: BTreeMap<String, String>,
    /// The route probe on the host, uploaded into each VM.
    probe: PathBuf,
}

/// The probe's `ROUTE key value` lines.
fn facts(text: &str) -> BTreeMap<String, String> {
    let mut facts = BTreeMap::new();
    for line in text.lines() {
        if let Some((key, value)) = line
            .trim_end_matches('\r')
            .strip_prefix("ROUTE ")
            .and_then(|rest| rest.split_once(' '))
        {
            facts
                .entry(key.to_owned())
                .or_insert_with(|| value.to_owned());
        }
    }
    facts
}

impl Driver {
    fn new(bundle: &str, data: &Path) -> Result<Self, String> {
        let options = BackendOptions {
            bundle_dir: PathBuf::from(bundle),
            data_dir: data.to_path_buf(),
            headless: true,
            serial_console: true,
            capture_quota_size: 1024 * 1024 * 1024,
            ..Default::default()
        };
        Ok(Self {
            backend: Backend::new(options.clone())?,
            options,
            snapshot: Snapshot::default(),
            replies: BTreeMap::new(),
            output: BTreeMap::new(),
            probe: PathBuf::new(),
        })
    }

    fn receive(&mut self) {
        while let Some(message) = self.backend.try_recv() {
            match message {
                Notification::Snapshot(snapshot) => self.snapshot = snapshot,
                Notification::CommandResult {
                    id,
                    success,
                    message,
                } => {
                    self.replies
                        .insert(id, if success { Ok(message) } else { Err(message) });
                }
                Notification::Terminal { run_id, data, .. } => {
                    self.output
                        .entry(run_id)
                        .or_default()
                        .push_str(&String::from_utf8_lossy(&data));
                }
                _ => {}
            }
        }
    }

    fn command_for(&mut self, command: Command, seconds: u64) -> Result<String, String> {
        let id = self.backend.send(command)?;
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if let Some(reply) = self.replies.remove(&id) {
                return reply;
            }
            if Instant::now() >= deadline {
                return Err(format!("command {id} timed out"));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(
        &mut self,
        label: &str,
        seconds: u64,
        ready: impl Fn(&Snapshot) -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            self.receive();
            if ready(&self.snapshot) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("{label} timed out: {:?}", self.snapshot.last_error));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// One VM with `vm`'s network, booted to the guest's ready line.
    fn create_and_boot(&mut self, vm: VmConfig) -> Result<String, String> {
        let known: Vec<String> = self.snapshot.vms.iter().map(|v| v.id.clone()).collect();
        self.command_for(Command::Create(vm), 600)?;
        self.wait("VM publication", 10, |s| {
            s.vms.iter().any(|v| !known.contains(&v.id))
        })?;
        let vm_id = self
            .snapshot
            .vms
            .iter()
            .find(|v| !known.contains(&v.id))
            .ok_or("new VM missing")?
            .id
            .clone();
        self.command_for(
            Command::Start {
                vm_id: vm_id.clone(),
            },
            900,
        )?;
        self.wait("guest", 240, |s| {
            s.guest_kernel.as_ref().and_then(|k| k.revision).is_some()
                && s.serial_log
                    .as_ref()
                    .and_then(|p| fs::read(p).ok())
                    .is_some_and(|log| log.windows(19).any(|w| w == b"BusyBox guest ready"))
        })?;
        thread::sleep(Duration::from_secs(3));
        self.command_for(
            Command::Upload {
                source: PathBuf::from(&self.probe),
                destination: PROBE.into(),
                overwrite: true,
                executable: true,
            },
            120,
        )?;
        Ok(vm_id)
    }

    fn stop(&mut self) -> Result<(), String> {
        self.command_for(Command::Stop, 120)?;
        self.wait("VM stop", 90, |s| s.state == VmState::Stopped)?;
        thread::sleep(Duration::from_secs(2));
        Ok(())
    }

    /// The runs Run History lists for `vm_id`.
    fn history(&self, vm_id: &str) -> Vec<RunSummary> {
        recording::list_vm_runs(&self.options, vm_id).unwrap_or_default()
    }

    /// Runs the probe with `route` and `capture_network` to its end, or
    /// returns the launch's error.
    fn probe(&mut self, route: Option<RouteKind>, capture: bool) -> Result<Probed, String> {
        self.launch(PROBE, route, capture)
    }

    fn launch(
        &mut self,
        path: &str,
        route: Option<RouteKind>,
        capture: bool,
    ) -> Result<Probed, String> {
        let known: Vec<String> = self.snapshot.runs.iter().map(|r| r.id.clone()).collect();
        let args = if path == PROBE {
            vec![NAME.into(), "80".into(), FALLBACK_IP.into()]
        } else {
            Vec::new()
        };
        let request = ExecRequest {
            path: path.into(),
            args,
            uid: 0,
            gid: 0,
            route,
            capture_network: capture,
            ..Default::default()
        };
        // The upload's answer can come before the guest closed the file;
        // a launch refused as busy (nothing started) is tried again.
        let mut tries = 0;
        loop {
            match self.command_for(Command::Execute(request.clone()), 180) {
                Err(error) if error.contains("Text file busy") && tries < 5 => {
                    tries += 1;
                    println!(
                        "NOTE launch {path}: the program is still open for writing; again in 1 s"
                    );
                    thread::sleep(Duration::from_secs(1));
                }
                other => {
                    other?;
                    break;
                }
            }
        }
        self.wait("run publication", 15, |s| {
            s.runs.iter().any(|r| !known.contains(&r.id))
        })?;
        let id = self
            .snapshot
            .runs
            .iter()
            .find(|r| !known.contains(&r.id))
            .ok_or("new run missing")?
            .id
            .clone();
        let wanted = id.clone();
        self.wait("run end", 120, move |s| {
            s.runs.iter().any(|r| {
                r.id == wanted && matches!(r.state, RunState::Finished | RunState::Stopped)
            })
        })?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !self
            .output
            .get(&id)
            .is_some_and(|o| o.contains("ROUTE-END"))
            && Instant::now() < deadline
        {
            self.receive();
            thread::sleep(Duration::from_millis(20));
        }
        // The route's counts are saved when the tree's artifacts settle.
        let wanted = id.clone();
        let _ = self.wait("route counts", 20, move |s| {
            s.runs.iter().any(|r| {
                r.id == wanted
                    && r.route
                        .as_ref()
                        .is_none_or(|route| route.via != RouteVia::Gateway || route.stats.is_some())
            })
        });
        let run = self
            .snapshot
            .runs
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or("run vanished")?;
        let text = self.output.get(&id).cloned().unwrap_or_default();
        // The probe's own lines, kept beside the table as evidence.
        let outputs = self.options.data_dir.join("outputs");
        let _ = fs::create_dir_all(&outputs)
            .and_then(|()| fs::write(outputs.join(format!("{id}.txt")), &text));
        Ok(Probed {
            facts: facts(&text),
            run,
        })
    }
}

struct Probed {
    facts: BTreeMap<String, String>,
    run: RunSummary,
}

impl Probed {
    fn fact(&self, key: &str) -> String {
        self.facts
            .get(key)
            .cloned()
            .unwrap_or_else(|| "(missing)".into())
    }

    fn answered(&self, key: &str) -> bool {
        self.fact(key).starts_with("HTTP/")
    }

    fn connections(&self) -> u64 {
        self.run
            .route
            .as_ref()
            .and_then(|route| route.stats)
            .map_or(0, |stats| stats.tcp_connections)
    }

    /// The run's network capture files and their sizes.
    fn captures(&self) -> Vec<(PathBuf, u64)> {
        let text =
            fs::read_to_string(self.run.directory.join("artifacts.json")).unwrap_or_default();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
        value["network_captures"]
            .as_array()
            .map(|files| {
                files
                    .iter()
                    .filter_map(|file| file.as_str().map(PathBuf::from))
                    .map(|file| {
                        let size = fs::metadata(&file).map_or(0, |m| m.len());
                        (file, size)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Default)]
struct Table {
    rows: Vec<(String, String, bool, String)>,
}

impl Table {
    fn check(&mut self, vm: &str, name: &str, ok: bool, got: impl Into<String>) {
        let got = got.into();
        println!("{} {vm} {name}: {got}", if ok { "PASS" } else { "FAIL" });
        self.rows.push((vm.into(), name.into(), ok, got));
    }

    fn failures(&self) -> Vec<String> {
        self.rows
            .iter()
            .filter(|row| !row.2)
            .map(|row| format!("{} {}", row.0, row.1))
            .collect()
    }

    fn markdown(&self) -> String {
        let mut text = String::from("| VM | Check | Result | Observed |\n|---|---|---|---|\n");
        for (vm, name, ok, got) in &self.rows {
            text.push_str(&format!(
                "| {vm} | {name} | {} | {} |\n",
                if *ok { "PASS" } else { "FAIL" },
                got.replace('|', "/")
            ));
        }
        text
    }
}

fn error_text(result: &Result<Probed, String>) -> String {
    match result {
        Ok(probed) => format!("started (run {})", probed.run.id),
        Err(error) => error.clone(),
    }
}

/// The cloud profile whose gateway answers 169.254.169.254.
fn cloud_profile() -> Result<StealthProfile, String> {
    CLOUDS
        .iter()
        .find(|provider| provider.id == "cloud-vultr-vc2")
        .map(StealthProfile::cloud_vps)
        .ok_or_else(|| "no Vultr profile".into())
}

fn vm_config(name: &str, network: VmNetwork, stealth: StealthProfile) -> VmConfig {
    VmConfig {
        name: name.into(),
        cpus: 2,
        ram_mib: 2048,
        disk_gib: 8,
        nat: network == VmNetwork::Nat,
        isolated_network: network == VmNetwork::Isolated,
        routed: network == VmNetwork::Routed,
        stealth,
        ..Default::default()
    }
}

fn save_routes(data: &Path, config: &RouteConfig) -> Result<(), String> {
    antinomie_monitor_core::route::save_config(data, config)
}

/// Every route of a Routed VM, the toolbar capture and the refused cases.
fn routed(d: &mut Driver, t: &mut Table, fakes: &Fakes, data: &Path) -> Result<(), String> {
    save_routes(data, &fakes.config())?;
    let vm_id = d.create_and_boot(vm_config(
        "route check routed",
        VmNetwork::Routed,
        cloud_profile()?,
    ))?;
    let vm = "routed";

    let drop = d.probe(Some(RouteKind::Drop), false);
    t.check(vm, "drop: run starts", drop.is_ok(), error_text(&drop));
    if let Ok(p) = &drop {
        t.check(
            vm,
            "drop: DNS unanswered",
            p.fact(&format!("dns.{NAME}")) == "(no answer)",
            p.fact(&format!("dns.{NAME}")),
        );
        t.check(
            vm,
            "drop: no connection leaves",
            !p.answered("http.status") && p.connections() == 0,
            format!("{} / {} upstream", p.fact("http.status"), p.connections()),
        );
        t.check(
            vm,
            "drop: metadata answered",
            p.answered("meta.status"),
            p.fact("meta.status"),
        );
    }

    // The reported case: Internet with the run's network capture.
    let internet = d.probe(Some(RouteKind::Internet), true);
    t.check(
        vm,
        "internet+capture: run starts",
        internet.is_ok(),
        error_text(&internet),
    );
    if let Ok(p) = &internet {
        t.check(
            vm,
            "internet: DNS from the host",
            !p.fact(&format!("dns.{NAME}")).starts_with('('),
            p.fact(&format!("dns.{NAME}")),
        );
        t.check(
            vm,
            "internet: HTTP answered by the real site",
            p.answered("http.status") && !p.facts.contains_key("http.via"),
            p.fact("http.status"),
        );
        t.check(
            vm,
            "internet: gateway carried it",
            p.connections() >= 1,
            format!("{} upstream", p.connections()),
        );
        t.check(
            vm,
            "internet: metadata answered",
            p.answered("meta.status"),
            p.fact("meta.status"),
        );
        let captures = p.captures();
        t.check(
            vm,
            "internet: run capture written",
            captures.iter().any(|(_, size)| *size > 24),
            format!("{captures:?}"),
        );
        t.check(
            vm,
            "internet: route recorded",
            p.run
                .route
                .as_ref()
                .is_some_and(|r| r.kind == RouteKind::Internet && r.via == RouteVia::Gateway),
            format!("{:?}", p.run.route.as_ref().map(|r| &r.label)),
        );
    }
    let plain = d.probe(Some(RouteKind::Internet), false);
    t.check(
        vm,
        "internet without capture: answered",
        plain.as_ref().is_ok_and(|p| p.answered("http.status")),
        plain
            .as_ref()
            .map_or_else(|e| e.clone(), |p| p.fact("http.status")),
    );

    let inetsim = d.probe(Some(RouteKind::InetSim), false);
    t.check(
        vm,
        "inetsim: run starts",
        inetsim.is_ok(),
        error_text(&inetsim),
    );
    if let Ok(p) = &inetsim {
        t.check(
            vm,
            "inetsim: DNS sinkhole",
            p.fact(&format!("dns.{NAME}")) == "198.51.100.1",
            p.fact(&format!("dns.{NAME}")),
        );
        t.check(
            vm,
            "inetsim: fake service answers",
            p.answered("http.status") && !p.facts.contains_key("http.via"),
            p.fact("http.status"),
        );
    }

    for (kind, label) in [
        (RouteKind::Tor, "tor"),
        (RouteKind::Vpn, "vpn"),
        (RouteKind::Socks5, "socks5"),
    ] {
        let before = match kind {
            RouteKind::Tor => seen(&fakes.tor.1).len(),
            RouteKind::Socks5 => seen(&fakes.socks.1).len(),
            _ => fakes.vpn_seen().len(),
        };
        let result = d.probe(Some(kind), false);
        t.check(
            vm,
            &format!("{label}: run starts"),
            result.is_ok(),
            error_text(&result),
        );
        let Ok(p) = &result else { continue };
        t.check(
            vm,
            &format!("{label}: answered through the proxy"),
            p.fact("http.via") == label,
            format!("{} via {}", p.fact("http.status"), p.fact("http.via")),
        );
        let after = match kind {
            RouteKind::Tor => seen(&fakes.tor.1),
            RouteKind::Socks5 => seen(&fakes.socks.1),
            _ => fakes.vpn_seen(),
        };
        let fresh: Vec<_> = after.iter().skip(before).cloned().collect();
        t.check(
            vm,
            &format!("{label}: proxy got the name, not an address"),
            fresh.iter().any(|s| s == &format!("{NAME}:80|probe")),
            format!("{fresh:?}"),
        );
    }
    // The VPN route's wireproxy stops with the run.
    thread::sleep(Duration::from_secs(1));
    t.check(
        vm,
        "vpn: wireproxy stopped after the run",
        TcpStream::connect_timeout(
            &SocketAddr::from(([127, 0, 0, 1], fakes.vpn_port)),
            Duration::from_millis(500),
        )
        .is_err(),
        format!("127.0.0.1:{}", fakes.vpn_port),
    );

    // The toolbar capture of a Routed VM.
    let started = d.command_for(Command::StartNetworkCapture, 60);
    t.check(
        vm,
        "toolbar capture starts",
        started.is_ok(),
        format!("{started:?}"),
    );
    if started.is_ok() {
        let stopped = d.command_for(Command::StopNetworkCapture, 60);
        t.check(
            vm,
            "toolbar capture stops",
            stopped.is_ok(),
            format!("{stopped:?}"),
        );
    }

    // Refused before the run exists: nothing is listed for them.
    let refused = |d: &mut Driver,
                   t: &mut Table,
                   name: &str,
                   config: RouteConfig,
                   kind: RouteKind,
                   wanted: &str|
     -> Result<(), String> {
        save_routes(data, &config)?;
        let listed = d.history(&vm_id).len();
        let result = d.probe(Some(kind), true);
        let text = error_text(&result);
        t.check(
            vm,
            &format!("{name}: refused before launch"),
            result.is_err() && text.contains(wanted),
            text,
        );
        t.check(
            vm,
            &format!("{name}: no run left in history"),
            d.history(&vm_id).len() == listed,
            format!("{} runs listed", d.history(&vm_id).len()),
        );
        Ok(())
    };
    let mut down = fakes.config();
    down.socks5.port = free_port()?;
    refused(d, t, "socks5 down", down, RouteKind::Socks5, "SOCKS5 proxy")?;
    let mut missing = fakes.config();
    missing.vpn.config = data.join("fakes/missing.conf").display().to_string();
    refused(d, t, "vpn config missing", missing, RouteKind::Vpn, "VPN")?;
    let mut no_tor = fakes.config();
    no_tor.tor.mode = TorMode::Own;
    no_tor.tor.program = data.join("fakes/no-such-tor").display().to_string();
    refused(d, t, "tor program missing", no_tor, RouteKind::Tor, "Tor")?;
    save_routes(data, &fakes.config())?;
    // The gateway is back on Drop after the refusals and still works.
    let after = d.probe(Some(RouteKind::InetSim), false);
    t.check(
        vm,
        "a route works after the refusals",
        after.as_ref().is_ok_and(|p| p.answered("http.status")),
        error_text(&after),
    );

    // A program that does not exist: the guest rejects the launch. With a
    // network capture the run is kept, as one that failed to start.
    let listed = d.history(&vm_id).len();
    let missing = d.launch("/tmp/route-check-missing", Some(RouteKind::Drop), true);
    t.check(
        vm,
        "missing program: launch fails",
        missing.is_err(),
        error_text(&missing),
    );
    let runs = d.history(&vm_id);
    let failed: Vec<_> = runs
        .iter()
        .filter(|r| r.request.path == "/tmp/route-check-missing")
        .collect();
    t.check(
        vm,
        "missing program: listed as failed to start, not unknown",
        runs.len() <= listed + 1
            && failed
                .iter()
                .all(|r| format!("{:?}", r.state) == "FailedToStart"),
        format!(
            "{:?}",
            failed
                .iter()
                .map(|r| (&r.state, r.recording_error.as_deref()))
                .collect::<Vec<_>>()
        ),
    );
    let unknown: Vec<_> = runs
        .iter()
        .filter(|r| r.state == RunState::Unknown)
        .map(|r| r.request.path.clone())
        .collect();
    t.check(
        vm,
        "no run is left unknown",
        unknown.is_empty(),
        format!("{unknown:?}"),
    );
    d.stop()?;
    let stopped = d.history(&vm_id);
    let unknown = stopped
        .iter()
        .filter(|r| r.state == RunState::Unknown)
        .count();
    t.check(
        vm,
        "after the VM stopped, no run reads unknown",
        unknown == 0,
        format!("{unknown} unknown of {}", stopped.len()),
    );
    let disk = d
        .options
        .data_dir
        .join("vms")
        .join(&vm_id)
        .join("disk.qcow2");
    fs::remove_file(disk).ok();
    Ok(())
}

/// A NAT VM: the Internet works, no metadata service, no route to choose.
fn nat(d: &mut Driver, t: &mut Table, data: &Path, fakes: &Fakes) -> Result<(), String> {
    save_routes(data, &fakes.config())?;
    let vm_id = d.create_and_boot(vm_config(
        "route check nat",
        VmNetwork::Nat,
        cloud_profile()?,
    ))?;
    let vm = "nat";
    let run = d.probe(None, true);
    t.check(
        vm,
        "internet+capture: run starts",
        run.is_ok(),
        error_text(&run),
    );
    if let Ok(p) = &run {
        t.check(
            vm,
            "internet: HTTP answered",
            p.answered("http.status"),
            p.fact("http.status"),
        );
        t.check(
            vm,
            "metadata address silent",
            !p.answered("meta.status"),
            p.fact("meta.status"),
        );
        t.check(
            vm,
            "route recorded as the VM's NAT",
            p.run
                .route
                .as_ref()
                .is_some_and(|r| r.via == RouteVia::VmNat),
            format!("{:?}", p.run.route.as_ref().map(|r| &r.label)),
        );
        let captures = p.captures();
        t.check(
            vm,
            "run capture written",
            captures.iter().any(|(_, size)| *size > 24),
            format!("{captures:?}"),
        );
    }
    let listed = d.history(&vm_id).len();
    let tor = d.probe(Some(RouteKind::Tor), false);
    let text = error_text(&tor);
    t.check(
        vm,
        "tor refused: the network is fixed",
        tor.is_err() && text.contains("Routed"),
        text,
    );
    t.check(
        vm,
        "tor refused: no run left",
        d.history(&vm_id).len() == listed,
        format!("{}", d.history(&vm_id).len()),
    );
    d.stop()?;
    fs::remove_file(
        d.options
            .data_dir
            .join("vms")
            .join(&vm_id)
            .join("disk.qcow2"),
    )
    .ok();
    Ok(())
}

/// No network card: no route, no capture, nothing reaches out.
fn none(d: &mut Driver, t: &mut Table) -> Result<(), String> {
    let vm_id = d.create_and_boot(vm_config(
        "route check none",
        VmNetwork::Disconnected,
        StealthProfile::default(),
    ))?;
    let vm = "none";
    let listed = d.history(&vm_id).len();
    let capture = d.probe(None, true);
    let text = error_text(&capture);
    t.check(
        vm,
        "capture refused: no network card",
        capture.is_err() && text.contains("network"),
        text,
    );
    let internet = d.probe(Some(RouteKind::Internet), false);
    let text = error_text(&internet);
    t.check(
        vm,
        "internet refused: the network is fixed",
        internet.is_err() && text.contains("Routed"),
        text,
    );
    t.check(
        vm,
        "refusals leave no run",
        d.history(&vm_id).len() == listed,
        format!("{}", d.history(&vm_id).len()),
    );
    let plain = d.probe(None, false);
    t.check(
        vm,
        "plain run: nothing reaches out",
        plain
            .as_ref()
            .is_ok_and(|p| !p.answered("http.status") && !p.answered("meta.status")),
        plain
            .as_ref()
            .map_or_else(|e| e.clone(), |p| p.fact("http.status")),
    );
    d.stop()?;
    fs::remove_file(
        d.options
            .data_dir
            .join("vms")
            .join(&vm_id)
            .join("disk.qcow2"),
    )
    .ok();
    Ok(())
}

fn check(bundle: &str, data: &str, probe: &str, only: &[&str]) -> Result<(), String> {
    let data = PathBuf::from(data);
    if data.exists() {
        return Err("the check needs a new disposable data folder".into());
    }
    fs::create_dir_all(&data).map_err(|e| e.to_string())?;
    let fakes = Fakes::start(&data)?;
    let mut d = Driver::new(bundle, &data)?;
    d.probe = PathBuf::from(probe);
    let mut table = Table::default();
    let wanted = |name: &str| only.is_empty() || only.contains(&name);
    let mut errors = Vec::new();
    if wanted("routed")
        && let Err(error) = routed(&mut d, &mut table, &fakes, &data)
    {
        errors.push(format!("routed: {error}"));
        let _ = d.stop();
    }
    if wanted("nat")
        && let Err(error) = nat(&mut d, &mut table, &data, &fakes)
    {
        errors.push(format!("nat: {error}"));
        let _ = d.stop();
    }
    if wanted("none")
        && let Err(error) = none(&mut d, &mut table)
    {
        errors.push(format!("none: {error}"));
        let _ = d.stop();
    }
    let _ = d.command_for(Command::Close, 30);
    fs::write(data.join("route-check.md"), table.markdown()).map_err(|e| e.to_string())?;
    let mut failures = table.failures();
    failures.extend(errors);
    if failures.is_empty() {
        println!("ROUTE-CHECK PASS {} checks", table.rows.len());
        Ok(())
    } else {
        Err(format!("failed: {}", failures.join(", ")))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let outcome = match args.as_slice() {
        ["-c", config] => fake_wireproxy(config),
        [bundle, data, probe, only @ ..] => check(bundle, data, probe, only),
        _ => {
            eprintln!("usage: route-check BUNDLE NEW_DATA_DIR ROUTE_PROBE [routed|nat|none...]");
            std::process::exit(2);
        }
    };
    if let Err(error) = outcome {
        eprintln!("FAIL {error}");
        std::process::exit(1);
    }
}

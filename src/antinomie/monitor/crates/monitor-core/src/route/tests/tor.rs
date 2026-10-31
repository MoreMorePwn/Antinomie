// SPDX-License-Identifier: GPL-3.0-only
//! The Tor route's own tor, with stand-in programs: nothing here starts a
//! real tor or reaches the Tor network.
use super::{WAIT, no_data, scratch};
use crate::route::{
    Gateway, GatewayNet, RouteConfig, RouteKind, TorMode, config::TorLaunch,
    tor::bootstrap_progress, tor::start_tor,
};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};

fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A stand-in for tor: reads the torrc it is given with `-f`, logs the
/// bootstrap the way tor does (to the `Log notice file`), records how it was
/// started in `seen.txt` next to the torrc, then answers SOCKS5 like an echo
/// proxy on the SocksPort.
const FAKE_TOR: &str = r#"#!/usr/bin/env python3
import os, re, socket, sys, threading
args = sys.argv[1:]
torrc = args[args.index("-f") + 1]
text = open(torrc).read()
port = int(re.search(r"SocksPort 127\.0\.0\.1:(\d+)", text).group(1))
log = re.search(r'Log notice file "([^"]+)"', text).group(1)
with open(os.path.join(os.path.dirname(torrc), "seen.txt"), "w") as seen:
    seen.write(os.environ.get("LD_LIBRARY_PATH", "") + "\n" + " ".join(args) + "\n")
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
LAST = 100
with open(log, "a") as out:
    for percent, tag in [(5, "conn"), (40, "loading_status"), (100, "done")]:
        if percent > LAST:
            break
        out.write("Oct 24 12:00:00.000 [notice] Bootstrapped %d%% (%s): step\n" % (percent, tag))
        out.flush()
def serve(c):
    try:
        c.recv(3); c.sendall(b"\x05\x00")
        head = c.recv(4)
        if head[3] == 1: c.recv(6)
        else:
            n = c.recv(1)[0]; c.recv(n + 2)
        c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except Exception:
        pass
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"#;

fn launch(dir: &Path, binary: std::path::PathBuf) -> TorLaunch {
    TorLaunch {
        binary,
        lib_dir: None,
        geoip_dir: None,
        state_root: dir.join("network").join("tor"),
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn tor_progress_is_read_from_its_log() {
    assert_eq!(bootstrap_progress(""), None);
    assert_eq!(bootstrap_progress("Oct 24 [notice] Tor starting\n"), None);
    let log = "[notice] Bootstrapped 5% (conn): Connecting\n[notice] Bootstrapped 45% (loading_descriptors): Loading relay descriptors\n";
    assert_eq!(
        bootstrap_progress(log),
        Some((
            45,
            "(loading_descriptors): Loading relay descriptors".into()
        ))
    );
    assert_eq!(
        bootstrap_progress("[notice] Bootstrapped 100% (done): Done\n")
            .unwrap()
            .0,
        100
    );
}

#[test]
fn tor_is_started_privately_on_a_free_local_port_waited_for_and_stopped() {
    let dir = scratch("tor-own");
    let tor = launch(&dir, script(&dir, "tor", FAKE_TOR));
    let (managed, port) = start_tor(&tor, "vm1", Duration::from_secs(20)).unwrap();
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    let pid = managed.pid();
    assert!(Path::new(&format!("/proc/{pid}")).exists());

    let state = tor.state_root.join("vm1");
    // Private folders and files, owner only.
    for private in [&tor.state_root, &state, &state.join("data")] {
        assert_eq!(mode(private), 0o700, "{}", private.display());
    }
    for file in ["torrc", "tor.log", "tor.out"] {
        assert_eq!(mode(&state.join(file)), 0o600, "{file}");
    }
    // The configuration offers one SOCKS listener on 127.0.0.1 and nothing else.
    let torrc = std::fs::read_to_string(state.join("torrc")).unwrap();
    assert!(
        torrc.contains(&format!("SocksPort 127.0.0.1:{port}\n")),
        "{torrc}"
    );
    assert!(torrc.contains("ControlPort 0\n"), "{torrc}");
    assert!(torrc.contains(&format!(
        "DataDirectory \"{}\"",
        state.join("data").display()
    )));
    for line in torrc.lines() {
        let key = line.split(' ').next().unwrap();
        assert!(
            !matches!(
                key,
                "ControlSocket"
                    | "DNSPort"
                    | "TransPort"
                    | "HTTPTunnelPort"
                    | "ORPort"
                    | "ExtORPort"
                    | "HiddenServiceDir"
                    | "SocksPolicy"
            ),
            "{line}"
        );
    }
    assert!(torrc.contains("ClientOnly 1"));
    // The system's torrc-defaults is replaced by an empty file.
    let seen = std::fs::read_to_string(state.join("seen.txt")).unwrap();
    assert!(seen.contains("--defaults-torrc"), "{seen}");
    assert_eq!(
        std::fs::metadata(state.join("torrc-defaults"))
            .unwrap()
            .len(),
        0
    );
    drop(managed);
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "tor was left running"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_bundle_runs_with_its_own_libraries() {
    let dir = scratch("tor-libs");
    let libs = dir.join("bundle").join("tor");
    let mut tor = launch(&dir, script(&dir, "tor", FAKE_TOR));
    tor.lib_dir = Some(libs.clone());
    let (managed, _) = start_tor(&tor, "vm1", Duration::from_secs(20)).unwrap();
    let seen = std::fs::read_to_string(tor.state_root.join("vm1").join("seen.txt")).unwrap();
    assert_eq!(seen.lines().next(), Some(libs.to_str().unwrap()));
    drop(managed);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_tor_that_stops_or_never_bootstraps_is_an_error_not_a_route() {
    let dir = scratch("tor-bad");
    let quits = launch(
        &dir,
        script(
            &dir,
            "quits",
            "#!/bin/sh\necho 'Failed to bind' >&2\nexit 1\n",
        ),
    );
    let error = start_tor(&quits, "a", WAIT).err().unwrap();
    assert!(error.contains("stopped before it was ready"), "{error}");
    assert!(error.contains("Failed to bind"), "{error}");

    let stuck = launch(
        &dir,
        script(&dir, "stuck", &FAKE_TOR.replace("LAST = 100", "LAST = 40")),
    );
    let error = start_tor(&stuck, "b", Duration::from_millis(1500))
        .err()
        .unwrap();
    assert!(error.contains("did not finish bootstrapping"), "{error}");
    assert!(error.contains("stuck at 40%"), "{error}");

    let silent = launch(&dir, script(&dir, "silent", "#!/bin/sh\nexec sleep 30\n"));
    let error = start_tor(&silent, "c", Duration::from_millis(600))
        .err()
        .unwrap();
    assert!(error.contains("nothing was reported"), "{error}");
    // A torrc cannot hold a path with a quote.
    let mut odd = launch(&dir, script(&dir, "tor", FAKE_TOR));
    odd.state_root = dir.join("a\"b");
    assert!(start_tor(&odd, "d", WAIT).err().unwrap().contains("torrc"));
    let _ = std::fs::remove_dir_all(dir);
}

fn own_config(dir: &Path, program: &Path) -> RouteConfig {
    let mut config = RouteConfig::default();
    config.tor.mode = TorMode::Own;
    config.tor.program = program.display().to_string();
    config.tor.probe = "probe.example:443".into();
    let _ = dir;
    config
}

#[test]
fn the_tor_route_runs_its_own_tor_for_the_run_and_stops_it_afterwards() {
    let dir = scratch("tor-route");
    let program = script(&dir, "tor", FAKE_TOR);
    let config = own_config(&dir, &program);
    let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let gateway = Gateway::start(&dir, net).unwrap();
    gateway
        .claim("run1", config.spec(&dir, RouteKind::Tor).unwrap())
        .unwrap();
    assert_eq!(gateway.kind(), RouteKind::Tor);
    // tor's folder is under the data folder, named after the gateway's.
    let slot = dir.file_name().unwrap().to_str().unwrap().replace('.', "_");
    let torrc = std::fs::read_to_string(dir.join("network/tor").join(&slot).join("torrc")).unwrap();
    let port: u16 = torrc
        .lines()
        .find_map(|l| l.strip_prefix("SocksPort 127.0.0.1:"))
        .unwrap()
        .parse()
        .unwrap();
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    gateway.release("run1");
    assert_eq!(gateway.kind(), RouteKind::Drop);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(std::time::Instant::now() < deadline, "tor still listens");
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(gateway);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_tor_that_does_not_come_up_leaves_the_gateway_on_drop() {
    let dir = scratch("tor-down");
    let quits = script(&dir, "tor", "#!/bin/sh\nexit 1\n");
    let config = own_config(&dir, &quits);
    let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let gateway = Gateway::start(&dir, net).unwrap();
    let error = gateway
        .claim("run1", config.spec(&dir, RouteKind::Tor).unwrap())
        .unwrap_err();
    assert!(error.contains("Tor:"), "{error}");
    assert_eq!(gateway.kind(), RouteKind::Drop);

    // A tor that bootstraps but does not speak SOCKS fails the check, and is stopped.
    let deaf = script(
        &dir,
        "deaf",
        &FAKE_TOR.replace(
            "c.recv(3); c.sendall(b\"\\x05\\x00\")",
            "c.recv(3); c.close(); return",
        ),
    );
    let config = own_config(&dir, &deaf);
    let error = gateway
        .claim("run2", config.spec(&dir, RouteKind::Tor).unwrap())
        .unwrap_err();
    assert!(error.contains("is not up"), "{error}");
    assert_eq!(gateway.kind(), RouteKind::Drop);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_settings_test_brings_the_own_tor_up_and_stops_it() {
    let dir = scratch("tor-test");
    let program = script(&dir, "tor", FAKE_TOR);
    let config = own_config(&dir, &program);
    let said = crate::route::test_route(&dir, &config, RouteKind::Tor).unwrap();
    assert!(said.contains("started by Antinomie"), "{said}");
    let state = dir.join("network/tor/settings-test");
    // The check leaves tor's cache for the next start, but no process.
    assert!(state.join("torrc").exists());
    let _ = no_data;
    let _ = std::fs::remove_dir_all(dir);
}

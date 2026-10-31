// SPDX-License-Identifier: GPL-3.0-only
//! wireproxy as the VPN route starts it, with stand-in programs.
use super::{
    WAIT,
    guest::{Connect, Guest, Tcp},
    no_data, scratch,
};
use crate::route::{
    Gateway, GatewayNet, RouteConfig, RouteKind, config::WireproxyLaunch, managed::start_wireproxy,
};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A stand-in for wireproxy: `-c <config>`, then a SOCKS5 server on the
/// BindAddress of the configuration that answers like an echo proxy.
const FAKE_WIREPROXY: &str = r#"#!/usr/bin/env python3
import socket, sys, threading, re
text = open(sys.argv[2]).read()
port = int(re.search(r"BindAddress\s*=\s*127.0.0.1:(\d+)", text).group(1))
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
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

fn config_file(dir: &Path, port: u16) -> std::path::PathBuf {
    let path = dir.join("wireproxy.conf");
    std::fs::write(
        &path,
        format!("[Interface]\nPrivateKey = x\n[Socks5]\nBindAddress = 127.0.0.1:{port}\n"),
    )
    .unwrap();
    path
}

#[test]
fn wireproxy_is_started_waited_for_and_stopped_with_the_route() {
    let dir = scratch("wp");
    let port = free_port();
    let launch = WireproxyLaunch {
        binary: script(&dir, "wireproxy", FAKE_WIREPROXY),
        config: config_file(&dir, port),
    };
    let managed =
        start_wireproxy(&launch, ("127.0.0.1", port), &dir, Duration::from_secs(20)).unwrap();
    let pid = managed.pid();
    assert!(Path::new(&format!("/proc/{pid}")).exists());
    drop(managed);
    assert!(
        !Path::new(&format!("/proc/{pid}")).exists(),
        "wireproxy was left running"
    );
    let log = dir.join("wireproxy.log");
    assert!(log.exists());
    assert_eq!(
        std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_wireproxy_that_stops_at_once_or_never_listens_is_a_failed_route() {
    let dir = scratch("wp-bad");
    let port = free_port();
    let config = config_file(&dir, port);
    let quits = WireproxyLaunch {
        binary: script(&dir, "quits", "#!/bin/sh\nexit 3\n"),
        config: config.clone(),
    };
    let error = start_wireproxy(&quits, ("127.0.0.1", port), &dir, WAIT)
        .err()
        .unwrap();
    assert!(error.contains("stopped at once"), "{error}");
    let idle = WireproxyLaunch {
        binary: script(&dir, "idle", "#!/bin/sh\nexec sleep 30\n"),
        config,
    };
    let error = start_wireproxy(&idle, ("127.0.0.1", port), &dir, Duration::from_millis(600))
        .err()
        .unwrap();
    assert!(error.contains("did not open"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn something_already_listening_is_not_taken_for_the_tunnel() {
    let dir = scratch("wp-busy");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let launch = WireproxyLaunch {
        binary: script(&dir, "wireproxy", FAKE_WIREPROXY),
        config: config_file(&dir, port),
    };
    let error = start_wireproxy(&launch, ("127.0.0.1", port), &dir, WAIT)
        .err()
        .unwrap();
    assert!(error.contains("already listens"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_vpn_route_runs_wireproxy_for_the_run_and_stops_it_afterwards() {
    let dir = scratch("vpn-route");
    let port = free_port();
    let mut config = RouteConfig::default();
    config.vpn.wireproxy = script(&dir, "wireproxy", FAKE_WIREPROXY)
        .display()
        .to_string();
    config.vpn.config = config_file(&dir, port).display().to_string();
    config.vpn.probe = "probe.example:443".into();
    let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let gateway = Gateway::start(&dir, net).unwrap();
    gateway
        .claim("run1", config.spec(no_data(), RouteKind::Vpn).unwrap())
        .unwrap();
    assert_eq!(gateway.kind(), RouteKind::Vpn);
    // The tunnel's SOCKS port answers while the run holds the route.
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    gateway.release("run1");
    assert_eq!(gateway.kind(), RouteKind::Drop);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "wireproxy still listens"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(gateway);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_tunnel_that_does_not_answer_its_check_stops_the_run_and_wireproxy() {
    let dir = scratch("vpn-down");
    let port = free_port();
    let mut config = RouteConfig::default();
    // Listens, but is not a SOCKS server.
    config.vpn.wireproxy = script(
        &dir,
        "wireproxy",
        &FAKE_WIREPROXY.replace(
            "c.recv(3); c.sendall(b\"\\x05\\x00\")",
            "c.recv(3); c.close(); return",
        ),
    )
    .display()
    .to_string();
    config.vpn.config = config_file(&dir, port).display().to_string();
    let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let gateway = Gateway::start(&dir, net).unwrap();
    let error = gateway
        .claim("run1", config.spec(no_data(), RouteKind::Vpn).unwrap())
        .unwrap_err();
    assert!(error.contains("is not up"), "{error}");
    assert_eq!(gateway.kind(), RouteKind::Drop);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "wireproxy was left running"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_wireproxy_that_stops_during_a_run_is_reported_once_and_its_route_drops_everything() {
    let dir = scratch("vpn-dies");
    let port = free_port();
    // The stand-in exits with status 7 when the test creates `stop`.
    let stop = dir.join("stop");
    let watcher = format!(
        "import os, time\ndef watch():\n    while not os.path.exists({:?}): time.sleep(0.05)\n    os._exit(7)\nthreading.Thread(target=watch, daemon=True).start()\nwhile True:\n    c, _ = srv.accept()",
        stop.display().to_string()
    );
    let mut config = RouteConfig::default();
    config.vpn.wireproxy = script(
        &dir,
        "wireproxy",
        &FAKE_WIREPROXY.replace("while True:\n    c, _ = srv.accept()", &watcher),
    )
    .display()
    .to_string();
    config.vpn.config = config_file(&dir, port).display().to_string();
    config.vpn.probe = "probe.example:443".into();
    let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let gateway = Gateway::start(&dir, net).unwrap();
    let mut guest = Guest::connect(gateway.socket_path());
    gateway
        .claim("run1", config.spec(no_data(), RouteKind::Vpn).unwrap())
        .unwrap();
    assert_eq!(gateway.helper_stopped(), None, "wireproxy runs");
    let target = std::net::Ipv4Addr::new(192, 0, 2, 10);
    let (_tcp, state) = Tcp::open(&mut guest, target, 80, WAIT);
    assert_eq!(state, Connect::Open, "the tunnel carries the run's traffic");
    std::fs::write(&stop, b"").unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let reason = loop {
        if let Some(reason) = gateway.helper_stopped() {
            break reason;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the stopped wireproxy was not noticed"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(reason.contains("went down during the run"), "{reason}");
    assert!(reason.contains("wireproxy stopped"), "{reason}");
    assert!(reason.contains('7'), "the exit status is named: {reason}");
    assert_eq!(gateway.helper_stopped(), None, "said once");
    // The run still holds the route, which now lets nothing out, even if
    // something else listened on wireproxy's port.
    assert_eq!(gateway.kind(), RouteKind::Vpn);
    let _taken = std::net::TcpListener::bind(("127.0.0.1", port)).unwrap();
    let (_tcp, state) = Tcp::open(&mut guest, target, 80, Duration::from_millis(600));
    assert_eq!(
        state,
        Connect::Silent,
        "nothing leaves after the tunnel died"
    );
    // Another run cannot join a route that went down.
    let error = gateway
        .claim("run2", config.spec(no_data(), RouteKind::Vpn).unwrap())
        .unwrap_err();
    assert!(error.contains("went down during another run"), "{error}");
    // The last run out puts the gateway back on Drop; the next claim starts afresh.
    gateway.release("run1");
    assert_eq!(gateway.kind(), RouteKind::Drop);
    drop(gateway);
    let _ = std::fs::remove_dir_all(dir);
}

// SPDX-License-Identifier: GPL-3.0-only
//! The Tor route's own tor, with stand-in programs: nothing here starts a
//! real tor or reaches the Tor network.
use super::{no_data, scratch};
use crate::route::{
    Gateway, GatewayNet, RouteConfig, RouteKind, TorMode, config::TorLaunch,
    tor::bootstrap_progress, tor::lock_slot, tor::lock_slot_within, tor::start_tor, tor::torrc,
};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};

/// A bootstrap wait that survives a loaded machine (the fake tor is a python
/// start, niced with the test run); a stall is noticed after half of it.
const LONG: Duration = Duration::from_secs(60);

fn script(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).unwrap();
    crate::test_exec::make_executable(&path, 0o755);
    path
}

/// A stand-in for tor: reads the torrc it is given with `-f`, logs the
/// bootstrap the way tor does (to stdout, `Log notice stdout`), records how it was
/// started in `seen.txt` next to the torrc, then answers SOCKS5 like an echo
/// proxy on the SocksPort.
const FAKE_TOR: &str = r#"#!/usr/bin/env python3
import os, re, socket, sys, threading
args = sys.argv[1:]
torrc = args[args.index("-f") + 1]
text = open(torrc).read()
port = int(re.search(r"SocksPort 127\.0\.0\.1:(\d+)", text).group(1))
assert "Log notice stdout\n" in text, text
with open(os.path.join(os.path.dirname(torrc), "starts.txt"), "a") as starts:
    starts.write("start\n")
with open(os.path.join(os.path.dirname(torrc), "seen.txt"), "w") as seen:
    seen.write(os.environ.get("LD_LIBRARY_PATH", "") + "\n" + " ".join(args) + "\n")
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(8)
LAST = 100
if True:
    out = sys.stdout
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
        helpers_dir: dir.join("network").join("helpers"),
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
    let error = start_tor(&quits, "a", LONG).err().unwrap();
    assert!(error.contains("stopped before it was ready"), "{error}");
    assert!(error.contains("Failed to bind"), "{error}");

    let stuck = launch(
        &dir,
        script(&dir, "stuck", &FAKE_TOR.replace("LAST = 100", "LAST = 40")),
    );
    let error = start_tor(&stuck, "b", Duration::from_secs(6))
        .err()
        .unwrap();
    assert!(error.contains("did not finish bootstrapping"), "{error}");
    // A starved fake tor may not have printed anything yet when the stall is called.
    assert!(
        error.contains("stuck at 40%") || error.contains("nothing was reported"),
        "{error}"
    );

    let silent = launch(&dir, script(&dir, "silent", "#!/bin/sh\nexec sleep 30\n"));
    let error = start_tor(&silent, "c", Duration::from_millis(600))
        .err()
        .unwrap();
    assert!(error.contains("nothing was reported"), "{error}");
    // A torrc cannot hold a path with a quote.
    let mut odd = launch(&dir, script(&dir, "tor", FAKE_TOR));
    odd.state_root = dir.join("a\"b");
    assert!(start_tor(&odd, "d", LONG).err().unwrap().contains("torrc"));
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

/// Tor reads a value quoted as a whole, but takes the quotes inside a
/// multi-word value such as `Log notice file "<path>"` as part of the name.
#[test]
fn the_torrc_has_no_path_on_the_log_line_and_quotes_paths_as_a_whole() {
    let dir = scratch("tor-torrc");
    let geoip = dir.join("geo ip");
    std::fs::create_dir_all(&geoip).unwrap();
    for file in ["geoip", "geoip6"] {
        std::fs::write(geoip.join(file), b"").unwrap();
    }
    let mut tor = launch(&dir, std::path::PathBuf::from("tor"));
    tor.geoip_dir = Some(geoip.clone());
    let state = dir.join("my state");
    let text = torrc(&tor, &state, 9150).unwrap();
    let log: Vec<_> = text.lines().filter(|l| l.starts_with("Log ")).collect();
    assert_eq!(log, ["Log notice stdout"], "{text}");
    assert!(
        text.contains(&format!(
            "DataDirectory \"{}\"\n",
            state.join("data").display()
        )),
        "{text}"
    );
    assert!(text.contains(&format!(
        "GeoIPFile \"{}\"\n",
        geoip.join("geoip").display()
    )));
    for line in text.lines() {
        let (key, value) = line.split_once(' ').unwrap();
        // A quote only ever wraps the whole value, and only on path keys.
        assert_eq!(
            value.contains('"'),
            matches!(key, "DataDirectory" | "GeoIPFile" | "GeoIPv6File"),
            "{line}"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Stops the tor of a test even when an assertion fails.
struct KillOnDrop(std::process::Child);
impl std::ops::Deref for KillOnDrop {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for KillOnDrop {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn real_tor() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("ANTINOMIE_TEST_TOR") {
        return Some(path.into());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join("tor"))
            .find(|tor| tor.is_file())
    })
}

/// A real tor with the generated torrc (plus `DisableNetwork 1`, so it never
/// touches the Tor network) in a data folder with a space in its name starts, logs to
/// stdout (so the log is readable for the progress) and stays up. With
/// `DisableNetwork` tor opens no listener, so the SocksPort is not checked.
#[test]
fn a_real_tor_accepts_the_generated_torrc_and_stays_up() {
    let Some(binary) = real_tor() else {
        eprintln!("skipped: no tor in ANTINOMIE_TEST_TOR or PATH");
        return;
    };
    let dir = scratch("tor-real");
    let state = dir.join("state with space");
    for folder in [&state, &state.join("data")] {
        crate::storage::private_dir(folder).unwrap();
    }
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut tor = launch(&dir, binary.clone());
    tor.geoip_dir = None;
    let mut text = torrc(&tor, &state, port).unwrap();
    text.push_str("DisableNetwork 1\n");
    std::fs::write(state.join("torrc"), text).unwrap();
    std::fs::write(state.join("defaults"), b"").unwrap();
    let log = std::fs::File::create(state.join("tor.log")).unwrap();
    let mut command = std::process::Command::new(&binary);
    command
        .arg("--defaults-torrc")
        .arg(state.join("defaults"))
        .arg("-f")
        .arg(state.join("torrc"))
        .stdin(std::process::Stdio::null())
        .stdout(log)
        .stderr(std::process::Stdio::null());
    if let Some(libraries) = binary.parent() {
        command.env("LD_LIBRARY_PATH", libraries);
    }
    let mut child = KillOnDrop(command.spawn().unwrap());
    let started = std::time::Instant::now();
    let mut opened = false;
    while started.elapsed() < Duration::from_secs(3) || !opened {
        if let Some(status) = child.try_wait().unwrap() {
            let said = std::fs::read_to_string(state.join("tor.log")).unwrap_or_default();
            panic!("tor stopped ({status}): {said}");
        }
        let said = std::fs::read_to_string(state.join("tor.log")).unwrap_or_default();
        opened = bootstrap_progress(&said).is_some();
        assert!(started.elapsed() < Duration::from_secs(20), "{said}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let said = std::fs::read_to_string(state.join("tor.log")).unwrap();
    eprintln!("{said}");
    assert!(said.contains("DisableNetwork is set"), "{said}");
    assert!(child.try_wait().unwrap().is_none(), "tor exited");
    drop(child);
    let _ = std::fs::remove_dir_all(dir);
}

fn starts(state: &Path) -> usize {
    std::fs::read_to_string(state.join("starts.txt")).map_or(0, |text| text.lines().count())
}

#[test]
fn the_same_slot_is_reused_between_starts_with_its_cached_state() {
    let dir = scratch("tor-reuse");
    let tor = launch(&dir, script(&dir, "tor", FAKE_TOR));
    let state = tor.state_root.join("vm1");
    let (first, _) = start_tor(&tor, "vm1", LONG).unwrap();
    // What tor caches in its data folder.
    std::fs::write(state.join("data/cached-microdesc-consensus"), b"consensus").unwrap();
    drop(first);
    let (second, _) = start_tor(&tor, "vm1", LONG).unwrap();
    assert_eq!(starts(&state), 2);
    assert_eq!(
        std::fs::read(state.join("data/cached-microdesc-consensus")).unwrap(),
        b"consensus"
    );
    for private in [&state, &state.join("data")] {
        assert_eq!(mode(private), 0o700);
    }
    assert_eq!(mode(&state.join("lock")), 0o600);
    // Another slot is another folder.
    drop(second);
    let (_other, _) = start_tor(&tor, "vm2", LONG).unwrap();
    assert!(
        !tor.state_root
            .join("vm2/data/cached-microdesc-consensus")
            .exists()
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn one_tor_runs_per_data_folder() {
    let dir = scratch("tor-lock");
    let tor = launch(&dir, script(&dir, "tor", FAKE_TOR));
    let (first, _) = start_tor(&tor, "vm1", LONG).unwrap();
    let error = start_tor(&tor, "vm1", LONG).err().unwrap();
    assert!(error.contains("another tor is already using"), "{error}");
    // The refused start did not touch the running tor's folder.
    assert_eq!(starts(&tor.state_root.join("vm1")), 1);
    drop(first);
    assert!(start_tor(&tor, "vm1", LONG).is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

/// A tor that stalls at 40% on its first start in a folder and is fine after.
fn stalls_once() -> String {
    FAKE_TOR.replace(
        "LAST = 100",
        "marker = os.path.join(os.path.dirname(torrc), \"stalled-once\")\n\
         LAST = 100 if os.path.exists(marker) else 40\n\
         open(marker, \"w\").close()",
    )
}

#[test]
fn a_stalled_bootstrap_is_retried_once_and_keeps_the_cached_state() {
    let dir = scratch("tor-stall");
    let tor = launch(&dir, script(&dir, "tor", &stalls_once()));
    let state = tor.state_root.join("vm1");
    std::fs::create_dir_all(state.join("data")).unwrap();
    std::fs::write(state.join("data/cached-microdesc-consensus"), b"consensus").unwrap();
    let began = std::time::Instant::now();
    let (managed, port) = start_tor(&tor, "vm1", Duration::from_secs(40)).unwrap();
    // The stall was noticed after half the wait, not the whole of it.
    assert!(
        began.elapsed() < Duration::from_secs(40),
        "{:?}",
        began.elapsed()
    );
    assert_eq!(starts(&state), 2);
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert!(state.join("data/cached-microdesc-consensus").exists());
    drop(managed);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_tor_that_stalls_twice_is_an_error_after_one_retry() {
    let dir = scratch("tor-stall2");
    let tor = launch(
        &dir,
        script(&dir, "tor", &FAKE_TOR.replace("LAST = 100", "LAST = 40")),
    );
    let error = start_tor(&tor, "vm1", Duration::from_secs(6))
        .err()
        .unwrap();
    assert!(
        error.contains("did not finish bootstrapping within 6 s"),
        "{error}"
    );
    // A starved fake tor may not have printed anything yet when the stall is called.
    assert!(
        error.contains("stuck at 40%") || error.contains("nothing was reported"),
        "{error}"
    );
    assert!(error.contains("after a second start"), "{error}");
    assert_eq!(starts(&tor.state_root.join("vm1")), 2);
    // The folder stays for the next run; the lock is free again.
    assert!(lock_is_free(&tor.state_root.join("vm1")));
    let _ = std::fs::remove_dir_all(dir);
}

fn lock_is_free(state: &Path) -> bool {
    let file = std::fs::File::open(state.join("lock")).unwrap();
    file.try_lock().is_ok()
}

#[test]
fn a_tor_that_exits_on_its_cached_state_is_retried_on_a_fresh_data_folder() {
    let dir = scratch("tor-corrupt");
    let broken = FAKE_TOR.replace(
        "port = int(",
        "data = os.path.join(os.path.dirname(torrc), \"data\")\n\
         if os.path.exists(os.path.join(data, \"corrupt\")):\n\
         \x20   sys.stderr.write(\"Could not read the state file\\n\"); sys.exit(1)\n\
         port = int(",
    );
    let tor = launch(&dir, script(&dir, "tor", &broken));
    let state = tor.state_root.join("vm1");
    std::fs::create_dir_all(state.join("data")).unwrap();
    std::fs::write(state.join("data/corrupt"), b"x").unwrap();
    let (managed, port) = start_tor(&tor, "vm1", LONG).unwrap();
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());
    assert!(!state.join("data/corrupt").exists());
    assert_eq!(mode(&state.join("data")), 0o700);
    drop(managed);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn month_old_unused_slots_are_removed_and_the_rest_kept() {
    let dir = scratch("tor-prune");
    let tor = launch(&dir, script(&dir, "tor", FAKE_TOR));
    let age = |name: &str, days: u64| {
        let path = tor.state_root.join(name);
        std::fs::create_dir_all(path.join("data")).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(days * 24 * 3600);
        std::fs::File::open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        path
    };
    std::fs::create_dir_all(&tor.state_root).unwrap();
    let stale = age("ant-1234", 40);
    let recent = age("vm-recent", 3);
    let busy = age("vm-busy", 40);
    let held = lock_slot(&busy).unwrap();
    held.set_modified(std::time::SystemTime::now() - Duration::from_secs(40 * 24 * 3600))
        .unwrap();
    let (_managed, _) = start_tor(&tor, "vm1", LONG).unwrap();
    assert!(!stale.exists(), "a month-old slot stays");
    assert!(recent.exists() && busy.exists());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn a_gateway_with_a_tor_slot_keeps_one_folder_across_vm_starts() {
    let dir = scratch("tor-slot");
    let program = script(&dir, "tor", FAKE_TOR);
    let config = own_config(&dir, &program);
    let net = || GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let state = dir.join("network/tor/vm-7");
    // Two VM starts: each has a folder of its own for the gateway.
    for (index, name) in ["runtime-a", "runtime-b"].into_iter().enumerate() {
        let work = dir.join(name);
        crate::storage::private_dir(&work).unwrap();
        let gateway = Gateway::start(&work, net()).unwrap().with_tor_slot("vm-7");
        gateway
            .claim("run1", config.spec(&dir, RouteKind::Tor).unwrap())
            .unwrap();
        assert_eq!(starts(&state), index + 1);
        gateway.release("run1");
        drop(gateway);
    }
    assert!(!dir.join("network/tor/runtime_a").exists());
    assert!(!dir.join("network/tor/runtime-b").exists());
    let _ = std::fs::remove_dir_all(dir);
}

/// A copy of the lock's descriptor held by a process that another thread forked
/// and that has not exec'd yet keeps the flock after the owner drops it. The
/// race is made certain here: the child sleeps between fork and exec.
#[test]
fn a_lock_held_for_a_moment_by_a_forked_child_is_waited_for_not_refused() {
    use std::os::unix::process::CommandExt;
    let dir = scratch("tor-lock-fork");
    let state = dir.join("slot");
    std::fs::create_dir_all(&state).unwrap();
    let first = lock_slot(&state).unwrap();
    // Forked (by another thread, as in the app) while `first` is open; the copy
    // is closed only at exec, 700 ms on. `std` waits for the exec, hence the thread.
    let forked = dir.join("forked");
    let marker = forked.clone();
    let spawner = std::thread::spawn(move || {
        let mut command = std::process::Command::new("true");
        unsafe {
            command.pre_exec(move || {
                std::fs::write(&marker, b"")?;
                std::thread::sleep(Duration::from_millis(700));
                Ok(())
            });
        }
        command.spawn().unwrap().wait().unwrap();
    });
    while !forked.exists() {
        std::thread::sleep(Duration::from_millis(5));
    }
    // Without a grace the next start is refused although no tor runs.
    drop(first);
    assert!(lock_slot_within(&state, Duration::ZERO).is_err());
    assert!(
        lock_slot(&state).is_ok(),
        "the lock frees when the child execs"
    );
    spawner.join().unwrap();
    let _ = std::fs::remove_dir_all(dir);
}

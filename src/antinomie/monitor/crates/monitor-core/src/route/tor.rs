// SPDX-License-Identifier: GPL-3.0-only
//! The Tor route's own tor: Antinomie starts a tor of its own for the run
//! and stops it when the route is released.
//!
//! * The data directory is private (mode 0700) under the app's data folder,
//!   one per gateway so two VMs never share a lock, and kept between runs so
//!   the next start finds its consensus.
//! * The SocksPort is a free port on 127.0.0.1 picked for each start; tor
//!   offers nothing else: no ControlPort, no listener on another address.
//! * Bootstrap progress is read from tor's log file, so no control
//!   connection is needed. A tor that stops, or that is not at 100% within
//!   the wait, is an error and the route does not come up.
use super::{config::TorLaunch, managed::Managed};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    net::TcpListener,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// A path that can be written inside a quoted torrc value.
fn torrc_path(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .filter(|text| !text.contains(['"', '\\', '\n', '\r', '\0']))
        .ok_or_else(|| {
            format!(
                "Tor: the path {} cannot be written in a torrc",
                path.display()
            )
        })?;
    Ok(format!("\"{text}\""))
}

/// A free port on 127.0.0.1. Tor binds it a moment later; if something else
/// takes it in between, tor stops and the route reports that.
fn free_port() -> Result<u16, String> {
    TcpListener::bind(("127.0.0.1", 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|e| format!("Tor: no free port on 127.0.0.1: {e}"))
}

fn private_file(path: &Path, truncate: bool) -> Result<File, String> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(truncate)
        .append(!truncate)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("Tor: {}: {e}", path.display()))
}

/// The torrc of one start.
fn torrc(launch: &TorLaunch, data: &Path, log: &Path, port: u16) -> Result<String, String> {
    let mut text = format!(
        "DataDirectory {}\nSocksPort 127.0.0.1:{port}\nControlPort 0\nCookieAuthentication 0\n\
         ClientOnly 1\nAvoidDiskWrites 1\nSafeLogging 1\nLog notice file {}\n",
        torrc_path(&data.join("data"))?,
        torrc_path(log)?,
    );
    for (key, file) in [("GeoIPFile", "geoip"), ("GeoIPv6File", "geoip6")] {
        if let Some(path) = launch.geoip_dir.as_ref().map(|dir| dir.join(file))
            && path.is_file()
        {
            text.push_str(&format!("{key} {}\n", torrc_path(&path)?));
        }
    }
    Ok(text)
}

/// Tor's last `Bootstrapped N% (tag): summary` line in `log`: the percentage
/// and the text after it.
pub(crate) fn bootstrap_progress(log: &str) -> Option<(u8, String)> {
    log.lines().rev().find_map(|line| {
        let rest = line.split_once("Bootstrapped ")?.1;
        let (percent, summary) = rest.split_once('%')?;
        Some((percent.trim().parse().ok()?, summary.trim().to_owned()))
    })
}

fn read_tail(path: &Path, from: u64) -> String {
    let mut text = String::new();
    if let Ok(mut file) = File::open(path)
        && file.seek(SeekFrom::Start(from)).is_ok()
    {
        let _ = (&mut file).take(1 << 20).read_to_string(&mut text);
    }
    text
}

/// The last non-empty lines of a file, for an error message.
fn last_lines(path: &Path) -> String {
    let text = read_tail(path, 0);
    let lines: Vec<_> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(2)..].join(" | ")
}

/// Starts tor in `<state_root>/<slot>` and waits until it has bootstrapped.
/// Returns the process (killed when dropped) and its SOCKS port on
/// 127.0.0.1.
pub(crate) fn start_tor(
    launch: &TorLaunch,
    slot: &str,
    wait: Duration,
) -> Result<(Managed, u16), String> {
    let state = launch.state_root.join(slot);
    for dir in [&launch.state_root, &state, &state.join("data")] {
        crate::storage::private_dir(dir).map_err(|e| format!("Tor: {}: {e}", dir.display()))?;
    }
    let port = free_port()?;
    let log_path = state.join("tor.log");
    // A fresh log, so an earlier start's "Bootstrapped 100%" is never read.
    drop(private_file(&log_path, true)?);
    let output = private_file(&state.join("tor.out"), true)?;
    let errors = output.try_clone().map_err(|e| format!("Tor: {e}"))?;
    // An empty defaults file stops tor reading the system's torrc-defaults.
    let defaults = state.join("torrc-defaults");
    fs::write(&defaults, b"").map_err(|e| format!("Tor: {}: {e}", defaults.display()))?;
    let config = state.join("torrc");
    private_file(&config, true)?
        .write_all(torrc(launch, &state, &log_path, port)?.as_bytes())
        .map_err(|e| format!("Tor: {}: {e}", config.display()))?;
    let mut command = Command::new(&launch.binary);
    command
        .arg("--defaults-torrc")
        .arg(&defaults)
        .arg("-f")
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(output))
        .stderr(Stdio::from(errors));
    if let Some(libraries) = &launch.lib_dir {
        // The bundle's own libevent and OpenSSL, next to its tor.
        command.env("LD_LIBRARY_PATH", libraries);
    }
    let child = command
        .spawn()
        .map_err(|e| format!("Tor: cannot start {}: {e}", launch.binary.display()))?;
    let mut managed = Managed::new(child, "tor");
    let deadline = Instant::now() + wait;
    loop {
        if let Some(status) = managed
            .child_mut()
            .try_wait()
            .map_err(|e| format!("Tor: {e}"))?
        {
            let said = last_lines(&state.join("tor.out"));
            let said = if said.is_empty() {
                last_lines(&log_path)
            } else {
                said
            };
            return Err(format!(
                "Tor: tor stopped before it was ready ({status}): {said}"
            ));
        }
        let progress = bootstrap_progress(&read_tail(&log_path, 0));
        if progress
            .as_ref()
            .is_some_and(|(percent, _)| *percent >= 100)
        {
            return Ok((managed, port));
        }
        if Instant::now() >= deadline {
            let at = progress.map_or_else(
                || "nothing was reported".to_owned(),
                |(percent, summary)| format!("stuck at {percent}% {summary}"),
            );
            return Err(format!(
                "Tor: tor did not finish bootstrapping within {} s ({at}); check that this \
                 computer can reach the Tor network, or set an existing SOCKS address \
                 in Settings. Log: {}",
                wait.as_secs(),
                log_path.display()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

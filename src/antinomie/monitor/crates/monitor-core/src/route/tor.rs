// SPDX-License-Identifier: GPL-3.0-only
//! The Tor route's own tor: Antinomie starts a tor of its own for the run
//! and stops it when the route is released.
//!
//! * The process dies with the app and is recorded for the next start
//!   (`helpers.rs`).
//! * The data directory is private (mode 0700) under the app's data folder,
//!   one per VM (the slot is the VM's id, not the start's), so two VMs never
//!   share a lock, and kept between runs so the next start finds its
//!   consensus, descriptors and guards. A `lock` file in the slot is held
//!   (flock) for as long as the tor runs: one tor per data directory.
//! * A start that stalls or whose tor exits is tried once more; after an exit
//!   the cached `data` folder is removed first, as it may be corrupt. Slots
//!   not used for a month are removed.
//! * The SocksPort is a free port on 127.0.0.1 picked for each start; tor
//!   offers nothing else: no ControlPort, no listener on another address.
//! * Tor logs to its stdout, which is the private `tor.log` (stderr goes to
//!   `tor.out`). Bootstrap progress is read from that log file, so no control
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
///
/// Every path value is quoted as a whole (`Key "<path>"`), which tor accepts
/// and which keeps a space in the data folder intact. `Log` takes no path:
/// tor does not unquote inside a multi-word value, so `Log notice file "<path>"`
/// makes tor open a file whose name contains the quote characters and exit.
/// `Log notice stdout` is used instead and the process's stdout is the
/// private log file.
pub(crate) fn torrc(launch: &TorLaunch, data: &Path, port: u16) -> Result<String, String> {
    let mut text = format!(
        "DataDirectory {}\nSocksPort 127.0.0.1:{port}\nControlPort 0\nCookieAuthentication 0\n\
         ClientOnly 1\nAvoidDiskWrites 1\nSafeLogging 1\nLog notice stdout\n",
        torrc_path(&data.join("data"))?,
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
    last_n_lines(path, 2)
}

/// The last `count` non-empty lines of a log, joined with ` | `.
fn last_n_lines(path: &Path, count: usize) -> String {
    let text = read_tail(path, 0);
    let lines: Vec<_> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    lines[lines.len().saturating_sub(count)..].join(" | ")
}

/// Slots untouched for this long are removed at the next start.
const STALE_SLOT: Duration = Duration::from_secs(30 * 24 * 3600);

/// Takes the slot's lock; an error when another tor (this app or another
/// instance) holds it.
pub(crate) fn lock_slot(state: &Path) -> Result<File, String> {
    lock_slot_within(state, LOCK_GRACE)
}

/// How long a start waits for a slot's lock before it calls the slot busy.
/// The file is opened close-on-exec, but a process forked by another thread
/// of the app (a helper being spawned, a VM's QEMU) holds a copy of the
/// descriptor, and so the lock, until its exec a moment later; the lock of a
/// tor that was just stopped can also take a moment to go. Neither is "another
/// tor is using the folder".
const LOCK_GRACE: Duration = Duration::from_secs(3);

pub(crate) fn lock_slot_within(state: &Path, grace: Duration) -> Result<File, String> {
    let path = state.join("lock");
    let file = private_file(&path, false)?;
    let give_up = Instant::now() + grace;
    while file.try_lock().is_err() {
        if Instant::now() >= give_up {
            return Err(format!(
                "Tor: another tor is already using {}; one tor runs per data folder. Wait for \
                 that run to end",
                state.display()
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
    // A use of the slot, for the month-old check.
    let _ = file.set_modified(std::time::SystemTime::now());
    Ok(file)
}

/// Removes the other slots under `root` that nothing has touched for a month
/// and that are not locked: the folders of VMs that are gone, and the
/// per-start folders of earlier versions.
fn prune_stale_slots(root: &Path, keep: &Path, now: std::time::SystemTime) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let old = entry
            .metadata()
            .ok()
            .filter(|meta| meta.is_dir() && !meta.file_type().is_symlink())
            .and_then(|meta| meta.modified().ok())
            .into_iter()
            .chain(
                fs::metadata(path.join("lock"))
                    .ok()
                    .and_then(|meta| meta.modified().ok()),
            )
            .max()
            .and_then(|time| now.duration_since(time).ok())
            .is_some_and(|age| age >= STALE_SLOT);
        if path == keep || !old {
            continue;
        }
        // Only a slot nobody holds.
        if let Ok(lock) = lock_slot(&path)
            && fs::remove_dir_all(&path).is_ok()
        {
            drop(lock);
        }
    }
}

/// Why one start of tor failed.
enum Failure {
    /// The tor exited before it was ready: its cached state may be corrupt.
    Exited(String),
    /// No progress, or not at 100% in time.
    Stalled(String),
    /// Nothing a second try would change.
    Fatal(String),
}

impl Failure {
    fn into_message(self) -> String {
        match self {
            Failure::Exited(m) | Failure::Stalled(m) | Failure::Fatal(m) => m,
        }
    }
}

/// Starts tor in `<state_root>/<slot>` and waits until it has bootstrapped.
/// Returns the process (killed when dropped; it also holds the slot's lock)
/// and its SOCKS port on 127.0.0.1.
///
/// The folder is reused from run to run. One retry follows a stalled
/// bootstrap or an exited tor; after an exit the `data` folder is rebuilt.
pub(crate) fn start_tor(
    launch: &TorLaunch,
    slot: &str,
    wait: Duration,
) -> Result<(Managed, u16), String> {
    let state = launch.state_root.join(slot);
    for dir in [&launch.state_root, &state, &state.join("data")] {
        crate::storage::private_dir(dir).map_err(|e| format!("Tor: {}: {e}", dir.display()))?;
    }
    let lock = lock_slot(&state)?;
    prune_stale_slots(&launch.state_root, &state, std::time::SystemTime::now());
    let mut retried = false;
    loop {
        match start_once(launch, &state, wait) {
            Ok((managed, port)) => return Ok((managed.holding(lock), port)),
            Err(Failure::Fatal(error)) => return Err(error),
            Err(failure) if retried => {
                return Err(format!(
                    "{} (after a second start of tor)",
                    failure.into_message()
                ));
            }
            Err(failure) => {
                retried = true;
                if matches!(failure, Failure::Exited(_)) {
                    let data = state.join("data");
                    let _ = fs::remove_dir_all(&data);
                    crate::storage::private_dir(&data)
                        .map_err(|e| format!("Tor: {}: {e}", data.display()))?;
                }
            }
        }
    }
}

fn start_once(launch: &TorLaunch, state: &Path, wait: Duration) -> Result<(Managed, u16), Failure> {
    let fatal = Failure::Fatal;
    let port = free_port().map_err(fatal)?;
    let log_path = state.join("tor.log");
    // A fresh log, so an earlier start's "Bootstrapped 100%" is never read.
    let log_file = private_file(&log_path, true).map_err(fatal)?;
    let output = private_file(&state.join("tor.out"), true).map_err(fatal)?;
    let errors = output
        .try_clone()
        .map_err(|e| Failure::Fatal(format!("Tor: {e}")))?;
    // An empty defaults file stops tor reading the system's torrc-defaults.
    let defaults = state.join("torrc-defaults");
    fs::write(&defaults, b"")
        .map_err(|e| Failure::Fatal(format!("Tor: {}: {e}", defaults.display())))?;
    let config = state.join("torrc");
    private_file(&config, true)
        .map_err(fatal)?
        .write_all(torrc(launch, state, port).map_err(fatal)?.as_bytes())
        .map_err(|e| Failure::Fatal(format!("Tor: {}: {e}", config.display())))?;
    let mut command = Command::new(&launch.binary);
    command
        .arg("--defaults-torrc")
        .arg(&defaults)
        .arg("-f")
        .arg(&config)
        .stdin(Stdio::null())
        // `Log notice stdout`: tor's log is the private log file.
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(errors));
    if let Some(libraries) = &launch.lib_dir {
        // The bundle's own libevent and OpenSSL, next to its tor.
        command.env("LD_LIBRARY_PATH", libraries);
    }
    let (child, record) =
        super::helpers::spawn(command, &launch.helpers_dir, "tor").map_err(|e| {
            Failure::Fatal(format!(
                "Tor: cannot start {}: {e}",
                launch.binary.display()
            ))
        })?;
    let mut managed = Managed::new(child, record, "tor");
    let started = Instant::now();
    let deadline = started + wait;
    // No progress for half the wait is a stall: the retry then has time.
    let stall = wait / 2;
    let mut last = (None, started);
    loop {
        if let Some(status) = managed
            .child_mut()
            .try_wait()
            .map_err(|e| Failure::Fatal(format!("Tor: {e}")))?
        {
            let said = last_lines(&state.join("tor.out"));
            let said = if said.is_empty() {
                last_lines(&log_path)
            } else {
                said
            };
            return Err(Failure::Exited(format!(
                "Tor: tor stopped before it was ready ({status}): {said}"
            )));
        }
        let progress = bootstrap_progress(&read_tail(&log_path, 0));
        if progress
            .as_ref()
            .is_some_and(|(percent, _)| *percent >= 100)
        {
            return Ok((managed, port));
        }
        let percent = progress.as_ref().map(|(percent, _)| *percent);
        if percent != last.0 {
            last = (percent, Instant::now());
        }
        if Instant::now() >= deadline || last.1.elapsed() >= stall {
            let at = progress.map_or_else(
                || "nothing was reported".to_owned(),
                |(percent, summary)| format!("stuck at {percent}% {summary}"),
            );
            return Err(Failure::Stalled(format!(
                "Tor: tor did not finish bootstrapping within {} s ({at}); check that this \
                 computer can reach the Tor network, or set an existing SOCKS address \
                 in Settings. Log: {}. Last log lines: {}",
                wait.as_secs(),
                log_path.display(),
                last_n_lines(&log_path, 6)
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

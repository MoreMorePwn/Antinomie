// SPDX-License-Identifier: GPL-3.0-only
//! One way to cancel anything that downloads or runs a child on the user's
//! behalf.
//!
//! A [`CancelToken`] is a shared flag. The code that waits on a child process
//! ([`wait`], [`capture`]) watches it every few tens of milliseconds, so a
//! cancel never waits for the network: it does not matter whether the server is
//! sending, silent or gone. A cancelled child is killed with the whole process
//! group it leads (the children are started with [`lead_group`]), reaped, and
//! the caller is told, so it can remove what the transfer left behind.
//!
//! Every child waited on here is also recorded by process id, so the app can
//! stop all of them when it exits ([`stop_all`]); no pattern kill is involved.
use std::{
    collections::HashSet,
    io::{self, Read},
    ops::Deref,
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// How long the wait loops sleep between looks at the flag and the child.
const POLL: Duration = Duration::from_millis(50);

/// The word every cancelled transfer puts in its error, so a caller can tell a
/// cancel (the user's own action, shown as information) from a failure.
pub const CANCELLED: &str = "cancelled";

/// Whether `error` reports a cancel.
pub fn is_cancelled(error: &str) -> bool {
    error.to_ascii_lowercase().contains(CANCELLED)
}

/// A registered flag for code that passes a plain `Arc<AtomicBool>` around:
/// like a [`CancelToken`], it is set when the app closes.
pub fn flag() -> Arc<AtomicBool> {
    CancelToken::new().0
}

/// A flag the owner of a job sets to stop it. Clones share the flag; it
/// dereferences to the [`AtomicBool`] the download functions take.
#[derive(Clone, Debug)]
pub struct CancelToken(Arc<AtomicBool>);

/// Every token made, so the app can cancel all jobs as it exits.
static TOKENS: Mutex<Vec<Weak<AtomicBool>>> = Mutex::new(Vec::new());

impl Default for CancelToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancelToken {
    pub fn new() -> Self {
        let flag = Arc::new(AtomicBool::new(false));
        let mut all = TOKENS.lock().unwrap_or_else(|e| e.into_inner());
        all.retain(|token| token.strong_count() > 0);
        all.push(Arc::downgrade(&flag));
        Self(flag)
    }

    /// Ask the job to stop.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

impl Deref for CancelToken {
    type Target = AtomicBool;
    fn deref(&self) -> &AtomicBool {
        &self.0
    }
}

/// Make the child lead its own process group, so a cancel reaches what it
/// started too (a build's compilers, pip's helpers).
pub fn lead_group(command: &mut Command) -> &mut Command {
    command.process_group(0)
}

/// Children being waited on, by process id.
static RUNNING: Mutex<Option<HashSet<u32>>> = Mutex::new(None);

fn running() -> std::sync::MutexGuard<'static, Option<HashSet<u32>>> {
    RUNNING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Records a child, for the app's exit, until the value is dropped.
pub struct Recorded(u32);

/// Record a child that a caller waits on itself (see [`wait_every`]).
pub fn record(pid: u32) -> Recorded {
    Recorded::new(pid)
}

impl Recorded {
    fn new(pid: u32) -> Self {
        running().get_or_insert_with(HashSet::new).insert(pid);
        Self(pid)
    }
}

impl Drop for Recorded {
    fn drop(&mut self) {
        if let Some(set) = running().as_mut() {
            set.remove(&self.0);
        }
    }
}

/// SIGKILL the group `pid` leads. A pid that leads no group is left alone
/// (the call then fails with ESRCH).
fn kill_group(pid: u32) {
    if let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

/// Kill a child and everything in its group, and reap it.
pub fn kill_tree(child: &mut Child) {
    kill_group(child.id());
    let _ = child.kill();
    let _ = child.wait();
}

/// Kill every child being waited on.
pub fn stop_all() {
    stop_where(|_| true);
}

/// The app is closing: cancel every job that has a [`CancelToken`], give the
/// jobs `grace` to stop their children and remove what they left, then kill
/// any child still running. No transfer outlives the app.
pub fn shutdown(grace: Duration) {
    for token in TOKENS.lock().unwrap_or_else(|e| e.into_inner()).iter() {
        if let Some(flag) = token.upgrade() {
            flag.store(true, Ordering::Relaxed);
        }
    }
    let started = std::time::Instant::now();
    while started.elapsed() < grace && running().as_ref().is_some_and(|set| !set.is_empty()) {
        std::thread::sleep(Duration::from_millis(20));
    }
    // The jobs clean up right after their child is gone.
    std::thread::sleep(Duration::from_millis(150));
    stop_all();
}

fn stop_where(chosen: impl Fn(u32) -> bool) {
    let pids: Vec<u32> = running()
        .as_ref()
        .map_or_else(Vec::new, |set| set.iter().copied().collect());
    for pid in pids.into_iter().filter(|pid| chosen(*pid)) {
        kill_group(pid);
    }
}

/// Wait for `child`, calling `tick` about every `interval` meanwhile (for
/// progress). `Ok(Some(status))` when it ended by itself; `Ok(None)` when
/// `cancel` was set: the child and its group are then killed and reaped.
pub fn wait_every(
    child: &mut Child,
    cancel: &AtomicBool,
    interval: Duration,
    mut tick: impl FnMut(),
) -> Result<Option<ExitStatus>, String> {
    let _recorded = Recorded::new(child.id());
    let mut since_tick = interval;
    loop {
        if cancel.load(Ordering::Relaxed) {
            kill_tree(child);
            return Ok(None);
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(Some(status)),
            Ok(None) => {}
            Err(error) => {
                kill_tree(child);
                return Err(error.to_string());
            }
        }
        if since_tick >= interval {
            since_tick = Duration::ZERO;
            tick();
        }
        std::thread::sleep(POLL);
        since_tick += POLL;
    }
}

/// [`wait_every`] without progress.
pub fn wait(child: &mut Child, cancel: &AtomicBool) -> Result<Option<ExitStatus>, String> {
    wait_every(child, cancel, Duration::from_secs(3600), || {})
}

/// What a child wrote and how it ended.
#[derive(Debug)]
pub struct Captured {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Read a pipe to its end: the first `keep` bytes are kept, the rest read and
/// dropped so the writer never blocks on a full pipe.
fn read_capped(mut pipe: impl Read, keep: u64) -> Vec<u8> {
    let mut kept = Vec::new();
    let _ = (&mut pipe).take(keep).read_to_end(&mut kept);
    let _ = io::copy(&mut pipe, &mut io::sink());
    kept
}

/// Wait for `child` while collecting its piped standard output (at most
/// `max_stdout` bytes kept) and diagnostics (at most `max_stderr`). `Ok(None)`
/// when `cancel` was set: the child is killed and nothing is returned.
pub fn capture(
    child: &mut Child,
    cancel: &AtomicBool,
    max_stdout: u64,
    max_stderr: u64,
) -> Result<Option<Captured>, String> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let out = std::thread::spawn(move || stdout.map(|pipe| read_capped(pipe, max_stdout)));
    let err = std::thread::spawn(move || stderr.map(|pipe| read_capped(pipe, max_stderr)));
    let waited = wait_every(child, cancel, Duration::from_secs(3600), || {});
    let stdout = out.join().ok().flatten().unwrap_or_default();
    let stderr = err.join().ok().flatten().unwrap_or_default();
    Ok(waited?.map(|status| Captured {
        status,
        stdout,
        stderr,
    }))
}

#[cfg(test)]
mod kind_tests;
#[cfg(test)]
mod tests;

// SPDX-License-Identifier: GPL-3.0-only
//! Stopping a spawned tool together with everything it started, and never
//! waiting unboundedly on a pipe a survivor may still hold.
//!
//! A tool spawned with [`own_group`] leads its own process group. Killing
//! only that process is not enough for bubblewrap: its namespace init runs in
//! a session of its own (`--new-session`) and, observed under load, outlives
//! a SIGKILLed launcher, keeping the output pipes open and the worker alive.
//! [`kill_tree`] therefore stops the launcher first (so it can start no
//! further child), kills each of its direct children (the namespace init,
//! whose death takes the whole PID namespace with it) through a pidfd, then
//! SIGKILLs the group and reaps the launcher. Reading threads are then joined
//! with [`join_within`], so a holder that escaped cannot hang the caller.
use std::{
    os::unix::process::CommandExt,
    process::{Child, Command},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

/// How long to wait for a reader thread once its tool was killed.
pub(crate) const KILLED_JOIN_WAIT: Duration = Duration::from_secs(3);

/// Make `command` the leader of a new process group.
pub(crate) fn own_group(command: &mut Command) -> &mut Command {
    command.process_group(0)
}

fn group(child: &Child) -> Option<rustix::process::Pid> {
    rustix::process::Pid::from_raw(i32::try_from(child.id()).ok()?)
}

/// The launcher's direct children, read while it is stopped.
fn direct_children(pid: u32) -> Vec<rustix::process::Pid> {
    let path = format!("/proc/{pid}/task/{pid}/children");
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    text.split_whitespace()
        .filter_map(|pid| pid.parse::<i32>().ok())
        .filter_map(rustix::process::Pid::from_raw)
        .collect()
}

/// Wait (briefly) until the stop signal took effect on `pid`.
fn wait_stopped(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|stat| {
                stat.rsplit_once(") ")
                    .and_then(|(_, rest)| rest.bytes().next())
            });
        if !matches!(state, Some(b'R' | b'S' | b'D')) {
            return;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

/// SIGKILL `child`'s direct children (through pidfds), its process group and
/// the child itself, then reap the child.
pub(crate) fn kill_tree(child: &mut Child) {
    if let Some(group) = group(child) {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::STOP);
        wait_stopped(child.id());
        for pid in direct_children(child.id()) {
            if let Ok(fd) = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()) {
                let _ = rustix::process::pidfd_send_signal(&fd, rustix::process::Signal::KILL);
            }
        }
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// SIGKILL whatever is left in the group of an exited `child` (so its pipes
/// reach end of file). Only for a child not yet reaped or just reaped by this
/// owner; the group id cannot have been reused while it still has members.
pub(crate) fn kill_leftovers(child: &Child) {
    if let Some(group) = group(child) {
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
    }
}

/// The result of `handle`, or `None` if it is still running after `wait`
/// (the thread is abandoned: it ends when its pipe does).
pub(crate) fn join_within<T>(handle: JoinHandle<T>, wait: Duration) -> Option<T> {
    let deadline = Instant::now() + wait;
    while !handle.is_finished() {
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(5));
    }
    handle.join().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::Read, process::Stdio};

    #[test]
    fn kill_tree_stops_a_child_in_its_own_session_that_holds_the_pipe() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "setsid sleep 300 & wait"])
            .stdout(Stdio::piped());
        own_group(&mut command);
        let mut child = command.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let reader = thread::spawn(move || {
            let mut text = Vec::new();
            let _ = stdout.read_to_end(&mut text);
        });
        thread::sleep(Duration::from_millis(200));
        kill_tree(&mut child);
        assert!(join_within(reader, Duration::from_secs(10)).is_some());
    }

    #[test]
    fn join_within_gives_up_on_a_thread_that_does_not_finish() {
        let (hold, wait) = std::sync::mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let _ = wait.recv();
        });
        assert!(join_within(handle, Duration::from_millis(100)).is_none());
        drop(hold);
    }
}

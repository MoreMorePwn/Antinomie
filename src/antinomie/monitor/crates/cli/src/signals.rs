// SPDX-License-Identifier: GPL-3.0-only
//! SIGINT and SIGTERM end a waiting command cleanly (design 3.3, exit 130): the
//! handler only sets a flag; the command notices it at its next poll, asks the
//! engine to stop the VM and exits. Nothing else happens in the handler.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
/// The daemon's signals, counted (design 2.7): stop (`SIGINT`, `SIGTERM`),
/// reload (`SIGHUP`), status (`SIGUSR1`).
static STOPS: AtomicUsize = AtomicUsize::new(0);
static RELOADS: AtomicUsize = AtomicUsize::new(0);
static STATUSES: AtomicUsize = AtomicUsize::new(0);

extern "C" fn on_daemon_signal(signal: libc::c_int) {
    match signal {
        libc::SIGHUP => {
            RELOADS.fetch_add(1, Ordering::SeqCst);
        }
        libc::SIGUSR1 => {
            STATUSES.fetch_add(1, Ordering::SeqCst);
        }
        _ => {
            INTERRUPTED.store(true, Ordering::SeqCst);
            STOPS.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Route the daemon's four signals to their counters. The handler only adds
/// to an atomic; the supervisor reads them every 100 ms.
pub fn install_daemon() {
    let handler = on_daemon_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: as in `install`: the handler only touches atomics.
    unsafe {
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGUSR1] {
            libc::signal(signal, handler);
        }
    }
}

/// The signals that arrived since the last call.
pub struct DaemonSignals {
    seen: [AtomicUsize; 3],
}

impl DaemonSignals {
    pub fn new() -> Self {
        Self {
            seen: [
                AtomicUsize::new(STOPS.load(Ordering::SeqCst)),
                AtomicUsize::new(RELOADS.load(Ordering::SeqCst)),
                AtomicUsize::new(STATUSES.load(Ordering::SeqCst)),
            ],
        }
    }
}

impl antinomie_service::daemon::Signals for DaemonSignals {
    fn take(&self) -> Vec<antinomie_service::daemon::Signal> {
        use antinomie_service::daemon::Signal;
        let mut out = Vec::new();
        for (index, (counter, signal)) in [
            (&STOPS, Signal::Stop),
            (&RELOADS, Signal::Reload),
            (&STATUSES, Signal::Status),
        ]
        .into_iter()
        .enumerate()
        {
            let now = counter.load(Ordering::SeqCst);
            let before = self.seen[index].swap(now, Ordering::SeqCst);
            for _ in before..now {
                out.push(signal);
            }
        }
        out
    }
}

extern "C" fn on_signal(_signal: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Route SIGINT and SIGTERM to the flag. Safe to call more than once.
pub fn install() {
    let handler = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
    // SAFETY: `signal` installs a handler that only stores to an atomic, which
    // is async-signal-safe; the function pointer outlives the process.
    unsafe {
        libc::signal(libc::SIGINT, handler);
        libc::signal(libc::SIGTERM, handler);
    }
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

#[cfg(test)]
pub fn raise_for_test() {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

#[cfg(test)]
pub fn clear_for_test() {
    INTERRUPTED.store(false, Ordering::SeqCst);
}

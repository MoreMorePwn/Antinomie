// SPDX-License-Identifier: GPL-3.0-only
//! SIGINT and SIGTERM end a waiting command cleanly (design 3.3, exit 130): the
//! handler only sets a flag; the command notices it at its next poll, asks the
//! engine to stop the VM and exits. Nothing else happens in the handler.
use std::sync::atomic::{AtomicBool, Ordering};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

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

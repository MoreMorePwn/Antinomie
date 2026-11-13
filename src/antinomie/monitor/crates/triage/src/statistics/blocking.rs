// SPDX-License-Identifier: GPL-3.0-only
//! Which calls wait by design (design 2.5 and 4.3.4).
//!
//! A sleep or a `poll` is slow because that is what it does. Counting it with
//! the ordinary calls would hide the ordinary calls that were slow, so the
//! latency tables keep the three classes apart. The class follows the call's
//! name and, for `futex`, `io_uring_enter` and `flock`, the operation
//! argument; names are the guest's own, so x86-64 and arm64 calls classify
//! alike.
use antinomie_monitor_core::syscalls;
use serde::{Deserialize, Serialize};

/// How a call's duration should be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockClass {
    /// Not expected to wait: a slow one is worth a look.
    Ordinary,
    /// Waits or not depending on the descriptor, which the engine does not track.
    MayBlock,
    /// Waits by design: shown apart so it does not hide slow ordinary calls.
    Waits,
}

impl BlockClass {
    pub const ALL: [Self; 3] = [Self::Ordinary, Self::MayBlock, Self::Waits];

    pub fn index(self) -> usize {
        match self {
            Self::Ordinary => 0,
            Self::MayBlock => 1,
            Self::Waits => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::MayBlock => "may block",
            Self::Waits => "waits by design",
        }
    }
}

/// `FUTEX_WAIT`, `FUTEX_LOCK_PI`, `FUTEX_WAIT_BITSET`, `FUTEX_WAIT_REQUEUE_PI`
/// and `FUTEX_LOCK_PI2`, after the private and clock bits are removed.
const FUTEX_WAITS: [u64; 5] = [0, 6, 9, 11, 13];
const FUTEX_CMD_MASK: u64 = 127;
const IORING_ENTER_GETEVENTS: u64 = 1;
const LOCK_SH: u64 = 1;
const LOCK_EX: u64 = 2;
const LOCK_NB: u64 = 4;

/// The class of call `name` (id `nr`, six argument words `args` at its
/// entry, when the recording has them).
pub fn classify(name: &str, nr: u64, args: Option<&[u64; 6]>) -> BlockClass {
    match name {
        "wait4" | "waitid" | "poll" | "ppoll" | "select" | "pselect6" | "epoll_wait"
        | "epoll_pwait" | "epoll_pwait2" | "nanosleep" | "clock_nanosleep" | "pause"
        | "rt_sigsuspend" | "rt_sigtimedwait" | "accept" | "accept4" | "msgrcv" | "semop"
        | "semtimedop" | "mq_timedreceive" | "io_getevents" | "io_pgetevents" | "futex_wait"
        | "futex_waitv" => BlockClass::Waits,
        "futex" => operation(nr, name, "op", args).map_or(BlockClass::Ordinary, |op| {
            if FUTEX_WAITS.contains(&(op & FUTEX_CMD_MASK)) {
                BlockClass::Waits
            } else {
                BlockClass::Ordinary
            }
        }),
        "io_uring_enter" => {
            operation(nr, name, "flags", args).map_or(BlockClass::Ordinary, |flags| {
                if flags & IORING_ENTER_GETEVENTS != 0 {
                    BlockClass::Waits
                } else {
                    BlockClass::Ordinary
                }
            })
        }
        "flock" => operation(nr, name, "cmd", args).map_or(BlockClass::Ordinary, |cmd| {
            if cmd & (LOCK_SH | LOCK_EX) != 0 && cmd & LOCK_NB == 0 {
                BlockClass::Waits
            } else {
                BlockClass::Ordinary
            }
        }),
        "read" | "readv" | "recvfrom" | "recvmsg" | "recvmmsg" | "write" | "writev" | "sendto"
        | "sendmsg" | "connect" | "openat" | "open" => BlockClass::MayBlock,
        _ => BlockClass::Ordinary,
    }
}

/// The value of argument `role` of call `name`, found by name in the table
/// of the call's own ABI (positions differ between ABIs).
fn operation(nr: u64, name: &str, role: &str, args: Option<&[u64; 6]>) -> Option<u64> {
    let index = syscalls::argument_of(nr, name, role)?;
    args?.get(index).copied()
}

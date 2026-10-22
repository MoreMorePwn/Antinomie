// SPDX-License-Identifier: GPL-3.0-only
//! Signal numbers. The guest speaks Linux x86-64 numbers; the GDB Remote Serial
//! Protocol speaks GDB's own table (`include/gdb/signals.def`), which differs
//! for a dozen signals (`SIGBUS` is 7 on Linux and 10 in GDB, `SIGUSR1` is 10 and
//! 30, `SIGCHLD` 17 and 20, ...). Every signal that crosses the RSP is converted
//! here, in both directions.

/// Linux number -> GDB number, indexed by the Linux number (0 and 16 have none).
const LINUX_TO_GDB: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 10, 8, 9, 30, 11, 31, 13, 14, 15, // 0..=15
    0, 20, 19, 17, 18, 21, 22, 16, 24, 25, 26, 27, 28, 23, 32, 12, // 16..=31
];

/// GDB's number for real-time signal `n` of Linux (32..=64).
fn realtime_to_gdb(linux: u32) -> Option<u8> {
    match linux {
        32 => Some(77),
        33..=63 => Some(45 + (linux - 33) as u8),
        64 => Some(78),
        _ => None,
    }
}

/// The GDB signal number for a Linux signal number; `None` when GDB has no name
/// for it (the stack-fault signal).
pub fn linux_to_gdb(linux: u32) -> Option<u8> {
    match linux {
        1..=31 => Some(LINUX_TO_GDB[linux as usize]).filter(|number| *number != 0),
        32..=64 => realtime_to_gdb(linux),
        _ => None,
    }
}

/// The Linux signal number for a GDB signal number; `None` for signals Linux
/// does not have.
pub fn gdb_to_linux(gdb: u8) -> Option<u32> {
    (1u32..=64).find(|linux| linux_to_gdb(*linux) == Some(gdb))
}

// SPDX-License-Identifier: GPL-3.0-only
use super::super::signals::{gdb_to_linux, linux_to_gdb};
/// GDB's own numbers (`include/gdb/signals.def`), written out: the oracle for the
/// mapping.
mod gdb {
    pub const SIGTRAP: u8 = 5;
    pub const SIGBUS: u8 = 10;
    pub const SIGSEGV: u8 = 11;
    pub const SIGSYS: u8 = 12;
    pub const SIGTERM: u8 = 15;
    pub const SIGURG: u8 = 16;
    pub const SIGSTOP: u8 = 17;
    pub const SIGCONT: u8 = 19;
    pub const SIGCHLD: u8 = 20;
    pub const SIGIO: u8 = 23;
    pub const SIGUSR1: u8 = 30;
    pub const SIGUSR2: u8 = 31;
    pub const SIGPWR: u8 = 32;
    pub const SIG34: u8 = 46;
    pub const SIG32: u8 = 77;
    pub const SIG64: u8 = 78;
}

#[test]
fn the_signals_programs_get_map_to_gdbs_numbers() {
    assert_eq!(linux_to_gdb(11), Some(gdb::SIGSEGV));
    assert_eq!(linux_to_gdb(7), Some(gdb::SIGBUS));
    assert_eq!(linux_to_gdb(10), Some(gdb::SIGUSR1));
    assert_eq!(linux_to_gdb(12), Some(gdb::SIGUSR2));
    assert_eq!(linux_to_gdb(17), Some(gdb::SIGCHLD));
    assert_eq!(linux_to_gdb(19), Some(gdb::SIGSTOP));
    assert_eq!(linux_to_gdb(18), Some(gdb::SIGCONT));
    assert_eq!(linux_to_gdb(23), Some(gdb::SIGURG));
    assert_eq!(linux_to_gdb(29), Some(gdb::SIGIO));
    assert_eq!(linux_to_gdb(30), Some(gdb::SIGPWR));
    assert_eq!(linux_to_gdb(31), Some(gdb::SIGSYS));
    assert_eq!(linux_to_gdb(5), Some(gdb::SIGTRAP));
    assert_eq!(linux_to_gdb(15), Some(gdb::SIGTERM));
    assert_eq!(linux_to_gdb(34), Some(gdb::SIG34));
    assert_eq!(linux_to_gdb(32), Some(gdb::SIG32));
    assert_eq!(linux_to_gdb(64), Some(gdb::SIG64));
}

#[test]
fn numbers_without_a_name_do_not_map() {
    assert_eq!(linux_to_gdb(0), None);
    assert_eq!(linux_to_gdb(16), None);
    assert_eq!(linux_to_gdb(65), None);
    assert_eq!(gdb_to_linux(0), None);
}

#[test]
fn every_mapped_signal_round_trips() {
    for linux in 1..=64u32 {
        if let Some(gdb) = linux_to_gdb(linux) {
            assert_eq!(gdb_to_linux(gdb), Some(linux), "signal {linux}");
        }
    }
}

// SPDX-License-Identifier: MIT
use super::super::signals::{gdb_to_linux, linux_to_gdb};
use gdbstub::common::Signal;

#[test]
fn the_signals_programs_get_map_to_gdbs_numbers() {
    assert_eq!(linux_to_gdb(11), Some(Signal::SIGSEGV.0));
    assert_eq!(linux_to_gdb(7), Some(Signal::SIGBUS.0));
    assert_eq!(linux_to_gdb(10), Some(Signal::SIGUSR1.0));
    assert_eq!(linux_to_gdb(12), Some(Signal::SIGUSR2.0));
    assert_eq!(linux_to_gdb(17), Some(Signal::SIGCHLD.0));
    assert_eq!(linux_to_gdb(19), Some(Signal::SIGSTOP.0));
    assert_eq!(linux_to_gdb(18), Some(Signal::SIGCONT.0));
    assert_eq!(linux_to_gdb(23), Some(Signal::SIGURG.0));
    assert_eq!(linux_to_gdb(29), Some(Signal::SIGIO.0));
    assert_eq!(linux_to_gdb(30), Some(Signal::SIGPWR.0));
    assert_eq!(linux_to_gdb(31), Some(Signal::SIGSYS.0));
    assert_eq!(linux_to_gdb(5), Some(Signal::SIGTRAP.0));
    assert_eq!(linux_to_gdb(15), Some(Signal::SIGTERM.0));
    assert_eq!(linux_to_gdb(34), Some(Signal::SIG34.0));
    assert_eq!(linux_to_gdb(32), Some(Signal::SIG32.0));
    assert_eq!(linux_to_gdb(64), Some(Signal::SIG64.0));
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

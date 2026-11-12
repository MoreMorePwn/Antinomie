// SPDX-License-Identifier: GPL-3.0-only
//! What the guest's console says about its boot (ANT-T0476): a guest kernel
//! that crashed (an oops, a `BUG`) keeps running tainted and its control
//! channel still answers, so the engine's state alone does not show it. The
//! console log of the running boot (`Snapshot::serial_log`) does.
//!
//! The console is guest output. It is read only before the program runs (a
//! clean guest's boot) to fail a job or a lane command, and after the run
//! only to add a warning.
use std::{fs::File, io::Read, path::Path};

/// The failure message of a job whose guest kernel crashed while it booted.
pub const BOOT_CRASH: &str =
    "the guest kernel crashed while the VM booted; the program was not started";

/// How much of a console log is read: a boot writes some 60 KiB.
const READ_LIMIT: u64 = 8 * 1024 * 1024;

/// Lines that say the guest kernel crashed, or that the base's start-up
/// could not grow the root file system to the VM's disk.
const MARKERS: [&str; 6] = [
    "kernel BUG at ",
    "BUG: ",
    "Oops: ",
    "general protection fault",
    "Kernel panic - not syncing",
    "Guest filesystem resize failed",
];

/// The first console line that says the guest kernel crashed (without its
/// timestamp), or `None` when there is none or the log cannot be read.
pub fn kernel_crash(path: &Path) -> Option<String> {
    let mut bytes = Vec::new();
    File::open(path)
        .ok()?
        .take(READ_LIMIT)
        .read_to_end(&mut bytes)
        .ok()?;
    crash_line(&String::from_utf8_lossy(&bytes))
}

/// [`kernel_crash`] on text.
pub fn crash_line(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let line = line.trim_end_matches('\r');
        // `[    3.668595] kernel BUG at ...`: the message after the stamp.
        let message = match line.trim_start().strip_prefix('[') {
            Some(rest) => rest.split_once(']').map_or(line, |(_, after)| after.trim()),
            None => line.trim(),
        };
        MARKERS
            .iter()
            .any(|marker| message.starts_with(marker))
            .then(|| message.chars().take(300).collect())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ext4_resize_bug_of_the_pc_soak_is_found() {
        let log = "[    3.473546] EXT4-fs (sda): mounted filesystem r/w\n\
                   resize2fs 1.47.2 (1-Jan-2025)\n\
                   [    3.665615] EXT4-fs (sda): resizing filesystem from 393217 to 4194304 blocks\n\
                   [    3.668595] ------------[ cut here ]------------\n\
                   [    3.668595] kernel BUG at ../source/linux-6.12.94/fs/ext4/resize.c:547!\n\
                   [    3.670000] Oops: invalid opcode: 0000 [#1] PREEMPT SMP NOPTI\n\
                   Guest filesystem resize failed\n\
                   BusyBox guest ready\n";
        assert_eq!(
            crash_line(log).as_deref(),
            Some("kernel BUG at ../source/linux-6.12.94/fs/ext4/resize.c:547!")
        );
    }

    #[test]
    fn a_failed_resize_alone_is_found_and_a_clean_boot_is_not() {
        assert_eq!(
            crash_line("resize2fs: bad\nGuest filesystem resize failed\r\n").as_deref(),
            Some("Guest filesystem resize failed")
        );
        let clean = "[    0.209921] PCI: Using host bridge windows from ACPI; if necessary, use \"pci=nocrs\" and report a bug\n\
                     [    3.760645] mount (90) used greatest stack depth: 13600 bytes left\n\
                     [    4.063149] EXT4-fs (sda): resizing filesystem from 262144 to 4194304 blocks\n\
                     [    4.400000] EXT4-fs (sda): resized filesystem to 4194304\n\
                     BusyBox guest ready\n";
        assert_eq!(crash_line(clean), None);
    }

    #[test]
    fn a_missing_log_says_nothing() {
        assert_eq!(kernel_crash(Path::new("/nonexistent/serial.log")), None);
    }
}

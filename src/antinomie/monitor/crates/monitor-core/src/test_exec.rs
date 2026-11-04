// SPDX-License-Identifier: GPL-3.0-only
//! Test helper: make a freshly written fake tool safe to execute at once.
//!
//! A test that writes a script and runs it straight away races every other
//! test thread. `fs::write` opens the file for writing; if another thread
//! forks in that window, the child inherits the descriptor until it execs, and
//! the kernel refuses to exec the script meanwhile (ETXTBSY, "Text file
//! busy"). Writing to a temporary name and renaming does not help: the
//! inherited descriptor still points at the same inode. So after the write is
//! closed and the mode set, wait until the kernel stops reporting the file as
//! busy. No new writer can appear after the close, so once the wait ends the
//! file stays executable for the test.
use std::{
    fs,
    io::ErrorKind,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const ETXTBSY: i32 = 26;
const E2BIG: i32 = 7;

/// Set `mode` on a script that was just written and wait until it can be
/// executed. Use it in place of a bare `set_permissions` after `fs::write`.
pub(crate) fn make_executable(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    wait_until_executable(path);
}

/// Probe with an argument longer than the kernel allows: `execve` opens the
/// file (and fails ETXTBSY if a writer holds it) before it copies the
/// arguments, so a free file answers E2BIG and nothing ever runs.
fn wait_until_executable(path: &Path) {
    let huge = vec![b'x'; 200_000];
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let error = Command::new(path)
            .arg(std::ffi::OsStr::from_bytes(&huge))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .err();
        match error {
            Some(error) if error.raw_os_error() == Some(ETXTBSY) => {
                assert!(Instant::now() < deadline, "{}: {error}", path.display());
                std::thread::sleep(Duration::from_millis(5));
            }
            Some(error) if error.raw_os_error() == Some(E2BIG) => return,
            // The kernel answered something else (a bad interpreter, say):
            // it is no longer reporting the file busy, which is all we need.
            Some(error) if error.kind() != ErrorKind::Interrupted => return,
            Some(_) => {}
            None => return,
        }
    }
}

#[test]
fn a_file_held_open_for_writing_is_waited_for_not_run() {
    let dir = std::env::temp_dir().join(format!("ant-test-exec-{}", crate::storage::unique_id()));
    fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("ran");
    let path = dir.join("tool");
    fs::write(&path, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(writer);
    });
    let started = Instant::now();
    make_executable(&path, 0o755);
    assert!(started.elapsed() >= Duration::from_millis(150));
    release.join().unwrap();
    assert!(Command::new(&path).status().unwrap().success());
    assert!(marker.exists(), "only the real run touches the marker");
    let _ = fs::remove_dir_all(&dir);
}

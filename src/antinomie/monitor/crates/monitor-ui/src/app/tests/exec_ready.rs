// SPDX-License-Identifier: GPL-3.0-only
//! Make a freshly written fake tool safe to execute at once. Another test
//! thread that forks while the script is still open for writing leaves the
//! child holding that descriptor until it execs, and the kernel refuses to run
//! the script meanwhile (ETXTBSY). Renaming into place does not help (same
//! inode), so wait until the kernel stops reporting the file busy. The probe
//! passes an argument list too long to run: `execve` checks the file first and
//! answers E2BIG, so nothing executes.
use std::{
    ffi::OsStr,
    fs,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(super) fn make_executable(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    let huge = vec![b'x'; 200_000];
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let busy = Command::new(path)
            .arg(OsStr::from_bytes(&huge))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .err()
            .is_some_and(|error| error.raw_os_error() == Some(26));
        if !busy {
            return;
        }
        assert!(Instant::now() < deadline, "{} stayed busy", path.display());
        std::thread::sleep(Duration::from_millis(5));
    }
}

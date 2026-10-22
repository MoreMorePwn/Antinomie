// SPDX-License-Identifier: GPL-3.0-only
//! The minimal bubblewrap mount profile shared by every external tool that
//! reads attacker-influenced input (analysis workers, TShark).
//!
//! Only `/usr`, the merged-/usr links, a few read-only `/etc` entries, a
//! private `/etc/passwd`, a minimal `/dev`, `/proc` and a bounded tmpfs
//! `/tmp` exist inside. Host sockets (`/run`, X11, D-Bus), `/dev/shm`, mounts,
//! the home directory and the data directory are never visible; a caller adds
//! only the inputs a tool needs. Every namespace is unshared (network off).
use std::{path::Path, process::Command};

/// Read-only `/etc` entries bound when present and not symlinks.
const ETC: [&str; 4] = [
    "/etc/alternatives",
    "/etc/java-17-openjdk",
    "/etc/java-21-openjdk",
    "/etc/ld.so.cache",
];

/// Append the shared options up to and including the private `/tmp`.
///
/// `account` is bound over `/etc/passwd`; `extra_etc` lists further read-only
/// `/etc` paths (bound only when they exist); `tmp_size` bounds `/tmp`.
pub(crate) fn apply(cmd: &mut Command, account: &Path, extra_etc: &[&str], tmp_size: u64) {
    cmd.args([
        "--unshare-all",
        // A neutral host name: tools log it, and logs are kept.
        "--hostname",
        "analysis",
        "--unshare-user",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/usr",
        "/usr",
    ]);
    // Merged-/usr systems keep /bin, /sbin and /lib as links into /usr; tool
    // scripts start with #!/bin/sh, so recreate the links.
    for path in ["/bin", "/sbin", "/lib", "/lib64"] {
        if let Ok(target) = std::fs::read_link(path) {
            cmd.arg("--symlink").arg(target).arg(path);
        }
    }
    let mut binds = vec!["/lib", "/lib64"];
    binds.extend(ETC);
    binds.extend(extra_etc.iter().copied());
    for path in binds {
        if Path::new(path).exists() && std::fs::read_link(path).is_err() {
            cmd.arg("--ro-bind").arg(path).arg(path);
        }
    }
    cmd.arg("--ro-bind").arg(account).arg("/etc/passwd");
    cmd.args([
        "--proc",
        "/proc",
        "--dir",
        "/dev",
        "--dev-bind",
        "/dev/null",
        "/dev/null",
        "--dev-bind",
        "/dev/urandom",
        "/dev/urandom",
        "--dev-bind",
        "/dev/random",
        "/dev/random",
        "--symlink",
        "/proc/self/fd",
        "/dev/fd",
        "--symlink",
        "/proc/self/fd/0",
        "/dev/stdin",
        "--symlink",
        "/proc/self/fd/1",
        "/dev/stdout",
        "--symlink",
        "/proc/self/fd/2",
        "/dev/stderr",
        "--size",
    ]);
    cmd.arg(tmp_size.to_string()).args(["--tmpfs", "/tmp"]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_never_mounts_the_host_root_or_session_paths() {
        let mut cmd = Command::new("bwrap");
        apply(&mut cmd, Path::new("/dev/null"), &[], 4096);
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for flag in ["--unshare-all", "--disable-userns", "--die-with-parent"] {
            assert!(args.iter().any(|a| a == flag), "{flag}");
        }
        let binds: Vec<_> = args
            .windows(3)
            .filter(|w| w[0] == "--ro-bind" || w[0] == "--bind")
            .map(|w| w[1].as_str())
            .collect();
        assert!(binds.contains(&"/usr"));
        for forbidden in ["/", "/run", "/tmp", "/dev/shm", "/var", "/home", "/mnt"] {
            assert!(!binds.contains(&forbidden), "{forbidden}");
        }
    }
}

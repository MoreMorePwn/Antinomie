// SPDX-License-Identifier: GPL-3.0-only
//! What the route gateway needs from QEMU: the `stream` network backend
//! (QEMU 7.2 and newer) that connects a NIC to a local socket.
use std::{path::Path, process::Command};

/// Whether `qemu -netdev help` lists the `stream` backend.
pub(crate) fn lists_stream(help: &str) -> bool {
    help.lines().any(|line| line.trim() == "stream")
}

/// A Routed VM needs the `stream` backend; without it the VM does not start
/// (it never falls back to a NAT it was not set to).
pub fn require_qemu_support(qemu: &Path) -> Result<(), String> {
    let output = Command::new(qemu)
        .args(["-netdev", "help"])
        .output()
        .map_err(|e| format!("{}: {e}", qemu.display()))?;
    let text = String::from_utf8_lossy(&output.stdout);
    if lists_stream(&text) {
        Ok(())
    } else {
        Err(
            "a Routed network needs QEMU 7.2 or newer (the stream network backend); \
             this QEMU does not have it"
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_backend_is_found_in_the_help_text() {
        let help = "Available netdev backend types:\nsocket\nstream\ndgram\nuser\n";
        assert!(lists_stream(help));
        assert!(!lists_stream(
            "Available netdev backend types:\nsocket\nuser\n"
        ));
        assert!(!lists_stream("streamer\n"));
    }

    #[test]
    fn a_missing_qemu_is_an_error_not_a_pass() {
        assert!(require_qemu_support(Path::new("/nonexistent/qemu")).is_err());
    }
}

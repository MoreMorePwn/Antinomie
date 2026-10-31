// SPDX-License-Identifier: GPL-3.0-only
//! QEMU's own `stream` netdev against the gateway. QEMU is started with no
//! machine and no CPU (`-machine none`), paused: it only parses the network
//! options and connects, so no guest is booted and no RAM is used.
use super::scratch;
use crate::route::{Gateway, GatewayNet, require_qemu_support};
use std::{
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn qemu_connects_its_stream_netdev_to_the_gateway_socket() {
    let qemu = Path::new("qemu-system-x86_64");
    if require_qemu_support(qemu).is_err() {
        eprintln!("skipped: no QEMU with the stream network backend");
        return;
    }
    let dir = scratch("qemu");
    let net = GatewayNet::from_nat(&crate::stealth::NatNetwork::default()).unwrap();
    let gateway = Gateway::start(&dir, net).unwrap();
    assert!(!gateway.linked());
    let mut child = Command::new(qemu)
        .args([
            "-machine",
            "none",
            "-S",
            "-display",
            "none",
            "-nodefaults",
            "-monitor",
            "none",
        ])
        .args(["-serial", "none", "-netdev"])
        .arg(gateway.netdev_option().unwrap())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut linked = false;
    while Instant::now() < deadline {
        if gateway.linked() {
            linked = true;
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let exited = child.try_wait().unwrap();
    // Only this test's own child is stopped, by its handle.
    let _ = child.kill();
    let output = child.wait_with_output().unwrap();
    assert!(
        linked,
        "QEMU did not connect (exited: {exited:?}): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    // QEMU going away ends the link.
    let deadline = Instant::now() + Duration::from_secs(5);
    while gateway.linked() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(!gateway.linked());
    let _ = std::fs::remove_dir_all(dir);
}

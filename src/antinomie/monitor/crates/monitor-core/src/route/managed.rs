// SPDX-License-Identifier: GPL-3.0-only
//! wireproxy for the VPN route: a userspace WireGuard client that offers a
//! SOCKS5 port, so the route needs no root, no TUN device and no kernel
//! module. The program is the analyst's own (wireproxy is ISC licensed and
//! run as a separate process); Antinomie starts it with their configuration
//! file for a run and stops it when the route is released.
use super::config::WireproxyLaunch;
use std::{
    fs::OpenOptions,
    net::{TcpStream, ToSocketAddrs},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

/// A helper process that is killed (by its recorded handle) when dropped.
pub struct Managed {
    child: Child,
}

impl Managed {
    pub(super) fn new(child: Child) -> Self {
        Self { child }
    }

    pub(super) fn child_mut(&mut self) -> &mut Child {
        &mut self.child
    }

    #[cfg(test)]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl Drop for Managed {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn listening(host: &str, port: u16) -> bool {
    (host, port).to_socket_addrs().is_ok_and(|mut addresses| {
        addresses.any(|a| TcpStream::connect_timeout(&a, Duration::from_millis(300)).is_ok())
    })
}

/// Starts wireproxy and waits until its SOCKS port accepts connections.
/// `log_dir` receives `wireproxy.log` (owner-only).
pub(crate) fn start_wireproxy(
    launch: &WireproxyLaunch,
    socks: (&str, u16),
    log_dir: &Path,
    wait: Duration,
) -> Result<Managed, String> {
    // Whatever already listens there is not ours: using it would send the
    // run's traffic somewhere unknown.
    if listening(socks.0, socks.1) {
        return Err(format!(
            "VPN: something already listens on {}:{}; stop it or change BindAddress in the \
             wireproxy configuration",
            socks.0, socks.1
        ));
    }
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log_dir.join("wireproxy.log"))
        .map_err(|e| format!("VPN: wireproxy log: {e}"))?;
    let errors = log.try_clone().map_err(|e| format!("VPN: {e}"))?;
    let child = Command::new(&launch.binary)
        .arg("-c")
        .arg(&launch.config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errors))
        .spawn()
        .map_err(|e| format!("VPN: cannot start {}: {e}", launch.binary.display()))?;
    let mut managed = Managed { child };
    let deadline = Instant::now() + wait;
    loop {
        if let Some(status) = managed
            .child
            .try_wait()
            .map_err(|e| format!("VPN: wireproxy: {e}"))?
        {
            return Err(format!(
                "VPN: wireproxy stopped at once ({status}); see wireproxy.log in the VM's runtime folder"
            ));
        }
        if listening(socks.0, socks.1) {
            return Ok(managed);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "VPN: wireproxy did not open {}:{} within {} s",
                socks.0,
                socks.1,
                wait.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// How long a wireproxy start may take before the route is called down.
pub(crate) const WIREPROXY_WAIT: Duration = Duration::from_secs(15);
/// How long tor may take to bootstrap. A first start downloads the network
/// consensus, which is slow on a poor connection.
pub(crate) const TOR_WAIT: Duration = Duration::from_secs(120);

/// Starts what `spec` needs besides the connection itself: wireproxy for the
/// VPN route, or an own tor, whose port then becomes the route's SOCKS port.
/// `log_dir` holds wireproxy's log; `slot` names the tor's data folder.
/// Dropping the result stops the program.
pub(crate) fn start_for(
    spec: &mut super::RouteSpec,
    log_dir: &Path,
    slot: &str,
    waits: (Duration, Duration),
) -> Result<Option<Managed>, String> {
    if let Some(launch) = &spec.wireproxy {
        let super::config::Egress::Socks(proxy) = &spec.egress else {
            return Err("VPN route without a SOCKS port".into());
        };
        return start_wireproxy(launch, (&proxy.host, proxy.port), log_dir, waits.0).map(Some);
    }
    if let Some(launch) = spec.tor.clone() {
        let (managed, port) = super::tor::start_tor(&launch, slot, waits.1)?;
        spec.set_socks_port(port);
        return Ok(Some(managed));
    }
    Ok(None)
}

// SPDX-License-Identifier: GPL-3.0-only
//! The check that a route is up before the sample starts. A route that fails
//! it is not used: the run does not start, and nothing falls back to
//! another route.
use super::{
    config::{Egress, RouteSpec},
    socks::{self, Target},
};
use std::{
    net::{Ipv4Addr, TcpStream, ToSocketAddrs},
    time::Duration,
};

const CHECK_TIMEOUT: Duration = Duration::from_secs(15);

/// Checks `spec` end to end as far as it can be checked: a SOCKS route must
/// answer the SOCKS5 greeting and, when it has a check target, connect to it
/// (so a Tor without a circuit or a tunnel that is down fails here); external
/// INetSim must accept a connection. Built-in services, the host Internet
/// and Drop need no check.
pub(crate) fn check(spec: &RouteSpec) -> Result<(), String> {
    match &spec.egress {
        Egress::Drop | Egress::Direct { .. } => Ok(()),
        Egress::Sink(sink) => {
            let Some((host, offset)) = &sink.external else {
                return Ok(());
            };
            // INetSim runs the services it was configured with; any of the
            // common ones shows that it is there.
            let mut last = String::new();
            for port in [80u16, 25, 443, 53] {
                let Some(target) = port.checked_add(*offset) else {
                    continue;
                };
                let Some(address) = (host.as_str(), target)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut a| a.next())
                else {
                    last = format!("cannot resolve {host}");
                    continue;
                };
                match TcpStream::connect_timeout(&address, Duration::from_secs(2)) {
                    Ok(_) => return Ok(()),
                    Err(error) => last = format!("{host}:{target}: {error}"),
                }
            }
            Err(format!("InetSim is not answering ({last})"))
        }
        Egress::Socks(proxy) => match &spec.probe {
            None => socks::open(proxy, CHECK_TIMEOUT).map(|_| ()),
            Some((host, port)) => {
                let target = host
                    .parse::<Ipv4Addr>()
                    .map_or_else(|_| Target::Name(host.clone()), Target::Ip);
                socks::connect(proxy, &target, *port, CHECK_TIMEOUT).map(|_| ())
            }
        }
        .map_err(|error| format!("{} is not up: {error}", spec.kind.label())),
    }
}

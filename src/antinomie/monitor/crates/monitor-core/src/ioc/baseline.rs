// SPDX-License-Identifier: GPL-3.0-only
//! The base image's own traffic: clock sync, DHCP, package-index fetches. A
//! run's guest does these whatever the sample does, so the IOC list sets them
//! apart (under "base image noise") instead of listing them as the sample's.
//!
//! An indicator is noise when the process that made it is a base-image
//! program, or when no process could be named and it matches a known base
//! value. An indicator attributed to any other process is never noise, so a
//! sample that talks NTP itself keeps its row.
use super::indicator::{Indicator, Process, Type};

/// Programs the Debian base runs on its own: time sync, DHCP, apt and its
/// methods, the resolver, the network managers.
const PROGRAMS: &[&str] = &[
    "chronyd",
    "ntpd",
    "ntpdate",
    "systemd-timesyncd",
    "dhclient",
    "dhcpcd",
    "udhcpc",
    "NetworkManager",
    "systemd-networkd",
    "systemd-resolved",
    "nm-dispatcher",
    "apt",
    "apt-get",
    "apt-helper",
    "apt-check",
    "unattended-upgrade",
    "unattended-upgrades",
    "dpkg",
];
/// Directories whose programs are the base's (apt's download methods are
/// named `http`, `https`, `gpgv`).
const PROGRAM_DIRS: &[&str] = &["/usr/lib/apt/", "/usr/lib/systemd/", "/lib/systemd/"];
/// Name suffixes the base looks up: NTP pools and package archives.
const DOMAINS: &[&str] = &[
    "pool.ntp.org",
    "ntp.ubuntu.com",
    "time.cloudflare.com",
    "deb.debian.org",
    "security.debian.org",
    "ftp.debian.org",
    "ftp.us.debian.org",
    "debian.map.fastly.net",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "connectivity-check.ubuntu.com",
];
/// Endpoints (address, port) the base talks to under QEMU user networking:
/// the DHCP server and the broadcast address, from the DHCP client's port.
const ENDPOINTS: &[(&str, u16)] = &[
    ("10.0.2.2", 67),
    ("255.255.255.255", 67),
    ("10.0.2.2", 68),
    ("10.0.2.15", 68),
];

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Whether the process is one the base image runs.
pub fn base_program(process: &Process) -> bool {
    let name = process.name.trim();
    PROGRAMS.contains(&base_name(name)) || PROGRAM_DIRS.iter().any(|dir| name.starts_with(dir))
}

fn domain_noise(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    DOMAINS
        .iter()
        .any(|suffix| name == *suffix || name.ends_with(&format!(".{suffix}")))
}

/// The host part of an indicator's value, when it has one.
fn host(indicator: &Indicator) -> Option<String> {
    match indicator.ty {
        Type::Domain => Some(indicator.value.clone()),
        // `GET host/path`
        Type::Url => {
            let rest = indicator
                .value
                .split_once(' ')
                .map_or(indicator.value.as_str(), |x| x.1);
            let rest = rest.split_once("://").map_or(rest, |x| x.1);
            Some(rest.split(['/', ':']).next().unwrap_or("").to_owned())
        }
        Type::Tls => indicator
            .tls
            .as_ref()
            .map(|tls| tls.sni.clone())
            .filter(|sni| !sni.is_empty()),
        _ => None,
    }
}

/// Why a UDP endpoint is the base's: DHCP to the QEMU server, or NTP.
fn endpoint_noise(value: &str, udp: bool) -> Option<&'static str> {
    let (address, port) = value.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    if udp && port == 123 {
        return Some("NTP, the base image's clock sync");
    }
    ENDPOINTS
        .iter()
        .any(|(ip, known)| *ip == address && *known == port)
        .then_some("DHCP, the base image's address request")
}

/// Why the indicator is the base image's, or `None` when it is the run's.
pub fn noise(indicator: &Indicator) -> Option<String> {
    if !matches!(
        indicator.ty,
        Type::Endpoint | Type::Domain | Type::Url | Type::Tls
    ) {
        return None;
    }
    if let Some(process) = &indicator.process {
        return base_program(process)
            .then(|| format!("{} is part of the base image", process.name));
    }
    if !indicator.candidates.is_empty() {
        return indicator
            .candidates
            .iter()
            .all(base_program)
            .then(|| "made only by base image programs".to_owned());
    }
    match indicator.ty {
        Type::Endpoint => {
            endpoint_noise(&indicator.value, indicator.sub.starts_with("udp")).map(str::to_owned)
        }
        _ => host(indicator)
            .filter(|host| domain_noise(host))
            .map(|host| format!("{host} is looked up by the base image (clock sync, apt)")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::indicator::{Collector, Seen, Source, Via};
    use std::net::IpAddr;

    fn process(pid: u32, name: &str) -> Process {
        Process {
            pid,
            cookie: u64::from(pid),
            name: name.into(),
        }
    }

    fn seen(process: Option<Process>) -> Seen {
        Seen {
            time_us: Some(1),
            process,
            ..Seen::default()
        }
    }

    fn noise_of(all: &[Indicator], ty: Type, key: &str) -> Option<String> {
        all.iter()
            .find(|i| i.ty == ty && i.key == key)
            .unwrap_or_else(|| panic!("no {key}"))
            .noise
            .clone()
    }

    #[test]
    fn the_base_images_own_traffic_is_set_apart() {
        let mut c = Collector::default();
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        c.endpoint(ip("10.0.2.2"), 67, "udp", Source::Pcap, seen(None));
        c.endpoint(ip("203.0.113.9"), 123, "udp", Source::Pcap, seen(None));
        c.domain(
            "2.debian.pool.ntp.org",
            Via::Dns,
            &[],
            Source::Pcap,
            seen(None),
        );
        c.domain("deb.debian.org", Via::Dns, &[], Source::Pcap, seen(None));
        c.domain("c2.evil.example", Via::Dns, &[], Source::Pcap, seen(None));
        c.endpoint(ip("203.0.113.9"), 4444, "tcp", Source::Pcap, seen(None));
        let all = c.finish();
        assert!(
            noise_of(&all, Type::Endpoint, "10.0.2.2:67")
                .unwrap()
                .contains("DHCP")
        );
        assert!(
            noise_of(&all, Type::Endpoint, "203.0.113.9:123")
                .unwrap()
                .contains("NTP")
        );
        assert!(noise_of(&all, Type::Domain, "2.debian.pool.ntp.org").is_some());
        assert!(noise_of(&all, Type::Domain, "deb.debian.org").is_some());
        assert!(noise_of(&all, Type::Domain, "c2.evil.example").is_none());
        assert!(noise_of(&all, Type::Endpoint, "203.0.113.9:4444").is_none());
    }

    #[test]
    fn the_process_decides_before_the_value_does() {
        let mut c = Collector::default();
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        // The base's chronyd reaching an odd server is the base's.
        c.endpoint(
            ip,
            9999,
            "tcp",
            Source::Syscall,
            seen(Some(process(5, "/usr/sbin/chronyd"))),
        );
        // The sample asking the NTP port is its own traffic.
        c.endpoint(
            ip,
            123,
            "udp",
            Source::Syscall,
            seen(Some(process(900, "/tmp/.kd"))),
        );
        // Several processes, all the base's.
        let other: IpAddr = "198.51.100.1".parse().unwrap();
        for who in [
            process(6, "/usr/lib/apt/methods/http"),
            process(7, "apt-get"),
        ] {
            c.endpoint(other, 80, "tcp", Source::Syscall, seen(Some(who)));
        }
        let all = c.finish();
        assert!(noise_of(&all, Type::Endpoint, "203.0.113.9:9999").is_some());
        assert!(noise_of(&all, Type::Endpoint, "203.0.113.9:123").is_none());
        assert!(noise_of(&all, Type::Endpoint, "198.51.100.1:80").is_some());
    }
}

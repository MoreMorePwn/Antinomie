// SPDX-License-Identifier: GPL-3.0-only
//! Rules for sockets: who the program talks to, what it offers, and what it sends.
use super::super::sigma_events::Socket;
use super::super::*;
use super::ctx::{base, nr, Ctx};
use super::state::{Contact, State};
use super::tools;
use super::{Hit, Tier};
use std::net::IpAddr;

const NS: u64 = 1_000_000_000;
const SCAN: (u64, usize, usize) = (10 * NS, 20, 10);
const LOGINS: (u64, usize) = (60 * NS, 10);
const EXPLOIT_HOSTS: usize = 3;
const LOGIN_PORTS: &[u16] = &[22, 23, 2323];
const EXPLOIT_PORTS: &[u16] = &[
    2375, 2376, 6379, 7001, 8161, 61616, 9200, 10250, 11211, 27017,
];
const FLOOD_PER_SECOND: usize = 1000;
const UPLOAD_BYTES: u64 = 10 * 1024 * 1024;
const UPLOAD_FLOOR: u64 = 1024 * 1024;
const METADATA: &[&str] = &["169.254.169.254", "169.254.170.2", "fd00:ec2::254"];
/// VM housekeeping that listens or answers by itself: DHCP, NTP, mDNS and LLMNR.
const HOUSEKEEPING_PORTS: &[u16] = &[67, 68, 123, 5353, 5355];

pub(super) fn rules(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    shell_on_socket(cx, out);
    match cx.nr {
        nr::SOCKET => raw_socket(cx, out),
        nr::CONNECT => connect(cx, st, out),
        nr::BIND => bind(cx, out),
        nr::LISTEN => listen(cx, out),
        nr::SETSOCKOPT => filter(cx, out),
        nr::SENDTO | nr::SENDMSG | 307 | nr::WRITE | 20 | 45 | 47 | nr::READ | 19 | 299 => {
            traffic(cx, st, out)
        }
        _ => {}
    }
}

fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn parse(address: &super::super::sigma_events::Address) -> Option<(IpAddr, u16)> {
    Some((address.ip.parse().ok()?, address.port))
}

fn raw_socket(cx: &Ctx, out: &mut Vec<Hit>) {
    let domain = cx.args[0];
    let kind = cx.args[1] & 0xf;
    if domain == 17 || (matches!(domain, 2 | 10) && kind == 3) {
        let what = if domain == 17 {
            "a packet socket"
        } else {
            "a raw socket"
        };
        out.push(Hit::new(
            "network.raw_socket",
            what,
            format!("socket opens {what}"),
        ));
    }
}

/// Remember who reached an address, to tie packets of the capture to a task.
fn reached(cx: &Ctx, st: &mut State, ip: IpAddr, port: u16) {
    if st.contacted.len() < 65_536 {
        st.contacted.entry(ip).or_insert_with(|| Contact::of(cx));
    }
    if port == 53 && st.dns_task.is_none() {
        st.dns_task = Some(Contact::of(cx));
    }
}

/// A unix socket path, from a `sockaddr_un`.
fn unix_path(cx: &Ctx, argument: usize) -> Option<String> {
    let field = cx.field(argument, "")?;
    let bytes = trace::covered_preview(field);
    if bytes.len() < 3 || u16::from_le_bytes([bytes[0], bytes[1]]) != 1 {
        return None;
    }
    let tail = &bytes[2..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn connect(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if let Some(path) = unix_path(cx, 1) {
        if matches!(
            path.as_str(),
            "/var/run/docker.sock"
                | "/run/docker.sock"
                | "/run/containerd/containerd.sock"
                | "/run/podman/podman.sock"
                | "/var/run/crio/crio.sock"
        ) {
            out.push(Hit::new(
                "privilege.container_escape",
                &path,
                format!("connect to the container socket {path}"),
            ));
        }
        return;
    }
    let Some((ip, port)) = cx.address(1).as_ref().and_then(parse) else {
        return;
    };
    let time = cx.time();
    let target = format!("{ip}:{port}");
    reached(cx, st, ip, port);
    if METADATA.contains(&ip.to_string().as_str()) {
        out.push(Hit::new(
            "credential.cloud_metadata",
            &target,
            format!("connect to the instance metadata service {target}"),
        ));
    }
    if matches!(port, 9050 | 9051) && ip.is_loopback() {
        out.push(Hit::new(
            "network.tor",
            &target,
            format!("connect to {target}, the Tor SOCKS or control port"),
        ));
    }
    if matches!(port, 2375 | 2376) {
        out.push(Hit::new(
            "privilege.container_escape",
            &target,
            format!("connect to the container API at {target}"),
        ));
    }
    if matches!(port, 6667 | 6697) {
        out.push(Hit::new(
            "network.irc_c2",
            &target,
            format!("connect to {target}, an IRC port"),
        ));
    }
    if ip.is_loopback() {
        return;
    }
    let task = st.task(cx);
    task.connects.push(time, LOGINS.0, (ip, port));
    let recent: Vec<(IpAddr, u16)> = task.connects.items_since(time, SCAN.0).copied().collect();
    let pairs: std::collections::BTreeSet<_> = recent.iter().collect();
    let hosts_on_port = |wanted: u16| {
        recent
            .iter()
            .filter(|(_, p)| *p == wanted)
            .map(|(ip, _)| ip)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    };
    if !task.scan_done && (pairs.len() >= SCAN.1 || hosts_on_port(port) >= SCAN.2) {
        task.scan_done = true;
        out.push(Hit::new(
            "discovery.network_scan",
            "scan",
            format!(
                "{} address and port pairs tried within 10 s ({} hosts on port {port})",
                pairs.len(),
                hosts_on_port(port)
            ),
        ));
    }
    let logins = task
        .connects
        .items()
        .filter(|(_, p)| LOGIN_PORTS.contains(p))
        .count();
    if !task.login_done && LOGIN_PORTS.contains(&port) && logins >= LOGINS.1 {
        task.login_done = true;
        out.push(Hit::new(
            "lateral.bruteforce",
            "login ports",
            format!("{logins} connections to login ports within a minute"),
        ));
    }
    let exploited: std::collections::BTreeSet<_> = task
        .connects
        .items()
        .filter(|(_, p)| EXPLOIT_PORTS.contains(p))
        .map(|(ip, _)| *ip)
        .collect();
    if !task.exploit_done && EXPLOIT_PORTS.contains(&port) && exploited.len() >= EXPLOIT_HOSTS {
        task.exploit_done = true;
        out.push(Hit::new(
            "lateral.service_exploit",
            "services",
            format!(
                "commonly attacked service ports on {} hosts within a minute",
                exploited.len()
            ),
        ));
    }
    if port == 22 && task.ssh_hosts_read {
        out.push(Hit::new(
            "lateral.ssh_spread",
            &target,
            format!("connect to {target} after reading known hosts or keys"),
        ));
    }
}

fn bind(cx: &Ctx, out: &mut Vec<Hit>) {
    // A datagram socket on a fixed port of every interface.
    let Some((ip, port)) = cx.address(1).as_ref().and_then(parse) else {
        return;
    };
    let datagram = cx
        .socket(cx.args[0])
        .is_some_and(|socket| socket.is_datagram());
    if datagram && port != 0 && !ip.is_loopback() && !HOUSEKEEPING_PORTS.contains(&port) {
        out.push(Hit::new(
            "network.listen_any",
            format!("udp {ip}:{port}"),
            format!("bind to UDP {ip}:{port}"),
        ));
    }
}

fn listen(cx: &Ctx, out: &mut Vec<Hit>) {
    let Some(socket) = cx.socket(cx.args[0]) else {
        return;
    };
    let Some((ip, port)) = socket.bound else {
        return;
    };
    if !ip.is_loopback() && !HOUSEKEEPING_PORTS.contains(&port) {
        out.push(Hit::new(
            "network.listen_any",
            format!("tcp {ip}:{port}"),
            format!("listen on TCP {ip}:{port}"),
        ));
    }
}

/// `setsockopt(SO_ATTACH_FILTER)`; with a raw or packet socket it is the BPFDoor shape.
fn filter(cx: &Ctx, out: &mut Vec<Hit>) {
    if !(cx.args[1] == 1 && cx.args[2] == 26) {
        return;
    }
    out.push(Hit::new(
        "bpf.socket_filter",
        "SO_ATTACH_FILTER",
        "classic socket filter".into(),
    ));
    if cx.socket(cx.args[0]).is_some_and(|socket| socket.raw) {
        out.push(
            Hit::new(
                "c2.bpf_backdoor",
                "SO_ATTACH_FILTER",
                "a classic filter on a raw or packet socket".into(),
            )
            .detail("A raw socket with a filter that waits for one packet is how BPFDoor listens."),
        );
    }
}

/// Bytes sent or received on a socket, and what they say.
fn traffic(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    let Some(socket) = cx.socket(cx.args[0]) else {
        elf_to_file(cx, st, out);
        return;
    };
    let sending = matches!(cx.nr, nr::SENDTO | nr::SENDMSG | 307 | nr::WRITE | 20);
    let size = cx.ret.filter(|ret| *ret > 0).map_or(0, |ret| ret as u64);
    let remote = socket.peer.is_some_and(|(ip, _)| !private(ip));
    let time = cx.time();
    let task = st.task(cx);
    task.active = true;
    if remote {
        if sending {
            task.sent = task.sent.saturating_add(size);
        } else {
            task.received = task.received.saturating_add(size);
        }
        if !task.upload_done
            && task.sent >= UPLOAD_FLOOR
            && (task.sent >= UPLOAD_BYTES || task.sent >= 10 * task.received)
        {
            task.upload_done = true;
            out.push(Hit::new(
                "exfil.large_upload",
                "upload",
                format!(
                    "{} bytes sent to the network, {} received",
                    task.sent, task.received
                ),
            ));
        }
    }
    if sending {
        let destination = socket
            .peer
            .or_else(|| cx.address(4).as_ref().and_then(parse));
        if let Some((ip, _)) = destination {
            task.flood.push(time, NS, ip);
            let same = task.flood.items().filter(|other| **other == ip).count();
            if !task.flood_done && same > FLOOD_PER_SECOND {
                task.flood_done = true;
                out.push(Hit::new(
                    "impact.ddos_flood",
                    ip.to_string(),
                    format!("{same} packets within a second to {ip}"),
                ));
            }
        }
        let bytes = cx.payload(false);
        if !bytes.is_empty() {
            content(&bytes, socket, out);
        }
    } else if cx.ok {
        let bytes = cx.payload(true);
        if bytes.starts_with(b"\x7fELF") {
            st.task(cx).net_elf = true;
        }
    }
}

/// What a payload sent to a server says about the program.
fn content(bytes: &[u8], socket: &Socket, out: &mut Vec<Hit>) {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(2048)]).into_owned();
    let lower = text.to_ascii_lowercase();
    let endpoint = socket
        .peer
        .map_or_else(|| "a socket".into(), |(ip, port)| format!("{ip}:{port}"));
    if ["nick ", "user ", "join #", "privmsg "]
        .iter()
        .any(|word| lower.starts_with(word))
    {
        out.push(Hit::new(
            "network.irc_c2",
            &endpoint,
            format!("IRC commands sent to {endpoint}"),
        ));
    }
    let stratum = (lower.contains("\"method\"")
        && lower.contains("\"login\"")
        && (lower.contains("\"agent\"")
            || lower.contains("\"rig-id\"")
            || lower.contains("\"pass\"")))
        || lower.contains("mining.subscribe")
        || lower.contains("mining.authorize");
    if stratum {
        out.push(Hit::new(
            "impact.miner",
            &endpoint,
            format!("Stratum mining protocol sent to {endpoint}"),
        ));
    }
}

/// An ELF image that came off a socket and is now written to a file.
fn elf_to_file(cx: &Ctx, st: &mut State, out: &mut Vec<Hit>) {
    if cx.nr != nr::WRITE || !cx.ok || !st.task(cx).net_elf {
        return;
    }
    let Some(path) = cx.fd_path(cx.args[0]).filter(|path| path.starts_with('/')) else {
        return;
    };
    if cx.payload(false).starts_with(b"\x7fELF") {
        st.task(cx).net_elf = false;
        out.push(Hit::new(
            "c2.elf_download",
            path,
            format!("an ELF image received from the network is written to {path}"),
        ));
    }
}

/// A socket on descriptors 0 and 1 when a shell or interpreter starts: a remote shell.
fn shell_on_socket(cx: &Ctx, out: &mut Vec<Hit>) {
    if !cx.is_exec() {
        return;
    }
    let Some(path) = cx.exec_path() else { return };
    if tools::interpreter(base(&path)).is_none() {
        return;
    }
    let sockets: Vec<&Socket> = (0..3).filter_map(|fd| cx.socket(fd)).collect();
    if sockets.len() < 2 || cx.socket(0).is_none() || cx.socket(1).is_none() {
        return;
    }
    let connected = sockets
        .iter()
        .find(|socket| socket.peer.is_some() && !socket.accepted);
    let accepted = sockets.iter().find(|socket| socket.accepted);
    if let Some(socket) = connected {
        let peer = socket
            .peer
            .map_or_else(String::new, |(ip, port)| format!("{ip}:{port}"));
        out.push(
            Hit::new(
                "c2.reverse_shell",
                &peer,
                format!("{path} started with a connection to {peer} as its input and output"),
            )
            .detail("The descriptors 0 and 1 are the connected socket."),
        );
    } else if let Some(socket) = accepted {
        let peer = socket
            .peer
            .map_or_else(|| "a client".into(), |(ip, port)| format!("{ip}:{port}"));
        out.push(
            Hit::new(
                "c2.bind_shell",
                &peer,
                format!(
                    "{path} started with a client connection from {peer} as its input and output"
                ),
            )
            .detail("The descriptors 0 and 1 are an accepted socket."),
        );
    }
    let _ = Tier::High;
}

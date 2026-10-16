// SPDX-License-Identifier: MIT
//! One-line packet summaries for the packet list.
use super::*;

pub(super) fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(super) fn ipv4(bytes: &[u8]) -> String {
    ipv4_addr(bytes).to_string()
}

pub(super) fn ipv4_addr(bytes: &[u8]) -> IpAddr {
    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into()
}

pub(super) fn ipv6_addr(bytes: &[u8]) -> IpAddr {
    let octets: [u8; 16] = bytes.try_into().expect("16 bytes");
    std::net::Ipv6Addr::from(octets).into()
}

pub(super) fn ipv6(bytes: &[u8]) -> String {
    ipv6_addr(bytes).to_string()
}

/// A packet summary without its place in the file.
pub(super) fn summary(
    source: String,
    destination: String,
    protocol: &str,
    info: String,
) -> NetworkPacket {
    NetworkPacket {
        source,
        destination,
        protocol: protocol.into(),
        info,
        ..NetworkPacket::default()
    }
}

/// Source, destination, protocol, a one-line description and the addresses
/// and ports of a frame (the returned packet's other fields are zero).
pub fn describe(frame: &[u8]) -> NetworkPacket {
    let Some(mut ethertype) = u16_be(frame, 12) else {
        return summary(
            String::new(),
            String::new(),
            "Ethernet",
            "truncated frame".into(),
        );
    };
    let mut at = 14;
    if ethertype == 0x8100 {
        ethertype = u16_be(frame, 16).unwrap_or(0);
        at = 18;
    }
    let payload = &frame[at.min(frame.len())..];
    let source_mac = frame.get(6..12).map(mac).unwrap_or_default();
    let destination_mac = frame.get(..6).map(mac).unwrap_or_default();
    match ethertype {
        0x0806 => {
            let info = match (u16_be(payload, 6), payload.get(14..18), payload.get(24..28)) {
                (Some(1), Some(sender), Some(target)) => {
                    format!("Who has {}? Tell {}", ipv4(target), ipv4(sender))
                }
                (Some(2), Some(sender), _) => format!(
                    "{} is at {}",
                    ipv4(sender),
                    payload.get(8..14).map(mac).unwrap_or_default()
                ),
                _ => "ARP".into(),
            };
            summary(source_mac, destination_mac, "ARP", info)
        }
        0x0800 if payload.len() >= 20 => {
            let header_len = usize::from(payload[0] & 0x0f) * 4;
            let total = usize::from(u16_be(payload, 2).unwrap_or(0)).min(payload.len());
            if payload[0] >> 4 != 4 || header_len < 20 || header_len > total {
                return summary(
                    source_mac,
                    destination_mac,
                    "IPv4",
                    "invalid or truncated IPv4 header".into(),
                );
            }
            let body = payload
                .get(header_len..total.max(header_len))
                .unwrap_or(&[]);
            let fragment = u16_be(payload, 6).unwrap_or(0) & 0x1fff;
            let (source, destination) = (ipv4_addr(&payload[12..16]), ipv4_addr(&payload[16..20]));
            if fragment != 0 {
                return NetworkPacket {
                    src_ip: Some(source),
                    dst_ip: Some(destination),
                    ..summary(
                        source.to_string(),
                        destination.to_string(),
                        "IPv4",
                        "fragment".into(),
                    )
                };
            }
            transport(payload[9], body, source, destination)
        }
        0x86dd if payload.len() >= 40 => {
            let (source, destination) = (ipv6_addr(&payload[8..24]), ipv6_addr(&payload[24..40]));
            let length = usize::from(u16_be(payload, 4).unwrap_or(0));
            let mut body = &payload[40..(40 + length).min(payload.len())];
            // Skip extension headers: hop-by-hop, routing, destination
            // options, fragment and authentication.
            let mut next = payload[6];
            for _ in 0..8 {
                if next == 44 && u16_be(body, 2).is_some_and(|flags| flags & 0xfff8 != 0) {
                    return NetworkPacket {
                        src_ip: Some(source),
                        dst_ip: Some(destination),
                        ..summary(
                            source.to_string(),
                            destination.to_string(),
                            "IPv6",
                            "fragment".into(),
                        )
                    };
                }
                let skip = match next {
                    0 | 43 | 60 => body.get(1).map(|len| (usize::from(*len) + 1) * 8),
                    44 => Some(8),
                    51 => body.get(1).map(|len| (usize::from(*len) + 2) * 4),
                    _ => break,
                };
                match (body.first(), skip.and_then(|skip| body.get(skip..))) {
                    (Some(&header), Some(rest)) => {
                        next = header;
                        body = rest;
                    }
                    _ => break,
                }
            }
            transport(next, body, source, destination)
        }
        other => summary(
            source_mac,
            destination_mac,
            &format!("0x{other:04x}"),
            format!("Ethernet type 0x{other:04x}"),
        ),
    }
}

/// "10.0.2.15:5353", "[fe80::1]:5353".
pub(super) fn endpoint(address: IpAddr, port: u16) -> String {
    match address {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("[{address}]:{port}"),
    }
}

pub(super) fn transport(
    protocol: u8,
    body: &[u8],
    source: IpAddr,
    destination: IpAddr,
) -> NetworkPacket {
    let addressed = |packet: NetworkPacket| NetworkPacket {
        src_ip: Some(source),
        dst_ip: Some(destination),
        ..packet
    };
    match protocol {
        6 if body.len() >= 20 => {
            let (sport, dport) = (u16_be(body, 0).unwrap_or(0), u16_be(body, 2).unwrap_or(0));
            let flags = body[13];
            let names: Vec<_> = [
                (TCP_SYN, "SYN"),
                (0x10, "ACK"),
                (0x08, "PSH"),
                (TCP_FIN, "FIN"),
                (TCP_RST, "RST"),
            ]
            .iter()
            .filter(|(bit, _)| flags & bit != 0)
            .map(|(_, name)| *name)
            .collect();
            let seq = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
            let data = body.get(usize::from(body[12] >> 4) * 4..).unwrap_or(&[]);
            let (protocol, info) = if let Some(host) = tls_server_name(data) {
                ("TLS", format!("Client Hello, SNI {host}"))
            } else if let Some(line) = http_line(data) {
                ("HTTP", line)
            } else {
                (
                    "TCP",
                    format!(
                        "{sport} → {dport} [{}] len {}",
                        names.join(", "),
                        data.len()
                    ),
                )
            };
            addressed(NetworkPacket {
                src_port: Some(sport),
                dst_port: Some(dport),
                tcp_flags: Some(flags),
                tcp_seq: Some(seq),
                ..summary(
                    endpoint(source, sport),
                    endpoint(destination, dport),
                    protocol,
                    info,
                )
            })
        }
        17 if body.len() >= 8 => {
            let (sport, dport) = (u16_be(body, 0).unwrap_or(0), u16_be(body, 2).unwrap_or(0));
            let data = &body[8..];
            let (protocol, info) = if sport == 53 || dport == 53 {
                ("DNS", dns(data))
            } else if matches!((sport, dport), (67, 68) | (68, 67)) {
                ("DHCP", "DHCP".to_owned())
            } else {
                ("UDP", format!("{sport} → {dport} len {}", data.len()))
            };
            addressed(NetworkPacket {
                src_port: Some(sport),
                dst_port: Some(dport),
                ..summary(
                    endpoint(source, sport),
                    endpoint(destination, dport),
                    protocol,
                    info,
                )
            })
        }
        1 | 58 => {
            let kind = body.first().copied().unwrap_or(0);
            let info = match (protocol, kind) {
                (1, 8) | (58, 128) => "Echo request".into(),
                (1, 0) | (58, 129) => "Echo reply".into(),
                (1, 3) | (58, 1) => "Destination unreachable".into(),
                (58, 133..=137) => "Neighbor discovery".into(),
                (58, 130 | 131 | 132 | 143) => "Multicast listener report or query".into(),
                _ => format!("type {kind}"),
            };
            let name = if protocol == 1 { "ICMP" } else { "ICMPv6" };
            addressed(summary(
                source.to_string(),
                destination.to_string(),
                name,
                info,
            ))
        }
        other => addressed(summary(
            source.to_string(),
            destination.to_string(),
            &format!("IP {other}"),
            format!("protocol {other}"),
        )),
    }
}

/// "standard query A example.com" / "response A example.com → 93.184.216.34".
pub(super) fn dns(data: &[u8]) -> String {
    let (Some(flags), Some(questions)) = (u16_be(data, 2), u16_be(data, 4)) else {
        return "DNS".into();
    };
    let response = flags & 0x8000 != 0;
    let mut at = 12;
    let mut name = Vec::new();
    while let Some(&len) = data.get(at) {
        if len == 0 || len & 0xc0 != 0 || name.len() > 32 {
            at += if len & 0xc0 != 0 { 2 } else { 1 };
            break;
        }
        let label = data.get(at + 1..at + 1 + usize::from(len)).unwrap_or(&[]);
        name.push(String::from_utf8_lossy(label).into_owned());
        at += 1 + usize::from(len);
    }
    let kind = dns_type(u16_be(data, at).unwrap_or(0));
    let name = name.join(".");
    if questions == 0 {
        return if response {
            "response".into()
        } else {
            "query".into()
        };
    }
    if !response {
        return format!("query {kind} {name}");
    }
    if flags & 0x000f != 0 {
        return format!("response {kind} {name}: error {}", flags & 0x000f);
    }
    // First answer address, when the answer starts with a compressed name.
    at += 4;
    let answers = u16_be(data, 6).unwrap_or(0);
    let mut addresses = Vec::new();
    for _ in 0..answers.min(8) {
        if data.get(at).is_some_and(|b| b & 0xc0 == 0xc0) {
            at += 2;
        } else {
            break;
        }
        let (kind, len) = (
            u16_be(data, at).unwrap_or(0),
            usize::from(u16_be(data, at + 8).unwrap_or(0)),
        );
        let value = data.get(at + 10..at + 10 + len).unwrap_or(&[]);
        match (kind, value.len()) {
            (1, 4) => addresses.push(ipv4(value)),
            (28, 16) => addresses.push(ipv6(value)),
            _ => {}
        }
        at += 10 + len;
    }
    if addresses.is_empty() {
        format!("response {kind} {name}")
    } else {
        format!("response {kind} {name} → {}", addresses.join(", "))
    }
}

/// "A", "AAAA", ..., or "type 99".
pub(super) fn dns_type(kind: u16) -> String {
    match kind {
        1 => "A".to_owned(),
        2 => "NS".to_owned(),
        28 => "AAAA".to_owned(),
        5 => "CNAME".to_owned(),
        6 => "SOA".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        12 => "PTR".to_owned(),
        33 => "SRV".to_owned(),
        41 => "OPT".to_owned(),
        65 => "HTTPS".to_owned(),
        other => format!("type {other}"),
    }
}

pub(super) fn http_line(data: &[u8]) -> Option<String> {
    let line = data.split(|b| *b == b'\r' || *b == b'\n').next()?;
    let text = std::str::from_utf8(line).ok()?;
    let method = text.split(' ').next()?;
    (matches!(
        method,
        "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "OPTIONS" | "PATCH" | "CONNECT"
    ) || text.starts_with("HTTP/1."))
    .then(|| text.chars().take(160).collect())
}

/// Server name from a TLS ClientHello in this segment, if it carries one.
fn tls_server_name(data: &[u8]) -> Option<String> {
    let (at, len) = tls_sni(data)?;
    Some(String::from_utf8_lossy(&data[at..at + len]).into_owned())
}

/// Offset and length of the server name in a TLS ClientHello.
pub(super) fn tls_sni(data: &[u8]) -> Option<(usize, usize)> {
    // Record: handshake (22), then ClientHello (1).
    if data.first() != Some(&22) || data.get(5) != Some(&1) {
        return None;
    }
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(*data.get(at)?);
    at += 2 + usize::from(u16_be(data, at)?);
    at += 1 + usize::from(*data.get(at)?);
    let end = (at + 2 + usize::from(u16_be(data, at)?)).min(data.len());
    at += 2;
    while at + 4 <= end {
        let (kind, len) = (u16_be(data, at)?, usize::from(u16_be(data, at + 2)?));
        if kind == 0 {
            // server_name list: u16 list length, u8 type, u16 name length, name.
            let name_len = usize::from(u16_be(data, at + 7)?);
            data.get(at + 9..at + 9 + name_len)?;
            return Some((at + 9, name_len));
        }
        at += 4 + len;
    }
    None
}

// SPDX-License-Identifier: MIT
//! Layer-by-layer packet dissection for the Details pane.
use super::*;

mod application;

use self::application::*;
// The DNS decoders also read reassembled TCP DNS messages.
pub(in crate::network) use self::application::{dns_class, dns_name};

impl PacketLayer {
    fn new(name: &str, summary: impl Into<String>, start: usize, len: usize) -> Self {
        PacketLayer {
            name: name.into(),
            summary: summary.into(),
            start,
            len,
            fields: Vec::new(),
        }
    }

    fn add(
        &mut self,
        name: &str,
        value: impl Into<String>,
        kind: FieldKind,
        start: usize,
        len: usize,
    ) {
        self.push(0, name, value.into(), kind, start, len);
    }

    /// A part of the previous field (a flag bit, a record's detail).
    fn sub(
        &mut self,
        name: &str,
        value: impl Into<String>,
        kind: FieldKind,
        start: usize,
        len: usize,
    ) {
        self.push(1, name, value.into(), kind, start, len);
    }

    fn push(
        &mut self,
        depth: u8,
        name: &str,
        value: String,
        kind: FieldKind,
        start: usize,
        len: usize,
    ) {
        self.fields.push(PacketField {
            name: name.into(),
            value,
            kind,
            start,
            len,
            depth,
        });
    }
}

pub(super) fn u32_be(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?))
}

/// "0x0800 (IPv4)".
fn ethertype_name(ethertype: u16) -> String {
    let name = match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86dd => "IPv6",
        0x8100 => "802.1Q VLAN",
        _ => return format!("0x{ethertype:04x}"),
    };
    format!("{name} (0x{ethertype:04x})")
}

fn ip_protocol_name(protocol: u8) -> String {
    let name = match protocol {
        0 => "Hop-by-hop options",
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        43 => "Routing",
        44 => "Fragment",
        50 => "ESP",
        51 => "Authentication",
        58 => "ICMPv6",
        59 => "No next header",
        60 => "Destination options",
        _ => return protocol.to_string(),
    };
    format!("{name} ({protocol})")
}

/// The decoded layers of a frame, outermost first. Every field's byte range
/// lies inside the frame; a truncated or unknown part ends as a Data layer.
pub fn dissect(frame: &[u8]) -> Vec<PacketLayer> {
    let mut layers = Vec::new();
    let Some(mut ethertype) = u16_be(frame, 12) else {
        let mut layer = PacketLayer::new("Ethernet", "truncated frame", 0, frame.len());
        layer.add(
            "Bytes",
            format!("{} of at least 14", frame.len()),
            FieldKind::Number,
            0,
            frame.len(),
        );
        layers.push(layer);
        return layers;
    };
    let (destination, source) = (mac(&frame[..6]), mac(&frame[6..12]));
    let mut ethernet = PacketLayer::new(
        "Ethernet II",
        format!("Src {source}, Dst {destination}"),
        0,
        14,
    );
    ethernet.add("Destination", destination, FieldKind::Address, 0, 6);
    ethernet.add("Source", source, FieldKind::Address, 6, 6);
    let mut at = 14;
    if ethertype == 0x8100 {
        if let (Some(tag), Some(inner)) = (u16_be(frame, 14), u16_be(frame, 16)) {
            ethernet.add("Type", ethertype_name(ethertype), FieldKind::Name, 12, 2);
            ethernet.add(
                "VLAN ID",
                (tag & 0x0fff).to_string(),
                FieldKind::Number,
                14,
                2,
            );
            ethertype = inner;
            at = 18;
            ethernet.len = 18;
            ethernet.add("Type", ethertype_name(ethertype), FieldKind::Name, 16, 2);
        }
    } else {
        ethernet.add("Type", ethertype_name(ethertype), FieldKind::Name, 12, 2);
    }
    layers.push(ethernet);
    let end = frame.len();
    match ethertype {
        0x0806 => arp_layer(frame, at, &mut layers),
        0x0800 => ipv4_layer(frame, at, &mut layers),
        0x86dd => ipv6_layer(frame, at, &mut layers),
        _ => data_layer(frame, at, end, &mut layers),
    }
    layers
}

/// The rest of the frame as raw data.
fn data_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
    let end = end.min(frame.len());
    if start >= end {
        return;
    }
    let bytes = &frame[start..end];
    let mut layer = PacketLayer::new("Data", format!("{} bytes", bytes.len()), start, bytes.len());
    let preview: Vec<_> = bytes.iter().take(24).map(|b| format!("{b:02x}")).collect();
    let more = if bytes.len() > 24 { "…" } else { "" };
    layer.add(
        "Data",
        format!("{}{more}", preview.join("")),
        FieldKind::Bytes,
        start,
        bytes.len(),
    );
    layer.add(
        "Length",
        bytes.len().to_string(),
        FieldKind::Number,
        start,
        bytes.len(),
    );
    layers.push(layer);
}

fn arp_layer(frame: &[u8], at: usize, layers: &mut Vec<PacketLayer>) {
    let payload = &frame[at.min(frame.len())..];
    if payload.len() < 28 {
        data_layer(frame, at, frame.len(), layers);
        return;
    }
    let opcode = u16_be(payload, 6).unwrap_or(0);
    let (sender, target) = (ipv4(&payload[14..18]), ipv4(&payload[24..28]));
    let summary = match opcode {
        1 => format!("Who has {target}? Tell {sender}"),
        2 => format!("{sender} is at {}", mac(&payload[8..14])),
        _ => format!("opcode {opcode}"),
    };
    let mut layer = PacketLayer::new("Address Resolution Protocol", summary, at, 28);
    let hardware = u16_be(payload, 0).unwrap_or(0);
    layer.add(
        "Hardware type",
        if hardware == 1 {
            "Ethernet (1)".into()
        } else {
            hardware.to_string()
        },
        FieldKind::Name,
        at,
        2,
    );
    layer.add(
        "Protocol type",
        ethertype_name(u16_be(payload, 2).unwrap_or(0)),
        FieldKind::Name,
        at + 2,
        2,
    );
    layer.add(
        "Hardware size",
        payload[4].to_string(),
        FieldKind::Number,
        at + 4,
        1,
    );
    layer.add(
        "Protocol size",
        payload[5].to_string(),
        FieldKind::Number,
        at + 5,
        1,
    );
    layer.add(
        "Opcode",
        match opcode {
            1 => "request (1)".into(),
            2 => "reply (2)".into(),
            other => other.to_string(),
        },
        FieldKind::Name,
        at + 6,
        2,
    );
    layer.add(
        "Sender MAC address",
        mac(&payload[8..14]),
        FieldKind::Address,
        at + 8,
        6,
    );
    layer.add("Sender IP address", sender, FieldKind::Address, at + 14, 4);
    layer.add(
        "Target MAC address",
        mac(&payload[18..24]),
        FieldKind::Address,
        at + 18,
        6,
    );
    layer.add("Target IP address", target, FieldKind::Address, at + 24, 4);
    layers.push(layer);
}

fn ipv4_layer(frame: &[u8], at: usize, layers: &mut Vec<PacketLayer>) {
    let payload = &frame[at.min(frame.len())..];
    let header_len = payload.first().map_or(0, |b| usize::from(b & 0x0f) * 4);
    if payload.len() < 20 || payload[0] >> 4 != 4 || header_len < 20 || header_len > payload.len() {
        let mut layer = PacketLayer::new(
            "Internet Protocol Version 4",
            "invalid or truncated header",
            at,
            payload.len(),
        );
        layer.add(
            "Bytes",
            payload.len().to_string(),
            FieldKind::Number,
            at,
            payload.len(),
        );
        layers.push(layer);
        return;
    }
    let total = usize::from(u16_be(payload, 2).unwrap_or(0));
    let end = at + total.clamp(header_len, payload.len());
    let (source, destination) = (ipv4_addr(&payload[12..16]), ipv4_addr(&payload[16..20]));
    let mut layer = PacketLayer::new(
        "Internet Protocol Version 4",
        format!("Src {source}, Dst {destination}"),
        at,
        header_len,
    );
    layer.add("Version", "4", FieldKind::Number, at, 1);
    layer.add(
        "Header length",
        format!("{header_len} bytes ({})", header_len / 4),
        FieldKind::Number,
        at,
        1,
    );
    layer.add(
        "Differentiated services",
        format!(
            "0x{:02x} (DSCP {}, ECN {})",
            payload[1],
            payload[1] >> 2,
            payload[1] & 3
        ),
        FieldKind::Flags,
        at + 1,
        1,
    );
    layer.add(
        "Total length",
        total.to_string(),
        FieldKind::Number,
        at + 2,
        2,
    );
    let id = u16_be(payload, 4).unwrap_or(0);
    layer.add(
        "Identification",
        format!("0x{id:04x} ({id})"),
        FieldKind::Number,
        at + 4,
        2,
    );
    let flags = u16_be(payload, 6).unwrap_or(0);
    let mut names = Vec::new();
    if flags & 0x4000 != 0 {
        names.push("Don't fragment");
    }
    if flags & 0x2000 != 0 {
        names.push("More fragments");
    }
    layer.add(
        "Flags",
        format!(
            "0x{:x}{}",
            flags >> 13,
            if names.is_empty() {
                String::new()
            } else {
                format!(", {}", names.join(", "))
            }
        ),
        FieldKind::Flags,
        at + 6,
        2,
    );
    let fragment = flags & 0x1fff;
    layer.add(
        "Fragment offset",
        (usize::from(fragment) * 8).to_string(),
        FieldKind::Number,
        at + 6,
        2,
    );
    layer.add(
        "Time to live",
        payload[8].to_string(),
        FieldKind::Number,
        at + 8,
        1,
    );
    layer.add(
        "Protocol",
        ip_protocol_name(payload[9]),
        FieldKind::Name,
        at + 9,
        1,
    );
    layer.add(
        "Header checksum",
        format!("0x{:04x}", u16_be(payload, 10).unwrap_or(0)),
        FieldKind::Number,
        at + 10,
        2,
    );
    layer.add(
        "Source address",
        source.to_string(),
        FieldKind::Address,
        at + 12,
        4,
    );
    layer.add(
        "Destination address",
        destination.to_string(),
        FieldKind::Address,
        at + 16,
        4,
    );
    if header_len > 20 {
        layer.add(
            "Options",
            format!("{} bytes", header_len - 20),
            FieldKind::Bytes,
            at + 20,
            header_len - 20,
        );
    }
    layers.push(layer);
    if fragment != 0 {
        data_layer(frame, at + header_len, end, layers);
        return;
    }
    transport_layer(frame, payload[9], at + header_len, end, layers);
}

fn ipv6_layer(frame: &[u8], at: usize, layers: &mut Vec<PacketLayer>) {
    let payload = &frame[at.min(frame.len())..];
    if payload.len() < 40 || payload[0] >> 4 != 6 {
        let mut layer = PacketLayer::new(
            "Internet Protocol Version 6",
            "invalid or truncated header",
            at,
            payload.len(),
        );
        layer.add(
            "Bytes",
            payload.len().to_string(),
            FieldKind::Number,
            at,
            payload.len(),
        );
        layers.push(layer);
        return;
    }
    let (source, destination) = (ipv6_addr(&payload[8..24]), ipv6_addr(&payload[24..40]));
    let length = usize::from(u16_be(payload, 4).unwrap_or(0));
    let end = at + 40 + length.min(payload.len() - 40);
    let mut layer = PacketLayer::new(
        "Internet Protocol Version 6",
        format!("Src {source}, Dst {destination}"),
        at,
        40,
    );
    let first = u32_be(payload, 0).unwrap_or(0);
    layer.add("Version", "6", FieldKind::Number, at, 1);
    layer.add(
        "Traffic class",
        format!("0x{:02x}", (first >> 20) & 0xff),
        FieldKind::Flags,
        at,
        2,
    );
    layer.add(
        "Flow label",
        format!("0x{:05x}", first & 0xfffff),
        FieldKind::Number,
        at + 1,
        3,
    );
    layer.add(
        "Payload length",
        length.to_string(),
        FieldKind::Number,
        at + 4,
        2,
    );
    layer.add(
        "Next header",
        ip_protocol_name(payload[6]),
        FieldKind::Name,
        at + 6,
        1,
    );
    layer.add(
        "Hop limit",
        payload[7].to_string(),
        FieldKind::Number,
        at + 7,
        1,
    );
    layer.add(
        "Source address",
        source.to_string(),
        FieldKind::Address,
        at + 8,
        16,
    );
    layer.add(
        "Destination address",
        destination.to_string(),
        FieldKind::Address,
        at + 24,
        16,
    );
    // Extension headers, as in `describe`.
    let mut next = payload[6];
    let mut position = at + 40;
    for _ in 0..8 {
        let header = &frame[position..end];
        if next == 44 && header.len() >= 8 {
            layer.add(
                "Fragment header",
                format!(
                    "offset {}, next {}",
                    usize::from(u16_be(header, 2).unwrap_or(0) >> 3) * 8,
                    ip_protocol_name(header[0])
                ),
                FieldKind::Name,
                position,
                8,
            );
            layer.len = position + 8 - at;
            if u16_be(header, 2).is_some_and(|flags| flags & 0xfff8 != 0) {
                layers.push(layer);
                data_layer(frame, position + 8, end, layers);
                return;
            }
        }
        let skip = match next {
            0 | 43 | 60 => header.get(1).map(|len| (usize::from(*len) + 1) * 8),
            44 => Some(8),
            51 => header.get(1).map(|len| (usize::from(*len) + 2) * 4),
            _ => break,
        };
        match (header.first(), skip.filter(|skip| *skip <= header.len())) {
            (Some(&following), Some(skip)) => {
                if next != 44 {
                    layer.add(
                        "Extension header",
                        format!("{}, {skip} bytes", ip_protocol_name(next)),
                        FieldKind::Name,
                        position,
                        skip,
                    );
                }
                next = following;
                position += skip;
                layer.len = position - at;
            }
            _ => break,
        }
    }
    layers.push(layer);
    transport_layer(frame, next, position, end, layers);
}

fn tcp_flag_names(flags: u16) -> Vec<&'static str> {
    [
        (0x100, "NS"),
        (0x80, "CWR"),
        (0x40, "ECE"),
        (0x20, "URG"),
        (0x10, "ACK"),
        (0x08, "PSH"),
        (0x04, "RST"),
        (0x02, "SYN"),
        (0x01, "FIN"),
    ]
    .iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| *name)
    .collect()
}

fn transport_layer(
    frame: &[u8],
    protocol: u8,
    start: usize,
    end: usize,
    layers: &mut Vec<PacketLayer>,
) {
    let end = end.min(frame.len());
    let body = frame.get(start..end).unwrap_or(&[]);
    match protocol {
        6 if body.len() >= 20 => {
            let (sport, dport) = (u16_be(body, 0).unwrap_or(0), u16_be(body, 2).unwrap_or(0));
            let header_len = (usize::from(body[12] >> 4) * 4).clamp(20, body.len());
            let flags = u16_be(body, 12).unwrap_or(0) & 0x01ff;
            let names = tcp_flag_names(flags);
            let data_len = body.len() - header_len;
            let mut layer = PacketLayer::new(
                "Transmission Control Protocol",
                format!(
                    "{sport} → {dport} [{}] Seq {} Len {data_len}",
                    names.join(", "),
                    u32_be(body, 4).unwrap_or(0)
                ),
                start,
                header_len,
            );
            layer.add(
                "Source port",
                sport.to_string(),
                FieldKind::Number,
                start,
                2,
            );
            layer.add(
                "Destination port",
                dport.to_string(),
                FieldKind::Number,
                start + 2,
                2,
            );
            layer.add(
                "Sequence number",
                u32_be(body, 4).unwrap_or(0).to_string(),
                FieldKind::Number,
                start + 4,
                4,
            );
            layer.add(
                "Acknowledgment number",
                u32_be(body, 8).unwrap_or(0).to_string(),
                FieldKind::Number,
                start + 8,
                4,
            );
            layer.add(
                "Header length",
                format!("{header_len} bytes ({})", header_len / 4),
                FieldKind::Number,
                start + 12,
                1,
            );
            layer.add(
                "Flags",
                format!("0x{flags:03x} [{}]", names.join(", ")),
                FieldKind::Flags,
                start + 12,
                2,
            );
            for name in &names {
                layer.sub(name, "Set", FieldKind::Flags, start + 13, 1);
            }
            layer.add(
                "Window",
                u16_be(body, 14).unwrap_or(0).to_string(),
                FieldKind::Number,
                start + 14,
                2,
            );
            layer.add(
                "Checksum",
                format!("0x{:04x}", u16_be(body, 16).unwrap_or(0)),
                FieldKind::Number,
                start + 16,
                2,
            );
            layer.add(
                "Urgent pointer",
                u16_be(body, 18).unwrap_or(0).to_string(),
                FieldKind::Number,
                start + 18,
                2,
            );
            if header_len > 20 {
                layer.add(
                    "Options",
                    format!("{} bytes", header_len - 20),
                    FieldKind::Bytes,
                    start + 20,
                    header_len - 20,
                );
            }
            layer.add(
                "Payload",
                format!("{data_len} bytes"),
                FieldKind::Number,
                start + header_len,
                data_len,
            );
            layers.push(layer);
            let data_start = start + header_len;
            let data = &body[header_len..];
            if data.is_empty() {
                return;
            }
            if data.first().is_some_and(|kind| (20..=23).contains(kind)) && data.get(1) == Some(&3)
            {
                tls_layer(frame, data_start, end, layers);
            } else if http_line(data).is_some() {
                http_layer(frame, data_start, end, layers);
            } else {
                data_layer(frame, data_start, end, layers);
            }
        }
        17 if body.len() >= 8 => {
            let (sport, dport) = (u16_be(body, 0).unwrap_or(0), u16_be(body, 2).unwrap_or(0));
            let mut layer = PacketLayer::new(
                "User Datagram Protocol",
                format!("{sport} → {dport} Len {}", body.len() - 8),
                start,
                8,
            );
            layer.add(
                "Source port",
                sport.to_string(),
                FieldKind::Number,
                start,
                2,
            );
            layer.add(
                "Destination port",
                dport.to_string(),
                FieldKind::Number,
                start + 2,
                2,
            );
            layer.add(
                "Length",
                u16_be(body, 4).unwrap_or(0).to_string(),
                FieldKind::Number,
                start + 4,
                2,
            );
            layer.add(
                "Checksum",
                format!("0x{:04x}", u16_be(body, 6).unwrap_or(0)),
                FieldKind::Number,
                start + 6,
                2,
            );
            layers.push(layer);
            if sport == 53 || dport == 53 {
                dns_layer(frame, start + 8, end, layers);
            } else if matches!((sport, dport), (67, 68) | (68, 67)) {
                dhcp_layer(frame, start + 8, end, layers);
            } else {
                data_layer(frame, start + 8, end, layers);
            }
        }
        1 | 58 if body.len() >= 4 => {
            let (kind, code) = (body[0], body[1]);
            let name = match (protocol, kind) {
                (1, 8) | (58, 128) => "Echo request",
                (1, 0) | (58, 129) => "Echo reply",
                (1, 3) | (58, 1) => "Destination unreachable",
                (1, 11) | (58, 3) => "Time exceeded",
                (58, 133) => "Router solicitation",
                (58, 134) => "Router advertisement",
                (58, 135) => "Neighbor solicitation",
                (58, 136) => "Neighbor advertisement",
                (58, 130 | 131 | 132 | 143) => "Multicast listener report or query",
                _ => "",
            };
            let title = if protocol == 1 {
                "Internet Control Message Protocol"
            } else {
                "Internet Control Message Protocol v6"
            };
            let mut layer = PacketLayer::new(
                title,
                if name.is_empty() {
                    format!("type {kind}")
                } else {
                    name.to_owned()
                },
                start,
                body.len().min(8),
            );
            layer.add(
                "Type",
                if name.is_empty() {
                    kind.to_string()
                } else {
                    format!("{kind} ({name})")
                },
                FieldKind::Name,
                start,
                1,
            );
            layer.add("Code", code.to_string(), FieldKind::Number, start + 1, 1);
            layer.add(
                "Checksum",
                format!("0x{:04x}", u16_be(body, 2).unwrap_or(0)),
                FieldKind::Number,
                start + 2,
                2,
            );
            let echo = matches!((protocol, kind), (1, 0 | 8) | (58, 128 | 129));
            if echo && body.len() >= 8 {
                layer.add(
                    "Identifier",
                    format!("0x{:04x}", u16_be(body, 4).unwrap_or(0)),
                    FieldKind::Number,
                    start + 4,
                    2,
                );
                layer.add(
                    "Sequence number",
                    u16_be(body, 6).unwrap_or(0).to_string(),
                    FieldKind::Number,
                    start + 6,
                    2,
                );
                layers.push(layer);
                data_layer(frame, start + 8, end, layers);
            } else {
                layer.len = 4;
                layers.push(layer);
                data_layer(frame, start + 4, end, layers);
            }
        }
        _ => data_layer(frame, start, end, layers),
    }
}

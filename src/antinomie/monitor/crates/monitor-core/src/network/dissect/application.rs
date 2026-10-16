// SPDX-License-Identifier: MIT
//! DNS, DHCP, HTTP and TLS layers.
use super::*;

/// A DNS name at `at`, following compression pointers: the name and the
/// offset just after it where it is written.
pub(in crate::network) fn dns_name(data: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut after = None;
    let mut jumps = 0;
    loop {
        let len = *data.get(at)?;
        if len & 0xc0 == 0xc0 {
            after.get_or_insert(at + 2);
            jumps += 1;
            if jumps > 16 {
                return None;
            }
            at = usize::from(u16_be(data, at)? & 0x3fff);
        } else if len & 0xc0 != 0 {
            return None;
        } else if len == 0 {
            after.get_or_insert(at + 1);
            break;
        } else {
            let label = data.get(at + 1..at + 1 + usize::from(len))?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            if labels.len() > 127 {
                return None;
            }
            at += 1 + usize::from(len);
        }
    }
    let name = if labels.is_empty() {
        "<Root>".to_owned()
    } else {
        labels.join(".")
    };
    Some((name, after?))
}

pub(in crate::network) fn dns_class(class: u16) -> String {
    match class & 0x7fff {
        1 => "IN".into(),
        3 => "CH".into(),
        255 => "ANY".into(),
        other => format!("class {other}"),
    }
}

pub(super) fn dns_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
    let data = frame.get(start..end).unwrap_or(&[]);
    if data.len() < 12 {
        data_layer(frame, start, end, layers);
        return;
    }
    let flags = u16_be(data, 2).unwrap_or(0);
    let response = flags & 0x8000 != 0;
    let mut layer = PacketLayer::new("Domain Name System", dns(data), start, data.len());
    let id = u16_be(data, 0).unwrap_or(0);
    layer.add(
        "Transaction ID",
        format!("0x{id:04x}"),
        FieldKind::Number,
        start,
        2,
    );
    let rcode = flags & 0x000f;
    layer.add(
        "Flags",
        format!(
            "0x{flags:04x} {}",
            match (response, rcode) {
                (false, _) => "Standard query".to_owned(),
                (true, 0) => "Standard query response, No error".to_owned(),
                (true, 3) => "Standard query response, No such name".to_owned(),
                (true, code) => format!("Standard query response, error {code}"),
            }
        ),
        FieldKind::Flags,
        start + 2,
        2,
    );
    layer.sub(
        "Response",
        if response {
            "Message is a response"
        } else {
            "Message is a query"
        },
        FieldKind::Flags,
        start + 2,
        1,
    );
    layer.sub(
        "Opcode",
        ((flags >> 11) & 0xf).to_string(),
        FieldKind::Number,
        start + 2,
        1,
    );
    layer.sub(
        "Recursion desired",
        if flags & 0x0100 != 0 { "Yes" } else { "No" },
        FieldKind::Flags,
        start + 2,
        1,
    );
    if response {
        layer.sub(
            "Recursion available",
            if flags & 0x0080 != 0 { "Yes" } else { "No" },
            FieldKind::Flags,
            start + 3,
            1,
        );
        layer.sub(
            "Reply code",
            rcode.to_string(),
            FieldKind::Number,
            start + 3,
            1,
        );
    }
    let counts: Vec<u16> = (0..4)
        .map(|i| u16_be(data, 4 + i * 2).unwrap_or(0))
        .collect();
    for (i, name) in ["Questions", "Answer RRs", "Authority RRs", "Additional RRs"]
        .iter()
        .enumerate()
    {
        layer.add(
            name,
            counts[i].to_string(),
            FieldKind::Number,
            start + 4 + i * 2,
            2,
        );
    }
    let mut at = 12;
    let mut listed = 0;
    'records: for (section, count) in ["Query", "Answer", "Authority", "Additional"]
        .iter()
        .zip(counts)
    {
        for _ in 0..count {
            listed += 1;
            if listed > 64 {
                break 'records;
            }
            let Some((name, after)) = dns_name(data, at) else {
                break 'records;
            };
            let (Some(kind), Some(class)) = (u16_be(data, after), u16_be(data, after + 2)) else {
                break 'records;
            };
            if *section == "Query" {
                layer.add(
                    section,
                    format!(
                        "{name}: type {}, class {}",
                        dns_type(kind),
                        dns_class(class)
                    ),
                    FieldKind::Name,
                    start + at,
                    after + 4 - at,
                );
                at = after + 4;
                continue;
            }
            let (Some(ttl), Some(len)) = (u32_be(data, after + 4), u16_be(data, after + 8)) else {
                break 'records;
            };
            let rdata_at = after + 10;
            let Some(rdata) = data.get(rdata_at..rdata_at + usize::from(len)) else {
                break 'records;
            };
            let value = match (kind, rdata.len()) {
                (1, 4) => format!("addr {}", ipv4(rdata)),
                (28, 16) => format!("addr {}", ipv6(rdata)),
                (2 | 5 | 12, _) => dns_name(data, rdata_at)
                    .map_or_else(|| format!("{len} bytes"), |(target, _)| target),
                _ => format!("{len} bytes"),
            };
            layer.add(
                section,
                format!(
                    "{name}: type {}, class {}, {value}",
                    dns_type(kind),
                    dns_class(class)
                ),
                FieldKind::Name,
                start + at,
                rdata_at + rdata.len() - at,
            );
            layer.sub(
                "Time to live",
                ttl.to_string(),
                FieldKind::Number,
                start + after + 4,
                4,
            );
            layer.sub(
                "Data",
                value,
                if matches!(kind, 1 | 28) {
                    FieldKind::Address
                } else {
                    FieldKind::Name
                },
                start + rdata_at,
                rdata.len(),
            );
            at = rdata_at + rdata.len();
        }
    }
    layers.push(layer);
}

pub(super) fn dhcp_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
    let data = frame.get(start..end).unwrap_or(&[]);
    if data.len() < 240 {
        data_layer(frame, start, end, layers);
        return;
    }
    let mut message = None;
    let mut options = Vec::new();
    // Options after the magic cookie: code, length, value; 0 pads, 255 ends.
    if u32_be(data, 236) == Some(0x6382_5363) {
        let mut at = 240;
        while let Some(&code) = data.get(at) {
            if code == 255 {
                break;
            }
            if code == 0 {
                at += 1;
                continue;
            }
            let Some(&len) = data.get(at + 1) else { break };
            let Some(value) = data.get(at + 2..at + 2 + usize::from(len)) else {
                break;
            };
            match code {
                53 if len == 1 => {
                    let name = match value[0] {
                        1 => "Discover",
                        2 => "Offer",
                        3 => "Request",
                        4 => "Decline",
                        5 => "ACK",
                        6 => "NAK",
                        7 => "Release",
                        8 => "Inform",
                        _ => "unknown",
                    };
                    message = Some(name);
                    options.push(("Message type", name.to_owned(), FieldKind::Name, at));
                }
                12 => options.push((
                    "Host name",
                    String::from_utf8_lossy(value).into_owned(),
                    FieldKind::Text,
                    at,
                )),
                50 if len == 4 => {
                    options.push(("Requested address", ipv4(value), FieldKind::Address, at))
                }
                54 if len == 4 => {
                    options.push(("Server identifier", ipv4(value), FieldKind::Address, at))
                }
                _ => {}
            }
            at += 2 + usize::from(len);
        }
    }
    let mut layer = PacketLayer::new(
        "Dynamic Host Configuration Protocol",
        message.unwrap_or("DHCP"),
        start,
        data.len(),
    );
    layer.add(
        "Message",
        if data[0] == 1 {
            "Boot request (1)"
        } else {
            "Boot reply (2)"
        },
        FieldKind::Name,
        start,
        1,
    );
    layer.add(
        "Transaction ID",
        format!("0x{:08x}", u32_be(data, 4).unwrap_or(0)),
        FieldKind::Number,
        start + 4,
        4,
    );
    for (name, at) in [
        ("Client IP address", 12),
        ("Your IP address", 16),
        ("Server IP address", 20),
    ] {
        layer.add(
            name,
            ipv4(&data[at..at + 4]),
            FieldKind::Address,
            start + at,
            4,
        );
    }
    layer.add(
        "Client MAC address",
        mac(&data[28..34]),
        FieldKind::Address,
        start + 28,
        6,
    );
    for (name, value, kind, at) in options {
        let len = usize::from(data[at + 1]) + 2;
        layer.add(name, value, kind, start + at, len);
    }
    layers.push(layer);
}

pub(super) fn http_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
    let data = frame.get(start..end).unwrap_or(&[]);
    let first = http_line(data).unwrap_or_default();
    let mut layer = PacketLayer::new("Hypertext Transfer Protocol", first, start, data.len());
    let mut at = 0;
    for index in 0..64 {
        let line_end = data[at..]
            .windows(2)
            .position(|pair| pair == b"\r\n")
            .map(|i| at + i);
        let Some(line_end) = line_end else {
            if at < data.len() {
                layer.add(
                    "Data",
                    format!("{} bytes", data.len() - at),
                    FieldKind::Number,
                    start + at,
                    data.len() - at,
                );
            }
            break;
        };
        let line = String::from_utf8_lossy(&data[at..line_end]).into_owned();
        if line.is_empty() {
            at = line_end + 2;
            if at < data.len() {
                layer.add(
                    "Body",
                    format!("{} bytes", data.len() - at),
                    FieldKind::Number,
                    start + at,
                    data.len() - at,
                );
            }
            break;
        }
        let (name, value) = if index == 0 {
            (
                if line.starts_with("HTTP/") {
                    "Status line"
                } else {
                    "Request line"
                },
                line,
            )
        } else {
            match line.split_once(':') {
                Some((name, value)) => {
                    layer.add(
                        name.trim(),
                        value.trim(),
                        FieldKind::Text,
                        start + at,
                        line_end + 2 - at,
                    );
                    at = line_end + 2;
                    continue;
                }
                None => ("Header", line),
            }
        };
        layer.add(name, value, FieldKind::Text, start + at, line_end + 2 - at);
        at = line_end + 2;
    }
    layers.push(layer);
}

pub(super) fn tls_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
    let data = frame.get(start..end).unwrap_or(&[]);
    let mut layer = PacketLayer::new("Transport Layer Security", "", start, data.len());
    let mut summary = Vec::new();
    let mut at = 0;
    for _ in 0..16 {
        let (Some(&kind), Some(version), Some(len)) =
            (data.get(at), u16_be(data, at + 1), u16_be(data, at + 3))
        else {
            break;
        };
        let content = match kind {
            20 => "Change cipher spec",
            21 => "Alert",
            22 => "Handshake",
            23 => "Application data",
            _ => break,
        };
        let version_name = match version {
            0x0300 => "SSL 3.0",
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x0304 => "TLS 1.3",
            _ => "unknown",
        };
        let record_len = (5 + usize::from(len)).min(data.len() - at);
        layer.add(
            "Record",
            format!("{content}, {version_name} (0x{version:04x}), {len} bytes"),
            FieldKind::Name,
            start + at,
            record_len,
        );
        layer.sub(
            "Content type",
            format!("{content} ({kind})"),
            FieldKind::Name,
            start + at,
            1,
        );
        layer.sub(
            "Version",
            format!("{version_name} (0x{version:04x})"),
            FieldKind::Number,
            start + at + 1,
            2,
        );
        layer.sub(
            "Length",
            len.to_string(),
            FieldKind::Number,
            start + at + 3,
            2,
        );
        let mut what = content.to_owned();
        if kind == 22
            && let Some(&handshake) = data.get(at + 5)
        {
            let name = match handshake {
                1 => "Client Hello",
                2 => "Server Hello",
                4 => "New Session Ticket",
                8 => "Encrypted Extensions",
                11 => "Certificate",
                12 => "Server Key Exchange",
                13 => "Certificate Request",
                14 => "Server Hello Done",
                15 => "Certificate Verify",
                16 => "Client Key Exchange",
                20 => "Finished",
                _ => "",
            };
            if !name.is_empty() {
                what = name.to_owned();
                layer.sub(
                    "Handshake type",
                    format!("{name} ({handshake})"),
                    FieldKind::Name,
                    start + at + 5,
                    1,
                );
            }
            if handshake == 1
                && let Some((sni, sni_len)) = tls_sni(&data[at..])
            {
                let host = String::from_utf8_lossy(&data[at + sni..at + sni + sni_len]);
                what = format!("Client Hello, SNI {host}");
                layer.sub(
                    "Server name",
                    host.into_owned(),
                    FieldKind::Name,
                    start + at + sni,
                    sni_len,
                );
            }
        }
        summary.push(what);
        at += record_len;
        if at >= data.len() {
            break;
        }
    }
    layer.summary = summary.join(", ");
    layers.push(layer);
}

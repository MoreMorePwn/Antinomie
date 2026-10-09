//! Network capture: QEMU writes every frame of a NAT VM's network interface
//! to `network.pcap` in the boot recording (filter-dump, outside the guest).
//! This module reads that file back as one-line packet summaries, the way a
//! packet list in Wireshark does, and hands raw frames to the detail view.
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

/// File name of a boot's network capture.
pub const PCAP_FILE: &str = "network.pcap";
/// Bytes of one frame kept by QEMU (maxlen) and accepted when reading.
const MAX_FRAME: u32 = 65_535;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPacket {
    /// Position in the capture, from 1.
    pub number: u64,
    /// File offset of the pcap record, for [`frame`].
    pub offset: u64,
    /// Capture time, microseconds since the Unix epoch (host clock).
    pub time_us: u64,
    /// Length on the wire and bytes captured.
    pub length: u32,
    pub captured: u32,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub info: String,
}

#[derive(Clone, Debug, Default)]
pub struct NetworkPage {
    pub packets: Vec<NetworkPacket>,
    /// Where the next read starts; equal to the file size at the end.
    pub next_offset: u64,
    pub next_number: u64,
}

fn u16_be(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(at..at + 2)?.try_into().ok()?))
}

/// The pcap global header: 24 bytes, microsecond timestamps, little or big
/// endian, Ethernet link type.
fn header_endian(header: &[u8; 24]) -> Result<bool, String> {
    let little = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
        _ => return Err("not a pcap file (or nanosecond pcap)".into()),
    };
    let read = |at: usize| {
        let bytes: [u8; 4] = header[at..at + 4].try_into().expect("4 bytes");
        if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    if read(20) != 1 {
        return Err(format!("pcap link type {} is not Ethernet", read(20)));
    }
    Ok(little)
}

/// Read up to `limit` packets starting at `offset` (0 or a previous
/// `next_offset`). A record still being written ends the page.
pub fn read_page(
    path: &Path,
    offset: u64,
    number: u64,
    limit: usize,
) -> Result<NetworkPage, String> {
    let mut file = BufReader::new(File::open(path).map_err(|e| e.to_string())?);
    let mut header = [0u8; 24];
    if let Err(error) = file.read_exact(&mut header) {
        // QEMU writes the header when it opens the file; until then it is empty.
        return if error.kind() == std::io::ErrorKind::UnexpectedEof {
            Ok(NetworkPage::default())
        } else {
            Err(error.to_string())
        };
    }
    let little = header_endian(&header)?;
    let read_u32 = |bytes: &[u8]| {
        let bytes: [u8; 4] = bytes.try_into().expect("4 bytes");
        if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        }
    };
    let mut position = offset.max(24);
    file.seek(SeekFrom::Start(position))
        .map_err(|e| e.to_string())?;
    let mut page = NetworkPage {
        packets: Vec::new(),
        next_offset: position,
        next_number: number,
    };
    let mut record = [0u8; 16];
    let mut frame = Vec::new();
    while page.packets.len() < limit {
        if file.read_exact(&mut record).is_err() {
            break;
        }
        let captured = read_u32(&record[8..12]);
        let length = read_u32(&record[12..16]);
        if captured > MAX_FRAME {
            return Err(format!("pcap record at {position} is {captured} bytes"));
        }
        frame.resize(captured as usize, 0);
        if file.read_exact(&mut frame).is_err() {
            break;
        }
        page.next_number += 1;
        let (source, destination, protocol, info) = describe(&frame);
        page.packets.push(NetworkPacket {
            number: page.next_number,
            offset: position,
            time_us: u64::from(read_u32(&record[..4])) * 1_000_000
                + u64::from(read_u32(&record[4..8])),
            length,
            captured,
            source,
            destination,
            protocol,
            info,
        });
        position += 16 + u64::from(captured);
        page.next_offset = position;
    }
    Ok(page)
}

/// The captured bytes of the frame whose record starts at `offset`.
pub fn frame(path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut header = [0u8; 24];
    file.read_exact(&mut header).map_err(|e| e.to_string())?;
    let little = header_endian(&header)?;
    if offset < 24 {
        return Err("offset is inside the pcap header".into());
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut record = [0u8; 16];
    file.read_exact(&mut record).map_err(|e| e.to_string())?;
    let bytes: [u8; 4] = record[8..12].try_into().expect("4 bytes");
    let captured = if little {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    };
    if captured > MAX_FRAME {
        return Err("pcap record too large".into());
    }
    let mut frame = vec![0; captured as usize];
    file.read_exact(&mut frame).map_err(|e| e.to_string())?;
    Ok(frame)
}

fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn ipv4(bytes: &[u8]) -> String {
    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
}

fn ipv6(bytes: &[u8]) -> String {
    let octets: [u8; 16] = bytes.try_into().expect("16 bytes");
    std::net::Ipv6Addr::from(octets).to_string()
}

/// Source, destination, protocol and a one-line description of a frame.
pub fn describe(frame: &[u8]) -> (String, String, String, String) {
    let Some(mut ethertype) = u16_be(frame, 12) else {
        return (
            String::new(),
            String::new(),
            "Ethernet".into(),
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
            (source_mac, destination_mac, "ARP".into(), info)
        }
        0x0800 if payload.len() >= 20 => {
            let header_len = usize::from(payload[0] & 0x0f) * 4;
            let total = usize::from(u16_be(payload, 2).unwrap_or(0)).min(payload.len());
            let body = payload
                .get(header_len..total.max(header_len))
                .unwrap_or(&[]);
            let fragment = u16_be(payload, 6).unwrap_or(0) & 0x1fff;
            let (source, destination) = (ipv4(&payload[12..16]), ipv4(&payload[16..20]));
            if fragment != 0 {
                return (source, destination, "IPv4".into(), "fragment".into());
            }
            transport(payload[9], body, source, destination)
        }
        0x86dd if payload.len() >= 40 => {
            let (source, destination) = (ipv6(&payload[8..24]), ipv6(&payload[24..40]));
            let length = usize::from(u16_be(payload, 4).unwrap_or(0));
            let mut body = &payload[40..(40 + length).min(payload.len())];
            // Skip extension headers: hop-by-hop, routing, destination
            // options, fragment and authentication.
            let mut next = payload[6];
            for _ in 0..8 {
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
        other => (
            source_mac,
            destination_mac,
            format!("0x{other:04x}"),
            format!("Ethernet type 0x{other:04x}"),
        ),
    }
}

fn transport(
    protocol: u8,
    body: &[u8],
    source: String,
    destination: String,
) -> (String, String, String, String) {
    match protocol {
        6 if body.len() >= 20 => {
            let (sport, dport) = (u16_be(body, 0).unwrap_or(0), u16_be(body, 2).unwrap_or(0));
            let flags = body[13];
            let names: Vec<_> = [
                (0x02, "SYN"),
                (0x10, "ACK"),
                (0x08, "PSH"),
                (0x01, "FIN"),
                (0x04, "RST"),
            ]
            .iter()
            .filter(|(bit, _)| flags & bit != 0)
            .map(|(_, name)| *name)
            .collect();
            let data = body.get(usize::from(body[12] >> 4) * 4..).unwrap_or(&[]);
            let (protocol, info) = if let Some(host) = tls_server_name(data) {
                ("TLS".to_owned(), format!("Client Hello, SNI {host}"))
            } else if let Some(line) = http_line(data) {
                ("HTTP".to_owned(), line)
            } else {
                (
                    "TCP".to_owned(),
                    format!(
                        "{sport} → {dport} [{}] len {}",
                        names.join(", "),
                        data.len()
                    ),
                )
            };
            (
                format!("{source}:{sport}"),
                format!("{destination}:{dport}"),
                protocol,
                info,
            )
        }
        17 if body.len() >= 8 => {
            let (sport, dport) = (u16_be(body, 0).unwrap_or(0), u16_be(body, 2).unwrap_or(0));
            let data = &body[8..];
            let (protocol, info) = if sport == 53 || dport == 53 {
                ("DNS".to_owned(), dns(data))
            } else if matches!((sport, dport), (67, 68) | (68, 67)) {
                ("DHCP".to_owned(), "DHCP".to_owned())
            } else {
                (
                    "UDP".to_owned(),
                    format!("{sport} → {dport} len {}", data.len()),
                )
            };
            (
                format!("{source}:{sport}"),
                format!("{destination}:{dport}"),
                protocol,
                info,
            )
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
            (source, destination, name.into(), info)
        }
        other => (
            source,
            destination,
            format!("IP {other}"),
            format!("protocol {other}"),
        ),
    }
}

/// "standard query A example.com" / "response A example.com → 93.184.216.34".
fn dns(data: &[u8]) -> String {
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
    let kind = match u16_be(data, at).unwrap_or(0) {
        1 => "A".to_owned(),
        28 => "AAAA".to_owned(),
        5 => "CNAME".to_owned(),
        15 => "MX".to_owned(),
        16 => "TXT".to_owned(),
        12 => "PTR".to_owned(),
        33 => "SRV".to_owned(),
        65 => "HTTPS".to_owned(),
        other => format!("type {other}"),
    };
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

fn http_line(data: &[u8]) -> Option<String> {
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
            let name = data.get(at + 9..at + 9 + name_len)?;
            return Some(String::from_utf8_lossy(name).into_owned());
        }
        at += 4 + len;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x52, 0x55, 0x0a, 0, 2, 2, 0x52, 0x54, 0, 0x12, 0x34, 0x56];
        frame.extend(ethertype.to_be_bytes());
        frame.extend(payload);
        frame
    }

    fn ipv4_packet(protocol: u8, body: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, protocol, 0, 0, 10, 0, 2, 15, 10, 0, 2, 3,
        ];
        let total = (20 + body.len()) as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet.extend(body);
        packet
    }

    fn udp(sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend(sport.to_be_bytes());
        udp.extend(dport.to_be_bytes());
        udp.extend(((8 + data.len()) as u16).to_be_bytes());
        udp.extend([0, 0]);
        udp.extend(data);
        udp
    }

    fn dns_query() -> Vec<u8> {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["example", "com"] {
            dns.push(label.len() as u8);
            dns.extend(label.as_bytes());
        }
        dns.extend([0, 0, 1, 0, 1]);
        dns
    }

    fn pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend(0xa1b2c3d4u32.to_le_bytes());
        file.extend(2u16.to_le_bytes());
        file.extend(4u16.to_le_bytes());
        file.extend([0; 8]);
        file.extend(65535u32.to_le_bytes());
        file.extend(1u32.to_le_bytes());
        for (i, frame) in frames.iter().enumerate() {
            file.extend((1_700_000_000u32 + i as u32).to_le_bytes());
            file.extend(250u32.to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend(frame);
        }
        file
    }

    #[test]
    fn reads_pages_and_describes_dns_tcp_arp_and_tls() {
        let mut syn = vec![0u8; 20];
        syn[..2].copy_from_slice(&40000u16.to_be_bytes());
        syn[2..4].copy_from_slice(&443u16.to_be_bytes());
        syn[12] = 5 << 4;
        syn[13] = 0x02;
        let mut hello = syn.clone();
        hello[13] = 0x18;
        let name = b"evil.example";
        let mut sni = Vec::new();
        sni.extend(0u16.to_be_bytes());
        sni.extend(((name.len() + 5) as u16).to_be_bytes());
        sni.extend(((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend((name.len() as u16).to_be_bytes());
        sni.extend(name);
        let mut body = vec![3, 3];
        body.extend([0; 32]);
        body.push(0);
        body.extend(2u16.to_be_bytes());
        body.extend([0x13, 0x01]);
        body.extend([1, 0]);
        body.extend((sni.len() as u16).to_be_bytes());
        body.extend(&sni);
        let mut handshake = vec![1];
        handshake.extend(&(body.len() as u32).to_be_bytes()[1..]);
        handshake.extend(&body);
        let mut record = vec![22, 3, 1];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(&handshake);
        hello.extend(&record);
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
        arp.extend([0x52, 0x54, 0, 0x12, 0x34, 0x56, 10, 0, 2, 15]);
        arp.extend([0, 0, 0, 0, 0, 0, 10, 0, 2, 2]);
        let frames = vec![
            ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
            ethernet(0x0800, &ipv4_packet(6, &syn)),
            ethernet(0x0800, &ipv4_packet(6, &hello)),
            ethernet(0x0806, &arp),
        ];
        let path = std::env::temp_dir().join(format!("ant-pcap-{}", crate::storage::unique_id()));
        std::fs::write(&path, pcap(&frames)).unwrap();
        let first = read_page(&path, 0, 0, 2).unwrap();
        assert_eq!(first.packets.len(), 2);
        assert_eq!(first.packets[0].protocol, "DNS");
        assert_eq!(first.packets[0].info, "query A example.com");
        assert_eq!(first.packets[0].source, "10.0.2.15:5353");
        assert_eq!(first.packets[0].time_us, 1_700_000_000_000_250);
        assert_eq!(first.packets[1].info, "40000 → 443 [SYN] len 0");
        let rest = read_page(&path, first.next_offset, first.next_number, 10).unwrap();
        assert_eq!(rest.packets.len(), 2);
        assert_eq!(rest.packets[0].number, 3);
        assert_eq!(rest.packets[0].protocol, "TLS");
        assert_eq!(rest.packets[0].info, "Client Hello, SNI evil.example");
        assert_eq!(rest.packets[1].info, "Who has 10.0.2.2? Tell 10.0.2.15");
        assert_eq!(frame(&path, rest.packets[1].offset).unwrap(), frames[3]);
        // A partly written record ends the page without an error.
        let mut partial = pcap(&frames);
        partial.truncate(partial.len() - 3);
        std::fs::write(&path, partial).unwrap();
        assert_eq!(read_page(&path, 0, 0, 10).unwrap().packets.len(), 3);
        std::fs::remove_file(path).unwrap();
    }
}

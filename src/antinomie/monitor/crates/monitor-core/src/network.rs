//! Network capture: while a capture runs, QEMU writes every frame of a NAT
//! VM's network interface to a pcap file in the boot recording (a filter-dump
//! object added over QMP, outside the guest). Each capture is
//! `boots/<boot>/network/<capture>.pcap` with a small JSON summary beside it;
//! boots recorded before captures were started by hand have one
//! `boots/<boot>/network.pcap` covering the whole boot.
//! This module reads a capture back as one-line packet summaries, the way a
//! packet list in Wireshark does, and hands raw frames to the detail view.
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    net::IpAddr,
    path::{Path, PathBuf},
};

/// File name of a whole-boot network capture (boots before 0.3.0 recorded
/// network traffic for as long as the VM ran).
pub const PCAP_FILE: &str = "network.pcap";
/// Folder of a boot recording that holds its network captures.
pub const CAPTURE_DIR: &str = "network";
/// Bytes of one frame kept by QEMU (maxlen) and accepted when reading.
const MAX_FRAME: u32 = 65_535;
/// TCP header flags, as in [`NetworkPacket::tcp_flags`].
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;

/// One network capture of a boot: a pcap file and when it ran.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCapture {
    pub id: String,
    pub boot_id: String,
    /// The pcap file. The saved summary names it relative to its folder.
    pub file: PathBuf,
    /// Wall clock, milliseconds since the Unix epoch.
    pub started_ms: u64,
    /// `None` while the capture runs (or when the app ended before it could
    /// write the stop).
    pub stopped_ms: Option<u64>,
    /// Packets and file size, counted when the capture stopped.
    pub packets: Option<u64>,
    pub bytes: Option<u64>,
    /// A whole-boot capture from before captures were started by hand.
    pub whole_boot: bool,
}

impl NetworkCapture {
    /// A new capture in the boot recording `boot_dir`.
    pub fn new(boot_dir: &Path, boot_id: &str, id: &str, started_ms: u64) -> Self {
        NetworkCapture {
            id: id.into(),
            boot_id: boot_id.into(),
            file: boot_dir.join(CAPTURE_DIR).join(format!("{id}.pcap")),
            started_ms,
            ..NetworkCapture::default()
        }
    }

    /// The summary file beside the pcap.
    pub fn summary_path(&self) -> PathBuf {
        self.file.with_extension("json")
    }

    /// The QEMU object that writes this capture.
    pub fn object_id(&self) -> String {
        // QOM ids start with a letter.
        format!("netdump-{}", self.id)
    }
}

/// QMP command that starts writing `capture` from the VM's `net0` interface.
pub fn filter_dump_add(capture: &NetworkCapture) -> Result<serde_json::Value, String> {
    let file = capture
        .file
        .to_str()
        .ok_or("network capture path is not UTF-8")?;
    Ok(serde_json::json!({
        "execute": "object-add",
        "arguments": {
            "qom-type": "filter-dump",
            "id": capture.object_id(),
            "netdev": "net0",
            "file": file,
            "maxlen": MAX_FRAME,
        }
    }))
}

/// QMP command that stops `capture` (QEMU closes the file).
pub fn filter_dump_del(capture: &NetworkCapture) -> serde_json::Value {
    serde_json::json!({"execute": "object-del", "arguments": {"id": capture.object_id()}})
}

/// Packets and bytes of a pcap file, from its record headers. A record still
/// being written is not counted.
pub fn count_packets(path: &Path) -> Result<(u64, u64), String> {
    let mut file = BufReader::new(open_capture(path)?);
    let size = file.get_ref().metadata().map_err(|e| e.to_string())?.len();
    let mut header = [0u8; 24];
    if file.read_exact(&mut header).is_err() {
        return Ok((0, size));
    }
    let little = header_endian(&header)?;
    let (mut packets, mut position) = (0u64, 24u64);
    let mut record = [0u8; 16];
    while file.read_exact(&mut record).is_ok() {
        let bytes: [u8; 4] = record[8..12].try_into().expect("4 bytes");
        let captured = if little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        };
        if captured > MAX_FRAME || position + 16 + u64::from(captured) > size {
            break;
        }
        file.seek_relative(i64::from(captured))
            .map_err(|e| e.to_string())?;
        position += 16 + u64::from(captured);
        packets += 1;
    }
    Ok((packets, size))
}

/// Save `capture`'s summary beside its pcap.
pub(crate) fn save_summary(capture: &NetworkCapture) -> Result<(), String> {
    let mut saved = capture.clone();
    saved.file = capture
        .file
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_default();
    crate::storage::atomic_json(&capture.summary_path(), &saved)
}

/// Every network capture in a VM's recording folder, newest first: the
/// captures of each boot and the whole-boot captures of older boots.
pub fn list_captures(recordings: &Path) -> Vec<NetworkCapture> {
    let mut found = Vec::new();
    for boot in std::fs::read_dir(recordings.join("boots"))
        .into_iter()
        .flatten()
        .flatten()
    {
        if !boot.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        let boot_dir = boot.path();
        let boot_id = boot.file_name().to_string_lossy().into_owned();
        let whole = boot_dir.join(PCAP_FILE);
        if let Ok(file) = crate::archive_io::open_regular(&boot_dir, &whole)
            && let Ok(metadata) = file.metadata()
        {
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |time| time.as_millis() as u64);
            let first = read_page(&whole, 0, 0, 1)
                .ok()
                .and_then(|page| page.packets.first().map(|p| p.time_us / 1000));
            found.push(NetworkCapture {
                id: boot_id.clone(),
                boot_id: boot_id.clone(),
                file: whole,
                started_ms: first.unwrap_or(modified),
                stopped_ms: Some(modified),
                packets: None,
                bytes: Some(metadata.len()),
                whole_boot: true,
            });
        }
        let dir = boot_dir.join(CAPTURE_DIR);
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(summary) = crate::archive_io::open_regular(&dir, &path) else {
                continue;
            };
            let Ok(mut capture) =
                serde_json::from_reader::<_, NetworkCapture>(summary.take(65_536))
            else {
                continue;
            };
            // Summaries store a single file name, never an imported absolute
            // path or a traversal into another capture's recording.
            if capture.file.components().count() != 1
                || !matches!(
                    capture.file.components().next(),
                    Some(std::path::Component::Normal(_))
                )
            {
                continue;
            }
            capture.file = dir.join(&capture.file);
            if capture.boot_id.is_empty() {
                capture.boot_id = boot_id.clone();
            }
            if crate::archive_io::open_regular(&dir, &capture.file).is_ok() {
                found.push(capture);
            }
        }
    }
    found.sort_by(|a, b| {
        b.started_ms
            .cmp(&a.started_ms)
            .then_with(|| b.id.cmp(&a.id))
    });
    found
}

fn open_capture(path: &Path) -> Result<File, String> {
    let path = std::fs::canonicalize(path).map_err(|error| error.to_string())?;
    crate::archive_io::open_regular(path.parent().unwrap_or(Path::new(".")), &path)
        .map_err(|error| format!("network capture file: {error}"))
}

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
    /// IP addresses and TCP/UDP ports, when the frame carries them.
    #[serde(default)]
    pub src_ip: Option<IpAddr>,
    #[serde(default)]
    pub dst_ip: Option<IpAddr>,
    #[serde(default)]
    pub src_port: Option<u16>,
    #[serde(default)]
    pub dst_port: Option<u16>,
    /// TCP header flags (`TCP_SYN`, ...), for TCP segments.
    #[serde(default)]
    pub tcp_flags: Option<u8>,
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
    let mut file = BufReader::new(open_capture(path)?);
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
        page.packets.push(NetworkPacket {
            number: page.next_number,
            offset: position,
            time_us: u64::from(read_u32(&record[..4])) * 1_000_000
                + u64::from(read_u32(&record[4..8])),
            length,
            captured,
            ..describe(&frame)
        });
        position += 16 + u64::from(captured);
        page.next_offset = position;
    }
    Ok(page)
}

/// The captured bytes of the frame whose record starts at `offset`.
pub fn frame(path: &Path, offset: u64) -> Result<Vec<u8>, String> {
    let mut file = open_capture(path)?;
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
    ipv4_addr(bytes).to_string()
}

fn ipv4_addr(bytes: &[u8]) -> IpAddr {
    std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).into()
}

fn ipv6_addr(bytes: &[u8]) -> IpAddr {
    let octets: [u8; 16] = bytes.try_into().expect("16 bytes");
    std::net::Ipv6Addr::from(octets).into()
}

fn ipv6(bytes: &[u8]) -> String {
    ipv6_addr(bytes).to_string()
}

/// A packet summary without its place in the file.
fn summary(source: String, destination: String, protocol: &str, info: String) -> NetworkPacket {
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
fn endpoint(address: IpAddr, port: u16) -> String {
    match address {
        IpAddr::V4(address) => format!("{address}:{port}"),
        IpAddr::V6(address) => format!("[{address}]:{port}"),
    }
}

fn transport(protocol: u8, body: &[u8], source: IpAddr, destination: IpAddr) -> NetworkPacket {
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
        // Addresses and ports are structured, not only text.
        let dns = &first.packets[0];
        assert_eq!(dns.src_ip, Some("10.0.2.15".parse().unwrap()));
        assert_eq!(dns.dst_ip, Some("10.0.2.3".parse().unwrap()));
        assert_eq!((dns.src_port, dns.dst_port), (Some(5353), Some(53)));
        assert_eq!(dns.tcp_flags, None);
        let syn = &first.packets[1];
        assert_eq!((syn.src_port, syn.dst_port), (Some(40000), Some(443)));
        assert_eq!(syn.tcp_flags, Some(TCP_SYN));
        let rest = read_page(&path, first.next_offset, first.next_number, 10).unwrap();
        assert_eq!(rest.packets.len(), 2);
        assert_eq!(rest.packets[0].number, 3);
        assert_eq!(rest.packets[0].protocol, "TLS");
        assert_eq!(rest.packets[0].info, "Client Hello, SNI evil.example");
        assert_eq!(rest.packets[1].info, "Who has 10.0.2.2? Tell 10.0.2.15");
        assert_eq!(rest.packets[1].src_ip, None);
        assert_eq!(rest.packets[1].src_port, None);
        assert_eq!(frame(&path, rest.packets[1].offset).unwrap(), frames[3]);
        // A partly written record ends the page without an error.
        let mut partial = pcap(&frames);
        partial.truncate(partial.len() - 3);
        std::fs::write(&path, partial).unwrap();
        assert_eq!(read_page(&path, 0, 0, 10).unwrap().packets.len(), 3);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn ipv6_and_icmp_carry_addresses_without_ports() {
        let mut ip = vec![0x60, 0, 0, 0, 0, 8, 58, 64];
        ip.extend(
            [0xfe, 0x80]
                .iter()
                .chain([0u8; 13].iter())
                .chain([1u8].iter()),
        );
        ip.extend(
            [0xff, 0x02]
                .iter()
                .chain([0u8; 13].iter())
                .chain([1u8].iter()),
        );
        ip.extend([128, 0, 0, 0, 0, 0, 0, 0]);
        let packet = describe(&ethernet(0x86dd, &ip));
        assert_eq!(packet.protocol, "ICMPv6");
        assert_eq!(packet.info, "Echo request");
        assert_eq!(packet.src_ip, Some("fe80::1".parse().unwrap()));
        assert_eq!(packet.dst_ip, Some("ff02::1".parse().unwrap()));
        assert_eq!((packet.src_port, packet.dst_port), (None, None));
        // A UDP endpoint over IPv6 brackets the address.
        let mut ip = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        ip.extend(
            [0xfe, 0x80]
                .iter()
                .chain([0u8; 13].iter())
                .chain([1u8].iter()),
        );
        ip.extend(
            [0xfe, 0x80]
                .iter()
                .chain([0u8; 13].iter())
                .chain([2u8].iter()),
        );
        ip.extend(udp(546, 547, &[]));
        let packet = describe(&ethernet(0x86dd, &ip));
        assert_eq!(packet.source, "[fe80::1]:546");
        assert_eq!(packet.dst_port, Some(547));
    }

    #[test]
    fn captures_are_listed_newest_first_with_older_whole_boot_files() {
        let root = std::env::temp_dir().join(format!("ant-netcap-{}", crate::storage::unique_id()));
        let frames = vec![ethernet(
            0x0800,
            &ipv4_packet(17, &udp(5353, 53, &dns_query())),
        )];
        // An older boot with one whole-boot capture.
        let old_boot = root.join("boots").join("oldboot");
        std::fs::create_dir_all(&old_boot).unwrap();
        std::fs::write(old_boot.join(PCAP_FILE), pcap(&frames)).unwrap();
        // A newer boot with a finished capture and a running one.
        let boot = root.join("boots").join("newboot");
        let first = NetworkCapture::new(&boot, "newboot", "aaaa", 1_800_000_000_000);
        let second = NetworkCapture::new(&boot, "newboot", "bbbb", 1_800_000_060_000);
        std::fs::create_dir_all(first.file.parent().unwrap()).unwrap();
        std::fs::write(&first.file, pcap(&[frames[0].clone(), frames[0].clone()])).unwrap();
        std::fs::write(&second.file, pcap(&[])).unwrap();
        let (packets, bytes) = count_packets(&first.file).unwrap();
        assert_eq!(packets, 2);
        assert_eq!(bytes, std::fs::metadata(&first.file).unwrap().len());
        let finished = NetworkCapture {
            stopped_ms: Some(1_800_000_030_000),
            packets: Some(packets),
            bytes: Some(bytes),
            ..first.clone()
        };
        save_summary(&finished).unwrap();
        save_summary(&second).unwrap();
        // The summary names the pcap relative to its folder.
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(first.summary_path()).unwrap()).unwrap();
        assert_eq!(saved["file"], "aaaa.pcap");
        let listed = list_captures(&root);
        let ids: Vec<_> = listed.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["bbbb", "aaaa", "oldboot"]);
        assert_eq!(listed[0].stopped_ms, None);
        assert_eq!(listed[1], finished);
        assert!(listed[2].whole_boot);
        assert_eq!(listed[2].file, old_boot.join(PCAP_FILE));
        assert_eq!(listed[2].started_ms, 1_700_000_000_000);
        // A partly written last record is not counted.
        let mut partial = pcap(&[frames[0].clone(), frames[0].clone()]);
        partial.truncate(partial.len() - 1);
        std::fs::write(&first.file, partial).unwrap();
        assert_eq!(count_packets(&first.file).unwrap().0, 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn qmp_commands_add_and_remove_a_filter_dump_on_net0() {
        let capture = NetworkCapture::new(Path::new("/rec/boots/b1"), "b1", "c0ffee", 1);
        assert_eq!(
            filter_dump_add(&capture).unwrap(),
            serde_json::json!({"execute": "object-add", "arguments": {
                "qom-type": "filter-dump", "id": "netdump-c0ffee", "netdev": "net0",
                "file": "/rec/boots/b1/network/c0ffee.pcap", "maxlen": 65535}})
        );
        assert_eq!(
            filter_dump_del(&capture),
            serde_json::json!({"execute": "object-del", "arguments": {"id": "netdump-c0ffee"}})
        );
        assert_eq!(
            capture.summary_path(),
            Path::new("/rec/boots/b1/network/c0ffee.json")
        );
    }

    #[test]
    fn malformed_ipv4_and_ipv6_fragments_do_not_invent_ports() {
        let mut ip = ipv4_packet(17, &udp(1234, 53, &dns_query()));
        ip[0] = 0x40;
        let packet = describe(&ethernet(0x0800, &ip));
        assert_eq!(packet.protocol, "IPv4");
        assert_eq!(packet.dst_port, None);
        let mut ip = vec![0x60, 0, 0, 0, 0, 16, 44, 64];
        ip.extend([0u8; 32]);
        ip.extend([17, 0, 0, 8, 0, 0, 0, 1]);
        ip.extend(udp(1234, 53, &[]));
        let packet = describe(&ethernet(0x86dd, &ip));
        assert_eq!(packet.protocol, "IPv6");
        assert_eq!(packet.info, "fragment");
        assert_eq!((packet.src_port, packet.dst_port), (None, None));
    }

    #[test]
    fn history_rejects_escaped_paths_and_fifo_members_without_blocking() {
        let root =
            std::env::temp_dir().join(format!("ant-net-reject-{}", crate::storage::unique_id()));
        let dir = root.join("boots/b1/network");
        std::fs::create_dir_all(&dir).unwrap();
        let external = root.join("outside.pcap");
        std::fs::write(&external, pcap(&[])).unwrap();
        let summary = |name: &str, file: PathBuf| {
            let capture = NetworkCapture {
                file,
                id: name.into(),
                ..NetworkCapture::default()
            };
            std::fs::write(
                dir.join(format!("{name}.json")),
                serde_json::to_vec(&capture).unwrap(),
            )
            .unwrap();
        };
        summary("absolute", external.clone());
        summary("traversal", PathBuf::from("../../../outside.pcap"));
        std::os::unix::fs::symlink(&external, dir.join("linked.pcap")).unwrap();
        summary("linked", PathBuf::from("linked.pcap"));
        let fifo = dir.join("fifo.pcap");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        summary("fifo", PathBuf::from("fifo.pcap"));
        assert!(list_captures(&root).is_empty());
        assert!(read_page(&fifo, 0, 0, 1).is_err());
        assert!(frame(&fifo, 24).is_err());
        assert!(count_packets(&fifo).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

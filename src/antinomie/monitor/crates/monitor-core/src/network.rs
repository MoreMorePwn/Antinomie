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
fn dns_type(kind: u16) -> String {
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
    let (at, len) = tls_sni(data)?;
    Some(String::from_utf8_lossy(&data[at..at + len]).into_owned())
}

/// Offset and length of the server name in a TLS ClientHello.
fn tls_sni(data: &[u8]) -> Option<(usize, usize)> {
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

/// What a decoded field holds, for its color in the packet tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    Number,
    /// MAC and IP addresses.
    Address,
    Flags,
    /// Host names, record and message types.
    Name,
    Text,
    Bytes,
}

/// One line of a decoded layer and the frame bytes it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketField {
    pub name: String,
    pub value: String,
    pub kind: FieldKind,
    /// Byte range in the frame.
    pub start: usize,
    pub len: usize,
    /// 0 for a field of the layer, 1 for a part of the field above it.
    pub depth: u8,
}

/// One protocol layer of a frame (Ethernet II, IPv4, TCP, DNS, ...), the
/// way Wireshark's packet details tree shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketLayer {
    pub name: String,
    /// A one-line summary beside the name ("Src 10.0.2.15, Dst 10.0.2.3").
    pub summary: String,
    /// Byte range in the frame.
    pub start: usize,
    pub len: usize,
    pub fields: Vec<PacketField>,
}

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

fn u32_be(data: &[u8], at: usize) -> Option<u32> {
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
        if next == 44 {
            if header.len() >= 8 {
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

/// A DNS name at `at`, following compression pointers: the name and the
/// offset just after it where it is written.
fn dns_name(data: &[u8], mut at: usize) -> Option<(String, usize)> {
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

fn dns_class(class: u16) -> String {
    match class & 0x7fff {
        1 => "IN".into(),
        3 => "CH".into(),
        255 => "ANY".into(),
        other => format!("class {other}"),
    }
}

fn dns_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
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

fn dhcp_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
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

fn http_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
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

fn tls_layer(frame: &[u8], start: usize, end: usize, layers: &mut Vec<PacketLayer>) {
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
        if kind == 22 {
            if let Some(&handshake) = data.get(at + 5) {
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
                if handshake == 1 {
                    if let Some((sni, sni_len)) = tls_sni(&data[at..]) {
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

    /// A TLS record with a ClientHello naming `name` (SNI).
    fn client_hello(name: &[u8]) -> Vec<u8> {
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
        record
    }

    fn arp_request() -> Vec<u8> {
        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
        arp.extend([0x52, 0x54, 0, 0x12, 0x34, 0x56, 10, 0, 2, 15]);
        arp.extend([0, 0, 0, 0, 0, 0, 10, 0, 2, 2]);
        arp
    }

    /// A TCP header from 40000 to `dport` with `flags` and no options.
    fn tcp(dport: u16, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&dport.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&64240u16.to_be_bytes());
        tcp.extend(data);
        tcp
    }

    fn field<'a>(layer: &'a PacketLayer, name: &str) -> &'a PacketField {
        layer
            .fields
            .iter()
            .find(|field| field.name == name)
            .unwrap_or_else(|| panic!("no {name} in {layer:?}"))
    }

    fn bytes<'a>(frame: &'a [u8], field: &PacketField) -> &'a [u8] {
        &frame[field.start..field.start + field.len]
    }

    #[test]
    fn dissects_layers_with_the_byte_range_of_each_field() {
        // DNS query: Ethernet, IPv4, UDP, DNS.
        let query = ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query())));
        let layers = dissect(&query);
        let names: Vec<_> = layers.iter().map(|layer| layer.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Ethernet II",
                "Internet Protocol Version 4",
                "User Datagram Protocol",
                "Domain Name System"
            ]
        );
        assert_eq!(field(&layers[0], "Source").value, "52:54:00:12:34:56");
        assert_eq!(field(&layers[0], "Type").value, "IPv4 (0x0800)");
        assert_eq!(layers[1].summary, "Src 10.0.2.15, Dst 10.0.2.3");
        let source = field(&layers[1], "Source address");
        assert_eq!((source.start, source.len), (26, 4));
        assert_eq!(bytes(&query, source), [10, 0, 2, 15]);
        assert_eq!(field(&layers[1], "Protocol").value, "UDP (17)");
        assert_eq!(field(&layers[2], "Destination port").value, "53");
        assert_eq!(
            bytes(&query, field(&layers[2], "Destination port")),
            [0, 53]
        );
        assert_eq!(layers[3].summary, "query A example.com");
        let question = field(&layers[3], "Query");
        assert_eq!(question.value, "example.com: type A, class IN");
        assert_eq!(question.start, 14 + 20 + 8 + 12);
        assert_eq!(question.start + question.len, query.len());
        // A response whose answer names the question by a compression pointer.
        let mut answer = dns_query();
        answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        answer[7] = 1;
        answer.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34]);
        let response = ethernet(0x0800, &ipv4_packet(17, &udp(53, 5353, &answer)));
        let dns_layer = &dissect(&response)[3];
        assert_eq!(
            field(dns_layer, "Answer").value,
            "example.com: type A, class IN, addr 93.184.216.34"
        );
        assert_eq!(field(dns_layer, "Time to live").value, "60");
        assert_eq!(
            bytes(&response, field(dns_layer, "Data")),
            [93, 184, 216, 34]
        );
        assert_eq!(
            describe(&response).info,
            "response A example.com → 93.184.216.34"
        );
        // TCP flags, then TLS with the server name's bytes.
        let hello = ethernet(
            0x0800,
            &ipv4_packet(6, &tcp(443, 0x18, &client_hello(b"evil.example"))),
        );
        let layers = dissect(&hello);
        assert_eq!(field(&layers[2], "Flags").value, "0x018 [ACK, PSH]");
        assert_eq!(field(&layers[2], "Sequence number").value, "1000");
        assert_eq!(layers[3].name, "Transport Layer Security");
        assert_eq!(layers[3].summary, "Client Hello, SNI evil.example");
        assert_eq!(
            bytes(&hello, field(&layers[3], "Server name")),
            b"evil.example"
        );
        // HTTP request lines and headers.
        let get = ethernet(
            0x0800,
            &ipv4_packet(
                6,
                &tcp(80, 0x18, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            ),
        );
        let http = &dissect(&get)[3];
        assert_eq!(http.name, "Hypertext Transfer Protocol");
        assert_eq!(field(http, "Request line").value, "GET / HTTP/1.1");
        assert_eq!(field(http, "Host").value, "example.com");
        assert_eq!(bytes(&get, field(http, "Host")), b"Host: example.com\r\n");
        // ARP and ICMP echo.
        let arp = dissect(&ethernet(0x0806, &arp_request()));
        assert_eq!(arp[1].summary, "Who has 10.0.2.2? Tell 10.0.2.15");
        assert_eq!(field(&arp[1], "Opcode").value, "request (1)");
        let ping = dissect(&ethernet(
            0x0800,
            &ipv4_packet(1, &[8, 0, 0, 0, 0, 7, 0, 1, 0xaa, 0xbb]),
        ));
        assert_eq!(field(&ping[2], "Type").value, "8 (Echo request)");
        assert_eq!(field(&ping[2], "Sequence number").value, "1");
        assert_eq!(ping[3].name, "Data");
        assert_eq!(ping[3].len, 2);
    }

    #[test]
    fn dissecting_truncated_frames_keeps_every_range_inside_the_frame() {
        let mut v6 = vec![0x60, 0, 0, 0, 0, 16, 0, 64];
        v6.extend([0u8; 32]);
        v6.extend([17, 0, 1, 4, 0, 0, 0, 0]);
        v6.extend(udp(1234, 53, &[]));
        let frames = [
            ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
            ethernet(
                0x0800,
                &ipv4_packet(6, &tcp(443, 0x18, &client_hello(b"evil.example"))),
            ),
            ethernet(0x0806, &arp_request()),
            ethernet(0x86dd, &v6),
        ];
        for frame in &frames {
            for end in 0..=frame.len() {
                let part = &frame[..end];
                for layer in dissect(part) {
                    assert!(layer.start + layer.len <= end, "{layer:?}");
                    for field in &layer.fields {
                        assert!(field.start + field.len <= end, "{field:?}");
                    }
                }
            }
        }
        // IPv6 hop-by-hop options are listed, then the UDP header.
        let layers = dissect(&frames[3]);
        assert_eq!(
            field(&layers[1], "Extension header").value,
            "Hop-by-hop options (0), 8 bytes"
        );
        assert_eq!(layers[2].name, "User Datagram Protocol");
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
        hello.extend(client_hello(b"evil.example"));
        let frames = vec![
            ethernet(0x0800, &ipv4_packet(17, &udp(5353, 53, &dns_query()))),
            ethernet(0x0800, &ipv4_packet(6, &syn)),
            ethernet(0x0800, &ipv4_packet(6, &hello)),
            ethernet(0x0806, &arp_request()),
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

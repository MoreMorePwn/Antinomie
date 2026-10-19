// SPDX-License-Identifier: MIT
//! Packet capture scans through TShark and the spool that bounds them.
use super::*;

pub(super) const TSHARK_FIELDS: &[&str] = &[
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.version",
    "http.response.code",
    "http.response_in",
    "http.request_in",
    "dns.id",
    "dns.qry.name",
    "dns.qry.type",
    "dns.qry.class",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.resp.name",
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.response_in",
    "dns.response_to",
    "dns.retransmission",
    "ip.geoip.dst_country",
    "ipv6.geoip.dst_country",
    "ip.geoip.dst_org",
    "ipv6.geoip.dst_org",
    "tls.handshake.extensions_server_name",
];

pub(super) const HTTP_HEADERS: &[&str] = &[
    "Frame",
    "Time",
    "Endpoint",
    "Method",
    "Host",
    "URI",
    "Response",
    "Response frame",
];

pub(super) const DNS_HEADERS: &[&str] = &[
    "Frame",
    "Endpoint",
    "Qname",
    "Qtype",
    "Rcode",
    "Answers",
    "Response frame",
];

impl PacketSpool {
    pub(super) fn new() -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "antinomie-triage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|error| error.to_string())?;
        let create = |name| {
            std::fs::OpenOptions::new()
                .mode(0o600)
                .read(true)
                .write(true)
                .create_new(true)
                .open(directory.join(name))
                .map_err(|error| error.to_string())
        };
        let result = (|| {
            Ok(Self {
                rows: create("rows.tsv")?,
                offsets: create("frames.idx")?,
                directory: directory.clone(),
                size: 0,
            })
        })();
        if result.is_err() {
            let _ = std::fs::remove_dir_all(directory);
        }
        result
    }
    fn push(&mut self, line: &str) -> Result<(), String> {
        use std::io::Write;
        let fields = tsv_fields(line)?;
        let frame = fields
            .first()
            .and_then(|number| number.parse::<u64>().ok())
            .ok_or("TShark frame ID is missing")?;
        let size = u64::try_from(line.len()).map_err(|_| "metadata line size overflow")? + 1;
        if self.size.saturating_add(size) > 512 * 1024 * 1024 {
            return Err(
                "Triage metadata scratch limit (512 MiB) exceeded; index incomplete".into(),
            );
        }
        self.offsets
            .write_all(&frame.to_le_bytes())
            .and_then(|()| self.offsets.write_all(&self.size.to_le_bytes()))
            .map_err(|error| error.to_string())?;
        self.rows
            .write_all(line.as_bytes())
            .and_then(|()| self.rows.write_all(b"\n"))
            .map_err(|error| error.to_string())?;
        self.size += size;
        Ok(())
    }
}

impl Drop for PacketSpool {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub(super) fn tsv_fields(line: &str) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    let mut value = String::new();
    let mut chars = line.trim_end_matches(['\r', '\n']).chars().peekable();
    let mut quoted = false;
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                chars.next();
                value.push('"');
            }
            '"' => quoted = !quoted,
            '\t' if !quoted => {
                values.push(std::mem::take(&mut value));
            }
            _ => value.push(ch),
        }
    }
    if quoted {
        return Err("TShark field quote was truncated".into());
    }
    values.push(value);
    Ok(values)
}

pub(super) fn epoch_us(value: &str) -> Option<u64> {
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds = seconds.parse::<u64>().ok()?;
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut fraction = fraction.chars().take(6).collect::<String>();
    while fraction.len() < 6 {
        fraction.push('0');
    }
    seconds
        .checked_mul(1_000_000)?
        .checked_add(fraction.parse().ok()?)
}

fn spool_response(
    frame: u64,
    offsets: &mut std::fs::File,
    rows: &mut std::io::BufReader<std::fs::File>,
) -> Result<Vec<String>, String> {
    use std::io::{BufRead, Read, Seek, SeekFrom};
    let count = offsets.metadata().map_err(|error| error.to_string())?.len() / 16;
    let (mut low, mut high) = (0, count);
    let mut entry = [0u8; 16];
    while low < high {
        let mid = low + (high - low) / 2;
        offsets
            .seek(SeekFrom::Start(mid * 16))
            .and_then(|_| offsets.read_exact(&mut entry))
            .map_err(|error| error.to_string())?;
        let id = u64::from_le_bytes(
            entry[..8]
                .try_into()
                .map_err(|_| "metadata index frame length")?,
        );
        match id.cmp(&frame) {
            std::cmp::Ordering::Less => low = mid + 1,
            std::cmp::Ordering::Greater => high = mid,
            std::cmp::Ordering::Equal => {
                let offset = u64::from_le_bytes(
                    entry[8..]
                        .try_into()
                        .map_err(|_| "metadata index offset length")?,
                );
                rows.seek(SeekFrom::Start(offset))
                    .map_err(|error| error.to_string())?;
                let mut line = String::new();
                rows.read_line(&mut line)
                    .map_err(|error| error.to_string())?;
                return tsv_fields(&line);
            }
        }
    }
    Ok(Vec::new())
}

pub(super) fn spool_packet_fields(
    identity: &antinomie_monitor_core::packet_filter::CaptureIdentity,
    live: bool,
    cancel: &Arc<AtomicBool>,
    geoip: bool,
) -> Result<
    (
        Arc<std::sync::Mutex<PacketSpool>>,
        antinomie_monitor_core::packet_filter::StreamExtent,
    ),
    String,
> {
    let spool = Arc::new(std::sync::Mutex::new(PacketSpool::new()?));
    let writer = Arc::clone(&spool);
    let fields: Vec<_> = TSHARK_FIELDS
        .iter()
        .enumerate()
        .filter(|(at, _)| geoip || !(31..35).contains(at))
        .map(|(_, field)| *field)
        .collect();
    let extent = antinomie_monitor_core::packet_filter::stream_fields(
        identity,
        "(ip || ipv6) && !tcp.analysis.retransmission",
        &fields,
        live,
        Arc::clone(cancel),
        move |line| {
            let mut spool = writer.lock().map_err(|_| "metadata spool lock poisoned")?;
            if geoip {
                spool.push(line)
            } else {
                let mut fields = tsv_fields(line)?;
                if fields.len() != TSHARK_FIELDS.len() - 4 {
                    return Err("TShark returned a different field layout".into());
                }
                for _ in 0..4 {
                    fields.insert(31, String::new());
                }
                let padded = fields
                    .iter()
                    .map(|field| format!("\"{}\"", field.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join("\t");
                spool.push(&padded)
            }
        },
    )?;
    Ok((spool, extent))
}

/// TShark reassembles the complete saved PCAP or an owned complete-record live
/// prefix. Output is disk-backed; response lookups use a fixed-size binary
/// index and memory holds only one query page. Source PCAP is unchanged.
#[cfg(test)]
pub(super) fn scan_pcap_query(
    path: &Path,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
) -> Result<PacketIndex, String> {
    scan_pcap_query_observed(
        path,
        pcap_open,
        cancel,
        request,
        &mut network::Inventory::default(),
        &mut |_, _, _, _| Ok(()),
    )
}

pub(super) fn scan_pcap_query_observed(
    path: &Path,
    pcap_open: bool,
    cancel: &Arc<AtomicBool>,
    request: &ScanRequest,
    inventory: &mut network::Inventory,
    observe: &mut impl FnMut(bool, &[Cell], &str, &str) -> Result<(), String>,
) -> Result<PacketIndex, String> {
    if !request.owned_pcap && request.identity.is_some() && request.started_ms.is_none() {
        return Err(
            "host start time unavailable; network evidence cannot be scoped to this run".into(),
        );
    }
    if !request.owned_pcap
        && request.identity.is_some()
        && request.run_finished
        && request.ended_ms.is_none()
    {
        return Err(
            "host end time unavailable; network evidence cannot be scoped to this run".into(),
        );
    }
    use std::io::{BufRead, BufReader};
    let identity = antinomie_monitor_core::packet_filter::CaptureIdentity::read(path)?;
    let use_geoip = request.address_lookup != AddressLookup::Whois;
    let (spool, extent) = match spool_packet_fields(&identity, pcap_open, cancel, use_geoip) {
        Err(error) if use_geoip && error.contains("geoip") && !cancel.load(Ordering::Relaxed) => {
            spool_packet_fields(&identity, pcap_open, cancel, false)?
        }
        result => result?,
    };
    let state = spool.lock().map_err(|_| "metadata spool lock poisoned")?;
    let mut rows = BufReader::new(
        std::fs::File::open(state.directory.join("rows.tsv")).map_err(|error| error.to_string())?,
    );
    let mut responses = BufReader::new(
        std::fs::File::open(state.directory.join("rows.tsv")).map_err(|error| error.to_string())?,
    );
    let mut offsets = std::fs::File::open(state.directory.join("frames.idx"))
        .map_err(|error| error.to_string())?;
    let mut index = PacketIndex {
        counts: None,
        coverage: String::new(),
        http: Vec::new(),
        http_omitted: 0,
        dns: Vec::new(),
        dns_omitted: 0,
        ips: Vec::new(),
        ips_omitted: 0,
        hosts: Vec::new(),
        hosts_omitted: 0,
        network_warning: None,
    };
    inventory.capture = path.display().to_string();
    let mut http_page = sorting::Page::new(request, 3, cancel);
    let mut dns_page = sorting::Page::new(request, 4, cancel);
    let http_query = query::compile_table(&request.filters[3], HTTP_FIELDS);
    let dns_query = query::compile_table(&request.filters[4], DNS_FIELDS);
    let mut line = String::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        line.clear();
        if rows
            .read_line(&mut line)
            .map_err(|error| error.to_string())?
            == 0
        {
            break;
        }
        let fields = tsv_fields(&line)?;
        if fields.len() != TSHARK_FIELDS.len() {
            return Err("TShark returned a different field layout".into());
        }
        let field = |at: usize| fields[at].as_str();
        let frame = field(0)
            .parse::<u64>()
            .map_err(|_| "invalid TShark frame number")?;
        let time = epoch_us(field(1));
        if !network::in_window(request, time) {
            continue;
        }
        let destination = if field(4).is_empty() {
            field(5)
        } else {
            field(4)
        };
        inventory.destination(
            destination,
            frame,
            if field(31).is_empty() {
                field(32)
            } else {
                field(31)
            },
            if field(33).is_empty() {
                field(34)
            } else {
                field(33)
            },
        );
        for hostname in field(35).split('\u{1f}').filter(|name| !name.is_empty()) {
            inventory.host(hostname, frame, time, &[destination.into()], "TLS SNI");
        }
        let endpoints = format!(
            "{}:{} → {}:{}",
            if field(2).is_empty() {
                field(3)
            } else {
                field(2)
            },
            if field(6).is_empty() {
                field(8)
            } else {
                field(6)
            },
            if field(4).is_empty() {
                field(5)
            } else {
                field(4)
            },
            if field(7).is_empty() {
                field(9)
            } else {
                field(7)
            }
        );
        if !field(11).is_empty() {
            let methods = field(11).split('\u{1f}').collect::<Vec<_>>();
            let response_frames = field(16)
                .split('\u{1f}')
                .filter_map(|id| id.parse::<u64>().ok())
                .collect::<Vec<_>>();
            for (at, method) in methods.iter().enumerate() {
                let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
                let response = match response_frames.get(at).copied() {
                    Some(frame) => spool_response(frame, &mut offsets, &mut responses)?,
                    None => Vec::new(),
                };
                let status = response
                    .get(15)
                    .and_then(|value| value.split('\u{1f}').next())
                    .and_then(|value| value.parse::<u16>().ok());
                let mut row = vec![
                    cell(format!("#{frame}"), theme::text(), true),
                    cell(
                        time.map_or("Unavailable".into(), crate::time_format::short_time_us),
                        theme::text(),
                        true,
                    ),
                    cell(&endpoints, theme::text(), true),
                    cell(*method, theme::text(), false),
                    cell(item(12), theme::text(), false),
                    cell(item(13), theme::text(), false),
                    cell(item(14), theme::text(), false),
                    cell(
                        status.map_or("—".into(), |status| status.to_string()),
                        theme::text(),
                        true,
                    ),
                    cell(field(16), theme::text(), true),
                    cell("unknown", theme::text(), false),
                    cell("decoded; capture gaps unknown", theme::text(), false),
                ];
                row[0].values = vec![
                    ("capture.path", RowValue::Text(path.display().to_string())),
                    ("frame.number", RowValue::Number(i128::from(frame))),
                    (
                        "frame.time_us",
                        time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                    ),
                    ("network.endpoints", RowValue::Text(endpoints.clone())),
                    ("http.method", RowValue::Text((*method).into())),
                    ("http.host", text_value(item(12))),
                    ("http.uri", text_value(item(13))),
                    ("http.version", text_value(item(14))),
                    (
                        "http.status",
                        status.map_or(RowValue::Missing, |status| {
                            RowValue::Number(i128::from(status))
                        }),
                    ),
                    ("entry.complete", RowValue::Missing),
                    ("network.attribution", RowValue::Text("unknown".into())),
                ];
                inventory.host(item(12), frame, time, &[destination.into()], "HTTP");
                // Keep protocol/version metadata in typed filters, but only requested display columns.
                row.remove(10);
                row.remove(9);
                row.remove(6);
                observe(
                    true,
                    &row,
                    destination,
                    if field(7).is_empty() {
                        field(9)
                    } else {
                        field(7)
                    },
                )?;
                if http_query.keep_table(&row[0].values) {
                    http_page.push(row)?;
                }
            }
        }
        if !field(19).is_empty() && tshark_boolean(field(22)) == Some(false) {
            let response_frame = field(28)
                .split('\u{1f}')
                .next()
                .and_then(|id| id.parse::<u64>().ok());
            let response = match response_frame {
                Some(frame) => spool_response(frame, &mut offsets, &mut responses)?,
                None => Vec::new(),
            };
            let rcode = response.get(23).and_then(|value| value.parse::<u16>().ok());
            let answers = [24, 25, 26, 27]
                .iter()
                .filter_map(|at| response.get(*at))
                .filter(|text| !text.is_empty())
                .flat_map(|text| text.split('\u{1f}').map(str::to_owned))
                .collect::<Vec<_>>();
            for (at, name) in field(19).split('\u{1f}').enumerate() {
                let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
                let id = field(18).split('\u{1f}').next().and_then(parse_integer);
                let protocol = if field(6).is_empty() { "UDP" } else { "TCP" };
                let retry = tshark_boolean(field(30));
                let mut row = vec![
                    cell(format!("#{frame}"), theme::text(), true),
                    cell(
                        time.map_or("Unavailable".into(), crate::time_format::short_time_us),
                        theme::text(),
                        true,
                    ),
                    cell(&endpoints, theme::text(), true),
                    cell(field(18), theme::text(), true),
                    cell(name, theme::text(), false),
                    cell(network::qtype(item(20)), theme::text(), false),
                    cell(item(21), theme::text(), false),
                    cell(protocol, theme::text(), false),
                    cell(
                        rcode.map_or("—".into(), |code| code.to_string()),
                        theme::text(),
                        true,
                    ),
                    cell(answers.join(", "), theme::text(), false),
                    cell(field(28), theme::text(), true),
                    cell(
                        match retry {
                            Some(true) => "retry",
                            Some(false) => "query",
                            None => "—",
                        },
                        theme::text(),
                        false,
                    ),
                ];
                row[0].values = vec![
                    ("capture.path", RowValue::Text(path.display().to_string())),
                    ("frame.number", RowValue::Number(i128::from(frame))),
                    (
                        "frame.time_us",
                        time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                    ),
                    ("network.endpoints", RowValue::Text(endpoints.clone())),
                    ("dns.id", id.map_or(RowValue::Missing, RowValue::Number)),
                    ("dns.name", RowValue::Text(name.into())),
                    ("dns.type", text_value(&network::qtype(item(20)))),
                    ("dns.class", text_value(item(21))),
                    ("dns.protocol", RowValue::Text(protocol.into())),
                    (
                        "dns.rcode",
                        rcode.map_or(RowValue::Missing, |code| RowValue::Number(i128::from(code))),
                    ),
                    ("dns.answers", RowValue::List(answers.clone())),
                    ("dns.retry", retry.map_or(RowValue::Missing, RowValue::Bool)),
                ];
                let addresses: Vec<_> = answers
                    .iter()
                    .filter(|answer| answer.parse::<std::net::IpAddr>().is_ok())
                    .cloned()
                    .collect();
                inventory.host(name, frame, time, &addresses, "DNS lookup");
                for at in [11, 7, 6, 3, 1] {
                    row.remove(at);
                }
                observe(
                    false,
                    &row,
                    destination,
                    if field(7).is_empty() {
                        field(9)
                    } else {
                        field(7)
                    },
                )?;
                if dns_query.keep_table(&row[0].values) {
                    dns_page.push(row)?;
                }
            }
        }
    }
    if request.address_lookup != AddressLookup::Tshark {
        network::enrich_public(inventory, cancel, &mut index.network_warning)?;
    }
    let (ips, hosts) = inventory.rows();
    index.counts = Some((extent.packet_count, ips.len() as u64, hosts.len() as u64));
    let (http, http_omitted, http_count) = http_page.finish()?;
    let (dns, dns_omitted, dns_count) = dns_page.finish()?;
    index.http = http;
    index.http_omitted = http_omitted;
    index.dns = dns;
    index.dns_omitted = dns_omitted;
    for (slot, rows, fields) in [
        (6, ips, network::IP_FIELDS),
        (7, hosts, network::HOST_FIELDS),
    ] {
        let query = query::compile_table(&request.filters[slot], fields);
        let mut page = sorting::Page::new(request, slot, cancel);
        for row in rows
            .into_iter()
            .filter(|row| query.keep_table(&row[0].values))
        {
            page.push(row)?;
        }
        let (rows, omitted, _) = page.finish()?;
        if slot == 6 {
            index.ips = rows;
            index.ips_omitted = omitted;
        } else {
            index.hosts = rows;
            index.hosts_omitted = omitted;
        }
    }
    if inventory.omitted > 0 {
        let retention =
            "Network inventory retention limit reached; packet evidence remains available.";
        index.network_warning = Some(match index.network_warning.take() {
            Some(existing) => format!("{retention} {existing}"),
            None => retention.into(),
        });
    }
    index.coverage = format!("TShark HTTP/1 and DNS/UDP/TCP; {} capture frames; complete-record extent {}/{} octets; HTTP matches {http_count}, DNS matches {dns_count}; response correlation uses decoder frame links; attribution unknown. TLS server names are read from handshakes; the content of HTTPS and HTTP/3 is encrypted, and cleartext HTTP/2 and encrypted DNS are not decoded{}",
        extent.packet_count, extent.complete_extent, extent.file_size,
        if pcap_open { "; live prefix watermark; final capture requires reanalysis" } else { "" });
    Ok(index)
}

pub(super) fn text_value(text: &str) -> RowValue {
    if text.is_empty() {
        RowValue::Missing
    } else {
        RowValue::Text(text.into())
    }
}

/// TShark releases format FT_BOOLEAN as textual True/False or numeric 1/0.
/// An absent, malformed or mixed repeated field stays unknown.
pub(super) fn tshark_boolean(text: &str) -> Option<bool> {
    let mut value = None;
    for item in text.split('\u{1f}') {
        let next = match item {
            "1" => true,
            "0" => false,
            text if text.eq_ignore_ascii_case("true") => true,
            text if text.eq_ignore_ascii_case("false") => false,
            _ => return None,
        };
        if value.is_some_and(|value| value != next) {
            return None;
        }
        value = Some(next);
    }
    value
}

fn parse_integer(text: &str) -> Option<i128> {
    if let Some(hex) = text.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else {
        text.parse().ok()
    }
}

#[cfg(test)]
const PACKET_BOUND: usize = 4096;

/// Read the owned pcap to the end, or to [`PACKET_BOUND`] frames. Reconstruction
/// uses those frames. A later frame is counted and not decoded.
#[cfg(test)]
pub(super) fn scan_pcap(
    path: &Path,
    pcap_open: bool,
    cancel: &AtomicBool,
) -> Result<PacketIndex, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    if !path.is_file() {
        return Err("pcap path is not a file".into());
    }
    let mut offset = 0u64;
    let mut number = 0u64;
    let mut held: Vec<(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)> = Vec::new();
    let mut omitted = 0u64;
    let mut stopped = false;
    loop {
        if cancel.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
        let page = antinomie_monitor_core::network::read_page(path, offset, number, 256)?;
        if page.packets.is_empty() {
            break;
        }
        for packet in page.packets {
            if held.len() >= PACKET_BOUND {
                omitted += 1;
                continue;
            }
            let bytes = antinomie_monitor_core::network::frame(path, packet.offset)?;
            held.push((packet, bytes));
        }
        if page.next_offset <= offset {
            break;
        }
        offset = page.next_offset;
        number = page.next_number;
    }
    let captured: Vec<_> = held
        .iter()
        .map(
            |(packet, bytes)| antinomie_monitor_core::network::CapturedFrame {
                number: packet.number,
                time_us: packet.time_us,
                bytes,
            },
        )
        .collect();
    let built = antinomie_monitor_core::network::reconstruct(&captured);
    let mut http = Vec::new();
    let mut http_omitted = 0u64;
    for request in &built.http {
        if http.len() >= STORED_ROWS {
            http_omitted += 1;
            continue;
        }
        http.push(http_index_row(request, &held));
    }
    let mut dns = Vec::new();
    let mut dns_omitted = 0u64;
    for query in &built.dns {
        if dns.len() >= STORED_ROWS {
            dns_omitted += 1;
            continue;
        }
        dns.push(dns_index_row(query, &held));
    }
    let mut coverage = format!(
        "pcap frames read {}, omitted {omitted}; retransmissions dropped {}; HTTPS segments {}; HTTP/2 prefaces {}; HTTP requests stored {}, omitted {http_omitted}; DNS requests stored {}, omitted {dns_omitted}",
        held.len(),
        built.retransmissions_dropped,
        built.https_segments,
        built.http2_prefaces,
        http.len(),
        dns.len()
    );
    if stopped {
        coverage.push_str("; scan stopped before the end of the pcap");
    } else if pcap_open {
        coverage.push_str(
            "; the capture file was read to its current end; a live capture may still grow",
        );
    }
    Ok(PacketIndex {
        counts: None,
        coverage,
        http,
        http_omitted,
        dns,
        dns_omitted,
        ips: Vec::new(),
        ips_omitted: 0,
        hosts: Vec::new(),
        hosts_omitted: 0,
        network_warning: None,
    })
}

#[cfg(test)]
fn packet_ends(
    number: Option<u64>,
    held: &[(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)],
) -> String {
    number
        .and_then(|number| held.iter().find(|(packet, _)| packet.number == number))
        .map(|(packet, _)| format!("{} → {}", packet.source, packet.destination))
        .unwrap_or_else(|| "—".into())
}

#[cfg(test)]
fn http_index_row(
    request: &antinomie_monitor_core::network::ReconstructedHttp,
    held: &[(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)],
) -> Vec<Cell> {
    let mut row = flow(
        request
            .request_frames
            .first()
            .map(|number| format!("#{number}"))
            .unwrap_or_else(|| "—".into()),
        packet_ends(request.request_frames.first().copied(), held),
        format!("{} {} {}", request.method, request.uri, request.version),
    );
    row.push(cell(
        request
            .status
            .map(|status| status.to_string())
            .unwrap_or_else(|| "—".into()),
        theme::text(),
        false,
    ));
    row.push(cell("—".to_string(), theme::text(), true));
    row
}

#[cfg(test)]
fn dns_index_row(
    query: &antinomie_monitor_core::network::ReconstructedDns,
    held: &[(antinomie_monitor_core::network::NetworkPacket, Vec<u8>)],
) -> Vec<Cell> {
    let detail = if query.answers.is_empty() {
        format!("{} {} {}", query.name, query.qtype, query.class_name)
    } else {
        format!(
            "{} {} {} → {}",
            query.name,
            query.qtype,
            query.class_name,
            query.answers.join(", ")
        )
    };
    let mut row = flow(
        query
            .query_frames
            .first()
            .map(|number| format!("#{number}"))
            .unwrap_or_else(|| "—".into()),
        packet_ends(query.query_frames.first().copied(), held),
        detail,
    );
    let kind = if query.retry {
        "retry"
    } else if query.rcode.is_some() {
        "response"
    } else {
        "query"
    };
    row.push(cell(
        format!("{kind} {}", query.protocol),
        theme::text(),
        false,
    ));
    row
}

pub(super) fn walk_pages(
    recording: &antinomie_monitor_core::recording::Recording,
    cancel: &AtomicBool,
    mut each: impl FnMut(&[InvocationSummary]) -> Result<(), String>,
) -> Result<(u64, bool, Vec<String>), String> {
    let mut offset = 0u64;
    let mut seen = 0u64;
    let mut issues = Vec::new();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok((seen, false, issues));
        }
        let page = match recording.invocation_page_cancellable(offset, 256, cancel) {
            Ok(page) => page,
            Err(error) => {
                let text = error.to_string();
                if text.contains("cancelled") {
                    return Ok((seen, false, issues));
                }
                return Err(text);
            }
        };
        seen += page.invocations.len() as u64;
        // The same page diagnostic repeats on every page that has one.
        for issue in page.issues {
            if issues.len() < 32 && !issues.contains(&issue) {
                issues.push(issue);
            }
        }
        each(&page.invocations)?;
        match page.next_offset {
            Some(next) if next > offset => offset = next,
            Some(_) => return Err("archive cursor did not advance".into()),
            None => return Ok((seen, true, issues)),
        }
    }
}

pub(super) fn note_cookie_sets(
    sets: &mut std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>>,
    invocations: &[InvocationSummary],
) {
    for invocation in invocations {
        for event in invocation
            .entry
            .iter()
            .chain(invocation.exit.iter())
            .chain(invocation.async_events.iter())
        {
            if event.tid == 0 {
                continue;
            }
            sets.entry(event.tid)
                .or_default()
                .insert(invocation.task_cookie);
        }
    }
}

pub(super) fn resolve_cookies(
    sets: &std::collections::BTreeMap<u32, std::collections::BTreeSet<u64>>,
) -> std::collections::BTreeMap<u32, u64> {
    sets.iter()
        .filter(|(_, cookies)| cookies.len() == 1)
        .map(|(pid, cookies)| (*pid, cookies.iter().next().copied().unwrap_or(0)))
        .collect()
}

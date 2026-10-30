// SPDX-License-Identifier: GPL-3.0-only
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
    // What the sessions and the HTTP/2 rows are built from.
    "_ws.col.protocol",
    "tls.handshake.type",
    "tls.handshake.extensions_alpn_str",
    "tls.handshake.ciphersuite",
    "tls.handshake.version",
    "ssh.protocol",
    "http2.headers.method",
    "http2.headers.authority",
    "http2.headers.path",
    "tls.handshake.ja3",
    "tls.handshake.ja4",
    "tls.handshake.ja3s",
    "tls.handshake.certificate",
    // The size of the frame and the version a hello names.
    "frame.len",
    "tls.handshake.extensions.supported_version",
];

const F_PROTOCOL: usize = 36;
const F_TLS_TYPE: usize = 37;
const F_ALPN: usize = 38;
const F_CIPHERS: usize = 39;
const F_SSH_BANNER: usize = 41;
const F_H2_METHOD: usize = 42;
const F_H2_AUTHORITY: usize = 43;
const F_H2_PATH: usize = 44;
const F_JA3: usize = 45;
const F_JA4: usize = 46;
const F_JA3S: usize = 47;
const F_CERT: usize = 48;
const F_FRAME_LEN: usize = 49;
const F_TLS_SUPPORTED: usize = 50;
/// Columns older TShark releases lack (the TLS fingerprints and certificate).
const FINGERPRINT_FIELDS: std::ops::Range<usize> = F_JA3..F_CERT + 1;
/// Columns of the GeoIP lookup, requested only when it is configured.
const GEOIP_FIELDS: std::ops::Range<usize> = 31..35;

pub(super) const SESSION_HEADERS: &[&str] = &[
    "Frame",
    "Time",
    "Endpoint",
    "Protocol",
    "Server name",
    "ALPN",
    "Details",
    "Fingerprint",
];

/// Which rows of a capture a callback is given.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RowKind {
    Http,
    Dns,
    Session,
}

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
    // Columns left out: GeoIP unless it is configured, and the TLS
    // fingerprints an older TShark does not have. They come back empty, so
    // every row keeps the layout of TSHARK_FIELDS.
    let mut skipped: Vec<usize> = if geoip {
        Vec::new()
    } else {
        GEOIP_FIELDS.collect()
    };
    let optional: Vec<&str> = FINGERPRINT_FIELDS.map(|at| TSHARK_FIELDS[at]).collect();
    if let Ok(known) =
        antinomie_monitor_core::packet_filter::known_fields(&optional, Arc::clone(cancel))
    {
        skipped.extend(
            known
                .iter()
                .zip(FINGERPRINT_FIELDS)
                .filter(|(known, _)| !**known)
                .map(|(_, at)| at),
        );
    }
    skipped.sort_unstable();
    let fields: Vec<_> = TSHARK_FIELDS
        .iter()
        .enumerate()
        .filter(|(at, _)| !skipped.contains(at))
        .map(|(_, field)| *field)
        .collect();
    let expected = fields.len();
    let extent = antinomie_monitor_core::packet_filter::stream_fields(
        identity,
        "(ip || ipv6) && !tcp.analysis.retransmission",
        &fields,
        live,
        Arc::clone(cancel),
        move |line| {
            let mut spool = writer.lock().map_err(|_| "metadata spool lock poisoned")?;
            if skipped.is_empty() {
                return spool.push(line);
            }
            let mut fields = tsv_fields(line)?;
            if fields.len() != expected {
                return Err("TShark returned a different field layout".into());
            }
            for &at in &skipped {
                fields.insert(at, String::new());
            }
            let padded = fields
                .iter()
                .map(|field| format!("\"{}\"", field.replace('"', "\"\"")))
                .collect::<Vec<_>>()
                .join("\t");
            spool.push(&padded)
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
    observe: &mut impl FnMut(RowKind, &[Cell], &str, &str) -> Result<(), String>,
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
        network_warning: None,
        ..PacketIndex::default()
    };
    inventory.capture = path.display().to_string();
    let mut http_page = sorting::Page::new(request, 3, cancel);
    let http_query = query::compile_table(&request.filters[3], HTTP_FIELDS);
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
        let source = if field(2).is_empty() {
            field(3)
        } else {
            field(2)
        };
        let source_port = if field(6).is_empty() {
            field(8)
        } else {
            field(6)
        };
        let destination_port = if field(7).is_empty() {
            field(9)
        } else {
            field(7)
        };
        inventory.packet(&network::PacketFacts {
            source,
            source_port,
            destination,
            destination_port,
            protocol: if field(6).is_empty() && field(7).is_empty() {
                "udp"
            } else {
                "tcp"
            },
            frame,
            time,
            length: field(F_FRAME_LEN).parse().unwrap_or(0),
        });
        let server_name_source = if field(F_PROTOCOL) == "QUIC" {
            "QUIC SNI"
        } else {
            "TLS SNI"
        };
        for hostname in field(35).split('\u{1f}').filter(|name| !name.is_empty()) {
            inventory.host(
                hostname,
                frame,
                time,
                &[destination.into()],
                server_name_source,
            );
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
                let row = http_row(
                    path,
                    &HttpRequest {
                        frame,
                        time,
                        endpoints: &endpoints,
                        method,
                        host: item(12),
                        uri: item(13),
                        version: item(14),
                        status,
                        response_frames: field(16),
                    },
                );
                inventory.host(item(12), frame, time, &[destination.into()], "HTTP");
                inventory.url(&network::UrlFacts {
                    frame,
                    time,
                    method,
                    host: item(12),
                    uri: item(13),
                    version: item(14),
                    status,
                    destination,
                    port: destination_port,
                });
                observe(
                    RowKind::Http,
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
                if let Some(code) = rcode {
                    inventory.host_rcode(
                        name,
                        &network::rcode_name(i128::from(code), !answers.is_empty()),
                    );
                }
                for at in [10, 6, 5, 2] {
                    row.remove(at);
                }
                observe(
                    RowKind::Dns,
                    &row,
                    destination,
                    if field(7).is_empty() {
                        field(9)
                    } else {
                        field(7)
                    },
                )?;
            }
        }
        let destination_port = if field(7).is_empty() {
            field(9)
        } else {
            field(7)
        };
        // Cleartext HTTP/2: TShark decodes the request headers; the response
        // is in another frame (a stream) and is not matched here.
        for (at, method) in field(F_H2_METHOD)
            .split('\u{1f}')
            .filter(|method| !method.is_empty())
            .enumerate()
        {
            let item = |column: usize| field(column).split('\u{1f}').nth(at).unwrap_or("");
            let row = http_row(
                path,
                &HttpRequest {
                    frame,
                    time,
                    endpoints: &endpoints,
                    method,
                    host: item(F_H2_AUTHORITY),
                    uri: item(F_H2_PATH),
                    version: "HTTP/2",
                    status: None,
                    response_frames: "",
                },
            );
            inventory.host(
                item(F_H2_AUTHORITY),
                frame,
                time,
                &[destination.into()],
                "HTTP/2",
            );
            inventory.url(&network::UrlFacts {
                frame,
                time,
                method,
                host: item(F_H2_AUTHORITY),
                uri: item(F_H2_PATH),
                version: "HTTP/2",
                status: None,
                destination,
                port: destination_port,
            });
            observe(RowKind::Http, &row, destination, destination_port)?;
            if http_query.keep_table(&row[0].values) {
                http_page.push(row)?;
            }
        }
        inventory.tls_frame(&network::TlsFrame {
            frame,
            time,
            stream: field(10),
            source: (source, source_port),
            destination: (destination, destination_port),
            kinds: field(F_TLS_TYPE)
                .split('\u{1f}')
                .filter(|kind| !kind.is_empty())
                .collect(),
            sni: field(35),
            alpn: field(F_ALPN),
            version: field(40),
            supported: field(F_TLS_SUPPORTED),
            ja3: field(F_JA3),
            ja4: field(F_JA4),
            ja3s: field(F_JA3S),
            certificate: field(F_CERT),
        });
        // TLS and QUIC handshakes and SSH banners, as TShark parsed them
        // without any key: what the encrypted session names about itself.
        for row in session_rows(path, frame, time, &endpoints, &fields) {
            observe(RowKind::Session, &row, destination, destination_port)?;
        }
    }
    if request.address_lookup != AddressLookup::Tshark {
        network::enrich_public(inventory, cancel, &mut index.network_warning)?;
    }
    let (ips, hosts) = inventory.rows();
    index.counts = Some((extent.packet_count, ips.len() as u64, hosts.len() as u64));
    let (http, http_omitted, http_count) = http_page.finish()?;
    index.http = http;
    index.http_omitted = http_omitted;
    if inventory.omitted > 0 {
        let retention =
            "The network lists are full, so some destinations are not listed. Every packet is still in the capture.";
        index.network_warning = Some(match index.network_warning.take() {
            Some(existing) => format!("{retention} {existing}"),
            None => retention.into(),
        });
    }
    index.coverage = format!("TShark parses every packet; {} capture frames; complete-record extent {}/{} octets; HTTP matches {http_count}; HTTP/1 response correlation uses decoder frame links; attribution unknown. TLS and QUIC server names, ALPN and SSH banners come from handshakes read without keys; the content of HTTPS, HTTP/3 and encrypted DNS stays encrypted, and cleartext HTTP/2 requests are listed without their responses{}",
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

pub(super) struct HttpRequest<'a> {
    frame: u64,
    time: Option<u64>,
    endpoints: &'a str,
    method: &'a str,
    host: &'a str,
    uri: &'a str,
    version: &'a str,
    status: Option<u16>,
    response_frames: &'a str,
}

/// One HTTP request row. The protocol version stays a typed filter value and
/// is not a display column.
fn http_row(path: &Path, request: &HttpRequest<'_>) -> Vec<Cell> {
    let time = request.time;
    let mut row = vec![
        cell(format!("#{}", request.frame), theme::text(), true),
        cell(
            time.map_or("Unavailable".into(), crate::time_format::short_time_us),
            theme::text(),
            true,
        ),
        cell(request.endpoints, theme::text(), true),
        cell(request.method, theme::text(), false),
        cell(request.host, theme::text(), false),
        cell(request.uri, theme::text(), false),
        cell(
            request
                .status
                .map_or("—".into(), |status| status.to_string()),
            theme::text(),
            true,
        ),
        cell(request.response_frames, theme::text(), true),
    ];
    row[0].values = vec![
        ("capture.path", RowValue::Text(path.display().to_string())),
        ("frame.number", RowValue::Number(i128::from(request.frame))),
        (
            "frame.time_us",
            time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
        ),
        (
            "network.endpoints",
            RowValue::Text(request.endpoints.into()),
        ),
        ("http.method", RowValue::Text(request.method.into())),
        ("http.host", text_value(request.host)),
        ("http.uri", text_value(request.uri)),
        ("http.version", text_value(request.version)),
        (
            "http.status",
            request.status.map_or(RowValue::Missing, |status| {
                RowValue::Number(i128::from(status))
            }),
        ),
        ("entry.complete", RowValue::Missing),
        ("network.attribution", RowValue::Text("unknown".into())),
    ];
    row
}

/// Session rows of one frame: a TLS or QUIC client or server hello, or an SSH
/// banner. Everything shown is a value TShark printed.
fn session_rows(
    path: &Path,
    frame: u64,
    time: Option<u64>,
    endpoints: &str,
    fields: &[String],
) -> Vec<Vec<Cell>> {
    let field = |at: usize| fields[at].as_str();
    let list = |at: usize| -> Vec<String> {
        field(at)
            .split('\u{1f}')
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let protocol = field(F_PROTOCOL);
    let handshakes = list(F_TLS_TYPE);
    let mut kinds: Vec<(&str, String, String)> = Vec::new();
    if handshakes.iter().any(|kind| kind == "1") {
        let offered = list(F_CIPHERS).len();
        kinds.push((
            "client hello",
            format!("{offered} cipher suites offered"),
            field(F_ALPN).replace('\u{1f}', ", "),
        ));
    }
    if handshakes.iter().any(|kind| kind == "2") {
        kinds.push((
            "server hello",
            format!("cipher suite {}", field(F_CIPHERS).replace('\u{1f}', ", ")),
            field(F_ALPN).replace('\u{1f}', ", "),
        ));
    }
    if !field(F_SSH_BANNER).is_empty() {
        kinds.push((
            "banner",
            field(F_SSH_BANNER).replace('\u{1f}', ", "),
            String::new(),
        ));
    }
    kinds
        .into_iter()
        .map(|(kind, details, alpn)| {
            let server_name = if kind == "client hello" {
                field(35).replace('\u{1f}', ", ")
            } else {
                String::new()
            };
            let fingerprint = [field(F_JA3), field(F_JA4)]
                .iter()
                .filter(|value| !value.is_empty())
                .map(|value| value.replace('\u{1f}', ", "))
                .collect::<Vec<_>>()
                .join(" ");
            let shown_protocol = format!("{protocol} {kind}");
            let mut row = vec![
                cell(format!("#{frame}"), theme::text(), true),
                cell(
                    time.map_or("Unavailable".into(), crate::time_format::short_time_us),
                    theme::text(),
                    true,
                ),
                cell(endpoints, theme::text(), true),
                cell(&shown_protocol, theme::text(), false),
                cell(&server_name, theme::text(), false),
                cell(&alpn, theme::text(), false),
                cell(&details, theme::text(), false),
                cell(&fingerprint, theme::text(), true),
            ];
            row[0].values = vec![
                ("capture.path", RowValue::Text(path.display().to_string())),
                ("frame.number", RowValue::Number(i128::from(frame))),
                (
                    "frame.time_us",
                    time.map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                ("network.endpoints", RowValue::Text(endpoints.into())),
                ("session.protocol", text_value(protocol)),
                ("session.kind", RowValue::Text(kind.into())),
                ("session.server_name", text_value(&server_name)),
                (
                    "session.alpn",
                    RowValue::List(
                        alpn.split(", ")
                            .filter(|a| !a.is_empty())
                            .map(str::to_owned)
                            .collect(),
                    ),
                ),
                ("session.details", text_value(&details)),
                ("session.fingerprint", text_value(&fingerprint)),
            ];
            row
        })
        .collect()
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

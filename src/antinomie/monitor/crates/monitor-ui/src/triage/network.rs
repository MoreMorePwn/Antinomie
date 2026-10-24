// SPDX-License-Identifier: GPL-3.0-only
//! Summaries of destinations and observed hostnames.
//! Public-address enrichment runs in the index worker, never while drawing.
use super::*;
use antinomie_monitor_core::ioc::indicator::{
    Collector, Evidence, Jump, Seen, Source, TlsFacts, Via,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// How a public destination receives a country and organization.
/// Local addresses are never queried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AddressLookup {
    /// Installed TShark GeoIP fields only.
    #[default]
    Tshark,
    /// `dig` and `whois` on this machine. TShark GeoIP fields are not requested.
    Whois,
    /// TShark GeoIP first. `dig` and `whois` fill a missing country or organization.
    TsharkThenWhois,
}
const INVENTORY_LIMIT: usize = 16384;

/// Only an identity-matching artifact manifest proves capture ownership.
/// A currently open capture from the same boot alone is insufficient.
pub(super) fn owned_capture(
    directory: &Path,
    identity: Option<&(String, String, String)>,
    path: &Path,
) -> Result<bool, String> {
    let Some((vm, boot, run)) = identity else {
        return Ok(false);
    };
    let Some(artifacts) = antinomie_monitor_core::RunArtifacts::load(directory)? else {
        return Ok(false);
    };
    if artifacts.run_id != *run || artifacts.vm_id != *vm || artifacts.boot_id != *boot {
        return Err("run artifact identity mismatch".into());
    }
    Ok(artifacts
        .network_captures
        .iter()
        .any(|candidate| candidate == path))
}

pub(super) fn in_window(request: &ScanRequest, packet_us: Option<u64>) -> bool {
    request.owned_pcap
        || (!request
            .started_ms
            .is_some_and(|start| packet_us.is_none_or(|time| time / 1000 < start))
            && !request
                .ended_ms
                .is_some_and(|end| packet_us.is_none_or(|time| time / 1000 > end)))
}

pub(super) const IP_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Capture segment of the evidence packet"),
    FieldSpec::text("network.ip", "Observed destination IP"),
    FieldSpec::text(
        "network.country",
        "Country from locally configured TShark GeoIP data",
    ),
    FieldSpec::text("network.organization", "Organization from local ASN data"),
    FieldSpec::number("frame.number", "First observed destination packet"),
];
pub(super) const HOST_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Capture segment of the evidence packet"),
    FieldSpec::number(
        "network.first_us",
        "First observed packet time in the capture clock",
    ),
    FieldSpec::number(
        "network.last_us",
        "Last observed packet time in the capture clock",
    ),
    FieldSpec::text("network.hostname", "DNS question, HTTP Host or TLS SNI"),
    FieldSpec::tags(
        "network.addresses",
        "Observed DNS addresses or connection destinations",
    ),
    FieldSpec::number("network.count", "Observed requests or client hellos"),
    FieldSpec::tags("network.sources", "DNS, HTTP or TLS"),
    FieldSpec::number("frame.number", "First original packet"),
];

pub(super) const SESSION_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Capture segment of the evidence packet"),
    FieldSpec::number("frame.number", "Original packet"),
    FieldSpec::number("frame.time_us", "Packet time in the capture clock"),
    FieldSpec::text("network.endpoints", "Source and destination endpoints"),
    FieldSpec::text("session.protocol", "Protocol column TShark printed"),
    FieldSpec::text("session.kind", "client hello, server hello or banner"),
    FieldSpec::text("session.server_name", "TLS or QUIC server name (SNI)"),
    FieldSpec::tags("session.alpn", "ALPN protocols offered or chosen"),
    FieldSpec::text("session.details", "Cipher suites or the SSH banner"),
    FieldSpec::text(
        "session.fingerprint",
        "JA3 and JA4 when TShark computes them",
    ),
];

/// The rebuilt Endpoints tab: one row per remote `ip:port`.
pub(super) const ENDPOINT_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Capture segment of the first frame"),
    FieldSpec::text("network.endpoint", "Remote ip:port"),
    FieldSpec::text("network.ip", "Remote IP"),
    FieldSpec::number("network.port", "Remote port"),
    FieldSpec::text("network.protocol", "tcp or udp"),
    FieldSpec::number("network.frames", "Frames to and from it"),
    FieldSpec::number("network.bytes", "Bytes of those frames"),
    FieldSpec::text(
        "network.country",
        "Country from locally configured TShark GeoIP data",
    ),
    FieldSpec::text("network.organization", "Organization from local ASN data"),
    FieldSpec::number(
        "network.first_us",
        "First observed packet time in the capture clock",
    ),
    FieldSpec::number(
        "network.last_us",
        "Last observed packet time in the capture clock",
    ),
    FieldSpec::number("frame.number", "First observed frame"),
];

/// The rebuilt Domains tab: the Hosts fields, and the DNS names they merge.
pub(super) const DOMAIN_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Capture segment of the evidence packet"),
    FieldSpec::number(
        "network.first_us",
        "First observed packet time in the capture clock",
    ),
    FieldSpec::number(
        "network.last_us",
        "Last observed packet time in the capture clock",
    ),
    FieldSpec::text("network.hostname", "DNS question, HTTP Host or TLS SNI"),
    FieldSpec::text("dns.name", "Same as network.hostname"),
    FieldSpec::tags(
        "network.addresses",
        "Observed DNS addresses or connection destinations",
    ),
    FieldSpec::number("network.count", "Observed requests or client hellos"),
    FieldSpec::tags("network.sources", "DNS, HTTP or TLS"),
    FieldSpec::tags("dns.rcode", "How DNS answered the name"),
    FieldSpec::number("frame.number", "First original packet"),
];

/// The rebuilt TLS tab: sessions grouped by server name, server and JA3.
pub(super) const TLS_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("capture.path", "Capture segment of the first hello"),
    FieldSpec::number("frame.number", "First client hello"),
    FieldSpec::number("frame.time_us", "Packet time in the capture clock"),
    FieldSpec::text("network.endpoints", "Server ip:port"),
    FieldSpec::text("session.server_name", "TLS or QUIC server name (SNI)"),
    FieldSpec::tags("session.alpn", "ALPN protocols offered"),
    FieldSpec::text("tls.sni", "TLS or QUIC server name (SNI)"),
    FieldSpec::text("tls.endpoint", "Server ip:port"),
    FieldSpec::text("tls.version", "The version the server hello named"),
    FieldSpec::text("tls.ja3", "JA3 client fingerprint"),
    FieldSpec::text("tls.ja4", "JA4 client fingerprint"),
    FieldSpec::text("tls.ja3s", "JA3S server fingerprint"),
    FieldSpec::text(
        "tls.cert",
        "SHA-1 of the server's certificate (not seen in TLS 1.3)",
    ),
    FieldSpec::number("tls.sessions", "Sessions in the group"),
];

#[derive(Default)]
struct Host {
    capture: String,
    frame: u64,
    first: Option<u64>,
    last: Option<u64>,
    count: u64,
    addresses: BTreeSet<String>,
    sources: BTreeSet<String>,
    /// How DNS answered the name: NOERROR, NXDOMAIN, ...
    rcodes: BTreeSet<String>,
}

/// One remote `ip:port` the capture shows traffic with.
#[derive(Default)]
struct Endpoint {
    capture: String,
    frame: u64,
    frames: u64,
    bytes: u64,
    first: Option<u64>,
    last: Option<u64>,
}

/// One TLS session, as far as its hellos showed.
#[derive(Default)]
struct TlsSession {
    capture: String,
    frame: u64,
    time: Option<u64>,
    server: Option<(IpAddr, u16)>,
    sni: String,
    alpn: String,
    version: String,
    ja3: String,
    ja4: String,
    ja3s: String,
    cert_sha1: String,
}

/// What a frame says about the two ends of its conversation.
pub(super) struct PacketFacts<'a> {
    pub source: &'a str,
    pub source_port: &'a str,
    pub destination: &'a str,
    pub destination_port: &'a str,
    pub protocol: &'static str,
    pub frame: u64,
    pub time: Option<u64>,
    pub length: u64,
}

/// One HTTP request of the capture.
pub(super) struct UrlFacts<'a> {
    pub frame: u64,
    pub time: Option<u64>,
    pub method: &'a str,
    pub host: &'a str,
    pub uri: &'a str,
    pub version: &'a str,
    pub status: Option<u16>,
    pub destination: &'a str,
    pub port: &'a str,
}

/// The TLS fields of one frame.
pub(super) struct TlsFrame<'a> {
    pub frame: u64,
    pub time: Option<u64>,
    /// `tcp.stream`, empty for datagrams.
    pub stream: &'a str,
    pub source: (&'a str, &'a str),
    pub destination: (&'a str, &'a str),
    /// Handshake types in the frame (1 client hello, 2 server hello, 11 certificate).
    pub kinds: Vec<&'a str>,
    pub sni: &'a str,
    pub alpn: &'a str,
    pub version: &'a str,
    pub supported: &'a str,
    pub ja3: &'a str,
    pub ja4: &'a str,
    pub ja3s: &'a str,
    pub certificate: &'a str,
}

#[derive(Default)]
pub(super) struct Inventory {
    ips: BTreeMap<String, (u64, String, String, String)>,
    hosts: BTreeMap<String, Host>,
    endpoints: BTreeMap<(IpAddr, u16, &'static str), Endpoint>,
    tls: BTreeMap<String, TlsSession>,
    /// The run's indicators the capture shows, for the IOC window.
    pub ioc: Collector,
    pub capture: String,
    pub omitted: u64,
}

/// The tables of the Network section's rebuilt tabs.
#[derive(Default)]
pub(super) struct Tables {
    pub endpoints: Vec<Vec<Cell>>,
    pub domains: Vec<Vec<Cell>>,
    pub tls: Vec<Vec<Cell>>,
}

fn port_of(text: &str) -> Option<u16> {
    text.parse().ok()
}

/// TLS version names from TShark's hexadecimal or decimal codes.
fn tls_version(code: &str) -> String {
    let value = code.strip_prefix("0x").map_or_else(
        || code.parse::<u32>().ok(),
        |hex| u32::from_str_radix(hex, 16).ok(),
    );
    match value {
        Some(0x0304) => "TLS 1.3".into(),
        Some(0x0303) => "TLS 1.2".into(),
        Some(0x0302) => "TLS 1.1".into(),
        Some(0x0301) => "TLS 1.0".into(),
        Some(0x0300) => "SSL 3.0".into(),
        _ => String::new(),
    }
}

/// A DNS response code by name; `NOERROR` with no answers says so.
pub(super) fn rcode_name(code: i128, answered: bool) -> String {
    match code {
        0 if answered => "NOERROR".into(),
        0 => "NOERROR, no answer".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => other.to_string(),
    }
}

fn packet_evidence(capture: &str, frame: u64) -> Evidence {
    Evidence {
        source: Source::Pcap,
        label: format!("Packets · frame {frame}"),
        jump: Jump::Packet {
            capture: capture.to_owned(),
            frame,
        },
    }
}

impl Inventory {
    pub fn destination(&mut self, ip: &str, frame: u64, country: &str, organization: &str) {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return;
        }
        let (country, organization) = if local_address(ip) {
            ("-", "local network")
        } else {
            (country, organization)
        };
        if self.ips.len() >= INVENTORY_LIMIT && !self.ips.contains_key(ip) {
            self.omitted += 1;
            return;
        }
        self.ips.entry(ip.into()).or_insert_with(|| {
            (
                frame,
                country.into(),
                organization.into(),
                self.capture.clone(),
            )
        });
    }
    pub fn host(
        &mut self,
        name: &str,
        frame: u64,
        time: Option<u64>,
        addresses: &[String],
        source: &str,
    ) {
        let name = name.trim().trim_end_matches('.').to_lowercase();
        if name.is_empty() {
            return;
        }
        if self.hosts.len() >= INVENTORY_LIMIT && !self.hosts.contains_key(&name) {
            self.omitted += 1;
            return;
        }
        let via = match source {
            "DNS lookup" => Via::Dns,
            "TLS SNI" | "QUIC SNI" => Via::Sni,
            _ => Via::HttpHost,
        };
        let seen = Seen {
            time_us: time,
            evidence: Some(packet_evidence(&self.capture, frame)),
            ..Seen::default()
        };
        let resolved: Vec<IpAddr> = addresses
            .iter()
            .filter_map(|address| address.parse().ok())
            .collect();
        self.ioc.domain(&name, via, &resolved, Source::Pcap, seen);
        let host = self.hosts.entry(name).or_insert_with(|| Host {
            capture: self.capture.clone(),
            frame,
            first: time,
            ..Host::default()
        });
        host.first = host.first.into_iter().chain(time).min();
        host.last = host.last.into_iter().chain(time).max();
        host.count = host.count.saturating_add(1);
        // A malicious DNS name must not grow a single aggregate without bounds.
        for address in addresses.iter().take(64) {
            if host.addresses.len() < 64 {
                host.addresses.insert(address.clone());
            }
        }
        host.sources.insert(source.into());
    }
    /// How DNS answered a name.
    pub fn host_rcode(&mut self, name: &str, rcode: &str) {
        let name = name.trim().trim_end_matches('.').to_lowercase();
        if let Some(host) = self.hosts.get_mut(&name) {
            if host.rcodes.len() < 8 {
                host.rcodes.insert(rcode.to_owned());
            }
        }
    }

    /// A frame of a conversation: counts it for the remote `ip:port`, the side
    /// that is not local (else the lower port, else the destination).
    pub fn packet(&mut self, facts: &PacketFacts<'_>) {
        let (Ok(source), Ok(destination)) = (
            facts.source.parse::<IpAddr>(),
            facts.destination.parse::<IpAddr>(),
        ) else {
            return;
        };
        let (Some(source_port), Some(destination_port)) =
            (port_of(facts.source_port), port_of(facts.destination_port))
        else {
            return;
        };
        let to_destination = match (
            local_address(facts.source),
            local_address(facts.destination),
        ) {
            (true, false) => true,
            (false, true) => false,
            _ => destination_port <= source_port,
        };
        let (ip, port) = if to_destination {
            (destination, destination_port)
        } else {
            (source, source_port)
        };
        let key = (ip, port, facts.protocol);
        if self.endpoints.len() >= INVENTORY_LIMIT && !self.endpoints.contains_key(&key) {
            self.omitted += 1;
            return;
        }
        let fresh = !self.endpoints.contains_key(&key);
        let endpoint = self.endpoints.entry(key).or_insert_with(|| Endpoint {
            capture: self.capture.clone(),
            frame: facts.frame,
            ..Endpoint::default()
        });
        endpoint.frames += 1;
        endpoint.bytes = endpoint.bytes.saturating_add(facts.length);
        endpoint.first = endpoint.first.into_iter().chain(facts.time).min();
        endpoint.last = endpoint.last.into_iter().chain(facts.time).max();
        // The first frame is the evidence; later ones only count.
        let evidence = fresh.then(|| packet_evidence(&self.capture, facts.frame));
        self.ioc.endpoint(
            ip,
            port,
            facts.protocol,
            Source::Pcap,
            Seen {
                time_us: facts.time,
                evidence,
                ..Seen::default()
            },
        );
    }

    /// An HTTP request (cleartext HTTP/1 or HTTP/2).
    pub fn url(&mut self, facts: &UrlFacts<'_>) {
        let endpoint = facts
            .destination
            .parse::<IpAddr>()
            .ok()
            .zip(port_of(facts.port));
        self.ioc.url(
            facts.method,
            facts.host,
            facts.uri,
            facts.version,
            facts.status,
            endpoint,
            Source::Pcap,
            Seen {
                time_us: facts.time,
                evidence: Some(packet_evidence(&self.capture, facts.frame)),
                ..Seen::default()
            },
        );
    }

    /// The TLS fields of a frame: a client hello starts a session, the server's
    /// reply and certificate complete it.
    pub fn tls_frame(&mut self, facts: &TlsFrame<'_>) {
        let hello = facts.kinds.contains(&"1");
        let reply = facts.kinds.iter().any(|kind| matches!(*kind, "2" | "11"))
            || !facts.ja3s.is_empty()
            || !facts.certificate.is_empty();
        if !hello && !reply {
            return;
        }
        let address = |pair: (&str, &str)| pair.0.parse::<IpAddr>().ok().zip(port_of(pair.1));
        let (client, server) = if hello {
            (address(facts.source), address(facts.destination))
        } else {
            (address(facts.destination), address(facts.source))
        };
        let (Some(client), Some(server)) = (client, server) else {
            return;
        };
        let key = if facts.stream.is_empty() {
            format!(
                "{}|{}:{}>{}:{}",
                self.capture, client.0, client.1, server.0, server.1
            )
        } else {
            format!("{}|{}", self.capture, facts.stream)
        };
        if self.tls.len() >= INVENTORY_LIMIT && !self.tls.contains_key(&key) {
            self.omitted += 1;
            return;
        }
        let session = self.tls.entry(key).or_insert_with(|| TlsSession {
            capture: self.capture.clone(),
            frame: facts.frame,
            time: facts.time,
            ..TlsSession::default()
        });
        session.server = Some(server);
        let fill = |slot: &mut String, value: &str| {
            if slot.is_empty() && !value.is_empty() {
                *slot = value.split('\u{1f}').next().unwrap_or("").to_owned();
            }
        };
        if hello {
            session.frame = facts.frame;
            session.time = facts.time;
            fill(&mut session.sni, facts.sni);
            fill(&mut session.alpn, facts.alpn);
            fill(&mut session.ja3, facts.ja3);
            fill(&mut session.ja4, facts.ja4);
        } else {
            fill(&mut session.ja3s, facts.ja3s);
            if session.cert_sha1.is_empty() {
                if let Some(sha1) =
                    antinomie_monitor_core::ioc::kind::certificate_sha1(facts.certificate)
                {
                    session.cert_sha1 = sha1;
                }
            }
            if session.alpn.is_empty() {
                fill(&mut session.alpn, facts.alpn);
            }
        }
        let version = if facts.supported.is_empty() {
            tls_version(facts.version.split('\u{1f}').next().unwrap_or(""))
        } else {
            // The highest version the hello names (a server hello names one).
            facts
                .supported
                .split('\u{1f}')
                .map(tls_version)
                .find(|name| !name.is_empty())
                .unwrap_or_default()
        };
        if !version.is_empty() && (reply || session.version.is_empty()) {
            session.version = version;
        }
    }

    /// The rebuilt Network section's tables, and the TLS sessions grouped for
    /// the IOC window. Call once, when every segment has been read.
    pub fn finish(&mut self) -> Tables {
        let mut tables = Tables::default();
        for ((ip, port, protocol), endpoint) in &self.endpoints {
            let address = ip.to_string();
            let (country, organization) = self
                .ips
                .get(&address)
                .map_or(("", ""), |(_, country, organization, _)| {
                    (country.as_str(), organization.as_str())
                });
            let shown = antinomie_monitor_core::ioc::kind::ip_port(*ip, *port);
            let mut row = vec![
                cell(&shown, theme::text(), true),
                cell(*protocol, theme::text(), false),
                cell(endpoint.frames.to_string(), theme::text(), true),
                cell(
                    crate::values::file_size(endpoint.bytes),
                    theme::text(),
                    true,
                ),
                cell(available(country), theme::text(), false),
                cell(available(organization), theme::text(), false),
                cell(
                    endpoint
                        .first
                        .map_or("Unavailable".into(), crate::time_format::short_time_us),
                    theme::text(),
                    true,
                ),
                cell(
                    endpoint
                        .last
                        .map_or("Unavailable".into(), crate::time_format::short_time_us),
                    theme::text(),
                    true,
                ),
            ];
            row[0].values = vec![
                ("capture.path", text_value(&endpoint.capture)),
                ("network.endpoint", RowValue::Text(shown.clone())),
                ("network.ip", RowValue::Text(address)),
                ("network.port", RowValue::Number(i128::from(*port))),
                ("network.protocol", RowValue::Text((*protocol).into())),
                (
                    "network.frames",
                    RowValue::Number(i128::from(endpoint.frames)),
                ),
                (
                    "network.bytes",
                    RowValue::Number(i128::from(endpoint.bytes)),
                ),
                ("network.country", text_value(country)),
                ("network.organization", text_value(organization)),
                (
                    "network.first_us",
                    endpoint
                        .first
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                (
                    "network.last_us",
                    endpoint
                        .last
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                ("frame.number", RowValue::Number(i128::from(endpoint.frame))),
            ];
            tables.endpoints.push(row);
        }
        for (name, host) in &self.hosts {
            let rcodes: Vec<String> = host.rcodes.iter().cloned().collect();
            let mut row = vec![
                cell(name, theme::text(), false),
                cell(
                    host.sources.iter().cloned().collect::<Vec<_>>().join(", "),
                    theme::text(),
                    false,
                ),
                cell(
                    host.addresses
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    theme::text(),
                    true,
                ),
                cell(host.count.to_string(), theme::text(), true),
                cell(
                    host.first
                        .map_or("Unavailable".into(), crate::time_format::short_time_us),
                    theme::text(),
                    true,
                ),
                cell(
                    host.last
                        .map_or("Unavailable".into(), crate::time_format::short_time_us),
                    theme::text(),
                    true,
                ),
                cell(
                    if rcodes.is_empty() {
                        "—".to_owned()
                    } else {
                        rcodes.join(", ")
                    },
                    theme::text(),
                    false,
                ),
            ];
            row[0].values = vec![
                ("capture.path", text_value(&host.capture)),
                ("network.hostname", RowValue::Text(name.clone())),
                ("dns.name", RowValue::Text(name.clone())),
                (
                    "network.addresses",
                    RowValue::List(host.addresses.iter().cloned().collect()),
                ),
                ("network.count", RowValue::Number(i128::from(host.count))),
                (
                    "network.first_us",
                    host.first
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                (
                    "network.last_us",
                    host.last
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                (
                    "network.sources",
                    RowValue::List(host.sources.iter().cloned().collect()),
                ),
                ("dns.rcode", RowValue::List(rcodes)),
                ("frame.number", RowValue::Number(i128::from(host.frame))),
            ];
            tables.domains.push(row);
        }
        // Sessions with the same server name, server and client fingerprint are one row.
        let mut groups: BTreeMap<(String, String, String), (TlsSession, u64)> = BTreeMap::new();
        for session in std::mem::take(&mut self.tls).into_values() {
            let Some(server) = session.server else {
                continue;
            };
            let name = antinomie_monitor_core::ioc::kind::ip_port(server.0, server.1);
            let key = (session.sni.clone(), name, session.ja3.clone());
            match groups.get_mut(&key) {
                Some((first, count)) => {
                    *count += 1;
                    if first.ja3s.is_empty() {
                        first.ja3s.clone_from(&session.ja3s);
                    }
                    if first.cert_sha1.is_empty() {
                        first.cert_sha1.clone_from(&session.cert_sha1);
                    }
                    if first.version.is_empty() {
                        first.version.clone_from(&session.version);
                    }
                }
                None => {
                    groups.insert(key, (session, 1));
                }
            }
        }
        for ((sni, endpoint, _), (session, count)) in &groups {
            let (ip, port) = session.server.unwrap_or((IpAddr::from([0, 0, 0, 0]), 0));
            for _ in 0..*count {
                self.ioc.tls(
                    (ip, port),
                    TlsFacts {
                        sni: sni.clone(),
                        ja3: session.ja3.clone(),
                        ja4: session.ja4.clone(),
                        ja3s: session.ja3s.clone(),
                        cert_sha1: session.cert_sha1.clone(),
                        alpn: session.alpn.clone(),
                        version: session.version.clone(),
                    },
                    Source::Pcap,
                    Seen {
                        time_us: session.time,
                        evidence: Some(packet_evidence(&session.capture, session.frame)),
                        ..Seen::default()
                    },
                );
            }
            let mut row = vec![
                cell(format!("#{}", session.frame), theme::text(), true),
                cell(
                    if sni.is_empty() {
                        "(none)"
                    } else {
                        sni.as_str()
                    },
                    theme::text(),
                    false,
                ),
                cell(endpoint, theme::text(), true),
                cell(&session.version, theme::text(), false),
                cell(&session.alpn, theme::text(), false),
                cell(&session.ja3, theme::text(), true),
                cell(&session.ja4, theme::text(), true),
                cell(&session.ja3s, theme::text(), true),
                cell(&session.cert_sha1, theme::text(), true),
                cell(count.to_string(), theme::text(), true),
            ];
            row[0].values = vec![
                ("capture.path", text_value(&session.capture)),
                ("frame.number", RowValue::Number(i128::from(session.frame))),
                (
                    "frame.time_us",
                    session
                        .time
                        .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                ),
                ("network.endpoints", RowValue::Text(endpoint.clone())),
                ("session.server_name", text_value(sni)),
                ("tls.sni", text_value(sni)),
                ("tls.endpoint", RowValue::Text(endpoint.clone())),
                ("tls.version", text_value(&session.version)),
                (
                    "session.alpn",
                    RowValue::List(if session.alpn.is_empty() {
                        Vec::new()
                    } else {
                        session
                            .alpn
                            .split(',')
                            .map(|a| a.trim().to_owned())
                            .collect()
                    }),
                ),
                ("tls.ja3", text_value(&session.ja3)),
                ("tls.ja4", text_value(&session.ja4)),
                ("tls.ja3s", text_value(&session.ja3s)),
                ("tls.cert", text_value(&session.cert_sha1)),
                ("tls.sessions", RowValue::Number(i128::from(*count))),
            ];
            tables.tls.push(row);
        }
        tables
    }

    fn incomplete(&self) -> Vec<String> {
        self.ips
            .iter()
            .filter_map(|(ip, (_, country, organization, _))| {
                if local_address(ip) || (!country.is_empty() && !organization.is_empty()) {
                    None
                } else {
                    Some(ip.clone())
                }
            })
            .collect()
    }
    fn fill_missing(&mut self, ip: &str, country: &str, organization: &str) {
        if let Some((_, stored_country, stored_organization, _)) = self.ips.get_mut(ip) {
            if stored_country.is_empty() && !country.is_empty() {
                *stored_country = country.to_owned();
            }
            if stored_organization.is_empty() && !organization.is_empty() {
                *stored_organization = organization.to_owned();
            }
        }
    }
    pub fn rows(&self) -> (Vec<Vec<Cell>>, Vec<Vec<Cell>>) {
        let ips = self
            .ips
            .iter()
            .map(|(ip, (frame, country, organization, capture))| {
                let mut row = vec![
                    cell(ip, theme::text(), true),
                    cell(available(country), theme::text(), false),
                    cell(available(organization), theme::text(), false),
                ];
                row[0].values = vec![
                    ("capture.path", text_value(capture)),
                    ("network.ip", text_value(ip)),
                    ("network.country", text_value(country)),
                    ("network.organization", text_value(organization)),
                    ("frame.number", RowValue::Number(i128::from(*frame))),
                ];
                row
            })
            .collect();
        let hosts = self
            .hosts
            .iter()
            .map(|(name, host)| {
                let mut row = vec![
                    cell(name, theme::text(), false),
                    cell(
                        host.addresses
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", "),
                        theme::text(),
                        true,
                    ),
                    cell(
                        host.first
                            .map_or("Unavailable".into(), crate::time_format::short_time_us),
                        theme::text(),
                        true,
                    ),
                    cell(
                        host.last
                            .map_or("Unavailable".into(), crate::time_format::short_time_us),
                        theme::text(),
                        true,
                    ),
                    cell(host.count.to_string(), theme::text(), true),
                    cell(
                        host.sources.iter().cloned().collect::<Vec<_>>().join(", "),
                        theme::text(),
                        false,
                    ),
                ];
                row[0].values = vec![
                    ("capture.path", text_value(&host.capture)),
                    ("network.hostname", RowValue::Text(name.clone())),
                    (
                        "network.addresses",
                        RowValue::List(host.addresses.iter().cloned().collect()),
                    ),
                    ("network.count", RowValue::Number(i128::from(host.count))),
                    (
                        "network.first_us",
                        host.first
                            .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                    ),
                    (
                        "network.last_us",
                        host.last
                            .map_or(RowValue::Missing, |time| RowValue::Number(i128::from(time))),
                    ),
                    (
                        "network.sources",
                        RowValue::List(host.sources.iter().cloned().collect()),
                    ),
                    ("frame.number", RowValue::Number(i128::from(host.frame))),
                ];
                row
            })
            .collect();
        (ips, hosts)
    }
}
pub(super) fn enrich_public(
    inventory: &mut Inventory,
    cancel: &std::sync::atomic::AtomicBool,
    warning: &mut Option<String>,
) -> Result<(), String> {
    let mut pending = inventory.incomplete();
    if pending.len() > 24 {
        *warning = Some(format!(
            "Address lookup limited to 24 public destinations; {} more were not queried.",
            pending.len() - 24
        ));
        pending.truncate(24);
    }
    let mut noted = warning.is_some();
    for ip in pending {
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        match lookup_public(&ip) {
            Ok((country, organization)) => inventory.fill_missing(&ip, &country, &organization),
            Err(error) if !noted => {
                *warning = Some(error);
                noted = true;
            }
            Err(_) => {}
        }
    }
    Ok(())
}

fn lookup_public(ip: &str) -> Result<(String, String), String> {
    let address = ip
        .parse::<std::net::IpAddr>()
        .map_err(|_| "address lookup is only for an IP address".to_owned())?;
    if local_address(ip) {
        return Err("local addresses are not queried".into());
    }
    let canonical = address.to_string();
    let whois = command_text("whois", &[&canonical]);
    let (country, mut organization) = whois.as_deref().map(parse_whois).unwrap_or_default();
    if organization.is_empty() {
        if let Ok(answer) =
            command_text("dig", &["+short", "+time=1", "+tries=1", "-x", &canonical])
        {
            if let Some(name) = ptr_name(&answer) {
                organization = name;
            }
        }
    }
    if country.is_empty() && organization.is_empty() {
        let message =
            format!("WHOIS lookup unavailable for {canonical}; country/organization unknown");
        return Err(match whois {
            Ok(_) => message,
            Err(error) => format!("{message}: {error}"),
        });
    }
    Ok((country, organization))
}

fn command_text(program: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("timeout")
        .args(["4", program])
        .args(args)
        .output()
        .map_err(|error| format!("{program} could not be started: {error}"))?;
    if output.stdout.is_empty() && !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        let detail = detail.trim();
        return Err(if detail.is_empty() {
            format!("{program} failed")
        } else {
            format!("{program} failed: {detail}")
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) fn parse_whois(text: &str) -> (String, String) {
    let country = whois_field(text, &["country"])
        .unwrap_or_default()
        .to_owned();
    let organization = whois_field(text, &["org-name", "orgname", "organization", "org"])
        .or_else(|| whois_field(text, &["netname"]))
        .unwrap_or_default()
        .to_owned();
    (country, organization)
}

fn whois_field<'a>(text: &'a str, keys: &[&str]) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        keys.iter()
            .any(|candidate| key.trim().eq_ignore_ascii_case(candidate))
            .then_some(value)
    })
}

fn ptr_name(text: &str) -> Option<String> {
    text.lines().map(str::trim).find_map(|line| {
        if line.is_empty() || line.starts_with(';') {
            None
        } else {
            Some(line.trim_end_matches('.').to_owned())
        }
    })
}

fn available(value: &str) -> &str {
    if value.is_empty() {
        "Unavailable"
    } else {
        value
    }
}

/// Loopback, link-local, and private ranges are local to the guest or host.
/// Carrier-grade NAT and public addresses keep their recorded lookup result.
fn local_address(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(address)) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
                || address.is_broadcast()
        }
        Ok(std::net::IpAddr::V6(address)) => {
            address.is_loopback()
                || address.is_unspecified()
                || address.is_unicast_link_local()
                || address.is_unique_local()
        }
        Err(_) => false,
    }
}

pub(super) fn qtype(text: &str) -> String {
    let label = match text {
        "1" => "A",
        "2" => "NS",
        "5" => "CNAME",
        "6" => "SOA",
        "12" => "PTR",
        "15" => "MX",
        "16" => "TXT",
        "28" => "AAAA",
        "33" => "SRV",
        "35" => "NAPTR",
        "41" => "OPT",
        "43" => "DS",
        "46" => "RRSIG",
        "48" => "DNSKEY",
        "52" => "TLSA",
        "64" => "SVCB",
        "65" => "HTTPS",
        "255" => "ANY",
        _ => return text.to_owned(),
    };
    label.into()
}

/// Temp-data key Open Packets leaves for the app.
pub(super) const OPEN_PACKETS: &str = "triage-open-packets";

/// The button that links the derived tables to the raw capture.
pub(super) fn open_packets_button(ui: &mut egui::Ui, available: bool) {
    let label = format!("{} Open Packets", egui_phosphor::regular::NETWORK);
    if ui
        .add_enabled(available, egui::Button::new(label))
        .on_hover_text("Show this run's capture in Packets")
        .on_disabled_hover_text("This run has no packet capture")
        .clicked()
    {
        ui.ctx()
            .data_mut(|data| data.insert_temp(egui::Id::new(OPEN_PACKETS), true));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedicated_capture_keeps_shifted_packets_without_loosening_shared_capture_scope() {
        let mut request = ScanRequest {
            started_ms: Some(1_792_069_584_210),
            ended_ms: Some(1_792_070_879_490),
            ..Default::default()
        };
        let shifted = Some(1_792_044_610_612_431);
        assert!(!in_window(&request, shifted));
        request.owned_pcap = true;
        assert!(in_window(&request, shifted));
        assert!(in_window(&request, None));
        request.owned_pcap = false;
        assert!(!in_window(&request, None));
        assert!(in_window(&request, Some(1_792_069_600_000_000)));
    }

    #[test]
    fn same_boot_is_not_capture_ownership_and_manifest_identity_is_required() {
        let spool = PacketSpool::new().unwrap();
        let pcap = spool.directory.join("run.pcap");
        let identity = ("vm".into(), "boot".into(), "run".into());
        let mut artifacts = antinomie_monitor_core::RunArtifacts {
            vm_id: "vm".into(),
            boot_id: "boot".into(),
            run_id: "run".into(),
            network_captures: vec![pcap.clone()],
            ..Default::default()
        };
        let save = |artifacts: &antinomie_monitor_core::RunArtifacts| {
            std::fs::write(
                spool.directory.join("artifacts.json"),
                serde_json::to_vec(artifacts).unwrap(),
            )
            .unwrap()
        };
        save(&artifacts);
        assert!(owned_capture(&spool.directory, Some(&identity), &pcap).unwrap());
        assert!(!owned_capture(
            &spool.directory,
            Some(&identity),
            &spool.directory.join("other.pcap")
        )
        .unwrap());
        assert!(!owned_capture(&spool.directory, None, &pcap).unwrap());
        artifacts.run_id = "another".into();
        save(&artifacts);
        assert!(owned_capture(&spool.directory, Some(&identity), &pcap).is_err());
    }

    #[test]
    fn whois_prefers_organization_and_ignores_blank_lines() {
        let (country, organization) =
            parse_whois("netname: EXAMPLE-NET\nOrgName: Example Org\nCountry: US\ncountry: \n");
        assert_eq!(country, "US");
        assert_eq!(organization, "Example Org");
        assert_eq!(ptr_name("example.net.\n"), Some("example.net".into()));
    }

    #[test]
    fn inventory_deduplicates_and_keeps_packet_evidence_and_unknown_geoip() {
        let mut inventory = Inventory::default();
        inventory.destination("1.2.3.4", 9, "", "");
        inventory.destination("1.2.3.4", 10, "", "");
        inventory.host(
            "Example.TEST.",
            9,
            Some(100),
            &["1.2.3.4".into()],
            "DNS lookup",
        );
        inventory.host("example.test", 12, Some(200), &["1.2.3.4".into()], "HTTP");
        let (ips, hosts) = inventory.rows();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0][1].text, "Unavailable");
        inventory.destination("10.0.2.15", 11, "US", "Example Org");
        inventory.destination("fe80::1", 12, "", "");
        let (ips, _) = inventory.rows();
        let local = ips.iter().find(|row| row[0].text == "10.0.2.15").unwrap();
        assert_eq!(local[1].text, "-");
        assert_eq!(local[2].text, "local network");
        let link_local = ips.iter().find(|row| row[0].text == "fe80::1").unwrap();
        assert_eq!(link_local[1].text, "-");
        assert_eq!(link_local[2].text, "local network");
        assert_eq!(files::number(&ips[0][0].values, "frame.number"), Some(9));
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0][0].text, "example.test");
        assert_eq!(hosts[0][4].text, "2");
        assert!(hosts[0][5].text.contains("HTTP"));
        assert_eq!(qtype("28"), "AAAA");
        assert_eq!(qtype("65000"), "65000");
    }
}

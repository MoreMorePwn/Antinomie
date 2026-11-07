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

const NS: u64 = 1_000;
/// The built-in suppression list changes with the rules.
pub(in crate::triage) const SUPPRESSION_VERSION: u32 = 1;
const MINUTE_US: u64 = 60 * 1_000_000;
const NXDOMAINS: usize = 10;
const LONG_LABEL: usize = 40;
const TUNNEL_QUERIES: usize = 5;
const TXT_QUERIES: usize = 20;
const BEACON_REQUESTS: u64 = 8;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::triage) enum FrameKind {
    Dns,
    Http,
    Session,
}

/// A row of the capture as the rules see it.
pub(super) struct Frame<'a> {
    pub kind: FrameKind,
    pub values: &'a [(&'static str, RowValue)],
    pub destination: &'a str,
    pub port: &'a str,
}

impl Frame<'_> {
    pub(super) fn text(&self, key: &str) -> &str {
        self.values
            .iter()
            .find_map(|(name, value)| match value {
                RowValue::Text(text) if *name == key => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or("")
    }

    pub(super) fn number(&self, key: &str) -> Option<u64> {
        files::number(self.values, key)
    }

    fn list(&self, key: &str) -> &[String] {
        self.values
            .iter()
            .find_map(|(name, value)| match value {
                RowValue::List(list) if *name == key => Some(list.as_slice()),
                _ => None,
            })
            .unwrap_or_default()
    }

    pub(super) fn port(&self) -> Option<u16> {
        self.port.parse().ok()
    }
}

/// What the rules remember across frames.
#[derive(Default)]
pub(super) struct Frames {
    /// Some resolver answered a name: failed lookups mean something.
    pub resolver_answers: bool,
    nxdomain: Window<String>,
    nxdomain_done: bool,
    /// The burst of failed names, with the frame it completed on, to report once a
    /// resolver is known to answer.
    pub nxdomain_hit: Option<(Hit, u64, String, u64)>,
    long_labels: BTreeMap<String, u64>,
    text_queries: BTreeMap<String, Window<u64>>,
    tunnel_done: std::collections::BTreeSet<String>,
    beats: BTreeMap<String, (Gaps, u64)>,
    beat_done: std::collections::BTreeSet<String>,
    /// Frames the suppression list skipped.
    pub suppressed: u64,
}

/// Names the base looks up by itself: time sync, package mirrors and connectivity checks.
const HOUSEKEEPING_NAMES: &[&str] = &[
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
const HOUSEKEEPING_PORTS: &[u16] = &[5353, 5355, 67, 68, 123];

/// Services that carry commands, files or messages for ordinary programs too.
const WEB_SERVICES: &[&str] = &[
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
const WEB_PORTS: &[u16] = &[80, 8080, 8000, 8008, 8888, 3000, 5000, 443, 8443];
const TLS_PORTS: &[u16] = &[443, 8443, 853, 993, 995, 465, 636, 5223, 4443];

fn under_domain(name: &str, domain: &str) -> bool {
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

fn housekeeping(name: &str) -> bool {
    name.ends_with(".local")
        || name.ends_with(".lan")
        || name.starts_with("_")
        || matches!(name, "wpad" | "isatap" | "localhost")
        || HOUSEKEEPING_NAMES
            .iter()
            .any(|domain| under_domain(name, domain))
}

fn entropy(text: &str) -> f64 {
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
fn random_looking(label: &str) -> bool {
    label.len() >= 10 && entropy(label) >= 3.0 && label.bytes().all(|b| b.is_ascii_alphanumeric())
}

fn parent(name: &str) -> String {
    let labels: Vec<_> = name.split('.').collect();
    labels[labels.len().saturating_sub(2)..].join(".")
}

fn service(name: &str, uri: &str) -> bool {
    WEB_SERVICES.iter().any(|domain| under_domain(name, domain))
        && !(name.ends_with("discord.com") && !uri.is_empty() && !uri.starts_with("/api/webhooks"))
}

/// Judge one row of the capture.
pub(super) fn rules(st: &mut super::state::State, frame: &Frame) -> Vec<Hit> {
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

/// Requests to one host at a steady pace.
fn beat(state: &mut Frames, host: &str, time: u64, hits: &mut Vec<Hit>) {
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
pub(super) fn contact<'a>(st: &'a super::state::State, frame: &Frame) -> Option<&'a Contact> {
    match frame.kind {
        FrameKind::Dns => st.dns_task.as_ref(),
        _ => frame
            .destination
            .parse::<IpAddr>()
            .ok()
            .and_then(|ip| st.contacted.get(&ip)),
    }
}

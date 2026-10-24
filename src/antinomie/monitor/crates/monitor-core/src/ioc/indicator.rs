// SPDX-License-Identifier: GPL-3.0-only
//! The indicators of one run: what the run showed (endpoints, domains, URLs,
//! TLS fingerprints, files), where each came from, which process made it and
//! which dataset values it can be matched by.
//!
//! The Triage scan feeds a [`Collector`] with plain observations; the
//! collector merges repeats, joins a process to a network row only when
//! exactly one process made a matching call, and sets what each indicator can
//! be matched by (private addresses and files with no content have nothing).
use super::kind::{self, Kind};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

/// Most indicators of one type kept.
pub const TYPE_LIMIT: usize = 20_000;

/// The five tabs of the IOC window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Type {
    Endpoint,
    Domain,
    Url,
    Tls,
    File,
}

impl Type {
    pub const ALL: [Type; 5] = [
        Type::Endpoint,
        Type::Domain,
        Type::Url,
        Type::Tls,
        Type::File,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Type::Endpoint => "Endpoints",
            Type::Domain => "Domains",
            Type::Url => "URLs",
            Type::Tls => "TLS",
            Type::File => "Files",
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            Type::Endpoint => "endpoint",
            Type::Domain => "domain",
            Type::Url => "url",
            Type::Tls => "tls",
            Type::File => "file",
        }
    }
}

/// Where an indicator came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The network capture, read by TShark.
    Pcap,
    /// A recorded system call.
    Syscall,
    /// The post-run disk image.
    Disk,
    /// Strings or hashes of the sample.
    Static,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Pcap => "pcap",
            Source::Syscall => "syscall",
            Source::Disk => "disk",
            Source::Static => "static",
        }
    }
}

/// A process of the run.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    /// The task's stable identity.
    pub cookie: u64,
    pub name: String,
}

impl Process {
    pub fn label(&self) -> String {
        format!("{} · {}", self.name, self.pid)
    }
}

/// Where to look at the evidence of an indicator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Jump {
    Packet {
        capture: String,
        frame: u64,
    },
    Call {
        stream: u64,
        cookie: u64,
        call: u64,
    },
    /// Shown as text only (strings, hashes).
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    pub source: Source,
    pub label: String,
    pub jump: Jump,
}

/// A value to look for in the datasets.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Lookup {
    pub kind: Kind,
    pub value: String,
}

/// What a TLS row shows.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsFacts {
    pub sni: String,
    pub ja3: String,
    pub ja4: String,
    pub ja3s: String,
    pub cert_sha1: String,
    pub alpn: String,
    pub version: String,
}

/// Digests of a file's content.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hashes {
    pub sha256: String,
    pub md5: String,
    pub sha1: String,
}

/// One indicator of the run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Indicator {
    pub ty: Type,
    /// Unique within its type.
    pub key: String,
    /// What the row shows.
    pub value: String,
    /// The line under it: protocol, how a domain was seen, HTTP version.
    pub sub: String,
    pub sources: BTreeSet<Source>,
    /// The one process that made a matching call.
    pub process: Option<Process>,
    /// Several processes did; none is named.
    pub candidates: Vec<Process>,
    pub first_us: Option<u64>,
    pub last_us: Option<u64>,
    /// "9 connections", "3 requests".
    pub count: String,
    pub details: Vec<(Source, String)>,
    pub evidence: Vec<Evidence>,
    pub lookups: Vec<Lookup>,
    pub tls: Option<TlsFacts>,
    pub hashes: Option<Hashes>,
    /// A file's path in the guest.
    pub path: String,
    /// A file's roles: sample, created, executed, deleted, written at close, changed.
    pub roles: Vec<String>,
    /// Why nothing was looked up: `private address`, `no content kept`.
    pub not_checked: Option<String>,
}

impl Indicator {
    fn new(ty: Type, key: String, value: String) -> Self {
        Self {
            ty,
            key,
            value,
            sub: String::new(),
            sources: BTreeSet::new(),
            process: None,
            candidates: Vec::new(),
            first_us: None,
            last_us: None,
            count: String::new(),
            details: Vec::new(),
            evidence: Vec::new(),
            lookups: Vec::new(),
            tls: None,
            hashes: None,
            path: String::new(),
            roles: Vec::new(),
            not_checked: None,
        }
    }

    /// A short stable name for stored results and exports.
    pub fn id(&self) -> String {
        format!("{}:{}", self.ty.id(), self.key)
    }
}

/// How an endpoint is named among the indicators.
pub fn endpoint_key(ip: IpAddr, port: u16) -> String {
    kind::ip_port(ip, port)
}

/// How a domain is named among the indicators.
pub fn domain_key(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// How an HTTP request is named: the method and the URL in its normal form.
pub fn url_key(method: &str, host: &str, uri: &str) -> String {
    let uri = if uri.starts_with('/') {
        uri.to_owned()
    } else {
        format!("/{uri}")
    };
    let full = format!("{}{uri}", host.trim());
    let shown = Kind::Url.normalize(&full).unwrap_or(full);
    format!("{} {shown}", method.to_ascii_uppercase())
}

/// How a TLS session group is named: server name, server endpoint, client JA3.
pub fn tls_key(sni: &str, server: &str, ja3: &str) -> String {
    let name = if sni.is_empty() { "(no SNI)" } else { sni };
    format!("{name} {server} {ja3}")
}

/// One sighting.
#[derive(Clone, Debug, Default)]
pub struct Seen {
    pub time_us: Option<u64>,
    pub evidence: Option<Evidence>,
    /// For a call: whether it succeeded.
    pub ok: Option<bool>,
    /// The process that made the call.
    pub process: Option<Process>,
    /// Something to say about this sighting, such as why a file has no hash.
    pub note: Option<String>,
}

/// How a name was seen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Via {
    Dns,
    Sni,
    HttpHost,
    Sample,
}

impl Via {
    fn label(self) -> &'static str {
        match self {
            Via::Dns => "DNS",
            Via::Sni => "SNI",
            Via::HttpHost => "HTTP Host",
            Via::Sample => "sample string",
        }
    }
}

#[derive(Default)]
struct Tally {
    count: u64,
    ok: u64,
    failed: u64,
    first_us: Option<u64>,
    last_us: Option<u64>,
    first_label: Option<String>,
    processes: BTreeSet<Process>,
    notes: BTreeSet<String>,
}

impl Tally {
    fn add(&mut self, seen: &Seen) {
        self.count += 1;
        match seen.ok {
            Some(true) => self.ok += 1,
            Some(false) => self.failed += 1,
            None => {}
        }
        if let Some(time) = seen.time_us {
            self.first_us = Some(self.first_us.map_or(time, |old| old.min(time)));
            self.last_us = Some(self.last_us.map_or(time, |old| old.max(time)));
        }
        if self.first_label.is_none() {
            self.first_label = seen.evidence.as_ref().map(|e| e.label.clone());
        }
        if let Some(process) = &seen.process {
            self.processes.insert(process.clone());
        }
        if let Some(note) = &seen.note
            && self.notes.len() < 4
        {
            self.notes.insert(note.clone());
        }
    }
}

#[derive(Default)]
struct Entry {
    indicator: Option<Indicator>,
    tallies: BTreeMap<Source, Tally>,
    via: BTreeSet<Via>,
    addresses: BTreeSet<IpAddr>,
    statuses: BTreeSet<String>,
    version: BTreeSet<String>,
    endpoint: Option<String>,
    methods: BTreeMap<String, u64>,
    private: bool,
}

/// Builds the indicator list from observations.
#[derive(Default)]
pub struct Collector {
    entries: BTreeMap<(Type, String), Entry>,
    /// Observations dropped because a type reached [`TYPE_LIMIT`].
    pub omitted: u64,
    counts: BTreeMap<Type, usize>,
}

fn proto_name(proto: &str) -> &str {
    match proto {
        "tcp" | "udp" => proto,
        _ => "tcp",
    }
}

impl Collector {
    fn entry(
        &mut self,
        ty: Type,
        key: String,
        value: impl FnOnce() -> String,
    ) -> Option<&mut Entry> {
        let slot = (ty, key);
        if !self.entries.contains_key(&slot) {
            let used = self.counts.entry(ty).or_default();
            if *used >= TYPE_LIMIT {
                self.omitted += 1;
                return None;
            }
            *used += 1;
            let entry = Entry {
                indicator: Some(Indicator::new(ty, slot.1.clone(), value())),
                ..Entry::default()
            };
            self.entries.insert(slot.clone(), entry);
        }
        self.entries.get_mut(&slot)
    }

    fn record(entry: &mut Entry, source: Source, seen: &Seen) {
        let indicator = entry.indicator.as_mut().expect("entry holds its indicator");
        indicator.sources.insert(source);
        entry.tallies.entry(source).or_default().add(seen);
        if let Some(evidence) = &seen.evidence
            && indicator.evidence.len() < 8
            && !indicator.evidence.contains(evidence)
        {
            indicator.evidence.push(evidence.clone());
        }
    }

    /// A connection or datagram to `ip:port`.
    pub fn endpoint(&mut self, ip: IpAddr, port: u16, proto: &str, source: Source, seen: Seen) {
        let key = endpoint_key(ip, port);
        let proto = proto_name(proto).to_owned();
        let shown = key.clone();
        let Some(entry) = self.entry(Type::Endpoint, key, || shown) else {
            return;
        };
        entry.private = kind::private_address(ip);
        entry.addresses.insert(ip);
        entry.version.insert(proto);
        Self::record(entry, source, &seen);
    }

    /// A name: a DNS question, a TLS server name, an HTTP Host.
    pub fn domain(
        &mut self,
        name: &str,
        via: Via,
        addresses: &[IpAddr],
        source: Source,
        seen: Seen,
    ) {
        let name = domain_key(name);
        if name.is_empty() || name.len() > 253 || name.parse::<IpAddr>().is_ok() {
            return;
        }
        let key = name.clone();
        let Some(entry) = self.entry(Type::Domain, key, || name.clone()) else {
            return;
        };
        entry.private = kind::local_name(&name) || Kind::Domain.normalize(&name).is_none();
        entry.via.insert(via);
        entry.addresses.extend(addresses.iter().copied());
        Self::record(entry, source, &seen);
    }

    /// An HTTP request. `host` is the Host header (or authority), `endpoint`
    /// the `ip:port` it went to.
    #[allow(clippy::too_many_arguments)]
    pub fn url(
        &mut self,
        method: &str,
        host: &str,
        uri: &str,
        version: &str,
        status: Option<u16>,
        endpoint: Option<(IpAddr, u16)>,
        source: Source,
        seen: Seen,
    ) {
        let host = host.trim();
        if host.is_empty() && endpoint.is_none() {
            return;
        }
        let host_part = if host.is_empty() {
            endpoint.map(|(ip, _)| ip.to_string()).unwrap_or_default()
        } else {
            host.to_owned()
        };
        let uri = if uri.starts_with('/') {
            uri.to_owned()
        } else {
            format!("/{uri}")
        };
        let full = format!("{host_part}{uri}");
        let canonical = Kind::Url.normalize(&full);
        let key = url_key(method, &host_part, &uri);
        let value = format!("{} {}", method.to_ascii_uppercase(), full);
        let Some(entry) = self.entry(Type::Url, key, || value) else {
            return;
        };
        let indicator = entry.indicator.as_mut().expect("entry holds its indicator");
        indicator.path = canonical.unwrap_or_default();
        if let Some((ip, port)) = endpoint {
            entry.private = kind::private_address(ip)
                || kind::url_parts(&host_part).is_some_and(|parts| {
                    parts.address().is_some_and(kind::private_address)
                        || kind::local_name(&parts.host)
                });
            entry.endpoint = Some(kind::ip_port(ip, port));
        }
        if !version.is_empty() {
            entry.version.insert(version.to_owned());
        }
        if let Some(status) = status {
            entry.statuses.insert(status.to_string());
        }
        *entry
            .methods
            .entry(method.to_ascii_uppercase())
            .or_default() += 1;
        Self::record(entry, source, &seen);
    }

    /// A TLS hello pair of one session.
    pub fn tls(&mut self, endpoint: (IpAddr, u16), facts: TlsFacts, source: Source, seen: Seen) {
        let server = kind::ip_port(endpoint.0, endpoint.1);
        let key = tls_key(&facts.sni, &server, &facts.ja3);
        let value = if facts.sni.is_empty() {
            format!("(no SNI) {server}")
        } else {
            facts.sni.clone()
        };
        let shown = value.clone();
        let Some(entry) = self.entry(Type::Tls, key, || shown) else {
            return;
        };
        entry.private = kind::private_address(endpoint.0);
        entry.endpoint = Some(server);
        entry.addresses.insert(endpoint.0);
        let indicator = entry.indicator.as_mut().expect("entry holds its indicator");
        match &mut indicator.tls {
            None => indicator.tls = Some(facts),
            Some(have) => {
                // A server hello arrives in another frame than the client hello.
                for (slot, new) in [
                    (&mut have.ja3, facts.ja3),
                    (&mut have.ja4, facts.ja4),
                    (&mut have.ja3s, facts.ja3s),
                    (&mut have.cert_sha1, facts.cert_sha1),
                    (&mut have.alpn, facts.alpn),
                    (&mut have.version, facts.version),
                    (&mut have.sni, facts.sni),
                ] {
                    if slot.is_empty() {
                        *slot = new;
                    }
                }
            }
        }
        Self::record(entry, source, &seen);
    }

    /// A file of the run. `hashes` is `None` when no content was kept.
    pub fn file(
        &mut self,
        path: &str,
        role: &str,
        hashes: Option<Hashes>,
        source: Source,
        seen: Seen,
    ) {
        let key = match &hashes {
            Some(hashes) => format!("{} {path}", hashes.sha256),
            None => format!("- {path}"),
        };
        let value = match &hashes {
            Some(hashes) => hashes.sha256.clone(),
            None => "(no content kept)".into(),
        };
        let Some(entry) = self.entry(Type::File, key, || value) else {
            return;
        };
        let indicator = entry.indicator.as_mut().expect("entry holds its indicator");
        indicator.path = path.to_owned();
        if !indicator.roles.iter().any(|have| have == role) {
            indicator.roles.push(role.to_owned());
        }
        if indicator.hashes.is_none() {
            indicator.hashes = hashes;
        }
        Self::record(entry, source, &seen);
    }

    /// Join processes, set the matchable values and return the indicators in
    /// a stable order.
    pub fn finish(self) -> Vec<Indicator> {
        // Which processes connected to each endpoint and to each address.
        let mut by_endpoint: BTreeMap<String, BTreeSet<Process>> = BTreeMap::new();
        let mut by_address: BTreeMap<IpAddr, BTreeSet<Process>> = BTreeMap::new();
        for ((ty, key), entry) in &self.entries {
            if *ty != Type::Endpoint {
                continue;
            }
            if let Some(tally) = entry.tallies.get(&Source::Syscall) {
                by_endpoint
                    .entry(key.clone())
                    .or_default()
                    .extend(tally.processes.iter().cloned());
                for ip in &entry.addresses {
                    by_address
                        .entry(*ip)
                        .or_default()
                        .extend(tally.processes.iter().cloned());
                }
            }
        }
        let mut out = Vec::new();
        for ((ty, _), mut entry) in self.entries {
            let mut indicator = entry.indicator.take().expect("entry holds its indicator");
            let processes: BTreeSet<Process> = match ty {
                Type::Endpoint => entry
                    .tallies
                    .get(&Source::Syscall)
                    .map(|tally| tally.processes.clone())
                    .unwrap_or_default(),
                Type::Url | Type::Tls => entry
                    .endpoint
                    .as_ref()
                    .and_then(|endpoint| by_endpoint.get(endpoint).cloned())
                    .unwrap_or_default(),
                Type::Domain => entry
                    .addresses
                    .iter()
                    .filter_map(|ip| by_address.get(ip))
                    .flatten()
                    .cloned()
                    .collect(),
                Type::File => entry
                    .tallies
                    .values()
                    .flat_map(|tally| tally.processes.iter().cloned())
                    .collect(),
            };
            match processes.len() {
                0 => {}
                1 => indicator.process = processes.into_iter().next(),
                _ => indicator.candidates = processes.into_iter().collect(),
            }
            indicator.first_us = entry.tallies.values().filter_map(|t| t.first_us).min();
            indicator.last_us = entry.tallies.values().filter_map(|t| t.last_us).max();
            describe(&mut indicator, &entry);
            set_lookups(&mut indicator, &entry);
            out.push(indicator);
        }
        out.sort_by(|a, b| {
            (a.ty, a.first_us.is_none(), a.first_us, &a.key).cmp(&(
                b.ty,
                b.first_us.is_none(),
                b.first_us,
                &b.key,
            ))
        });
        out
    }
}

fn plural(count: u64, one: &str, many: &str) -> String {
    format!("{count} {}", if count == 1 { one } else { many })
}

/// The sub line, count and per-source details.
fn describe(indicator: &mut Indicator, entry: &Entry) {
    let syscall = entry.tallies.get(&Source::Syscall);
    let pcap = entry.tallies.get(&Source::Pcap);
    match indicator.ty {
        Type::Endpoint => {
            let proto = entry.version.iter().next().map_or("tcp", String::as_str);
            let failed = syscall.is_some_and(|t| t.failed > 0 && t.ok == 0);
            indicator.sub = if failed {
                format!("{proto} · failed")
            } else if pcap.is_none() && syscall.is_some() {
                format!("{proto} · no packets")
            } else {
                proto.to_owned()
            };
            indicator.count = match (syscall, pcap) {
                (Some(t), _) => plural(
                    t.count,
                    if proto == "udp" {
                        "datagram"
                    } else {
                        "connection"
                    },
                    if proto == "udp" {
                        "datagrams"
                    } else {
                        "connections"
                    },
                ),
                (None, Some(t)) => plural(t.count, "frame", "frames"),
                _ => String::new(),
            };
            if let Some(t) = pcap {
                indicator
                    .details
                    .push((Source::Pcap, plural(t.count, "frame", "frames")));
            }
            if let Some(t) = syscall {
                let who: Vec<String> = t.processes.iter().map(Process::label).collect();
                let outcome = match (t.ok, t.failed) {
                    (0, 0) => String::new(),
                    (ok, 0) => format!(", {ok} succeeded"),
                    (0, failed) => format!(", {failed} failed"),
                    (ok, failed) => format!(", {ok} succeeded, {failed} failed"),
                };
                indicator.details.push((
                    Source::Syscall,
                    format!(
                        "{} from {}{outcome}",
                        plural(t.count, "call", "calls"),
                        if who.is_empty() {
                            "an unnamed process".to_owned()
                        } else {
                            who.join(", ")
                        }
                    ),
                ));
            }
        }
        Type::Domain => {
            indicator.sub = entry
                .via
                .iter()
                .map(|via| via.label())
                .collect::<Vec<_>>()
                .join(" · ");
            let n = pcap.map_or(0, |t| t.count);
            indicator.count = plural(
                n.max(1),
                if entry.via.contains(&Via::Dns) {
                    "lookup"
                } else {
                    "sighting"
                },
                if entry.via.contains(&Via::Dns) {
                    "lookups"
                } else {
                    "sightings"
                },
            );
            if let Some(t) = pcap {
                let mut text = format!("{} seen in the capture", plural(t.count, "time", "times"));
                if !entry.addresses.is_empty() {
                    let ips: Vec<String> = entry
                        .addresses
                        .iter()
                        .take(6)
                        .map(IpAddr::to_string)
                        .collect();
                    text.push_str(&format!("; addresses {}", ips.join(", ")));
                }
                indicator.details.push((Source::Pcap, text));
            }
            if let Some(t) = entry.tallies.get(&Source::Static) {
                indicator.details.push((
                    Source::Static,
                    format!(
                        "{} in the sample's strings",
                        plural(t.count, "string", "strings")
                    ),
                ));
            }
        }
        Type::Url => {
            indicator.sub = entry.version.iter().cloned().collect::<Vec<_>>().join(", ");
            let n = pcap.map_or(0, |t| t.count);
            indicator.count = plural(n, "request", "requests");
            if let Some(t) = pcap {
                let status = if entry.statuses.is_empty() {
                    "no response matched".to_owned()
                } else {
                    format!(
                        "response {}",
                        entry
                            .statuses
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                indicator.details.push((
                    Source::Pcap,
                    format!("{}, {status}", plural(t.count, "request", "requests")),
                ));
            }
        }
        Type::Tls => {
            let tls = indicator.tls.clone().unwrap_or_default();
            let endpoint = entry.endpoint.clone().unwrap_or_default();
            indicator.sub = if tls.version.is_empty() {
                endpoint
            } else {
                format!("{endpoint} · {}", tls.version)
            };
            let n = pcap.map_or(0, |t| t.count);
            indicator.count = plural(n, "session", "sessions");
            if let Some(t) = pcap {
                indicator.details.push((
                    Source::Pcap,
                    format!(
                        "{}; the first hello is {}",
                        plural(t.count, "session", "sessions"),
                        t.first_label
                            .clone()
                            .unwrap_or_else(|| "in the capture".into())
                    ),
                ));
            }
        }
        Type::File => {
            indicator.sub = indicator.path.clone();
            indicator.count = indicator.roles.join(", ");
            for source in [Source::Static, Source::Syscall, Source::Disk] {
                if let Some(t) = entry.tallies.get(&source) {
                    indicator.details.push((
                        source,
                        match source {
                            Source::Static => {
                                "hashes of the verified sample, as static analysis stored them"
                                    .to_owned()
                            }
                            Source::Disk => "hashed from the post-run disk image".to_owned(),
                            _ => format!("{} recorded", plural(t.count, "call", "calls")),
                        },
                    ));
                    for note in &t.notes {
                        indicator.details.push((source, note.clone()));
                    }
                }
            }
        }
    }
}

fn set_lookups(indicator: &mut Indicator, entry: &Entry) {
    let mut lookups: BTreeSet<Lookup> = BTreeSet::new();
    let mut add = |kind: Kind, value: &str| {
        if let Some(value) = kind.normalize(value) {
            lookups.insert(Lookup { kind, value });
        }
    };
    match indicator.ty {
        Type::Endpoint => {
            if !entry.private {
                add(Kind::IpPort, &indicator.key);
            }
        }
        Type::Domain => {
            if !entry.private {
                add(Kind::Domain, &indicator.key);
            }
        }
        Type::Url => {
            if !entry.private {
                add(Kind::Url, &indicator.path);
            }
        }
        Type::Tls => {
            let tls = indicator.tls.clone().unwrap_or_default();
            add(Kind::Ja3, &tls.ja3);
            add(Kind::CertSha1, &tls.cert_sha1);
            if !entry.private
                && let Some(endpoint) = &entry.endpoint
            {
                add(Kind::IpPort, endpoint);
            }
            if !tls.sni.is_empty() && !kind::local_name(&tls.sni) {
                add(Kind::Domain, &tls.sni);
            }
        }
        Type::File => {
            if let Some(hashes) = &indicator.hashes {
                add(Kind::Sha256, &hashes.sha256);
                add(Kind::Md5, &hashes.md5);
            }
        }
    }
    indicator.lookups = lookups.into_iter().collect();
    if indicator.lookups.is_empty() {
        indicator.not_checked = Some(match indicator.ty {
            Type::File => "no content kept".to_owned(),
            Type::Tls => "private address".to_owned(),
            Type::Domain => "local name".to_owned(),
            _ => "private address".to_owned(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn proc(pid: u32, name: &str) -> Process {
        Process {
            pid,
            cookie: u64::from(pid),
            name: name.into(),
        }
    }

    fn call(process: &Process, ok: bool, time: u64) -> Seen {
        Seen {
            time_us: Some(time),
            ok: Some(ok),
            process: Some(process.clone()),
            evidence: Some(Evidence {
                source: Source::Syscall,
                label: format!("Syscall Trace · connect #{time}"),
                jump: Jump::Call {
                    stream: 1,
                    cookie: process.cookie,
                    call: time,
                },
            }),
            note: None,
        }
    }

    fn packet(frame: u64, time: u64) -> Seen {
        Seen {
            time_us: Some(time),
            evidence: Some(Evidence {
                source: Source::Pcap,
                label: format!("Packets · frame {frame}"),
                jump: Jump::Packet {
                    capture: "run.pcap".into(),
                    frame,
                },
            }),
            ..Seen::default()
        }
    }

    fn find<'a>(all: &'a [Indicator], ty: Type, key: &str) -> &'a Indicator {
        all.iter()
            .find(|i| i.ty == ty && i.key == key)
            .unwrap_or_else(|| panic!("no {key}"))
    }

    #[test]
    fn a_process_is_named_only_when_exactly_one_made_the_call() {
        let mut c = Collector::default();
        let (a, b) = (proc(1412, "kworkerd"), proc(1420, ".kd"));
        // One process reaches the first endpoint; two reach the second.
        c.endpoint(
            ip("203.0.113.45"),
            443,
            "tcp",
            Source::Syscall,
            call(&a, true, 10),
        );
        c.endpoint(
            ip("203.0.113.45"),
            443,
            "tcp",
            Source::Syscall,
            call(&a, false, 20),
        );
        c.endpoint(
            ip("203.0.113.45"),
            443,
            "tcp",
            Source::Pcap,
            packet(211, 12),
        );
        c.endpoint(
            ip("198.51.100.77"),
            80,
            "tcp",
            Source::Syscall,
            call(&a, true, 30),
        );
        c.endpoint(
            ip("198.51.100.77"),
            80,
            "tcp",
            Source::Syscall,
            call(&b, true, 31),
        );
        c.endpoint(ip("198.51.100.99"), 80, "tcp", Source::Pcap, packet(9, 40));
        let all = c.finish();
        let first = find(&all, Type::Endpoint, "203.0.113.45:443");
        assert_eq!(first.process, Some(a.clone()));
        assert_eq!(first.count, "2 connections");
        assert_eq!(
            first.details[1].1,
            "2 calls from kworkerd · 1412, 1 succeeded, 1 failed"
        );
        assert_eq!((first.first_us, first.last_us), (Some(10), Some(20)));
        assert_eq!(first.evidence.len(), 3);
        let shared = find(&all, Type::Endpoint, "198.51.100.77:80");
        assert_eq!(shared.process, None);
        assert_eq!(
            shared.candidates,
            [a, b],
            "candidates are listed, none is guessed"
        );
        let pcap_only = find(&all, Type::Endpoint, "198.51.100.99:80");
        assert!(pcap_only.process.is_none() && pcap_only.candidates.is_empty());
        assert_eq!(pcap_only.count, "1 frame");
    }

    #[test]
    fn private_addresses_and_local_names_have_nothing_to_look_up() {
        let mut c = Collector::default();
        c.endpoint(ip("10.0.2.3"), 53, "udp", Source::Pcap, packet(3, 1));
        c.endpoint(ip("224.0.0.251"), 5353, "udp", Source::Pcap, packet(4, 2));
        c.domain("printer.local", Via::Dns, &[], Source::Pcap, packet(5, 3));
        c.domain(
            "gate.kd-relay.example",
            Via::Dns,
            &[],
            Source::Pcap,
            packet(6, 4),
        );
        let all = c.finish();
        for key in ["10.0.2.3:53", "224.0.0.251:5353"] {
            let one = find(&all, Type::Endpoint, key);
            assert!(one.lookups.is_empty());
            assert_eq!(one.not_checked.as_deref(), Some("private address"));
        }
        assert_eq!(
            find(&all, Type::Domain, "printer.local")
                .not_checked
                .as_deref(),
            Some("local name")
        );
        let public = find(&all, Type::Domain, "gate.kd-relay.example");
        assert_eq!(
            public.lookups,
            [Lookup {
                kind: Kind::Domain,
                value: "gate.kd-relay.example".into()
            }]
        );
        assert!(public.not_checked.is_none());
    }

    #[test]
    fn a_domain_takes_the_process_that_reached_its_addresses() {
        let mut c = Collector::default();
        let a = proc(1412, "kworkerd");
        c.endpoint(
            ip("203.0.113.45"),
            443,
            "tcp",
            Source::Syscall,
            call(&a, true, 5),
        );
        c.domain(
            "c2.update-cdn.example",
            Via::Dns,
            &[ip("203.0.113.45")],
            Source::Pcap,
            packet(188, 1),
        );
        c.domain(
            "c2.update-cdn.example",
            Via::Sni,
            &[ip("203.0.113.45")],
            Source::Pcap,
            packet(215, 2),
        );
        c.domain(
            "nobody.example",
            Via::Dns,
            &[ip("203.0.113.99")],
            Source::Pcap,
            packet(10, 3),
        );
        let all = c.finish();
        let d = find(&all, Type::Domain, "c2.update-cdn.example");
        assert_eq!(d.sub, "DNS · SNI");
        assert_eq!(d.process, Some(a));
        assert_eq!(d.count, "2 lookups");
        assert!(find(&all, Type::Domain, "nobody.example").process.is_none());
    }

    #[test]
    fn urls_merge_by_method_and_canonical_form_and_look_up_the_url() {
        let mut c = Collector::default();
        let endpoint = Some((ip("198.51.100.77"), 80));
        for frame in [1030, 1031] {
            c.url(
                "get",
                "CDN.fastmirror.example",
                "/bin/x86_64/.kd",
                "HTTP/1.1",
                Some(200),
                endpoint,
                Source::Pcap,
                packet(frame, 5),
            );
        }
        c.url(
            "GET",
            "cdn.fastmirror.example",
            "/check?v=2",
            "HTTP/2",
            None,
            endpoint,
            Source::Pcap,
            packet(2210, 9),
        );
        let all = c.finish();
        assert_eq!(all.len(), 2);
        let kd = find(&all, Type::Url, "GET cdn.fastmirror.example/bin/x86_64/.kd");
        assert_eq!(kd.count, "2 requests");
        assert_eq!(kd.sub, "HTTP/1.1");
        assert_eq!(
            kd.lookups[0],
            Lookup {
                kind: Kind::Url,
                value: "cdn.fastmirror.example/bin/x86_64/.kd".into()
            }
        );
        assert!(kd.details[0].1.contains("response 200"));
    }

    #[test]
    fn a_tls_row_joins_hellos_and_looks_up_ja3_certificate_endpoint_and_name() {
        let mut c = Collector::default();
        let a = proc(1412, "kworkerd");
        c.endpoint(
            ip("203.0.113.45"),
            443,
            "tcp",
            Source::Syscall,
            call(&a, true, 5),
        );
        let hello = TlsFacts {
            sni: "C2.update-cdn.example".into(),
            ja3: "f6d64cbcb6dead5e8e864400f056fa32".into(),
            ja4: "t13d1715h2_a3c9d5e8f001_77b2e41d09ce".into(),
            version: "TLS 1.3".into(),
            ..TlsFacts::default()
        };
        let server = TlsFacts {
            sni: "C2.update-cdn.example".into(),
            ja3: "f6d64cbcb6dead5e8e864400f056fa32".into(),
            ja3s: "49086b3b1199e4e4df787c02f072157e".into(),
            cert_sha1: "2F22765D04931A078909145CA628D2264C852D7D".into(),
            ..TlsFacts::default()
        };
        c.tls(
            (ip("203.0.113.45"), 443),
            hello,
            Source::Pcap,
            packet(215, 6),
        );
        c.tls(
            (ip("203.0.113.45"), 443),
            server,
            Source::Pcap,
            packet(217, 7),
        );
        let all = c.finish();
        let tls: Vec<_> = all.iter().filter(|i| i.ty == Type::Tls).collect();
        assert_eq!(tls.len(), 1);
        let t = tls[0];
        assert_eq!(t.process, Some(a));
        let facts = t.tls.as_ref().unwrap();
        assert_eq!(facts.ja3s, "49086b3b1199e4e4df787c02f072157e");
        assert_eq!(facts.cert_sha1.len(), 40);
        let kinds: Vec<_> = t.lookups.iter().map(|l| l.kind).collect();
        assert!(kinds.contains(&Kind::Ja3) && kinds.contains(&Kind::CertSha1));
        assert!(kinds.contains(&Kind::IpPort) && kinds.contains(&Kind::Domain));
        assert_eq!(t.sub, "203.0.113.45:443 · TLS 1.3");
    }

    #[test]
    fn files_without_content_are_listed_as_not_checked() {
        let mut c = Collector::default();
        let hashes = Hashes {
            sha256: "f66025c51e65b02ffdaf55ea9460656a0b79598cb7db1514dc7a23a81b4cf1aa".into(),
            md5: "87221652a79fc3c9b04cde0b335fdd5b".into(),
            sha1: "fbe0c7a10f88830329b843444e239faff412172d".into(),
        };
        let b = proc(1420, ".kd");
        c.file(
            "/tmp/.X11-unix/.kd",
            "created",
            Some(hashes.clone()),
            Source::Disk,
            Seen::default(),
        );
        c.file(
            "/tmp/.X11-unix/.kd",
            "executed",
            Some(hashes),
            Source::Syscall,
            Seen {
                process: Some(b.clone()),
                ..Seen::default()
            },
        );
        c.file(
            "/var/tmp/.upd.sh",
            "deleted",
            None,
            Source::Syscall,
            Seen::default(),
        );
        let all = c.finish();
        let kd = all.iter().find(|i| i.path == "/tmp/.X11-unix/.kd").unwrap();
        assert_eq!(kd.roles, ["created", "executed"]);
        assert_eq!(kd.process, Some(b));
        assert_eq!(kd.lookups.len(), 2);
        let gone = all.iter().find(|i| i.path == "/var/tmp/.upd.sh").unwrap();
        assert_eq!(gone.value, "(no content kept)");
        assert_eq!(gone.not_checked.as_deref(), Some("no content kept"));
    }

    #[test]
    fn a_type_stops_at_its_limit_and_counts_the_rest() {
        let mut c = Collector::default();
        for n in 0..(TYPE_LIMIT + 5) {
            let ip = IpAddr::from([10 + (n >> 16) as u8, (n >> 8) as u8, n as u8, 1]);
            c.endpoint(ip, 80, "tcp", Source::Pcap, Seen::default());
        }
        assert_eq!(c.omitted, 5);
        assert_eq!(c.finish().len(), TYPE_LIMIT);
    }
}

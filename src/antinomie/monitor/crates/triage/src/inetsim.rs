// SPDX-License-Identifier: GPL-3.0-only
//! What the InetSim route's built-in services saw, from the log the gateway
//! wrote into the run's folder (`inetsim.json`): findings for the telnet
//! logins, the loader lines and the transfers; indicators for the URLs and
//! hosts the guest asked for; the rows of the Network view's InetSim tab; and
//! the stand-ins the services served, which are labelled and never counted as
//! the sample's payload or an indicator.
use super::*;
use antinomie_monitor_core::{
    HostClockAnchor,
    ioc::indicator::{Collector, Evidence, Indicator, Jump, Seen, Source, Type, Via},
    route::{InetSimReport, STAND_IN},
};
use std::net::IpAddr;

/// The InetSim tab's columns.
pub const HEADERS: &[&str] = &["Time", "Service", "Endpoint", "What", "Detail", "Served"];
/// Lines of a session listed in a finding's details.
const DETAIL_LINES: usize = 24;

fn guest_ns(clock: Option<HostClockAnchor>, ms: u64) -> u64 {
    crate::ioc_scan::guest_ns(clock, ms.saturating_mul(1000))
}

fn evidence() -> Evidence {
    Evidence {
        source: Source::Gateway,
        label: "InetSim log (inetsim.json)".into(),
        jump: Jump::Text,
    }
}

fn seen(ms: u64, note: Option<String>) -> Seen {
    Seen {
        time_us: Some(ms.saturating_mul(1000)),
        evidence: Some(evidence()),
        ok: Some(true),
        note,
        ..Seen::default()
    }
}

/// `host` as an address, or `None` for a name.
fn address(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[').trim_end_matches(']').parse().ok()
}

/// The URLs, hosts and endpoints of the downloads typed into telnet sessions
/// and of the FTP and TFTP transfers, as indicators. HTTP requests are in
/// the capture and come from there.
pub fn feed(collector: &mut Collector, report: &InetSimReport) {
    let downloads = report.sessions.iter().flat_map(|session| {
        session
            .downloads
            .iter()
            .map(move |d| (d.ms, d.tool.as_str(), d.url.as_str(), d.host.as_str(), d.port, d.name.as_str(), d.served.as_str(), session.endpoint.as_str()))
    });
    let transfers = report.transfers.iter().filter(|t| t.protocol != "http").map(|t| {
        let port = if t.protocol == "ftp" { 21 } else { 69 };
        (t.ms, t.protocol.as_str(), t.url.as_str(), t.host.as_str(), port, t.name.as_str(), t.served.as_str(), t.endpoint.as_str())
    });
    for (ms, tool, url, host, port, name, served, via) in downloads.chain(transfers) {
        if host.is_empty() {
            continue;
        }
        let note = Some(if served.is_empty() {
            format!("{tool} through {via}")
        } else {
            format!("{tool} through {via}; the answer was the {served}")
        });
        let method = match tool {
            "tftp" => "TFTP",
            "ftp" | "ftpget" | "ftpput" => "FTP",
            _ => "GET",
        };
        let endpoint = address(host).map(|ip| (ip, port));
        if url.starts_with("http") {
            let authority = if port == 80 { host.to_owned() } else { format!("{host}:{port}") };
            collector.url(method, &authority, name, "", None, endpoint, Source::Gateway, seen(ms, note.clone()));
        } else {
            collector.url(method, host, name, url.split("://").next().unwrap_or(""), None, endpoint, Source::Gateway, seen(ms, note.clone()));
        }
        match endpoint {
            Some((ip, port)) => collector.endpoint(ip, port, if tool == "tftp" { "udp" } else { "tcp" }, Source::Gateway, seen(ms, note)),
            None => collector.domain(host, Via::Sample, &[], Source::Gateway, seen(ms, note)),
        }
    }
}

/// Marks every file indicator whose SHA-256 is one of the stand-ins the
/// services serve: it is InetSim's, not the sample's, and no indicator.
pub fn mark_stand_ins(indicators: &mut [Indicator]) {
    for indicator in indicators.iter_mut().filter(|i| i.ty == Type::File) {
        let Some(sha) = indicator.hashes.as_ref().map(|h| h.sha256.clone()) else {
            continue;
        };
        if let Some(what) = antinomie_monitor_core::route::stand_in_described(&sha) {
            indicator.noise = Some(format!("{what} (Antinomie's own harmless file, not the sample's payload)"));
        }
    }
}

/// One row of the InetSim tab.
fn row(ms: u64, service: &str, endpoint: &str, what: String, detail: String, served: &str) -> Vec<Cell> {
    let mut time = crate::table::cell(crate::time_format::unix_us(ms.saturating_mul(1000)), crate::tone::muted(), false);
    time.values = vec![("inetsim.ms", RowValue::Number(i128::from(ms)))];
    vec![
        time,
        crate::table::cell(service, crate::tone::text(), false),
        crate::table::cell(endpoint, crate::tone::text(), true),
        crate::table::cell(what, crate::tone::text(), false),
        crate::table::cell(detail, crate::tone::muted(), true),
        crate::table::cell(served, if served.starts_with(STAND_IN) { crate::tone::warn() } else { crate::tone::muted() }, false),
    ]
}

/// The rows of the InetSim tab: each session, each download it asked for,
/// each transfer, in time order.
pub fn rows(report: &InetSimReport) -> Vec<Vec<Cell>> {
    let mut rows: Vec<(u64, Vec<Cell>)> = Vec::new();
    for session in &report.sessions {
        let logins: Vec<String> = session
            .logins
            .iter()
            .map(|l| format!("{}/{}{}", l.user, l.password, if l.accepted { "" } else { " (refused)" }))
            .collect();
        let what = format!(
            "{} session: {} lines, {} logins tried, ended: {}",
            session.service,
            session.lines.len() as u64 + session.lines_omitted,
            session.logins.len(),
            if session.ended.is_empty() { "still open at the run's end" } else { &session.ended }
        );
        let lines: Vec<&str> = session.lines.iter().take(6).map(|l| l.text.as_str()).collect();
        let detail = format!("logins: {}; {}", logins.join(", "), lines.join(" ⏎ "));
        rows.push((session.start_ms, row(session.start_ms, &session.service, &session.endpoint, what, detail, "")));
        for d in &session.downloads {
            let what = format!("{} asked for {}", d.tool, d.url);
            let detail = if d.saved_as.is_empty() { String::new() } else { format!("saved as {}", d.saved_as) };
            rows.push((d.ms, row(d.ms, &session.service, &session.endpoint, what, detail, &d.served)));
        }
        for w in &session.written {
            let what = format!("wrote {} with echo ({} bytes)", w.name, w.size);
            rows.push((session.end_ms, row(session.end_ms, &session.service, &session.endpoint, what, format!("SHA-256 {}", w.sha256), "")));
        }
        for x in &session.executed {
            rows.push((session.end_ms, row(session.end_ms, &session.service, &session.endpoint, format!("ran {x}"), String::new(), "")));
        }
    }
    for t in &report.transfers {
        let what = format!("{} {} {} ({} bytes)", t.protocol.to_ascii_uppercase(), t.direction, t.url, t.size);
        let mut detail = format!("SHA-256 {}", t.sha256);
        if !t.artifact.is_empty() {
            detail.push_str(&format!("; kept as {}", t.artifact));
        }
        if t.truncated {
            detail.push_str("; cut at the size limit");
        }
        rows.push((t.ms, row(t.ms, &t.protocol, &t.endpoint, what, detail, &t.served)));
    }
    if report.sessions_refused > 0 {
        rows.push((u64::MAX, row(0, "limit", "", format!("{} sessions hung up: the run's session limit was reached", report.sessions_refused), String::new(), "")));
    }
    rows.sort_by_key(|(ms, _)| *ms);
    rows.into_iter().map(|(_, row)| row).collect()
}

impl rules::Engine {
    /// The findings of the built-in services' log: a telnet login (with the
    /// logins tried), the download lines a session typed, the stand-ins
    /// served and the files uploaded. The host saw them, not a task.
    pub fn inetsim_report(&mut self, report: &InetSimReport, clock: Option<HostClockAnchor>) {
        const EVIDENCE: &str = "inetsim.json in the run's folder";
        const PROCESS: &str = "VM-wide (seen by the InetSim route's built-in services)";
        for session in report.sessions.iter().filter(|s| s.service == "telnet") {
            let at = guest_ns(clock, session.start_ms);
            let end = guest_ns(clock, session.end_ms.max(session.start_ms));
            if let Some(login) = session.logins.iter().find(|l| l.accepted) {
                let mut detail: Vec<String> = session
                    .logins
                    .iter()
                    .map(|l| format!("login {} / {}: {}", l.user, l.password, if l.accepted { "accepted" } else { "refused" }))
                    .collect();
                detail.extend(session.lines.iter().take(DETAIL_LINES).map(|l| format!("typed: {}", l.text)));
                self.host_row_from(
                    "network.inetsim_telnet_login",
                    (
                        session.endpoint.clone(),
                        format!(
                            "logged into the fake telnet device at {} as {} after {} tries",
                            session.endpoint,
                            login.user,
                            session.logins.len()
                        ),
                    ),
                    (at, 1, end),
                    detail,
                    PROCESS,
                    EVIDENCE,
                );
            }
            if !session.downloads.is_empty() {
                let detail = session
                    .downloads
                    .iter()
                    .map(|d| {
                        let served = if d.served.is_empty() { String::new() } else { format!(" (answered with the {})", d.served) };
                        format!("{}: {}{served}", d.tool, d.url)
                    })
                    .chain(session.executed.iter().map(|x| format!("ran {x}")))
                    .collect();
                self.host_row_from(
                    "network.inetsim_loader",
                    (
                        session.endpoint.clone(),
                        format!(
                            "typed a loader into the fake telnet device at {}: {} download{}",
                            session.endpoint,
                            session.downloads.len(),
                            if session.downloads.len() == 1 { "" } else { "s" }
                        ),
                    ),
                    (at, session.downloads.len() as u64, end),
                    detail,
                    PROCESS,
                    EVIDENCE,
                );
            }
        }
        for t in &report.transfers {
            let at = guest_ns(clock, t.ms);
            let (rule, summary) = match t.direction.as_str() {
                "upload" => (
                    "network.inetsim_upload",
                    format!("uploaded {} ({} bytes) over {} to {}", t.name, t.size, t.protocol.to_ascii_uppercase(), t.endpoint),
                ),
                _ if t.served.starts_with(STAND_IN) => (
                    "network.inetsim_download",
                    format!("downloaded {} over {}; InetSim answered with its {}", t.url, t.protocol.to_ascii_uppercase(), t.served.trim_start_matches(STAND_IN).trim_start_matches(": ")),
                ),
                _ if t.protocol != "http" => (
                    "network.inetsim_download",
                    format!("downloaded {} over {}", t.url, t.protocol.to_ascii_uppercase()),
                ),
                _ => continue,
            };
            let mut detail = vec![format!("SHA-256 {} ({} bytes)", t.sha256, t.size)];
            if !t.served.is_empty() {
                detail.push(format!("served: {}, not the sample's payload", t.served));
            }
            if !t.artifact.is_empty() {
                detail.push(format!("kept in the run's folder as {}", t.artifact));
            }
            self.host_row_from(rule, (t.url.clone(), summary), (at, 1, at), detail, PROCESS, EVIDENCE);
        }
    }
}

/// The report's InetSim notes: one per session and per transfer, in words,
/// for the JSON, STIX and MISP exports.
pub fn notes(report: &InetSimReport) -> Vec<antinomie_monitor_core::report::InetSimNote> {
    use antinomie_monitor_core::report::InetSimNote;
    let mut out = Vec::new();
    for s in &report.sessions {
        let mut detail: Vec<String> = s.logins.iter().map(|l| format!("login {} / {} {}", l.user, l.password, if l.accepted { "accepted" } else { "refused" })).collect();
        detail.extend(s.downloads.iter().map(|d| format!("{} {}{}", d.tool, d.url, if d.served.is_empty() { String::new() } else { format!(" ({})", d.served) })));
        detail.extend(s.lines.iter().take(DETAIL_LINES).map(|l| format!("typed: {}", l.text)));
        out.push(InetSimNote {
            kind: format!("{}-session", s.service),
            summary: format!("{} session to {}: {} logins tried, {} lines, {} downloads asked for", s.service, s.endpoint, s.logins.len(), s.lines.len() as u64 + s.lines_omitted, s.downloads.len()),
            detail,
            stand_in: s.downloads.iter().any(|d| d.served.starts_with(STAND_IN)),
        });
    }
    for t in &report.transfers {
        let stand_in = t.served.starts_with(STAND_IN);
        if t.protocol == "http" && !stand_in {
            continue;
        }
        out.push(InetSimNote {
            kind: format!("{}-{}", t.protocol, t.direction),
            summary: if stand_in {
                format!("{}: {} answered over {} with SHA-256 {}, not the sample's payload", t.served, t.url, t.protocol.to_ascii_uppercase(), t.sha256)
            } else {
                format!("{} {} {} ({} bytes, SHA-256 {})", t.protocol.to_ascii_uppercase(), t.direction, t.url, t.size, t.sha256)
            },
            detail: Vec::new(),
            stand_in,
        });
    }
    out
}

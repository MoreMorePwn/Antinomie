// SPDX-License-Identifier: GPL-3.0-only
//! Scanning as one behaviour, not thousands of indicators (ANT-T0556, A36).
//!
//! A bot that sweeps the internet connects to thousands of addresses on one
//! port and sprays them with exploit requests. Each target is no indicator of
//! the bot: listing them filled a 23 MB STIX bundle with 19,649 indicators.
//! A port with [`SCAN_TARGETS`] or more addresses is a scan; its targets
//! leave the indicator list and are told as one [`super::ScanSummary`] with
//! the counts, the port and a sample of targets. Endpoints of a scan that
//! look like a command server stay: a dataset matched them, or the program
//! came back to them [`KEEP_CONNECTIONS`] times or more (at most
//! [`KEEP_PER_SCAN`] of those per port).
use super::{Indicator, ScanSummary};
use std::collections::{BTreeMap, BTreeSet};

/// Distinct addresses on one port from which a port is a scan.
pub const SCAN_TARGETS: usize = 32;
/// Connections to one target from which it is kept as an indicator.
pub const KEEP_CONNECTIONS: u64 = 3;
/// Repeated targets kept per scanned port, most connections first.
pub const KEEP_PER_SCAN: usize = 8;
/// Targets named in a summary.
pub const SAMPLE: usize = 10;

/// `1.2.3.4:23` or `[2001:db8::1]:23` as the address and the port.
fn split_endpoint(value: &str) -> Option<(&str, u16)> {
    let (host, port) = value.rsplit_once(':')?;
    let port = port.parse().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.parse::<std::net::IpAddr>().ok().map(|_| (host, port))
}

/// The address a URL or TLS indicator went to, when its value names one.
fn host_of(indicator: &Indicator) -> Option<String> {
    let text = match indicator.kind.as_str() {
        // `GET 1.2.3.4:8080/path` or `POST 1.2.3.4/x`.
        "url" => indicator.value.split_once(' ').map(|(_, rest)| rest)?,
        // `(no SNI) 1.2.3.4:443` or `name 1.2.3.4:443`.
        "tls" => indicator.value.rsplit(' ').next()?,
        _ => return None,
    };
    let authority = text.split('/').next()?;
    if let Some((host, _)) = split_endpoint(authority) {
        return Some(host.to_owned());
    }
    authority
        .parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

/// The leading number of "12 connections".
fn connections(indicator: &Indicator) -> u64 {
    indicator
        .count
        .split_whitespace()
        .next()
        .and_then(|n| n.replace(',', "").parse().ok())
        .unwrap_or(1)
}

/// Take the targets of every scanned port out of `rows` and say what they
/// were. Rows keep their order; a row a dataset matched is never removed.
pub fn collapse(rows: &mut Vec<(Indicator, bool)>) -> Vec<ScanSummary> {
    let mut by_port: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for (indicator, _) in rows.iter() {
        if indicator.kind != "endpoint" || !indicator.base_noise.is_empty() {
            continue;
        }
        if let Some((host, port)) = split_endpoint(&indicator.value) {
            by_port.entry(port).or_default().insert(host.to_owned());
        }
    }
    by_port.retain(|_, hosts| hosts.len() >= SCAN_TARGETS);
    if by_port.is_empty() {
        return Vec::new();
    }
    // Per scanned port, the targets kept as indicators.
    let mut kept: BTreeMap<u16, BTreeSet<String>> = BTreeMap::new();
    for port in by_port.keys() {
        let mut repeated: Vec<(u64, String)> = rows
            .iter()
            .filter(|(i, _)| i.kind == "endpoint")
            .filter_map(|(i, matched)| {
                let (host, p) = split_endpoint(&i.value)?;
                let n = connections(i);
                (p == *port && (*matched || n >= KEEP_CONNECTIONS))
                    .then(|| (if *matched { u64::MAX } else { n }, host.to_owned()))
            })
            .collect();
        repeated.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        kept.insert(
            *port,
            repeated
                .into_iter()
                .take(KEEP_PER_SCAN)
                .map(|(_, host)| host)
                .collect(),
        );
    }
    let mut summaries: BTreeMap<u16, ScanSummary> = by_port
        .iter()
        .map(|(port, hosts)| {
            (
                *port,
                ScanSummary {
                    port: *port,
                    targets: hosts.len() as u64,
                    ..ScanSummary::default()
                },
            )
        })
        .collect();
    // Every address that is only a scan target (on any scanned port).
    let kept_ref = &kept;
    let target_ports: BTreeMap<&str, u16> = by_port
        .iter()
        .flat_map(|(port, hosts)| {
            hosts
                .iter()
                .filter(move |host| !kept_ref[port].contains(*host))
                .map(move |host| (host.as_str(), *port))
        })
        .collect();
    let target_ports: BTreeMap<String, u16> = target_ports
        .into_iter()
        .map(|(host, port)| (host.to_owned(), port))
        .collect();
    rows.retain(|(indicator, matched)| {
        if *matched {
            return true;
        }
        match indicator.kind.as_str() {
            "endpoint" => {
                let Some((host, port)) = split_endpoint(&indicator.value) else {
                    return true;
                };
                if !by_port.contains_key(&port) || kept[&port].contains(host) {
                    return true;
                }
                let summary = summaries.get_mut(&port).expect("a scanned port");
                summary.connections += connections(indicator);
                if summary.sample.len() < SAMPLE {
                    summary.sample.push(indicator.value.clone());
                }
                false
            }
            "url" | "tls" => {
                let Some(port) =
                    host_of(indicator).and_then(|host| target_ports.get(&host).copied())
                else {
                    return true;
                };
                let summary = summaries.get_mut(&port).expect("a scanned port");
                summary.requests += connections(indicator);
                if indicator.kind == "url" && summary.sample_requests.len() < 3 {
                    summary.sample_requests.push(indicator.value.clone());
                }
                false
            }
            _ => true,
        }
    });
    summaries.into_values().collect()
}

/// The sentence a document, MISP comment or STIX note says for one scan.
pub fn sentence(scan: &ScanSummary) -> String {
    let mut text = format!(
        "The run scanned {} addresses on port {} ({} connections){}; they are one behaviour here, not indicators.",
        scan.targets,
        scan.port,
        scan.connections,
        if scan.requests > 0 {
            format!(", with {} requests to them", scan.requests)
        } else {
            String::new()
        }
    );
    if !scan.sample.is_empty() {
        text.push_str(&format!(" Sample of targets: {}.", scan.sample.join(", ")));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(value: &str, count: &str) -> (Indicator, bool) {
        (
            Indicator {
                kind: "endpoint".into(),
                value: value.into(),
                count: count.into(),
                ..Indicator::default()
            },
            false,
        )
    }

    fn url(value: &str) -> (Indicator, bool) {
        (
            Indicator {
                kind: "url".into(),
                value: value.into(),
                count: "1 request".into(),
                ..Indicator::default()
            },
            false,
        )
    }

    #[test]
    fn a_scan_is_one_summary_and_the_command_server_stays() {
        // A36, runs 122797288 (116 targets on :8080 sprayed with 580 exploit
        // requests, C2 on :2323) and 8a747bf3 (10,380 connects).
        let mut rows = vec![endpoint("94.154.43.158:2323", "40 connections")];
        for n in 0..116u32 {
            let ip = format!("22.0.{}.{}", n / 200, n % 200 + 1);
            rows.push(endpoint(&format!("{ip}:8080"), "1 connection"));
            rows.push(url(&format!("GET {ip}:8080/cgi-bin/nas_sharing.cgi?x")));
            rows.push(url(&format!("POST {ip}:8080/admin/service/run")));
        }
        // A target the bot came back to, and one a dataset knew.
        rows.push(endpoint("22.9.9.9:8080", "6 connections"));
        let mut matched = endpoint("22.9.9.10:8080", "1 connection");
        matched.1 = true;
        rows.push(matched);
        let scans = collapse(&mut rows);
        assert_eq!(scans.len(), 1);
        let scan = &scans[0];
        assert_eq!((scan.port, scan.targets), (8080, 118));
        assert_eq!(scan.connections, 116);
        assert_eq!(scan.requests, 232);
        assert_eq!(scan.sample.len(), SAMPLE);
        assert_eq!(scan.sample_requests.len(), 3);
        let left: Vec<&str> = rows.iter().map(|(i, _)| i.value.as_str()).collect();
        assert_eq!(
            left,
            ["94.154.43.158:2323", "22.9.9.9:8080", "22.9.9.10:8080"]
        );
        assert!(sentence(scan).contains("118 addresses on port 8080"));
    }

    #[test]
    fn a_few_destinations_on_one_port_are_no_scan() {
        let mut rows: Vec<(Indicator, bool)> = (0..SCAN_TARGETS as u32 - 1)
            .map(|n| endpoint(&format!("203.0.113.{}:443", n + 1), "1 connection"))
            .collect();
        rows.push(url("GET 203.0.113.1:443/x"));
        let before = rows.len();
        assert!(collapse(&mut rows).is_empty());
        assert_eq!(rows.len(), before);
        // IPv6 targets are told by their address too.
        let mut six: Vec<(Indicator, bool)> = (0..40u32)
            .map(|n| endpoint(&format!("[2001:db8::{:x}]:23", n + 1), "1 connection"))
            .collect();
        assert_eq!(collapse(&mut six)[0].targets, 40);
        assert!(six.is_empty());
    }
}

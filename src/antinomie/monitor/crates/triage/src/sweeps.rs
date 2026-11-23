// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Scan storms (ANT-T0612): one process's `connect` and `sendto` calls to
//! thousands of addresses (a scanner) are one summarised row in the Endpoints
//! tab, the IOC list and the report, "scanned 16,384 addresses on ports 23,
//! 2323", instead of thousands of rows that push everything else out of the
//! lists. Nothing is lost: the calls stay in the trace, every rule sees each
//! of them, every address is matched against the datasets, and an address
//! that matched one, or that the online check answered for, keeps its own row.
use super::*;
use antinomie_monitor_core::ioc::indicator::{Indicator, Type};
use rules::ioc::{Log, Sweep};
use std::collections::HashMap;
use std::net::IpAddr;

/// The run's scans: each process's sweep that reached enough addresses.
#[derive(Clone, Debug, Default)]
pub struct Sweeps {
    pub scans: Vec<Sweep>,
    /// Endpoint (address, port) to the scan that reached it.
    endpoints: HashMap<(IpAddr, u16), usize>,
}

impl Sweeps {
    /// The scans among the calls the rules pass logged, oldest first.
    pub fn of(log: &Log) -> Self {
        let mut scans: Vec<Sweep> = log
            .sweeps
            .values()
            .filter(|sweep| sweep.is_scan())
            .cloned()
            .collect();
        scans.sort_by_key(|sweep| (sweep.who.time_ns, sweep.who.cookie));
        let mut endpoints = HashMap::new();
        for (at, sweep) in scans.iter().enumerate() {
            for (ip, port, _) in &sweep.endpoints {
                endpoints.entry((*ip, *port)).or_insert(at);
            }
        }
        Self { scans, endpoints }
    }

    pub fn is_empty(&self) -> bool {
        self.scans.is_empty()
    }

    /// The scan that reached `ip:port`.
    pub fn find(&self, ip: IpAddr, port: u16) -> Option<usize> {
        self.endpoints.get(&(ip, port)).copied()
    }

    /// The protocols a scan used, as the Endpoints tab names them.
    pub fn protocol(sweep: &Sweep) -> &'static str {
        let udp = sweep.endpoints.iter().any(|(_, _, udp)| *udp);
        let tcp = sweep.endpoints.iter().any(|(_, _, udp)| !*udp);
        match (tcp, udp) {
            (true, true) => "tcp and udp",
            (false, true) => "udp",
            _ => "tcp",
        }
    }

    /// The IOC list with each scan's endpoints folded into one row: an
    /// endpoint only a scan reached, that matched no dataset and no online
    /// answer, is counted in its scan's row instead of listed.
    pub fn fold(
        &self,
        indicators: Vec<Indicator>,
        scan: &antinomie_monitor_core::ioc::verdict::Scan,
        online: &antinomie_monitor_core::ioc::verdict::OnlineResults,
        clock: Option<antinomie_monitor_core::HostClockAnchor>,
    ) -> Vec<Indicator> {
        use antinomie_monitor_core::ioc::verdict::{evaluate, Outcome};
        if self.is_empty() {
            return indicators;
        }
        let mut folded: Vec<Option<Indicator>> = vec![None; self.scans.len()];
        let mut counts = vec![0u64; self.scans.len()];
        let mut kept = Vec::with_capacity(indicators.len());
        for indicator in indicators {
            let reached = (indicator.ty == Type::Endpoint)
                .then(|| endpoint_of(&indicator.key))
                .flatten()
                .and_then(|(ip, port)| self.find(ip, port));
            let Some(at) = reached else {
                kept.push(indicator);
                continue;
            };
            let outcome = evaluate(&indicator, scan, &[], online).outcome;
            let answered = indicator.lookups.iter().any(|lookup| {
                online
                    .entry(lookup.kind, &lookup.value)
                    .is_some_and(|entry| !entry.records.is_empty())
            });
            if answered || matches!(outcome, Outcome::Matched | Outcome::KnownFp) {
                kept.push(indicator);
                continue;
            }
            counts[at] += 1;
            let row = folded[at].get_or_insert_with(|| indicator.clone());
            row.sources.extend(indicator.sources.iter().cloned());
            row.first_us = row.first_us.into_iter().chain(indicator.first_us).min();
            row.last_us = row.last_us.into_iter().chain(indicator.last_us).max();
        }
        for (at, row) in folded.into_iter().enumerate() {
            let Some(mut row) = row else { continue };
            let sweep = &self.scans[at];
            row.key = format!("scan {} {}", sweep.who.cookie, sweep.who.pid);
            row.value = sweep.summary();
            row.sub = format!("{} scan", Self::protocol(sweep));
            row.process = Some(ioc_scan::process(&sweep.who));
            row.candidates.clear();
            row.count = format!(
                "{} calls; {} addresses listed here, each checked against the datasets",
                crate::values::thousands(sweep.calls),
                crate::values::thousands(counts[at])
            );
            row.details.clear();
            row.lookups.clear();
            row.evidence = vec![ioc_scan::call_evidence(&sweep.who, "connect")];
            row.not_checked = Some("a scan: each address was checked on its own".into());
            if row.first_us.is_none() {
                row.first_us = ioc_scan::host_us(clock, sweep.who.time_ns);
            }
            kept.push(row);
        }
        kept
    }
}

/// `ip:port` (or `[ip]:port`) back to its parts.
pub fn endpoint_of(key: &str) -> Option<(IpAddr, u16)> {
    let (ip, port) = key.rsplit_once(':')?;
    let ip = ip.trim_start_matches('[').trim_end_matches(']');
    Some((ip.parse().ok()?, port.parse().ok()?))
}

/// The traffic the capture showed with a scan's addresses: one row in the
/// Endpoints tab.
#[derive(Clone, Debug, Default)]
pub struct Traffic {
    pub capture: String,
    pub frame: u64,
    pub frames: u64,
    pub bytes: u64,
    pub first: Option<u64>,
    pub last: Option<u64>,
}

impl Traffic {
    pub fn add(&mut self, capture: &str, frame: u64, length: u64, time: Option<u64>) {
        if self.frames == 0 {
            self.capture = capture.to_owned();
            self.frame = frame;
        }
        self.frames += 1;
        self.bytes = self.bytes.saturating_add(length);
        self.first = self.first.into_iter().chain(time).min();
        self.last = self.last.into_iter().chain(time).max();
    }
}

impl network::Inventory {
    /// One Endpoints row for each scan the capture shows traffic of: its
    /// summary where the endpoint goes, the frames and bytes of all of it.
    pub fn sweep_rows(&self, attribution: &net_attr::NetAttribution, rows: &mut Vec<Vec<Cell>>) {
        let Some(sweeps) = &self.sweeps else { return };
        for (at, traffic) in &self.sweep_traffic {
            let sweep = &sweeps.scans[*at];
            let Some((ip, port, udp)) = sweep.endpoints.iter().min().copied() else {
                continue;
            };
            let source = attribution.source_of(&net_attr::FlowKey {
                udp: Some(udp),
                endpoint: (ip, port),
                others: &[],
                first_us: traffic.first,
                last_us: traffic.last,
            });
            let summary = sweep.summary();
            let time = |at: Option<u64>| {
                at.map_or("Unavailable".into(), crate::time_format::short_time_us)
            };
            let protocol = Sweeps::protocol(sweep);
            let mut row = vec![
                cell(&summary, tone::text(), false),
                net_tabs::source_cell(&source),
                cell(protocol, tone::text(), false),
                cell(traffic.frames.to_string(), tone::text(), true),
                cell(crate::values::file_size(traffic.bytes), tone::text(), true),
                cell("Many", tone::text(), false),
                cell("Many", tone::text(), false),
                cell(time(traffic.first), tone::text(), true),
                cell(time(traffic.last), tone::text(), true),
            ];
            let number =
                |at: Option<u64>| at.map_or(RowValue::Missing, |t| RowValue::Number(i128::from(t)));
            let busiest = sweep
                .ports
                .iter()
                .max_by_key(|(_, calls)| **calls)
                .map_or(port, |(p, _)| *p);
            row[0].values = vec![
                ("capture.path", RowValue::Text(traffic.capture.clone())),
                ("network.endpoint", RowValue::Text(summary)),
                ("network.ip", RowValue::Missing),
                ("network.port", RowValue::Number(i128::from(busiest))),
                ("network.protocol", RowValue::Text(protocol.into())),
                (
                    "network.frames",
                    RowValue::Number(i128::from(traffic.frames)),
                ),
                ("network.bytes", RowValue::Number(i128::from(traffic.bytes))),
                ("network.country", RowValue::Missing),
                ("network.organization", RowValue::Missing),
                ("network.first_us", number(traffic.first)),
                ("network.last_us", number(traffic.last)),
                ("frame.number", RowValue::Number(i128::from(traffic.frame))),
            ];
            row[0].values.extend(net_tabs::source_values(&source));
            rows.push(row);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use antinomie_monitor_core::ioc::indicator::{Collector, Seen, Source};

    fn log(scanner: u32, addresses: u32, other: u32) -> Log {
        let mut log = Log::default();
        let who = |pid: u32| rules::ioc::Who {
            cookie: u64::from(pid),
            pid,
            tid: pid,
            time_ns: 1_000,
            stream: 1,
            call_id: 1,
            ..Default::default()
        };
        for at in 0..addresses {
            let ip = std::net::Ipv4Addr::from(0x0b00_0000 + at);
            rules::ioc::push(
                &mut log,
                rules::ioc::Connection {
                    ip: ip.into(),
                    port: if at % 3 == 0 { 2323 } else { 23 },
                    udp: false,
                    ok: false,
                    who: who(scanner),
                    name: "connect",
                },
            );
        }
        for at in 0..other {
            rules::ioc::push(
                &mut log,
                rules::ioc::Connection {
                    ip: std::net::Ipv4Addr::new(198, 51, 100, at as u8).into(),
                    port: 443,
                    udp: false,
                    ok: true,
                    who: who(scanner + 1),
                    name: "connect",
                },
            );
        }
        log
    }

    #[test]
    fn a_process_that_reaches_many_addresses_is_one_scan_and_the_rest_stay() {
        let sweeps = Sweeps::of(&log(7, 600, 3));
        assert_eq!(
            sweeps.scans.len(),
            1,
            "the three calls of the other process are no scan"
        );
        let scan = &sweeps.scans[0];
        assert_eq!(scan.summary(), "scanned 600 addresses on ports 23, 2323");
        assert!(sweeps.find("11.0.0.5".parse().unwrap(), 2323).is_none());
        assert_eq!(sweeps.find("11.0.0.3".parse().unwrap(), 2323), Some(0));
        assert!(sweeps.find("198.51.100.1".parse().unwrap(), 443).is_none());
        // Below the threshold nothing is a scan.
        assert!(Sweeps::of(&log(7, 100, 0)).is_empty());
    }

    #[test]
    fn the_ioc_list_folds_a_scan_and_keeps_an_answered_address() {
        let log = log(7, 400, 2);
        let sweeps = Sweeps::of(&log);
        let mut collector = Collector::default();
        for connection in &log.connections {
            collector.endpoint(
                connection.ip,
                connection.port,
                "tcp",
                Source::Syscall,
                Seen {
                    process: Some(ioc_scan::process(&connection.who)),
                    ..Seen::default()
                },
            );
        }
        let indicators = collector.finish();
        assert_eq!(indicators.len(), 402);
        // The online check answered for one scanned address: it keeps its row.
        let answered = indicators
            .iter()
            .find(|indicator| indicator.key == "11.0.0.9:2323")
            .expect("a scanned address")
            .lookups
            .first()
            .cloned()
            .expect("an address is looked up");
        let online = antinomie_monitor_core::ioc::verdict::OnlineResults {
            entries: vec![antinomie_monitor_core::ioc::verdict::OnlineEntry {
                kind: answered.kind,
                value: answered.value.clone(),
                at_unix: 1,
                records: vec![Default::default()],
            }],
        };
        let folded = sweeps.fold(indicators, &Default::default(), &online, None);
        let keys: Vec<&str> = folded
            .iter()
            .map(|indicator| indicator.key.as_str())
            .collect();
        assert_eq!(folded.len(), 4, "{keys:?}");
        assert!(keys.contains(&"11.0.0.9:2323"));
        assert!(keys.contains(&"198.51.100.0:443") && keys.contains(&"198.51.100.1:443"));
        let row = folded
            .iter()
            .find(|indicator| indicator.key.starts_with("scan "))
            .unwrap();
        assert_eq!(row.value, "scanned 400 addresses on ports 23, 2323");
        assert!(
            row.count.contains("399 addresses listed here"),
            "{}",
            row.count
        );
        assert_eq!(row.process.as_ref().map(|process| process.pid), Some(7));
    }

    #[test]
    fn an_endpoint_key_reads_back_for_both_address_families() {
        assert_eq!(
            endpoint_of("1.2.3.4:23"),
            Some(("1.2.3.4".parse().unwrap(), 23))
        );
        assert_eq!(
            endpoint_of("[2001:db8::1]:2323"),
            Some(("2001:db8::1".parse().unwrap(), 2323))
        );
        assert_eq!(endpoint_of("not an endpoint"), None);
    }
}

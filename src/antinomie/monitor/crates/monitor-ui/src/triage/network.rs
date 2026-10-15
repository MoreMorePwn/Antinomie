// SPDX-License-Identifier: MIT
//! Summaries of destinations and observed hostnames, without remote enrichment.
use super::*;
use std::collections::{BTreeMap, BTreeSet};
const INVENTORY_LIMIT: usize = 16384;

pub(super) const IP_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("network.ip", "Observed destination IP"),
    FieldSpec::text(
        "network.country",
        "Country from locally configured TShark GeoIP data",
    ),
    FieldSpec::text("network.organization", "Organization from local ASN data"),
    FieldSpec::number("frame.number", "First observed destination packet"),
];
pub(super) const HOST_FIELDS: &[FieldSpec<'static>] = &[
    FieldSpec::text("network.hostname", "DNS question, HTTP Host or TLS SNI"),
    FieldSpec::tags(
        "network.addresses",
        "Observed DNS addresses or connection destinations",
    ),
    FieldSpec::number("network.count", "Observed requests or client hellos"),
    FieldSpec::tags("network.sources", "DNS, HTTP or TLS"),
    FieldSpec::number("frame.number", "First original packet"),
];

#[derive(Default)]
struct Host {
    frame: u64,
    first: Option<u64>,
    last: Option<u64>,
    count: u64,
    addresses: BTreeSet<String>,
    sources: BTreeSet<String>,
}

#[derive(Default)]
pub(super) struct Inventory {
    ips: BTreeMap<String, (u64, String, String)>,
    hosts: BTreeMap<String, Host>,
    pub omitted: u64,
}

impl Inventory {
    pub fn destination(&mut self, ip: &str, frame: u64, country: &str, organization: &str) {
        if ip.parse::<std::net::IpAddr>().is_err() {
            return;
        }
        if self.ips.len() >= INVENTORY_LIMIT && !self.ips.contains_key(ip) {
            self.omitted += 1;
            return;
        }
        self.ips
            .entry(ip.into())
            .or_insert_with(|| (frame, country.into(), organization.into()));
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
        let host = self.hosts.entry(name).or_insert_with(|| Host {
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
    pub fn rows(&self) -> (Vec<Vec<Cell>>, Vec<Vec<Cell>>) {
        let ips = self
            .ips
            .iter()
            .map(|(ip, (frame, country, organization))| {
                let mut row = vec![
                    cell(ip, theme::text(), true),
                    cell(available(country), theme::text(), false),
                    cell(available(organization), theme::text(), false),
                ];
                row[0].values = vec![
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
                    ("network.hostname", RowValue::Text(name.clone())),
                    (
                        "network.addresses",
                        RowValue::List(host.addresses.iter().cloned().collect()),
                    ),
                    ("network.count", RowValue::Number(i128::from(host.count))),
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
fn available(value: &str) -> &str {
    if value.is_empty() {
        "Unavailable"
    } else {
        value
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

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(files::number(&ips[0][0].values, "frame.number"), Some(9));
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0][0].text, "example.test");
        assert_eq!(hosts[0][4].text, "2");
        assert!(hosts[0][5].text.contains("HTTP"));
        assert_eq!(qtype("28"), "AAAA");
        assert_eq!(qtype("65000"), "65000");
    }
}

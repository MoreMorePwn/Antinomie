// SPDX-License-Identifier: GPL-3.0-only
//! Summaries of destinations and observed hostnames.
//! Public-address enrichment runs in the index worker, never while drawing.
use super::*;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Default)]
struct Host {
    capture: String,
    frame: u64,
    first: Option<u64>,
    last: Option<u64>,
    count: u64,
    addresses: BTreeSet<String>,
    sources: BTreeSet<String>,
}

#[derive(Default)]
pub(super) struct Inventory {
    ips: BTreeMap<String, (u64, String, String, String)>,
    hosts: BTreeMap<String, Host>,
    pub capture: String,
    pub omitted: u64,
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

// SPDX-License-Identifier: GPL-3.0-only
//! The Summary's Indicators: the endpoints the run contacted (with country
//! and organization), its DNS names, HTTP URLs and the files it dropped or
//! ran, as text to copy and as JSON to export.
use antinomie_monitor_core::ioc::indicator::{Indicator, Type};
use serde_json::json;

/// Rows of each kind the box lists before "Show N more".
pub const SHOWN: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointRow {
    pub endpoint: String,
    pub country: String,
    pub organization: String,
    /// How the endpoint was seen ("tcp", "udp").
    pub note: String,
    /// The name the gateway's stand-in address (198.18.x.x on a proxied route)
    /// was handed out for.
    pub stand_in: Option<String>,
}

/// An endpoint, name or URL that is the base image's own traffic: kept out of
/// the lists, counted in one muted line at the end of its group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Background {
    /// 0 endpoints, 1 DNS names, 2 URLs (the order of the Indicators box).
    pub group: usize,
    pub value: String,
    /// What it is: "NTP", "DHCP", "apt".
    pub kind: &'static str,
    pub why: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRow {
    pub path: String,
    pub kind: &'static str,
    pub sha256: String,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Indicators {
    pub endpoints: Vec<EndpointRow>,
    pub domains: Vec<String>,
    pub urls: Vec<String>,
    pub files: Vec<FileRow>,
    pub background: Vec<Background>,
}

/// What kind of base image traffic a noise tag is about.
pub fn background_kind(value: &str, why: &str) -> &'static str {
    let text = format!("{value} {why}").to_ascii_lowercase();
    if text.contains("ntp") || text.contains("clock sync") {
        "NTP"
    } else if text.contains("dhcp") {
        "DHCP"
    } else if ["debian", "apt", "ubuntu"]
        .iter()
        .any(|word| text.contains(word))
    {
        "apt"
    } else {
        "system"
    }
}

/// What a file is, from its name and what the run did to it. The recording
/// keeps no content type of its own.
fn file_kind(path: &str, roles: &[String]) -> &'static str {
    let name = crate::process_cells::file_name(path);
    if name.ends_with(".so") || name.contains(".so.") {
        "shared object"
    } else if name.ends_with(".sh") || name.ends_with(".py") || name.ends_with(".pl") {
        "script"
    } else if roles.iter().any(|role| role == "executed") {
        "executable"
    } else {
        "file"
    }
}

impl Indicators {
    /// `geo` gives the country and organization of an `ip:port`.
    pub fn of(indicators: &[Indicator], geo: impl Fn(&str) -> (String, String)) -> Self {
        let mut out = Indicators::default();
        for indicator in indicators {
            if let Some(why) = &indicator.noise {
                let group = match indicator.ty {
                    Type::Endpoint => 0,
                    Type::Domain => 1,
                    Type::Url => 2,
                    // A TLS session is the same traffic as its name and address.
                    _ => continue,
                };
                out.background.push(Background {
                    group,
                    value: indicator.value.clone(),
                    kind: background_kind(&indicator.value, why),
                    why: why.clone(),
                });
                continue;
            }
            match indicator.ty {
                Type::Endpoint => {
                    let (country, organization) = geo(&indicator.value);
                    out.endpoints.push(EndpointRow {
                        endpoint: indicator.value.clone(),
                        country,
                        organization,
                        note: indicator.sub.clone(),
                        stand_in: indicator.stand_in.clone(),
                    });
                }
                Type::Domain => out.domains.push(indicator.value.clone()),
                Type::Url => {
                    let url = if indicator.value.contains("://") {
                        indicator.value.clone()
                    } else {
                        format!("http://{}", indicator.value)
                    };
                    out.urls.push(url);
                }
                Type::File => {
                    let dropped = indicator.roles.iter().any(|role| {
                        matches!(role.as_str(), "created" | "written at close" | "executed")
                    });
                    if !dropped {
                        continue;
                    }
                    let path = if indicator.path.is_empty() {
                        &indicator.value
                    } else {
                        &indicator.path
                    };
                    out.files.push(FileRow {
                        kind: file_kind(path, &indicator.roles),
                        sha256: indicator
                            .hashes
                            .as_ref()
                            .map(|h| h.sha256.clone())
                            .unwrap_or_default(),
                        roles: indicator.roles.clone(),
                        path: path.clone(),
                    });
                }
                Type::Tls => {}
            }
        }
        out.domains.sort();
        out.domains.dedup();
        out.urls.sort();
        out.urls.dedup();
        out
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
            && self.domains.is_empty()
            && self.urls.is_empty()
            && self.files.is_empty()
    }

    pub fn total(&self) -> usize {
        self.endpoints.len() + self.domains.len() + self.urls.len() + self.files.len()
    }

    /// "NL \u{b7} AS49870 Alsycon": the geolocation words of an endpoint.
    pub fn place(row: &EndpointRow) -> String {
        [row.country.as_str(), row.organization.as_str()]
            .iter()
            .filter(|part| !part.is_empty() && **part != "\u{2014}")
            .copied()
            .collect::<Vec<_>>()
            .join(" \u{b7} ")
    }

    /// "Base image background: NTP, apt (4)" for a group, when it has any.
    pub fn background_label(&self, group: usize) -> Option<String> {
        let mut kinds: Vec<&str> = Vec::new();
        let mut count = 0;
        for item in self.background.iter().filter(|item| item.group == group) {
            count += 1;
            if !kinds.contains(&item.kind) {
                kinds.push(item.kind);
            }
        }
        const ORDER: [&str; 4] = ["NTP", "DHCP", "apt", "system"];
        kinds.sort_by_key(|kind| ORDER.iter().position(|known| known == kind));
        (count > 0).then(|| format!("Base image background: {} ({count})", kinds.join(", ")))
    }

    /// Plain text, one indicator per line, grouped.
    #[cfg(test)]
    pub fn copy_text(&self) -> String {
        self.copy_text_with(&[false; 3])
    }

    /// [`Self::copy_text`] with the background lines of the groups the
    /// analyst has opened.
    pub fn copy_text_with(&self, shown: &[bool; 3]) -> String {
        let mut text = String::new();
        let mut group = |title: &str, lines: Vec<String>| {
            if lines.is_empty() {
                return;
            }
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(&format!("# {title}\n"));
            for line in lines {
                text.push_str(&line);
                text.push('\n');
            }
        };
        group(
            "Endpoints",
            self.endpoints
                .iter()
                .map(|row| {
                    let name = row
                        .stand_in
                        .as_ref()
                        .map_or(String::new(), |name| format!(" \u{2192} {name}"));
                    match Self::place(row) {
                        place if place.is_empty() => format!("{}{name}", row.endpoint),
                        place => format!("{}{name} ({place})", row.endpoint),
                    }
                })
                .chain(self.background_lines(0, shown[0]))
                .collect(),
        );
        group(
            "DNS names",
            self.domains
                .iter()
                .cloned()
                .chain(self.background_lines(1, shown[1]))
                .collect(),
        );
        group(
            "URLs",
            self.urls
                .iter()
                .cloned()
                .chain(self.background_lines(2, shown[2]))
                .collect(),
        );
        group(
            "Files",
            self.files
                .iter()
                .map(|row| match row.sha256.as_str() {
                    "" => format!("{} ({})", row.path, row.kind),
                    hash => format!("{} ({}) {hash}", row.path, row.kind),
                })
                .collect(),
        );
        text
    }

    fn background_lines(&self, group: usize, shown: bool) -> Vec<String> {
        self.background
            .iter()
            .filter(|item| shown && item.group == group)
            .map(|item| format!("{} (base image: {})", item.value, item.kind))
            .collect()
    }

    pub fn json(&self) -> String {
        let value = json!({
            "endpoints": self.endpoints.iter().map(|row| json!({
                "endpoint": row.endpoint,
                "country": row.country,
                "organization": row.organization,
                "stand_in_for": row.stand_in,
            })).collect::<Vec<_>>(),
            "dns": self.domains,
            "urls": self.urls,
            "files": self.files.iter().map(|row| json!({
                "path": row.path,
                "type": row.kind,
                "sha256": row.sha256,
                "roles": row.roles,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_string_pretty(&value).unwrap_or_default()
    }
}

#[cfg(any(test, feature = "test-support"))]
pub mod tests {
    use super::*;
    use antinomie_monitor_core::ioc::indicator::Hashes;

    pub fn indicator(ty: Type, value: &str) -> Indicator {
        Indicator {
            ty,
            key: value.into(),
            value: value.into(),
            sub: String::new(),
            sources: Default::default(),
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
            hash_note: None,
            noise: None,
            stand_in: None,
        }
    }

    pub fn sample() -> Vec<Indicator> {
        let mut file = indicator(Type::File, "9b1c");
        file.path = "/tmp/.x/kdevtmpfsi".into();
        file.roles = vec!["created".into(), "executed".into()];
        file.hashes = Some(Hashes {
            sha256: "9b1c".repeat(16),
            md5: String::new(),
            sha1: String::new(),
        });
        let mut changed = indicator(Type::File, "x");
        changed.path = "/etc/hosts".into();
        changed.roles = vec!["changed".into()];
        let mut noise = indicator(Type::Endpoint, "10.0.2.2:67");
        noise.noise = Some("DHCP".into());
        vec![
            indicator(Type::Endpoint, "45.9.148.9:80"),
            noise,
            indicator(Type::Domain, "pool.minexmr.com"),
            indicator(Type::Domain, "pool.minexmr.com"),
            indicator(Type::Url, "45.9.148.9/k"),
            indicator(Type::Url, "http://45.9.148.9/hook.so"),
            file,
            changed,
        ]
    }

    #[cfg(test)]
    fn geo(endpoint: &str) -> (String, String) {
        if endpoint.starts_with("45.9.148.9") {
            ("NL".into(), "AS49870 Alsycon".into())
        } else {
            (String::new(), String::new())
        }
    }

    #[test]
    fn indicators_keep_what_the_run_contacted_and_dropped() {
        let found = Indicators::of(&sample(), geo);
        assert_eq!(found.endpoints.len(), 1, "base-image noise is left out");
        assert_eq!(
            Indicators::place(&found.endpoints[0]),
            "NL \u{b7} AS49870 Alsycon"
        );
        assert_eq!(found.domains, ["pool.minexmr.com"]);
        assert_eq!(
            found.urls,
            ["http://45.9.148.9/hook.so", "http://45.9.148.9/k"]
        );
        assert_eq!(found.files.len(), 1, "a changed file is not dropped or run");
        assert_eq!(found.files[0].kind, "executable");
        assert_eq!(found.files[0].sha256.len(), 64);
        assert_eq!(found.total(), 5);
        assert!(!found.is_empty());
        assert!(Indicators::of(&[], geo).is_empty());
    }

    #[test]
    fn copy_all_is_plain_text_one_per_line_grouped() {
        let text = Indicators::of(&sample(), geo).copy_text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "# Endpoints");
        assert_eq!(lines[1], "45.9.148.9:80 (NL \u{b7} AS49870 Alsycon)");
        assert_eq!(lines[2], "");
        assert_eq!(lines[3], "# DNS names");
        assert_eq!(lines[4], "pool.minexmr.com");
        assert!(
            text.contains("# URLs\nhttp://45.9.148.9/hook.so\nhttp://45.9.148.9/k\n"),
            "{text}"
        );
        assert!(text.contains("/tmp/.x/kdevtmpfsi (executable) "), "{text}");
        assert!(Indicators::default().copy_text().is_empty());
    }

    #[test]
    fn export_is_json_with_every_group() {
        let value: serde_json::Value =
            serde_json::from_str(&Indicators::of(&sample(), geo).json()).unwrap();
        assert_eq!(value["endpoints"][0]["country"], "NL");
        assert_eq!(value["dns"][0], "pool.minexmr.com");
        assert_eq!(value["urls"].as_array().unwrap().len(), 2);
        assert_eq!(value["files"][0]["type"], "executable");
    }

    #[cfg(test)]
    fn background() -> Vec<Indicator> {
        let mut ntp = indicator(Type::Endpoint, "198.18.0.2:123");
        ntp.noise = Some("NTP, the base image's clock sync".into());
        let mut apt = indicator(Type::Endpoint, "198.18.0.7:443");
        apt.noise = Some("198.18.0.7 is the address the base image's lookup of metadata.ftp-master.debian.org got".into());
        let mut name = indicator(Type::Domain, "metadata.ftp-master.debian.org");
        name.noise = Some("metadata.ftp-master.debian.org is looked up by the base image".into());
        let mut c2 = indicator(Type::Endpoint, "198.18.0.1:8443");
        c2.stand_in = Some("apache-update.ddns.net".into());
        vec![c2, ntp, apt, name]
    }

    #[test]
    fn background_traffic_is_one_counted_line_per_branch_and_stays_out_of_copy_all() {
        let found = Indicators::of(&background(), geo);
        assert_eq!(
            found.endpoints.len(),
            1,
            "only the sample's endpoint is a row"
        );
        assert_eq!(
            found.background_label(0).as_deref(),
            Some("Base image background: NTP, apt (2)")
        );
        assert_eq!(
            found.background_label(1).as_deref(),
            Some("Base image background: apt (1)")
        );
        assert_eq!(found.background_label(2), None);
        let closed = found.copy_text();
        assert!(
            !closed.contains("198.18.0.2") && !closed.contains("metadata"),
            "{closed}"
        );
        assert!(
            closed.contains("198.18.0.1:8443 \u{2192} apache-update.ddns.net"),
            "{closed}"
        );
        let open = found.copy_text_with(&[true, false, false]);
        assert!(open.contains("198.18.0.2:123 (base image: NTP)"), "{open}");
        assert!(
            !open.contains("metadata"),
            "only the opened branch is added"
        );
    }
}

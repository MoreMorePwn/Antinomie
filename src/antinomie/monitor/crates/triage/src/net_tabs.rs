// SPDX-License-Identifier: GPL-3.0-only
//! The columns of the Network tabs, shown and stored.
use super::*;

pub const ENDPOINT_HEADERS: &[&str] = &[
    "Endpoint",
    "IOC",
    "Proto",
    "Frames",
    "Bytes",
    "Country",
    "Organization",
    "First seen",
    "Last seen",
];
/// The columns of the Endpoints table that hold the geolocation.
pub const ENDPOINT_COUNTRY: usize = 5;
pub const ENDPOINT_ORGANIZATION: usize = 6;
pub const DOMAIN_HEADERS: &[&str] = &[
    "Domain",
    "IOC",
    "Seen as",
    "Resolved / connected IPs",
    "Queries",
    "First seen",
    "Last seen",
    "Rcode",
];
/// The 0.7.0 HTTP columns, with the verdict after the endpoint and the protocol
/// version before the response (the response frame stays in Details).
pub const URL_HEADERS: &[&str] = &[
    "Frame", "Time", "Endpoint", "IOC", "Method", "Host", "URI", "Version", "Response",
];
pub const TLS_HEADERS: &[&str] = &[
    "Frame",
    "Server name",
    "IOC",
    "Endpoint",
    "Version",
    "ALPN",
    "JA3",
    "JA4",
    "JA3S",
    "Cert SHA-1",
    "Sessions",
];

/// The same columns as the scan stores them, before the IOC column is added
/// (a sort is made on the stored rows).
pub const ENDPOINT_STORED: &[&str] = &[
    "Endpoint",
    "Proto",
    "Frames",
    "Bytes",
    "Country",
    "Organization",
    "First seen",
    "Last seen",
];
pub const DOMAIN_STORED: &[&str] = &[
    "Domain",
    "Seen as",
    "Resolved / connected IPs",
    "Queries",
    "First seen",
    "Last seen",
    "Rcode",
];
pub const TLS_STORED: &[&str] = &[
    "Frame",
    "Server name",
    "Endpoint",
    "Version",
    "ALPN",
    "JA3",
    "JA4",
    "JA3S",
    "Cert SHA-1",
    "Sessions",
];

/// The column of the stored HTTP row behind column `shown` of the URLs tab:
/// the verdict and the version are not stored, and sorting by them sorts by
/// the first column.
pub fn stored_url_column(shown: usize) -> usize {
    match shown {
        0..=2 => shown,
        3 | 7 => 0,
        4..=6 => shown - 1,
        _ => 6,
    }
}

/// The column of the stored row behind column `shown` of a rebuilt tab: the
/// IOC column is not stored, and sorting by it sorts by the first column.
pub fn stored_column(slot: usize, shown: usize) -> usize {
    let ioc = if slot == TLS_SLOT { 2 } else { 1 };
    match shown.cmp(&ioc) {
        std::cmp::Ordering::Less => shown,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => shown - 1,
    }
}

/// Whether the earliest packet of the run is a whole zone offset (a non-zero
/// multiple of 15 minutes under 15 h, within two minutes) away from the run's
/// clock anchor: the sign of a capture QEMU stamped in the host zone (runs
/// recorded before 0.8.2). Uses only what the Endpoints table already holds;
/// `fallback` is the request's anchor, for an index that recorded none.
pub fn capture_zone_shift(
    scan: &ScanData,
    fallback: Option<antinomie_monitor_core::HostClockAnchor>,
) -> bool {
    let Some(clock) = scan.clock_anchor.or(fallback) else {
        return false;
    };
    let first = scan
        .new_tabs
        .endpoints
        .iter()
        .filter_map(|row| row.first())
        .filter_map(|cell| files::number(&cell.values, "network.first_us"))
        .min();
    let Some(first) = first else {
        return false;
    };
    let seconds = (i128::from(first) - i128::from(clock.host_us)) / 1_000_000;
    let offset = (seconds as f64 / 900.0).round() as i128 * 900;
    offset != 0 && offset.abs() < 15 * 3600 && (seconds - offset).abs() <= 120
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_geolocation_columns_are_the_countries_and_organizations() {
        // The Summary's indicator export reads these two (a shift by one put
        // the byte count under "country").
        assert_eq!(ENDPOINT_HEADERS[ENDPOINT_COUNTRY], "Country");
        assert_eq!(ENDPOINT_HEADERS[ENDPOINT_ORGANIZATION], "Organization");
    }
}

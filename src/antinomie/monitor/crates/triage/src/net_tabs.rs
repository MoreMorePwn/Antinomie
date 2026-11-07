// SPDX-License-Identifier: GPL-3.0-only
//! The columns of the Network tabs, shown and stored.
use super::*;

pub(super) const ENDPOINT_HEADERS: &[&str] = &[
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
pub(super) const DOMAIN_HEADERS: &[&str] = &[
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
pub(super) const URL_HEADERS: &[&str] = &[
    "Frame", "Time", "Endpoint", "IOC", "Method", "Host", "URI", "Version", "Response",
];
pub(super) const TLS_HEADERS: &[&str] = &[
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
pub(super) const ENDPOINT_STORED: &[&str] = &[
    "Endpoint",
    "Proto",
    "Frames",
    "Bytes",
    "Country",
    "Organization",
    "First seen",
    "Last seen",
];
pub(super) const DOMAIN_STORED: &[&str] = &[
    "Domain",
    "Seen as",
    "Resolved / connected IPs",
    "Queries",
    "First seen",
    "Last seen",
    "Rcode",
];
pub(super) const TLS_STORED: &[&str] = &[
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
pub(super) fn stored_url_column(shown: usize) -> usize {
    match shown {
        0..=2 => shown,
        3 | 7 => 0,
        4..=6 => shown - 1,
        _ => 6,
    }
}

/// The column of the stored row behind column `shown` of a rebuilt tab: the
/// IOC column is not stored, and sorting by it sorts by the first column.
pub(super) fn stored_column(slot: usize, shown: usize) -> usize {
    let ioc = if slot == TLS_SLOT { 2 } else { 1 };
    match shown.cmp(&ioc) {
        std::cmp::Ordering::Less => shown,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => shown - 1,
    }
}


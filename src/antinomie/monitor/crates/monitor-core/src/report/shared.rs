// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Which indicators are worth sharing. A report lists everything the run
//! showed, but MISP and STIX are for other people's blocklists and rules, so
//! they carry only what a consumer could match: not the sandbox's own
//! resolver, not the Tor gateway's stand-in addresses (the name they stand
//! for is the indicator), not Debian programs the run merely started.
use std::net::IpAddr;

/// The range the Tor gateway hands out for names (RFC 2544 benchmarking
/// space, 198.18.0.0/15).
pub fn tor_stand_in(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
}

/// Whether the address is local to the sandbox: private, loopback, link-local,
/// unspecified, multicast or broadcast.
pub fn local_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Why an endpoint is the guest's own DNS resolver (a private address on port
/// 53): the names it was asked for are indicators of their own, so the
/// address is the base image's traffic, not the sample's.
pub fn resolver_noise(kind: &str, value: &str) -> Option<&'static str> {
    (kind == "endpoint"
        && value.ends_with(":53")
        && not_shared_reason(kind, value, &[], "").starts_with("private"))
    .then_some(
        "the guest's own DNS resolver (a private address); the names it was asked for are listed as domains",
    )
}

/// Why an indicator is kept out of MISP and STIX, or empty when it is shared.
/// `roles` are a file's roles, `not_checked` the reason no dataset was asked
/// (`private address`, `no content kept`).
pub fn not_shared_reason(kind: &str, value: &str, roles: &[String], not_checked: &str) -> String {
    match kind {
        "endpoint" => {
            if let Some((ip, _)) = super::misp::split_endpoint(value)
                && let Ok(ip) = ip.parse::<IpAddr>()
            {
                if tor_stand_in(&ip) {
                    return "Tor gateway stand-in address; the name it stands for is the indicator"
                        .into();
                }
                if local_address(&ip) {
                    return "private address of the sandbox network".into();
                }
            }
        }
        "file" => {
            if value == "(no content kept)" || not_checked.contains("no content kept") {
                return "no content kept, so there is no hash to match".into();
            }
            let has = |role: &str| roles.iter().any(|r| r == role);
            if has("executed")
                && !(has("created") || has("written at close") || has("changed") || has("sample"))
            {
                return "a program of the base image the run started, not written by the run"
                    .into();
            }
        }
        _ => {}
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sandboxs_own_addresses_are_not_shared() {
        for value in [
            "198.18.0.1:20",
            "198.19.255.2:443",
            "192.168.1.10:53",
            "10.0.2.2:67",
        ] {
            assert!(
                !not_shared_reason("endpoint", value, &[], "").is_empty(),
                "{value}"
            );
        }
        for value in ["203.0.113.9:4444", "198.20.0.1:80", "[2001:db8::1]:443"] {
            assert!(
                not_shared_reason("endpoint", value, &[], "").is_empty(),
                "{value}"
            );
        }
    }

    #[test]
    fn executed_base_programs_and_empty_files_are_not_shared() {
        let roles = |names: &[&str]| names.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        assert!(!not_shared_reason("file", "ab", &roles(&["executed"]), "").is_empty());
        assert!(not_shared_reason("file", "ab", &roles(&["created", "executed"]), "").is_empty());
        assert!(not_shared_reason("file", "(no content kept)", &[], "no content kept").len() > 5);
        assert!(not_shared_reason("domain", "mircd.xiao.my.id", &[], "").is_empty());
    }
}

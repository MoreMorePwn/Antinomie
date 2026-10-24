// SPDX-License-Identifier: GPL-3.0-only
//! Network indicators in the text strings of a sample: `ip:port`, URLs and
//! domain names. A string is only a hint (the sample may never use it), so
//! these rows are marked as coming from "static" and a connection that never
//! happened reads "never contacted".
use super::kind::{self, Kind};
use std::net::IpAddr;

/// A network value found in a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    Endpoint(IpAddr, u16),
    Url(String),
    Domain(String),
}

/// File extensions that look like a top-level domain but are not one.
const NOT_TLDS: &[&str] = &[
    "so", "c", "h", "o", "a", "d", "py", "pl", "rb", "sh", "js", "txt", "log", "conf", "cfg",
    "ini", "bin", "dat", "tmp", "lib", "dll", "exe", "dylib", "ko", "rs", "go", "cc", "cpp", "hpp",
    "md", "html", "htm", "css", "json", "xml", "yml", "yaml", "png", "jpg", "gif", "svg", "ttf",
    "gz", "xz", "bz2", "zip", "tar", "pid", "lock", "sock", "service", "desktop", "rules", "map",
    "pc", "la", "in", "s", "ld", "elf", "debug", "cache", "db", "sql", "pem", "crt", "key", "csr",
];

fn token_end(c: char) -> bool {
    !(c.is_ascii_alphanumeric()
        || matches!(
            c,
            '.' | '-'
                | '_'
                | ':'
                | '/'
                | '?'
                | '='
                | '&'
                | '%'
                | '~'
                | '+'
                | '@'
                | '#'
                | '['
                | ']'
                | ','
        ))
}

/// What `text` names, at most `limit` values, without repeats.
pub fn scan(text: &str, limit: usize) -> Vec<Found> {
    let mut out: Vec<Found> = Vec::new();
    let mut push = |found: Found| {
        if out.len() < limit && !out.contains(&found) {
            out.push(found);
        }
    };
    for raw in text.split(token_end) {
        let token = raw.trim_matches(|c: char| matches!(c, '.' | ',' | ':' | '-' | '_' | '/'));
        if token.len() < 4 || token.len() > 2048 {
            continue;
        }
        let lower = token.to_ascii_lowercase();
        if (lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ftp://"))
            && let Some(parts) = kind::url_parts(token)
            && !parts.host.contains('%')
            && (parts.address().is_some() || Kind::Domain.normalize(&parts.host).is_some())
        {
            push(Found::Url(token.to_owned()));
            continue;
        }
        if let Some((host, port)) = token.rsplit_once(':')
            && let (Ok(ip), Ok(port)) = (
                host.trim_matches(['[', ']']).parse::<IpAddr>(),
                port.parse::<u16>(),
            )
            && port != 0
        {
            push(Found::Endpoint(ip, port));
            continue;
        }
        if token.parse::<IpAddr>().is_ok() {
            continue;
        }
        let name = lower.trim_matches('.');
        if let Some(domain) = Kind::Domain.normalize(name) {
            let tld = domain.rsplit('.').next().unwrap_or("");
            let letters = tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic());
            if letters
                && !NOT_TLDS.contains(&tld)
                && !domain.contains('_')
                && domain.split('.').all(|label| {
                    !label.is_empty() && !label.starts_with('-') && !label.ends_with('-')
                })
            {
                push(Found::Domain(domain));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_values_are_found_and_file_names_are_not() {
        let text = "connect to 203.0.113.200:4444 now\n\
                    GET http://cdn.fastmirror.example/bin/x86_64/.kd HTTP/1.1\n\
                    c2.update-cdn.example\n\
                    libc.so.6 libm.so ld-linux-x86-64.so.2 /etc/ld.so.cache config.h main.c\n\
                    version 1.2.3 and 10.0.0.1 alone\n\
                    api.telemetry-check.invalid, again c2.update-cdn.example";
        let found = scan(text, 100);
        assert!(found.contains(&Found::Endpoint("203.0.113.200".parse().unwrap(), 4444)));
        assert!(found.contains(&Found::Url(
            "http://cdn.fastmirror.example/bin/x86_64/.kd".into()
        )));
        assert!(found.contains(&Found::Domain("c2.update-cdn.example".into())));
        assert!(found.contains(&Found::Domain("api.telemetry-check.invalid".into())));
        let domains: Vec<_> = found
            .iter()
            .filter(|f| matches!(f, Found::Domain(_)))
            .collect();
        assert_eq!(
            domains.len(),
            2,
            "libc.so.6, config.h and the like are not names: {found:?}"
        );
        assert!(
            !found
                .iter()
                .any(|f| matches!(f, Found::Endpoint(ip, _) if ip.to_string() == "10.0.0.1"))
        );
        assert_eq!(
            found
                .iter()
                .filter(|f| **f == Found::Domain("c2.update-cdn.example".into()))
                .count(),
            1
        );
    }

    #[test]
    fn the_result_is_bounded() {
        let text: String = (0..500).map(|n| format!("host{n}.example ")).collect();
        assert_eq!(scan(&text, 50).len(), 50);
    }

    #[test]
    fn ipv6_endpoints_and_odd_tokens_are_handled() {
        let found = scan("[2001:db8::1]:8080 http:// ://x :::: ....", 10);
        assert_eq!(
            found,
            [Found::Endpoint("2001:db8::1".parse().unwrap(), 8080)]
        );
    }
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Making indicators safe to read: `hxxp://example[.]com`, `203[.]0[.]113[.]5`.
//! HTML and PDF use it when the person asks; JSON, MISP and STIX keep raw
//! values. Only values the report marked as indicators are rewritten, plus a
//! URL scheme or a dotted IPv4 address found in free text. File hashes and
//! guest paths are never changed.
use super::IndicatorKind;

/// A scheme as it is defanged; `None` keeps it.
fn scheme(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        "http" => "hxxp",
        "https" => "hxxps",
        "ftp" => "fxp",
        "ftps" => "fxps",
        _ => return None,
    })
}

fn dots(text: &str) -> String {
    text.replace('.', "[.]")
}

/// A URL: scheme to `hxxp`, dots of the host to `[.]`, the rest as it is.
pub fn url(text: &str) -> String {
    let Some((name, rest)) = text.split_once("://") else {
        // No scheme: a host and maybe a path.
        let split = text.find(['/', '?', '#']).unwrap_or(text.len());
        return format!("{}{}", dots(&text[..split]), &text[split..]);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (host, tail) = rest.split_at(end);
    format!("{}://{}{tail}", scheme(name).unwrap_or(name), dots(host))
}

/// An IPv4 address or `host:port` endpoint: dots to `[.]`; an IPv6 address
/// has its colons put in brackets instead.
pub fn endpoint(text: &str) -> String {
    if text.matches(':').count() >= 2 && !text.contains('.') {
        return text.replace(':', "[:]");
    }
    dots(text)
}

/// A domain name.
pub fn domain(text: &str) -> String {
    dots(text)
}

/// `text` as the indicator `kind` it is.
pub fn indicator(kind: IndicatorKind, text: &str) -> String {
    match kind {
        IndicatorKind::Url => url(text),
        IndicatorKind::Domain => domain(text),
        IndicatorKind::Endpoint => endpoint(text),
        // A server name is a domain; a certificate or file hash is not changed.
        IndicatorKind::Tls => {
            if text.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                text.to_owned()
            } else {
                domain(text)
            }
        }
        IndicatorKind::File => text.to_owned(),
    }
}

/// Free text: every `scheme://host` and dotted IPv4 address defanged.
pub fn text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        let rest = &text[at..];
        if let Some(found) = url_at(rest) {
            out.push_str(&url(&rest[..found]));
            at += found;
        } else if let Some(found) = ipv4_at(text, at) {
            out.push_str(&dots(&text[at..at + found]));
            at += found;
        } else {
            let c = rest.chars().next().unwrap_or(' ');
            out.push(c);
            at += c.len_utf8();
        }
    }
    out
}

/// The length of a URL starting at the head of `rest`, when it starts with a
/// scheme this module knows and `://`.
fn url_at(rest: &str) -> Option<usize> {
    let (name, tail) = rest.split_once("://")?;
    scheme(name)?;
    let end = tail
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '<' | '>' | ')' | ','))
        .unwrap_or(tail.len());
    Some(name.len() + 3 + end)
}

/// The length of a dotted IPv4 address starting at `at` (not inside a longer
/// number or word), when there is one.
fn ipv4_at(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'.') {
        return None;
    }
    let mut end = at;
    let mut groups = 0;
    loop {
        let start = end;
        while end < bytes.len() && bytes[end].is_ascii_digit() && end - start < 3 {
            end += 1;
        }
        if end == start || text[start..end].parse::<u16>().ok()? > 255 {
            return None;
        }
        groups += 1;
        if groups == 4 {
            break;
        }
        if end >= bytes.len() || bytes[end] != b'.' {
            return None;
        }
        end += 1;
    }
    if end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'.') {
        // `1.2.3.4.5` or `1.2.3.45x` is not an address.
        if bytes[end] != b'.' || bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
            return None;
        }
    }
    Some(end - at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_endpoints_and_domains_are_defanged() {
        assert_eq!(
            url("http://evil.example.com/a.b?x=1.2"),
            "hxxp://evil[.]example[.]com/a.b?x=1.2"
        );
        assert_eq!(
            url("https://203.0.113.5:8443/p"),
            "hxxps://203[.]0[.]113[.]5:8443/p"
        );
        assert_eq!(url("evil.example/x.php"), "evil[.]example/x.php");
        assert_eq!(endpoint("203.0.113.5:443"), "203[.]0[.]113[.]5:443");
        assert_eq!(endpoint("2001:db8::1"), "2001[:]db8[:][:]1");
        assert_eq!(domain("a.b.example"), "a[.]b[.]example");
        assert_eq!(
            indicator(IndicatorKind::Tls, "ab:cd:ef"),
            "ab:cd:ef",
            "a hash stays"
        );
        assert_eq!(indicator(IndicatorKind::File, "/tmp/x.sh"), "/tmp/x.sh");
    }

    #[test]
    fn free_text_changes_urls_and_addresses_only() {
        assert_eq!(
            text("fetched http://a.example/x from 10.0.0.5, then /lib/libc.so.6 v1.2.3"),
            "fetched hxxp://a[.]example/x from 10[.]0[.]0[.]5, then /lib/libc.so.6 v1.2.3"
        );
        assert_eq!(text("version 1.2.3.4.5"), "version 1.2.3.4.5");
        assert_eq!(text("é http://é.example/"), "é hxxp://é[.]example/");
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! What an indicator is, and the one normal form of each kind. A dataset
//! record and a value seen in a run match only when their normal forms are
//! equal, so every comparison goes through these functions.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The kinds of value a dataset can list and a run can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// `1.2.3.4:443`, `[2001:db8::1]:443`.
    IpPort,
    Domain,
    Url,
    Sha256,
    Md5,
    Sha1,
    /// JA3 fingerprint (an MD5).
    Ja3,
    /// SHA-1 of a TLS certificate.
    CertSha1,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::IpPort,
        Kind::Domain,
        Kind::Url,
        Kind::Sha256,
        Kind::Md5,
        Kind::Sha1,
        Kind::Ja3,
        Kind::CertSha1,
    ];

    /// The name used in exports and in the false-positive list.
    pub fn id(self) -> &'static str {
        match self {
            Kind::IpPort => "ip:port",
            Kind::Domain => "domain",
            Kind::Url => "url",
            Kind::Sha256 => "sha256",
            Kind::Md5 => "md5",
            Kind::Sha1 => "sha1",
            Kind::Ja3 => "ja3",
            Kind::CertSha1 => "cert-sha1",
        }
    }

    pub fn from_id(id: &str) -> Option<Kind> {
        Kind::ALL.into_iter().find(|kind| kind.id() == id)
    }

    /// The normal form of `value` for this kind, or `None` when it cannot be one.
    pub fn normalize(self, value: &str) -> Option<String> {
        match self {
            Kind::IpPort => ip_port_text(value),
            Kind::Domain => domain(value),
            Kind::Url => url(value),
            Kind::Sha256 => hex(value, 64),
            Kind::Md5 | Kind::Ja3 => hex(value, 32),
            Kind::Sha1 | Kind::CertSha1 => hex(value, 40),
        }
    }
}

/// `ip:port` in normal form: IPv6 in brackets, no leading zeros.
pub fn ip_port(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("{ip}:{port}"),
        IpAddr::V6(ip) => format!("[{ip}]:{port}"),
    }
}

fn ip_port_text(value: &str) -> Option<String> {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        value.rsplit_once(':')?
    };
    let ip: IpAddr = host.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    Some(ip_port(ip, port))
}

/// Lower case, no trailing dot, letters, digits, `-`, `_` and dots only, with
/// at least one dot. An IP address is not a domain.
pub fn domain(value: &str) -> Option<String> {
    let name = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty()
        || name.len() > 253
        || !name.contains('.')
        || name.parse::<IpAddr>().is_ok()
        || name.starts_with('.')
        || name.contains("..")
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return None;
    }
    Some(name)
}

fn hex(value: &str, len: usize) -> Option<String> {
    let value = value.trim();
    (value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| value.to_ascii_lowercase())
}

/// The parts of a URL that matter for matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UrlParts {
    pub scheme: String,
    /// Lower case host; an IPv6 address without brackets.
    pub host: String,
    pub port: Option<u16>,
    /// Path and query, starting with `/`.
    pub path: String,
}

/// Split a URL. A URL without a scheme is taken as `http`.
pub fn url_parts(text: &str) -> Option<UrlParts> {
    let text = text.trim();
    if text.is_empty() || text.chars().any(|c| c.is_control() || c == ' ') {
        return None;
    }
    let (scheme, rest) = match text.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("http".to_owned(), text),
    };
    if !matches!(scheme.as_str(), "http" | "https" | "ftp") {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or("");
    let (authority, path) = match rest.find(['/', '?']) {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit('@').next().unwrap_or("");
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host.to_owned(), rest.strip_prefix(':').map(str::to_owned))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port.to_owned())),
            None => (authority.to_owned(), None),
        }
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let port = match port {
        Some(port) if port.is_empty() => None,
        Some(port) => Some(port.parse::<u16>().ok()?),
        None => None,
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path.to_owned()
    };
    Some(UrlParts {
        scheme,
        host,
        port,
        path,
    })
}

fn default_port(scheme: &str) -> u16 {
    match scheme {
        "https" => 443,
        "ftp" => 21,
        _ => 80,
    }
}

impl UrlParts {
    /// The port the URL reaches.
    pub fn effective_port(&self) -> u16 {
        self.port.unwrap_or_else(|| default_port(&self.scheme))
    }

    /// `host[:port]/path`: no scheme (HTTP and HTTPS reports of one URL are
    /// the same indicator), no default port, no fragment.
    pub fn canonical(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let port = match self.port {
            Some(port) if port != 80 && port != 443 => format!(":{port}"),
            _ => String::new(),
        };
        format!("{host}{port}{}", self.path)
    }

    /// The host as an address, when it is one.
    pub fn address(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }
}

fn url(value: &str) -> Option<String> {
    url_parts(value).map(|parts| parts.canonical())
}

/// SHA-1 of the first certificate in TShark's `tls.handshake.certificate`
/// (hexadecimal DER, with or without colons; several certificates are
/// separated by the unit separator), as lowercase hex.
pub fn certificate_sha1(field: &str) -> Option<String> {
    use sha1::{Digest, Sha1};
    let first = field.split('\u{1f}').next()?.trim();
    let digits: Vec<u8> = first.bytes().filter(|b| *b != b':').collect();
    if digits.len() < 2
        || !digits.len().is_multiple_of(2)
        || !digits.iter().all(u8::is_ascii_hexdigit)
    {
        return None;
    }
    let der: Vec<u8> = digits
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
            let low = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
            high << 4 | low
        })
        .collect();
    Some(format!("{:x}", Sha1::digest(&der)))
}

/// Whether `ip` can never be listed by a public feed: private, loopback,
/// link-local, multicast, unspecified or broadcast. Documentation ranges
/// count as public so examples and fixtures stay checkable.
pub fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_unspecified()
                || ip.is_broadcast()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
        }
    }
}

/// Whether a name is local to the guest or the network and so can never
/// appear in a public feed.
pub fn local_name(name: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    !name.contains('.')
        || [
            "local",
            "localdomain",
            "lan",
            "internal",
            "home",
            "localhost",
            "arpa",
        ]
        .iter()
        .any(|suffix| name.rsplit('.').next() == Some(*suffix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_have_one_normal_form() {
        assert_eq!(
            Kind::IpPort.normalize("[2001:db8:0::1]:443").as_deref(),
            Some("[2001:db8::1]:443")
        );
        assert_eq!(
            Kind::IpPort.normalize("203.0.113.45:443").as_deref(),
            Some("203.0.113.45:443")
        );
        assert_eq!(Kind::IpPort.normalize("203.0.113.45"), None);
        assert_eq!(
            Kind::Domain.normalize("C2.Update-CDN.example.").as_deref(),
            Some("c2.update-cdn.example")
        );
        assert_eq!(Kind::Domain.normalize("203.0.113.45"), None);
        assert_eq!(Kind::Domain.normalize("localhost"), None);
        let sha1 = "2F22765D04931A078909145CA628D2264C852D7D";
        assert_eq!(
            Kind::CertSha1.normalize(sha1).as_deref(),
            Some(&sha1.to_lowercase()[..])
        );
        assert_eq!(Kind::Md5.normalize(sha1), None);
        for kind in Kind::ALL {
            assert_eq!(Kind::from_id(kind.id()), Some(kind));
        }
    }

    #[test]
    fn urls_compare_without_scheme_default_port_or_fragment() {
        let a = Kind::Url.normalize("http://CDN.FastMirror.example:80/bin/x86_64/.kd#frag");
        let b = Kind::Url.normalize("https://cdn.fastmirror.example/bin/x86_64/.kd");
        let c = Kind::Url.normalize("cdn.fastmirror.example/bin/x86_64/.kd");
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a.as_deref(), Some("cdn.fastmirror.example/bin/x86_64/.kd"));
        assert_eq!(
            Kind::Url
                .normalize("http://198.51.100.77:8080/a?b=1")
                .as_deref(),
            Some("198.51.100.77:8080/a?b=1")
        );
        assert_eq!(
            Kind::Url.normalize("http://host.example").as_deref(),
            Some("host.example/")
        );
        assert_eq!(Kind::Url.normalize("gopher://x/"), None);
        let parts = url_parts("http://198.51.100.77/bins/arm.sh").unwrap();
        assert_eq!(parts.effective_port(), 80);
        assert!(parts.address().is_some());
    }

    #[test]
    fn a_certificate_field_gives_the_sha1_of_the_first_certificate() {
        // SHA-1 of the three bytes 0x61 0x62 0x63 ("abc").
        let expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
        assert_eq!(certificate_sha1("616263").as_deref(), Some(expected));
        assert_eq!(
            certificate_sha1("61:62:63\u{1f}ffff").as_deref(),
            Some(expected)
        );
        assert_eq!(certificate_sha1(""), None);
        assert_eq!(certificate_sha1("6162z3"), None);
        assert_eq!(certificate_sha1("616"), None);
    }

    #[test]
    fn private_and_local_values_are_told_apart() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        for private in [
            "10.0.2.15",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "fe80::1",
            "fd00::1",
            "ff02::1",
        ] {
            assert!(private_address(ip(private)), "{private}");
        }
        // Documentation ranges stand for public addresses.
        for public in ["203.0.113.45", "198.51.100.77", "192.0.2.53", "8.8.8.8"] {
            assert!(!private_address(ip(public)), "{public}");
        }
        assert!(local_name("printer"));
        assert!(local_name("host.local"));
        assert!(local_name("gateway.lan."));
        assert!(!local_name("c2.update-cdn.example"));
    }
}

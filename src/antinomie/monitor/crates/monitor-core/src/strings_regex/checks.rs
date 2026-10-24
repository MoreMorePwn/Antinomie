// SPDX-License-Identifier: GPL-3.0-only
//! What a match must pass to be kept: the validators that cut the false
//! positives of the plain patterns.
use sha2::{Digest, Sha256};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    ops::Range,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Check {
    /// The pattern is the whole test.
    None,
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Email,
    Btc,
    Bech32,
    Eth,
    Xmr,
    Tox,
    Telegram,
    Jwt,
    SshKey,
    /// Run through the decoder rather than kept as it is.
    Base64,
    Hex,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Verdict {
    /// Characters of the match to leave out, at its start and its end.
    pub trim_start: usize,
    pub trim_end: usize,
    /// Added to the type: "private", "https".
    pub detail: Option<String>,
    pub note: String,
}

impl Verdict {
    fn detail(detail: impl Into<String>) -> Self {
        Self {
            detail: Some(detail.into()),
            ..Self::default()
        }
    }
}

/// Look at the match `range` of `text`; None drops it.
pub(super) fn run(check: Check, text: &str, range: Range<usize>) -> Option<Verdict> {
    let found = &text[range.clone()];
    match check {
        Check::None | Check::Base64 | Check::Hex => Some(Verdict::default()),
        Check::Ipv4 => ipv4(text, range),
        Check::Ipv6 => ipv6(text, range),
        Check::Domain => domain(text, range),
        Check::Url => url(found),
        Check::Email => email(found),
        Check::Btc => btc(found),
        Check::Bech32 => bech32(found),
        Check::Eth => eth(found),
        Check::Xmr => xmr(found),
        Check::Tox => tox(found),
        Check::Telegram => telegram(found),
        Check::Jwt => jwt(found),
        Check::SshKey => ssh_key(found),
    }
}

fn before(text: &str, range: &Range<usize>) -> Option<char> {
    text[..range.start].chars().next_back()
}

fn after(text: &str, range: &Range<usize>) -> Option<char> {
    text[range.end..].chars().next()
}

/// File name extensions that are also top-level domains. `libc.so`,
/// `install.sh` and `run.py` are files, not hosts, unless a scheme or an
/// `@` says otherwise.
const FILE_LIKE_TLDS: [&str; 14] = [
    "so", "sh", "py", "pl", "pm", "rs", "md", "cc", "ml", "ps", "zip", "mov", "run", "lib",
];

/// A host name whose last label is a known public suffix. `explicit` is true
/// where the text itself says it is a host (a URL or an address).
fn host_name(host: &str, explicit: bool) -> Option<()> {
    if host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return None;
    }
    let lower = host.to_ascii_lowercase();
    // Identifiers such as `strings.Builder` or `os.Exit` are not host names;
    // real ones are all lower or all upper case.
    if host != lower && host != host.to_ascii_uppercase() {
        return None;
    }
    let labels: Vec<_> = lower.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    let tld = *labels.last()?;
    if tld.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !explicit && FILE_LIKE_TLDS.contains(&tld) {
        return None;
    }
    let suffix = psl::suffix(lower.as_bytes())?;
    // A name that is only a suffix (`co.uk`) has no registrable part.
    (suffix.is_known() && psl::domain(lower.as_bytes()).is_some()).then_some(())
}

fn domain(text: &str, range: Range<usize>) -> Option<Verdict> {
    // Part of a longer path, name or number: `a/b.c.d`, `x_y.com`, `1.2.com`.
    if before(text, &range)
        .is_some_and(|c| c == '.' || c == '_' || c == '/' || c == '\\' || c == '@')
        || after(text, &range).is_some_and(|c| c == '_' || c == '@')
    {
        return None;
    }
    host_name(&text[range], false).map(|()| Verdict::default())
}

fn ipv4(text: &str, range: Range<usize>) -> Option<Verdict> {
    let found = &text[range.clone()];
    let mut octets = [0u8; 4];
    for (slot, part) in found.split('.').enumerate() {
        if slot > 3 || part.len() > 3 || (part.len() > 1 && part.starts_with('0')) {
            return None;
        }
        octets[slot] = part.parse().ok()?;
    }
    let ip = Ipv4Addr::from(octets);
    // Longer dotted numbers (1.2.3.4.5) and version numbers.
    if before(text, &range).is_some_and(|c| c.is_ascii_digit() || c == '.')
        || after(text, &range).is_some_and(|c| c.is_ascii_digit())
    {
        return None;
    }
    let tail = &text[range.end..];
    if tail.starts_with('.')
        && tail[1..]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        || tail.starts_with("-")
            && tail[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic())
        || tail.starts_with('_')
    {
        return None;
    }
    // The word before the number: "v1.2.3.4", "version 1.2.3.4".
    let head = text[..range.start].to_ascii_lowercase();
    let word = head
        .trim_end_matches([' ', '=', ':', '/', '-', '_'])
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .unwrap_or("");
    if matches!(
        word,
        "v" | "version" | "ver" | "release" | "rev" | "openssl" | "glibc" | "gcc" | "build"
    ) {
        return None;
    }
    if octets[0] == 0 && !ip.is_unspecified() {
        return None;
    }
    let class = ipv4_class(ip);
    Some(Verdict::detail(class))
}

/// What kind of address `ip` is.
pub(super) fn ipv4_class(ip: Ipv4Addr) -> &'static str {
    let octets = ip.octets();
    if ip.is_unspecified() {
        "unspecified"
    } else if ip.is_loopback() {
        "loopback"
    } else if ip.is_private() {
        "private"
    } else if ip.is_link_local() {
        "link-local"
    } else if ip.is_multicast() {
        "multicast"
    } else if ip.is_broadcast() || octets[0] >= 240 {
        "reserved"
    } else if matches!(
        octets,
        [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
    ) {
        "documentation"
    } else {
        "public"
    }
}

fn ipv6(text: &str, range: Range<usize>) -> Option<Verdict> {
    // The pattern takes any run of hex digits, colons and dots; the end of
    // a sentence or a trailing colon is not part of the address.
    let mut found = &text[range.clone()];
    let mut trim_end = 0;
    while found.ends_with(['.', ':']) && !found.ends_with("::") {
        found = &found[..found.len() - 1];
        trim_end += 1;
    }
    let range = range.start..range.end - trim_end;
    if before(text, &range).is_some_and(|c| c.is_ascii_alphanumeric() || c == ':')
        || after(text, &range).is_some_and(|c| c.is_ascii_alphanumeric() || c == ':')
    {
        return None;
    }
    let ip: Ipv6Addr = found.parse().ok()?;
    let segments = found.split(':').filter(|part| !part.is_empty()).count();
    // `ab::cd` in C++ code, `::` alone, 12:34:56 times.
    let wordlike = found
        .split(':')
        .filter(|part| !part.is_empty())
        .all(|part| part.bytes().all(|byte| byte.is_ascii_alphabetic()));
    if found == "::" || (segments <= 2 && wordlike && !ip.is_loopback()) {
        return None;
    }
    let class = if ip.is_loopback() {
        "loopback"
    } else if ip.is_unspecified() {
        return None;
    } else if ip.is_multicast() {
        "multicast"
    } else if (ip.segments()[0] & 0xfe00) == 0xfc00 {
        "unique local"
    } else if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        "link-local"
    } else if ip.to_ipv4_mapped().is_some() {
        "IPv4-mapped"
    } else {
        "global"
    };
    Some(Verdict {
        trim_end,
        ..Verdict::detail(class)
    })
}

fn url(found: &str) -> Option<Verdict> {
    // Closing punctuation after the address belongs to the sentence.
    let trimmed = found.trim_end_matches(['.', ',', ';', ':', ')', ']', '!', '?']);
    let trim_end = found.len() - trimmed.len();
    let (scheme, rest) = trimmed.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    if host.is_empty()
        || host
            .bytes()
            .any(|b| matches!(b, b'%' | b'$' | b'*' | b'{' | b'<'))
    {
        return None;
    }
    let host_only = if let Some(bracketed) = host.strip_prefix('[') {
        let inner = bracketed.split(']').next()?;
        inner.parse::<Ipv6Addr>().ok()?;
        inner
    } else {
        host.rsplit_once(':')
            .filter(|(_, port)| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
            .map_or(host, |(name, _)| name)
    };
    let valid = host_only.parse::<Ipv6Addr>().is_ok()
        || host_only
            .parse::<Ipv4Addr>()
            .is_ok_and(|ip| !ip.is_unspecified() || scheme.eq_ignore_ascii_case("tcp"))
        || host_only.eq_ignore_ascii_case("localhost")
        || host_name(host_only, true).is_some();
    valid.then(|| Verdict {
        trim_end,
        ..Verdict::detail(scheme.to_ascii_lowercase())
    })
}

fn email(found: &str) -> Option<Verdict> {
    let (local, host) = found.rsplit_once('@')?;
    (!local.is_empty()
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && host_name(host, true).is_some())
    .then(Verdict::default)
}

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The octets of a base58 number, or None for a character outside the alphabet.
fn base58(text: &str) -> Option<Vec<u8>> {
    let mut number: Vec<u8> = Vec::new();
    for byte in text.bytes() {
        let mut carry = BASE58.iter().position(|c| *c == byte)? as u32;
        for digit in number.iter_mut() {
            carry += u32::from(*digit) * 58;
            *digit = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            number.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let zeros = text.bytes().take_while(|byte| *byte == b'1').count();
    number.extend(std::iter::repeat_n(0, zeros));
    number.reverse();
    Some(number)
}

fn btc(found: &str) -> Option<Verdict> {
    let decoded = base58(found)?;
    if decoded.len() != 25 || !matches!(decoded[0], 0x00 | 0x05) {
        return None;
    }
    let digest = Sha256::digest(Sha256::digest(&decoded[..21]));
    (digest[..4] == decoded[21..])
        .then(|| Verdict::detail(if decoded[0] == 0 { "P2PKH" } else { "P2SH" }))
}

const BECH32_CHARS: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn bech32_polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let mut checksum = 1u32;
    for value in values {
        let top = checksum >> 25;
        checksum = ((checksum & 0x1ffffff) << 5) ^ u32::from(*value);
        for (bit, generator) in GENERATOR.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                checksum ^= generator;
            }
        }
    }
    checksum
}

fn bech32(found: &str) -> Option<Verdict> {
    let (prefix, data) = found.split_at(found.rfind('1')?);
    let data = &data[1..];
    if data.len() < 7 || !matches!(prefix, "bc" | "tb") {
        return None;
    }
    let mut values: Vec<u8> = prefix.bytes().map(|b| b >> 5).collect();
    values.push(0);
    values.extend(prefix.bytes().map(|b| b & 31));
    for byte in data.bytes() {
        values.push(BECH32_CHARS.iter().position(|c| *c == byte)? as u8);
    }
    match bech32_polymod(&values) {
        1 => Some(Verdict::detail("bech32")),
        0x2bc830a3 => Some(Verdict::detail("bech32m")),
        _ => None,
    }
}

fn eth(found: &str) -> Option<Verdict> {
    let digits = &found[2..];
    let mut distinct = digits.to_ascii_lowercase().into_bytes();
    distinct.sort_unstable();
    distinct.dedup();
    // 0x0000…, 0xffff… and the like are placeholders and masks.
    (distinct.len() >= 6).then(Verdict::default)
}

/// Monero base58 takes eleven characters for each eight octets.
fn xmr(found: &str) -> Option<Verdict> {
    if found.len() != 95 && found.len() != 106 {
        return None;
    }
    let mut octets = 0usize;
    for block in found.as_bytes().chunks(11) {
        let mut value: u128 = 0;
        for byte in block {
            value = value * 58 + BASE58.iter().position(|c| c == byte)? as u128;
        }
        let size = match block.len() {
            11 => 8,
            7 => 5,
            _ => return None,
        };
        if value >= 1u128 << (size * 8) {
            return None;
        }
        octets += size;
    }
    let kind = match found.as_bytes()[0] {
        b'4' => "standard",
        b'8' => "subaddress",
        _ => return None,
    };
    (octets >= 69).then_some(Verdict {
        note: "the checksum is not verified".into(),
        ..Verdict::detail(kind)
    })
}

/// A Tox ID is a public key, a nospam value and a two-octet checksum: the
/// exclusive or of the first 36 octets taken two at a time.
fn tox(found: &str) -> Option<Verdict> {
    let mut octets = Vec::with_capacity(38);
    for pair in found.as_bytes().chunks(2) {
        octets.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
    }
    let mut checksum = [0u8; 2];
    for (index, octet) in octets[..36].iter().enumerate() {
        checksum[index % 2] ^= octet;
    }
    (checksum == octets[36..38]).then(Verdict::default)
}

fn telegram(found: &str) -> Option<Verdict> {
    let (_, secret) = found.split_once(':')?;
    let first = secret.as_bytes()[0];
    (!secret.bytes().all(|byte| byte == first)).then(Verdict::default)
}

fn base64url(text: &str) -> Option<Vec<u8>> {
    super::encoded::base64_decode(text, 4096)
}

fn jwt(found: &str) -> Option<Verdict> {
    let header = base64url(found.split('.').next()?)?;
    let header: serde_json::Value = serde_json::from_slice(&header).ok()?;
    header.get("alg")?.as_str().map(Verdict::detail)
}

fn ssh_key(found: &str) -> Option<Verdict> {
    let (kind, blob) = found.split_once(char::is_whitespace)?;
    let blob = super::encoded::base64_decode(blob.trim_start(), 16384)?;
    let length = u32::from_be_bytes(blob.get(..4)?.try_into().ok()?) as usize;
    (blob.get(4..4 + length)? == kind.as_bytes()).then(|| Verdict::detail(kind))
}

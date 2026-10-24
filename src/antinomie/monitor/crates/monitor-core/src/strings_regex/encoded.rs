// SPDX-License-Identifier: GPL-3.0-only
//! Base64 and hex runs that decode to text or to a known file type, so the
//! text can be scanned again.
use super::checks::Check;

/// Longest run decoded, in characters.
const RUN_MAX_LEN: usize = 16384;
/// Longest preview of the decoded octets, in characters.
const PREVIEW_MAX_LEN: usize = 120;

pub(super) struct Decoded {
    /// "base64" or "hex".
    pub how: &'static str,
    /// "text", "ELF", "gzip"…
    pub what: &'static str,
    /// The decoded text, when it is text.
    pub text: Option<String>,
    pub preview: String,
}

const MAGIC: [(&[u8], &str); 8] = [
    (b"\x7fELF", "ELF"),
    (b"PK\x03\x04", "ZIP"),
    (b"\x1f\x8b", "gzip"),
    (b"MZ", "PE"),
    (b"#!", "script"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\0", "xz"),
    (b"!<arch>", "ar archive"),
];

pub(super) fn decode(check: Check, run: &str) -> Option<Decoded> {
    if run.len() > RUN_MAX_LEN {
        return None;
    }
    let (how, octets) = match check {
        Check::Base64 => ("base64", base64_decode(run, RUN_MAX_LEN)?),
        Check::Hex => ("hex", hex_decode(run)?),
        _ => return None,
    };
    if octets.len() < 8 {
        return None;
    }
    if let Some((_, what)) = MAGIC.iter().find(|(magic, _)| octets.starts_with(magic)) {
        // `#!` is a script, which is also text worth scanning.
        let text = (*what == "script").then(|| lossy(&octets));
        return Some(Decoded {
            how,
            what,
            text,
            preview: format!("{} octets of {what} data", octets.len()),
        });
    }
    let printable = octets
        .iter()
        .filter(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        .count();
    // Text, not a hash or a key: nearly all printable, and with a word in it.
    let letters = octets
        .iter()
        .filter(|byte| byte.is_ascii_alphabetic())
        .count();
    if printable * 100 < octets.len() * 90 || letters * 4 < octets.len() {
        return None;
    }
    let text = lossy(&octets);
    Some(Decoded {
        how,
        what: "text",
        preview: text.chars().take(PREVIEW_MAX_LEN).collect(),
        text: Some(text),
    })
}

fn lossy(octets: &[u8]) -> String {
    octets
        .iter()
        .map(|&byte| {
            if byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                byte as char
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

fn hex_decode(run: &str) -> Option<Vec<u8>> {
    if !run.len().is_multiple_of(2) {
        return None;
    }
    run.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

/// Standard or URL-safe base64, with or without padding; None for anything
/// else, for a mix of both alphabets and for more than `max` characters.
pub(super) fn base64_decode(text: &str, max: usize) -> Option<Vec<u8>> {
    let text = text.trim_end_matches('=');
    if text.len() > max || text.len() % 4 == 1 {
        return None;
    }
    let standard = text.bytes().any(|byte| matches!(byte, b'+' | b'/'));
    let url = text.bytes().any(|byte| matches!(byte, b'-' | b'_'));
    if standard && url {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        buffer = (buffer << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

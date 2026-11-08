// SPDX-License-Identifier: GPL-3.0-only
//! Strict standard Base64 (RFC 4648, `+/` and `=` padding) for the bytes of
//! `upload.put` and of an artifact range on the local socket (design 5.9). No
//! whitespace, no URL alphabet, padding required, non-zero trailing bits
//! refused: one text for one byte string. The decoder stops before it
//! allocates more than `max` bytes.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Why a text is not Base64.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The length is not a multiple of four.
    Length,
    /// A byte outside the alphabet, or padding in the wrong place.
    Symbol(usize),
    /// Bits after the last byte are not zero.
    Trailing,
    /// More than `max` bytes would result.
    TooLarge,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Length => f.write_str("the length is not a multiple of 4"),
            Self::Symbol(at) => write!(f, "not Base64 at byte {at}"),
            Self::Trailing => f.write_str("non-zero bits after the last byte"),
            Self::TooLarge => f.write_str("the data is too large"),
        }
    }
}

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn value(symbol: u8) -> Option<u32> {
    Some(match symbol {
        b'A'..=b'Z' => symbol - b'A',
        b'a'..=b'z' => symbol - b'a' + 26,
        b'0'..=b'9' => symbol - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    } as u32)
}

/// Decode `text`, refusing anything [`encode`] would not have written.
pub fn decode(text: &[u8], max: usize) -> Result<Vec<u8>, DecodeError> {
    if !text.len().is_multiple_of(4) {
        return Err(DecodeError::Length);
    }
    let pad = text.iter().rev().take_while(|&&b| b == b'=').count();
    if pad > 2 {
        return Err(DecodeError::Symbol(text.len() - pad));
    }
    let size = text.len() / 4 * 3 - pad;
    if size > max {
        return Err(DecodeError::TooLarge);
    }
    let mut out = Vec::with_capacity(size);
    for (index, chunk) in text.chunks(4).enumerate() {
        let last = (index + 1) * 4 == text.len();
        let used = if last { 4 - pad } else { 4 };
        let mut n = 0u32;
        for (i, &symbol) in chunk.iter().enumerate() {
            let v = if i < used {
                value(symbol).ok_or(DecodeError::Symbol(index * 4 + i))?
            } else {
                0
            };
            n |= v << (18 - 6 * i);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let keep = used - 1;
        if bytes[keep..].iter().any(|&b| b != 0) && keep < 3 {
            return Err(DecodeError::Trailing);
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_4648_vectors_round_trip() {
        let vectors = [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ];
        for (plain, coded) in vectors {
            assert_eq!(encode(plain.as_bytes()), coded);
            assert_eq!(decode(coded.as_bytes(), 64).unwrap(), plain.as_bytes());
        }
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(encode(&all).as_bytes(), 256).unwrap(), all);
    }

    #[test]
    fn anything_the_encoder_would_not_write_is_refused() {
        assert_eq!(decode(b"Zm9", 64), Err(DecodeError::Length));
        assert_eq!(decode(b"Zm 9", 64), Err(DecodeError::Symbol(2)));
        assert_eq!(decode(b"Zm9-", 64), Err(DecodeError::Symbol(3)));
        assert_eq!(decode(b"Z===", 64), Err(DecodeError::Symbol(1)));
        assert_eq!(decode(b"Zm=v", 64), Err(DecodeError::Symbol(2)));
        assert_eq!(decode(b"Zh==", 64), Err(DecodeError::Trailing));
        assert_eq!(decode(b"Zm9=Zm9v", 64), Err(DecodeError::Symbol(3)));
        assert_eq!(decode(b"Zm9vYmFy", 5), Err(DecodeError::TooLarge));
        assert_eq!(decode(b"Zm9vYmFy", 6).unwrap(), b"foobar");
    }
}

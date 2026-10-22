// SPDX-License-Identifier: GPL-3.0-only
//! GDB Remote Serial Protocol framing: `$payload#xx` packets with `}` escaping
//! and run-length decoding, `%name:payload#xx` notifications, the acknowledgement
//! bytes and the interrupt byte. Pure functions and a byte-at-a-time parser, so
//! every case is unit-tested without a socket.

/// What the parser found in the byte stream.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Incoming {
    /// A well-formed packet's payload, escapes and run lengths removed.
    Packet(Vec<u8>),
    /// A packet whose checksum did not match: the client wants `-`.
    BadPacket,
    /// `+`
    Ack,
    /// `-`
    Nack,
    /// The interrupt byte (0x03) outside a packet.
    Interrupt,
}

#[derive(Default)]
pub(super) struct Framer {
    state: State,
    raw: Vec<u8>,
    sum: u8,
    high: u8,
}

#[derive(Default, PartialEq, Eq)]
enum State {
    #[default]
    Idle,
    Body,
    SumHigh,
    SumLow,
}

/// Packets are bounded: a client that never ends one is not allowed to grow
/// the buffer without limit.
const LIMIT: usize = 1 << 20;

impl Framer {
    /// Feed one byte; `Some` when it completed something.
    pub(super) fn feed(&mut self, byte: u8) -> Option<Incoming> {
        match self.state {
            State::Idle => match byte {
                b'$' => {
                    self.raw.clear();
                    self.sum = 0;
                    self.state = State::Body;
                    None
                }
                b'+' => Some(Incoming::Ack),
                b'-' => Some(Incoming::Nack),
                0x03 => Some(Incoming::Interrupt),
                _ => None,
            },
            State::Body => {
                if byte == b'#' {
                    self.state = State::SumHigh;
                } else if byte == b'$' {
                    // A new packet starts: the old one was cut short.
                    self.raw.clear();
                    self.sum = 0;
                } else if self.raw.len() < LIMIT {
                    self.raw.push(byte);
                    self.sum = self.sum.wrapping_add(byte);
                } else {
                    self.state = State::Idle;
                    return Some(Incoming::BadPacket);
                }
                None
            }
            State::SumHigh => {
                self.high = byte;
                self.state = State::SumLow;
                None
            }
            State::SumLow => {
                self.state = State::Idle;
                let wanted = hex_value(self.high)
                    .zip(hex_value(byte))
                    .map(|(high, low)| high << 4 | low);
                if wanted == Some(self.sum) {
                    Some(Incoming::Packet(decode(&self.raw)))
                } else {
                    Some(Incoming::BadPacket)
                }
            }
        }
    }
}

/// Remove run-length encoding (`x*n` repeats `x` by `n - 29` more) and `}`
/// escapes.
fn decode(raw: &[u8]) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(raw.len());
    let mut at = 0;
    while at < raw.len() {
        let byte = raw[at];
        if byte == b'*'
            && let (Some(last), Some(count)) = (expanded.last().copied(), raw.get(at + 1))
        {
            // The escape byte may itself be the repeated one: repeat the pair.
            let repeat = usize::from(count.saturating_sub(29));
            for _ in 0..repeat {
                expanded.push(last);
            }
            at += 2;
            continue;
        }
        expanded.push(byte);
        at += 1;
    }
    let mut out = Vec::with_capacity(expanded.len());
    let mut escaped = false;
    for byte in expanded {
        if escaped {
            out.push(byte ^ 0x20);
            escaped = false;
        } else if byte == b'}' {
            escaped = true;
        } else {
            out.push(byte);
        }
    }
    out
}

fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

/// `$payload#xx` for a reply; `}`, `#`, `$` and `*` are escaped.
pub(super) fn encode(payload: &[u8]) -> Vec<u8> {
    frame(b'$', b"", payload)
}

/// `%name:payload#xx`, an asynchronous notification.
pub(super) fn encode_notification(name: &str, payload: &[u8]) -> Vec<u8> {
    frame(b'%', name.as_bytes(), payload)
}

fn frame(start: u8, name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(name.len() + payload.len() + 1);
    if !name.is_empty() {
        body.extend_from_slice(name);
        body.push(b':');
    }
    for byte in payload {
        if matches!(byte, b'}' | b'#' | b'$' | b'*') {
            body.push(b'}');
            body.push(byte ^ 0x20);
        } else {
            body.push(*byte);
        }
    }
    let mut out = Vec::with_capacity(body.len() + 4);
    out.push(start);
    out.extend_from_slice(&body);
    out.push(b'#');
    out.extend_from_slice(format!("{:02x}", checksum(&body)).as_bytes());
    out
}

pub(super) fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(super) fn to_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(data.len() * 2);
    for byte in data {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

pub(super) fn from_hex(text: &[u8]) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    text.chunks(2)
        .map(|pair| Some(hex_value(pair[0])? << 4 | hex_value(pair[1])?))
        .collect()
}

/// A hexadecimal number from the whole of `text`.
pub(super) fn parse_hex(text: &[u8]) -> Option<u64> {
    if text.is_empty() || text.len() > 16 {
        return None;
    }
    text.iter().try_fold(0u64, |value, byte| {
        Some(value << 4 | u64::from(hex_value(*byte)?))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(framer: &mut Framer, bytes: &[u8]) -> Vec<Incoming> {
        bytes.iter().filter_map(|byte| framer.feed(*byte)).collect()
    }

    #[test]
    fn a_packet_is_framed_and_checked() {
        let mut framer = Framer::default();
        let found = feed_all(&mut framer, b"+$qSupported:multiprocess+#c6-\x03");
        assert_eq!(
            found,
            [
                Incoming::Ack,
                Incoming::Packet(b"qSupported:multiprocess+".to_vec()),
                Incoming::Nack,
                Incoming::Interrupt,
            ]
        );
        assert_eq!(
            feed_all(&mut framer, b"$g#00"),
            [Incoming::BadPacket],
            "a wrong checksum is reported"
        );
        assert_eq!(
            feed_all(&mut framer, b"$g#67"),
            [Incoming::Packet(b"g".to_vec())]
        );
    }

    #[test]
    fn escapes_and_run_lengths_are_removed() {
        // "X10,1:" then an escaped '#' (0x23 ^ 0x20 = 0x03) and a run of five zeros.
        let payload = b"X10,1:}\x03";
        let mut packet = vec![b'$'];
        packet.extend_from_slice(payload);
        packet.push(b'#');
        packet.extend_from_slice(format!("{:02x}", checksum(payload)).as_bytes());
        let mut framer = Framer::default();
        assert_eq!(
            feed_all(&mut framer, &packet),
            [Incoming::Packet(b"X10,1:#".to_vec())]
        );
        // 0* followed by '"' (0x22 = 34, 34 - 29 = 5 more zeros).
        let payload = b"0*\"";
        let mut packet = vec![b'$'];
        packet.extend_from_slice(payload);
        packet.push(b'#');
        packet.extend_from_slice(format!("{:02x}", checksum(payload)).as_bytes());
        assert_eq!(
            feed_all(&mut framer, &packet),
            [Incoming::Packet(b"000000".to_vec())]
        );
    }

    #[test]
    fn replies_escape_the_framing_bytes() {
        assert_eq!(encode(b"OK"), b"$OK#9a");
        let escaped = encode(b"a#b$c}d*e");
        let mut framer = Framer::default();
        assert_eq!(
            feed_all(&mut framer, &escaped),
            [Incoming::Packet(b"a#b$c}d*e".to_vec())],
            "what we send, a client reads back"
        );
        assert_eq!(
            encode_notification("Stop", b"T05"),
            format!("%Stop:T05#{:02x}", checksum(b"Stop:T05")).into_bytes()
        );
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(to_hex(&[0, 0xab, 0x7f]), "00ab7f");
        assert_eq!(from_hex(b"00AB7f"), Some(vec![0, 0xab, 0x7f]));
        assert_eq!(from_hex(b"0"), None);
        assert_eq!(from_hex(b"zz"), None);
        assert_eq!(parse_hex(b"1f"), Some(0x1f));
        assert_eq!(parse_hex(b""), None);
        assert_eq!(parse_hex(b"fffffffffffffffff"), None);
    }
}

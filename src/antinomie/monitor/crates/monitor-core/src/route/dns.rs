// SPDX-License-Identifier: GPL-3.0-only
//! The DNS messages the gateway understands: one question per query, answered
//! with A records, an empty answer or an error.
use std::net::Ipv4Addr;

pub const TYPE_A: u16 = 1;
#[cfg(test)]
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Lower case, without the final dot.
    pub name: String,
    pub qtype: u16,
    /// The query's header flags, for the recursion-desired bit.
    flags: u16,
    /// The question section as received, copied into the answer.
    question: Vec<u8>,
}

/// A single-question standard query, or `None` (a response, another opcode,
/// several questions, a compressed or malformed name).
pub fn parse_query(message: &[u8]) -> Option<Query> {
    if message.len() < 17 {
        return None;
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    let counts = |at: usize| u16::from_be_bytes([message[at], message[at + 1]]);
    if flags & 0x8000 != 0 || flags & 0x7800 != 0 || counts(4) != 1 || counts(6) != 0 {
        return None;
    }
    let mut at = 12;
    let mut name = String::new();
    loop {
        let len = usize::from(*message.get(at)?);
        at += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        let label = message.get(at..at + len)?;
        at += len;
        if !label
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'*')
        {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|&b| char::from(b.to_ascii_lowercase())));
        if name.len() > 253 {
            return None;
        }
    }
    let tail = message.get(at..at + 4)?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    if u16::from_be_bytes([tail[2], tail[3]]) != CLASS_IN {
        return None;
    }
    Some(Query {
        id: u16::from_be_bytes([message[0], message[1]]),
        name,
        qtype,
        flags,
        question: message[12..at + 4].to_vec(),
    })
}

fn header(query: &Query, rcode: u16, answers: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&query.id.to_be_bytes());
    // Response, recursion available, recursion desired as asked.
    let flags = 0x8000 | 0x0080 | (query.flags & 0x0100) | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query.question);
    out
}

/// An answer with these A records.
pub fn answer_a(query: &Query, addresses: &[Ipv4Addr], ttl: u32) -> Vec<u8> {
    let mut out = header(query, 0, addresses.len() as u16);
    for address in addresses {
        out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&[0, 4]);
        out.extend_from_slice(&address.octets());
    }
    out
}

/// "No data": the name exists, this record type has no answer.
pub fn answer_empty(query: &Query) -> Vec<u8> {
    header(query, 0, 0)
}

/// "No such name".
pub fn answer_nxdomain(query: &Query) -> Vec<u8> {
    header(query, 3, 0)
}

#[cfg(test)]
pub(super) fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = id.to_be_bytes().to_vec();
    out.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_names_are_folded_and_answered() {
        let query = parse_query(&build_query(0x1234, "Evil.Example.COM", TYPE_A)).unwrap();
        assert_eq!(
            (query.id, query.name.as_str()),
            (0x1234, "evil.example.com")
        );
        let answer = answer_a(&query, &[Ipv4Addr::new(198, 18, 0, 1)], 30);
        assert_eq!(&answer[0..2], &[0x12, 0x34]);
        assert_eq!(answer[2] & 0x81, 0x81);
        assert_eq!(&answer[6..8], &[0, 1]);
        assert_eq!(&answer[answer.len() - 4..], &[198, 18, 0, 1]);
        assert_eq!(answer_empty(&query)[3] & 15, 0);
        assert_eq!(answer_nxdomain(&query)[3] & 15, 3);
    }

    #[test]
    fn unusual_messages_are_refused() {
        let good = build_query(1, "a.b", TYPE_A);
        assert!(parse_query(&good).is_some());
        let mut response = good.clone();
        response[2] |= 0x80;
        assert!(parse_query(&response).is_none());
        let mut two = good.clone();
        two[5] = 2;
        assert!(parse_query(&two).is_none());
        let mut pointer = good.clone();
        pointer[12] = 0xc0;
        assert!(parse_query(&pointer).is_none());
        assert!(parse_query(&good[..good.len() - 1]).is_none());
        assert!(parse_query(&build_query(1, "bad name.example", TYPE_A)).is_none());
        let mut chaos = good;
        let end = chaos.len();
        chaos[end - 1] = 3;
        assert!(parse_query(&chaos).is_none());
    }
}

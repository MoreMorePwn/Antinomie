// SPDX-License-Identifier: GPL-3.0-only
//! Ethernet, ARP, IPv4, UDP and TCP frames, read with checked offsets and
//! built with correct checksums. Only what the route gateway needs: IPv6 and
//! IP fragments are not handled (the gateway counts and drops them).
use std::net::Ipv4Addr;

pub type Mac = [u8; 6];

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

/// The Ethernet payload limit the gateway builds frames for.
pub const MTU: usize = 1500;
/// Largest TCP payload in one segment (MTU - IPv4 - TCP headers).
pub const MSS: usize = MTU - 40;
pub const BROADCAST: Mac = [0xff; 6];

pub struct Eth<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

pub fn parse_eth(frame: &[u8]) -> Option<Eth<'_>> {
    if frame.len() < 14 {
        return None;
    }
    Some(Eth {
        dst: frame[0..6].try_into().ok()?,
        src: frame[6..12].try_into().ok()?,
        ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        payload: &frame[14..],
    })
}

pub struct Ipv4<'a> {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    /// Part of a fragmented datagram; the gateway does not reassemble.
    pub fragment: bool,
    pub payload: &'a [u8],
}

pub fn parse_ipv4(packet: &[u8]) -> Option<Ipv4<'_>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total < header_len || total > packet.len() {
        return None;
    }
    let fragment_field = u16::from_be_bytes([packet[6], packet[7]]);
    Some(Ipv4 {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        fragment: fragment_field & 0x3fff != 0,
        payload: &packet[header_len..total],
    })
}

pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// The MSS option of a SYN.
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

pub fn parse_tcp(segment: &[u8]) -> Option<Tcp<'_>> {
    if segment.len() < 20 {
        return None;
    }
    let header_len = usize::from(segment[12] >> 4) * 4;
    if header_len < 20 || header_len > segment.len() {
        return None;
    }
    let mut mss = None;
    let mut options = &segment[20..header_len];
    while let Some((&kind, rest)) = options.split_first() {
        match kind {
            0 => break,
            1 => options = rest,
            _ => {
                let len = usize::from(*rest.first()?);
                if len < 2 || len - 1 > rest.len() {
                    return None;
                }
                if kind == 2 && len == 4 {
                    mss = Some(u16::from_be_bytes([rest[1], rest[2]]));
                }
                options = &rest[len - 1..];
            }
        }
    }
    Some(Tcp {
        src_port: u16::from_be_bytes([segment[0], segment[1]]),
        dst_port: u16::from_be_bytes([segment[2], segment[3]]),
        seq: u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]),
        ack: u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]),
        flags: segment[13],
        window: u16::from_be_bytes([segment[14], segment[15]]),
        mss,
        payload: &segment[header_len..],
    })
}

pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

pub fn parse_udp(datagram: &[u8]) -> Option<Udp<'_>> {
    if datagram.len() < 8 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([datagram[4], datagram[5]]));
    if len < 8 || len > datagram.len() {
        return None;
    }
    Some(Udp {
        src_port: u16::from_be_bytes([datagram[0], datagram[1]]),
        dst_port: u16::from_be_bytes([datagram[2], datagram[3]]),
        payload: &datagram[8..len],
    })
}

/// The Internet checksum of `parts` taken as one byte string.
fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    let mut carry: Option<u8> = None;
    for part in parts {
        for &byte in *part {
            match carry.take() {
                Some(high) => sum += u32::from(u16::from_be_bytes([high, byte])),
                None => carry = Some(byte),
            }
        }
    }
    if let Some(high) = carry {
        sum += u32::from(u16::from_be_bytes([high, 0]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn build_eth(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    // Identification 0, "don't fragment", TTL 64.
    packet.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    let sum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, len: usize) -> [u8; 12] {
    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(&src.octets());
    header[4..8].copy_from_slice(&dst.octets());
    header[9] = protocol;
    header[10..12].copy_from_slice(&(len as u16).to_be_bytes());
    header
}

pub struct TcpOut<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub window: u16,
    /// Sent as an MSS option (SYN segments).
    pub mss: Option<u16>,
    pub payload: &'a [u8],
}

pub fn build_tcp(src: Ipv4Addr, dst: Ipv4Addr, out: &TcpOut) -> Vec<u8> {
    let header_len = if out.mss.is_some() { 24 } else { 20 };
    let mut segment = Vec::with_capacity(header_len + out.payload.len());
    segment.extend_from_slice(&out.src_port.to_be_bytes());
    segment.extend_from_slice(&out.dst_port.to_be_bytes());
    segment.extend_from_slice(&out.seq.to_be_bytes());
    segment.extend_from_slice(&out.ack.to_be_bytes());
    segment.push(((header_len / 4) as u8) << 4);
    segment.push(out.flags);
    segment.extend_from_slice(&out.window.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    if let Some(mss) = out.mss {
        segment.extend_from_slice(&[2, 4]);
        segment.extend_from_slice(&mss.to_be_bytes());
    }
    segment.extend_from_slice(out.payload);
    let pseudo = pseudo_header(src, dst, PROTO_TCP, segment.len());
    let sum = checksum(&[&pseudo, &segment]);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    segment
}

pub fn build_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&src_port.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    let pseudo = pseudo_header(src, dst, PROTO_UDP, datagram.len());
    let mut sum = checksum(&[&pseudo, &datagram]);
    if sum == 0 {
        sum = 0xffff;
    }
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    datagram
}

/// An ICMP echo reply for an echo request payload (`request` starts at the
/// ICMP header).
pub fn build_icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 8 || request[0] != 8 {
        return None;
    }
    let mut reply = request.to_vec();
    reply[0] = 0;
    reply[2..4].copy_from_slice(&[0, 0]);
    let sum = checksum(&[&reply]);
    reply[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(reply)
}

pub struct Arp {
    pub operation: u16,
    pub sender_mac: Mac,
    pub sender_ip: Ipv4Addr,
    pub target_ip: Ipv4Addr,
}

pub fn parse_arp(payload: &[u8]) -> Option<Arp> {
    // Ethernet/IPv4 only: hardware type 1, protocol 0x0800, sizes 6 and 4.
    if payload.len() < 28 || payload[0..6] != [0, 1, 8, 0, 6, 4] {
        return None;
    }
    Some(Arp {
        operation: u16::from_be_bytes([payload[6], payload[7]]),
        sender_mac: payload[8..14].try_into().ok()?,
        sender_ip: Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]),
        target_ip: Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]),
    })
}

/// An ARP reply saying that `ip` is at `mac`, to `to_mac`/`to_ip`.
pub fn build_arp_reply(mac: Mac, ip: Ipv4Addr, to_mac: Mac, to_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 2];
    arp.extend_from_slice(&mac);
    arp.extend_from_slice(&ip.octets());
    arp.extend_from_slice(&to_mac);
    arp.extend_from_slice(&to_ip.octets());
    build_eth(to_mac, mac, ETHERTYPE_ARP, &arp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_of_a_valid_header_is_zero() {
        let packet = build_ipv4(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            PROTO_UDP,
            b"abc",
        );
        assert_eq!(checksum(&[&packet[..20]]), 0);
        let parsed = parse_ipv4(&packet).unwrap();
        assert_eq!(parsed.payload, b"abc");
        assert!(!parsed.fragment);
    }

    #[test]
    fn tcp_round_trip_with_odd_payload_and_mss() {
        let (src, dst) = (Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(2, 2, 2, 2));
        let segment = build_tcp(
            src,
            dst,
            &TcpOut {
                src_port: 80,
                dst_port: 4000,
                seq: 7,
                ack: 9,
                flags: SYN | ACK,
                window: 1000,
                mss: Some(1460),
                payload: b"odd",
            },
        );
        let pseudo = pseudo_header(src, dst, PROTO_TCP, segment.len());
        assert_eq!(checksum(&[&pseudo, &segment]), 0);
        let parsed = parse_tcp(&segment).unwrap();
        assert_eq!(
            (parsed.seq, parsed.ack, parsed.mss, parsed.payload),
            (7, 9, Some(1460), &b"odd"[..])
        );
    }

    #[test]
    fn malformed_input_is_refused() {
        assert!(parse_eth(&[0; 13]).is_none());
        assert!(parse_ipv4(&[0x45; 10]).is_none());
        let mut packet = build_ipv4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 6, b"xx");
        packet[2..4].copy_from_slice(&200u16.to_be_bytes());
        assert!(parse_ipv4(&packet).is_none());
        // A TCP option that claims more bytes than the header holds.
        let mut segment = vec![0u8; 24];
        segment[12] = 6 << 4;
        segment[20..24].copy_from_slice(&[2, 9, 0, 0]);
        assert!(parse_tcp(&segment).is_none());
        assert!(parse_udp(&[0; 7]).is_none());
        assert!(parse_arp(&[0; 20]).is_none());
    }

    #[test]
    fn echo_reply_has_a_valid_checksum() {
        let mut request = vec![8, 0, 0, 0, 0, 1, 0, 1, 9, 9];
        let sum = checksum(&[&request]);
        request[2..4].copy_from_slice(&sum.to_be_bytes());
        let reply = build_icmp_echo_reply(&request).unwrap();
        assert_eq!(reply[0], 0);
        assert_eq!(checksum(&[&reply]), 0);
        assert!(build_icmp_echo_reply(&reply).is_none());
    }
}

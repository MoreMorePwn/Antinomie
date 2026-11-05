// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! A captured `struct sockaddr` as an address, by its family: `10.0.2.3:53`,
//! `[::1]:443`, `unix:/run/x.sock`, `netlink:NETLINK_ROUTE:pid=0,groups=RTMGRP_LINK`,
//! `packet:proto=ETH_P_ALL,ifindex=2,mac=52:54:00:12:34:56`,
//! `vsock:VMADDR_CID_HOST:1234`, `alg:hash/sha256`, `can:ifindex=3` and
//! `AF_UNSPEC` (the disconnect idiom). The layouts are the same on every ABI.
//! A family that is not decoded here is None and the views show its bytes.
use super::spec::{self, mac};
use super::{flags, named};
use crate::syscalls::scalars::{ETHERNET, NETLINK};

const ARPHRD: &[(&str, u64)] = &[
    ("ARPHRD_NETROM", 0),
    ("ARPHRD_ETHER", 1),
    ("ARPHRD_EETHER", 2),
    ("ARPHRD_AX25", 3),
    ("ARPHRD_IEEE802", 6),
    ("ARPHRD_PPP", 512),
    ("ARPHRD_RAWIP", 519),
    ("ARPHRD_TUNNEL", 768),
    ("ARPHRD_SIT", 776),
    ("ARPHRD_IPGRE", 778),
    ("ARPHRD_LOOPBACK", 772),
    ("ARPHRD_CAN", 280),
    ("ARPHRD_IEEE80211", 801),
    ("ARPHRD_IEEE80211_RADIOTAP", 803),
    ("ARPHRD_IEEE802154", 804),
    ("ARPHRD_NONE", 0xfffe),
    ("ARPHRD_VOID", 0xffff),
];

const PACKET_TYPES: &[(&str, u64)] = &[
    ("PACKET_HOST", 0),
    ("PACKET_BROADCAST", 1),
    ("PACKET_MULTICAST", 2),
    ("PACKET_OTHERHOST", 3),
    ("PACKET_OUTGOING", 4),
    ("PACKET_LOOPBACK", 5),
];

/// `RTMGRP_*`, the multicast groups of a NETLINK_ROUTE socket.
const RTMGRP: &[(&str, u64)] = &[
    ("RTMGRP_LINK", 0x1),
    ("RTMGRP_NOTIFY", 0x2),
    ("RTMGRP_NEIGH", 0x4),
    ("RTMGRP_TC", 0x8),
    ("RTMGRP_IPV4_IFADDR", 0x10),
    ("RTMGRP_IPV4_MROUTE", 0x20),
    ("RTMGRP_IPV4_ROUTE", 0x40),
    ("RTMGRP_IPV4_RULE", 0x80),
    ("RTMGRP_IPV6_IFADDR", 0x100),
    ("RTMGRP_IPV6_MROUTE", 0x200),
    ("RTMGRP_IPV6_ROUTE", 0x400),
    ("RTMGRP_IPV6_IFINFO", 0x800),
    ("RTMGRP_DECnet_IFADDR", 0x1000),
    ("RTMGRP_DECnet_ROUTE", 0x4000),
    ("RTMGRP_IPV6_PREFIX", 0x2_0000),
];

const VSOCK_CIDS: &[(&str, u64)] = &[
    ("VMADDR_CID_HYPERVISOR", 0),
    ("VMADDR_CID_LOCAL", 1),
    ("VMADDR_CID_HOST", 2),
    ("VMADDR_CID_ANY", 0xffff_ffff),
];

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(spec::word(data, at, 2)? as u16)
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(spec::word(data, at, 4)? as u32)
}

fn port(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?))
}

/// A NUL-terminated name in a fixed array.
fn name_at(data: &[u8], from: usize, len: usize) -> String {
    let bytes = data.get(from..data.len().min(from + len)).unwrap_or(&[]);
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The address `data` holds, by its family. `netlink_protocol` is the
/// protocol of the socket (`NETLINK_ROUTE` is 0) when the caller knows it from
/// the `socket` call; it names the netlink groups.
pub fn sockaddr(data: &[u8], netlink_protocol: Option<u64>) -> Option<String> {
    match u16_at(data, 0)? {
        0 => Some("AF_UNSPEC".into()),
        // AF_UNIX; a leading NUL names an abstract socket.
        1 => {
            let path = data.get(2..)?;
            let (prefix, path) = match path.split_first() {
                Some((0, rest)) => ("@", rest),
                _ => ("", path),
            };
            let end = path
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(path.len());
            Some(format!(
                "unix:{prefix}{}",
                String::from_utf8_lossy(&path[..end])
            ))
        }
        2 => {
            let address: [u8; 4] = data.get(4..8)?.try_into().ok()?;
            Some(format!(
                "{}:{}",
                std::net::Ipv4Addr::from(address),
                port(data)?
            ))
        }
        10 => {
            let address: [u8; 16] = data.get(8..24)?.try_into().ok()?;
            Some(format!(
                "[{}]:{}",
                std::net::Ipv6Addr::from(address),
                port(data)?
            ))
        }
        // AF_NETLINK: {family, pad, nl_pid, nl_groups}.
        16 => {
            let pid = u32_at(data, 4)?;
            let groups = u64::from(u32_at(data, 8)?);
            let protocol = netlink_protocol.map(|number| named(number, NETLINK));
            let groups = match netlink_protocol {
                Some(0) => flags(groups, RTMGRP),
                _ => format!("{groups:#x}"),
            };
            let head =
                protocol.map_or_else(|| "netlink:".to_owned(), |name| format!("netlink:{name}:"));
            Some(format!("{head}pid={pid},groups={groups}"))
        }
        // AF_PACKET: {family, protocol (network order), ifindex, hatype,
        // pkttype, halen, addr[8]}.
        17 => {
            let protocol = u64::from(u16::from_be_bytes(data.get(2..4)?.try_into().ok()?));
            let ifindex = i32::from_le_bytes(data.get(4..8)?.try_into().ok()?);
            let mut parts = vec![
                format!("proto={}", named(protocol, ETHERNET)),
                format!("ifindex={ifindex}"),
            ];
            if let Some(hatype) = u16_at(data, 8).filter(|hatype| *hatype != 0) {
                parts.push(format!("hatype={}", named(u64::from(hatype), ARPHRD)));
            }
            if let Some(pkttype) = data.get(10).filter(|kind| **kind != 0) {
                parts.push(format!(
                    "pkttype={}",
                    named(u64::from(*pkttype), PACKET_TYPES)
                ));
            }
            if let Some(length) = data.get(11).map(|len| usize::from(*len).min(8))
                && length > 0
                && let Some(address) = data.get(12..12 + length)
            {
                parts.push(format!("mac={}", mac(address)));
            }
            Some(format!("packet:{}", parts.join(",")))
        }
        // AF_CAN: {family, ifindex at 4}.
        29 => Some(format!(
            "can:ifindex={}",
            i32::from_le_bytes(data.get(4..8)?.try_into().ok()?)
        )),
        // AF_ALG: {family, salg_type[14], salg_feat, salg_mask, salg_name[64]}.
        38 => {
            let mut text = format!("alg:{}/{}", name_at(data, 2, 14), name_at(data, 24, 64));
            for (label, at) in [("feat", 16), ("mask", 20)] {
                if let Some(value) = u32_at(data, at).filter(|value| *value != 0) {
                    text.push_str(&format!(",{label}={value:#x}"));
                }
            }
            Some(text)
        }
        // AF_VSOCK: {family, reserved, port, cid}.
        40 => {
            let port = u32_at(data, 4)?;
            let cid = u64::from(u32_at(data, 8)?);
            let port = if port == u32::MAX {
                "VMADDR_PORT_ANY".to_owned()
            } else {
                port.to_string()
            };
            Some(format!("vsock:{}:{port}", named(cid, VSOCK_CIDS)))
        }
        _ => None,
    }
}

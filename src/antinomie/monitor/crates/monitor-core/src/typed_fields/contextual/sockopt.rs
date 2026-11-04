// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The value of a socket option by its level and name. The guest captures the
//! value with the layout its rule gives (`int`, `u8`, `linger`, `ucred`,
//! `ip_mreq`...); this names it: a flag as `on`/`off`, `SO_TYPE` as
//! `SOCK_STREAM`, `SO_ERROR` as an errno, the structures as members.
use super::{Call, Decoded, ipv4};
use crate::syscalls::{self, Abi};
use crate::typed_fields::{Shape, i32_at, named, u8_at, u32_at};

/// Options whose value is a switch.
const SWITCHES: &[&str] = &[
    "SO_DEBUG",
    "SO_REUSEADDR",
    "SO_DONTROUTE",
    "SO_BROADCAST",
    "SO_KEEPALIVE",
    "SO_OOBINLINE",
    "SO_NO_CHECK",
    "SO_PASSCRED",
    "SO_REUSEPORT",
    "SO_PASSSEC",
    "SO_RXQ_OVFL",
    "SO_WIFI_STATUS",
    "SO_NOFCS",
    "SO_LOCK_FILTER",
    "SO_SELECT_ERR_QUEUE",
    "SO_ZEROCOPY",
    "SO_CNX_ADVICE",
    "SO_ACCEPTCONN",
    "SO_PASSPIDFD",
    "SO_PREFER_BUSY_POLL",
    "IP_PKTINFO",
    "IP_RECVTTL",
    "IP_RECVOPTS",
    "IP_RECVTOS",
    "IP_RETOPTS",
    "IP_HDRINCL",
    "IP_RECVERR",
    "IP_ROUTER_ALERT",
    "IP_FREEBIND",
    "IP_PASSSEC",
    "IP_TRANSPARENT",
    "IP_NODEFRAG",
    "IP_BIND_ADDRESS_NO_PORT",
    "IP_MULTICAST_LOOP",
    "IP_MULTICAST_ALL",
    "IP_RECVORIGDSTADDR",
    "IP_CHECKSUM",
    "IPV6_V6ONLY",
    "IPV6_RECVPKTINFO",
    "IPV6_RECVHOPLIMIT",
    "IPV6_RECVRTHDR",
    "IPV6_RECVHOPOPTS",
    "IPV6_RECVDSTOPTS",
    "IPV6_RECVTCLASS",
    "IPV6_RECVPATHMTU",
    "IPV6_TRANSPARENT",
    "IPV6_FREEBIND",
    "IPV6_RECVORIGDSTADDR",
    "IPV6_MULTICAST_LOOP",
    "IPV6_MULTICAST_ALL",
    "IPV6_DONTFRAG",
    "IPV6_RECVERR",
    "IPV6_AUTOFLOWLABEL",
    "TCP_NODELAY",
    "TCP_CORK",
    "TCP_QUICKACK",
    "TCP_REPAIR",
    "TCP_FASTOPEN_CONNECT",
    "TCP_FASTOPEN_NO_COOKIE",
    "TCP_THIN_LINEAR_TIMEOUTS",
    "TCP_THIN_DUPACK",
    "TCP_SAVE_SYN",
    "TCP_INQ",
    "TCP_TIMESTAMP",
];

const SOCKET_TYPES: &[(&str, u64)] = &[
    ("SOCK_STREAM", 1),
    ("SOCK_DGRAM", 2),
    ("SOCK_RAW", 3),
    ("SOCK_RDM", 4),
    ("SOCK_SEQPACKET", 5),
    ("SOCK_DCCP", 6),
    ("SOCK_PACKET", 10),
];

pub const FAMILIES: &[(&str, u64)] = &[
    ("AF_UNSPEC", 0),
    ("AF_UNIX", 1),
    ("AF_INET", 2),
    ("AF_AX25", 3),
    ("AF_IPX", 4),
    ("AF_APPLETALK", 5),
    ("AF_X25", 9),
    ("AF_INET6", 10),
    ("AF_NETLINK", 16),
    ("AF_PACKET", 17),
    ("AF_BLUETOOTH", 31),
    ("AF_ALG", 38),
    ("AF_VSOCK", 40),
];

pub const PROTOCOLS: &[(&str, u64)] = &[
    ("IPPROTO_IP", 0),
    ("IPPROTO_ICMP", 1),
    ("IPPROTO_IGMP", 2),
    ("IPPROTO_TCP", 6),
    ("IPPROTO_UDP", 17),
    ("IPPROTO_DCCP", 33),
    ("IPPROTO_IPV6", 41),
    ("IPPROTO_GRE", 47),
    ("IPPROTO_ESP", 50),
    ("IPPROTO_AH", 51),
    ("IPPROTO_ICMPV6", 58),
    ("IPPROTO_SCTP", 132),
    ("IPPROTO_UDPLITE", 136),
    ("IPPROTO_RAW", 255),
    ("IPPROTO_MPTCP", 262),
];

const TCP_STATES: &[(&str, u64)] = &[
    ("TCP_ESTABLISHED", 1),
    ("TCP_SYN_SENT", 2),
    ("TCP_SYN_RECV", 3),
    ("TCP_FIN_WAIT1", 4),
    ("TCP_FIN_WAIT2", 5),
    ("TCP_TIME_WAIT", 6),
    ("TCP_CLOSE", 7),
    ("TCP_CLOSE_WAIT", 8),
    ("TCP_LAST_ACK", 9),
    ("TCP_LISTEN", 10),
    ("TCP_CLOSING", 11),
];

const TIMESTAMPING: &[(&str, u64)] = &[
    ("SOF_TIMESTAMPING_TX_HARDWARE", 1),
    ("SOF_TIMESTAMPING_TX_SOFTWARE", 2),
    ("SOF_TIMESTAMPING_RX_HARDWARE", 4),
    ("SOF_TIMESTAMPING_RX_SOFTWARE", 8),
    ("SOF_TIMESTAMPING_SOFTWARE", 16),
    ("SOF_TIMESTAMPING_SYS_HARDWARE", 32),
    ("SOF_TIMESTAMPING_RAW_HARDWARE", 64),
    ("SOF_TIMESTAMPING_OPT_ID", 128),
    ("SOF_TIMESTAMPING_TX_SCHED", 256),
    ("SOF_TIMESTAMPING_TX_ACK", 512),
    ("SOF_TIMESTAMPING_OPT_CMSG", 1024),
    ("SOF_TIMESTAMPING_OPT_TSONLY", 2048),
];

/// The option's name in the ABI's table, from the call's level and name.
fn option_name(abi: Abi, call: &Call<'_>) -> Option<String> {
    let args = call.args?;
    let table = syscalls::table(abi);
    let number = table.number(call.name)?;
    table.selector_name(number, 2, &args)
}

fn switch(value: i64) -> String {
    match value {
        0 => "off".into(),
        1 => "on".into(),
        other => other.to_string(),
    }
}

/// The option's value: a structure by its layout, or a plain value named by
/// the option; None for a layout and option this has nothing to add to.
pub(super) fn value(abi: Abi, call: &Call<'_>, layout: &str, data: &[u8]) -> Option<Decoded> {
    let structure = match layout {
        "ucred" => ucred(data),
        "ip_mreq" => mreq(data, false),
        "ip_mreqn" => mreq(data, true),
        "ipv6_mreq" => ipv6_mreq(data),
        "so_timestamping" => so_timestamping(data),
        "sock_txtime" => txtime(data),
        "tcp_info" => tcp_info(data),
        "__kernel_old_timeval" | "__kernel_sock_timeval" => {
            return crate::typed_fields::layout::decode(abi, "timeval", Some(call), Some(3), data);
        }
        _ => None,
    };
    if structure.is_some() {
        return structure;
    }
    let number = match layout {
        "int" | "unsigned_int" | "u32" => i64::from(i32_at(data, 0)?),
        "u8" => i64::from(u8_at(data, 0)?),
        _ => return None,
    };
    let name = option_name(abi, call)?;
    let text = if SWITCHES.contains(&name.as_str()) {
        switch(number)
    } else {
        match name.as_str() {
            "SO_TYPE" => named(number as u64, SOCKET_TYPES),
            "SO_DOMAIN" => named(number as u64, FAMILIES),
            "SO_PROTOCOL" => named(number as u64, PROTOCOLS),
            "SO_ERROR" => match crate::errno::errno_name(number.unsigned_abs()) {
                Some(errno) if number != 0 => errno.to_owned(),
                _ => number.to_string(),
            },
            _ => number.to_string(),
        }
    };
    Some(Decoded::value(text))
}

/// `struct ucred`: the peer's process, user and group.
fn ucred(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("pid", i32_at(data, 0)?.to_string());
    decoded.push("uid", u32_at(data, 4)?.to_string());
    decoded.push("gid", u32_at(data, 8)?.to_string());
    Some(decoded)
}

/// `struct ip_mreq` (8 bytes) or `ip_mreqn` (12): the group, the interface.
fn mreq(data: &[u8], with_index: bool) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("imr_multiaddr", ipv4(data, 0)?);
    decoded.push(
        if with_index {
            "imr_address"
        } else {
            "imr_interface"
        },
        ipv4(data, 4)?,
    );
    if with_index {
        decoded.push("imr_ifindex", i32_at(data, 8)?.to_string());
    }
    Some(decoded)
}

/// `struct ipv6_mreq`: a 16-byte group address and the interface index.
fn ipv6_mreq(data: &[u8]) -> Option<Decoded> {
    let address = data.get(..16)?;
    let groups: Vec<String> = address
        .chunks(2)
        .map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]])))
        .collect();
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("ipv6mr_multiaddr", groups.join(":"));
    decoded.push("ipv6mr_interface", u32_at(data, 16)?.to_string());
    Some(decoded)
}

fn so_timestamping(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push(
        "flags",
        crate::typed_fields::flags(u64::from(u32_at(data, 0)?), TIMESTAMPING),
    );
    if let Some(phc) = u32_at(data, 4) {
        decoded.push("bind_phc", phc.to_string());
    }
    Some(decoded)
}

fn txtime(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("clockid", i32_at(data, 0)?.to_string());
    decoded.push("flags", format!("{:#x}", u32_at(data, 4)?));
    Some(decoded)
}

/// `struct tcp_info`'s leading members: the state, and the sizes and timers
/// a bot reads to check a link.
fn tcp_info(data: &[u8]) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::Struct);
    decoded.push("tcpi_state", named(u64::from(u8_at(data, 0)?), TCP_STATES));
    decoded.push("tcpi_retransmits", u8_at(data, 2)?.to_string());
    for (name, at) in [
        ("tcpi_rto", 8),
        ("tcpi_snd_mss", 16),
        ("tcpi_rcv_mss", 20),
        ("tcpi_unacked", 24),
        ("tcpi_lost", 32),
        ("tcpi_retrans", 36),
    ] {
        if let Some(value) = u32_at(data, at) {
            decoded.push(name, value.to_string());
        }
    }
    Some(decoded)
}

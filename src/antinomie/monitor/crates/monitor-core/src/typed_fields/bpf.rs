// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! `union bpf_attr` by command. The command (bpf's first argument) selects
//! which anonymous structure of the union the kernel reads; each command's
//! members and offsets below are those of the pinned Linux 6.12.94
//! `include/uapi/linux/bpf.h` (the union is the same on every 64-bit
//! architecture). BPF_LINK_CREATE's tail is a further union selected by the
//! attach type. Members past the bytes the program passed (bpf's `size`
//! argument, so the capture) are not shown: the kernel reads them as zero.
use super::{Decoded, Shape, c_string, i32_at, named, pointer, u32_at, u64_at};

/// How a member reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    U32,
    U64,
    /// A descriptor (or other signed 32-bit value) in a `__u32`/`__s32`.
    Fd,
    Hex32,
    Hex64,
    Pointer,
    /// `char[BPF_OBJ_NAME_LEN]`.
    Name,
    MapType,
    ProgType,
    AttachType,
}

impl Kind {
    fn size(self) -> usize {
        match self {
            Kind::U64 | Kind::Hex64 | Kind::Pointer => 8,
            Kind::Name => 16,
            _ => 4,
        }
    }
}

pub(super) type Member = (&'static str, usize, Kind);

use Kind::{AttachType, Fd, Hex32, Hex64, MapType, Name, Pointer, ProgType, U32, U64};

const MAP_CREATE: &[Member] = &[
    ("map_type", 0, MapType),
    ("key_size", 4, U32),
    ("value_size", 8, U32),
    ("max_entries", 12, U32),
    ("map_flags", 16, Hex32),
    ("inner_map_fd", 20, Fd),
    ("numa_node", 24, U32),
    ("map_name", 28, Name),
    ("map_ifindex", 44, U32),
    ("btf_fd", 48, Fd),
    ("btf_key_type_id", 52, U32),
    ("btf_value_type_id", 56, U32),
    ("btf_vmlinux_value_type_id", 60, U32),
    ("map_extra", 64, Hex64),
    ("value_type_btf_obj_fd", 72, Fd),
    ("map_token_fd", 76, Fd),
];
const ELEM_VALUE: &[Member] = &[
    ("map_fd", 0, Fd),
    ("key", 8, Pointer),
    ("value", 16, Pointer),
    ("flags", 24, Hex64),
];
const ELEM_DELETE: &[Member] = &[("map_fd", 0, Fd), ("key", 8, Pointer), ("flags", 24, Hex64)];
const ELEM_NEXT: &[Member] = &[
    ("map_fd", 0, Fd),
    ("key", 8, Pointer),
    ("next_key", 16, Pointer),
];
const MAP_FD: &[Member] = &[("map_fd", 0, Fd)];
const BATCH: &[Member] = &[
    ("in_batch", 0, Pointer),
    ("out_batch", 8, Pointer),
    ("keys", 16, Pointer),
    ("values", 24, Pointer),
    ("count", 32, U32),
    ("map_fd", 36, Fd),
    ("elem_flags", 40, Hex64),
    ("flags", 48, Hex64),
];
const PROG_LOAD: &[Member] = &[
    ("prog_type", 0, ProgType),
    ("insn_cnt", 4, U32),
    ("insns", 8, Pointer),
    ("license", 16, Pointer),
    ("log_level", 24, U32),
    ("log_size", 28, U32),
    ("log_buf", 32, Pointer),
    ("kern_version", 40, U32),
    ("prog_flags", 44, Hex32),
    ("prog_name", 48, Name),
    ("prog_ifindex", 64, U32),
    ("expected_attach_type", 68, AttachType),
    ("prog_btf_fd", 72, Fd),
    ("func_info_rec_size", 76, U32),
    ("func_info", 80, Pointer),
    ("func_info_cnt", 88, U32),
    ("line_info_rec_size", 92, U32),
    ("line_info", 96, Pointer),
    ("line_info_cnt", 104, U32),
    ("attach_btf_id", 108, U32),
    ("attach_prog_fd", 112, Fd),
    ("core_relo_cnt", 116, U32),
    ("fd_array", 120, Pointer),
    ("core_relos", 128, Pointer),
    ("core_relo_rec_size", 136, U32),
    ("log_true_size", 140, U32),
    ("prog_token_fd", 144, Fd),
];
const OBJ: &[Member] = &[
    ("pathname", 0, Pointer),
    ("bpf_fd", 8, Fd),
    ("file_flags", 12, Hex32),
    ("path_fd", 16, Fd),
];
const PROG_ATTACH: &[Member] = &[
    ("target_fd", 0, Fd),
    ("attach_bpf_fd", 4, Fd),
    ("attach_type", 8, AttachType),
    ("attach_flags", 12, Hex32),
    ("replace_bpf_fd", 16, Fd),
    ("relative_fd", 20, Fd),
    ("expected_revision", 24, U64),
];
const TEST_RUN: &[Member] = &[
    ("prog_fd", 0, Fd),
    ("retval", 4, U32),
    ("data_size_in", 8, U32),
    ("data_size_out", 12, U32),
    ("data_in", 16, Pointer),
    ("data_out", 24, Pointer),
    ("repeat", 32, U32),
    ("duration", 36, U32),
    ("ctx_size_in", 40, U32),
    ("ctx_size_out", 44, U32),
    ("ctx_in", 48, Pointer),
    ("ctx_out", 56, Pointer),
    ("flags", 64, Hex32),
    ("cpu", 68, U32),
    ("batch_size", 72, U32),
];
const NEXT_ID: &[Member] = &[
    ("start_id", 0, U32),
    ("next_id", 4, U32),
    ("open_flags", 8, Hex32),
];
const PROG_BY_ID: &[Member] = &[("prog_id", 0, U32), ("open_flags", 8, Hex32)];
const MAP_BY_ID: &[Member] = &[("map_id", 0, U32), ("open_flags", 8, Hex32)];
const BTF_BY_ID: &[Member] = &[("btf_id", 0, U32), ("open_flags", 8, Hex32)];
const LINK_BY_ID: &[Member] = &[("link_id", 0, U32), ("open_flags", 8, Hex32)];
const INFO: &[Member] = &[
    ("bpf_fd", 0, Fd),
    ("info_len", 4, U32),
    ("info", 8, Pointer),
];
const QUERY: &[Member] = &[
    ("target_fd", 0, Fd),
    ("attach_type", 4, AttachType),
    ("query_flags", 8, Hex32),
    ("attach_flags", 12, Hex32),
    ("prog_ids", 16, Pointer),
    ("prog_cnt", 24, U32),
    ("prog_attach_flags", 32, Pointer),
    ("link_ids", 40, Pointer),
    ("link_attach_flags", 48, Pointer),
    ("revision", 56, U64),
];
const RAW_TRACEPOINT: &[Member] = &[
    ("name", 0, Pointer),
    ("prog_fd", 8, Fd),
    ("cookie", 16, Hex64),
];
const BTF_LOAD: &[Member] = &[
    ("btf", 0, Pointer),
    ("btf_log_buf", 8, Pointer),
    ("btf_size", 16, U32),
    ("btf_log_size", 20, U32),
    ("btf_log_level", 24, U32),
    ("btf_log_true_size", 28, U32),
    ("btf_flags", 32, Hex32),
    ("btf_token_fd", 36, Fd),
];
const TASK_FD_QUERY: &[Member] = &[
    ("pid", 0, U32),
    ("fd", 4, Fd),
    ("flags", 8, Hex32),
    ("buf_len", 12, U32),
    ("buf", 16, Pointer),
    ("prog_id", 24, U32),
    ("fd_type", 28, U32),
    ("probe_offset", 32, Hex64),
    ("probe_addr", 40, Pointer),
];
const LINK_CREATE: &[Member] = &[
    ("prog_fd", 0, Fd),
    ("target_fd", 4, Fd),
    ("attach_type", 8, AttachType),
    ("flags", 12, Hex32),
];
const LINK_UPDATE: &[Member] = &[
    ("link_fd", 0, Fd),
    ("new_prog_fd", 4, Fd),
    ("flags", 8, Hex32),
    ("old_prog_fd", 12, Fd),
];
const LINK_FD: &[Member] = &[("link_fd", 0, Fd)];
const ENABLE_STATS: &[Member] = &[("type", 0, U32)];
const ITER_CREATE: &[Member] = &[("link_fd", 0, Fd), ("flags", 4, Hex32)];
const PROG_BIND_MAP: &[Member] = &[("prog_fd", 0, Fd), ("map_fd", 4, Fd), ("flags", 8, Hex32)];
const TOKEN_CREATE: &[Member] = &[("flags", 0, Hex32), ("bpffs_fd", 4, Fd)];

// BPF_LINK_CREATE's union at offset 16, by attach type.
const LINK_PERF_EVENT: &[Member] = &[("perf_event.bpf_cookie", 16, Hex64)];
const LINK_KPROBE_MULTI: &[Member] = &[
    ("kprobe_multi.flags", 16, Hex32),
    ("kprobe_multi.cnt", 20, U32),
    ("kprobe_multi.syms", 24, Pointer),
    ("kprobe_multi.addrs", 32, Pointer),
    ("kprobe_multi.cookies", 40, Pointer),
];
const LINK_UPROBE_MULTI: &[Member] = &[
    ("uprobe_multi.path", 16, Pointer),
    ("uprobe_multi.offsets", 24, Pointer),
    ("uprobe_multi.ref_ctr_offsets", 32, Pointer),
    ("uprobe_multi.cookies", 40, Pointer),
    ("uprobe_multi.cnt", 48, U32),
    ("uprobe_multi.flags", 52, Hex32),
    ("uprobe_multi.pid", 56, U32),
];
const LINK_NETFILTER: &[Member] = &[
    ("netfilter.pf", 16, U32),
    ("netfilter.hooknum", 20, U32),
    ("netfilter.priority", 24, Fd),
    ("netfilter.flags", 28, Hex32),
];
const LINK_RELATIVE: &[Member] = &[("relative_fd", 16, Fd), ("expected_revision", 24, U64)];
const LINK_ITER: &[Member] = &[("iter_info", 16, Pointer), ("iter_info_len", 24, U32)];
const LINK_TRACING: &[Member] = &[
    ("tracing.target_btf_id", 16, U32),
    ("tracing.cookie", 24, Hex64),
];

/// The members command `cmd` uses, None for a command 6.12.94 does not have.
fn members(cmd: u64) -> Option<&'static [Member]> {
    Some(match cmd {
        0 => MAP_CREATE,
        1 | 2 | 21 => ELEM_VALUE,
        3 => ELEM_DELETE,
        4 => ELEM_NEXT,
        5 => PROG_LOAD,
        6 | 7 => OBJ,
        8 | 9 => PROG_ATTACH,
        10 => TEST_RUN,
        11 | 12 | 23 | 31 => NEXT_ID,
        13 => PROG_BY_ID,
        14 => MAP_BY_ID,
        15 => INFO,
        16 => QUERY,
        17 => RAW_TRACEPOINT,
        18 => BTF_LOAD,
        19 => BTF_BY_ID,
        20 => TASK_FD_QUERY,
        22 => MAP_FD,
        24..=27 => BATCH,
        28 => LINK_CREATE,
        29 => LINK_UPDATE,
        30 => LINK_BY_ID,
        32 => ENABLE_STATS,
        33 => ITER_CREATE,
        34 => LINK_FD,
        35 => PROG_BIND_MAP,
        36 => TOKEN_CREATE,
        _ => return None,
    })
}

/// BPF_LINK_CREATE's members after the common four, by attach type.
fn link_tail(attach_type: u32) -> &'static [Member] {
    match attach_type {
        // BPF_PERF_EVENT
        41 => LINK_PERF_EVENT,
        // BPF_TRACE_KPROBE_MULTI, BPF_TRACE_KPROBE_SESSION
        42 | 56 => LINK_KPROBE_MULTI,
        // BPF_TRACE_UPROBE_MULTI
        48 => LINK_UPROBE_MULTI,
        // BPF_NETFILTER
        45 => LINK_NETFILTER,
        // BPF_TCX_INGRESS, BPF_TCX_EGRESS, BPF_NETKIT_PRIMARY, BPF_NETKIT_PEER
        46 | 47 | 54 | 55 => LINK_RELATIVE,
        // BPF_TRACE_ITER
        28 => LINK_ITER,
        // BPF_TRACE_FENTRY, BPF_TRACE_FEXIT, BPF_MODIFY_RETURN, BPF_LSM_MAC
        24..=27 => LINK_TRACING,
        _ => &[],
    }
}

fn read(data: &[u8], at: usize, kind: Kind) -> Option<u64> {
    match kind.size() {
        8 => u64_at(data, at),
        4 => u32_at(data, at).map(u64::from),
        _ => None,
    }
}

fn shown(data: &[u8], at: usize, kind: Kind) -> Option<String> {
    if kind == Name {
        return Some(c_string(data.get(at..at + 16)?));
    }
    let value = read(data, at, kind)?;
    Some(match kind {
        U32 | U64 => value.to_string(),
        Fd => i32_at(data, at)?.to_string(),
        Hex32 | Hex64 => format!("{value:#x}"),
        Pointer => pointer(value),
        MapType => named(value, MAP_TYPES),
        ProgType => named(value, PROG_TYPES),
        AttachType => named(value, ATTACH_TYPES),
        Name => unreachable!("handled above"),
    })
}

/// The members of `cmd`'s branch present in `data`, in declaration order.
pub(super) fn attr(cmd: u64, data: &[u8]) -> Option<Decoded> {
    let mut list = members(cmd)?.to_vec();
    if cmd == 28
        && let Some(kind) = u32_at(data, 8)
    {
        list.extend_from_slice(link_tail(kind));
    }
    let mut decoded = Decoded::new(Shape::Struct);
    for (name, at, kind) in list {
        match shown(data, at, kind) {
            Some(text) => decoded.push(name, text),
            None => break,
        }
    }
    (!decoded.members.is_empty()).then_some(decoded)
}

/// One member of a command's branch as a number (a name member as None), for
/// Triage: `attr_member(5, attr, "insn_cnt")`. None when the command has no
/// such member or the bytes do not reach it.
pub fn attr_member(cmd: u64, data: &[u8], member: &str) -> Option<u64> {
    let mut list = members(cmd)?.to_vec();
    if cmd == 28 {
        list.extend_from_slice(link_tail(u32_at(data, 8)?));
    }
    let (_, at, kind) = list.into_iter().find(|(name, _, _)| *name == member)?;
    if kind == Name {
        return None;
    }
    read(data, at, kind)
}

/// `enum bpf_map_type` names (the deprecated cgroup storage aliases keep the
/// name the header gives the number).
pub fn map_type_name(value: u64) -> String {
    named(value, MAP_TYPES)
}

pub fn prog_type_name(value: u64) -> String {
    named(value, PROG_TYPES)
}

pub fn attach_type_name(value: u64) -> String {
    named(value, ATTACH_TYPES)
}

/// Names in declaration order: the index is the value.
macro_rules! enumeration {
    ($name:ident = [$($item:literal),* $(,)?]) => {
        const $name: &[(&str, u64)] = &{
            let names = [$($item),*];
            let mut table = [("", 0u64); [$($item),*].len()];
            let mut index = 0;
            while index < names.len() {
                table[index] = (names[index], index as u64);
                index += 1;
            }
            table
        };
    };
}

enumeration!(
    MAP_TYPES = [
        "BPF_MAP_TYPE_UNSPEC",
        "BPF_MAP_TYPE_HASH",
        "BPF_MAP_TYPE_ARRAY",
        "BPF_MAP_TYPE_PROG_ARRAY",
        "BPF_MAP_TYPE_PERF_EVENT_ARRAY",
        "BPF_MAP_TYPE_PERCPU_HASH",
        "BPF_MAP_TYPE_PERCPU_ARRAY",
        "BPF_MAP_TYPE_STACK_TRACE",
        "BPF_MAP_TYPE_CGROUP_ARRAY",
        "BPF_MAP_TYPE_LRU_HASH",
        "BPF_MAP_TYPE_LRU_PERCPU_HASH",
        "BPF_MAP_TYPE_LPM_TRIE",
        "BPF_MAP_TYPE_ARRAY_OF_MAPS",
        "BPF_MAP_TYPE_HASH_OF_MAPS",
        "BPF_MAP_TYPE_DEVMAP",
        "BPF_MAP_TYPE_SOCKMAP",
        "BPF_MAP_TYPE_CPUMAP",
        "BPF_MAP_TYPE_XSKMAP",
        "BPF_MAP_TYPE_SOCKHASH",
        "BPF_MAP_TYPE_CGROUP_STORAGE",
        "BPF_MAP_TYPE_REUSEPORT_SOCKARRAY",
        "BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE",
        "BPF_MAP_TYPE_QUEUE",
        "BPF_MAP_TYPE_STACK",
        "BPF_MAP_TYPE_SK_STORAGE",
        "BPF_MAP_TYPE_DEVMAP_HASH",
        "BPF_MAP_TYPE_STRUCT_OPS",
        "BPF_MAP_TYPE_RINGBUF",
        "BPF_MAP_TYPE_INODE_STORAGE",
        "BPF_MAP_TYPE_TASK_STORAGE",
        "BPF_MAP_TYPE_BLOOM_FILTER",
        "BPF_MAP_TYPE_USER_RINGBUF",
        "BPF_MAP_TYPE_CGRP_STORAGE",
        "BPF_MAP_TYPE_ARENA",
    ]
);

enumeration!(
    PROG_TYPES = [
        "BPF_PROG_TYPE_UNSPEC",
        "BPF_PROG_TYPE_SOCKET_FILTER",
        "BPF_PROG_TYPE_KPROBE",
        "BPF_PROG_TYPE_SCHED_CLS",
        "BPF_PROG_TYPE_SCHED_ACT",
        "BPF_PROG_TYPE_TRACEPOINT",
        "BPF_PROG_TYPE_XDP",
        "BPF_PROG_TYPE_PERF_EVENT",
        "BPF_PROG_TYPE_CGROUP_SKB",
        "BPF_PROG_TYPE_CGROUP_SOCK",
        "BPF_PROG_TYPE_LWT_IN",
        "BPF_PROG_TYPE_LWT_OUT",
        "BPF_PROG_TYPE_LWT_XMIT",
        "BPF_PROG_TYPE_SOCK_OPS",
        "BPF_PROG_TYPE_SK_SKB",
        "BPF_PROG_TYPE_CGROUP_DEVICE",
        "BPF_PROG_TYPE_SK_MSG",
        "BPF_PROG_TYPE_RAW_TRACEPOINT",
        "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
        "BPF_PROG_TYPE_LWT_SEG6LOCAL",
        "BPF_PROG_TYPE_LIRC_MODE2",
        "BPF_PROG_TYPE_SK_REUSEPORT",
        "BPF_PROG_TYPE_FLOW_DISSECTOR",
        "BPF_PROG_TYPE_CGROUP_SYSCTL",
        "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
        "BPF_PROG_TYPE_CGROUP_SOCKOPT",
        "BPF_PROG_TYPE_TRACING",
        "BPF_PROG_TYPE_STRUCT_OPS",
        "BPF_PROG_TYPE_EXT",
        "BPF_PROG_TYPE_LSM",
        "BPF_PROG_TYPE_SK_LOOKUP",
        "BPF_PROG_TYPE_SYSCALL",
        "BPF_PROG_TYPE_NETFILTER",
    ]
);

enumeration!(
    ATTACH_TYPES = [
        "BPF_CGROUP_INET_INGRESS",
        "BPF_CGROUP_INET_EGRESS",
        "BPF_CGROUP_INET_SOCK_CREATE",
        "BPF_CGROUP_SOCK_OPS",
        "BPF_SK_SKB_STREAM_PARSER",
        "BPF_SK_SKB_STREAM_VERDICT",
        "BPF_CGROUP_DEVICE",
        "BPF_SK_MSG_VERDICT",
        "BPF_CGROUP_INET4_BIND",
        "BPF_CGROUP_INET6_BIND",
        "BPF_CGROUP_INET4_CONNECT",
        "BPF_CGROUP_INET6_CONNECT",
        "BPF_CGROUP_INET4_POST_BIND",
        "BPF_CGROUP_INET6_POST_BIND",
        "BPF_CGROUP_UDP4_SENDMSG",
        "BPF_CGROUP_UDP6_SENDMSG",
        "BPF_LIRC_MODE2",
        "BPF_FLOW_DISSECTOR",
        "BPF_CGROUP_SYSCTL",
        "BPF_CGROUP_UDP4_RECVMSG",
        "BPF_CGROUP_UDP6_RECVMSG",
        "BPF_CGROUP_GETSOCKOPT",
        "BPF_CGROUP_SETSOCKOPT",
        "BPF_TRACE_RAW_TP",
        "BPF_TRACE_FENTRY",
        "BPF_TRACE_FEXIT",
        "BPF_MODIFY_RETURN",
        "BPF_LSM_MAC",
        "BPF_TRACE_ITER",
        "BPF_CGROUP_INET4_GETPEERNAME",
        "BPF_CGROUP_INET6_GETPEERNAME",
        "BPF_CGROUP_INET4_GETSOCKNAME",
        "BPF_CGROUP_INET6_GETSOCKNAME",
        "BPF_XDP_DEVMAP",
        "BPF_CGROUP_INET_SOCK_RELEASE",
        "BPF_XDP_CPUMAP",
        "BPF_SK_LOOKUP",
        "BPF_XDP",
        "BPF_SK_SKB_VERDICT",
        "BPF_SK_REUSEPORT_SELECT",
        "BPF_SK_REUSEPORT_SELECT_OR_MIGRATE",
        "BPF_PERF_EVENT",
        "BPF_TRACE_KPROBE_MULTI",
        "BPF_LSM_CGROUP",
        "BPF_STRUCT_OPS",
        "BPF_NETFILTER",
        "BPF_TCX_INGRESS",
        "BPF_TCX_EGRESS",
        "BPF_TRACE_UPROBE_MULTI",
        "BPF_CGROUP_UNIX_CONNECT",
        "BPF_CGROUP_UNIX_SENDMSG",
        "BPF_CGROUP_UNIX_RECVMSG",
        "BPF_CGROUP_UNIX_GETPEERNAME",
        "BPF_CGROUP_UNIX_GETSOCKNAME",
        "BPF_NETKIT_PRIMARY",
        "BPF_NETKIT_PEER",
        "BPF_TRACE_KPROBE_SESSION",
    ]
);

#[cfg(test)]
pub(super) fn all_commands() -> impl Iterator<Item = (u64, &'static [Member])> {
    (0..=36).filter_map(|cmd| members(cmd).map(|list| (cmd, list)))
}

#[cfg(test)]
pub(super) fn member_offset(cmd: u64, name: &str) -> Option<usize> {
    members(cmd)?
        .iter()
        .find(|(member, _, _)| *member == name)
        .map(|(_, at, _)| *at)
}

#[cfg(test)]
pub(super) const ALL_LINK_TAILS: &[&[Member]] = &[
    LINK_PERF_EVENT,
    LINK_KPROBE_MULTI,
    LINK_UPROBE_MULTI,
    LINK_NETFILTER,
    LINK_RELATIVE,
    LINK_ITER,
    LINK_TRACING,
];
#[cfg(test)]
pub(super) fn member_size(member: &Member) -> usize {
    member.2.size()
}

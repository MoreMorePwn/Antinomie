// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The table of record arrays: one [`Spec`] per layout type. The sizes are the
//! 64-bit Linux 6.12.94 UAPI's; the architecture is not part of a row because
//! none of these records differ between x86-64 and aarch64 (`desc_struct[]` is
//! x86 only and is simply never captured elsewhere). A record that does differ
//! gets its own row, selected by the layout's `<arch>/` source prefix.
use super::{Ctx, decoders as d, layout_rows as l};
use crate::typed_fields::{Decoded, records, signals};

/// The length of the record at the start of the bytes.
pub(super) enum Length {
    Bytes(usize),
    /// The header that holds the length is not all captured.
    Short,
    /// The length cannot be right.
    Bad(&'static str),
}

pub(super) enum Size {
    Fixed(usize),
    /// Read from the record's header.
    Header(fn(&[u8]) -> Length),
    /// The size of the named layout in the ABI's member inventory (an
    /// `epoll_event` is 12 bytes on x86-64 and 16 on aarch64).
    Layout(&'static str),
}

pub(super) struct Spec {
    /// The layout types this row decodes (`linux_dirent64[]`).
    pub names: &'static [&'static str],
    /// One record's type.
    pub element: &'static str,
    pub size: Size,
    pub decode: fn(&Ctx<'_>, &[u8]) -> Option<Decoded>,
    /// The collapsed line of a decoded record.
    pub summary: fn(&Decoded) -> String,
}

const fn spec(
    names: &'static [&'static str],
    element: &'static str,
    size: Size,
    decode: fn(&Ctx<'_>, &[u8]) -> Option<Decoded>,
    summary: fn(&Decoded) -> String,
) -> Spec {
    Spec {
        names,
        element,
        size,
        decode,
        summary,
    }
}

static SPECS: &[Spec] = &[
    spec(
        &["linux_dirent64[]"],
        "linux_dirent64",
        Size::Header(d::dirent64_length),
        |_, bytes| records::dirent(bytes, true),
        d::dirent_summary,
    ),
    spec(
        &["linux_dirent[]"],
        "linux_dirent",
        Size::Header(d::dirent_length),
        |_, bytes| records::dirent(bytes, false),
        d::dirent_summary,
    ),
    spec(
        &["cap_data[]"],
        "__user_cap_data_struct",
        Size::Fixed(12),
        |ctx, bytes| records::capability_element(bytes, ctx.index),
        d::first_members,
    ),
    spec(
        &["gid_t[]", "uid_t[2]"],
        "gid_t",
        Size::Fixed(4),
        |_, bytes| records::id(bytes),
        d::value_summary,
    ),
    spec(
        &["siginfo_t[]"],
        "siginfo_t",
        Size::Fixed(128),
        |_, bytes| signals::siginfo(bytes),
        d::first_members,
    ),
    spec(
        &["desc_struct[]"],
        "desc_struct",
        Size::Fixed(8),
        |_, bytes| records::descriptor(bytes),
        d::descriptor_summary,
    ),
    spec(
        &["pollfd[]"],
        "pollfd",
        Size::Fixed(8),
        |_, bytes| d::pollfd(bytes),
        d::pollfd_summary,
    ),
    spec(
        &["sembuf[]"],
        "sembuf",
        Size::Fixed(6),
        |_, bytes| d::sembuf(bytes),
        d::sembuf_summary,
    ),
    spec(
        &["cmsghdr[]"],
        "cmsghdr",
        Size::Header(d::cmsg_length),
        |_, bytes| d::cmsg(bytes),
        d::cmsg_summary,
    ),
    spec(
        &["sock_filter[]"],
        "sock_filter",
        Size::Fixed(8),
        super::classic::decode,
        d::asm_summary,
    ),
    spec(
        &["futex_waitv[]"],
        "futex_waitv",
        Size::Fixed(24),
        |_, bytes| d::futex_waitv(bytes),
        d::futex_summary,
    ),
    spec(
        &["kexec_segment[]"],
        "kexec_segment",
        Size::Fixed(32),
        |_, bytes| d::kexec_segment(bytes),
        d::kexec_summary,
    ),
    spec(
        &["bpf_insn[]"],
        "bpf_insn",
        Size::Fixed(8),
        d::bpf_insn,
        d::asm_summary,
    ),
    spec(
        &["bpf_func_info[]"],
        "bpf_func_info",
        Size::Fixed(8),
        |_, bytes| d::bpf_func_info(bytes),
        d::first_members,
    ),
    spec(
        &["bpf_line_info[]"],
        "bpf_line_info",
        Size::Fixed(16),
        |_, bytes| d::bpf_line_info(bytes),
        d::line_info_summary,
    ),
    spec(
        &["bpf_core_relo[]"],
        "bpf_core_relo",
        Size::Fixed(16),
        |_, bytes| d::bpf_core_relo(bytes),
        d::first_members,
    ),
    spec(
        &["iovec[]"],
        "iovec",
        Size::Layout("iovec"),
        l::iovec,
        l::iovec_summary,
    ),
    spec(
        &["epoll_event[]"],
        "epoll_event",
        Size::Layout("epoll_event"),
        l::epoll_event,
        l::epoll_summary,
    ),
    spec(
        &["mmsghdr[]"],
        "mmsghdr",
        Size::Layout("mmsghdr"),
        l::mmsghdr,
        l::mmsg_summary,
    ),
    spec(
        &["u32[]"],
        "u32",
        Size::Fixed(4),
        |_, bytes| d::number(bytes, 4),
        d::value_summary,
    ),
    spec(
        &["u64[]"],
        "u64",
        Size::Fixed(8),
        |_, bytes| d::number(bytes, 8),
        d::value_summary,
    ),
];

pub(super) fn spec_named(layout: &str) -> Option<&'static Spec> {
    SPECS.iter().find(|spec| spec.names.contains(&layout))
}

/// Whether `layout` is a record array.
pub fn is_array(layout: &str) -> bool {
    spec_named(crate::typed_fields::layout_type(layout)).is_some()
}

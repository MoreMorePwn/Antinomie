// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Record arrays read by the member inventory instead of by fixed offsets: the
//! record's size and members come from the ABI's `captured-layout-members.json`,
//! so an `epoll_event` is 12 bytes on x86-64 and 16 on aarch64, and a compat
//! program's `iovec` is its 8-byte one. Records read with the layout decoder
//! ([`crate::typed_fields::layout`]); this file is the rows' summaries.
use super::{Ctx, Record};
use crate::typed_fields::{Decoded, layout};

pub(super) fn iovec(ctx: &Ctx<'_>, bytes: &[u8]) -> Option<Decoded> {
    layout::decode(ctx.abi, "iovec", None, None, bytes)
}

pub(super) fn epoll_event(ctx: &Ctx<'_>, bytes: &[u8]) -> Option<Decoded> {
    layout::decode(ctx.abi, "epoll_event", None, None, bytes)
}

pub(super) fn mmsghdr(ctx: &Ctx<'_>, bytes: &[u8]) -> Option<Decoded> {
    layout::decode(ctx.abi, "mmsghdr", None, None, bytes)
}

fn member(decoded: &Decoded, name: &str) -> String {
    decoded
        .members
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.clone())
        .unwrap_or_default()
}

/// `8 bytes at 0x7ffd1000`.
pub(super) fn iovec_summary(decoded: &Decoded) -> String {
    format!(
        "{} bytes at {}",
        member(decoded, "iov_len"),
        member(decoded, "iov_base")
    )
}

/// `EPOLLIN|EPOLLET data=0x4`.
pub(super) fn epoll_summary(decoded: &Decoded) -> String {
    format!(
        "{} data={}",
        member(decoded, "events"),
        member(decoded, "data")
    )
}

/// `120 bytes in 2 buffers`: what the call moved, and how many buffers it
/// was given.
pub(super) fn mmsg_summary(decoded: &Decoded) -> String {
    let header = decoded
        .nodes()
        .into_iter()
        .find(|node| node.name == "msg_hdr")
        .map(|node| node.children)
        .unwrap_or_default();
    let buffers = header
        .iter()
        .find(|node| node.name == "msg_iovlen")
        .map_or("?", |node| node.text.as_str());
    format!("{} bytes in {buffers} buffers", member(decoded, "msg_len"))
}

/// The number of a record's field.
fn count(record: &Record, name: &str) -> u64 {
    record
        .fields
        .iter()
        .find(|(candidate, _)| candidate == name)
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0)
}

/// `, 15 bytes`: the bytes the buffers hold together.
pub(super) fn iovec_total(records: &[Record]) -> String {
    let bytes: u64 = records.iter().map(|record| count(record, "iov_len")).sum();
    format!(", {bytes} bytes")
}

/// `, 120 bytes`: what the messages moved together.
pub(super) fn mmsg_total(records: &[Record]) -> String {
    let bytes: u64 = records.iter().map(|record| count(record, "msg_len")).sum();
    format!(", {bytes} bytes")
}

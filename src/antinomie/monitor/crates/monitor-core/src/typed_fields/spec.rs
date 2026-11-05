// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! A table-driven reader for the layouts the member inventory does not
//! describe (the AIO and io_uring structures, signal frames, register sets):
//! a layout is a list of members with an offset, a width and how the value
//! reads, and a decode is the list read from the bytes. Members past the
//! captured bytes are left out and the decode is `more`; a group is a nested
//! structure.
use super::{Decoded, Node, Shape, flags, named, pointer};

pub(super) type Table = &'static [(&'static str, u64)];

/// How a member's value is written.
#[derive(Clone, Copy)]
pub(super) enum Show {
    Dec,
    Hex,
    /// An address: `NULL` or hex.
    Ptr,
    Fd,
    Enum(Table),
    Flags(Table),
    /// A signal set of up to 64 signals, `[SIGINT SIGTERM]`.
    SigSet,
    /// A rule of its own.
    Custom(fn(u64) -> String),
}

#[derive(Clone, Copy)]
pub(super) enum Item<'a> {
    Field {
        name: &'static str,
        at: usize,
        width: u8,
        signed: bool,
        show: Show,
    },
    Group(&'static str, &'a [Item<'a>]),
}

pub(super) const fn u8f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 1, false, show)
}
pub(super) const fn u16f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 2, false, show)
}
pub(super) const fn i16f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 2, true, show)
}
pub(super) const fn u32f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 4, false, show)
}
pub(super) const fn i32f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 4, true, show)
}
pub(super) const fn u64f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 8, false, show)
}
pub(super) const fn i64f(name: &'static str, at: usize, show: Show) -> Item<'static> {
    field(name, at, 8, true, show)
}
pub(super) const fn field(
    name: &'static str,
    at: usize,
    width: u8,
    signed: bool,
    show: Show,
) -> Item<'static> {
    Item::Field {
        name,
        at,
        width,
        signed,
        show,
    }
}

/// The unsigned little-endian value of `width` bytes at `at`.
pub(super) fn word(data: &[u8], at: usize, width: usize) -> Option<u64> {
    let bytes = data.get(at..at + width)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |value, byte| value << 8 | u64::from(*byte)),
    )
}

fn sign(value: u64, width: usize) -> i64 {
    let bits = width * 8;
    if bits >= 64 {
        value as i64
    } else {
        ((value << (64 - bits)) as i64) >> (64 - bits)
    }
}

fn show(value: u64, signed: bool, width: usize, how: Show) -> String {
    match how {
        Show::Dec if signed => sign(value, width).to_string(),
        Show::Dec => value.to_string(),
        Show::Hex => format!("{value:#x}"),
        Show::Ptr => pointer(value),
        Show::Fd => {
            let fd = sign(value, width);
            if fd == -100 {
                "AT_FDCWD".into()
            } else {
                fd.to_string()
            }
        }
        Show::Enum(table) => named(value, table),
        Show::Flags(table) => flags(value, table),
        Show::SigSet => super::signals::sigset_text(value),
        Show::Custom(text) => text(value),
    }
}

/// The members of `items` read from `data` as nodes; `cut` is set when a
/// member lay past the bytes.
pub(super) fn nodes(items: &[Item], data: &[u8], cut: &mut bool) -> Vec<Node> {
    let mut out = Vec::new();
    for item in items {
        match *item {
            Item::Field {
                name,
                at,
                width,
                signed,
                show: how,
            } => {
                let Some(value) = word(data, at, usize::from(width)) else {
                    *cut = true;
                    continue;
                };
                out.push(Node::leaf(
                    name,
                    show(value, signed, usize::from(width), how),
                ));
            }
            Item::Group(name, inner) => {
                let children = nodes(inner, data, cut);
                if children.is_empty() {
                    continue;
                }
                out.push(Node {
                    name: name.to_owned(),
                    text: struct_line(&children),
                    children,
                });
            }
        }
    }
    out
}

/// `aa:bb:cc:dd:ee:ff`.
pub(super) fn mac(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub(super) fn struct_line(nodes: &[Node]) -> String {
    let items: Vec<String> = nodes
        .iter()
        .map(|node| format!("{}={}", node.name, node.text))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// A structure decoded from `items`, or None when not even its first member
/// is in the bytes.
pub(super) fn structure(items: &[Item], data: &[u8]) -> Option<Decoded> {
    let mut cut = false;
    let tree = nodes(items, data, &mut cut);
    if tree.is_empty() {
        return None;
    }
    Some(from_nodes(tree, cut))
}

/// A decoded structure whose members are `tree`.
pub(super) fn from_nodes(tree: Vec<Node>, cut: bool) -> Decoded {
    let mut decoded = Decoded::new(Shape::Struct);
    for node in tree {
        let at = decoded.members.len();
        decoded.members.push((node.name.clone(), node.text.clone()));
        if !node.children.is_empty() {
            decoded.children.insert(at, node.children);
        }
    }
    decoded.more = cut;
    decoded
}

/// An array of `stride`-byte records, each read from `items`; the last
/// record may be cut. At most `limit` records are listed.
pub(super) fn records(items: &[Item], stride: usize, data: &[u8], limit: usize) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::List);
    let count = data.len().div_ceil(stride);
    decoded.more = count > limit;
    for chunk in data.chunks(stride).take(limit) {
        let mut cut = false;
        let tree = nodes(items, chunk, &mut cut);
        if tree.is_empty() {
            decoded.more = true;
            break;
        }
        decoded.more |= cut;
        let at = decoded.members.len();
        decoded.members.push((String::new(), struct_line(&tree)));
        decoded.children.insert(at, tree);
    }
    (!decoded.members.is_empty()).then_some(decoded)
}

// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The layout-driven decoder: any captured layout the member inventory
//! (`protocol/<arch>/captured-layout-members.json`) describes is decoded from
//! its members' bit offsets and widths, so one reader serves every structure
//! and array of every architecture and ABI (`epoll_event` is 12 bytes on
//! x86-64 and 16 on aarch64 because the inventories say so).
//!
//! The lookup is (ABI, layout name). The ABI is the one the layout's
//! `linux-6.12.94/<arch>/` prefix names: `x86_64`, `aarch64`, and the compat
//! ABIs `x86` (an i386 program on x86-64) and `arm` (AArch32 on arm64). A
//! 32-bit program's structures are never read with 64-bit offsets: a compat
//! layout the compat inventory does not have is [`compat_gap`], and the views
//! show its bytes with that note.
//!
//! Members come out as a tree: a dotted inventory name (`it_value.tv_sec`)
//! is a nested structure, an indexed one (`val[0]`) an array. Members that
//! hold a known kind of value are named by [`names`]. Reserved and padding
//! members, and single-bit flags that are clear, are left out; members past
//! the captured bytes are left out and the decode is `more`.
use super::{Call, Decoded, Node, Shape, c_string};
use crate::syscalls::{self, Abi};
use serde::Deserialize;
use std::{collections::HashMap, sync::OnceLock};

mod kernel;
pub(super) mod names;
pub(super) mod time;

pub(crate) use kernel::{LSM_ATTR, LSM_FLAGS};

/// Elements of an array one decode lists (the rest is `more`).
const ARRAY_LIMIT: usize = 64;

/// Layouts the views draw by their own rule, never by members.
const NOT_BY_MEMBERS: &[&str] = &["sockaddr"];

// The inventory -----------------------------------------------------------

#[derive(Deserialize)]
struct Inventory {
    layouts: Vec<Entry>,
}
#[derive(Deserialize)]
struct Entry {
    layout: String,
    supported: bool,
    #[serde(default)]
    stride: usize,
    #[serde(default)]
    array: bool,
    array_count: Option<usize>,
    #[serde(default)]
    members: Vec<InventoryMember>,
}
#[derive(Deserialize)]
struct InventoryMember {
    member: String,
    bit_offset: usize,
    bit_size: usize,
    size: usize,
    kind: String,
    signed: bool,
    #[serde(default)]
    pointer: bool,
    #[serde(default)]
    selector: Option<serde_json::Value>,
}

/// A scalar member.
#[derive(Clone, Debug)]
pub(super) struct Leaf {
    pub bit_offset: usize,
    pub bit_size: usize,
    /// Bytes of the member (a text member's whole array).
    pub size: usize,
    pub signed: bool,
    pub pointer: bool,
    pub text: bool,
}

#[derive(Clone, Debug)]
enum Body {
    Leaf(Leaf),
    /// A structure's members.
    Group(Vec<Item>),
    /// An array's elements, named `[0]`, `[1]`.
    Array(Vec<Item>),
}

#[derive(Clone, Debug)]
struct Item {
    name: String,
    body: Body,
}

/// One layout's members as a tree, in offset order.
struct Schema {
    stride: usize,
    array: bool,
    count: Option<usize>,
    /// Members chosen by another argument (`bpf_attr`): not decoded here.
    selectors: bool,
    root: Vec<Item>,
}

enum Segment {
    Name(String),
    Index(usize),
}

/// `a.b[0][1].c` as its segments.
fn segments(member: &str) -> Vec<Segment> {
    let mut out = Vec::new();
    for part in member.split('.') {
        let (name, mut rest) = part.split_once('[').map_or((part, ""), |(n, r)| (n, r));
        out.push(Segment::Name(name.to_owned()));
        while let Some((index, tail)) = rest.split_once(']') {
            out.push(Segment::Index(index.parse().unwrap_or(0)));
            rest = tail.strip_prefix('[').unwrap_or("");
        }
    }
    out
}

fn insert(items: &mut Vec<Item>, path: &[Segment], leaf: Leaf) {
    let name = match &path[0] {
        Segment::Name(name) => name.clone(),
        Segment::Index(index) => format!("[{index}]"),
    };
    let at = match items.iter().position(|item| item.name == name) {
        Some(at) => at,
        None => {
            items.push(Item {
                name,
                body: Body::Group(Vec::new()),
            });
            items.len() - 1
        }
    };
    if path.len() == 1 {
        items[at].body = Body::Leaf(leaf);
        return;
    }
    let item = &mut items[at];
    if !matches!(item.body, Body::Group(_) | Body::Array(_)) {
        item.body = Body::Group(Vec::new());
    }
    let inner = match (&mut item.body, &path[1]) {
        (Body::Group(inner), Segment::Index(_)) if inner.is_empty() => {
            item.body = Body::Array(Vec::new());
            let Body::Array(inner) = &mut item.body else {
                return;
            };
            inner
        }
        (Body::Group(inner) | Body::Array(inner), _) => inner,
        _ => return,
    };
    insert(inner, &path[1..], leaf);
}

fn first_bit(item: &Item) -> usize {
    match &item.body {
        Body::Leaf(leaf) => leaf.bit_offset,
        Body::Group(items) | Body::Array(items) => {
            items.iter().map(first_bit).min().unwrap_or(usize::MAX)
        }
    }
}

fn index_of(name: &str) -> usize {
    name.trim_matches(['[', ']']).parse().unwrap_or(usize::MAX)
}

fn sort(items: &mut [Item]) {
    for item in items.iter_mut() {
        if let Body::Group(inner) | Body::Array(inner) = &mut item.body {
            sort(inner);
        }
    }
    items.sort_by_key(|item| (first_bit(item), index_of(&item.name)));
}

impl Schema {
    fn build(entry: &Entry) -> Self {
        let mut root = Vec::new();
        for member in &entry.members {
            let leaf = Leaf {
                bit_offset: member.bit_offset,
                bit_size: member.bit_size,
                size: member.size,
                signed: member.signed,
                pointer: member.pointer,
                text: member.kind == "text",
            };
            insert(&mut root, &segments(&member.member), leaf);
        }
        sort(&mut root);
        Self {
            stride: entry.stride,
            array: entry.array,
            count: entry.array_count,
            selectors: entry.members.iter().any(|member| member.selector.is_some()),
            root,
        }
    }

    /// A scalar layout: one member named `value`.
    fn scalar(&self) -> Option<&Leaf> {
        match self.root.as_slice() {
            [
                Item {
                    name,
                    body: Body::Leaf(leaf),
                },
            ] if name == "value" => Some(leaf),
            _ => None,
        }
    }
}

type Schemas = HashMap<String, Schema>;

/// The schemas of one ABI's inventory by layout type name; unsupported
/// layouts are absent.
fn schemas(abi: Abi) -> &'static Schemas {
    static CELLS: [OnceLock<Schemas>; 4] = [
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
        OnceLock::new(),
    ];
    let cell = match abi {
        Abi::X86_64 => &CELLS[0],
        Abi::Aarch64 => &CELLS[1],
        Abi::Arm => &CELLS[2],
        Abi::I386 => &CELLS[3],
    };
    cell.get_or_init(|| {
        let inventory: Inventory = serde_json::from_str(syscalls::arch::captured_layouts_json(abi))
            .expect("invalid compiled captured member inventory");
        inventory
            .layouts
            .iter()
            .filter(|entry| entry.supported)
            .map(|entry| {
                let name = super::layout_type(&entry.layout).to_owned();
                (name, Schema::build(entry))
            })
            .collect()
    })
}

/// The ABI a layout name's `linux-6.12.94/<arch>/` source selects. A layout
/// with no source (a type name alone) is the native x86-64 one; None for a
/// source this host has no inventory for.
pub fn abi_of_layout(layout: &str) -> Option<Abi> {
    let mut parts = layout.rsplit('/');
    let _name = parts.next();
    match parts.next() {
        None => Some(Abi::X86_64),
        Some("x86_64") => Some(Abi::X86_64),
        Some("aarch64") => Some(Abi::Aarch64),
        Some("x86") => Some(Abi::I386),
        Some("arm") => Some(Abi::Arm),
        Some(_) => None,
    }
}

/// Whether an ABI is a compat one (32-bit programs on a 64-bit kernel).
pub(super) fn is_compat(abi: Abi) -> bool {
    matches!(abi, Abi::Arm | Abi::I386)
}

/// The size of one element of a layout on an ABI (an array's stride, a
/// structure's size), from the inventory.
pub(super) fn stride(abi: Abi, layout: &str) -> Option<usize> {
    let schema = schemas(abi).get(layout)?;
    (schema.stride > 0).then_some(schema.stride)
}

/// Why a compat field has no decode: the compat inventory lacks its layout
/// (or no decoder reads it), so its 32-bit bytes are shown undecoded rather
/// than read with 64-bit offsets. None for a native field, a field that
/// decodes, and the layouts the views draw as text.
pub fn compat_gap(field: &crate::FieldSummary) -> Option<String> {
    let abi = abi_of_layout(&field.layout)?;
    let layout = super::layout_type(&field.layout);
    if !is_compat(abi)
        || layout.is_empty()
        || layout.starts_with("char[")
        || layout == "mount_options"
        || NOT_BY_MEMBERS.contains(&layout)
        || super::decode(None, field).is_some()
    {
        return None;
    }
    Some(format!(
        "No compat layout: the {} (32-bit) layout of {layout} is not in the member inventory, \
         so its bytes are shown undecoded.",
        match abi {
            Abi::Arm => "AArch32",
            _ => "i386",
        }
    ))
}

// Reading members ---------------------------------------------------------

/// What the decode knows about the field it reads.
pub(super) struct Cx<'a> {
    pub abi: Abi,
    /// The layout's type name (`timespec`).
    pub layout: &'a str,
    pub time: time::TimeKind,
}

/// A member's value, read from the bytes.
pub(super) struct Raw {
    pub value: u64,
    pub signed: i64,
    pub leaf: Leaf,
}

/// `bits` bits of `data` from bit `at`, little-endian; None past the bytes.
fn bits(data: &[u8], at: usize, bits: usize) -> Option<u64> {
    if bits == 0 || bits > 64 {
        return None;
    }
    let first = at / 8;
    let last = (at + bits).div_ceil(8);
    let bytes = data.get(first..last)?;
    let mut wide = 0u128;
    for (index, byte) in bytes.iter().enumerate() {
        wide |= u128::from(*byte) << (8 * index);
    }
    let wide = wide >> (at % 8);
    let mask = if bits == 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    Some(wide as u64 & mask)
}

fn read(leaf: &Leaf, data: &[u8]) -> Option<Raw> {
    let value = bits(data, leaf.bit_offset, leaf.bit_size)?;
    let signed = if leaf.bit_size < 64 && value >> (leaf.bit_size - 1) & 1 == 1 {
        (value | (u64::MAX << leaf.bit_size)) as i64
    } else {
        value as i64
    };
    Some(Raw {
        value,
        signed,
        leaf: leaf.clone(),
    })
}

/// Members that are padding or reserved space, never shown.
fn is_padding(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with('_')
        || lower.contains("pad")
        || lower.contains("spare")
        || lower.contains("reserved")
}

struct Walk<'a> {
    cx: &'a Cx<'a>,
    /// A member lay past the bytes.
    cut: bool,
}

impl Walk<'_> {
    fn nodes(&mut self, items: &[Item], data: &[u8], path: &str) -> Vec<Node> {
        let mut nodes = Vec::new();
        for item in items {
            if item.name.starts_with('[') {
                // array elements are never padding by name
            } else if is_padding(&item.name) {
                continue;
            }
            let here = if path.is_empty() || item.name.starts_with('[') {
                format!("{path}{}", item.name)
            } else {
                format!("{path}.{}", item.name)
            };
            match &item.body {
                Body::Leaf(leaf) => {
                    let Some(raw) = (if leaf.text {
                        (data.len() > leaf.bit_offset / 8).then(|| Raw {
                            value: 0,
                            signed: 0,
                            leaf: leaf.clone(),
                        })
                    } else {
                        read(leaf, data)
                    }) else {
                        self.cut = true;
                        continue;
                    };
                    if leaf.bit_size == 1 && raw.value == 0 {
                        continue;
                    }
                    let text = if leaf.text {
                        let from = leaf.bit_offset / 8;
                        c_string(&data[from..data.len().min(from + leaf.size)])
                    } else {
                        names::leaf(self.cx, &here, &raw)
                    };
                    nodes.push(Node::leaf(item.name.clone(), text));
                }
                Body::Group(inner) => {
                    let children = self.nodes(inner, data, &here);
                    if children.is_empty() {
                        continue;
                    }
                    // `sigset_t { unsigned long sig[1]; }` is one value.
                    if let [only] = children.as_slice()
                        && only.name == "sig"
                        && let [word] = only.children.as_slice()
                    {
                        nodes.push(Node::leaf(item.name.clone(), word.text.clone()));
                        continue;
                    }
                    let text = names::group(self.cx, &here, &children)
                        .unwrap_or_else(|| struct_line(&children));
                    nodes.push(Node {
                        name: item.name.clone(),
                        text,
                        children,
                    });
                }
                Body::Array(inner) => {
                    let children = self.nodes(inner, data, &here);
                    if children.is_empty() {
                        continue;
                    }
                    let texts: Vec<&str> = children.iter().map(|node| node.text.as_str()).collect();
                    let text = format!("[{}]", texts.join(", "));
                    nodes.push(Node {
                        name: item.name.clone(),
                        text,
                        children,
                    });
                }
            }
        }
        nodes
    }
}

fn struct_line(nodes: &[Node]) -> String {
    let items: Vec<String> = nodes
        .iter()
        .map(|node| format!("{}={}", node.name, node.text))
        .collect();
    format!("{{{}}}", items.join(", "))
}

/// One element of a layout decoded: its tree and its one line (a time
/// structure as its time, a scalar as its value). `cut` when members lay past
/// the bytes.
fn element(cx: &Cx<'_>, schema: &Schema, data: &[u8]) -> Option<(String, Vec<Node>, bool)> {
    if let Some(leaf) = schema.scalar() {
        let raw = read(leaf, data)?;
        return Some((names::leaf(cx, "value", &raw), Vec::new(), false));
    }
    let mut walk = Walk { cx, cut: false };
    let mut nodes = walk.nodes(&schema.root, data, "");
    kernel::refine(cx.layout, &mut nodes, data);
    if nodes.is_empty() {
        return None;
    }
    let text = names::summary(cx, &nodes).unwrap_or_else(|| struct_line(&nodes));
    Some((text, nodes, walk.cut))
}

/// `layout` (a type name) read from `data` as `abi`'s inventory lays it out.
/// None when the ABI's inventory has no such layout, the layout is one the
/// views draw by their own rule, or the bytes hold not one member.
pub(super) fn decode(
    abi: Abi,
    layout: &str,
    call: Option<&Call<'_>>,
    arg: Option<usize>,
    data: &[u8],
) -> Option<Decoded> {
    if NOT_BY_MEMBERS.contains(&layout) || layout.is_empty() {
        return None;
    }
    let schema = schemas(abi).get(layout)?;
    if schema.selectors {
        return None;
    }
    let cx = Cx {
        abi,
        layout,
        time: names::time_kind(call, arg),
    };
    if schema.array {
        let stride = schema.stride;
        if stride == 0 {
            return None;
        }
        let mut count = data.len().div_ceil(stride);
        if let Some(fixed) = schema.count {
            count = count.min(fixed);
        }
        let mut decoded = Decoded::new(Shape::List);
        decoded.more = count > ARRAY_LIMIT;
        for index in 0..count.min(ARRAY_LIMIT) {
            let bytes = &data[index * stride..data.len().min((index + 1) * stride)];
            let Some((text, nodes, cut)) = element(&cx, schema, bytes) else {
                decoded.more = true;
                break;
            };
            decoded.more |= cut;
            let at = decoded.members.len();
            decoded.push("", text);
            if !nodes.is_empty() {
                decoded.children.insert(at, nodes);
            }
        }
        return (!decoded.members.is_empty()).then_some(decoded);
    }
    let (text, nodes, cut) = element(&cx, schema, data)?;
    let mut decoded = if schema.scalar().is_some() || names::summary_layout(layout) {
        let mut value = Decoded::value(text);
        if !nodes.is_empty() {
            value.children.insert(0, nodes);
        }
        value
    } else {
        let mut structure = Decoded::new(Shape::Struct);
        for node in nodes {
            let at = structure.members.len();
            structure
                .members
                .push((node.name.clone(), node.text.clone()));
            if !node.children.is_empty() {
                structure.children.insert(at, node.children);
            }
        }
        structure
    };
    decoded.more = cut;
    Some(decoded)
}

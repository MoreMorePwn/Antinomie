// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Typed members of retained Linux 6.12.94 native x86-64 captured arguments.
//!
//! The compiled JSON contains compiler-derived offsets, scalar widths, signedness
//! and source hashes. Decoding reads owned previews only, never raw files or guest
//! pointers. A member is missing when its layout, selector, range or phase is
//! unsupported or ambiguous. Metadata describes the observed field, not an
//! inferred syscall outcome.
use crate::{FieldSummary, InvocationSummary, syscalls};
use serde::Deserialize;
use std::{collections::BTreeMap, sync::OnceLock};

/// Type supplied to filter validation and completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    Integer,
    Text,
    Boolean,
}

/// Exact owned filter value. Missing is separate from zero, false or empty text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemberValue {
    Integer(i128),
    Text(String),
    Boolean(bool),
    Missing,
}

/// One registered args.<actual native argument>.<member> filter keyword.
/// Latest applicable captured phase wins; conflicts in that phase stay missing.
/// Layout applicability is qualified by native syscall number and argument slot.
#[derive(Clone, Debug)]
pub struct MemberDescriptor {
    pub name: String,
    pub kind: MemberKind,
    pub detail: String,
    pub layouts: Vec<String>,
}

#[derive(Deserialize)]
struct Inventory {
    metadata_members: Vec<MetadataMember>,
    layouts: Vec<Layout>,
}
#[derive(Deserialize)]
struct MetadataMember {
    member: String,
    kind: String,
    detail: String,
}
#[derive(Deserialize)]
struct Layout {
    layout: String,
    supported: bool,
    #[serde(default)]
    stride: u64,
    #[serde(default)]
    array: bool,
    array_count: Option<usize>,
    #[serde(default)]
    members: Vec<Member>,
    #[serde(default)]
    arguments: Vec<Argument>,
}
#[derive(Deserialize)]
struct Argument {
    syscall_number: u64,
    argument_index: usize,
    name: String,
}
#[derive(Deserialize)]
struct Member {
    member: String,
    bit_offset: u64,
    bit_size: u64,
    size: u64,
    kind: String,
    signed: bool,
    #[serde(default)]
    pointer: bool,
    selector: Option<Selector>,
}
#[derive(Deserialize)]
struct Selector {
    argument_index: usize,
    values: Vec<u64>,
    syscall_numbers: Vec<u64>,
}

fn inventory() -> &'static Inventory {
    static INVENTORY: OnceLock<Inventory> = OnceLock::new();
    INVENTORY.get_or_init(|| {
        // Generated compiled input is validated by tests and the generator.
        serde_json::from_str(include_str!(
            "../../../protocol/captured-layout-members.json"
        ))
        .expect("invalid compiled captured member inventory")
    })
}
fn kind(text: &str) -> MemberKind {
    match text {
        "text" => MemberKind::Text,
        "boolean" => MemberKind::Boolean,
        _ => MemberKind::Integer,
    }
}

/// Complete compiled keyword registry, including capture metadata for every
/// native argument name and indexed patterns for structured arrays. The first
/// 64 indices are completion examples; arbitrary retained indices decode through
/// the pattern with checked arithmetic and the actual capture extent.
pub fn registry() -> &'static [MemberDescriptor] {
    static REGISTRY: OnceLock<Vec<MemberDescriptor>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut values: BTreeMap<String, MemberDescriptor> = BTreeMap::new();
        for syscall in syscalls::all() {
            for argument in &syscall.arguments {
                for metadata in &inventory().metadata_members {
                    let name = format!("args.{}.{}", argument.name, metadata.member);
                    values.entry(name.clone()).or_insert_with(|| MemberDescriptor {
                        name, kind: kind(&metadata.kind),
                        detail: format!("{}; latest uniquely applicable captured phase, missing without captured argument", metadata.detail),
                        layouts: Vec::new(),
                    });
                }
            }
        }
        for layout in &inventory().layouts {
            if !layout.supported { continue; }
            let count = if layout.array { layout.array_count.unwrap_or(64).min(64) } else { 1 };
            for argument in &layout.arguments {
                if layout.array && layout.array_count.is_none() {
                    for member in &layout.members {
                        let name = format!("args.{}[].{}", argument.name, member.member);
                        let descriptor = values.entry(name.clone()).or_insert_with(|| MemberDescriptor {
                            name, kind: kind(&member.kind),
                            detail: format!("Indexed {} member: replace [] with any nonnegative decimal index. Only captured elements exist; checked index/extent, exact native layout and latest unique phase",
                                member.member),
                            layouts: Vec::new(),
                        });
                        if !descriptor.layouts.contains(&layout.layout) {
                            descriptor.layouts.push(layout.layout.clone());
                        }
                    }
                }
                for index in 0..count {
                    for member in &layout.members {
                        let member_name = if layout.array {
                            format!("[{index}].{}", member.member)
                        } else { member.member.clone() };
                        let name = if layout.array {
                            format!("args.{}{member_name}", argument.name)
                        } else { format!("args.{}.{member_name}", argument.name) };
                        let descriptor = values.entry(name.clone()).or_insert_with(|| MemberDescriptor {
                            name, kind: kind(&member.kind),
                            detail: format!("Recorded {}; {}-bit {}; {}. Native syscall/slot, exact layout and selector required; latest unique captured phase; missing on partial range",
                                member.member, member.bit_size, if member.signed { "signed" } else { "unsigned" },
                                if member.pointer { "observed address only, never dereferenced" } else { "captured value" }),
                            layouts: Vec::new(),
                        });
                        // Incompatible reuse of one argument/member name must not
                        // give the validator a misleading type.
                        if descriptor.kind != kind(&member.kind) { continue; }
                        if !descriptor.layouts.contains(&layout.layout) {
                            descriptor.layouts.push(layout.layout.clone());
                        }
                    }
                }
            }
        }
        values.into_values().collect()
    })
}

/// Exact keyword lookup. Unknown keywords stay unknown for parser validation.
pub fn descriptor(name: &str) -> Option<&'static MemberDescriptor> {
    let entries = registry();
    let exact = entries
        .binary_search_by(|entry| entry.name.as_str().cmp(name))
        .ok()
        .map(|index| &entries[index]);
    if exact.is_some() {
        return exact;
    }
    let (before, rest) = name.split_once('[')?;
    let (index, after) = rest.split_once(']')?;
    if index.is_empty()
        || index.len() > 20
        || !index.bytes().all(|byte| byte.is_ascii_digit())
        || index.parse::<u64>().is_err()
        || !after.starts_with('.')
    {
        return None;
    }
    let pattern = format!("{before}[]{after}");
    entries
        .binary_search_by(|entry| entry.name.as_str().cmp(&pattern))
        .ok()
        .map(|index| &entries[index])
}

/// Decode the latest phase uniquely supplying this member. Multiple conflicting
/// matching fields in one event are ambiguous and return Missing. A partial later
/// field does not silently fall back to a previous complete value.
pub fn decode(invocation: &InvocationSummary, name: &str) -> MemberValue {
    if descriptor(name).is_none() {
        return MemberValue::Missing;
    }
    let Some(rest) = name.strip_prefix("args.") else {
        return MemberValue::Missing;
    };
    let Some(event) = invocation
        .entry
        .as_ref()
        .or(invocation.exit.as_ref())
        .or_else(|| invocation.async_events.first())
    else {
        return MemberValue::Missing;
    };
    let Some(syscall) = syscalls::syscall(event.syscall_nr) else {
        return MemberValue::Missing;
    };
    let Some((index, member)) =
        syscall
            .arguments
            .iter()
            .enumerate()
            .find_map(|(index, argument)| {
                rest.strip_prefix(&argument.name).and_then(|suffix| {
                    if let Some(member) = suffix.strip_prefix('.') {
                        Some((index, member))
                    } else if suffix.starts_with('[') {
                        Some((index, suffix))
                    } else {
                        None
                    }
                })
            })
    else {
        return MemberValue::Missing;
    };
    let args = invocation
        .entry
        .as_ref()
        .and_then(|event| event.args)
        .or_else(|| invocation.exit.as_ref().and_then(|event| event.args));
    let mut events = invocation
        .entry
        .iter()
        .chain(invocation.exit.iter())
        .chain(invocation.async_events.iter())
        .collect::<Vec<_>>();
    events.sort_by_key(|event| (event.phase, event.event_seq));
    for event in events.into_iter().rev() {
        let prefix = format!("arg{index}.");
        let candidates = event
            .fields
            .iter()
            .filter(|field| {
                field.key.starts_with(&prefix) && applicable(event.syscall_nr, index, field, member)
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            continue;
        }
        let mut value = None;
        for field in candidates {
            let decoded = decode_field_inner(event.syscall_nr, index, field, member, args);
            match &value {
                None => value = Some(decoded),
                Some(previous) if previous == &decoded => {}
                Some(_) => return MemberValue::Missing,
            }
        }
        return value.unwrap_or(MemberValue::Missing);
    }
    MemberValue::Missing
}

/// Decode a specified captured phase/argument without syscall scalar selectors.
/// Selector-dependent union members return Missing; use decode(invocation, name)
/// to supply the invocation's recorded selector words.
pub fn decode_field(
    syscall_number: u64,
    argument_index: usize,
    field: &FieldSummary,
    member: &str,
) -> MemberValue {
    decode_field_inner(syscall_number, argument_index, field, member, None)
}

fn metadata(field: &FieldSummary, member: &str) -> Option<MemberValue> {
    Some(match member {
        "complete" => MemberValue::Boolean(field.complete),
        "captured_size" => MemberValue::Integer(i128::from(field.captured_len)),
        "expected_size" => field.logical_len.map_or(MemberValue::Missing, |size| {
            MemberValue::Integer(i128::from(size))
        }),
        "status" => field.status.map_or(MemberValue::Missing, |status| {
            MemberValue::Integer(i128::from(status))
        }),
        "capture_error" => MemberValue::Integer(i128::from(field.capture_error)),
        "layout" => MemberValue::Text(field.layout.clone()),
        _ => return None,
    })
}

fn layout(field: &FieldSummary, nr: u64, index: usize) -> Option<&'static Layout> {
    inventory().layouts.iter().find(|layout| {
        layout.supported
            && layout.layout == field.layout
            && layout
                .arguments
                .iter()
                .any(|argument| argument.syscall_number == nr && argument.argument_index == index)
    })
}

fn member_extent<'a>(layout: &'a Layout, name: &str) -> Option<(&'a Member, u64)> {
    let (name, array_offset) = if layout.array {
        let suffix = name.strip_prefix('[')?;
        let (index, rest) = suffix.split_once("].")?;
        let index = index.parse::<usize>().ok()?;
        if layout.array_count.is_some_and(|count| index >= count) {
            return None;
        }
        (rest, layout.stride.checked_mul(u64::try_from(index).ok()?)?)
    } else {
        (name, 0)
    };
    layout
        .members
        .iter()
        .find(|member| member.member == name)
        .map(|member| (member, array_offset))
}

fn applicable(nr: u64, index: usize, field: &FieldSummary, member: &str) -> bool {
    if metadata(field, member).is_some() {
        // Argument metadata refers to the top-level captured argument, never
        // arbitrary nested buffers of the same syscall argument.
        return field.key.split('.').count() == 2;
    }
    layout(field, nr, index)
        .and_then(|layout| member_extent(layout, member))
        .is_some()
}

fn decode_field_inner(
    nr: u64,
    index: usize,
    field: &FieldSummary,
    name: &str,
    args: Option<[u64; 6]>,
) -> MemberValue {
    let prefix = format!("arg{index}.");
    if !field.key.starts_with(&prefix) {
        return MemberValue::Missing;
    }
    if syscalls::syscall(nr).is_none_or(|syscall| index >= syscall.arguments.len()) {
        return MemberValue::Missing;
    }
    if let Some(value) = metadata(field, name) {
        return if field.key.split('.').count() == 2 {
            value
        } else {
            MemberValue::Missing
        };
    }
    let Some(layout) = layout(field, nr, index) else {
        return MemberValue::Missing;
    };
    let Some((member, array_offset)) = member_extent(layout, name) else {
        return MemberValue::Missing;
    };
    if let Some(selector) = &member.selector
        && (!selector.syscall_numbers.contains(&nr)
            || args
                .and_then(|args| args.get(selector.argument_index).copied())
                .is_none_or(|value| !selector.values.contains(&value)))
    {
        return MemberValue::Missing;
    }
    let Some(bit_offset) = array_offset
        .checked_mul(8)
        .and_then(|offset| offset.checked_add(member.bit_offset))
    else {
        return MemberValue::Missing;
    };
    if member.bit_size == 0 || member.bit_size > 64 && member.kind != "text" {
        return MemberValue::Missing;
    }
    let start = bit_offset / 8;
    let Some(end) = bit_offset
        .checked_add(member.bit_size)
        .and_then(|bits| bits.checked_add(7))
        .map(|bits| bits / 8)
    else {
        return MemberValue::Missing;
    };
    let Some(bytes) = covered(field, start, end) else {
        return MemberValue::Missing;
    };
    if member.kind == "text" {
        if bit_offset % 8 != 0 || member.bit_size % 8 != 0 {
            return MemberValue::Missing;
        }
        let len = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        return std::str::from_utf8(&bytes[..len])
            .map_or(MemberValue::Missing, |text| MemberValue::Text(text.into()));
    }
    if member.size == 0 || member.size > 8 {
        return MemberValue::Missing;
    }
    let mut value = 0u128;
    for (index, byte) in bytes.iter().enumerate() {
        value |= u128::from(*byte) << (index * 8);
    }
    value >>= bit_offset % 8;
    value &= (1u128 << member.bit_size) - 1;
    let signed = if member.signed && value & (1u128 << (member.bit_size - 1)) != 0 {
        (value as i128) - (1i128 << member.bit_size)
    } else {
        value as i128
    };
    MemberValue::Integer(signed)
}

/// The preview is a contiguous prefix. Every requested byte also needs explicit
/// observed coverage; old incomplete previews without ranges cannot fill gaps.
fn covered(field: &FieldSummary, start: u64, end: u64) -> Option<&[u8]> {
    if end <= start || end > field.captured_len || end > field.logical_len.unwrap_or(u64::MAX) {
        return None;
    }
    let mut ranges = field.ranges.clone();
    ranges.sort_unstable();
    let mut position = start;
    for (offset, len) in ranges {
        let range_end = offset.checked_add(len)?;
        if offset <= position && range_end > position {
            position = range_end.min(end);
        }
        if position == end {
            break;
        }
        if offset > position {
            return None;
        }
    }
    if position != end && !(field.ranges.is_empty() && field.complete) {
        return None;
    }
    field
        .preview
        .get(usize::try_from(start).ok()?..usize::try_from(end).ok()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EventSummary;
    fn invocation(nr: u64, args: [u64; 6], field: FieldSummary) -> InvocationSummary {
        InvocationSummary {
            stream_id: 1,
            task_cookie: 1,
            call_id: 1,
            entry: Some(EventSummary {
                root_task_cookie: 1,
                stream_id: 1,
                task_cookie: 1,
                call_id: 1,
                event_seq: 1,
                phase: 1,
                syscall_nr: nr,
                syscall_name: syscalls::name(nr),
                pid: 1,
                tid: 1,
                cpu: 0,
                timestamp_ns: 1,
                args: Some(args),
                result: None,
                complete: true,
                issues: Vec::new(),
                fields: vec![field],
            }),
            exit: None,
            async_events: Vec::new(),
            async_saved: 0,
            task_exit: None,
            kernel_notes: Vec::new(),
        }
    }
    #[test]
    fn phase_ownership_rejects_conflicts_and_does_not_fall_back_after_a_partial_update() {
        let mut first = field("timespec", 16);
        first.key = "arg0.data".into();
        first.preview[..8].copy_from_slice(&8i64.to_le_bytes());
        let mut row = invocation(35, [0; 6], first.clone());
        assert_eq!(decode(&row, "args.rqtp.tv_sec"), MemberValue::Integer(8));
        // nanosleep arg0 has no exit field; the entry remains authoritative.
        let mut unrelated = row.entry.as_ref().unwrap().clone();
        unrelated.phase = 2;
        unrelated.fields[0].key = "arg1.data".into();
        row.exit = Some(unrelated);
        assert_eq!(decode(&row, "args.rqtp.tv_sec"), MemberValue::Integer(8));
        let mut second = first.clone();
        second.preview[..8].copy_from_slice(&9i64.to_le_bytes());
        row.entry.as_mut().unwrap().fields.push(second);
        assert_eq!(decode(&row, "args.rqtp.tv_sec"), MemberValue::Missing);
        let mut data = field("timex", 208);
        data.key = "arg0.data".into();
        let mut row = invocation(159, [0; 6], data);
        let mut exit = row.entry.as_ref().unwrap().clone();
        exit.phase = 2;
        exit.fields[0].complete = false;
        exit.fields[0].preview.clear();
        exit.fields[0].ranges.clear();
        row.exit = Some(exit);
        assert_eq!(decode(&row, "args.txc_p.modes"), MemberValue::Missing);
    }
    #[test]
    fn bpf_union_member_requires_exact_recorded_command_and_pointer_members_stay_addresses() {
        let mut attr = field("bpf_attr", 152);
        attr.key = "arg1.attr".into();
        attr.preview[4..8].copy_from_slice(&30u32.to_le_bytes());
        attr.preview[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut row = invocation(321, [5, 0, 152, 0, 0, 0], attr.clone());
        assert_eq!(decode(&row, "args.attr.insn_cnt"), MemberValue::Integer(30));
        assert_eq!(
            decode(&row, "args.attr.insns"),
            MemberValue::Integer(i128::from(u64::MAX))
        );
        assert_eq!(
            decode(&row, "args.attr.attach_bpf_fd"),
            MemberValue::Missing
        );
        assert_eq!(
            decode_field(321, 1, &attr, "insn_cnt"),
            MemberValue::Missing
        );
        row.entry.as_mut().unwrap().args.as_mut().unwrap()[0] = 8;
        assert_eq!(decode(&row, "args.attr.insn_cnt"), MemberValue::Missing);
        assert_eq!(
            decode(&row, "args.attr.attach_bpf_fd"),
            MemberValue::Integer(30)
        );
        row.entry.as_mut().unwrap().args = None;
        assert_eq!(
            decode(&row, "args.attr.attach_bpf_fd"),
            MemberValue::Missing
        );
        let mut program = field("sock_fprog", 16);
        program.key = "arg3.optval".into();
        program.preview[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_field(54, 3, &program, "filter"),
            MemberValue::Integer(i128::from(u64::MAX))
        );
    }
    #[test]
    fn packed_epoll_and_bitfield_layouts_use_compiler_offsets() {
        let mut event = field("epoll_event", 12);
        event.key = "arg3.event".into();
        event.preview[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(
            decode_field(233, 3, &event, "data"),
            MemberValue::Integer(i128::from(u64::MAX))
        );
        let mut user = field("user_desc", 16);
        user.key = "arg1.ldt_entry".into();
        user.preview[12] = 1;
        assert_eq!(
            decode_field(154, 1, &user, "seg_32bit"),
            MemberValue::Integer(1)
        );
        assert_eq!(
            decode_field(154, 1, &user, "contents"),
            MemberValue::Integer(0)
        );
    }
    #[test]
    fn arbitrary_retained_array_indices_use_pattern_registry_without_unbounded_allocation() {
        let mut vectors = field("iovec[]", 16 * 66);
        vectors.key = "arg1.iov".into();
        vectors.preview[16 * 65..16 * 65 + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        let row = invocation(19, [0; 6], vectors);
        assert!(descriptor("args.vec[65].iov_base").is_some());
        assert_eq!(
            decode(&row, "args.vec[65].iov_base"),
            MemberValue::Integer(i128::from(u64::MAX))
        );
        assert_eq!(decode(&row, "args.vec[66].iov_base"), MemberValue::Missing);
        assert_eq!(
            decode(&row, "args.vec[18446744073709551615].iov_base"),
            MemberValue::Missing
        );
        assert!(descriptor("args.vec[18446744073709551616].iov_base").is_none());
        assert!(descriptor("args.vec[-1].iov_base").is_none());
    }
    fn field(layout: &str, size: usize) -> FieldSummary {
        FieldSummary {
            arg: None,
            object_id: 1,
            key: "arg2.data".into(),
            layout: format!("linux-6.12.94/x86_64/{layout}"),
            logical_len: Some(size as u64),
            captured_len: size as u64,
            status: Some(0),
            capture_error: 0,
            complete: true,
            preview: vec![0; size],
            raw_path: None,
            ranges: vec![(0, size as u64)],
            recapture: None,
            encoding: None,
        }
    }
    #[test]
    fn open_how_offsets_are_pinned_and_u64_is_exact() {
        let mut data = field("open_how", 24);
        data.preview[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        data.preview[8..16].copy_from_slice(&0o700u64.to_le_bytes());
        data.preview[16..24].copy_from_slice(&0x1234u64.to_le_bytes());
        assert_eq!(
            decode_field(437, 2, &data, "flags"),
            MemberValue::Integer(i128::from(u64::MAX))
        );
        assert_eq!(
            decode_field(437, 2, &data, "mode"),
            MemberValue::Integer(0o700)
        );
        assert_eq!(
            decode_field(437, 2, &data, "resolve"),
            MemberValue::Integer(0x1234)
        );
        assert!(descriptor("args.how.flags").is_some());
        assert!(descriptor("args.how.complete").is_some());
        assert_eq!(decode_field(9, 2, &data, "flags"), MemberValue::Missing);
    }
    #[test]
    fn partial_ranges_never_read_holes_or_zero_extend_missing_members() {
        let mut data = field("open_how", 24);
        data.complete = false;
        data.ranges = vec![(0, 8), (16, 8)];
        assert_eq!(
            decode_field(437, 2, &data, "flags"),
            MemberValue::Integer(0)
        );
        assert_eq!(decode_field(437, 2, &data, "mode"), MemberValue::Missing);
        data.preview.truncate(12);
        assert_eq!(decode_field(437, 2, &data, "resolve"), MemberValue::Missing);
        data.key = "arg20.data".into();
        assert_eq!(decode_field(437, 2, &data, "flags"), MemberValue::Missing);
    }
    #[test]
    fn scalar_metadata_survives_unknown_layout_without_guessing_members() {
        let mut data = field("unknown", 8);
        data.complete = false;
        data.logical_len = None;
        data.status = None;
        data.capture_error = -14;
        assert_eq!(
            decode_field(437, 2, &data, "expected_size"),
            MemberValue::Missing
        );
        assert_eq!(decode_field(437, 2, &data, "status"), MemberValue::Missing);
        assert_eq!(
            decode_field(437, 2, &data, "capture_error"),
            MemberValue::Integer(-14)
        );
        assert_eq!(
            decode_field(437, 2, &data, "complete"),
            MemberValue::Boolean(false)
        );
        assert_eq!(decode_field(437, 2, &data, "flags"), MemberValue::Missing);
    }
    #[test]
    fn signed_timespec_and_array_members_keep_exact_native_width() {
        let mut data = field("timespec", 16);
        data.key = "arg0.data".into();
        data.preview[..8].copy_from_slice(&(-9i64).to_le_bytes());
        assert_eq!(
            decode_field(35, 0, &data, "tv_sec"),
            MemberValue::Integer(-9)
        );
        let mut pair = field("timespec[2]", 32);
        pair.preview[16..24].copy_from_slice(&(-1i64).to_le_bytes());
        assert_eq!(
            decode_field(280, 2, &pair, "[1].tv_sec"),
            MemberValue::Integer(-1)
        );
        assert_eq!(
            decode_field(280, 2, &pair, "[2].tv_sec"),
            MemberValue::Missing
        );
    }
    #[test]
    fn registry_covers_all_arguments_and_qualified_layouts() {
        let entries = registry();
        assert!(entries.windows(2).all(|pair| pair[0].name < pair[1].name));
        for syscall in syscalls::all() {
            for argument in &syscall.arguments {
                assert!(descriptor(&format!("args.{}.captured_size", argument.name)).is_some());
            }
        }
        assert!(descriptor("args.attr.insn_cnt").is_some());
        assert!(descriptor("args.uargs.flags").is_some());
    }
}

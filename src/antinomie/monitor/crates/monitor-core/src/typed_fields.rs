// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Captured fields decoded by the native layout their descriptor names: a
//! signal set as signal names, a `siginfo_t` by the union branch its
//! `si_code` selects, a `union bpf_attr` by the command that passed it, a
//! directory listing as its entries, and so on. The Syscall Trace view shows
//! these instead of the bytes; Triage reads the BPF members from here.
//!
//! Decoding reads a field's owned preview (its first 256 captured bytes) at
//! explicit little-endian offsets of the 64-bit Linux 6.12.94 UAPI layouts; it
//! never trusts a length or count inside the data beyond the bytes present,
//! and never follows a pointer: a pointer member is shown as the address the
//! program passed. Members past the captured bytes are left out, and
//! [`Decoded::more`] says when the field holds more than was decoded.
//!
//! Only the layouts listed in [`decode`] are decoded; any other field is left
//! to the views' byte rendering. Reserved and padding members are not shown.
use crate::FieldSummary;

mod bpf;
mod records;
mod signals;
#[cfg(test)]
mod tests;

pub use bpf::{attach_type_name, attr_member as bpf_attr_member, map_type_name, prog_type_name};
pub use signals::signal_name;

/// The call a field belongs to: the decoders that depend on another argument
/// (bpf's command, a capability header's syscall) read it from here.
#[derive(Clone, Copy, Debug)]
pub struct Call<'a> {
    /// The syscall's name in the native table (`bpf`, `capget`).
    pub name: &'a str,
    /// The call's register arguments, when recorded.
    pub args: Option<[u64; 6]>,
}

/// How a decoded field reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// One value: a number or a name (`1000`, `_LINUX_CAPABILITY_VERSION_3`).
    Value,
    /// A structure's members, `{name=value, ...}`.
    Struct,
    /// An array's elements, `[a, b]`.
    List,
    /// A set of names, `[SIGINT SIGTERM]` (or `~[...]`, all but these).
    Set,
}

/// A field decoded by its layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub shape: Shape,
    /// Members in order as (name, value). A list's elements and a set's names
    /// have an empty name; a value has one member.
    pub members: Vec<(String, String)>,
    /// The field holds more than was decoded: the preview ended, or the
    /// capture is partial, or a record did not fit.
    pub more: bool,
    /// For a [`Shape::Set`], the names are the members *not* in the set.
    pub complement: bool,
}

/// One-line forms longer than this are cut with `...`.
const LINE_MAX: usize = 240;

impl Decoded {
    fn new(shape: Shape) -> Self {
        Self {
            shape,
            members: Vec::new(),
            more: false,
            complement: false,
        }
    }

    fn value(text: impl Into<String>) -> Self {
        let mut decoded = Self::new(Shape::Value);
        decoded.members.push((String::new(), text.into()));
        decoded
    }

    fn push(&mut self, name: &str, value: impl Into<String>) {
        self.members.push((name.to_owned(), value.into()));
    }

    /// The whole decode on one line, never cut: `{a=1, b=2}`, `[1, 2]`,
    /// `[SIGINT SIGTERM]`, a value as is; `...` marks more data.
    pub fn full_line(&self) -> String {
        let more = if self.more { ", ..." } else { "" };
        match self.shape {
            Shape::Value => self
                .members
                .first()
                .map_or_else(String::new, |(_, value)| value.clone()),
            Shape::Struct => {
                let items: Vec<String> = self
                    .members
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect();
                format!("{{{}{more}}}", items.join(", "))
            }
            Shape::List => {
                let items: Vec<&str> = self.members.iter().map(|(_, v)| v.as_str()).collect();
                format!("[{}{more}]", items.join(", "))
            }
            Shape::Set => {
                let items: Vec<&str> = self.members.iter().map(|(_, v)| v.as_str()).collect();
                format!(
                    "{}[{}]",
                    if self.complement { "~" } else { "" },
                    items.join(" ")
                )
            }
        }
    }

    /// The one-line form the trace shows, cut at a character boundary with
    /// `...` past [`LINE_MAX`] characters.
    pub fn line(&self) -> String {
        let full = self.full_line();
        if full.chars().count() <= LINE_MAX {
            return full;
        }
        let cut: String = full.chars().take(LINE_MAX).collect();
        format!("{cut}...")
    }

    /// One line per member, for a detail pane: `name = value`, a list's
    /// elements as `[i] value`.
    pub fn lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = match self.shape {
            Shape::Value | Shape::Set => vec![self.full_line()],
            Shape::Struct => self
                .members
                .iter()
                .map(|(name, value)| format!("{name} = {value}"))
                .collect(),
            Shape::List => self
                .members
                .iter()
                .enumerate()
                .map(|(index, (_, value))| format!("[{index}] {value}"))
                .collect(),
        };
        if self.more && self.shape != Shape::Value {
            lines.push("... (more captured than decoded)".into());
        }
        lines
    }
}

/// The type name of a layout, without its `linux-6.12.94/<arch>/` source.
pub fn layout_type(layout: &str) -> &str {
    layout.rsplit('/').next().unwrap_or(layout)
}

/// The bytes of a field's preview that the capture covers from offset 0.
fn covered(field: &FieldSummary) -> &[u8] {
    let covered = field
        .ranges
        .iter()
        .find(|(offset, _)| *offset == 0)
        .map_or(0, |(_, len)| *len);
    &field.preview[..field
        .preview
        .len()
        .min(usize::try_from(covered).unwrap_or(usize::MAX))]
}

/// Whether the field holds more bytes than `used` of its preview.
fn holds_more(field: &FieldSummary, used: usize) -> bool {
    let used = used as u64;
    field.captured_len > used || field.logical_len.is_some_and(|len| len > used)
}

/// `field` decoded by its layout (and, for a few, by its call), or None when
/// the layout is not one decoded here or the bytes are too short for it.
///
/// | Layout | Decoded as |
/// | --- | --- |
/// | `sigset_t` | signal names |
/// | `sigset_argpack` | pselect6's `{ss, ss_len}` |
/// | `siginfo_t`, `siginfo_t[]` | common members and the `si_code` branch |
/// | `sigevent` | the `sigev_notify` branch |
/// | `stack_t` | `ss_sp`, `ss_flags`, `ss_size` |
/// | `bpf_attr` | the members of the call's command |
/// | `cap_data[]`, capget/capset `arg0.version`/`arg0.pid` | capability names, header version |
/// | `uid_t`, `gid_t`, `gid_t[]`, `uid_t[2]` | numbers |
/// | `linux_dirent[]`, `linux_dirent64[]` | directory entries |
/// | `file_handle` | `handle_bytes`, `handle_type` |
/// | `io_uring_params` | parameters, flags and features by name, ring offsets |
/// | `msgbuf` | `mtype` and `mtext` |
/// | `ipt_replace`, `xt_counters_info` | the table header |
/// | `user_desc`, `desc_struct[]` | LDT entry fields |
pub fn decode(call: Option<&Call<'_>>, field: &FieldSummary) -> Option<Decoded> {
    let data = covered(field);
    if data.is_empty() {
        return None;
    }
    let layout = layout_type(&field.layout);
    let mut decoded = match layout {
        "sigset_t" => signals::sigset(data)?,
        "sigset_argpack" => signals::argpack(data)?,
        "siginfo_t" => signals::siginfo(data)?,
        "siginfo_t[]" => list(data, 128, signals::siginfo)?,
        "sigevent" => signals::sigevent(data)?,
        "stack_t" => signals::stack(data)?,
        "bpf_attr" => bpf::attr(call?.args?[0], data)?,
        "cap_data[]" => records::capabilities(data)?,
        "uid_t" | "gid_t" => records::id(data)?,
        "gid_t[]" | "uid_t[2]" => records::ids(data)?,
        "u32" | "pid_t" => records::capability_header(call?, &field.key, data)?,
        "linux_dirent[]" => records::dirents(data, false)?,
        "linux_dirent64[]" => records::dirents(data, true)?,
        "file_handle" => records::file_handle(data)?,
        "io_uring_params" => records::io_uring_params(data)?,
        "msgbuf" => records::msgbuf(data)?,
        "ipt_replace" => records::ipt_replace(data)?,
        "xt_counters_info" => records::counters_info(data)?,
        "user_desc" => records::user_desc(data)?,
        "desc_struct[]" => list(data, 8, records::descriptor)?,
        _ => return None,
    };
    // A decoder sets `more` for a record it could not finish; past that, the
    // field holds more when its capture is longer than the preview decoded.
    decoded.more |= holds_more(field, data.len());
    Some(decoded)
}

/// An array of fixed-size records, each decoded on one line. A trailing
/// partial record makes the list `more`.
fn list(data: &[u8], stride: usize, element: fn(&[u8]) -> Option<Decoded>) -> Option<Decoded> {
    let mut decoded = Decoded::new(Shape::List);
    for chunk in data.chunks(stride) {
        if chunk.len() < stride {
            decoded.more = true;
            break;
        }
        decoded.push("", element(chunk)?.full_line());
    }
    Some(decoded)
}

// Little-endian readers over the captured bytes; None past the end.
fn u8_at(data: &[u8], at: usize) -> Option<u8> {
    data.get(at).copied()
}
fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(data.get(at..at + 2)?.try_into().ok()?))
}
fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}
fn i32_at(data: &[u8], at: usize) -> Option<i32> {
    Some(i32::from_le_bytes(data.get(at..at + 4)?.try_into().ok()?))
}
fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}
fn i64_at(data: &[u8], at: usize) -> Option<i64> {
    Some(i64::from_le_bytes(data.get(at..at + 8)?.try_into().ok()?))
}

/// An address the program passed: `NULL` or hex. Never dereferenced.
fn pointer(value: u64) -> String {
    if value == 0 {
        "NULL".into()
    } else {
        format!("{value:#x}")
    }
}

/// `value` by name, or in decimal when the table has none.
fn named(value: u64, names: &[(&str, u64)]) -> String {
    names
        .iter()
        .find(|(_, candidate)| *candidate == value)
        .map_or_else(|| value.to_string(), |(name, _)| (*name).to_owned())
}

/// Flag names joined with `|`, unnamed bits after them in hex; `0` for none.
fn flags(value: u64, names: &[(&str, u64)]) -> String {
    if value == 0 {
        return "0".into();
    }
    let mut parts = Vec::new();
    let mut rest = value;
    for (name, bit) in names {
        if *bit != 0 && value & bit == *bit && rest & bit != 0 {
            parts.push((*name).to_owned());
            rest &= !bit;
        }
    }
    if rest != 0 {
        parts.push(format!("{rest:#x}"));
    }
    parts.join("|")
}

/// A C string from a fixed-size or NUL-terminated byte run, quoted: printable
/// ASCII as is, other bytes escaped, stopping at the first NUL.
fn c_string(data: &[u8]) -> String {
    let end = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    quoted(&data[..end])
}

/// Every byte quoted, binary escaped (`\0`, `\n`, `\x7f`).
fn quoted(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len() + 2);
    text.push('"');
    for byte in data {
        match byte {
            0 => text.push_str("\\0"),
            b'\n' => text.push_str("\\n"),
            b'\r' => text.push_str("\\r"),
            b'\t' => text.push_str("\\t"),
            b'"' => text.push_str("\\\""),
            b'\\' => text.push_str("\\\\"),
            byte if byte.is_ascii_graphic() || *byte == b' ' => text.push(char::from(*byte)),
            byte => text.push_str(&format!("\\x{byte:02x}")),
        }
    }
    text.push('"');
    text
}

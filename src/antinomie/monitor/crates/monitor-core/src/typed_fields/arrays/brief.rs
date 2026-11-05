// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The compact form of a record array for a table cell: a count and the
//! records' own short forms, cut to fit (`4 entries: ".", "..", "a.txt", +1
//! more`), built from the same per-record summaries the tree shows. The full
//! list of items goes to a hover.
use super::{Record, Records, layout_rows as l};
use crate::FieldSummary;
use crate::typed_fields::{Call, covered, holds_more, layout_type};

/// Characters of items a cell line carries before `+N more`.
const LINE_BUDGET: usize = 84;

/// Records whose sizes a heading adds up.
const MAX_TOTALED: usize = 4096;

/// Items the hover lists.
const HOVER_ITEMS: usize = 200;

/// A record array in one line, and every record as an item for a hover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Brief {
    /// `4 entries`, `3 fds`; empty for a kind that has no count (control
    /// messages).
    pub heading: String,
    /// The cell line, `4 entries: ".", "a", +2 more`.
    pub line: String,
    /// One short form per decoded record (at most 200); `+N more` ends a
    /// longer list.
    pub items: Vec<String>,
    /// The field holds more records than the ones decoded from its preview.
    pub more: bool,
}

/// How a kind of record reads in a cell.
struct Kind {
    one: &'static str,
    many: &'static str,
    item: fn(&Record) -> String,
    separator: &'static str,
    /// What follows the count in the heading: the bytes the records hold.
    total: fn(&[Record]) -> String,
}

fn field<'a>(record: &'a Record, name: &str) -> &'a str {
    record
        .fields
        .iter()
        .find(|(candidate, _)| candidate == name)
        .map_or("", |(_, value)| value.as_str())
}

fn summary(record: &Record) -> String {
    record.summary.clone()
}

fn name(record: &Record) -> String {
    field(record, "d_name").to_owned()
}

/// `4 POLLIN`, `7 POLLOUT -> POLLIN` once the call returned events.
fn pollfd(record: &Record) -> String {
    let (fd, events, revents) = (
        field(record, "fd"),
        field(record, "events"),
        field(record, "revents"),
    );
    if revents == "0" {
        format!("{fd} {events}")
    } else {
        format!("{fd} {events} -> {revents}")
    }
}

/// `SCM_RIGHTS fds 5, 6`.
fn cmsg(record: &Record) -> String {
    record.summary.replace(['[', ']'], "")
}

/// `sem0 +1`, `sem1 -1 SEM_UNDO`, `sem2 wait`.
fn sembuf(record: &Record) -> String {
    let op = field(record, "sem_op");
    let op = match op.parse::<i32>() {
        Ok(0) => "wait".to_owned(),
        Ok(n) if n > 0 => format!("+{n}"),
        _ => op.to_owned(),
    };
    let flags = field(record, "sem_flg");
    let flags = if flags == "0" {
        String::new()
    } else {
        format!(" {flags}")
    };
    format!("sem{} {op}{flags}", field(record, "sem_num"))
}

fn kind(element: &str) -> Kind {
    let mut total: fn(&[Record]) -> String = |_| String::new();
    let (one, many, item, separator): (_, _, fn(&Record) -> String, _) = match element {
        "linux_dirent" | "linux_dirent64" => ("entry", "entries", name, ", "),
        "pollfd" => ("fd", "fds", pollfd, ", "),
        "cmsghdr" => ("", "", cmsg, "; "),
        "sembuf" => ("op", "ops", sembuf, ", "),
        "gid_t" => ("id", "ids", summary, ", "),
        "u32" | "u64" => ("value", "values", summary, ", "),
        "__user_cap_data_struct" => ("capability set", "capability sets", summary, "; "),
        "siginfo_t" => ("siginfo", "siginfos", summary, "; "),
        "desc_struct" => ("descriptor", "descriptors", summary, "; "),
        "futex_waitv" => ("waiter", "waiters", summary, "; "),
        "kexec_segment" => ("segment", "segments", summary, "; "),
        "sock_filter" | "bpf_insn" => ("instruction", "instructions", summary, "; "),
        "bpf_func_info" => ("func info", "func infos", summary, "; "),
        "bpf_line_info" => ("line info", "line infos", summary, "; "),
        "bpf_core_relo" => ("relocation", "relocations", summary, "; "),
        "iovec" => {
            total = l::iovec_total;
            ("buffer", "buffers", summary, "; ")
        }
        "epoll_event" => ("event", "events", summary, "; "),
        "mmsghdr" => {
            total = l::mmsg_total;
            ("message", "messages", summary, "; ")
        }
        _ => ("record", "records", summary, "; "),
    };
    Kind {
        one,
        many,
        item,
        separator,
        total,
    }
}

impl Records {
    /// The compact form of the records found in `data`; `more` when the field
    /// holds bytes past `data`. None when no record was decoded.
    pub(super) fn brief(&self, data: &[u8], more: bool) -> Option<Brief> {
        let count = self.count();
        if count == 0 {
            return None;
        }
        let kind = kind(self.element());
        let more = more || self.cut().is_some() || self.capped();
        let items: Vec<String> = self
            .page(data, 0, HOVER_ITEMS)
            .iter()
            .map(|(_, record)| (kind.item)(record))
            .collect();
        let heading = if kind.many.is_empty() {
            String::new()
        } else {
            let plus = if more { "+" } else { "" };
            let noun = if count == 1 && !more {
                kind.one
            } else {
                kind.many
            };
            let records: Vec<Record> = self
                .page(data, 0, MAX_TOTALED)
                .into_iter()
                .map(|(_, record)| record)
                .collect();
            format!("{count}{plus} {noun}{}", (kind.total)(&records))
        };
        let mut shown = 0usize;
        let mut used = 0usize;
        for item in &items {
            let width = item.chars().count() + kind.separator.len();
            if shown > 0 && used + width > LINE_BUDGET {
                break;
            }
            used += width;
            shown += 1;
        }
        let mut line = items[..shown].join(kind.separator);
        if shown < count {
            let rest = count - shown;
            line = format!("{line}{}+{rest} more", kind.separator);
        } else if more {
            line = format!("{line}{}...", kind.separator);
        }
        let line = if heading.is_empty() {
            line
        } else {
            format!("{heading}: {line}")
        };
        let mut items = items;
        if count > items.len() {
            items.push(format!("+{} more", count - items.len()));
        }
        Some(Brief {
            heading,
            line,
            items,
            more,
        })
    }
}

/// The compact form of a captured record-array `field` (from its owned
/// preview), or None when it is not one or nothing was decoded: the caller
/// shows its usual text then.
pub fn brief(call: Option<&Call<'_>>, field: &FieldSummary) -> Option<Brief> {
    let layout = layout_type(&field.layout);
    if !super::is_array(layout) {
        return None;
    }
    let data = covered(field);
    let records = Records::open(call, &field.layout, &field.key, data)?;
    records.brief(data, holds_more(field, data.len()))
}

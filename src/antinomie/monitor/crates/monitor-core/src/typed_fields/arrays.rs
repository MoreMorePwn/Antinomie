// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Record arrays: a captured field that is an array of records (directory
//! entries, `pollfd`s, control messages, BPF instructions, ...) opened as a
//! list of [`Record`]s the views draw as an expandable tree.
//!
//! The arrays are described by a table of [`Spec`]s, one per layout: how long
//! a record is (a fixed size, or read from its header), how to decode one
//! record, and the one-line summary a collapsed record shows. Another
//! architecture adds its own table rows; nothing else here names x86-64.
//!
//! The bytes come from the caller: the owned 256-byte preview, or the whole
//! captured field read from the recording. [`Records::open`] walks the record
//! boundaries once, with checked arithmetic and a bound on the record count;
//! a final record that does not fit, or a length that cannot be right, ends
//! the walk and is reported as a [`Cut`] instead of being guessed at. Records
//! are decoded one at a time on demand, so a huge array costs one boundary
//! per record, not one decode per record.
use super::{Call, Decoded, Shape, u16_at};
use serde::{Serialize, Serializer, ser::SerializeMap};

mod classic;
mod decoders;
mod table;

pub use table::is_array;
use table::{Length, Size, Spec};

/// Records walked in one array; more are left undecoded (`capped`).
pub const MAX_RECORDS: usize = 1_000_000;

/// One decoded record: the line shown while it is collapsed, and its fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub summary: String,
    /// Members in order as (name, value).
    pub fields: Vec<(String, String)>,
}

impl Record {
    fn from_decoded(decoded: &Decoded, summary: String) -> Self {
        let fields = match decoded.shape {
            Shape::Struct => decoded.members.clone(),
            _ => vec![("value".to_owned(), decoded.full_line())],
        };
        Self { summary, fields }
    }

    /// `{a=1, b=2}`: the record on one line.
    pub fn line(&self) -> String {
        let items: Vec<String> = self
            .fields
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        format!("{{{}}}", items.join(", "))
    }
}

/// Why the walk over the records stopped before the end of the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CutKind {
    /// The bytes end inside a record: `have` captured, `need` known only once
    /// the record's header was captured.
    Short { have: usize, need: Option<usize> },
    /// A record's own length field cannot be right; nothing after it can be
    /// found.
    Malformed(&'static str),
}

/// The record the walk stopped at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cut {
    /// Index of the record that was not decoded.
    pub index: usize,
    /// Byte offset of that record.
    pub at: usize,
    pub kind: CutKind,
}

impl Cut {
    /// A sentence for the view: what was cut and where.
    pub fn note(&self, element: &str) -> String {
        match &self.kind {
            CutKind::Short {
                have,
                need: Some(need),
            } => format!(
                "Record {} ({element}) is cut: {have} of {need} bytes were captured.",
                self.index
            ),
            CutKind::Short { have, need: None } => format!(
                "Record {} ({element}) is cut: its header is incomplete ({have} bytes captured).",
                self.index
            ),
            CutKind::Malformed(why) => format!(
                "Record {} ({element}) is malformed: {why}; decoding stops at byte {}.",
                self.index, self.at
            ),
        }
    }
}

enum Starts {
    Fixed(usize),
    Listed(Vec<usize>),
}

/// The record boundaries of one array's bytes. Holds no bytes itself: ask
/// for a record with the same bytes it was opened over.
pub struct Records {
    spec: &'static Spec,
    call: String,
    count: usize,
    consumed: usize,
    starts: Starts,
    cut: Option<Cut>,
    capped: bool,
}

/// What a record decoder is told about where the record sits.
pub(super) struct Ctx<'a> {
    pub call: &'a str,
    /// Position among the records, and how many there are.
    pub index: usize,
    pub total: usize,
    /// All the bytes, and where this record starts in them.
    pub data: &'a [u8],
    pub at: usize,
}

impl Records {
    /// The records of `data`, the bytes of a field of layout type `layout`
    /// (see [`super::layout_type`]); None for a layout that is not a record
    /// array here, or no bytes.
    pub fn open(call: Option<&Call<'_>>, layout: &str, _key: &str, data: &[u8]) -> Option<Self> {
        let spec = table::spec_named(layout)?;
        if data.is_empty() {
            return None;
        }
        let mut records = Self {
            spec,
            call: call.map_or_else(String::new, |call| call.name.to_owned()),
            count: 0,
            consumed: 0,
            starts: Starts::Fixed(0),
            cut: None,
            capped: false,
        };
        records.walk(data);
        Some(records)
    }

    fn walk(&mut self, data: &[u8]) {
        match self.spec.size {
            Size::Fixed(size) => {
                let whole = data.len() / size.max(1);
                self.count = whole.min(MAX_RECORDS);
                self.capped = whole > MAX_RECORDS;
                self.consumed = self.count * size;
                self.starts = Starts::Fixed(size);
                if !self.capped && self.consumed < data.len() {
                    self.cut = Some(Cut {
                        index: self.count,
                        at: self.consumed,
                        kind: CutKind::Short {
                            have: data.len() - self.consumed,
                            need: Some(size),
                        },
                    });
                }
            }
            Size::Header(length) => {
                let mut starts = Vec::new();
                let mut at = 0usize;
                while at < data.len() {
                    if starts.len() >= MAX_RECORDS {
                        self.capped = true;
                        break;
                    }
                    let rest = &data[at..];
                    let kind = match length(rest) {
                        Length::Bytes(size) if size > 0 && size <= rest.len() => {
                            starts.push(at);
                            at += size;
                            continue;
                        }
                        Length::Bytes(size) => CutKind::Short {
                            have: rest.len(),
                            need: Some(size),
                        },
                        Length::Short => CutKind::Short {
                            have: rest.len(),
                            need: None,
                        },
                        Length::Bad(why) => CutKind::Malformed(why),
                    };
                    self.cut = Some(Cut {
                        index: starts.len(),
                        at,
                        kind,
                    });
                    break;
                }
                self.count = starts.len();
                self.consumed = at;
                self.starts = Starts::Listed(starts);
            }
        }
    }

    /// The record layout's element type, `linux_dirent64`.
    pub fn element(&self) -> &'static str {
        self.spec.element
    }

    /// Records found in the bytes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Bytes the records found cover.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// The record the bytes end inside of, or that cannot be read.
    pub fn cut(&self) -> Option<&Cut> {
        self.cut.as_ref()
    }

    /// More records than [`MAX_RECORDS`] were in the bytes.
    pub fn capped(&self) -> bool {
        self.capped
    }

    fn span(&self, index: usize) -> Option<(usize, usize)> {
        if index >= self.count {
            return None;
        }
        match &self.starts {
            Starts::Fixed(size) => {
                let start = index.checked_mul(*size)?;
                Some((start, start.checked_add(*size)?))
            }
            Starts::Listed(starts) => {
                let start = *starts.get(index)?;
                let end = starts.get(index + 1).copied().unwrap_or(self.consumed);
                Some((start, end))
            }
        }
    }

    /// Record `index` decoded from `data` (the bytes this was opened over).
    pub fn record(&self, data: &[u8], index: usize) -> Option<Record> {
        let (start, end) = self.span(index)?;
        let bytes = data.get(start..end)?;
        let ctx = Ctx {
            call: &self.call,
            index,
            total: self.count,
            data,
            at: start,
        };
        Some(match (self.spec.decode)(&ctx, bytes) {
            Some(decoded) => {
                let summary = (self.spec.summary)(&decoded);
                Record::from_decoded(&decoded, summary)
            }
            None => Record {
                summary: "not decodable".into(),
                fields: vec![("bytes".into(), hex(bytes))],
            },
        })
    }

    /// Up to `count` records from `from`, as (index, record).
    pub fn page(&self, data: &[u8], from: usize, count: usize) -> Vec<(usize, Record)> {
        let end = from.saturating_add(count).min(self.count);
        (from..end)
            .filter_map(|index| Some((index, self.record(data, index)?)))
            .collect()
    }

    /// The records as an array's one-line list: each record's summary, `...`
    /// when the bytes hold more than was decoded.
    pub fn decoded(&self, data: &[u8], limit: usize) -> Decoded {
        let mut decoded = Decoded::new(Shape::List);
        for (_, record) in self.page(data, 0, limit) {
            decoded.push("", record.summary);
        }
        decoded.more = self.cut.is_some() || self.capped || self.count > limit;
        decoded
    }

    /// `records` (from `first`) with their array's identity as JSON.
    pub fn json(&self, data: &[u8], first: usize, count: usize, about: &About<'_>) -> String {
        let page = self.page(data, first, count);
        let records: Vec<JsonRecord<'_>> = page
            .iter()
            .map(|(index, record)| JsonRecord {
                index: *index,
                summary: &record.summary,
                fields: Ordered(&record.fields),
            })
            .collect();
        let array = JsonArray {
            syscall: about.syscall,
            field: about.field,
            layout: about.layout,
            element: self.spec.element,
            captured_bytes: about.captured_bytes,
            decoded_bytes: self.consumed,
            records_found: self.count,
            first_index: first,
            cut: self.cut.as_ref().map(|cut| cut.note(self.spec.element)),
            more_than_decoded: about.more || self.capped,
            records,
        };
        serde_json::to_string_pretty(&array).unwrap_or_default()
    }
}

/// Where an exported array came from.
pub struct About<'a> {
    pub syscall: &'a str,
    pub field: &'a str,
    pub layout: &'a str,
    pub captured_bytes: u64,
    /// The bytes decoded were not all the field holds (a preview).
    pub more: bool,
}

/// One record as JSON: `{"index":.., "summary":.., "fields":{..}}`.
pub fn record_json(index: usize, record: &Record) -> String {
    serde_json::to_string_pretty(&JsonRecord {
        index,
        summary: &record.summary,
        fields: Ordered(&record.fields),
    })
    .unwrap_or_default()
}

#[derive(Serialize)]
struct JsonRecord<'a> {
    index: usize,
    summary: &'a str,
    fields: Ordered<'a>,
}

#[derive(Serialize)]
struct JsonArray<'a> {
    syscall: &'a str,
    field: &'a str,
    layout: &'a str,
    element: &'a str,
    captured_bytes: u64,
    decoded_bytes: usize,
    records_found: usize,
    first_index: usize,
    cut: Option<String>,
    more_than_decoded: bool,
    records: Vec<JsonRecord<'a>>,
}

/// Members as a JSON object in their order.
struct Ordered<'a>(&'a [(String, String)]);

impl Serialize for Ordered<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

/// Bytes as `aa bb cc`, at most 64 of them, `...` after.
pub(super) fn hex(bytes: &[u8]) -> String {
    let shown: Vec<String> = bytes.iter().take(64).map(|b| format!("{b:02x}")).collect();
    let more = if bytes.len() > 64 { " ..." } else { "" };
    format!("{}{more}", shown.join(" "))
}

/// A record's `u16` at `at` as a usize (for length fields).
pub(super) fn len16(data: &[u8], at: usize) -> Option<usize> {
    u16_at(data, at).map(usize::from)
}

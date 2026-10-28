// SPDX-License-Identifier: GPL-3.0-only
//! Read only captured payload ranges; never concatenate across a capture hole.
use super::*;
use antinomie_monitor_core::api::FieldSummary;
use antinomie_monitor_core::file_writes::{self, Captured, Source};
use std::{path::PathBuf, sync::Arc};

#[derive(Default)]
pub(super) struct CapturedPayload {
    chunks: Vec<(u64, Vec<u8>)>,
    captured_size: usize,
    logical_size: u64,
}

impl CapturedPayload {
    pub fn len(&self) -> usize {
        self.captured_size
    }
    pub fn iter(&self) -> impl Iterator<Item = (u64, u8)> + '_ {
        self.chunks.iter().flat_map(|(start, data)| {
            data.iter().enumerate().filter_map(move |(index, byte)| {
                start
                    .checked_add(index as u64)
                    .map(|offset| (offset, *byte))
            })
        })
    }
    /// The first `limit` octets of the transfer, up to the first one that was
    /// not captured.
    pub fn head(&self, limit: usize) -> Vec<u8> {
        let mut head = Vec::new();
        for (start, data) in &self.chunks {
            if *start != head.len() as u64 || head.len() >= limit {
                break;
            }
            head.extend(data.iter().take(limit - head.len()));
        }
        head
    }
    pub fn preview(&self) -> String {
        let mut shown = vec![
            None;
            usize::try_from(self.logical_size)
                .unwrap_or(usize::MAX)
                .min(512)
        ];
        for (offset, byte) in self.iter() {
            if let Ok(offset) = usize::try_from(offset) {
                if let Some(cell) = shown.get_mut(offset) {
                    *cell = Some(byte);
                }
            }
        }
        let mut text: String = shown
            .into_iter()
            .map(|byte| match byte {
                None => "??".into(),
                Some(b'\n') => "\\n".into(),
                Some(b'\r') => "\\r".into(),
                Some(b'\t') => "\\t".into(),
                Some(byte @ 32..=126) => char::from(byte).to_string(),
                Some(byte) => format!("\\x{byte:02x}"),
            })
            .collect();
        if self.logical_size > 512 {
            text.push_str(" …");
        }
        text
    }
}

/// The fields that carry a read's or write's data, in payload order: the
/// exit's for a read, the entry's for a write.
fn payload_fields(
    call: &InvocationSummary,
    reading: bool,
) -> Option<Vec<(usize, bool, &antinomie_monitor_core::api::FieldSummary)>> {
    let event = (if reading {
        call.exit.as_ref()
    } else {
        call.entry.as_ref()
    })?;
    let mut fields: Vec<_> = event
        .fields
        .iter()
        .filter_map(|field| {
            let key = field.key.as_str();
            // file.copy.data: what a splice from a pipe gave the file.
            if key == "buf"
                || key == "arg1.data"
                || key == "arg1.buf"
                || key == antinomie_monitor_core::kernel_notes::FILE_COPY_DATA_KEY
            {
                Some((0, false, field))
            } else {
                key.strip_prefix("arg1.iov[")
                    .and_then(|key| key.strip_suffix("].data"))
                    .and_then(|index| index.parse::<usize>().ok())
                    .map(|index| (index, true, field))
            }
        })
        .collect();
    fields.sort_by_key(|(index, _, _)| *index);
    Some(fields)
}

/// The stretches of a write's payload the kernel captured, as ranges of the
/// run's object store (or inline copies where there is no object), without
/// reading them. Whatever they leave uncovered was not captured.
pub(super) fn write_stretches(
    call: &InvocationSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    stretches(call, false, directory, size, interned)
}

/// The stretches of a read's payload the kernel captured.
pub(super) fn read_stretches(
    call: &InvocationSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    stretches(call, true, directory, size, interned)
}

/// The same for the bytes a splice from a pipe gave its
/// file (`file.copy.data`, an Exit field).
pub(super) fn copy_stretches(
    call: &InvocationSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    stretches(call, true, directory, size, interned)
}

fn stretches(
    call: &InvocationSummary,
    exit: bool,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    let Some(fields) = payload_fields(call, exit) else {
        return Vec::new();
    };
    let mut stretches = Vec::new();
    let mut base = 0u64;
    for (expected, (index, vector, field)) in fields.into_iter().enumerate() {
        if vector && index != expected {
            break;
        }
        if base >= size {
            break;
        }
        field_stretches_at(field, base, directory, size, interned, &mut stretches);
        if !vector {
            break;
        }
        let Some(next) = field
            .logical_len
            .and_then(|length| base.checked_add(length))
        else {
            break;
        };
        base = next;
    }
    stretches.sort_by_key(|stretch| stretch.rel);
    stretches
}

/// The captured stretches of one field whose bytes begin `base` bytes into
/// a transfer of `size` bytes.
fn field_stretches_at(
    field: &FieldSummary,
    base: u64,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
    stretches: &mut Vec<Captured>,
) {
    for (start, end) in field_ranges(field) {
        let Some(at) = base.checked_add(start).filter(|at| *at < size) else {
            continue;
        };
        let count = (end - start).min(size - at);
        match (directory, &field.raw_path) {
            (Some(directory), Some(raw)) => stretches.push(Captured {
                rel: at,
                len: count,
                source: interned.source(directory, raw, start),
            }),
            _ => {
                let rest = usize::try_from(start)
                    .ok()
                    .and_then(|from| field.preview.get(from..))
                    .unwrap_or_default();
                let kept = rest.len().min(usize::try_from(count).unwrap_or(usize::MAX));
                if kept > 0 {
                    stretches.push(Captured {
                        rel: at,
                        len: kept as u64,
                        source: Source::Inline(rest[..kept].to_vec()),
                    });
                }
            }
        }
    }
}

/// A field's captured ranges, `(start, end)`, ascending and not overlapping.
fn field_ranges(field: &FieldSummary) -> Vec<(u64, u64)> {
    let mut ranges: Vec<_> = field.ranges.iter().copied().take(4096).collect();
    ranges.sort_unstable_by_key(|range| range.0);
    let mut covered_end = 0;
    let mut out = Vec::new();
    for (start, length) in ranges {
        let Some(end) = start.checked_add(length) else {
            continue;
        };
        let start = start.max(covered_end);
        if start >= end {
            continue;
        }
        covered_end = end;
        out.push((start, end));
    }
    out
}

/// The stretches of the `size` bytes one field holds (the bytes of pages
/// written through a mapping), as [`write_stretches`] gives a write's.
pub(super) fn field_stretches(
    field: &FieldSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    let mut stretches = Vec::new();
    field_stretches_at(field, 0, directory, size, interned, &mut stretches);
    stretches
}

/// The bytes of one field, as [`capture`] reads a transfer's.
pub(super) fn field_capture(
    field: &FieldSummary,
    directory: Option<&Path>,
    size: u64,
) -> CapturedPayload {
    let mut result = CapturedPayload {
        logical_size: size,
        ..Default::default()
    };
    field_capture_at(field, 0, directory, size, &mut result);
    result
}

/// Directory and object names shared by every extent of a field.
#[derive(Default)]
pub(super) struct Interned {
    recording: Option<Arc<PathBuf>>,
    raw: Option<Arc<PathBuf>>,
}

impl Interned {
    fn source(&mut self, directory: &Path, raw: &Path, at: u64) -> Source {
        if self.recording.as_deref().map(PathBuf::as_path) != Some(directory) {
            self.recording = Some(Arc::new(directory.to_path_buf()));
        }
        if self.raw.as_deref().map(PathBuf::as_path) != Some(raw) {
            self.raw = Some(Arc::new(raw.to_path_buf()));
        }
        match (&self.recording, &self.raw) {
            (Some(recording), Some(raw)) => file_writes::object_source(recording, raw, at),
            _ => unreachable!("both were just set"),
        }
    }
}

pub(super) fn capture(
    call: &InvocationSummary,
    reading: bool,
    directory: Option<&Path>,
    size: u64,
) -> CapturedPayload {
    let mut result = CapturedPayload {
        logical_size: size,
        ..Default::default()
    };
    let Some(fields) = payload_fields(call, reading) else {
        return result;
    };
    let mut base = 0u64;
    for (expected, (index, vector, field)) in fields.into_iter().enumerate() {
        if vector && index != expected {
            break;
        }
        if base >= size {
            break;
        }
        field_capture_at(field, base, directory, size, &mut result);
        if !vector {
            break;
        }
        let Some(next) = field
            .logical_len
            .and_then(|length| base.checked_add(length))
        else {
            break;
        };
        base = next;
    }
    result
}

/// Read one field's captured bytes, placed `base` bytes into a transfer of
/// `size` bytes, into `result` (at most 64 KiB and 1024 chunks in all).
fn field_capture_at(
    field: &FieldSummary,
    base: u64,
    directory: Option<&Path>,
    size: u64,
    result: &mut CapturedPayload,
) {
    for (start, end) in field_ranges(field) {
        let Some(at) = base.checked_add(start).filter(|at| *at < size) else {
            continue;
        };
        let count = usize::try_from((end - start).min(size - at))
            .unwrap_or(usize::MAX)
            .min(65536usize.saturating_sub(result.captured_size));
        if count == 0 || result.chunks.len() >= 1024 {
            break;
        }
        let data = directory
            .and_then(|directory| {
                antinomie_monitor_core::recording::read_captured_range(
                    directory, field, start, count,
                )
                .ok()
            })
            .unwrap_or_else(|| {
                usize::try_from(start)
                    .ok()
                    .and_then(|start| field.preview.get(start..))
                    .unwrap_or_default()
                    .iter()
                    .take(count)
                    .copied()
                    .collect()
            });
        if !data.is_empty() {
            result.captured_size += data.len();
            result.chunks.push((at, data));
        }
    }
}

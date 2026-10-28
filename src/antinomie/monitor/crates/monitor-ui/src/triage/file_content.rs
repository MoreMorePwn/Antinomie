// SPDX-License-Identifier: GPL-3.0-only
//! Read only captured payload ranges; never concatenate across a capture hole.
use super::*;
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
            if key == "buf" || key == "arg1.data" || key == "arg1.buf" {
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
    let Some(fields) = payload_fields(call, false) else {
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
        let mut ranges: Vec<_> = field.ranges.iter().copied().take(4096).collect();
        ranges.sort_unstable_by_key(|range| range.0);
        let mut covered_end = 0;
        for (start, length) in ranges {
            let Some(end) = start.checked_add(length) else {
                continue;
            };
            let start = start.max(covered_end);
            if start >= end {
                continue;
            }
            covered_end = end;
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
        let mut ranges: Vec<_> = field.ranges.iter().copied().take(4096).collect();
        ranges.sort_unstable_by_key(|range| range.0);
        let mut covered_end = 0;
        for (start, length) in ranges {
            let Some(end) = start.checked_add(length) else {
                continue;
            };
            let start = start.max(covered_end);
            if start >= end {
                continue;
            }
            covered_end = end;
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

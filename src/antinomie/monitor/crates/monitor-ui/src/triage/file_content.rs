// SPDX-License-Identifier: GPL-3.0-only
//! Read only captured payload ranges; never concatenate across a capture hole.
use super::*;

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
    let Some(event) = (if reading {
        call.exit.as_ref()
    } else {
        call.entry.as_ref()
    }) else {
        return result;
    };
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

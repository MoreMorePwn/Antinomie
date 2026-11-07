// SPDX-License-Identifier: GPL-3.0-only
//! Read only captured payload ranges; never concatenate across a capture hole.
use super::*;
use antinomie_monitor_core::api::FieldSummary;
use antinomie_monitor_core::file_writes::{self, Captured, Source};
use std::sync::atomic::{AtomicU64, Ordering};
use std::{path::PathBuf, sync::Arc};

/// Most captured bytes read from the run's object store in one go.
pub const READ_STEP: u64 = 65_536;
/// How much of a transfer's start is kept in memory for previews.
pub const LEAD: usize = 512;

/// A stretch of a transfer's captured bytes: where it lies in the transfer,
/// and where to read it from when it is needed.
pub struct Segment {
    pub at: u64,
    pub len: u64,
    /// The run's object store, when the field has a saved object.
    pub source: Option<Source>,
    /// What the event itself holds of the stretch, used when the object cannot
    /// be read (or there is none).
    pub fallback: Vec<u8>,
}

impl Segment {
    pub fn read(&self, skip: u64, len: u64) -> Option<Vec<u8>> {
        if let Some(data) = self
            .source
            .as_ref()
            .and_then(|source| source.read(skip, len).ok())
        {
            return Some(data);
        }
        let from = usize::try_from(skip).ok()?;
        let to = from.checked_add(usize::try_from(len).ok()?)?;
        self.fallback.get(from..to).map(<[u8]>::to_vec)
    }
}

/// The bytes one call moved that the recording captured. Only the first
/// few hundred are held; the rest are read from the object store in steps of
/// at most 64 KiB while [`Self::iter`] runs, so a call's memory does not grow
/// with the size of its buffer.
#[derive(Default)]
pub struct CapturedPayload {
    pub segments: Vec<Segment>,
    /// Bytes the recording says it captured, in place within the transfer.
    pub captured_size: u64,
    pub logical_size: u64,
    /// The transfer's first bytes, `None` where not captured.
    pub lead: Vec<Option<u8>>,
    /// Bytes of a captured stretch that could not be read back.
    pub unread: AtomicU64,
}

/// The captured bytes in transfer order, read as they are asked for.
pub struct Bytes<'a> {
    pub payload: &'a CapturedPayload,
    pub until: u64,
    pub count_unread: bool,
    pub segment: usize,
    pub within: u64,
    pub chunk: Vec<u8>,
    pub chunk_at: u64,
    pub next: usize,
}

impl Iterator for Bytes<'_> {
    type Item = (u64, u8);
    fn next(&mut self) -> Option<(u64, u8)> {
        loop {
            if let Some(byte) = self.chunk.get(self.next) {
                let offset = self.chunk_at + self.next as u64;
                self.next += 1;
                return Some((offset, *byte));
            }
            let segment = self.payload.segments.get(self.segment)?;
            let at = segment.at + self.within;
            if self.within >= segment.len || at >= self.until {
                self.segment += 1;
                self.within = 0;
                continue;
            }
            let step = READ_STEP
                .min(segment.len - self.within)
                .min(self.until - at);
            let from = self.within;
            self.within += step;
            match segment.read(from, step) {
                Some(data) => {
                    self.chunk = data;
                    self.chunk_at = at;
                    self.next = 0;
                }
                None if self.count_unread => {
                    self.payload.unread.fetch_add(step, Ordering::Relaxed);
                }
                None => {}
            }
        }
    }
}

impl CapturedPayload {
    /// Bytes of the transfer the recording captured and that read back.
    pub fn len(&self) -> usize {
        let lost = self.unread.load(Ordering::Relaxed);
        usize::try_from(self.captured_size.saturating_sub(lost)).unwrap_or(usize::MAX)
    }
    /// Every captured byte with its offset in the transfer. Reads in steps of
    /// at most 64 KiB; one that cannot be read is counted out of [`Self::len`].
    pub fn iter(&self) -> Bytes<'_> {
        self.bytes(u64::MAX, true)
    }
    pub fn bytes(&self, until: u64, count_unread: bool) -> Bytes<'_> {
        Bytes {
            payload: self,
            until,
            count_unread,
            segment: 0,
            within: 0,
            chunk: Vec::new(),
            chunk_at: 0,
            next: 0,
        }
    }
    /// Fill in what is held in memory once the stretches are known.
    pub fn settle(&mut self) {
        self.captured_size = self.segments.iter().map(|segment| segment.len).sum();
        let mut lead = vec![
            None;
            usize::try_from(self.logical_size)
                .unwrap_or(usize::MAX)
                .min(LEAD)
        ];
        for (offset, byte) in self.bytes(LEAD as u64, false) {
            if let Some(cell) = usize::try_from(offset)
                .ok()
                .and_then(|offset| lead.get_mut(offset))
            {
                *cell = Some(byte);
            }
        }
        self.lead = lead;
    }
    /// The first `limit` octets of the transfer, up to the first one that was
    /// not captured.
    pub fn head(&self, limit: usize) -> Vec<u8> {
        self.lead
            .iter()
            .take(limit)
            .map_while(|byte| *byte)
            .collect()
    }
    pub fn preview(&self) -> String {
        let shown = &self.lead;
        let mut text: String = shown
            .iter()
            .map(|byte| match *byte {
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
pub fn payload_fields(
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
pub fn write_stretches(
    call: &InvocationSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    stretches(call, false, directory, size, interned)
}

/// The stretches of a read's payload the kernel captured.
pub fn read_stretches(
    call: &InvocationSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    stretches(call, true, directory, size, interned)
}

/// The same for the bytes a splice from a pipe gave its
/// file (`file.copy.data`, an Exit field).
pub fn copy_stretches(
    call: &InvocationSummary,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
) -> Vec<Captured> {
    stretches(call, true, directory, size, interned)
}

pub fn stretches(
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
pub fn field_stretches_at(
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
pub fn field_ranges(field: &FieldSummary) -> Vec<(u64, u64)> {
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
pub fn field_stretches(
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
pub fn field_capture(
    field: &FieldSummary,
    directory: Option<&Path>,
    size: u64,
) -> CapturedPayload {
    let mut result = CapturedPayload {
        logical_size: size,
        ..Default::default()
    };
    field_capture_at(
        field,
        0,
        directory,
        size,
        &mut Interned::default(),
        &mut result,
    );
    result.settle();
    result
}

/// Directory and object names shared by every extent of a field.
#[derive(Default)]
pub struct Interned {
    pub recording: Option<Arc<PathBuf>>,
    pub raw: Option<Arc<PathBuf>>,
}

impl Interned {
    pub fn source(&mut self, directory: &Path, raw: &Path, at: u64) -> Source {
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

pub fn capture(
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
    let mut interned = Interned::default();
    for (expected, (index, vector, field)) in fields.into_iter().enumerate() {
        if vector && index != expected {
            break;
        }
        if base >= size {
            break;
        }
        field_capture_at(field, base, directory, size, &mut interned, &mut result);
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
    result.settle();
    result
}

/// Note one field's captured stretches, placed `base` bytes into a transfer
/// of `size` bytes, in `result`. Nothing is read here.
pub fn field_capture_at(
    field: &FieldSummary,
    base: u64,
    directory: Option<&Path>,
    size: u64,
    interned: &mut Interned,
    result: &mut CapturedPayload,
) {
    for (start, end) in field_ranges(field) {
        let Some(at) = base.checked_add(start).filter(|at| *at < size) else {
            continue;
        };
        let count = (end - start).min(size - at);
        let rest = usize::try_from(start)
            .ok()
            .and_then(|from| field.preview.get(from..))
            .unwrap_or_default();
        let kept = rest.len().min(usize::try_from(count).unwrap_or(usize::MAX));
        match (directory, &field.raw_path) {
            (Some(directory), Some(raw)) => result.segments.push(Segment {
                at,
                len: count,
                source: Some(interned.source(directory, raw, start)),
                fallback: rest[..kept].to_vec(),
            }),
            _ if kept > 0 => result.segments.push(Segment {
                at,
                len: kept as u64,
                source: None,
                fallback: rest[..kept].to_vec(),
            }),
            _ => {}
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tests::{call, captured};

    #[test]
    fn a_big_buffer_is_read_in_steps_of_at_most_64_kib() {
        let size = 3 * (1u64 << 20) + 123;
        let root = std::env::temp_dir().join(format!("ant-payload-steps-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("objects")).unwrap();
        let data: Vec<u8> = (0..size).map(|at| (at % 253) as u8).collect();
        std::fs::write(root.join("objects/big.raw"), &data).unwrap();
        let mut write = call(1, 1, "write", size as i64);
        let mut field = captured("buf", "", b"");
        field.raw_path = Some(PathBuf::from("objects/big.raw"));
        field.logical_len = Some(size);
        field.captured_len = size;
        field.ranges = vec![(0, size)];
        write.entry.as_mut().unwrap().fields.push(field);
        let payload = capture(&write, false, Some(&root), size);
        assert_eq!(payload.len() as u64, size);
        // Nothing but the first bytes is held before the bytes are asked for.
        assert!(payload.lead.len() <= LEAD);
        let mut bytes = payload.iter();
        let (mut count, mut widest) = (0u64, 0);
        while let Some((offset, byte)) = bytes.next() {
            assert_eq!((offset, byte), (count, data[count as usize]));
            count += 1;
            widest = widest.max(bytes.chunk.len());
        }
        assert_eq!(count, size);
        assert_eq!(widest as u64, READ_STEP);
        assert_eq!(payload.len() as u64, size);
        std::fs::remove_dir_all(&root).unwrap();
    }
}

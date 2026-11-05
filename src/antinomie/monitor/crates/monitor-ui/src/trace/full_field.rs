// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! Decoding past the 256-byte preview. A field's trace summary keeps only its
//! first 256 bytes, so a layout longer than that (an aarch64 signal frame or
//! register set, the io_uring rings) decodes with `more`. When the selected
//! call's recording can be read, the decode reads the capture's leading bytes
//! (at most [`CAP`], only as many as the field holds) and decodes those. The
//! result is kept in a small cache so a repaint does not read again.
use antinomie_monitor_core::{recording, typed_fields, FieldSummary};
use std::path::Path;

/// The most bytes of one field read for decoding.
pub(crate) const CAP: usize = 64 * 1024;

/// Fields kept; the oldest is dropped first. At most `ENTRIES * CAP` bytes
/// (4 MiB), usually a few KiB.
const ENTRIES: usize = 64;

#[derive(Default)]
pub(crate) struct FullFields {
    /// (object, key, captured length) and the field with its leading bytes as
    /// the preview; None when they could not be read.
    entries: Vec<((u32, String, u64), Option<FieldSummary>)>,
}

impl FullFields {
    fn load(directory: &Path, field: &FieldSummary) -> Option<FieldSummary> {
        let wanted = usize::try_from(field.captured_len).ok()?.min(CAP);
        // The capture must hold these bytes from offset 0 without a hole.
        let covered = field
            .ranges
            .iter()
            .find(|(offset, _)| *offset == 0)
            .map_or(0, |(_, len)| *len);
        let wanted = wanted.min(usize::try_from(covered).ok()?);
        if wanted <= field.preview.len() {
            return None;
        }
        let bytes = recording::read_captured_range(directory, field, 0, wanted).ok()?;
        let mut full = field.clone();
        full.ranges = vec![(0, bytes.len() as u64)];
        full.preview = bytes;
        Some(full)
    }

    /// `field` with its leading bytes as the preview, when it holds more than
    /// its preview and they can be read.
    fn get(&mut self, directory: &Path, field: &FieldSummary) -> Option<&FieldSummary> {
        let key = (field.object_id, field.key.clone(), field.captured_len);
        let at = match self.entries.iter().position(|(known, _)| *known == key) {
            Some(at) => at,
            None => {
                if self.entries.len() >= ENTRIES {
                    self.entries.remove(0);
                }
                self.entries.push((key, Self::load(directory, field)));
                self.entries.len() - 1
            }
        };
        self.entries[at].1.as_ref()
    }

    /// The field decoded: by its preview, and again by its leading bytes when
    /// the preview decode left members out and the capture holds more.
    pub(crate) fn decode(
        &mut self,
        directory: Option<&Path>,
        call: Option<&typed_fields::Call<'_>>,
        field: &FieldSummary,
    ) -> Option<typed_fields::Decoded> {
        let short = typed_fields::decode(call, field);
        let Some(directory) = directory else {
            return short;
        };
        if !short.as_ref().is_some_and(|decoded| decoded.more)
            || field.captured_len <= field.preview.len() as u64
            || field.raw_path.is_none()
        {
            return short;
        }
        match self.get(directory, field) {
            Some(full) => typed_fields::decode(call, full).or(short),
            None => short,
        }
    }
}

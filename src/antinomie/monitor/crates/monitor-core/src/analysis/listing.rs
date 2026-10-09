// SPDX-License-Identifier: MIT
//! Complete category results kept beside the bounded report.
//!
//! A listing is `listings/<kind>.jsonl`: one `AnalysisEntry` per line, record
//! ids 1, 2, 3... The worker writes it inside the sandbox; the host validates
//! every line before adopting it and reads it in pages afterwards, so a
//! disassembly or decompilation never has to fit the live-snapshot report.
use super::*;
use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Write},
    path::Path,
};

/// Largest single listing, in octets.
pub(crate) const LISTING_MAX_SIZE: u64 = 64 * 1024 * 1024;
/// Largest sum of all listings of one report, in octets.
pub(crate) const LISTINGS_MAX_TOTAL: u64 = 128 * 1024 * 1024;
/// Largest page a reader may request.
pub const LISTING_PAGE_MAX_ROWS: usize = 1024;

/// The listing file name of a category.
pub(crate) fn file_name(kind: AnalysisKind) -> &'static str {
    match kind {
        AnalysisKind::Metadata => "metadata.jsonl",
        AnalysisKind::Structures => "structures.jsonl",
        AnalysisKind::Strings => "strings.jsonl",
        AnalysisKind::Entropy => "entropy.jsonl",
        AnalysisKind::Hardening => "hardening.jsonl",
        AnalysisKind::Rules => "rules.jsonl",
        AnalysisKind::Identification => "identification.jsonl",
        AnalysisKind::Capabilities => "capabilities.jsonl",
        AnalysisKind::Disassembly => "disassembly.jsonl",
        AnalysisKind::Decompilation => "decompilation.jsonl",
    }
}

/// Worker-side writer; stops accepting rows at its byte budget.
pub(crate) struct ListingWriter {
    file: BufWriter<File>,
    rows: u64,
    bytes: u64,
    limit: u64,
    truncated: bool,
}

impl ListingWriter {
    pub fn create(directory: &Path, kind: AnalysisKind, limit: u64) -> Result<Self, String> {
        let file =
            File::create(directory.join(file_name(kind))).map_err(|e| format!("listing: {e}"))?;
        Ok(Self {
            file: BufWriter::new(file),
            rows: 0,
            bytes: 0,
            limit: limit.min(LISTING_MAX_SIZE),
            truncated: false,
        })
    }

    /// Append one row; false once the budget is spent (the listing is then
    /// marked truncated and later rows are dropped).
    pub fn push(
        &mut self,
        label: impl Into<String>,
        value: impl Into<String>,
        location: Option<AnalysisLocation>,
        mut data: AnalysisData,
    ) -> bool {
        if self.truncated {
            return false;
        }
        let mut label = label.into();
        let mut value = value.into();
        // Row text is bounded like report rows; the row itself stays.
        super::worker::clip(&mut label);
        super::worker::clip(&mut value);
        super::worker::bound_data(&mut data);
        if let AnalysisData::String { retained_len, .. } = &mut data {
            *retained_len = value.len() as u64;
        }
        let entry = AnalysisEntry {
            label,
            value,
            offset: location
                .as_ref()
                .and_then(|l| l.file_range.map(|r| r.offset)),
            record: Some(AnalysisRecord {
                revision: 1,
                id: self.rows + 1,
                location,
                data,
            }),
        };
        let Ok(mut line) = serde_json::to_vec(&entry) else {
            return true;
        };
        line.push(b'\n');
        if self.bytes + line.len() as u64 > self.limit {
            self.truncated = true;
            return false;
        }
        if self.file.write_all(&line).is_err() {
            self.truncated = true;
            return false;
        }
        self.rows += 1;
        self.bytes += line.len() as u64;
        true
    }

    pub fn finish(mut self, cut_short: bool) -> Result<AnalysisListing, String> {
        self.file
            .flush()
            .and_then(|_| self.file.get_ref().sync_all())
            .map_err(|e| format!("listing: {e}"))?;
        Ok(AnalysisListing {
            rows: self.rows,
            bytes: self.bytes,
            truncated: self.truncated || cut_short,
        })
    }
}

/// Validate a worker listing before the host adopts it: size, row count and
/// every row against the category's record rules.
pub(crate) fn validate(
    path: &Path,
    kind: AnalysisKind,
    expected: &AnalysisListing,
    total_len: Option<u64>,
) -> Result<(), String> {
    let file =
        crate::archive_io::open_regular(path.parent().ok_or("listing has no directory")?, path)
            .map_err(|e| format!("listing: {e}"))?;
    let len = file.metadata().map_err(|e| e.to_string())?.len();
    if len > LISTING_MAX_SIZE || len != expected.bytes {
        return Err("listing size disagrees with its report or bound".into());
    }
    let mut rows = 0u64;
    for line in BufReader::new(file).split(b'\n') {
        let line = line.map_err(|e| format!("listing: {e}"))?;
        let entry: AnalysisEntry =
            serde_json::from_slice(&line).map_err(|e| format!("listing row malformed: {e}"))?;
        rows += 1;
        let record = entry.record.as_ref().ok_or("listing row without record")?;
        if record.revision != 1 || record.id != rows {
            return Err("listing row id out of sequence".into());
        }
        if entry.label.len() > 4096 || entry.value.len() > 4096 {
            return Err("listing row exceeds text bound".into());
        }
        super::jobs::validate_record(kind, &entry, record, total_len)?;
    }
    if rows != expected.rows {
        return Err("listing row count disagrees with its report".into());
    }
    Ok(())
}

/// Read one page of a retained listing.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory` | Host-retained analysis directory of the report. |
/// | `report_id` | Expected report identity. |
/// | `kind` | Category whose listing to read. |
/// | `start`, `count` | First matching row and at most `LISTING_PAGE_MAX_ROWS` rows. |
/// | `query` | Case-insensitive text every returned row's label or value contains; empty for all. |
///
/// Returns the page and the number of matching rows. Call on a background
/// archive reader; a search scans the whole listing.
pub fn read_listing_page(
    directory: &Path,
    report_id: &str,
    kind: AnalysisKind,
    start: u64,
    count: usize,
    query: &str,
) -> Result<AnalysisListingPage, String> {
    let report = super::open_report(directory)?;
    if report.id != report_id {
        return Err("saved analysis report identity mismatch".into());
    }
    let section = report
        .sections
        .iter()
        .find(|section| section.kind == kind)
        .ok_or("category not in this report")?;
    let listing = section.listing.as_ref().ok_or("category has no listing")?;
    let path = directory.join("listings").join(file_name(kind));
    let file = crate::archive_io::open_regular(&directory.join("listings"), &path)
        .map_err(|e| format!("listing: {e}"))?;
    if file.metadata().map_err(|e| e.to_string())?.len() != listing.bytes {
        return Err("listing changed after it was saved".into());
    }
    let needle = query.to_lowercase();
    let count = count.min(LISTING_PAGE_MAX_ROWS);
    let mut rows = Vec::new();
    let mut total = 0u64;
    for (index, line) in BufReader::new(file).split(b'\n').enumerate() {
        let line = line.map_err(|e| format!("listing: {e}"))?;
        let parse = || -> Result<AnalysisEntry, String> {
            serde_json::from_slice(&line).map_err(|e| format!("listing row malformed: {e}"))
        };
        if needle.is_empty() {
            if total >= start && rows.len() < count {
                rows.push((index as u64, parse()?));
            }
            total += 1;
            continue;
        }
        // The raw line holds escapes, so it can only rule rows out.
        if !String::from_utf8_lossy(&line)
            .to_lowercase()
            .contains(&needle)
        {
            continue;
        }
        let entry = parse()?;
        if entry.label.to_lowercase().contains(&needle)
            || entry.value.to_lowercase().contains(&needle)
        {
            if total >= start && rows.len() < count {
                rows.push((index as u64, entry));
            }
            total += 1;
        }
    }
    Ok(AnalysisListingPage {
        report_id: report_id.into(),
        kind,
        query: query.into(),
        start,
        total,
        rows,
    })
}

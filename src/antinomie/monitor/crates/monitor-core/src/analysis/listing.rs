// SPDX-License-Identifier: GPL-3.0-only
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
/// Most references one instruction row lists on each side.
pub(crate) const REFERENCES_MAX: usize = 16;
/// The file of the disassembly Ghidra exports beside its decompilation.
pub(crate) const GHIDRA_DISASSEMBLY_FILE: &str = "ghidra-disassembly.jsonl";
/// Largest page a reader may request.
pub const LISTING_PAGE_MAX_ROWS: usize = 1024;

/// The listing file name of a category.
pub(crate) fn file_name(kind: AnalysisKind) -> &'static str {
    match kind {
        AnalysisKind::Metadata => "metadata.jsonl",
        AnalysisKind::Structures => "structures.jsonl",
        AnalysisKind::Strings => "strings.jsonl",
        AnalysisKind::Regex => "regex.jsonl",
        AnalysisKind::Entropy => "entropy.jsonl",
        AnalysisKind::Hardening => "hardening.jsonl",
        AnalysisKind::Rules => "rules.jsonl",
        AnalysisKind::Identification => "identification.jsonl",
        AnalysisKind::Capabilities => "capabilities.jsonl",
        AnalysisKind::Disassembly => "disassembly.jsonl",
        AnalysisKind::Decompilation => "decompilation.jsonl",
        AnalysisKind::Embedded => "embedded.jsonl",
        AnalysisKind::Floss => "floss.jsonl",
        AnalysisKind::Unpacking => "unpacking.jsonl",
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
        Self::create_named(directory, file_name(kind), limit)
    }

    /// A listing of `kind` rows in the file `name` (a companion listing).
    pub fn create_named(directory: &Path, name: &str, limit: u64) -> Result<Self, String> {
        let file = File::create(directory.join(name)).map_err(|e| format!("listing: {e}"))?;
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
        super::bounds::clip(&mut label);
        super::bounds::clip(&mut value);
        super::bounds::bound_data(&mut data);
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
        super::validation::validate_record(kind, &entry, record, total_len)?;
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
    let needle = query.to_lowercase();
    read_listing_page_with(directory, report_id, kind, start, count, query, |entry| {
        needle.is_empty()
            || entry.label.to_lowercase().contains(&needle)
            || entry.value.to_lowercase().contains(&needle)
    })
}

/// Read the whole retained listing with a caller's typed row predicate.
///
/// | Argument | Meaning |
/// |---|---|
/// | `directory`, `report_id`, `kind` | Retained report/category identity, validated before reading. |
/// | `start`, `count` | First matching row and bounded page length. |
/// | `query` | Query identity echoed in the returned page; interpretation belongs to `keep`. |
/// | `keep` | Predicate evaluated for each decoded row, on the archive worker. |
///
/// Returns a bounded page and the exact matching count; no rows are skipped by a
/// substring shortcut when the caller supplies a structured filter.
pub fn read_listing_page_with(
    directory: &Path,
    report_id: &str,
    kind: AnalysisKind,
    start: u64,
    count: usize,
    query: &str,
    keep: impl FnMut(&AnalysisEntry) -> bool,
) -> Result<AnalysisListingPage, String> {
    read_listing_page_sorted(directory, report_id, kind, start, count, query, None, keep)
}

/// [`read_listing_page_with`] with the matching rows ordered by `sort` before
/// the page is cut, so `start` counts in the sorted order over the whole
/// listing, not within one page. A Strings listing sorts by column and every
/// listing but the disassembly and the decompiled source by field (see
/// [`ListingSort`]); otherwise `sort` is ignored and the page says so. Ties keep the listing order. Holds every matching row while it
/// sorts, which the listing's size bound keeps small.
#[allow(clippy::too_many_arguments)]
pub fn read_listing_page_sorted(
    directory: &Path,
    report_id: &str,
    kind: AnalysisKind,
    start: u64,
    count: usize,
    query: &str,
    sort: Option<ListingSort>,
    keep: impl FnMut(&AnalysisEntry) -> bool,
) -> Result<AnalysisListingPage, String> {
    read_page(
        directory, report_id, kind, false, start, count, query, sort, keep,
    )
}

/// One page of the disassembly Ghidra exported during the decompilation run
/// (`AnalysisSection::disassembly` of the Decompilation category). The page's
/// `kind` is `Disassembly`: its rows are the same instruction and function
/// records as the Disassembly category's own listing, in address order, with
/// Ghidra's labels and references. Same arguments and rules as
/// [`read_listing_page_with`].
pub fn read_ghidra_disassembly_page(
    directory: &Path,
    report_id: &str,
    start: u64,
    count: usize,
    query: &str,
    keep: impl FnMut(&AnalysisEntry) -> bool,
) -> Result<AnalysisListingPage, String> {
    read_page(
        directory,
        report_id,
        AnalysisKind::Disassembly,
        true,
        start,
        count,
        query,
        None,
        keep,
    )
}

/// `ghidra` reads the companion listing of the Decompilation section instead
/// of the category's own; the rows are then checked as `kind` rows.
#[allow(clippy::too_many_arguments)]
fn read_page(
    directory: &Path,
    report_id: &str,
    kind: AnalysisKind,
    ghidra: bool,
    start: u64,
    count: usize,
    query: &str,
    sort: Option<ListingSort>,
    mut keep: impl FnMut(&AnalysisEntry) -> bool,
) -> Result<AnalysisListingPage, String> {
    let sort = sort.filter(|sort| match kind {
        AnalysisKind::Strings => sort.field.is_none(),
        // Disassembly and decompiled source stay in the order that means something.
        AnalysisKind::Disassembly | AnalysisKind::Decompilation => false,
        _ => sort.field.is_some(),
    });
    let report = super::open_report(directory)?;
    if report.id != report_id {
        return Err("saved analysis report identity mismatch".into());
    }
    let section = report
        .sections
        .iter()
        .find(|section| {
            section.kind
                == if ghidra {
                    AnalysisKind::Decompilation
                } else {
                    kind
                }
        })
        .ok_or("category not in this report")?;
    let (listing, name) = if ghidra {
        (
            section.disassembly.as_ref().map(|d| &d.listing),
            GHIDRA_DISASSEMBLY_FILE,
        )
    } else {
        (section.listing.as_ref(), file_name(kind))
    };
    let listing = listing.ok_or("category has no listing")?;
    let path = directory.join("listings").join(name);
    let file = crate::archive_io::open_regular(&directory.join("listings"), &path)
        .map_err(|e| format!("listing: {e}"))?;
    if file.metadata().map_err(|e| e.to_string())?.len() != listing.bytes {
        return Err("listing changed after it was saved".into());
    }
    let count = count.min(LISTING_PAGE_MAX_ROWS);
    let mut rows = Vec::new();
    // Every match, when the page is cut after sorting.
    let mut matches = Vec::new();
    let mut total = 0u64;
    let mut seen = 0u64;
    let mut functions: Vec<AnalysisFunctionLines> = Vec::new();
    for (index, line) in BufReader::new(file).split(b'\n').enumerate() {
        let line = line.map_err(|error| format!("listing: {error}"))?;
        let entry: AnalysisEntry = serde_json::from_slice(&line)
            .map_err(|error| format!("listing row malformed: {error}"))?;
        seen = seen.checked_add(1).ok_or("listing row count overflow")?;
        let record = entry.record.as_ref().ok_or("listing row without record")?;
        if record.revision != 1 || record.id != seen {
            return Err("listing row id out of sequence".into());
        }
        super::validation::validate_record(kind, &entry, record, report.specimen_len)?;
        count_function_line(kind, &entry, &mut functions);
        if keep(&entry) {
            if sort.is_some() {
                matches.push((index as u64, entry));
            } else if total >= start && rows.len() < count {
                rows.push((index as u64, entry));
            }
            total = total.checked_add(1).ok_or("listing row count overflow")?;
        }
    }
    if seen != listing.rows {
        return Err("listing row count disagrees with its report".into());
    }
    if let Some(sort) = sort {
        match sort.field {
            Some(field) => sort_structures(&mut matches, field, sort.descending),
            None => sort_strings(&mut matches, sort),
        }
        rows = matches
            .into_iter()
            .skip(usize::try_from(start).unwrap_or(usize::MAX))
            .take(count)
            .collect();
    }
    Ok(AnalysisListingPage {
        report_id: report_id.into(),
        kind,
        query: query.into(),
        sort,
        start,
        total,
        rows,
        functions,
    })
}

/// Order Strings rows by the column of `sort`: file offset, encoding, length
/// in octets, or text (ignoring case).
fn sort_strings(rows: &mut [(u64, AnalysisEntry)], sort: ListingSort) {
    let byte_len = |entry: &AnalysisEntry| match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::String { byte_len, .. }) => *byte_len,
        _ => 0,
    };
    match sort.column {
        0 => rows.sort_by_key(|(_, entry)| entry.offset.unwrap_or(0)),
        1 => rows.sort_by_cached_key(|(_, entry)| {
            match entry.record.as_ref().map(|record| &record.data) {
                Some(AnalysisData::String { encoding, .. }) => encoding.clone(),
                _ => String::new(),
            }
        }),
        2 => rows.sort_by_key(|(_, entry)| byte_len(entry)),
        _ => rows.sort_by_cached_key(|(_, entry)| entry.value.to_lowercase()),
    }
    if sort.descending {
        rows.reverse();
    }
}

/// The number of a Structures cell, as its table shows it.
fn structure_number(field: StructureField, entry: &AnalysisEntry) -> Option<u64> {
    let record = entry.record.as_ref();
    match field {
        StructureField::Offset => record
            .and_then(|r| r.location.as_ref())
            .and_then(|l| l.file_range)
            .map(|r| r.offset)
            .or(entry.offset)
            .or_else(|| match &record?.data {
                AnalysisData::Signature { offset, .. } => Some(*offset),
                _ => None,
            }),
        StructureField::Address => record
            .and_then(|r| r.location.as_ref())
            .filter(|l| l.kind != AnalysisAddressKind::FileOffset)
            .map(|l| l.value)
            .or_else(|| match &record?.data {
                AnalysisData::Section { address, .. } => Some(*address),
                AnalysisData::Symbol { address, .. } | AnalysisData::Export { address, .. } => {
                    *address
                }
                AnalysisData::FlossString { function, .. } => *function,
                _ => None,
            }),
        _ => match (&record?.data, field) {
            (AnalysisData::Section { virtual_size, .. }, StructureField::VirtualSize) => {
                Some(*virtual_size)
            }
            (AnalysisData::Section { file_size, .. }, StructureField::FileSize) => *file_size,
            (AnalysisData::Symbol { size, .. }, StructureField::Size) => Some(*size),
            (
                AnalysisData::Import { ordinal, .. } | AnalysisData::Export { ordinal, .. },
                StructureField::Ordinal,
            ) => *ordinal,
            _ => None,
        },
    }
}

/// The text of a Structures cell that has no number.
fn structure_text(field: StructureField, entry: &AnalysisEntry) -> String {
    let data = entry.record.as_ref().map(|record| &record.data);
    match (field, data) {
        (StructureField::Value, _) => entry.value.to_lowercase(),
        (StructureField::Name, data) => match data {
            Some(
                AnalysisData::Section { name, .. }
                | AnalysisData::Symbol { name, .. }
                | AnalysisData::Function { name, .. },
            ) => name.to_lowercase(),
            Some(
                AnalysisData::Import {
                    name: Some(name), ..
                }
                | AnalysisData::Export {
                    name: Some(name), ..
                },
            ) => name.to_lowercase(),
            _ => entry.label.to_lowercase(),
        },
        (
            StructureField::Flags,
            Some(AnalysisData::Section {
                raw_flags, flags, ..
            }),
        ) => format!("{raw_flags} {}", flags.join(" | ")).to_lowercase(),
        (StructureField::Library, Some(AnalysisData::Import { library, .. })) => {
            library.clone().unwrap_or_default().to_lowercase()
        }
        (
            StructureField::Scope,
            Some(AnalysisData::Symbol { scope, .. } | AnalysisData::Property { scope, .. }),
        ) => scope.to_lowercase(),
        (StructureField::Kind, Some(AnalysisData::Symbol { kind, .. })) => kind.to_lowercase(),
        (StructureField::Defined, Some(AnalysisData::Symbol { undefined, .. })) => {
            if *undefined { "undefined" } else { "defined" }.into()
        }
        _ => String::new(),
    }
}

/// Order Structures rows by one table column: numbers numerically (rows
/// without one after them), the rest as text ignoring case.
fn sort_structures(rows: &mut [(u64, AnalysisEntry)], field: StructureField, descending: bool) {
    rows.sort_by(|(_, left), (_, right)| {
        match (
            structure_number(field, left),
            structure_number(field, right),
        ) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            _ => structure_text(field, left).cmp(&structure_text(field, right)),
        }
    });
    if descending {
        rows.reverse();
    }
}

/// Tally `entry` under the function it follows: a function header starts a
/// count, an instruction (disassembly) or source line (decompilation) adds one.
fn count_function_line(
    kind: AnalysisKind,
    entry: &AnalysisEntry,
    functions: &mut Vec<AnalysisFunctionLines>,
) {
    if !matches!(
        kind,
        AnalysisKind::Disassembly | AnalysisKind::Decompilation
    ) {
        return;
    }
    match entry.record.as_ref().map(|record| &record.data) {
        Some(AnalysisData::Function { name, address, .. }) => {
            functions.push(AnalysisFunctionLines {
                name: name.clone(),
                address: *address,
                lines: 0,
            })
        }
        Some(AnalysisData::Instruction { .. }) if kind == AnalysisKind::Disassembly => {
            if let Some(function) = functions.last_mut() {
                function.lines += 1;
            }
        }
        Some(AnalysisData::SourceLine { .. }) if kind == AnalysisKind::Decompilation => {
            if let Some(function) = functions.last_mut() {
                function.lines += 1;
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_reads_every_row_counts_matches_and_rejects_corruption_even_when_filtered_out() {
        let root =
            std::env::temp_dir().join(format!("ant-listing-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        std::fs::create_dir(root.join("listings")).unwrap();
        let mut writer = ListingWriter::create(
            &root.join("listings"),
            AnalysisKind::Decompilation,
            LISTING_MAX_SIZE,
        )
        .unwrap();
        for line in 1..=2400 {
            assert!(writer.push(
                "routine",
                format!("source {line}"),
                None,
                AnalysisData::SourceLine {
                    function: "routine".into(),
                    address: None,
                    line
                }
            ));
        }
        let mut section = AnalysisSection::new(AnalysisKind::Decompilation);
        section.state = AnalysisSectionState::Partial;
        section.listing = Some(writer.finish(true).unwrap());
        let report = AnalysisReport {
            id: "retained".into(),
            state: AnalysisState::Partial,
            source_path: "/fixture".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: Some("partial fixture".into()),
            sections: vec![section],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
        };
        std::fs::write(
            root.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        let page = read_listing_page_with(
            &root,
            "retained",
            AnalysisKind::Decompilation,
            5,
            3,
            "line >= 2200 && line < 2300",
            |entry| {
                matches!(
                    entry.record.as_ref().map(|record| &record.data),
                    Some(AnalysisData::SourceLine {
                        line: 2200..2300,
                        ..
                    })
                )
            },
        )
        .unwrap();
        assert_eq!(page.total, 100);
        assert_eq!(page.rows.len(), 3);
        assert_eq!(page.rows[0].0, 2204);
        assert_eq!(page.rows[0].1.value, "source 2205");
        assert!(
            read_listing_page_with(
                &root,
                "wrong",
                AnalysisKind::Decompilation,
                0,
                1,
                "",
                |_| true
            )
            .is_err()
        );
        let path = root.join("listings/decompilation.jsonl");
        let mut encoded = std::fs::read(&path).unwrap();
        encoded[0] = b'!';
        std::fs::write(&path, encoded).unwrap();
        assert!(
            read_listing_page_with(
                &root,
                "retained",
                AnalysisKind::Decompilation,
                0,
                1,
                "never",
                |_| false
            )
            .unwrap_err()
            .contains("malformed")
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Write a listing of `kind` made of `(function, address, body lines)` and
    /// a report that holds it.
    fn function_listing(kind: AnalysisKind, functions: &[(&str, u64, u32)]) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("ant-listing-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        std::fs::create_dir(root.join("listings")).unwrap();
        let mut writer =
            ListingWriter::create(&root.join("listings"), kind, LISTING_MAX_SIZE).unwrap();
        for (name, address, lines) in functions {
            assert!(writer.push(
                *name,
                *name,
                None,
                AnalysisData::Function {
                    name: (*name).into(),
                    address: *address,
                    size: 0
                }
            ));
            for line in 1..=*lines {
                let data = if kind == AnalysisKind::Disassembly {
                    AnalysisData::Instruction {
                        address: address + u64::from(line),
                        bytes: "90".into(),
                        mnemonic: "nop".into(),
                        operands: String::new(),
                        function: Some((*name).into()),
                        label: None,
                        targets: Vec::new(),
                        xrefs: Vec::new(),
                    }
                } else {
                    AnalysisData::SourceLine {
                        function: (*name).into(),
                        address: None,
                        line,
                    }
                };
                assert!(writer.push("row", format!("row {line}"), None, data));
            }
        }
        let mut section = AnalysisSection::new(kind);
        section.state = AnalysisSectionState::Complete;
        section.listing = Some(writer.finish(false).unwrap());
        let report = AnalysisReport {
            id: "counted".into(),
            state: AnalysisState::Complete,
            source_path: "/fixture".into(),
            specimen_sha256: None,
            specimen_len: None,
            reason: None,
            sections: vec![section],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
        };
        std::fs::write(
            root.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        root
    }

    /// A Strings listing of `(offset, encoding, text)` and its report.
    fn strings_listing(strings: &[(u64, &str, &str)]) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("ant-listing-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        std::fs::create_dir(root.join("listings")).unwrap();
        let mut writer = ListingWriter::create(
            &root.join("listings"),
            AnalysisKind::Strings,
            LISTING_MAX_SIZE,
        )
        .unwrap();
        for (offset, encoding, text) in strings {
            let byte_len = text.len() as u64;
            assert!(writer.push(
                "string",
                *text,
                Some(AnalysisLocation {
                    kind: AnalysisAddressKind::FileOffset,
                    value: *offset,
                    file_range: Some(AnalysisRange {
                        offset: *offset,
                        len: byte_len
                    }),
                }),
                AnalysisData::String {
                    encoding: (*encoding).into(),
                    byte_len,
                    retained_len: byte_len,
                }
            ));
        }
        let mut section = AnalysisSection::new(AnalysisKind::Strings);
        section.state = AnalysisSectionState::Complete;
        section.listing = Some(writer.finish(false).unwrap());
        let report = AnalysisReport {
            id: "sorted".into(),
            state: AnalysisState::Complete,
            source_path: "/fixture".into(),
            specimen_sha256: None,
            specimen_len: Some(0x1000),
            reason: None,
            sections: vec![section],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
        };
        std::fs::write(
            root.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        root
    }

    /// A Structures listing of sections `(name, address, virtual size, file size)`.
    fn sections_listing(sections: &[(&str, u64, u64, Option<u64>)]) -> std::path::PathBuf {
        let root =
            std::env::temp_dir().join(format!("ant-listing-{}", crate::storage::unique_id()));
        crate::storage::private_dir(&root).unwrap();
        std::fs::create_dir(root.join("listings")).unwrap();
        let mut writer = ListingWriter::create(
            &root.join("listings"),
            AnalysisKind::Structures,
            LISTING_MAX_SIZE,
        )
        .unwrap();
        for (name, address, virtual_size, file_size) in sections {
            assert!(writer.push(
                "Section",
                *name,
                None,
                AnalysisData::Section {
                    name: (*name).into(),
                    address: *address,
                    virtual_size: *virtual_size,
                    file_size: *file_size,
                    raw_flags: "0x6".into(),
                    flags: vec!["ALLOC".into()],
                }
            ));
        }
        let mut section = AnalysisSection::new(AnalysisKind::Structures);
        section.state = AnalysisSectionState::Complete;
        section.listing = Some(writer.finish(false).unwrap());
        let report = AnalysisReport {
            id: "structs".into(),
            state: AnalysisState::Complete,
            source_path: "/fixture".into(),
            specimen_sha256: None,
            specimen_len: Some(0x1000),
            reason: None,
            sections: vec![section],
            layer: None,
            specimen_source: None,
            time_limit_seconds: None,
        };
        std::fs::write(
            root.join("report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn a_structures_sort_names_its_field_and_orders_the_whole_listing() {
        let root = sections_listing(&[
            (".text", 0x3000, 0x500, Some(0x400)),
            (".bss", 0x1000, 0x80, None),
            (".Data", 0x2000, 0x10, Some(0x10)),
        ]);
        let names = |field, descending, start, count| {
            let page = read_listing_page_sorted(
                &root,
                "structs",
                AnalysisKind::Structures,
                start,
                count,
                "",
                Some(ListingSort {
                    column: 0,
                    descending,
                    field: Some(field),
                }),
                |_| true,
            )
            .unwrap();
            assert!(page.sort.is_some_and(|sort| sort.field == Some(field)));
            page.rows
                .iter()
                .map(|(_, entry)| entry.value.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            names(StructureField::Name, false, 0, 9),
            [".bss", ".Data", ".text"]
        );
        assert_eq!(
            names(StructureField::Address, true, 0, 9),
            [".text", ".Data", ".bss"]
        );
        assert_eq!(
            names(StructureField::VirtualSize, false, 0, 9),
            [".Data", ".bss", ".text"]
        );
        // A row without a number follows the rows that have one.
        assert_eq!(
            names(StructureField::FileSize, false, 0, 9),
            [".Data", ".text", ".bss"]
        );
        // The page is cut after sorting.
        assert_eq!(names(StructureField::Address, false, 2, 9), [".text"]);
        // Without a field a Structures listing is not sorted, and the
        // disassembly never is.
        let plain = read_listing_page_sorted(
            &root,
            "structs",
            AnalysisKind::Structures,
            0,
            9,
            "",
            Some(ListingSort {
                column: 1,
                descending: true,
                field: None,
            }),
            |_| true,
        )
        .unwrap();
        assert_eq!(plain.sort, None);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_sorted_page_orders_the_whole_listing_before_it_is_cut() {
        let root = strings_listing(&[
            (0x30, "UTF-16LE", "mango-fruit"),
            (0x10, "ASCII", "Zebra-animal"),
            (0x50, "ASCII", "apple-fruit-long"),
            (0x20, "UTF-16LE", "kiwi"),
        ]);
        let page = |start, column, descending, keep: &str| {
            let keep = keep.to_owned();
            read_listing_page_sorted(
                &root,
                "sorted",
                AnalysisKind::Strings,
                start,
                2,
                &keep,
                Some(ListingSort {
                    column,
                    descending,
                    field: None,
                }),
                |entry| entry.value.contains(&keep),
            )
            .unwrap()
        };
        fn values(page: &AnalysisListingPage) -> Vec<&str> {
            page.rows
                .iter()
                .map(|(_, entry)| entry.value.as_str())
                .collect()
        }
        // The second page of an offset sort holds the two highest offsets,
        // which a sort of the listing's first page could not.
        let second = page(2, 0, false, "");
        assert_eq!(values(&second), ["mango-fruit", "apple-fruit-long"]);
        assert_eq!((second.total, second.start), (4, 2));
        assert_eq!(
            values(&page(0, 0, true, "")),
            ["apple-fruit-long", "mango-fruit"]
        );
        // Text ignores case; length orders by octets; encoding by name.
        assert_eq!(values(&page(0, 3, false, "")), ["apple-fruit-long", "kiwi"]);
        assert_eq!(values(&page(0, 2, false, "")), ["kiwi", "mango-fruit"]);
        assert_eq!(values(&page(0, 1, false, ""))[0], "Zebra-animal");
        // A filter narrows before the sort; the listing index stays.
        let narrowed = page(0, 0, true, "fruit");
        assert_eq!(values(&narrowed), ["apple-fruit-long", "mango-fruit"]);
        assert_eq!(narrowed.rows[0].0, 2);
        assert_eq!(
            narrowed.sort,
            Some(ListingSort {
                column: 0,
                descending: true,
                field: None
            })
        );
        // Another category ignores the sort.
        std::fs::remove_dir_all(root).unwrap();
        let root = function_listing(AnalysisKind::Disassembly, &[("main", 0x2000, 3)]);
        let unsorted = read_listing_page_sorted(
            &root,
            "counted",
            AnalysisKind::Disassembly,
            0,
            2,
            "",
            Some(ListingSort {
                column: 0,
                descending: true,
                field: None,
            }),
            |_| true,
        )
        .unwrap();
        assert_eq!(unsorted.sort, None);
        assert_eq!(unsorted.rows[0].0, 0);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_page_counts_the_lines_of_every_function_whatever_the_query() {
        for kind in [AnalysisKind::Disassembly, AnalysisKind::Decompilation] {
            let root = function_listing(kind, &[("_start", 0x1000, 7), ("main", 0x2000, 3)]);
            let all = read_listing_page(&root, "counted", kind, 0, 2, "").unwrap();
            let narrowed = read_listing_page(&root, "counted", kind, 0, 2, "row 1").unwrap();
            let expected = vec![
                AnalysisFunctionLines {
                    name: "_start".into(),
                    address: 0x1000,
                    lines: 7,
                },
                AnalysisFunctionLines {
                    name: "main".into(),
                    address: 0x2000,
                    lines: 3,
                },
            ];
            assert_eq!(all.functions, expected, "{kind:?}");
            assert_eq!(narrowed.functions, expected, "{kind:?} under a query");
            assert!(narrowed.total < all.total);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

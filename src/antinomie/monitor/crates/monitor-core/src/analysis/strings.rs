// SPDX-License-Identifier: GPL-3.0-only
//! The Strings check: printable ASCII and UTF-16LE strings in file order, the
//! first ones in the report and all of them in the listing.
use super::worker::structured_entry;
use super::*;
use std::path::Path;

/// Strings kept in the report itself; the listing holds all of them.
pub(super) const REPORT_STRINGS: usize = 256;

/// Printable ASCII (four or more octets) and UTF-16LE strings, in file order.
pub(crate) fn find_strings(specimen: &[u8]) -> Vec<(usize, usize, &'static str, String)> {
    let value_max = super::limits::value_bytes();
    let mut found = Vec::new();
    let mut start = 0;
    for index in 0..=specimen.len() {
        if index < specimen.len() && (specimen[index].is_ascii_graphic() || specimen[index] == b' ')
        {
            continue;
        }
        if index - start >= 4 {
            let retained = &specimen[start..index.min(start + value_max)];
            found.push((
                start,
                index - start,
                "ASCII",
                String::from_utf8_lossy(retained).into_owned(),
            ));
        }
        start = index + 1;
    }
    // UTF-16LE: printable ASCII code units, each followed by a zero octet.
    let mut index = 0;
    while index + 1 < specimen.len() {
        let begin = index;
        let mut text = String::new();
        while index + 1 < specimen.len()
            && specimen[index + 1] == 0
            && (specimen[index].is_ascii_graphic() || specimen[index] == b' ')
        {
            if text.len() < value_max {
                text.push(specimen[index] as char);
            }
            index += 2;
        }
        if index - begin >= 8 {
            found.push((begin, index - begin, "UTF-16LE", text));
        } else {
            index = begin + 1;
        }
    }
    found.sort_by_key(|(offset, ..)| *offset);
    found
}

pub(super) fn strings(section: &mut AnalysisSection, specimen: &[u8], listings: &Path) {
    let found = find_strings(specimen);
    let mut writer = super::listing::ListingWriter::create(
        listings,
        AnalysisKind::Strings,
        super::limits::listing_bytes(),
    )
    .ok();
    let mut full = false;
    for (index, (offset, len, encoding, text)) in found.iter().enumerate() {
        let range = AnalysisRange {
            offset: *offset as u64,
            len: *len as u64,
        };
        let location = || {
            Some(AnalysisLocation {
                kind: AnalysisAddressKind::FileOffset,
                value: range.offset,
                file_range: Some(range),
            })
        };
        let data = || AnalysisData::String {
            encoding: (*encoding).into(),
            byte_len: range.len,
            retained_len: text.len() as u64,
        };
        if index < REPORT_STRINGS {
            structured_entry(section, *encoding, text.clone(), location(), data());
        }
        if let Some(writer) = writer.as_mut()
            && !full
            && !writer.push(*encoding, text.clone(), location(), data())
        {
            full = true;
        }
    }
    // A string longer than the row bound keeps only its start.
    let cut = found
        .iter()
        .filter(|(_, len, encoding, text)| {
            let units = if *encoding == "ASCII" { *len } else { len / 2 };
            text.len() < units
        })
        .count();
    section.state = AnalysisSectionState::Complete;
    if cut > 0 {
        section.state = AnalysisSectionState::Partial;
        super::limits::add_for(
            section,
            AnalysisLimitKind::Text,
            LimitSetting::Value,
            format!(
                "{} {} longer than {} bytes; only the start of each is kept.",
                super::detection::group_digits(cut as u64),
                if cut == 1 { "string is" } else { "strings are" },
                super::detection::group_digits(super::limits::value_bytes() as u64)
            ),
        );
    }
    if let Some(listing) = writer.and_then(|w| w.finish(full).ok()) {
        if listing.truncated {
            section.state = AnalysisSectionState::Partial;
            super::limits::add_for(
                section,
                AnalysisLimitKind::Size,
                LimitSetting::Listing,
                format!(
                    "The listing reached its {} limit after {} of {} strings; later strings are not listed.",
                    crate::byte_size::short_size(super::limits::listing_bytes()),
                    super::detection::group_digits(listing.rows),
                    super::detection::group_digits(found.len() as u64)
                ),
            );
        }
        section.listing = Some(listing);
    } else if found.len() > REPORT_STRINGS {
        section.state = AnalysisSectionState::Partial;
        super::limits::add(
            section,
            AnalysisLimitKind::Rows,
            format!(
                "The listing could not be written, so the report keeps only the first {REPORT_STRINGS} of {} strings.",
                super::detection::group_digits(found.len() as u64)
            ),
            None,
        );
    }
    section.summary = format!(
        "{} strings (printable ASCII of four or more bytes, UTF-16LE of four or more characters); offsets are file offsets",
        found.len()
    );
}

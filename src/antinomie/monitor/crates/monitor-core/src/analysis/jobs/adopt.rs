// SPDX-License-Identifier: GPL-3.0-only
//! Adoption of the listings a worker wrote: validated, then moved next to the
//! report.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// The bytes of listings adopted so far and the most a report may hold.
struct Budget {
    used: u64,
    most: u64,
}

/// Why a listing was not kept: a bound, or a file that failed its checks.
enum Refusal {
    /// The listings together passed their budget.
    Bound,
    /// The listing failed validation or could not be moved.
    Failed(String),
}

/// Validate one worker listing of `kind` rows and move it to the report.
fn adopt(
    output: &Path,
    target: &Path,
    name: &str,
    kind: AnalysisKind,
    listing: &AnalysisListing,
    total_len: Option<u64>,
    total: &mut Budget,
) -> Result<(), Refusal> {
    total.used = total.used.saturating_add(listing.bytes);
    if total.used > total.most {
        return Err(Refusal::Bound);
    }
    super::super::listing::validate(&output.join(name), kind, listing, total_len)
        .and_then(|()| {
            fs::create_dir_all(target).map_err(|e| e.to_string())?;
            fs::set_permissions(target, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
            fs::rename(output.join(name), target.join(name)).map_err(|e| e.to_string())
        })
        .map_err(Refusal::Failed)
}

/// Keep a section's summary within its bound after a note is added.
fn note(section: &mut AnalysisSection, text: String) {
    section.summary = format!("{}; {text}", section.summary);
    if section.summary.len() > 4096 {
        section.summary.truncate(4000);
    }
}

/// A section that lost part of its result is Partial.
fn partial(section: &mut AnalysisSection) {
    if section.state == AnalysisSectionState::Complete {
        section.state = AnalysisSectionState::Partial;
    }
}

/// Say on `section` that Ghidra's disassembly listing was dropped.
fn drop_disassembly(section: &mut AnalysisSection, refusal: Refusal) {
    section.disassembly = None;
    partial(section);
    match refusal {
        Refusal::Bound => {
            let size =
                crate::byte_size::short_size(super::super::limits::ghidra_listing_bytes());
            super::super::limits::add_for(
                section,
                AnalysisLimitKind::Size,
                LimitSetting::GhidraListing,
                format!(
                    "Ghidra's disassembly listing was not kept: it is bigger than the {size} Ghidra disassembly size limit."
                ),
            );
            note(section, "Ghidra disassembly rejected: over its size limit".into());
        }
        Refusal::Failed(error) => {
            super::super::limits::add(
                section,
                AnalysisLimitKind::Input,
                format!("Ghidra's disassembly listing was not kept: {error}."),
                None,
            );
            note(section, format!("Ghidra disassembly rejected: {error}"));
        }
    }
}

/// Say on `section` that a kept Ghidra listing stops early.
fn note_cut_disassembly(section: &mut AnalysisSection, disassembly: &AnalysisDisassembly) {
    if !disassembly.listing.truncated && disassembly.note.is_empty() {
        return;
    }
    partial(section);
    let rows = super::super::detection::group_digits(disassembly.instructions);
    if disassembly.note.contains("time budget") {
        super::super::limits::add(
            section,
            AnalysisLimitKind::Time,
            format!(
                "Ghidra ran out of time while it listed the code: its disassembly listing stops after {rows} instructions."
            ),
            None,
        );
    } else {
        super::super::limits::add_for(
            section,
            AnalysisLimitKind::Size,
            LimitSetting::GhidraListing,
            format!(
                "Ghidra's disassembly listing reached its {} size limit after {rows} instructions; later code is not listed.",
                crate::byte_size::short_size(super::super::limits::ghidra_listing_bytes())
            ),
        );
    }
}

/// Move validated worker listings next to the report; a listing that fails
/// validation is dropped and its category marked partial. A `carried` category
/// is one a finished analysis already had: the worker did not make its listing.
/// Ghidra's disassembly listing (on the Decompilation or the Disassembly
/// section) has a budget of its own, apart from the combined one.
pub(in super::super) fn adopt_listings(
    directory: &Path,
    report: &mut AnalysisReport,
    carried: &[AnalysisKind],
) {
    let output = directory.join("output/listings");
    let target = directory.join("listings");
    let total_len = report.specimen_len;
    let limits = report.limits.unwrap_or_default().clamped();
    let mut total = Budget {
        used: 0,
        most: limits.listings_total(),
    };
    let mut ghidra = Budget {
        used: 0,
        most: limits.ghidra_listing_bytes(),
    };
    for section in &mut report.sections {
        if carried.contains(&section.kind) {
            continue;
        }
        if let Some(disassembly) = section.disassembly.clone() {
            match adopt(
                &output,
                &target,
                super::super::listing::GHIDRA_DISASSEMBLY_FILE,
                AnalysisKind::Disassembly,
                &disassembly.listing,
                total_len,
                &mut ghidra,
            ) {
                Ok(()) => note_cut_disassembly(section, &disassembly),
                Err(refusal) => drop_disassembly(section, refusal),
            }
        }
        let Some(listing) = section.listing.clone() else {
            continue;
        };
        let name = super::super::listing::file_name(section.kind);
        if let Err(refusal) = adopt(
            &output,
            &target,
            name,
            section.kind,
            &listing,
            total_len,
            &mut total,
        ) {
            section.listing = None;
            section.state = AnalysisSectionState::Partial;
            match refusal {
                Refusal::Bound => {
                    super::super::limits::add_for(
                        section,
                        AnalysisLimitKind::Size,
                        LimitSetting::Listing,
                        "Full listing not kept: the listings of this report exceeded their combined size limit.",
                    );
                    note(section, "full listing rejected: listings exceed their combined bound".into());
                }
                Refusal::Failed(error) => {
                    super::super::limits::add(
                        section,
                        AnalysisLimitKind::Input,
                        format!("Full listing not kept: {error}."),
                        None,
                    );
                    note(section, format!("full listing rejected: {error}"));
                }
            }
        }
    }
    let _ = fs::remove_dir_all(&output);
}

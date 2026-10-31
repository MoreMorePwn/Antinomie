// SPDX-License-Identifier: GPL-3.0-only
//! Adoption of the listings a worker wrote: validated, then moved next to the
//! report.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

/// Validate one worker listing of `kind` rows and move it to the report.
fn adopt(
    output: &Path,
    target: &Path,
    name: &str,
    kind: AnalysisKind,
    listing: &AnalysisListing,
    total_len: Option<u64>,
    total: &mut u64,
    budget: u64,
) -> Result<(), String> {
    *total = total.saturating_add(listing.bytes);
    if *total > budget {
        return Err("listings exceed their combined bound".to_string());
    }
    super::super::listing::validate(&output.join(name), kind, listing, total_len).and_then(|()| {
        fs::create_dir_all(target).map_err(|e| e.to_string())?;
        fs::set_permissions(target, fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        fs::rename(output.join(name), target.join(name)).map_err(|e| e.to_string())
    })
}

/// Keep a section's summary within its bound after a note is added.
fn note(section: &mut AnalysisSection, text: String) {
    section.summary = format!("{}; {text}", section.summary);
    if section.summary.len() > 4096 {
        section.summary.truncate(4000);
    }
}

/// Move validated worker listings next to the report; a listing that fails
/// validation is dropped and its category marked partial. A `carried` category
/// is one a finished analysis already had: the worker did not make its listing.
/// The Decompilation section may also carry the disassembly Ghidra exported.
pub(in super::super) fn adopt_listings(
    directory: &Path,
    report: &mut AnalysisReport,
    carried: &[AnalysisKind],
) {
    let output = directory.join("output/listings");
    let target = directory.join("listings");
    let mut total = 0u64;
    let total_len = report.specimen_len;
    let budget = report.limits.unwrap_or_default().clamped().listings_total();
    for section in &mut report.sections {
        if carried.contains(&section.kind) {
            continue;
        }
        if let Some(disassembly) = section.disassembly.clone()
            && let Err(error) = adopt(
                &output,
                &target,
                super::super::listing::GHIDRA_DISASSEMBLY_FILE,
                AnalysisKind::Disassembly,
                &disassembly.listing,
                total_len,
                &mut total,
                budget,
            )
        {
            section.disassembly = None;
            note(section, format!("Ghidra disassembly rejected: {error}"));
        }
        let Some(listing) = section.listing.clone() else {
            continue;
        };
        let name = super::super::listing::file_name(section.kind);
        if let Err(error) = adopt(
            &output,
            &target,
            name,
            section.kind,
            &listing,
            total_len,
            &mut total,
            budget,
        ) {
            section.listing = None;
            section.state = AnalysisSectionState::Partial;
            note(section, format!("full listing rejected: {error}"));
        }
    }
    let _ = fs::remove_dir_all(&output);
}

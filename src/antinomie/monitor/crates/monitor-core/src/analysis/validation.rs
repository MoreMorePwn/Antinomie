// SPDX-License-Identifier: GPL-3.0-only
//! Bounds and consistency checks on analysis reports and their records,
//! applied to worker output, archived reports and listing rows.
use super::worker::REPORT_MAX_SIZE;
use super::*;
use crate::control;

pub(crate) fn validate_report(report: &AnalysisReport) -> Result<(), String> {
    if serde_json::to_vec(report).map_err(|e| e.to_string())?.len() > REPORT_MAX_SIZE
        || report.sections.len() > AnalysisKind::TRIAGE.len() + AnalysisKind::DEEP.len()
        || report.id.len() > 128
        || report.source_path.len() > 4096
        || report.reason.as_ref().is_some_and(|s| s.len() > 4096)
        || report
            .specimen_len
            .is_some_and(|len| len > u64::from(control::SPECIMEN_MAX_SIZE))
        || report
            .specimen_sha256
            .as_ref()
            .is_some_and(|hash| hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()))
        || report.sections.iter().any(|s| {
            s.entries.len() > 2048
                || s.tools.len() > 16
                || s.tools.iter().any(|t| t.len() > 256)
                || s.listing
                    .as_ref()
                    .is_some_and(|l| l.bytes > super::listing::LISTING_MAX_SIZE)
                || s.summary.len() > 4096
                || s.entries
                    .iter()
                    .any(|e| e.label.len() > 4096 || e.value.len() > 4096)
        })
    {
        return Err("analysis report violates archive bounds".into());
    }
    for (index, section) in report.sections.iter().enumerate() {
        if report.sections[..index]
            .iter()
            .any(|s| s.kind == section.kind)
        {
            return Err("duplicate archived analysis section".into());
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut entropy_count = 0;
        for entry in &section.entries {
            if let Some(record) = &entry.record {
                if matches!(record.data, AnalysisData::Entropy { .. }) {
                    entropy_count += 1;
                    if entropy_count > 65 {
                        return Err(
                            "entropy section exceeds whole-file plus 64-region bound".into()
                        );
                    }
                }
                if record.revision != 1 || record.id == 0 || !ids.insert(record.id) {
                    return Err("invalid revision or duplicate/zero analysis record id".into());
                }
                validate_record(section.kind, entry, record, report.specimen_len)?;
            }
        }
    }
    Ok(())
}
fn validate_range(range: AnalysisRange, total_len: Option<u64>) -> Result<(), String> {
    let total_len = total_len.ok_or("analysis file range has no complete specimen length")?;
    if range
        .offset
        .checked_add(range.len)
        .is_none_or(|end| end > total_len)
    {
        return Err("analysis file range exceeds specimen or overflows".into());
    }
    Ok(())
}
pub(crate) fn validate_record(
    kind: AnalysisKind,
    entry: &AnalysisEntry,
    record: &AnalysisRecord,
    total_len: Option<u64>,
) -> Result<(), String> {
    let location = record.location.as_ref();
    if let Some(location) = location {
        if let Some(range) = location.file_range {
            validate_range(range, total_len)?;
            if location.kind == AnalysisAddressKind::FileOffset && location.value != range.offset {
                return Err("file-offset location disagrees with range".into());
            }
            if entry.offset.is_some_and(|offset| offset != range.offset) {
                return Err("legacy file offset disagrees with structured range".into());
            }
        }
        if location.kind == AnalysisAddressKind::FileOffset
            && total_len.is_none_or(|len| location.value > len)
        {
            return Err("file-offset location exceeds specimen length".into());
        }
    }
    let bounded = |text: &str| text.len() <= 4096;
    let address_location = |address: Option<u64>| {
        location
            .is_none_or(|l| l.kind != AnalysisAddressKind::FileOffset && Some(l.value) == address)
    };
    let valid = match &record.data {
        AnalysisData::Field { group } => bounded(group),
        AnalysisData::Section {
            name,
            address,
            file_size,
            raw_flags,
            flags,
            ..
        } => {
            kind == AnalysisKind::Structures
                && bounded(name)
                && bounded(raw_flags)
                && flags.len() <= 64
                && flags.iter().all(|f| bounded(f))
                && address_location(Some(*address))
                && location
                    .and_then(|l| l.file_range)
                    .is_none_or(|r| Some(r.len) == *file_size)
        }
        AnalysisData::Symbol {
            name,
            kind: symbol_kind,
            scope,
            undefined,
            address,
            size,
        } => {
            kind == AnalysisKind::Structures
                && bounded(name)
                && bounded(symbol_kind)
                && bounded(scope)
                && (!*undefined || address.is_none())
                && address_location(*address)
                && location
                    .and_then(|l| l.file_range)
                    .is_none_or(|r| r.len == *size)
        }
        AnalysisData::Import {
            name,
            library,
            ordinal,
        } => {
            kind == AnalysisKind::Structures
                && name.is_some() != ordinal.is_some()
                && name.as_ref().is_none_or(|s| bounded(s))
                && library.as_ref().is_none_or(|s| bounded(s))
                && location.is_none()
        }
        AnalysisData::Export {
            name,
            ordinal,
            address,
        } => {
            kind == AnalysisKind::Structures
                && name.is_some() != ordinal.is_some()
                && name.as_ref().is_none_or(|s| bounded(s))
                && address_location(*address)
        }
        AnalysisData::String {
            encoding,
            byte_len,
            retained_len,
        } => {
            kind == AnalysisKind::Strings
                && bounded(encoding)
                && !encoding.is_empty()
                && *retained_len == entry.value.len() as u64
                && (!matches!(encoding.as_str(), "ASCII" | "UTF-8") || *retained_len <= *byte_len)
                && location.is_none_or(|l| {
                    l.kind == AnalysisAddressKind::FileOffset
                        && l.file_range.is_none_or(|r| r.len == *byte_len)
                })
        }
        AnalysisData::Entropy { range, milli_bits } => {
            validate_range(*range, total_len)?;
            kind == AnalysisKind::Entropy
                && *milli_bits <= 8000
                && location.is_none_or(|l| {
                    l.kind == AnalysisAddressKind::FileOffset
                        && l.value == range.offset
                        && l.file_range == Some(*range)
                })
        }
        AnalysisData::Property {
            scope,
            observed,
            evidence,
        } => {
            kind == AnalysisKind::Hardening
                && bounded(scope)
                && bounded(observed)
                && bounded(evidence)
        }
        AnalysisData::Instruction {
            address,
            bytes,
            mnemonic,
            operands,
            function,
        } => {
            kind == AnalysisKind::Disassembly
                && bytes.len() <= 64
                && bytes.bytes().all(|c| c.is_ascii_hexdigit() || c == b' ')
                && bounded(mnemonic)
                && bounded(operands)
                && function.as_deref().is_none_or(bounded)
                && address_location(Some(*address))
        }
        AnalysisData::Function { name, address, .. } => {
            matches!(
                kind,
                AnalysisKind::Disassembly | AnalysisKind::Decompilation
            ) && bounded(name)
                && address_location(Some(*address))
        }
        AnalysisData::SourceLine {
            function, address, ..
        } => kind == AnalysisKind::Decompilation && bounded(function) && address_location(*address),
        AnalysisData::RuleMatch {
            rule,
            namespace,
            tags,
            ruleset,
        } => {
            matches!(kind, AnalysisKind::Rules | AnalysisKind::Identification)
                && bounded(rule)
                && !rule.is_empty()
                && bounded(namespace)
                && bounded(ruleset)
                && tags.len() <= 64
                && tags.iter().all(|t| bounded(t))
        }
        AnalysisData::Capability {
            name,
            namespace,
            attack,
            mbc,
        } => {
            kind == AnalysisKind::Capabilities
                && bounded(name)
                && !name.is_empty()
                && bounded(namespace)
                && attack.len() <= 64
                && mbc.len() <= 64
                && attack.iter().chain(mbc.iter()).all(|t| bounded(t))
        }
        AnalysisData::Signature {
            offset,
            description,
        } => {
            kind == AnalysisKind::Embedded
                && bounded(description)
                && !description.is_empty()
                && location.is_some_and(|l| {
                    l.kind == AnalysisAddressKind::FileOffset
                        && l.value == *offset
                        && l.file_range.is_none()
                })
        }
        AnalysisData::Identification {
            category,
            name,
            version,
        } => {
            kind == AnalysisKind::Identification
                && bounded(category)
                && bounded(name)
                && !name.is_empty()
                && version.as_deref().is_none_or(bounded)
        }
    };
    if !valid {
        return Err("structured analysis record violates kind, text or evidence bounds".into());
    }
    Ok(())
}

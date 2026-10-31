// SPDX-License-Identifier: GPL-3.0-only
//! The bound on the text of a row: a value or a list inside a record is cut
//! to what a report keeps, and the cut is reported to the caller.
use super::*;

pub(super) const VALUE_MAX_SIZE: usize = 4096;

pub(super) fn clip(text: &mut String) -> bool {
    if text.len() <= VALUE_MAX_SIZE {
        return false;
    }
    let mut end = VALUE_MAX_SIZE;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}
pub(super) fn bound_data(data: &mut AnalysisData) -> bool {
    let mut truncated = false;
    let mut bound = |text: &mut String| {
        truncated |= clip(text);
    };
    match data {
        AnalysisData::Field { group } => bound(group),
        AnalysisData::Section {
            name,
            raw_flags,
            flags,
            ..
        } => {
            bound(name);
            bound(raw_flags);
            for flag in flags.iter_mut() {
                bound(flag);
            }
            if flags.len() > 64 {
                flags.truncate(64);
                truncated = true;
            }
        }
        AnalysisData::Symbol {
            name, kind, scope, ..
        } => {
            bound(name);
            bound(kind);
            bound(scope);
        }
        AnalysisData::Import { name, library, .. } => {
            if let Some(name) = name {
                bound(name);
            }
            if let Some(library) = library {
                bound(library);
            }
        }
        AnalysisData::Export { name, .. } => {
            if let Some(name) = name {
                bound(name);
            }
        }
        AnalysisData::String { encoding, .. } => bound(encoding),
        AnalysisData::Entropy { .. } => {}
        AnalysisData::Signature { description, .. } => bound(description),
        AnalysisData::FlossString {
            origin, encoding, ..
        } => {
            bound(origin);
            bound(encoding);
        }
        AnalysisData::Layer {
            method,
            sha256,
            packer,
            file,
            report_id,
            note,
            ..
        } => {
            bound(method);
            bound(sha256);
            bound(note);
            for text in [packer, file, report_id].into_iter().flatten() {
                bound(text);
            }
        }
        AnalysisData::Property {
            scope,
            observed,
            evidence,
        } => {
            bound(scope);
            bound(observed);
            bound(evidence);
        }
        AnalysisData::Instruction {
            bytes,
            mnemonic,
            operands,
            function,
            label,
            targets,
            xrefs,
            ..
        } => {
            bound(bytes);
            bound(mnemonic);
            bound(operands);
            if let Some(function) = function {
                bound(function);
            }
            if let Some(label) = label {
                bound(label);
            }
            targets.truncate(super::listing::REFERENCES_MAX);
            xrefs.truncate(super::listing::REFERENCES_MAX);
        }
        AnalysisData::Function { name, .. } => bound(name),
        AnalysisData::SourceLine { function, .. } => bound(function),
        AnalysisData::RuleMatch {
            rule,
            namespace,
            tags,
            ruleset,
        } => {
            bound(rule);
            bound(namespace);
            bound(ruleset);
            truncated |= bound_list(tags);
        }
        AnalysisData::Capability {
            name,
            namespace,
            attack,
            mbc,
        } => {
            bound(name);
            bound(namespace);
            truncated |= bound_list(attack);
            truncated |= bound_list(mbc);
        }
        AnalysisData::Identification {
            category,
            name,
            version,
        } => {
            bound(category);
            bound(name);
            if let Some(version) = version {
                bound(version);
            }
        }
    }
    truncated
}
/// Keep at most 64 list items of bounded text.
fn bound_list(items: &mut Vec<String>) -> bool {
    let mut truncated = items.len() > 64;
    items.truncate(64);
    for item in items.iter_mut() {
        truncated |= clip(item);
    }
    truncated
}

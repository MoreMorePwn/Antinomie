// SPDX-License-Identifier: MIT
//! The Sigma filter: keep the rules whose log source the catalog lists.
//!
//! Keeping a rule only imports it. Whether Antinomie can evaluate it is
//! decided by the rule index and the Sigma adapter, which report a reason for
//! every rule whose category is not captured.
use super::*;

/// `product`, `category` and `service` of a rule document's `logsource` block.
pub(super) fn logsource_of(doc: &str) -> (String, String, String) {
    let mut product = String::new();
    let mut category = String::new();
    let mut service = String::new();
    let mut inside = false;
    let mut indent = 0usize;
    for line in doc.lines() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let width = line.len() - line.trim_start().len();
        if !inside {
            if width == 0 && line.trim_end() == "logsource:" {
                inside = true;
                indent = 0;
            }
            continue;
        }
        if width <= indent {
            break;
        }
        let Some((key, value)) = line.trim().split_once(':') else {
            continue;
        };
        let value = value
            .trim()
            .trim_matches(|c| c == '"' || c == '\'')
            .to_ascii_lowercase();
        match key.trim() {
            "product" => product = value,
            "category" => category = value,
            "service" => service = value,
            _ => {}
        }
    }
    (product, category, service)
}

fn keeps(filter: &SigmaFilter, logsource: &(String, String, String)) -> bool {
    filter.keep.iter().any(|want| {
        let same = |wanted: &str, actual: &str| wanted.is_empty() || wanted == actual;
        same(&want.product.to_ascii_lowercase(), &logsource.0)
            && same(&want.category.to_ascii_lowercase(), &logsource.1)
            && same(&want.service.to_ascii_lowercase(), &logsource.2)
    })
}

/// The documents of `text` whose log source is kept, or `None` when none is.
pub(super) fn filter_sigma_file(
    text: &str,
    filter: &SigmaFilter,
    report: &mut FilterReport,
) -> Option<String> {
    let mut kept = Vec::new();
    for doc in text.split("\n---\n") {
        if !doc.contains("title:") {
            continue;
        }
        if keeps(filter, &logsource_of(doc)) {
            kept.push(doc);
            report.kept += 1;
        } else {
            report.omit("its log source is not one the catalog keeps", 1);
        }
    }
    (!kept.is_empty()).then(|| kept.join("\n---\n"))
}

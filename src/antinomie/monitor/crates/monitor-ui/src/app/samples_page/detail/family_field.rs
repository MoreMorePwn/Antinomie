// SPDX-License-Identifier: GPL-3.0-only
//! The Family field of the Summary's Verdict and family box: the download
//! source's names, the recorded one and the latest Triage candidates.
use super::*;
use antinomie_monitor_core::samples::{Tag, TagKind};

/// The family a YARA rule that matched names, newest rule list first.
fn yara_family(data: &Data) -> Option<&antinomie_monitor_core::samples::RuleRow> {
    data.rollup
        .rules
        .iter()
        .find(|rule| rule.engine.eq_ignore_ascii_case("yara") && !rule.family.trim().is_empty())
}

/// The families the download source's record names: its signature and its
/// tags, when they name different ones.
fn bazaar_families(data: &Data) -> Vec<(String, &'static str)> {
    crate::triage::family::bazaar_families(
        data.record.info.signature.as_deref(),
        &data.record.info.tags,
    )
}

/// The family candidates the newest run with detections names, with the
/// run's name ("Triage, run 3") and where each was named. The same logic as
/// Triage's, without the download source's record (that is shown from the
/// record itself). A sample with no run that names one (it never ran, or its
/// runs had no detections) gets the candidates of its kept static analysis
/// report's rule matches ("Static analysis").
pub(super) fn triage_families(
    data: &Data,
) -> Option<(String, Vec<crate::triage::family::Candidate>)> {
    let named = |hits: &[antinomie_monitor_core::run_digest::DetectionHit]| {
        let found = crate::triage::family::family_candidates(
            hits,
            crate::triage::family::Bazaar::default(),
        );
        (!found.is_empty()).then_some(found)
    };
    data.runs
        .iter()
        .find_map(|entry| {
            let hits = entry.digest.as_ref()?.detections.as_ref()?;
            named(hits).map(|found| (format!("Triage, run {}", entry.number), found))
        })
        .or_else(|| named(&data.static_hits).map(|found| ("Static analysis".to_owned(), found)))
}

/// The families the Family field names, each with where it said so: the
/// recorded family, the download source's signature and tags, then the latest
/// Triage candidates (at most three), each name once.
fn named_families(data: &Data) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut add = |name: &str, source: String| {
        let name = name.trim();
        if !name.is_empty()
            && !out
                .iter()
                .any(|(known, _)| known.eq_ignore_ascii_case(name))
        {
            out.push((name.to_owned(), source));
        }
    };
    let looked_up = data.record.info.looked_up;
    for (name, source) in bazaar_families(data) {
        add(
            &name,
            if looked_up {
                format!("{source} (looked up by hash)")
            } else {
                source.to_owned()
            },
        );
    }
    add(&data.record.family, "recorded with the sample".to_owned());
    if let Some((label, found)) = triage_families(data) {
        for candidate in found.iter().take(3) {
            add(&candidate.name, format!("{label}: {}", candidate.source));
        }
    }
    out
}

/// The Family field: the family names (the download source's, the recorded
/// one, the latest Triage candidates), else a YARA rule's, else the sample's
/// malware-category tags, else "Unknown".
pub(super) fn family(ui: &mut egui::Ui, data: &Data) {
    let named = named_families(data);
    if !named.is_empty() {
        let names = named
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(" \u{b7} ");
        let sources = named
            .iter()
            .map(|(name, source)| format!("{name}: {source}"))
            .collect::<Vec<_>>()
            .join("\n");
        ui.label(RichText::new(names).strong())
            .on_hover_text(sources);
        return;
    }
    if let Some(rule) = yara_family(data) {
        ui.label(RichText::new(rule.family.trim()).strong());
        return;
    }
    let categories: Vec<&Tag> = data
        .tags
        .iter()
        .filter(|tag| tag.kind == TagKind::Category)
        .collect();
    if categories.is_empty() {
        ui.label(theme::hint_text("Unknown"));
    }
    for tag in categories {
        sample_tags::tag(ui, tag);
    }
}

/// Where the family name came from: the download source's signature, a YARA
/// rule, Triage's candidates, or several of them. Nothing when the field shows
/// tags.
pub(super) fn family_source(data: &Data) -> Option<String> {
    let base = download_source(data);
    let triage = triage_families(data).map(|(label, found)| {
        let first = found.first().map(|c| c.source.as_str()).unwrap_or_default();
        format!(
            "{}: {first}",
            label.replacen("Triage, run", "Triage run", 1)
        )
    });
    match (base, triage) {
        (Some(base), Some(triage)) => Some(format!("{base} \u{b7} {triage}")),
        (base, triage) => base.or(triage),
    }
}

fn download_source(data: &Data) -> Option<String> {
    use antinomie_monitor_core::samples::OriginKind;
    if data.record.info.looked_up && !bazaar_families(data).is_empty() {
        return Some("MalwareBazaar signature, looked up by hash".into());
    }
    if bazaar_families(data).len() > 1 {
        return Some("MalwareBazaar signature and tags".into());
    }
    let named = data.record.family.trim();
    let yara = yara_family(data);
    let downloaded = data
        .origins
        .iter()
        .find(|origin| origin.kind == OriginKind::Download);
    match (named.is_empty(), downloaded, yara) {
        (false, Some(origin), Some(rule)) if rule.family.trim().eq_ignore_ascii_case(named) => {
            Some(format!(
                "{} signature \u{b7} YARA rule {}",
                origin.source, rule.rule
            ))
        }
        (false, Some(origin), _) => Some(format!("{} signature", origin.source)),
        (false, None, _) => Some("Recorded with the sample".into()),
        (true, _, Some(rule)) => Some(format!("YARA rule {}", rule.rule)),
        (true, _, None) => None,
    }
}

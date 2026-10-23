// SPDX-License-Identifier: GPL-3.0-only
//! The rows of the Suspicious activity table, and the chips that narrow them.
use super::super::*;
use super::noise::{flag, pace, Agg, Overflow};
use super::{Category, Tier};

/// The table's columns.
pub(in crate::triage) const HEADERS: &[&str] = &[
    "Rule",
    "Tier",
    "Category",
    "Process",
    "Summary",
    "Count",
    "Source",
    "Time",
    "Confidence",
    "Evidence",
    "Version",
    "Outcome",
];
pub(in crate::triage) const COL_TIER: usize = 1;
pub(in crate::triage) const COL_PROCESS: usize = 3;
pub(in crate::triage) const COL_SUMMARY: usize = 4;
pub(in crate::triage) const COL_TIME: usize = 7;

/// Which rows the table shows: the chips above it.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(in crate::triage) struct View {
    /// INFO rows are built only when asked for; their counts are always kept.
    pub show_info: bool,
    /// Rows hidden as housekeeping or outside the run's tree.
    pub show_hidden: bool,
    /// One bit per [`Tier::index`]; none set means every tier.
    pub tiers: u8,
    /// One bit per category in [`Category::ALL`] order; none set means every category.
    pub categories: u16,
}

impl View {
    pub(in crate::triage) fn tier_on(&self, tier: Tier) -> bool {
        self.tiers & (1 << tier.index()) != 0
    }

    pub(in crate::triage) fn toggle_tier(&mut self, tier: Tier) {
        self.tiers ^= 1 << tier.index();
    }

    pub(in crate::triage) fn category_on(&self, category: Category) -> bool {
        self.categories
            & (1 << Category::ALL
                .iter()
                .position(|other| *other == category)
                .unwrap_or(0))
            != 0
    }

    pub(in crate::triage) fn toggle_category(&mut self, category: Category) {
        self.categories ^= 1
            << Category::ALL
                .iter()
                .position(|other| *other == category)
                .unwrap_or(0);
    }
}

fn text<'a>(values: &'a [(&'static str, RowValue)], key: &str) -> Option<&'a str> {
    values.iter().find_map(|(name, value)| match value {
        RowValue::Text(text) if *name == key => Some(text.as_str()),
        _ => None,
    })
}

/// Whether a row passes the chips.
pub(in crate::triage) fn view_keeps(view: &View, values: &[(&'static str, RowValue)]) -> bool {
    if !view.show_hidden
        && values
            .iter()
            .any(|(name, value)| *name == "finding.hidden" && matches!(value, RowValue::Bool(true)))
    {
        return false;
    }
    let tier = text(values, "finding.tier");
    if view.tiers != 0
        && !Tier::ALL
            .iter()
            .any(|candidate| view.tier_on(*candidate) && Some(candidate.tag()) == tier)
    {
        return false;
    }
    let category = text(values, "finding.category");
    view.categories == 0
        || Category::ALL
            .iter()
            .any(|candidate| view.category_on(*candidate) && Some(candidate.tag()) == category)
}

fn tags(agg: &Agg) -> Vec<String> {
    flag::NAMES
        .iter()
        .filter(|(bit, _)| agg.flags & bit != 0)
        .map(|(_, name)| (*name).to_owned())
        .collect()
}

/// The `Outcome` cell: what the first call returned, and how many failed.
fn outcome(agg: &Agg) -> String {
    if agg.count <= 1 {
        agg.outcome.clone()
    } else if agg.failed == agg.count {
        format!("all {} failed", agg.count)
    } else if agg.failed > 0 {
        format!("{} of {} failed", agg.failed, agg.count)
    } else {
        format!("{} succeeded", agg.count)
    }
}

pub(super) fn finding(agg: &Agg) -> Finding {
    let spec = agg.spec();
    let color = agg.tier.color();
    let mut summary = agg.summary.clone();
    if agg.count > 1 {
        if let Some(period) = agg.period() {
            summary.push_str(&format!(" · ×{} every ~{}", agg.count, pace(period)));
        }
    }
    if agg.siblings > 1 {
        summary.push_str(&format!(" · the same in {} processes", agg.siblings));
    }
    let attack: Vec<String> = agg.attack.iter().map(|id| (*id).to_owned()).collect();
    let source = spec.source(agg.attack);
    let time = if agg.first_ns == 0 {
        "—".to_string()
    } else {
        agg.first_ns.to_string()
    };
    let success = match (agg.ret, agg.count) {
        (None, _) => RowValue::Missing,
        (Some(_), count) => RowValue::Bool(agg.failed < count),
    };
    let values = vec![
        ("finding.rule", RowValue::Text(agg.rule.into())),
        (
            "finding.version",
            RowValue::Number(i128::from(spec.version)),
        ),
        ("finding.severity", RowValue::Text(agg.tier.tag().into())),
        ("finding.tier", RowValue::Text(agg.tier.tag().into())),
        ("finding.base_tier", RowValue::Text(agg.base.tag().into())),
        (
            "finding.category",
            RowValue::Text(spec.category.tag().into()),
        ),
        ("finding.technique", RowValue::List(attack)),
        ("finding.count", RowValue::Number(i128::from(agg.count))),
        ("finding.flags", RowValue::List(tags(agg))),
        ("finding.hidden", RowValue::Bool(agg.hidden())),
        (
            "finding.confidence",
            RowValue::Text(
                if agg.high_confidence {
                    "high"
                } else {
                    "limited"
                }
                .into(),
            ),
        ),
        ("finding.source", RowValue::Text(source.clone())),
        ("finding.summary", RowValue::Text(summary.clone())),
        ("finding.object", RowValue::Text(agg.object.clone())),
        ("finding.attempted", RowValue::Bool(true)),
        ("finding.success", success),
        (
            "finding.first_ns",
            RowValue::Number(i128::from(agg.first_ns)),
        ),
        ("finding.last_ns", RowValue::Number(i128::from(agg.last_ns))),
        ("finding.why", RowValue::List(agg.why.clone())),
        ("finding.detail", RowValue::List(agg.detail.clone())),
        (
            "syscall.ret",
            agg.ret
                .map_or(RowValue::Missing, |ret| RowValue::Number(i128::from(ret))),
        ),
        ("event.id", RowValue::Number(i128::from(agg.call_id))),
        ("stream.id", RowValue::Number(i128::from(agg.stream))),
        ("event.time_ns", RowValue::Number(i128::from(agg.first_ns))),
        ("process.pid", RowValue::Number(i128::from(agg.pid))),
        ("process.tid", RowValue::Number(i128::from(agg.tid))),
        ("process.cookie", RowValue::Number(i128::from(agg.cookie))),
        (
            "process.exe",
            agg.image
                .as_ref()
                .map_or(RowValue::Missing, |image| RowValue::Text(image.clone())),
        ),
        ("entry.tag", RowValue::Missing),
    ];
    Finding {
        key: agg.key(),
        call_id: agg.call_id,
        values,
        cells: vec![
            cell(agg.rule, color, false),
            cell(agg.tier.tag(), color, false),
            cell(spec.category.label(), theme::text(), false),
            cell(agg.process.clone(), theme::text(), true),
            cell(summary, theme::text(), false),
            cell(agg.count.to_string(), theme::text(), true),
            cell(source, theme::muted(), false),
            cell(time, theme::text(), true),
            cell(
                if agg.high_confidence {
                    "high"
                } else {
                    "limited"
                },
                theme::text(),
                false,
            ),
            cell(agg.evidence.clone(), theme::text(), true),
            cell(spec.version.to_string(), theme::text(), true),
            cell(outcome(agg), theme::text(), false),
        ],
    }
}

/// The row that stands for rows a cap did not keep.
pub(super) fn overflow_row(rule: &'static str, overflow: &Overflow) -> Option<Finding> {
    let first = overflow.first.as_ref()?;
    let mut agg = first.clone();
    agg.count = overflow.count;
    agg.tier = overflow.tier.unwrap_or(first.tier);
    agg.flags |= flag::CAPPED;
    agg.summary = format!("+{} more not stored (cap)", overflow.count);
    agg.object = "cap".into();
    agg.siblings = 0;
    agg.gaps = Default::default();
    agg.why = vec![format!(
        "{rule}: the caps keep 50 rows per rule and task, 2,000 per rule, 500 per task and 20,000 per run. {} more are counted here and still in the recording.",
        overflow.count
    )];
    agg.detail.clear();
    Some(finding(&agg))
}

// SPDX-License-Identifier: GPL-3.0-only
//! The columns of the Suspicious activity table, its default order and the
//! calls a row keeps as evidence.
use super::super::{
    COL_ATTACK, COL_BEHAVIOUR, COL_COUNT, COL_PROCESS, COL_RESULT, COL_TARGET, COL_TIER, COL_WHEN,
    HEADERS, SHOWN,
};
use super::support::*;
use crate::triage::files;

/// A program that writes `path` once.
fn writes(path: &str) -> Calls {
    vec![open_write(1, path, 3), write(1, 3, b"x"), close(1, 3)]
}

#[test]
fn the_table_lays_out_eight_columns_and_keeps_the_rest_in_the_row() {
    let shown: Vec<&str> = SHOWN.iter().map(|column| HEADERS[*column]).collect();
    assert_eq!(
        shown,
        [
            "Tier",
            "Behaviour",
            "Target",
            "Process",
            "ATT&CK",
            "Count",
            "Result",
            "When"
        ]
    );
    for kept in [
        "Rule",
        "Category",
        "Summary",
        "Source",
        "Time",
        "Confidence",
        "Evidence",
        "Version",
        "Outcome",
    ] {
        assert!(HEADERS.contains(&kept), "{kept} is still stored");
    }
}

#[test]
fn a_row_reads_in_plain_words() {
    let out = run(writes("/etc/cron.d/job"));
    let row = rows(&out, "persistence.cron")[0];
    assert_eq!(row.cells[COL_TIER].text, "high");
    assert_eq!(row.cells[COL_BEHAVIOUR].text, "Cron job installed");
    assert_eq!(row.cells[COL_TARGET].text, "/etc/cron.d/job");
    assert_eq!(row.cells[COL_ATTACK].text, "T1053.003 Cron");
    assert_eq!(
        row.cells[COL_COUNT].text,
        format!("\u{d7}{}", count(row)),
        "the count, as the table reads it"
    );
    assert_eq!(row.cells[COL_RESULT].text, "succeeded");
    assert!(
        row.cells[COL_PROCESS].text.ends_with("(1 \u{b7} 1)"),
        "{}",
        row.cells[COL_PROCESS].text
    );
    assert_eq!(text(row, "finding.title"), "Cron job installed");
    assert_eq!(text(row, "finding.result"), "succeeded");
}

#[test]
fn the_behaviour_cell_names_the_rule_and_its_version_on_hover() {
    let out = run(writes("/etc/cron.d/job"));
    let row = rows(&out, "persistence.cron")[0];
    let tip = row.cells[COL_BEHAVIOUR]
        .values
        .iter()
        .find_map(|(key, value)| match value {
            super::super::super::RowValue::Text(text) if *key == super::super::TIP => Some(text),
            _ => None,
        })
        .expect("a hover text");
    assert!(tip.starts_with("persistence.cron \u{b7} version "), "{tip}");
}

#[test]
fn a_tier_chip_explains_the_tier_and_a_limited_row_says_why() {
    let out = run(writes("/etc/cron.d/job"));
    let row = rows(&out, "persistence.cron")[0];
    let tier = &row.cells[COL_TIER];
    let tip = |key: &str| {
        tier.values.iter().find_map(|(name, value)| match value {
            super::super::super::RowValue::Text(text) if *name == key => Some(text.clone()),
            _ => None,
        })
    };
    let hover = tip(super::super::TIP).expect("a hover text");
    assert!(hover.starts_with("High: Something ordinary software essentially never does"));
    assert!(hover.contains("The rule's own tier (High)."));
    // A call recorded in full has full confidence.
    assert_eq!(text(row, "finding.confidence"), "high");
    assert!(tip(super::super::LIMITED).is_none());
}

#[test]
fn a_failed_call_is_greyed_and_says_all_failed_and_why_the_tier_dropped() {
    let out = run(vec![open(1, "/etc/ld.so.preload", 1, -13)]);
    let row = rows(&out, "injection.ld_so_preload")[0];
    assert_eq!(row.cells[COL_RESULT].text, "all failed");
    assert_eq!(row.cells[COL_TIER].text, "medium");
    let hover = row.cells[COL_TIER]
        .values
        .iter()
        .find_map(|(key, value)| match value {
            super::super::super::RowValue::Text(text) if *key == super::super::TIP => Some(text),
            _ => None,
        })
        .expect("a hover text");
    assert!(
        hover.contains("The rule's tier is High; lowered to Medium because every call failed."),
        "{hover}"
    );
}

#[test]
fn repeats_fold_into_one_row_that_keeps_each_call_as_evidence() {
    let mut calls = Vec::new();
    for fd in 3..6 {
        calls.push(open_write(1, "/etc/cron.d/job", fd));
        calls.push(close(1, fd as u64));
    }
    let out = run(calls);
    let row = rows(&out, "persistence.cron")[0];
    assert!(count(row) >= 3);
    assert_eq!(row.cells[COL_COUNT].text, format!("\u{d7}{}", count(row)));
    let kept = list(row, "finding.samples");
    assert_eq!(kept.len() as u64, count(row));
    let first: Vec<&str> = kept[0].split('\u{1f}').collect();
    assert_eq!(first.len(), 6);
    assert_eq!(first[3], "open");
    assert!(first[4].contains("/etc/cron.d/job"));
    assert!(first[5].starts_with("returned"));
    // The calls are numbered in order, so the evidence is too.
    let calls: Vec<u64> = kept
        .iter()
        .map(|line| line.split('\u{1f}').nth(2).unwrap().parse().unwrap())
        .collect();
    assert!(calls.windows(2).all(|pair| pair[0] < pair[1]), "{calls:?}");
}

#[test]
fn rows_come_worst_tier_first_then_by_time() {
    let out = run(vec![
        exec(1, "/bin/bash", &["bash"]),
        open_write(1, "/etc/cron.d/job", 3),
        open_write(1, "/etc/at.deny.d/x", 4),
        stat(1, "/proc/cpuinfo", 0),
    ]);
    let tiers: Vec<(usize, u64)> = out
        .rows
        .iter()
        .map(|row| {
            (
                super::super::Tier::from_tag(&text(row, "finding.tier"))
                    .unwrap()
                    .index(),
                files::number(&row.values, "finding.first_ns").unwrap_or(0),
            )
        })
        .collect();
    assert!(tiers.len() >= 3, "{tiers:?}");
    let mut sorted = tiers.clone();
    sorted.sort();
    assert_eq!(tiers, sorted, "tier first, then first time");
    assert_eq!(text(&out.rows[0], "finding.rule"), "persistence.cron");
}

#[test]
fn the_when_column_is_a_placeholder_until_the_run_start_is_known() {
    let out = run(writes("/etc/cron.d/job"));
    let row = rows(&out, "persistence.cron")[0];
    assert!(row.cells[COL_WHEN].text.starts_with('+'));
}

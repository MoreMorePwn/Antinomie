// SPDX-License-Identifier: GPL-3.0-only
//! Card C, Hierarchy: the tree, its two switches, the click-through and the
//! equality with the Syscall Trace's count.
use super::*;
use crate::statistics::hierarchy::{rows, Row, State};
use crate::statistics::navigate::with_window_filter;
use antinomie_monitor_core::recording::open_recording_cancellable;
use antinomie_triage::statistics::aggregate::ResultKey;
use serde_json::json;
use std::sync::atomic::AtomicBool;

/// Every call row open, so the result rows show too.
fn all_open(stats: &antinomie_triage::statistics::RunStatistics) -> State {
    let mut state = State::default();
    for group in &stats.hierarchy {
        for call in &group.calls_by_name {
            state
                .toggled
                .insert(format!("{}/{}", group.group, call.name));
        }
    }
    state
}

fn row<'a>(rows: &'a [Row], label: &str) -> &'a Row {
    rows.iter()
        .find(|row| row.label == label)
        .unwrap_or_else(|| {
            panic!(
                "no row {label}: {:?}",
                rows.iter().map(|r| &r.label).collect::<Vec<_>>()
            )
        })
}

#[test]
fn c2_the_tree_has_group_call_and_result_rows_with_shares_and_sorts() {
    let fixture = Fixture::new(&calls());
    let stats = stats_of(&fixture, "");
    assert_eq!(stats.calls, 15);
    let state = all_open(&stats);
    let all = rows(&stats, &state, None);
    // Depths: groups 0, calls 1, results 2; a call's results add up to it.
    let groups: Vec<&Row> = all.iter().filter(|r| r.depth == 0).collect();
    assert_eq!(groups.iter().map(|g| g.calls).sum::<u64>(), 15);
    let mut checked = 0;
    for (i, call) in all.iter().enumerate().filter(|(_, r)| r.depth == 1) {
        let results: u64 = all[i + 1..]
            .iter()
            .take_while(|r| r.depth == 2)
            .map(|r| r.calls)
            .sum();
        assert_eq!(results, call.calls, "{}", call.label);
        checked += 1;
    }
    assert_eq!(checked, 5, "openat, newfstatat, read, write, connect");
    let openat = row(&all, "openat");
    assert_eq!(openat.calls, 5);
    assert!((openat.of_view - 5.0 * 100.0 / 15.0).abs() < 1e-9);
    let group_calls = groups
        .iter()
        .find(|g| {
            g.label
                == antinomie_monitor_core::syscall_groups::SyscallGroup::of("openat")
                    .unwrap()
                    .label()
        })
        .unwrap()
        .calls;
    assert!((openat.of_parent.unwrap() - 5.0 * 100.0 / group_calls as f64).abs() < 1e-9);
    assert_eq!(openat.failed, 2);
    assert_eq!(
        row(&all, "ENOENT").clause.as_deref(),
        Some("syscall.name == openat && syscall.errno == 2")
    );
    // Closed calls hide their results.
    let closed = rows(&stats, &State::default(), None);
    assert!(closed.iter().all(|r| r.depth <= 1));
    // Sorting by calls descending puts the busiest call first inside its group.
    let sorted = rows(&stats, &State::default(), Some((1, true)));
    let file_calls: Vec<&Row> = sorted
        .iter()
        .skip_while(|r| r.label != groups[0].label)
        .skip(1)
        .take_while(|r| r.depth == 1)
        .collect();
    assert!(
        file_calls.windows(2).all(|w| w[0].calls >= w[1].calls),
        "{file_calls:?}"
    );
    // By name, ascending.
    let named = rows(&stats, &State::default(), Some((0, false)));
    let names: Vec<&str> = named
        .iter()
        .filter(|r| r.depth == 1)
        .map(|r| r.label.as_str())
        .collect();
    assert!(!names.is_empty());
}

#[test]
fn c3_failed_only_and_by_error_come_from_the_same_result() {
    let fixture = Fixture::new(&calls());
    let stats = stats_of(&fixture, "");
    let plain: u64 = stats.hierarchy.iter().map(|g| g.failed).sum();
    assert_eq!(plain, 5, "openat x2, newfstatat x2, connect x1");
    let failed = rows(
        &stats,
        &State {
            failed_only: true,
            ..State::default()
        },
        None,
    );
    let total: u64 = failed
        .iter()
        .filter(|r| r.depth == 0)
        .map(|r| r.calls)
        .sum();
    assert_eq!(total, plain);
    for r in failed.iter().filter(|r| r.depth == 0) {
        assert!((r.of_view - r.calls as f64 * 100.0 / plain as f64).abs() < 1e-9);
    }
    // Pivot: ENOENT first with its calls.
    let pivot = rows(
        &stats,
        &State {
            by_error: true,
            ..State::default()
        },
        None,
    );
    let enoent = row(&pivot, "ENOENT");
    assert_eq!(enoent.depth, 0);
    assert_eq!(enoent.calls, 4);
    assert_eq!(enoent.clause.as_deref(), Some("syscall.errno == 2"));
    let children: Vec<&Row> = pivot
        .iter()
        .skip_while(|r| r.label != "ENOENT")
        .skip(1)
        .take_while(|r| r.depth == 1)
        .collect();
    assert_eq!(children.iter().map(|r| r.calls).sum::<u64>(), 4);
    assert!(children.iter().any(|r| r.label == "openat" && r.calls == 2));
    assert!(children
        .iter()
        .any(|r| r.label == "newfstatat" && r.calls == 2));
    // Failed only plus By error lists errors alone and totals the same.
    let both = rows(
        &stats,
        &State {
            failed_only: true,
            by_error: true,
            ..State::default()
        },
        None,
    );
    assert!(both.iter().filter(|r| r.depth == 0).all(|r| r.is_error));
    assert_eq!(
        both.iter()
            .filter(|r| r.depth == 0)
            .map(|r| r.calls)
            .sum::<u64>(),
        plain
    );
    // A no-result row shows in the plain pivot.
    assert!(pivot.iter().any(|r| r.no_result && r.depth == 0));
}

/// What the Syscall Trace would count for `filter`: its own read, no hidden category.
pub(super) fn trace_count(fixture: &Fixture, filter: &str) -> u64 {
    let compiled = crate::query::compile_note(filter);
    assert!(compiled.error.is_none(), "{filter}: {:?}", compiled.error);
    let cancel = AtomicBool::new(false);
    open_recording_cancellable(&fixture.directory, &cancel)
        .unwrap()
        .matching_totals_cancellable(None, &cancel, |call| compiled.keep(call))
        .unwrap()
        .total
}

#[test]
fn c4_every_clause_opens_exactly_the_calls_behind_its_number() {
    let fixture = Fixture::new(&calls());
    let stats = stats_of(&fixture, "");
    let all = rows(&stats, &all_open(&stats), None);
    let mut checked = 0;
    for r in &all {
        for (clause, expected) in [(&r.clause, r.calls), (&r.failed_clause, r.failed)] {
            let Some(clause) = clause else { continue };
            let filter = with_window_filter("", clause);
            let behind = stats_of(&fixture, &filter);
            assert_eq!(behind.calls, expected, "{} · {filter}", r.label);
            // The Trace's count is ours plus the other program's calls it also lists.
            assert_eq!(
                trace_count(&fixture, &filter),
                behind.calls + behind.out_of_scope,
                "{filter}"
            );
            checked += 1;
        }
    }
    assert!(checked >= 20, "{checked}");
    // With a window filter the clause is added to it.
    let combined = with_window_filter(
        "syscall.name == openat || syscall.name == read",
        "syscall.errno == 2",
    );
    assert_eq!(
        combined,
        "(syscall.name == openat || syscall.name == read) && syscall.errno == 2"
    );
    assert_eq!(stats_of(&fixture, &combined).calls, 2);
    // The result kinds of section 6.
    assert_eq!(
        row(&all, "returned")
            .clause
            .as_deref()
            .map(|c| c.ends_with("syscall.success == true")),
        Some(true)
    );
    let none = row(&all, ResultKey::NO_RESULT_LABEL);
    assert!(none.clause.as_deref().unwrap().ends_with("missing ret"));
    assert_eq!(none.calls, 1);
}

#[test]
fn c4_a_click_in_the_window_sends_the_filter_to_the_trace() {
    let fixture = Fixture::new(&calls());
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(Some(Tab::Hierarchy));
    rig.settle();
    rig.click("openat");
    assert_eq!(
        rig.navigated,
        [Navigate::Filter("syscall.name == openat".into())]
    );
    // The window's own filter stays in front.
    rig.navigated.clear();
    rig.window.filter = "tid == 2".into();
    rig.window.apply();
    rig.settle();
    rig.click("openat");
    assert_eq!(
        rig.navigated,
        [Navigate::Filter(
            "(tid == 2) && syscall.name == openat".into()
        )]
    );
}

#[test]
fn c5_a_hidden_group_asks_first_and_cancel_changes_nothing() {
    let fixture = Fixture::new(&calls());
    let group = antinomie_monitor_core::syscall_groups::SyscallGroup::of("openat").unwrap();
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.hidden = vec![group];
    rig.window.request_open(Some(Tab::Hierarchy));
    rig.settle();
    rig.click("openat");
    assert!(rig.navigated.is_empty(), "nothing opens before the answer");
    let question = rig.window.question.clone().expect("the question");
    assert_eq!(question.group, group);
    let shown = rig.texts();
    assert!(
        shown.iter().any(|(t, _)| t
            == &format!(
                "{} is hidden in the Syscall Trace. Show it there and open these calls?",
                group.label()
            )),
        "{shown:?}"
    );
    rig.click("Cancel");
    assert!(rig.window.question.is_none());
    assert!(rig.navigated.is_empty());
    // Show and open sends the group to show with the filter.
    rig.click("openat");
    rig.click("Show and open");
    assert_eq!(
        rig.navigated,
        [Navigate::ShowGroup {
            group,
            filter: "syscall.name == openat".into()
        }]
    );
    assert!(rig.window.question.is_none());
    // A group that is not hidden opens straight away.
    rig.navigated.clear();
    rig.hidden.clear();
    rig.click("openat");
    assert_eq!(rig.navigated.len(), 1);
}

#[test]
fn c6_a_reduced_recording_shows_not_saved_apart_from_the_exact_counts() {
    let fixture = Fixture::with_manifest(
        &calls(),
        json!({"run": {"reduced": {
            "at_ms": 1, "at_guest_ns": 12_000, "quota_bytes": 100,
            "dropped_calls": {"openat": 4, "read": 1}
        }}}),
    );
    let stats = stats_of(&fixture, "");
    assert_eq!(stats.calls, 15, "the saved counts stay exact");
    let all = rows(&stats, &State::default(), None);
    assert_eq!(row(&all, "openat").not_saved, Some(4));
    assert_eq!(row(&all, "read").not_saved, Some(1));
    assert_eq!(row(&all, "write").not_saved, None);
    let file = antinomie_monitor_core::syscall_groups::SyscallGroup::of("openat")
        .unwrap()
        .label();
    assert!(row(&all, file).not_saved.unwrap() >= 5);
    let mut rig = Rig::new(Some(target(&fixture, "run-a")));
    rig.window.request_open(Some(Tab::Hierarchy));
    rig.settle();
    let shown = rig.texts();
    assert!(shown.iter().any(|(t, _)| t == "+4 not saved"), "{shown:?}");
    // The strip says the run was reduced.
    assert!(
        shown.iter().any(|(t, _)| t.contains("Reduced from")),
        "{shown:?}"
    );
}

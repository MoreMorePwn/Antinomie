// SPDX-License-Identifier: GPL-3.0-only
//! Re-readings of the hierarchy that need no new walk (design 2.3): "Failed
//! only" and "By error" are cuts of the same counts.
use super::aggregate::{CallRow, GroupRow, ResultKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The hierarchy keeping only calls that returned an error. A call row keeps
/// its failed count and its error results; groups and calls with no failure go.
pub fn failed_only(hierarchy: &[GroupRow]) -> Vec<GroupRow> {
    hierarchy
        .iter()
        .filter_map(|group| {
            let calls_by_name: Vec<CallRow> = group
                .calls_by_name
                .iter()
                .filter(|call| call.failed > 0)
                .map(|call| CallRow {
                    name: call.name.clone(),
                    calls: call.failed,
                    failed: call.failed,
                    results: call
                        .results
                        .iter()
                        .filter(|(key, _)| key.is_error())
                        .cloned()
                        .collect(),
                    other_results: failed_in_overflow(call),
                })
                .collect();
            (group.failed > 0).then(|| GroupRow {
                group: group.group.clone(),
                calls: group.failed,
                failed: group.failed,
                calls_by_name,
            })
        })
        .collect()
}

/// Failed calls of `call` whose error was past the kept results.
fn failed_in_overflow(call: &CallRow) -> u64 {
    let kept: u64 = call
        .results
        .iter()
        .filter(|(key, _)| key.is_error())
        .map(|(_, n)| n)
        .sum();
    call.failed.saturating_sub(kept)
}

/// One error (or other result) and the calls that returned it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultRow {
    pub result: ResultKey,
    pub calls: u64,
    /// Call names with their counts, most numerous first.
    pub by_call: Vec<(String, u64)>,
}

/// The pivot: results with their calls, and the failed calls whose error was
/// past the per-call cap of results ("other errors", by call name).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorPivot {
    pub rows: Vec<ResultRow>,
    pub other_errors: Vec<(String, u64)>,
}

impl ErrorPivot {
    /// Calls the pivot lists, errors only when it was made `failed_only`.
    pub fn total(&self) -> u64 {
        self.rows.iter().map(|row| row.calls).sum::<u64>()
            + self.other_errors.iter().map(|(_, n)| n).sum::<u64>()
    }
}

/// The hierarchy pivoted to result -> call. With `failed_only` only errors are
/// listed; then `total()` equals the sum of the calls' `failed`.
pub fn by_error(hierarchy: &[GroupRow], failed_only: bool) -> ErrorPivot {
    let mut rows: BTreeMap<ResultKey, BTreeMap<&str, u64>> = BTreeMap::new();
    let mut other_errors = BTreeMap::<&str, u64>::new();
    for group in hierarchy {
        for call in &group.calls_by_name {
            for (key, n) in &call.results {
                if failed_only && !key.is_error() {
                    continue;
                }
                *rows.entry(*key).or_default().entry(&call.name).or_default() += n;
            }
            let overflow = failed_in_overflow(call);
            if overflow > 0 {
                *other_errors.entry(&call.name).or_default() += overflow;
            }
        }
    }
    let mut out: Vec<ResultRow> = rows
        .into_iter()
        .map(|(result, calls)| {
            let mut by_call: Vec<(String, u64)> = calls
                .into_iter()
                .map(|(name, n)| (name.to_owned(), n))
                .collect();
            by_call.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            ResultRow {
                result,
                calls: by_call.iter().map(|(_, n)| n).sum(),
                by_call,
            }
        })
        .collect();
    out.sort_by(|a, b| b.calls.cmp(&a.calls).then(a.result.cmp(&b.result)));
    let mut other: Vec<(String, u64)> = other_errors
        .into_iter()
        .map(|(name, n)| (name.to_owned(), n))
        .collect();
    other.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ErrorPivot {
        rows: out,
        other_errors: other,
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! What Triage, Run History and the report say about a recording that ran in
//! reduced mode (see `antinomie_monitor_core::reduced`). One wording, so the
//! three places agree.
use crate::time_format::{elapsed, local_seconds};
use antinomie_monitor_core::reduced::ReducedRecording;

/// How many dropped calls the second line names.
const NAMED: usize = 6;

/// "12,345" for 12345.
fn grouped(count: u64) -> String {
    let digits = count.to_string();
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

/// The lines to show: the headline, what was dropped, and how it ended.
/// `started_ms` puts the switch on the run's own clock.
pub(crate) fn lines(reduced: &ReducedRecording, started_ms: Option<u64>) -> Vec<String> {
    let into = started_ms
        .filter(|start| reduced.at_ms >= *start)
        .map(|start| format!(" ({} into the run)", elapsed(reduced.at_ms - start)))
        .unwrap_or_default();
    let calls = reduced.dropped_total();
    let mut lines = vec![format!(
        "Recording quota nearly full at {}{into}; from then on only suspicious-activity calls were kept, {} {} dropped.",
        local_seconds(reduced.at_ms / 1000),
        grouped(calls),
        if calls == 1 { "call" } else { "calls" },
    )];
    let ranked = reduced.dropped_ranked();
    if !ranked.is_empty() {
        let named: Vec<String> = ranked
            .iter()
            .take(NAMED)
            .map(|(name, count)| format!("{name} {}", grouped(*count)))
            .collect();
        let more = ranked.len().saturating_sub(NAMED);
        lines.push(format!(
            "Dropped calls: {}{}. Saved after the switch: {} packets; dropped: {} packets.",
            named.join(", "),
            if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            },
            grouped(reduced.kept_packets),
            grouped(reduced.dropped_packets),
        ));
    }
    if let Some(stopped) = reduced.network_stopped_ms {
        lines.push(format!(
            "The network capture was stopped at {} to leave the rest of the quota for system calls; packets it saved before that are kept.",
            local_seconds(stopped / 1000)
        ));
    }
    if let Some(full) = reduced.full_at_ms {
        lines.push(format!(
            "Recording quota reached at {}: it was full, and nothing more was saved after that.",
            local_seconds(full / 1000)
        ));
    }
    lines
}

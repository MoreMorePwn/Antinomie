// SPDX-License-Identifier: GPL-3.0-only
//! The service log's line for a sensitive read (design 5.12.7): the bytes the
//! sample or the guest produced, or the sample itself, left the daemon for a
//! caller. The line names the caller, the operation, the run or sample and the
//! number of bytes. It never carries the bytes, a host path or a name from the
//! sample.

use std::sync::Arc;

/// Where audit lines go: the daemon's service log.
pub type AuditLog = Arc<dyn Fn(&str) + Send + Sync>;

/// A value that is safe on one log line: printable ASCII only, at most 128
/// characters (a caller id or key is short; anything else is cut).
fn plain(text: &str) -> String {
    text.chars()
        .take(128)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// `sensitive read: caller=<id> op=<op> <kind>=<subject> size=<bytes>`.
pub fn line(caller: &str, op: &str, kind: &str, subject: &str, size: u64) -> String {
    format!(
        "sensitive read: caller={} op={} {}={} size={}",
        plain(caller),
        plain(op),
        plain(kind),
        plain(subject),
        size
    )
}

/// Write the line if a log is set.
pub fn record(
    log: Option<&AuditLog>,
    caller: &str,
    op: &str,
    kind: &str,
    subject: &str,
    size: u64,
) {
    if let Some(log) = log {
        log(&line(caller, op, kind, subject, size));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_has_the_four_facts_and_stays_on_one_line() {
        let text = line(
            "local:1000",
            "recording.files.content",
            "recording",
            "abc",
            42,
        );
        assert_eq!(
            text,
            "sensitive read: caller=local:1000 op=recording.files.content recording=abc size=42"
        );
        let odd = line("a\nb c", "op", "run", "x\ty", 1);
        assert!(!odd.contains('\n') && !odd.contains('\t'));
        assert!(odd.contains("caller=a?b?c"));
    }
}

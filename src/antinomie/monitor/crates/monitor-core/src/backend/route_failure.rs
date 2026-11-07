// SPDX-License-Identifier: GPL-3.0-only
//! A run whose route could not be brought up before the program started: it
//! never ran, but it leaves a record, so Run History shows what was asked for
//! and why it did not start.
use super::*;
use crate::route::{RouteKind, RouteRecord, RouteVia};

/// The route record of a run that never got its route: the one it asked for.
pub(super) fn unstarted_record(requested: Option<RouteKind>, default: RouteKind) -> RouteRecord {
    let kind = requested.unwrap_or(default);
    RouteRecord {
        kind,
        label: kind.label().to_owned(),
        via: RouteVia::Gateway,
        checked_ms: None,
        stats: None,
        blocked_ports: Vec::new(),
    }
}

/// "Not started: the Tor route did not become ready in 90 s", with the route's
/// own error (and the tor log lines it carries) after it.
pub(super) fn not_started_text(kind: RouteKind, error: &str) -> String {
    let seconds = error
        .split_once("within ")
        .and_then(|(_, rest)| rest.split_once(" s"))
        .map(|(seconds, _)| seconds.trim().to_owned())
        .filter(|seconds| seconds.chars().all(|c| c.is_ascii_digit()));
    match seconds {
        Some(seconds) => format!(
            "Not started: the {} route did not become ready in {seconds} s. {error}",
            kind.label()
        ),
        None => format!(
            "Not started: the {} route could not be brought up. {error}",
            kind.label()
        ),
    }
}

impl Session {
    /// Saves the run that did not start because its route failed: state
    /// Failed to start, the reason as the run's issue, nothing captured.
    pub(super) fn record_unstarted_run(
        &mut self,
        run: &mut ProgramRun,
        mut owner: RunArtifactOwner,
        text: String,
    ) -> String {
        run.summary.state = RunState::FailedToStart;
        run.settle_unstarted_analysis(&text);
        owner.tree_complete = true;
        owner.issue(text.clone());
        let mut issues = vec![text];
        if let Err(error) = owner.save() {
            issues.push(error);
        }
        run.storage_error(issues.join("; "));
        if let Err(error) = run.persist_summary() {
            issues.push(error);
        }
        issues.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tor_bootstrap_timeout_is_reported_as_not_ready_in_so_many_seconds() {
        let error = "Tor: tor did not finish bootstrapping within 90 s (stuck at 50% Loading \
                     relay descriptors); check that this computer can reach the Tor network. \
                     Log: /d/tor.log. Last log lines: Bootstrapped 50%";
        let text = not_started_text(RouteKind::Tor, error);
        assert!(
            text.starts_with("Not started: the Tor route did not become ready in 90 s."),
            "{text}"
        );
        assert!(text.contains("stuck at 50%") && text.contains("Last log lines"));
        let other = not_started_text(RouteKind::Tor, "Tor: cannot start tor: not found");
        assert!(other.starts_with("Not started: the Tor route could not be brought up."));
    }

    #[test]
    fn the_record_names_the_route_that_was_asked_for() {
        let record = unstarted_record(Some(RouteKind::Tor), RouteKind::default());
        assert_eq!(record.kind, RouteKind::Tor);
        assert_eq!(record.via, RouteVia::Gateway);
        assert!(record.stats.is_none() && record.checked_ms.is_none());
        assert_eq!(unstarted_record(None, RouteKind::Tor).kind, RouteKind::Tor);
    }
}

// SPDX-License-Identifier: GPL-3.0-only
//! The job state machine of design 5.6, as data. Every transition the store
//! makes is checked against this table; the tests walk every pair of states.

use crate::api::run::RunState::{self, *};

/// Every edge of the diagram of 5.6 (the two entry edges, `[*] -> queued` and
/// `[*] -> rejected`, are made by `submit`), plus the shutdown edge of 2.7:
/// `cancelling -> queued` for a running job put back when the daemon stops.
pub const EDGES: [(RunState, RunState); 11] = [
    (Queued, Running),
    (Queued, Cancelled),
    (Queued, Failed),
    (Running, Cancelling),
    (Running, Succeeded),
    (Running, Partial),
    (Running, Failed),
    (Running, Queued),
    (Cancelling, Cancelled),
    (Cancelling, Failed),
    (Cancelling, Queued),
];

/// Whether `from -> to` is an edge.
pub fn allowed(from: RunState, to: RunState) -> bool {
    EDGES.contains(&(from, to))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [RunState; 8] = [
        Queued, Running, Cancelling, Succeeded, Partial, Failed, Cancelled, Rejected,
    ];

    #[test]
    fn terminal_states_have_no_way_out() {
        for from in ALL.into_iter().filter(|s| s.is_terminal()) {
            for to in ALL {
                assert!(!allowed(from, to), "{from:?} -> {to:?}");
            }
        }
    }

    #[test]
    fn nothing_leads_into_rejected_or_back_to_the_start() {
        for from in ALL {
            assert!(!allowed(from, Rejected), "{from:?} -> rejected");
            assert!(!allowed(from, from), "{from:?} -> itself");
        }
        assert!(
            !allowed(Queued, Cancelling),
            "a queued job is cancelled at once"
        );
        assert!(!allowed(Queued, Succeeded) && !allowed(Queued, Partial));
        assert!(
            !allowed(Running, Cancelled),
            "a running job goes through cancelling"
        );
        assert!(!allowed(Cancelling, Running));
        assert!(!allowed(Cancelling, Succeeded) && !allowed(Cancelling, Partial));
    }

    #[test]
    fn the_diagram_edges_are_present() {
        assert!(allowed(Queued, Running) && allowed(Queued, Cancelled) && allowed(Queued, Failed));
        assert!(allowed(Running, Cancelling) && allowed(Running, Queued));
        assert!(allowed(Cancelling, Cancelled) && allowed(Cancelling, Failed));
        assert_eq!(EDGES.len(), 11);
    }
}

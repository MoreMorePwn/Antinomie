// SPDX-License-Identifier: GPL-3.0-only
//! The guest connections every gateway of the process carries at once (A27).
//!
//! A daemon runs every lane's engine in one process, so the lanes' gateways
//! share one descriptor table with the recordings, the host tools and the
//! job store. A guest that scans the network opens hundreds of connections a
//! second; each costs one descriptor (two for a built-in service). Besides
//! each gateway's own limit, the gateways together keep below what the
//! open-file limit leaves after [`RESERVE`] descriptors for everything else;
//! a connection over it is dropped like one over the gateway's own limit
//! (the guest sees no answer and may retry), never the rest of the process.
use std::sync::atomic::{AtomicUsize, Ordering};

/// Descriptors kept for the rest of the process.
const RESERVE: u64 = 512;
/// Descriptors one connection may hold (a built-in service's socket pair).
const PER_CONNECTION: u64 = 2;
/// Connections allowed whatever the limit says.
const FLOOR: usize = 16;

static LIVE: AtomicUsize = AtomicUsize::new(0);

/// One connection's share; given back when dropped.
pub(crate) struct Slot(());

impl Drop for Slot {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How many connections the process may carry under the soft limit `soft`
/// (`None`: unlimited).
fn capacity(soft: Option<u64>) -> usize {
    match soft {
        None => usize::MAX,
        Some(soft) => usize::try_from(soft.saturating_sub(RESERVE) / PER_CONNECTION)
            .unwrap_or(usize::MAX)
            .max(FLOOR),
    }
}

fn take_within(capacity: usize) -> Option<Slot> {
    LIVE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
        (live < capacity).then_some(live + 1)
    })
    .ok()
    .map(|_| Slot(()))
}

/// A slot for one more connection, or `None` when the process carries as
/// many as its open-file limit allows.
pub(crate) fn take() -> Option<Slot> {
    take_within(capacity(crate::open_files::soft_limit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_capacity_leaves_the_reserve_and_has_a_floor() {
        assert_eq!(capacity(Some(1024)), 256);
        assert_eq!(capacity(Some(65_536)), 32_512);
        assert_eq!(capacity(Some(256)), FLOOR);
        assert_eq!(capacity(None), usize::MAX);
    }

    #[test]
    fn slots_are_given_back_when_dropped() {
        // Other tests may hold slots: measure from what is live now.
        let base = LIVE.load(Ordering::Acquire);
        let first = take_within(base + 2).expect("room for one");
        let second = take_within(base + 2).expect("room for two");
        assert!(take_within(base + 2).is_none());
        drop(first);
        let third = take_within(base + 2).expect("a slot came back");
        drop((second, third));
    }

    const CHILD: &str = "ANTINOMIE_ROUTE_BUDGET_CHILD";

    /// A guest that opens as many built-in service connections as it can,
    /// under the 1,024 soft limit many distributions start a process with:
    /// the gateways stop at their share and the rest of the process can
    /// still open files (A27). Runs in a child process, so the lowered limit
    /// touches no other test.
    #[test]
    fn a_1024_limit_keeps_room_for_the_rest_of_the_process() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "route::budget::tests::child_fills_the_budget_under_a_1024_limit",
                "--ignored",
                "--test-threads=1",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success(), "the child test failed: {status}");
    }

    #[test]
    #[ignore = "the child of a_1024_limit_keeps_room_for_the_rest_of_the_process"]
    fn child_fills_the_budget_under_a_1024_limit() {
        use super::super::{
            config::{Egress, Sink},
            upstream::{self, Dest},
        };
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        use std::{net::Ipv4Addr, sync::Arc};
        if std::env::var_os(CHILD).is_none() {
            return;
        }
        let hard = getrlimit(Resource::Nofile).maximum;
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: Some(1024),
                maximum: hard,
            },
        )
        .unwrap();
        let sink = Egress::Sink(Sink {
            address: Ipv4Addr::new(10, 0, 2, 2),
            external: None,
        });
        let mut held = Vec::new();
        while let Some(slot) = take() {
            let stream = upstream::dial(&sink, &Dest::Ip(Ipv4Addr::new(192, 0, 2, 1), 80))
                .expect("a connection within the budget is dialed");
            let pipes = upstream::start_pipes(stream, Arc::new(|| {}))
                .expect("a connection within the budget gets its pipes");
            held.push((slot, pipes));
            assert!(held.len() <= 1024, "the budget has no end");
        }
        assert_eq!(held.len(), 256);
        let files: Vec<_> = (0..400)
            .map(|_| std::fs::File::open("/proc/self/stat").expect("the reserve is left"))
            .collect();
        assert!(crate::open_files::count().unwrap() < 1024);
        drop(files);
        drop(held);
    }
}

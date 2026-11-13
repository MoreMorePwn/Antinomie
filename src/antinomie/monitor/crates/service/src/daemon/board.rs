// SPDX-License-Identifier: GPL-3.0-only
//! The lane choice of design 4.6.1 with several lanes (ANT-T0455 card C).
//!
//! Every lane's loop claims from the one job store. Before it claims, a lane
//! posts on the board whether it could take a job now and what it runs (its
//! VM, base and architecture). For each queued job the claiming lane then asks
//! [`LaneBoard::decide`]:
//!
//! | Case | Answer |
//! |---|---|
//! | the lane cannot run the job (another base than the policy's lane VM, or an ELF of another architecture) but another lane can | `Wait(lane)`: the job waits for that lane |
//! | no lane of the daemon can run it | every lane counts as able (as with one lane: the run then says why it failed) |
//! | another lane that can run it is free too and was used less recently | `Skip`: the job is left for that lane, which is woken (ties by least recently used, then by lane number) |
//! | otherwise | `Ready`: this lane takes it |
//!
//! So jobs spread over the free lanes, and a quarantined or busy lane holds
//! back only the jobs that no other lane can run. The queue order (priority,
//! then age) is the store's and does not change; the host work pool stays
//! one first come, first served queue for every lane.
//!
//! A lane that cannot take a job leaves the jobs' `waiting_for` alone unless
//! no lane can take one; then the first lane writes the reason, the least
//! lasting of the lanes' reasons (busy before a pending layer, before low
//! resources, before a quarantine), so the reason does not flap between lanes.
//!
//! A post older than [`FRESH_MS`] is ignored: a lane whose thread stopped
//! does not hold jobs back.
use crate::{
    api::{
        ids::LaneId,
        job::{Job, WaitingFor},
    },
    store::Eligibility,
};
use antinomie_monitor_core::GuestArch;
use std::{
    collections::BTreeMap,
    sync::{Mutex, mpsc},
};

/// How long a lane's post counts (a lane posts every turn, at least once a
/// second).
pub const FRESH_MS: u64 = 3_000;

/// What a lane runs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaneProfile {
    pub vm_id: String,
    pub vm_name: Option<String>,
    pub base_identity: String,
    /// The lane base's architecture, when the engine lists the base.
    pub arch: Option<GuestArch>,
}

impl LaneProfile {
    /// Whether this lane's VM can run `job`: the base of the policy's lane
    /// VM (`base`, when the policy names a lane VM of the daemon) and the
    /// sample's architecture (an ELF; a script runs anywhere).
    pub fn fits(&self, job: &Job, base: Option<&str>) -> bool {
        if base.is_some_and(|base| base != self.base_identity) {
            return false;
        }
        match (
            self.arch,
            job.sample.as_ref().and_then(|s| s.architecture.as_deref()),
        ) {
            (Some(arch), Some(sample)) => runs(arch, sample),
            _ => true,
        }
    }
}

/// Whether a guest of `arch` runs an ELF whose architecture `detect_type`
/// names `sample` (x86-64 runs i386 programs, arm64 32-bit ARM ones).
pub fn runs(arch: GuestArch, sample: &str) -> bool {
    match sample {
        "x86_64" | "x86" => arch == GuestArch::X86_64,
        "AArch64" => arch == GuestArch::AARCH64,
        "ARM" => arch == GuestArch::AARCH64 || arch == GuestArch::ARM,
        "RISC-V" => arch == GuestArch::RISCV64,
        "MIPS" => arch == GuestArch::MIPS || arch == GuestArch::MIPSEL,
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct Post {
    state: Eligibility,
    profile: Option<LaneProfile>,
    at_ms: u64,
    last_claim_ms: u64,
}

/// The lanes of one daemon (see the module text).
#[derive(Default)]
pub struct LaneBoard {
    posts: Mutex<BTreeMap<LaneId, Post>>,
    wakes: Mutex<BTreeMap<LaneId, mpsc::Sender<()>>>,
}

/// How lasting a wait is: the reason the job shows when no lane can take it
/// is the least lasting one.
fn rank(wait: WaitingFor) -> u8 {
    match wait {
        WaitingFor::Lane => 0,
        WaitingFor::LayerPending => 1,
        WaitingFor::Backoff => 2,
        WaitingFor::Resources => 3,
        WaitingFor::Quota => 4,
        WaitingFor::Dependency => 5,
        WaitingFor::QueuePaused => 6,
        WaitingFor::LaneQuarantined => 7,
    }
}

impl LaneBoard {
    /// A lane of the daemon and how to wake its loop.
    pub fn join(&self, lane: &LaneId, wake: mpsc::Sender<()>) {
        crate::store::lock(&self.wakes).insert(lane.clone(), wake);
        crate::store::lock(&self.posts)
            .entry(lane.clone())
            .or_insert(Post {
                state: Eligibility::Wait(WaitingFor::Lane),
                profile: None,
                at_ms: 0,
                last_claim_ms: 0,
            });
    }

    /// The lane's loop ended: it no longer counts.
    pub fn leave(&self, lane: &LaneId) {
        crate::store::lock(&self.posts).remove(lane);
        crate::store::lock(&self.wakes).remove(lane);
    }

    /// What the lane can do now, as its loop saw it at `now_ms`.
    pub fn post(
        &self,
        lane: &LaneId,
        state: Eligibility,
        profile: Option<LaneProfile>,
        now_ms: u64,
    ) {
        let mut posts = crate::store::lock(&self.posts);
        let post = posts.entry(lane.clone()).or_insert(Post {
            state,
            profile: None,
            at_ms: now_ms,
            last_claim_ms: 0,
        });
        post.state = state;
        post.profile = profile;
        post.at_ms = now_ms;
    }

    /// The lane took a job at `now_ms`: it is busy and the most recently used.
    pub fn claimed(&self, lane: &LaneId, now_ms: u64) {
        if let Some(post) = crate::store::lock(&self.posts).get_mut(lane) {
            post.state = Eligibility::Wait(WaitingFor::Lane);
            post.last_claim_ms = now_ms;
            post.at_ms = now_ms;
        }
    }

    /// Wake every lane's loop (a submit, a resume of the queue).
    pub fn wake_all(&self) {
        for wake in crate::store::lock(&self.wakes).values() {
            let _ = wake.send(());
        }
    }

    fn wake(&self, lane: &LaneId) {
        if let Some(wake) = crate::store::lock(&self.wakes).get(lane) {
            let _ = wake.send(());
        }
    }

    /// The lanes that joined, in order.
    pub fn lanes(&self) -> Vec<LaneId> {
        crate::store::lock(&self.posts).keys().cloned().collect()
    }

    /// Whether `job` goes to `me` now (see the module text). `lane_vm` is the
    /// lane VM of the job's lane group (`[lanes] vm`).
    pub fn decide(
        &self,
        me: &LaneId,
        job: &Job,
        lane_vm: Option<&str>,
        now_ms: u64,
    ) -> Eligibility {
        let deferred = {
            let posts = crate::store::lock(&self.posts);
            let Some(mine) = posts.get(me) else {
                return Eligibility::Ready;
            };
            // The base of the lane group's VM, when it is one of the lanes'.
            let base = lane_vm.and_then(|name| {
                posts.values().find_map(|post| {
                    post.profile
                        .as_ref()
                        .filter(|p| p.vm_id == name || p.vm_name.as_deref() == Some(name))
                        .map(|p| p.base_identity.clone())
                })
            });
            let fits = |post: &Post| {
                post.profile
                    .as_ref()
                    .is_none_or(|p| p.fits(job, base.as_deref()))
            };
            let any_fits = posts.values().any(fits);
            let able = |post: &Post| !any_fits || fits(post);
            if !able(mine) {
                // The job waits for the lanes that can run it: the least
                // lasting of their waits (`lane` for a busy or free one), so
                // a job only a quarantined lane can run says so.
                let theirs = posts
                    .iter()
                    .filter(|&(lane, post)| lane != me && fits(post))
                    .map(|(_, post)| match post.state {
                        Eligibility::Wait(why) => why,
                        _ => WaitingFor::Lane,
                    })
                    .min_by_key(|why| rank(*why))
                    .unwrap_or(WaitingFor::Lane);
                return Eligibility::Wait(theirs);
            }
            let order = |lane: &LaneId, post: &Post| (post.last_claim_ms, lane.clone());
            let my_order = order(me, mine);
            posts
                .iter()
                .filter(|&(lane, post)| {
                    lane != me
                        && post.state == Eligibility::Ready
                        && now_ms.saturating_sub(post.at_ms) <= FRESH_MS
                        && able(post)
                        && order(lane, post) < my_order
                })
                .map(|(lane, _)| lane.clone())
                .next()
        };
        match deferred {
            Some(other) => {
                self.wake(&other);
                Eligibility::Skip
            }
            None => Eligibility::Ready,
        }
    }

    /// For a lane that cannot take a job: `Some(reason)` when it is the lane
    /// that writes the jobs' `waiting_for` (no lane can take a job, and it is
    /// the first of the lanes), with the least lasting reason of the lanes.
    pub fn report(&self, me: &LaneId, mine: WaitingFor, now_ms: u64) -> Option<WaitingFor> {
        let posts = crate::store::lock(&self.posts);
        let fresh: Vec<(&LaneId, &Post)> = posts
            .iter()
            .filter(|(lane, post)| *lane == me || now_ms.saturating_sub(post.at_ms) <= FRESH_MS)
            .collect();
        if fresh
            .iter()
            .any(|(_, post)| post.state == Eligibility::Ready)
        {
            return None;
        }
        if fresh.first().is_none_or(|(lane, _)| *lane != me) {
            return None;
        }
        fresh
            .iter()
            .filter_map(|(lane, post)| match post.state {
                Eligibility::Wait(why) => Some(why),
                _ if *lane == me => Some(mine),
                _ => None,
            })
            .min_by_key(|why| rank(*why))
            .or(Some(mine))
    }
}

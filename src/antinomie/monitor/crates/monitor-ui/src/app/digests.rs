// SPDX-License-Identifier: GPL-3.0-only
//! The digest of every finished run, built in the background (ANT-T0400).
//!
//! The Triage digest used to be written only once a run was selected and its
//! scan was done, so a run nobody opened (a write flood of a million calls, a
//! run that lost telemetry) had none. Here every run that ended is handed to
//! the digest queue (`antinomie_triage::digest_job`), once per app session; the
//! queue builds them one at a time, a heavy recording within a size and time
//! budget, and the run's Triage view shows the progress while one builds.
use super::*;
use crate::time_format::now_ms;
use antinomie_triage::digest_job::{self, Budget, Job};
use std::collections::HashSet;

/// Runs older than this are left to `antinomie-cli digest --pending` and to
/// being opened: the window does not read a whole old history at start.
const RECENT_MS: u64 = 7 * 24 * 3600 * 1000;
/// How often the digests that were partial only because their recording was
/// still being written are looked at again.
const RECHECK_SECONDS: f64 = 5.0;

impl MonitorApp {
    /// Hand the runs that ended to the digest queue. Cheap in a frame where
    /// nothing new ended: one set lookup per run.
    pub(super) fn queue_digests(&self, ctx: &egui::Context) {
        let since = now_ms().saturating_sub(RECENT_MS);
        let key = egui::Id::new("digest-queued");
        let mut due = Vec::new();
        ctx.data_mut(|data| {
            let seen = data.get_temp_mut_or_default::<HashSet<String>>(key);
            for run in self.snapshot.runs.iter().chain(&self.history) {
                if run.state.is_live()
                    || run.root_task_cookie == 0
                    || run.started_ms.is_some_and(|started| started < since)
                {
                    continue;
                }
                if seen.insert(run.id.clone()) {
                    due.push(run.clone());
                }
            }
        });
        for run in due {
            digest_job::queue().submit(Job {
                run,
                options: self.options.clone(),
                budget: Budget::default(),
            });
        }
        let now = ctx.input(|input| input.time);
        let last = egui::Id::new("digest-rechecked");
        let before: f64 = ctx.data(|data| data.get_temp(last)).unwrap_or(0.0);
        if now - before >= RECHECK_SECONDS {
            ctx.data_mut(|data| data.insert_temp(last, now));
            digest_job::queue().recheck();
        }
    }
}

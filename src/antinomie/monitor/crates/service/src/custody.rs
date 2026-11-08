// SPDX-License-Identifier: GPL-3.0-only
//! Custody entries for jobs (design 4.11, card P3-7): who caused what.
//!
//! Every library entry a job causes names the caller that submitted it:
//! `local:<uid>`, `web:<user>` or, for a watch folder, `auto:policy-<name>`
//! (the job's `client_id`). The intake writes `added` under that name
//! (`Library::add_bytes_as`); the lane sets the process's current actor for the
//! length of the job ([`ActorScope`]) so that the run log and the push record,
//! which the engine writes on its own threads, carry it too. One entry of kind
//! `automation` per job records the job, the policy digest, the route and the
//! submitter.

use crate::api::{job::Job, spec::Route};
use antinomie_monitor_core::samples::{self, CustodyEvent, Library, actor};
use std::path::Path;

/// The custody actor of a job: its `client_id`, when the log accepts it, else
/// `app`.
pub fn actor_of(job: &Job) -> String {
    if actor::is_valid(&job.client_id) {
        job.client_id.clone()
    } else {
        actor::APP.to_owned()
    }
}

/// Make `actor` the current actor of the process's own custody entries until
/// the scope is dropped (then `app` again). One lane runs one job at a time
/// (decided D4), so one slot is enough.
pub struct ActorScope(());

impl ActorScope {
    /// `Err` for a name the log does not accept; nothing is changed then.
    pub fn enter(actor: &str) -> Result<Self, String> {
        actor::set_current(Some(actor))?;
        Ok(Self(()))
    }
}

impl Drop for ActorScope {
    fn drop(&mut self) {
        let _ = actor::set_current(None);
    }
}

fn route_name(route: Route) -> String {
    serde_json::to_value(route)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// Write the `automation` entry of a job to its sample's custody log, under
/// the job's actor. The job must have its sample (`job.sample`).
pub fn record_automation(data_dir: &Path, job: &Job) -> Result<(), String> {
    let sample = job.sample.as_ref().ok_or("the job has no sample yet")?;
    let by = actor_of(job);
    let library = Library::open(data_dir)?.with_actor(&by)?;
    let route = job
        .spec
        .overrides
        .route
        .map_or("drop".to_owned(), route_name);
    library.record_event(
        sample.sha256.as_str(),
        &by,
        CustodyEvent::Automation {
            job: job.id.to_string(),
            policy: job.policy.name.clone(),
            policy_digest: job.policy.digest.clone(),
            route,
            submitted_by: job.client_id.clone(),
        },
    )
}

/// The kinds the log can hold, for a client that offers a filter.
pub fn kinds() -> impl Iterator<Item = &'static str> {
    samples::KINDS.iter().map(|(key, _)| *key)
}

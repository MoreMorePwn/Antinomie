// SPDX-License-Identifier: GPL-3.0-only
//! Custody entries for jobs (design 4.11, card P3-7): who caused what.
//!
//! Every library entry a job causes names the caller that submitted it:
//! `local:<uid>`, `web:<user>` or, for a watch folder, `auto:policy-<name>`
//! (the job's `client_id`). The intake writes `added` under that name
//! (`Library::add_bytes_as`); the lane names it as its engine's custody actor
//! for the job's launch (`Engine::set_custody_actor`) so that the push record
//! and the run log, which the engine writes on its own thread, carry it too.
//! Each lane has its own engine, so lanes running at once each name their own
//! job (BH-29); there is no process-wide actor. One entry of kind
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

/// The actor of an entry the service writes on its own account (a tag it
/// sets on a sample): `auto:policy-<preset>` (the preset a Custom run was
/// based on), else the job's own actor.
pub fn automation_actor(job: &Job) -> String {
    let preset = job
        .policy
        .based_on
        .as_ref()
        .map_or(&job.policy.name, |base| &base.name);
    let actor = format!("auto:policy-{preset}");
    if actor::is_valid(&actor) {
        actor
    } else {
        actor_of(job)
    }
}

/// Write the `automation` entry of a job to its sample's custody log, under
/// the job's actor, with the route its preset uses. The job must have its
/// sample (`job.sample`).
pub fn record_automation(data_dir: &Path, job: &Job, route: &Route) -> Result<(), String> {
    let sample = job.sample.as_ref().ok_or("the job has no sample yet")?;
    let by = actor_of(job);
    let library = Library::open_patient(data_dir)?.with_actor(&by)?;
    let route = route.to_string();
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

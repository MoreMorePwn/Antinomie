// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's side of the watch folders (card P4-2): the [`WatchEnv`] that
//! turns a watched file into a job, and the thread that scans the folders.
//!
//! A file becomes a job in two steps, both under the actor
//! `auto:policy-<policy>`: the intake steps of 4.2 on the open descriptor
//! (type, size, library, custody `Added`), then `job.submit` for the library
//! sample (so the queue caps, the duplicate rule and the policy's ceilings
//! apply as for any other caller).

use super::service::Service;
use crate::config::PolicyLookup;
use crate::{
    api::{
        error::ErrorCode,
        job::JobState,
        ops::{Caller, Scope},
        spec::{JobSpec, SampleSource},
    },
    watch::{Admission, Admit, Defer, SCAN_EVERY, WatchEnv, Watcher},
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

/// The caller a watch folder acts as: a client named for the policy, with
/// only the right to submit to that policy.
pub fn watch_caller(policy: &str) -> Caller {
    Caller {
        client_id: format!("auto:policy-{policy}"),
        scopes: vec![Scope::Submit],
        policies: vec![policy.to_owned()],
    }
}

pub struct ServiceEnv(pub Arc<Service>);

impl WatchEnv for ServiceEnv {
    fn policy_exists(&self, name: &str) -> bool {
        crate::config::PolicyLookup::get(&*self.0.policies, name).is_some()
    }

    fn queue_has_room(&self) -> bool {
        let max = self
            .0
            .config
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .queue
            .max_queued;
        self.0
            .store
            .counts()
            .map(|counts| counts.queued < max)
            .unwrap_or(false)
    }

    fn intake_held(&self) -> bool {
        matches!(
            self.0.store.pause_reason(),
            Ok(Some(crate::api::status::PauseReason::LowDisk))
        )
    }

    fn admit(&self, request: Admit) -> Result<Admission, Defer> {
        let service = &self.0;
        let policies = service.policies.snapshot();
        let loaded = policies
            .get(&request.policy)
            .ok_or_else(|| Defer(format!("policy {} does not exist", request.policy)))?;
        let caller = watch_caller(&request.policy);
        if !loaded.allows(&caller.client_id, Scope::Submit) {
            return Err(Defer(format!(
                "policy {} does not let {} submit (access.clients)",
                request.policy, caller.client_id
            )));
        }
        let name = (!request.file_name.is_empty()).then_some(request.file_name.as_str());
        let sample = match service.intake.sample_from_file(
            request.file,
            &request.shown,
            name,
            &loaded,
            &caller.client_id,
        ) {
            Ok(sample) => sample,
            Err(error) => {
                return Ok(Admission::Rejected {
                    code: crate::store::Store::wire_name(&error.code),
                    message: error.message,
                });
            }
        };
        let mut labels = BTreeMap::new();
        labels.insert("watch".to_owned(), request.folder_label);
        let spec = JobSpec {
            sample: SampleSource {
                sha256: Some(sample.sha256),
                ..Default::default()
            },
            name: name.map(str::to_owned),
            policy: Some(request.policy),
            priority: None,
            labels,
            idempotency_key: None,
            overrides: Default::default(),
        };
        let mut context = service.submit_context(&policies);
        context.on_duplicate = request.on_duplicate;
        match service.store.submit(&caller, spec, &context) {
            Ok(submitted) if submitted.job.state == JobState::Rejected => {
                let (code, message) = submitted.job.failure.as_ref().map_or_else(
                    || ("rejected".to_owned(), "the job was rejected".to_owned()),
                    |f| (crate::store::Store::wire_name(&f.code), f.message.clone()),
                );
                Ok(Admission::Rejected { code, message })
            }
            Ok(submitted) => {
                service.wake_lane();
                Ok(Admission::Submitted {
                    job: submitted.job.id.to_string(),
                })
            }
            Err(error)
                if matches!(
                    error.code,
                    ErrorCode::QuotaExceeded | ErrorCode::Unavailable
                ) =>
            {
                Err(Defer(error.message))
            }
            Err(error) => Err(Defer(format!(
                "{}: {}",
                crate::store::Store::wire_name(&error.code),
                error.message
            ))),
        }
    }

    fn alert(&self, code: &str, text: &str) {
        let _ = self
            .0
            .store
            .emit_engine(crate::api::event::EventBody::EngineAlert {
                code: code.to_owned(),
                text: text.to_owned(),
            });
    }

    fn log(&self, line: &str) {
        (self.0.log)(line);
    }
}

/// The watcher's thread: scan every [`SCAN_EVERY`] (or at once on request)
/// until the daemon stops.
pub fn run(service: Arc<Service>) {
    let inbox = {
        let config = service.config.read().unwrap_or_else(|p| p.into_inner());
        config.inbox_dir(&service.data_dir)
    };
    let mut watcher = Watcher::new(&inbox);
    let env = ServiceEnv(Arc::clone(&service));
    let mut next = std::time::Instant::now();
    loop {
        if service.controls.stopping() {
            return;
        }
        let asked = service.watch.take_request();
        if asked || std::time::Instant::now() >= next {
            let folders = service
                .config
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .inbox
                .watch
                .clone();
            watcher.configure(&folders);
            watcher.scan_all(
                &env,
                crate::clock::Clock::now_ms(&crate::clock::SystemClock),
            );
            service.watch.publish(watcher.statuses());
            next = std::time::Instant::now() + SCAN_EVERY;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

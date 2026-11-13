// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's side of the watch folders (card P4-2): the [`WatchEnv`] that
//! turns a watched file into a job, and the thread that scans the folders.
//!
//! A file becomes a job in two steps, both under the actor
//! `auto:policy-<policy>`: the intake steps of 4.2 on the open descriptor
//! (type, size, library, custody `Added`), then `job.submit` for the library
//! sample (so the queue caps, the duplicate rule, the permission checks and
//! the policy's ceilings apply as for any other caller). The caller holds
//! `runs.submit` and the folder's `permissions`.

use super::service::Service;
use crate::config::PresetLookup;
use crate::{
    api::{
        error::ErrorCode,
        job::JobState,
        spec::{JobSpec, SampleSource},
    },
    watch::{Admission, Admit, Defer, SCAN_EVERY, WatchEnv, Watcher},
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub use crate::config::callers::watch_caller;

pub struct ServiceEnv(pub Arc<Service>);

/// The callers of `service.toml` as it reads now (a SIGHUP reload changes a
/// watch folder's `permissions` for runs still waiting).
impl crate::config::callers::CallerLookup for Service {
    fn permissions_now(
        &self,
        client_id: &str,
        labels: &crate::config::callers::Labels,
    ) -> Option<std::collections::BTreeSet<crate::api::ops::Permission>> {
        let config = self.config.read().unwrap_or_else(|p| p.into_inner());
        crate::config::callers::permissions_now(&config, client_id, labels)
    }
}

impl WatchEnv for ServiceEnv {
    fn preset_exists(&self, name: &str) -> bool {
        crate::config::PresetLookup::get(&*self.0.presets, name).is_some()
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
        let presets = service.presets.snapshot();
        let loaded = presets
            .get(&request.preset)
            .ok_or_else(|| Defer(format!("preset {} does not exist", request.preset)))?;
        let caller = watch_caller(&request.preset, &request.permissions);
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
            policy: Some(request.preset),
            priority: None,
            labels,
            idempotency_key: None,
            overrides: Default::default(),
        };
        let mut context = service.submit_context(&presets);
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

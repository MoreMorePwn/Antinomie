// SPDX-License-Identifier: GPL-3.0-only
//! The delivery thread (card P4-4): when a job ends, write its result files
//! and run the command hook. It listens to the store's own events, so every
//! way a job can end (the lane, a cancel, a rejection) is covered, and it
//! works one job at a time on a thread of its own: a slow hook never holds
//! the lane.

use super::service::Service;
use crate::{
    api::event::EventBody,
    clock::{Clock, SystemClock},
    notify::{Delivery, hook},
};
use std::{sync::Arc, time::Duration};

fn delivery<'a>(
    service: &'a Service,
    log: &'a dyn Fn(&str),
    alert: &'a dyn Fn(&str, &str),
) -> Delivery<'a> {
    let config = service.config.read().unwrap_or_else(|p| p.into_inner());
    Delivery {
        store: &service.store,
        results_dir: config.results.dir.clone(),
        results_mode: config.results.mode,
        on_finish: config.notify.on_finish.clone(),
        hook_timeout: hook::TIMEOUT,
        now_ms: SystemClock.now_ms(),
        log,
        alert,
    }
}

pub fn run(service: Arc<Service>) {
    let events = service.store.subscribe();
    let log = |line: &str| (service.log)(line);
    let alert = |code: &str, text: &str| {
        let _ = service.store.emit_engine(EventBody::EngineAlert {
            code: code.to_owned(),
            text: text.to_owned(),
        });
    };
    delivery(&service, &log, &alert).sweep();
    loop {
        match events.recv_timeout(Duration::from_millis(300)) {
            Ok(event) => {
                if matches!(event.body, EventBody::RunFinished { .. })
                    && let Some(id) = &event.run_id
                {
                    let _ = delivery(&service, &log, &alert).deliver(id);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if service.controls.lane_has_ended() {
                    return;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        }
    }
}

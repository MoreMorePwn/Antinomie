// SPDX-License-Identifier: GPL-3.0-only
//! The daemon's side of retention and the watch folders' operations (cards
//! P4-2, P4-3): the hourly pass, `gc.run`, `job.delete`, `watch.list` and
//! `watch.scan`. These are additions to the operations of 5.3 (which has no
//! operation for `auto gc` or `auto watch`), named like the lane operations.

use super::service::{Service, params, to_value};
use crate::{
    api::{
        error::{ApiError, ErrorCode},
        ops::{Deleted, JobDeleteParams, Scope},
    },
    clock::{Clock, SystemClock},
    retention::{self, GcReport, RealRuns, Retention},
    server::CallContext,
};
use serde::Deserialize;
use serde_json::Value;
use std::{sync::Arc, time::Duration};

/// The first pass runs this long after the start, then every hour.
const FIRST_PASS: Duration = Duration::from_secs(60);
const EVERY: Duration = Duration::from_secs(3600);

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct GcParams {
    #[serde(default)]
    dry_run: bool,
}

impl Service {
    /// One retention pass, one at a time.
    pub fn gc(&self, dry_run: bool) -> GcReport {
        let _one_at_a_time = crate::store::lock(&self.gc_lock);
        let config = self
            .config
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let runs = RealRuns {
            options: &self.options,
            query: Some(&self.query),
        };
        let log = |line: &str| (self.log)(line);
        Retention {
            store: &self.store,
            runs: &runs,
            config: config.retention.clone(),
            rejected_dir: config.inbox_dir(&self.data_dir).join("rejected"),
            processed_dir: config.inbox_dir(&self.data_dir).join("processed"),
            processed_keep_days: config.inbox.processed_keep_days,
            uploads: Some(self.intake.staging()),
            now_ms: SystemClock.now_ms(),
            log: &log,
        }
        .run(dry_run)
    }

    pub(super) fn job_delete(&self, value: Value) -> Result<Value, ApiError> {
        let request: JobDeleteParams = params(value)?;
        let _one_at_a_time = crate::store::lock(&self.gc_lock);
        let runs = RealRuns {
            options: &self.options,
            query: Some(&self.query),
        };
        let log = |line: &str| (self.log)(line);
        retention::delete_job(
            &self.store,
            &runs,
            &request.job_id,
            request.with_recording.unwrap_or(false),
            &log,
        )?;
        to_value(&Deleted { deleted: true })
    }
}

/// `Some` for `gc.run`, `watch.list`, `watch.scan`; `None` for any other op.
pub(super) fn call(
    service: &Service,
    op: &str,
    value: Value,
    ctx: &CallContext,
) -> Option<Result<Value, ApiError>> {
    let need = match op {
        "watch.list" => Scope::Read,
        "watch.scan" | "gc.run" => Scope::Manage,
        _ if op.starts_with("watch.") || op.starts_with("gc.") => {
            return Some(Err(ApiError::invalid_argument(
                "op",
                format!("unknown operation {op:?}"),
            )));
        }
        _ => return None,
    };
    if !ctx.caller.has(need) {
        return Some(Err(ApiError::new(
            ErrorCode::Forbidden,
            "this operation needs another scope",
        )));
    }
    Some(match op {
        "watch.list" => to_value(&service.watch.list()),
        "watch.scan" => to_value(&service.watch.scan_now(Duration::from_secs(30))),
        _ => params::<GcParams>(value).and_then(|p| to_value(&service.gc(p.dry_run))),
    })
}

/// The hourly pass, until the daemon stops.
pub fn run(service: Arc<Service>) {
    let mut next = std::time::Instant::now() + FIRST_PASS;
    loop {
        if service.controls.stopping() {
            return;
        }
        if std::time::Instant::now() >= next {
            let report = service.gc(false);
            if !report.actions.is_empty() || !report.errors.is_empty() {
                (service.log)(&format!(
                    "gc: {} action(s), {} skipped, {} error(s), {} bytes freed",
                    report.actions.len(),
                    report.skipped.len(),
                    report.errors.len(),
                    report.freed_bytes
                ));
            }
            next = std::time::Instant::now() + EVERY;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

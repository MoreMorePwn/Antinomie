// SPDX-License-Identifier: GPL-3.0-only
//! The CLI as a client of the read-only query API (design 5.12.10). In direct
//! mode the commands call `QueryService` in this process; no daemon ships yet,
//! so `--daemon` runs the same way. Reads take no lock and write nothing into
//! a recording, so they work beside the GUI.
//!
//! A class T read (Triage) whose scan is not built yet answers `building`; the
//! client asks again after `retry_after_ms`, logging the scan's progress,
//! until the answer comes, `--timeout` ends the wait or Ctrl-C interrupts it.
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    signals,
};
use antinomie_service::{
    api::error::{ApiError, ErrorCode as ApiCode},
    query::{
        QueryApi, QueryService, ReadContext,
        key::RunKey,
        request::{RecordingRead, RecordingReply},
    },
};
use serde_json::{Value, json};
use std::time::{Duration, Instant};

/// How the CLI names itself to the query service: the local owner.
fn caller() -> String {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    format!("local:{}", unsafe { libc::getuid() })
}

pub struct Client<'a> {
    context: &'a Context,
    service: QueryService,
}

impl<'a> Client<'a> {
    pub fn new(context: &'a Context) -> Self {
        Self {
            context,
            service: QueryService::new(context.options.clone()),
        }
    }

    /// One operation with parameters `params` (the request members of 5.12.3).
    pub fn call(&self, op: &str, params: Value) -> Result<Value, CliError> {
        let request = RecordingRead::parse(op, params).map_err(api_error)?;
        let reply = self.read(request)?;
        serde_json::to_value(&reply).map_err(|error| CliError::internal(error.to_string()))
    }

    /// The run `text` names, as the key the query API takes.
    pub fn key_of(&self, run: &antinomie_monitor_core::RunSummary) -> Result<RunKey, CliError> {
        RunKey::new(&run.vm_id, &run.boot_id, &run.id)
            .map_err(|error| CliError::invalid(format!("{error}")).with_field("run"))
    }

    pub fn read(&self, request: RecordingRead) -> Result<RecordingReply, CliError> {
        signals::install();
        let started = Instant::now();
        let mut last = String::new();
        let mut logged = Instant::now() - Duration::from_secs(10);
        loop {
            let reads = ReadContext::local_owner(&caller());
            let reply = self
                .service
                .read(request.clone(), &reads)
                .map_err(api_error)?;
            let Some(building) = building_of(&reply) else {
                return Ok(reply);
            };
            if signals::interrupted() {
                return Err(CliError::new(
                    ErrorCode::Internal,
                    "interrupted while the run was being indexed",
                )
                .with_exit(Exit::Interrupted));
            }
            if self
                .context
                .timeout()
                .is_some_and(|limit| started.elapsed() >= limit)
            {
                return Err(CliError::new(
                    ErrorCode::Unavailable,
                    "the timeout passed while the run was being indexed",
                )
                .with_exit(Exit::WaitTimeout));
            }
            if logged.elapsed() >= Duration::from_secs(2) {
                logged = Instant::now();
                let text = match building["progress"].as_object() {
                    Some(progress) => {
                        format!("indexing: {} of {}", progress["done"], progress["total"])
                    }
                    None => "indexing".to_owned(),
                };
                if text != last {
                    self.context.logger.info(&text);
                    last = text;
                }
            }
            let wait = building["retry_after_ms"].as_u64().unwrap_or(750).min(1000);
            std::thread::sleep(Duration::from_millis(wait.max(50)));
        }
    }
}

/// The `building` member of a reply, when its scan is still being made.
fn building_of(reply: &RecordingReply) -> Option<Value> {
    let value = serde_json::to_value(reply).ok()?;
    value.get("building").filter(|b| !b.is_null()).cloned()
}

/// An `ApiError` as the CLI's error, with its exit code.
pub fn api_error(error: ApiError) -> CliError {
    let code = match error.code {
        ApiCode::InvalidArgument => ErrorCode::InvalidArgument,
        ApiCode::Forbidden | ApiCode::PolicyDenied | ApiCode::Unauthenticated => {
            ErrorCode::PolicyDenied
        }
        ApiCode::NotFound => ErrorCode::NotFound,
        ApiCode::Conflict => ErrorCode::Conflict,
        ApiCode::PreconditionFailed => ErrorCode::PreconditionFailed,
        ApiCode::PayloadTooLarge => ErrorCode::PayloadTooLarge,
        ApiCode::QuotaExceeded => ErrorCode::QuotaExceeded,
        ApiCode::Unavailable => ErrorCode::Unavailable,
        ApiCode::Unsupported => ErrorCode::Unsupported,
        ApiCode::Internal => ErrorCode::Internal,
    };
    let mut out = CliError::new(code, error.message.clone());
    if let Some(field) = &error.field {
        out = out.with_field(field.clone());
    }
    if !error.details.is_empty() {
        out = out.with_details(json!(error.details));
    }
    out
}

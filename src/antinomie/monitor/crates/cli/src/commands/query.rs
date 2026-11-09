// SPDX-License-Identifier: GPL-3.0-only
//! The CLI as a client of the read-only query API (design 5.12.10). With a
//! daemon at the socket the commands send the `recording.*` operations to it;
//! without one they call `QueryService` in this process. Either way the
//! objects are the same, reads take no lock and write nothing into a
//! recording, so they work beside the GUI.
//!
//! A class T read (Triage) whose scan is not built yet answers `building`; the
//! client asks again after `retry_after_ms`, logging the scan's progress,
//! until the answer comes, `--timeout` ends the wait or Ctrl-C interrupts it.
use super::{
    auto::link,
    recording::{RUN_PREFIX, find_run},
};
use crate::{
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    signals,
};
use antinomie_service::{
    api::error::{ApiError, ErrorCode as ApiCode},
    query::{QueryApi, QueryService, ReadContext, key::RunKey, request::RecordingRead},
    server::client::Client as SocketClient,
    store::job_index::StoreJobIndex,
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

/// How the CLI names itself to the query service: the local owner.
fn caller() -> String {
    // SAFETY: `getuid` has no preconditions and cannot fail.
    format!("local:{}", unsafe { libc::getuid() })
}

/// The query service in this process: the job store (when the data directory
/// has one) tells it the job of each run, as the daemon's does.
fn direct_service(context: &Context) -> QueryService {
    let service = QueryService::new(context.options.clone());
    match StoreJobIndex::open_read_only(context.data_dir()) {
        Some(index) => service.with_jobs(std::sync::Arc::new(index)),
        None => service,
    }
}

/// Where the reads go: the query service in this process, or the daemon that
/// owns the data directory (design 2.2). Both answer with the same objects.
enum Via {
    Direct(Box<QueryService>),
    Daemon(RefCell<SocketClient>),
}

pub struct Client<'a> {
    context: &'a Context,
    via: Via,
}

impl<'a> Client<'a> {
    /// A client for the reads of `context`: the daemon when one answers at
    /// the socket (and `--direct` is not given), else the query service over
    /// the data directory. `--daemon` with no daemon is `unavailable`.
    pub fn new(context: &'a Context) -> Result<Self, CliError> {
        let via = match link::daemon(context)? {
            Some(client) => Via::Daemon(RefCell::new(client)),
            None => Via::Direct(Box::new(direct_service(context))),
        };
        Ok(Self { context, via })
    }

    /// The reads go through the daemon.
    pub fn is_daemon(&self) -> bool {
        matches!(self.via, Via::Daemon(_))
    }

    /// One operation with parameters `params` (the request members of 5.12.3),
    /// asked again while a Triage scan is being built.
    pub fn call(&self, op: &str, params: Value) -> Result<Value, CliError> {
        signals::install();
        let started = Instant::now();
        let mut last = String::new();
        let mut logged = Instant::now() - Duration::from_secs(10);
        loop {
            let reply = self.once(op, &params)?;
            let Some(building) = reply
                .get("building")
                .filter(|building| !building.is_null())
                .cloned()
            else {
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

    fn once(&self, op: &str, params: &Value) -> Result<Value, CliError> {
        match &self.via {
            Via::Direct(service) => {
                let request = RecordingRead::parse(op, params.clone()).map_err(api_error)?;
                let reads = ReadContext::local_owner(&caller());
                let reply = service.read(request, &reads).map_err(api_error)?;
                serde_json::to_value(&reply).map_err(|error| CliError::internal(error.to_string()))
            }
            Via::Daemon(client) => {
                let mut client = client.borrow_mut();
                client.deadline_in(self.context.timeout());
                link::call(&mut client, op, params.clone())
            }
        }
    }

    /// The run `text` names, as the key the query API takes: a run key or
    /// `vm:boot:run`, the id or the first characters of it, or the run's
    /// folder. Through a daemon the id is looked up in `recording.run.list`.
    pub fn resolve(&self, text: &str) -> Result<RunKey, CliError> {
        let Via::Daemon(_) = self.via else {
            let run = find_run(self.context, text)?;
            return self.key_of(&run);
        };
        let text = text.trim();
        if text.is_empty() {
            return Err(CliError::invalid("RUN is empty").with_field("run"));
        }
        let key = RunKey::try_from(text.to_owned()).ok().or_else(|| {
            text.contains(':')
                .then(|| RunKey::from_triple(text).ok())
                .flatten()
        });
        if let Some(key) = key {
            return Ok(key);
        }
        if std::path::Path::new(text).join("run.json").is_file() {
            // A folder is a place on this host; the daemon is on it too.
            let run = find_run(self.context, text)?;
            return self.key_of(&run);
        }
        let mut found = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut params = json!({"limit": 500});
            if let Some(cursor) = &cursor {
                params["cursor"] = json!(cursor);
            }
            let page = self.call("recording.run.list", params)?;
            for run in page["items"].as_array().into_iter().flatten() {
                let id = run["run_id"].as_str().unwrap_or_default();
                let exact = id == text;
                if exact || (text.len() >= RUN_PREFIX && id.starts_with(text)) {
                    found.push((
                        exact,
                        run["run_key"].as_str().unwrap_or_default().to_owned(),
                    ));
                }
            }
            match page["next_cursor"].as_str() {
                Some(next) => cursor = Some(next.to_owned()),
                None => break,
            }
        }
        if found.iter().any(|(exact, _)| *exact) {
            found.retain(|(exact, _)| *exact);
        }
        match found.as_slice() {
            [(_, key)] => RunKey::try_from(key.clone())
                .map_err(|e| CliError::internal(format!("run key: {e}"))),
            [] => Err(CliError::not_found(format!(
                "no run {text:?} in the data directory of the daemon{}",
                if text.len() < RUN_PREFIX {
                    format!(" (give at least {RUN_PREFIX} characters of the id)")
                } else {
                    String::new()
                }
            ))
            .with_field("run")),
            many => Err(CliError::invalid(format!(
                "{text:?} names {} runs; give more of the id, or vm:boot:run",
                many.len()
            ))
            .with_field("run")
            .with_details(json!({"runs": many.iter().map(|(_, key)| key).collect::<Vec<_>>()}))),
        }
    }

    /// The key of a run found on this host.
    pub fn key_of(&self, run: &antinomie_monitor_core::RunSummary) -> Result<RunKey, CliError> {
        RunKey::new(&run.vm_id, &run.boot_id, &run.id)
            .map_err(|error| CliError::invalid(format!("{error}")).with_field("run"))
    }
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

// SPDX-License-Identifier: GPL-3.0-only
//! How an `auto` command reaches the run API (design 2.2): the daemon's socket
//! when one answers, else the job store read-only (reads) or the store under
//! the data-directory lock (cancel, pause), and the conversions of the
//! service's errors into the CLI's.
//!
//! | Situation | Behaviour |
//! |---|---|
//! | a daemon answers at the socket | client mode |
//! | no daemon, `--daemon` | `unavailable` (exit 21): "no daemon answers at ..." |
//! | no daemon, the folder owned by the window or a command | a read is served from the store read-only; a change is refused with exit 21 naming the owner |
//! | no daemon, no owner | a read from the store read-only; a change takes the lock for itself |
//! | `--direct` | never the socket |
use crate::{
    args::Mode,
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
};
use antinomie_monitor_core::data_owner::{self, OwnerClaim, OwnerKind};
use antinomie_service::{
    api::error::{ApiError, ErrorCode as ApiCode},
    server::client::{Client, ClientError},
    store::Store,
};
use serde_json::Value;
use std::time::Duration;

/// How long a client waits for the daemon's hello.
const CONNECT: Duration = Duration::from_secs(10);

/// A service error as the CLI reports it (same code, field and details).
pub fn api(error: ApiError) -> CliError {
    let code = match error.code {
        ApiCode::InvalidArgument => ErrorCode::InvalidArgument,
        ApiCode::PermissionDenied | ApiCode::Unauthenticated | ApiCode::Forbidden => {
            ErrorCode::PermissionDenied
        }
        ApiCode::PresetDenied => ErrorCode::PresetDenied,
        ApiCode::LimitExceeded => ErrorCode::LimitExceeded,
        ApiCode::UnavailableOnNode => ErrorCode::UnavailableOnNode,
        ApiCode::NotFound => ErrorCode::NotFound,
        ApiCode::Conflict => ErrorCode::Conflict,
        ApiCode::PreconditionFailed => ErrorCode::PreconditionFailed,
        ApiCode::PayloadTooLarge => ErrorCode::PayloadTooLarge,
        ApiCode::QuotaExceeded => ErrorCode::QuotaExceeded,
        ApiCode::Unavailable => ErrorCode::Unavailable,
        ApiCode::Unsupported => ErrorCode::Unsupported,
        ApiCode::Internal => ErrorCode::Internal,
    };
    let mut out = CliError::new(code, error.message).with_details(Value::Object(error.details));
    out.retryable = error.retryable;
    if let Some(field) = error.field {
        out = out.with_field(field);
    }
    out
}

/// A client failure as the CLI reports it.
pub fn client(error: ClientError) -> CliError {
    match error {
        ClientError::Api(error) => api(error),
        ClientError::TimedOut => CliError::new(
            ErrorCode::Unavailable,
            "the --timeout passed while waiting for the daemon",
        )
        .with_exit(Exit::WaitTimeout),
        ClientError::Interrupted => CliError::internal("interrupted").with_exit(Exit::Interrupted),
        ClientError::NoDaemon(error) => CliError::new(
            ErrorCode::Unavailable,
            format!("no daemon answers at the socket: {error}"),
        ),
        other => CliError::new(ErrorCode::Unavailable, format!("the daemon: {other}")),
    }
}

/// The daemon, when one answers at the socket; `None` when none does and the
/// mode allows another way. `--daemon` with no daemon is an error.
pub fn daemon(context: &Context) -> Result<Option<Client>, CliError> {
    if context.mode() == Mode::Direct {
        return Ok(None);
    }
    let socket = context.socket();
    match Client::connect(&socket, CONNECT) {
        Ok(mut client) => {
            client.interrupt_when(crate::signals::interrupted);
            crate::signals::install();
            Ok(Some(client))
        }
        Err(ClientError::NoDaemon(_)) if context.mode() == Mode::Auto => Ok(None),
        Err(ClientError::NoDaemon(error)) => Err(CliError::new(
            ErrorCode::Unavailable,
            format!(
                "no daemon answers at {}: {error}; start one with `antinomie-cli auto daemon`",
                socket.display()
            ),
        )),
        Err(other) => Err(client(other)),
    }
}

/// One call through the daemon.
pub fn call(client: &mut Client, op: &str, params: Value) -> Result<Value, CliError> {
    client.call(op, params).map_err(self::client)
}

/// The job store for reading, beside any owner (a daemon, the window).
pub fn read_store(context: &Context) -> Result<Store, CliError> {
    let dir = context.data_dir().join("service");
    if !dir.join("jobs.sqlite").is_file() {
        return Err(CliError::not_found(format!(
            "no run store in {} (no run was ever submitted there)",
            context.data_dir().display()
        )));
    }
    Store::open_read_only(&dir).map_err(api)
}

/// The job store for a change without a daemon: this command takes the data
/// directory's lock for itself (refused with exit 21 when someone owns it).
pub fn locked_store(
    context: &Context,
) -> Result<(Store, antinomie_monitor_core::data_owner::OwnerGuard), CliError> {
    let data_dir = context.data_dir();
    let guard = data_owner::lock_data_dir(
        data_dir,
        &OwnerClaim {
            kind: OwnerKind::Cli,
            socket: None,
            lane: None,
        },
    )
    .map_err(|message| CliError::from_engine_start(data_dir, &message))?;
    let store = Store::open(&data_dir.join("service")).map_err(api)?;
    Ok((store, guard))
}

/// The caller this command is (the OS user), for calls made in this process.
pub fn me() -> antinomie_service::api::ops::Caller {
    antinomie_service::server::local_caller(antinomie_service::server::own_uid())
}

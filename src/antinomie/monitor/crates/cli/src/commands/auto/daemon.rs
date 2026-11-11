// SPDX-License-Identifier: GPL-3.0-only
//! `auto daemon` (design 2.7, 3.4.4; card P3-6a).
//!
//! The command takes the data folder as its `daemon` owner, with the socket
//! path in `run/owner.json`; a folder the window, another daemon or a
//! command owns is refused with exit 21 and the owner named. It then runs
//! the service until a stop signal and exits 0 (130 after a second signal
//! within 5 s).
use crate::{
    args::Mode,
    context::Context,
    error::{CliError, ErrorCode},
    exit::Exit,
    logging::Logger,
    output::Reply,
    service_log::ServiceLog,
    signals,
};
use antinomie_monitor_core::{
    Backend,
    data_owner::{OwnerClaim, OwnerKind},
};
use antinomie_service::{
    api::status::Owner,
    config::{ServiceConfig, validate},
    daemon::{Daemon, Exit as DaemonExit, Setup},
    server::limits::Limits,
};
use clap::Args;
use serde_json::json;
use std::{os::unix::fs::DirBuilderExt, path::PathBuf, sync::Arc, time::Duration};

/// The longest path a Unix socket address holds (`sun_path`, less the NUL).
const SOCKET_PATH_MAX: usize = 107;

#[derive(Args, Debug)]
pub struct DaemonArgs {
    /// The service configuration [default: <data>/service.toml].
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Run in the foreground (the only mode; accepted for the design's grammar).
    #[arg(long)]
    pub foreground: bool,
}

/// `service.toml` from `--config` or the data folder; a missing default file
/// is the defaults, a file with errors stops the start (exit 4).
/// The daemon's socket, the one rule for the daemon and its clients:
/// `--socket`, else `[daemon] socket` of `service.toml`, else
/// `<data>/run/antinomie.sock`.
pub fn socket_path(
    flag: Option<&std::path::Path>,
    config: &ServiceConfig,
    data_dir: &std::path::Path,
) -> PathBuf {
    flag.map(PathBuf::from)
        .unwrap_or_else(|| config.socket_path(data_dir))
}

/// The socket a client looks for. It reads `<data>/service.toml` like the
/// daemon does; a file that is missing or has errors is no reason to fail a
/// client, which then uses the default path.
pub fn client_socket(flag: Option<&std::path::Path>, data_dir: &std::path::Path) -> PathBuf {
    let config = load_config(None, data_dir).unwrap_or_default();
    socket_path(flag, &config, data_dir)
}

pub fn load_config(
    path: Option<&PathBuf>,
    data_dir: &std::path::Path,
) -> Result<ServiceConfig, CliError> {
    let file = path
        .cloned()
        .unwrap_or_else(|| data_dir.join("service.toml"));
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && path.is_none() => {
            return Ok(ServiceConfig::default());
        }
        Err(error) => return Err(CliError::io(&file, &error)),
    };
    let shown = file.display().to_string();
    let (config, problems) = validate::parse_service(&shown, &text);
    let errors: Vec<_> = problems
        .iter()
        .filter(|p| p.severity == antinomie_service::config::Severity::Error)
        .collect();
    match config {
        Some(config) if errors.is_empty() => Ok(config),
        _ => Err(CliError::new(
            ErrorCode::InvalidArgument,
            format!(
                "{shown} has {} error(s); `antinomie-cli config validate` lists them",
                errors.len().max(1)
            ),
        )
        .with_details(json!({ "problems": problems }))),
    }
}

pub fn run(arguments: &DaemonArgs, context: &Context) -> Result<Reply, CliError> {
    if context.mode() == Mode::Daemon {
        return Err(CliError::invalid(
            "`auto daemon` is the daemon; --daemon does not apply to it",
        ));
    }
    let data_dir = context.data_dir().to_path_buf();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&data_dir)
        .map_err(|e| CliError::io(&data_dir, &e))?;
    let config = load_config(arguments.config.as_ref(), &data_dir)?;
    let socket = socket_path(context.global.socket.as_deref(), &config, &data_dir);
    if socket.as_os_str().len() > SOCKET_PATH_MAX {
        return Err(CliError::invalid(format!(
            "the socket path is {} bytes; a Unix socket path holds at most {SOCKET_PATH_MAX} (set [daemon] socket or --socket)",
            socket.as_os_str().len()
        ))
        .with_field("socket"));
    }
    let mut options = context.options.clone();
    options.owner = OwnerClaim {
        kind: OwnerKind::Daemon,
        socket: Some(socket.clone()),
        lane: None,
    };
    let backend = Backend::new(options.clone())
        .map_err(|message| CliError::from_engine_start(&data_dir, &message))?;
    signals::install_daemon();
    // Flags win over `service.toml [log]`: -q, -v and --log-format set the
    // level and format; the file's apply otherwise. The file's destination
    // (`[log] file`, else stderr) has no flag.
    let logger = Logger::for_daemon(&context.global, &config.log);
    let service_log = Arc::new(
        ServiceLog::open(logger, config.log.file.as_deref()).map_err(|error| {
            CliError::invalid(format!("[log] file cannot be opened: {error}"))
                .with_field("log.file")
        })?,
    );
    let setup = Setup {
        options,
        socket: Some(socket.clone()),
        owner: Owner::Daemon,
        host_grace: Duration::from_secs(u64::from(config.daemon.shutdown_host_grace_s)),
        limits: Limits::default(),
        log: Arc::new(move |line: &str| service_log.log(line)),
        config,
    };
    let mut daemon = Daemon::start(setup, backend)
        .map_err(|message| CliError::new(ErrorCode::Unavailable, message))?;
    let exit = daemon.supervise(&signals::DaemonSignals::new(), &|_| false);
    let mut backend = daemon
        .finish()
        .map_err(|error| CliError::internal(error.message))?;
    // Stops a VM that still runs and releases the data folder.
    let _ = backend.shutdown();
    let result = json!({"stopped": true, "data_dir": data_dir, "socket": socket});
    match exit {
        DaemonExit::Clean => Ok(Reply::value(result).with_human("daemon stopped".into())),
        DaemonExit::Hurried => Ok(Reply::value(result)
            .with_human("daemon stopped at once (second signal)".into())
            .with_exit(Exit::Interrupted)),
        DaemonExit::EngineLost => Err(CliError::internal(
            "the engine stopped under the daemon; see the log",
        )),
    }
}

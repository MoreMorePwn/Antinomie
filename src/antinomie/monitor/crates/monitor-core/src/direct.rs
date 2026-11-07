// SPDX-License-Identifier: GPL-3.0-only
//! Run one engine command to its result from a process that owns a `Backend`
//! and has no window: the one-shot flows of the app's command line and of
//! `antinomie-cli`. The wait never gives up by itself, because the worker owns
//! the operation until it ends (copying and verifying a desktop image can
//! take longer than two minutes) and a frontend deadline could neither
//! cancel it nor report its outcome truthfully.
use crate::{Backend, BackendOptions, Command, Notification};
use std::{path::PathBuf, time::Duration};

/// Wait for the `CommandResult` of command `id`: its message on success, or
/// the failure message. Other notifications are ignored; a closed channel
/// ends the wait with the receiver's error.
pub fn wait_for_result(
    id: u64,
    mut receive: impl FnMut(Duration) -> Result<Option<Notification>, String>,
) -> Result<String, String> {
    loop {
        if let Some(Notification::CommandResult {
            id: reply,
            success,
            message,
        }) = receive(Duration::from_secs(1))?
            && reply == id
        {
            return if success { Ok(message) } else { Err(message) };
        }
    }
}

/// Start an engine on `options`, send one command, wait for its result and
/// shut the engine down. A failed shutdown is reported with the result.
pub fn run_command(options: BackendOptions, command: Command) -> Result<String, String> {
    let mut backend = Backend::new(options)?;
    let result = backend
        .send(command)
        .and_then(|id| wait_for_result(id, |timeout| backend.recv_timeout(timeout)));
    let shutdown = backend.shutdown();
    match (result, shutdown) {
        (Ok(message), Ok(())) => Ok(message),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(shutdown)) => Err(format!("{error}; shutdown: {shutdown}")),
    }
}

/// Import the base in `directory` into the data directory and return the
/// engine's message (the app's `--install-base`).
pub fn install_base(options: BackendOptions, directory: PathBuf) -> Result<String, String> {
    run_command(options, Command::ImportBase { directory })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_import_waits_past_two_minutes_of_receive_timeouts_for_its_result() {
        let mut polls = 0;
        let result = wait_for_result(7, |timeout| {
            assert_eq!(timeout, Duration::from_secs(1));
            polls += 1;
            Ok((polls > 130).then(|| Notification::CommandResult {
                id: 7,
                success: true,
                message: "base imported".into(),
            }))
        });
        assert_eq!(result.as_deref(), Ok("base imported"));
        assert_eq!(polls, 131);
    }

    #[test]
    fn base_import_ignores_other_commands_and_preserves_its_failure() {
        let mut notifications = [
            Notification::CommandResult {
                id: 6,
                success: true,
                message: "another command completed".into(),
            },
            Notification::CommandResult {
                id: 7,
                success: false,
                message: "bundle changed during import; copies rejected".into(),
            },
        ]
        .into_iter();
        let result = wait_for_result(7, |_| Ok(notifications.next()));
        assert_eq!(
            result,
            Err("bundle changed during import; copies rejected".into())
        );
    }

    #[test]
    fn base_import_reports_disconnected_worker_without_claiming_success() {
        let result = wait_for_result(7, |_| Err("backend owner disconnected".into()));
        assert_eq!(result, Err("backend owner disconnected".into()));
    }
}

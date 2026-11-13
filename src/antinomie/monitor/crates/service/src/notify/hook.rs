// SPDX-License-Identifier: GPL-3.0-only
//! The `[notify] on_finish` command hook (design 4.10).
//!
//! The command is the configured argv, run directly: **no shell** is
//! involved and nothing a job controls is part of the argv. The environment
//! is cleared and holds exactly the variables named below. The process is
//! the daemon's own user, with `/dev/null` as its input, `/` as its working
//! folder, and its own process group, which is killed when the time limit
//! passes. Its output is captured (64 KiB of each stream) for `job.log`.
//!
//! | Variable | Value |
//! |---|---|
//! | `ANTINOMIE_RUN_ID` | the run id (`r_` and 26 characters) |
//! | `ANTINOMIE_STATE` | `succeeded`, `partial`, `failed`, `cancelled` or `rejected` |
//! | `ANTINOMIE_LABEL` | `clean_observed`, `suspicious`, `malicious`, `inconclusive`, or empty |
//! | `ANTINOMIE_SHA256` | the sample's SHA-256, or empty |
//! | `ANTINOMIE_RESULT_JSON` | the absolute path of the job's `job.json` |

use std::{
    io::Read,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

/// How long the hook may run.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Bytes kept of each of its output streams.
pub const OUTPUT_LIMIT: usize = 64 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HookRun {
    pub exit: Option<i32>,
    /// The signal that ended it, when one did.
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The command could not be started.
    pub error: Option<String>,
}

impl HookRun {
    pub fn succeeded(&self) -> bool {
        self.exit == Some(0) && !self.timed_out && self.error.is_none()
    }

    /// One line for the log.
    pub fn words(&self) -> String {
        if let Some(error) = &self.error {
            format!("could not be started: {error}")
        } else if self.timed_out {
            format!("did not finish in {} s and was killed", TIMEOUT.as_secs())
        } else if let Some(code) = self.exit {
            format!("exited with code {code}")
        } else if let Some(signal) = self.signal {
            format!("was ended by signal {signal}")
        } else {
            "ended".into()
        }
    }
}

fn drain(mut stream: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = OUTPUT_LIMIT.saturating_sub(kept.len());
                    kept.extend_from_slice(&buffer[..n.min(room)]);
                }
            }
        }
        let _ = sender.send(kept);
    });
    receiver
}

/// Run `argv` (the program and its fixed arguments) with exactly `env` and
/// the time limit `timeout`.
pub fn run(argv: &[String], env: &[(&str, String)], timeout: Duration) -> HookRun {
    let mut out = HookRun::default();
    let Some((program, args)) = argv.split_first() else {
        out.error = Some("no command is configured".into());
        return out;
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(env.iter().map(|(k, v)| (*k, v.as_str())))
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own group, so the limit can end the command and what it started.
        .process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            out.error = Some(error.to_string());
            return out;
        }
    };
    let stdout = child.stdout.take().map(drain);
    let stderr = child.stderr.take().map(drain);
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if started.elapsed() >= timeout => {
                out.timed_out = true;
                // Only the group this function made, by the pid it recorded.
                if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = child.kill();
                break child.wait().ok();
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                out.error = Some(error.to_string());
                break None;
            }
        }
    };
    if let Some(status) = status {
        out.exit = status.code();
        out.signal = status.signal();
    }
    // A grandchild that keeps a pipe open must not hold the daemon.
    let wait = Duration::from_secs(2);
    if let Some(receiver) = stdout {
        out.stdout = receiver.recv_timeout(wait).unwrap_or_default();
    }
    if let Some(receiver) = stderr {
        out.stderr = receiver.recv_timeout(wait).unwrap_or_default();
    }
    out
}

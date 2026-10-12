// SPDX-License-Identifier: MIT
//! Running optional local tools inside the analysis sandbox: bounded output,
//! a wall-clock timeout and an explicit environment.
use std::{
    io::Read,
    path::Path,
    process::{Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};

pub(super) struct Run {
    pub stdout: String,
    /// Output reached `max_output` and was cut.
    pub truncated: bool,
    /// The tool ran out of time and was stopped.
    pub timed_out: bool,
    pub success: bool,
}

/// First existing executable among `candidates`.
pub(super) fn find(candidates: &[&'static str]) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
}

/// A tool: the system's copy first, then the one Antinomie installed
/// (mounted at `analysis_tools::SANDBOX_DIR`).
/// `ANTINOMIE_ANALYSIS_TOOLS=managed` (passed in from the host) prefers the
/// copy Antinomie installed over the system's.
pub(super) fn find_tool(system: &[&'static str], managed: &'static str) -> Option<&'static str> {
    let managed = Path::new(managed).is_file().then_some(managed);
    if std::env::var("ANTINOMIE_ANALYSIS_TOOLS").as_deref() == Ok("managed") {
        managed.or_else(|| find(system))
    } else {
        find(system).or(managed)
    }
}

/// Run `path` with `args`; `env` adds to a cleared environment with
/// `LC_ALL=C` and a standard `PATH`.
pub(super) fn run(
    path: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    max_output: usize,
) -> Result<Run, String> {
    run_with(path, args, env, timeout, max_output, false)
}

/// `run`, optionally passing the tool's diagnostics on to worker.log.
pub(super) fn run_with(
    path: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    max_output: usize,
    log_stderr: bool,
) -> Result<Run, String> {
    run_cancellable(
        path,
        args,
        env,
        timeout,
        max_output,
        log_stderr,
        &AtomicBool::new(false),
    )
}

/// [`run_with`], stopping the tool when `cancel` is set.
pub(super) fn run_cancellable(
    path: &str,
    args: &[&str],
    env: &[(&str, &str)],
    timeout: Duration,
    max_output: usize,
    log_stderr: bool,
    cancel: &AtomicBool,
) -> Result<Run, String> {
    let mut command = Command::new(path);
    command
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        // The sandbox has no passwd database; tools that ask for the user
        // name (Python's getpass) take it from here.
        .env("USER", "analysis")
        .env("LOGNAME", "analysis")
        .current_dir("/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(if log_stderr {
            Stdio::inherit()
        } else {
            Stdio::null()
        });
    for (key, value) in env {
        command.env(key, value);
    }
    let mut child = command.spawn().map_err(|e| format!("{path}: {e}"))?;
    let mut stdout = child.stdout.take().ok_or("tool stdout unavailable")?;
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        let _ = (&mut stdout)
            .take(max_output as u64 + 1)
            .read_to_end(&mut output);
        // Drain the rest so the tool never blocks on a full pipe.
        let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        output
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait().map_err(|e| format!("{path}: {e}"))? {
            Some(status) => break status,
            None if cancel.load(Ordering::Relaxed) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("cancelled".into());
            }
            None if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().map_err(|e| format!("{path}: {e}"))?;
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    };
    let mut output = reader.join().map_err(|_| "tool reader failed")?;
    let truncated = output.len() > max_output;
    output.truncate(max_output);
    Ok(Run {
        stdout: String::from_utf8_lossy(&output).into_owned(),
        truncated,
        timed_out,
        success: status.success(),
    })
}

/// The first line a tool prints for `args` (its version), or the tool name.
pub(super) fn version(path: &str, args: &[&str]) -> String {
    run(path, args, &[], Duration::from_secs(20), 4096)
        .ok()
        .and_then(|run| run.stdout.lines().next().map(|l| l.trim().to_owned()))
        .filter(|line| !line.is_empty())
        .unwrap_or_else(|| {
            Path::new(path)
                .file_name()
                .map_or(path.to_owned(), |n| n.to_string_lossy().into_owned())
        })
}

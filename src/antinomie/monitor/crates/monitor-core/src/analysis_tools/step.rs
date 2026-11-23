// SPDX-License-Identifier: GPL-3.0-only
//! One tool-installation step (venv, pip): run to its end, a cancel or its time limit.
use super::CANCELLED_INSTALL;
use std::{
    process::{Command, Stdio},
    sync::atomic::AtomicBool,
    time::Duration,
};

/// The longest one installation step (a venv or a pip run) may take.
pub(super) const STEP_LIMIT: Duration = Duration::from_secs(30 * 60);

/// Run one installation step; its standard output on success, the end of
/// its diagnostics on failure. `cancel` stops it and everything it started,
/// and so does the step time limit.
pub(super) fn step(command: &mut Command, cancel: &AtomicBool) -> Result<String, String> {
    step_within(command, cancel, STEP_LIMIT)
}

fn step_within(
    command: &mut Command,
    cancel: &AtomicBool,
    limit: Duration,
) -> Result<String, String> {
    crate::cancel::lead_group(command);
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stop = AtomicBool::new(false);
    let finished = AtomicBool::new(false);
    let timed_out = AtomicBool::new(false);
    let captured = std::thread::scope(|scope| {
        scope.spawn(|| {
            let started = std::time::Instant::now();
            while !finished.load(std::sync::atomic::Ordering::Relaxed) {
                if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                } else if started.elapsed() >= limit {
                    timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let captured = crate::cancel::capture(&mut child, &stop, 1 << 20, 1 << 16);
        finished.store(true, std::sync::atomic::Ordering::Relaxed);
        captured
    });
    let Some(done) = captured? else {
        if timed_out.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(format!(
                "the step took longer than {} minutes and was stopped",
                limit.as_secs() / 60
            ));
        }
        return Err(CANCELLED_INSTALL.into());
    };
    if done.status.success() {
        Ok(String::from_utf8_lossy(&done.stdout).into_owned())
    } else {
        let diagnostics = String::from_utf8_lossy(&done.stderr);
        let tail: Vec<_> = diagnostics.lines().rev().take(3).collect();
        Err(tail
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" ")
            .trim()
            .to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_install_step_that_never_ends_is_stopped_at_its_limit() {
        let cancel = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let error = step_within(
            Command::new("sleep").arg("30"),
            &cancel,
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(error.contains("was stopped"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let cancel = AtomicBool::new(true);
        let error = step_within(Command::new("sleep").arg("30"), &cancel, STEP_LIMIT).unwrap_err();
        assert_eq!(error, CANCELLED_INSTALL);
        let cancel = AtomicBool::new(false);
        assert_eq!(
            step_within(Command::new("echo").arg("ok"), &cancel, STEP_LIMIT).unwrap(),
            "ok\n"
        );
    }
}

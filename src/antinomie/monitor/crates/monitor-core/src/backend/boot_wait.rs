// SPDX-License-Identifier: GPL-3.0-only
//! Before the first program of a boot is launched, wait for a systemd guest to
//! finish booting. The guest control channel is ready long before systemd and
//! cron are, and persistence such as `@reboot` cron would otherwise start a
//! second copy of the program outside the recording.
//!
//! The control channel cannot run a command, and a program run through it is a
//! recorded run, so the wait asks the guest kernel to open a file systemd
//! writes (ACQUIRE, the call static analysis uses): no process starts in the
//! guest, so nothing of the wait is in the recording or the process tree.
//! `/run/systemd/system` tells a systemd guest from any other (BusyBox, Alpine);
//! `/run/systemd/boot-finished` is created when systemd's start-up job queue
//! is empty, which is what `systemctl is-system-running --wait` waits for. It
//! is created whether or not every unit succeeded, so a degraded system counts
//! as done.
use super::worker_guest::GUEST_REPLY_TIMEOUT;
use super::*;
use crate::boot_wait::{BootWait, BootWaitOutcome, LaunchWait, WAIT_TEXT};

/// Present on a system that was booted with systemd (`sd_booted()`).
const SYSTEMD_RUNTIME: &str = "/run/systemd/system";
/// Created by systemd's manager when start-up has finished.
const BOOT_FINISHED: &str = "/run/systemd/boot-finished";
/// Pause between two looks at the guest.
const POLL: Duration = Duration::from_millis(1000);
const ENOENT: i32 = 2;

/// What the guest said about a path.
enum Probe {
    Present,
    Absent,
    /// Anything else; the wait goes on and tries again.
    Unsure,
}

/// Cancellation and bookkeeping of the wait; one per worker.
#[derive(Default)]
pub(super) struct BootWaitState {
    pub(super) waiting: bool,
    pub(super) cancel: bool,
}

impl Worker {
    fn probe_path(&mut self, path: &str) -> Probe {
        let Some(session) = self.session.as_mut() else {
            return Probe::Unsure;
        };
        let Ok(args) = control::acquire(path, 0, 0, 4096) else {
            return Probe::Unsure;
        };
        match session.request_typed(
            control::ACQUIRE,
            &args,
            &mut self.snapshot,
            &self.sender,
            GUEST_REPLY_TIMEOUT,
        ) {
            Ok(reply) => match control::acquisition(&reply) {
                Ok((id, _)) => {
                    let _ = session.request(
                        control::SPECIMEN_RELEASE,
                        &control::with_session(id),
                        &mut self.snapshot,
                        &self.sender,
                        GUEST_REPLY_TIMEOUT,
                    );
                    Probe::Present
                }
                Err(_) if reply.len() == 24 => {
                    match crate::parser::u32_at(&reply, 16).map(|status| status as i32) {
                        Ok(status) if status == -ENOENT => Probe::Absent,
                        _ => Probe::Unsure,
                    }
                }
                Err(_) => Probe::Unsure,
            },
            Err(RequestError::Rejected { status, .. }) if status == -ENOENT => Probe::Absent,
            Err(_) => Probe::Unsure,
        }
    }

    /// Wait until the guest has finished booting, serving the app's commands
    /// meanwhile (Stop VM, Cancel). `Err` when the launch was given up.
    pub(super) fn wait_for_boot(&mut self, program: &str) -> Result<BootWait, String> {
        let skipped = |detail: &str| BootWait {
            waited_ms: 0,
            outcome: BootWaitOutcome::Skipped,
            detail: Some(detail.into()),
        };
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        if session.boot_settled {
            return Ok(BootWait {
                waited_ms: 0,
                outcome: BootWaitOutcome::Ready,
                detail: None,
            });
        }
        let revision = self.snapshot.guest_kernel.as_ref().and_then(|k| k.revision);
        if control::specimen_request(revision, session.vm.ram_mib).is_none() {
            return Ok(skipped("this base cannot be asked about its boot"));
        }
        let deadline = session.process.waits.scaled(Duration::from_secs(u64::from(
            self.options.start.boot_wait_secs,
        )));
        let started = Instant::now();
        let mut systemd = None;
        // The first look decides whether there is anything to wait for.
        loop {
            if systemd.is_none() {
                match self.probe_path(SYSTEMD_RUNTIME) {
                    Probe::Absent => {
                        self.finish_boot_wait();
                        return Ok(skipped("the guest does not run systemd"));
                    }
                    Probe::Present => systemd = Some(true),
                    Probe::Unsure => {}
                }
            }
            if systemd.is_some() && matches!(self.probe_path(BOOT_FINISHED), Probe::Present) {
                break;
            }
            if started.elapsed() >= deadline {
                self.finish_boot_wait();
                return Ok(BootWait {
                    waited_ms: started.elapsed().as_millis() as u64,
                    outcome: BootWaitOutcome::Timeout,
                    detail: Some(format!("gave up after {} s", deadline.as_secs())),
                });
            }
            if !self.boot_wait_state.waiting {
                self.boot_wait_state.waiting = true;
                self.boot_wait_state.cancel = false;
                self.snapshot.launch_wait = Some(LaunchWait {
                    program: program.into(),
                    started_ms: unix_ms(),
                    text: WAIT_TEXT.into(),
                });
                self.publish();
            }
            let pause = Instant::now();
            while pause.elapsed() < POLL {
                if self.handle_commands() {
                    self.closing.store(true, Ordering::Relaxed);
                }
                if self.closing.load(Ordering::Acquire) || self.session.is_none() {
                    self.finish_boot_wait();
                    return Err("VM stopped while the launch waited for the boot".into());
                }
                if self.boot_wait_state.cancel {
                    self.finish_boot_wait();
                    return Err("launch cancelled while it waited for the guest to boot".into());
                }
            }
        }
        let waited_ms = started.elapsed().as_millis() as u64;
        if let Some(session) = self.session.as_mut() {
            session.boot_settled = true;
        }
        self.finish_boot_wait();
        Ok(BootWait {
            waited_ms,
            outcome: BootWaitOutcome::Ready,
            detail: None,
        })
    }

    fn finish_boot_wait(&mut self) {
        let was_waiting = self.boot_wait_state.waiting;
        self.boot_wait_state = BootWaitState::default();
        if was_waiting {
            self.snapshot.launch_wait = None;
            self.publish();
        }
    }
}

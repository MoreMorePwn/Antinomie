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
//! Whether the guest runs systemd is decided from the base, not from the
//! guest: a base with a guest profile is a full distribution (Debian) and
//! boots with systemd; one without (BusyBox) does not. Asking the guest
//! (`/run/systemd/system`) is wrong early in boot, when `/run` is not mounted
//! yet but the in-kernel control channel already answers, so an absent file
//! there says nothing; it is only used for a base without a profile.
//! A systemd guest has finished booting when `/run/systemd/system` is there
//! (userspace runs, `/run` is mounted) and `/run/systemd/boot-finished`
//! (systemd's start-up job queue is empty, so `local-fs.target`, `tmp.mount`
//! and `basic.target` are done; a degraded system counts too) or
//! `/run/crond.reboot` (cron has started and run its `@reboot` entries) shows.
//! A probe that is unsure or absent keeps the wait going until the timeout.
use super::*;
use crate::boot_wait::{
    BootWait, BootWaitOutcome, LaunchWait, NETWORK_WAIT_TEXT, NetworkWait, WAIT_TEXT,
};

/// Present on a system that was booted with systemd (`sd_booted()`).
const SYSTEMD_RUNTIME: &str = "/run/systemd/system";
/// Created by systemd's manager when start-up has finished.
const BOOT_FINISHED: &str = "/run/systemd/boot-finished";
/// Created by cron once it has started and run its `@reboot` entries.
const CRON_STARTED: &str = "/run/crond.reboot";
/// Pause between two looks at the guest.
const POLL: Duration = Duration::from_millis(1000);
/// Pause between two looks at the gateway (it answers at once).
const NETWORK_POLL: Duration = Duration::from_millis(250);
const ENOENT: i32 = 2;

/// Errors that say nothing about the file: busy, out of memory, interrupted,
/// out of handles, timed out.
fn transient(errno: i32) -> bool {
    matches!(errno, 4 | 11 | 12 | 16 | 23 | 24 | 110)
}

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
        let timeout = session.reply_timeout();
        match session.request_typed(
            control::ACQUIRE,
            &args,
            &mut self.snapshot,
            &self.sender,
            timeout,
        ) {
            Ok(reply) => match control::acquisition(&reply) {
                Ok((id, _)) => {
                    let _ = session.request(
                        control::SPECIMEN_RELEASE,
                        &control::with_session(id),
                        &mut self.snapshot,
                        &self.sender,
                        timeout,
                    );
                    Probe::Present
                }
                // The guest answered with an errno for the file: any but
                // "no such file" means the file is there (an empty file or a
                // directory cannot be kept as a specimen).
                Err(_) if reply.len() == 24 => {
                    match crate::parser::u32_at(&reply, 16).map(|status| status as i32) {
                        Ok(status) if status == -ENOENT => Probe::Absent,
                        Ok(status) if status < 0 && !transient(-status) => Probe::Present,
                        _ => Probe::Unsure,
                    }
                }
                Err(_) => Probe::Unsure,
            },
            Err(RequestError::Rejected { status, .. }) if status == -ENOENT => Probe::Absent,
            Err(RequestError::Rejected { status, .. }) if status < 0 && !transient(-status) => {
                Probe::Present
            }
            Err(_) => Probe::Unsure,
        }
    }

    /// Whether a systemd guest has finished booting: userspace is up (`/run`
    /// is mounted) and one of the end-of-boot markers is there.
    fn boot_finished(&mut self) -> bool {
        matches!(self.probe_path(SYSTEMD_RUNTIME), Probe::Present)
            && (matches!(self.probe_path(BOOT_FINISHED), Probe::Present)
                || matches!(self.probe_path(CRON_STARTED), Probe::Present))
    }

    /// Wait until the guest has finished booting, serving the app's commands
    /// meanwhile (Stop VM, Cancel). `Err` when the launch was given up.
    pub(super) fn wait_for_boot(&mut self, program: &str) -> Result<BootWait, String> {
        let skipped = |detail: &str| BootWait {
            waited_ms: 0,
            outcome: BootWaitOutcome::Skipped,
            detail: Some(detail.into()),
            network: None,
        };
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        if session.boot_settled {
            return Ok(BootWait {
                waited_ms: 0,
                outcome: BootWaitOutcome::Ready,
                detail: None,
                network: None,
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
        // A base with a guest profile is a full distribution that boots with
        // systemd; any other is asked once (a BusyBox base has no systemd).
        let mut systemd = session.bundle.guest.is_some();
        loop {
            if !systemd {
                match self.probe_path(SYSTEMD_RUNTIME) {
                    Probe::Absent => {
                        self.finish_boot_wait();
                        return Ok(skipped("the guest does not run systemd"));
                    }
                    Probe::Present => systemd = true,
                    Probe::Unsure => {}
                }
            }
            if systemd && self.boot_finished() {
                break;
            }
            if started.elapsed() >= deadline {
                self.finish_boot_wait();
                return Ok(BootWait {
                    waited_ms: started.elapsed().as_millis() as u64,
                    outcome: BootWaitOutcome::Timeout,
                    detail: Some(format!("gave up after {} s", deadline.as_secs())),
                    network: None,
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
            network: None,
        })
    }

    /// The guest has its network address, as the Routed VM's gateway saw it;
    /// `None` without a gateway.
    fn guest_has_address(&self) -> Option<bool> {
        let gateway = self.session.as_ref()?.process.gateway.as_ref()?;
        Some(gateway.guest_has_address())
    }

    fn probe_guest(&self, on: bool) {
        if let Some(gateway) = self
            .session
            .as_ref()
            .and_then(|session| session.process.gateway.as_ref())
        {
            gateway.probe_guest(on);
        }
    }

    /// After the boot wait, wait until a Routed VM's guest has its network
    /// address, serving the app's commands meanwhile. Without it a program
    /// that connects at once gets ENETUNREACH, and one that kills the DHCP
    /// client before the lease (Mirai's killer on BusyBox) has no network for
    /// the whole run. `Err` when the launch was given up.
    pub(super) fn wait_for_network(&mut self, program: &str) -> Result<NetworkWait, String> {
        let skipped = |detail: &str| NetworkWait {
            waited_ms: 0,
            outcome: BootWaitOutcome::Skipped,
            detail: Some(detail.into()),
        };
        let session = self.session.as_ref().ok_or("VM is stopped")?;
        let secs = self.options.start.network_wait_secs;
        let Some(ready) = self.guest_has_address() else {
            return Ok(skipped(
                "the VM's network is not Routed: only a Routed VM's gateway sees the guest's address",
            ));
        };
        if ready {
            return Ok(NetworkWait {
                waited_ms: 0,
                outcome: BootWaitOutcome::Ready,
                detail: None,
            });
        }
        if secs == 0 {
            return Ok(skipped("the network wait is off in the settings"));
        }
        if session.network_unseen {
            return Ok(skipped(
                "an earlier wait of this boot ran out: the guest does not take the gateway's address",
            ));
        }
        let deadline = session
            .process
            .waits
            .scaled(Duration::from_secs(u64::from(secs)));
        let started = Instant::now();
        self.probe_guest(true);
        let outcome = loop {
            if self.guest_has_address() == Some(true) {
                break Ok(BootWaitOutcome::Ready);
            }
            if started.elapsed() >= deadline {
                if let Some(session) = self.session.as_mut() {
                    session.network_unseen = true;
                }
                break Ok(BootWaitOutcome::Timeout);
            }
            if !self.boot_wait_state.waiting {
                self.boot_wait_state.waiting = true;
                self.boot_wait_state.cancel = false;
                self.snapshot.launch_wait = Some(LaunchWait {
                    program: program.into(),
                    started_ms: unix_ms(),
                    text: NETWORK_WAIT_TEXT.into(),
                });
                self.publish();
            }
            let pause = Instant::now();
            let mut given_up = None;
            while pause.elapsed() < NETWORK_POLL {
                if self.handle_commands() {
                    self.closing.store(true, Ordering::Relaxed);
                }
                if self.closing.load(Ordering::Acquire) || self.session.is_none() {
                    given_up = Some("VM stopped while the launch waited for the guest's network");
                    break;
                }
                if self.boot_wait_state.cancel {
                    given_up = Some("launch cancelled while it waited for the guest's network");
                    break;
                }
            }
            if let Some(why) = given_up {
                break Err(why.to_string());
            }
        };
        self.probe_guest(false);
        self.finish_boot_wait();
        let waited_ms = started.elapsed().as_millis() as u64;
        Ok(NetworkWait {
            waited_ms,
            outcome: outcome?,
            detail: None,
        })
        .map(|mut wait| {
            if wait.outcome == BootWaitOutcome::Timeout {
                wait.detail = Some(format!("gave up after {} s", deadline.as_secs()));
            }
            wait
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

// SPDX-License-Identifier: MIT
//! `DebugBackend` over the guest kernel's debug engine. Requests go through a
//! `GuestLink`; the backend keeps the session id and the generation of the last
//! stop it saw, and sends that generation with every request so an operation
//! made against a stop that has since ended is refused, never misapplied.
use super::{
    target::{
        ArchTag, DebugBackend, DebugCaps, DebugError, DetachMode, GuestLink, LinkError, RegsetBlob,
        ResumeAction, StopEvent, StopKind, TargetState, ThreadInfo,
    },
    wire,
};
use crate::observation::GuestProcessIdentity;
use std::time::{Duration, Instant};

const EBUSY: i32 = 16;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ESRCH: i32 = 3;
const EOPNOTSUPP: i32 = 95;
const ESTALE: i32 = 116;

fn map_link(error: LinkError) -> DebugError {
    match error.errno {
        Some(EBUSY) => DebugError::Busy,
        Some(ESTALE) => DebugError::Stale,
        Some(ESRCH) => DebugError::Gone,
        Some(EFAULT) => DebugError::Fault,
        Some(EOPNOTSUPP) => DebugError::Unsupported(error.message),
        Some(EINVAL) => DebugError::Invalid(error.message),
        Some(errno) => DebugError::Guest {
            errno,
            message: error.message,
        },
        None => DebugError::Transport(error.message),
    }
}
fn protocol(message: String) -> DebugError {
    DebugError::Transport(message)
}

/// A session the guest opened, before a backend owns it.
pub struct AttachedSession {
    pub caps: DebugCaps,
    pub session: u64,
    pub generation: u64,
}

pub struct KernelDebugBackend {
    link: Box<dyn GuestLink + Send>,
    caps: DebugCaps,
    session: u64,
    generation: u64,
    failure: Option<String>,
    reported_error: i32,
}

impl KernelDebugBackend {
    /// What the guest's debugger can do, without attaching to anything.
    pub fn probe(link: &mut dyn GuestLink) -> Result<DebugCaps, DebugError> {
        let reply = link
            .request(wire::CAPS, &wire::caps_request())
            .map_err(|error| match error.errno {
                Some(EOPNOTSUPP) => DebugError::Unsupported(
                    "this guest has no debugger; its base is older than this feature".into(),
                ),
                _ => map_link(error),
            })?;
        wire::parse_caps(&reply).map_err(protocol)
    }

    /// Attach to one process of the guest. The nonce makes a repeated attach
    /// idempotent in the guest; `stop_now` stops the group at once.
    pub fn attach_session(
        link: &mut dyn GuestLink,
        identity: &GuestProcessIdentity,
        nonce: [u64; 2],
        stop_now: bool,
    ) -> Result<AttachedSession, DebugError> {
        let caps = Self::probe(link)?;
        if !caps.software_breakpoints || !caps.multi_thread {
            return Err(DebugError::Unsupported(
                "the guest debugger lacks software breakpoints".into(),
            ));
        }
        let request = wire::attach_request(&wire::AttachRequest {
            task_cookie: identity.task_cookie,
            start_boot_ns: identity.start_boot_ns,
            tgid: identity.tgid,
            arch: caps.arch,
            nonce,
            stop_now,
        })
        .map_err(DebugError::Invalid)?;
        let reply = link
            .request(wire::ATTACH, &request)
            .map_err(map_link)
            .and_then(|reply| wire::parse_attach(&reply).map_err(protocol))?;
        if reply.arch != caps.arch {
            return Err(protocol("guest architecture changed during attach".into()));
        }
        Ok(AttachedSession {
            caps,
            session: reply.session,
            generation: reply.generation,
        })
    }

    /// A backend for a session `attach_session` opened, talking over `link`.
    pub fn new(link: Box<dyn GuestLink + Send>, attached: AttachedSession) -> Self {
        Self {
            link,
            caps: attached.caps,
            session: attached.session,
            generation: attached.generation,
            failure: None,
            reported_error: 0,
        }
    }

    pub fn attach(
        mut link: Box<dyn GuestLink + Send>,
        identity: &GuestProcessIdentity,
        nonce: [u64; 2],
        stop_now: bool,
    ) -> Result<Self, DebugError> {
        let attached = Self::attach_session(link.as_mut(), identity, nonce, stop_now)?;
        Ok(Self::new(link, attached))
    }

    pub fn arch(&self) -> ArchTag {
        self.caps.arch
    }
    pub fn session(&self) -> u64 {
        self.session
    }

    fn call(&mut self, opcode: u32, args: &[u8]) -> Result<Vec<u8>, DebugError> {
        self.link.request(opcode, args).map_err(map_link)
    }
}

impl DebugBackend for KernelDebugBackend {
    fn caps(&self) -> &DebugCaps {
        &self.caps
    }

    fn state(&mut self) -> Result<TargetState, DebugError> {
        let reply = self.call(wire::STATUS, &wire::status_request(self.session))?;
        let status = wire::parse_status(&reply).map_err(protocol)?;
        if status.session != self.session {
            return Err(DebugError::Gone);
        }
        if status.last_error != 0 && status.last_error != self.reported_error {
            self.failure = Some(match -status.last_error {
                110 => "a thread did not stop in time; it may be in an uninterruptible wait".into(),
                code => format!("the guest could not complete the request (error {})", -code),
            });
        }
        self.reported_error = status.last_error;
        Ok(match status.state {
            wire::STATE_RUNNING => TargetState::Running,
            wire::STATE_STOPPING | wire::STATE_RESUMING | wire::STATE_DETACHING => {
                TargetState::Transition
            }
            wire::STATE_STOPPED => {
                self.generation = status.generation;
                TargetState::Stopped(status.stop_event().unwrap_or(StopEvent {
                    sequence: status.event_sequence,
                    kind: StopKind::Interrupt,
                    tid: status.event_tid,
                    pc: status.event_pc,
                }))
            }
            wire::STATE_EXITED => TargetState::Exited {
                wait_status: status.wait_status,
            },
            wire::STATE_EXEC => TargetState::Replaced,
            _ => return Err(protocol("unknown guest debug state".into())),
        })
    }

    fn threads(&mut self) -> Result<Vec<ThreadInfo>, DebugError> {
        let reply = self.call(wire::THREADS, &wire::threads_request(self.session))?;
        Ok(wire::parse_threads(&reply)
            .map_err(protocol)?
            .into_iter()
            .map(|entry| ThreadInfo {
                tid: entry.tid,
                stopped: entry.stopped,
                pc: entry.pc,
            })
            .collect())
    }

    fn interrupt(&mut self) -> Result<(), DebugError> {
        self.call(wire::STOP, &wire::stop_request(self.session))
            .and_then(|reply| wire::parse_cont(&reply).map(|_| ()).map_err(protocol))
    }

    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError> {
        let step = match action {
            ResumeAction::Continue => None,
            ResumeAction::Step { tid } => Some(tid),
        };
        let reply = self.call(
            wire::CONT,
            &wire::cont_request(self.session, step, self.generation),
        )?;
        wire::parse_cont(&reply).map_err(protocol)?;
        Ok(())
    }

    fn read_regset(&mut self, tid: u32, nt_type: u32) -> Result<RegsetBlob, DebugError> {
        if self.caps.regset(nt_type).is_none() {
            return Err(DebugError::Unsupported(format!(
                "register set {nt_type} is not offered by the guest"
            )));
        }
        let reply = self.call(
            wire::REGS_READ,
            &wire::regs_read_request(self.session, tid, nt_type, self.generation),
        )?;
        wire::parse_regs(&reply, nt_type).map_err(protocol)
    }

    fn write_regset(&mut self, tid: u32, blob: &RegsetBlob) -> Result<(), DebugError> {
        if !self
            .caps
            .regset(blob.nt_type)
            .is_some_and(|set| set.writable)
        {
            return Err(DebugError::Unsupported(format!(
                "register set {} is read-only",
                blob.nt_type
            )));
        }
        let request = wire::regs_write_request(self.session, tid, blob, self.generation)
            .map_err(DebugError::Invalid)?;
        self.call(wire::REGS_WRITE, &request).map(|_| ())
    }

    fn read_memory(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, DebugError> {
        let chunk = self.caps.max_transfer as usize;
        let mut data = Vec::with_capacity(len.min(1 << 20));
        while data.len() < len {
            let want = (len - data.len()).min(chunk);
            let at = addr
                .checked_add(data.len() as u64)
                .ok_or(DebugError::Fault)?;
            let request = wire::mem_read_request(self.session, at, want, self.generation)
                .map_err(DebugError::Invalid)?;
            let part = match self.call(wire::MEM_READ, &request) {
                Ok(reply) => wire::parse_mem_read(&reply, want).map_err(protocol)?,
                Err(DebugError::Fault) if !data.is_empty() => break,
                Err(error) => return Err(error),
            };
            let short = part.len() < want;
            data.extend(part);
            if short {
                break;
            }
        }
        Ok(data)
    }

    fn write_memory(&mut self, addr: u64, data: &[u8]) -> Result<(), DebugError> {
        let chunk = self.caps.max_transfer as usize;
        for (index, part) in data.chunks(chunk).enumerate() {
            let at = addr
                .checked_add((index * chunk) as u64)
                .ok_or(DebugError::Fault)?;
            let request = wire::mem_write_request(self.session, at, part, self.generation)
                .map_err(DebugError::Invalid)?;
            let reply = self.call(wire::MEM_WRITE, &request)?;
            wire::parse_mem_write(&reply, part.len()).map_err(protocol)?;
        }
        Ok(())
    }

    fn set_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError> {
        if !self.caps.supports_breakpoint_len(len) {
            return Err(DebugError::Unsupported(format!(
                "{len}-byte software breakpoints"
            )));
        }
        let request = wire::breakpoint_request(self.session, addr, len, self.generation);
        self.call(wire::BP_SET, &request).map(|_| ())
    }

    fn clear_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError> {
        let request = wire::breakpoint_request(self.session, addr, len, self.generation);
        self.call(wire::BP_CLEAR, &request).map(|_| ())
    }

    /// Detach is asynchronous in the guest (it stops the group, removes the
    /// breakpoints and resumes it): poll until the session is gone.
    fn detach(&mut self, mode: DetachMode) -> Result<(), DebugError> {
        match self.call(
            wire::DETACH,
            &wire::detach_request(self.session, mode == DetachMode::Kill),
        ) {
            Ok(_) => {}
            Err(DebugError::Gone) => return Ok(()),
            Err(error) => return Err(error),
        }
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            match self.call(wire::STATUS, &wire::status_request(self.session)) {
                Err(DebugError::Gone) => return Ok(()),
                Err(error) => return Err(error),
                Ok(reply) => {
                    let status = wire::parse_status(&reply).map_err(protocol)?;
                    if status.state != wire::STATE_DETACHING && status.last_error != 0 {
                        return Err(DebugError::Guest {
                            errno: -status.last_error,
                            message: "the guest could not stop the process to detach".into(),
                        });
                    }
                }
            }
            if Instant::now() >= deadline {
                return Err(DebugError::Transport(
                    "detach did not finish in time".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn take_failure(&mut self) -> Option<String> {
        self.failure.take()
    }
}

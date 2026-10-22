// SPDX-License-Identifier: GPL-3.0-only
//! `DebugBackend` over the guest kernel's debug engine. Requests go through a
//! `GuestLink`; the backend keeps the session id and the generation of the last
//! stop it saw, and sends that generation with every request so an operation
//! made against a stop that has since ended is refused, never misapplied.
use super::{
    target::{
        ArchTag, ChildRef, DebugBackend, DebugCaps, DebugError, DetachMode, EventBatch,
        GuestBreakpoint, GuestLink, LinkError, RegsetBlob, ResumeAction, SessionInfo,
        SessionOptions, StopEvent, StopKind, TargetState, ThreadAction, ThreadInfo,
    },
    view::BreakpointKind,
    wire,
};
use crate::observation::GuestProcessIdentity;
use std::time::{Duration, Instant};

const EBUSY: i32 = 16;
const EFAULT: i32 = 14;
const EINVAL: i32 = 22;
const ESRCH: i32 = 3;
const ENOSPC: i32 = 28;
const EOPNOTSUPP: i32 = 95;
const ESTALE: i32 = 116;

fn map_link(error: LinkError) -> DebugError {
    match error.errno {
        Some(EBUSY) => DebugError::Busy,
        Some(ESTALE) => DebugError::Stale,
        Some(ESRCH) => DebugError::Gone,
        Some(EFAULT) => DebugError::Fault,
        Some(ENOSPC) => DebugError::NoSlots,
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
    pub tgid: u32,
}

pub struct KernelDebugBackend {
    link: Box<dyn GuestLink + Send>,
    caps: DebugCaps,
    session: u64,
    generation: u64,
    failure: Option<String>,
    reported_error: i32,
    tgid: u32,
    options: SessionOptions,
    /// Non-stop: the newest event sequence seen in STATUS, and the one fetched.
    seen_sequence: u32,
    fetched_sequence: u32,
    /// The details of the stop being reported (fork, vfork and exec carry more
    /// than STATUS does), by event sequence.
    detail: Option<(u32, StopEvent, Option<String>)>,
}

impl KernelDebugBackend {
    /// What the guest's debugger can do, without attaching to anything. A guest of
    /// phase 3 also reports what it adds; an earlier one refuses that request and
    /// is asked in the earlier form.
    pub fn probe(link: &mut dyn GuestLink) -> Result<DebugCaps, DebugError> {
        match link.request(wire::CAPS, &wire::caps_request_ext()) {
            Ok(reply) => return wire::parse_caps(&reply, true).map_err(protocol),
            Err(error) if error.errno == Some(EINVAL) => {}
            Err(error) => return Err(Self::caps_error(error)),
        }
        let reply = link
            .request(wire::CAPS, &wire::caps_request())
            .map_err(Self::caps_error)?;
        wire::parse_caps(&reply, false).map_err(protocol)
    }
    fn caps_error(error: LinkError) -> DebugError {
        match error.errno {
            Some(EOPNOTSUPP) => DebugError::Unsupported(
                "this guest has no debugger; its base is older than this feature".into(),
            ),
            _ => map_link(error),
        }
    }

    /// The live sessions of the guest (phase 3): what a debugger that lost its own
    /// finds again after a reconnect or a restored snapshot.
    pub fn list_sessions(link: &mut dyn GuestLink) -> Result<Vec<SessionInfo>, DebugError> {
        let reply = link
            .request(wire::SESSIONS, &wire::sessions_request())
            .map_err(map_link)?;
        wire::parse_sessions(&reply).map_err(protocol)
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
        Self::attach_with(link, caps, identity, nonce, stop_now, false)
    }

    /// Take over a live session of the guest (a followed child, or the session of
    /// a debugger that lost it) with a nonce of our own.
    pub fn adopt_session(
        link: &mut dyn GuestLink,
        caps: DebugCaps,
        identity: &GuestProcessIdentity,
        nonce: [u64; 2],
    ) -> Result<AttachedSession, DebugError> {
        Self::attach_with(link, caps, identity, nonce, false, true)
    }

    fn attach_with(
        link: &mut dyn GuestLink,
        caps: DebugCaps,
        identity: &GuestProcessIdentity,
        nonce: [u64; 2],
        stop_now: bool,
        adopt: bool,
    ) -> Result<AttachedSession, DebugError> {
        let request = wire::attach_request(&wire::AttachRequest {
            task_cookie: identity.task_cookie,
            start_boot_ns: identity.start_boot_ns,
            tgid: identity.tgid,
            arch: caps.arch,
            nonce,
            stop_now,
            adopt,
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
            tgid: identity.tgid,
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
            tgid: attached.tgid,
            options: SessionOptions::default(),
            seen_sequence: 0,
            fetched_sequence: 0,
            detail: None,
        }
    }

    /// The generation to send: non-stop sessions have no group stop to name.
    fn generation(&self) -> u64 {
        if self.options.nonstop {
            0
        } else {
            self.generation
        }
    }

    /// The fork, vfork and exec details STATUS does not carry, from the guest's
    /// event list, once per event.
    fn event_detail(&mut self, sequence: u32) -> Option<(StopEvent, Option<String>)> {
        if let Some((cached, event, path)) = &self.detail
            && *cached == sequence
        {
            return Some((*event, path.clone()));
        }
        let request = wire::events_request(self.session, 0, true);
        let reply = self.call(wire::EVENTS, &request).ok()?;
        let (mut entries, _) = wire::parse_events(&reply).ok()?;
        let entry = entries.pop()?;
        if entry.event.sequence != sequence {
            return None;
        }
        self.detail = Some((sequence, entry.event, entry.path.clone()));
        Some((entry.event, entry.path))
    }

    /// A backend for a session found in the guest's list and adopted.
    pub fn adopted(
        link: Box<dyn GuestLink + Send>,
        attached: AttachedSession,
        info: &SessionInfo,
    ) -> Self {
        let mut backend = Self::new(link, attached);
        backend.options = info.options;
        if info.options.nonstop {
            backend.generation = 0;
        }
        backend
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

    /// A hardware request the guest advertised support for.
    fn check_hardware(&self, kind: BreakpointKind, len: u32) -> Result<(), DebugError> {
        let caps = &self.caps;
        let supported = match kind {
            BreakpointKind::Hardware => caps.hardware_breakpoints > 0 && len == 1,
            _ => {
                caps.hardware_watchpoints > 0
                    && matches!(len, 1 | 2 | 4 | 8)
                    && caps.watch_len_mask & (1 << (len - 1)) != 0
            }
        };
        if supported {
            Ok(())
        } else {
            Err(DebugError::Unsupported(format!(
                "{kind:?} of {len} bytes in the debug registers"
            )))
        }
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
                if matches!(
                    status.event_kind,
                    wire::EVENT_FORK | wire::EVENT_VFORK | wire::EVENT_VFORK_DONE
                ) && let Some((event, _)) = self.event_detail(status.event_sequence)
                {
                    return Ok(TargetState::Stopped(event));
                }
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
                signal: entry.signal,
                vfork_wait: entry.vfork_wait,
            })
            .collect())
    }

    fn interrupt(&mut self) -> Result<(), DebugError> {
        self.call(wire::STOP, &wire::stop_request(self.session))
            .and_then(|reply| wire::parse_cont(&reply).map(|_| ()).map_err(protocol))
    }

    fn resume(&mut self, action: ResumeAction) -> Result<(), DebugError> {
        let (step, signal) = match action {
            ResumeAction::Continue => (None, None),
            ResumeAction::Step { tid } => (Some(tid), None),
            ResumeAction::ContinueSignal { tid, signal } => (None, Some((tid, signal))),
            ResumeAction::StepSignal { tid, signal } => (Some(tid), Some((tid, signal))),
        };
        if signal.is_some() && !self.caps.signals {
            return Err(DebugError::Unsupported(
                "this guest cannot pass signals to the program".into(),
            ));
        }
        let reply = self.call(
            wire::CONT,
            &wire::cont_request(self.session, step, self.generation(), signal),
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
            &wire::regs_read_request(self.session, tid, nt_type, self.generation()),
        )?;
        wire::parse_regs(&reply, nt_type).map_err(protocol)
    }

    fn read_regsets(&mut self, tid: u32, nt_types: &[u32]) -> Result<Vec<RegsetBlob>, DebugError> {
        let mut mask = 0u32;
        for nt_type in nt_types {
            match self
                .caps
                .regsets
                .iter()
                .position(|set| set.nt_type == *nt_type)
            {
                Some(index) if index < 32 => mask |= 1 << index,
                _ => {
                    return Err(DebugError::Unsupported(format!(
                        "register set {nt_type} is not offered by the guest"
                    )));
                }
            }
        }
        // The guest answers in table order: ask in that order, then arrange.
        let table: Vec<u32> = self
            .caps
            .regsets
            .iter()
            .map(|set| set.nt_type)
            .enumerate()
            .filter(|(index, _)| mask & (1 << index) != 0)
            .map(|(_, nt_type)| nt_type)
            .collect();
        if !self.caps.batch_regs || nt_types.len() < 2 || table.len() != nt_types.len() {
            return nt_types
                .iter()
                .map(|nt_type| self.read_regset(tid, *nt_type))
                .collect();
        }
        let reply = self.call(
            wire::REGS_READ,
            &wire::regs_read_many_request(self.session, tid, mask, self.generation()),
        )?;
        let mut blobs = wire::parse_regs_many(&reply, &table).map_err(protocol)?;
        Ok(nt_types
            .iter()
            .filter_map(|nt_type| {
                blobs
                    .iter()
                    .position(|blob| blob.nt_type == *nt_type)
                    .map(|index| blobs.swap_remove(index))
            })
            .collect())
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
        let request = wire::regs_write_request(self.session, tid, blob, self.generation())
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
            let request = wire::mem_read_request(self.session, at, want, self.generation())
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
            let request = wire::mem_write_request(self.session, at, part, self.generation())
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
        let request = wire::breakpoint_request(self.session, addr, len, self.generation());
        self.call(wire::BP_SET, &request).map(|_| ())
    }

    fn clear_breakpoint(&mut self, addr: u64, len: u32) -> Result<(), DebugError> {
        let request = wire::breakpoint_request(self.session, addr, len, self.generation());
        self.call(wire::BP_CLEAR, &request).map(|_| ())
    }

    fn insert_breakpoint(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if kind == BreakpointKind::Software {
            return self.set_breakpoint(addr, len);
        }
        self.check_hardware(kind, len)?;
        let request =
            wire::breakpoint_kind_request(self.session, kind, addr, len, self.generation());
        self.call(wire::BP_SET, &request).map(|_| ())
    }

    fn remove_breakpoint(
        &mut self,
        kind: BreakpointKind,
        addr: u64,
        len: u32,
    ) -> Result<(), DebugError> {
        if kind == BreakpointKind::Software {
            return self.clear_breakpoint(addr, len);
        }
        let request =
            wire::breakpoint_kind_request(self.session, kind, addr, len, self.generation());
        self.call(wire::BP_CLEAR, &request).map(|_| ())
    }

    fn auxv(&mut self) -> Result<Vec<u8>, DebugError> {
        if !self.caps.auxv {
            return Err(DebugError::Unsupported(
                "this guest cannot read the auxiliary vector".into(),
            ));
        }
        let reply = self.call(
            wire::AUXV,
            &wire::auxv_request(self.session, self.generation()),
        )?;
        wire::parse_auxv(&reply).map_err(protocol)
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

    fn session_id(&self) -> u64 {
        self.session
    }

    fn target_pid(&self) -> u32 {
        self.tgid
    }

    fn configure(&mut self, options: SessionOptions) -> Result<SessionOptions, DebugError> {
        if (options.fork || options.exec) && !self.caps.follow
            || options.nonstop && !self.caps.nonstop
        {
            return Err(DebugError::Unsupported(
                "this guest cannot follow forks or run threads one at a time".into(),
            ));
        }
        let reply = self.call(wire::CONFIG, &wire::config_request(self.session, options))?;
        let now = wire::parse_config(&reply).map_err(protocol)?;
        self.options = now;
        if now.nonstop {
            // No group stop to name: requests carry generation 0.
            self.generation = 0;
        }
        Ok(now)
    }

    fn exec_path(&mut self) -> Option<String> {
        let sequence = self
            .detail
            .as_ref()
            .filter(|(_, event, _)| event.kind == StopKind::Exec)
            .map(|(sequence, _, _)| *sequence);
        if let Some(sequence) = sequence
            && let Some((_, path)) = self.event_detail(sequence)
        {
            return path;
        }
        // Not fetched yet: ask for the current event.
        let reply = self
            .call(wire::EVENTS, &wire::events_request(self.session, 0, true))
            .ok()?;
        let (mut entries, _) = wire::parse_events(&reply).ok()?;
        let entry = entries.pop()?;
        let path = entry.path.clone();
        self.detail = Some((entry.event.sequence, entry.event, entry.path));
        path
    }

    fn adopt_child(&mut self, child: &ChildRef) -> Result<Box<dyn DebugBackend>, DebugError> {
        let mut link = self
            .link
            .duplicate()
            .ok_or_else(|| DebugError::Unsupported("this link cannot be shared".into()))?;
        let identity = GuestProcessIdentity {
            boot_id: String::new(),
            task_cookie: child.task_cookie,
            start_boot_ns: child.start_boot_ns,
            tgid: child.tgid,
        };
        let nonce = [
            (child.session << 1) | 1,
            child.task_cookie ^ child.start_boot_ns,
        ];
        let attached = Self::adopt_session(link.as_mut(), self.caps.clone(), &identity, nonce)?;
        if attached.session != child.session {
            return Err(protocol("the guest adopted another session".into()));
        }
        let mut backend = Self::new(link, attached);
        backend.tgid = child.tgid;
        backend.options = self.options;
        if self.options.nonstop {
            backend.generation = 0;
        }
        if !child.shared_memory {
            // The copy of the parent's memory holds the parent's breakpoint
            // bytes and the guest's table remembers them; whoever controls the
            // child sets its own.
            if !self.options.nonstop {
                let deadline = Instant::now() + Duration::from_secs(3);
                loop {
                    match backend.state()? {
                        TargetState::Stopped(_) => break,
                        TargetState::Exited { .. } | TargetState::Replaced => {
                            return Ok(Box::new(backend));
                        }
                        _ => {}
                    }
                    if Instant::now() >= deadline {
                        return Err(DebugError::Transport(
                            "the followed child did not stop".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            for held in backend.guest_breakpoints()? {
                if held.kind == BreakpointKind::Software {
                    backend.clear_breakpoint(held.addr, held.len)?;
                }
            }
        }
        Ok(Box::new(backend))
    }

    fn events(&mut self, acknowledged: u32) -> Result<EventBatch, DebugError> {
        // STATUS is one cheap request that says whether anything is new.
        let reply = self.call(wire::STATUS, &wire::status_request(self.session))?;
        let status = wire::parse_status(&reply).map_err(protocol)?;
        if status.state == wire::STATE_EXITED {
            return Ok(EventBatch {
                exited: Some(status.wait_status),
                ..EventBatch::default()
            });
        }
        if status.state == wire::STATE_EXEC {
            return Err(DebugError::Gone);
        }
        self.seen_sequence = status.event_sequence;
        if status.event_sequence == self.fetched_sequence && self.fetched_sequence <= acknowledged {
            return Ok(EventBatch::default());
        }
        let reply = self.call(
            wire::EVENTS,
            &wire::events_request(self.session, acknowledged, false),
        )?;
        let (entries, dropped) = wire::parse_events(&reply).map_err(protocol)?;
        if let Some(last) = entries.last() {
            self.fetched_sequence = last.event.sequence;
        } else {
            self.fetched_sequence = status.event_sequence;
        }
        if let Some(entry) = entries
            .iter()
            .rev()
            .find(|entry| entry.event.kind == StopKind::Exec)
        {
            self.detail = Some((entry.event.sequence, entry.event, entry.path.clone()));
        }
        Ok(EventBatch {
            events: entries.into_iter().map(|entry| entry.event).collect(),
            dropped,
            exited: None,
        })
    }

    fn thread_action(&mut self, tid: Option<u32>, action: ThreadAction) -> Result<u32, DebugError> {
        let reply = self.call(
            wire::THREAD_CTL,
            &wire::thread_ctl_request(self.session, tid, action),
        )?;
        wire::parse_thread_ctl(&reply).map_err(protocol)
    }

    fn guest_breakpoints(&mut self) -> Result<Vec<GuestBreakpoint>, DebugError> {
        let reply = self.call(wire::BP_LIST, &wire::bp_list_request(self.session))?;
        wire::parse_bp_list(&reply).map_err(protocol)
    }
}

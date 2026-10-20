// SPDX-License-Identifier: MIT
//! The gdbstub `Target`: translates RSP requests into `DebugBackend` calls.
//! All-stop, one process. Breakpoints are reference-counted here (a debugger
//! may ask for the same address twice) and live in the guest only while the
//! group runs, so memory read while stopped is always the sample's own bytes.
//! The in-app panel shares the guest's breakpoint table: an address stays
//! registered while either a connected debugger or the panel wants it.
use super::{
    amd64::{Amd64, BreakpointLen},
    regs::{RegisterFile, TargetDescription},
    target::{DebugBackend, DebugError, ResumeAction, StopEvent, StopKind, TargetState},
};
use gdbstub::{
    common::{Signal, Tid},
    stub::MultiThreadStopReason,
    target::{
        Target, TargetError, TargetResult,
        ext::{
            base::{
                BaseOps,
                multithread::{
                    MultiThreadBase, MultiThreadResume, MultiThreadResumeOps,
                    MultiThreadSchedulerLocking, MultiThreadSchedulerLockingOps,
                    MultiThreadSingleStep, MultiThreadSingleStepOps,
                },
            },
            breakpoints::{Breakpoints, BreakpointsOps, SwBreakpoint, SwBreakpointOps},
        },
    },
};
use std::{collections::BTreeMap, num::NonZeroUsize};

/// The packet size advertised to the client: reads and writes of this order fit
/// a guest request, larger ones are split by the backend.
pub(super) const PACKET_BUFFER: usize = 0x4000;

fn tid_of(tid: Tid) -> u32 {
    u32::try_from(tid.get()).unwrap_or(0)
}

/// A backend error as the RSP target reports it: transport trouble ends the
/// session, anything else is an error reply the client shows to its user.
fn report(error: DebugError) -> TargetError<DebugError> {
    match error {
        DebugError::Fault => TargetError::Errno(14),
        DebugError::Busy => TargetError::Errno(16),
        DebugError::Gone => TargetError::Errno(3),
        DebugError::Stale => TargetError::Errno(116),
        DebugError::Unsupported(_) | DebugError::Invalid(_) => TargetError::Errno(22),
        error @ (DebugError::Transport(_) | DebugError::Guest { .. }) => TargetError::Fatal(error),
    }
}

#[derive(Default)]
struct Actions {
    step: Option<u32>,
}

/// Who wants a breakpoint at one address: the RSP client (counted, it may ask
/// twice) and the in-app panel (once).
#[derive(Default)]
struct Wanted {
    client: u32,
    panel: bool,
}
impl Wanted {
    fn none(&self) -> bool {
        self.client == 0 && !self.panel
    }
}

pub(super) struct RspTarget {
    backend: Box<dyn DebugBackend>,
    description: &'static TargetDescription,
    actions: Actions,
    breakpoints: BTreeMap<u64, Wanted>,
    registers: Option<(u32, RegisterFile)>,
    stop: Option<StopEvent>,
    last_sequence: Option<u32>,
    running: bool,
}

impl RspTarget {
    pub(super) fn new(backend: Box<dyn DebugBackend>) -> Self {
        let description = backend.caps().arch.description();
        Self {
            backend,
            description,
            actions: Actions::default(),
            breakpoints: BTreeMap::new(),
            registers: None,
            stop: None,
            last_sequence: None,
            running: false,
        }
    }
    pub(super) fn backend(&mut self) -> &mut dyn DebugBackend {
        self.backend.as_mut()
    }
    pub(super) fn is_running(&self) -> bool {
        self.running
    }
    /// A new client: learn the target's current state without assuming it.
    pub(super) fn adopt(&mut self) -> Result<TargetState, DebugError> {
        self.registers = None;
        let state = self.backend.state()?;
        match state {
            TargetState::Stopped(event) => {
                self.stop = Some(event);
                self.last_sequence = Some(event.sequence);
                self.running = false;
            }
            _ => self.running = true,
        }
        Ok(state)
    }
    /// Drop every breakpoint the RSP client set (the target must be stopped).
    /// The panel's own stay registered.
    pub(super) fn clear_client_breakpoints(&mut self) {
        let addresses: Vec<u64> = self.breakpoints.keys().copied().collect();
        for address in addresses {
            if let Some(wanted) = self.breakpoints.get_mut(&address) {
                wanted.client = 0;
                if wanted.none() {
                    let _ = self.backend.clear_breakpoint(address, 1);
                    self.breakpoints.remove(&address);
                }
            }
        }
    }
    /// Register (or release) the panel's interest in a breakpoint at `addr`;
    /// the guest is asked only when nobody else already holds the address.
    /// The target must be stopped.
    pub(super) fn panel_breakpoint(&mut self, addr: u64, on: bool) -> Result<(), DebugError> {
        if on {
            if self
                .breakpoints
                .get(&addr)
                .is_some_and(|wanted| wanted.panel)
            {
                return Ok(());
            }
            if !self.breakpoints.contains_key(&addr) {
                self.backend.set_breakpoint(addr, 1)?;
            }
            self.breakpoints.entry(addr).or_default().panel = true;
            return Ok(());
        }
        let Some(wanted) = self.breakpoints.get_mut(&addr) else {
            return Ok(());
        };
        if !wanted.panel {
            return Ok(());
        }
        wanted.panel = false;
        if wanted.none() {
            self.backend.clear_breakpoint(addr, 1)?;
            self.breakpoints.remove(&addr);
        }
        Ok(())
    }
    pub(super) fn resume_plain(&mut self) -> Result<(), DebugError> {
        self.registers = None;
        self.running = true;
        self.backend.resume(ResumeAction::Continue)
    }
    /// The panel resumed the process (it is running, its registers are stale).
    pub(super) fn note_resumed(&mut self) {
        self.registers = None;
        self.running = true;
    }
    /// The panel saw the process stop.
    pub(super) fn note_stopped(&mut self) {
        self.registers = None;
        self.running = false;
    }
    pub(super) fn interrupt(&mut self) -> Result<(), DebugError> {
        self.backend.interrupt()
    }

    /// The next stop of a running target, if it has happened.
    pub(super) fn poll(&mut self) -> Result<Option<MultiThreadStopReason<u64>>, DebugError> {
        let state = self.backend.state()?;
        Ok(match state {
            TargetState::Running | TargetState::Transition => None,
            TargetState::Stopped(event) => {
                self.last_sequence = Some(event.sequence);
                self.stop = Some(event);
                self.running = false;
                self.registers = None;
                let tid = NonZeroUsize::new(event.tid as usize);
                Some(match (event.kind, tid) {
                    (StopKind::Breakpoint { .. }, Some(tid)) => MultiThreadStopReason::SwBreak(tid),
                    (StopKind::Step, Some(tid)) => MultiThreadStopReason::SignalWithThread {
                        tid,
                        signal: Signal::SIGTRAP,
                    },
                    (_, Some(tid)) => MultiThreadStopReason::SignalWithThread {
                        tid,
                        signal: Signal::SIGINT,
                    },
                    (_, None) => MultiThreadStopReason::Signal(Signal::SIGINT),
                })
            }
            TargetState::Exited { wait_status } => {
                self.running = false;
                if wait_status & 0x7f == 0 {
                    Some(MultiThreadStopReason::Exited(
                        ((wait_status >> 8) & 0xff) as u8,
                    ))
                } else {
                    Some(MultiThreadStopReason::Terminated(Signal(
                        (wait_status & 0x7f) as u8,
                    )))
                }
            }
            TargetState::Replaced => {
                self.running = false;
                Some(MultiThreadStopReason::Exited(0))
            }
        })
    }
    fn load(&mut self, tid: u32) -> Result<&RegisterFile, DebugError> {
        if self
            .registers
            .as_ref()
            .is_none_or(|(cached, _)| *cached != tid)
        {
            let mut file = RegisterFile::new();
            for nt_type in &self.description.regsets {
                file.insert(self.backend.read_regset(tid, *nt_type)?);
            }
            self.registers = Some((tid, file));
        }
        Ok(&self
            .registers
            .as_ref()
            .expect("registers were just loaded")
            .1)
    }
}

impl Target for RspTarget {
    type Arch = Amd64;
    type Error = DebugError;
    fn base_ops(&mut self) -> BaseOps<'_, Self::Arch, Self::Error> {
        BaseOps::MultiThread(self)
    }
    fn support_breakpoints(&mut self) -> Option<BreakpointsOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadBase for RspTarget {
    fn read_registers(
        &mut self,
        regs: &mut super::amd64::Amd64Registers,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let description = self.description;
        let file = self.load(tid_of(tid)).map_err(report)?;
        regs.image = description.serialize(file);
        Ok(())
    }
    fn write_registers(
        &mut self,
        regs: &super::amd64::Amd64Registers,
        tid: Tid,
    ) -> TargetResult<(), Self> {
        let tid = tid_of(tid);
        let description = self.description;
        let mut file = self.load(tid).map_err(report)?.clone();
        let changed = description
            .deserialize(&regs.image, &mut file)
            .map_err(|_| TargetError::Errno(22))?;
        for nt_type in changed {
            let data = file.get(nt_type).expect("changed set exists").to_vec();
            self.backend
                .write_regset(tid, &super::target::RegsetBlob { nt_type, data })
                .map_err(report)?;
        }
        self.registers = None;
        Ok(())
    }
    fn read_addrs(
        &mut self,
        start_addr: u64,
        data: &mut [u8],
        _tid: Tid,
    ) -> TargetResult<usize, Self> {
        let bytes = self
            .backend
            .read_memory(start_addr, data.len())
            .map_err(report)?;
        data[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len())
    }
    fn write_addrs(&mut self, start_addr: u64, data: &[u8], _tid: Tid) -> TargetResult<(), Self> {
        self.backend
            .write_memory(start_addr, data)
            .map_err(report)?;
        self.registers = None;
        Ok(())
    }
    fn list_active_threads(
        &mut self,
        thread_is_active: &mut dyn FnMut(Tid),
    ) -> Result<(), DebugError> {
        for thread in self.backend.threads()? {
            if let Some(tid) = NonZeroUsize::new(thread.tid as usize) {
                thread_is_active(tid);
            }
        }
        Ok(())
    }
    fn support_resume(&mut self) -> Option<MultiThreadResumeOps<'_, Self>> {
        Some(self)
    }
}

impl MultiThreadResume for RspTarget {
    fn resume(&mut self) -> Result<(), DebugError> {
        self.registers = None;
        self.running = true;
        match self.actions.step.take() {
            Some(tid) => self.backend.resume(ResumeAction::Step { tid }),
            None => self.backend.resume(ResumeAction::Continue),
        }
    }
    fn clear_resume_actions(&mut self) -> Result<(), DebugError> {
        self.actions = Actions::default();
        Ok(())
    }
    // Signals are not injected yet: the engine reports no signal stops, so a
    // client has no signal to pass. Every thread resumes together.
    fn set_resume_action_continue(
        &mut self,
        _tid: Tid,
        _signal: Option<Signal>,
    ) -> Result<(), DebugError> {
        Ok(())
    }
    fn support_single_step(&mut self) -> Option<MultiThreadSingleStepOps<'_, Self>> {
        self.backend.caps().hardware_single_step.then_some(self)
    }
    fn support_scheduler_locking(&mut self) -> Option<MultiThreadSchedulerLockingOps<'_, Self>> {
        Some(self)
    }
}
impl MultiThreadSingleStep for RspTarget {
    fn set_resume_action_step(
        &mut self,
        tid: Tid,
        _signal: Option<Signal>,
    ) -> Result<(), DebugError> {
        self.actions.step = Some(tid_of(tid));
        Ok(())
    }
}
impl MultiThreadSchedulerLocking for RspTarget {
    fn set_resume_action_scheduler_lock(&mut self) -> Result<(), DebugError> {
        // Only the stepped thread runs: that is what the engine does for a step.
        Ok(())
    }
}

impl Breakpoints for RspTarget {
    fn support_sw_breakpoint(&mut self) -> Option<SwBreakpointOps<'_, Self>> {
        self.backend.caps().software_breakpoints.then_some(self)
    }
}
impl SwBreakpoint for RspTarget {
    fn add_sw_breakpoint(&mut self, addr: u64, kind: BreakpointLen) -> TargetResult<bool, Self> {
        let len = u32::try_from(kind.0).map_err(|_| TargetError::Errno(22))?;
        if let Some(wanted) = self.breakpoints.get_mut(&addr) {
            wanted.client += 1;
            return Ok(true);
        }
        self.backend.set_breakpoint(addr, len).map_err(report)?;
        self.breakpoints.insert(
            addr,
            Wanted {
                client: 1,
                panel: false,
            },
        );
        Ok(true)
    }
    fn remove_sw_breakpoint(&mut self, addr: u64, kind: BreakpointLen) -> TargetResult<bool, Self> {
        let len = u32::try_from(kind.0).map_err(|_| TargetError::Errno(22))?;
        let Some(wanted) = self.breakpoints.get_mut(&addr) else {
            return Ok(false);
        };
        if wanted.client == 0 {
            return Ok(false);
        }
        wanted.client -= 1;
        if wanted.none() {
            self.backend.clear_breakpoint(addr, len).map_err(report)?;
            self.breakpoints.remove(&addr);
        }
        Ok(true)
    }
}
